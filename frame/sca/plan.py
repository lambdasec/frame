"""Upgrade plans for vulnerable dependencies: the smallest version that leaves every known
advisory, and the kind of change it takes.

The target is the lowest version at or above the current one that no advisory for the
package affects, chosen among the versions the advisories name as fixed (published releases);
it needs no registry, so planning runs offline. What the change takes follows from the
requirements recorded in the lockfile and manifest (`DependencyFile.requires`):

    update-lockfile    every known requirement already admits the target (re-lock); never for NuGet,
                       which resolves the lowest version a range admits, so re-locking moves nothing
                       (a manifest without a lockfile, Maven and go.mod are edited instead: their
                       versions are the requirements)
    raise-requirement  the project's own range excludes it (edit the manifest)
    override           a package in between pins a range that excludes it (npm `overrides`, yarn
                       `resolutions`, pnpm `overrides`, a pip constraint, Maven
                       `dependencyManagement`, a direct NuGet reference), or upgrade that package
    no-fix             no unaffected version is known

`major` marks a target in a later major version (a breaking-change risk).

With a registry (`frame deps --plan --registry`, npm), the plan for a lockfile is instead
solved over every package's constraints together (`solve.py`): upgrades of the packages in
between whose newer versions admit the fix replace overrides, and the packages that only
need re-locking to a newer version are listed with the version the solution needs:

    update-lockfile    as above (the solver's target is reachable within every chosen range)
    raise-requirement  a direct dependency's new version is outside the project's range
    removed            a chosen upgrade no longer depends on it: it leaves the tree

A vulnerable package the upgrades cannot fix keeps its override.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from frame.sca.model import DependencyFile, normalize_name
from frame.sca.osv import is_affected
from frame.sca.ranges import satisfies
from frame.sca.versions import sort_key, sorted_versions

OVERRIDE_HOW = {
    "npm": "an `overrides` entry (npm), `resolutions` (yarn) or `pnpm.overrides`",
    "PyPI": "a constraint (`-c constraints.txt`, or `[tool.uv] constraint-dependencies`)",
    "Maven": "a `dependencyManagement` entry",
    "NuGet": "a direct PackageReference at that version",
    "crates.io": "a `[patch]` entry or `cargo update -p`",
    "Go": "a `require` of that version in go.mod",
    "SwiftURL": "a dependency requirement in Package.swift",
}


def _major(version: str) -> Optional[int]:
    m = re.match(r"^\s*v?(?:\d+!)?(\d+)", version)
    return int(m.group(1)) if m else None


# where a language package found in an image comes from, and so where to upgrade it
IN_IMAGE = {"PyPI": "upgrade it in the image's pip install step (or its requirements file)",
            "npm": "upgrade it in the project whose node_modules the image copies, and rebuild",
            "Maven": "replace the jar the image copies (or rebuild the application with the fixed version)"}


def fixable(advisories: List[dict]) -> List[dict]:
    """Advisories that name a fixed version: one with none (an unmaintained package, an unfixed
    flaw) affects every version, and must not hide the upgrades that fix the others."""
    return [a for a in advisories if any(isinstance(e, dict) and e.get("fixed")
                                         for r in a.get("ranges", ()) for e in r.get("events") or [])]


def target_version(ecosystem: str, current: str, advisories: List[dict]) -> Optional[str]:
    """The lowest fixed version >= current that no advisory with a fix affects."""
    advisories = fixable(advisories)
    cur = sort_key(ecosystem, current)
    fixed = set()
    for adv in advisories:
        for r in adv.get("ranges", ()):
            for e in r.get("events") or []:
                f = e.get("fixed") if isinstance(e, dict) else None
                if f is not None:
                    k = sort_key(ecosystem, str(f))
                    if k is not None and cur is not None and k >= cur:
                        fixed.add(str(f))
    for v in sorted_versions(ecosystem, fixed):
        if not any(is_affected(ecosystem, v, a) for a in advisories):
            return v
    return None


def plan(findings: List[dict], files: List[DependencyFile], db, registry=None) -> List[dict]:
    """One plan per vulnerable package version in each manifest or lockfile (plus, with a
    registry, the packages in between that the solved upgrade changes)."""
    by_path = {f.path: f for f in files}
    groups: Dict[Tuple[str, str, str], List[dict]] = {}
    for f in findings:
        groups.setdefault((f["path"], f["package"], f["version"]), []).append(f)
    out: List[dict] = []
    for (path, name, version), fs in sorted(groups.items()):
        eco = fs[0]["ecosystem"]
        df = by_path.get(path)
        every = db.advisories(eco, name)                  # all of the package's advisories, not only matched
        target = target_version(eco, version, every)
        if target is not None and sort_key(eco, target) == sort_key(eco, version):
            target = None                                  # only advisories with no fix are left
        ids = sorted({f["id"] for f in fs})
        by_id = {a["id"]: a for a in every}
        still = sorted(i for i in ids if target and i in by_id and is_affected(eco, target, by_id[i]))
        entry = {"ecosystem": eco, "package": name, "current": version, "target": target, "path": path,
                 "direct": fs[0]["direct"], "dev": fs[0]["dev"],
                 "fixes": [i for i in ids if i not in still] if target else [],
                 "unfixed": still if target else ids, "via": fs[0]["via"],
                 "major": bool(target and _major(target) is not None and _major(version) is not None
                               and _major(target) > _major(version))}
        requirers = []
        if df is not None:
            key = next((k for k, p in df.packages.items() if p.name == name and p.version == version), None)
            n = normalize_name(eco, name)
            parents = [p for p, cs in df.edges.items() if key in cs] if key else []
            for parent in [""] + parents:
                spec = df.requires.get(parent, {}).get(n)
                if spec is None or (parent == "" and not fs[0]["direct"]):
                    continue
                label = "(project)" if parent == "" else f"{df.packages[parent].name}@{df.packages[parent].version}"
                requirers.append({"by": label, "spec": spec,
                                  "admits_target": satisfies(eco, target, spec) if target else None})
        entry["requirers"] = requirers
        kind = df.kind if df is not None else ""
        if target is None:
            action = "no-fix"
        elif kind == "installed":
            action = "upgrade-os-package"                 # a package of a container image or root filesystem
        elif kind == "image":
            action = "upgrade-in-image"                   # a language package found in an image: no manifest to edit
        elif eco == "Go":
            action = "raise-requirement"                  # go.mod is the requirement list, indirect ones too
        elif eco == "Maven" and kind in ("manifest", "resolved"):
            # Maven has no lockfile: resolution is the pom, so a direct version is edited there and
            # a transitive one is managed (re-running Maven would resolve the same versions)
            action = "raise-requirement" if fs[0]["direct"] else "override"
        elif kind == "manifest" and fs[0]["direct"]:
            action = "raise-requirement"                  # the pinned version is the requirement
        elif any(r["admits_target"] is False and r["by"] == "(project)" for r in requirers):
            action = "raise-requirement"
        elif any(r["admits_target"] is False for r in requirers):
            action = "override"
        else:
            action = "update-lockfile"
        if action == "update-lockfile" and eco == "NuGet":
            # NuGet resolves the LOWEST version every range admits, so re-locking moves nothing:
            # a direct reference is raised, a transitive one needs its own direct reference
            action = "raise-requirement" if fs[0]["direct"] else "override"
        entry["action"] = action
        entry["known_requirements"] = bool(requirers)
        if action == "override":
            entry["how"] = OVERRIDE_HOW.get(eco, "")
        out.append(entry)
    if registry is not None:
        out = _solved(out, findings, by_path, db, registry)
        _go_toolchains(out, findings, by_path, db, registry)
    return out


def _go_toolchains(plans: List[dict], findings: List[dict], by_path: Dict[str, DependencyFile], db,
                   registry) -> None:
    """Go needs no solver (go.mod lists every module, and Minimal Version Selection takes the
    highest any go.mod requires), but a version can need a newer Go than the module builds with.
    Say so, and name the newest fix the module's own Go can build and what it fixes."""
    reg = registry.for_ecosystem("Go") if hasattr(registry, "for_ecosystem") else None
    if reg is None:
        return
    for p in plans:
        df = by_path.get(p["path"])
        if p["ecosystem"] != "Go" or not p.get("target") or df is None or not df.go_version:
            continue
        need = reg.go_directive(p["package"], p["target"])
        if not need or sort_key("Go", need) <= sort_key("Go", df.go_version):
            continue
        p["requires_go"], p["module_go"] = need, df.go_version
        every = fixable(db.advisories("Go", p["package"]))
        matched = [a for a in every if a["id"] in set(p["fixes"])]
        cands = sorted_versions("Go", {e["fixed"] for a in every for r in a.get("ranges", ())
                                       for e in r.get("events") or [] if e.get("fixed")
                                       and sort_key("Go", e["fixed"]) is not None
                                       and sort_key("Go", e["fixed"]) > sort_key("Go", p["current"])
                                       and sort_key("Go", e["fixed"]) < sort_key("Go", p["target"])})
        for v in reversed(cands):                           # the newest fix the module's Go builds
            g = reg.go_directive(p["package"], v)
            if g and sort_key("Go", g) <= sort_key("Go", df.go_version):
                p["within_go"] = {"version": v, "go": g,
                                  "fixes": sorted(a["id"] for a in matched if not is_affected("Go", v, a))}
                break


def _solved(plans: List[dict], findings: List[dict], by_path: Dict[str, DependencyFile], db, registry) -> List[dict]:
    from frame.sca.solve import SUPPORTED, solve_file
    out = list(plans)
    for path, df in sorted(by_path.items()):
        if df.ecosystem not in SUPPORTED or df.kind != "lockfile":
            continue
        vulnerable_pairs = {(f["package"], f["version"]) for f in findings if f["path"] == path}
        vuln = {k for k, p in df.packages.items() if (p.name, p.version) in vulnerable_pairs}
        if not vuln:
            continue
        reg = registry.for_ecosystem(df.ecosystem) if hasattr(registry, "for_ecosystem") else registry
        if reg is None:
            continue
        sol = solve_file(df, vuln, db, reg)
        if sol is None or not sol.changes:
            continue
        index = {(p["package"], p["current"]): p for p in out if p["path"] == path}

        def fixed_below(name: str, version: str) -> List[str]:
            """The vulnerable packages this one's upgrade lets go: fixed ones beneath it."""
            start = [k for k, p in df.packages.items() if p.name == name and p.version == version]
            seen, stack = set(), list(start)
            while stack:
                k = stack.pop()
                for c in df.edges.get(k, ()):
                    if c not in seen:
                        seen.add(c)
                        stack.append(c)
            return sorted({df.packages[k].name for k in seen & sol.fixed})
        changed_pairs = {(c.package, c.current) for c in sol.changes}
        for c in sol.changes:
            entry = index.get((c.package, c.current))
            if entry is not None and entry["action"] == "no-fix" and c.target is not None:
                continue                                   # nothing safe was found for it
            if entry is None:
                entry = {"ecosystem": df.ecosystem, "package": c.package, "current": c.current, "path": path,
                         "direct": c.direct, "dev": next((p.dev for p in df.packages.values()
                                                          if p.name == c.package and p.version == c.current), False),
                         "fixes": [], "unfixed": [], "via": [], "requirers": [], "known_requirements": True,
                         "enables": fixed_below(c.package, c.current)}
                out.append(entry)
            elif any(k for k in sol.unresolved if df.packages[k].name == c.package):
                continue                                   # still vulnerable: keep the per-package plan
            entry["target"] = c.target
            entry["action"] = "removed" if c.target is None else \
                "raise-requirement" if c.raise_requirement or (c.direct and df.ecosystem == "NuGet") \
                else "update-lockfile"
            entry["solved"] = True
            entry.pop("how", None)
            entry["major"] = bool(c.target and _major(c.target) is not None and _major(c.current) is not None
                                  and _major(c.target) > _major(c.current))
            entry["brings"] = _brings(df, reg, c, {pk for (pk, _v) in changed_pairs})
    return out


def _brings(df: DependencyFile, reg, change, changed: set) -> List[dict]:
    """Other installed packages the new version needs at a version the lockfile does not have:
    re-locking moves them too (they are outside the solved set, so the plan does not choose)."""
    if change.target is None:
        return []
    deps = reg.deps(change.package, change.target) or {}
    out = []
    for name, rng in sorted(deps.items()):
        n = normalize_name(df.ecosystem, name)
        installed = sorted({pk.version for pk in df.packages.values()
                            if normalize_name(df.ecosystem, pk.name) == n and pk.version and pk.name not in changed})
        # a copy that already satisfies the range is the one the new version gets (npm keeps several)
        if installed and not any(satisfies(df.ecosystem, v, rng) is True for v in installed):
            out.append({"package": name, "current": ", ".join(installed), "requires": rng})
    return out


def format_plan(plans: List[dict]) -> str:
    if not plans:
        return ""
    lines = [f"\nUpgrade plan ({len(plans)} package{'s' if len(plans) != 1 else ''}):"]
    for p in plans:
        tag = " [major]" if p["major"] else ""
        if p["action"] == "no-fix":
            lines.append(f"  {p['package']}@{p['current']}: no fixed version known ({', '.join(p['unfixed'])})")
            continue
        if p["action"] == "removed":
            lines.append(f"  {p['package']}@{p['current']}: leaves the tree (no upgraded package depends on it)  "
                         f"[{p['path']}; fixes {len(p['fixes'])}]")
            continue
        what = {"upgrade-os-package": "upgrade it in the image (apt-get / apk upgrade, or a newer base image)",
                "upgrade-in-image": IN_IMAGE.get(p["ecosystem"], "upgrade it where the image installs it"),
                "update-lockfile": "re-lock (every known range admits it)",
                "raise-requirement": "raise the project's requirement",
                "override": f"override: {p.get('how', '')}"}[p["action"]]
        if p.get("solved") and p["action"] == "update-lockfile":
            what = "re-lock to it (admitted by the solved upgrades)"
        elif not p["known_requirements"] and p["action"] == "update-lockfile":
            what = "re-lock (requirements not recorded in this file)"
        gain = f"fixes {len(p['fixes'])}" if p["fixes"] else f"lets {', '.join(p.get('enables', [])[:3])} upgrade"
        if p.get("unfixed"):
            gain += f"; {len(p['unfixed'])} with no fix stay open: {', '.join(p['unfixed'][:3])}"
        lines.append(f"  {p['package']} {p['current']} -> {p['target']}{tag}: {what}  [{p['path']}; {gain}]")
        if p.get("requires_go"):
            df_go = p.get("within_go")
            lines.append(f"      needs Go {p['requires_go']} (go.mod says go {p['module_go']})" + (
                f"; the newest fix that Go builds is {df_go['version']} (go {df_go['go']}), fixing "
                f"{len(df_go['fixes'])} of {len(p['fixes'])}" if df_go else "; no fix builds with it"))
        if p.get("brings"):
            lines.append("      re-locking also moves " + ", ".join(
                f"{b['package']} {b['current']} ({b['requires']})" for b in p["brings"][:5]))
        for r in [] if p.get("solved") else p["requirers"]:
            if r["admits_target"] is False:
                lines.append(f"      {r['by']} requires {r['spec']}")
    return "\n".join(lines)
