"""Upgrade plans for vulnerable dependencies: the smallest version that leaves every known
advisory, and the kind of change it takes.

The target is the lowest version at or above the current one that no advisory for the
package affects, chosen among the versions the advisories name as fixed (published releases);
it needs no registry, so planning runs offline. What the change takes follows from the
requirements recorded in the lockfile and manifest (`DependencyFile.requires`):

    update-lockfile    every known requirement already admits the target (re-lock)
    raise-requirement  the project's own range excludes it (edit the manifest)
    override           a package in between pins a range that excludes it (npm `overrides`, yarn
                       `resolutions`, pnpm `overrides`, a pip constraint, Maven
                       `dependencyManagement`, a direct NuGet reference), or upgrade that package
    no-fix             no unaffected version is known

`major` marks a target in a later major version (a breaking-change risk). Choosing upgrades
of the packages in between (whose newer versions widen the range) needs their release
metadata from the registry; that, and solving all packages' constraints together, is the
next step.
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


def target_version(ecosystem: str, current: str, advisories: List[dict]) -> Optional[str]:
    """The lowest fixed version >= current that no advisory affects."""
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


def plan(findings: List[dict], files: List[DependencyFile], db) -> List[dict]:
    """One plan per vulnerable package version in each manifest or lockfile."""
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
        ids = sorted({f["id"] for f in fs})
        entry = {"ecosystem": eco, "package": name, "current": version, "target": target, "path": path,
                 "direct": fs[0]["direct"], "dev": fs[0]["dev"], "fixes": ids if target else [],
                 "unfixed": [] if target else ids, "via": fs[0]["via"],
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
        if target is None:
            action = "no-fix"
        elif any(r["admits_target"] is False and r["by"] == "(project)" for r in requirers):
            action = "raise-requirement"
        elif any(r["admits_target"] is False for r in requirers):
            action = "override"
        else:
            action = "update-lockfile"
        entry["action"] = action
        entry["known_requirements"] = bool(requirers)
        if action == "override":
            entry["how"] = OVERRIDE_HOW.get(eco, "")
        out.append(entry)
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
        what = {"update-lockfile": "re-lock (every known range admits it)",
                "raise-requirement": "raise the project's requirement",
                "override": f"override: {p.get('how', '')}"}[p["action"]]
        if not p["known_requirements"] and p["action"] == "update-lockfile":
            what = "re-lock (requirements not recorded in this file)"
        lines.append(f"  {p['package']} {p['current']} -> {p['target']}{tag}: {what}  "
                     f"[{p['path']}; fixes {len(p['fixes'])}]")
        for r in p["requirers"]:
            if r["admits_target"] is False:
                lines.append(f"      {r['by']} requires {r['spec']}")
    return "\n".join(lines)
