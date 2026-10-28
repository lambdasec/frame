"""Find and read every dependency manifest and lockfile under a directory."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Union

from frame.sca.osv import DISTRO_FAMILIES
from frame.sca.jvm import (GRADLE_REPORT_FILES, MAVEN_TREE_FILES, MAVEN_TREE_JSON_FILES, parse_gradle_report,
                           parse_maven_tree, parse_maven_tree_json)
from frame.sca.lockfiles import (DEV_FLAGGED, LOCKFILES, LockfileError, _propagate_dev, _pyproject_direct,
                                 central_package_versions, lockfile_ecosystem, manifest_ecosystem,
                                 manifest_parser, parse_csproj, parse_requirements)
from frame.sca.model import MAVEN, PYPI, DependencyFile, normalize_name

# build-tool reports read as resolved graphs (they stand in for a lockfile of their ecosystem)
REPORTS: Dict[str, Callable[[str, str], DependencyFile]] = {
    **{n: parse_maven_tree for n in MAVEN_TREE_FILES},
    **{n: parse_maven_tree_json for n in MAVEN_TREE_JSON_FILES},
    **{n: parse_gradle_report for n in GRADLE_REPORT_FILES},
}
_GRADLE_BUILD = ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts")


@dataclass
class DependencyReport:
    root: str
    files: List[DependencyFile] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Dict[str, int]]:
        """Per ecosystem: distinct packages (name and version), how many are direct, dev."""
        out: Dict[str, Dict[str, int]] = {}
        seen: Dict[str, dict] = {}
        for f in self.files:
            for p in f.packages.values():
                cur = seen.get(p.key)
                if cur is None:
                    seen[p.key] = {"eco": p.ecosystem, "direct": bool(p.direct), "dev": p.dev}
                else:
                    cur["direct"] |= bool(p.direct)
                    cur["dev"] &= p.dev
        for s in seen.values():
            e = out.setdefault(s["eco"], {"packages": 0, "direct": 0, "dev": 0})
            e["packages"] += 1
            e["direct"] += s["direct"]
            e["dev"] += s["dev"]
        return dict(sorted(out.items()))

    def to_dict(self) -> dict:
        return {"root": self.root, "summary": self.summary(),
                "files": [f.to_dict() for f in self.files], "warnings": self.warnings}


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _home(path: Path) -> Path:
    """The project directory a file describes (`obj/project.assets.json` -> the project,
    `vcpkg_installed/vcpkg/status` -> the project)."""
    if path.name == "project.assets.json" and path.parent.name == "obj":
        return path.parent.parent
    if _is_vcpkg_status(path):
        return path.parent.parent.parent
    return path.parent


def _is_vcpkg_status(path: Path) -> bool:
    return path.name == "status" and path.parent.name == "vcpkg" and path.parent.parent.name == "vcpkg_installed"


def _kind(path: Path) -> str:
    """The name a file is handled under (vcpkg's generically named status file)."""
    return "vcpkg-status" if _is_vcpkg_status(path) else path.name


def _ecosystem_of(name: str) -> Optional[str]:
    if name in REPORTS:
        return MAVEN
    return lockfile_ecosystem(name)


def _apply_manifest(df: DependencyFile, manifest: Path, names_of: Callable[[str], Dict[str, bool]]) -> None:
    mtext = _read(manifest) if manifest.is_file() else None
    if mtext is None:
        return
    parse = manifest_parser(manifest.name)
    if parse is not None and "" not in df.requires:          # the project's own declared ranges
        try:
            declared = parse(manifest.name, mtext)
        except (LockfileError, ValueError, TypeError, KeyError):
            declared = None
        for pk in (declared.packages.values() if declared is not None else ()):
            df.require("", pk.name, pk.spec or pk.version or "")
    names = {normalize_name(df.ecosystem, n): dev for n, dev in names_of(mtext).items()}
    if names and all(pk.direct is None for pk in df.packages.values()):
        df.mark_direct(names)
    elif names:                             # the lockfile says what is direct; the manifest says dev
        for pk in df.packages.values():
            n = normalize_name(df.ecosystem, pk.name)
            if pk.direct and n in names:
                pk.dev = names[n]


def _central_versions(start: Path, base: Path) -> Dict[str, str]:
    for d in [start, *start.parents]:
        props = d / "Directory.Packages.props"
        if props.is_file():
            text = _read(props)
            return central_package_versions(text) if text else {}
        if d == base:
            break
    return {}


def _topmost(dirs: Iterable[Path]) -> List[Path]:
    ds = sorted(set(dirs), key=lambda p: len(p.parts))
    out: List[Path] = []
    for d in ds:
        if not any(d == t or t in d.parents for t in out):
            out.append(d)
    return out


def read_dependencies(root: Union[str, Path], exclude_dirs: Optional[Iterable[str]] = None,
                      resolve: bool = False) -> DependencyReport:
    """Every lockfile and build-tool report under `root`, plus each manifest that has neither
    for its ecosystem in the same directory (its versions are then ranges unless pinned). With
    `resolve`, Maven, Gradle and pip are run to resolve what has no lockfile (`resolve.py`)."""
    from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS, FrameScanner
    base = Path(root).resolve()
    excluded = frozenset(DEFAULT_EXCLUDED_SCAN_DIRS if exclude_dirs is None else exclude_dirs)
    report = DependencyReport(root=str(base))
    by_dir: Dict[Path, List[Path]] = {}
    gradle_dirs: List[Path] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file() or FrameScanner._is_excluded_dir_member(path, base, excluded):
            continue
        name = path.name
        if name in _GRADLE_BUILD:
            gradle_dirs.append(path.parent)
        if _kind(path) in LOCKFILES or name in REPORTS or manifest_parser(name) is not None:
            if name == "project.assets.json" and path.parent.name != "obj":
                continue
            by_dir.setdefault(_home(path), []).append(path)

    def rel(p: Path) -> str:
        return p.relative_to(base).as_posix()

    locked_in: Dict[Path, Set[Optional[str]]] = {
        d: {_ecosystem_of(_kind(p)) for p in ps if _kind(p) in LOCKFILES or p.name in REPORTS}
        for d, ps in by_dir.items()}

    resolved: Dict[Path, DependencyFile] = {}       # manifest path -> its resolved graph
    covered: Set[Path] = set()                      # manifests a resolved graph stands for
    # a Maven / Gradle report (of a multi-module build) covers the build files of its modules
    report_dirs = [d for d, ps in by_dir.items() if any(p.name in REPORTS for p in ps)]
    covered.update(p for d, ps in by_dir.items() for p in ps if p.name in ("pom.xml", "build.gradle", "build.gradle.kts")
                   and any(r == d or r in d.parents for r in report_dirs))
    if resolve:
        from frame.sca import resolve as R
        poms = [d for d, ps in by_dir.items() if any(p.name == "pom.xml" for p in ps)
                and MAVEN not in locked_in.get(d, set())]
        for d in _topmost(poms):
            df, warn = R.resolve_maven(d, rel(d / "pom.xml"))
            if warn:
                report.warnings.append(warn)
            if df is not None:
                resolved[d / "pom.xml"] = df
                covered.update(p for dd, ps in by_dir.items() if dd == d or d in dd.parents
                               for p in ps if p.name == "pom.xml")
        for d in _topmost(g for g in gradle_dirs if MAVEN not in locked_in.get(g, set())):
            build = next((d / n for n in _GRADLE_BUILD if (d / n).is_file()), d / "build.gradle")
            df, warn = R.resolve_gradle(d, rel(build))
            if warn:
                report.warnings.append(warn)
            if df is not None:
                report.files.append(df)
                covered.update(p for dd, ps in by_dir.items() if dd == d or d in dd.parents
                               for p in ps if p.name in ("build.gradle", "build.gradle.kts"))
        for d, ps in by_dir.items():
            if PYPI in locked_in.get(d, set()):
                continue
            for p in ps:
                if manifest_parser(p.name) is parse_requirements:
                    df, warn = R.resolve_python(d, rel(p), requirements=p)
                elif p.name == "pyproject.toml":
                    text = _read(p) or ""
                    specs = _pyproject_specs(text)
                    df, warn = R.resolve_python(d, rel(p), specs=specs) if specs else (None, None)
                else:
                    continue
                if warn:
                    report.warnings.append(warn)
                if df is not None:
                    resolved[p] = df

    for d, paths in by_dir.items():
        locked = locked_in.get(d, set())
        has_lock = {p.name for p in paths}
        for p in paths:
            if p in covered and p not in resolved:
                continue
            if p in resolved:
                report.files.append(resolved[p])
                continue
            text = _read(p)
            if text is None:
                continue
            try:
                df = _read_one(p, text, d, base, rel, locked, has_lock)
            except (LockfileError, KeyError, TypeError, ValueError) as e:
                report.warnings.append(f"{rel(p)}: could not be read ({e})")
                continue
            if df is not None:
                report.files.append(df)
    report.files.sort(key=lambda f: f.path)
    return report


def _pyproject_specs(text: str) -> List[str]:
    try:
        from frame.sca.lockfiles import tomllib
        data = tomllib.loads(text)
    except Exception:
        return []
    project = data.get("project") or {}
    own = normalize_name(PYPI, str(project.get("name", "")))
    specs = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():   # extras users install
        specs += list(group or [])
    out: List[str] = []
    for s in specs:
        if not isinstance(s, str):
            continue
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", s)
        if m and normalize_name(PYPI, m.group(1)) == own:
            continue                     # `proj[extra]` names the project itself, not a PyPI package
        if s not in out:
            out.append(s)
    return out


def _read_one(p: Path, text: str, d: Path, base: Path, rel: Callable[[Path], str],
              locked: Set[Optional[str]], names_here: Set[str]) -> Optional[DependencyFile]:
    if p.name in REPORTS:
        return REPORTS[p.name](rel(p), text)
    if _kind(p) in LOCKFILES:
        if p.name == "project.assets.json" and "packages.lock.json" in names_here:
            return None                                 # the committed lockfile wins over restore output
        parse, beside = LOCKFILES[_kind(p)]
        df = parse(rel(p), text)
        if beside is not None:
            _apply_manifest(df, d / beside[0], beside[1])
        if _kind(p) not in DEV_FLAGGED:
            _propagate_dev(df)                          # dev only = no production dependency reaches it
        return df
    if manifest_ecosystem(p.name) in locked:
        return None
    parse = manifest_parser(p.name)
    if parse is parse_requirements:
        df = parse_requirements(rel(p), text, lambda r: _read(base / r))
    elif parse is parse_csproj:
        df = parse_csproj(rel(p), text, _central_versions(d, base))
    elif p.name == ".gitmodules":
        df = parse(rel(p), text, base)
    elif p.name in ("build.gradle", "build.gradle.kts"):
        from frame.sca.gradle import find_catalog, gradle_properties
        catalog = find_catalog(d, base)
        df = parse(rel(p), text, gradle_properties(d, base), _read(catalog) if catalog else None)
    else:
        df = parse(rel(p), text)
    return df if df.packages else None


def format_text(report: DependencyReport) -> str:
    lines = [f"Dependencies under {report.root}"]
    if not report.files:
        lines.append("  no manifests or lockfiles found")
    for f in report.files:
        pkgs = list(f.packages.values())
        direct = sum(1 for p in pkgs if p.direct)
        unknown = all(p.direct is None for p in pkgs)
        ranged = sum(1 for p in pkgs if not p.version)
        detail = "direct unknown" if unknown else f"{direct} direct"
        if ranged:
            detail += f", {ranged} without an exact version"
        lines.append(f"  {f.path}  ({f.ecosystem} {f.kind}): {len(pkgs)} packages, {detail}")
    for eco, s in report.summary().items():
        lines.append(f"{eco}: {s['packages']} distinct packages ({s['direct']} direct, {s['dev']} dev only)")
    for w in report.warnings:
        lines.append(f"warning: {w}")
    return "\n".join(lines)


__all__: List[str] = ["DependencyReport", "read_dependencies", "format_text", "REPORTS"]


def _pull_hint(missing: Sequence[str]) -> str:
    from frame.sca.advisories import pull_hint
    return pull_hint(missing)


def format_vulns(findings: List[dict], missing: Sequence[str] = (), undecided: int = 0) -> str:
    """`missing`: ecosystems with no advisories cached; `undecided`: advisories matching could
    not decide (an untagged commit, see the warnings). Neither is ever called "no known
    vulnerabilities"."""
    gap = (f"NOT CHECKED: no advisories cached for {', '.join(missing)} "
           f"(run `{_pull_hint(missing)}`)") if missing else ""
    if undecided:
        gap = "\n".join(x for x in (gap, f"NOT DECIDED: {undecided} advisory(ies) (see the warnings above)") if x)
    if not findings:
        return gap or "No known vulnerabilities in the resolved versions."
    lines = [f"{len(findings)} known vulnerabilit{'y' if len(findings) == 1 else 'ies'}:"]
    for f in findings:
        sev = (f["severity"] or "unknown").upper()
        fix = (f"fixed in {f['fixed'][0]}" if f["fixed"] else
               ("fixed upstream after this commit (see the advisory)" if f.get("commit") else "fixed upstream after this tag (see the advisory)") if f.get("repo") else "no fixed version")
        kind = ("direct" if f["direct"] else "transitive" if f["direct"] is False else
                "os package" if f["ecosystem"].split(":", 1)[0] in DISTRO_FAMILIES else "dependency")
        reach = f.get("reachability") or {}
        level = f", {reach['level']}" if reach.get("level") in ("imported", "called") else ""
        lines.append(f"  {sev:8} {f['package']}@{f['version']} ({kind}{', dev' if f['dev'] else ''}{level}) "
                     f"{f['id']}: {' '.join(f['summary'].split())[:80]}; {fix}  [{f['path']}]")
        if len(f["via"]) > 1:
            lines.append(f"           via {' -> '.join(f['via'])}")
        for c in reach.get("calls", [])[:3]:
            lines.append(f"           contains {c['function']} (linked into the binary)" if c.get("in_binary")
                         else f"           calls {c['function']} at {c['location']}")
        if reach.get("changed_classes") and not reach.get("calls"):
            changed = ", ".join(reach["changed_classes"][:2])
            where = (f"imported in {', '.join(reach['imported_in'][:2])}" if reach.get("imported_in")
                     else "its package is not imported here")
            lines.append(f"           the fix changed {changed} ({where})")
        if f.get("mitigations"):
            from frame.sca.mitigations import format_lines
            lines.extend(f"           {m}" for m in format_lines(f))
    if gap:
        lines.append(gap)
    return "\n".join(lines)
