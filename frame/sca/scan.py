"""`frame scan --sca`: dependency findings inside a source scan, and the last reachability level.

Before the source is analysed, every function an advisory names as vulnerable in a resolved
dependency becomes a taint sink (`vulnerable_dependency`, CWE-1395) through a pack generated
for this scan, added only where nothing already makes the call a sink (`yaml.load` stays a
deserialization sink). After the scan, each taint finding at a call site of such a function
raises that advisory's reachability to `tainted` with the finding's evidence (data-flow or
solver-verified), and a `vulnerable_dependency` finding is rewritten to name the advisory, the
package version and the fix, at the advisory's severity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from frame.sca.model import MAVEN, NPM, NUGET, PYPI

_LANGUAGES = {PYPI: ("python",), NPM: ("javascript",), MAVEN: ("java",), NUGET: ("csharp",)}
_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class ScaRun:
    findings: List[dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    revision: Optional[str] = None
    missing: List[str] = field(default_factory=list)     # ecosystems not checked: no advisories cached


def prepare(target: Path, excluded: Iterable) -> ScaRun:
    """Read the dependency graph under `target`, match it against the cached advisories and
    annotate imports and calls. Never fetches: with nothing cached it says how to pull."""
    from frame.sca import read_dependencies
    from frame.sca.advisories import AdvisoryDB, ecosystems_of, match, repos_of
    from frame.sca.reachability import Usage, annotate
    target = Path(target).resolve()
    report = read_dependencies(target, exclude_dirs=excluded)
    run = ScaRun(warnings=list(report.warnings))
    ecos = ecosystems_of(report.files)
    if not ecos:
        return run
    db = AdvisoryDB.cached(ecos, repos_of(report.files))
    run.revision = db.revision
    run.missing = list(db.missing)
    if db.missing:
        run.warnings.append(f"no advisories cached for {', '.join(db.missing)}: run `frame kb pull --advisories`")
    run.findings = match(report.files, db)
    if run.findings:
        from frame.sca.advisories import cached_revision_dir
        from frame.sca.mitigations import annotate as annotate_mitigations
        annotate(run.findings, Usage(target, excluded), target)
        annotate_mitigations(run.findings, target, cached_revision_dir(), excluded)
    return run


def sink_packs(run: ScaRun) -> list:
    """One generated pack per language: a sink for every vulnerable function of a matched
    advisory (any argument), describing the advisories it stands for."""
    from frame.sil.packs.schema import Pack, Rule
    by_lang: Dict[str, Dict[str, List[str]]] = {}
    for f in run.findings:
        for fn in f.get("functions", []):
            for lang in _LANGUAGES.get(f["ecosystem"], ()):
                by_lang.setdefault(lang, {}).setdefault(fn["id"], []).append(
                    f"{f['id']} ({f['package']}@{f['version']})")
    packs = []
    for lang, fns in sorted(by_lang.items()):
        rules = [Rule(role="sink", call=[fid], kind="vulnerable_dependency", args=list(range(8)),
                      description=f"{fid}: vulnerable in {', '.join(sorted(set(advs)))}", only_if_not_sink=True)
                 for fid, advs in sorted(fns.items())]
        packs.append(Pack(name="sca-vulnerable-functions", language=lang,
                          description="Vulnerable functions of this project's dependencies (frame scan --sca)",
                          rules=rules, origin="generated"))
    return packs


def _rel(location: str, root: Path) -> str:
    p = Path(location)
    try:                                   # both resolved: /var/... and /private/var/... are one place
        return (p.resolve() if p.is_absolute() or p.exists() else p).relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def link(run: ScaRun, results: list, root: Path) -> None:
    """Join taint findings to the advisories whose vulnerable functions they reach (by call
    site), in both directions."""
    from frame.sil.scanner import Severity
    root = Path(root).resolve()
    by_site: Dict[Tuple[str, int], List[Tuple[dict, dict]]] = {}
    for f in run.findings:
        for call in f.get("reachability", {}).get("calls", []):
            rel, _, line = call["location"].rpartition(":")
            by_site.setdefault((rel, int(line)), []).append((f, call))
    if not by_site:
        return
    for result in results:
        for v in result.vulnerabilities:
            # the same call site AND the finding's sink is that call (not another sink on the line)
            hits = [(f, c) for f, c in by_site.get((_rel(v.location, root), v.line), ())
                    if v.sink_call and v.sink_call in (c["function"], c.get("call"))]
            if not hits:
                continue
            flow = {"location": f"{_rel(v.location, root)}:{v.line}", "type": v.type.value,
                    "evidence": getattr(v, "evidence", "") or "data-flow", "source": v.source_var or ""}
            for f, _ in hits:
                reach = f["reachability"]
                reach["level"] = "tainted"
                if flow not in reach.setdefault("flows", []):      # one per site, however many paths reach it
                    reach["flows"].append(flow)
                if _evidence_rank(flow["evidence"]) > _evidence_rank(f.get("evidence", "matched")):
                    f["evidence"] = flow["evidence"]
            if v.type.value == "vulnerable_dependency":
                advs = sorted({f["id"] for f, _ in hits})
                worst = max((f for f, _ in hits), key=lambda f: _RANK.get(f["severity"] or "", 0))
                fn = hits[0][1]["function"]
                fix = worst["fixed"][0] if worst["fixed"] else None
                v.description = (f"Attacker data reaches {fn}, vulnerable in {worst['package']}@{worst['version']} "
                                 f"({', '.join(advs)})" + (f"; fixed in {fix}" if fix else ""))
                if worst["severity"]:
                    v.severity = Severity(worst["severity"])


_EVIDENCE = ("matched", "llm-detected", "llm-verified", "data-flow", "solver-verified", "exploit-confirmed")


def _evidence_rank(e: str) -> int:
    return _EVIDENCE.index(e) if e in _EVIDENCE else 0


def worst_severity(run: ScaRun) -> int:
    return max((_RANK.get(f["severity"] or "", 0) for f in run.findings), default=0)


def format_text(run: ScaRun) -> str:
    from frame.sca.discover import format_vulns
    head = "\nDependencies" + (f" (advisories {run.revision})" if run.revision else "") + ":\n"
    body = format_vulns(run.findings, run.missing)
    tainted = [f for f in run.findings if f.get("reachability", {}).get("level") == "tainted"]
    for f in tainted:
        for flow in f["reachability"].get("flows", [])[:3]:
            body += f"\n  tainted: {f['id']} reached by attacker data at {flow['location']} ({flow['evidence']})"
    warn = "".join(f"\nwarning: {w}" for w in run.warnings)
    return head + body + warn + "\n"


def sarif_results(run: ScaRun) -> List[dict]:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    out = []
    for f in run.findings:
        reach = f.get("reachability", {})
        out.append({
            "ruleId": f"dependency/{f['id']}",
            "level": level.get(f["severity"] or "", "warning"),
            "message": {"text": f"{f['package']}@{f['version']}: {f['summary'] or f['id']}"
                                + (f" (fixed in {f['fixed'][0]})" if f["fixed"] else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}}}],
            "properties": {"category": "dependency", "evidence": f.get("evidence", "matched"),
                           "reachability": reach.get("level", "installed"), "aliases": f["aliases"],
                           "purl": f["purl"], "security-severity": str(f["score"]) if f["score"] else None},
        })
    return out
