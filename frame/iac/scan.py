"""Checking infrastructure files against the policy packs (`frame iac`, `frame scan --iac`).

Each format's reader turns files into resources (frame/iac/model.py); every policy of the packs
for that format is decided on every resource that has the views it names (frame/iac/engine.py).
A resource the configuration makes violate a policy is a finding (category `iac`), pointing at
the line of the value that decides it. A violation that depends on values the files do not
give is `undecided`: listed apart, never a finding. A policy that `overrides` another replaces
it on a resource where both hold (keeping the higher severity), as the Pod Security admission
controller replaces a Baseline check with its Restricted version.

Findings honour `frame: ignore[<policy id or CWE>]` on their line or the comment line above.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import dockerfile, kubernetes, terraform
from .engine import decide
from .model import ReadResult, Resource, dotted

FORMATS = ("kubernetes", "dockerfile", "terraform")
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_YAML_SUFFIXES = (".yaml", ".yml", ".json")


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    cwe: str
    format: str
    resource: str                    # the resource's address
    resource_type: str
    file: str
    line: int
    field: str                       # the value that decides it (dotted path in the document)
    evidence: str                    # matched / solver-verified
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    also: List[str] = field(default_factory=list)       # policies this finding replaced

    # what `frame.sil.suppressions` matches on
    @property
    def cwe_id(self) -> str:
        return self.cwe

    @property
    def type(self) -> str:
        return self.rule

    @property
    def fingerprint(self) -> str:
        key = "\0".join((self.file, self.rule, self.resource, self.field))
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = {"rule": self.rule, "title": self.title, "severity": self.severity, "cwe_id": self.cwe,
             "category": "iac", "evidence": self.evidence, "format": self.format,
             "resource": self.resource, "resource_type": self.resource_type, "path": self.file,
             "line": self.line, "field": self.field, "references": self.references, "tags": self.tags,
             "fingerprint": self.fingerprint}
        if self.also:
            d["also"] = self.also
        return d


@dataclass
class IacRun:
    root: str
    findings: List[Finding] = field(default_factory=list)
    suppressed: List[Finding] = field(default_factory=list)
    undecided: List[dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    files: Dict[str, List[str]] = field(default_factory=dict)       # format -> files with resources
    resources: int = 0
    packs: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"root": self.root, "packs": self.packs, "files": self.files, "resources": self.resources,
                "findings": [f.to_dict() for f in self.findings],
                "suppressed": [f.to_dict() for f in self.suppressed],
                "undecided": self.undecided, "warnings": self.warnings}


def _candidates(target: Path, excluded) -> List[Tuple[Path, str]]:
    from frame.sil.scanner import FrameScanner
    if target.is_file():
        return [(target, target.name)]
    out = []
    for path in sorted(target.rglob("*")):
        if path.is_file() and (path.suffix.lower() in _YAML_SUFFIXES or path.suffix == ".tf"
                               or dockerfile.is_dockerfile(path)) \
                and not FrameScanner._is_excluded_dir_member(path, target, excluded):
            out.append((path, path.relative_to(target).as_posix()))
    return out


def read(target: Path, excluded) -> Dict[str, ReadResult]:
    """Every format's resources under `target` (a directory or one file)."""
    files = _candidates(target, excluded)
    root = target if target.is_dir() else target.parent
    docker = [(p, r) for p, r in files if dockerfile.is_dockerfile(p)]
    k8s = kubernetes.read([(p, r) for p, r in files if p.suffix.lower() in _YAML_SUFFIXES], root)
    _one_warning_per_chart(k8s)
    tf = terraform.read([(p, r) for p, r in files if p.suffix == ".tf"], root)
    return {"kubernetes": k8s, "dockerfile": dockerfile.read(docker), "terraform": tf}


def _one_warning_per_chart(result: ReadResult) -> None:
    charts: Dict[str, int] = {}
    rest = []
    for w in result.warnings:
        if "a Helm template" in w:
            path = w.split(": ", 1)[0]
            chart = path.rsplit("/templates/", 1)[0] if "/templates/" in path else "."
            charts[chart] = charts.get(chart, 0) + 1
        else:
            rest.append(w)
    rest += [f"{c}: Helm chart with {n} template(s) not checked (render it with `helm template` "
             f"and scan the output)" for c, n in sorted(charts.items())]
    result.warnings = rest


def _applies(policy, resource: Resource, needed: set) -> bool:
    if policy.resources and not any(fnmatchcase(resource.type, g) for g in policy.resources):
        return False
    return needed <= set(resource.views)


def _pointer(resource: Resource, why) -> tuple:
    """The value a finding points at: the deepest of the paths that decided it; between equals
    the first that is not a flag (a rule's CIDR before its ports, a stage's USER rather than its
    `final`), else the last."""
    paths = [p for p in why if not (p and p[0] == "@")]          # another resource's paths
    if not paths:
        return ()
    depth = max(len(p) for p in paths)
    deepest = [p for p in paths if len(p) == depth]
    for p in deepest:
        try:
            value = resource.document
            for step in p:
                value = value[step]
        except (KeyError, IndexError, TypeError):
            continue
        if not isinstance(value, bool):
            return p
    return deepest[-1]


def check(resources: Sequence[Resource], policies: Sequence, run: IacRun) -> List[Finding]:
    from .policy import roots
    needs = {p.id: roots(p.expr) for p in policies}
    found: List[Finding] = []
    for r in resources:
        fired: Dict[str, Finding] = {}
        for p in policies:
            if not _applies(p, r, needs[p.id]):
                continue
            v = decide(p.expr, r.subject())
            if v.outcome == "pass":
                continue
            path = _pointer(r, v.why)
            if v.outcome == "undecided":
                run.undecided.append({"rule": p.id, "resource": r.address, "path": r.file,
                                      "line": r.line_of(path), "depends_on": list(v.unknowns)})
                continue
            fired[p.id] = Finding(rule=p.id, title=p.title, severity=p.severity, cwe=p.cwe, format=r.format,
                                  resource=r.address, resource_type=r.type, file=r.file,
                                  line=r.line_of(path), field=dotted(path), evidence=v.evidence,
                                  references=list(p.references), tags=list(p.tags))
        for p in policies:
            f = fired.get(p.id)
            if f is None:
                continue
            for o in p.overrides:
                old = fired.pop(o, None)
                if old is not None:
                    f.also.append(o)
                    if _SEVERITY_ORDER[old.severity] > _SEVERITY_ORDER[f.severity]:
                        f.severity = old.severity
        found.extend(fired.values())
    return found


def _suppress(findings: List[Finding], root: Path, single: Optional[Path]) -> Tuple[List[Finding], List[Finding]]:
    from frame.sil.suppressions import split_suppressed
    by_file: Dict[str, List[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    kept, dropped = [], []
    for rel, group in by_file.items():
        path = single if single is not None else root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            kept.extend(group)
            continue
        k, d = split_suppressed(group, text)
        kept += k
        dropped += d
    return kept, dropped


def scan(target, packs=None, exclude_dirs: Optional[Iterable] = None) -> IacRun:
    """Check every infrastructure file under `target` against the policies of `packs`
    (a frame.sil.packs.PackSet; default: the built-in and knowledge-base packs)."""
    from frame.sil.packs import PackSet
    from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS
    target = Path(target)
    excluded = DEFAULT_EXCLUDED_SCAN_DIRS if exclude_dirs is None else frozenset(exclude_dirs)
    if packs is None:
        packs = PackSet.build(project_start=target)
    run = IacRun(root=str(target.resolve()))
    found: List[Finding] = []
    for fmt, result in read(target, excluded).items():
        run.warnings += result.warnings
        if result.files:
            run.files[fmt] = sorted(set(result.files))
        run.resources += len(result.resources)
        fmt_packs = packs.for_language(fmt)
        if result.resources:                    # the packs that had something to check
            run.packs += [f"{p.language}/{p.name}" for p in fmt_packs]
        found += check(result.resources, [pol for p in fmt_packs for pol in p.policies], run)
    root = target if target.is_dir() else target.parent
    kept, run.suppressed = _suppress(found, root, target if target.is_file() else None)
    run.findings = sorted(kept, key=lambda f: (f.file, f.line, f.rule))
    return run


def at_least(run: IacRun, min_severity: Optional[str]) -> IacRun:
    """A copy of `run` holding only the findings at or above `min_severity`."""
    import dataclasses
    floor = _SEVERITY_ORDER.get(min_severity or "info", 0)
    return dataclasses.replace(run, findings=[f for f in run.findings if _SEVERITY_ORDER[f.severity] >= floor])


def fails(run: IacRun, fail_on: Optional[str]) -> bool:
    """Does a finding reach `fail_on` (a severity, `any` or `none`)?"""
    if not run.findings or fail_on in (None, "none"):
        return False
    if fail_on == "any":
        return True
    return any(_SEVERITY_ORDER[f.severity] >= _SEVERITY_ORDER[fail_on] for f in run.findings)


def format_text(run: IacRun) -> str:
    lines = []
    for f in run.findings:
        lines.append(f"{f.file}:{f.line}: [{f.severity}] {f.rule} ({f.cwe}) {f.resource}: {f.title}"
                     + (f" [{f.field}]" if f.field else "") + (f" (also {', '.join(f.also)})" if f.also else ""))
    checked = ", ".join(f"{k}: {len(v)} file(s)" for k, v in sorted(run.files.items())) or "no files"
    summary = (("\n" if lines else "") + f"Infrastructure: {run.resources} resource(s) in {checked}; {len(run.findings)} finding(s)"
               + (f", {len(run.suppressed)} suppressed" if run.suppressed else "")
               + (f", {len(run.undecided)} undecided (depend on values the files do not give)"
                  if run.undecided else ""))
    lines.append(summary)
    for u in run.undecided:
        on = ", ".join(u.get("depends_on", [])[:3])
        lines.append(f"undecided: {u['path']}:{u['line']} {u['rule']} {u['resource']}"
                     + (f" (depends on {on})" if on else ""))
    lines += [f"warning: {w}" for w in run.warnings]
    return "\n".join(lines) + "\n"


def sarif_results(run: IacRun) -> List[dict]:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    return [{
        "ruleId": f"iac/{f.rule}",
        "level": level[f.severity],
        "message": {"text": f"{f.resource}: {f.title}" + (f" ({f.field})" if f.field else "")},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                            "region": {"startLine": f.line}}}],
        "partialFingerprints": {"frame/iac": f.fingerprint},
        "properties": {"category": "iac", "evidence": f.evidence, "cwe": f.cwe, "severity": f.severity,
                       "resource": f.resource, "tags": f.tags},
    } for f in run.findings]


def sarif_rules(run: IacRun) -> List[dict]:
    seen: Dict[str, dict] = {}
    for f in run.findings:
        rule = seen.setdefault(f.rule, {"id": f"iac/{f.rule}", "name": f.rule,
                                        "shortDescription": {"text": f.title},
                                        "properties": {"tags": ["security", "iac", f.cwe] + f.tags}})
        if f.references:
            rule["helpUri"] = f.references[0]
    return list(seen.values())


def sarif(run: IacRun) -> dict:
    return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Frame Security Scanner", "rules": sarif_rules(run)}},
                      "results": sarif_results(run)}]}


__all__ = ["FORMATS", "Finding", "IacRun", "at_least", "check", "fails", "format_text", "read", "sarif", "sarif_results",
           "sarif_rules", "scan"]
