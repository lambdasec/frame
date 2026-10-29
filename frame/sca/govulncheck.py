"""Go reachability from `govulncheck -json` (`frame deps --govulncheck FILE`).

govulncheck decides reachability on the compiler's call graph, which is better evidence than any
re-derivation, so Frame imports its answer for the advisories it matched in a `go.mod`. Each of
govulncheck's findings for an advisory stops at a depth: a `function` the program calls, a
`package` it imports, or only a `module` it requires. The deepest one is the advisory's level
(`called`, `imported`, `installed`); a called one keeps its trace's ends, the vulnerable function
and the call in the program. Findings in the standard library depend on the Go toolchain that ran
govulncheck, which `go.mod` does not pin, so they are counted in a note, not matched.

The report is govulncheck's JSON stream (`govulncheck -json ./... > govulncheck.json`, protocol
v1): JSON objects one after another (`config`, `progress`, `osv`, `finding`, `SBOM`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

_RANK = {"installed": 0, "imported": 1, "called": 2}


class GovulncheckError(ValueError):
    pass


@dataclass
class Report:
    path: str
    go_version: str = ""
    scanner: str = ""
    by_advisory: Dict[str, dict] = field(default_factory=dict)    # OSV id -> {"level", "calls", "packages"}
    stdlib: Dict[str, str] = field(default_factory=dict)          # OSV id -> level, for the standard library


def _objects(text: str, origin: str) -> Iterator[dict]:
    dec, i = json.JSONDecoder(), 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError as e:
            raise GovulncheckError(f"{origin}: not govulncheck -json output ({e})") from e
        if isinstance(obj, dict):
            yield obj


def _frame_name(frame: dict) -> str:
    recv = frame.get("receiver", "")
    fn = frame.get("function", "")
    pkg = frame.get("package", "")
    return f"{pkg}.{('(' + recv + ').') if recv else ''}{fn}" if fn else pkg


def read(path: Path) -> Report:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise GovulncheckError(f"{p}: {e}") from e
    rep = Report(str(p))
    seen_config = False
    for obj in _objects(text, str(p)):
        if "config" in obj:
            cfg = obj["config"] or {}
            seen_config = True
            rep.go_version = cfg.get("go_version") or ""
            rep.scanner = f"{cfg.get('scanner_name', '')} {cfg.get('scanner_version', '')}".strip()
            if cfg.get("scan_mode") not in (None, "source"):
                raise GovulncheckError(f"{p}: a {cfg.get('scan_mode')}-mode report; Frame reads source-mode "
                                       "reports for go.mod (binaries are read with --image / --rootfs)")
        finding = obj.get("finding")
        if not isinstance(finding, dict) or not finding.get("osv") or not finding.get("trace"):
            continue
        top = finding["trace"][0]
        level = "called" if top.get("function") else "imported" if top.get("package") else "installed"
        if top.get("module") == "stdlib":
            if _RANK[level] >= _RANK.get(rep.stdlib.get(finding["osv"], "installed"), 0):
                rep.stdlib[finding["osv"]] = level
            continue
        entry = rep.by_advisory.setdefault(finding["osv"], {"level": "installed", "calls": [], "packages": []})
        if _RANK[level] > _RANK[entry["level"]]:
            entry["level"] = level
        if level == "called":
            caller = finding["trace"][-1]
            pos = caller.get("position") or {}
            entry["calls"].append({"function": _frame_name(top),
                                   "location": f"{pos.get('filename', '?')}:{pos.get('line', '?')}",
                                   "in": _frame_name(caller), "source": "govulncheck"})
        if top.get("package") and top["package"] not in entry["packages"]:
            entry["packages"].append(top["package"])
    if not seen_config:
        raise GovulncheckError(f"{p}: no govulncheck config object (run govulncheck -json)")
    return rep


def apply(findings: List[dict], reports: List[Report]) -> List[str]:
    """Replace the reachability of each Go finding govulncheck decided (in place), by advisory id
    or alias. Returns notes for the user."""
    notes: List[str] = []
    merged: Dict[str, dict] = {}
    for rep in reports:
        for osv, e in rep.by_advisory.items():
            cur = merged.get(osv)
            if cur is None or _RANK[e["level"]] > _RANK[cur["level"]]:
                merged[osv] = {**e, "report": rep.path}
    matched = set()
    for f in findings:
        if f.get("ecosystem") != "Go":
            continue
        hit = next((merged[i] for i in [f["id"], *f.get("aliases", [])] if i in merged), None)
        if hit is None:
            continue
        matched.add(f["id"])
        f["reachability"] = {"level": hit["level"], "imported_in": hit["packages"][:20], "calls": hit["calls"][:50],
                             "analysed": True, "evidence": f"govulncheck ({hit['report']})"}
    for rep in reports:
        if rep.stdlib:
            called = sum(1 for v in rep.stdlib.values() if v == "called")
            notes.append(f"{rep.path}: govulncheck also reports {len(rep.stdlib)} advisory(ies) in the Go standard "
                         f"library of {rep.go_version or 'its toolchain'} ({called} called): they depend on the Go "
                         "that builds the program, which go.mod does not pin")
    return notes


__all__ = ["GovulncheckError", "Report", "read", "apply"]
