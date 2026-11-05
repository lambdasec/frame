#!/usr/bin/env python3
"""Decide whether a Frame finding describes a BAC-Bench advisory's disclosed defect.

BAC-Bench's own `match_criteria` is prose for a human or an LLM to judge. This module is
a sound, deterministic APPROXIMATION of that judgement for automated scoring: a finding
matches a case when it is an access-control finding (CWE family) located in one of the
case's recorded source locations (a sink or root file, within a sink line range when one
is given), or -- with the case's code regions (regions.py) -- in the function holding a
recorded range, a direct caller of it in the same file, or a function it calls that the
repository defines exactly once. It never reads the prose; it is intentionally conservative
about location so a finding elsewhere in the same large application is not credited.

Kept as a pure function with no Frame imports so it can be unit-tested offline without
cloning any application (tests/test_bacbench_match.py).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# The access-control CWE family. BAC-Bench's expected_cwes are drawn from it, and Frame may
# report a sibling (639 vs 862 vs 863) for the same disclosed issue, so a finding is credited
# when it and the case's expected set overlap within this family (or share an exact id).
ACCESS_CONTROL_CWES = {
    "CWE-639", "CWE-862", "CWE-863", "CWE-284", "CWE-285",
    "CWE-200", "CWE-915", "CWE-269", "CWE-306", "CWE-840",
}


def norm_cwe(c: Any) -> str:
    s = str(c or "").upper().strip()
    if s.startswith("CWE-"):
        return s
    return f"CWE-{s}" if s.isdigit() else s


def _same_file(a: str, b: str) -> bool:
    """Same file when the paths are equal or one is a path suffix of the other (a scan may
    report the path rooted differently). Never by basename alone: in a JS/TS monorepo every
    controller is `index.ts`, and a basename match credited an unrelated controller's finding
    to the advisory's sink file (flowise: `controllers/leads/index.ts` scored against
    `controllers/documentstore/index.ts`)."""
    a, b = str(a or "").replace("\\", "/"), str(b or "").replace("\\", "/")
    if not a or not b:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _cwe_ok(finding_cwe: str, expected: List[str]) -> bool:
    fc = norm_cwe(finding_cwe)
    exp = {norm_cwe(c) for c in (expected or [])}
    if fc in exp:
        return True
    # A sibling access-control weakness for the same issue (e.g. Frame 639 vs advisory 862).
    return bool(fc in ACCESS_CONTROL_CWES and (exp & ACCESS_CONTROL_CWES))


def _location_ok(finding: Dict[str, Any], case: Dict[str, Any], window: int) -> bool:
    """The finding is in a file the case records (a sink or root file), and -- when that
    file has sink line ranges -- within one of them (widened by `window`, since a handler-
    level finding sits above the sink). A file with no recorded range matches file-only."""
    ffile = finding.get("file", "")
    fline = finding.get("line")
    try:
        fline = int(fline) if fline is not None else None
    except (TypeError, ValueError):
        fline = None
    case_files = list(case.get("sink_files") or []) + list(case.get("root_files") or [])
    if not any(_same_file(ffile, cf) for cf in case_files):
        return False
    ranges = [loc for loc in (case.get("sink_locations") or [])
              if _same_file(ffile, loc.get("file", ""))]
    if not ranges or fline is None:
        return True            # file-level match (no line range to check against)
    for loc in ranges:
        lo = int(loc.get("line_start", 0) or 0) - window
        hi = int(loc.get("line_end", loc.get("line_start", 0)) or 0) + window
        if lo <= fline <= hi:
            return True
    return False


def _in_region(finding: Dict[str, Any], regions: Optional[List[Dict[str, Any]]]) -> bool:
    """The finding sits in the own code (not a nested function) of one of the case's code
    regions on this checkout (regions.py: the function holding a recorded range, its direct
    callers in the same file, the uniquely-defined functions it calls)."""
    try:
        line = int(finding.get("line"))
    except (TypeError, ValueError):
        return False
    for r in regions or []:
        if _same_file(finding.get("file", ""), r.get("file", "")) and \
                int(r["start"]) <= line <= int(r["end"]) and \
                not any(int(a) <= line <= int(b) for a, b in r.get("holes") or []):
            return True
    return False


def regions_holding(findings: List[Dict[str, Any]], case: Dict[str, Any],
                    regions: Optional[List[Dict[str, Any]]]) -> set:
    """(file, function name) of the regions a matching finding sits in: where the defect was
    actually found on this checkout."""
    out = set()
    for f in findings or []:
        if not _cwe_ok(f.get("cwe", ""), case.get("expected_cwes") or []):
            continue
        for r in regions or []:
            if r.get("name") and _in_region(f, [r]):
                out.add((r.get("file", ""), r.get("name")))
    return out


def finding_matches_case(finding: Dict[str, Any], case: Dict[str, Any], window: int = 40,
                         regions: Optional[List[Dict[str, Any]]] = None) -> bool:
    """True if `finding` (normalised: file, line, cwe) plausibly describes `case`'s defect:
    an access-control CWE in a recorded source location of the case, or in one of its code
    `regions` for the checkout being scored."""
    return _cwe_ok(finding.get("cwe", ""), case.get("expected_cwes") or []) and \
        (_location_ok(finding, case, window) or _in_region(finding, regions))


def case_detected(findings: List[Dict[str, Any]], case: Dict[str, Any],
                  regions: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """The first finding that matches the case, or None."""
    for f in findings or []:
        if finding_matches_case(f, case, regions=regions):
            return f
    return None
