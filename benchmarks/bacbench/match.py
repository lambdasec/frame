#!/usr/bin/env python3
"""Decide whether a Frame finding describes a BAC-Bench advisory's disclosed defect.

BAC-Bench's own `match_criteria` is prose for a human or an LLM to judge. This module is
a sound, deterministic APPROXIMATION of that judgement for automated scoring: a finding
matches a case when it is an access-control finding (CWE family) located in one of the
case's recorded source locations (a sink or root file, within a sink line range when one
is given). It never reads the prose; it is intentionally conservative about location so a
finding elsewhere in the same large application is not credited.

Kept as a pure function with no Frame imports so it can be unit-tested offline without
cloning any application (tests/test_bacbench_match.py).
"""

from __future__ import annotations

import os
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
    a, b = str(a or "").replace("\\", "/"), str(b or "").replace("\\", "/")
    if not a or not b:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a) or os.path.basename(a) == os.path.basename(b)


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


def finding_matches_case(finding: Dict[str, Any], case: Dict[str, Any], window: int = 40) -> bool:
    """True if `finding` (normalised: file, line, cwe) plausibly describes `case`'s defect:
    an access-control CWE in a recorded source location of the case."""
    return _cwe_ok(finding.get("cwe", ""), case.get("expected_cwes") or []) and \
        _location_ok(finding, case, window)


def case_detected(findings: List[Dict[str, Any]], case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The first finding that matches the case, or None."""
    for f in findings or []:
        if finding_matches_case(f, case):
            return f
    return None
