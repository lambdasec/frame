"""The BAC-Bench scoring matcher (benchmarks/bacbench/match.py).

A Frame finding is credited for a disclosed advisory when it is an access-control finding
(CWE family) in one of the case's recorded source locations. The matcher is a deterministic
approximation of the dataset's prose match_criteria; these tests pin its behaviour offline
(no application clones needed)."""

from benchmarks.bacbench.match import finding_matches_case, case_detected, norm_cwe

CASE = {
    "id": "demo",
    "expected_cwes": ["CWE-862"],
    "sink_files": ["backend/app/access.py"],
    "root_files": ["backend/app/routes.py"],
    "sink_locations": [{"file": "backend/app/access.py", "line_start": 68, "line_end": 72}],
}


def _f(file, line, cwe):
    return {"file": file, "line": line, "cwe": cwe}


def test_exact_cwe_in_sink_range_matches():
    assert finding_matches_case(_f("backend/app/access.py", 70, "CWE-862"), CASE)


def test_sibling_access_control_cwe_matches():
    # Frame may report 639 where the advisory is filed 862 -- same disclosed issue.
    assert finding_matches_case(_f("backend/app/access.py", 70, "CWE-639"), CASE)


def test_non_access_control_cwe_does_not_match():
    # A SQLi finding in the very same file is not this access-control advisory.
    assert not finding_matches_case(_f("backend/app/access.py", 70, "CWE-89"), CASE)


def test_line_far_outside_the_range_does_not_match():
    assert not finding_matches_case(_f("backend/app/access.py", 400, "CWE-862"), CASE)


def test_different_file_does_not_match():
    assert not finding_matches_case(_f("backend/app/other.py", 70, "CWE-862"), CASE)


def test_root_file_without_a_range_matches_file_level():
    # routes.py has no sink_locations range, so a file-level access-control hit counts.
    assert finding_matches_case(_f("backend/app/routes.py", 999, "CWE-285"), CASE)


def test_basename_match_tolerates_path_prefixes():
    # The scan may report a path rooted differently; basename agreement still matches.
    assert finding_matches_case(_f("/tmp/co/backend/app/access.py", 69, "CWE-862"), CASE)


def test_case_detected_returns_first_match():
    findings = [_f("x.py", 1, "CWE-89"), _f("backend/app/access.py", 71, "CWE-863")]
    hit = case_detected(findings, CASE)
    assert hit is not None and hit["cwe"] == "CWE-863"
    assert case_detected([_f("x.py", 1, "CWE-89")], CASE) is None


def test_norm_cwe_forms():
    assert norm_cwe("862") == "CWE-862" and norm_cwe("cwe-862") == "CWE-862"
