"""Realistic C/C++ flows Frame does not follow yet (or reports wrongly), pinned so they cannot go unnoticed.

Each entry is a strict xfail: a MISS asserts the CWE is reported in the file, a FALSE POSITIVE asserts
it is not. The day the analysis learns the idiom the test XPASSes and fails the run until the entry is
moved into the regular matrix (`projects_c.py`).
"""

import pytest

from e2e_helpers import scan, write_tree

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n"

# (id, kind, cwe, source). kind: "miss" -> the CWE must be reported; "fp" -> it must not be.
GAPS = [
    # ---- C has no interprocedural taint: the request value is read in one function, used in another
    # ---- validation idioms that make a value safe for a shell are not recognised
    # ---- buffer overflows

    # ---- heap lifecycle
    # ---- weak randomness is only reported in a file that includes a crypto header
]


@pytest.mark.xfail(strict=True, reason="known limitation (see test_known_gaps_cnative.py)")
@pytest.mark.parametrize("gap", GAPS, ids=[g[0] for g in GAPS])
def test_known_gap(gap, tmp_path):
    _name, kind, cwe, filename, source = gap
    write_tree(tmp_path, {filename: source})
    got = scan(tmp_path)
    reported = {f["cwe_id"] for f in got.findings}
    if kind == "miss":
        assert cwe in reported, f"{cwe} not reported; got {sorted(reported)}"
    else:
        assert cwe not in reported, f"false {cwe}: {[(f['line'], f['cwe_id']) for f in got.findings]}"
