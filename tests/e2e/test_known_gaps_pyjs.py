"""Realistic Python / JavaScript flows Frame does not follow yet, pinned so they cannot go unnoticed.

Each entry is a normal project case (vulnerable tree + safe twin, same markers and rules as
`test_cross_file_e2e.py`). It is a strict xfail: the day the analysis learns the idiom the test
XPASSes and fails the run until the case is moved into `projects_python_more.py` /
`projects_js_more.py`. The comment above each case names the missing piece.
"""

import re

import pytest

from e2e_helpers import expectations, scan, write_tree

_CHOICE = re.compile(r"<<(.*?)\|\|(.*?)>>", re.S)
KNOWN_GAPS = {}


def case(name, files):
    KNOWN_GAPS[name] = (
        {p: _CHOICE.sub(lambda m: m.group(1), t) for p, t in files.items()},
        {p: _CHOICE.sub(lambda m: m.group(2), t) for p, t in files.items()},
    )




@pytest.mark.xfail(strict=True, reason="known limitation (see the comment above the case)")
@pytest.mark.parametrize("name", sorted(KNOWN_GAPS))
def test_known_gap(name, tmp_path):
    vulnerable, safe = KNOWN_GAPS[name]
    vdir = write_tree(tmp_path / "vulnerable", vulnerable)
    sdir = write_tree(tmp_path / "safe", safe)
    expected = expectations(vdir)
    wanted = set().union(*expected.values())
    got = scan(vdir)
    missed = [(p, n) for (p, n), c in expected.items() if not c <= got.at(p, n)]
    leaked = [f for f in scan(sdir).findings if f["cwe_id"] in wanted]
    assert not missed and not leaked, f"missed {missed}; safe twin flagged {[(f['path'], f['line']) for f in leaked]}"
