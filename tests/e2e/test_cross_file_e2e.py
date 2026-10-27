"""Cross-file taint, scanned the way a user scans a project.

Every case writes a small multi-file project to a temp directory, runs
`frame scan <dir>` through the real CLI, and checks the JSON: the marked line in the
helper/repository file is reported with the marked CWE, and the safe twin (same
layout, the flaw fixed) reports none of those CWEs.
"""

import importlib
import pathlib

import pytest

from e2e_helpers import expectations, scan, write_tree

ALL_CASES = {}
for _path in sorted(pathlib.Path(__file__).parent.glob("projects_*.py")):
    _mod = importlib.import_module(_path.stem)       # every projects_*.py module contributes its CASES
    for _name, _case in _mod.CASES.items():
        ALL_CASES[f"{_path.stem[len('projects_'):]}/{_name}"] = _case      # one id space per module


@pytest.mark.parametrize("name", sorted(ALL_CASES))
def test_project(name, tmp_path):
    vulnerable, safe = ALL_CASES[name]
    vdir = write_tree(tmp_path / "vulnerable", vulnerable)
    sdir = write_tree(tmp_path / "safe", safe)
    expected = expectations(vdir)
    assert expected, f"{name}: no frame-expect marker"
    wanted = set().union(*expected.values())

    got = scan(vdir)
    assert got.exit_code == 0, got.stderr
    missed = [(p, n, sorted(c)) for (p, n), c in sorted(expected.items()) if not c <= got.at(p, n)]
    reported = sorted((f["path"], f["line"], f["cwe_id"]) for f in got.findings)
    assert not missed, f"{name}: missed {missed}; reported {reported}"
    unlabelled = [(f["path"], f["line"], f["cwe_id"]) for f in got.findings
                  if f["cwe_id"] in wanted and f["cwe_id"] not in expected.get((f["path"], f["line"]), ())]
    assert not unlabelled, f"{name}: unlabelled findings {unlabelled}"

    twin = scan(sdir)
    assert twin.exit_code == 0, twin.stderr
    leaked = [(f["path"], f["line"], f["cwe_id"]) for f in twin.findings if f["cwe_id"] in wanted]
    assert not leaked, f"{name}: the safe twin is flagged: {leaked}"
