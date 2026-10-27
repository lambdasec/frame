"""Realistic Java / C# flows Frame does not follow yet, pinned so they cannot go unnoticed.

Each gap is a vulnerable project (with `frame-expect` markers) from `projects_java_more.KNOWN_GAPS` /
`projects_csharp_more.KNOWN_GAPS`. The test is a strict xfail: the day the analysis learns the idiom it
XPASSes and fails the run until the project is moved into that module's CASES (with a safe twin).
"""

import importlib

import pytest

from e2e_helpers import expectations, scan, write_tree

GAPS = {}
for _mod_name in ("projects_java_more", "projects_csharp_more"):
    try:
        _mod = importlib.import_module(_mod_name)
    except ModuleNotFoundError:          # module not written yet
        continue
    for _name, _files in getattr(_mod, "KNOWN_GAPS", {}).items():
        GAPS[f"{_mod_name[len('projects_'):]}/{_name}"] = _files


@pytest.mark.parametrize("name", sorted(GAPS))
@pytest.mark.xfail(strict=True, reason="known limitation (see KNOWN_GAPS in the projects module)")
def test_gap(name, tmp_path):
    root = write_tree(tmp_path, GAPS[name])
    expected = expectations(root)
    assert expected, f"{name}: no frame-expect marker"
    got = scan(root)
    missed = [(p, n) for (p, n), cwes in expected.items() if not cwes <= got.at(p, n)]
    assert not missed, f"missed {missed}"
