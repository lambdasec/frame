"""The built-in framework packs must ship with an installed Frame."""

from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:                 # Python < 3.11
    import tomli as tomllib                 # type: ignore[no-redef]

from frame.sil.packs import builtin_packs
from frame.sil.packs.loader import BUILTIN_DIR

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_ships_the_pack_data_files():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    patterns = data["tool"]["setuptools"]["package-data"]["frame"]
    assert any(p.endswith("sil/packs/data/**/*.toml") for p in patterns)


def test_every_pack_file_is_loaded():
    files = sorted(BUILTIN_DIR.rglob("*.toml"))
    assert len(files) >= 70
    assert len(builtin_packs()) == len(files)


def test_pre_commit_hook_installs_the_scan_extra():
    # pre-commit installs the repo without extras, so the hook lists the
    # grammars itself; a missing one would silently skip a language.
    yaml = pytest.importorskip("yaml")
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())
    scan = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]["scan"]
    assert sorted(hooks[0]["additional_dependencies"]) == sorted(scan)


def test_github_action_installs_the_scan_extra():
    yaml = pytest.importorskip("yaml")
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    runs = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
    assert '"${GITHUB_ACTION_PATH}[scan]"' in runs
    assert "frame scan" in runs
