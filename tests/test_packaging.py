"""The built-in framework packs must ship with an installed Frame."""

from pathlib import Path

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
