"""Shells as data (`data/shells.toml`): the programs that parse a command string and the flags that
hand them one. Loaded strictly."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, NamedTuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "shells.toml"
_KEYS = ("programs", "command_flags")


class Shells(NamedTuple):
    programs: FrozenSet[str]                # lower case
    command_flags: FrozenSet[str]


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> Shells:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_KEYS) or not all(isinstance(data[k], list) and data[k]
                                          and all(isinstance(n, str) and n for n in data[k]) for k in _KEYS):
        raise ValueError(f"{Path(path).name}: needs exactly {list(_KEYS)}, each a non-empty list")
    return Shells(*(frozenset(n.lower() for n in data[k]) for k in _KEYS))


def is_shell(program: str) -> bool:
    """`program` (a literal path or name) names a shell: its last path part, either separator."""
    return program.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower() in load().programs


__all__ = ["PATH", "Shells", "is_shell", "load"]
