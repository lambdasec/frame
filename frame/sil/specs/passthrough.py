"""Calls that hand back their input (`data/passthrough.toml`): JavaScript functions that only
re-encode their argument and C# methods that return (a part of) the same text. Loaded strictly."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, NamedTuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "passthrough.toml"
_SHAPE = {"javascript": "calls", "csharp": "methods"}


class Passthrough(NamedTuple):
    javascript_calls: FrozenSet[str]
    csharp_methods: FrozenSet[str]


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> Passthrough:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_SHAPE):
        raise ValueError(f"{name}: needs exactly {sorted(_SHAPE)}")
    for section, key in _SHAPE.items():
        table = data[section]
        if not isinstance(table, dict) or set(table) != {key} or not isinstance(table[key], list) \
                or not table[key] or not all(isinstance(n, str) and n for n in table[key]):
            raise ValueError(f"{name}: [{section}] needs exactly {key}, a non-empty list of names")
    return Passthrough(frozenset(data["javascript"]["calls"]), frozenset(data["csharp"]["methods"]))


__all__ = ["PATH", "Passthrough", "load"]
