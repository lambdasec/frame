"""Weak algorithm names (`data/weak-algorithms.toml`): hashes, ciphers and cipher modes that are
weak wherever an API takes the algorithm by name. Loaded strictly; names are upper-case."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, NamedTuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "weak-algorithms.toml"
_KEYS = ("hashes", "ciphers", "cipher_modes")


class WeakAlgorithms(NamedTuple):
    hashes: FrozenSet[str]
    ciphers: FrozenSet[str]
    cipher_modes: FrozenSet[str]


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> WeakAlgorithms:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_KEYS) or not all(isinstance(data[k], list) and data[k]
                                          and all(isinstance(n, str) and n for n in data[k]) for k in _KEYS):
        raise ValueError(f"{Path(path).name}: needs exactly {list(_KEYS)}, each a non-empty list of names")
    return WeakAlgorithms(*(frozenset(n.upper() for n in data[k]) for k in _KEYS))


__all__ = ["PATH", "WeakAlgorithms", "load"]
