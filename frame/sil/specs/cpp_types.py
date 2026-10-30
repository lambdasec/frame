"""The C/C++ type model (`data/cpp-types.toml`): scalar typedefs, content accessors, view wrappers.
Loaded strictly."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, NamedTuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "cpp-types.toml"
_KEYS = ("scalar_typedefs", "content_accessors", "view_wrappers")


class CppTypes(NamedTuple):
    scalar_typedefs: FrozenSet[str]
    content_accessors: FrozenSet[str]
    view_wrappers: FrozenSet[str]

    def is_scalar_typedef(self, type_text: str) -> bool:
        return type_text.rsplit("::", 1)[-1] in self.scalar_typedefs


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> CppTypes:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_KEYS) or not all(isinstance(data[k], list) and data[k]
                                          and all(isinstance(n, str) and n for n in data[k]) for k in _KEYS):
        raise ValueError(f"{Path(path).name}: needs exactly {list(_KEYS)}, each a non-empty list of names")
    return CppTypes(*(frozenset(data[k]) for k in _KEYS))


__all__ = ["CppTypes", "PATH", "load"]
