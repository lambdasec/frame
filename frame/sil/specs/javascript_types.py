"""The JavaScript / TypeScript type model (`data/javascript-types.toml`): Node core modules,
in-memory collection libraries, database-handle factories, builtin method result kinds, global
constructors and factories. Loaded strictly."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, NamedTuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "javascript-types.toml"
_SHAPE = {"modules": {"node_core", "in_memory"},
          "methods": {"db_handle_factories", "array_to_array", "string_to_string"},
          "string_only_methods": None, "constructors": None, "factories": None}


class JavaScriptTypes(NamedTuple):
    node_core_modules: FrozenSet[str]
    in_memory_libs: FrozenSet[str]
    db_handle_factories: FrozenSet[str]
    array_to_array: FrozenSet[str]
    string_to_string: FrozenSet[str]
    string_only_methods: Dict[str, str]
    constructors: Dict[str, str]
    factories: Dict[str, str]


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> JavaScriptTypes:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_SHAPE):
        raise ValueError(f"{name}: needs exactly {sorted(_SHAPE)}")
    for table, keys in _SHAPE.items():
        value = data[table]
        if not isinstance(value, dict) or not value:
            raise ValueError(f"{name}: [{table}] must be a non-empty table")
        if keys is None:
            if not all(isinstance(v, str) and v for v in value.values()):
                raise ValueError(f"{name}: [{table}] maps names to kinds")
        elif set(value) != keys or not all(isinstance(v, list) and v and all(isinstance(x, str) and x for x in v)
                                           for v in value.values()):
            raise ValueError(f"{name}: [{table}] needs exactly {sorted(keys)}, each a non-empty list")
    m, f = data["modules"], data["methods"]
    return JavaScriptTypes(
        frozenset(m["node_core"]), frozenset(m["in_memory"]), frozenset(f["db_handle_factories"]),
        frozenset(f["array_to_array"]), frozenset(f["string_to_string"]),
        dict(data["string_only_methods"]), dict(data["constructors"]), dict(data["factories"]))


__all__ = ["PATH", "JavaScriptTypes", "load"]
