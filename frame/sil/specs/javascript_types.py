"""The JavaScript / TypeScript type model (`data/javascript-types.toml`): Node core modules,
in-memory collection libraries, database-handle factories, builtin method result kinds, global
constructors and factories, the callback parameters builtin methods hand a value, and the methods
that store their arguments in the receiver. Loaded strictly."""

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
          "methods": {"array_to_array", "string_to_string"},
          "string_only_methods": None, "constructors": None, "factories": None, "array_index_params": int,
          "callback_values": int, "receiver_writes": int}


class JavaScriptTypes(NamedTuple):
    node_core_modules: FrozenSet[str]
    in_memory_libs: FrozenSet[str]
    array_to_array: FrozenSet[str]
    string_to_string: FrozenSet[str]
    string_only_methods: Dict[str, str]
    constructors: Dict[str, str]
    factories: Dict[str, str]
    array_index_params: Dict[str, int]
    callback_values: Dict[str, int]
    receiver_writes: Dict[str, int]


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
        if keys is int:
            if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in value.values()):
                raise ValueError(f"{name}: [{table}] maps method names to a parameter position")
        elif keys is None:
            if not all(isinstance(v, str) and v for v in value.values()):
                raise ValueError(f"{name}: [{table}] maps names to kinds")
        elif set(value) != keys or not all(isinstance(v, list) and v and all(isinstance(x, str) and x for x in v)
                                           for v in value.values()):
            raise ValueError(f"{name}: [{table}] needs exactly {sorted(keys)}, each a non-empty list")
    m, f = data["modules"], data["methods"]
    return JavaScriptTypes(
        frozenset(m["node_core"]), frozenset(m["in_memory"]),
        frozenset(f["array_to_array"]), frozenset(f["string_to_string"]),
        dict(data["string_only_methods"]), dict(data["constructors"]), dict(data["factories"]),
        dict(data["array_index_params"]), dict(data["callback_values"]), dict(data["receiver_writes"]))


__all__ = ["PATH", "JavaScriptTypes", "load"]
