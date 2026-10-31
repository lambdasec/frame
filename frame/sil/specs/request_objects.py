"""Which parts of a Python web request the server set
(`data/request-objects.toml`). Loaded strictly."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import FrozenSet, NamedTuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "request-objects.toml"
_KEYS = ("server_state", "python_request_names")


class RequestObjects(NamedTuple):
    server_state: FrozenSet[str]            # Python: request.<attr> the server set
    python_request_names: FrozenSet[str] = frozenset()   # Python: names server_state applies to


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> RequestObjects:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_KEYS) or not all(isinstance(data[k], list) and data[k]
                                          and all(isinstance(n, str) and n for n in data[k]) for k in _KEYS):
        raise ValueError(f"{Path(path).name}: needs exactly {list(_KEYS)}, each a non-empty list of names")
    return RequestObjects(frozenset(data["server_state"]), frozenset(data["python_request_names"]))


__all__ = ["PATH", "RequestObjects", "load"]
