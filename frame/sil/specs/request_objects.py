"""Which parts of a web request the client chose and which the server set
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
_KEYS = ("client_properties", "server_state", "js_request_names", "js_handler_names", "js_framework_modules",
         "js_handler_decorators", "js_request_types")


class RequestObjects(NamedTuple):
    client_properties: FrozenSet[str]       # JS: destructured from a handler's request parameter
    server_state: FrozenSet[str]            # Python: request.<attr> the server set
    js_request_names: tuple = ()            # JS: conventional names of a handler's request object
    js_handler_names: FrozenSet[str] = frozenset()   # JS: conventional names of its other parameters
    js_framework_modules: FrozenSet[str] = frozenset()   # JS: imports that show a web framework
    js_handler_decorators: tuple = ()       # JS: decorators that show a handler (NestJS)
    js_request_types: tuple = ()            # JS: parameter types that show a request


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> RequestObjects:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_KEYS) or not all(isinstance(data[k], list) and data[k]
                                          and all(isinstance(n, str) and n for n in data[k]) for k in _KEYS):
        raise ValueError(f"{Path(path).name}: needs exactly {list(_KEYS)}, each a non-empty list of names")
    both = set(data["client_properties"]) & set(data["server_state"])
    if both:
        raise ValueError(f"{Path(path).name}: {sorted(both)} cannot be both client data and server state")
    return RequestObjects(frozenset(data["client_properties"]), frozenset(data["server_state"]),
                          tuple(data["js_request_names"]), frozenset(data["js_handler_names"]),
                          frozenset(data["js_framework_modules"]), tuple(data["js_handler_decorators"]),
                          tuple(data["js_request_types"]))


__all__ = ["PATH", "RequestObjects", "load"]
