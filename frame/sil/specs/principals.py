"""The caller's own identity as data (`data/principals.toml`): credential header names and the
frameworks' authenticated-principal names. Loaded strictly."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import NamedTuple, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "principals.toml"
_KEYS = ("credential_headers", "principal_tokens")


class Principals(NamedTuple):
    credential_headers: Tuple[str, ...]     # lower case
    principal_tokens: Tuple[str, ...]


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> Principals:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_KEYS) or not all(isinstance(data[k], list) and data[k]
                                          and all(isinstance(n, str) and n for n in data[k]) for k in _KEYS):
        raise ValueError(f"{Path(path).name}: needs exactly {list(_KEYS)}, each a non-empty list of names")
    if any(h != h.lower() for h in data["credential_headers"]):
        raise ValueError(f"{Path(path).name}: credential_headers are lower case")
    return Principals(tuple(data["credential_headers"]), tuple(data["principal_tokens"]))


__all__ = ["PATH", "Principals", "load"]
