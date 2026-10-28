"""Provider credential formats as data (`specs/data/secret-formats.toml`): a string literal that
contains one is a hardcoded credential whatever it is assigned to (a token passed straight to a
client constructor, or kept in a variable named `x`). Loaded strictly: an unknown field or a
pattern that does not compile is an error naming the entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Pattern, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "specs" / "data" / "secret-formats.toml"
_KEYS = {"id", "provider", "pattern", "within", "description", "reference", "ignore"}


@dataclass(frozen=True)
class SecretFormat:
    id: str
    provider: str
    regex: Pattern
    description: str
    reference: str
    ignore: Tuple[str, ...] = field(default=())


class SecretFormatError(ValueError):
    pass


def load(path: Path = PATH) -> List[SecretFormat]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    out: List[SecretFormat] = []
    for i, f in enumerate(data.get("format", [])):
        where = f"{path}: format {i + 1} ({f.get('id', '?')})"
        if set(f) - _KEYS:
            raise SecretFormatError(f"{where}: unknown keys {sorted(set(f) - _KEYS)}")
        for k in ("id", "provider", "pattern", "description", "reference"):
            if not isinstance(f.get(k), str) or not f[k]:
                raise SecretFormatError(f"{where}: `{k}` is required")
        try:
            # a token is never part of a longer identifier on either side
            regex = re.compile(rf"(?<![A-Za-z0-9_])(?:{f['pattern']})(?![A-Za-z0-9_])", re.DOTALL)
        except re.error as e:
            raise SecretFormatError(f"{where}: pattern does not compile: {e}") from e
        out.append(SecretFormat(f["id"], f["provider"], regex, f["description"], f["reference"],
                                tuple(f.get("ignore", []))))
    return out


@lru_cache(maxsize=1)
def formats() -> Tuple[SecretFormat, ...]:
    return tuple(load())


def find(value: str) -> Optional[Tuple[SecretFormat, str]]:
    """The first provider format a literal contains, and the matched text; documented example
    values are not credentials."""
    for f in formats():
        m = f.regex.search(value)
        if m and m.group(0) not in f.ignore and not any(x in m.group(0) for x in f.ignore):
            return f, m.group(0)
    return None
