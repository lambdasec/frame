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
from typing import Any, List, Optional, Pattern, Tuple
from urllib.parse import urlsplit

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "specs" / "data" / "secret-formats.toml"
_KEYS = {"id", "provider", "pattern", "within", "description", "reference", "ignore", "verify"}
_VERIFY_KEYS = {"method", "url", "headers", "valid", "invalid", "valid_json", "invalid_json", "reference"}


@dataclass(frozen=True)
class Verify:
    """A read-only request to the provider's own API that says whether a credential works."""
    method: str
    url: str                                   # fixed: the token never goes anywhere else
    headers: Tuple[Tuple[str, str], ...]       # `{token}` is replaced in these only
    valid: Tuple[int, ...]
    invalid: Tuple[int, ...]
    valid_json: Tuple[Tuple[str, Any], ...] = ()
    invalid_json: Tuple[Tuple[str, Any], ...] = ()
    reference: str = ""

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""


@dataclass(frozen=True)
class SecretFormat:
    id: str
    provider: str
    regex: Pattern
    description: str
    reference: str
    ignore: Tuple[str, ...] = field(default=())
    verify: Optional[Verify] = None


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
                                tuple(f.get("ignore", [])), _verify(where, f.get("verify"))))
    return out


def _verify(where: str, v: Any) -> Optional[Verify]:
    if v is None:
        return None
    where = f"{where}: verify"
    if not isinstance(v, dict) or set(v) - _VERIFY_KEYS:
        raise SecretFormatError(f"{where}: unknown keys {sorted(set(v) - _VERIFY_KEYS) if isinstance(v, dict) else v}")
    url, method, headers = v.get("url"), v.get("method"), v.get("headers")
    # the token goes to the provider's fixed https endpoint and nowhere else
    if not isinstance(url, str) or not url.startswith("https://") or "{" in url or not urlsplit(url).hostname:
        raise SecretFormatError(f"{where}: `url` must be a fixed https URL (no placeholder)")
    if method not in ("GET", "POST"):
        raise SecretFormatError(f"{where}: `method` must be GET or POST")
    if not isinstance(headers, dict) or not any("{token}" in str(x) for x in headers.values()):
        raise SecretFormatError(f"{where}: `headers` must carry {{token}}")
    codes = {}
    for k in ("valid", "invalid"):
        codes[k] = v.get(k, [])
        if not isinstance(codes[k], list) or not all(isinstance(c, int) for c in codes[k]):
            raise SecretFormatError(f"{where}: `{k}` is a list of status codes")
    for k in ("valid_json", "invalid_json"):
        if not isinstance(v.get(k, {}), dict):
            raise SecretFormatError(f"{where}: `{k}` is a table of top-level fields")
    if not codes["valid"] or not (codes["invalid"] or v.get("invalid_json")):
        raise SecretFormatError(f"{where}: needs `valid` and a way to say invalid")
    if not isinstance(v.get("reference"), str) or not v["reference"].startswith("https://"):
        raise SecretFormatError(f"{where}: `reference` (the provider's documentation) is required")
    return Verify(method, url, tuple((str(a), str(b)) for a, b in headers.items()), tuple(codes["valid"]),
                  tuple(codes["invalid"]), tuple(v.get("valid_json", {}).items()),
                  tuple(v.get("invalid_json", {}).items()), v["reference"])


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
