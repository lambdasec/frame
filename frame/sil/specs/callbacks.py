"""Library calls whose result is made from what a function passed to them returns
(`data/callbacks.toml`): `re.sub(p, repl, s)`, `s.replace(re, fn)`, `xs.map(fn)`. Loaded strictly:
an unknown key or language, a missing position, or an entry naming neither calls nor methods is an
error naming the entry."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "callbacks.toml"
LANGUAGES = ("python", "javascript")
_KEYS = {"language", "call", "method", "arg", "elements"}


@dataclass(frozen=True)
class Callback:
    language: str
    calls: Tuple[str, ...]
    methods: Tuple[str, ...]
    arg: int
    elements: bool


def _names(where: str, value) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{where}: must be a list of names")
    return tuple(value)


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> Tuple[Callback, ...]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    name = Path(path).name
    if set(data) - {"callback"}:
        raise ValueError(f"{name}: only [[callback]] entries; has {sorted(set(data) - {'callback'})}")
    out = []
    for i, e in enumerate(data.get("callback", [])):
        where = f"{name}: callback {i + 1}"
        if not isinstance(e, dict) or set(e) - _KEYS:
            raise ValueError(f"{where}: unknown keys {sorted(set(e) - _KEYS) if isinstance(e, dict) else e}")
        if e.get("language") not in LANGUAGES:
            raise ValueError(f"{where}: language must be one of {LANGUAGES}")
        arg = e.get("arg")
        if not isinstance(arg, int) or isinstance(arg, bool) or arg < 0:
            raise ValueError(f"{where}: arg must be a position")
        calls, methods = _names(f"{where}.call", e.get("call")), _names(f"{where}.method", e.get("method"))
        if not calls and not methods:
            raise ValueError(f"{where}: needs call or method")
        if methods and e["language"] != "javascript":
            raise ValueError(f"{where}: methods by name are for JavaScript (a receiver of any type)")
        out.append(Callback(e["language"], calls, methods, arg, bool(e.get("elements", False))))
    return tuple(out)


def for_call(language: str, names: Tuple[Optional[str], ...]) -> Optional[Callback]:
    """The entry for a call written or resolved as one of `names` (`a.b.c`), in `language`
    (TypeScript uses JavaScript's)."""
    lang = (language or "").lower()
    lang = "javascript" if lang == "typescript" else lang
    for cb in load():
        if cb.language != lang:
            continue
        for n in names:
            if not n:
                continue
            if n in cb.calls or ("." in n and n.rsplit(".", 1)[-1] in cb.methods):
                return cb
    return None


__all__ = ["Callback", "PATH", "for_call", "load"]
