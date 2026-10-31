"""Conventional receiver names a call on an untyped receiver is also looked up under, per
language (`data/receiver-guesses.toml`). A heuristic, kept as data until value-origin typing
replaces it."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "receiver-guesses.toml"
LANGUAGES = ("python", "java", "javascript", "csharp")


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> Dict[str, Tuple[str, ...]]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) - set(LANGUAGES):
        raise ValueError(f"{Path(path).name}: unknown language(s) {sorted(set(data) - set(LANGUAGES))}")
    for lang, names in data.items():
        if not isinstance(names, list) or not all(isinstance(n, str) and n for n in names) \
                or len(set(names)) != len(names):
            raise ValueError(f"{Path(path).name}: {lang} must be a list of distinct receiver names")
    return {lang: tuple(names) for lang, names in data.items()}


def guesses(language: str) -> Tuple[str, ...]:
    """The receiver names for `language` (TypeScript uses JavaScript's)."""
    lang = (language or "").lower()
    return load().get("javascript" if lang == "typescript" else lang, ())


__all__ = ["LANGUAGES", "PATH", "guesses", "load"]
