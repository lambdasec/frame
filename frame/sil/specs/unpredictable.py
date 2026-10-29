"""Arguments that must be unpredictable (`data/unpredictable.toml`): where a `weak_random` value is
CWE-338. Loaded strictly: an unknown field or language is an error naming the entry."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "data" / "unpredictable.toml"
_KEYS = {"language", "call", "names", "args", "kwargs", "description"}
_LANGUAGES = {"java", "python", "javascript", "typescript", "csharp"}
_FAMILY = {"typescript": "javascript"}

Want = Tuple[FrozenSet[int], FrozenSet[str]]


@lru_cache(maxsize=1)
def table() -> Dict[str, Tuple[Dict[str, Want], List[Tuple[Tuple[str, ...], Want]]]]:
    """language -> ({canonical id: want}, [(trailing name parts, want)])."""
    data = tomllib.loads(PATH.read_text(encoding="utf-8"))
    out: Dict[str, Tuple[Dict[str, Want], List[Tuple[Tuple[str, ...], Want]]]] = {}
    for i, e in enumerate(data.get("call", [])):
        where = f"{PATH.name}: call {i + 1}"
        if set(e) - _KEYS or e.get("language") not in _LANGUAGES or not (e.get("call") or e.get("names")) \
                or not (e.get("args") or e.get("kwargs")) or not e.get("description"):
            raise ValueError(f"{where}: needs language, call or names, args or kwargs, description; "
                             f"unknown keys {sorted(set(e) - _KEYS)}")
        want: Want = (frozenset(int(a) for a in e.get("args", [])), frozenset(e.get("kwargs", [])))
        by_id, by_name = out.setdefault(e["language"], ({}, []))
        for c in e.get("call", []):
            by_id[c] = want
        for n in e.get("names", []):
            by_name.append((tuple(n.split(".")), want))
    return out


def arguments_for(language: str, canonical: Optional[str], name: str) -> Optional[Want]:
    by_id, by_name = table().get(_FAMILY.get(language, language), ({}, []))
    if canonical and canonical in by_id:
        return by_id[canonical]
    parts = tuple(name.split("."))
    for tail, want in by_name:
        if parts[-len(tail):] == tail:
            return want
    return None
