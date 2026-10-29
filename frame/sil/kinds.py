"""Sink kinds and finding types as data (`specs/data/kinds.toml`): the finding type each sink kind
reports, the other spellings of a sink kind, and each finding type's CWE and category.

Plain strings, so this module imports neither `SinkKind` nor `VulnType`; `check` compares the
table with both enums where they are defined, and a table that does not cover them exactly fails
every scan (as a broken built-in pack does)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, Optional

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

PATH = Path(__file__).parent / "specs" / "data" / "kinds.toml"
CATEGORIES = ("taint", "memory", "crypto", "secret", "access-control", "hardening",
              "dependency", "iac", "container", "ai")
_SINK_KEYS = {"kind", "vuln", "aliases"}
_VULN_KEYS = {"type", "cwe", "category"}


@dataclass(frozen=True)
class Kinds:
    sink_vuln: Dict[str, Optional[str]]     # sink kind -> finding type (None: a generic taint flow)
    aliases: Dict[str, str]                 # other spelling -> sink kind
    cwe: Dict[str, str]                     # finding type -> CWE id (types without one are absent)
    category: Dict[str, str]                # finding type -> category


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> Kinds:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) - {"sink", "vuln"}:
        raise ValueError(f"{Path(path).name}: unknown tables {sorted(set(data) - {'sink', 'vuln'})}")
    sink_vuln: Dict[str, Optional[str]] = {}
    aliases: Dict[str, str] = {}
    cwe: Dict[str, str] = {}
    category: Dict[str, str] = {}
    for i, v in enumerate(data.get("vuln", [])):
        where = f"{Path(path).name}: vuln {i + 1} ({v.get('type')})"
        if set(v) - _VULN_KEYS or not v.get("type") or v.get("category") not in CATEGORIES:
            raise ValueError(f"{where}: needs type and a category in {CATEGORIES}; unknown keys "
                             f"{sorted(set(v) - _VULN_KEYS)}")
        if v["type"] in category:
            raise ValueError(f"{where}: listed twice")
        if "cwe" in v and not str(v["cwe"]).startswith("CWE-"):
            raise ValueError(f"{where}: cwe must be CWE-<n>")
        category[v["type"]] = v["category"]
        if "cwe" in v:
            cwe[v["type"]] = v["cwe"]
    for i, s in enumerate(data.get("sink", [])):
        where = f"{Path(path).name}: sink {i + 1} ({s.get('kind')})"
        if set(s) - _SINK_KEYS or not s.get("kind"):
            raise ValueError(f"{where}: needs kind; unknown keys {sorted(set(s) - _SINK_KEYS)}")
        if s["kind"] in sink_vuln:
            raise ValueError(f"{where}: listed twice")
        if s.get("vuln") is not None and s["vuln"] not in category:
            raise ValueError(f"{where}: unknown finding type {s['vuln']!r}")
        sink_vuln[s["kind"]] = s.get("vuln")
        for a in s.get("aliases", []):
            if a in aliases:
                raise ValueError(f"{where}: alias {a!r} also names {aliases[a]!r}")
            aliases[a] = s["kind"]
    clash = set(aliases) & set(sink_vuln)
    if clash:
        raise ValueError(f"{Path(path).name}: aliases that are kinds themselves: {sorted(clash)}")
    return Kinds(sink_vuln, aliases, cwe, category)


def check(sink_kinds: Iterable[str], vuln_types: Iterable[str], kinds: Optional[Kinds] = None) -> None:
    """The table covers exactly these sink kinds and finding types."""
    k = kinds or load()
    for what, have, want in (("sink kinds", set(k.sink_vuln), set(sink_kinds)),
                             ("finding types", set(k.category), set(vuln_types))):
        if have != want:
            raise ValueError(f"{PATH.name}: {what} missing {sorted(want - have)}, unknown {sorted(have - want)}")


__all__ = ["CATEGORIES", "Kinds", "PATH", "check", "load"]
