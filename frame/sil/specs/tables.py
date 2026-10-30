"""Library specifications as data: `data/<table>.toml` holds one `[[spec]]` entry per call
name (in lookup order) with the `ProcSpec` fields that differ from their defaults.

The tables are Frame's built-in knowledge of each language's libraries (sources, sinks,
sanitizers, propagators, allocators, ...). They are data, so they can be reviewed as data and
delivered between releases like framework packs.
"""

from __future__ import annotations

import json
from dataclasses import fields
from functools import lru_cache
from pathlib import Path
from typing import Dict

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from frame.sil.procedure import ProcSpec

DATA_DIR = Path(__file__).parent / "data"
TABLES = ("python", "javascript", "java", "csharp", "c", "cpp")
_FIELDS = {f.name: f for f in fields(ProcSpec)}
_SET_FIELDS = {"modifies"}
ALLOCATION_KINDS = frozenset({"heap", "stack", "mapped", "new", "new_array"})
RELEASE_KINDS = ALLOCATION_KINDS - {"stack"}           # stack memory is never released by a call


class SpecTableError(ValueError):
    """A spec table that does not describe ProcSpecs."""


def parse_table(data: dict, origin: str) -> Dict[str, ProcSpec]:
    specs: Dict[str, ProcSpec] = {}
    for i, entry in enumerate(data.get("spec", [])):
        entry = dict(entry)
        name = entry.pop("name", None)
        if not isinstance(name, str) or not name:
            raise SpecTableError(f"{origin}: spec #{i + 1} has no name")
        unknown = set(entry) - set(_FIELDS)
        if unknown:
            raise SpecTableError(f"{origin}: {name}: unknown field(s) {sorted(unknown)}")
        if name in specs:
            raise SpecTableError(f"{origin}: {name} is listed twice")
        for key, kinds in (("allocates", ALLOCATION_KINDS), ("frees", RELEASE_KINDS)):
            if key in entry and entry[key] not in kinds:
                raise SpecTableError(f"{origin}: {name}: {key} must be one of {sorted(kinds)}")
        derefs = entry.get("dereferences", [])
        if not isinstance(derefs, list) or not all(isinstance(i, int) and i >= -1 for i in derefs):
            raise SpecTableError(f"{origin}: {name}: dereferences must be argument positions (-1: every one)")
        sizes = entry.get("size_args", [])
        if not isinstance(sizes, list) or not all(isinstance(i, int) and i >= 0 for i in sizes):
            raise SpecTableError(f"{origin}: {name}: size_args must be argument positions")
        specs[name] = ProcSpec(**{k: (set(v) if k in _SET_FIELDS else v) for k, v in entry.items()})
    return specs


@lru_cache(maxsize=None)
def _load(path: str) -> Dict[str, ProcSpec]:
    p = Path(path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise SpecTableError(f"{p}: {e}") from e
    return parse_table(data, str(p))


def load_table(name: str) -> Dict[str, ProcSpec]:
    """A fresh copy of spec table `name` (callers may add to it): the knowledge base's, when
    the last pulled revision has one that loads cleanly, else the built-in one."""
    if name not in TABLES:
        raise SpecTableError(f"no spec table {name!r}")
    try:
        from frame.kb.store import kb_spec_file
        kb = kb_spec_file(name)
    except Exception:                     # the knowledge base must never stop a scan
        kb = None
    if kb is not None:
        try:
            return dict(_load(str(kb)))
        except SpecTableError:
            pass
    return dict(_load(str(DATA_DIR / f"{name}.toml")))


def dump_table(specs: Dict[str, ProcSpec], header: str = "") -> str:
    """TOML for `specs`, in order, with only the fields that differ from a default ProcSpec."""
    default = ProcSpec()
    out = [header.rstrip() + "\n"] if header else []

    def lit(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return repr(v)
        if isinstance(v, str):
            return json.dumps(v)                 # a JSON string is a valid TOML basic string
        if isinstance(v, (list, tuple, set, frozenset)):
            items = sorted(v) if isinstance(v, (set, frozenset)) else v
            return "[" + ", ".join(lit(x) for x in items) + "]"
        raise SpecTableError(f"cannot write {v!r} as TOML")

    for name, spec in specs.items():
        out.append("\n[[spec]]\n")
        out.append(f"name = {lit(name)}\n")
        for f in _FIELDS:
            v = getattr(spec, f)
            if v != getattr(default, f):
                out.append(f"{f} = {lit(v)}\n")
    return "".join(out)
