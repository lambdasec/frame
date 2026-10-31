"""C and C++ library facts, from the c and cpp spec tables (`specs/data/c.toml`, `cpp.toml`): which
functions allocate or release which kind of memory, which never return, and which read through
their pointer arguments. The memory analyzers take their function sets from here, so one table
says what malloc, free or exit do."""

from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterator, List, Mapping, NamedTuple, Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from frame.sil.procedure import ProcSpec
from frame.sil.specs.tables import load_table


# Facts the packs applied to the file being analysed add (`[[function]]`), over the tables'.
_EXTRA: ContextVar[Mapping[str, Any]] = ContextVar("c_facts_extra", default={})


@lru_cache(maxsize=1)
def _table_specs() -> Dict[str, ProcSpec]:
    out: Dict[str, ProcSpec] = {}
    for table in ("c", "cpp"):
        for name, spec in load_table(table).items():
            out.setdefault(name, spec)
    return out


def _specs() -> Mapping[str, Any]:
    extra = _EXTRA.get()
    return {**_table_specs(), **extra} if extra else _table_specs()


@contextmanager
def active(facts: Mapping[str, Any]) -> Iterator[None]:
    """While analysing one file: its packs' library facts (`Program.library_facts`) count too.
    The analyzers read their sets when they are created, inside this block."""
    token = _EXTRA.set(dict(facts or {}))
    try:
        yield
    finally:
        _EXTRA.reset(token)


_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")


def _names(pred) -> FrozenSet[str]:
    """Plain C identifiers only (not `std::malloc` or `operator new[]`): the analyzers match call
    names, several of them inside regular expressions."""
    return frozenset(n for n, s in _specs().items() if _IDENTIFIER.fullmatch(n) and pred(s))


def allocators(*kinds: str, returning: bool = False) -> FrozenSet[str]:
    """Functions allocating memory of these kinds (every kind when none is given); with
    `returning`, only those that return the memory (not posix_memalign)."""
    return _names(lambda s: s.allocates and (not kinds or s.allocates in kinds)
                  and not (returning and s.allocates_via is not None))


def releasers(*kinds: str) -> FrozenSet[str]:
    """Functions releasing memory of these kinds (every kind when none is given)."""
    return _names(lambda s: s.frees and (not kinds or s.frees in kinds))


def noreturn() -> FrozenSet[str]:
    return _names(lambda s: s.noreturn)


def dereferences() -> Dict[str, List[int]]:
    """Function -> the argument positions it reads through (-1: every argument)."""
    return {n: list(s.dereferences) for n, s in _specs().items()
            if s.dereferences and _IDENTIFIER.fullmatch(n)}


# -- specs/data/c-library.toml: facts about functions the spec tables need not have a row for -----

LIBRARY_PATH = Path(__file__).parent / "specs" / "data" / "c-library.toml"
_LIB_LISTS = ("non_retaining", "bare_out_params", "string_compares", "length_sinks", "container_lookups",
              "unbounded_copies", "copies")
_LIB_MAPS = ("bounded_copies", "format_functions")
_BUFFER_KEYS = {"name", "element_writes", "element_reads", "bounded_write", "bounded_reads", "literal_copy"}

Access = Tuple[int, Optional[int]]          # (buffer argument, count argument or None)


class Library(NamedTuple):
    non_retaining: FrozenSet[str]
    bare_out_params: FrozenSet[str]
    string_compares: FrozenSet[str]
    length_sinks: FrozenSet[str]
    container_lookups: FrozenSet[str]
    unbounded_copies: FrozenSet[str]
    copies: FrozenSet[str]
    bounded_copies: Dict[str, int]          # name -> size argument
    format_functions: Dict[str, int]        # name -> format argument
    element_writes: Dict[str, List[Access]]
    element_reads: Dict[str, List[Access]]
    bounded_writes: Dict[str, Tuple[int, int]]
    bounded_reads: Dict[str, Tuple[Tuple[int, int], ...]]
    literal_copies: Dict[str, int]


def _position(name: str, where: str, v, allow_none: bool = False) -> Optional[int]:
    if isinstance(v, int) and not isinstance(v, bool) and (v >= 0 or (allow_none and v == -1)):
        return None if v == -1 else v
    raise ValueError(f"{name}: {where} must be argument positions" + (" (-1: none)" if allow_none else ""))


def _pairs(name: str, where: str, v, allow_none: bool) -> List[Access]:
    if not isinstance(v, list) or not v or not all(isinstance(p, list) and len(p) == 2 for p in v):
        raise ValueError(f"{name}: {where} must be a list of [buffer, count] pairs")
    return [(_position(name, where, b), _position(name, where, c, allow_none)) for b, c in v]


@lru_cache(maxsize=None)
def library(path: Path = LIBRARY_PATH) -> Library:
    name = Path(path).name
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) != set(_LIB_LISTS) | set(_LIB_MAPS) | {"buffer"}:
        raise ValueError(f"{name}: needs exactly {sorted(set(_LIB_LISTS) | set(_LIB_MAPS) | {'buffer'})}")
    for k in _LIB_MAPS:
        if not isinstance(data[k], dict) or not data[k]:
            raise ValueError(f"{name}: [{k}] maps function names to an argument position")
        for fn, pos in data[k].items():
            _position(name, f"[{k}] {fn}", pos)
    for k in _LIB_LISTS:
        if not isinstance(data[k], list) or not data[k] or not all(isinstance(n, str) and n for n in data[k]):
            raise ValueError(f"{name}: {k} must be a non-empty list of names")
    ew: Dict[str, List[Access]] = {}
    er: Dict[str, List[Access]] = {}
    bw: Dict[str, Tuple[int, int]] = {}
    br: Dict[str, Tuple[Tuple[int, int], ...]] = {}
    lc: Dict[str, int] = {}
    for i, b in enumerate(data["buffer"]):
        fn = b.get("name") if isinstance(b, dict) else None
        where = f"[[buffer]] {fn or '#' + str(i + 1)}"
        if not isinstance(fn, str) or not fn or set(b) - _BUFFER_KEYS or len(b) < 2:
            raise ValueError(f"{name}: {where} needs a name and at least one of {sorted(_BUFFER_KEYS - {'name'})}")
        if fn in ew or fn in er or fn in bw or fn in br or fn in lc:
            raise ValueError(f"{name}: {where} is listed twice")
        if "element_writes" in b:
            ew[fn] = _pairs(name, f"{where} element_writes", b["element_writes"], True)
        if "element_reads" in b:
            er[fn] = _pairs(name, f"{where} element_reads", b["element_reads"], True)
        if "bounded_write" in b:
            (d, n), = _pairs(name, f"{where} bounded_write", [b["bounded_write"]], False)
            bw[fn] = (d, n)
        if "bounded_reads" in b:
            br[fn] = tuple(_pairs(name, f"{where} bounded_reads", b["bounded_reads"], False))
        if "literal_copy" in b:
            lc[fn] = _position(name, f"{where} literal_copy", b["literal_copy"])
    return Library(*(frozenset(data[k]) for k in _LIB_LISTS), *(dict(data[k]) for k in _LIB_MAPS),
                   ew, er, bw, br, lc)


__all__ = ["Library", "active", "allocators", "dereferences", "library", "noreturn", "releasers"]
