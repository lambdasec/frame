"""C and C++ library facts, from the c and cpp spec tables (`specs/data/c.toml`, `cpp.toml`): which
functions allocate or release which kind of memory, which never return, and which read through
their pointer arguments. The memory analyzers take their function sets from here, so one table
says what malloc, free or exit do."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, FrozenSet, List

from frame.sil.procedure import ProcSpec
from frame.sil.specs.tables import load_table


@lru_cache(maxsize=1)
def _specs() -> Dict[str, ProcSpec]:
    out: Dict[str, ProcSpec] = {}
    for table in ("c", "cpp"):
        for name, spec in load_table(table).items():
            out.setdefault(name, spec)
    return out


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


__all__ = ["allocators", "dereferences", "noreturn", "releasers"]
