"""C and C++ library facts in the spec tables (`allocates`, `frees`, `allocates_via`, `noreturn`,
`dereferences` in specs/data/c.toml and cpp.toml), read through `frame/sil/c_facts.py` by the memory
analyzers and the translator, and validated strictly when a table loads."""

import pytest

from frame.sil import c_facts
from frame.sil.analyzers.memory_safety import MemorySafetyAnalyzer
from frame.sil.analyzers.sl_memory_analyzer import SLMemoryAnalyzer
from frame.sil.specs.tables import SpecTableError, parse_table
from frame.sil.translator import SILTranslator


def test_allocation_kinds():
    heap = c_facts.allocators("heap", returning=True)
    assert {"malloc", "calloc", "realloc", "reallocarray", "strdup", "aligned_alloc"} <= heap
    assert "posix_memalign" in c_facts.allocators("heap") and "posix_memalign" not in heap   # via its argument
    assert "alloca" in c_facts.allocators("stack") and "alloca" not in c_facts.allocators("heap")
    assert c_facts.allocators("mapped") == {"mmap"} and c_facts.releasers("mapped") == {"munmap"}
    assert c_facts.releasers("heap") == {"free", "cfree"}
    assert all(":" not in n and "[" not in n for n in c_facts.allocators())   # plain identifiers only


def test_noreturn_and_dereferences():
    assert {"exit", "_Exit", "abort", "longjmp", "__assert_fail", "errx"} <= c_facts.noreturn()
    d = c_facts.dereferences()
    assert d["strlen"] == [0] and d["memcpy"] == [0, 1] and d["printf"] == [-1]


def test_the_analyzers_read_the_facts():
    assert SLMemoryAnalyzer.ALLOC_FUNCS == c_facts.allocators("heap", returning=True)
    assert MemorySafetyAnalyzer.FREE_FUNCS == c_facts.releasers("heap", "mapped")
    assert c_facts.allocators("heap") == SILTranslator._C_HEAP_ALLOCATORS
    assert c_facts.noreturn() <= SILTranslator._NORETURN_FUNCS


@pytest.mark.parametrize("entry,error", [
    ({"name": "f", "allocates": True}, "allocates must be one of"),
    ({"name": "f", "frees": "stack"}, "frees must be one of"),
    ({"name": "f", "dereferences": [-2]}, "dereferences must be argument positions"),
    ({"name": "f", "dereferences": "0"}, "dereferences must be argument positions"),
])
def test_malformed_facts_are_errors(entry, error):
    with pytest.raises(SpecTableError, match=error):
        parse_table({"spec": [entry]}, "t.toml")
