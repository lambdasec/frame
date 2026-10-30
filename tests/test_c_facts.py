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


# --- [[function]]: a C pack states library facts for a project's own functions ---------------

from frame.sil.packs.schema import PackError, parse_pack              # noqa: E402

try:                                                                   # Python 3.11+
    import tomllib
except ModuleNotFoundError:                                            # pragma: no cover - 3.10
    import tomli as tomllib


def load_pack_text(text, origin):
    return parse_pack(tomllib.loads(text), origin)
from frame.sil.scanner import FrameScanner                            # noqa: E402

PACK = '''
[pack]
name = "acme-memory"
language = "c"
detect = { imports = ["acme.h"] }

[[function]]
name = "acme_alloc"
allocates = "heap"

[[function]]
name = "acme_release"
frees = "heap"

[[function]]
name = "acme_log"
dereferences = [0]

[[function]]
name = "die"
noreturn = true
'''


def test_a_pack_states_facts_for_the_files_it_applies_to(tmp_path):
    (tmp_path / "acme.toml").write_text(PACK)
    code = ('#include "acme.h"\n'
            'void f(void)\n{\n    char *p = acme_alloc(10);\n    acme_release(p);\n    acme_log(p);\n}\n')
    with_pack = FrameScanner(language="c", packs=[str(tmp_path / "acme.toml")]).scan(code, "a.c")
    assert "CWE-416" in {v.cwe_id for v in with_pack.vulnerabilities}
    assert "CWE-416" not in {v.cwe_id for v in FrameScanner(language="c").scan(code, "a.c").vulnerabilities}
    other = code.replace('#include "acme.h"\n', '')                  # the pack is not detected there
    assert "CWE-416" not in {v.cwe_id for v in
                             FrameScanner(language="c", packs=[str(tmp_path / "acme.toml")]).scan(other, "a.c")
                             .vulnerabilities}


def test_facts_are_active_only_inside_the_block():
    from frame.sil.packs.schema import FunctionFact
    with c_facts.active({"acme_alloc": FunctionFact("acme_alloc", allocates="heap")}):
        assert "acme_alloc" in c_facts.allocators("heap", returning=True)
        assert SLMemoryAnalyzer().ALLOC_FUNCS >= {"acme_alloc", "malloc"}
    assert "acme_alloc" not in c_facts.allocators()


@pytest.mark.parametrize("body,error", [
    ('[[function]]\nname = "f"\n', "states nothing"),
    ('[[function]]\nname = "f"\nfrees = "stack"\n', "must be one of"),
    ('[[function]]\nname = "f"\ndereferences = [-2]\n', "argument positions"),
    ('[[function]]\nname = "f"\nnoreturn = "yes"\n', "true or false"),
    ('[[function]]\nname = "f"\nnoreturn = true\nreturns = 1\n', "returns"),
])
def test_malformed_function_facts_are_errors(body, error):
    with pytest.raises(PackError, match=error):
        load_pack_text('[pack]\nname = "x"\nlanguage = "c"\n' + body, "x.toml")


def test_outside_c_a_function_fact_states_only_noreturn():
    # flask.abort never returns: any language may say so; memory facts are C and C++ only
    pack = load_pack_text('[pack]\nname = "x"\nlanguage = "python"\n[[function]]\nname = "f"\nnoreturn = true\n',
                          "x.toml")
    assert pack.functions[0].noreturn
    with pytest.raises(PackError, match="only noreturn"):
        load_pack_text('[pack]\nname = "x"\nlanguage = "python"\n[[function]]\nname = "f"\nallocates = "heap"\n',
                       "x.toml")
