"""Standard-library facts the engine reads are data, and each table answers as the code it replaced:
the kinds guards clear (kinds.toml), C string lengths and size-only allocators (c-library.toml),
ctype and JS key tests and URL host getters (guards.toml), Python stdlib parse functions taking a
parser (parser-hardening.toml), Java builders, capacity constructors and String's static methods
(java-types.toml)."""

from frame.sil.c_facts import library
from frame.sil.kinds import load as kinds
from frame.sil.specs import java_specs
from frame.sil.specs.guards import load as guards
from frame.sil.specs.parser_hardening import load as hardening


def test_the_kinds_guards_clear():
    k = kinds()
    charset = k.guard_cleared("charset")
    assert {"sql", "filesystem", "path", "shell_command", "code", "log"} <= charset
    assert "vulnerable_dependency" not in charset
    assert k.guard_cleared("exact") == charset | {"vulnerable_dependency"}
    assert k.spellings(k.dot_unsafe) >= {"filesystem", "path"}
    assert "sensitive_log" in k.confidentiality and "sql" not in k.confidentiality


def test_c_library_and_guard_facts():
    lib = library()
    assert lib.string_lengths == {"strlen", "strnlen", "wcslen"}
    assert lib.size_only_allocators == {"alloca", "calloc", "malloc"} and "realloc" not in lib.size_only_allocators
    g = guards()
    assert "isxdigit" in g.charset_functions and {"indexOf", "lastIndexOf"} == g.position_methods
    assert "has" in g.key_methods and "getHost" in g.host_getters and "new java.net.URI" in g.url_parsers


def test_parser_and_java_type_facts():
    h = hardening()
    assert "xml.dom.minidom.parseString" in h.stdlib_parse_functions and h.stdlib_parser_arg == 1
    assert java_specs.JAVA_STRING_STATIC_TYPES["format"] == "String"
    assert "append" in java_specs.JAVA_BUILDER_SELF_METHODS and "StringBuffer" in java_specs.JAVA_BUILDER_TYPES
    assert "ArrayList" in java_specs.JAVA_CAPACITY_CONSTRUCTORS and "String" not in java_specs.JAVA_CAPACITY_CONSTRUCTORS
