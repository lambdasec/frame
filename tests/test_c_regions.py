"""C/C++ accesses through a pointer into a REGION (a fixed local array, or the start of a block an
allocator returned), decided by the solver over the path facts (`SILTranslator._region_of`,
`_out_of_bounds_checks`, `_tainted_index_checks`):

* provable: the path facts entail `offset + index < 0` (CWE-124 write / CWE-127 read) or
  `>= bound` (CWE-787 / CWE-125); a constant is the simplest case, a join of constants another;
* attacker index: attacker data can make `offset + index` leave the region on a feasible path,
  given the declared type of the index (an unsigned index is never negative);
* library calls writing or reading through a pointer before its region's start (memcpy, strcpy).

Each positive is paired with the in-bounds form that must stay silent."""

import pytest

from frame.sil.scanner import FrameScanner

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n"


def source(body, params="void"):
    return HDR + f"void f({params})\n{{\n" + "\n".join("    " + line for line in body) + "\n}\n"


def found(body, params="void", language="c"):
    r = FrameScanner(language=language, verify=False).scan(source(body, params), "t.c" if language == "c" else "t.cpp")
    assert not r.errors, r.errors
    return {(v.cwe_id, v.line) for v in r.vulnerabilities}


def at(body, line_text):
    """The source line number of the first line containing `line_text`."""
    return 1 + next(i for i, line in enumerate(source(body).split("\n")) if line_text in line)


BUF = ['char buf[10] = "abc";']


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("decl, access, cwe", [
    ("char *p = buf;", "*(p - 5) = 'x';", "CWE-124"),
    ("char *p = buf;", "char c = *(p - 5);", "CWE-127"),
    ("char *p = buf + 3;", "p[-4] = 1;", "CWE-124"),
    ("char *p = buf;", "char c = p[-2];", "CWE-127"),
    ("char *p = buf + 9;", "char c = *(p + 1);", "CWE-125"),
    ("char *p = buf + 10;", "*p = 0;", "CWE-787"),
    ("char *q = buf + 2;\n    char *p = q - 3;", "*p = 0;", "CWE-124"),
])
def test_an_access_through_a_pointer_outside_its_array(decl, access, cwe, language):
    body = BUF + [decl, access, 'printf("%s", buf);']
    assert (cwe, at(body, access)) in found(body, language=language)


@pytest.mark.parametrize("decl, access", [
    ("char *p = buf + 3;", "p[-2] = 1;"),          # element 1: inside
    ("char *p = buf + 3;", "char c = *(p + 6);"),  # element 9: the last one
    ("char *p = buf;", "char c = *p;"),
])
def test_an_access_through_a_pointer_inside_its_array_is_not(decl, access):
    body = BUF + [decl, access, 'printf("%s", buf);']
    assert not {f for f in found(body) if f[0] in ("CWE-124", "CWE-127", "CWE-125", "CWE-787")}


def test_a_pointer_of_another_element_type_is_not_followed():
    """Pointer arithmetic counts elements of the pointer's type; a cast changes the unit."""
    same = ["int ints[4] = {0};", "int *c = ints;", "c[10] = 0;", 'printf("%d", ints[0]);']
    other = ["int ints[4] = {0};", "char *c = (char *)ints;", "c[10] = 0;", 'printf("%d", ints[0]);']
    assert ("CWE-787", at(same, "c[10]")) in found(same)
    assert not {f for f in found(other) if f[0] in ("CWE-787", "CWE-124")}


def test_a_pointer_whose_address_is_taken_is_not_followed():
    body = BUF + ["char *p = buf;", "move(&p);", "*(p - 5) = 'x';", 'printf("%s", buf);']
    assert not {f for f in found(body) if f[0] == "CWE-124"}


def test_a_reassigned_pointer_is_not_followed():
    body = BUF + ["char *p = buf;", "p = buf + 6;", "*(p - 5) = 'x';", 'printf("%s", buf);']
    assert not {f for f in found(body) if f[0] == "CWE-124"}


def test_before_a_heap_block():
    body = ["char *heap = malloc(16);", "if (heap == NULL)", "{", "return;", "}",
            "char *before = heap - 8;", "before[0] = 'y';", "heap[3] = 'z';", "free(heap);"]
    got = found(body)
    assert ("CWE-124", at(body, "before[0]")) in got
    assert not {f for f in got if f[1] == at(body, "heap[3]")}


def test_an_index_every_path_makes_negative_is_proven():
    body = BUF + ["int i = -1;", "if (k > 0)", "{", "i = -2;", "}", "buf[i] = 'w';", 'printf("%s", buf);']
    assert ("CWE-124", at(body, "buf[i]")) in found(body, "int k")


def test_an_index_only_some_path_makes_outside_is_not_a_proof():
    body = BUF + ["int j = 0;", "if (k > 0)", "{", "j = 12;", "}", "buf[j] = 'v';", 'printf("%s", buf);']
    assert not {f for f in found(body, "int k") if f[0] in ("CWE-787", "CWE-124")}


READ = ["char in[16];", "int buffer[10] = { 0 };", "fgets(in, 16, stdin);"]


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_an_attacker_index_with_only_an_upper_guard_can_be_negative(language):
    body = READ + ["int data = atoi(in);", "if (data < 10)", "{", "buffer[data] = 1;", "}"]
    got = found(body, language=language)
    assert ("CWE-124", at(body, "buffer[data]")) in got
    assert ("CWE-787", at(body, "buffer[data]")) not in got


def test_an_attacker_read_with_no_guard_is_both_ways_out():
    body = READ + ["int data = atoi(in);", "int v = buffer[data];", 'printf("%d", v);']
    got = found(body)
    assert {("CWE-125", at(body, "buffer[data]")), ("CWE-127", at(body, "buffer[data]"))} <= got


@pytest.mark.parametrize("lines", [
    ["int data = atoi(in);", "if (data >= 0 && data < 10)", "{", "buffer[data] = 1;", "}"],
    ["unsigned u = atoi(in);", "if (u < 10)", "{", "buffer[u] = 1;", "}"],
    ["size_t n = strlen(in);", "if (n < 10)", "{", "buffer[n] = 1;", "}"],
])
def test_a_guarded_or_unsigned_attacker_index_is_not(lines):
    got = found(READ + lines)
    assert not {f for f in got if f[0] in ("CWE-124", "CWE-127", "CWE-787", "CWE-125")}


@pytest.mark.parametrize("call, cwe", [
    ("memcpy(data, src, 10);", "CWE-124"),
    ("strcpy(data, src);", "CWE-124"),
    ("memcpy(dest, data, 10);", "CWE-127"),
    ("strncpy(dest, data, 10);", "CWE-127"),
])
def test_a_library_call_through_a_pointer_before_its_start(call, cwe):
    body = ["char dataBuffer[100];", "char dest[100];", "char *data = dataBuffer - 8;", call,
            'printf("%s", dest);']
    assert (cwe, at(body, call)) in found(body, "const char *src")


@pytest.mark.parametrize("call", ["memcpy(data, src, 0);", "memcpy(dataBuffer, src, 10);",
                                  "memcpy(dest, dataBuffer + 8, 10);"])
def test_a_library_call_that_stays_inside_is_not(call):
    body = ["char dataBuffer[100];", "char dest[100];", "char *data = dataBuffer - 8;", call,
            'printf("%s", dest);']
    assert not {f for f in found(body, "const char *src") if f[0] in ("CWE-124", "CWE-127")}


STRLEN = ["char buf[100];", "char *p = buf;", "if (fgets(p, 100, stdin) == NULL)", "{", "return;", "}",
          "size_t n = strlen(p);"]


def test_strlen_through_a_pointer_is_bounded_by_the_array():
    """`n = strlen(p)` with p into a char[100]: 0 <= n <= 99, so `p[n - 1]` after `n > 0` is inside."""
    body = STRLEN + ["if (n > 0)", "{", "p[n - 1] = '\\0';", "}", 'printf("%s", buf);']
    assert not {f for f in found(body) if f[0] in ("CWE-787", "CWE-124")}


def test_an_empty_string_makes_n_minus_one_negative():
    body = STRLEN + ["p[n - 1] = '\\0';", 'printf("%s", buf);']
    got = found(body)
    assert ("CWE-124", at(body, "p[n - 1]")) in got
    assert not {f for f in got if f[0] == "CWE-787"}


def test_an_index_holding_a_call_is_not_modelled():
    body = ["char filename[100] = \"\";", "if (fgets(filename, 100, stdin) == NULL)", "{", "return;", "}",
            "if (strlen(filename) > 0)", "{", "filename[strlen(filename) - 1] = '\\0';", "}", 'printf("%s", filename);']
    assert not {f for f in found(body) if f[0] in ("CWE-787", "CWE-124")}
