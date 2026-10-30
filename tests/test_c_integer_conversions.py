"""CWE-191, 194, 195 and 197 in C/C++, decided by the solver over the path facts and each
operand's declared integer type (the same machinery as CWE-190, tests/test_cwe190_detection.py).
Each positive is paired with the guard or type that clears it; nothing depends on a name."""

import pytest

from frame.sil.scanner import FrameScanner

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdint.h>\n"
READ = ("char in[16];", "fgets(in, 16, stdin);")


def found(cwe, *body, language="c"):
    src = HDR + "void f(void)\n{\n" + "\n".join(READ + body) + "\n}\n"
    r = FrameScanner(language=language, verify=False).scan(src, "t.c" if language == "c" else "t.cpp")
    assert not r.errors, r.errors
    return [v.line for v in r.vulnerabilities if v.cwe_id == cwe]


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_underflow(language):
    assert found("CWE-191", "int d = atoi(in);", "int r = d - 1;", 'printf("%d", r);', language=language)
    assert found("CWE-191", "unsigned d = atoi(in);", "unsigned r = d - 1;", 'printf("%u", r);', language=language)
    assert found("CWE-191", "int d = atoi(in);", "if (d < 0) {", "int r = d * 2;", 'printf("%d", r);', "}",
                 language=language)


@pytest.mark.parametrize("lines", [
    ("int d = atoi(in);", "if (d > -2147483647) {", "int r = d - 1;", 'printf("%d", r);', "}"),
    ("int d = atoi(in);", "if (d > 0) {", "int r = d * 2;", 'printf("%d", r);', "}"),
    ("int d = 5;", "int r = d - 1;", 'printf("%d", r);'),
])
def test_no_underflow(lines):
    assert not found("CWE-191", *lines)


def test_truncation():
    assert found("CWE-197", "int d = atoi(in);", "short s = d;", 'printf("%d", s);')
    assert found("CWE-197", "short d = (short)atoi(in);", "char c = (char)d;", 'printf("%d", c);')


@pytest.mark.parametrize("lines", [
    ("int d = atoi(in);", "if (d >= 0 && d < 100) {", "char c = (char)d;", 'printf("%d", c);', "}"),
    ("short d = (short)atoi(in);", "int i = d;", 'printf("%d", i);'),      # widening
    ("int d = atoi(in);", "unsigned u = d;", 'printf("%u", u);'),         # same width: not truncation
])
def test_no_truncation(lines):
    assert not found("CWE-197", *lines)


_COPY = ("char src[100];", "char dst[100];", "memset(src, 'A', 99);")


def test_negative_size_from_int_is_cwe_195():
    assert found("CWE-195", *_COPY, "int n = atoi(in);", "if (n < 100) {", "memcpy(dst, src, n);", "}")


def test_negative_size_from_short_is_cwe_194():
    assert found("CWE-194", *_COPY, "short n = (short)atoi(in);", "if (n < 100) {", "memcpy(dst, src, n);", "}")


@pytest.mark.parametrize("lines", [
    ("int n = atoi(in);", "if (n >= 0 && n < 100) {", "memcpy(dst, src, n);", "}"),
    ("int n = atoi(in);", "if (n <= 0 || n >= 100) {", "return;", "}", "memcpy(dst, src, n);"),
    ("unsigned n = atoi(in);", "if (n < 100) {", "memcpy(dst, src, n);", "}"),
    ("int n = 50;", "memcpy(dst, src, n);"),
])
def test_a_size_that_cannot_be_negative_is_not(lines):
    assert not found("CWE-195", *_COPY, *lines) and not found("CWE-194", *_COPY, *lines)


_TWO_SIDED = ("int t = atoi(in);", "short s;", "if (t > SHRT_MAX || t < SHRT_MIN)", "{", "s = -1;", "}",
              "else", "{", "s = t;", "}", 'printf("%d", s);')


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_standard_limits_are_their_values_and_cpp_conditions_are_guards(language):
    """`SHRT_MAX` is 32767 to the solver (c_int_model.LIMITS), and a C++ `if` condition (a
    `condition_clause` in tree-sitter-cpp) is a real guard, not an opaque name."""
    assert not found("CWE-197", *_TWO_SIDED, language=language)
    one_sided = tuple(x.replace(" || t < SHRT_MIN", "") for x in _TWO_SIDED)
    assert found("CWE-197", *one_sided, language=language)


def test_a_cpp_reference_is_its_variable():
    lines = ("int data;", "int &ref = data;", "data = atoi(in);", "int result = ref - 1;", 'printf("%d", result);')
    assert found("CWE-191", *lines, language="cpp")
    assert not found("CWE-191", *(x.replace("data = atoi(in);", "data = 5;") for x in lines), language="cpp")
