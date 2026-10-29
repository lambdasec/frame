"""CWE-190 (integer overflow) in C/C++, decided by the solver: attacker data in an operand of
`*`, `+` or a constant `<<`, whose declared integer type is known, and a path on which the
result can exceed the maximum of the type the usual arithmetic conversions give. A guard that
keeps the result in range clears it; nothing depends on a variable's name."""

import pytest

from frame.sil.scanner import FrameScanner

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\n"


def cwe190(*body, language="c"):
    src = HDR + "void f(void)\n{\n" + "\n".join(body) + "\n}\n"
    r = FrameScanner(language=language, verify=False).scan(src, "t.c" if language == "c" else "t.cpp")
    assert not r.errors, r.errors
    return [v.line for v in r.vulnerabilities if v.cwe_id == "CWE-190"]


READ = ("char in[16];", "fgets(in, 16, stdin);")


@pytest.mark.parametrize("decl, use", [
    ("int d = atoi(in);", "int r = d * d;"),
    ("int d = atoi(in);", "int r = d * 2;"),
    ("int d = atoi(in);", "int r = d + 1;"),
    ("unsigned d = atoi(in);", "unsigned r = d << 20;"),
    ("int d = atoi(in);", "int r = 7; r += d;"),
    ("int d = atoi(in);", "int r = 3; r *= d;"),
    ("int64_t d = atoll(in);", "int64_t r = d * 2;"),
])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_attacker_arithmetic_that_can_exceed_the_type_is_reported(decl, use, language):
    assert cwe190(*READ, decl, use, 'printf("%d", (int)r);', language=language)


@pytest.mark.parametrize("lines", [
    # a guard that keeps the result in range
    ("int d = atoi(in);", "if (d < 1000) {", "int r = d * 2;", 'printf("%d", r);', "}"),
    ("int d = atoi(in);", "if (d > -46341 && d < 46341) {", "int r = d * d;", 'printf("%d", r);', "}"),
    ("int d = atoi(in);", "if (d >= 2147483647) {", "return;", "}", "int r = d + 1;", 'printf("%d", r);'),
    # promoted to int: a char squared cannot overflow it (narrowing it back is CWE-197)
    ("char c = in[0];", "int r = c * c;", 'printf("%d", r);'),
    # no attacker data
    ("int d = 5;", "int r = d * 2;", 'printf("%d", r);'),
    # a platform-dependent width is not guessed
    ("long d = atol(in);", "long r = d * 2;", 'printf("%ld", r);'),
    # a variable shift amount is not modelled
    ("int d = atoi(in);", "int r = 1 << d;", 'printf("%d", r);'),
])
def test_in_range_or_unknown_is_not(lines):
    assert not cwe190(*READ, *lines)


def test_a_guard_too_loose_for_the_multiplier_is_still_reported():
    assert cwe190(*READ, "int d = atoi(in);", "if (d < 2000000000) {", "int r = d * 2;",
                  'printf("%d", r);', "}")


def test_parameters_without_attacker_data_are_not_reported():
    src = HDR + "int area(int a, int b)\n{\n    return a * b;\n}\n"
    r = FrameScanner(language="c", verify=False).scan(src, "t.c")
    assert not [v for v in r.vulnerabilities if v.cwe_id == "CWE-190"]
