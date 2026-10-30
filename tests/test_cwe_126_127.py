"""CWE-125/126 (a read past a buffer's end) and CWE-127 (a read before its start) in C, from the
structural checks: a constant length read from a buffer of smaller constant capacity (memcpy,
memmove, memcmp, bcopy), a constant index past a fixed array, a constant negative index. Reads
through a pointer moved before the start are a known gap (tests/e2e/test_known_gaps_cnative.py)."""

import pytest

from frame.sil.scanner import FrameScanner

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n"


def cwes(*body):
    src = HDR + "void f(void)\n{\n" + "\n".join("    " + line for line in body) + "\n}\n"
    r = FrameScanner(language="c", verify=False).scan(src, "t.c")
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


@pytest.mark.parametrize("body", [
    ("char src[100];", "char dest[4096];", "memset(src, 'a', 99);", "memcpy(dest, src, 2048);"),
    ("char *src = malloc(50);", "char dest[100];", "if (src == NULL) return;", "memset(src, 'a', 49);",
     "memmove(dest, src, 99);", "free(src);"),
    ("char a[8];", "char b[64];", "memset(a, 0, 8);", "memset(b, 0, 64);", "int same = memcmp(a, b, 64);",
     'printf("%d", same);'),
])
def test_a_constant_read_past_the_source_is_cwe_126(body):
    assert "CWE-126" in cwes(*body)


def test_a_read_that_fits_is_not():
    assert "CWE-126" not in cwes("char src[100];", "char dest[100];", "memset(src, 'a', 99);",
                                 "memcpy(dest, src, 100);")


def test_a_large_constant_index_is_an_out_of_bounds_read():
    assert "CWE-125" in cwes("char buf[10];", "char c = buf[5000];", 'printf("%c", c);')


def test_a_negative_index_read_is_cwe_127():
    assert "CWE-127" in cwes("char buf[10];", "char c = buf[-1];", 'printf("%c", c);')


def test_strlen_of_a_literal_is_not_an_over_read():
    assert not {"CWE-125", "CWE-126"} & cwes('const char *msg = "hello";', "size_t len = strlen(msg);",
                                             'printf("%zu", len);')
