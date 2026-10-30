"""CWE-120/121/122 (a copy or fill bigger than its destination) and CWE-124 (a write before a
buffer's start) in C, from the structural checks: a constant size against a constant capacity
(a local array, or a pointer whose one definition is a constant malloc/alloca), and a constant
negative index. Accesses through pointers into a region are tests/test_c_regions.py."""

import pytest

from frame.sil.scanner import FrameScanner

HDR = "#include <stdlib.h>\n#include <string.h>\n\n"
OVERFLOW = {"CWE-120", "CWE-121", "CWE-122", "CWE-787"}


def cwes(body, params="void"):
    src = HDR + f"void f({params})\n{{\n" + "\n".join("    " + line for line in body) + "\n}\n"
    r = FrameScanner(language="c", verify=False).scan(src, "t.c")
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


@pytest.mark.parametrize("body, params", [
    (("char *buf = malloc(10);", "if (buf == NULL) return;", "memcpy(buf, src, 100);", "free(buf);"), "const char *src"),
    (("char *buf = malloc(16);", "if (buf == NULL) return;", "memset(buf, 0, 256);", "free(buf);"), "void"),
    (("char *buf = malloc(8);", "if (buf == NULL) return;", 'strcpy(buf, "far too long for eight");', "free(buf);"), "void"),
])
def test_heap_copy_bigger_than_the_allocation(body, params):
    assert cwes(body, params) & OVERFLOW


def test_a_copy_that_fits_is_not():
    body = ("char *buf = malloc(100);", "if (buf == NULL) return;", "memcpy(buf, src, 50);", "free(buf);")
    assert not cwes(body, "const char *src") & OVERFLOW


def test_negative_index_write_is_cwe_124():
    assert "CWE-124" in cwes(("char buf[10];", "buf[-1] = 'x';"))


def test_positive_index_write_is_not():
    assert "CWE-124" not in cwes(("char buf[10];", "buf[5] = 'x';"))
