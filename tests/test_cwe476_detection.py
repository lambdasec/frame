"""CWE-476 NULL pointer dereference: the structural, precision-first contract.

CWE-476 detection moved off the line-regex that used to live in
`interprocedural_analyzer.py` and onto the separation-logic translator, which
reasons over the SIL/CFG. The regex fired on every dereference of an
unchecked allocation, which is the ordinary correct C idiom, so it produced
false positives on correct code (a `malloc; use; free` sequence looks identical
at the dereference to a `malloc; use` one). The structural detector instead
fires only where the pointer is PROVABLY null on the path: a branch that
confirms `p == NULL` guarding the dereference, the classic "dereference after
null check" shape of this weakness.

The obligations these tests pin down, precision weighted heaviest:

* an unchecked allocation that is dereferenced is NOT reported (it is the
  common correct idiom, and flagging it would flag correct code),
* a dereference guarded by a null check (`if(p)`, `if(p != NULL)`) is NOT
  reported,
* a pointer proved null by the guard it sits under and then dereferenced IS
  reported,
* a type declaration is never mistaken for a dereference.
"""

import pytest
from frame.sil.analyzers.interprocedural_analyzer import analyze_interprocedural
from frame.sil.scanner import scan_code


def _cwe476(code, language="c"):
    result = scan_code(code, language=language, filename="t.c")
    return [v for v in result.vulnerabilities if v.cwe_id == "CWE-476"]


class TestCWE476TypeDeclarations:
    """A pointer type declaration is not a dereference."""

    def test_no_fp_basic_type_declaration(self):
        """`int *ptr` must not read as a dereference of ptr."""
        code = '''
void foo() {
    int *ptr;
    ptr = malloc(sizeof(int));
    if (ptr != NULL) {
        *ptr = 5;
    }
}
'''
        assert _cwe476(code) == []

    def test_no_fp_struct_type_declaration(self):
        """`struct Node *ptr` under a null check is clean."""
        code = '''
struct Node {
    int data;
    struct Node *next;
};
void foo() {
    struct Node *head;
    head = malloc(sizeof(struct Node));
    if (head) {
        head->data = 10;
    }
}
'''
        assert _cwe476(code) == []

    def test_no_fp_typedef_declaration(self):
        """A typedef pointer declaration under a null check is clean."""
        code = '''
typedef struct { int x; } Point;
void foo() {
    Point *p = malloc(sizeof(Point));
    if (p != NULL) {
        p->x = 5;
    }
}
'''
        assert _cwe476(code) == []


class TestCWE476PrecisionOnUncheckedUse:
    """Dereferencing an unchecked allocation is the common correct idiom and is
    deliberately NOT reported: it cannot be told apart from correct code (a
    `malloc; use; free` sequence dereferences identically), so firing on it would
    fire on correct programs. Recall is traded for precision here on purpose."""

    def test_malloc_no_check_is_not_flagged(self):
        """`malloc` then use without a null check: no CWE-476 (would flag
        correct code, which dereferences a fresh allocation the same way)."""
        code = '''
void f() {
    int *data = malloc(sizeof(int) * 100);
    data[0] = 42;
}
'''
        assert _cwe476(code) == []

    def test_arrow_dereference_no_check_is_not_flagged(self):
        """An arrow dereference of an unchecked allocation is not reported."""
        code = '''
struct Node { int value; };
void f() {
    struct Node *node = malloc(sizeof(struct Node));
    node->value = 10;
}
'''
        assert _cwe476(code) == []

    def test_nullable_return_deref_is_not_flagged(self):
        """A dereference of a NULL-returnable call result (strstr) without a
        check is not reported: same precision trade as an unchecked malloc."""
        code = '''
void f(char *haystack, char *needle) {
    char *result = strstr(haystack, needle);
    *result = 'X';
}
'''
        assert _cwe476(code) == []


class TestCWE476NullCheckScope:
    """A dereference guarded by a null check is clean."""

    def test_null_check_suppresses_detection(self):
        """`if (ptr != NULL)` protects the dereferences inside it."""
        code = '''
void safe_use() {
    char *ptr = malloc(100);
    if (ptr != NULL) {
        *ptr = 'a';
        ptr[0] = 'b';
    }
}
'''
        assert _cwe476(code) == []

    def test_truthiness_check_suppresses(self):
        """`if (ptr)` protects the dereference inside it."""
        code = '''
void safe_use() {
    char *ptr = malloc(100);
    if (ptr) {
        *ptr = 'a';
    }
}
'''
        assert _cwe476(code) == []

    def test_early_return_guard_suppresses(self):
        """`if(!p) return;` proves p non-null afterwards, so the later
        dereference is clean."""
        code = '''
void safe_use() {
    char *ptr = malloc(100);
    if (!ptr) return;
    *ptr = 'a';
}
'''
        assert _cwe476(code) == []


class TestCWE476TruePositives:
    """A pointer proved null on the path and then dereferenced is CWE-476."""

    def test_deref_confirmed_null(self):
        """Dereference inside `if(p == NULL)` -- the pointer is provably null on
        exactly the path that dereferences it."""
        code = '''
void f() {
    int *p = 0;
    if (p == NULL) {
        int x = *p;
    }
}
'''
        assert len(_cwe476(code)) > 0

    def test_regex_layer_no_longer_emits_cwe476(self):
        """The retired line-regex in interprocedural_analyzer no longer emits any
        CWE-476; the structural translator owns this weakness now."""
        code = '''
void f() {
    int *data = malloc(sizeof(int) * 100);
    data[0] = 42;
}
'''
        vulns = analyze_interprocedural(code, "t.c")
        assert [v for v in vulns if v.cwe_id == "CWE-476"] == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
