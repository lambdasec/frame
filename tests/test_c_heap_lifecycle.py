"""The C/C++ heap-lifecycle cluster: CWE-416, CWE-415, CWE-476 and CWE-590.

Four detectors, all of them structural: they reason over the SIL/CFG and the
symbolic heap state the translator threads through it (an `allocated` map, a
`freed` set, per-pointer storage origin, and per-path null-confirmation), never
over the source text. This is the separation-logic heap model that Reynolds and
O'Hearn built for exactly C heap safety, finally wired to how the C frontend
lowers `malloc`/`free`:

* **CWE-416 (Use After Free)** fires when a dereference reads through a pointer
  that is in the `freed` set on the path. The dereference base is extracted from
  the address, so `p[i]` and `*(p + i)` are recognised as reads through `p`.
* **CWE-415 (Double Free)** fires when a deallocator is called on a pointer
  already in the `freed` set.
* **CWE-476 (NULL Pointer Dereference)** fires only where the pointer is PROVABLY
  null on the path: a branch that confirms `p == NULL` guarding the dereference,
  the classic "dereference after null check". An unchecked allocation that is
  simply dereferenced is NOT reported: it is the ordinary correct idiom and
  cannot be told apart from correct code, so firing on it would flag correct
  programs.
* **CWE-590 (Free of Non-Heap Memory)** fires when a deallocator is called on a
  pointer whose tracked storage origin is a stack array or the address of a
  local, never a heap allocation.

The negatives carry most of the weight. Each of these classes is prone to false
positives (a matched malloc/use/free is correct, a null-checked dereference is
correct, freeing a heap pointer once is correct), and a detector that fires on
correct code is worse than a miss. So the tests pin down what each rule declines
to say at least as firmly as what it says.
"""

from frame.sil import FrameScanner


def _cwes(src, language="c"):
    """Every CWE id reported for a C/C++ snippet."""
    result = FrameScanner(language=language, verify=False).scan(src, "t.c")
    return {v.cwe_id for v in result.vulnerabilities}


# =============================================================================
# CWE-416: Use After Free
# =============================================================================

def test_use_after_free_is_reported():
    # p is freed, then written through on the same straight-line path.
    src = "void f(){char*p=malloc(8);free(p);p[0]=1;}"
    assert "CWE-416" in _cwes(src)


def test_use_after_free_through_star_deref_is_reported():
    src = "void f(){int*p=malloc(4);free(p);*p=1;}"
    assert "CWE-416" in _cwes(src)


def test_matched_malloc_use_free_is_not_a_uaf():
    # The dereference happens BEFORE the free: a correct lifecycle, no UAF.
    src = "void f(){char*p=malloc(8);p[0]=1;free(p);}"
    assert "CWE-416" not in _cwes(src)


def test_free_without_later_use_is_not_a_uaf():
    src = "void f(){char*p=malloc(8);free(p);}"
    assert "CWE-416" not in _cwes(src)


def test_reassigned_after_free_then_used_is_not_a_uaf():
    # p is given a fresh allocation after the free, so the later write is through
    # live memory, not the dangling pointer.
    src = "void f(){char*p=malloc(8);free(p);p=malloc(8);p[0]=1;}"
    assert "CWE-416" not in _cwes(src)


# =============================================================================
# CWE-415: Double Free
# =============================================================================

def test_double_free_is_reported():
    src = "void f(){char*p=malloc(8);free(p);free(p);}"
    assert "CWE-415" in _cwes(src)


def test_single_free_is_not_a_double_free():
    src = "void f(){char*p=malloc(8);free(p);}"
    assert "CWE-415" not in _cwes(src)


def test_free_reallocate_free_is_not_a_double_free():
    # The pointer is re-allocated between the two frees, so the second free
    # releases live memory, not an already-freed region.
    src = "void f(){char*p=malloc(8);free(p);p=malloc(8);free(p);}"
    assert "CWE-415" not in _cwes(src)


# =============================================================================
# CWE-476: NULL Pointer Dereference
# =============================================================================

def test_deref_confirmed_null_is_reported():
    # The dereference sits on the path where `p == NULL` was just confirmed true.
    src = "void f(){int*p=0; if(p==NULL){ int x=*p; } }"
    assert "CWE-476" in _cwes(src)


def test_deref_confirmed_null_via_bang_is_reported():
    # `if(!p)` confirms p null on its true side.
    src = "void f(){int*p=0; if(!p){ int x=*p; } }"
    assert "CWE-476" in _cwes(src)


def test_unchecked_malloc_deref_is_not_reported():
    # Dereferencing a fresh, unchecked allocation is the ordinary correct idiom;
    # it is indistinguishable from correct code and must not be flagged.
    src = "void f(){char*p=malloc(8);p[0]=1;}"
    assert "CWE-476" not in _cwes(src)


def test_null_checked_then_deref_is_not_reported():
    # `if(!p) return;` proves p non-null afterwards, so the dereference is clean.
    src = "void f(){char*p=malloc(8); if(!p) return; p[0]=1;}"
    assert "CWE-476" not in _cwes(src)


def test_deref_after_nonnull_check_is_not_reported():
    src = "void f(){char*p=malloc(8); if(p!=NULL){ p[0]=1; } }"
    assert "CWE-476" not in _cwes(src)


def test_guard_that_exits_on_null_clears_nullness():
    # `if(p==NULL){exit(1);}` -- the null branch never returns, so the later
    # dereference is reached only where p is non-null.
    src = "void f(){int*p=malloc(4); if(p==NULL){ exit(1); } p[0]=1;}"
    assert "CWE-476" not in _cwes(src)


# =============================================================================
# CWE-590: Free of Non-Heap Memory
# =============================================================================

def test_free_of_stack_array_is_reported():
    src = "void f(){char b[8];free(b);}"
    assert "CWE-590" in _cwes(src)


def test_free_of_address_of_local_is_reported():
    src = "void f(){int x; int*p=&x; free(p);}"
    assert "CWE-590" in _cwes(src)


def test_free_of_heap_pointer_is_not_reported():
    src = "void f(){char*p=malloc(8);free(p);}"
    assert "CWE-590" not in _cwes(src)


def test_free_of_heap_pointer_through_temp_is_not_reported():
    # The malloc result flows through a second variable; its heap origin must
    # follow the copy so freeing it is not mistaken for a non-heap free.
    src = "void f(){char*p=malloc(8);char*q=p;free(q);}"
    assert "CWE-590" not in _cwes(src)
