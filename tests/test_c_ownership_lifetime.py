"""Phase 2 of the C/C++ memory-safety cluster: ownership and lifetime.

Three structural detectors, all reasoning over the SIL IR and the symbolic heap
state the translator threads through the CFG, never over source text:

* **CWE-401 (Memory Leak)** is separation-logic frame/ownership reasoning. A heap
  allocation is an owned resource; it leaks only if that ownership is DROPPED --
  the owning pointer goes out of scope (function exit) or is overwritten, on a
  path where the allocation was neither released (freed) nor transferred out
  (returned, stored to a caller-visible location, or passed to another function).
  The escape analysis is deliberately conservative: when ownership cannot be
  shown to be dropped, nothing is reported. Correct ownership-transfer code must
  never be flagged, so the negatives here carry the weight.
* **CWE-762 (Mismatched Memory Routine)** tracks the allocator KIND per pointer
  (malloc-family / new / new[]) and checks it against the shape of the
  deallocator (free / delete / delete[]). `free` on a `new`, `delete` on a
  `malloc`, `delete` on a `new[]`, and `delete[]` on a `new` are each a provable
  mismatch. `new`/`delete` are C++, so these run under the C++ frontend.
* **CWE-562 (Return of Stack Address)** fires when a Return hands back the address
  of a local: `&x` for a declared local, a fixed local array that decays to a
  pointer, or a pointer earlier set to the address of a local. Returning a heap
  pointer or a parameter is fine.

As in Phase 1, the negatives dominate: each rule declines to fire on the correct
idiom it is most likely to be confused by (an ownership transfer for the leak, a
matched allocator/deallocator pair for the mismatch, a returned heap pointer for
the stack-address check).
"""

from frame.sil import FrameScanner


def _cwes(src, language="c"):
    """Every CWE id reported for a C/C++ snippet."""
    result = FrameScanner(language=language, verify=False).scan(src, "t.c")
    return {v.cwe_id for v in result.vulnerabilities}


# =============================================================================
# CWE-401: Memory Leak (positives)
# =============================================================================

def test_alloc_then_return_void_is_a_leak():
    # p owns the allocation and the function returns without releasing it.
    src = "void f(){char*p=malloc(8);return;}"
    assert "CWE-401" in _cwes(src)


def test_alloc_then_fall_off_end_is_a_leak():
    # No explicit return: the owning pointer still goes out of scope unreleased.
    src = "void f(){char*p=malloc(8);}"
    assert "CWE-401" in _cwes(src)


def test_reassignment_loses_first_allocation():
    # The first allocation is overwritten before it is freed or handed off; the
    # second is freed. The first leaks.
    src = "void f(){char*p=malloc(8);p=malloc(8);free(p);}"
    assert "CWE-401" in _cwes(src)


def test_leak_through_calloc_is_reported():
    src = "void f(){char*p=(char*)calloc(4,8);return;}"
    assert "CWE-401" in _cwes(src)


# =============================================================================
# CWE-401: Memory Leak (negatives -- ownership transfer, weighted heaviest)
# =============================================================================

def test_freed_before_exit_is_not_a_leak():
    src = "void f(){char*p=malloc(8);free(p);}"
    assert "CWE-401" not in _cwes(src)


def test_returned_pointer_is_not_a_leak():
    # Ownership transfers to the caller. This is the exact case the old regex
    # false-positived on; the structural detector must not.
    src = "char* f(){char*p=malloc(8);return p;}"
    assert "CWE-401" not in _cwes(src)


def test_stored_to_out_parameter_is_not_a_leak():
    # `*o = p` hands the allocation to a caller-visible location.
    src = "void f(char**o){char*p=malloc(8);*o=p;}"
    assert "CWE-401" not in _cwes(src)


def test_passed_to_another_function_is_not_a_leak():
    # An unknown callee may take ownership, so passing the pointer is an escape.
    src = "void f(){char*p=malloc(8);use(p);}"
    assert "CWE-401" not in _cwes(src)


def test_aliased_pointer_that_escapes_is_not_a_leak():
    # The allocation is aliased to q, which is then passed out; the shared
    # allocation escapes and must not be reported against p.
    src = "void f(){char*p=malloc(8);char*q=p;use(q);}"
    assert "CWE-401" not in _cwes(src)


def test_aliased_pointer_that_is_freed_is_not_a_leak():
    # Freeing an alias releases the shared allocation; no leak.
    src = "void f(){char*p=malloc(8);char*q=p;free(q);}"
    assert "CWE-401" not in _cwes(src)


def test_null_checked_early_return_is_not_a_leak():
    # On the early-return path the allocation failed (p is NULL), so there is
    # nothing to leak; on the other path it is freed.
    src = "void f(){char*p=malloc(8); if(!p) return; free(p);}"
    assert "CWE-401" not in _cwes(src)


def test_field_store_is_not_a_leak():
    # Storing the allocation into a struct field the caller reaches is a transfer.
    src = "void f(struct S*s){char*p=malloc(8); s->buf=p;}"
    assert "CWE-401" not in _cwes(src)


def test_new_then_matching_delete_is_not_a_leak():
    src = "void f(){int*p=new int;delete p;}"
    assert "CWE-401" not in _cwes(src, language="cpp")


def test_reallocated_then_freed_is_not_a_leak():
    # realloc replaces the allocation p owns; the result is still owned by p and
    # then freed, so nothing leaks.
    src = "void f(){char*p=malloc(8);p=(char*)realloc(p,16);free(p);}"
    assert "CWE-401" not in _cwes(src)


# =============================================================================
# CWE-762: Mismatched Memory Routine (positives, C++)
# =============================================================================

def test_free_on_new_is_mismatch():
    src = "void f(){int*p=new int;free(p);}"
    assert "CWE-762" in _cwes(src, language="cpp")


def test_delete_on_malloc_is_mismatch():
    src = "void f(){int*p=(int*)malloc(8);delete p;}"
    assert "CWE-762" in _cwes(src, language="cpp")


def test_delete_on_new_array_is_mismatch():
    src = "void f(){int*p=new int[8];delete p;}"
    assert "CWE-762" in _cwes(src, language="cpp")


def test_delete_array_on_new_is_mismatch():
    src = "void f(){int*p=new int;delete[] p;}"
    assert "CWE-762" in _cwes(src, language="cpp")


# =============================================================================
# CWE-762: Mismatched Memory Routine (negatives -- matched pairs)
# =============================================================================

def test_free_on_malloc_is_not_a_mismatch():
    src = "void f(){int*p=(int*)malloc(8);free(p);}"
    assert "CWE-762" not in _cwes(src, language="cpp")


def test_delete_on_new_is_not_a_mismatch():
    src = "void f(){int*p=new int;delete p;}"
    assert "CWE-762" not in _cwes(src, language="cpp")


def test_delete_array_on_new_array_is_not_a_mismatch():
    src = "void f(){int*p=new int[8];delete[] p;}"
    assert "CWE-762" not in _cwes(src, language="cpp")


def test_matched_malloc_free_is_not_a_mismatch_in_c():
    src = "void f(){int*p=(int*)malloc(8);free(p);}"
    assert "CWE-762" not in _cwes(src)


# =============================================================================
# CWE-562: Return of Stack Address (positives)
# =============================================================================

def test_return_of_stack_array_is_reported():
    src = "char* f(){char b[8];return b;}"
    assert "CWE-562" in _cwes(src)


def test_return_of_address_of_local_is_reported():
    src = "int* f(){int x; return &x;}"
    assert "CWE-562" in _cwes(src)


def test_return_of_pointer_to_local_is_reported():
    # p was set to the address of a local; returning it dangles.
    src = "int* f(){int x; int*p=&x; return p;}"
    assert "CWE-562" in _cwes(src)


def test_return_of_string_initialized_array_is_reported():
    # `char s[] = "..."` has no written size but a size the initializer fixes; it
    # is still a stack array that dangles when returned.
    src = 'const char* f(){char s[]="hi";return s;}'
    assert "CWE-562" in _cwes(src)


# =============================================================================
# CWE-562: Return of Stack Address (negatives)
# =============================================================================

def test_return_of_heap_pointer_is_not_a_stack_address():
    src = "char* f(){char*p=malloc(8);return p;}"
    assert "CWE-562" not in _cwes(src)


def test_return_of_parameter_is_not_a_stack_address():
    src = "char* f(char*p){return p;}"
    assert "CWE-562" not in _cwes(src)


def test_return_null_is_not_a_stack_address():
    src = "char* f(){return 0;}"
    assert "CWE-562" not in _cwes(src)


def test_return_of_heap_pointer_through_alias_is_not_a_stack_address():
    src = "char* f(){char*p=malloc(8);char*q=p;return q;}"
    assert "CWE-562" not in _cwes(src)
