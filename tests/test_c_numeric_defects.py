"""Phase 3 of the C/C++ cluster: numeric and value defects.

Two structural detectors, both reasoning over the SIL IR and the symbolic state
the translator threads through the CFG, never over source text:

* **CWE-457 (Use of Uninitialized Variable)** is reaching-definition dataflow. A
  declared local starts with NO reaching definition; a real (non-declaration)
  write, an address-of (`&x`), or passing it to a function marks it defined. A
  scalar value-read of a local that still has no reaching definition on the path
  is the defect. The set is merged by UNION at joins (the intersection of the
  dual "initialized" sets), so a variable defined on only one branch is still
  uninitialized where the branches meet.
* **CWE-369 (Divide by Zero)** is a Z3 query. A division or modulo is flagged only
  when its divisor is PROVABLY zero on the path: `divisor != 0` is unsatisfiable
  given the accumulated path condition. A literal 0, a variable the path pins to
  0, and `x - x` qualify; an unconstrained `a / b` keeps `b != 0` satisfiable and
  is never flagged, because every program divides and firing on an ordinary
  division would be a catastrophic false positive.

As in Phases 1 and 2 the negatives carry the weight. Each rule declines to fire
on the correct idiom it is most likely to be confused by: a variable written on
all paths or handed to a function for CWE-457, and a guarded, opaque, or
nonzero-constant divisor for CWE-369.
"""

from frame.sil import FrameScanner


def _cwes(src, language="c"):
    """Every CWE id reported for a C/C++ snippet."""
    result = FrameScanner(language=language, verify=False).scan(src, "t.c")
    return {v.cwe_id for v in result.vulnerabilities}


# =============================================================================
# CWE-457: Use of Uninitialized Variable (positives)
# =============================================================================

def test_read_of_declared_local_is_reported():
    src = "int f(){int x; return x;}"
    assert "CWE-457" in _cwes(src)


def test_uninitialized_on_the_else_path_is_reported():
    # x is written only on the if-branch; on the else path it reaches the return
    # with no definition, and the join keeps it uninitialized.
    src = "int f(int c){int x; if(c) x=1; return x;}"
    assert "CWE-457" in _cwes(src)


def test_uninitialized_used_in_arithmetic_is_reported():
    src = "int f(){int x; int y=x+1; return y;}"
    assert "CWE-457" in _cwes(src)


def test_dereference_of_uninitialized_pointer_is_reported():
    src = "int f(){int*p; return *p;}"
    assert "CWE-457" in _cwes(src)


# =============================================================================
# CWE-457: Use of Uninitialized Variable (negatives -- weighted heaviest)
# =============================================================================

def test_initialized_at_declaration_is_not_reported():
    src = "int f(){int x=3; return x;}"
    assert "CWE-457" not in _cwes(src)


def test_written_before_read_on_all_paths_is_not_reported():
    src = "int f(){int x; x=5; return x;}"
    assert "CWE-457" not in _cwes(src)


def test_written_on_both_branches_is_not_reported():
    # A definition on every incoming path means the join has a reaching
    # definition, so the later read is clean.
    src = "int f(int c){int x; if(c) x=1; else x=2; return x;}"
    assert "CWE-457" not in _cwes(src)


def test_parameter_read_is_not_reported():
    # Function parameters always have a reaching definition.
    src = "int f(int p){return p;}"
    assert "CWE-457" not in _cwes(src)


def test_address_passed_to_function_then_read_is_not_reported():
    # `&x` handed to a callee may initialize x, so a later read is not flagged.
    src = "void g(int*); int f(){int x; g(&x); return x;}"
    assert "CWE-457" not in _cwes(src)


def test_scanf_into_address_then_read_is_not_reported():
    src = "int f(){int x; scanf(\"%d\", &x); return x;}"
    assert "CWE-457" not in _cwes(src)


def test_bare_variable_passed_to_function_then_read_is_not_reported():
    # A bare-variable argument may be a C++ reference out-parameter, so passing it
    # is treated as a possible initialization rather than a use.
    src = "void g(int); int f(){int x; g(x); return x;}"
    assert "CWE-457" not in _cwes(src)


def test_struct_field_written_then_field_read_is_not_reported():
    # The aggregate base is not tracked by the scalar model; writing a field then
    # reading it must not be mistaken for an uninitialized read.
    src = "struct S{int a;}; int f(){struct S s; s.a=1; return s.a;}"
    assert "CWE-457" not in _cwes(src)


def test_array_element_written_then_read_is_not_reported():
    src = "int f(){int b[4]; b[0]=1; return b[0];}"
    assert "CWE-457" not in _cwes(src)


def test_python_local_is_not_perturbed():
    # The detector is C/C++ only; a Python read of a name must never be flagged
    # CWE-457 by this pass.
    src = "def f():\n    x = 3\n    return x\n"
    assert "CWE-457" not in _cwes(src, language="python")


# =============================================================================
# CWE-369: Divide by Zero (positives)
# =============================================================================

def test_division_by_zero_constant_is_reported():
    src = "int f(int a){int z=0; return a/z;}"
    assert "CWE-369" in _cwes(src)


def test_modulo_by_literal_zero_is_reported():
    src = "int f(int a){return a%0;}"
    assert "CWE-369" in _cwes(src)


def test_division_by_cancelling_expression_is_reported():
    # x - x is zero for every x, so the divisor is provably zero.
    src = "int f(int a,int x){return a/(x-x);}"
    assert "CWE-369" in _cwes(src)


def test_division_inside_zero_confirming_guard_is_reported():
    # On the branch where b == 0 was confirmed, dividing by b is provably zero.
    src = "int f(int a,int b){if(b==0){return a/b;} return 0;}"
    assert "CWE-369" in _cwes(src)


# =============================================================================
# CWE-369: Divide by Zero (negatives -- weighted heaviest)
# =============================================================================

def test_opaque_divisor_is_not_reported():
    # The critical negative: an ordinary a / b with an unconstrained b divides
    # fine on almost every input and must never be flagged.
    src = "int f(int a,int b){return a/b;}"
    assert "CWE-369" not in _cwes(src)


def test_guarded_nonzero_divisor_is_not_reported():
    src = "int f(int a,int b){if(b!=0)return a/b;return 0;}"
    assert "CWE-369" not in _cwes(src)


def test_nonzero_constant_divisor_is_not_reported():
    src = "int f(int a){int z=2; return a/z;}"
    assert "CWE-369" not in _cwes(src)


def test_literal_nonzero_divisor_is_not_reported():
    src = "int f(int a){return a/2;}"
    assert "CWE-369" not in _cwes(src)


def test_modulo_by_opaque_divisor_is_not_reported():
    src = "int f(int a,int b){return a%b;}"
    assert "CWE-369" not in _cwes(src)


def test_product_of_two_variables_divisor_is_not_reported():
    # n * k is not provably zero (n, k unconstrained), so no flag.
    src = "int f(int a,int n,int k){return a/(n*k);}"
    assert "CWE-369" not in _cwes(src)


def test_python_division_is_not_perturbed():
    src = "def f(a, b):\n    return a / b\n"
    assert "CWE-369" not in _cwes(src, language="python")
