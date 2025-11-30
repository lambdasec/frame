"""
Regression Tests: List Predicates

Tests for list segment (ls) and linked list (list) predicates.
"""

import pytest
from test_framework import *




# Shared fixture for checker
@pytest.fixture
def checker():
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000)

def test_ls_x_x_emp_empty_list_segment(checker):
    """ls(x, x) |- emp (empty list segment)"""
    result = checker.check(ls("x", "x"), emp())
    assert result.valid

def test_ls_x_y_ls_x_y(checker):
    """ls(x, y) |- ls(x, y)"""
    result = checker.check(ls("x", "y"), ls("x", "y"))
    assert result.valid

def test_x_y_list_y_list_x_cons(checker):
    """x |-> y * list(y) |- list(x) (cons)"""
    result = checker.check(sep(pts("x", "y"), lst("y")), lst("x"))
    assert result.valid

def test_x_y_ls_y_z_ls_x_z_segment_cons(checker):
    """x |-> y * ls(y, z) |- ls(x, z) (segment cons)"""
    result = checker.check(sep(pts("x", "y"), ls("y", "z")), ls("x", "z"))
    assert result.valid

def test_ls_transitivity_invalid_without_disequality(checker):
    """ls(x, y) * ls(y, z) |- ls(x, z) is INVALID without x != z

    Nov 2025: SL-COMP semantics require explicit disequality constraints.

    This entailment is INVALID because:
    - When x = z, antecedent ls(x,y) * ls(y,x) has non-empty heap cells
    - Consequent ls(x,x) = emp (empty heap)
    - Non-empty heap cannot entail empty heap

    This matches SL-COMP benchmark ls-vc06.sb.smt2 which expects status sat (INVALID).
    """
    result = checker.check(sep(ls("x", "y"), ls("y", "z")), ls("x", "z"))
    assert not result.valid  # INVALID without disequality proof


def test_ls_aliased_transitivity_invalid(checker):
    """ls(x, y) * ls(y, x) |- ls(x, x) is INVALID (aliased case)

    This is the counterexample case where transitivity could be unsound:
    - Antecedent ls(x,y) * ls(y,x) can have heap cells (if y != x)
    - Consequent ls(x,x) = emp (base case)
    A non-empty heap cannot entail an empty heap.

    The system correctly rejects this case even with transitivity enabled.
    """
    result = checker.check(sep(ls("x", "y"), ls("y", "x")), ls("x", "x"))
    assert not result.valid  # Should be INVALID (non-empty ⊢ emp)

def test_list_x_list_x(checker):
    """list(x) |- list(x)"""
    result = checker.check(lst("x"), lst("x"))
    assert result.valid

def test_x_y_list_y_z_w_list_x_with_frame(checker):
    """x |-> y * list(y) * z |-> w |- list(x) (with frame)

    With affine semantics (default for bug finding), extra heap can be dropped.
    The cons construction matches and z |-> w is dropped as frame.
    """
    result = checker.check(sep(pts("x", "y"), lst("y"), pts("z", "w")), lst("x"))
    assert result.valid  # Affine semantics: extra heap can be dropped

def test_list_x_list_y_list_x_list_y_two_lists(checker):
    """list(x) * list(y) |- list(x) * list(y) (two lists)"""
    result = checker.check(sep(lst("x"), lst("y")), sep(lst("x"), lst("y")))
    assert result.valid

def test_list_x_list_y_list_x_frame_second_list(checker):
    """list(x) * list(y) |- list(x) (frame second list)

    NOTE (Nov 2025): In exact semantics (SL-COMP), this is INVALID because
    we cannot drop list(y). Frame rule only applies when frame appears on BOTH sides.
    """
    result = checker.check(sep(lst("x"), lst("y")), lst("x"))
    assert not result.valid  # INVALID - extra heap cannot be dropped

def test_x_y_y_z_ls_z_nil_ls_x_nil_2_element(checker):
    """x |-> y * y |-> z * ls(z, nil) |- ls(x, nil) (2-element)"""
    result = checker.check(sep(pts("x", "y"), pts("y", "z"), ls("z", "nil")), ls("x", "nil"))
    assert result.valid

def test_list_x_list_x_list_y_invalid_missing_list(checker):
    """list(x) |- list(x) * list(y) (INVALID - missing list)"""
    result = checker.check(lst("x"), sep(lst("x"), lst("y")))
    assert not result.valid

def test_ls_x_y_ls_x_z_invalid_different_endpoints(checker):
    """ls(x, y) |- ls(x, z) (INVALID - different endpoints)"""
    result = checker.check(ls("x", "y"), ls("x", "z"))
    assert not result.valid

def test_emp_list_x_invalid_cannot_create_list(checker):
    """emp |- list(x) (INVALID - cannot create list)"""
    result = checker.check(emp(), lst("x"))
    assert not result.valid

def test_ls_x_y_emp_ls_x_y(checker):
    """ls(x, y) * emp |- ls(x, y)"""
    result = checker.check(sep(ls("x", "y"), emp()), ls("x", "y"))
    assert result.valid

def test_list_x_is_satisfiable(checker):
    """list(x) is satisfiable"""
    result = checker.is_satisfiable(lst("x"))
    assert result is True

def test_ls_x_y_is_satisfiable(checker):
    """ls(x, y) is satisfiable"""
    result = checker.is_satisfiable(ls("x", "y"))
    assert result is True
