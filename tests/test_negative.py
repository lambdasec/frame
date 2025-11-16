"""
Regression Tests: Negative Cases

Tests for entailments that SHOULD NOT hold.
These are critical for ensuring the checker is sound.
"""

import pytest
from test_framework import *




# Shared fixture for checker
@pytest.fixture
def checker():
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000)

def test_x_5_x_3_invalid_wrong_value(checker):
    """x |-> 5 |- x |-> 3 (INVALID - wrong value)"""
    result = checker.check(pts("x", 5), pts("x", 3))
    assert not result.valid

def test_x_5_y_5_invalid_wrong_variable(checker):
    """x |-> 5 |- y |-> 5 (INVALID - wrong variable)"""
    result = checker.check(pts("x", 5), pts("y", 5))
    assert not result.valid

def test_x_5_x_5_y_3_invalid_missing_heap(checker):
    """x |-> 5 |- x |-> 5 * y |-> 3 (INVALID - missing heap)"""
    result = checker.check(pts("x", 5), sep(pts("x", 5), pts("y", 3)))
    assert not result.valid

def test_emp_x_5_invalid_cannot_create_heap(checker):
    """emp |- x |-> 5 (INVALID - cannot create heap)"""
    result = checker.check(emp(), pts("x", 5))
    assert not result.valid

def test_x_x_y_z_invalid_missing_two_cells(checker):
    """x |- x * y * z (INVALID - missing two cells)"""
    result = checker.check(pts("x", 5), sep(pts("x", 5), pts("y", 3), pts("z", 7)))
    assert not result.valid

def test_x_5_x_5_3_invalid_wrong_field_count(checker):
    """x |-> 5 |- x |-> (5, 3) (INVALID - wrong field count)"""
    result = checker.check(pts("x", 5), pts("x", [5, 3]))
    assert not result.valid

def test_x_5_3_x_5_invalid_field_count_mismatch(checker):
    """x |-> (5, 3) |- x |-> 5 (INVALID - field count mismatch)"""
    result = checker.check(pts("x", [5, 3]), pts("x", 5))
    assert not result.valid

def test_x_5_x_5_x_5_invalid_missing_pure_constraint(checker):
    """x |-> 5 |- x = 5 & x |-> 5 (INVALID - missing pure constraint)"""
    result = checker.check(pts("x", 5), And(eq("x", 5), pts("x", 5)))
    assert not result.valid

def test_y_3_x_5_y_3_invalid_missing_x(checker):
    """y |-> 3 |- x |-> 5 * y |-> 3 (INVALID - missing x)"""
    result = checker.check(pts("y", 3), sep(pts("x", 5), pts("y", 3)))
    assert not result.valid

def test_x_y_x_y_z_invalid_missing_z(checker):
    """x * y |- x * y * z (INVALID - missing z)"""
    result = checker.check(sep(pts("x", 5), pts("y", 3)), sep(pts("x", 5), pts("y", 3), pts("z", 7)))
    assert not result.valid

def test_x_y_x_z_invalid_different_variables(checker):
    """x |-> y |- x |-> z (INVALID - different variables)"""
    result = checker.check(pts("x", "y"), pts("x", "z"))
    assert not result.valid

def test_x_y_x_y_z_invalid(checker):
    """(x * y) |- (x * y * z) (INVALID)"""
    result = checker.check(sep(pts("x", 1), pts("y", 2)), sep(pts("x", 1), pts("y", 2), pts("z", 3)))
    assert not result.valid

def test_x_5_x_3_is_unsatisfiable_disjointness(checker):
    """x |-> 5 * x |-> 3 is UNSATISFIABLE (disjointness)"""
    result = checker.is_satisfiable(sep(pts("x", 5), pts("x", 3)))
    assert result is False

def test_x_5_x_5_is_unsatisfiable_same_location(checker):
    """x |-> 5 * x |-> 5 is UNSATISFIABLE (same location)"""
    result = checker.is_satisfiable(sep(pts("x", 5), pts("x", 5)))
    assert result is False

def test_false_is_unsatisfiable(checker):
    """false is UNSATISFIABLE"""
    result = checker.is_satisfiable(False_())
    assert result is False

def test_x_5_x_3_is_unsatisfiable_contradiction(checker):
    """x = 5 & x = 3 is UNSATISFIABLE (contradiction)"""
    result = checker.is_satisfiable(And(eq("x", 5), eq("x", 3)))
    assert result is False
