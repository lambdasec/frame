"""
Regression Tests: Pure Reasoning

Tests for equality, disequality, and boolean logic in separation logic.
"""

import pytest
from test_framework import *




# Shared fixture for checker
@pytest.fixture
def checker():
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000)

def test_x_5_x_5_reflexivity(checker):
    """x = 5 |- x = 5 (reflexivity)"""
    result = checker.check(eq("x", 5), eq("x", 5))
    assert result.valid

def test_x_y_x_y(checker):
    """x = y |- x = y"""
    result = checker.check(eq("x", "y"), eq("x", "y"))
    assert result.valid

def test_x_5_y_3_x_5(checker):
    """x = 5 & y = 3 |- x = 5"""
    result = checker.check(And(eq("x", 5), eq("y", 3)), eq("x", 5))
    assert result.valid

def test_x_5_y_3_y_3(checker):
    """x = 5 & y = 3 |- y = 3"""
    result = checker.check(And(eq("x", 5), eq("y", 3)), eq("y", 3))
    assert result.valid

def test_x_5_x_5_x_5(checker):
    """x = 5 & x |-> 5 |- x |-> 5"""
    result = checker.check(And(eq("x", 5), pts("x", 5)), pts("x", 5))
    assert result.valid

def test_x_y_x_3_x_3(checker):
    """x = y & x |-> 3 |- x |-> 3"""
    result = checker.check(And(eq("x", "y"), pts("x", 3)), pts("x", 3))
    assert result.valid

def test_x_5_y_3_x_5_1(checker):
    """x |-> 5 & y = 3 |- x |-> 5"""
    result = checker.check(And(pts("x", 5), eq("y", 3)), pts("x", 5))
    assert result.valid

def test_x_5_x_5_y_3_x_5(checker):
    """(x = 5) & (x |-> 5 * y |-> 3) |- x |-> 5"""
    result = checker.check(And(eq("x", 5), sep(pts("x", 5), pts("y", 3))), pts("x", 5))
    assert result.valid

def test_true_true(checker):
    """true |- true"""
    result = checker.check(True_(), True_())
    assert result.valid

def test_true_x_5_x_5(checker):
    """true & x |-> 5 |- x |-> 5"""
    result = checker.check(And(True_(), pts("x", 5)), pts("x", 5))
    assert result.valid

def test_x_5_true_x_5(checker):
    """x |-> 5 & true |- x |-> 5"""
    result = checker.check(And(pts("x", 5), True_()), pts("x", 5))
    assert result.valid

def test_x_1_y_2_z_3_y_2(checker):
    """x = 1 & y = 2 & z = 3 |- y = 2"""
    result = checker.check(And(And(eq("x", 1), eq("y", 2)), eq("z", 3)), eq("y", 2))
    assert result.valid

def test_x_5_x_5_y_3_x_5_pure_with_frame(checker):
    """(x = 5 & x |-> 5) * y |-> 3 |- x |-> 5 (pure with frame)"""
    result = checker.check(sep(And(eq("x", 5), pts("x", 5)), pts("y", 3)), pts("x", 5))
    assert result.valid

def test_x_5_x_5(checker):
    """x != 5 |- x != 5"""
    result = checker.check(neq("x", 5), neq("x", 5))
    assert result.valid

def test_x_y_x_y_1(checker):
    """x != y |- x != y"""
    result = checker.check(neq("x", "y"), neq("x", "y"))
    assert result.valid

def test_x_0_x_5_x_5_nil_check(checker):
    """x != 0 & x |-> 5 |- x |-> 5 (nil check)"""
    result = checker.check(And(neq("x", 0), pts("x", 5)), pts("x", 5))
    assert result.valid

def test_x_5_is_satisfiable(checker):
    """x = 5 is satisfiable"""
    result = checker.is_satisfiable(eq("x", 5))
    assert result is True

def test_true_is_satisfiable(checker):
    """true is satisfiable"""
    result = checker.is_satisfiable(True_())
    assert result is True

def test_x_5_x_5_is_satisfiable(checker):
    """x = 5 & x |-> 5 IS satisfiable (self-loop is valid heap configuration)"""
    result = checker.is_satisfiable(And(eq("x", 5), pts("x", 5)))
    # After equality substitution: 5 = 5 & 5 |-> 5
    # This represents a heap cell where location 5 stores value 5
    # While unusual, this is a valid heap configuration in separation logic
    # (Note: acyclicity constraints are disabled for SAT checking to allow cyclic heaps)
    assert result is True
