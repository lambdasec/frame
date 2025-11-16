"""
Regression Tests: Frame Rule

The frame rule is a key principle in separation logic:
If P |- Q, then P * R |- Q * R

These tests verify frame-based reasoning.
"""

import pytest
from test_framework import *




# Shared fixture for checker
@pytest.fixture
def checker():
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000)

def test_x_5_y_3_x_5_basic_frame(checker):
    """x |-> 5 * y |-> 3 |- x |-> 5 (basic frame)"""
    result = checker.check(sep(pts("x", 5), pts("y", 3)), pts("x", 5))
    assert result.valid

def test_x_5_y_3_y_3_frame_on_other_side(checker):
    """x |-> 5 * y |-> 3 |- y |-> 3 (frame on other side)"""
    result = checker.check(sep(pts("x", 5), pts("y", 3)), pts("y", 3))
    assert result.valid

def test_x_y_z_x_frame_y_z(checker):
    """x * y * z |- x (frame: y * z)"""
    result = checker.check(sep(pts("x", 1), pts("y", 2), pts("z", 3)), pts("x", 1))
    assert result.valid

def test_x_y_z_y_z_frame_x(checker):
    """x * y * z |- y * z (frame: x)"""
    result = checker.check(sep(pts("x", 1), pts("y", 2), pts("z", 3)), sep(pts("y", 2), pts("z", 3)))
    assert result.valid

def test_x_y_z_x_z_frame_y(checker):
    """x * y * z |- x * z (frame: y)"""
    result = checker.check(sep(pts("x", 1), pts("y", 2), pts("z", 3)), sep(pts("x", 1), pts("z", 3)))
    assert result.valid

def test_x_5_emp_x_5(checker):
    """x |-> 5 * emp |- x |-> 5"""
    result = checker.check(sep(pts("x", 5), emp()), pts("x", 5))
    assert result.valid

def test_x_y_emp_x(checker):
    """x * y * emp |- x"""
    result = checker.check(sep(pts("x", 5), pts("y", 3), emp()), pts("x", 5))
    assert result.valid

def test_nested_frame_x_y_z_w_x_z(checker):
    """Nested frame: (x * y) * (z * w) |- x * z"""
    result = checker.check(sep(sep(pts("x", 1), pts("y", 2)), sep(pts("z", 3), pts("w", 4))), sep(pts("x", 1), pts("z", 3)))
    assert result.valid

def test_frame_preservation_p_q_p_q(checker):
    """Frame preservation: P * Q |- P * Q"""
    result = checker.check(sep(pts("x", 5), pts("y", 3)), sep(pts("x", 5), pts("y", 3)))
    assert result.valid

def test_frame_with_multi_field_x_a_b_y_x_a_b(checker):
    """Frame with multi-field: x |-> (a, b) * y |- x |-> (a, b)"""
    result = checker.check(sep(pts("x", ["a", "b"]), pts("y", "c")), pts("x", ["a", "b"]))
    assert result.valid

def test_large_frame_5_vars_1_var(checker):
    """Large frame: 5 vars |- 1 var"""
    result = checker.check(sep(pts("a", 1), pts("b", 2), pts("c", 3), pts("d", 4), pts("e", 5)), pts("c", 3))
    assert result.valid

def test_large_frame_5_vars_3_vars(checker):
    """Large frame: 5 vars |- 3 vars"""
    result = checker.check(sep(pts("a", 1), pts("b", 2), pts("c", 3), pts("d", 4), pts("e", 5)), sep(pts("b", 2), pts("d", 4), pts("e", 5)))
    assert result.valid
