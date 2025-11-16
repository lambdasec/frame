"""
Regression Tests: Basic Spatial Formulas

Tests for emp, points-to, and separating conjunction.
"""

import pytest
from test_framework import *


# Shared fixture for checker
@pytest.fixture
def checker():
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000)


# ========== Empty Heap Tests ==========

def test_emp_reflexivity(checker):
    """emp |- emp (reflexivity)"""
    result = checker.check(emp(), emp())
    assert result.valid


def test_emp_idempotent_left(checker):
    """emp * emp |- emp (emp is idempotent)"""
    result = checker.check(sep(emp(), emp()), emp())
    assert result.valid


def test_emp_idempotent_right(checker):
    """emp |- emp * emp"""
    result = checker.check(emp(), sep(emp(), emp()))
    assert result.valid


# ========== Points-To Reflexivity ==========

def test_pto_const_reflexivity(checker):
    """x |-> 5 |- x |-> 5"""
    result = checker.check(pts("x", 5), pts("x", 5))
    assert result.valid


def test_pto_var_reflexivity(checker):
    """x |-> y |- x |-> y"""
    result = checker.check(pts("x", "y"), pts("x", "y"))
    assert result.valid


# ========== Multi-field Points-To ==========

def test_pto_multifield_two(checker):
    """x |-> (y, z) |- x |-> (y, z)"""
    result = checker.check(pts("x", ["y", "z"]), pts("x", ["y", "z"]))
    assert result.valid


def test_pto_multifield_three(checker):
    """x |-> (1, 2, 3) |- x |-> (1, 2, 3)"""
    result = checker.check(pts("x", [1, 2, 3]), pts("x", [1, 2, 3]))
    assert result.valid


# ========== Separating Conjunction Commutativity ==========

def test_sepconj_commutativity(checker):
    """x |-> 5 * y |-> 3 |- y |-> 3 * x |-> 5 (commutativity)"""
    result = checker.check(
        sep(pts("x", 5), pts("y", 3)),
        sep(pts("y", 3), pts("x", 5))
    )
    assert result.valid


# ========== Separating Conjunction Associativity ==========

def test_sepconj_associativity(checker):
    """(x |-> 1 * y |-> 2) * z |-> 3 |- x |-> 1 * (y |-> 2 * z |-> 3) (associativity)"""
    result = checker.check(
        sep(sep(pts("x", 1), pts("y", 2)), pts("z", 3)),
        sep(pts("x", 1), sep(pts("y", 2), pts("z", 3)))
    )
    assert result.valid


# ========== Separating Conjunction with emp ==========

def test_sepconj_emp_right_to_plain(checker):
    """x |-> 5 * emp |- x |-> 5 (emp is neutral)"""
    result = checker.check(sep(pts("x", 5), emp()), pts("x", 5))
    assert result.valid


def test_sepconj_plain_to_emp_right(checker):
    """x |-> 5 |- x |-> 5 * emp"""
    result = checker.check(pts("x", 5), sep(pts("x", 5), emp()))
    assert result.valid


def test_sepconj_emp_left_to_plain(checker):
    """emp * x |-> 5 |- x |-> 5"""
    result = checker.check(sep(emp(), pts("x", 5)), pts("x", 5))
    assert result.valid


# ========== Multiple Variables ==========

def test_three_variables_reflexivity(checker):
    """x * y * z |- x * y * z (three variables)"""
    result = checker.check(
        sep(pts("x", 1), pts("y", 2), pts("z", 3)),
        sep(pts("x", 1), pts("y", 2), pts("z", 3))
    )
    assert result.valid


def test_four_variables_reordering(checker):
    """Four variables with reordering"""
    result = checker.check(
        sep(pts("x", 1), pts("y", 2), pts("z", 3), pts("w", 4)),
        sep(pts("w", 4), pts("z", 3), pts("y", 2), pts("x", 1))
    )
    assert result.valid


# ========== Satisfiability Tests ==========

def test_pto_satisfiable(checker):
    """x |-> 5 is satisfiable"""
    result = checker.is_satisfiable(pts("x", 5))
    assert result is True


def test_emp_satisfiable(checker):
    """emp is satisfiable"""
    result = checker.is_satisfiable(emp())
    assert result is True


def test_sepconj_satisfiable(checker):
    """x |-> 5 * y |-> 3 is satisfiable"""
    result = checker.is_satisfiable(sep(pts("x", 5), pts("y", 3)))
    assert result is True
