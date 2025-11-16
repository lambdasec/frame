"""
Regression Tests: Edge Cases

Tests for corner cases, boundary conditions, and unusual inputs.
"""

import pytest
from test_framework import *


# Shared fixture for checker
@pytest.fixture
def checker():
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000)


# Module-level test data (reusable across tests)
def make_ten_vars():
    """10 variables for large heap tests"""
    return sep(
        pts("a", 1), pts("b", 2), pts("c", 3), pts("d", 4), pts("e", 5),
        pts("f", 6), pts("g", 7), pts("h", 8), pts("i", 9), pts("j", 10)
    )


def make_deeply_nested():
    """Deeply nested separating conjunction"""
    return sep(sep(sep(sep(pts("x", 1), pts("y", 2)), pts("z", 3)), pts("w", 4)), pts("v", 5))


def make_complex_formula():
    """Complex formula with mixed pure and spatial"""
    return sep(
        And(eq("x", 5), pts("x", 5)),
        And(eq("y", 3), pts("y", 3)),
        tree("z")
    )


def make_large_heap():
    """Large heap with 8 cells"""
    return sep(
        pts("a", 1), pts("b", 2), pts("c", 3), pts("d", 4),
        pts("e", 5), pts("f", 6), pts("g", 7), pts("h", 8)
    )


# ========== Empty Heap Edge Cases ==========

def test_emp_triple(checker):
    """emp * emp * emp |- emp"""
    result = checker.check(sep(emp(), emp(), emp()), emp())
    assert result.valid


def test_emp_quad_right(checker):
    """emp |- emp * emp * emp * emp"""
    result = checker.check(emp(), sep(emp(), emp(), emp(), emp()))
    assert result.valid


# ========== Single Variable Multiple Occurrences ==========

def test_pto_with_multiple_emp(checker):
    """x |-> 5 |- x |-> 5 * emp * emp"""
    result = checker.check(pts("x", 5), sep(pts("x", 5), emp(), emp()))
    assert result.valid


# ========== Many Variables ==========

def test_ten_variables_reflexivity(checker):
    """10 variables |- 10 variables"""
    ten_vars = make_ten_vars()
    result = checker.check(ten_vars, ten_vars)
    assert result.valid


def test_ten_variables_large_frame(checker):
    """10 variables |- 1 variable (large frame)"""
    ten_vars = make_ten_vars()
    result = checker.check(ten_vars, pts("e", 5))
    assert result.valid


# ========== Large Multi-Field Structures ==========

def test_five_field_points_to(checker):
    """x |-> (a, b, c, d, e) |- x |-> (a, b, c, d, e) (5 fields)"""
    result = checker.check(
        pts("x", ["a", "b", "c", "d", "e"]),
        pts("x", ["a", "b", "c", "d", "e"])
    )
    assert result.valid


# ========== Deeply Nested Separating Conjunctions ==========

def test_deeply_nested_sepconj(checker):
    """Deeply nested sepconj |- single var"""
    deeply_nested = make_deeply_nested()
    result = checker.check(deeply_nested, pts("x", 1))
    assert result.valid


# ========== Mixed Pure and Spatial ==========

def test_complex_pure_spatial(checker):
    """Complex pure + spatial |- spatial"""
    result = checker.check(
        And(And(eq("x", 5), eq("y", 3)), sep(pts("x", 5), pts("y", 3))),
        pts("x", 5)
    )
    assert result.valid


# ========== Reflexivity Edge Cases ==========

def test_complex_formula_reflexivity(checker):
    """Complex formula |- itself (reflexivity)"""
    complex_formula = make_complex_formula()
    result = checker.check(complex_formula, complex_formula)
    assert result.valid


# ========== True/False Edge Cases ==========

def test_true_and_true(checker):
    """true & true |- true"""
    result = checker.check(And(True_(), True_()), True_())
    assert result.valid


def test_true_with_pto(checker):
    """true & x |-> 5 & true |- x |-> 5"""
    result = checker.check(
        And(And(True_(), pts("x", 5)), True_()),
        pts("x", 5)
    )
    assert result.valid


def test_false_implies_anything(checker):
    """false |- x |-> 5 (false implies anything)"""
    result = checker.check(False_(), pts("x", 5))
    assert result.valid


def test_true_false_invalid(checker):
    """true |- false (should be invalid)"""
    result = checker.check(True_(), False_())
    assert not result.valid


# ========== Satisfiability Edge Cases ==========

def test_true_is_satisfiable(checker):
    """true is satisfiable"""
    result = checker.is_satisfiable(True_())
    assert result is True


def test_large_heap_is_satisfiable(checker):
    """Large heap (8 cells) is satisfiable"""
    large_heap = make_large_heap()
    result = checker.is_satisfiable(large_heap)
    assert result is True
