"""
Regression Tests: Tree Predicates

Tests for binary tree predicates.
"""

import pytest
from test_framework import *




# Shared fixture for checker
@pytest.fixture
def checker():
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000)

def test_tree_x_tree_x(checker):
    """tree(x) |- tree(x)"""
    result = checker.check(tree("x"), tree("x"))
    assert result.valid

def test_x_l_r_tree_l_tree_r_tree_x_construction(checker):
    """x |-> (l, r) * tree(l) * tree(r) |- tree(x) (construction)"""
    result = checker.check(sep(pts("x", ["l", "r"]), tree("l"), tree("r")), tree("x"))
    assert result.valid

def test_x_l_r_tree_l_tree_r_y_z_tree_x_with_frame(checker):
    """x |-> (l, r) * tree(l) * tree(r) * y |-> z |- tree(x) (with frame)"""
    result = checker.check(sep(pts("x", ["l", "r"]), tree("l"), tree("r"), pts("y", "z")), tree("x"))
    assert result.valid

def test_tree_x_tree_y_tree_x_tree_y_two_trees(checker):
    """tree(x) * tree(y) |- tree(x) * tree(y) (two trees)"""
    result = checker.check(sep(tree("x"), tree("y")), sep(tree("x"), tree("y")))
    assert result.valid

def test_tree_x_tree_y_tree_x_frame_second_tree(checker):
    """tree(x) * tree(y) |- tree(x) (frame second tree)"""
    result = checker.check(sep(tree("x"), tree("y")), tree("x"))
    assert result.valid

def test_tree_x_tree_y_tree_y_frame_first_tree(checker):
    """tree(x) * tree(y) |- tree(y) (frame first tree)"""
    result = checker.check(sep(tree("x"), tree("y")), tree("y"))
    assert result.valid

def test_explicit_tree_decomposition(checker):
    """Explicit tree decomposition"""
    result = checker.check(sep(pts("x", ["l", "r"]), tree("l"), tree("r")), tree("x"))
    assert result.valid

def test_tree_x_tree_x_tree_y_invalid_missing_tree(checker):
    """tree(x) |- tree(x) * tree(y) (INVALID - missing tree)"""
    result = checker.check(tree("x"), sep(tree("x"), tree("y")))
    assert not result.valid

def test_emp_tree_x_invalid_cannot_create_tree(checker):
    """emp |- tree(x) (INVALID - cannot create tree)"""
    result = checker.check(emp(), tree("x"))
    assert not result.valid

def test_x_l_r_tree_x_invalid_missing_subtrees(checker):
    """x |-> (l, r) |- tree(x) (INVALID - missing subtrees)"""
    result = checker.check(pts("x", ["l", "r"]), tree("x"))
    assert not result.valid

def test_tree_x_tree_y_invalid_different_variables(checker):
    """tree(x) |- tree(y) (INVALID - different variables)"""
    result = checker.check(tree("x"), tree("y"))
    assert not result.valid

def test_tree_x_emp_tree_x(checker):
    """tree(x) * emp |- tree(x)"""
    result = checker.check(sep(tree("x"), emp()), tree("x"))
    assert result.valid

def test_tree_x_list_y_tree_x_tree_and_list(checker):
    """tree(x) * list(y) |- tree(x) (tree and list)"""
    result = checker.check(sep(tree("x"), lst("y")), tree("x"))
    assert result.valid

def test_tree_x_list_y_list_y(checker):
    """tree(x) * list(y) |- list(y)"""
    result = checker.check(sep(tree("x"), lst("y")), lst("y"))
    assert result.valid

def test_tree_x_list_y_tree_x_list_y(checker):
    """tree(x) * list(y) |- tree(x) * list(y)"""
    result = checker.check(sep(tree("x"), lst("y")), sep(tree("x"), lst("y")))
    assert result.valid

def test_tree_x_is_satisfiable(checker):
    """tree(x) is satisfiable"""
    result = checker.is_satisfiable(tree("x"))
    assert result is True
