"""
Comprehensive tests for bi-abduction-style predicate matching.

Tests the frame inference implementation that matches heap shapes
at the separation logic level (rather than pushing to Z3).
"""

import pytest
from test_framework import *


# Shared fixture for checker
@pytest.fixture
def checker():
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000)


# ========== List Cons Pattern ==========

def test_list_cons_basic(checker):
    """List cons: x |-> y * list(y) |- list(x)"""
    result = checker.check(sep(pts("x", "y"), lst("y")), lst("x"))
    assert result.valid


def test_list_cons_with_frame(checker):
    """List cons with frame: x |-> y * list(y) * z |-> w |- list(x)"""
    result = checker.check(sep(pts("x", "y"), lst("y"), pts("z", "w")), lst("x"))
    assert result.valid


def test_list_cons_with_data_field(checker):
    """List cons with data field: x |-> (y, data) * list(y) |- list(x)"""
    x = Var("x")
    y = Var("y")
    data = Var("data")
    result = checker.check(sep(PointsTo(x, [y, data]), lst("y")), lst("x"))
    assert result.valid


def test_list_cons_reversed(checker):
    """List cons reversed: list(y) * x |-> y |- list(x)"""
    result = checker.check(sep(lst("y"), pts("x", "y")), lst("x"))
    assert result.valid


def test_list_cons_complex_frame(checker):
    """List cons with complex frame"""
    result = checker.check(
        sep(pts("x", "y"), lst("y"), pts("a", "b"), pts("c", "d")),
        lst("x")
    )
    assert result.valid


# ========== List Segment Cons Pattern ==========

def test_segment_cons_basic(checker):
    """Segment cons: x |-> y * ls(y, z) |- ls(x, z)"""
    result = checker.check(sep(pts("x", "y"), ls("y", "z")), ls("x", "z"))
    assert result.valid


def test_segment_cons_to_nil(checker):
    """Segment cons to nil: x |-> y * ls(y, nil) |- ls(x, nil)"""
    result = checker.check(sep(pts("x", "y"), ls("y", "nil")), ls("x", "nil"))
    assert result.valid


def test_segment_cons_with_frame(checker):
    """Segment cons with frame: x |-> y * ls(y, z) * w |-> v |- ls(x, z)"""
    result = checker.check(
        sep(pts("x", "y"), ls("y", "z"), pts("w", "v")),
        ls("x", "z")
    )
    assert result.valid


# ========== Recursive Chaining Pattern ==========

def test_two_element_chain(checker):
    """2-element chain: x |-> y * y |-> z * ls(z, nil) |- ls(x, nil)"""
    result = checker.check(
        sep(pts("x", "y"), pts("y", "z"), ls("z", "nil")),
        ls("x", "nil")
    )
    assert result.valid


def test_three_element_chain(checker):
    """3-element chain: x |-> y * y |-> z * z |-> w * ls(w, nil) |- ls(x, nil)"""
    result = checker.check(
        sep(pts("x", "y"), pts("y", "z"), pts("z", "w"), ls("w", "nil")),
        ls("x", "nil")
    )
    assert result.valid


def test_chained_segment_with_frame(checker):
    """Chained segment with frame"""
    result = checker.check(
        sep(pts("x", "y"), pts("y", "z"), ls("z", "nil"), pts("a", "b")),
        ls("x", "nil")
    )
    assert result.valid


def test_chained_segment_different_order(checker):
    """Chained segment different order"""
    result = checker.check(
        sep(pts("y", "z"), pts("x", "y"), ls("z", "nil")),
        ls("x", "nil")
    )
    assert result.valid


# ========== Tree Cons Pattern ==========

def test_tree_cons_basic(checker):
    """Tree cons: x |-> (l, r) * tree(l) * tree(r) |- tree(x)"""
    x = Var("x")
    l = Var("l")
    r = Var("r")
    result = checker.check(
        sep(PointsTo(x, [l, r]), tree("l"), tree("r")),
        tree("x")
    )
    assert result.valid


def test_tree_cons_with_frame(checker):
    """Tree cons with frame: x |-> (l, r) * tree(l) * tree(r) * y |-> z |- tree(x)"""
    x = Var("x")
    l = Var("l")
    r = Var("r")
    y = Var("y")
    z = Var("z")
    result = checker.check(
        sep(PointsTo(x, [l, r]), tree("l"), tree("r"), PointsTo(y, [z])),
        tree("x")
    )
    assert result.valid


def test_tree_cons_different_order(checker):
    """Tree cons different order"""
    x = Var("x")
    l = Var("l")
    r = Var("r")
    result = checker.check(
        sep(tree("r"), PointsTo(x, [l, r]), tree("l")),
        tree("x")
    )
    assert result.valid


def test_tree_cons_with_data_field(checker):
    """Tree cons with data field"""
    x = Var("x")
    l = Var("l")
    r = Var("r")
    data = Var("data")
    result = checker.check(
        sep(PointsTo(x, [l, r, data]), tree("l"), tree("r")),
        tree("x")
    )
    assert result.valid


# ========== Negative Cases (Should Fail) ==========

def test_invalid_missing_list_predicate(checker):
    """INVALID: x |-> y |- list(x) (missing list(y))"""
    result = checker.check(pts("x", "y"), lst("x"))
    assert not result.valid


def test_invalid_mismatched_pointers(checker):
    """INVALID: x |-> y * list(z) |- list(x) (mismatched)"""
    result = checker.check(sep(pts("x", "y"), lst("z")), lst("x"))
    assert not result.valid


def test_invalid_wrong_segment_endpoint(checker):
    """INVALID: x |-> y * ls(y, z) |- ls(x, w) (wrong endpoint)"""
    result = checker.check(sep(pts("x", "y"), ls("y", "z")), ls("x", "w"))
    assert not result.valid


def test_invalid_missing_tree_child(checker):
    """INVALID: x |-> (l, r) * tree(l) |- tree(x) (missing tree(r))"""
    x = Var("x")
    l = Var("l")
    r = Var("r")
    result = checker.check(sep(PointsTo(x, [l, r]), tree("l")), tree("x"))
    assert not result.valid


def test_invalid_broken_chain(checker):
    """INVALID: broken chain (z != w)"""
    result = checker.check(
        sep(pts("x", "y"), pts("y", "z"), ls("w", "nil")),
        ls("x", "nil")
    )
    assert not result.valid


# ========== Edge Cases ==========

def test_single_cell_to_segment(checker):
    """Single cell to segment is INVALID without distinctness proof.

    x |-> y * ls(y, y) |- ls(x, y) is INVALID because:
    - ls(y, y) = emp, so antecedent is just x |-> y
    - To prove ls(x, y) recursive case, we need x != y
    - But we can't prove x != y from x |-> y alone (cell can point to itself)

    Note: Even x |-> y * y |-> z * z |-> w |- ls(x, w) is INVALID!
    Reason: w is just a value, not necessarily a heap location. If x = w,
    we'd have a 3-cycle, making ls(x, x) unprovable.
    """
    # This should be INVALID (soundness fix)
    result = checker.check(sep(pts("x", "y"), ls("y", "y")), ls("x", "y"))
    assert not result.valid  # Changed: this is unsound without x != y

    # Valid alternative: x |-> y * ls(y, z) |- ls(x, z)
    # This works because ls(y, z) provides the necessary structure
    result_valid = checker.check(
        sep(pts("x", "y"), ls("y", "z")),
        ls("x", "z")
    )
    assert result_valid.valid  # This is sound (ls cons lemma)


def test_nil_pointers(checker):
    """Nil pointers: x |-> nil * list(nil) |- list(x)"""
    x = Var("x")
    nil_var = Var("nil")
    result = checker.check(
        sep(PointsTo(x, [nil_var]), PredicateCall("list", [nil_var])),
        lst("x")
    )
    assert result.valid


def test_multiple_frames(checker):
    """Multiple frames"""
    result = checker.check(
        sep(pts("x", "y"), lst("y"), pts("a", "b"), pts("c", "d"), pts("e", "f")),
        lst("x")
    )
    assert result.valid


# ========== Composition Tests ==========

def test_two_separate_lists(checker):
    """Two separate lists (frame second one)"""
    result = checker.check(
        sep(pts("x", "y"), lst("y"), pts("a", "b"), lst("b")),
        lst("x")
    )
    assert result.valid


def test_chain_to_list_predicate(checker):
    """Chain to list predicate (requires folding)"""
    result = checker.check(
        sep(pts("x", "y"), pts("y", "z"), lst("z")),
        lst("x")
    )
    assert result.valid


def test_segment_chain_to_segment(checker):
    """Segment chain to segment"""
    result = checker.check(
        sep(pts("x", "y"), pts("y", "z"), ls("z", "w")),
        ls("x", "w")
    )
    assert result.valid
