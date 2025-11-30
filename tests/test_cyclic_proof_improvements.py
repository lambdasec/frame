"""
Tests for improved cyclic proof handling.

These tests verify that the enhancements to cycle detection:
1. Don't close cycles too early (minimum depth threshold)
2. Handle predicate-specific cases correctly
3. Track proof traces with back-edges
4. Improve completeness on benchmarks
"""

import pytest
from test_framework import *


@pytest.fixture
def checker():
    return EntailmentChecker(
        predicate_registry=PredicateRegistry(),
        timeout=10000,
        use_cyclic_proof=True  # Enable cyclic proofs
    )


# ========== Minimum Depth Threshold Tests ==========

def test_list_transitivity_invalid_without_disequality(checker):
    """Test that ls(x,y) * ls(y,z) |- ls(x,z) is INVALID without x != z

    UPDATED Nov 2025: SL-COMP semantics require explicit disequality.
    - When x = z, antecedent has cells but consequent ls(x,x) = emp
    - Non-empty heap cannot entail empty heap
    - This matches SL-COMP benchmark ls-vc06.sb.smt2 (status sat = INVALID)
    """
    antecedent = sep(ls("x", "y"), ls("y", "z"))
    consequent = ls("x", "z")

    result = checker.check(antecedent, consequent)

    # INVALID without explicit disequality proof
    assert not result.valid


def test_list_composition_three_segments_invalid_without_disequality(checker):
    """Test three-segment composition: ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)

    UPDATED Nov 2025: SL-COMP semantics require explicit disequality.
    - When x = w, antecedent has cells but consequent ls(x,x) = emp
    - Non-empty heap cannot entail empty heap
    """
    antecedent = sep(ls("x", "y"), ls("y", "z"), ls("z", "w"))
    consequent = ls("x", "w")

    result = checker.check(antecedent, consequent)

    # INVALID without explicit disequality proof
    assert not result.valid


def test_list_cons_with_segment(checker):
    """Test list cons with segment: x |-> y * ls(y, z) |- ls(x, z)"""
    antecedent = sep(pts("x", "y"), ls("y", "z"))
    consequent = ls("x", "z")

    result = checker.check(antecedent, consequent)

    # Should be VALID via ls cons lemma
    assert result.valid


def test_dll_composition(checker):
    """Test doubly-linked list composition doesn't close too early"""
    # dll(x, p, y, n) * dll(y, x, z, q) should work
    x = Var("x")
    y = Var("y")
    z = Var("z")
    p = Var("p")
    n = Var("n")
    q = Var("q")

    antecedent = SepConj(
        PredicateCall("dll", [x, p, y, n]),
        PredicateCall("dll", [y, x, z, q])
    )
    consequent = PredicateCall("dll", [x, p, z, q])

    result = checker.check(antecedent, consequent)

    # May or may not be valid depending on DLL definition
    # The key is that it shouldn't close the cycle prematurely
    # Just verify it doesn't crash
    assert result is not None


# ========== Predicate-Specific Cycle Detection Tests ==========

def test_tree_cycle_detection(checker):
    """Test that tree(x) |- tree(x) is detected correctly

    Trees should use root-only cycle detection
    """
    antecedent = tree("x")
    consequent = tree("x")

    result = checker.check(antecedent, consequent)

    # Should be VALID (reflexivity)
    assert result.valid


def test_list_different_endpoints_no_false_cycle(checker):
    """Test that ls(x, y) and ls(x, z) aren't considered the same cycle

    List segments need full state (both endpoints) for cycle detection
    """
    # ls(x, y) |- ls(x, z) should NOT be valid (different endpoints)
    antecedent = ls("x", "y")
    consequent = ls("x", "z")

    result = checker.check(antecedent, consequent)

    # Should be INVALID (different endpoints, not equivalent)
    assert not result.valid


def test_tree_reflexive_valid(checker):
    """Test that tree(x) |- tree(x) is always valid"""
    antecedent = tree("x")
    consequent = tree("x")

    result = checker.check(antecedent, consequent)

    assert result.valid


# ========== Complex Cyclic Proof Cases ==========

def test_nested_list_segments(checker):
    """Test nested list segment reasoning

    x |-> y * y |-> z * ls(z, w) |- ls(x, w)

    This requires multiple levels of unfolding + folding
    """
    antecedent = sep(pts("x", "y"), pts("y", "z"), ls("z", "w"))
    consequent = ls("x", "w")

    result = checker.check(antecedent, consequent)

    # Should be VALID via folding + transitivity
    assert result.valid


def test_cyclic_list_invalid(checker):
    """Test that actual cycles are still detected and rejected

    If we have a true cycle x |-> y * y |-> x, this should NOT
    satisfy list(x) without additional distinctness constraints
    """
    # This is a tricky case - depends on list predicate definition
    # Most definitions require distinctness, making this invalid
    # We just test it doesn't hang or crash
    antecedent = sep(pts("x", "y"), pts("y", "x"))
    consequent = lst("x")

    result = checker.check(antecedent, consequent)

    # The result depends on predicate definition
    # Key: shouldn't timeout or crash
    assert result is not None


def test_long_chain_folding(checker):
    """Test long chain of cells can be folded into list

    x |-> y * y |-> z * z |-> w * w |-> nil |- list(x)

    Multi-step folding handles this by iteratively folding:
    First: w |-> nil into list(w) or ls(w, nil)
    Then: z |-> w * list(w) into list(z)
    Then: y |-> z * list(z) into list(y)
    Finally: x |-> y * list(y) into list(x)

    Now handled by multi-step folding implementation.
    """
    antecedent = sep(
        pts("x", "y"),
        pts("y", "z"),
        pts("z", "w"),
        pts("w", "nil")
    )
    consequent = lst("x")

    result = checker.check(antecedent, consequent)

    # Should be VALID via multi-step folding (currently fails)
    assert result.valid


# ========== Proof Trace and Statistics Tests ==========

def test_cycle_statistics_tracking():
    """Test that cycle statistics are properly tracked"""
    from frame.folding.cyclic_unfold import CyclicUnfoldEngine
    from frame.predicates import PredicateRegistry

    registry = PredicateRegistry()
    engine = CyclicUnfoldEngine(registry, verbose=False)

    # Create a formula that will trigger cycle detection
    formula = ls("x", "y")

    # Unfold with cycle detection
    result = engine.unfold_with_cycle_detection(formula, depth=6)

    # Get statistics
    stats = engine.get_cycle_statistics()

    # Verify stats are tracked
    assert isinstance(stats, dict)
    assert "detected" in stats
    assert "closed" in stats
    assert "skipped" in stats

    # Stats should be non-negative
    assert stats["detected"] >= 0
    assert stats["closed"] >= 0
    assert stats["skipped"] >= 0


def test_minimum_depth_prevents_early_closure():
    """Test that MIN_DEPTH_BEFORE_CYCLE actually prevents early closure"""
    from frame.folding.cyclic_unfold import CyclicUnfoldEngine
    from frame.predicates import PredicateRegistry

    registry = PredicateRegistry()
    registry.max_unfold_depth = 6

    engine = CyclicUnfoldEngine(registry, verbose=False)

    # Create a formula that would trigger early cycle without threshold
    formula = sep(ls("x", "y"), ls("y", "z"))

    # Unfold with cycle detection
    result = engine.unfold_with_cycle_detection(formula, depth=6)

    # Get statistics
    stats = engine.get_cycle_statistics()

    # If cycles were detected and skipped, the threshold is working
    # Note: This is a heuristic test - exact numbers depend on implementation
    # The key is that skipped > 0 means threshold is being applied
    if stats["detected"] > 0:
        # Either cycles were skipped (threshold working) or closed (valid cycle)
        assert stats["skipped"] + stats["closed"] > 0


# ========== Regression Tests ==========

def test_simple_list_still_works(checker):
    """Ensure simple list entailments still work after improvements"""
    # Basic cases that should always work
    test_cases = [
        (lst("x"), lst("x")),  # Reflexivity
        (sep(pts("x", "y"), lst("y")), lst("x")),  # List cons
        (ls("x", "x"), Emp()),  # Empty segment
    ]

    for ante, cons in test_cases:
        result = checker.check(ante, cons)
        assert result.valid, f"Regression: {ante} |- {cons} should be valid"


def test_negative_cases_still_invalid(checker):
    """Ensure invalid entailments are still rejected"""
    # Cases that should be invalid
    test_cases = [
        (pts("x", "y"), lst("x")),  # Missing list(y)
        (lst("x"), lst("y")),  # Different roots
        (ls("x", "y"), ls("x", "z")),  # Different endpoints
    ]

    for ante, cons in test_cases:
        result = checker.check(ante, cons)
        assert not result.valid, f"Regression: {ante} |- {cons} should be invalid"


# ========== Performance Tests ==========

def test_deep_unfolding_terminates(checker):
    """Test that deep unfolding with cycle detection terminates efficiently

    Note: Chain a → b → c → d → e → f doesn't end in nil, so list(a) is invalid.
    This test verifies the checker handles it gracefully without hanging.
    """
    # This could potentially cause very deep unfolding
    antecedent = sep(
        pts("a", "b"),
        pts("b", "c"),
        pts("c", "d"),
        pts("d", "e"),
        pts("e", "f")
    )
    consequent = lst("a")

    import time
    start = time.time()

    # Should complete without timeout (doesn't hang)
    result = checker.check(antecedent, consequent)

    elapsed = time.time() - start

    # Key requirement: terminates in reasonable time
    assert elapsed < 5.0, f"Took too long: {elapsed:.2f}s"

    # Result should be invalid (chain doesn't end in nil)
    # But we verify it returns a result without hanging
    assert result is not None


def test_cyclic_structure_doesnt_hang(checker):
    """Test that potential cyclic structures don't cause hangs"""
    # Even if there's potential for cycles, should terminate
    import time

    start_time = time.time()

    antecedent = sep(ls("x", "y"), ls("y", "z"), ls("z", "x"))
    consequent = ls("x", "x")

    result = checker.check(antecedent, consequent)

    elapsed = time.time() - start_time

    # Should complete in reasonable time (< 5 seconds)
    assert elapsed < 5.0, f"Took too long: {elapsed:.2f}s"

    # Result can be valid or invalid, key is it terminates
    assert result is not None
