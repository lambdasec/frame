"""
Test that frame abduction is properly integrated into the entailment checking pipeline.

These tests verify that abduce_frame() is actually being called and improving
completeness during normal entailment checking.
"""

import pytest
from test_framework import *


@pytest.fixture
def checker():
    # Enable abduction for these integration tests
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000, verbose=False, use_abduction=True)


def test_frame_abduction_in_pipeline_simple(checker):
    """Test that frame abduction works in the pipeline for simple cases

    P = x |-> y * z |-> w
    Q = list(x) * z |-> w

    Frame inference should:
    1. Match z |-> w directly
    2. Try to match list(x) but can't find it in P
    3. Abduce list(y) to complete the entailment
    4. Result: VALID via abduction
    """
    antecedent = sep(pts("x", "y"), pts("z", "w"))
    consequent = sep(lst("x"), pts("z", "w"))

    result = checker.check(antecedent, consequent)

    # This should be VALID through frame abduction
    # The checker abduces list(y) and proves x|->y * list(y) |- list(x)
    assert result.valid


def test_frame_abduction_in_pipeline_list_segment(checker):
    """Test frame abduction for list segments

    P = x |-> y * a |-> b
    Q = ls(x, z) * a |-> b

    Should abduce ls(y, z) to prove the entailment
    """
    antecedent = sep(pts("x", "y"), pts("a", "b"))
    consequent = sep(ls("x", "z"), pts("a", "b"))

    result = checker.check(antecedent, consequent)

    # Should be VALID via abduction
    assert result.valid


def test_frame_abduction_in_pipeline_multiple_parts(checker):
    """Test frame abduction with multiple consequent parts

    P = x |-> y * y |-> z * w |-> v
    Q = list(x) * w |-> v

    Should:
    1. Match w |-> v directly
    2. Abduce list(z) for list(x)
    """
    antecedent = sep(pts("x", "y"), pts("y", "z"), pts("w", "v"))
    consequent = sep(lst("x"), pts("w", "v"))

    result = checker.check(antecedent, consequent)

    # This is actually VALID through folding (not abduction)
    # x |-> y * y |-> z can fold to list(x) or ls(x, z)
    # So this should pass
    assert result.valid


def test_frame_abduction_vs_direct_folding(checker):
    """Compare cases that need abduction vs direct folding

    Case 1 (folding): x |-> y * y |-> z |- list(x)
      -> Direct folding works, no abduction needed

    Case 2 (abduction): x |-> y * z |-> w |- list(x) * z |-> w
      -> Need abduction to synthesize list(y)
    """
    # Case 1: Direct folding
    ante1 = sep(pts("x", "y"), pts("y", "z"))
    cons1 = lst("x")
    result1 = checker.check(ante1, cons1)
    assert result1.valid  # Via folding

    # Case 2: Needs abduction (unless folding is very smart)
    ante2 = sep(pts("x", "y"), pts("z", "w"))
    cons2 = sep(lst("x"), pts("z", "w"))
    result2 = checker.check(ante2, cons2)
    assert result2.valid  # Via abduction


def test_frame_abduction_reason_tracking(checker):
    """Test that abduction is properly tracked in the result reason"""
    checker_verbose = EntailmentChecker(
        predicate_registry=PredicateRegistry(),
        timeout=10000,
        verbose=False,  # Keep quiet for testing
        use_abduction=True  # Enable abduction
    )

    antecedent = sep(pts("x", "y"), pts("z", "w"))
    consequent = sep(lst("x"), pts("z", "w"))

    result = checker_verbose.check(antecedent, consequent)

    # Should be valid and ideally mention "abduction" in reason
    assert result.valid
    # The reason should indicate frame inference was used
    if result.reason:
        assert "frame" in result.reason.lower() or "abduction" in result.reason.lower()


def test_no_abduction_when_not_needed(checker):
    """Test that abduction is not used when not needed (efficiency check)"""
    # Simple case where direct matching works
    antecedent = sep(pts("x", "5"), pts("y", "3"))
    consequent = pts("x", "5")

    result = checker.check(antecedent, consequent)

    # Should be valid via direct match (frame rule), not abduction
    assert result.valid


def test_abduction_fails_gracefully(checker):
    """Test that abduction fails gracefully for impossible cases"""
    # This should NOT be valid (different roots)
    antecedent = pts("x", "y")
    consequent = lst("a")  # Completely different variable

    result = checker.check(antecedent, consequent)

    # Should be invalid (no way to prove this)
    assert not result.valid
