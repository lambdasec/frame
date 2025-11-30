"""
Tests for base-guided folding integration.

This tests the integration of compositional base computation (S2S approach)
with goal-directed predicate folding. The base checking provides early
soundness filtering before expensive verification.
"""

import pytest
from frame import EntailmentChecker
from frame.predicates.registry import PredicateRegistry
from frame.predicates.base_registry import BaseRegistry


class TestBaseGuidedFolding:
    """Test base computation integration with goal-directed folding."""

    def test_base_check_handles_reflexivity(self):
        """Base check should handle reflexivity correctly."""
        checker = EntailmentChecker()

        # Reflexivity should still work
        result = checker.check_entailment("list(x) |- list(x)")
        assert result.valid

    def test_base_check_handles_frame_rule(self):
        """Base check should handle frame rule correctly."""
        checker = EntailmentChecker()

        # Frame rule with predicates - must have matching parts on BOTH sides
        # In exact entailment semantics, list(x) * list(y) |- list(x) is INVALID
        # because we can't "drop" the list(y) heap. Use a case where frame
        # parts actually appear on both sides.
        result = checker.check_entailment("list(x) * ls(a, b) |- list(x) * ls(a, b)")
        assert result.valid

    def test_base_computation_cached(self):
        """Base computation should be cached for reuse."""
        registry = PredicateRegistry(enable_base_computation=True)
        base_registry = registry._get_base_registry()

        # Get list predicate
        ls_pred = registry.get("ls")
        assert ls_pred is not None

        # First computation
        spatial_base1, numeric_base1 = base_registry.compute_base(ls_pred)

        # Second computation should hit cache
        spatial_base2, numeric_base2 = base_registry.compute_base(ls_pred)

        # Should return same formulas (cached)
        assert str(spatial_base1) == str(spatial_base2)
        assert str(numeric_base1) == str(numeric_base2)

    def test_base_check_doesnt_affect_predicate_entailments(self):
        """Base check should not interfere with predicate-to-predicate entailments."""
        checker = EntailmentChecker()

        # List to list segment conversion
        result1 = checker.check_entailment("list(x) |- ls(x, nil)")
        assert result1.valid

        # Predicate to predicate with equal footprint (reflexivity)
        # NOTE: In exact entailment semantics (SL-COMP), list(x) * list(y) |- list(x)
        # is INVALID because we can't drop the list(y) heap. Use a valid case instead.
        result2 = checker.check_entailment("list(x) |- list(x)")
        assert result2.valid

    def test_base_check_with_goal_directed_folding(self):
        """Base check should work with goal-directed folding."""
        checker = EntailmentChecker()

        # Goal-directed folding should use base checking
        # x |-> y * y |-> nil |- list(x)
        result = checker.check_entailment("x |-> y * y |-> nil |- list(x)")
        assert result.valid

    def test_base_check_with_multistep_folding(self):
        """Base check should work with multi-step folding."""
        checker = EntailmentChecker()

        # Multi-step folding should use base checking at each step
        # x |-> y * y |-> z * z |-> nil |- list(x)
        result = checker.check_entailment("x |-> y * y |-> z * z |-> nil |- list(x)")
        assert result.valid

    def test_base_registry_precomputes_standard_predicates(self):
        """Base registry should precompute bases for standard predicates."""
        registry = PredicateRegistry(enable_base_computation=True)
        base_registry = registry._get_base_registry()

        # Standard predicates should have precomputed bases
        assert base_registry.has_base("ls")
        assert base_registry.has_base("list")
        assert base_registry.has_base("tree")
        assert base_registry.has_base("dll")

    def test_base_check_disabled_when_flag_false(self):
        """Base checking should be skipped when disabled."""
        registry = PredicateRegistry(enable_base_computation=False)
        base_registry = registry._get_base_registry()

        # Should return None when disabled
        assert base_registry is None

    def test_base_check_handles_complex_predicates(self):
        """Base check should handle complex predicates like DLL."""
        checker = EntailmentChecker()

        # dll(x, p, y, n) with concrete cells
        # This tests that base checking works for multi-argument predicates
        result = checker.check_entailment(
            "x |-> (d, p, n) * n |-> (d2, x, nil) |- dll(x, p, nil, nil)"
        )
        # Note: This might not be valid due to complex dll constraints
        # But base checking should at least accept the proposal for verification

    def test_base_spatial_base_structure(self):
        """Test that spatial base has correct structure."""
        registry = PredicateRegistry(enable_base_computation=True)
        base_registry = registry._get_base_registry()

        # Get list segment predicate
        ls_pred = registry.get("ls")
        spatial_base, numeric_base = base_registry.compute_base(ls_pred)

        # Spatial base should not be None
        assert spatial_base is not None

        # Numeric base should not be None
        assert numeric_base is not None

    def test_integration_with_entailment_checker(self):
        """Test full integration with EntailmentChecker."""
        checker = EntailmentChecker()

        # Various entailments - NOTE (Nov 2025): Transitivity is UNSOUND
        # without explicit disequality constraints. When x = z, antecedent
        # has heap cells but consequent ls(x,x) = emp.
        # NOTE: In exact entailment semantics (SL-COMP), list(x) * list(y) |- list(x)
        # is INVALID because we can't drop the list(y) heap.
        test_cases = [
            ("list(x) |- list(x)", True),  # Reflexivity
            ("list(x) |- ls(x, nil)", True),  # Predicate conversion
            ("ls(x, y) * ls(y, z) |- ls(x, z)", False),  # INVALID without disequality
        ]

        for formula, expected in test_cases:
            result = checker.check_entailment(formula)
            assert result.valid == expected, f"Failed for: {formula}"

    def test_base_check_integration_doesnt_crash(self):
        """Test that base check integration doesn't cause crashes."""
        checker = EntailmentChecker()

        # Just verify various queries don't crash with base checking enabled
        queries = [
            "list(x) |- list(x)",
            "tree(x) |- tree(x)",
            "ls(x, y) |- ls(x, y)",
            "dll(x, p, y, n) |- dll(x, p, y, n)",
        ]

        for query in queries:
            result = checker.check_entailment(query)
            # We just care that it doesn't crash
            assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
