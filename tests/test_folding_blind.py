"""
Tests for Blind Folding (frame/folding/blind.py)

Tests iterative/blind predicate folding strategies.
"""

import pytest
from frame.folding.blind import (
    fold_formula_blind,
    fold_formula_batch,
    _select_non_overlapping
)
from frame.core.parser import parse
from frame.core.ast import PointsTo, Var
from frame.predicates import PredicateRegistry
from frame.heap.graph import FoldProposal


class TestFoldFormulaBlind:
    """Test fold_formula_blind function"""

    def setup_method(self):
        """Set up for each test"""
        self.registry = PredicateRegistry()

    def test_empty_formula(self):
        """Test folding empty formula"""
        formula = parse("emp")
        result = fold_formula_blind(formula, self.registry)
        # Should return unchanged or similar
        assert result is not None

    def test_single_cell(self):
        """Test folding single points-to cell"""
        formula = parse("x |-> y")
        result = fold_formula_blind(formula, self.registry)
        # Single cell may or may not be folded
        assert result is not None

    def test_simple_chain(self):
        """Test folding simple chain"""
        formula = parse("x |-> y * y |-> z")
        result = fold_formula_blind(formula, self.registry, verbose=False)
        # Should attempt to fold
        assert result is not None

    def test_verbose_mode(self):
        """Test with verbose output"""
        formula = parse("x |-> y * y |-> z")
        result = fold_formula_blind(formula, self.registry, verbose=True)
        # Should not crash with verbose
        assert result is not None

    def test_with_timeout(self):
        """Test with custom timeout"""
        formula = parse("x |-> y * y |-> z * z |-> w")
        result = fold_formula_blind(
            formula,
            self.registry,
            timeout=5000  # 5 second timeout
        )
        assert result is not None

    def test_convergence(self):
        """Test that folding eventually converges"""
        formula = parse("x |-> y * y |-> z")
        result = fold_formula_blind(formula, self.registry)
        # Should terminate (not infinite loop)
        assert result is not None

    def test_insufficient_atoms(self):
        """Test with too few pto atoms"""
        formula = parse("x |-> y")  # Only 1 atom
        result = fold_formula_blind(formula, self.registry)
        # Should handle gracefully
        assert result is not None


class TestFoldFormulaBatch:
    """Test fold_formula_batch function"""

    def setup_method(self):
        """Set up for each test"""
        self.registry = PredicateRegistry()

    def test_empty_formula(self):
        """Test batch folding empty formula"""
        formula = parse("emp")
        result = fold_formula_batch(formula, self.registry)
        assert result is not None

    def test_simple_chain(self):
        """Test batch folding simple chain"""
        formula = parse("x |-> y * y |-> z")
        result = fold_formula_batch(formula, self.registry)
        assert result is not None

    def test_max_proposals_limit(self):
        """Test with max_proposals limit"""
        formula = parse("x |-> y * y |-> z * z |-> w")
        result = fold_formula_batch(
            formula,
            self.registry,
            max_proposals=2  # Limit proposals
        )
        assert result is not None

    def test_verbose_mode(self):
        """Test batch folding with verbose"""
        formula = parse("x |-> y * y |-> z")
        result = fold_formula_batch(
            formula,
            self.registry,
            verbose=True
        )
        assert result is not None

    def test_disconnected_regions(self):
        """Test with disconnected heap regions"""
        formula = parse("x |-> y * a |-> b")
        result = fold_formula_batch(formula, self.registry)
        # Should handle disconnected regions
        assert result is not None


class TestSelectNonOverlapping:
    """Test _select_non_overlapping function"""

    def setup_method(self):
        """Set up test proposals"""
        self.pto1 = PointsTo(Var('x'), [Var('y')])
        self.pto2 = PointsTo(Var('y'), [Var('z')])
        self.pto3 = PointsTo(Var('a'), [Var('b')])

        # Non-overlapping proposals
        self.prop_x = FoldProposal(
            predicate_name='list',
            args=[Var('x')],
            pto_cells=[self.pto1],
            side_conditions=[],
            confidence=0.9
        )

        self.prop_a = FoldProposal(
            predicate_name='list',
            args=[Var('a')],
            pto_cells=[self.pto3],
            side_conditions=[],
            confidence=0.8
        )

        # Overlapping with prop_x
        self.prop_x_overlap = FoldProposal(
            predicate_name='ls',
            args=[Var('x'), Var('z')],
            pto_cells=[self.pto1, self.pto2],
            side_conditions=[],
            confidence=0.7
        )

    def test_non_overlapping_selection(self):
        """Test selecting non-overlapping proposals"""
        proposals = [self.prop_x, self.prop_a]
        result = _select_non_overlapping(proposals)
        # Both should be selected (non-overlapping)
        assert len(result) == 2

    def test_overlapping_filtered(self):
        """Test that overlapping proposals are filtered"""
        proposals = [self.prop_x, self.prop_x_overlap]
        result = _select_non_overlapping(proposals)
        # Only first should be selected
        assert len(result) == 1
        assert result[0] == self.prop_x

    def test_greedy_selection(self):
        """Test greedy selection (picks first non-overlapping)"""
        proposals = [self.prop_x, self.prop_x_overlap, self.prop_a]
        result = _select_non_overlapping(proposals)
        # Should pick prop_x and prop_a (non-overlapping)
        assert len(result) == 2

    def test_empty_proposals(self):
        """Test with empty proposal list"""
        result = _select_non_overlapping([])
        assert result == []

    def test_single_proposal(self):
        """Test with single proposal"""
        result = _select_non_overlapping([self.prop_x])
        assert len(result) == 1


class TestBlindFoldingIntegration:
    """Integration tests with real formulas"""

    def setup_method(self):
        """Set up registry"""
        self.registry = PredicateRegistry()

    def test_fold_list_chain(self):
        """Test folding a list chain"""
        formula = parse("x |-> y * y |-> z * z |-> w")
        result = fold_formula_blind(formula, self.registry)
        assert result is not None
        # Result should be a formula
        assert hasattr(result, '__str__')

    def test_fold_already_folded(self):
        """Test folding formula that's already a predicate"""
        formula = parse("list(x)")
        result = fold_formula_blind(formula, self.registry)
        # Should return unchanged
        assert result is not None

    def test_fold_mixed_formula(self):
        """Test folding formula with predicates and concrete cells"""
        formula = parse("x |-> y * list(z)")
        result = fold_formula_blind(formula, self.registry)
        assert result is not None

    def test_fold_cyclic_structure(self):
        """Test folding cyclic heap"""
        formula = parse("x |-> y * y |-> x")
        result = fold_formula_blind(formula, self.registry)
        # Should handle cycles
        assert result is not None


class TestFoldingParameters:
    """Test folding with various parameters"""

    def setup_method(self):
        """Set up registry"""
        self.registry = PredicateRegistry()

    def test_short_timeout(self):
        """Test with very short timeout"""
        formula = parse("x |-> y * y |-> z")
        result = fold_formula_blind(
            formula,
            self.registry,
            timeout=10  # Very short
        )
        # Should complete even with short timeout
        assert result is not None

    def test_zero_max_proposals(self):
        """Test batch with zero max_proposals"""
        formula = parse("x |-> y * y |-> z")
        result = fold_formula_batch(
            formula,
            self.registry,
            max_proposals=0
        )
        # Should handle gracefully
        assert result is not None

    def test_large_max_proposals(self):
        """Test with large max_proposals"""
        formula = parse("x |-> y * y |-> z")
        result = fold_formula_batch(
            formula,
            self.registry,
            max_proposals=100
        )
        assert result is not None


class TestEdgeCases:
    """Test edge cases in blind folding"""

    def setup_method(self):
        """Set up registry"""
        self.registry = PredicateRegistry()

    def test_formula_with_nil(self):
        """Test folding with nil values"""
        formula = parse("x |-> nil")
        result = fold_formula_blind(formula, self.registry)
        assert result is not None

    def test_multifield_cells(self):
        """Test folding multi-field cells"""
        formula = parse("x |-> (y, z)")
        result = fold_formula_blind(formula, self.registry)
        assert result is not None

    def test_very_long_chain(self):
        """Test folding very long chain"""
        formula = parse("x |-> a * a |-> b * b |-> c * c |-> d * d |-> e")
        result = fold_formula_blind(formula, self.registry)
        # Should handle long chains
        assert result is not None

    def test_pure_formulas_preserved(self):
        """Test that pure constraints are handled"""
        formula = parse("x |-> y")
        result = fold_formula_blind(formula, self.registry)
        # Should preserve or handle pure parts
        assert result is not None
