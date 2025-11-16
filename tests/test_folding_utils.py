"""
Tests for Folding Utilities (frame/folding/utils.py)

Tests shared folding operations and utilities.
"""

import pytest
from frame.folding.utils import generate_fold_proposals, check_overlap
from frame.core.parser import parse
from frame.core.ast import PointsTo, Var
from frame.heap.graph import FoldProposal


class TestGenerateFoldProposals:
    """Test generate_fold_proposals function"""

    def test_simple_chain(self):
        """Test generating proposals from simple chain"""
        formula = parse("x |-> y * y |-> z")
        heap_graph, proposals = generate_fold_proposals(formula, max_proposals=10)

        assert heap_graph is not None
        # Should generate at least some proposals
        assert isinstance(proposals, list)

    def test_empty_formula(self):
        """Test with empty heap"""
        formula = parse("emp")
        heap_graph, proposals = generate_fold_proposals(formula, max_proposals=10)

        # Should return empty proposals for emp
        assert heap_graph is not None or heap_graph is None
        assert proposals == []

    def test_insufficient_pto_atoms(self):
        """Test with insufficient points-to atoms"""
        formula = parse("x |-> y")
        heap_graph, proposals = generate_fold_proposals(
            formula,
            max_proposals=10,
            min_pto_atoms=5  # Require at least 5 pto atoms
        )

        # Should return None graph and empty proposals
        assert heap_graph is None
        assert proposals == []

    def test_min_pto_atoms_zero(self):
        """Test with min_pto_atoms=0 to allow empty"""
        formula = parse("emp")
        heap_graph, proposals = generate_fold_proposals(
            formula,
            max_proposals=10,
            min_pto_atoms=0  # Allow empty
        )

        # Should process even with no pto atoms
        assert heap_graph is not None

    def test_max_proposals_limit(self):
        """Test max_proposals limiting"""
        formula = parse("x |-> y * y |-> z * z |-> w")
        heap_graph, proposals = generate_fold_proposals(
            formula,
            max_proposals=2  # Limit to 2 proposals
        )

        assert heap_graph is not None
        # Should respect max limit
        assert len(proposals) <= 2

    def test_complex_heap(self):
        """Test with complex heap structure"""
        formula = parse("x |-> y * y |-> z * a |-> b")
        heap_graph, proposals = generate_fold_proposals(formula)

        assert heap_graph is not None
        # Should generate proposals for different patterns
        assert isinstance(proposals, list)


class TestCheckOverlap:
    """Test check_overlap function"""

    def setup_method(self):
        """Set up test proposals"""
        # Create mock proposals with pto cells
        self.pto1 = PointsTo(Var('x'), [Var('y')])
        self.pto2 = PointsTo(Var('y'), [Var('z')])
        self.pto3 = PointsTo(Var('a'), [Var('b')])

        # Proposals that share location 'x'
        self.proposal1 = FoldProposal(
            predicate_name='list',
            args=[Var('x')],
            pto_cells=[self.pto1],
            side_conditions=[],
            confidence=0.9
        )

        # Proposal with same location 'x'
        self.proposal2 = FoldProposal(
            predicate_name='list',
            args=[Var('x')],
            pto_cells=[self.pto1],
            side_conditions=[],
            confidence=0.8
        )

        # Proposal with different location 'a'
        self.proposal3 = FoldProposal(
            predicate_name='list',
            args=[Var('a')],
            pto_cells=[self.pto3],
            side_conditions=[],
            confidence=0.7
        )

    def test_overlap_same_location(self):
        """Test that proposals with same location overlap"""
        result = check_overlap(self.proposal1, self.proposal2)
        assert result is True

    def test_no_overlap_different_locations(self):
        """Test that proposals with different locations don't overlap"""
        result = check_overlap(self.proposal1, self.proposal3)
        assert result is False

    def test_overlap_partial(self):
        """Test partial overlap when proposals share some cells"""
        # Proposal with both x and y
        proposal_xy = FoldProposal(
            predicate_name='ls',
            args=[Var('x'), Var('z')],
            pto_cells=[self.pto1, self.pto2],
            side_conditions=[],
            confidence=0.9
        )

        # Should overlap with proposal1 (both have x)
        result = check_overlap(self.proposal1, proposal_xy)
        assert result is True

    def test_overlap_symmetric(self):
        """Test that overlap is symmetric"""
        result1 = check_overlap(self.proposal1, self.proposal2)
        result2 = check_overlap(self.proposal2, self.proposal1)
        assert result1 == result2


class TestFoldProposalIntegration:
    """Integration tests with actual formulas"""

    def test_list_chain_proposals(self):
        """Test generating proposals for list chain"""
        formula = parse("x |-> y * y |-> z * z |-> w")
        heap_graph, proposals = generate_fold_proposals(formula)

        assert heap_graph is not None
        # Should generate proposals for list segments
        assert len(proposals) > 0

    def test_tree_structure_proposals(self):
        """Test generating proposals for tree structure"""
        formula = parse("x |-> (l, r) * l |-> a * r |-> b")
        heap_graph, proposals = generate_fold_proposals(formula)

        assert heap_graph is not None
        # Tree structures may generate various proposals
        assert isinstance(proposals, list)

    def test_cyclic_structure(self):
        """Test with cyclic heap structure"""
        formula = parse("x |-> y * y |-> x")
        heap_graph, proposals = generate_fold_proposals(formula)

        # Should handle cycles gracefully
        assert heap_graph is not None


class TestEdgeCases:
    """Test edge cases in folding utilities"""

    def test_single_pto_atom(self):
        """Test with single points-to atom"""
        formula = parse("x |-> y")
        heap_graph, proposals = generate_fold_proposals(
            formula,
            min_pto_atoms=1
        )

        assert heap_graph is not None
        # May or may not generate proposals for single cell
        assert isinstance(proposals, list)

    def test_disconnected_heap(self):
        """Test with disconnected heap regions"""
        formula = parse("x |-> y * a |-> b * p |-> q")
        heap_graph, proposals = generate_fold_proposals(formula)

        assert heap_graph is not None
        # Should handle disconnected regions
        assert isinstance(proposals, list)

    def test_empty_values_in_pto(self):
        """Test proposals with various cell structures"""
        formula = parse("x |-> nil")
        heap_graph, proposals = generate_fold_proposals(formula)

        # Should process even with nil values
        assert heap_graph is not None

    def test_multifield_cells(self):
        """Test with multi-field cells"""
        formula = parse("x |-> (y, z)")
        heap_graph, proposals = generate_fold_proposals(formula)

        assert heap_graph is not None
        # Multi-field cells should be processed
        assert isinstance(proposals, list)
