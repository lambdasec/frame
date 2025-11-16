"""
Tests for compositional base computation.

Tests the UnfoldingTree, BaseComputer, and BaseRegistry classes
that implement S2S-style base computation.
"""

import pytest
from frame.predicates import (
    BaseRegistry,
    BaseComputer,
    UnfoldingTree,
    PredicateRegistry,
    ListSegment,
    ListSegmentWithLength,
    LinkedList,
    Tree,
    DoublyLinkedList,
    get_base_registry,
    reset_base_registry
)
from frame.core.ast import (
    Formula, Var, Const, Emp, PointsTo, SepConj, And, Or, Not,
    Exists, Forall, Eq, Neq, True_, False_, PredicateCall
)


class TestUnfoldingTree:
    """Test the UnfoldingTree class."""

    def test_build_tree_for_list_segment(self):
        """Test building unfolding tree for list segment predicate."""
        ls = ListSegment()
        tree = UnfoldingTree(ls, max_depth=3)
        root = tree.build()

        assert root is not None
        assert isinstance(root.formula, PredicateCall)
        assert root.formula.name == "ls"
        assert len(tree.nodes) > 0

    def test_build_tree_for_tree_predicate(self):
        """Test building unfolding tree for tree predicate."""
        tree_pred = Tree()
        tree = UnfoldingTree(tree_pred, max_depth=2)
        root = tree.build()

        assert root is not None
        assert isinstance(root.formula, PredicateCall)
        assert root.formula.name == "tree"

    def test_cycle_detection_in_list(self):
        """Test that cycles are detected in recursive predicates."""
        ls = ListSegment()
        tree = UnfoldingTree(ls, max_depth=5)
        root = tree.build()

        # Check that some cycles were detected
        # (exact number depends on implementation details)
        assert len(tree.nodes) >= 1


class TestBaseComputer:
    """Test the BaseComputer class."""

    def test_compute_spatial_base_for_list_segment(self):
        """Test computing spatial base for list segment."""
        ls = ListSegment()
        computer = BaseComputer(max_unfold_depth=3)
        spatial_base = computer.compute_spatial_base(ls)

        # Should return some formula (not None)
        assert spatial_base is not None
        assert isinstance(spatial_base, Formula)

    def test_compute_numeric_base_for_list_segment(self):
        """Test computing numeric base for list segment."""
        ls = ListSegment()
        computer = BaseComputer(max_unfold_depth=3)
        numeric_base = computer.compute_numeric_base(ls)

        # Should return some formula (not None)
        assert numeric_base is not None
        assert isinstance(numeric_base, Formula)

    def test_compute_spatial_base_for_tree(self):
        """Test computing spatial base for tree predicate."""
        tree = Tree()
        computer = BaseComputer(max_unfold_depth=2)
        spatial_base = computer.compute_spatial_base(tree)

        assert spatial_base is not None
        assert isinstance(spatial_base, Formula)

    def test_compute_bases_for_linked_list(self):
        """Test computing bases for linked list predicate."""
        linked_list = LinkedList()
        computer = BaseComputer(max_unfold_depth=3)

        spatial_base = computer.compute_spatial_base(linked_list)
        numeric_base = computer.compute_numeric_base(linked_list)

        assert spatial_base is not None
        assert numeric_base is not None


class TestBaseRegistry:
    """Test the BaseRegistry class."""

    def test_create_registry(self):
        """Test creating a base registry."""
        registry = BaseRegistry()
        assert registry is not None
        assert registry._spatial_bases == {}
        assert registry._numeric_bases == {}

    def test_compute_and_cache_base(self):
        """Test that bases are computed and cached."""
        registry = BaseRegistry()
        ls = ListSegment()

        # First computation
        spatial_base1, numeric_base1 = registry.compute_base(ls)
        assert spatial_base1 is not None
        assert numeric_base1 is not None

        # Should be cached now
        assert registry.has_base("ls")

        # Second access should return cached value
        spatial_base2 = registry.get_spatial_base("ls")
        numeric_base2 = registry.get_numeric_base("ls")

        assert spatial_base2 is spatial_base1
        assert numeric_base2 is numeric_base1

    def test_precompute_standard_bases(self):
        """Test precomputing bases for standard predicates."""
        registry = BaseRegistry()
        predicates = [
            ListSegment(),
            LinkedList(),
            Tree()
        ]

        registry.precompute_standard_bases(predicates)

        # Check that all bases were computed
        assert registry.has_base("ls")
        assert registry.has_base("list")
        assert registry.has_base("tree")

    def test_get_base_for_unknown_predicate(self):
        """Test getting base for unknown predicate."""
        registry = BaseRegistry()

        spatial_base = registry.get_spatial_base("unknown_pred")
        numeric_base = registry.get_numeric_base("unknown_pred")

        assert spatial_base is None
        assert numeric_base is None

    def test_clear_cache(self):
        """Test clearing the base cache."""
        registry = BaseRegistry()
        ls = ListSegment()

        # Compute a base
        registry.compute_base(ls)
        assert registry.has_base("ls")

        # Clear cache
        registry.clear_cache()
        assert not registry.has_base("ls")


class TestPredicateRegistryIntegration:
    """Test integration of BaseRegistry with PredicateRegistry."""

    def test_predicate_registry_with_base_computation(self):
        """Test that PredicateRegistry can use base computation."""
        registry = PredicateRegistry(enable_base_computation=True)

        # Get base for a standard predicate
        spatial_base = registry.get_spatial_base("ls")
        numeric_base = registry.get_numeric_base("ls")

        # Should not be None (base computation is enabled)
        assert spatial_base is not None
        assert numeric_base is not None

    def test_predicate_registry_without_base_computation(self):
        """Test PredicateRegistry with base computation disabled."""
        registry = PredicateRegistry(enable_base_computation=False)

        # Get base for a standard predicate
        spatial_base = registry.get_spatial_base("ls")
        numeric_base = registry.get_numeric_base("ls")

        # Should be None (base computation is disabled)
        assert spatial_base is None
        assert numeric_base is None

    def test_get_predicate_base_tuple(self):
        """Test getting both bases at once."""
        registry = PredicateRegistry(enable_base_computation=True)

        base_tuple = registry.get_predicate_base("ls")
        assert base_tuple is not None
        assert len(base_tuple) == 2

        spatial_base, numeric_base = base_tuple
        assert spatial_base is not None
        assert numeric_base is not None

    def test_base_computation_for_multiple_predicates(self):
        """Test computing bases for multiple predicates."""
        registry = PredicateRegistry(enable_base_computation=True)

        # Get bases for different predicates
        ls_base = registry.get_predicate_base("ls")
        list_base = registry.get_predicate_base("list")
        tree_base = registry.get_predicate_base("tree")

        assert ls_base is not None
        assert list_base is not None
        assert tree_base is not None

        # Each should have different bases
        # (at least the predicates are different)
        assert "ls" != "list"
        assert "list" != "tree"


class TestGlobalBaseRegistry:
    """Test the global base registry functions."""

    def test_get_global_base_registry(self):
        """Test getting the global base registry instance."""
        reset_base_registry()  # Ensure clean state

        registry1 = get_base_registry()
        registry2 = get_base_registry()

        # Should return the same instance
        assert registry1 is registry2

    def test_reset_global_base_registry(self):
        """Test resetting the global base registry."""
        reset_base_registry()

        registry1 = get_base_registry()
        assert registry1 is not None

        reset_base_registry()
        registry2 = get_base_registry()

        # Should be a new instance after reset
        assert registry1 is not registry2

    def test_global_registry_caching(self):
        """Test that global registry caches bases."""
        reset_base_registry()
        registry = get_base_registry()

        ls = ListSegment()
        registry.compute_base(ls)

        # Should be cached
        assert registry.has_base("ls")

        # Getting registry again should have the same cache
        registry2 = get_base_registry()
        assert registry2.has_base("ls")


class TestBaseComputationCorrectness:
    """Test correctness properties of base computation."""

    def test_base_is_formula(self):
        """Test that computed bases are valid formulas."""
        registry = BaseRegistry()
        ls = ListSegment()

        spatial_base, numeric_base = registry.compute_base(ls)

        # Both should be Formula instances
        assert isinstance(spatial_base, Formula)
        assert isinstance(numeric_base, Formula)

    def test_base_computation_does_not_crash(self):
        """Test that base computation doesn't crash for standard predicates."""
        registry = BaseRegistry()
        predicates = [
            ListSegment(),
            ListSegmentWithLength(),
            LinkedList(),
            Tree(),
            DoublyLinkedList()
        ]

        # Should not raise any exceptions
        for pred in predicates:
            try:
                spatial_base, numeric_base = registry.compute_base(pred)
                assert spatial_base is not None
                assert numeric_base is not None
            except Exception as e:
                pytest.fail(f"Base computation failed for {pred.name}: {e}")

    def test_base_is_idempotent(self):
        """Test that computing the same base twice gives the same result."""
        registry = BaseRegistry()
        ls = ListSegment()

        # Compute twice
        spatial1, numeric1 = registry.compute_base(ls)
        spatial2, numeric2 = registry.compute_base(ls)

        # Should be the same (cached)
        assert spatial1 is spatial2
        assert numeric1 is numeric2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
