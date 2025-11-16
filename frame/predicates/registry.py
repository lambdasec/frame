"""
Predicate registry for managing inductive predicates
"""

from typing import Dict, Optional, List, Set, Tuple
from frame.core.ast import (
    PredicateCall, Formula, Expr, SepConj, And, Or, Not, Exists, Forall
)
from frame.predicates.base import InductivePredicate, PredicateValidationError
from frame.predicates.list_predicates import (
    ListSegmentWithLength, LinkedList, ReverseList, NestedList
)
from frame.predicates.tree_predicates import Tree
from frame.predicates.dll_predicates import DoublyLinkedList
from frame.predicates.skiplist_predicates import SkipList1, SkipList2, SkipList3
from frame.predicates.sorted_predicates import SortedListSegment
from frame.predicates.lsso_predicates import ListSegmentSentinel

class PredicateRegistry:
    """Registry for managing inductive predicates"""

    def __init__(self, enable_base_computation: bool = True):
        self.predicates: Dict[str, InductivePredicate] = {}
        # Set to 6 for balanced performance
        # Adaptive unfolding will adjust based on formula complexity
        self.max_unfold_depth = 6

        # Base registry for compositional base computation (lazy initialization)
        self._base_registry = None
        self._enable_base_computation = enable_base_computation

        # Auto-register standard predicates
        self._register_standard_predicates()

    def _register_standard_predicates(self):
        """Register standard built-in predicates"""
        # Register length-parameterized list segment (supports both ls(x,y) and ls(x,y,n))
        self.register(ListSegmentWithLength(), validate=False)

        # Register standard list predicate
        self.register(LinkedList(), validate=False)

        # Register tree predicate
        self.register(Tree(), validate=False)

        # Register doubly-linked list
        self.register(DoublyLinkedList(), validate=False)

        # Register reverse list
        self.register(ReverseList(), validate=False)

        # Register nested list
        self.register(NestedList(), validate=False)

        # Register skip lists (levels 1, 2, 3)
        self.register(SkipList1(), validate=False)
        self.register(SkipList2(), validate=False)
        self.register(SkipList3(), validate=False)

        # Register sorted list segment
        self.register(SortedListSegment(), validate=False)

        # Register list segment with sentinel
        self.register(ListSegmentSentinel(), validate=False)

        # Precompute bases for standard predicates if enabled
        if self._enable_base_computation:
            self._precompute_standard_bases()

    def _precompute_standard_bases(self):
        """Precompute bases for standard predicates (lazy)."""
        # This will be called lazily when base_registry is first accessed
        # For now, we defer precomputation until it's actually needed
        pass

    def _get_base_registry(self):
        """Get or create the base registry (lazy initialization)."""
        if self._base_registry is None and self._enable_base_computation:
            from frame.predicates.base_registry import BaseRegistry
            self._base_registry = BaseRegistry()

            # Precompute bases for all registered predicates
            standard_preds = [
                self.get("ls"),
                self.get("list"),
                self.get("tree"),
                self.get("dll"),
            ]
            # Filter out None values
            valid_preds = [p for p in standard_preds if p is not None]
            if valid_preds:
                self._base_registry.precompute_standard_bases(valid_preds)

        return self._base_registry

    def register(self, predicate: InductivePredicate, validate: bool = True):
        """
        Register a new predicate.

        Args:
            predicate: The predicate to register
            validate: Whether to validate the predicate definition for soundness (default: True)

        Raises:
            PredicateValidationError: If validate=True and the predicate definition is unsound
        """
        if validate:
            is_valid, errors, warnings = predicate.validate_definition()

            if warnings:
                print(f"Warning: Predicate '{predicate.name}' has potential issues:")
                for warning in warnings:
                    print(f"  - {warning}")

            if not is_valid:
                error_msg = f"Predicate '{predicate.name}' has invalid definition:\n"
                for error in errors:
                    error_msg += f"  - {error}\n"
                raise PredicateValidationError(error_msg)

        self.predicates[predicate.name] = predicate

    def get(self, name: str) -> Optional[InductivePredicate]:
        """Get a predicate by name"""
        return self.predicates.get(name)

    def _count_predicates(self, formula: Formula) -> int:
        """Count number of predicate calls in a formula"""
        if isinstance(formula, PredicateCall):
            return 1
        elif isinstance(formula, (SepConj, And, Or)):
            return self._count_predicates(formula.left) + self._count_predicates(formula.right)
        elif isinstance(formula, (Not, Exists, Forall)):
            return self._count_predicates(formula.formula)
        else:
            return 0

    def _contains_tree_predicate(self, formula: Formula) -> bool:
        """Check if formula contains tree or other branching predicates"""
        if isinstance(formula, PredicateCall):
            # Check for tree or other branching predicates
            return formula.name in {'tree', 'btree', 'bstree', 'avl'}
        elif isinstance(formula, (SepConj, And, Or)):
            return self._contains_tree_predicate(formula.left) or self._contains_tree_predicate(formula.right)
        elif isinstance(formula, (Not, Exists, Forall)):
            return self._contains_tree_predicate(formula.formula)
        else:
            return False

    def _get_adaptive_depth(self, formula: Formula) -> int:
        """
        Determine unfolding depth based on formula complexity.

        Respects max_unfold_depth as the upper bound - adaptive logic can only
        reduce depth for complex formulas, never increase it beyond the configured max.
        """
        pred_count = self._count_predicates(formula)

        # Check if formula contains tree predicates (exponential growth)
        has_tree = self._contains_tree_predicate(formula)

        # Adaptive strategy: Use max_unfold_depth as the cap, reduce for complex formulas
        # Tree predicates cause exponential growth (2^n nodes), so use shallower depths
        # Linear predicates (lists, DLLs) scale linearly, so can handle deeper unfolding

        if has_tree:
            # Shallower depths for tree predicates to avoid exponential blowup
            if pred_count <= 2:
                return min(self.max_unfold_depth, 4)
            elif pred_count <= 5:
                return min(self.max_unfold_depth, 3)
            else:
                return min(self.max_unfold_depth, 3)
        else:
            # Normal depths for linear predicates (lists, segments, etc.)
            # Use max_unfold_depth for simple formulas to ensure complete unfolding
            if pred_count <= 2:
                return self.max_unfold_depth  # Use full depth for simple formulas
            elif pred_count <= 5:
                return min(self.max_unfold_depth, self.max_unfold_depth - 1)
            elif pred_count <= 10:
                return min(self.max_unfold_depth, self.max_unfold_depth - 2)
            else:
                return min(self.max_unfold_depth, self.max_unfold_depth - 3)

    def unfold_predicates(self, formula: Formula, depth: Optional[int] = None, adaptive: bool = False) -> Formula:
        """
        Unfold all predicate calls in a formula to a bounded depth.

        Args:
            formula: The formula to unfold
            depth: Maximum unfolding depth (uses default if None)
            adaptive: If True, determine depth adaptively based on formula complexity

        Returns:
            Formula with predicates unfolded
        """
        if depth is None:
            if adaptive:
                depth = self._get_adaptive_depth(formula)
            else:
                depth = self.max_unfold_depth

        return self._unfold_recursive(formula, depth)

    def _unfold_recursive(self, formula: Formula, depth: int) -> Formula:
        """Recursively unfold predicates in a formula"""
        if isinstance(formula, PredicateCall):
            predicate = self.get(formula.name)
            if predicate:
                return predicate.unfold_bounded(formula.args, depth)
            else:
                # Unknown predicate, leave as is
                return formula

        elif isinstance(formula, SepConj):
            return SepConj(
                self._unfold_recursive(formula.left, depth),
                self._unfold_recursive(formula.right, depth)
            )

        elif isinstance(formula, And):
            return And(
                self._unfold_recursive(formula.left, depth),
                self._unfold_recursive(formula.right, depth)
            )

        elif isinstance(formula, Or):
            return Or(
                self._unfold_recursive(formula.left, depth),
                self._unfold_recursive(formula.right, depth)
            )

        elif isinstance(formula, Not):
            return Not(self._unfold_recursive(formula.formula, depth))

        elif isinstance(formula, Exists):
            return Exists(
                formula.var,
                self._unfold_recursive(formula.formula, depth)
            )

        elif isinstance(formula, Forall):
            return Forall(
                formula.var,
                self._unfold_recursive(formula.formula, depth)
            )

        else:
            # Base formulas (Emp, PointsTo, True_, False_, Eq, Neq)
            return formula

    def get_predicate_base(self, pred_name: str) -> Optional[Tuple[Formula, Formula]]:
        """
        Get the spatial and numeric base for a predicate.

        Args:
            pred_name: Name of the predicate

        Returns:
            (spatial_base, numeric_base) tuple, or None if base computation is disabled
        """
        base_registry = self._get_base_registry()
        if base_registry is None:
            return None

        predicate = self.get(pred_name)
        if predicate is None:
            return None

        return base_registry.compute_base(predicate)

    def get_spatial_base(self, pred_name: str) -> Optional[Formula]:
        """
        Get the spatial base for a predicate.

        Args:
            pred_name: Name of the predicate

        Returns:
            Spatial base formula, or None if not available
        """
        base_registry = self._get_base_registry()
        if base_registry is None:
            return None

        # Check cache first
        cached = base_registry.get_spatial_base(pred_name)
        if cached is not None:
            return cached

        # Compute if predicate exists
        predicate = self.get(pred_name)
        if predicate is None:
            return None

        spatial_base, _ = base_registry.compute_base(predicate)
        return spatial_base

    def get_numeric_base(self, pred_name: str) -> Optional[Formula]:
        """
        Get the numeric base for a predicate.

        Args:
            pred_name: Name of the predicate

        Returns:
            Numeric base formula, or None if not available
        """
        base_registry = self._get_base_registry()
        if base_registry is None:
            return None

        # Check cache first
        cached = base_registry.get_numeric_base(pred_name)
        if cached is not None:
            return cached

        # Compute if predicate exists
        predicate = self.get(pred_name)
        if predicate is None:
            return None

        _, numeric_base = base_registry.compute_base(predicate)
        return numeric_base
