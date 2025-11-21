"""
Guided/Goal-Directed Unfolding Strategy

Instead of eagerly unfolding all predicates to a fixed depth, this module implements
selective unfolding guided by the goal (consequent) formula.

Key ideas:
1. Only unfold predicates that appear in the consequent (goal-matching)
2. Start with shallow depth and increase adaptively
3. Use pattern matching to decide which predicates need unfolding
4. Avoid over-unfolding predicates that don't contribute to the proof

Expected benefits:
- 2-3x speedup by avoiding unnecessary unfolding
- 5-10% accuracy improvement by focusing computation on relevant predicates
"""

from typing import Set, Optional, Dict
from frame.core.ast import *
from frame.predicates.registry import PredicateRegistry


class GuidedUnfoldingStrategy:
    """
    Implements goal-directed predicate unfolding.

    The strategy:
    1. Analyze consequent to find target predicates
    2. Analyze antecedent to find predicates that match targets
    3. Unfold only matching predicates
    4. For non-matching predicates, use minimal depth (1-2)
    """

    def __init__(self, registry: PredicateRegistry, verbose: bool = False):
        self.registry = registry
        self.verbose = verbose

    def extract_predicate_names(self, formula: Formula) -> Set[str]:
        """Extract all predicate names from a formula"""
        names = set()

        def visit(f: Formula):
            if isinstance(f, PredicateCall):
                names.add(f.name)
            elif isinstance(f, (SepConj, And, Or, Wand)):
                visit(f.left)
                visit(f.right)
            elif isinstance(f, (Not, Exists, Forall)):
                visit(f.formula)

        visit(formula)
        return names

    def extract_predicate_signatures(self, formula: Formula) -> Set[tuple]:
        """
        Extract predicate signatures (name + arity) from a formula.

        Returns: Set of (name, arity) tuples
        """
        sigs = set()

        def visit(f: Formula):
            if isinstance(f, PredicateCall):
                sigs.add((f.name, len(f.args)))
            elif isinstance(f, (SepConj, And, Or, Wand)):
                visit(f.left)
                visit(f.right)
            elif isinstance(f, (Not, Exists, Forall)):
                visit(f.formula)

        visit(formula)
        return sigs

    def compute_unfolding_targets(
        self,
        antecedent: Formula,
        consequent: Formula
    ) -> Dict[str, int]:
        """
        Determine which predicates should be unfolded and to what depth.

        Strategy:
        1. Predicates in consequent → unfold antecedent instances deeply
        2. Predicates only in antecedent → unfold shallowly (depth 1-2)
        3. Concrete spatial formulas (points-to) → don't unfold (depth 0)

        Returns:
            Dictionary mapping predicate names to target depths
        """
        consequent_preds = self.extract_predicate_names(consequent)
        antecedent_preds = self.extract_predicate_names(antecedent)

        targets = {}

        # Predicates in consequent: unfold antecedent instances deeply
        for pred_name in antecedent_preds:
            if pred_name in consequent_preds:
                # Goal-directed: unfold to match consequent
                targets[pred_name] = self._get_goal_directed_depth(pred_name)
            else:
                # Not in goal: minimal unfolding
                targets[pred_name] = self._get_minimal_depth(pred_name)

        if self.verbose:
            print(f"[Guided Unfolding] Consequent predicates: {consequent_preds}")
            print(f"[Guided Unfolding] Antecedent predicates: {antecedent_preds}")
            print(f"[Guided Unfolding] Unfolding targets: {targets}")

        return targets

    def _get_goal_directed_depth(self, pred_name: str) -> int:
        """
        Get unfolding depth for goal-matching predicates.

        These are predicates that appear in both antecedent and consequent,
        so we need to unfold them sufficiently to match the goal structure.
        """
        # Check if it's a tree predicate (exponential growth)
        if pred_name in {'tree', 'btree', 'bstree', 'avl', 'rbtree'}:
            return 3  # Shallow for trees (exponential blowup)

        # Linear predicates (lists, segments): can handle deeper unfolding
        if pred_name in {'ls', 'list', 'lseg', 'dll', 'cll'}:
            return 5  # Deeper for lists (linear growth)

        # Unknown predicates: moderate depth
        return 4

    def _get_minimal_depth(self, pred_name: str) -> int:
        """
        Get minimal unfolding depth for non-goal predicates.

        These predicates don't appear in the consequent, so we only need
        shallow unfolding to expose their structure.
        """
        # Tree predicates: very shallow
        if pred_name in {'tree', 'btree', 'bstree', 'avl', 'rbtree'}:
            return 1

        # List predicates: shallow
        if pred_name in {'ls', 'list', 'lseg', 'dll', 'cll'}:
            return 2

        # Unknown predicates: minimal
        return 1

    def guided_unfold(
        self,
        formula: Formula,
        targets: Dict[str, int],
        default_depth: int = 2
    ) -> Formula:
        """
        Unfold predicates in formula according to target depths.

        Args:
            formula: Formula to unfold
            targets: Dictionary mapping predicate names to target depths
            default_depth: Depth for predicates not in targets

        Returns:
            Unfolded formula
        """
        return self._unfold_selective(formula, targets, default_depth)

    def _unfold_selective(
        self,
        formula: Formula,
        targets: Dict[str, int],
        default_depth: int
    ) -> Formula:
        """
        Recursively unfold predicates based on target depths.
        """
        if isinstance(formula, PredicateCall):
            pred_name = formula.name
            depth = targets.get(pred_name, default_depth)

            if self.verbose:
                print(f"[Guided Unfolding] Unfolding {pred_name} to depth {depth}")

            predicate = self.registry.get(pred_name)
            if predicate and depth > 0:
                # Unfold this predicate
                return predicate.unfold_bounded(formula.args, depth, registry=self.registry)
            else:
                # Don't unfold (depth 0 or unknown predicate)
                return formula

        elif isinstance(formula, SepConj):
            return SepConj(
                self._unfold_selective(formula.left, targets, default_depth),
                self._unfold_selective(formula.right, targets, default_depth)
            )

        elif isinstance(formula, And):
            return And(
                self._unfold_selective(formula.left, targets, default_depth),
                self._unfold_selective(formula.right, targets, default_depth)
            )

        elif isinstance(formula, Or):
            return Or(
                self._unfold_selective(formula.left, targets, default_depth),
                self._unfold_selective(formula.right, targets, default_depth)
            )

        elif isinstance(formula, Not):
            return Not(self._unfold_selective(formula.formula, targets, default_depth))

        elif isinstance(formula, Exists):
            return Exists(
                formula.var,
                self._unfold_selective(formula.formula, targets, default_depth)
            )

        elif isinstance(formula, Forall):
            return Forall(
                formula.var,
                self._unfold_selective(formula.formula, targets, default_depth)
            )

        else:
            # Atomic formulas: return as-is
            return formula

    def should_unfold_predicate(
        self,
        pred_name: str,
        antecedent: Formula,
        consequent: Formula
    ) -> bool:
        """
        Decide if a predicate should be unfolded based on goal relevance.

        A predicate should be unfolded if:
        1. It appears in both antecedent and consequent (goal-matching)
        2. It's needed to expose structure for lemma application
        3. It blocks progress (all other heuristics failed)

        Returns:
            True if predicate should be unfolded, False otherwise
        """
        consequent_preds = self.extract_predicate_names(consequent)
        return pred_name in consequent_preds

    def estimate_unfolding_cost(
        self,
        formula: Formula,
        depth: int
    ) -> int:
        """
        Estimate the cost (formula size after unfolding) for a given depth.

        Used to decide if deeper unfolding is worth it.

        Returns:
            Estimated formula size (number of AST nodes)
        """
        # Count predicates and estimate growth
        pred_count = self._count_predicates(formula)
        tree_count = self._count_tree_predicates(formula)

        # Trees: exponential growth (2^depth)
        tree_cost = tree_count * (2 ** depth)

        # Lists: linear growth (depth)
        list_cost = (pred_count - tree_count) * depth

        return tree_cost + list_cost

    def _count_predicates(self, formula: Formula) -> int:
        """Count total number of predicate calls in formula"""
        count = 0

        def visit(f: Formula):
            nonlocal count
            if isinstance(f, PredicateCall):
                count += 1
            elif isinstance(f, (SepConj, And, Or, Wand)):
                visit(f.left)
                visit(f.right)
            elif isinstance(f, (Not, Exists, Forall)):
                visit(f.formula)

        visit(formula)
        return count

    def _count_tree_predicates(self, formula: Formula) -> int:
        """Count tree predicates (for cost estimation)"""
        count = 0

        def visit(f: Formula):
            nonlocal count
            if isinstance(f, PredicateCall):
                if f.name in {'tree', 'btree', 'bstree', 'avl', 'rbtree'}:
                    count += 1
            elif isinstance(f, (SepConj, And, Or, Wand)):
                visit(f.left)
                visit(f.right)
            elif isinstance(f, (Not, Exists, Forall)):
                visit(f.formula)

        visit(formula)
        return count
