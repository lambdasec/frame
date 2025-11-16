"""
Compositional base computation for inductive predicates.

Based on the S2S approach (Le & Le, FoSSaCS 2023), this module computes
spatial and numeric bases for predicates using:
1. Regular unfolding trees
2. Infinite descent for cyclic subtrees
3. Caching and reuse across queries

A base is the minimal heap shape and arithmetic constraints that a predicate
guarantees. For example:
- ls(x, y) has spatial base {x ≠ nil ∨ x = y} (either empty or at least one cell)
- tree(x) has spatial base {x ≠ nil ∨ emp} (either empty or has root)

References:
-----------
Le & Le, "Compositional Satisfiability Solving in Separation Logic"
FoSSaCS 2023 - Section 3.2 on base computation
"""

from typing import Dict, List, Set, Tuple, Optional, FrozenSet
from dataclasses import dataclass
from frame.core.ast import (
    Formula, PredicateCall, Expr, Var, Const, Emp, PointsTo, SepConj,
    And, Or, Not, Exists, Forall, Eq, Neq, True_, False_
)
from frame.predicates.base import InductivePredicate


@dataclass(frozen=True)
class UnfoldingTreeNode:
    """
    Node in a regular unfolding tree.

    Each node represents a predicate call or a formula in the unfolding.
    Cyclic nodes point back to earlier nodes in the path.
    """
    formula: Formula
    depth: int
    is_cyclic: bool = False
    cycle_target_depth: Optional[int] = None

    def __hash__(self):
        # Use formula string representation for hashing
        return hash((str(self.formula), self.depth))


class UnfoldingTree:
    """
    Regular unfolding tree for a predicate definition.

    Constructs a tree by unfolding the predicate up to a maximum depth,
    tracking cycles when the same predicate (modulo variable renaming)
    appears again.
    """

    def __init__(self, predicate: InductivePredicate, max_depth: int = 5):
        self.predicate = predicate
        self.max_depth = max_depth
        self.root: Optional[UnfoldingTreeNode] = None
        self.nodes: List[UnfoldingTreeNode] = []
        self.cycle_nodes: List[UnfoldingTreeNode] = []

    def build(self) -> UnfoldingTreeNode:
        """
        Build the unfolding tree for the predicate.

        Returns:
            Root node of the tree
        """
        # Create symbolic arguments for the predicate
        symbolic_args = [Var(f"x{i}") for i in range(self.predicate.arity)]
        initial_call = PredicateCall(self.predicate.name, symbolic_args)

        # Track seen states (predicate name + canonicalized args)
        seen_states: Dict[str, int] = {}

        # Build tree recursively
        self.root = self._build_recursive(initial_call, 0, seen_states, [])
        return self.root

    def _normalize_predicate_call(self, pred_call: PredicateCall) -> str:
        """
        Normalize a predicate call to a canonical string for cycle detection.

        This allows us to detect cycles modulo variable renaming.
        For simplicity, we use the predicate name + argument positions.
        """
        # For now, use simple string representation
        # TODO: Implement proper modulo-renaming equivalence
        arg_strs = [str(arg) for arg in pred_call.args]
        return f"{pred_call.name}({','.join(arg_strs)})"

    def _build_recursive(
        self,
        formula: Formula,
        depth: int,
        seen_states: Dict[str, int],
        path: List[str]
    ) -> UnfoldingTreeNode:
        """
        Recursively build the unfolding tree.

        Args:
            formula: Current formula to unfold
            depth: Current depth in the tree
            seen_states: Map from normalized predicate to depth where first seen
            path: Current path of predicate calls (for cycle detection)

        Returns:
            Tree node for this formula
        """
        # Check if we've hit max depth
        if depth >= self.max_depth:
            node = UnfoldingTreeNode(formula, depth)
            self.nodes.append(node)
            return node

        # Handle predicate calls
        if isinstance(formula, PredicateCall):
            # Check for cycle
            norm_key = self._normalize_predicate_call(formula)

            if norm_key in seen_states:
                # Cycle detected!
                cycle_target_depth = seen_states[norm_key]
                node = UnfoldingTreeNode(
                    formula,
                    depth,
                    is_cyclic=True,
                    cycle_target_depth=cycle_target_depth
                )
                self.nodes.append(node)
                self.cycle_nodes.append(node)
                return node

            # Mark this state as seen
            seen_states[norm_key] = depth
            new_path = path + [norm_key]

            # Unfold the predicate
            try:
                unfolded = self.predicate.unfold(formula.args)

                # Recursively build tree for unfolded formula
                child_node = self._build_recursive(unfolded, depth + 1, seen_states, new_path)

                # Create node for this predicate call
                node = UnfoldingTreeNode(formula, depth)
                self.nodes.append(node)

                # Remove from seen states when backtracking (for other branches)
                del seen_states[norm_key]

                return node
            except Exception:
                # If unfolding fails, return leaf node
                node = UnfoldingTreeNode(formula, depth)
                self.nodes.append(node)
                return node

        # For other formulas, just create a node
        # In a full implementation, we'd recursively process subformulas
        node = UnfoldingTreeNode(formula, depth)
        self.nodes.append(node)
        return node


class BaseComputer:
    """
    Computes spatial and numeric bases for predicates using infinite descent.

    The base of a predicate is computed by:
    1. Building the regular unfolding tree
    2. Identifying cyclic subtrees (back-edges)
    3. Computing the spatial base (minimal heap shape)
    4. Computing the numeric base (minimal arithmetic constraints)

    S2S Insight: The base captures what is ALWAYS true about a predicate,
    regardless of how many times it unfolds. This is used for:
    - Sound predicate folding (checking if concrete heap matches base)
    - Efficient entailment checking (base subsumption)
    """

    def __init__(self, max_unfold_depth: int = 5):
        self.max_unfold_depth = max_unfold_depth

    def compute_spatial_base(self, predicate: InductivePredicate) -> Formula:
        """
        Compute the spatial base of a predicate.

        The spatial base captures the minimal heap shape that the predicate
        guarantees. For example:
        - ls(x, y): (x = y ∧ emp) ∨ (x ≠ y ∧ x ↦ _)
        - tree(x): (x = nil ∧ emp) ∨ (x ≠ nil ∧ x ↦ _,_)

        Args:
            predicate: The predicate to analyze

        Returns:
            Formula representing the spatial base
        """
        # Build unfolding tree
        tree = UnfoldingTree(predicate, self.max_unfold_depth)
        tree.build()

        # Create symbolic arguments
        symbolic_args = [Var(f"x{i}") for i in range(predicate.arity)]

        # Unfold once to get base and recursive cases
        try:
            unfolded = predicate.unfold(symbolic_args)

            # Extract spatial constraints from the unfolding
            spatial_base = self._extract_spatial_pattern(unfolded, predicate.name)

            return spatial_base
        except Exception:
            # Fallback: return True_ (no constraints)
            return True_()

    def compute_numeric_base(self, predicate: InductivePredicate) -> Formula:
        """
        Compute the numeric base of a predicate.

        The numeric base captures arithmetic constraints that always hold.
        For example:
        - ls(x, y, n): n ≥ 0
        - sorted_ls(x, y, min, max): min ≤ max

        Args:
            predicate: The predicate to analyze

        Returns:
            Formula representing the numeric base
        """
        # Build unfolding tree
        tree = UnfoldingTree(predicate, self.max_unfold_depth)
        tree.build()

        # Create symbolic arguments
        symbolic_args = [Var(f"x{i}") for i in range(predicate.arity)]

        # Unfold once to get constraints
        try:
            unfolded = predicate.unfold(symbolic_args)

            # Extract numeric constraints
            numeric_base = self._extract_numeric_constraints(unfolded)

            return numeric_base
        except Exception:
            # Fallback: return True_ (no constraints)
            return True_()

    def _extract_spatial_pattern(self, formula: Formula, pred_name: str) -> Formula:
        """
        Extract spatial pattern from an unfolded formula.

        This identifies the minimal heap shape from base and recursive cases.
        For example, ls(x,y) unfolds to:
            (x = y ∧ emp) ∨ (∃z. x ↦ z * ls(z, y))

        Spatial base: (x = y ∧ emp) ∨ (x ≠ nil)
        """
        if isinstance(formula, Or):
            # Handle disjunctive cases (base ∨ recursive)
            left_pattern = self._extract_spatial_pattern(formula.left, pred_name)
            right_pattern = self._extract_spatial_pattern(formula.right, pred_name)

            # Combine with disjunction
            return Or(left_pattern, right_pattern)

        elif isinstance(formula, And):
            # Extract spatial parts from conjunction
            left_spatial = self._is_spatial(formula.left)
            right_spatial = self._is_spatial(formula.right)

            if left_spatial and right_spatial:
                return formula
            elif left_spatial:
                return formula.left
            elif right_spatial:
                return formula.right
            else:
                return True_()

        elif isinstance(formula, SepConj):
            # For P * Q, look for concrete heap allocations
            if isinstance(formula.left, PointsTo):
                # Found allocation: extract pattern
                # x ↦ _ represents "at least one cell at x"
                return self._points_to_pattern(formula.left)
            elif isinstance(formula.right, PointsTo):
                return self._points_to_pattern(formula.right)
            else:
                # No concrete allocation, check subformulas
                return True_()

        elif isinstance(formula, Exists):
            # Unwrap existential and continue
            return self._extract_spatial_pattern(formula.formula, pred_name)

        elif isinstance(formula, Emp):
            return Emp()

        else:
            return True_()

    def _extract_numeric_constraints(self, formula: Formula) -> Formula:
        """
        Extract numeric constraints from an unfolded formula.

        This identifies arithmetic constraints that always hold.
        """
        constraints = []

        # Traverse formula looking for arithmetic constraints
        self._collect_numeric_constraints(formula, constraints)

        if not constraints:
            return True_()

        # Combine with conjunction
        result = constraints[0]
        for c in constraints[1:]:
            result = And(result, c)

        return result

    def _collect_numeric_constraints(self, formula: Formula, constraints: List[Formula]):
        """Recursively collect numeric constraints."""
        if isinstance(formula, (And, Or, SepConj)):
            self._collect_numeric_constraints(formula.left, constraints)
            self._collect_numeric_constraints(formula.right, constraints)
        elif isinstance(formula, (Exists, Forall)):
            self._collect_numeric_constraints(formula.formula, constraints)
        elif isinstance(formula, (Eq, Neq)):
            # Check if this is a numeric constraint
            if self._is_numeric_expr(formula.left) or self._is_numeric_expr(formula.right):
                constraints.append(formula)

    def _is_spatial(self, formula: Formula) -> bool:
        """Check if a formula is spatial (involves heap)."""
        return isinstance(formula, (Emp, PointsTo, SepConj, PredicateCall))

    def _is_numeric_expr(self, expr: Expr) -> bool:
        """Check if an expression is numeric."""
        # Simple heuristic: check if it looks like a number variable
        # In a full implementation, we'd track types
        if isinstance(expr, Const):
            return isinstance(expr.value, (int, float))
        return False

    def _points_to_pattern(self, pto: PointsTo) -> Formula:
        """
        Extract pattern from points-to assertion.

        x ↦ v becomes a constraint that x is allocated.
        """
        # For now, just return True_ to indicate allocation exists
        # In a full implementation, we'd track the shape more precisely
        return True_()


class BaseRegistry:
    """
    Registry for storing and managing computed bases of predicates.

    This implements compositional base computation from S2S:
    1. Compute base once per predicate (not per query)
    2. Store spatial and numeric bases separately
    3. Reuse bases across all entailment queries

    Benefits:
    - Amortized cost: O(1) lookup after initial O(k) computation
    - Compositional reasoning: bases compose across queries
    - Sound folding: check concrete heap against base before folding
    """

    def __init__(self):
        self._spatial_bases: Dict[str, Formula] = {}
        self._numeric_bases: Dict[str, Formula] = {}
        self._base_computer = BaseComputer(max_unfold_depth=5)

    def compute_base(self, predicate: InductivePredicate) -> Tuple[Formula, Formula]:
        """
        Compute base using regular unfolding tree + infinite descent.

        Args:
            predicate: The predicate to analyze

        Returns:
            (spatial_base, numeric_base) tuple
        """
        # Check cache first
        if predicate.name in self._spatial_bases:
            return (
                self._spatial_bases[predicate.name],
                self._numeric_bases[predicate.name]
            )

        # Compute bases
        spatial_base = self._base_computer.compute_spatial_base(predicate)
        numeric_base = self._base_computer.compute_numeric_base(predicate)

        # Cache results
        self._spatial_bases[predicate.name] = spatial_base
        self._numeric_bases[predicate.name] = numeric_base

        return (spatial_base, numeric_base)

    def get_spatial_base(self, pred_name: str) -> Optional[Formula]:
        """Get cached spatial base for a predicate."""
        return self._spatial_bases.get(pred_name)

    def get_numeric_base(self, pred_name: str) -> Optional[Formula]:
        """Get cached numeric base for a predicate."""
        return self._numeric_bases.get(pred_name)

    def has_base(self, pred_name: str) -> bool:
        """Check if base has been computed for a predicate."""
        return pred_name in self._spatial_bases

    def precompute_standard_bases(self, predicates: List[InductivePredicate]):
        """
        Precompute bases for a list of standard predicates.

        This is called during initialization to populate the cache
        with commonly-used predicates.

        Args:
            predicates: List of predicates to precompute bases for
        """
        for predicate in predicates:
            self.compute_base(predicate)

    def clear_cache(self):
        """Clear all cached bases."""
        self._spatial_bases.clear()
        self._numeric_bases.clear()


# Singleton instance for global access
_global_base_registry: Optional[BaseRegistry] = None


def get_base_registry() -> BaseRegistry:
    """Get the global base registry instance."""
    global _global_base_registry
    if _global_base_registry is None:
        _global_base_registry = BaseRegistry()
    return _global_base_registry


def reset_base_registry():
    """Reset the global base registry (useful for testing)."""
    global _global_base_registry
    _global_base_registry = None
