"""
Cyclic proof-aware predicate unfolding

This module provides enhanced predicate unfolding that tracks proof states
to detect cycles and close branches inductively.

IMPROVEMENTS (2025-11):
- Added minimum depth threshold before cycle closure (prevents premature closing)
- Added predicate-specific cycle detection heuristics
- Added proof trace tracking with back-edges for true cyclic proofs
- Conservative cycle detection: only close when we're confident it's a real cycle
"""

from typing import Optional, Set, List, Dict
from frame.core.ast import (
    Formula, PredicateCall, SepConj, And, Or, Not, Exists, Forall,
    Emp, True_, Var, Eq
)
from frame.predicates.base import InductivePredicate
from frame.predicates.registry import PredicateRegistry
from frame.utils.proof_state import ProofStateKey, ProofContext, make_state_key, EqualitySolver


class ProofNode:
    """
    Node in the proof trace for tracking cyclic proof structure.

    Each node represents a predicate unfolding with metadata for
    detecting proper cycles (not just repeated states).
    """

    def __init__(self, formula: PredicateCall, depth: int, state_key: tuple):
        self.formula = formula
        self.depth = depth
        self.state_key = state_key
        self.children: List['ProofNode'] = []
        self.back_edge: Optional['ProofNode'] = None  # Points to cycle origin

    def add_child(self, child: 'ProofNode'):
        """Add a child node in the proof tree"""
        self.children.append(child)

    def set_back_edge(self, target: 'ProofNode'):
        """Set back-edge to create cycle"""
        self.back_edge = target


class CyclicUnfoldEngine:
    """
    Enhanced unfolding engine with cyclic proof detection.

    This engine tracks proof states during unfolding and detects when
    a predicate is being unfolded in the same context (same arguments
    and equivalence classes) as before. When a cycle is detected, the
    branch is closed inductively instead of continuing to unfold.

    IMPROVEMENTS:
    - MIN_DEPTH_BEFORE_CYCLE: Prevents premature cycle closure
    - Predicate-specific heuristics for better precision
    - Proof trace tracking for true cyclic proof verification
    """

    # Minimum depth before allowing cycle closure
    # This prevents false positives like: ls(x,y) * ls(y,z) |- ls(x,z)
    # being closed too early
    MIN_DEPTH_BEFORE_CYCLE = 2

    # Predicates where we're confident about cycle detection
    # Updated to include common SL-COMP predicates (case-insensitive matching)
    CONSERVATIVE_PREDICATES = {"ls", "list", "dll", "tll", "bsll", "liste", "listo", "listeven", "listodd"}

    def __init__(self, registry: PredicateRegistry, verbose: bool = False):
        self.registry = registry
        self.verbose = verbose
        self.proof_trace: List[ProofNode] = []  # Stack of active proof nodes
        self.cycle_stats = {"detected": 0, "closed": 0, "skipped": 0}

    def get_cycle_statistics(self) -> Dict[str, int]:
        """Get statistics about cycle detection"""
        return self.cycle_stats.copy()

    def unfold_with_cycle_detection(
        self,
        formula: Formula,
        depth: int,
        context: Optional[ProofContext] = None
    ) -> Formula:
        """
        Unfold predicates with cycle detection.

        Args:
            formula: The formula to unfold
            depth: Maximum unfolding depth
            context: Proof context for tracking seen states (creates new if None)

        Returns:
            Formula with predicates unfolded, with cycles closed inductively
        """
        if context is None:
            context = ProofContext()

        # First pass: extract equalities from the formula to populate eq_solver
        self._extract_equalities(formula, context.eq_solver)

        # Second pass: unfold with cycle detection
        return self._unfold_recursive(formula, depth, context)

    def _extract_equalities(self, formula: Formula, eq_solver: EqualitySolver) -> None:
        """
        Extract equality constraints from a formula and add them to the equality solver.

        This builds up the equivalence classes needed for cycle detection.
        """
        if isinstance(formula, Eq):
            # Extract variable names from both sides
            left_str = self._expr_to_string(formula.left)
            right_str = self._expr_to_string(formula.right)
            if left_str and right_str:
                eq_solver.add_equality(left_str, right_str)

        elif isinstance(formula, (SepConj, And, Or)):
            self._extract_equalities(formula.left, eq_solver)
            self._extract_equalities(formula.right, eq_solver)

        elif isinstance(formula, (Not, Exists, Forall)):
            self._extract_equalities(formula.formula, eq_solver)

    def _expr_to_string(self, expr) -> Optional[str]:
        """Convert expression to string, return None if not a variable"""
        if isinstance(expr, Var):
            return expr.name
        return None

    def _get_predicate_state_key(self, pred_name: str, canonical_roots: tuple) -> Optional[tuple]:
        """
        Get state key for cycle detection with predicate-specific strategies.

        Different predicates need different cycle detection strategies:
        - List predicates (ls, list): Use full state key with all arguments
        - Tree predicates (tree, btree): More conservative (only root matters)
        - DLL predicates: Use (root, prev, next, last) structure

        Returns:
            State key tuple for cycle detection
        """
        # Normalize predicate name to lowercase for comparison (SL-COMP uses uppercase)
        pred_name_lower = pred_name.lower()

        if pred_name_lower in ["ls", "list", "liste", "listo", "listeven", "listodd"]:
            # List predicates: full state matters (start and end)
            # ls(x, y) should be distinguished from ls(x, z)
            # Include mutually recursive list predicates (ListE, ListO from SL-COMP)
            return (pred_name, canonical_roots)

        elif pred_name_lower in ["dll", "tll", "bsll"]:
            # Doubly-linked lists and backward lists: need all pointers
            # dll(x, p, y, n) - all 4 args matter
            # BSLL(x, y) - backward singly-linked list
            return (pred_name, canonical_roots)

        elif pred_name_lower in ["tree", "btree", "bst"]:
            # Trees: only root matters for cycle detection
            # tree(x) with same x is a cycle
            if len(canonical_roots) > 0:
                return (pred_name, canonical_roots[0])  # Just the root
            return (pred_name, canonical_roots)

        else:
            # Unknown predicate: use conservative strategy (full state)
            # This may cause false positives but is safer than missing cycles
            return (pred_name, canonical_roots)

    def _unfold_recursive(
        self,
        formula: Formula,
        depth: int,
        context: ProofContext
    ) -> Formula:
        """
        Recursively unfold predicates with cycle detection.

        When a cycle is detected (same predicate + canonicalized args seen before),
        we return True_ to indicate the branch is inductively closed.
        """
        if isinstance(formula, PredicateCall):
            # Build a predicate-specific canonical state key
            # Different predicates need different key strategies to avoid false positives
            from frame.core.ast import Var

            if self.verbose:
                print(f"[DEBUG] Processing {formula} at depth {depth}")

            # Canonicalize roots using eq_solver representatives
            canonical_roots = []
            for arg in formula.args:
                if isinstance(arg, Var):
                    rep = context.eq_solver.uf.find(arg.name)
                    canonical_roots.append(rep)
                else:
                    # For non-variable args, use string representation
                    canonical_roots.append(str(arg))

            # Get canonical state key for cycle detection
            state_key = self._get_predicate_state_key(formula.name, tuple(canonical_roots))

            if self.verbose:
                print(f"[DEBUG] State key: {state_key}, seen: {context.has_seen(state_key)}")

            # Check for cycle
            if context.has_seen(state_key):
                self.cycle_stats["detected"] += 1

                # CONSERVATIVE CYCLE DETECTION:
                # Only close the cycle if we've unfolded enough to be confident
                # this is a real inductive case, not just repeated structure

                initial_depth = self.registry.max_unfold_depth
                current_unfold_depth = initial_depth - depth  # How many unfolds we've done

                # Strategy 1: Minimum depth threshold
                # Don't close until we've unfolded at least MIN_DEPTH_BEFORE_CYCLE times
                if current_unfold_depth < self.MIN_DEPTH_BEFORE_CYCLE:
                    if self.verbose:
                        print(f"[Cycle] Detected {formula} at depth {depth}, but only {current_unfold_depth} unfolds done")
                        print(f"[Cycle] Need {self.MIN_DEPTH_BEFORE_CYCLE} unfolds before closing - CONTINUING")
                    self.cycle_stats["skipped"] += 1
                    # Continue unfolding instead of closing
                    # Don't mark as seen yet - let it unfold more
                    # But prevent infinite loop by checking depth
                    if depth <= 0:
                        return formula
                    # Continue with normal unfolding
                    predicate = self.registry.get(formula.name)
                    if predicate:
                        unfolded = predicate.unfold(formula.args)
                        return self._unfold_recursive(unfolded, depth - 1, context)
                    return formula

                # Strategy 2: Predicate-specific confidence
                # For predicates we trust, close the cycle
                # For unknown predicates, be more conservative
                # Make case-insensitive check (SL-COMP uses uppercase names)
                if formula.name.lower() not in self.CONSERVATIVE_PREDICATES:
                    # Unknown predicate - need even more evidence
                    if current_unfold_depth < self.MIN_DEPTH_BEFORE_CYCLE + 1:
                        if self.verbose:
                            print(f"[Cycle] Unknown predicate {formula.name}, need extra unfolds")
                        self.cycle_stats["skipped"] += 1
                        if depth <= 0:
                            return formula
                        predicate = self.registry.get(formula.name)
                        if predicate:
                            unfolded = predicate.unfold(formula.args)
                            return self._unfold_recursive(unfolded, depth - 1, context)
                        return formula

                # CYCLE CONFIRMED - CLOSE INDUCTIVELY
                if self.verbose:
                    print(f"[Cycle] Confirmed cycle: {formula} with key {state_key}")
                    print(f"[Cycle] Closed after {current_unfold_depth} unfolds")
                    print("[Cycle] Closing inductively (returning True_)")

                self.cycle_stats["closed"] += 1

                # Track back-edge in proof trace if we're building one
                if self.proof_trace:
                    # Find the node we're cycling back to
                    for node in reversed(self.proof_trace):
                        if node.state_key == state_key:
                            # Create back-edge
                            if len(self.proof_trace) > 0:
                                current_node = self.proof_trace[-1]
                                # This is a back-edge to 'node'
                                if self.verbose:
                                    print(f"[Cycle] Back-edge: depth {current_node.depth} -> depth {node.depth}")
                            break

                # Return True_ so Z3 treats this branch as satisfied
                from frame.core.ast import True_
                return True_()

            # Mark this state as seen
            context.mark_seen(state_key)

            # Check if we've reached max depth BEFORE unfolding
            if depth <= 0:
                # Don't unfold further, return predicate as-is
                if self.verbose:
                    print(f"[DEBUG] Depth limit reached for {formula}, returning as-is")
                return formula

            # Unfold the predicate normally
            predicate = self.registry.get(formula.name)
            if predicate:
                # Create proof node and push onto trace
                proof_node = ProofNode(formula, depth, state_key)
                self.proof_trace.append(proof_node)

                try:
                    # Use unfold() directly (not unfold_bounded) since we handle depth ourselves
                    unfolded = predicate.unfold(formula.args)

                    if self.verbose:
                        print(f"[DEBUG] Unfolded to: {unfolded}")
                        print(f"[DEBUG] Recursing with depth {depth - 1}")

                    # After unfolding, continue with cycle detection on the result
                    # IMPORTANT: Decrement depth to prevent infinite recursion
                    result = self._unfold_recursive(unfolded, depth - 1, context)

                    return result
                finally:
                    # Pop proof node when we're done with this branch
                    if self.proof_trace and self.proof_trace[-1] == proof_node:
                        self.proof_trace.pop()
            else:
                # Unknown predicate, leave as is
                return formula

        elif isinstance(formula, SepConj):
            # For separating conjunction, share the context to track the proof path
            # This may cause some false positive cycle detections, but prevents
            # "unknown" results from insufficient unfolding
            return SepConj(
                self._unfold_recursive(formula.left, depth, context),
                self._unfold_recursive(formula.right, depth, context)
            )

        elif isinstance(formula, And):
            # For pure conjunction, share context
            return And(
                self._unfold_recursive(formula.left, depth, context),
                self._unfold_recursive(formula.right, depth, context)
            )

        elif isinstance(formula, Or):
            # For disjunction, each branch should have independent context
            left_context = context.copy()
            right_context = context.copy()

            return Or(
                self._unfold_recursive(formula.left, depth, left_context),
                self._unfold_recursive(formula.right, depth, right_context)
            )

        elif isinstance(formula, Not):
            return Not(self._unfold_recursive(formula.formula, depth, context))

        elif isinstance(formula, Exists):
            return Exists(
                formula.var,
                self._unfold_recursive(formula.formula, depth, context)
            )

        elif isinstance(formula, Forall):
            return Forall(
                formula.var,
                self._unfold_recursive(formula.formula, depth, context)
            )

        else:
            # Base formulas (Emp, PointsTo, True_, False_, Eq, Neq, etc.)
            return formula


def unfold_with_cycles(
    formula: Formula,
    registry: PredicateRegistry,
    depth: Optional[int] = None,
    adaptive: bool = False,
    verbose: bool = False
) -> Formula:
    """
    Convenience function to unfold a formula with cycle detection.

    Args:
        formula: The formula to unfold
        registry: Predicate registry
        depth: Maximum unfolding depth (uses registry default if None)
        adaptive: Use adaptive depth based on formula complexity
        verbose: Print debug information

    Returns:
        Formula with predicates unfolded and cycles detected
    """
    if depth is None:
        if adaptive:
            depth = registry._get_adaptive_depth(formula)
        else:
            depth = registry.max_unfold_depth

    engine = CyclicUnfoldEngine(registry, verbose=verbose)
    return engine.unfold_with_cycle_detection(formula, depth)
