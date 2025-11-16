"""
Proof state tracking for cyclic proof detection

This module provides data structures and utilities for tracking proof states
during entailment checking to detect and handle cyclic reasoning.
"""

from typing import NamedTuple, FrozenSet, Tuple, Set, Dict, Optional, List
from frame.core.ast import PredicateCall, Var, Expr


class ProofStateKey(NamedTuple):
    """
    Key representing a unique proof state for cyclic detection.

    A proof state is identified by:
    - The predicate being unfolded
    - The root variables/arguments
    - The equivalence classes of variables (aliasing information)
    """
    predicate: str                              # e.g., "ls" or "dll"
    roots: Tuple[str, ...]                      # e.g., (x, y) or (x, p, y, q)
    eq_classes: FrozenSet[FrozenSet[str]]       # partition of aliases


class UnionFind:
    """
    Union-Find data structure for tracking equivalence classes.
    """
    def __init__(self):
        self.parent: Dict[str, str] = {}
        self.rank: Dict[str, int] = {}

    def find(self, x: str) -> str:
        """Find the representative of x's equivalence class"""
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0
            return x

        # Path compression
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: str, y: str) -> None:
        """Union the equivalence classes of x and y"""
        root_x = self.find(x)
        root_y = self.find(y)

        if root_x == root_y:
            return

        # Union by rank
        if self.rank[root_x] < self.rank[root_y]:
            self.parent[root_x] = root_y
        elif self.rank[root_x] > self.rank[root_y]:
            self.parent[root_y] = root_x
        else:
            self.parent[root_y] = root_x
            self.rank[root_x] += 1

    def get_equivalence_classes(self) -> List[Set[str]]:
        """
        Get all equivalence classes as a list of sets.

        Returns:
            List of sets, where each set contains equivalent variables
        """
        classes: Dict[str, Set[str]] = {}

        for var in self.parent.keys():
            root = self.find(var)
            if root not in classes:
                classes[root] = set()
            classes[root].add(var)

        return list(classes.values())


class EqualitySolver:
    """
    Tracks and propagates equality constraints for proof state tracking.
    """
    def __init__(self):
        self.uf = UnionFind()

    def add_equality(self, x: str, y: str) -> None:
        """Record that x = y"""
        self.uf.union(x, y)

    def are_equal(self, x: str, y: str) -> bool:
        """Check if x and y are in the same equivalence class"""
        return self.uf.find(x) == self.uf.find(y)

    def get_equivalence_classes(self) -> FrozenSet[FrozenSet[str]]:
        """
        Get equivalence classes as a frozen set of frozen sets.

        This format is suitable for use in ProofStateKey.
        """
        classes = self.uf.get_equivalence_classes()
        return frozenset(frozenset(cls) for cls in classes)


def make_state_key(pred_call: PredicateCall, eq_solver: EqualitySolver) -> ProofStateKey:
    """
    Create a ProofStateKey from a predicate call and equality context.

    Args:
        pred_call: The predicate call being unfolded
        eq_solver: Current equality solver with known equivalences

    Returns:
        A ProofStateKey representing this proof state
    """
    # Extract argument names (assume they are variables for now)
    roots = tuple(_expr_to_string(arg) for arg in pred_call.args)

    return ProofStateKey(
        predicate=pred_call.name,
        roots=roots,
        eq_classes=eq_solver.get_equivalence_classes()
    )


def _expr_to_string(expr: Expr) -> str:
    """
    Convert an expression to a string representation.

    For simplicity, we use the expression's string representation.
    """
    if isinstance(expr, Var):
        return expr.name
    else:
        return str(expr)


class ProofContext:
    """
    Context for tracking proof state during entailment checking.

    This maintains the set of seen proof states to detect cycles.
    """
    def __init__(self):
        self.seen_states: Set[ProofStateKey] = set()
        self.eq_solver = EqualitySolver()

    def has_seen(self, key: ProofStateKey) -> bool:
        """Check if this proof state has been seen before"""
        return key in self.seen_states

    def mark_seen(self, key: ProofStateKey) -> None:
        """Mark this proof state as seen"""
        self.seen_states.add(key)

    def copy(self) -> 'ProofContext':
        """
        Create a copy of this context for branching.

        Each branch in the proof should have its own context copy.
        """
        new_ctx = ProofContext()
        new_ctx.seen_states = self.seen_states.copy()
        # Note: We share the equality solver for now
        # In a full implementation, this should also be copied
        new_ctx.eq_solver = self.eq_solver
        return new_ctx
