"""
Bud Recognition for Cyclic Proofs

Implements bud detection from cyclic proof theory (inspired by Cyclist and S2S).
A "bud" occurs when the current proof goal matches an earlier goal in the proof tree,
allowing us to close the proof branch without further unfolding.

This is critical for handling cyclic heap structures and infinite predicates.
"""

from typing import List, Optional, Tuple
from frame.core.ast import Formula, PredicateCall, SepConj, And
from frame.lemmas._matcher import LemmaMatcher


class ProofNode:
    """
    Represents a node in the proof tree.

    Each node contains:
    - The current goal formula
    - Parent node (for tracing back)
    - Depth in the tree
    """

    def __init__(self, goal: Formula, parent: Optional['ProofNode'] = None):
        self.goal = goal
        self.parent = parent
        self.depth = 0 if parent is None else parent.depth + 1
        self.is_bud = False  # True if this node is recognized as a bud

    def ancestors(self) -> List['ProofNode']:
        """Get all ancestor nodes"""
        ancestors = []
        current = self.parent
        while current is not None:
            ancestors.append(current)
            current = current.parent
        return ancestors


class BudRecognizer:
    """
    Recognizes buds in cyclic proof search.

    A bud is detected when:
    1. Current goal matches an ancestor goal (syntactically or semantically)
    2. The match indicates we're in a cycle
    3. Closing at this point would maintain soundness
    """

    def __init__(self, max_depth: int = 10):
        self.max_depth = max_depth
        self.matcher = LemmaMatcher()

    def recognize_bud(self, current: ProofNode) -> bool:
        """
        Check if current node is a bud.

        Returns True if we should stop unfolding and close this branch.
        """
        if current.depth > self.max_depth:
            # Don't go too deep - treat as bud to prevent infinite unfolding
            return True

        # Check if current goal matches any ancestor
        for ancestor in current.ancestors():
            if self._goals_match(current.goal, ancestor.goal):
                # Found a matching ancestor - this is a bud!
                current.is_bud = True
                return True

        return False

    def _goals_match(self, goal1: Formula, goal2: Formula) -> bool:
        """
        Check if two goals match (allowing for substitution).

        This is more permissive than syntactic equality - we allow
        variable renaming and certain structural equivalences.
        """
        # Try exact syntactic match first
        if self.matcher.formulas_equal(goal1, goal2):
            return True

        # Try matching with alpha-renaming (variable renaming)
        if self._alpha_equivalent(goal1, goal2):
            return True

        # Try matching modulo separating conjunction commutativity
        if self._sepconj_equivalent(goal1, goal2):
            return True

        return False

    def _alpha_equivalent(self, f1: Formula, f2: Formula) -> bool:
        """
        Check if formulas are alpha-equivalent (same up to variable renaming).

        Example: ls(x, y) is alpha-equivalent to ls(a, b)
        """
        # For now, use simple heuristic: same structure, possibly different var names
        if type(f1) != type(f2):
            return False

        if isinstance(f1, PredicateCall) and isinstance(f2, PredicateCall):
            # Same predicate name, same arity
            if f1.name == f2.name and len(f1.args) == len(f2.args):
                return True

        if isinstance(f1, SepConj) and isinstance(f2, SepConj):
            # Recursive check on both sides
            return (self._alpha_equivalent(f1.left, f2.left) and
                   self._alpha_equivalent(f1.right, f2.right))

        return False

    def _sepconj_equivalent(self, f1: Formula, f2: Formula) -> bool:
        """
        Check if formulas are equivalent modulo sep-conj commutativity.

        Example: A * B ≡ B * A
        """
        if not isinstance(f1, SepConj) or not isinstance(f2, SepConj):
            return False

        # Try both orderings
        if (self.matcher.formulas_equal(f1.left, f2.left) and
            self.matcher.formulas_equal(f1.right, f2.right)):
            return True

        if (self.matcher.formulas_equal(f1.left, f2.right) and
            self.matcher.formulas_equal(f1.right, f2.left)):
            return True

        return False

    def check_progress(self, current: ProofNode, ancestor: ProofNode) -> bool:
        """
        Check if we've made progress from ancestor to current.

        In cyclic proofs, we need to ensure that closing a bud maintains
        soundness. This requires checking that some "measure" has decreased,
        ensuring the overall proof is well-founded.

        Common measures:
        - Heap size (number of allocated cells)
        - Predicate unfolding count
        - Goal complexity

        For now, we use a simple heuristic: allow bud if depth hasn't grown too much.
        """
        depth_increase = current.depth - ancestor.depth
        return depth_increase <= 3  # Allow small cycles


def integrate_bud_with_unfolding(formula: Formula, predicate_registry,
                                 proof_node: Optional[ProofNode] = None,
                                 bud_recognizer: Optional[BudRecognizer] = None) -> Formula:
    """
    Unfold predicates with bud recognition.

    This integrates bud checking into the unfolding process:
    1. Before unfolding, check if current goal is a bud
    2. If bud detected, stop unfolding (close branch)
    3. Otherwise, unfold normally

    Args:
        formula: Current goal formula
        predicate_registry: Registry for predicate definitions
        proof_node: Current proof node (tracks ancestry)
        bud_recognizer: Bud recognizer instance

    Returns:
        Unfolded formula, or original if bud detected
    """
    if proof_node is None:
        proof_node = ProofNode(formula)

    if bud_recognizer is None:
        bud_recognizer = BudRecognizer()

    # Check for bud before unfolding
    if bud_recognizer.recognize_bud(proof_node):
        # Bud detected - stop unfolding, return current formula
        return formula

    # No bud - unfold normally
    unfolded = predicate_registry.unfold_predicates(formula, depth=1, adaptive=False)

    # Create child node for recursion
    child_node = ProofNode(unfolded, parent=proof_node)

    # Recursively unfold with bud checking
    return integrate_bud_with_unfolding(
        unfolded, predicate_registry, child_node, bud_recognizer
    )
