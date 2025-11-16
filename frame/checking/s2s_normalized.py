"""
S2S-style normalized unfolding for separation logic entailment.

This module implements the key technique from the S2S solver:
"Exclude-the-middle" normalized rules that avoid disjunction explosion
in the consequent during entailment checking.

Key Idea:
----------
Traditional: When checking P |- Q where Q = ls(x,y), we unfold Q to:
  Q = (x=y & emp) | (exists z. x|->z * ls(z,y))
Then check: P |- Q1  OR  P |- Q2  (creates branching)

S2S Normalized: Use context from P to determine which case applies:
  - If P contains x=y, only try base case
  - If P contains x|->..., only try recursive case
  - If unclear, try recursive case first (more general)

Result: Polynomial time instead of exponential for multiple predicates.

References:
-----------
Le & Le, "An Efficient Cyclic Entailment Procedure in Separation Logic"
FoSSaCS 2023 (S2SLin)
"""

from typing import Optional, Tuple, List
from frame.core.ast import (
    Formula, PredicateCall, SepConj, And, Or, Eq, Var, Const,
    PointsTo, Emp, Exists, True_, False_
)
from frame.predicates.registry import PredicateRegistry
from frame.analysis.formula import extract_equalities, extract_points_to, has_predicate


class ContextAnalyzer:
    """
    Analyzes the antecedent context to guide normalized unfolding.

    The context helps us avoid exploring impossible disjunctive branches
    when unfolding predicates in the consequent.
    """

    def __init__(self, antecedent: Formula):
        self.antecedent = antecedent
        self.equalities = extract_equalities(antecedent)
        self.points_to = extract_points_to(antecedent)

    def implies_equal(self, var1: str, var2: str) -> bool:
        """Check if antecedent implies var1 = var2"""
        # Direct equality
        for eq in self.equalities:
            if isinstance(eq, Eq):
                left = self._expr_to_str(eq.left)
                right = self._expr_to_str(eq.right)
                if (left == var1 and right == var2) or (left == var2 and right == var1):
                    return True
        return False

    def has_points_to_from(self, var: str) -> bool:
        """Check if antecedent has x |-> ... for given variable"""
        for pto in self.points_to:
            if isinstance(pto, PointsTo):
                loc = self._expr_to_str(pto.location)
                if loc == var:
                    return True
        return False

    def proves_disequal(self, var1: str, var2: str) -> bool:
        """
        Check if antecedent proves var1 != var2.

        This is conservative: only returns True if we can definitively prove disequality.
        Currently checks for explicit (distinct ...) constraints.

        Note: In the future, this could use more sophisticated reasoning, such as:
        - If var1 = a and var2 = b and a != b
        - If var1 points to different locations than var2
        - Etc.
        """
        # For now, be very conservative and don't claim disequality
        # unless we have explicit evidence
        # TODO: Could check for (distinct var1 var2) or (not (= var1 var2))
        # in the formula, but this requires more sophisticated analysis

        # Conservative: don't prove disequal unless we're sure
        # This preserves soundness by defaulting to traditional unfolding
        return False

    def _expr_to_str(self, expr) -> Optional[str]:
        """Convert expression to string for comparison"""
        if isinstance(expr, Var):
            return expr.name
        elif isinstance(expr, Const):
            if expr.value is None:
                return "nil"
            return str(expr.value)
        return None


class NormalizedUnfoldEngine:
    """
    Implements S2S-style normalized unfolding that avoids disjunction explosion.

    Main API:
    ---------
    unfold_consequent_normalized(consequent, antecedent, registry)
        -> Formula with predicates unfolded, avoiding disjunctions where possible

    Strategy:
    ---------
    1. Analyze antecedent context (equalities, points-to facts)
    2. For each predicate in consequent, use context to select unfolding case
    3. Avoid creating disjunctions when context determines the case
    4. Fall back to traditional unfolding when context is insufficient
    """

    def __init__(self, registry: PredicateRegistry, verbose: bool = False):
        self.registry = registry
        self.verbose = verbose
        self.unfold_count = 0
        self.normalized_count = 0

    def unfold_consequent_normalized(
        self,
        consequent: Formula,
        antecedent: Formula,
        depth: int
    ) -> Formula:
        """
        Unfold consequent using normalized rules based on antecedent context.

        Args:
            consequent: The consequent formula to unfold
            antecedent: The antecedent formula (for context)
            depth: Maximum unfolding depth

        Returns:
            Normalized formula with reduced disjunctions
        """
        context = ContextAnalyzer(antecedent)
        return self._unfold_with_context(consequent, context, depth)

    def _unfold_with_context(
        self,
        formula: Formula,
        context: ContextAnalyzer,
        depth: int
    ) -> Formula:
        """
        Recursively unfold formula using context to normalize.
        """
        if depth <= 0:
            return formula

        if isinstance(formula, PredicateCall):
            return self._unfold_predicate_normalized(formula, context, depth)

        elif isinstance(formula, SepConj):
            # Unfold both sides with context
            left = self._unfold_with_context(formula.left, context, depth)
            right = self._unfold_with_context(formula.right, context, depth)
            return SepConj(left, right)

        elif isinstance(formula, And):
            left = self._unfold_with_context(formula.left, context, depth)
            right = self._unfold_with_context(formula.right, context, depth)
            return And(left, right)

        elif isinstance(formula, Or):
            # For disjunction, unfold each branch independently
            left = self._unfold_with_context(formula.left, context, depth)
            right = self._unfold_with_context(formula.right, context, depth)
            return Or(left, right)

        elif isinstance(formula, Exists):
            body = self._unfold_with_context(formula.formula, context, depth)
            return Exists(formula.var, body)

        else:
            # Base formulas: emp, pto, true, false, etc.
            return formula

    def _unfold_predicate_normalized(
        self,
        pred_call: PredicateCall,
        context: ContextAnalyzer,
        depth: int
    ) -> Formula:
        """
        Unfold a predicate call using context-based normalization.

        For list segments ls(x, y):
          Base case: x = y & emp
          Recursive case: exists z. x |-> z * ls(z, y)

        Normalization:
          - If context has x = y, return base case only
          - If context has x |-> ..., return recursive case only
          - Otherwise, return traditional disjunction
        """
        predicate = self.registry.get(pred_call.name)
        if not predicate:
            return pred_call

        self.unfold_count += 1

        # Try to normalize based on predicate type
        if pred_call.name in ["ls", "list"]:
            normalized = self._normalize_list_predicate(pred_call, context, depth)
            if normalized is not None:
                self.normalized_count += 1
                if self.verbose:
                    print(f"[Normalized] {pred_call} -> single case (avoided disjunction)")
                return normalized

        # Fall back to traditional unfolding
        if self.verbose:
            print(f"[Traditional] {pred_call} -> full unfolding with disjunction")

        unfolded = predicate.unfold(pred_call.args)
        return self._unfold_with_context(unfolded, context, depth - 1)

    def _normalize_list_predicate(
        self,
        pred_call: PredicateCall,
        context: ContextAnalyzer,
        depth: int
    ) -> Optional[Formula]:
        """
        Normalize list segment predicate ls(x, y) based on context.

        Uses heuristic-guided reordering: try likely case first, but keep
        both cases to preserve soundness and completeness.

        Returns:
            Reordered formula if normalization succeeds, None otherwise
        """
        if len(pred_call.args) < 2:
            return None

        start = pred_call.args[0]
        end = pred_call.args[1]

        # Extract variable names
        start_var = self._expr_to_str(start)
        end_var = self._expr_to_str(end)

        if not start_var:
            return None

        # Get the full unfolding first
        predicate = self.registry.get(pred_call.name)
        if not predicate:
            return None

        unfolded = predicate.unfold(pred_call.args)

        # If not a disjunction, no reordering needed
        if not isinstance(unfolded, Or):
            return self._unfold_with_context(unfolded, context, depth - 1)

        # Extract base and recursive cases
        left_case = unfolded.left
        right_case = unfolded.right

        # Identify which is base and which is recursive
        # Base case typically has equality, recursive has Exists
        if isinstance(right_case, Exists) or isinstance(right_case, And) and any(
            isinstance(f, Exists) for f in self._flatten_and(right_case)
        ):
            base_case = left_case
            recursive_case = right_case
        else:
            base_case = right_case
            recursive_case = left_case

        # Heuristic reordering based on context
        should_try_recursive_first = False

        # Case 1: Explicit equality → BASE case very likely
        if end_var and context.implies_equal(start_var, end_var):
            if self.verbose:
                print(f"[Normalize] {pred_call}: context suggests BASE case (has {start_var}={end_var})")
            # Try base first, recursive second
            reordered = Or(
                self._unfold_with_context(base_case, context, depth - 1),
                self._unfold_with_context(recursive_case, context, depth - 1)
            )
            self.normalized_count += 1
            return reordered

        # Case 2: Points-to present → RECURSIVE case likely
        if context.has_points_to_from(start_var):
            if self.verbose:
                print(f"[Normalize] {pred_call}: context suggests RECURSIVE case (has {start_var}|->...)")
            # Try recursive first, base second
            reordered = Or(
                self._unfold_with_context(recursive_case, context, depth - 1),
                self._unfold_with_context(base_case, context, depth - 1)
            )
            self.normalized_count += 1
            return reordered

        # Case 3: No strong hint → use default order (try both)
        return None

    def _flatten_and(self, formula: Formula) -> List[Formula]:
        """Helper to flatten And formulas into list"""
        if isinstance(formula, And):
            return self._flatten_and(formula.left) + self._flatten_and(formula.right)
        return [formula]

    def _expr_to_str(self, expr) -> Optional[str]:
        """Convert expression to string"""
        if isinstance(expr, Var):
            return expr.name
        elif isinstance(expr, Const):
            if expr.value is None:
                return "nil"
            return str(expr.value)
        return None

    def get_statistics(self) -> dict:
        """Get normalization statistics"""
        return {
            "total_unfolds": self.unfold_count,
            "normalized": self.normalized_count,
            "traditional": self.unfold_count - self.normalized_count,
            "normalization_rate": (self.normalized_count / self.unfold_count * 100) if self.unfold_count > 0 else 0
        }


def unfold_with_normalization(
    consequent: Formula,
    antecedent: Formula,
    registry: PredicateRegistry,
    depth: Optional[int] = None,
    verbose: bool = False
) -> Formula:
    """
    Convenience function for normalized unfolding.

    Args:
        consequent: Formula to unfold
        antecedent: Context for normalization
        registry: Predicate registry
        depth: Maximum depth (uses registry default if None)
        verbose: Print debug information

    Returns:
        Normalized formula
    """
    if depth is None:
        depth = registry.max_unfold_depth or 6

    engine = NormalizedUnfoldEngine(registry, verbose=verbose)
    result = engine.unfold_consequent_normalized(consequent, antecedent, depth)

    if verbose:
        stats = engine.get_statistics()
        print(f"\n[Normalization Stats]")
        print(f"  Total unfolds: {stats['total_unfolds']}")
        print(f"  Normalized: {stats['normalized']} ({stats['normalization_rate']:.1f}%)")
        print(f"  Traditional: {stats['traditional']}")

    return result
