"""
Footprint analysis for separation logic formulas.

A footprint is the set of heap locations (variables) that a formula may allocate or access.
This is used for sound affine weakening in the frame rule.

Key principles:
- Allocated locations are always in footprint
- Variable values (potential pointers) are in footprint
- Constant values are NOT in footprint
- Inductive predicates use one-step unfolding for precision
"""

from typing import Set, List, Tuple
from frame.core.ast import (
    Formula, Expr, Var, Const, Emp, PointsTo, SepConj, And, Or, Not,
    PredicateCall, Exists, Forall, Wand
)


class FootprintAnalyzer:
    """
    Analyzes footprints (allocated heap locations + stored pointers) of separation logic formulas.

    Uses one-step unfolding of inductive predicates for sound and precise footprint tracking.
    Conservative: includes symbolic values that could alias other heap cells.
    """

    def __init__(self, unfold_depth=1):
        """
        Args:
            unfold_depth: Depth of unfolding for inductive predicates (default: 1)
        """
        self.unfold_depth = unfold_depth
        self._predicate_registry = None  # Will be set by EntailmentChecker if available

    def _is_constant(self, expr: Expr) -> bool:
        """Check if expression is a constant (not a potential pointer)"""
        if isinstance(expr, Const):
            return True
        if isinstance(expr, Var):
            # Check if variable name looks like a constant (e.g., "nil", or numeric)
            if expr.name in ["nil", "null"]:
                return True
            try:
                int(expr.name)  # Numeric string like "5"
                return True
            except ValueError:
                return False  # Regular variable name
        return False

    def footprint(self, formula: Formula) -> Set[str]:
        """
        Compute the footprint of a formula.

        Footprint includes:
        - All allocated locations (addresses in x |-> y)
        - All variable values that could be pointers (y in x |-> y)
        - Symbolic next values from unfolded predicates

        Returns:
            Set of variable names that may be allocated or referenced by this formula.
        """
        if isinstance(formula, Emp):
            return set()

        elif isinstance(formula, PointsTo):
            # x |-> y allocates location x
            fp = set()
            if isinstance(formula.location, Var):
                fp.add(formula.location.name)

            # Include values that are potential pointers (variables, not constants)
            # x |-> y → include y (variable, might be pointer)
            # x |-> 5 → don't include 5 (constant, not a pointer)
            for val in formula.values:
                if isinstance(val, Var) and not self._is_constant(val):
                    fp.add(val.name)

            return fp

        elif isinstance(formula, PredicateCall):
            # One-step unfolding for precision
            # list(z) unfolds to: z |-> next * list(next)
            # Footprint: {z, z_next} where z_next is symbolic
            fp = set()

            # Always include root pointer
            for arg in formula.args:
                if isinstance(arg, Var):
                    fp.add(arg.name)

            # Add symbolic next values (conservative: any variable from predicate might store pointers)
            # This captures that list(z) might contain any heap value
            if self.unfold_depth >= 1:
                # For predicates, add symbolic "next" values
                # This conservatively assumes the predicate stores pointers
                for arg in formula.args:
                    if isinstance(arg, Var):
                        # Add a symbolic next value for this root
                        fp.add(f"{arg.name}_next")

            return fp

        elif isinstance(formula, SepConj):
            # P * Q: union of footprints
            left_fp = self.footprint(formula.left)
            right_fp = self.footprint(formula.right)
            return left_fp.union(right_fp)

        elif isinstance(formula, And):
            # P & Q: union of spatial footprints
            left_fp = self.footprint(formula.left)
            right_fp = self.footprint(formula.right)
            return left_fp.union(right_fp)

        elif isinstance(formula, Or):
            # P | Q: union (overapproximation - may allocate either)
            left_fp = self.footprint(formula.left)
            right_fp = self.footprint(formula.right)
            return left_fp.union(right_fp)

        elif isinstance(formula, Not):
            # ¬P: no allocation in classical logic
            # (negation is typically pure)
            return set()

        elif isinstance(formula, (Exists, Forall)):
            # Quantifiers: footprint of body
            return self.footprint(formula.formula)

        elif isinstance(formula, Wand):
            # P -* Q: footprint of Q (what's allocated when P is available)
            # Conservative: union of both
            left_fp = self.footprint(formula.left)
            right_fp = self.footprint(formula.right)
            return left_fp.union(right_fp)

        else:
            # Pure formulas, True, False, etc.
            return set()

    def _get_root_vars(self, formula: Formula) -> Set[str]:
        """Extract root variables (allocated locations) from a formula"""
        roots = set()
        if isinstance(formula, PointsTo):
            if isinstance(formula.location, Var):
                roots.add(formula.location.name)
        elif isinstance(formula, PredicateCall):
            # For predicates, the first argument is typically the root
            if formula.args and isinstance(formula.args[0], Var):
                roots.add(formula.args[0].name)
        elif isinstance(formula, SepConj):
            roots.update(self._get_root_vars(formula.left))
            roots.update(self._get_root_vars(formula.right))
        return roots

    def _contains_predicates(self, formula: Formula) -> bool:
        """Check if formula contains any predicate calls"""
        if isinstance(formula, PredicateCall):
            return True
        elif isinstance(formula, SepConj):
            return self._contains_predicates(formula.left) or self._contains_predicates(formula.right)
        elif isinstance(formula, And):
            return self._contains_predicates(formula.left) or self._contains_predicates(formula.right)
        return False

    def _get_symbolic_values(self, formula: Formula) -> Set[str]:
        """
        Extract symbolic values (variables, not constants) stored in cells.
        For x |-> y: returns {y} if y is variable, {} if y is constant
        For x |-> 5: returns {}
        """
        values = set()
        if isinstance(formula, PointsTo):
            for val in formula.values:
                if isinstance(val, Var) and not self._is_constant(val):
                    values.add(val.name)
        elif isinstance(formula, PredicateCall):
            # Predicates have symbolic _next values from one-step unfolding
            # These are handled in footprint(), not here
            pass
        elif isinstance(formula, SepConj):
            values.update(self._get_symbolic_values(formula.left))
            values.update(self._get_symbolic_values(formula.right))
        return values

    def _flatten_sepconj(self, formula: Formula, start_pos: int = 0) -> List[Tuple[Formula, int]]:
        """
        Flatten a SepConj structure to assign positions to each conjunct.
        Returns list of (formula, position) tuples.

        Left-most formulas get lower positions (earlier in * order).
        Example: (A * B) * C → [(A, 0), (B, 1), (C, 2)]
        """
        if isinstance(formula, SepConj):
            # Recursively flatten left and right
            left_flat = self._flatten_sepconj(formula.left, start_pos)
            next_pos = start_pos + len(left_flat)
            right_flat = self._flatten_sepconj(formula.right, next_pos)
            return left_flat + right_flat
        else:
            # Base case: single formula
            return [(formula, start_pos)]

    def can_drop_safely_order_aware(self, remainder: Formula, remainder_pos: int,
                                     other: Formula, other_pos: int) -> bool:
        """
        Check if remainder can be safely dropped using order-aware heuristic.

        Order-aware affine SL heuristic:
        - Remainder AFTER kept predicate (higher position) → safe to drop if disjoint
        - Remainder BEFORE kept predicate (lower position) → conservative, block if has symbolic values

        This captures: earlier cells may be referenced by later predicates,
        but cells added later are safe to drop.

        Args:
            remainder: Formula to drop
            remainder_pos: Position in * structure (lower = earlier)
            other: Formula to keep
            other_pos: Position in * structure

        Returns:
            True if safe to drop, False otherwise
        """
        fp_remainder = self.footprint(remainder)
        fp_other = self.footprint(other)

        remainder_roots = self._get_root_vars(remainder)
        other_roots = self._get_root_vars(other)
        remainder_symbolic_values = self._get_symbolic_values(remainder)

        # Special case: List segments with same root
        # ls(x,y) * ls(x,z) is only SAT when x=y=z (both empty)
        # Let Z3 discover this constraint instead of blocking early
        if isinstance(remainder, PredicateCall) and isinstance(other, PredicateCall):
            if remainder.name == "ls" and other.name == "ls":
                if remainder.args and other.args:
                    # Check if both have the same root variable
                    rem_root = remainder.args[0]
                    other_root = other.args[0]
                    if isinstance(rem_root, Var) and isinstance(other_root, Var):
                        if rem_root.name == other_root.name:
                            # Same root - allow Z3 to handle the constraints
                            return True

        # Check 1: Locations must be disjoint
        if not remainder_roots.isdisjoint(fp_other):
            return False

        # Check 2: Order-aware symbolic value check
        if remainder_symbolic_values:
            # Check if kept has symbolic footprint (predicates with _next)
            has_symbolic_in_kept = any(v.endswith('_next') for v in fp_other)

            if has_symbolic_in_kept:
                # Check if remainder value matches kept predicate root
                if not remainder_symbolic_values.isdisjoint(other_roots):
                    # Example: x |-> z * list(z) where value z IS the root
                    return False

                # ORDER-AWARE HEURISTIC:
                # If remainder occurs AFTER kept predicate → safe to drop (affine weakening)
                # If remainder occurs BEFORE kept predicate → unsafe (conservative)
                if remainder_pos < other_pos:
                    # Remainder before kept → may be referenced
                    # Example: x |-> y * list(z) where position(x|->y) < position(list(z))
                    return False
                else:
                    # Remainder after kept → safe
                    # Example: list(x) * y |-> z where position(list(x)) < position(y|->z)
                    return True

        # No symbolic values or no predicates → safe
        return True

    def can_drop_safely(self, remainder: Formula, other: Formula) -> bool:
        """
        Check if remainder can be safely dropped (backwards compatibility).

        This version flattens both formulas and checks all combinations.
        For simple cases (single formulas), assigns same position.
        """
        # Flatten both to get positions
        remainder_flat = self._flatten_sepconj(remainder)
        other_flat = self._flatten_sepconj(other)

        # Check all combinations
        for r_formula, r_pos in remainder_flat:
            for o_formula, o_pos in other_flat:
                if not self.can_drop_safely_order_aware(r_formula, r_pos, o_formula, o_pos):
                    return False

        return True

    def entails_emp_footprint_aware(self, antecedent: Formula, consequent: Formula) -> bool:
        """
        Check if antecedent can be weakened to emp when consequent is emp.

        This implements affine weakening with footprint safety:
        - If antecedent is emp, trivially true
        - If antecedent has concrete allocations disjoint from consequent, can drop
        - Otherwise, cannot safely weaken to emp

        Args:
            antecedent: The formula we're checking (remainder after frame rule)
            consequent: Should be emp or contain spatial parts

        Returns:
            True if antecedent can safely entail emp in this context
        """
        if isinstance(antecedent, Emp):
            return True

        fp_ante = self.footprint(antecedent)

        # If antecedent has no footprint, it's effectively emp
        if not fp_ante:
            return True

        # If consequent is emp, check if antecedent footprint is disjoint from anything
        if isinstance(consequent, Emp):
            # In affine SL, we can drop cells that don't interfere
            # But we can't drop cells if they're the *only* thing
            # (i.e., x |-> y ⊬ emp when there's nothing else)
            # This is the soundness check
            return False  # Cannot weaken non-empty to emp without context

        # If consequent has spatial parts, check overlap
        fp_cons = self.footprint(consequent)

        # Can drop antecedent if its footprint doesn't overlap with consequent
        return fp_ante.isdisjoint(fp_cons)
