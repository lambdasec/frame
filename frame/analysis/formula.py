"""
Formula Analysis Utilities

Provides utilities for analyzing and comparing separation logic formulas.
"""

from typing import List
from frame.core.ast import (
    Formula, Expr, Var, Const, Emp, PointsTo, SepConj, Wand, And, Or, Not,
    Eq, Neq, True_, False_, Exists, Forall, PredicateCall
)


class FormulaAnalyzer:
    """Analyzes and compares separation logic formulas"""

    def formulas_syntactically_equal(self, f1: Formula, f2: Formula) -> bool:
        """Check if two formulas are syntactically equal (modulo some normalization)"""
        # Simple structural equality check
        if type(f1) != type(f2):
            return False

        if isinstance(f1, (Emp, True_, False_)):
            return True

        if isinstance(f1, (Eq, Neq)):
            return (self._expr_equal(f1.left, f2.left) and
                   self._expr_equal(f1.right, f2.right))

        if isinstance(f1, PointsTo):
            if not self._expr_equal(f1.location, f2.location):
                return False
            if len(f1.values) != len(f2.values):
                return False
            return all(self._expr_equal(v1, v2)
                      for v1, v2 in zip(f1.values, f2.values))

        if isinstance(f1, (And, Or, SepConj)):
            # Try both orderings (commutativity)
            return ((self.formulas_syntactically_equal(f1.left, f2.left) and
                    self.formulas_syntactically_equal(f1.right, f2.right)) or
                   (self.formulas_syntactically_equal(f1.left, f2.right) and
                    self.formulas_syntactically_equal(f1.right, f2.left)))

        if isinstance(f1, Wand):
            # Wand is NOT commutative: P -* Q is different from Q -* P
            return (self.formulas_syntactically_equal(f1.left, f2.left) and
                   self.formulas_syntactically_equal(f1.right, f2.right))

        if isinstance(f1, Not):
            return self.formulas_syntactically_equal(f1.formula, f2.formula)

        if isinstance(f1, (Exists, Forall)):
            return (f1.var == f2.var and
                   self.formulas_syntactically_equal(f1.formula, f2.formula))

        if isinstance(f1, PredicateCall):
            if f1.name != f2.name or len(f1.args) != len(f2.args):
                return False
            return all(self._expr_equal(a1, a2)
                      for a1, a2 in zip(f1.args, f2.args))

        return False

    def _expr_equal(self, e1: Expr, e2: Expr) -> bool:
        """Check if two expressions are equal"""
        if type(e1) != type(e2):
            return False
        if isinstance(e1, Var):
            return e1.name == e2.name
        if isinstance(e1, Const):
            return e1.value == e2.value
        return False

    def _is_all_emp(self, formula: Formula) -> bool:
        """Check if a formula is entirely composed of emp (emp * emp * ...)"""
        if isinstance(formula, Emp):
            return True
        if isinstance(formula, SepConj):
            return self._is_all_emp(formula.left) and self._is_all_emp(formula.right)
        return False

    def _has_predicates(self, formula: Formula) -> bool:
        """Check if formula contains predicate calls"""
        if isinstance(formula, PredicateCall):
            return True
        elif isinstance(formula, (SepConj, Wand, And, Or)):
            return self._has_predicates(formula.left) or self._has_predicates(formula.right)
        elif isinstance(formula, (Not, Exists, Forall)):
            return self._has_predicates(formula.formula)
        return False

    def _count_predicates(self, formula: Formula) -> int:
        """Count predicate calls in a formula"""
        if isinstance(formula, PredicateCall):
            return 1
        elif isinstance(formula, (SepConj, Wand, And, Or)):
            return self._count_predicates(formula.left) + self._count_predicates(formula.right)
        elif isinstance(formula, (Not, Exists, Forall)):
            return self._count_predicates(formula.formula)
        return 0

    def _count_points_to(self, formula: Formula) -> int:
        """Count concrete points-to facts in a formula"""
        if isinstance(formula, PointsTo):
            return 1
        elif isinstance(formula, (SepConj, And)):
            return self._count_points_to(formula.left) + self._count_points_to(formula.right)
        elif isinstance(formula, Or):
            # For Or, take minimum (conservative)
            return min(self._count_points_to(formula.left), self._count_points_to(formula.right))
        else:
            return 0

    def _min_cells_required(self, formula: Formula, depth: int = 2) -> int:
        """Estimate minimum cells required by predicates (conservative lower bound)"""
        if isinstance(formula, PredicateCall):
            # List segment can be empty or have cells - return 0 for minimum
            return 0
        elif isinstance(formula, PointsTo):
            return 1
        elif isinstance(formula, SepConj):
            return self._min_cells_required(formula.left, depth) + self._min_cells_required(formula.right, depth)
        elif isinstance(formula, (And, Or)):
            # Conservative: take minimum
            return min(self._min_cells_required(formula.left, depth), self._min_cells_required(formula.right, depth))
        else:
            return 0

    def _expr_to_str(self, expr: Expr) -> str:
        """Convert expression to string for comparison"""
        if isinstance(expr, Var):
            return expr.name
        elif isinstance(expr, Const):
            return str(expr.value)
        else:
            return str(expr)

    def _extract_sepconj_parts(self, formula: Formula) -> List[Formula]:
        """Extract all parts of a separating conjunction into a list"""
        if isinstance(formula, SepConj):
            return self._extract_sepconj_parts(formula.left) + self._extract_sepconj_parts(formula.right)
        elif isinstance(formula, And):
            # For And formulas, extract spatial parts recursively
            # This handles cases like: (pure & (P * Q))
            left_parts = self._extract_sepconj_parts(formula.left)
            right_parts = self._extract_sepconj_parts(formula.right)
            # Filter out non-spatial parts (pure formulas)
            spatial_parts = [p for p in left_parts + right_parts if p.is_spatial()]
            if spatial_parts:
                return spatial_parts
            else:
                return [formula]
        else:
            return [formula]

    def _build_sepconj(self, parts: List[Formula]) -> Formula:
        """Build a separating conjunction from a list of parts"""
        if len(parts) == 0:
            return Emp()
        elif len(parts) == 1:
            return parts[0]
        else:
            result = parts[0]
            for part in parts[1:]:
                result = SepConj(result, part)
            return result

    def _formula_sort_key(self, formula: Formula) -> tuple:
        """
        Generate a sort key for canonical ordering of formulas.

        Uses (type_priority, string_repr) to ensure deterministic ordering:
        - Emp < PointsTo < PredicateCall < And < Or < Not < ...
        - Within same type, sort by string representation
        """
        # Type priority: simpler types first
        type_priority = {
            Emp: 0,
            True_: 1,
            False_: 2,
            PointsTo: 3,
            PredicateCall: 4,
            And: 5,
            Or: 6,
            Not: 7,
            Eq: 8,
            Neq: 9,
            Exists: 10,
            Forall: 11,
            Wand: 12,
        }

        priority = type_priority.get(type(formula), 99)
        str_repr = str(formula)
        return (priority, str_repr)

    def normalize_sepconj(self, formula: Formula) -> Formula:
        """
        Normalize a formula by sorting SepConj operands canonically.

        This ensures that P * Q and Q * P have the same normal form,
        enabling efficient syntactic matching in lemmas and frame rule.

        Also normalizes nested operators recursively (And, Or, Not, etc.)
        """
        # Base cases
        if isinstance(formula, (Emp, True_, False_)):
            return formula

        # Recursively normalize subformulas
        if isinstance(formula, SepConj):
            # Extract all parts, normalize each, then sort
            parts = self._extract_sepconj_parts(formula)
            normalized_parts = [self.normalize_sepconj(p) for p in parts]
            # Sort by canonical key
            normalized_parts.sort(key=self._formula_sort_key)
            # Rebuild
            return self._build_sepconj(normalized_parts)

        elif isinstance(formula, And):
            # Normalize both sides, then sort for canonical order
            left_norm = self.normalize_sepconj(formula.left)
            right_norm = self.normalize_sepconj(formula.right)
            # Sort for deterministic ordering
            if self._formula_sort_key(left_norm) <= self._formula_sort_key(right_norm):
                return And(left_norm, right_norm)
            else:
                return And(right_norm, left_norm)

        elif isinstance(formula, Or):
            # Normalize both sides, then sort for canonical order
            left_norm = self.normalize_sepconj(formula.left)
            right_norm = self.normalize_sepconj(formula.right)
            # Sort for deterministic ordering
            if self._formula_sort_key(left_norm) <= self._formula_sort_key(right_norm):
                return Or(left_norm, right_norm)
            else:
                return Or(right_norm, left_norm)

        elif isinstance(formula, Wand):
            # Wand is NOT commutative - don't reorder
            left_norm = self.normalize_sepconj(formula.left)
            right_norm = self.normalize_sepconj(formula.right)
            return Wand(left_norm, right_norm)

        elif isinstance(formula, Not):
            inner_norm = self.normalize_sepconj(formula.formula)
            return Not(inner_norm)

        elif isinstance(formula, Exists):
            inner_norm = self.normalize_sepconj(formula.formula)
            return Exists(formula.var, inner_norm)

        elif isinstance(formula, Forall):
            inner_norm = self.normalize_sepconj(formula.formula)
            return Forall(formula.var, inner_norm)

        elif isinstance(formula, (PointsTo, PredicateCall, Eq, Neq)):
            # Atomic formulas - already normalized
            return formula

        else:
            # Unknown type - return as-is
            return formula

    def eliminate_wand(self, formula: Formula, checker=None) -> Formula:
        """
        Eliminate magic wand when pattern P * (P -* Q) appears.

        Rewrite:  P * (P -* Q)  →  P * Q

        This is sound because:
        - P holds in the current heap
        - (P -* Q) means "if P then Q"
        - Therefore Q must hold
        - No extension heap needed

        This fixes SAT divisions (bsl_sat, rev-*, dispose-*) where
        wands should not create fresh heaps.

        Args:
            formula: The formula to process
            checker: Optional EntailmentChecker for entailment checking
                    If None, uses syntactic equality only

        Returns:
            Formula with wands eliminated where possible
        """
        # Recursively process subformulas first
        if isinstance(formula, SepConj):
            left = self.eliminate_wand(formula.left, checker)
            right = self.eliminate_wand(formula.right, checker)

            # Pattern 1: P * (P -* Q)  →  P * Q
            if isinstance(right, Wand):
                wand_left = right.left
                wand_right = right.right

                # Check if left |- wand_left (P holds)
                if self._can_prove_entailment(left, wand_left, checker):
                    # Replace with P * Q
                    return SepConj(left, wand_right)

            # Pattern 2: (P -* Q) * P  →  P * Q (symmetric)
            if isinstance(left, Wand):
                wand_left = left.left
                wand_right = left.right

                # Check if right |- wand_left (P holds)
                if self._can_prove_entailment(right, wand_left, checker):
                    # Replace with P * Q
                    return SepConj(right, wand_right)

            # No match - return with processed subformulas
            return SepConj(left, right)

        elif isinstance(formula, And):
            left = self.eliminate_wand(formula.left, checker)
            right = self.eliminate_wand(formula.right, checker)
            return And(left, right)

        elif isinstance(formula, Or):
            left = self.eliminate_wand(formula.left, checker)
            right = self.eliminate_wand(formula.right, checker)
            return Or(left, right)

        elif isinstance(formula, Not):
            inner = self.eliminate_wand(formula.formula, checker)
            return Not(inner)

        elif isinstance(formula, Exists):
            inner = self.eliminate_wand(formula.formula, checker)
            return Exists(formula.var, inner)

        elif isinstance(formula, Forall):
            inner = self.eliminate_wand(formula.formula, checker)
            return Forall(formula.var, inner)

        else:
            # Atomic formula - return as-is
            return formula

    def _can_prove_entailment(self, antecedent: Formula, consequent: Formula, checker) -> bool:
        """
        Check if antecedent |- consequent can be proven.

        Uses syntactic equality first (fast path), then lemma matching if checker provided.
        """
        # Fast path: syntactic equality
        if self.formulas_syntactically_equal(antecedent, consequent):
            return True

        # If no checker, use only syntactic equality
        if checker is None:
            return False

        # Try lemma matching (Phase 1 only - fast)
        # Import here to avoid circular dependency
        try:
            from frame.lemmas.base import LemmaLibrary
            library = LemmaLibrary()

            # Try direct lemma application
            lemma_name = library.try_apply_lemma(antecedent, consequent)
            if lemma_name:
                return True
        except:
            pass

        # TODO: Could add more sophisticated entailment checking here
        # For now, conservative: only prove if syntactically equal or by lemma

        return False


# ============================================================================
# Standalone utility functions for formula analysis
# ============================================================================

def extract_equalities(formula: Formula) -> List[Formula]:
    """
    Extract all equality constraints from a formula.

    Returns:
        List of Eq formulas
    """
    result = []

    if isinstance(formula, Eq):
        result.append(formula)
    elif isinstance(formula, (SepConj, And, Or)):
        result.extend(extract_equalities(formula.left))
        result.extend(extract_equalities(formula.right))
    elif isinstance(formula, (Not, Exists, Forall)):
        result.extend(extract_equalities(formula.formula))

    return result


def extract_points_to(formula: Formula) -> List[PointsTo]:
    """
    Extract all points-to assertions from a formula.

    Returns:
        List of PointsTo formulas
    """
    result = []

    if isinstance(formula, PointsTo):
        result.append(formula)
    elif isinstance(formula, (SepConj, And, Or)):
        result.extend(extract_points_to(formula.left))
        result.extend(extract_points_to(formula.right))
    elif isinstance(formula, (Exists, Forall)):
        result.extend(extract_points_to(formula.formula))

    return result


def has_predicate(formula: Formula, predicate_name: str = None) -> bool:
    """
    Check if formula contains any predicate calls (or specific predicate if name given).

    Args:
        formula: Formula to check
        predicate_name: Optional specific predicate name to look for

    Returns:
        True if formula contains matching predicate call
    """
    if isinstance(formula, PredicateCall):
        if predicate_name is None:
            return True
        return formula.name == predicate_name
    elif isinstance(formula, (SepConj, Wand, And, Or)):
        return has_predicate(formula.left, predicate_name) or has_predicate(formula.right, predicate_name)
    elif isinstance(formula, (Not, Exists, Forall)):
        return has_predicate(formula.formula, predicate_name)
    return False
