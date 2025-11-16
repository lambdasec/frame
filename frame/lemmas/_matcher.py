"""
Pattern matching for lemmas

This module contains the pattern matching logic for lemma application.
It supports meta-variable matching (capitalized variables like X, Y, Z)
and handles commutativity of spatial and pure connectives.
"""

from typing import Dict, Optional
from frame.core.ast import *


class LemmaMatcher:
    """Pattern matching for lemma application"""

    def match_formula(self, pattern: Formula, formula: Formula,
                     bindings: Optional[Dict[str, Expr]] = None) -> Optional[Dict[str, Expr]]:
        """
        Try to match a pattern formula against an actual formula.

        Returns a dictionary of variable bindings if match succeeds, None otherwise.
        Pattern variables (capitalized meta-variables like X, Y, Z) can match any expression.
        """
        if bindings is None:
            bindings = {}

        # If pattern is a meta-variable (capitalized), bind it
        if isinstance(pattern, Var) and pattern.name[0].isupper():
            if pattern.name in bindings:
                # Already bound - check consistency
                return bindings if self._expr_equal(bindings[pattern.name], formula) else None
            else:
                # Bind the meta-variable to this formula/expression
                # Meta-variables can match ANY formula (Emp, PointsTo, Wand, etc.) or expression
                # This is essential for lemma patterns like: (P -* Q) * P
                # where P needs to match Emp(), PointsTo(), or any other formula
                bindings[pattern.name] = formula
                return bindings

        # Special case: If pattern is spatial (SepConj, PointsTo, PredicateCall, Emp)
        # and formula is And(spatial, pure), try matching against the spatial part
        if self._is_spatial_pattern(pattern) and isinstance(formula, And):
            # Try matching against left side
            result = self.match_formula(pattern, formula.left, bindings)
            if result is not None:
                return result
            # Try matching against right side
            result = self.match_formula(pattern, formula.right, bindings)
            if result is not None:
                return result
            # No match found
            return None

        # Type must match
        if type(pattern) != type(formula):
            return None

        # Match based on type
        if isinstance(pattern, (Emp, True_, False_)):
            return bindings

        if isinstance(pattern, Var):
            # Non-meta variable must match exactly
            if pattern.name == formula.name:
                return bindings
            return None

        if isinstance(pattern, Const):
            if pattern.value == formula.value:
                return bindings
            return None

        if isinstance(pattern, (Eq, Neq, Lt, Le, Gt, Ge)):
            # Match both sides
            bindings = self.match_expr(pattern.left, formula.left, bindings)
            if bindings is None:
                return None
            return self.match_expr(pattern.right, formula.right, bindings)

        if isinstance(pattern, PointsTo):
            # Match location
            bindings = self.match_expr(pattern.location, formula.location, bindings)
            if bindings is None:
                return None
            # Match values
            if len(pattern.values) != len(formula.values):
                return None
            for pv, fv in zip(pattern.values, formula.values):
                bindings = self.match_expr(pv, fv, bindings)
                if bindings is None:
                    return None
            return bindings

        if isinstance(pattern, PredicateCall):
            # Match predicate name
            if pattern.name != formula.name:
                return None
            # Match arguments
            if len(pattern.args) != len(formula.args):
                return None
            for pa, fa in zip(pattern.args, formula.args):
                bindings = self.match_expr(pa, fa, bindings)
                if bindings is None:
                    return None
            return bindings

        if isinstance(pattern, (SepConj, And, Or)):
            # Try matching in both orders (commutativity)
            # Try left-to-left, right-to-right
            bindings1 = dict(bindings)
            bindings1 = self.match_formula(pattern.left, formula.left, bindings1)
            if bindings1 is not None:
                bindings1 = self.match_formula(pattern.right, formula.right, bindings1)
                if bindings1 is not None:
                    return bindings1

            # Try left-to-right, right-to-left (commutativity)
            bindings2 = dict(bindings)
            bindings2 = self.match_formula(pattern.left, formula.right, bindings2)
            if bindings2 is not None:
                bindings2 = self.match_formula(pattern.right, formula.left, bindings2)
                if bindings2 is not None:
                    return bindings2

            return None

        if isinstance(pattern, Wand):
            # Wand is NOT commutative: P -* Q is different from Q -* P
            # Match left to left, right to right only
            bindings = self.match_formula(pattern.left, formula.left, bindings)
            if bindings is None:
                return None
            return self.match_formula(pattern.right, formula.right, bindings)

        if isinstance(pattern, Not):
            return self.match_formula(pattern.formula, formula.formula, bindings)

        if isinstance(pattern, (Exists, Forall)):
            # For quantifiers, match the variable name and body
            if pattern.var != formula.var:
                return None
            return self.match_formula(pattern.formula, formula.formula, bindings)

        return None

    def match_expr(self, pattern: Expr, expr: Expr,
                   bindings: Optional[Dict[str, Expr]] = None) -> Optional[Dict[str, Expr]]:
        """Match a pattern expression against an actual expression"""
        from frame.core.ast import ArithExpr

        if bindings is None:
            bindings = {}

        # Meta-variable matching
        if isinstance(pattern, Var) and pattern.name[0].isupper():
            if pattern.name in bindings:
                return bindings if self._expr_equal(bindings[pattern.name], expr) else None
            else:
                bindings[pattern.name] = expr
                return bindings

        # Type must match
        if type(pattern) != type(expr):
            return None

        if isinstance(pattern, Var):
            return bindings if pattern.name == expr.name else None

        if isinstance(pattern, Const):
            return bindings if pattern.value == expr.value else None

        if isinstance(pattern, ArithExpr):
            # Match arithmetic expressions recursively
            if pattern.op != expr.op:
                return None
            bindings = self.match_expr(pattern.left, expr.left, bindings)
            if bindings is None:
                return None
            return self.match_expr(pattern.right, expr.right, bindings)

        return None

    def _expr_equal(self, e1, e2) -> bool:
        """
        Check if two expressions or formulas are equal.

        This is used for consistency checking when meta-variables are bound.
        It needs to handle both Expr and Formula types since meta-variables
        can be bound to either.
        """
        from frame.core.ast import ArithExpr, Formula

        if type(e1) != type(e2):
            return False

        # For simple expressions
        if isinstance(e1, Var):
            return e1.name == e2.name
        if isinstance(e1, Const):
            return e1.value == e2.value
        if isinstance(e1, ArithExpr):
            return (e1.op == e2.op and
                   self._expr_equal(e1.left, e2.left) and
                   self._expr_equal(e1.right, e2.right))

        # For formulas (Emp, PointsTo, Wand, etc.), use formulas_equal
        if isinstance(e1, Formula):
            return self.formulas_equal(e1, e2)

        return False

    def _is_spatial_pattern(self, formula: Formula) -> bool:
        """Check if a formula is a spatial pattern (for lemma matching)"""
        return isinstance(formula, (SepConj, PointsTo, PredicateCall, Emp, Wand))

    def formulas_equal(self, f1: Formula, f2: Formula) -> bool:
        """Check if two formulas are structurally equal"""
        if type(f1) != type(f2):
            return False

        if isinstance(f1, (Emp, True_, False_)):
            return True

        if isinstance(f1, Var):
            return f1.name == f2.name

        if isinstance(f1, Const):
            return f1.value == f2.value

        if isinstance(f1, (Eq, Neq, Lt, Le, Gt, Ge)):
            return (self._expr_equal(f1.left, f2.left) and
                   self._expr_equal(f1.right, f2.right))

        if isinstance(f1, PointsTo):
            if not self._expr_equal(f1.location, f2.location):
                return False
            if len(f1.values) != len(f2.values):
                return False
            return all(self._expr_equal(v1, v2) for v1, v2 in zip(f1.values, f2.values))

        if isinstance(f1, PredicateCall):
            if f1.name != f2.name or len(f1.args) != len(f2.args):
                return False
            return all(self._expr_equal(a1, a2) for a1, a2 in zip(f1.args, f2.args))

        if isinstance(f1, (SepConj, And, Or)):
            # Try both orders (commutativity)
            return ((self.formulas_equal(f1.left, f2.left) and
                    self.formulas_equal(f1.right, f2.right)) or
                   (self.formulas_equal(f1.left, f2.right) and
                    self.formulas_equal(f1.right, f2.left)))

        if isinstance(f1, Not):
            return self.formulas_equal(f1.formula, f2.formula)

        if isinstance(f1, (Exists, Forall)):
            return (f1.var == f2.var and
                   self.formulas_equal(f1.formula, f2.formula))

        return False
