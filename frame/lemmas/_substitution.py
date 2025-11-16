"""
Substitution and equality normalization for lemmas

This module handles:
- Meta-variable substitution in formulas and expressions
- Equality constraint extraction and normalization
- Transitive closure of equality constraints
"""

from typing import Dict, Optional
from frame.core.ast import *


class LemmaSubstitution:
    """Substitution and equality normalization"""

    def substitute_bindings(self, formula: Formula, bindings: Dict[str, Expr]) -> Formula:
        """Substitute meta-variable bindings into a formula"""
        if isinstance(formula, Var):
            if formula.name in bindings:
                # Replace with bound value (can be any Formula or Expr)
                # This is essential for lemma patterns like (P -* Q) where
                # P and Q are meta-variables that can be bound to complex formulas
                return bindings[formula.name]
            return formula

        if isinstance(formula, (Emp, True_, False_, Const)):
            return formula

        if isinstance(formula, (Eq, Neq, Lt, Le, Gt, Ge)):
            return type(formula)(
                self.substitute_expr(formula.left, bindings),
                self.substitute_expr(formula.right, bindings)
            )

        if isinstance(formula, PointsTo):
            return PointsTo(
                self.substitute_expr(formula.location, bindings),
                [self.substitute_expr(v, bindings) for v in formula.values]
            )

        if isinstance(formula, PredicateCall):
            return PredicateCall(
                formula.name,
                [self.substitute_expr(a, bindings) for a in formula.args]
            )

        if isinstance(formula, (SepConj, And, Or)):
            return type(formula)(
                self.substitute_bindings(formula.left, bindings),
                self.substitute_bindings(formula.right, bindings)
            )

        if isinstance(formula, Not):
            return Not(self.substitute_bindings(formula.formula, bindings))

        if isinstance(formula, (Exists, Forall)):
            return type(formula)(
                formula.var,
                self.substitute_bindings(formula.formula, bindings)
            )

        return formula

    def substitute_expr(self, expr: Expr, bindings: Dict[str, Expr]) -> Expr:
        """Substitute meta-variable bindings into an expression"""
        from frame.core.ast import ArithExpr

        if isinstance(expr, Var):
            return bindings.get(expr.name, expr)
        elif isinstance(expr, Const):
            return expr
        elif isinstance(expr, ArithExpr):
            # Recursively substitute in arithmetic expressions
            left_sub = self.substitute_expr(expr.left, bindings)
            right_sub = self.substitute_expr(expr.right, bindings)

            # Simplify if both operands are constants
            if isinstance(left_sub, Const) and isinstance(right_sub, Const):
                left_val = left_sub.value
                right_val = right_sub.value
                # Only simplify if both are integers (not None)
                if isinstance(left_val, int) and isinstance(right_val, int):
                    if expr.op == '+':
                        return Const(left_val + right_val)
                    elif expr.op == '-':
                        return Const(left_val - right_val)
                    elif expr.op == '*':
                        return Const(left_val * right_val)
                    elif expr.op == 'div' and right_val != 0:
                        return Const(left_val // right_val)
                    elif expr.op == 'mod' and right_val != 0:
                        return Const(left_val % right_val)

            # If not simplified, return the ArithExpr with substituted operands
            return ArithExpr(expr.op, left_sub, right_sub)
        return expr

    def extract_equality_constraints(self, formula: Formula) -> Dict[str, Expr]:
        """
        Extract equality constraints (x = y) from a formula and build substitution map.
        Returns a dictionary mapping variables to their canonical representatives.
        """
        equalities = {}
        self._collect_equalities(formula, equalities)

        # Apply transitive closure to get canonical mapping
        return self._transitive_closure(equalities)

    def _collect_equalities(self, formula: Formula, equalities: Dict[str, Expr]):
        """Recursively collect all equality constraints from formula"""
        if isinstance(formula, Eq):
            # Add equality to map
            left, right = formula.left, formula.right
            if isinstance(left, Var) and isinstance(right, Var):
                # Both variables - map to lexicographically smaller one
                if left.name < right.name:
                    equalities[right.name] = left
                else:
                    equalities[left.name] = right
            elif isinstance(left, Var):
                # Left is var, right is not - map var to right
                equalities[left.name] = right
            elif isinstance(right, Var):
                # Right is var, left is not - map var to left
                equalities[right.name] = left

        # Recurse into subformulas
        if isinstance(formula, And):
            self._collect_equalities(formula.left, equalities)
            self._collect_equalities(formula.right, equalities)
        elif isinstance(formula, (SepConj, Or)):
            # Don't extract from spatial or disjunctions
            pass
        elif isinstance(formula, Not):
            # Don't extract from negations
            pass

    def _transitive_closure(self, equalities: Dict[str, Expr]) -> Dict[str, Expr]:
        """Apply transitive closure to equality map"""
        from frame.core.ast import ArithExpr

        # Keep substituting until we reach fixed point
        changed = True
        max_iterations = 100  # Prevent infinite loops
        iteration = 0

        while changed and iteration < max_iterations:
            changed = False
            iteration += 1

            for var in list(equalities.keys()):
                target = equalities[var]
                # If target is a variable that's also in the map, follow the chain
                if isinstance(target, Var) and target.name in equalities:
                    new_target = equalities[target.name]
                    if not self._expr_equal(new_target, target):
                        equalities[var] = new_target
                        changed = True

        return equalities

    def _expr_equal(self, e1: Expr, e2: Expr) -> bool:
        """Check if two expressions are equal"""
        from frame.core.ast import ArithExpr

        if type(e1) != type(e2):
            return False
        if isinstance(e1, Var):
            return e1.name == e2.name
        if isinstance(e1, Const):
            return e1.value == e2.value
        if isinstance(e1, ArithExpr):
            return (e1.op == e2.op and
                   self._expr_equal(e1.left, e2.left) and
                   self._expr_equal(e1.right, e2.right))
        return False

    def apply_substitution_to_formula(self, formula: Formula, substitution: Dict[str, Expr]) -> Formula:
        """Apply variable substitution to a formula"""
        if isinstance(formula, Var):
            return substitution.get(formula.name, formula)

        if isinstance(formula, (Emp, True_, False_, Const)):
            return formula

        if isinstance(formula, (Eq, Neq, Lt, Le, Gt, Ge)):
            return type(formula)(
                self._apply_substitution_to_expr(formula.left, substitution),
                self._apply_substitution_to_expr(formula.right, substitution)
            )

        if isinstance(formula, PointsTo):
            return PointsTo(
                self._apply_substitution_to_expr(formula.location, substitution),
                [self._apply_substitution_to_expr(v, substitution) for v in formula.values]
            )

        if isinstance(formula, PredicateCall):
            return PredicateCall(
                formula.name,
                [self._apply_substitution_to_expr(a, substitution) for a in formula.args]
            )

        if isinstance(formula, (SepConj, And, Or)):
            return type(formula)(
                self.apply_substitution_to_formula(formula.left, substitution),
                self.apply_substitution_to_formula(formula.right, substitution)
            )

        if isinstance(formula, Not):
            return Not(self.apply_substitution_to_formula(formula.formula, substitution))

        if isinstance(formula, (Exists, Forall)):
            # Don't substitute bound variables
            return formula

        if isinstance(formula, Wand):
            return Wand(
                self.apply_substitution_to_formula(formula.left, substitution),
                self.apply_substitution_to_formula(formula.right, substitution)
            )

        return formula

    def _apply_substitution_to_expr(self, expr: Expr, substitution: Dict[str, Expr]) -> Expr:
        """Apply variable substitution to an expression"""
        from frame.core.ast import ArithExpr

        if isinstance(expr, Var):
            return substitution.get(expr.name, expr)
        elif isinstance(expr, Const):
            return expr
        elif isinstance(expr, ArithExpr):
            return ArithExpr(
                expr.op,
                self._apply_substitution_to_expr(expr.left, substitution),
                self._apply_substitution_to_expr(expr.right, substitution)
            )
        return expr
