"""
Equality Preprocessing for Separation Logic Formulas

This module implements equality preprocessing using union-find to canonicalize
variables before Z3 encoding and predicate folding. This fixes entailments like:
    list(x) & x = y ⊢ list(y)

Algorithm:
1. Extract top-level pure equalities (Var = Var or Var = Const)
2. Build union-find over variable names
3. Compute canonical representative for each variable
4. Substitute every occurrence with its representative
5. Preserve quantified variables (don't substitute bound vars)
"""

from typing import Dict, Set, Optional, Tuple
from frame.core.ast import *


class UnionFind:
    """Union-Find data structure for variable canonicalization"""

    def __init__(self):
        self.parent: Dict[str, str] = {}
        self.rank: Dict[str, int] = {}

    def find(self, x: str) -> str:
        """Find canonical representative with path compression"""
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0
            return x

        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])  # Path compression
        return self.parent[x]

    def union(self, a: str, b: str):
        """Union with preference for constants over variables"""
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return

        # Prefer constants over variables
        a_is_const = self._is_constant_name(ra)
        b_is_const = self._is_constant_name(rb)

        if a_is_const and not b_is_const:
            self.parent[rb] = ra
        elif b_is_const and not a_is_const:
            self.parent[ra] = rb
        else:
            # Both vars or both consts - use rank-based union
            if self.rank[ra] < self.rank[rb]:
                self.parent[ra] = rb
            elif self.rank[ra] > self.rank[rb]:
                self.parent[rb] = ra
            else:
                self.parent[rb] = ra
                self.rank[ra] += 1

    @staticmethod
    def _is_constant_name(name: str) -> bool:
        """Check if a string looks like a constant (number or 'nil')"""
        if name == 'nil':
            return True
        try:
            int(name)
            return True
        except ValueError:
            return False


class EqualityPreprocessor:
    """Preprocessor that applies equality substitution to formulas"""

    def __init__(self, preserve_quantified: bool = True):
        self.preserve_quantified = preserve_quantified
        self.uf = UnionFind()
        self.substitution_map: Dict[str, str] = {}  # Simple var-to-var/const substitutions
        self.expr_substitution_map: Dict[str, Expr] = {}  # Var-to-ArithExpr substitutions
        self.quantified_vars: Set[str] = set()

    def preprocess(self, formula: Formula) -> Formula:
        """
        Main entry point: preprocess a formula by applying equality substitution.

        Args:
            formula: Input formula

        Returns:
            Formula with variables substituted by their canonical representatives
        """
        # Step 1: Collect quantified variables to preserve
        if self.preserve_quantified:
            self._collect_quantified_vars(formula)

        # Step 2: Extract equalities and build union-find
        self._extract_equalities(formula)

        # Step 3: Build substitution map
        for var in self.uf.parent.keys():
            rep = self.uf.find(var)
            # Don't substitute quantified variables
            if var not in self.quantified_vars:
                self.substitution_map[var] = rep

        # Step 4: Apply substitution
        return self._substitute_formula(formula)

    def _collect_quantified_vars(self, formula: Formula):
        """Collect all quantified variable names"""
        if isinstance(formula, (Exists, Forall)):
            self.quantified_vars.add(formula.var)
            self._collect_quantified_vars(formula.formula)
        elif isinstance(formula, (And, Or, SepConj, Wand)):
            self._collect_quantified_vars(formula.left)
            self._collect_quantified_vars(formula.right)
        elif isinstance(formula, Not):
            self._collect_quantified_vars(formula.formula)

    def _extract_equalities(self, formula: Formula):
        """Extract top-level equalities and build union-find"""
        self._extract_from_formula(formula)

    def _extract_from_formula(self, formula: Formula):
        """Recursively extract equalities from formula"""
        if isinstance(formula, Eq):
            # Handle three cases:
            # 1. Var = Var or Var = Const (use union-find)
            # 2. Var = ArithExpr (direct substitution)
            # 3. ArithExpr = Var (direct substitution, reversed)

            left_key = self._get_simple_key(formula.left)
            right_key = self._get_simple_key(formula.right)

            if left_key and right_key:
                # Case 1: Simple equality - use union-find
                self.uf.union(left_key, right_key)
            elif isinstance(formula.left, Var) and isinstance(formula.right, ArithExpr):
                # Case 2: Var = ArithExpr - direct substitution
                var_name = formula.left.name
                if var_name not in self.quantified_vars:
                    self.expr_substitution_map[var_name] = formula.right
            elif isinstance(formula.right, Var) and isinstance(formula.left, ArithExpr):
                # Case 3: ArithExpr = Var - direct substitution (reversed)
                var_name = formula.right.name
                if var_name not in self.quantified_vars:
                    self.expr_substitution_map[var_name] = formula.left

        elif isinstance(formula, And):
            # Recursively extract from both sides of conjunction
            self._extract_from_formula(formula.left)
            self._extract_from_formula(formula.right)

        elif isinstance(formula, (Exists, Forall)):
            # Extract from body but mark quantified var
            self._extract_from_formula(formula.formula)

        # Don't extract from other formula types (Or, SepConj, etc.)
        # to keep things conservative

    def _get_simple_key(self, expr: Expr) -> Optional[str]:
        """Get string key for simple expressions (Var or Const)"""
        if isinstance(expr, Var):
            return expr.name
        elif isinstance(expr, Const):
            if expr.value is None:
                return "nil"
            elif isinstance(expr.value, (int, str)):
                return str(expr.value)
        return None

    def _substitute_formula(self, formula: Formula) -> Formula:
        """Apply substitution to a formula"""
        if isinstance(formula, Emp) or isinstance(formula, (True_, False_)):
            return formula

        if isinstance(formula, Var):
            # This shouldn't happen (Var is Expr not Formula)
            return formula

        if isinstance(formula, Eq):
            return Eq(
                self._substitute_expr(formula.left),
                self._substitute_expr(formula.right)
            )

        if isinstance(formula, Neq):
            return Neq(
                self._substitute_expr(formula.left),
                self._substitute_expr(formula.right)
            )

        if isinstance(formula, (Lt, Le, Gt, Ge)):
            return type(formula)(
                self._substitute_expr(formula.left),
                self._substitute_expr(formula.right)
            )

        if isinstance(formula, PointsTo):
            return PointsTo(
                self._substitute_expr(formula.location),
                [self._substitute_expr(v) for v in formula.values]
            )

        if isinstance(formula, PredicateCall):
            return PredicateCall(
                formula.name,
                [self._substitute_expr(arg) for arg in formula.args]
            )

        if isinstance(formula, (And, Or, SepConj)):
            return type(formula)(
                self._substitute_formula(formula.left),
                self._substitute_formula(formula.right)
            )

        if isinstance(formula, Wand):
            # Wand is NOT commutative, preserve order
            return Wand(
                self._substitute_formula(formula.left),
                self._substitute_formula(formula.right)
            )

        if isinstance(formula, Not):
            return Not(self._substitute_formula(formula.formula))

        if isinstance(formula, (Exists, Forall)):
            # Don't substitute the quantified variable itself
            return type(formula)(
                formula.var,
                self._substitute_formula(formula.formula)
            )

        # Return unchanged for unknown types
        return formula

    def _substitute_expr(self, expr: Expr) -> Expr:
        """Apply substitution to an expression"""
        if isinstance(expr, Var):
            # First check if this variable has an arithmetic expression substitution
            if expr.name in self.expr_substitution_map:
                # Recursively substitute to handle transitive dependencies
                return self._substitute_expr(self.expr_substitution_map[expr.name])

            # Then check union-find-based substitutions
            rep = self.substitution_map.get(expr.name, expr.name)
            if rep != expr.name:
                # Check if representative is a constant
                if rep == 'nil':
                    return Const(None)
                try:
                    val = int(rep)
                    return Const(val)
                except ValueError:
                    return Var(rep)
            return expr

        elif isinstance(expr, Const):
            return expr

        elif isinstance(expr, ArithExpr):
            # Recursively substitute in arithmetic expressions
            left_sub = self._substitute_expr(expr.left)
            right_sub = self._substitute_expr(expr.right)

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

        # For other expressions, return unchanged
        return expr


def preprocess_equalities(formula: Formula) -> Formula:
    """
    Convenience function to preprocess a formula with equality substitution.

    Args:
        formula: Input formula

    Returns:
        Formula with variables canonicalized via equality substitution

    Example:
        >>> from frame.core.ast import *
        >>> x, y = Var("x"), Var("y")
        >>> # list(x) & x = y becomes list(y) & y = y
        >>> f = And(PredicateCall("list", [x]), Eq(x, y))
        >>> result = preprocess_equalities(f)
    """
    preprocessor = EqualityPreprocessor()
    return preprocessor.preprocess(formula)
