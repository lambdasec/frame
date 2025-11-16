"""
Unification algorithm for separation logic terms.

Implements Robinson's unification algorithm adapted for our AST,
with support for:
- Variable-to-expression unification
- Substitution composition
- Occurs check (prevents infinite terms)
- Existential witness instantiation
"""

from typing import Dict, Optional, Set
from frame.core.ast import *


class Substitution:
    """
    A substitution mapping variables to expressions.

    Represents a mapping σ: Var → Expr
    """

    def __init__(self, mappings: Optional[Dict[str, Expr]] = None):
        """
        Initialize substitution.

        Args:
            mappings: Variable name -> Expression mappings
        """
        self.mappings: Dict[str, Expr] = mappings if mappings else {}

    def apply(self, expr: Expr) -> Expr:
        """
        Apply substitution to an expression.

        Args:
            expr: Expression to substitute into

        Returns:
            Expression with substitutions applied
        """
        if isinstance(expr, Var):
            if expr.name in self.mappings:
                # Recursively apply to handle chained substitutions
                return self.apply(self.mappings[expr.name])
            return expr

        elif isinstance(expr, Const):
            return expr  # Constants don't change

        elif isinstance(expr, ArithExpr):
            return ArithExpr(
                self.apply(expr.left),
                expr.op,
                self.apply(expr.right)
            )

        else:
            # Unknown expression type, return as-is
            return expr

    def extend(self, var: str, expr: Expr) -> 'Substitution':
        """
        Extend substitution with a new mapping var -> expr.

        Also applies the new mapping to all existing mappings (composition).

        Args:
            var: Variable name
            expr: Expression to map to

        Returns:
            New extended substitution
        """
        # Create new mappings by applying new substitution to existing values
        new_mappings = {}
        for k, v in self.mappings.items():
            # Apply the new substitution [var -> expr] to existing value
            new_mappings[k] = self._substitute_in_expr(v, var, expr)

        # Add the new mapping
        new_mappings[var] = expr

        return Substitution(new_mappings)

    def _substitute_in_expr(self, target: Expr, var: str, replacement: Expr) -> Expr:
        """Helper to substitute var with replacement in target expression"""
        if isinstance(target, Var):
            return replacement if target.name == var else target
        elif isinstance(target, Const):
            return target
        elif isinstance(target, ArithExpr):
            return ArithExpr(
                self._substitute_in_expr(target.left, var, replacement),
                target.op,
                self._substitute_in_expr(target.right, var, replacement)
            )
        else:
            return target

    def compose(self, other: 'Substitution') -> 'Substitution':
        """
        Compose two substitutions: self ∘ other

        Returns substitution that applies other first, then self.
        """
        result = Substitution()

        # Apply self to all mappings in other
        for var, expr in other.mappings.items():
            result.mappings[var] = self.apply(expr)

        # Add mappings from self that aren't in other
        for var, expr in self.mappings.items():
            if var not in result.mappings:
                result.mappings[var] = expr

        return result

    def __repr__(self) -> str:
        if not self.mappings:
            return "∅"
        items = [f"{k} ↦ {v}" for k, v in self.mappings.items()]
        return "{" + ", ".join(items) + "}"

    def __bool__(self) -> bool:
        """Check if substitution is non-empty"""
        return bool(self.mappings)


class Unifier:
    """
    Unification algorithm for separation logic expressions.

    Finds substitutions that make two expressions equal.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def occurs_check(self, var: str, expr: Expr) -> bool:
        """
        Check if var occurs in expr (prevents infinite terms).

        Args:
            var: Variable name to check for
            expr: Expression to search in

        Returns:
            True if var occurs in expr, False otherwise
        """
        if isinstance(expr, Var):
            return expr.name == var
        elif isinstance(expr, Const):
            return False
        elif isinstance(expr, ArithExpr):
            return self.occurs_check(var, expr.left) or self.occurs_check(var, expr.right)
        else:
            return False

    def unify_exprs(self, e1: Expr, e2: Expr, subst: Optional[Substitution] = None) -> Optional[Substitution]:
        """
        Unify two expressions.

        Args:
            e1: First expression
            e2: Second expression
            subst: Current substitution (optional)

        Returns:
            Substitution that makes e1 and e2 equal, or None if unification fails
        """
        if subst is None:
            subst = Substitution()

        # Apply current substitution to both expressions
        e1 = subst.apply(e1)
        e2 = subst.apply(e2)

        # If expressions are already equal, we're done
        if self._exprs_equal(e1, e2):
            return subst

        # Case 1: e1 is a variable
        if isinstance(e1, Var):
            if self.occurs_check(e1.name, e2):
                if self.verbose:
                    print(f"Occurs check failed: {e1.name} in {e2}")
                return None  # Occurs check failed
            return subst.extend(e1.name, e2)

        # Case 2: e2 is a variable
        if isinstance(e2, Var):
            if self.occurs_check(e2.name, e1):
                if self.verbose:
                    print(f"Occurs check failed: {e2.name} in {e1}")
                return None  # Occurs check failed
            return subst.extend(e2.name, e1)

        # Case 3: Both are constants
        if isinstance(e1, Const) and isinstance(e2, Const):
            if e1.value == e2.value:
                return subst
            else:
                if self.verbose:
                    print(f"Constants don't match: {e1.value} ≠ {e2.value}")
                return None  # Different constants

        # Case 4: Both are arithmetic expressions
        if isinstance(e1, ArithExpr) and isinstance(e2, ArithExpr):
            if e1.op != e2.op:
                if self.verbose:
                    print(f"Operators don't match: {e1.op} ≠ {e2.op}")
                return None  # Different operators

            # Unify left sides
            subst = self.unify_exprs(e1.left, e2.left, subst)
            if subst is None:
                return None

            # Unify right sides
            subst = self.unify_exprs(e1.right, e2.right, subst)
            return subst

        # Case 5: Different types - can't unify
        if self.verbose:
            print(f"Can't unify different types: {type(e1).__name__} vs {type(e2).__name__}")
        return None

    def unify_lists(self, exprs1: list, exprs2: list, subst: Optional[Substitution] = None) -> Optional[Substitution]:
        """
        Unify two lists of expressions pairwise.

        Args:
            exprs1: First list of expressions
            exprs2: Second list of expressions
            subst: Current substitution

        Returns:
            Substitution that unifies all pairs, or None if any pair fails
        """
        if subst is None:
            subst = Substitution()

        # Lists must have same length
        if len(exprs1) != len(exprs2):
            if self.verbose:
                print(f"List length mismatch: {len(exprs1)} ≠ {len(exprs2)}")
            return None

        # Unify each pair
        for e1, e2 in zip(exprs1, exprs2):
            subst = self.unify_exprs(e1, e2, subst)
            if subst is None:
                return None  # Unification failed

        return subst

    def _exprs_equal(self, e1: Expr, e2: Expr) -> bool:
        """Check if two expressions are syntactically equal"""
        if type(e1) != type(e2):
            return False

        if isinstance(e1, Var):
            return e1.name == e2.name
        elif isinstance(e1, Const):
            return e1.value == e2.value
        elif isinstance(e1, ArithExpr):
            return (e1.op == e2.op and
                   self._exprs_equal(e1.left, e2.left) and
                   self._exprs_equal(e1.right, e2.right))
        else:
            return False

    def unify_formulas(self, f1: Formula, f2: Formula, subst: Optional[Substitution] = None) -> Optional[Substitution]:
        """
        Attempt to unify two formulas.

        This is more complex than expression unification because formulas
        have spatial structure (separating conjunction, etc.)

        Args:
            f1: First formula
            f2: Second formula
            subst: Current substitution

        Returns:
            Substitution if unification succeeds, None otherwise
        """
        if subst is None:
            subst = Substitution()

        # Apply current substitution
        f1 = self.apply_subst_formula(f1, subst)
        f2 = self.apply_subst_formula(f2, subst)

        # If same type, try to unify components
        if type(f1) == type(f2):
            if isinstance(f1, PointsTo) and isinstance(f2, PointsTo):
                # Unify location
                subst = self.unify_exprs(f1.location, f2.location, subst)
                if subst is None:
                    return None
                # Unify values (PointsTo can have multiple fields)
                return self.unify_lists(f1.values, f2.values, subst)

            elif isinstance(f1, PredicateCall) and isinstance(f2, PredicateCall):
                # Predicates must have same name
                if f1.name != f2.name:
                    return None
                # Unify arguments
                return self.unify_lists(f1.args, f2.args, subst)

        return None  # Can't unify

    def apply_subst_formula(self, formula: Formula, subst: Substitution) -> Formula:
        """Apply substitution to a formula"""
        if isinstance(formula, PointsTo):
            return PointsTo(
                subst.apply(formula.location),
                [subst.apply(v) for v in formula.values]
            )
        elif isinstance(formula, PredicateCall):
            return PredicateCall(
                formula.name,
                [subst.apply(arg) for arg in formula.args]
            )
        elif isinstance(formula, SepConj):
            return SepConj(
                self.apply_subst_formula(formula.left, subst),
                self.apply_subst_formula(formula.right, subst)
            )
        elif isinstance(formula, And):
            return And(
                self.apply_subst_formula(formula.left, subst),
                self.apply_subst_formula(formula.right, subst)
            )
        else:
            return formula  # Return unchanged for other types
