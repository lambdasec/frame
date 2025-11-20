"""
Parsed predicate definitions from SMT2 files

Includes ParsedPredicate and GenericPredicate for dynamically loaded predicates.
"""

from typing import List, Dict, Optional
from frame.core.ast import *
from frame.predicates.base import InductivePredicate, PredicateValidator

class ParsedPredicate(InductivePredicate):
    """
    Predicate with a parsed body from define-funs-rec.

    Supports proper unfolding with parameter substitution.
    """

    def __init__(self, name: str, params: List[str], body: Formula):
        super().__init__(name, len(params))
        self.params = params  # Formal parameter names
        self.body = body  # Parsed body formula

    def unfold(self, args: List[Expr]) -> Formula:
        """
        Unfold the predicate by substituting arguments for parameters in the body.

        Args:
            args: Actual arguments to substitute

        Returns:
            Body with parameters replaced by arguments
        """
        if len(args) != len(self.params):
            raise ValueError(f"{self.name} expects {len(self.params)} arguments, got {len(args)}")

        # Create substitution map: param_name -> actual_arg
        subst_map = {param: arg for param, arg in zip(self.params, args)}

        # Perform substitution
        return self._substitute(self.body, subst_map)

    def unfold_bounded(self, args: List[Expr], depth: int, registry=None) -> Formula:
        """
        Unfold the predicate to a bounded depth, recursively unfolding nested predicates.

        Args:
            args: Arguments to the predicate
            depth: Maximum unfolding depth
            registry: Optional PredicateRegistry for unfolding nested predicates

        Returns:
            The bounded unfolded formula with nested predicates also unfolded
        """
        if depth <= 0:
            return PredicateCall(self.name, args)

        # First unfold this predicate
        unfolded = self.unfold(args)

        # Then recursively unfold any nested PredicateCalls in the result
        # This is critical for predicates like ls(x,y) that contain recursive calls
        return self._unfold_nested(unfolded, depth - 1, registry)

    def _unfold_nested(self, formula: Formula, remaining_depth: int, registry=None) -> Formula:
        """
        Recursively unfold nested PredicateCalls within a formula.

        This handles the body of an unfolded predicate that contains recursive calls.
        For example, after unfolding ls(x,y) to "x=y & emp | exists u. x|->u * ls(u,y)",
        we need to continue unfolding the nested ls(u,y) call.

        Args:
            formula: The formula to unfold
            remaining_depth: Remaining unfold depth
            registry: Optional PredicateRegistry for unfolding other predicates
        """
        if remaining_depth <= 0:
            return formula

        if isinstance(formula, PredicateCall):
            # If it's a recursive call to the same predicate, handle it directly
            if formula.name == self.name:
                return self.unfold_bounded(formula.args, remaining_depth, registry)
            # If we have a registry, use it to unfold other predicates
            elif registry is not None:
                other_predicate = registry.get(formula.name)
                if other_predicate:
                    return other_predicate.unfold_bounded(formula.args, remaining_depth, registry)
            # Otherwise leave it as-is
            return formula

        elif isinstance(formula, SepConj):
            return SepConj(
                self._unfold_nested(formula.left, remaining_depth, registry),
                self._unfold_nested(formula.right, remaining_depth, registry)
            )
        elif isinstance(formula, And):
            return And(
                self._unfold_nested(formula.left, remaining_depth, registry),
                self._unfold_nested(formula.right, remaining_depth, registry)
            )
        elif isinstance(formula, Or):
            return Or(
                self._unfold_nested(formula.left, remaining_depth, registry),
                self._unfold_nested(formula.right, remaining_depth, registry)
            )
        elif isinstance(formula, Not):
            return Not(self._unfold_nested(formula.formula, remaining_depth, registry))
        elif isinstance(formula, Exists):
            return Exists(
                formula.var,
                self._unfold_nested(formula.formula, remaining_depth, registry)
            )
        elif isinstance(formula, Forall):
            return Forall(
                formula.var,
                self._unfold_nested(formula.formula, remaining_depth, registry)
            )
        else:
            # Base formulas: Emp, PointsTo, Eq, Neq, etc.
            return formula

    def _substitute(self, formula: Formula, subst_map: Dict[str, Expr]) -> Formula:
        """
        Recursively substitute variables in a formula.

        Args:
            formula: Formula to substitute in
            subst_map: Mapping from variable names to expressions

        Returns:
            Formula with substitutions applied
        """
        if isinstance(formula, Var):
            # Replace variable if in substitution map
            return subst_map.get(formula.name, formula)

        elif isinstance(formula, (Const, Emp, True_, False_)):
            return formula

        elif isinstance(formula, Eq):
            return Eq(
                self._substitute_expr(formula.left, subst_map),
                self._substitute_expr(formula.right, subst_map)
            )

        elif isinstance(formula, Neq):
            return Neq(
                self._substitute_expr(formula.left, subst_map),
                self._substitute_expr(formula.right, subst_map)
            )

        elif isinstance(formula, PointsTo):
            new_location = self._substitute_expr(formula.location, subst_map)
            new_values = [self._substitute_expr(v, subst_map) for v in formula.values]
            return PointsTo(new_location, new_values)

        elif isinstance(formula, PredicateCall):
            new_args = [self._substitute_expr(arg, subst_map) for arg in formula.args]
            return PredicateCall(formula.name, new_args)

        elif isinstance(formula, SepConj):
            return SepConj(
                self._substitute(formula.left, subst_map),
                self._substitute(formula.right, subst_map)
            )

        elif isinstance(formula, And):
            return And(
                self._substitute(formula.left, subst_map),
                self._substitute(formula.right, subst_map)
            )

        elif isinstance(formula, Or):
            return Or(
                self._substitute(formula.left, subst_map),
                self._substitute(formula.right, subst_map)
            )

        elif isinstance(formula, Not):
            return Not(self._substitute(formula.formula, subst_map))

        elif isinstance(formula, Exists):
            # Alpha-renaming to avoid variable capture
            # If the bound variable conflicts with free variables in substitution values,
            # rename it to a fresh variable
            bound_var = formula.var

            # Check if we need to rename to avoid capture
            needs_rename = False
            for subst_expr in subst_map.values():
                if self._expr_contains_var(subst_expr, bound_var):
                    needs_rename = True
                    break

            if needs_rename:
                # Generate a fresh variable name
                import uuid
                fresh_var = f"{bound_var}_{str(uuid.uuid4())[:8]}"
                # Rename the bound variable in the body
                renamed_body = self._substitute(formula.formula, {bound_var: Var(fresh_var)})
                # Then apply the outer substitution
                new_subst = {k: v for k, v in subst_map.items() if k != bound_var}
                result_body = self._substitute(renamed_body, new_subst)
                return Exists(fresh_var, result_body)
            else:
                # No renaming needed
                new_subst = {k: v for k, v in subst_map.items() if k != formula.var}
                return Exists(
                    formula.var,
                    self._substitute(formula.formula, new_subst)
                )

        elif isinstance(formula, Forall):
            # Alpha-renaming to avoid variable capture (same as Exists)
            bound_var = formula.var

            # Check if we need to rename to avoid capture
            needs_rename = False
            for subst_expr in subst_map.values():
                if self._expr_contains_var(subst_expr, bound_var):
                    needs_rename = True
                    break

            if needs_rename:
                # Generate a fresh variable name
                import uuid
                fresh_var = f"{bound_var}_{str(uuid.uuid4())[:8]}"
                # Rename the bound variable in the body
                renamed_body = self._substitute(formula.formula, {bound_var: Var(fresh_var)})
                # Then apply the outer substitution
                new_subst = {k: v for k, v in subst_map.items() if k != bound_var}
                result_body = self._substitute(renamed_body, new_subst)
                return Forall(fresh_var, result_body)
            else:
                # No renaming needed
                new_subst = {k: v for k, v in subst_map.items() if k != formula.var}
                return Forall(
                    formula.var,
                    self._substitute(formula.formula, new_subst)
                )

        else:
            return formula

    def _substitute_expr(self, expr: Expr, subst_map: Dict[str, Expr]) -> Expr:
        """Substitute in an expression recursively"""
        if isinstance(expr, Var):
            return subst_map.get(expr.name, expr)
        elif isinstance(expr, ArithExpr):
            # Recursively substitute in arithmetic expressions
            left_sub = self._substitute_expr(expr.left, subst_map)
            right_sub = self._substitute_expr(expr.right, subst_map)
            return ArithExpr(expr.op, left_sub, right_sub)
        else:
            # Const and other expressions remain unchanged
            return expr

    def _expr_contains_var(self, expr: Expr, var_name: str) -> bool:
        """Check if an expression contains a variable with the given name"""
        if isinstance(expr, Var):
            return expr.name == var_name
        elif isinstance(expr, ArithExpr):
            return (self._expr_contains_var(expr.left, var_name) or
                    self._expr_contains_var(expr.right, var_name))
        else:
            # Const and other expressions don't contain variables
            return False


class GenericPredicate(InductivePredicate):
    """
    Generic predicate that can handle any arity.

    Used as a placeholder for custom predicates with unknown definitions.
    Provides minimal unfolding: emp or a simple heap cell.
    """

    def __init__(self, name: str, arity: int):
        super().__init__(name, arity)

    def unfold(self, args: List[Expr]) -> Formula:
        """
        Simple unfolding: either emp or a single heap cell
        This is a sound over-approximation for satisfiability checking
        """
        if len(args) == 0:
            return Emp()

        # Base case: emp (predicate holds vacuously)
        base_case = Emp()

        # Recursive case: first arg points to some values, rest is the same predicate
        if len(args) >= 1:
            x = args[0]
            # Create fresh variables for heap values
            fresh_vars = [Var(f"v_{id(args)}_{i}") for i in range(min(len(args), 2))]

            if fresh_vars:
                recursive_case = PointsTo(x, fresh_vars)
                return Or(base_case, recursive_case)

        return base_case


