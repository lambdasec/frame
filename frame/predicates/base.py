"""
Base classes for inductive predicates

Defines the abstract base class and validator for all predicates.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Set, Tuple
from frame.core.ast import *


class PredicateValidationError(Exception):
    """Exception raised when predicate definition is unsound"""
    pass


class PredicateValidator:
    """
    Validates inductive predicate definitions for soundness.

    Checks:
    1. Strict Positivity: Predicate doesn't appear in negative positions
    2. Free Variables: All variables are properly bound
    3. Arity Consistency: Recursive calls have correct number of arguments
    """

    def __init__(self, predicate_name: str, arity: int, formal_params: List[str]):
        self.predicate_name = predicate_name
        self.arity = arity
        self.formal_params = set(formal_params)
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate(self, definition: Formula) -> Tuple[bool, List[str], List[str]]:
        """
        Validate a predicate definition.

        Args:
            definition: The formula defining the predicate

        Returns:
            (is_valid, errors, warnings) tuple
        """
        self.errors = []
        self.warnings = []

        # Check strict positivity
        self._check_positivity(definition, polarity=True)

        # Check free variables
        self._check_free_variables(definition, bound_vars=self.formal_params.copy())

        # Check arity consistency
        self._check_arity_consistency(definition)

        return len(self.errors) == 0, self.errors, self.warnings

    def _check_positivity(self, formula: Formula, polarity: bool):
        """
        Check strict positivity: predicate should only appear in positive positions.

        Args:
            formula: Formula to check
            polarity: True for positive context, False for negative
        """
        if isinstance(formula, PredicateCall):
            if formula.name == self.predicate_name and not polarity:
                self.errors.append(
                    f"Predicate '{self.predicate_name}' appears in negative position. "
                    f"This violates strict positivity and makes the definition unsound."
                )

        elif isinstance(formula, Not):
            # Negation flips polarity
            self._check_positivity(formula.formula, polarity=not polarity)

        elif isinstance(formula, And):
            self._check_positivity(formula.left, polarity)
            self._check_positivity(formula.right, polarity)

        elif isinstance(formula, Or):
            self._check_positivity(formula.left, polarity)
            self._check_positivity(formula.right, polarity)

        elif isinstance(formula, SepConj):
            self._check_positivity(formula.left, polarity)
            self._check_positivity(formula.right, polarity)

        elif isinstance(formula, Exists):
            self._check_positivity(formula.formula, polarity)

        elif isinstance(formula, Forall):
            # Forall can flip polarity in implication contexts, but we don't have
            # implication, so we keep the same polarity
            self._check_positivity(formula.formula, polarity)

        # Base cases (Emp, PointsTo, Eq, Neq, True_, False_) don't contain predicates

    def _check_free_variables(self, formula: Formula, bound_vars: Set[str]):
        """
        Check that all variables are properly bound.

        Args:
            formula: Formula to check
            bound_vars: Set of currently bound variable names
        """
        if isinstance(formula, Var):
            if formula.name not in bound_vars:
                self.errors.append(
                    f"Free variable '{formula.name}' in predicate definition. "
                    f"All variables must be parameters or bound by quantifiers."
                )

        elif isinstance(formula, PointsTo):
            # Check location
            self._check_expr_variables(formula.location, bound_vars)
            # Check values
            for val in formula.values:
                self._check_expr_variables(val, bound_vars)

        elif isinstance(formula, PredicateCall):
            for arg in formula.args:
                self._check_expr_variables(arg, bound_vars)

        elif isinstance(formula, Eq) or isinstance(formula, Neq):
            self._check_expr_variables(formula.left, bound_vars)
            self._check_expr_variables(formula.right, bound_vars)

        elif isinstance(formula, And) or isinstance(formula, Or) or isinstance(formula, SepConj):
            self._check_free_variables(formula.left, bound_vars)
            self._check_free_variables(formula.right, bound_vars)

        elif isinstance(formula, Not):
            self._check_free_variables(formula.formula, bound_vars)

        elif isinstance(formula, Exists) or isinstance(formula, Forall):
            # Add quantified variable to bound set
            new_bound = bound_vars.copy()
            new_bound.add(formula.var)
            self._check_free_variables(formula.formula, new_bound)

        # Base cases: Emp, True_, False_, Const don't have variables

    def _check_expr_variables(self, expr: Expr, bound_vars: Set[str]):
        """Check variables in an expression."""
        if isinstance(expr, Var):
            if expr.name not in bound_vars:
                self.errors.append(
                    f"Free variable '{expr.name}' in predicate definition. "
                    f"All variables must be parameters or bound by quantifiers."
                )
        # Const doesn't have variables

    def _check_arity_consistency(self, formula: Formula):
        """
        Check that recursive calls have the correct arity.

        Args:
            formula: Formula to check
        """
        if isinstance(formula, PredicateCall):
            if formula.name == self.predicate_name:
                if len(formula.args) != self.arity:
                    self.errors.append(
                        f"Recursive call to '{self.predicate_name}' has {len(formula.args)} "
                        f"arguments, but predicate is defined with arity {self.arity}."
                    )

        elif isinstance(formula, And) or isinstance(formula, Or) or isinstance(formula, SepConj):
            self._check_arity_consistency(formula.left)
            self._check_arity_consistency(formula.right)

        elif isinstance(formula, Not):
            self._check_arity_consistency(formula.formula)

        elif isinstance(formula, Exists) or isinstance(formula, Forall):
            self._check_arity_consistency(formula.formula)

        # Base cases don't have predicate calls


class InductivePredicate(ABC):
    """Base class for inductive predicates"""

    def __init__(self, name: str, arity: int):
        self.name = name
        self.arity = arity

    @abstractmethod
    def unfold(self, args: List[Expr]) -> Formula:
        """
        Unfold the predicate into its definition.

        For example, ls(x, y) unfolds to:
            (x = y ∧ emp) ∨ (∃z. x |-> z * ls(z, y))

        Args:
            args: Arguments to the predicate

        Returns:
            Formula representing the unfolding
        """
        pass

    def unfold_bounded(self, args: List[Expr], depth: int) -> Formula:
        """
        Unfold the predicate to a bounded depth to avoid infinite unfolding.

        Args:
            args: Arguments to the predicate
            depth: Maximum unfolding depth

        Returns:
            The bounded unfolded formula
        """
        if depth <= 0:
            return PredicateCall(self.name, args)
        return self.unfold(args)

    def validate_definition(self) -> Tuple[bool, List[str], List[str]]:
        """
        Validate the predicate definition for soundness.

        Returns:
            (is_valid, errors, warnings) tuple

        Raises:
            PredicateValidationError: If the definition is unsound
        """
        # Create symbolic arguments for validation
        symbolic_args = [Var(f"param{i}") for i in range(self.arity)]
        formal_param_names = [arg.name for arg in symbolic_args]

        # Get the definition by unfolding
        definition = self.unfold(symbolic_args)

        # Create validator and check
        validator = PredicateValidator(self.name, self.arity, formal_param_names)
        return validator.validate(definition)

    def __str__(self) -> str:
        return f"{self.name}/{self.arity}"

    def __repr__(self) -> str:
        return f"InductivePredicate({self.name}, {self.arity})"
