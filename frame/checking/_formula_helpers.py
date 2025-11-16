"""
Formula inspection helper functions

Provides utility functions for inspecting formula structure and contents.
These are extracted from EntailmentChecker to reduce its size and improve modularity.
"""

from frame.core.ast import Formula


def has_predicate_calls(formula: Formula) -> bool:
    """
    Check if a formula contains any predicate calls.
    This is used to determine if the UNSAT antecedent check should be applied.
    """
    from frame.core.ast import PredicateCall, SepConj, And, Or, Not, Exists, Forall

    if isinstance(formula, PredicateCall):
        return True
    elif isinstance(formula, (SepConj, And, Or)):
        return has_predicate_calls(formula.left) or has_predicate_calls(formula.right)
    elif isinstance(formula, Not):
        return has_predicate_calls(formula.formula)
    elif isinstance(formula, (Exists, Forall)):
        return has_predicate_calls(formula.formula)
    else:
        return False


def has_concrete_spatial(formula: Formula) -> bool:
    """
    Check if a formula contains concrete spatial assertions (points-to, emp).
    This is used to distinguish concrete heaps from pure predicate formulas.
    """
    from frame.core.ast import PointsTo, Emp, SepConj, And, Or, Not, Exists, Forall

    if isinstance(formula, (PointsTo, Emp)):
        return True
    elif isinstance(formula, (SepConj, And, Or)):
        return has_concrete_spatial(formula.left) or has_concrete_spatial(formula.right)
    elif isinstance(formula, Not):
        return has_concrete_spatial(formula.formula)
    elif isinstance(formula, (Exists, Forall)):
        return has_concrete_spatial(formula.formula)
    else:
        return False


def count_formulas_by_type(formula: Formula, formula_type) -> int:
    """Count how many subformulas of given type appear in formula"""
    from frame.core.ast import SepConj, And, Or, Not, Exists, Forall

    if isinstance(formula, formula_type):
        return 1
    elif isinstance(formula, (SepConj, And, Or)):
        return (count_formulas_by_type(formula.left, formula_type) +
                count_formulas_by_type(formula.right, formula_type))
    elif isinstance(formula, (Not, Exists, Forall)):
        return count_formulas_by_type(formula.formula, formula_type)
    else:
        return 0


def contains_formula_type(formula: Formula, formula_type) -> bool:
    """Check if formula contains any subformula of given type"""
    return count_formulas_by_type(formula, formula_type) > 0
