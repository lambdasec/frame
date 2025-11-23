"""
Apply fold transformations to formulas.

This module handles the actual transformation of concrete heap cells
into predicate calls after verification.
"""

from typing import List, Set
from frame.heap.graph import FoldProposal
from frame.core.ast import (
    Formula, PointsTo, SepConj, PredicateCall, And, Exists, Emp,
    Var
)


def apply_fold(proposal: FoldProposal, formula: Formula) -> Formula:
    """
    Apply a verified fold proposal to a formula.

    Transformation:
    1. Remove concrete pto cells AND predicate calls from formula (for hierarchical predicates)
    2. Add new predicate call in their place
    3. Add pure side conditions (as conjuncts)
    4. Wrap in existential quantifiers if needed (for witnesses)

    Args:
        proposal: Verified fold proposal
        formula: Original formula to transform

    Returns:
        Transformed formula with fold applied
    """
    # Step 1a: Remove the pto cells that are being folded
    formula_after_pto_removal = _remove_pto_cells(formula, proposal.pto_cells)

    # Step 1b: Remove predicate calls that are being folded (for hierarchical predicates like nll)
    formula_after_removal = _remove_predicate_calls(formula_after_pto_removal, proposal.predicate_calls)

    # Step 2: Create the new predicate call
    pred_call = proposal.to_predicate_call()

    # Step 3: Add new predicate call to formula
    if isinstance(formula_after_removal, Emp):
        # If we removed everything, just use the new predicate
        result = pred_call
    else:
        # Otherwise, add predicate in separating conjunction
        result = SepConj(formula_after_removal, pred_call)

    # Step 4: Add pure side conditions if any
    if proposal.side_conditions:
        for side_cond in proposal.side_conditions:
            result = And(result, side_cond)

    # Step 5: Wrap in existentials for witness variables if needed
    # (This would be needed for length witnesses in ldll, for example)
    witness_vars = _extract_witness_vars(proposal)
    for var in witness_vars:
        result = Exists(var, result)

    return result


def _remove_pto_cells(formula: Formula, pto_cells: List[PointsTo]) -> Formula:
    """
    Remove specific pto cells from a formula.

    Args:
        formula: Formula to remove from
        pto_cells: List of pto cells to remove

    Returns:
        Formula with specified pto cells removed
    """
    # Create a set of pto cell identifiers for quick lookup
    pto_ids = set()
    for pto in pto_cells:
        # Use location name as identifier
        if hasattr(pto.location, 'name'):
            pto_ids.add(pto.location.name)
        else:
            pto_ids.add(str(pto.location))

    return _remove_pto_cells_recursive(formula, pto_ids)


def _remove_pto_cells_recursive(formula: Formula, pto_ids: Set[str]) -> Formula:
    """Recursively remove pto cells matching the given identifiers."""

    if isinstance(formula, PointsTo):
        # Check if this pto cell should be removed
        if hasattr(formula.location, 'name'):
            loc_id = formula.location.name
        else:
            loc_id = str(formula.location)

        if loc_id in pto_ids:
            # Remove this cell (return emp)
            return Emp()
        else:
            # Keep this cell
            return formula

    elif isinstance(formula, SepConj):
        left_result = _remove_pto_cells_recursive(formula.left, pto_ids)
        right_result = _remove_pto_cells_recursive(formula.right, pto_ids)

        # Simplify: remove emp from separating conjunction
        if isinstance(left_result, Emp):
            return right_result
        if isinstance(right_result, Emp):
            return left_result

        return SepConj(left_result, right_result)

    elif isinstance(formula, And):
        left_result = _remove_pto_cells_recursive(formula.left, pto_ids)
        right_result = _remove_pto_cells_recursive(formula.right, pto_ids)

        # Keep And structure (pure constraints should remain)
        return And(left_result, right_result)

    elif isinstance(formula, Exists):
        body_result = _remove_pto_cells_recursive(formula.body, pto_ids)
        return Exists(formula.var_name, body_result)

    else:
        # For other formula types (Emp, PredicateCall, etc.), keep as-is
        return formula


def _remove_predicate_calls(formula: Formula, predicate_calls: List[PredicateCall]) -> Formula:
    """
    Remove specific predicate calls from a formula (for hierarchical folding).

    For example, when folding into nll, we need to remove inner ls predicates.

    Args:
        formula: Formula to remove from
        predicate_calls: List of predicate calls to remove

    Returns:
        Formula with specified predicate calls removed
    """
    if not predicate_calls:
        return formula

    # Create identifiers for predicate calls to remove
    # Use (predicate_name, first_arg) as identifier
    pred_ids = set()
    for pred_call in predicate_calls:
        if len(pred_call.args) > 0:
            arg = pred_call.args[0]
            if hasattr(arg, 'name'):
                pred_ids.add((pred_call.name, arg.name))
            else:
                pred_ids.add((pred_call.name, str(arg)))

    return _remove_predicate_calls_recursive(formula, pred_ids)


def _remove_predicate_calls_recursive(formula: Formula, pred_ids: Set) -> Formula:
    """Recursively remove predicate calls matching the given identifiers."""

    if isinstance(formula, PredicateCall):
        # Check if this predicate call should be removed
        if len(formula.args) > 0:
            arg = formula.args[0]
            if hasattr(arg, 'name'):
                call_id = (formula.name, arg.name)
            else:
                call_id = (formula.name, str(arg))

            if call_id in pred_ids:
                # Remove this predicate call (return emp)
                return Emp()

        # Keep this predicate call
        return formula

    elif isinstance(formula, SepConj):
        left_result = _remove_predicate_calls_recursive(formula.left, pred_ids)
        right_result = _remove_predicate_calls_recursive(formula.right, pred_ids)

        # Simplify: remove emp from separating conjunction
        if isinstance(left_result, Emp):
            return right_result
        if isinstance(right_result, Emp):
            return left_result

        return SepConj(left_result, right_result)

    elif isinstance(formula, And):
        left_result = _remove_predicate_calls_recursive(formula.left, pred_ids)
        right_result = _remove_predicate_calls_recursive(formula.right, pred_ids)
        return And(left_result, right_result)

    elif isinstance(formula, Exists):
        # Fix: use formula.formula instead of formula.body
        if hasattr(formula, 'formula'):
            body_result = _remove_predicate_calls_recursive(formula.formula, pred_ids)
            return Exists(formula.var, body_result)
        else:
            # Fallback for legacy code
            body_result = _remove_predicate_calls_recursive(formula.body, pred_ids)
            return Exists(formula.var_name, body_result)

    else:
        # For other formula types, keep as-is
        return formula


def _extract_witness_vars(proposal: FoldProposal) -> List[str]:
    """
    Extract witness variables that need existential quantification.

    For example, length variables in ldll predicates.

    Args:
        proposal: Fold proposal

    Returns:
        List of variable names that need to be existentially quantified
    """
    witness_vars = []

    # Check if any args are witness variables (typically generated names)
    for arg in proposal.args:
        if isinstance(arg, Var):
            # Heuristic: if variable name ends with _witness or _len, it's a witness
            if '_witness' in arg.name or '_len' in arg.name:
                witness_vars.append(arg.name)

    return witness_vars


def apply_multiple_folds(proposals: List[FoldProposal], formula: Formula) -> Formula:
    """
    Apply multiple non-overlapping folds to a formula.

    Proposals are applied in order (typically largest/highest confidence first).

    Args:
        proposals: List of verified, non-overlapping proposals
        formula: Original formula

    Returns:
        Transformed formula with all folds applied
    """
    result = formula

    for proposal in proposals:
        result = apply_fold(proposal, result)

    return result
