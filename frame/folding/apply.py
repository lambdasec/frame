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
    1. Remove concrete pto cells from formula
    2. Add predicate call in their place
    3. Add pure side conditions (as conjuncts)
    4. Wrap in existential quantifiers if needed (for witnesses)

    Args:
        proposal: Verified fold proposal
        formula: Original formula to transform

    Returns:
        Transformed formula with fold applied
    """
    # Step 1: Remove the pto cells that are being folded
    formula_without_ptos = _remove_pto_cells(formula, proposal.pto_cells)

    # Step 2: Create the predicate call
    pred_call = proposal.to_predicate_call()

    # Step 3: Add predicate call to formula
    if isinstance(formula_without_ptos, Emp):
        # If we removed everything, just use the predicate
        result = pred_call
    else:
        # Otherwise, add predicate in separating conjunction
        result = SepConj(formula_without_ptos, pred_call)

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
