"""
Formula utility functions.

Common formula operations and transformations used across the codebase.
"""

from typing import Optional, List
from frame.core.ast import Formula, Emp, PointsTo, PredicateCall, SepConj, Wand, And


def extract_spatial_part(formula: Formula) -> Optional[Formula]:
    """
    Extract the spatial part from a formula (ignoring pure constraints).

    The spatial part consists of:
    - Empty heap (emp)
    - Points-to assertions (x |-> y)
    - Predicate calls (ls(x, y))
    - Separating conjunction (P * Q)
    - Magic wand (P -* Q)

    Pure constraints (equality, arithmetic) are filtered out.

    Args:
        formula: Formula to extract spatial part from

    Returns:
        The spatial formula, or None if no spatial part exists

    Example:
        extract_spatial_part(x |-> 5 & x != nil) = x |-> 5
        extract_spatial_part(ls(x,y) * y |-> z & z = 3) = ls(x,y) * y |-> z
    """
    if isinstance(formula, (Emp, PointsTo, PredicateCall, SepConj, Wand)):
        return formula
    elif isinstance(formula, And):
        # Try to extract spatial from either side
        left_spatial = extract_spatial_part(formula.left)
        if left_spatial:
            return left_spatial
        return extract_spatial_part(formula.right)
    return None


def extract_pure_formulas(formula: Formula) -> List[Formula]:
    """
    Extract pure (non-spatial) constraints from a formula.

    Pure constraints include:
    - Equality/inequality (x = y, x != nil)
    - Arithmetic comparisons (x < y, x >= 0)

    These are needed for verification to ensure transformations
    preserve the pure part of the formula.

    Args:
        formula: Formula to extract pure constraints from

    Returns:
        List of pure constraint formulas

    Example:
        extract_pure_formulas(x |-> 5 & x != nil & y = 3) = [x != nil, y = 3]
    """
    from frame.core.ast import Eq, Neq, Lt, Le, Gt, Ge

    pure_constraints = []

    def extract_recursive(f: Formula):
        if isinstance(f, (Eq, Neq, Lt, Le, Gt, Ge)):
            pure_constraints.append(f)
        elif isinstance(f, And):
            extract_recursive(f.left)
            extract_recursive(f.right)
        # Ignore spatial formulas (PointsTo, SepConj, etc.)

    extract_recursive(formula)
    return pure_constraints
