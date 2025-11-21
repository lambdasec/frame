"""
Wand Encoding Utility Functions

Internal helper module for wand (magic wand) encoding utilities.
Extracts common utility functions from _wand.py to keep it manageable.
"""

import z3
from typing import Set, Dict
from frame.core.ast import Formula, Expr, Var, Const, PointsTo, SepConj, And, Or, Not, Exists, Forall, PredicateCall


def collect_known_locations(encoder, P: Formula, Q: Formula, prefix: str) -> Set[z3.ExprRef]:
    """
    Collect locations that are known to exist in P or Q.

    These are locations that appear in PointsTo cells (concrete allocations).
    We use this set for finite-location reduction in wand encoding.

    Args:
        encoder: Parent Z3Encoder for accessing encode_expr
        P: Wand antecedent
        Q: Wand consequent
        prefix: Variable prefix for scoping

    Returns:
        Set of Z3 location expressions that appear in P or Q
    """
    locations = set()

    def collect_from_formula(formula: Formula):
        if isinstance(formula, PointsTo):
            loc = encoder.encode_expr(formula.location, prefix=prefix)
            locations.add(loc)

            # Also add field offsets for struct points-to
            for i in range(len(formula.values)):
                locations.add(loc + i)

        elif isinstance(formula, (SepConj, And, Or)):
            collect_from_formula(formula.left)
            collect_from_formula(formula.right)

        elif isinstance(formula, Not):
            collect_from_formula(formula.formula)

        elif isinstance(formula, (Exists, Forall)):
            collect_from_formula(formula.formula)

        # PredicateCall doesn't directly contribute concrete locations
        # (it's an abstraction over heap structure)

    collect_from_formula(P)
    collect_from_formula(Q)

    # Also add nil as a known location
    locations.add(z3.IntVal(encoder.nil))

    return locations


def extract_locations_from_antecedent(encoder, P: Formula, prefix: str) -> Set[z3.ExprRef]:
    """
    Extract location expressions from wand antecedent.

    Similar to collect_known_locations but only for P (the antecedent).
    Used for domain tracking during wand encoding.

    Args:
        encoder: Parent Z3Encoder
        P: Wand antecedent formula
        prefix: Variable prefix

    Returns:
        Set of Z3 location expressions
    """
    locations = set()

    def extract(formula: Formula):
        if isinstance(formula, PointsTo):
            loc = encoder.encode_expr(formula.location, prefix=prefix)
            locations.add(loc)
        elif isinstance(formula, (SepConj, And)):
            extract(formula.left)
            extract(formula.right)

    extract(P)
    return locations


def extract_footprint_with_values(encoder, formula: Formula, prefix: str) -> Dict[z3.ExprRef, z3.ExprRef]:
    """
    Extract heap footprint (location -> value mappings) from a formula.

    This builds a map of all points-to cells in the formula, mapping
    each location to its value. Used for wand elimination optimization.

    Args:
        encoder: Parent Z3Encoder
        formula: Formula to extract from
        prefix: Variable prefix

    Returns:
        Dictionary mapping Z3 locations to Z3 values
    """
    footprint = {}

    if isinstance(formula, PointsTo):
        loc = encoder.encode_expr(formula.location, prefix=prefix)

        # Single value case: x |-> v
        if len(formula.values) == 1:
            val = encoder.encode_expr(formula.values[0], prefix=prefix)
            footprint[loc] = val

        # Multi-value case: x |-> (v1, v2, ...)
        else:
            for i, value in enumerate(formula.values):
                field_loc = loc + i
                val = encoder.encode_expr(value, prefix=prefix)
                footprint[field_loc] = val

    elif isinstance(formula, SepConj):
        # Merge footprints from both sides
        left_footprint = extract_footprint_with_values(encoder, formula.left, prefix)
        right_footprint = extract_footprint_with_values(encoder, formula.right, prefix)
        footprint.update(left_footprint)
        footprint.update(right_footprint)

    return footprint


def compute_extension_bound(formula: Formula) -> int:
    """
    Compute a bound on how many new locations a formula might allocate.

    This is used for finite-domain reasoning in wand encoding.
    We count the number of PointsTo cells in the formula.

    Args:
        formula: Formula to analyze

    Returns:
        Upper bound on number of new locations (0 if unknown/infinite)
    """
    if isinstance(formula, PointsTo):
        # Each PointsTo allocates 1 location (plus field offsets handled separately)
        return 1

    elif isinstance(formula, SepConj):
        # Sum bounds from both sides
        return compute_extension_bound(formula.left) + compute_extension_bound(formula.right)

    elif isinstance(formula, And):
        # For And, take max (formulas share heap in pure conjunction)
        left_bound = compute_extension_bound(formula.left)
        right_bound = compute_extension_bound(formula.right)
        return max(left_bound, right_bound)

    elif isinstance(formula, PredicateCall):
        # Predicates can allocate unbounded heap - return 0 to signal "unknown"
        return 0

    # For other formulas (Emp, pure, etc.), no allocations
    return 0


def encode_disjointness(domain1: Set[z3.ExprRef], domain2: Set[z3.ExprRef]) -> z3.BoolRef:
    """
    Encode disjointness constraint: domain1 and domain2 are disjoint.

    Creates constraint that all pairs of locations from domain1 and domain2 are distinct.

    Args:
        domain1: First set of locations
        domain2: Second set of locations

    Returns:
        Z3 constraint encoding disjointness
    """
    if not domain1 or not domain2:
        return z3.BoolVal(True)

    constraints = []
    for loc1 in domain1:
        for loc2 in domain2:
            constraints.append(loc1 != loc2)

    if not constraints:
        return z3.BoolVal(True)

    return z3.And(constraints)


def is_allocated_in_domain(loc: z3.ExprRef, domain_set: Set[z3.ExprRef]) -> z3.BoolRef:
    """
    Check if a location is allocated in a domain.

    Returns:
        Z3 boolean: True if loc is in domain_set, False otherwise
    """
    if not domain_set:
        return z3.BoolVal(False)

    # Check if loc equals any location in domain
    checks = [loc == domain_loc for domain_loc in domain_set]

    if not checks:
        return z3.BoolVal(False)

    return z3.Or(checks)


def get_value_from_heap(encoder, loc: z3.ExprRef, heap_id: z3.ExprRef) -> z3.ExprRef:
    """Get value stored at location in heap"""
    return encoder.hval(heap_id, loc)


def formulas_equal(f1: Formula, f2: Formula) -> bool:
    """Structural equality check for formulas"""
    return str(f1) == str(f2)
