"""
Arithmetic Constraint Verification using Z3

This module verifies arithmetic side conditions for fold proposals
to ensure they are consistent with or entailed by existing pure constraints.
"""

import z3
from typing import List, Optional
from functools import lru_cache


def verify_side_conditions(
    side_constraints: List[z3.BoolRef],
    pure_constraints: List[z3.BoolRef],
    timeout_ms: int = 1000
) -> bool:
    """
    Check whether side constraints are valid given pure constraints.

    Uses two criteria (in order of preference):
    1. Entailment: pure_constraints => side_constraints (strongest)
    2. Satisfiability: pure_constraints && side_constraints is satisfiable (weaker)

    Args:
        side_constraints: Arithmetic constraints from proposal synthesis
        pure_constraints: Existing pure constraints from antecedent
        timeout_ms: Z3 solver timeout in milliseconds

    Returns:
        True if side constraints are acceptable (entailed or satisfiable)
    """

    if not side_constraints:
        # No side constraints to verify => trivially OK
        return True

    # Try entailment check first: pure => side
    # This means: pure && !side is unsat
    if _check_entailment(side_constraints, pure_constraints, timeout_ms):
        return True

    # Fallback: check satisfiability
    # This means: pure && side is sat
    if _check_satisfiability(side_constraints, pure_constraints, timeout_ms):
        return True

    return False


def _check_entailment(
    side_constraints: List[z3.BoolRef],
    pure_constraints: List[z3.BoolRef],
    timeout_ms: int
) -> bool:
    """
    Check if pure_constraints entails side_constraints.

    Equivalent to checking: (pure && !side) is unsat
    """
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    # Add pure constraints
    for pc in pure_constraints:
        solver.add(pc)

    # Add negation of side constraints
    if len(side_constraints) == 1:
        solver.add(z3.Not(side_constraints[0]))
    else:
        conj_side = z3.And(*side_constraints)
        solver.add(z3.Not(conj_side))

    # Check if unsat (which means entailment holds)
    result = solver.check()
    return result == z3.unsat


def _check_satisfiability(
    side_constraints: List[z3.BoolRef],
    pure_constraints: List[z3.BoolRef],
    timeout_ms: int
) -> bool:
    """
    Check if pure_constraints && side_constraints is satisfiable.

    This is a weaker condition than entailment, but allows introducing
    existential witnesses.
    """
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    # Add all constraints
    for pc in pure_constraints:
        solver.add(pc)

    for sc in side_constraints:
        solver.add(sc)

    # Check satisfiability
    result = solver.check()
    return result == z3.sat


@lru_cache(maxsize=256)
def _cached_verify(
    side_tuple: tuple,
    pure_tuple: tuple,
    timeout_ms: int
) -> bool:
    """
    Cached version of verification for performance.

    Note: This requires constraints to be hashable, so we use tuples of strings.
    """
    # This is a placeholder for caching - in practice, Z3 expressions aren't
    # directly hashable, so we'd need to serialize them first.
    # For now, we rely on the uncached version.
    pass


def verify_side_conditions_with_model(
    side_constraints: List[z3.BoolRef],
    pure_constraints: List[z3.BoolRef],
    timeout_ms: int = 1000
) -> tuple[bool, Optional[z3.ModelRef]]:
    """
    Enhanced verification that also returns a model if satisfiable.

    Returns:
        (is_valid, model) where model is None if not satisfiable
    """

    if not side_constraints:
        return True, None

    # Check satisfiability with model extraction
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    for pc in pure_constraints:
        solver.add(pc)

    for sc in side_constraints:
        solver.add(sc)

    result = solver.check()

    if result == z3.sat:
        return True, solver.model()
    elif result == z3.unsat:
        # Also check if entailed
        if _check_entailment(side_constraints, pure_constraints, timeout_ms):
            return True, None
        return False, None
    else:  # unknown
        return False, None


def simplify_constraints(constraints: List[z3.BoolRef]) -> List[z3.BoolRef]:
    """
    Simplify a list of Z3 constraints.

    Returns a potentially smaller list of equivalent constraints.
    """
    if not constraints:
        return []

    if len(constraints) == 1:
        simplified = z3.simplify(constraints[0])
        return [simplified] if not z3.is_true(simplified) else []

    # Simplify conjunction
    conj = z3.And(*constraints)
    simplified = z3.simplify(conj)

    # If simplified to True, no constraints needed
    if z3.is_true(simplified):
        return []

    # If simplified to False, contradictory
    if z3.is_false(simplified):
        return [z3.BoolVal(False)]

    # Otherwise return simplified form
    return [simplified]


def check_arithmetic_consistency(
    constraints: List[z3.BoolRef],
    timeout_ms: int = 1000
) -> bool:
    """
    Check if a set of arithmetic constraints is internally consistent (satisfiable).

    Args:
        constraints: List of Z3 boolean constraints
        timeout_ms: Solver timeout

    Returns:
        True if constraints are satisfiable
    """
    if not constraints:
        return True

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    for c in constraints:
        solver.add(c)

    return solver.check() == z3.sat
