"""
Arithmetic Witness Synthesis for Heap Graph Patterns

This module synthesizes arithmetic constraints from heap graph patterns
to enable lemma matching with side conditions.
"""

import z3
from typing import List, Dict, Tuple, Optional, Any
from frame.core.ast import Var, Const, ArithExpr, Eq
from frame.heap.graph import Chain, FoldProposal


def synthesize_arith_for_chain(
    chain: Chain,
    proposal: FoldProposal,
    encoder
) -> Tuple[Optional[List[z3.BoolRef]], Optional[Dict[str, str]]]:
    """
    Synthesize arithmetic constraints for a chain-based fold proposal.

    Args:
        chain: Detected chain pattern
        proposal: Fold proposal that may need arithmetic witnesses
        encoder: Z3Encoder instance for creating Z3 expressions

    Returns:
        (side_constraints_z3, witness_map) or (None, None) if no synthesis needed
    """

    # Check if this proposal needs arithmetic synthesis
    if not hasattr(proposal, 'predicate_name'):
        return None, None

    side_constraints = []
    witness_map = {}

    # Pattern 1: ldll (length-annotated doubly-linked list) proposals
    # These need length arithmetic: len1 = len2 + chain_length
    if proposal.predicate_name == "ldll":
        return _synthesize_ldll_constraints(chain, proposal, encoder, side_constraints, witness_map)

    # Pattern 2: List segment composition
    # ls(x, y) * ls(y, z) needs len(x,z) = len(x,y) + len(y,z)
    if proposal.predicate_name == "ls" and hasattr(proposal, 'compose_segments'):
        return _synthesize_ls_compose_constraints(proposal, encoder, side_constraints, witness_map)

    # Pattern 3: Single cell to ldll with arithmetic offset
    # E.g., E1 |-> E2 with x1 = x2 + 1 becomes ldll(E1, E1_p, 1, E2, E2_p, 0)
    if proposal.predicate_name == "ldll" and len(chain.nodes) == 1:
        return _synthesize_single_cell_ldll(chain, proposal, encoder, side_constraints, witness_map)

    # No arithmetic synthesis needed
    if not side_constraints:
        return None, None

    return side_constraints, witness_map


def _synthesize_ldll_constraints(
    chain: Chain,
    proposal: FoldProposal,
    encoder,
    side_constraints: List[z3.BoolRef],
    witness_map: Dict[str, str]
) -> Tuple[List[z3.BoolRef], Dict[str, str]]:
    """
    Synthesize constraints for ldll predicate:
    ldll(E, P, len1, F, L, len2)

    For a chain of length N, we need: len1 = len2 + N
    """

    # Check if proposal has length arguments
    if len(proposal.args) < 6:
        return None, None

    # Extract length arguments (positions 2 and 5 in ldll signature)
    len1_arg = proposal.args[2]  # len1
    len2_arg = proposal.args[5]  # len2

    # Encode as Z3 expressions
    len1_z3 = _encode_arith_expr(len1_arg, encoder)
    len2_z3 = _encode_arith_expr(len2_arg, encoder)

    # Chain length
    chain_len = chain.length

    # Constraint: len1 = len2 + chain_length
    side_constraints.append(len1_z3 == len2_z3 + chain_len)

    # Non-negativity constraints
    side_constraints.append(len1_z3 >= 0)
    side_constraints.append(len2_z3 >= 0)

    witness_map["ldll_length"] = f"len1 = len2 + {chain_len}"

    return side_constraints, witness_map


def _synthesize_ls_compose_constraints(
    proposal: FoldProposal,
    encoder,
    side_constraints: List[z3.BoolRef],
    witness_map: Dict[str, str]
) -> Tuple[List[z3.BoolRef], Dict[str, str]]:
    """
    Synthesize constraints for list segment composition:
    ls(x, y, n1) * ls(y, z, n2) => ls(x, z, n_total) where n_total = n1 + n2
    """

    if not hasattr(proposal, 'n1') or not hasattr(proposal, 'n2'):
        return None, None

    n1 = proposal.n1
    n2 = proposal.n2

    # Encode operands
    n1_z3 = _encode_arith_expr(n1, encoder)
    n2_z3 = _encode_arith_expr(n2, encoder)

    # Create fresh variable for total length
    n_total_z3 = encoder.fresh_var("len_total", z3.IntSort())

    # Constraint: n_total = n1 + n2
    side_constraints.append(n_total_z3 == n1_z3 + n2_z3)
    side_constraints.append(n_total_z3 >= 0)

    witness_map["ls_compose_length"] = f"len_total = n1 + n2"

    return side_constraints, witness_map


def _synthesize_single_cell_ldll(
    chain: Chain,
    proposal: FoldProposal,
    encoder,
    side_constraints: List[z3.BoolRef],
    witness_map: Dict[str, str]
) -> Tuple[List[z3.BoolRef], Dict[str, str]]:
    """
    Synthesize constraints for single-cell ldll pattern.

    Pattern: E1 |-> E2 becomes ldll(E1, E1_p, 1, E2, E2_p, 0)
    Common side condition: some length variable x1 = x2 + 1
    """

    # For single cell, len1 should be 1, len2 should be 0
    if len(proposal.args) >= 6:
        len1_arg = proposal.args[2]
        len2_arg = proposal.args[5]

        len1_z3 = _encode_arith_expr(len1_arg, encoder)
        len2_z3 = _encode_arith_expr(len2_arg, encoder)

        # Basic constraints for single cell
        side_constraints.append(len1_z3 == 1)
        side_constraints.append(len2_z3 == 0)

        witness_map["single_cell_ldll"] = "len1 = 1, len2 = 0"

        return side_constraints, witness_map

    return None, None


def _encode_arith_expr(expr: Any, encoder) -> z3.ArithRef:
    """
    Encode an expression to Z3 arithmetic.

    Args:
        expr: Can be int, Const, Var, ArithExpr, or already a z3 expression
        encoder: Z3Encoder instance

    Returns:
        Z3 arithmetic expression
    """
    # Already a Z3 expression
    if isinstance(expr, (z3.ArithRef, z3.IntNumRef)):
        return expr

    # Integer constant
    if isinstance(expr, int):
        return z3.IntVal(expr)

    # Frame AST Const
    if isinstance(expr, Const):
        if isinstance(expr.value, int):
            return z3.IntVal(expr.value)
        elif expr.value is None:  # nil
            return z3.IntVal(0)
        else:
            # Try to convert to int
            try:
                return z3.IntVal(int(expr.value))
            except (ValueError, TypeError):
                # Create a symbolic variable
                return encoder.get_or_create_var(str(expr.value), z3.IntSort())

    # Frame AST Var
    if isinstance(expr, Var):
        # Try to parse as integer first
        try:
            return z3.IntVal(int(expr.name))
        except (ValueError, TypeError):
            # Symbolic variable
            return encoder.get_or_create_var(expr.name, z3.IntSort())

    # Frame AST ArithExpr
    if isinstance(expr, ArithExpr):
        left_z3 = _encode_arith_expr(expr.left, encoder)
        right_z3 = _encode_arith_expr(expr.right, encoder)

        if expr.op == '+':
            return left_z3 + right_z3
        elif expr.op == '-':
            return left_z3 - right_z3
        elif expr.op == '*':
            return left_z3 * right_z3
        elif expr.op == 'div':
            return left_z3 / right_z3
        elif expr.op == 'mod':
            return left_z3 % right_z3
        else:
            raise ValueError(f"Unsupported arithmetic operator: {expr.op}")

    # String (variable name)
    if isinstance(expr, str):
        try:
            return z3.IntVal(int(expr))
        except (ValueError, TypeError):
            return encoder.get_or_create_var(expr, z3.IntSort())

    # Fallback: try using encoder's encode_expr
    try:
        return encoder.encode_expr(expr)
    except Exception:
        # Last resort: create symbolic variable
        return encoder.get_or_create_var(str(expr), z3.IntSort())


def extract_pure_constraints_z3(formula, encoder) -> List[z3.BoolRef]:
    """
    Extract pure (non-spatial) constraints from a formula and convert to Z3.

    Args:
        formula: Separation logic formula
        encoder: Z3Encoder instance

    Returns:
        List of Z3 boolean constraints
    """
    from frame.core.ast import And, Eq, Neq, Lt, Le, Gt, Ge

    constraints = []

    if isinstance(formula, Eq):
        left_z3 = encoder.encode_expr(formula.left)
        right_z3 = encoder.encode_expr(formula.right)
        constraints.append(left_z3 == right_z3)

    elif isinstance(formula, Neq):
        left_z3 = encoder.encode_expr(formula.left)
        right_z3 = encoder.encode_expr(formula.right)
        constraints.append(left_z3 != right_z3)

    elif isinstance(formula, Lt):
        left_z3 = encoder.encode_expr(formula.left)
        right_z3 = encoder.encode_expr(formula.right)
        constraints.append(left_z3 < right_z3)

    elif isinstance(formula, Le):
        left_z3 = encoder.encode_expr(formula.left)
        right_z3 = encoder.encode_expr(formula.right)
        constraints.append(left_z3 <= right_z3)

    elif isinstance(formula, Gt):
        left_z3 = encoder.encode_expr(formula.left)
        right_z3 = encoder.encode_expr(formula.right)
        constraints.append(left_z3 > right_z3)

    elif isinstance(formula, Ge):
        left_z3 = encoder.encode_expr(formula.left)
        right_z3 = encoder.encode_expr(formula.right)
        constraints.append(left_z3 >= right_z3)

    elif isinstance(formula, And):
        # Recursively extract from both sides
        constraints.extend(extract_pure_constraints_z3(formula.left, encoder))
        constraints.extend(extract_pure_constraints_z3(formula.right, encoder))

    # For other formula types (PointsTo, PredicateCall, etc.), no pure constraints

    return constraints
