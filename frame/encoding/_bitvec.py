"""
Bitvector Theory Encoding (QF_BV)

This module handles encoding of bitvector expressions and formulas for Z3.
Extracted from encoder.py to improve modularity.
"""

import z3
from typing import Dict, Tuple, Optional
from frame.core.ast import (
    Expr, Var, BitVecVal, BitVecExpr
)


class BitVecEncoder:
    """Encodes bitvector expressions for Z3"""

    def __init__(self, parent_encoder):
        """Initialize bitvector encoder

        Args:
            parent_encoder: The main Z3Encoder instance (for accessing shared state)
        """
        self.encoder = parent_encoder
        # Cache for bitvector variables: (name, width) -> BitVec
        self.bitvec_var_cache: Dict[Tuple[str, int], z3.BitVecRef] = {}

    def is_bitvec_expr(self, expr: Expr) -> bool:
        """Check if an expression is a bitvector expression

        Args:
            expr: Expression to check

        Returns:
            True if the expression is a bitvector type
        """
        return isinstance(expr, (BitVecVal, BitVecExpr))

    def get_bitvec_width(self, expr: Expr) -> Optional[int]:
        """Get the bit width of a bitvector expression

        Args:
            expr: Expression to check

        Returns:
            Bit width if expression is a bitvector, None otherwise
        """
        if isinstance(expr, BitVecVal):
            return expr.width
        elif isinstance(expr, BitVecExpr):
            return expr.width
        return None

    def encode_bitvec_expr(self, expr: Expr, width: int, prefix: str = "") -> z3.BitVecRef:
        """Encode an expression as a bitvector (for bitvector contexts)

        Args:
            expr: Expression to encode
            width: Expected bit width
            prefix: Variable prefix for scoping

        Returns:
            Z3 bitvector expression
        """
        if isinstance(expr, BitVecVal):
            return z3.BitVecVal(expr.value, expr.width)
        elif isinstance(expr, BitVecExpr):
            return self.encode_bitvec_op(expr, prefix=prefix)
        elif isinstance(expr, Var):
            # In bitvector context, create a bitvector variable
            cache_key = (f"{prefix}{expr.name}", width)
            if cache_key not in self.bitvec_var_cache:
                self.bitvec_var_cache[cache_key] = z3.BitVec(f"{prefix}{expr.name}", width)
            return self.bitvec_var_cache[cache_key]
        else:
            # For other expressions, try regular encoding
            return self.encoder.encode_expr(expr, prefix=prefix)

    def encode_bitvec_op(self, expr: BitVecExpr, prefix: str = "") -> z3.BitVecRef:
        """Encode a bitvector operation

        Args:
            expr: Bitvector expression
            prefix: Variable prefix for scoping

        Returns:
            Z3 bitvector expression
        """
        # Encode operands
        operands_z3 = []
        for op in expr.operands:
            if isinstance(op, Var):
                # Bitvector variable
                cache_key = (f"{prefix}{op.name}", expr.width)
                if cache_key not in self.bitvec_var_cache:
                    self.bitvec_var_cache[cache_key] = z3.BitVec(f"{prefix}{op.name}", expr.width)
                operands_z3.append(self.bitvec_var_cache[cache_key])
            else:
                operands_z3.append(self.encoder.encode_expr(op, prefix=prefix))

        # Apply operation
        op = expr.op
        ops = operands_z3

        # Arithmetic operations
        if op == 'bvadd':
            return ops[0] + ops[1]
        elif op == 'bvsub':
            return ops[0] - ops[1]
        elif op == 'bvmul':
            return ops[0] * ops[1]
        elif op == 'bvudiv':
            return z3.UDiv(ops[0], ops[1])
        elif op == 'bvurem':
            return z3.URem(ops[0], ops[1])
        elif op == 'bvsdiv':
            return ops[0] / ops[1]
        elif op == 'bvsrem':
            return z3.SRem(ops[0], ops[1])

        # Bitwise operations
        elif op == 'bvand':
            return ops[0] & ops[1]
        elif op == 'bvor':
            return ops[0] | ops[1]
        elif op == 'bvxor':
            return ops[0] ^ ops[1]
        elif op == 'bvnot':
            return ~ops[0]
        elif op == 'bvshl':
            return ops[0] << ops[1]
        elif op == 'bvlshr':
            return z3.LShR(ops[0], ops[1])
        elif op == 'bvashr':
            return ops[0] >> ops[1]

        # Comparison operations (return Bool by default, or 1-bit BitVec if width=1)
        elif op == 'bvult':
            bool_result = z3.ULT(ops[0], ops[1])
        elif op == 'bvule':
            bool_result = z3.ULE(ops[0], ops[1])
        elif op == 'bvugt':
            bool_result = z3.UGT(ops[0], ops[1])
        elif op == 'bvuge':
            bool_result = z3.UGE(ops[0], ops[1])
        elif op == 'bvslt':
            bool_result = ops[0] < ops[1]
        elif op == 'bvsle':
            bool_result = ops[0] <= ops[1]
        elif op == 'bvsgt':
            bool_result = ops[0] > ops[1]
        elif op == 'bvsge':
            bool_result = ops[0] >= ops[1]
        else:
            raise ValueError(f"Unsupported bitvector operation: {op}")

        # For comparison operations, convert Bool to 1-bit bitvector if width=1 is specified
        if op in ['bvult', 'bvule', 'bvugt', 'bvuge', 'bvslt', 'bvsle', 'bvsgt', 'bvsge']:
            if expr.width == 1:
                # Convert boolean result to 1-bit bitvector: true -> 0b1, false -> 0b0
                return z3.If(bool_result, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
            else:
                # Return as boolean (standard SMT-LIB behavior)
                return bool_result
