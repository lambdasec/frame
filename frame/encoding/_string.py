"""
String Theory Encoding (QF_S)

This module handles encoding of string expressions and formulas for Z3.
Extracted from encoder.py to improve modularity.
"""

import z3
from typing import Dict
from frame.core.ast import (
    Expr, Var, StrLiteral, StrConcat, StrSubstr
)


class StringEncoder:
    """Encodes string expressions for Z3"""

    def __init__(self, parent_encoder):
        """Initialize string encoder

        Args:
            parent_encoder: The main Z3Encoder instance (for accessing shared state)
        """
        self.encoder = parent_encoder
        self.StringSort = z3.StringSort()
        # String variable cache (separate from location variables)
        self.string_var_cache: Dict[str, z3.ExprRef] = {}

    def is_string_expr(self, expr: Expr) -> bool:
        """Check if an expression is a string expression

        Args:
            expr: Expression to check

        Returns:
            True if the expression is a string type
        """
        return isinstance(expr, (StrLiteral, StrConcat, StrSubstr))

    def encode_string_expr(self, expr: Expr, prefix: str = "") -> z3.SeqRef:
        """Encode an expression as a string (for string contexts)

        Args:
            expr: Expression to encode
            prefix: Variable prefix for scoping

        Returns:
            Z3 string expression
        """
        if isinstance(expr, StrLiteral):
            return z3.StringVal(expr.value)
        elif isinstance(expr, StrConcat):
            left_z3 = self.encode_string_expr(expr.left, prefix=prefix)
            right_z3 = self.encode_string_expr(expr.right, prefix=prefix)
            return z3.Concat(left_z3, right_z3)
        elif isinstance(expr, StrSubstr):
            string_z3 = self.encode_string_expr(expr.string, prefix=prefix)
            start_z3 = self.encoder.encode_expr(expr.start, prefix=prefix)
            end_z3 = self.encoder.encode_expr(expr.end, prefix=prefix)
            length = end_z3 - start_z3
            return z3.SubString(string_z3, start_z3, length)
        elif isinstance(expr, Var):
            # In string context, create a string variable
            cache_key = f"{prefix}{expr.name}_str"
            if cache_key not in self.string_var_cache:
                self.string_var_cache[cache_key] = z3.String(cache_key)
            return self.string_var_cache[cache_key]
        else:
            # For other expressions, try regular encoding and hope it's a string
            return self.encoder.encode_expr(expr, prefix=prefix)
