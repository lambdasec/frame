"""
Array and Bitvector expression AST nodes

Defines expressions for:
- Array Theory (QF_AX): select, store, const
- Bitvector Theory (QF_BV): bitvector operations, overflow detection
"""

from typing import Set, Any
from frame.core._ast_base import Expr, Formula


# ============================================================================
# Array Theory (QF_AX)
# ============================================================================

class ArraySelect(Expr):
    """Array select operation: (select array index)

    Returns the value stored at index in the array.
    In SMT-LIB: (select arr i)
    In programming: arr[i]

    Example:
        ArraySelect(Var("users"), Const(0))  # users[0]
    """

    def __init__(self, array: Expr, index: Expr):
        self.array = array
        self.index = index

    def __str__(self) -> str:
        return f"(select {self.array} {self.index})"

    def free_vars(self) -> Set[str]:
        return self.array.free_vars() | self.index.free_vars()

    def __eq__(self, other):
        return (isinstance(other, ArraySelect) and
                self.array == other.array and
                self.index == other.index)

    def __hash__(self):
        return hash(("select", self.array, self.index))


class ArrayStore(Expr):
    """Array store operation: (store array index value)

    Returns a NEW array that is identical to array except at index,
    which now maps to value. Original array is unchanged (functional).

    In SMT-LIB: (store arr i v)
    In programming: arr[i] = v (but returns new array)

    Example:
        ArrayStore(Var("users"), Const(0), StrLiteral("admin"))
        # users with users[0] = "admin"
    """

    def __init__(self, array: Expr, index: Expr, value: Expr):
        self.array = array
        self.index = index
        self.value = value

    def __str__(self) -> str:
        return f"(store {self.array} {self.index} {self.value})"

    def free_vars(self) -> Set[str]:
        return self.array.free_vars() | self.index.free_vars() | self.value.free_vars()

    def __eq__(self, other):
        return (isinstance(other, ArrayStore) and
                self.array == other.array and
                self.index == other.index and
                self.value == other.value)

    def __hash__(self):
        return hash(("store", self.array, self.index, self.value))


class ArrayConst(Expr):
    """Constant array: (const default_value)

    An array where every index maps to the same default_value.

    In SMT-LIB: ((as const (Array Int Int)) 0) means all elements = 0

    Example:
        ArrayConst(Const(0))  # Array where all elements are 0
    """

    def __init__(self, default_value: Expr):
        self.default_value = default_value

    def __str__(self) -> str:
        return f"(const {self.default_value})"

    def free_vars(self) -> Set[str]:
        return self.default_value.free_vars()

    def __eq__(self, other):
        return (isinstance(other, ArrayConst) and
                self.default_value == other.default_value)

    def __hash__(self):
        return hash(("const", self.default_value))


# ============================================================================
# Bitvector Theory (QF_BV)
# ============================================================================

class BitVecVal(Expr):
    """Bitvector constant: #bXXXX or #xXXXX

    A constant bitvector value with specified width.

    Args:
        value: Integer value
        width: Number of bits (8, 16, 32, 64, etc.)

    Example:
        BitVecVal(255, 8)    # 8-bit value 255 (0xFF)
        BitVecVal(42, 32)    # 32-bit value 42
    """

    def __init__(self, value: int, width: int):
        self.value = value
        self.width = width

    def __str__(self) -> str:
        # Format as hex for readability
        return f"#x{self.value:0{self.width//4}x}"

    def free_vars(self) -> Set[str]:
        return set()

    def __eq__(self, other):
        return (isinstance(other, BitVecVal) and
                self.value == other.value and
                self.width == other.width)

    def __hash__(self):
        return hash(("bvval", self.value, self.width))


class BitVecExpr(Expr):
    """Bitvector operation expression

    Supports bitvector operations:
    - Arithmetic: bvadd, bvsub, bvmul, bvudiv, bvurem, bvsdiv, bvsrem
    - Bitwise: bvand, bvor, bvxor, bvnot, bvshl, bvlshr, bvashr
    - Comparison: bvult, bvule, bvugt, bvuge, bvslt, bvsle, bvsgt, bvsge

    Args:
        op: Operation name (e.g., "bvadd", "bvand")
        operands: List of operand expressions
        width: Bit width for result (inherited from operands usually)

    Example:
        BitVecExpr("bvadd", [BitVecVal(10, 8), BitVecVal(20, 8)], 8)
        BitVecExpr("bvand", [Var("x"), Const(0xFF)], 8)
    """

    def __init__(self, op: str, operands: list, width: int = None):
        self.op = op
        self.operands = operands if isinstance(operands, list) else [operands]
        self.width = width

    def __str__(self) -> str:
        ops = " ".join(str(o) for o in self.operands)
        if self.width:
            return f"({self.op}[{self.width}] {ops})"
        return f"({self.op} {ops})"

    def free_vars(self) -> Set[str]:
        result = set()
        for op in self.operands:
            result.update(op.free_vars())
        return result

    def __eq__(self, other):
        return (isinstance(other, BitVecExpr) and
                self.op == other.op and
                self.operands == other.operands and
                self.width == other.width)

    def __hash__(self):
        return hash(("bvexpr", self.op, tuple(self.operands), self.width))


# ============================================================================
# Security Predicates for Arrays and Bitvectors
# ============================================================================

class TaintedArray(Formula):
    """Tainted array: Some elements contain tainted data

    Tracks which array indices contain tainted data from user input.
    Critical for analyzing vulnerabilities in code using collections.

    Args:
        array: Array expression
        tainted_indices: Optional list of known tainted indices
                        If None, means "some unknown indices are tainted"

    Example:
        TaintedArray(Var("users"), [Const(0), Const(2)])
        # users[0] and users[2] contain tainted data
    """

    def __init__(self, array: Expr, tainted_indices: list = None):
        self.array = array
        self.tainted_indices = tainted_indices  # None = unknown which indices

    def __str__(self) -> str:
        if self.tainted_indices is None:
            return f"TaintedArray({self.array})"
        indices = ", ".join(str(i) for i in self.tainted_indices)
        return f"TaintedArray({self.array}, [{indices}])"

    def free_vars(self) -> Set[str]:
        result = self.array.free_vars()
        if self.tainted_indices:
            for idx in self.tainted_indices:
                result.update(idx.free_vars())
        return result

    def is_spatial(self) -> bool:
        return False


class BufferOverflowCheck(Formula):
    """Buffer overflow check: Verify array access is within bounds

    Checks that an array access is safe (index within bounds).

    Args:
        array: Array being accessed
        index: Index being used
        size: Size of the array (upper bound)

    Semantics:
        Safe if: 0 <= index < size
        Violation: index < 0 or index >= size

    Example:
        BufferOverflowCheck(Var("buffer"), Var("user_len"), Const(256))
        # Checks: 0 <= user_len < 256
    """

    def __init__(self, array: Expr, index: Expr, size: Expr):
        self.array = array
        self.index = index
        self.size = size

    def __str__(self) -> str:
        return f"BufferOverflowCheck({self.array}, {self.index}, {self.size})"

    def free_vars(self) -> Set[str]:
        return self.array.free_vars() | self.index.free_vars() | self.size.free_vars()

    def is_spatial(self) -> bool:
        return False


class IntegerOverflow(Formula):
    """Integer overflow detection for bitvectors

    Checks if a bitvector operation would overflow/underflow.

    Args:
        op: Operation ("add", "sub", "mul", etc.)
        operands: Operand expressions
        width: Bit width
        signed: True for signed overflow, False for unsigned

    Example:
        IntegerOverflow("add", [Var("x"), Var("y")], 32, signed=False)
        # Checks if x + y overflows in unsigned 32-bit arithmetic
    """

    def __init__(self, op: str, operands: list, width: int, signed: bool = False):
        self.op = op
        self.operands = operands
        self.width = width
        self.signed = signed

    def __str__(self) -> str:
        sign = "signed" if self.signed else "unsigned"
        ops = ", ".join(str(o) for o in self.operands)
        return f"IntegerOverflow({self.op}, [{ops}], {self.width}, {sign})"

    def free_vars(self) -> Set[str]:
        result = set()
        for op in self.operands:
            result.update(op.free_vars())
        return result

    def is_spatial(self) -> bool:
        return False
