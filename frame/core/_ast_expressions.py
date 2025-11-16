"""
Expression AST nodes

Defines concrete expression types: variables, constants, and arithmetic expressions.
"""

from typing import Set, Any
from frame.core._ast_base import Expr


class Var(Expr):
    """Variable expression"""

    def __init__(self, name: str):
        self.name = name

    def __str__(self) -> str:
        return self.name

    def free_vars(self) -> Set[str]:
        return {self.name}

    def __eq__(self, other):
        return isinstance(other, Var) and self.name == other.name

    def __hash__(self):
        return hash(self.name)


class Const(Expr):
    """Constant expression (integers, nil)"""

    def __init__(self, value: Any):
        self.value = value

    def __str__(self) -> str:
        if self.value is None:
            return "nil"
        return str(self.value)

    def free_vars(self) -> Set[str]:
        return set()

    def __eq__(self, other):
        return isinstance(other, Const) and self.value == other.value

    def __hash__(self):
        return hash(self.value)


class ArithExpr(Expr):
    """Arithmetic expression (for Linear Integer Arithmetic)"""

    def __init__(self, op: str, left: Expr, right: Expr):
        """
        Args:
            op: Operator ('+', '-', '*', 'div', 'mod')
            left: Left operand expression
            right: Right operand expression
        """
        self.op = op
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def __eq__(self, other):
        return (isinstance(other, ArithExpr) and
                self.op == other.op and
                self.left == other.left and
                self.right == other.right)

    def __hash__(self):
        return hash((self.op, self.left, self.right))
