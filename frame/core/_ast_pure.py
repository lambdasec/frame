"""
Pure formula AST nodes

Defines pure (non-spatial) formulas:
- Boolean literals (true, false)
- Comparison operators (=, !=, <, <=, >, >=)
- Boolean operators (and, or, not)
"""

from typing import Set
from frame.core._ast_base import Formula, Expr


class True_(Formula):
    """Boolean true"""

    def __str__(self) -> str:
        return "true"

    def free_vars(self) -> Set[str]:
        return set()

    def is_spatial(self) -> bool:
        return False


class False_(Formula):
    """Boolean false"""

    def __str__(self) -> str:
        return "false"

    def free_vars(self) -> Set[str]:
        return set()

    def is_spatial(self) -> bool:
        return False


class Eq(Formula):
    """Equality: e1 = e2"""

    def __init__(self, left: Expr, right: Expr):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"{self.left} = {self.right}"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return False


class Neq(Formula):
    """Disequality: e1 != e2"""

    def __init__(self, left: Expr, right: Expr):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"{self.left} != {self.right}"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return False


class Lt(Formula):
    """Less than: e1 < e2"""

    def __init__(self, left: Expr, right: Expr):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"{self.left} < {self.right}"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return False


class Le(Formula):
    """Less than or equal: e1 <= e2"""

    def __init__(self, left: Expr, right: Expr):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"{self.left} <= {self.right}"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return False


class Gt(Formula):
    """Greater than: e1 > e2"""

    def __init__(self, left: Expr, right: Expr):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"{self.left} > {self.right}"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return False


class Ge(Formula):
    """Greater than or equal: e1 >= e2"""

    def __init__(self, left: Expr, right: Expr):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"{self.left} >= {self.right}"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return False


class And(Formula):
    """Logical conjunction: P ∧ Q (or P & Q)"""

    def __init__(self, left: Formula, right: Formula):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"({self.left} & {self.right})"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return self.left.is_spatial() or self.right.is_spatial()


class Or(Formula):
    """Logical disjunction: P ∨ Q (or P | Q)"""

    def __init__(self, left: Formula, right: Formula):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"({self.left} | {self.right})"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return self.left.is_spatial() or self.right.is_spatial()


class Not(Formula):
    """Logical negation: ¬P (or !P)"""

    def __init__(self, formula: Formula):
        self.formula = formula

    def __str__(self) -> str:
        return f"!{self.formula}"

    def free_vars(self) -> Set[str]:
        return self.formula.free_vars()

    def is_spatial(self) -> bool:
        return self.formula.is_spatial()
