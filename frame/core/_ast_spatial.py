"""
Spatial formula AST nodes

Defines spatial formulas for separation logic:
- emp (empty heap)
- points-to assertions
- separating conjunction
- magic wand
- array points-to
- array bounds
"""

from typing import Set, List
from frame.core._ast_base import Formula, Expr


class Emp(Formula):
    """Empty heap: emp"""

    def __str__(self) -> str:
        return "emp"

    def free_vars(self) -> Set[str]:
        return set()

    def is_spatial(self) -> bool:
        return True


class PointsTo(Formula):
    """Points-to assertion: x |-> y

    Represents that location x points to value y in the heap.
    For structured data, can have multiple fields: x |-> (y, z)
    """

    def __init__(self, location: Expr, values: List[Expr]):
        self.location = location
        self.values = values if isinstance(values, list) else [values]

    def __str__(self) -> str:
        if len(self.values) == 1:
            return f"{self.location} |-> {self.values[0]}"
        else:
            vals = ", ".join(str(v) for v in self.values)
            return f"{self.location} |-> ({vals})"

    def free_vars(self) -> Set[str]:
        vars_set = self.location.free_vars()
        for v in self.values:
            vars_set.update(v.free_vars())
        return vars_set

    def is_spatial(self) -> bool:
        return True


class SepConj(Formula):
    """Separating conjunction: P * Q

    Asserts that P and Q hold on disjoint portions of the heap.
    """

    def __init__(self, left: Formula, right: Formula):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"({self.left} * {self.right})"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return self.left.is_spatial() or self.right.is_spatial()


class Wand(Formula):
    """Magic wand: P -* Q

    Asserts that if P is added to the current heap, then Q will hold.
    The magic wand is the adjoint of separating conjunction:
    (P -* Q) * P |- Q (modus ponens for separation logic)
    """

    def __init__(self, left: Formula, right: Formula):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"({self.left} -* {self.right})"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars().union(self.right.free_vars())

    def is_spatial(self) -> bool:
        return True  # Wand is a spatial operator


class ArrayPointsTo(Formula):
    """Array element points-to: array[index] |-> value

    Spatial formula representing array element access.
    Similar to PointsTo but with indexed access.

    Example: arr[5] |-> 42
    """

    def __init__(self, array: Expr, index: Expr, value: Expr):
        self.array = array
        self.index = index
        self.value = value

    def __str__(self) -> str:
        return f"{self.array}[{self.index}] |-> {self.value}"

    def free_vars(self) -> Set[str]:
        return self.array.free_vars() | self.index.free_vars() | self.value.free_vars()

    def is_spatial(self) -> bool:
        return True


class ArrayBounds(Formula):
    """Array bounds constraint: bounds(array, size)

    Pure formula specifying the size of an array.
    Used for buffer overflow detection - valid indices are 0 <= i < size.

    Example: bounds(arr, 10) means arr has 10 elements (indices 0-9)
    """

    def __init__(self, array: Expr, size: Expr):
        self.array = array
        self.size = size

    def __str__(self) -> str:
        return f"bounds({self.array}, {self.size})"

    def free_vars(self) -> Set[str]:
        return self.array.free_vars() | self.size.free_vars()

    def is_spatial(self) -> bool:
        return False
