"""
Error state and heap lifecycle AST nodes

Defines error states for incorrectness logic and heap lifecycle tracking:
- General error states
- Null dereference errors
- Use-after-free errors
- Buffer overflow errors
- Heap allocation states
- Heap freed states
"""

from typing import Set
from frame.core._ast_base import Formula, Expr


class Error(Formula):
    """Error state: error() or error("type")

    Represents an error condition in incorrectness logic.
    Used to prove that errors ARE reachable (not just possible).
    """

    def __init__(self, kind: str = None, message: str = None):
        self.kind = kind
        self.message = message

    def __str__(self) -> str:
        if self.kind:
            return f'error("{self.kind}")'
        return "error()"

    def free_vars(self) -> Set[str]:
        return set()

    def is_spatial(self) -> bool:
        return False


class NullDeref(Formula):
    """Null dereference error: null_deref(x)

    Represents a null pointer dereference bug.
    Used in incorrectness logic to prove null deref is reachable.
    """

    def __init__(self, var: Expr):
        self.var = var

    def __str__(self) -> str:
        return f"null_deref({self.var})"

    def free_vars(self) -> Set[str]:
        return self.var.free_vars()

    def is_spatial(self) -> bool:
        return False


class UseAfterFree(Formula):
    """Use-after-free error: use_after_free(x)

    Represents accessing memory after it has been freed.
    """

    def __init__(self, var: Expr):
        self.var = var

    def __str__(self) -> str:
        return f"use_after_free({self.var})"

    def free_vars(self) -> Set[str]:
        return self.var.free_vars()

    def is_spatial(self) -> bool:
        return False


class BufferOverflow(Formula):
    """Buffer overflow error: buffer_overflow(arr, index, size)

    Represents accessing array beyond its bounds.
    """

    def __init__(self, array: Expr, index: Expr, size: Expr):
        self.array = array
        self.index = index
        self.size = size

    def __str__(self) -> str:
        return f"buffer_overflow({self.array}, {self.index}, {self.size})"

    def free_vars(self) -> Set[str]:
        return self.array.free_vars() | self.index.free_vars() | self.size.free_vars()

    def is_spatial(self) -> bool:
        return False


class Allocated(Formula):
    """Allocation state: allocated(ptr)

    Pure formula stating that a pointer is currently allocated.
    Used for tracking heap lifecycle and detecting use-after-free.
    """

    def __init__(self, ptr: Expr):
        self.ptr = ptr

    def __str__(self) -> str:
        return f"allocated({self.ptr})"

    def free_vars(self) -> Set[str]:
        return self.ptr.free_vars()

    def is_spatial(self) -> bool:
        return False


class Freed(Formula):
    """Freed state: freed(ptr)

    Pure formula stating that a pointer has been freed.
    Complementary to Allocated - a pointer cannot be both allocated and freed.
    """

    def __init__(self, ptr: Expr):
        self.ptr = ptr

    def __str__(self) -> str:
        return f"freed({self.ptr})"

    def free_vars(self) -> Set[str]:
        return self.ptr.free_vars()

    def is_spatial(self) -> bool:
        return False
