"""
Base classes for AST nodes

Defines the abstract base classes for expressions and formulas
that all other AST nodes inherit from.
"""

from abc import ABC, abstractmethod
from typing import Set


class Expr(ABC):
    """Base class for expressions (variables, constants)"""

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def free_vars(self) -> Set[str]:
        """Return set of free variables"""
        pass

    def is_spatial(self) -> bool:
        """Expressions are never spatial (only formulas can be spatial)"""
        return False


class Formula(ABC):
    """Base class for separation logic formulas"""

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def free_vars(self) -> Set[str]:
        """Return set of free variables in the formula"""
        pass

    @abstractmethod
    def is_spatial(self) -> bool:
        """Return True if this is a spatial formula (emp, pto, *, -*)"""
        pass
