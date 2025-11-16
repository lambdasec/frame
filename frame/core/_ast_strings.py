"""
String operation AST nodes

Defines string expressions and formulas:
- String literals
- String concatenation
- String length
- Substring extraction
- String containment testing
- Regular expression matching
"""

from typing import Set
from frame.core._ast_base import Expr, Formula


class StrLiteral(Expr):
    """String literal: "hello"

    Represents a constant string value.
    """

    def __init__(self, value: str):
        self.value = value

    def __str__(self) -> str:
        return f'"{self.value}"'

    def free_vars(self) -> Set[str]:
        return set()

    def __eq__(self, other):
        return isinstance(other, StrLiteral) and self.value == other.value

    def __hash__(self):
        return hash(('str', self.value))


class StrConcat(Expr):
    """String concatenation: s1 ++ s2

    Concatenates two string expressions.
    """

    def __init__(self, left: Expr, right: Expr):
        self.left = left
        self.right = right

    def __str__(self) -> str:
        return f"({self.left} ++ {self.right})"

    def free_vars(self) -> Set[str]:
        return self.left.free_vars() | self.right.free_vars()

    def __eq__(self, other):
        return (isinstance(other, StrConcat) and
                self.left == other.left and
                self.right == other.right)

    def __hash__(self):
        return hash(('concat', self.left, self.right))


class StrLen(Expr):
    """String length: len(s)

    Returns the length of a string as an integer.
    """

    def __init__(self, string: Expr):
        self.string = string

    def __str__(self) -> str:
        return f"len({self.string})"

    def free_vars(self) -> Set[str]:
        return self.string.free_vars()

    def __eq__(self, other):
        return isinstance(other, StrLen) and self.string == other.string

    def __hash__(self):
        return hash(('strlen', self.string))


class StrSubstr(Expr):
    """Substring: substr(s, start, end)

    Extracts substring from start to end (exclusive).
    """

    def __init__(self, string: Expr, start: Expr, end: Expr):
        self.string = string
        self.start = start
        self.end = end

    def __str__(self) -> str:
        return f"substr({self.string}, {self.start}, {self.end})"

    def free_vars(self) -> Set[str]:
        return self.string.free_vars() | self.start.free_vars() | self.end.free_vars()

    def __eq__(self, other):
        return (isinstance(other, StrSubstr) and
                self.string == other.string and
                self.start == other.start and
                self.end == other.end)

    def __hash__(self):
        return hash(('substr', self.string, self.start, self.end))


class StrContains(Formula):
    """String containment: s1 contains s2

    Tests whether haystack contains needle as a substring.
    """

    def __init__(self, haystack: Expr, needle: Expr):
        self.haystack = haystack
        self.needle = needle

    def __str__(self) -> str:
        return f"({self.haystack} contains {self.needle})"

    def free_vars(self) -> Set[str]:
        return self.haystack.free_vars() | self.needle.free_vars()

    def is_spatial(self) -> bool:
        return False


class StrMatches(Formula):
    """Regular expression matching: s matches regex

    Tests whether string matches the given regular expression pattern.
    """

    def __init__(self, string: Expr, regex: str):
        self.string = string
        self.regex = regex

    def __str__(self) -> str:
        return f"({self.string} matches /{self.regex}/)"

    def free_vars(self) -> Set[str]:
        return self.string.free_vars()

    def is_spatial(self) -> bool:
        return False
