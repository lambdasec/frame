"""
Security and taint tracking AST nodes

Defines predicates for taint analysis and security vulnerability detection:
- Taint marking
- Sanitization tracking
- Taint sources
- Taint sinks
"""

from typing import Set
from frame.core._ast_base import Formula, Expr


class Taint(Formula):
    """Taint marker: taint(x)

    Marks a value as tainted (originating from an untrusted source).
    Tainted values should not flow into sensitive sinks without sanitization.
    """

    def __init__(self, var: Expr):
        self.var = var

    def __str__(self) -> str:
        return f"taint({self.var})"

    def free_vars(self) -> Set[str]:
        return self.var.free_vars()

    def is_spatial(self) -> bool:
        return False


class Sanitized(Formula):
    """Sanitization marker: sanitized(x)

    Marks a value as sanitized (safe to use in sensitive contexts).
    Opposite of taint - indicates proper validation/escaping has occurred.
    """

    def __init__(self, var: Expr):
        self.var = var

    def __str__(self) -> str:
        return f"sanitized({self.var})"

    def free_vars(self) -> Set[str]:
        return self.var.free_vars()

    def is_spatial(self) -> bool:
        return False


class Source(Formula):
    """Taint source: source(x, "type")

    Marks a variable as a taint source of a specific type.
    Types: "user", "network", "file", "env", etc.
    """

    def __init__(self, var: Expr, source_type: str):
        self.var = var
        self.source_type = source_type

    def __str__(self) -> str:
        return f'source({self.var}, "{self.source_type}")'

    def free_vars(self) -> Set[str]:
        return self.var.free_vars()

    def is_spatial(self) -> bool:
        return False


class Sink(Formula):
    """Taint sink: sink(x, "type")

    Marks a variable as a taint sink of a specific type.
    Types: "sql", "shell", "html", "filesystem", etc.
    """

    def __init__(self, var: Expr, sink_type: str):
        self.var = var
        self.sink_type = sink_type

    def __str__(self) -> str:
        return f'sink({self.var}, "{self.sink_type}")'

    def free_vars(self) -> Set[str]:
        return self.var.free_vars()

    def is_spatial(self) -> bool:
        return False
