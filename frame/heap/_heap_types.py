"""
Heap graph type definitions

Data structures for heap graph representation and folding proposals.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from frame.core.ast import Formula, Expr, PointsTo, PredicateCall


@dataclass
class HeapNode:
    """A node in the heap graph representing a location"""
    name: str  # Variable name
    fields: Dict[str, Expr] = field(default_factory=dict)  # Field name -> value/target
    outgoing: List['HeapEdge'] = field(default_factory=list)
    incoming: List['HeapEdge'] = field(default_factory=list)


@dataclass
class HeapEdge:
    """An edge in the heap graph representing a pointer"""
    source: str  # Source node name
    target: str  # Target node name (or "nil" for null)
    label: str   # Field name (e.g., "next", "prev", "data")


@dataclass
class Chain:
    """A detected chain pattern in the heap"""
    nodes: List[str]  # Node names in order
    field: str        # Field name used for linking (e.g., "next")
    length: int       # Number of nodes in chain

    @property
    def head(self) -> str:
        return self.nodes[0] if self.nodes else None

    @property
    def tail(self) -> str:
        return self.nodes[-1] if self.nodes else None


@dataclass
class DLLPattern:
    """A detected doubly-linked list pattern"""
    nodes: List[str]
    next_field: str = "next"
    prev_field: str = "prev"
    length: int = 0

    @property
    def head(self) -> str:
        return self.nodes[0] if self.nodes else None

    @property
    def tail(self) -> str:
        return self.nodes[-1] if self.nodes else None


@dataclass
class FoldProposal:
    """
    A proposed fold of pto cells and/or predicate calls into a predicate.

    Represents: (pto_cells * predicate_calls) ⊢ predicate_call with side_conditions

    For hierarchical predicates like nll (nested list), both pto_cells AND
    predicate_calls are needed:
      Example: x |-> (y, z) * ls(z, nil) ⊢ nll(x, nil, nil)
    """
    predicate_name: str                    # e.g., "ls", "dll", "nll"
    args: List[Expr]                       # Arguments to the predicate
    pto_cells: List[PointsTo]             # The pto cells to be folded
    predicate_calls: List[PredicateCall] = field(default_factory=list)  # Nested predicates to fold
    side_conditions: List[Formula] = field(default_factory=list)  # Arithmetic or pure constraints required
    confidence: float = 1.0                # Confidence score (0-1) for heuristic ordering

    def to_predicate_call(self) -> PredicateCall:
        """Convert proposal to a PredicateCall"""
        return PredicateCall(self.predicate_name, self.args)

    def __str__(self) -> str:
        parts = []
        if self.pto_cells:
            parts.append(" * ".join(str(pto) for pto in self.pto_cells))
        if self.predicate_calls:
            parts.append(" * ".join(str(pred) for pred in self.predicate_calls))

        lhs = " * ".join(parts) if parts else "emp"
        pred_str = f"{self.predicate_name}({', '.join(str(arg) for arg in self.args)})"

        if self.side_conditions:
            conds = " & ".join(str(c) for c in self.side_conditions)
            return f"{lhs} ⊢ {pred_str} [if {conds}]"
        return f"{lhs} ⊢ {pred_str}"
