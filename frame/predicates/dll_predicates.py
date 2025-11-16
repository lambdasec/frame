"""
Doubly-linked list predicates
"""

from typing import List, Dict, Optional
from frame.core.ast import *
from frame.predicates.base import InductivePredicate

class DoublyLinkedList(InductivePredicate):
    """
    Doubly-linked list predicate: dll(fr, bk, pr, nx)

    Represents a doubly-linked list segment from fr to bk, where:
    - fr is the front (first node of segment)
    - bk is the back (last node of segment)
    - pr is the previous node before fr (predecessor)
    - nx is the next node after bk (successor)

    This matches SL-COMP semantics.

    Definition (from SL-COMP):
        dll(fr, bk, pr, nx) ::= (fr = nx ∧ bk = pr ∧ emp)
                              ∨ (∃u. distinct(fr, nx) ∧ distinct(bk, pr) ∧
                                     fr |-> (u, pr) * dll(u, bk, fr, nx))

    Note: Points-to fields are (next, prev) in that order.
    """

    def __init__(self):
        super().__init__("dll", 4)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 4:
            raise ValueError(f"dll expects 4 arguments, got {len(args)}")

        fr, bk, pr, nx = args

        # Base case: fr = nx ∧ bk = pr ∧ emp
        # This means the segment is empty (front meets next, back meets prev)
        base_case = And(And(Eq(fr, nx), Eq(bk, pr)), Emp())

        # Recursive case: ∃u. distinct(fr, nx) ∧ distinct(bk, pr) ∧
        #                     fr |-> (u, pr) * dll(u, bk, fr, nx)
        # The current node (fr) points to next node (u) and previous node (pr)
        # Then recurse with u as new front, same back (bk), fr as new prev, same nx
        u = Var(f"u_{id(args)}")
        recursive_case = Exists(
            u.name,
            And(
                And(Neq(fr, nx), Neq(bk, pr)),  # distinct constraints
                SepConj(
                    PointsTo(fr, [u, pr]),  # fr points to (next=u, prev=pr)
                    PredicateCall("dll", [u, bk, fr, nx])  # dll(u, bk, fr, nx)
                )
            )
        )

        return Or(base_case, recursive_case)


