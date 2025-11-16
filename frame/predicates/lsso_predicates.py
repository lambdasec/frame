"""
List segment with sentinel (lsso) predicate
"""

from typing import List
from frame.core.ast import *
from frame.predicates.base import InductivePredicate


class ListSegmentSentinel(InductivePredicate):
    """
    List segment with sentinel: lsso(in, out)

    A list where each node has two fields that point to the SAME next location.
    This is used in some data structure implementations where redundancy is used
    for verification or sentinel purposes.

    Definition (from SL-COMP):
        lsso(in, out) ::= (in = out ∧ emp)
                        ∨ (∃u. in |-> (u, u) * lsso(u, out))

    Points-to has structure: in |-> (next1, next2) where next1 = next2 = u
    """

    def __init__(self):
        super().__init__("lsso", 2)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 2:
            raise ValueError(f"lsso expects 2 arguments, got {len(args)}")

        in_ptr, out_ptr = args

        # Base case: in = out ∧ emp
        base_case = And(Eq(in_ptr, out_ptr), Emp())

        # Recursive case: ∃u. in |-> (u, u) * lsso(u, out)
        # Note: both fields point to the same location u
        u = Var(f"u_{id(args)}")
        recursive_case = Exists(
            u.name,
            SepConj(
                PointsTo(in_ptr, [u, u]),  # Both fields point to u
                PredicateCall("lsso", [u, out_ptr])
            )
        )

        return Or(base_case, recursive_case)
