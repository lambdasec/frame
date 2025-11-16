"""
Sorted list predicates
"""

from typing import List, Dict, Optional
from frame.core.ast import *
from frame.predicates.base import InductivePredicate

class SortedListSegment(InductivePredicate):
    """
    Sorted list segment: sls(x, v_min, y, v_max)

    Represents a sorted list segment from x to y with values >= v_min and <= v_max.

    Definition:
        sls(x, v_min, y, v_max) ::= (x = y ∧ emp)
                                  ∨ (∃z, v. x |-> (z, v) * sls(z, v, y, v_max) ∧ v_min <= v ∧ v <= v_max)
    """

    def __init__(self):
        super().__init__("sls", 4)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 4:
            raise ValueError(f"sls expects 4 arguments, got {len(args)}")

        x, v_min, y, v_max = args

        # Base case: x = y ∧ emp
        base_case = And(Eq(x, y), Emp())

        # Recursive case: ∃v,z. x |-> (v, z) * sls(z, v, y, v_max) & v_min <= v <= v_max
        # Node structure: x |-> (value, next)
        # Value v must be in range [v_min, v_max]
        # Next segment starts with minimum value v (ensures sorted order)
        v = Var(f"v_sls_{id(args)}")
        z = Var(f"z_sls_{id(args)}")

        from frame.core.ast import Le  # Import comparison operator

        recursive_case = Exists(
            v.name,
            Exists(
                z.name,
                And(
                    And(
                        Le(v_min, v),  # v_min <= v
                        Le(v, v_max)   # v <= v_max
                    ),
                    SepConj(
                        PointsTo(x, [v, z]),  # x |-> (value, next)
                        PredicateCall("sls", [z, v, y, v_max])  # Next segment has min=v
                    )
                )
            )
        )

        return Or(base_case, recursive_case)


