"""
Skip list predicates
"""

from typing import List, Dict, Optional
from frame.core.ast import *
from frame.predicates.base import InductivePredicate

class SkipList1(InductivePredicate):
    """
    Skip list level 1: skl1(x, y)

    Represents the base level of a skip list.

    Definition:
        skl1(x, y) ::= (x = y ∧ emp)
                     ∨ (∃z. x |-> z * skl1(z, y))
    """

    def __init__(self):
        super().__init__("skl1", 2)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 2:
            raise ValueError(f"skl1 expects 2 arguments, got {len(args)}")

        x, y = args

        # Base case: x = y ∧ emp
        base_case = And(Eq(x, y), Emp())

        # Recursive case: ∃z. x |-> z * skl1(z, y)
        z = Var(f"z_skl1_{id(args)}")
        recursive_case = Exists(
            z.name,
            SepConj(
                PointsTo(x, [z]),
                PredicateCall("skl1", [z, y])
            )
        )

        return Or(base_case, recursive_case)


class SkipList2(InductivePredicate):
    """
    Skip list level 2: skl2(x, y)

    Represents level 2 of a skip list (every other node).

    Definition:
        skl2(x, y) ::= (x = y ∧ emp)
                     ∨ (∃z1, z2. x |-> (z1, z2) * skl2(z2, y))
    """

    def __init__(self):
        super().__init__("skl2", 2)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 2:
            raise ValueError(f"skl2 expects 2 arguments, got {len(args)}")

        x, y = args

        # Base case: x = y ∧ emp
        base_case = And(Eq(x, y), Emp())

        # Recursive case: ∃z1, z2. x |-> (z1, z2) * skl2(z2, y)
        z1 = Var(f"z1_skl2_{id(args)}")
        z2 = Var(f"z2_skl2_{id(args)}")
        recursive_case = Exists(
            z1.name,
            Exists(
                z2.name,
                SepConj(
                    PointsTo(x, [z1, z2]),
                    PredicateCall("skl2", [z2, y])
                )
            )
        )

        return Or(base_case, recursive_case)


class SkipList3(InductivePredicate):
    """
    Skip list level 3: skl3(x, y)

    Represents level 3 of a skip list (every fourth node).

    Definition:
        skl3(x, y) ::= (x = y ∧ emp)
                     ∨ (∃z1, z2, z3. x |-> (z1, z2, z3) * skl3(z3, y))
    """

    def __init__(self):
        super().__init__("skl3", 2)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 2:
            raise ValueError(f"skl3 expects 2 arguments, got {len(args)}")

        x, y = args

        # Base case: x = y ∧ emp
        base_case = And(Eq(x, y), Emp())

        # Recursive case: ∃z1, z2, z3. x |-> (z1, z2, z3) * skl3(z3, y)
        z1 = Var(f"z1_skl3_{id(args)}")
        z2 = Var(f"z2_skl3_{id(args)}")
        z3 = Var(f"z3_skl3_{id(args)}")
        recursive_case = Exists(
            z1.name,
            Exists(
                z2.name,
                Exists(
                    z3.name,
                    SepConj(
                        PointsTo(x, [z1, z2, z3]),
                        PredicateCall("skl3", [z3, y])
                    )
                )
            )
        )

        return Or(base_case, recursive_case)


