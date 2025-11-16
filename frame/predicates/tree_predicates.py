"""
Tree-related inductive predicates
"""

from typing import List, Dict, Optional
from frame.core.ast import *
from frame.predicates.base import InductivePredicate

class Tree(InductivePredicate):
    """
    Binary tree predicate: tree(x)

    Represents a binary tree with root at x.

    Definition:
        tree(x) ::= (x = nil ∧ emp)
                  ∨ (∃l, r. x |-> (l, r) * tree(l) * tree(r))
    """

    def __init__(self):
        super().__init__("tree", 1)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 1:
            raise ValueError(f"tree expects 1 argument, got {len(args)}")

        x = args[0]
        nil = Const(None)

        # Base case: x = nil ∧ emp
        base_case = And(Eq(x, nil), Emp())

        # Recursive case: ∃l, r. x |-> (l, r) * tree(l) * tree(r)
        l = Var(f"l_{id(args)}")
        r = Var(f"r_{id(args)}")

        points_to = PointsTo(x, [l, r])
        left_tree = PredicateCall("tree", [l])
        right_tree = PredicateCall("tree", [r])

        recursive_case = Exists(
            l.name,
            Exists(
                r.name,
                SepConj(
                    SepConj(points_to, left_tree),
                    right_tree
                )
            )
        )

        return Or(base_case, recursive_case)

    def unfold_bounded(self, args: List[Expr], depth: int) -> Formula:
        if depth <= 0:
            return PredicateCall(self.name, args)

        if len(args) != 1:
            raise ValueError(f"tree expects 1 argument, got {len(args)}")

        x = args[0]
        nil = Const(None)

        # Base case: x = nil ∧ emp
        base_case = And(Eq(x, nil), Emp())

        # Recursive case with bounded depth
        l = Var(f"l_{id(args)}_{depth}")
        r = Var(f"r_{id(args)}_{depth}")

        points_to = PointsTo(x, [l, r])
        left_tree = Tree().unfold_bounded([l], depth - 1)
        right_tree = Tree().unfold_bounded([r], depth - 1)

        recursive_case = Exists(
            l.name,
            Exists(
                r.name,
                SepConj(
                    SepConj(points_to, left_tree),
                    right_tree
                )
            )
        )

        return Or(base_case, recursive_case)


