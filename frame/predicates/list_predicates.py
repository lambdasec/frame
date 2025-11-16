"""
List-related inductive predicates

Includes ListSegment, LinkedList, ReverseList, and NestedList.
"""

from typing import List, Dict, Optional
from frame.core.ast import *
from frame.predicates.base import InductivePredicate

class ListSegment(InductivePredicate):
    """
    List segment predicate: ls(x, y)

    Represents a singly-linked list from x to y (not including y).

    Definition:
        ls(x, y) ::= (x = y ∧ emp)
                   ∨ (∃z. x |-> z * ls(z, y))
    """

    def __init__(self):
        super().__init__("ls", 2)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 2:
            raise ValueError(f"ls expects 2 arguments, got {len(args)}")

        x, y = args

        # Base case: x = y ∧ emp
        base_case = And(Eq(x, y), Emp())

        # Recursive case: ∃z. (x != y) ∧ (x |-> z * ls(z, y))
        # This matches SL-COMP semantics where recursive case requires distinct endpoints
        z = Var(f"z_{id(args)}")  # Fresh variable
        recursive_case = Exists(
            z.name,
            And(
                Neq(x, y),  # Distinct constraint: x != y in recursive case
                SepConj(
                    PointsTo(x, [z]),
                    PredicateCall("ls", [z, y])
                )
            )
        )

        return Or(base_case, recursive_case)

    def unfold_bounded(self, args: List[Expr], depth: int) -> Formula:
        if depth <= 0:
            return PredicateCall(self.name, args)

        if len(args) != 2:
            raise ValueError(f"ls expects 2 arguments, got {len(args)}")

        x, y = args

        # Base case: x = y ∧ emp
        base_case = And(Eq(x, y), Emp())

        # Recursive case with bounded depth: ∃z. (x != y) ∧ (x |-> z * ls(z, y))
        z = Var(f"z_{id(args)}_{depth}")  # Fresh variable
        recursive_call = ListSegment().unfold_bounded([z, y], depth - 1)
        recursive_case = Exists(
            z.name,
            And(
                Neq(x, y),  # Distinct constraint: x != y in recursive case
                SepConj(
                    PointsTo(x, [z]),
                    recursive_call
                )
            )
        )

        return Or(base_case, recursive_case)


class ListSegmentWithLength(InductivePredicate):
    """
    List segment with length parameter: ls(x, y, n)

    Represents a singly-linked list from x to y with exactly n cells.

    Definition:
        ls(x, y, 0) ::= (x = y ∧ emp)
        ls(x, y, n) ::= ∃z. x |-> z * ls(z, y, n-1)  [n > 0]
    """

    def __init__(self):
        super().__init__("ls", 3)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 3:
            # Fallback: if called with 2 args, treat as regular segment without length
            if len(args) == 2:
                # Delegate to regular list segment
                x, y = args
                base_case = And(Eq(x, y), Emp())
                z = Var(f"z_{id(args)}")
                recursive_case = Exists(
                    z.name,
                    And(
                        Neq(x, y),
                        SepConj(
                            PointsTo(x, [z]),
                            PredicateCall("ls", [z, y])
                        )
                    )
                )
                return Or(base_case, recursive_case)
            else:
                raise ValueError(f"ls expects 2 or 3 arguments, got {len(args)}")

        x, y, n = args

        # Check if n is a constant
        if isinstance(n, Const):
            length = n.value
            if length is not None and isinstance(length, int):
                if length == 0:
                    # Base case: ls(x, y, 0) = (x = y ∧ emp)
                    return And(Eq(x, y), Emp())
                elif length == 1:
                    # Special case: ls(x, y, 1) = x |-> y
                    return PointsTo(x, [y])
                else:
                    # Recursive case: ls(x, y, n) = x != y & ∃z. x |-> z * ls(z, y, n-1)
                    # The x != y constraint is essential for constraint propagation
                    z = Var(f"z_{id(args)}")
                    n_minus_1 = Const(length - 1)
                    return And(
                        Neq(x, y),  # Non-empty segment implies start != end
                        Exists(
                            z.name,
                            SepConj(
                                PointsTo(x, [z]),
                                PredicateCall("ls", [z, y, n_minus_1])
                            )
                        )
                    )

        # If n is symbolic (variable), use general unfolding
        # Base case: n = 0 ∧ x = y ∧ emp
        base_case = And(And(Eq(n, Const(0)), Eq(x, y)), Emp())

        # Recursive case: n > 0 ∧ ∃z. x |-> z * ls(z, y, n-1)
        z = Var(f"z_{id(args)}")
        # Create n-1 symbolically (would need arithmetic expressions, simplified for now)
        recursive_case = Exists(
            z.name,
            And(
                Neq(n, Const(0)),  # n > 0
                SepConj(
                    PointsTo(x, [z]),
                    PredicateCall("ls", [z, y])  # Simplified: drop length in recursive call
                )
            )
        )

        return Or(base_case, recursive_case)

    def unfold_bounded(self, args: List[Expr], depth: int) -> Formula:
        """
        Unfold list segment to a bounded depth with recursive unfolding of nested predicates.

        This is critical for verification - we need to fully unfold nested ls(...) calls
        so Z3 doesn't encode them as uninterpreted boolean variables.

        Args:
            args: Arguments to ls (either [x, y] or [x, y, n])
            depth: Maximum unfolding depth

        Returns:
            Formula with nested predicates recursively unfolded
        """
        if depth <= 0:
            return PredicateCall(self.name, args)

        # First unfold this predicate once
        unfolded = self.unfold(args)

        # Then recursively unfold any nested PredicateCalls in the result
        # This handles nested ls(...) calls that appear in the recursive case
        return self._unfold_nested(unfolded, depth - 1)

    def _unfold_nested(self, formula: Formula, remaining_depth: int) -> Formula:
        """
        Recursively unfold nested PredicateCalls within a formula.

        For example, after unfolding ls(x,y) to \"(x=y & emp) | exists u. (x|->u * ls(u,y))\",
        we need to continue unfolding the nested ls(u,y) call.
        """
        if remaining_depth <= 0:
            return formula

        if isinstance(formula, PredicateCall):
            # If it's a recursive call to ls, unfold it further
            if formula.name == self.name:
                return self.unfold_bounded(formula.args, remaining_depth)
            # Otherwise leave it as-is (other predicates handled separately)
            return formula

        elif isinstance(formula, SepConj):
            return SepConj(
                self._unfold_nested(formula.left, remaining_depth),
                self._unfold_nested(formula.right, remaining_depth)
            )
        elif isinstance(formula, And):
            return And(
                self._unfold_nested(formula.left, remaining_depth),
                self._unfold_nested(formula.right, remaining_depth)
            )
        elif isinstance(formula, Or):
            return Or(
                self._unfold_nested(formula.left, remaining_depth),
                self._unfold_nested(formula.right, remaining_depth)
            )
        elif isinstance(formula, Not):
            return Not(self._unfold_nested(formula.formula, remaining_depth))
        elif isinstance(formula, Exists):
            return Exists(
                formula.var,
                self._unfold_nested(formula.formula, remaining_depth)
            )
        elif isinstance(formula, Forall):
            return Forall(
                formula.var,
                self._unfold_nested(formula.formula, remaining_depth)
            )
        else:
            # Base formulas: Emp, PointsTo, Eq, Neq, etc.
            return formula


class LinkedList(InductivePredicate):
    """
    Linked list predicate: list(x)

    Represents a singly-linked list starting at x and ending at nil.

    Definition:
        list(x) ::= (x = nil ∧ emp)
                  ∨ (∃y. x |-> y * list(y))
    """

    def __init__(self):
        super().__init__("list", 1)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 1:
            raise ValueError(f"list expects 1 argument, got {len(args)}")

        x = args[0]
        nil = Const(None)

        # Base case: x = nil ∧ emp
        base_case = And(Eq(x, nil), Emp())

        # Recursive case: ∃y. x |-> y * list(y)
        y = Var(f"y_{id(args)}")
        recursive_case = Exists(
            y.name,
            SepConj(
                PointsTo(x, [y]),
                PredicateCall("list", [y])
            )
        )

        return Or(base_case, recursive_case)

    def unfold_bounded(self, args: List[Expr], depth: int) -> Formula:
        if depth <= 0:
            return PredicateCall(self.name, args)

        if len(args) != 1:
            raise ValueError(f"list expects 1 argument, got {len(args)}")

        x = args[0]
        nil = Const(None)

        # Base case: x = nil ∧ emp
        base_case = And(Eq(x, nil), Emp())

        # Recursive case with bounded depth
        y = Var(f"y_{id(args)}_{depth}")
        recursive_call = LinkedList().unfold_bounded([y], depth - 1)
        recursive_case = Exists(
            y.name,
            SepConj(
                PointsTo(x, [y]),
                recursive_call
            )
        )

        return Or(base_case, recursive_case)


class ReverseList(InductivePredicate):
    """
    Reverse list predicate: RList(x, y)

    Represents a reverse-linked list segment from x to y.
    Similar to ls but conceptually represents a reverse pointer structure.

    Definition:
        RList(x, y) ::= (x = y ∧ emp)
                      ∨ (∃z. x |-> z * RList(z, y))
    """

    def __init__(self):
        super().__init__("RList", 2)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 2:
            raise ValueError(f"RList expects 2 arguments, got {len(args)}")

        x, y = args

        # Base case: x = y ∧ emp
        base_case = And(Eq(x, y), Emp())

        # Recursive case: ∃z. x |-> z * RList(z, y)
        z = Var(f"z_rlist_{id(args)}")
        recursive_case = Exists(
            z.name,
            SepConj(
                PointsTo(x, [z]),
                PredicateCall("RList", [z, y])
            )
        )

        return Or(base_case, recursive_case)


class NestedList(InductivePredicate):
    """
    Nested list predicate: nll(x, y, z)

    Represents a list with nested structure.
    Each node can have a nested list.

    Definition:
        nll(x, y, z) ::= (x = y ∧ emp)
                       ∨ (∃n. x |-> (n, z) * nll(n, y, z))
    """

    def __init__(self):
        super().__init__("nll", 3)

    def unfold(self, args: List[Expr]) -> Formula:
        if len(args) != 3:
            raise ValueError(f"nll expects 3 arguments, got {len(args)}")

        x, y, z = args

        # Base case: x = y ∧ emp
        base_case = And(Eq(x, y), Emp())

        # Recursive case: ∃n. x |-> (n, z) * nll(n, y, z)
        n = Var(f"n_nll_{id(args)}")
        recursive_case = Exists(
            n.name,
            SepConj(
                PointsTo(x, [n, z]),
                PredicateCall("nll", [n, y, z])
            )
        )

        return Or(base_case, recursive_case)


