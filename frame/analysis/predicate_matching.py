"""
Predicate Pattern Matching

Provides pattern matching for common predicate structures to prove
entailments without unfolding.
"""

from typing import Optional
from frame.core.ast import (
    Formula, Expr, Var, Emp, PointsTo, SepConj, PredicateCall, True_
)
from frame.analysis.formula import FormulaAnalyzer


class PredicateMatcher:
    """Matches predicate patterns for bi-abduction style reasoning"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.analyzer = FormulaAnalyzer()

    def try_predicate_matching(self, antecedent: Formula, consequent: Formula) -> Optional[bool]:
        """
        Try to match antecedent against consequent using predicate shape matching.
        This implements bi-abduction-style matching for common patterns.

        Handles patterns like:
        - x |-> y * list(y) |- list(x)  (cons operation)
        - x |-> y * ls(y, z) |- ls(x, z)  (segment cons)

        Returns:
            True if entailment is valid via predicate matching
            False if entailment is invalid via matching
            None if matching is inconclusive
        """
        # Only apply if consequent is a single predicate call
        if not isinstance(consequent, PredicateCall):
            # Try to extract single predicate from And/SepConj
            cons_parts = self.analyzer._extract_sepconj_parts(consequent)
            predicate_calls = [p for p in cons_parts if isinstance(p, PredicateCall)]
            if len(predicate_calls) != 1:
                return None  # Multiple or no predicates, skip this check
            consequent_pred = predicate_calls[0]
        else:
            consequent_pred = consequent

        # Handle list(x) pattern: x |-> y * list(y) |- list(x)
        if consequent_pred.name == 'list' and len(consequent_pred.args) == 1:
            return self._match_list_cons(antecedent, consequent_pred.args[0])

        # Handle ls(x, z) pattern: x |-> y * ls(y, z) |- ls(x, z)
        if consequent_pred.name == 'ls' and len(consequent_pred.args) == 2:
            return self._match_ls_cons(antecedent, consequent_pred.args[0], consequent_pred.args[1])

        # Handle tree(x) pattern: x |-> (l, r) * tree(l) * tree(r) |- tree(x)
        if consequent_pred.name == 'tree' and len(consequent_pred.args) == 1:
            return self._match_tree_cons(antecedent, consequent_pred.args[0])

        # Handle RList(x, z) pattern: x |-> y * RList(y, z) |- RList(x, z)
        if consequent_pred.name == 'RList' and len(consequent_pred.args) == 2:
            return self._match_rlist_cons(antecedent, consequent_pred.args[0], consequent_pred.args[1])

        # Handle nll(x, y, z) pattern: x |-> (n, z) * nll(n, y, z) |- nll(x, y, z)
        if consequent_pred.name == 'nll' and len(consequent_pred.args) == 3:
            return self._match_nll_cons(antecedent, consequent_pred.args[0], consequent_pred.args[1], consequent_pred.args[2])

        return None

    def _match_list_cons(self, antecedent: Formula, target_var: Expr) -> Optional[bool]:
        """
        Match: x |-> y * list(y) |- list(x)

        Returns True if antecedent matches the recursive case of list(target_var).
        """
        # Extract spatial parts from antecedent
        ante_parts = self.analyzer._extract_sepconj_parts(antecedent)

        # Look for pattern: target_var |-> next * list(next) in some order
        points_to = None
        list_preds = []  # Collect ALL list predicates
        other_parts = []

        for part in ante_parts:
            if isinstance(part, PointsTo):
                # Check if this is target_var |-> something
                if self.analyzer._expr_equal(part.location, target_var):
                    points_to = part
                else:
                    other_parts.append(part)
            elif isinstance(part, PredicateCall) and part.name == 'list':
                list_preds.append(part)
            elif not isinstance(part, (Emp, True_)):
                other_parts.append(part)

        # Must have points_to and at least one list predicate
        if not points_to or not list_preds:
            return None

        # Try to find a list predicate that matches the points-to chain
        # pattern: x |-> y * list(y)
        if len(points_to.values) >= 1:
            next_val = points_to.values[0]

            for list_pred in list_preds:
                if len(list_pred.args) == 1:
                    list_arg = list_pred.args[0]

                    if self.analyzer._expr_equal(next_val, list_arg):
                        # Perfect match! This is exactly the recursive case of list(x)
                        if self.verbose:
                            print(f"Matched list cons pattern: {target_var} |-> {next_val} * list({list_arg})")
                        return True

            # Chaining pattern: x |-> y * (y |-> z * ... * list(...))
            remaining = other_parts + list_preds
            if len(remaining) >= 1:
                # Recursively check if remaining parts form list(next_val)
                remaining_formula = self.analyzer._build_sepconj(remaining)
                if self._match_list_cons(remaining_formula, next_val):
                    if self.verbose:
                        print(f"Matched chained list cons: {target_var} |-> {next_val} * list({next_val})")
                    return True

        return None

    def _match_ls_cons(self, antecedent: Formula, start_var: Expr, end_var: Expr) -> Optional[bool]:
        """
        Match: x |-> y * ls(y, z) |- ls(x, z)
        Also handles chaining: x |-> y * y |-> z * ls(z, end) |- ls(x, end)

        Returns True if antecedent matches the recursive case of ls(start_var, end_var).
        """
        # Extract spatial parts from antecedent
        ante_parts = self.analyzer._extract_sepconj_parts(antecedent)

        # Look for pattern: start_var |-> next * ls(next, end_var)
        points_to = None
        ls_pred = None
        other_points_to = []

        for part in ante_parts:
            if isinstance(part, PointsTo):
                if self.analyzer._expr_equal(part.location, start_var):
                    points_to = part
                else:
                    other_points_to.append(part)
            elif isinstance(part, PredicateCall) and part.name == 'ls':
                ls_pred = part

        if not points_to:
            return None

        # Direct pattern: x |-> y * ls(y, z)
        if ls_pred and len(points_to.values) >= 1 and len(ls_pred.args) == 2:
            next_val = points_to.values[0]
            ls_start = ls_pred.args[0]
            ls_end = ls_pred.args[1]

            if self.analyzer._expr_equal(next_val, ls_start) and self.analyzer._expr_equal(ls_end, end_var):
                if self.verbose:
                    print(f"Matched ls cons pattern: {start_var} |-> {next_val} * ls({ls_start}, {ls_end})")
                return True

        # Chaining pattern: x |-> y * (y |-> z * ... * ls(..., end))
        if len(points_to.values) >= 1:
            next_val = points_to.values[0]

            # SOUNDNESS FIX: Disabled base case chain matching
            # The pattern x |-> y * y |-> z |- ls(x, z) is UNSOUND with distinctness constraints!
            # Reason: The recursive case of ls(x, z) requires proving x ≠ z, but the heap
            # only proves x ≠ y and y ≠ z (from disjointness). If x = z, we'd have a cycle
            # x |-> y * y |-> x, which is 2 cells, not the emp required by ls(x, x) base case.
            #
            # This heuristic was causing over-proving on SL-COMP benchmarks like ls-vc01.
            # Disabled to maintain soundness - let Z3 verification handle distinctness properly.
            #
            # Original code (UNSOUND):
            # for pto in other_points_to:
            #     if self.analyzer._expr_equal(pto.location, next_val) and len(pto.values) >= 1:
            #         if self.analyzer._expr_equal(pto.values[0], end_var):
            #             return True

            # Build formula from remaining parts
            remaining = other_points_to + ([ls_pred] if ls_pred else [])
            if len(remaining) >= 2:  # At least y |-> z and ls(z, end)
                # Recursively check if remaining parts form ls(next_val, end_var)
                remaining_formula = self.analyzer._build_sepconj(remaining)
                if self._match_ls_cons(remaining_formula, next_val, end_var):
                    if self.verbose:
                        print(f"Matched chained ls cons: {start_var} |-> {next_val} * ls({next_val}, {end_var})")
                    return True

        return None

    def _match_tree_cons(self, antecedent: Formula, root_var: Expr) -> Optional[bool]:
        """
        Match: x |-> (l, r) * tree(l) * tree(r) |- tree(x)

        Returns True if antecedent matches the recursive case of tree(root_var).
        """
        # Extract spatial parts from antecedent
        ante_parts = self.analyzer._extract_sepconj_parts(antecedent)

        # Look for pattern: root_var |-> (left, right) * tree(left) * tree(right)
        points_to = None
        tree_preds = []

        for part in ante_parts:
            if isinstance(part, PointsTo):
                if self.analyzer._expr_equal(part.location, root_var):
                    points_to = part
            elif isinstance(part, PredicateCall) and part.name == 'tree':
                tree_preds.append(part)

        if not points_to or len(tree_preds) != 2:
            return None

        # Check pattern: x |-> (l, r) * tree(l) * tree(r)
        if len(points_to.values) >= 2:
            left_child = points_to.values[0]
            right_child = points_to.values[1]

            # Check if tree predicates match the children
            tree_args = {self.analyzer._expr_to_str(pred.args[0]) for pred in tree_preds if len(pred.args) == 1}
            expected_args = {self.analyzer._expr_to_str(left_child), self.analyzer._expr_to_str(right_child)}

            if tree_args == expected_args:
                if self.verbose:
                    print(f"Matched tree cons pattern: {root_var} |-> ({left_child}, {right_child}) * tree * tree")
                return True

        return None

    def _match_rlist_cons(self, antecedent: Formula, start_var: Expr, end_var: Expr) -> Optional[bool]:
        """
        Match: x |-> y * RList(y, z) |- RList(x, z)

        Returns True if antecedent matches the recursive case of RList(start_var, end_var).
        """
        # Extract spatial parts from antecedent
        ante_parts = self.analyzer._extract_sepconj_parts(antecedent)

        # Look for pattern: start_var |-> next * RList(next, end_var)
        points_to = None
        rlist_pred = None

        for part in ante_parts:
            if isinstance(part, PointsTo):
                if self.analyzer._expr_equal(part.location, start_var):
                    points_to = part
            elif isinstance(part, PredicateCall) and part.name == 'RList':
                rlist_pred = part

        if not points_to:
            return None

        # Pattern: x |-> y * RList(y, z)
        if rlist_pred and len(points_to.values) >= 1 and len(rlist_pred.args) == 2:
            next_val = points_to.values[0]
            rlist_start = rlist_pred.args[0]
            rlist_end = rlist_pred.args[1]

            if self.analyzer._expr_equal(next_val, rlist_start) and self.analyzer._expr_equal(rlist_end, end_var):
                if self.verbose:
                    print(f"Matched RList cons pattern: {start_var} |-> {next_val} * RList({rlist_start}, {rlist_end})")
                return True

        return None

    def _match_nll_cons(self, antecedent: Formula, start_var: Expr, middle_var: Expr, end_var: Expr) -> Optional[bool]:
        """
        Match: x |-> (n, z) * nll(n, y, z) |- nll(x, y, z)

        Returns True if antecedent matches the recursive case of nll(start_var, middle_var, end_var).
        """
        # Extract spatial parts from antecedent
        ante_parts = self.analyzer._extract_sepconj_parts(antecedent)

        # Look for pattern: start_var |-> (next, end_var) * nll(next, middle_var, end_var)
        points_to = None
        nll_pred = None

        for part in ante_parts:
            if isinstance(part, PointsTo):
                if self.analyzer._expr_equal(part.location, start_var):
                    points_to = part
            elif isinstance(part, PredicateCall) and part.name == 'nll':
                nll_pred = part

        if not points_to:
            return None

        # Pattern: x |-> (n, z) * nll(n, y, z)
        if nll_pred and len(points_to.values) >= 2 and len(nll_pred.args) == 3:
            next_val = points_to.values[0]
            nested_val = points_to.values[1]
            nll_start = nll_pred.args[0]
            nll_middle = nll_pred.args[1]
            nll_end = nll_pred.args[2]

            if (self.analyzer._expr_equal(next_val, nll_start) and
                self.analyzer._expr_equal(nll_middle, middle_var) and
                self.analyzer._expr_equal(nested_val, end_var) and
                self.analyzer._expr_equal(nll_end, end_var)):
                if self.verbose:
                    print(f"Matched nll cons pattern: {start_var} |-> ({next_val}, {nested_val}) * nll({nll_start}, {nll_middle}, {nll_end})")
                return True

        return None
