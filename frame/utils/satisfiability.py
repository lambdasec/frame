"""
Satisfiability Checking

Provides utilities for checking formula satisfiability and detecting
obvious contradictions.
"""

from typing import List, Tuple, Dict
from frame.core.ast import (
    Formula, Expr, Var, Const, Emp, PointsTo, SepConj, And, Or, Not,
    Eq, Neq, PredicateCall, Exists, Forall, True_, False_
)
from frame.analysis.formula import FormulaAnalyzer
from frame.heap.graph_analysis import HeapGraphAnalyzer
from frame.utils._normalization import FormulaNormalizer


class SatisfiabilityChecker:
    """Checks formula satisfiability and detects contradictions"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.analyzer = FormulaAnalyzer()
        self.heap_analyzer = HeapGraphAnalyzer(verbose=verbose)
        self.normalizer = FormulaNormalizer()

    def is_simple_ls_chain(self, formula: Formula) -> bool:
        """
        Check if formula is a simple conjunction of list segments WITHOUT pure constraints.

        These are almost always satisfiable (just need distinct vars).
        Example: ls(x, y) * ls(y, z) * ls(a, b)

        Returns True only if:
        - Formula is ONLY standard ls/list/dll predicates in SepConj (no custom predicates!)
        - No points-to, no And with pure constraints
        - No Eq/Neq/arithmetic that could cause contradictions
        - No self-loops like ls(x,x,5) which would be UNSAT
        """
        def is_pure_spatial_standard(f):
            """Check if formula is purely spatial with STANDARD predicates only"""
            if isinstance(f, PredicateCall):
                # Only accept well-known standard predicates
                # Reject custom predicates (P, Q, R, etc.) that might have complex semantics
                standard_preds = {"ls", "list", "dll", "tree", "RList", "nll"}
                return f.name in standard_preds
            elif isinstance(f, SepConj):
                return is_pure_spatial_standard(f.left) and is_pure_spatial_standard(f.right)
            elif isinstance(f, Emp):
                return True  # emp is fine
            else:
                # Any And, Or, Not, Eq, Neq means we have pure constraints
                return False

        # Must be purely spatial standard predicates only
        if not is_pure_spatial_standard(formula):
            return False

        # Extract all predicate calls
        def extract_predicates(f, calls=None):
            if calls is None:
                calls = []
            if isinstance(f, PredicateCall):
                calls.append(f)
            elif isinstance(f, SepConj):
                extract_predicates(f.left, calls)
                extract_predicates(f.right, calls)
            return calls

        pred_calls = extract_predicates(formula)

        # If we have many predicate calls (>10), it's complex - use normal path
        if len(pred_calls) > 10:
            return False

        # Check for obvious self-loops that would be UNSAT
        # Example: ls(x,x,5) means 5-element segment from x to x, which is impossible
        for pred in pred_calls:
            if pred.name == "ls" and len(pred.args) >= 2:
                # Check if same variable appears as both start and end
                start, end = pred.args[0], pred.args[1]
                if isinstance(start, Var) and isinstance(end, Var):
                    if start.name == end.name:
                        # ls(x,x,...) - only valid if length is 0
                        if len(pred.args) == 3:  # length-annotated
                            length_arg = pred.args[2]
                            if isinstance(length_arg, Const) and length_arg.value != 0:
                                return False  # UNSAT: non-zero length self-loop

        # Simple standard predicate chain without pure constraints - likely SAT
        return True

    def has_obvious_contradiction(self, formula: Formula) -> bool:
        """
        Check for obvious contradictions that make the formula unsatisfiable.

        Detects:
        1. Pure contradictions: x = y AND x != y
        2. Spatial contradictions: emp AND x |-> y
        3. Self-loops: x |-> x (in separation logic, this is typically UNSAT)
        4. P AND NOT(P) contradictions (after normalizing emp)
        5. Or where ALL branches contradict: (A ∨ B) where both A and B are UNSAT
        """
        # Check for Or where all branches contradict
        if self._check_or_all_branches_contradict(formula):
            if self.verbose:
                print(f"Contradiction: All Or branches lead to contradictions")
            return True

        # Check for P AND NOT(P) contradictions
        if self._has_p_and_not_p_contradiction(formula):
            if self.verbose:
                print(f"Contradiction: P AND NOT(P) detected")
            return True

        # Check for direct And-conjunctions containing emp with spatial formulas
        def has_emp_and_spatial_contradiction(f):
            """Check if formula is emp & P where P is spatial (this is a contradiction)"""
            if isinstance(f, And):
                # Check if one side is emp and the other is spatial
                if isinstance(f.left, Emp) and f.right.is_spatial():
                    return True
                if isinstance(f.right, Emp) and f.left.is_spatial():
                    return True
                # Recurse into And/SepConj
                if has_emp_and_spatial_contradiction(f.left):
                    return True
                if has_emp_and_spatial_contradiction(f.right):
                    return True
            elif isinstance(f, SepConj):
                # Recurse but don't check contradiction here (emp * P is valid)
                if has_emp_and_spatial_contradiction(f.left):
                    return True
                if has_emp_and_spatial_contradiction(f.right):
                    return True
            return False

        if has_emp_and_spatial_contradiction(formula):
            if self.verbose:
                print(f"Contradiction: emp & spatial_formula")
            return True

        # Extract all atomic formulas (but NOT from Or branches - handle those separately above)
        equalities = []
        inequalities = []
        points_to = []

        def extract(f):
            if isinstance(f, Eq):
                equalities.append((f.left, f.right))
            elif isinstance(f, Neq):
                inequalities.append((f.left, f.right))
            elif isinstance(f, PointsTo):
                points_to.append(f)
            elif isinstance(f, (And, SepConj)):
                extract(f.left)
                extract(f.right)
            # Don't extract from Or - those are handled by _check_or_all_branches_contradict

        extract(formula)

        # Build equivalence classes for transitivity and aliasing checks
        eq_classes = self._build_equivalence_classes(equalities)

        # Check for pure contradictions: x != y but x = y (by transitivity)
        # For example: x != y AND x = nil AND y = nil => contradiction
        for neq_left, neq_right in inequalities:
            if self._in_same_eq_class(neq_left, neq_right, eq_classes):
                if self.verbose:
                    print(f"Contradiction: {neq_left} != {neq_right} but they are equal by transitivity")
                return True

        # Check for self-loops: x |-> x or x |-> ... where x appears in values
        for pto in points_to:
            if isinstance(pto.location, Var):
                for val in pto.values:
                    if isinstance(val, Var) and val.name == pto.location.name:
                        if self.verbose:
                            print(f"Self-loop: {pto.location.name} |-> {val.name}")
                        return True

        # REMOVED INCORRECT CYCLE CHECK
        # The previous code incorrectly treated ALL cycles as contradictions.
        # This is WRONG - cyclic heaps (e.g., circular doubly-linked lists) are valid!
        # Example: dll-vc14 has x -> y -> x (cycle) which is perfectly satisfiable.
        # Separation logic allows cycles. Only true self-loops (x |-> x) are unsound.
        # Self-loops are already checked above (lines 175-180).
        # DO NOT re-add general cycle detection without careful consideration!

        # Check for aliasing violations in separating conjunction
        if len(points_to) >= 2:
            for i, pto1 in enumerate(points_to):
                for pto2 in points_to[i+1:]:
                    # Check if both point from the same location
                    if self._exprs_equal(pto1.location, pto2.location):
                        if self.verbose:
                            print(f"Aliasing contradiction: {pto1.location} points to multiple values in separating conjunction")
                        return True

        # Check for aliasing through equalities (eq_classes already built above)
        # Check if aliased locations point to different values
        for i, pto1 in enumerate(points_to):
            for pto2 in points_to[i+1:]:
                # Check if locations are in same equivalence class
                if self._in_same_eq_class(pto1.location, pto2.location, eq_classes):
                    # Same location (through equality) pointing to different values
                    if not all(self._in_same_eq_class(v1, v2, eq_classes)
                              for v1 in pto1.values for v2 in pto2.values):
                        if self.verbose:
                            print(f"Aliasing through equality: {pto1.location} and {pto2.location} are equal but point to different values")
                        return True

        return False

    def _check_or_all_branches_contradict(self, formula: Formula) -> bool:
        """
        Check if formula contains an Or where ALL branches lead to contradictions.

        For example:
        - (x=y ∧ x≠y) ∨ (x=z ∧ x≠z) => TRUE (both branches contradict)
        - (x=y) ∨ (x≠y) => FALSE (neither branch contradicts individually)
        - (x=y ∧ x≠y) ∨ (x=z) => FALSE (only one branch contradicts)
        """
        def check_formula(f):
            if isinstance(f, Or):
                # Check if BOTH branches have contradictions
                # We recursively check each branch as a standalone formula
                left_contradicts = self._check_branch_contradiction(f.left)
                right_contradicts = self._check_branch_contradiction(f.right)

                if left_contradicts and right_contradicts:
                    if self.verbose:
                        print(f"Or contradiction: both branches contradict")
                    return True

                # Also recursively check within each branch for nested Ors
                if check_formula(f.left) or check_formula(f.right):
                    return True

            elif isinstance(f, (And, SepConj)):
                # Recursively check both sides
                return check_formula(f.left) or check_formula(f.right)
            elif isinstance(f, Not):
                return check_formula(f.formula)
            elif isinstance(f, (Exists, Forall)):
                return check_formula(f.formula)

            return False

        return check_formula(formula)

    def _check_branch_contradiction(self, branch: Formula) -> bool:
        """
        Check if a single branch (from an Or) has an obvious contradiction.
        This is similar to has_obvious_contradiction but without the Or-branch check
        to avoid infinite recursion.
        """
        # Check for P AND NOT(P) contradictions
        if self._has_p_and_not_p_contradiction(branch):
            return True

        # Extract atomic formulas from this branch only
        equalities = []
        inequalities = []
        points_to = []

        def extract(f):
            if isinstance(f, Eq):
                equalities.append((f.left, f.right))
            elif isinstance(f, Neq):
                inequalities.append((f.left, f.right))
            elif isinstance(f, PointsTo):
                points_to.append(f)
            elif isinstance(f, (And, SepConj)):
                extract(f.left)
                extract(f.right)
            # Don't recurse into Or - we're checking a single branch

        extract(branch)

        # Build equivalence classes for this branch
        eq_classes = self._build_equivalence_classes(equalities)

        # Check for pure contradictions: x != y but x = y (by transitivity)
        for neq_left, neq_right in inequalities:
            if self._in_same_eq_class(neq_left, neq_right, eq_classes):
                return True

        # Check for self-loops
        for pto in points_to:
            if isinstance(pto.location, Var):
                for val in pto.values:
                    if isinstance(val, Var) and val.name == pto.location.name:
                        return True

        # Check for aliasing violations
        if len(points_to) >= 2:
            for i, pto1 in enumerate(points_to):
                for pto2 in points_to[i+1:]:
                    if self._exprs_equal(pto1.location, pto2.location):
                        return True

        # Check for aliasing through equalities
        for i, pto1 in enumerate(points_to):
            for pto2 in points_to[i+1:]:
                if self._in_same_eq_class(pto1.location, pto2.location, eq_classes):
                    if not all(self._in_same_eq_class(v1, v2, eq_classes)
                              for v1 in pto1.values for v2 in pto2.values):
                        return True

        return False

    def _build_equivalence_classes(self, equalities: List[Tuple[Expr, Expr]]) -> Dict:
        """Build equivalence classes from equality assertions"""
        # Use union-find structure
        parent = {}

        def find(x):
            if x not in parent:
                parent[x] = x
                return x
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Process all equalities
        for left, right in equalities:
            left_key = self._expr_to_key(left)
            right_key = self._expr_to_key(right)
            union(left_key, right_key)

        return parent

    def _in_same_eq_class(self, e1: Expr, e2: Expr, eq_classes: Dict) -> bool:
        """Check if two expressions are in the same equivalence class"""
        k1 = self._expr_to_key(e1)
        k2 = self._expr_to_key(e2)

        def find(x):
            if x not in eq_classes:
                return x
            if eq_classes[x] != x:
                eq_classes[x] = find(eq_classes[x])
            return eq_classes[x]

        return find(k1) == find(k2)

    def _expr_to_key(self, expr: Expr):
        """Convert expression to hashable key"""
        if isinstance(expr, Var):
            return ('var', expr.name)
        elif isinstance(expr, Const):
            return ('const', expr.value)
        else:
            return ('unknown', str(expr))

    def _exprs_equal(self, e1: Expr, e2: Expr) -> bool:
        """Delegate to normalizer"""
        return self.normalizer.exprs_equal(e1, e2)

    def _is_pure_formula(self, formula: Formula) -> bool:
        """Delegate to normalizer"""
        return self.normalizer.is_pure_formula(formula)

    def _sepconj_contains(self, sepconj: SepConj, target: Formula) -> bool:
        """Delegate to normalizer"""
        return self.normalizer.sepconj_contains(sepconj, target)

    def _normalize_spatial(self, formula: Formula) -> Formula:
        """Delegate to normalizer"""
        return self.normalizer.normalize_spatial(formula)

    def _normalize_once(self, formula: Formula) -> Formula:
        """Delegate to normalizer"""
        return self.normalizer.normalize_once(formula)

    def _formulas_equal(self, f1: Formula, f2: Formula) -> bool:
        """Delegate to normalizer"""
        return self.normalizer.formulas_equal(f1, f2)

    def _has_p_and_not_p_contradiction(self, formula: Formula) -> bool:
        """
        Detect P AND NOT(P) contradictions where P is a formula.

        Critical for dispose/rev benchmarks which have patterns like:
        (pto w nil) AND NOT((emp * pto w nil) AND (pto w nil))

        After normalizing emp, this becomes:
        (pto w nil) AND NOT(pto w nil AND pto w nil)
        (pto w nil) AND NOT(pto w nil)

        Which is a clear contradiction.

        Also handles the pattern:
        (A * B) AND NOT((A * X) & (A * Y))
        Where both branches of the negated AND contain the same spatial cell A
        from the positive formula.
        """
        # Normalize the formula first to simplify emp
        normalized = self._normalize_spatial(formula)

        # Extract positive and negative assertions
        positive_assertions = []
        negative_assertions = []

        def extract_assertions(f, negated=False):
            if isinstance(f, Not):
                # Flip negation and recurse
                extract_assertions(f.formula, not negated)
            elif isinstance(f, And):
                extract_assertions(f.left, negated)
                extract_assertions(f.right, negated)
            elif isinstance(f, SepConj):
                # Don't break down SepConj - treat as atomic for contradiction checking
                if negated:
                    negative_assertions.append(f)
                else:
                    positive_assertions.append(f)
            elif isinstance(f, (PointsTo, Emp, Eq, Neq, PredicateCall)):
                # Atomic formulas
                if negated:
                    negative_assertions.append(f)
                else:
                    positive_assertions.append(f)
            # Skip Or (conservative - don't traverse into disjunctions)

        extract_assertions(normalized)

        # Check if any positive assertion appears in negative assertions
        for pos in positive_assertions:
            for neg in negative_assertions:
                if self._formulas_equal(pos, neg):
                    if self.verbose:
                        print(f"P AND NOT(P) contradiction found:")
                        print(f"  P: {pos}")
                        print(f"  NOT(P): NOT({neg})")
                    return True

        # Check for pattern: positive SepConj contains cell A, and
        # negated SepConj also contains cell A at the same position
        # This handles: (A * B) & NOT((A * X) & ...)
        if self._has_shared_cell_contradiction(normalized):
            return True

        return False

    def _has_shared_cell_contradiction(self, formula: Formula) -> bool:
        """
        Detect contradiction where positive and negated formulas share cells.

        Pattern 1: (A * B) & NOT((A * X) & (A * Y))
        If the heap has cells A * B, and the negated formula has conjuncts
        that both require cell A, then if A and B together satisfy the
        negated formula's structure, it's a contradiction.

        Pattern 2: (A * B) & NOT(A * wand(P, Q))
        If the heap has cells A * B, and the negated formula is A * wand,
        then if B can satisfy the wand, the negated formula is true,
        making NOT(...) = false, hence UNSAT.

        This is a heuristic that catches common BSL patterns.
        """
        from frame.core.ast import Wand

        # Extract positive cells (from SepConj or PointsTo)
        positive_cells = []
        negated_and_parts = []
        negated_sepconjs = []

        def extract_positive_cells(f):
            if isinstance(f, PointsTo):
                positive_cells.append(f)
            elif isinstance(f, SepConj):
                extract_positive_cells(f.left)
                extract_positive_cells(f.right)
            elif isinstance(f, And):
                # Handle And containing spatial formulas
                if f.left.is_spatial():
                    extract_positive_cells(f.left)
                if f.right.is_spatial():
                    extract_positive_cells(f.right)

        def extract_negated_structure(f, negated=False):
            if isinstance(f, Not):
                extract_negated_structure(f.formula, not negated)
            elif isinstance(f, And):
                if negated:
                    # We're inside NOT(And(...))
                    negated_and_parts.append(f)
                else:
                    extract_negated_structure(f.left, negated)
                    extract_negated_structure(f.right, negated)
            elif isinstance(f, SepConj):
                if negated:
                    # We're inside NOT(SepConj(...))
                    negated_sepconjs.append(f)

        extract_positive_cells(formula)
        extract_negated_structure(formula)

        if not positive_cells:
            return False

        # Pattern 1: Check negated ANDs
        for negated_and in negated_and_parts:
            left_has_cell = self._sepconj_shares_cells(negated_and.left, positive_cells)
            right_has_cell = self._sepconj_shares_cells(negated_and.right, positive_cells)

            if left_has_cell and right_has_cell:
                if self.verbose:
                    print(f"Shared cell contradiction: NOT(And) has cells from positive in both branches")
                return True

        # Pattern 2: Check negated SepConjs with wands
        for negated_sep in negated_sepconjs:
            # Check if this SepConj has a wand and shares cells with positive
            has_wand = self._contains_wand(negated_sep)
            shares_cells = self._sepconj_shares_cells(negated_sep, positive_cells)

            if has_wand and shares_cells:
                # Count cells in positive vs negated SepConj's non-wand parts
                negated_cell_count = self._count_non_wand_cells(negated_sep)
                positive_cell_count = len(positive_cells)

                # If positive has more cells than negated needs (excluding wand),
                # the extra cells might satisfy the wand, making negated true
                if positive_cell_count >= negated_cell_count:
                    if self.verbose:
                        print(f"Wand contradiction: positive heap can satisfy negated SepConj with wand")
                    return True

        return False

    def _contains_wand(self, formula: Formula) -> bool:
        """Check if formula contains a Wand"""
        from frame.core.ast import Wand
        if isinstance(formula, Wand):
            return True
        elif isinstance(formula, (SepConj, And, Or)):
            return self._contains_wand(formula.left) or self._contains_wand(formula.right)
        elif isinstance(formula, Not):
            return self._contains_wand(formula.formula)
        return False

    def _count_non_wand_cells(self, formula: Formula) -> int:
        """Count PointsTo cells in formula, excluding wand contents"""
        from frame.core.ast import Wand
        if isinstance(formula, PointsTo):
            return 1
        elif isinstance(formula, Wand):
            return 0  # Don't count cells inside wand
        elif isinstance(formula, SepConj):
            return self._count_non_wand_cells(formula.left) + self._count_non_wand_cells(formula.right)
        elif isinstance(formula, And):
            return self._count_non_wand_cells(formula.left) + self._count_non_wand_cells(formula.right)
        return 0

    def _sepconj_shares_cells(self, formula: Formula, cells: list) -> bool:
        """Check if formula contains any of the given cells in a SepConj"""
        if isinstance(formula, PointsTo):
            for cell in cells:
                if self._cells_same_location(formula, cell):
                    return True
        elif isinstance(formula, SepConj):
            return (self._sepconj_shares_cells(formula.left, cells) or
                    self._sepconj_shares_cells(formula.right, cells))
        elif isinstance(formula, And):
            return (self._sepconj_shares_cells(formula.left, cells) or
                    self._sepconj_shares_cells(formula.right, cells))
        return False

    def _cells_same_location(self, cell1: PointsTo, cell2: PointsTo) -> bool:
        """Check if two PointsTo cells reference the same location"""
        if not isinstance(cell1, PointsTo) or not isinstance(cell2, PointsTo):
            return False
        return self._exprs_equal(cell1.location, cell2.location)
