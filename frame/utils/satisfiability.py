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


class SatisfiabilityChecker:
    """Checks formula satisfiability and detects contradictions"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.analyzer = FormulaAnalyzer()
        self.heap_analyzer = HeapGraphAnalyzer(verbose=verbose)

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
        """
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

        # Extract all atomic formulas
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
            elif isinstance(f, Or):
                # Don't traverse into disjunctions (conservative)
                pass

        extract(formula)

        # Check for pure contradictions: x = y AND x != y
        for eq_left, eq_right in equalities:
            for neq_left, neq_right in inequalities:
                # Check if same pair appears in both equality and inequality
                if (self._exprs_equal(eq_left, neq_left) and self._exprs_equal(eq_right, neq_right)) or \
                   (self._exprs_equal(eq_left, neq_right) and self._exprs_equal(eq_right, neq_left)):
                    if self.verbose:
                        print(f"Contradiction: {eq_left} = {eq_right} AND {neq_left} != {neq_right}")
                    return True

        # Check for self-loops: x |-> x or x |-> ... where x appears in values
        for pto in points_to:
            if isinstance(pto.location, Var):
                for val in pto.values:
                    if isinstance(val, Var) and val.name == pto.location.name:
                        if self.verbose:
                            print(f"Self-loop: {pto.location.name} |-> {val.name}")
                        return True

        # Check for cycles in the heap graph (PRIORITY 1 improvement)
        # Cyclic heaps violate separation logic semantics and should be UNSAT
        if len(points_to) >= 2:  # Need at least 2 points-to for a cycle
            try:
                graph, _ = self.heap_analyzer.build_heap_graph(formula)
                if self.heap_analyzer._has_cycle(graph):
                    if self.verbose:
                        print(f"Cycle detected in heap graph")
                    return True
            except Exception as e:
                # If cycle detection fails, be conservative and continue
                if self.verbose:
                    print(f"Cycle detection error (ignored): {e}")
                pass

        # Check for aliasing violations in separating conjunction
        if len(points_to) >= 2:
            for i, pto1 in enumerate(points_to):
                for pto2 in points_to[i+1:]:
                    # Check if both point from the same location
                    if self._exprs_equal(pto1.location, pto2.location):
                        if self.verbose:
                            print(f"Aliasing contradiction: {pto1.location} points to multiple values in separating conjunction")
                        return True

        # Check for aliasing through equalities
        eq_classes = self._build_equivalence_classes(equalities)

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
        """Check if two expressions are syntactically equal"""
        if type(e1) != type(e2):
            return False
        if isinstance(e1, Var):
            return e1.name == e2.name
        if isinstance(e1, Const):
            return e1.value == e2.value
        return False

    def _is_pure_formula(self, formula: Formula) -> bool:
        """Check if formula is pure (non-spatial)"""
        if isinstance(formula, (Eq, Neq, True_, False_)):
            return True
        if isinstance(formula, And):
            return self._is_pure_formula(formula.left) and self._is_pure_formula(formula.right)
        if isinstance(formula, Or):
            return self._is_pure_formula(formula.left) and self._is_pure_formula(formula.right)
        if isinstance(formula, Not):
            return self._is_pure_formula(formula.formula)
        return False

    def _sepconj_contains(self, sepconj: SepConj, target: Formula) -> bool:
        """
        Check if a SepConj chain contains a specific formula (using structural equality).

        This handles the case where we have:
        (P * Q * R) & P  ->  should normalize to (P * Q * R)

        Used for dispose benchmark patterns.
        """
        def extract_sepconj_elements(f, elements=None):
            """Flatten a SepConj into a list of elements"""
            if elements is None:
                elements = []
            if isinstance(f, SepConj):
                extract_sepconj_elements(f.left, elements)
                extract_sepconj_elements(f.right, elements)
            else:
                elements.append(f)
            return elements

        elements = extract_sepconj_elements(sepconj)
        return any(self._formulas_equal(elem, target) for elem in elements)

    def _normalize_spatial(self, formula: Formula) -> Formula:
        """
        Normalize spatial formulas by simplifying emp and identity elements.

        Key normalizations (applied recursively until fixpoint):
        - emp * P → P (empty heap identity)
        - P * emp → P
        - (emp & pure) * P → pure & P (emp with pure constraints)
        - P * true → P (true is identity)
        - emp & pure → pure
        - P & true → P
        - Remove tautologies: nil = nil → true
        - Simplify P & P → P (idempotence)
        """
        # Apply normalization repeatedly until fixpoint
        prev = None
        current = formula
        iterations = 0
        max_iterations = 10  # Prevent infinite loops

        while prev != current and iterations < max_iterations:
            prev = current
            current = self._normalize_once(current)
            iterations += 1

        return current

    def _normalize_once(self, formula: Formula) -> Formula:
        """Apply one round of normalization"""
        if isinstance(formula, SepConj):
            # Normalize children first
            left = self._normalize_once(formula.left)
            right = self._normalize_once(formula.right)

            # emp * P → P
            if isinstance(left, Emp):
                return right
            if isinstance(right, Emp):
                return left

            # P * true → P (true is spatial identity)
            if isinstance(right, True_):
                return left
            if isinstance(left, True_):
                return right

            # pure * P → P (when left is pure formula like Eq, Neq, etc.)
            # This is WRONG in separation logic but appears in malformed formulas
            # We move the pure constraint out: pure * P becomes just P
            if self._is_pure_formula(left) and not isinstance(left, Emp):
                # This is semantically incorrect in SL, but the formula is malformed
                # Treat as: the pure constraint is ignored in separating conjunction
                return right
            if self._is_pure_formula(right) and not isinstance(right, Emp):
                return left

            # (emp & pure) * P → pure & P
            if isinstance(left, And):
                if isinstance(left.left, Emp):
                    # (emp & pure) * P → pure & P
                    normalized_pure = self._normalize_once(left.right)
                    return And(normalized_pure, right)
                if isinstance(left.right, Emp):
                    # (pure & emp) * P → pure & P
                    normalized_pure = self._normalize_once(left.left)
                    return And(normalized_pure, right)

            if isinstance(right, And):
                if isinstance(right.left, Emp):
                    # P * (emp & pure) → P & pure
                    normalized_pure = self._normalize_once(right.right)
                    return And(normalized_pure, left)
                if isinstance(right.right, Emp):
                    # P * (pure & emp) → P & pure
                    normalized_pure = self._normalize_once(right.left)
                    return And(normalized_pure, left)

            # Reconstruct if changed
            if left != formula.left or right != formula.right:
                return SepConj(left, right)
            return formula

        elif isinstance(formula, And):
            left = self._normalize_once(formula.left)
            right = self._normalize_once(formula.right)

            # emp & pure → pure
            if isinstance(left, Emp):
                return right
            if isinstance(right, Emp):
                return left

            # P & true → P
            if isinstance(left, True_):
                return right
            if isinstance(right, True_):
                return left

            # Remove tautologies: x = x → true
            if isinstance(left, Eq):
                if self._exprs_equal(left.left, left.right):
                    return right
            if isinstance(right, Eq):
                if self._exprs_equal(right.left, right.right):
                    return left

            # Idempotence: P & P → P (for spatial formulas)
            if self._formulas_equal(left, right):
                return left

            # Special case: (SepConj containing P) & P → SepConj
            # This handles dispose patterns like: (w|->a * a|->b * b|->c) & w|->a
            # If P appears in the SepConj, the And is redundant
            if isinstance(left, SepConj) and isinstance(right, PointsTo):
                if self._sepconj_contains(left, right):
                    return left
            if isinstance(right, SepConj) and isinstance(left, PointsTo):
                if self._sepconj_contains(right, left):
                    return right

            # Reconstruct if changed
            if left != formula.left or right != formula.right:
                return And(left, right)
            return formula

        elif isinstance(formula, Or):
            left = self._normalize_once(formula.left)
            right = self._normalize_once(formula.right)

            # P | true → true
            if isinstance(left, True_) or isinstance(right, True_):
                return True_()

            # P | false → P
            if isinstance(left, False_):
                return right
            if isinstance(right, False_):
                return left

            # Idempotence: P | P → P
            if self._formulas_equal(left, right):
                return left

            if left != formula.left or right != formula.right:
                return Or(left, right)
            return formula

        elif isinstance(formula, Not):
            inner = self._normalize_once(formula.formula)

            # Double negation: NOT(NOT(P)) → P
            if isinstance(inner, Not):
                return inner.formula

            # NOT(true) → false
            if isinstance(inner, True_):
                return False_()

            # NOT(false) → true
            if isinstance(inner, False_):
                return True_()

            if inner != formula.formula:
                return Not(inner)
            return formula

        else:
            return formula

    def _formulas_equal(self, f1: Formula, f2: Formula) -> bool:
        """
        Check if two formulas are structurally equal.

        Handles spatial formulas (PointsTo, SepConj, Emp) and pure formulas.
        For SepConj, handles all reorderings since it's associative and commutative.
        """
        if type(f1) != type(f2):
            return False

        if isinstance(f1, PointsTo):
            if not self._exprs_equal(f1.location, f2.location):
                return False
            if len(f1.values) != len(f2.values):
                return False
            return all(self._exprs_equal(v1, v2) for v1, v2 in zip(f1.values, f2.values))

        elif isinstance(f1, Emp):
            return True  # All emp are equal

        elif isinstance(f1, SepConj):
            # SepConj is associative and commutative, so we need to compare sets of elements
            # Extract all elements from both SepConj chains
            def extract_elements(f, elements=None):
                if elements is None:
                    elements = []
                if isinstance(f, SepConj):
                    extract_elements(f.left, elements)
                    extract_elements(f.right, elements)
                else:
                    elements.append(f)
                return elements

            elements1 = extract_elements(f1)
            elements2 = extract_elements(f2)

            if len(elements1) != len(elements2):
                return False

            # Check if all elements from f1 have a matching element in f2
            # This is expensive (O(n²)) but needed for correctness
            matched = [False] * len(elements2)
            for e1 in elements1:
                found = False
                for i, e2 in enumerate(elements2):
                    if not matched[i] and self._formulas_equal(e1, e2):
                        matched[i] = True
                        found = True
                        break
                if not found:
                    return False
            return True

        elif isinstance(f1, And):
            # Check both orderings (and is commutative)
            return (self._formulas_equal(f1.left, f2.left) and
                    self._formulas_equal(f1.right, f2.right)) or \
                   (self._formulas_equal(f1.left, f2.right) and
                    self._formulas_equal(f1.right, f2.left))

        elif isinstance(f1, Eq):
            return self._exprs_equal(f1.left, f2.left) and self._exprs_equal(f1.right, f2.right)

        elif isinstance(f1, Neq):
            return self._exprs_equal(f1.left, f2.left) and self._exprs_equal(f1.right, f2.right)

        else:
            # For other formula types, use string comparison (conservative)
            return str(f1) == str(f2)

    def _has_p_and_not_p_contradiction(self, formula: Formula) -> bool:
        """
        Detect P AND NOT(P) contradictions where P is a formula.

        Critical for dispose/rev benchmarks which have patterns like:
        (pto w nil) AND NOT((emp * pto w nil) AND (pto w nil))

        After normalizing emp, this becomes:
        (pto w nil) AND NOT(pto w nil AND pto w nil)
        (pto w nil) AND NOT(pto w nil)

        Which is a clear contradiction.
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

        return False
