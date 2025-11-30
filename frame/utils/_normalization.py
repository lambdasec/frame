"""
Formula Normalization Utilities

Provides normalization and simplification for separation logic formulas.
Extracted from satisfiability.py to improve modularity.
"""

from frame.core.ast import (
    Formula, Expr, Var, Const, Emp, PointsTo, SepConj, And, Or, Not,
    Eq, Neq, True_, False_
)


class FormulaNormalizer:
    """Normalizes and simplifies separation logic formulas"""

    def __init__(self):
        pass

    def is_pure_formula(self, formula: Formula) -> bool:
        """Check if formula is pure (non-spatial)"""
        if isinstance(formula, (Eq, Neq, True_, False_)):
            return True
        if isinstance(formula, And):
            return self.is_pure_formula(formula.left) and self.is_pure_formula(formula.right)
        if isinstance(formula, Or):
            return self.is_pure_formula(formula.left) and self.is_pure_formula(formula.right)
        if isinstance(formula, Not):
            return self.is_pure_formula(formula.formula)
        return False

    def exprs_equal(self, e1: Expr, e2: Expr) -> bool:
        """Check if two expressions are syntactically equal"""
        if type(e1) != type(e2):
            return False
        if isinstance(e1, Var):
            return e1.name == e2.name
        if isinstance(e1, Const):
            return e1.value == e2.value
        return False

    def sepconj_contains(self, sepconj: SepConj, target: Formula) -> bool:
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
        return any(self.formulas_equal(elem, target) for elem in elements)

    def formulas_equal(self, f1: Formula, f2: Formula) -> bool:
        """
        Check if two formulas are structurally equal.

        Handles spatial formulas (PointsTo, SepConj, Emp) and pure formulas.
        For SepConj, handles all reorderings since it's associative and commutative.
        """
        if type(f1) != type(f2):
            return False

        if isinstance(f1, PointsTo):
            if not self.exprs_equal(f1.location, f2.location):
                return False
            if len(f1.values) != len(f2.values):
                return False
            return all(self.exprs_equal(v1, v2) for v1, v2 in zip(f1.values, f2.values))

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
                    if not matched[i] and self.formulas_equal(e1, e2):
                        matched[i] = True
                        found = True
                        break
                if not found:
                    return False
            return True

        elif isinstance(f1, And):
            # Check both orderings (and is commutative)
            return (self.formulas_equal(f1.left, f2.left) and
                    self.formulas_equal(f1.right, f2.right)) or \
                   (self.formulas_equal(f1.left, f2.right) and
                    self.formulas_equal(f1.right, f2.left))

        elif isinstance(f1, Eq):
            return self.exprs_equal(f1.left, f2.left) and self.exprs_equal(f1.right, f2.right)

        elif isinstance(f1, Neq):
            return self.exprs_equal(f1.left, f2.left) and self.exprs_equal(f1.right, f2.right)

        else:
            # For other formula types, use string comparison (conservative)
            return str(f1) == str(f2)

    def normalize_spatial(self, formula: Formula) -> Formula:
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
            current = self.normalize_once(current)
            iterations += 1

        return current

    def normalize_once(self, formula: Formula) -> Formula:
        """Apply one round of normalization"""
        if isinstance(formula, SepConj):
            # Normalize children first
            left = self.normalize_once(formula.left)
            right = self.normalize_once(formula.right)

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
            if self.is_pure_formula(left) and not isinstance(left, Emp):
                # This is semantically incorrect in SL, but the formula is malformed
                # Treat as: the pure constraint is ignored in separating conjunction
                return right
            if self.is_pure_formula(right) and not isinstance(right, Emp):
                return left

            # (emp & pure) * P → pure & P
            if isinstance(left, And):
                if isinstance(left.left, Emp):
                    # (emp & pure) * P → pure & P
                    normalized_pure = self.normalize_once(left.right)
                    return And(normalized_pure, right)
                if isinstance(left.right, Emp):
                    # (pure & emp) * P → pure & P
                    normalized_pure = self.normalize_once(left.left)
                    return And(normalized_pure, right)

            if isinstance(right, And):
                if isinstance(right.left, Emp):
                    # P * (emp & pure) → P & pure
                    normalized_pure = self.normalize_once(right.right)
                    return And(normalized_pure, left)
                if isinstance(right.right, Emp):
                    # P * (pure & emp) → P & pure
                    normalized_pure = self.normalize_once(right.left)
                    return And(normalized_pure, left)

            # Reconstruct if changed
            if left != formula.left or right != formula.right:
                return SepConj(left, right)
            return formula

        elif isinstance(formula, And):
            left = self.normalize_once(formula.left)
            right = self.normalize_once(formula.right)

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
                if self.exprs_equal(left.left, left.right):
                    return right
            if isinstance(right, Eq):
                if self.exprs_equal(right.left, right.right):
                    return left

            # Idempotence: P & P → P (for spatial formulas)
            if self.formulas_equal(left, right):
                return left

            # Special case: (SepConj containing P) & P → SepConj
            # This handles dispose patterns like: (w|->a * a|->b * b|->c) & w|->a
            # If P appears in the SepConj, the And is redundant
            if isinstance(left, SepConj) and isinstance(right, PointsTo):
                if self.sepconj_contains(left, right):
                    return left
            if isinstance(right, SepConj) and isinstance(left, PointsTo):
                if self.sepconj_contains(right, left):
                    return right

            # Reconstruct if changed
            if left != formula.left or right != formula.right:
                return And(left, right)
            return formula

        elif isinstance(formula, Or):
            left = self.normalize_once(formula.left)
            right = self.normalize_once(formula.right)

            # P | true → true
            if isinstance(left, True_) or isinstance(right, True_):
                return True_()

            # P | false → P
            if isinstance(left, False_):
                return right
            if isinstance(right, False_):
                return left

            # Idempotence: P | P → P
            if self.formulas_equal(left, right):
                return left

            if left != formula.left or right != formula.right:
                return Or(left, right)
            return formula

        elif isinstance(formula, Not):
            inner = self.normalize_once(formula.formula)

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

        elif isinstance(formula, Eq):
            # Simplify constant equalities: 2 = 0 → false, 0 = 0 → true
            left_val = self._eval_const_expr(formula.left)
            right_val = self._eval_const_expr(formula.right)
            if left_val is not None and right_val is not None:
                return True_() if left_val == right_val else False_()
            return formula

        else:
            return formula

    def _eval_const_expr(self, expr):
        """
        Evaluate a constant expression to an integer value.
        Returns None if the expression is not a constant.
        Handles Const, ArithExpr with subtraction, etc.
        """
        from frame.core.ast import ArithExpr

        if isinstance(expr, Const):
            return expr.value

        if isinstance(expr, ArithExpr):
            # Handle arithmetic: (- a b) → a - b
            if expr.op == '-':
                left_val = self._eval_const_expr(expr.left)
                right_val = self._eval_const_expr(expr.right)
                if left_val is not None and right_val is not None:
                    return left_val - right_val
            elif expr.op == '+':
                left_val = self._eval_const_expr(expr.left)
                right_val = self._eval_const_expr(expr.right)
                if left_val is not None and right_val is not None:
                    return left_val + right_val
            elif expr.op == '*':
                left_val = self._eval_const_expr(expr.left)
                right_val = self._eval_const_expr(expr.right)
                if left_val is not None and right_val is not None:
                    return left_val * right_val

        return None
