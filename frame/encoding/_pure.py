"""
Pure formula encoding for Z3 Encoder

Internal module for encoding pure (non-spatial) formulas, taint tracking,
and high-level formula/entailment encoding.
"""

import z3
from typing import Set, Tuple, Optional
from frame.core.ast import (
    Formula, Expr, Var, Const, Emp, PointsTo, SepConj, Wand, And, Or, Not,
    Eq, Neq, Lt, Le, Gt, Ge, True_, False_, Exists, Forall, PredicateCall,
    StrLiteral, StrConcat, StrLen, StrSubstr, StrContains, StrMatches,
    Taint, Sanitized, Source, Sink,
    Error, NullDeref, UseAfterFree, BufferOverflow,
    Allocated, Freed, ArrayPointsTo, ArrayBounds,
    TaintedArray, BufferOverflowCheck, IntegerOverflow
)
from frame.encoding._pure_core import (
    encode_pure as _encode_pure_impl,
    encode_entailment as _encode_entailment_impl
)


class PureEncoder:
    """Encoder for pure (non-spatial) formulas and high-level encoding"""

    def __init__(self, main_encoder):
        """Initialize with reference to main Z3Encoder"""
        self.encoder = main_encoder

    def encode_pure(self, formula: Formula, prefix: str = "") -> z3.BoolRef:
        """Delegate to pure encoding helper"""
        return _encode_pure_impl(self, formula, prefix)

    def _get_var_name(self, expr: Expr) -> Optional[str]:
        """Extract variable name from expression, or None if not a simple variable"""
        if isinstance(expr, Var):
            return expr.name
        return None

    def _collect_tainted_vars(self, formula: Formula) -> Set[str]:
        """Collect all variables that are marked as tainted in the formula

        Args:
            formula: Formula to analyze

        Returns:
            Set of variable names that are tainted
        """
        tainted = set()

        if isinstance(formula, Taint):
            var_name = self._get_var_name(formula.var)
            if var_name:
                tainted.add(var_name)
        elif isinstance(formula, Source):
            var_name = self._get_var_name(formula.var)
            if var_name:
                tainted.add(var_name)
        elif isinstance(formula, SepConj):
            tainted.update(self._collect_tainted_vars(formula.left))
            tainted.update(self._collect_tainted_vars(formula.right))
        elif isinstance(formula, And):
            tainted.update(self._collect_tainted_vars(formula.left))
            tainted.update(self._collect_tainted_vars(formula.right))
        elif isinstance(formula, Or):
            # Conservative: only include if tainted in BOTH branches
            left_tainted = self._collect_tainted_vars(formula.left)
            right_tainted = self._collect_tainted_vars(formula.right)
            tainted.update(left_tainted & right_tainted)

        return tainted

    def _contains_tainted_subexpr(self, expr: Expr, tainted_vars: Set[str]) -> bool:
        """Check if expression contains any tainted sub-expressions

        Args:
            expr: Expression to check
            tainted_vars: Set of known tainted variable names

        Returns:
            True if expr contains any tainted variables
        """
        if isinstance(expr, Var):
            return expr.name in tainted_vars
        elif isinstance(expr, StrConcat):
            return (self._contains_tainted_subexpr(expr.left, tainted_vars) or
                   self._contains_tainted_subexpr(expr.right, tainted_vars))
        elif isinstance(expr, StrSubstr):
            return self._contains_tainted_subexpr(expr.string, tainted_vars)
        return False

    def _infer_taint_propagation(self, formula: Formula, prefix: str = "") -> z3.BoolRef:
        """Infer taint propagation through string operations

        Implements automatic taint propagation rules:
        - If taint(x) and y = x ++ z, then taint(y)
        - If taint(x) and y = z ++ x, then taint(y)
        - If taint(x) and y = substr(x, ...), then taint(y)
        - If taint(x) and y = x, then taint(y)

        Args:
            formula: Formula to analyze
            prefix: Variable prefix for scoping

        Returns:
            Z3 constraints encoding taint propagation
        """
        # Collect tainted variables
        tainted_vars = self._collect_tainted_vars(formula)

        if not tainted_vars:
            return z3.BoolVal(True)

        # Collect equalities and propagate taint
        propagation_constraints = []

        def collect_equalities(f: Formula):
            """Recursively collect Eq formulas"""
            if isinstance(f, Eq):
                # Check if right side contains tainted expressions
                left_var = self._get_var_name(f.left)
                if left_var and self._contains_tainted_subexpr(f.right, tainted_vars):
                    # Left variable should be tainted too
                    propagation_constraints.append(
                        z3.IsMember(z3.StringVal(left_var), self.encoder.taint_set)
                    )
            elif isinstance(f, SepConj):
                collect_equalities(f.left)
                collect_equalities(f.right)
            elif isinstance(f, And):
                collect_equalities(f.left)
                collect_equalities(f.right)

        collect_equalities(formula)

        if propagation_constraints:
            return z3.And(propagation_constraints)
        else:
            return z3.BoolVal(True)

    def encode_formula(self, formula: Formula) -> Tuple[z3.BoolRef, z3.ExprRef, Set[z3.ExprRef]]:
        """
        Encode a complete separation logic formula.

        Returns:
            (pure_constraints, heap_id, domain): Pure Z3 constraints, top-level heap ID, and domain locations
        """
        # Create top-level heap ID (H0)
        top_heap_id = self.encoder.fresh_heap_id("H0")

        # Separate pure and spatial parts
        pure_part = self.extract_pure_part(formula)
        spatial_part = self.extract_spatial_part(formula)

        # Encode pure part
        pure_constraints = self.encode_pure(pure_part)

        # Encode spatial part with heap-relative semantics
        if spatial_part is not None:
            spatial_constraints, domain = self.encoder._spatial_encoder.encode_heap_assertion(
                spatial_part, top_heap_id, set()
            )
            combined_constraints = z3.And(pure_constraints, spatial_constraints)
        else:
            combined_constraints = pure_constraints
            domain = set()

        return (combined_constraints, top_heap_id, domain)

    def extract_pure_part(self, formula: Formula) -> Formula:
        """Extract the pure (non-spatial) part of a formula"""
        if not formula.is_spatial():
            return formula
        elif isinstance(formula, And):
            left = self.extract_pure_part(formula.left)
            right = self.extract_pure_part(formula.right)
            if left is not None and right is not None:
                return And(left, right)
            elif left is not None:
                return left
            elif right is not None:
                return right
        elif isinstance(formula, Not):
            # If inner formula is pure, the negation is also pure
            if not formula.formula.is_spatial():
                return formula
            # Otherwise, can't extract pure part from negation of spatial formula
            return True_()
        return True_()

    def extract_spatial_part(self, formula: Formula) -> Formula:
        """Extract the spatial part of a formula"""
        if isinstance(formula, (Emp, PointsTo, SepConj, Wand, PredicateCall)):
            return formula
        elif isinstance(formula, And):
            left = self.extract_spatial_part(formula.left)
            right = self.extract_spatial_part(formula.right)
            if left is not None and right is not None:
                # CRITICAL: Keep And as And, don't convert to SepConj!
                # And means both hold on SAME heap, SepConj means DISJOINT heaps
                return And(left, right)
            elif left is not None:
                return left
            elif right is not None:
                return right
        elif isinstance(formula, Or):
            # For Or, keep it as-is if either side is spatial
            # This allows Or with spatial formulas to be handled in encode_heap_assertion
            if formula.is_spatial():
                return formula
            return None
        elif isinstance(formula, Not):
            # If the inner formula is spatial, the whole Not is spatial
            if formula.formula.is_spatial():
                return formula
            # Otherwise, it's a pure negation
            return None
        return None

    def _has_existentials(self, formula: Formula) -> bool:
        """Check if a formula contains existential quantifiers"""
        if isinstance(formula, Exists):
            return True
        elif isinstance(formula, (And, Or, SepConj)):
            return self._has_existentials(formula.left) or self._has_existentials(formula.right)
        elif isinstance(formula, Not):
            return self._has_existentials(formula.formula)
        elif isinstance(formula, Forall):
            return self._has_existentials(formula.formula)
        return False

    def encode_entailment(self, antecedent: Formula, consequent: Formula) -> z3.BoolRef:
        """Delegate to entailment encoding helper"""
        return _encode_entailment_impl(self, antecedent, consequent)


    def _has_syntactic_allocations(self, formula: Formula) -> bool:
        """
        Syntactic check: does formula definitely allocate heap cells?

        Returns True if formula syntactically contains:
        - PointsTo assertions
        - PredicateCall that is known to be non-empty

        Returns False if uncertain (e.g., predicate that could be empty)
        """
        if formula is None or isinstance(formula, (Emp, True_, False_)):
            return False

        if isinstance(formula, PointsTo):
            return True  # Definitely allocates

        if isinstance(formula, PredicateCall):
            # Most predicates can be empty (e.g., list(nil), ls(x,x))
            # Return False to be conservative (will use semantic check)
            return False

        if isinstance(formula, (SepConj, And, Or)):
            # If either side definitely allocates, the whole formula does
            left_alloc = self._has_syntactic_allocations(formula.left)
            right_alloc = self._has_syntactic_allocations(formula.right)

            if isinstance(formula, SepConj):
                # P * Q allocates if P or Q allocates
                return left_alloc or right_alloc
            elif isinstance(formula, And):
                # P & Q allocates if either P or Q allocates (spatial part)
                return left_alloc or right_alloc
            elif isinstance(formula, Or):
                # P | Q allocates if both branches allocate
                return left_alloc and right_alloc

        if isinstance(formula, Not):
            # ¬P is tricky; conservatively say no
            return False

        return False
