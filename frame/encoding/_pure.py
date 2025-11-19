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


class PureEncoder:
    """Encoder for pure (non-spatial) formulas and high-level encoding"""

    def __init__(self, main_encoder):
        """Initialize with reference to main Z3Encoder"""
        self.encoder = main_encoder

    def encode_pure(self, formula: Formula, prefix: str = "") -> z3.BoolRef:
        """Encode a pure (non-spatial) formula to Z3

        Args:
            formula: Formula to encode
            prefix: Variable prefix for scoping
        """
        if isinstance(formula, True_):
            return z3.BoolVal(True)

        elif isinstance(formula, False_):
            return z3.BoolVal(False)

        elif isinstance(formula, Eq):
            # Check if either side is a string expression
            if self.encoder._is_string_expr(formula.left) or self.encoder._is_string_expr(formula.right):
                # Encode both sides as strings
                left = self.encoder.encode_string_expr(formula.left, prefix=prefix)
                right = self.encoder.encode_string_expr(formula.right, prefix=prefix)
            # Check if either side is a bitvector expression
            elif self.encoder._is_bitvec_expr(formula.left) or self.encoder._is_bitvec_expr(formula.right):
                # Encode both sides as bitvectors
                # Determine the width from whichever side is a bitvector
                width = self.encoder._get_bitvec_width(formula.left) or self.encoder._get_bitvec_width(formula.right)
                if width is None:
                    width = 32  # Default width if not specified
                left = self.encoder.encode_bitvec_expr(formula.left, width, prefix=prefix)
                right = self.encoder.encode_bitvec_expr(formula.right, width, prefix=prefix)
            else:
                # Regular (integer/location) equality
                left = self.encoder.encode_expr(formula.left, prefix=prefix)
                right = self.encoder.encode_expr(formula.right, prefix=prefix)
            return left == right

        elif isinstance(formula, Neq):
            # Handle bitvectors similar to Eq
            if self.encoder._is_bitvec_expr(formula.left) or self.encoder._is_bitvec_expr(formula.right):
                width = self.encoder._get_bitvec_width(formula.left) or self.encoder._get_bitvec_width(formula.right)
                if width is None:
                    width = 32  # Default width if not specified
                left = self.encoder.encode_bitvec_expr(formula.left, width, prefix=prefix)
                right = self.encoder.encode_bitvec_expr(formula.right, width, prefix=prefix)
            else:
                left = self.encoder.encode_expr(formula.left, prefix=prefix)
                right = self.encoder.encode_expr(formula.right, prefix=prefix)
            return left != right

        elif isinstance(formula, Lt):
            left = self.encoder.encode_expr(formula.left, prefix=prefix)
            right = self.encoder.encode_expr(formula.right, prefix=prefix)
            return left < right

        elif isinstance(formula, Le):
            left = self.encoder.encode_expr(formula.left, prefix=prefix)
            right = self.encoder.encode_expr(formula.right, prefix=prefix)
            return left <= right

        elif isinstance(formula, Gt):
            left = self.encoder.encode_expr(formula.left, prefix=prefix)
            right = self.encoder.encode_expr(formula.right, prefix=prefix)
            return left > right

        elif isinstance(formula, Ge):
            left = self.encoder.encode_expr(formula.left, prefix=prefix)
            right = self.encoder.encode_expr(formula.right, prefix=prefix)
            return left >= right

        elif isinstance(formula, And):
            left = self.encode_pure(formula.left, prefix=prefix) if not formula.left.is_spatial() else z3.BoolVal(True)
            right = self.encode_pure(formula.right, prefix=prefix) if not formula.right.is_spatial() else z3.BoolVal(True)
            return z3.And(left, right)

        elif isinstance(formula, Or):
            left = self.encode_pure(formula.left, prefix=prefix) if not formula.left.is_spatial() else z3.BoolVal(True)
            right = self.encode_pure(formula.right, prefix=prefix) if not formula.right.is_spatial() else z3.BoolVal(True)
            return z3.Or(left, right)

        elif isinstance(formula, SepConj):
            # SepConj can contain pure formulas too (like taint tracking)
            # Encode both sides and combine with And
            left = self.encode_pure(formula.left, prefix=prefix)
            right = self.encode_pure(formula.right, prefix=prefix)
            return z3.And(left, right)

        elif isinstance(formula, Not):
            inner = self.encode_pure(formula.formula, prefix=prefix)
            return z3.Not(inner)

        # String formulas
        elif isinstance(formula, StrContains):
            haystack = self.encoder.encode_string_expr(formula.haystack, prefix=prefix)
            needle = self.encoder.encode_string_expr(formula.needle, prefix=prefix)
            return z3.Contains(haystack, needle)

        elif isinstance(formula, StrMatches):
            string = self.encoder.encode_string_expr(formula.string, prefix=prefix)
            # Convert regex string to Z3 regex using proper parser
            try:
                from frame.encoding.regex_parser import parse_regex
                regex = parse_regex(formula.regex)
                return z3.InRe(string, regex)
            except Exception as e:
                # If regex parsing fails, just return true (conservative)
                # In production, we'd want better error handling
                import warnings
                warnings.warn(f"Failed to parse regex '{formula.regex}': {e}")
                return z3.BoolVal(True)

        # Security and taint tracking
        elif isinstance(formula, Taint):
            # Taint(var) means var is in the taint set
            var_name = self._get_var_name(formula.var)
            if var_name:
                return z3.IsMember(z3.StringVal(var_name), self.encoder.taint_set)
            else:
                # Complex expression - conservatively assume not tainted
                return z3.BoolVal(False)

        elif isinstance(formula, Sanitized):
            # Sanitized(var) means var is NOT in the taint set
            var_name = self._get_var_name(formula.var)
            if var_name:
                return z3.Not(z3.IsMember(z3.StringVal(var_name), self.encoder.taint_set))
            else:
                # Complex expression - conservatively assume sanitized
                return z3.BoolVal(True)

        elif isinstance(formula, Source):
            # Source(var, type) tracks taint source
            var_name = self._get_var_name(formula.var)
            if var_name:
                self.encoder.sources[var_name] = formula.source_type
                # Also mark as tainted
                return z3.IsMember(z3.StringVal(var_name), self.encoder.taint_set)
            return z3.BoolVal(True)

        elif isinstance(formula, Sink):
            # Sink(var, type) tracks taint sink
            var_name = self._get_var_name(formula.var)
            if var_name:
                self.encoder.sinks[var_name] = formula.sink_type
                # Sink itself doesn't constrain anything, just marks it
                return z3.BoolVal(True)
            return z3.BoolVal(True)

        # Error states (for incorrectness logic)
        elif isinstance(formula, Error):
            # Error states are markers - they don't constrain the model
            # In incorrectness logic, we'd check SAT with error reachable
            return z3.BoolVal(True)

        elif isinstance(formula, NullDeref):
            # null_deref(ptr) is reachable if ptr == nil
            var_z3 = self.encoder.encode_expr(formula.var, prefix=prefix)
            return var_z3 == z3.IntVal(self.encoder.nil)

        elif isinstance(formula, UseAfterFree):
            # use_after_free(var) means var is in freed_set AND we try to access it
            # The dereference part is handled by spatial formulas
            # Here we just check if it's freed
            var_z3 = self.encoder.encode_expr(formula.var, prefix=prefix)
            return z3.IsMember(var_z3, self.encoder.freed_set)

        elif isinstance(formula, BufferOverflow):
            # buffer_overflow(arr, index, size) means index >= size
            index_z3 = self.encoder.encode_expr(formula.index, prefix=prefix)
            size_z3 = self.encoder.encode_expr(formula.size, prefix=prefix)
            return index_z3 >= size_z3

        # Heap lifecycle predicates
        elif isinstance(formula, Allocated):
            # allocated(ptr) means ptr is in allocated_set (and not in freed_set)
            ptr_z3 = self.encoder.encode_expr(formula.ptr, prefix=prefix)
            return z3.And(
                z3.IsMember(ptr_z3, self.encoder.allocated_set),
                z3.Not(z3.IsMember(ptr_z3, self.encoder.freed_set))
            )

        elif isinstance(formula, Freed):
            # freed(ptr) means ptr is in freed_set (and not in allocated_set)
            ptr_z3 = self.encoder.encode_expr(formula.ptr, prefix=prefix)
            return z3.And(
                z3.IsMember(ptr_z3, self.encoder.freed_set),
                z3.Not(z3.IsMember(ptr_z3, self.encoder.allocated_set))
            )

        elif isinstance(formula, ArrayBounds):
            # bounds(array, size) constrains the size of an array
            # Use array_size function to track sizes - this allows Z3 to infer that
            # if arr1 = arr2, then array_size(arr1) = array_size(arr2)
            array_z3 = self.encoder.encode_expr(formula.array, prefix=prefix)
            size_z3 = self.encoder.encode_expr(formula.size, prefix=prefix)
            return self.encoder.array_size_fn(array_z3) == size_z3

        # Array and bitvector security predicates
        elif isinstance(formula, TaintedArray):
            # TaintedArray(arr, indices) means some array elements are tainted
            # We track this by checking if ANY of the specified indices contain tainted data
            array_z3 = self.encoder._encode_array_expr(formula.array, prefix=prefix)

            if formula.tainted_indices is None:
                # Unknown which indices - conservatively assume some are tainted
                # Create existential: exists i. tainted(array[i])
                return z3.BoolVal(True)  # Conservative approximation
            elif len(formula.tainted_indices) == 0:
                # No tainted indices
                return z3.BoolVal(False)
            else:
                # Check if any specified index has tainted value
                constraints = []
                for idx in formula.tainted_indices:
                    idx_z3 = self.encoder.encode_expr(idx, prefix=prefix)
                    value_z3 = z3.Select(array_z3, idx_z3)
                    # Value is tainted (implementation-specific)
                    # For now, we mark it in a separate tracking structure
                    constraints.append(z3.BoolVal(True))  # Placeholder
                return z3.Or(*constraints) if constraints else z3.BoolVal(False)

        elif isinstance(formula, BufferOverflowCheck):
            # BufferOverflowCheck(arr, index, size) verifies: 0 <= index < size
            index_z3 = self.encoder.encode_expr(formula.index, prefix=prefix)
            size_z3 = self.encoder.encode_expr(formula.size, prefix=prefix)

            # Convert bitvector indices to integers for comparison
            if self.encoder._is_bitvec_expr(formula.index):
                index_z3 = z3.BV2Int(index_z3)

            # Safe access: index in bounds
            in_bounds = z3.And(
                index_z3 >= 0,
                index_z3 < size_z3
            )
            return in_bounds

        elif isinstance(formula, IntegerOverflow):
            # IntegerOverflow(op, operands, width, signed) detects overflow
            ops_z3 = [self.encoder.encode_expr(op, prefix=prefix) for op in formula.operands]
            width = formula.width
            signed = formula.signed

            if formula.op == 'add':
                if signed:
                    # Signed overflow: result doesn't fit in width bits
                    # For signed addition: overflow if signs match but result sign differs
                    if len(ops_z3) == 2:
                        result = ops_z3[0] + ops_z3[1]
                        max_val = 2**(width-1) - 1
                        min_val = -(2**(width-1))
                        return z3.Or(result > max_val, result < min_val)
                else:
                    # Unsigned overflow: result > 2^width - 1
                    result = ops_z3[0] + ops_z3[1]
                    max_val = 2**width - 1
                    return result > max_val

            elif formula.op == 'sub':
                if signed:
                    result = ops_z3[0] - ops_z3[1]
                    max_val = 2**(width-1) - 1
                    min_val = -(2**(width-1))
                    return z3.Or(result > max_val, result < min_val)
                else:
                    result = ops_z3[0] - ops_z3[1]
                    return result < 0  # Unsigned underflow

            elif formula.op == 'mul':
                if signed:
                    result = ops_z3[0] * ops_z3[1]
                    max_val = 2**(width-1) - 1
                    min_val = -(2**(width-1))
                    return z3.Or(result > max_val, result < min_val)
                else:
                    result = ops_z3[0] * ops_z3[1]
                    max_val = 2**width - 1
                    return result > max_val

            else:
                # Unsupported operation - conservatively return false
                return z3.BoolVal(False)

        else:
            # For spatial formulas, return true (handled separately)
            return z3.BoolVal(True)

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
        """
        Encode an entailment check: antecedent |- consequent

        We check if: antecedent => consequent
        This is done by checking if antecedent & !consequent is UNSAT

        Special handling for P ⊢ emp: must verify P implies no allocated locations.

        Variable scoping: Pure formulas (arithmetic, equalities) use NO prefix because
        they represent global constraints about the same logical variables. Spatial
        formulas use prefix="cons_" for consequent to distinguish heap structures.
        """
        # Create heap IDs for antecedent and consequent
        # Both use the same top-level heap ID for entailment checking
        heap_id = self.encoder.fresh_heap_id("Hent")

        # Encode antecedent with empty prefix (original variable names)
        ante_pure = self.extract_pure_part(antecedent)
        ante_spatial = self.extract_spatial_part(antecedent)

        # CRITICAL: Pure formulas should NOT use prefixes - they represent global
        # constraints about the same variables in both antecedent and consequent
        ante_constraints = self.encode_pure(ante_pure, prefix="")

        # Add automatic taint propagation inference for antecedent
        ante_taint_propagation = self._infer_taint_propagation(antecedent, prefix="")
        ante_constraints = z3.And(ante_constraints, ante_taint_propagation)

        if ante_spatial is not None:
            ante_heap_constraints, ante_domain = self.encoder.encode_heap_assertion(
                ante_spatial, heap_id, set(), prefix=""
            )
            ante_constraints = z3.And(ante_constraints, ante_heap_constraints)
        else:
            ante_domain = set()

        # Encode consequent
        cons_pure = self.extract_pure_part(consequent)
        cons_spatial = self.extract_spatial_part(consequent)

        # CRITICAL FIX: Pure formulas use NO prefix (same variables as antecedent)
        # Only spatial formulas use "cons_" prefix to distinguish heap structures
        cons_constraints = self.encode_pure(cons_pure, prefix="")

        # Add automatic taint propagation inference for consequent
        cons_taint_propagation = self._infer_taint_propagation(consequent, prefix="")
        cons_constraints = z3.And(cons_constraints, cons_taint_propagation)

        if cons_spatial is not None:
            cons_heap_constraints, cons_domain = self.encoder.encode_heap_assertion(
                cons_spatial, heap_id, set(), prefix="cons_"
            )
            cons_constraints = z3.And(cons_constraints, cons_heap_constraints)
        else:
            cons_domain = set()

        # NOTE: Footprint-aware affine weakening is handled at the frame rule level
        # in checker.py using FootprintAnalyzer. This allows safe weakening while
        # preventing soundness bugs like x |-> y * list(z) ⊢ list(z).

        # Standard entailment check: ante_constraints => cons_constraints
        entailment = z3.Implies(ante_constraints, cons_constraints)

        return entailment

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
