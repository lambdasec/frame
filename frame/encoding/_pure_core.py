"""
Core Pure Encoding Functions

Extracted from _pure.py to reduce file size.
Contains the main encode_pure() and encode_entailment() implementations.
"""

import z3
from typing import Set, Tuple
from frame.core.ast import (
    Formula, Expr, Var, Const, Emp, PointsTo, SepConj, Wand, And, Or, Not,
    Eq, Neq, Lt, Le, Gt, Ge, True_, False_, Exists, Forall, PredicateCall,
    StrLiteral, StrConcat, StrLen, StrSubstr, StrContains, StrMatches,
    Taint, Sanitized, Source, Sink,
    Error, NullDeref, UseAfterFree, BufferOverflow,
    Allocated, Freed, ArrayPointsTo, ArrayBounds,
    TaintedArray, BufferOverflowCheck, IntegerOverflow
)


def encode_pure(
    encoder_self,
    formula: Formula,
    prefix: str = ""
) -> z3.BoolRef:
    """Encode a pure (non-spatial) formula to Z3

    Args:
        encoder_self: The PureEncoder instance
        formula: Formula to encode
        prefix: Variable prefix for scoping
    """
    if isinstance(formula, True_):
        return z3.BoolVal(True)

    elif isinstance(formula, False_):
        return z3.BoolVal(False)

    elif isinstance(formula, Eq):
        # Check if either side is a string expression
        if encoder_self.encoder._is_string_expr(formula.left) or encoder_self.encoder._is_string_expr(formula.right):
            # Encode both sides as strings
            left = encoder_self.encoder.encode_string_expr(formula.left, prefix=prefix)
            right = encoder_self.encoder.encode_string_expr(formula.right, prefix=prefix)
        # Check if either side is a bitvector expression
        elif encoder_self.encoder._is_bitvec_expr(formula.left) or encoder_self.encoder._is_bitvec_expr(formula.right):
            # Encode both sides as bitvectors
            # Determine the width from whichever side is a bitvector
            width = encoder_self.encoder._get_bitvec_width(formula.left) or encoder_self.encoder._get_bitvec_width(formula.right)
            if width is None:
                width = 32  # Default width if not specified
            left = encoder_self.encoder.encode_bitvec_expr(formula.left, width, prefix=prefix)
            right = encoder_self.encoder.encode_bitvec_expr(formula.right, width, prefix=prefix)
        else:
            # Regular (integer/location) equality
            left = encoder_self.encoder.encode_expr(formula.left, prefix=prefix)
            right = encoder_self.encoder.encode_expr(formula.right, prefix=prefix)
        return left == right

    elif isinstance(formula, Neq):
        # Handle bitvectors similar to Eq
        if encoder_self.encoder._is_bitvec_expr(formula.left) or encoder_self.encoder._is_bitvec_expr(formula.right):
            width = encoder_self.encoder._get_bitvec_width(formula.left) or encoder_self.encoder._get_bitvec_width(formula.right)
            if width is None:
                width = 32  # Default width if not specified
            left = encoder_self.encoder.encode_bitvec_expr(formula.left, width, prefix=prefix)
            right = encoder_self.encoder.encode_bitvec_expr(formula.right, width, prefix=prefix)
        else:
            left = encoder_self.encoder.encode_expr(formula.left, prefix=prefix)
            right = encoder_self.encoder.encode_expr(formula.right, prefix=prefix)
        return left != right

    elif isinstance(formula, Lt):
        left = encoder_self.encoder.encode_expr(formula.left, prefix=prefix)
        right = encoder_self.encoder.encode_expr(formula.right, prefix=prefix)
        return left < right

    elif isinstance(formula, Le):
        left = encoder_self.encoder.encode_expr(formula.left, prefix=prefix)
        right = encoder_self.encoder.encode_expr(formula.right, prefix=prefix)
        return left <= right

    elif isinstance(formula, Gt):
        left = encoder_self.encoder.encode_expr(formula.left, prefix=prefix)
        right = encoder_self.encoder.encode_expr(formula.right, prefix=prefix)
        return left > right

    elif isinstance(formula, Ge):
        left = encoder_self.encoder.encode_expr(formula.left, prefix=prefix)
        right = encoder_self.encoder.encode_expr(formula.right, prefix=prefix)
        return left >= right

    elif isinstance(formula, And):
        left = encoder_self.encode_pure(formula.left, prefix=prefix) if not formula.left.is_spatial() else z3.BoolVal(True)
        right = encoder_self.encode_pure(formula.right, prefix=prefix) if not formula.right.is_spatial() else z3.BoolVal(True)
        return z3.And(left, right)

    elif isinstance(formula, Or):
        left = encoder_self.encode_pure(formula.left, prefix=prefix) if not formula.left.is_spatial() else z3.BoolVal(True)
        right = encoder_self.encode_pure(formula.right, prefix=prefix) if not formula.right.is_spatial() else z3.BoolVal(True)
        return z3.Or(left, right)

    elif isinstance(formula, SepConj):
        # SepConj can contain pure formulas too (like taint tracking)
        # Encode both sides and combine with And
        left = encoder_self.encode_pure(formula.left, prefix=prefix)
        right = encoder_self.encode_pure(formula.right, prefix=prefix)
        return z3.And(left, right)

    elif isinstance(formula, Not):
        inner = encoder_self.encode_pure(formula.formula, prefix=prefix)
        return z3.Not(inner)

    # String formulas
    elif isinstance(formula, StrContains):
        haystack = encoder_self.encoder.encode_string_expr(formula.haystack, prefix=prefix)
        needle = encoder_self.encoder.encode_string_expr(formula.needle, prefix=prefix)
        return z3.Contains(haystack, needle)

    elif isinstance(formula, StrMatches):
        string = encoder_self.encoder.encode_string_expr(formula.string, prefix=prefix)
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
        var_name = encoder_self._get_var_name(formula.var)
        if var_name:
            return z3.IsMember(z3.StringVal(var_name), encoder_self.encoder.taint_set)
        else:
            # Complex expression - conservatively assume not tainted
            return z3.BoolVal(False)

    elif isinstance(formula, Sanitized):
        # Sanitized(var) means var is NOT in the taint set
        var_name = encoder_self._get_var_name(formula.var)
        if var_name:
            return z3.Not(z3.IsMember(z3.StringVal(var_name), encoder_self.encoder.taint_set))
        else:
            # Complex expression - conservatively assume sanitized
            return z3.BoolVal(True)

    elif isinstance(formula, Source):
        # Source(var, type) tracks taint source
        var_name = encoder_self._get_var_name(formula.var)
        if var_name:
            encoder_self.encoder.sources[var_name] = formula.source_type
            # Also mark as tainted
            return z3.IsMember(z3.StringVal(var_name), encoder_self.encoder.taint_set)
        return z3.BoolVal(True)

    elif isinstance(formula, Sink):
        # Sink(var, type) tracks taint sink
        var_name = encoder_self._get_var_name(formula.var)
        if var_name:
            encoder_self.encoder.sinks[var_name] = formula.sink_type
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
        var_z3 = encoder_self.encoder.encode_expr(formula.var, prefix=prefix)
        return var_z3 == z3.IntVal(encoder_self.encoder.nil)

    elif isinstance(formula, UseAfterFree):
        # use_after_free(var) means var is in freed_set AND we try to access it
        # The dereference part is handled by spatial formulas
        # Here we just check if it's freed
        var_z3 = encoder_self.encoder.encode_expr(formula.var, prefix=prefix)
        return z3.IsMember(var_z3, encoder_self.encoder.freed_set)

    elif isinstance(formula, BufferOverflow):
        # buffer_overflow(arr, index, size) means index >= size
        index_z3 = encoder_self.encoder.encode_expr(formula.index, prefix=prefix)
        size_z3 = encoder_self.encoder.encode_expr(formula.size, prefix=prefix)
        return index_z3 >= size_z3

    # Heap lifecycle predicates
    elif isinstance(formula, Allocated):
        # allocated(ptr) means ptr is in allocated_set (and not in freed_set)
        ptr_z3 = encoder_self.encoder.encode_expr(formula.ptr, prefix=prefix)
        return z3.And(
            z3.IsMember(ptr_z3, encoder_self.encoder.allocated_set),
            z3.Not(z3.IsMember(ptr_z3, encoder_self.encoder.freed_set))
        )

    elif isinstance(formula, Freed):
        # freed(ptr) means ptr is in freed_set (and not in allocated_set)
        ptr_z3 = encoder_self.encoder.encode_expr(formula.ptr, prefix=prefix)
        return z3.And(
            z3.IsMember(ptr_z3, encoder_self.encoder.freed_set),
            z3.Not(z3.IsMember(ptr_z3, encoder_self.encoder.allocated_set))
        )

    elif isinstance(formula, ArrayBounds):
        # bounds(array, size) constrains the size of an array
        # Use array_size function to track sizes - this allows Z3 to infer that
        # if arr1 = arr2, then array_size(arr1) = array_size(arr2)
        array_z3 = encoder_self.encoder.encode_expr(formula.array, prefix=prefix)
        size_z3 = encoder_self.encoder.encode_expr(formula.size, prefix=prefix)
        return encoder_self.encoder.array_size_fn(array_z3) == size_z3

    # Array and bitvector security predicates
    elif isinstance(formula, TaintedArray):
        # TaintedArray(arr, indices) means some array elements are tainted
        # We track this by checking if ANY of the specified indices contain tainted data
        array_z3 = encoder_self.encoder._encode_array_expr(formula.array, prefix=prefix)

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
                idx_z3 = encoder_self.encoder.encode_expr(idx, prefix=prefix)
                value_z3 = z3.Select(array_z3, idx_z3)
                # Value is tainted (implementation-specific)
                # For now, we mark it in a separate tracking structure
                constraints.append(z3.BoolVal(True))  # Placeholder
            return z3.Or(*constraints) if constraints else z3.BoolVal(False)

    elif isinstance(formula, BufferOverflowCheck):
        # BufferOverflowCheck(arr, index, size) verifies: 0 <= index < size
        index_z3 = encoder_self.encoder.encode_expr(formula.index, prefix=prefix)
        size_z3 = encoder_self.encoder.encode_expr(formula.size, prefix=prefix)

        # Convert bitvector indices to integers for comparison
        if encoder_self.encoder._is_bitvec_expr(formula.index):
            index_z3 = z3.BV2Int(index_z3)

        # Safe access: index in bounds
        in_bounds = z3.And(
            index_z3 >= 0,
            index_z3 < size_z3
        )
        return in_bounds

    elif isinstance(formula, IntegerOverflow):
        # IntegerOverflow(op, operands, width, signed) detects overflow
        ops_z3 = [encoder_self.encoder.encode_expr(op, prefix=prefix) for op in formula.operands]
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



def encode_entailment(
    encoder_self,
    antecedent: Formula,
    consequent: Formula
) -> z3.BoolRef:
    """
    Encode an entailment check: antecedent |- consequent

    We check if: antecedent => consequent
    This is done by checking if antecedent & !consequent is UNSAT

    Special handling for P => emp: must verify P implies no allocated locations.

    Variable scoping: Pure formulas (arithmetic, equalities) use NO prefix because
    they represent global constraints about the same logical variables. Spatial
    formulas use prefix="cons_" for consequent to distinguish heap structures.
    """
    # Create heap IDs for antecedent and consequent
    # Both use the same top-level heap ID for entailment checking
    heap_id = encoder_self.encoder.fresh_heap_id("Hent")

    # Encode antecedent with empty prefix (original variable names)
    ante_pure = encoder_self.extract_pure_part(antecedent)
    ante_spatial = encoder_self.extract_spatial_part(antecedent)

    # CRITICAL: Pure formulas should NOT use prefixes - they represent global
    # constraints about the same variables in both antecedent and consequent
    ante_constraints = encoder_self.encode_pure(ante_pure, prefix="")

    # Add automatic taint propagation inference for antecedent
    ante_taint_propagation = encoder_self._infer_taint_propagation(antecedent, prefix="")
    ante_constraints = z3.And(ante_constraints, ante_taint_propagation)

    if ante_spatial is not None:
        ante_heap_constraints, ante_domain = encoder_self.encoder.encode_heap_assertion(
            ante_spatial, heap_id, set(), prefix=""
        )
        ante_constraints = z3.And(ante_constraints, ante_heap_constraints)
    else:
        ante_domain = set()

    # Encode consequent
    cons_pure = encoder_self.extract_pure_part(consequent)
    cons_spatial = encoder_self.extract_spatial_part(consequent)

    # CRITICAL FIX: Pure formulas use NO prefix (same variables as antecedent)
    # Only spatial formulas use "cons_" prefix to distinguish heap structures
    cons_constraints = encoder_self.encode_pure(cons_pure, prefix="")

    # Add automatic taint propagation inference for consequent
    cons_taint_propagation = encoder_self._infer_taint_propagation(consequent, prefix="")
    cons_constraints = z3.And(cons_constraints, cons_taint_propagation)

    if cons_spatial is not None:
        # CRITICAL FIX (Nov 2025): Use NO prefix for consequent spatial encoding
        #
        # Previously we used prefix="cons_" which caused variables in the consequent
        # to be prefixed (e.g., x became cons_x). This meant the antecedent's x and
        # consequent's cons_x were DIFFERENT Z3 variables, breaking entailment checking.
        #
        # For entailment P(x) |- Q(x), the x in both must be the SAME variable.
        # The prefix was intended to distinguish heap structures, but it incorrectly
        # prefixed all variables including those from the original formula.
        #
        # The fix: Use empty prefix so variables are shared between antecedent and consequent.
        cons_heap_constraints, cons_domain = encoder_self.encoder.encode_heap_assertion(
            cons_spatial, heap_id, set(), prefix=""
        )
        cons_constraints = z3.And(cons_constraints, cons_heap_constraints)
    else:
        cons_domain = set()

    # NOTE: Footprint-aware affine weakening is handled at the frame rule level
    # in checker.py using FootprintAnalyzer. This allows safe weakening while
    # preventing soundness bugs like x |-> y * list(z) ⊢ list(z).

    # CRITICAL FIX (Nov 2025): Handle P |- emp correctly
    #
    # When the consequent is emp (empty heap), we must verify that the antecedent
    # has NO allocations. The issue was that emp encodes as z3.BoolVal(True),
    # making any entailment P |- emp trivially valid (since X => True is always true).
    #
    # The fix: When cons_spatial is emp (or consequent is pure-only), we must
    # verify that the antecedent's domain is empty. We do this by adding constraints
    # that any alloc boolean tracked by the antecedent must be false.
    #
    # This fixes false positives like: ls(x, nil) |- emp being marked valid
    # when it should be invalid (ls could have non-empty heap if x != nil).

    # Check if consequent spatial part is emp or None (pure-only)
    # CRITICAL FIX (Dec 2025): Also detect when formula effectively simplifies to emp
    # For example: Or(And(x=x, emp), And(x!=x, stuff)) simplifies to emp because
    # the second branch has x!=x which is always false
    from frame.core.ast import Emp
    consequent_is_emp = (cons_spatial is None or
                         isinstance(cons_spatial, Emp) or
                         _is_effectively_emp(cons_spatial))

    if consequent_is_emp and ante_spatial is not None:
        # Consequent expects empty heap, so antecedent must have empty domain
        # Get all alloc booleans that were set during antecedent encoding
        # Access via encoder -> _spatial_encoder -> alloc_map
        alloc_map = encoder_self.encoder._spatial_encoder.alloc_map

        if alloc_map:
            # Add constraint: all alloc booleans must be false for the entailment to hold
            # This means: if any location is allocated, the entailment fails
            all_unallocated = z3.And([z3.Not(alloc) for alloc in alloc_map.values()])
            # The entailment is: ante => (cons AND all_unallocated)
            # Or equivalently: if antecedent holds, then no locations are allocated
            cons_constraints = z3.And(cons_constraints, all_unallocated)

    # Standard entailment check: ante_constraints => cons_constraints
    entailment = z3.Implies(ante_constraints, cons_constraints)

    return entailment


def _is_effectively_emp(formula: Formula) -> bool:
    """
    Check if a formula effectively simplifies to emp.

    This handles cases like:
    - Or(And(x=x, emp), And(x!=x, stuff)) -> emp (second branch is always false)
    - And(True_, emp) -> emp
    - Or(emp, false) -> emp

    Critical for fixing false positives like:
      (heap_cells) |- dll(x, y, y, x)
    where dll(x, y, y, x) simplifies to emp because the base case
    has conditions x=x and y=y which are always true.
    """
    if formula is None:
        return False

    if isinstance(formula, Emp):
        return True

    if isinstance(formula, And):
        # And(pure, emp) -> emp if pure is trivially true
        # And(emp, pure) -> emp if pure is trivially true
        left_is_emp = isinstance(formula.left, Emp) or _is_effectively_emp(formula.left)
        right_is_emp = isinstance(formula.right, Emp) or _is_effectively_emp(formula.right)

        if left_is_emp and _is_trivially_true(formula.right):
            return True
        if right_is_emp and _is_trivially_true(formula.left):
            return True
        # Both sides are emp is still emp
        if left_is_emp and right_is_emp:
            return True
        return False

    if isinstance(formula, Or):
        # Or(emp_branch, false_branch) -> emp
        # Check if one branch is emp and other is trivially false
        left_is_emp = _is_effectively_emp(formula.left)
        right_is_emp = _is_effectively_emp(formula.right)
        left_is_false = _is_trivially_false(formula.left)
        right_is_false = _is_trivially_false(formula.right)

        if left_is_emp and right_is_false:
            return True
        if right_is_emp and left_is_false:
            return True
        return False

    if isinstance(formula, Exists):
        # exists x. (false & stuff) -> false, not emp
        # exists x. (emp & stuff) -> might be emp if stuff is true
        if _is_trivially_false(formula.formula):
            return False  # The whole exists is false, not emp
        return _is_effectively_emp(formula.formula)

    return False


def _is_trivially_true(formula: Formula) -> bool:
    """Check if a formula is trivially true (e.g., x=x, true)"""
    if formula is None:
        return True

    if isinstance(formula, True_):
        return True

    if isinstance(formula, Emp):
        # emp is spatially "true" for empty heap
        return True

    if isinstance(formula, Eq):
        # x = x is always true
        if isinstance(formula.left, Var) and isinstance(formula.right, Var):
            if formula.left.name == formula.right.name:
                return True
        if isinstance(formula.left, Const) and isinstance(formula.right, Const):
            if formula.left.value == formula.right.value:
                return True
        return False

    if isinstance(formula, And):
        return _is_trivially_true(formula.left) and _is_trivially_true(formula.right)

    return False


def _is_trivially_false(formula: Formula) -> bool:
    """Check if a formula is trivially false (e.g., x!=x, false)"""
    if formula is None:
        return False

    if isinstance(formula, False_):
        return True

    if isinstance(formula, Neq):
        # x != x is always false
        if isinstance(formula.left, Var) and isinstance(formula.right, Var):
            if formula.left.name == formula.right.name:
                return True
        if isinstance(formula.left, Const) and isinstance(formula.right, Const):
            if formula.left.value == formula.right.value:
                return True
        return False

    if isinstance(formula, And):
        # And is false if either side is false
        return _is_trivially_false(formula.left) or _is_trivially_false(formula.right)

    if isinstance(formula, Exists):
        # exists x. false -> false
        return _is_trivially_false(formula.formula)

    return False

