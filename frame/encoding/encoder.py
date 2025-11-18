"""
Z3 Encoder for Separation Logic

This module encodes separation logic formulas into Z3 SMT constraints.
The heap is represented as an array from locations to values, and we track
the domain (allocated locations) explicitly.
"""

import z3
from typing import Dict, Set, Tuple, List, Optional
from frame.core.ast import (
    Formula, Expr, Var, Const, Emp, PointsTo, SepConj, Wand, And, Or, Not,
    Eq, Neq, Lt, Le, Gt, Ge, True_, False_, Exists, Forall, PredicateCall,
    # String expressions and formulas
    StrLiteral, StrConcat, StrLen, StrSubstr, StrContains, StrMatches,
    # Security and taint tracking
    Taint, Sanitized, Source, Sink,
    # Error states
    Error, NullDeref, UseAfterFree, BufferOverflow,
    # Heap lifecycle and arrays
    Allocated, Freed, ArrayPointsTo, ArrayBounds,
    # Array theory
    ArraySelect, ArrayStore, ArrayConst,
    # Bitvector theory
    BitVecVal, BitVecExpr,
    # Array and bitvector security
    TaintedArray, BufferOverflowCheck, IntegerOverflow
)
from frame.encoding._spatial import SpatialEncoder


class Z3Encoder:
    """Encodes separation logic formulas into Z3 constraints"""

    def __init__(self):
        # Z3 sort for locations (integers)
        self.LocSort = z3.IntSort()
        # Z3 sort for values (integers)
        self.ValSort = z3.IntSort()
        # Special nil value
        self.nil = 0
        # Counter for generating fresh variables
        self.fresh_counter = 0
        # Variable cache
        self.var_cache: Dict[str, z3.ExprRef] = {}

        # HEAP-RELATIVE ENCODING (for correct negation semantics)
        # HeapId sort for representing heap fragments
        self.HeapIdSort = z3.DeclareSort('HeapId')
        # alloc(heap_id, loc) -> Bool: is location allocated in this heap fragment?
        self.alloc = z3.Function('alloc', self.HeapIdSort, self.LocSort, z3.BoolSort())
        # hval(heap_id, loc) -> Val: what value is stored at location in this heap fragment?
        self.hval = z3.Function('hval', self.HeapIdSort, self.LocSort, self.ValSort)
        # rank(loc) -> Int: GLOBAL rank function for acyclicity constraints
        # NOTE: rank is global, not per-heap-fragment, because acyclicity is a global property
        # Even though allocations are split across heap fragments, the rank ordering must be consistent
        self.rank = z3.Function('rank', self.LocSort, z3.IntSort())
        # Counter for fresh heap IDs
        self.heap_counter = 0
        # Flag to enable/disable acyclicity constraints (default: enabled)
        self.use_acyclicity_constraints = True

        # Spatial encoder (delegate for spatial formula encoding)
        self._spatial_encoder = SpatialEncoder(self)

        # String theory support
        self.StringSort = z3.StringSort()
        # String variable cache (separate from location variables)
        self.string_var_cache: Dict[str, z3.ExprRef] = {}

        # Taint tracking support
        # We model taint as a set of tainted expressions
        # For simplicity, we track tainted variable names
        self.TaintSetSort = z3.SetSort(z3.StringSort())
        self.taint_set = z3.Const('TaintSet', self.TaintSetSort)

        # Security source/sink tracking
        self.sources: Dict[str, str] = {}  # var -> source_type
        self.sinks: Dict[str, str] = {}    # var -> sink_type

        # Heap lifecycle tracking
        # allocated_set: set of currently allocated pointers (not freed)
        self.AllocSetSort = z3.SetSort(self.LocSort)
        self.allocated_set = z3.Const('AllocatedSet', self.AllocSetSort)
        # freed_set: set of freed pointers (mutually exclusive with allocated_set)
        self.freed_set = z3.Const('FreedSet', self.AllocSetSort)

        # Array bounds tracking
        # array_bounds(array_ptr, size) - tracks size of each array
        self.array_bounds = z3.Function('array_bounds', self.LocSort, z3.IntSort())
        # array_heap: array heap mapping (array_base, index) -> value
        # We model arrays as a separate heap for efficient reasoning
        self.array_heap = z3.Function('array_heap', self.LocSort, z3.IntSort(), self.ValSort)

        # Array Theory (QF_AX) support
        # Cache for array variables and constants
        self.array_var_cache: Dict[str, z3.ArrayRef] = {}
        # Default array sort: Array from Int to Int (can be parameterized later)
        self.ArrayIntIntSort = z3.ArraySort(z3.IntSort(), z3.IntSort())
        # Array from Int to String (for string arrays)
        self.ArrayIntStringSort = z3.ArraySort(z3.IntSort(), z3.StringSort())

        # Bitvector Theory (QF_BV) support
        # Cache for bitvector variables
        self.bitvec_var_cache: Dict[Tuple[str, int], z3.BitVecRef] = {}  # (name, width) -> BitVec

    def fresh_var(self, prefix: str = "v", sort=None) -> z3.ExprRef:
        """Generate a fresh Z3 variable"""
        if sort is None:
            sort = self.LocSort
        name = f"{prefix}_{self.fresh_counter}"
        self.fresh_counter += 1
        return z3.Const(name, sort)

    def fresh_heap_id(self, prefix: str = "H") -> z3.ExprRef:
        """Generate a fresh heap ID for heap fragment splitting"""
        name = f"{prefix}{self.heap_counter}"
        self.heap_counter += 1
        return z3.Const(name, self.HeapIdSort)

    def get_or_create_var(self, name: str, sort=None, prefix: str = "") -> z3.ExprRef:
        """Get or create a Z3 variable for a given name

        Args:
            name: Variable name
            sort: Z3 sort (default: LocSort)
            prefix: Optional prefix for variable scoping (e.g., "cons_" for consequent)
        """
        if sort is None:
            sort = self.LocSort

        # Use prefixed name for cache lookup to create separate namespaces
        cache_key = f"{prefix}{name}" if prefix else name

        if cache_key not in self.var_cache:
            # Create Z3 variable with prefixed name to avoid collisions
            self.var_cache[cache_key] = z3.Const(cache_key, sort)
        return self.var_cache[cache_key]

    def _is_string_expr(self, expr: Expr) -> bool:
        """Check if an expression is a string expression

        Args:
            expr: Expression to check

        Returns:
            True if the expression is a string type
        """
        from frame.core.ast import StrLiteral, StrConcat, StrSubstr
        return isinstance(expr, (StrLiteral, StrConcat, StrSubstr))

    def encode_string_expr(self, expr: Expr, prefix: str = "") -> z3.SeqRef:
        """Encode an expression as a string (for string contexts)

        Args:
            expr: Expression to encode
            prefix: Variable prefix for scoping

        Returns:
            Z3 string expression
        """
        if isinstance(expr, StrLiteral):
            return z3.StringVal(expr.value)
        elif isinstance(expr, StrConcat):
            left_z3 = self.encode_string_expr(expr.left, prefix=prefix)
            right_z3 = self.encode_string_expr(expr.right, prefix=prefix)
            return z3.Concat(left_z3, right_z3)
        elif isinstance(expr, StrSubstr):
            string_z3 = self.encode_string_expr(expr.string, prefix=prefix)
            start_z3 = self.encode_expr(expr.start, prefix=prefix)
            end_z3 = self.encode_expr(expr.end, prefix=prefix)
            length = end_z3 - start_z3
            return z3.SubString(string_z3, start_z3, length)
        elif isinstance(expr, Var):
            # In string context, create a string variable
            cache_key = f"{prefix}{expr.name}_str"
            if cache_key not in self.string_var_cache:
                self.string_var_cache[cache_key] = z3.String(cache_key)
            return self.string_var_cache[cache_key]
        else:
            # For other expressions, try regular encoding and hope it's a string
            return self.encode_expr(expr, prefix=prefix)

    def encode_expr(self, expr: Expr, prefix: str = "") -> z3.ExprRef:
        """Encode an expression to Z3

        Args:
            expr: Expression to encode
            prefix: Variable prefix for scoping (e.g., "cons_" for consequent)
        """
        from frame.core.ast import ArithExpr

        # String expressions
        if isinstance(expr, StrLiteral):
            return z3.StringVal(expr.value)

        elif isinstance(expr, StrConcat):
            left_z3 = self.encode_string_expr(expr.left, prefix=prefix)
            right_z3 = self.encode_string_expr(expr.right, prefix=prefix)
            return z3.Concat(left_z3, right_z3)

        elif isinstance(expr, StrLen):
            string_z3 = self.encode_string_expr(expr.string, prefix=prefix)
            return z3.Length(string_z3)

        elif isinstance(expr, StrSubstr):
            string_z3 = self.encode_string_expr(expr.string, prefix=prefix)
            start_z3 = self.encode_expr(expr.start, prefix=prefix)
            end_z3 = self.encode_expr(expr.end, prefix=prefix)
            # Z3's SubString takes (string, offset, length)
            # We use (string, start, end-start) to match our AST semantics
            length = end_z3 - start_z3
            return z3.SubString(string_z3, start_z3, length)

        # Regular expressions
        elif isinstance(expr, Var):
            # Check if variable name is actually a numeric constant
            try:
                numeric_value = int(expr.name)
                return z3.IntVal(numeric_value)
            except ValueError:
                # Not a number, treat as variable
                # Variables could be strings or integers depending on context
                # For now, default to integer (location) sort
                return self.get_or_create_var(expr.name, prefix=prefix)

        elif isinstance(expr, Const):
            if expr.value is None:  # nil
                return z3.IntVal(self.nil)
            elif isinstance(expr.value, int):
                return z3.IntVal(expr.value)
            else:
                raise ValueError(f"Unsupported constant type: {type(expr.value)}")

        elif isinstance(expr, ArithExpr):
            # Encode arithmetic expressions
            left_z3 = self.encode_expr(expr.left, prefix=prefix)
            right_z3 = self.encode_expr(expr.right, prefix=prefix)

            if expr.op == '+':
                return left_z3 + right_z3
            elif expr.op == '-':
                return left_z3 - right_z3
            elif expr.op == '*':
                return left_z3 * right_z3
            elif expr.op == 'div':
                return left_z3 / right_z3
            elif expr.op == 'mod':
                return left_z3 % right_z3
            else:
                raise ValueError(f"Unsupported arithmetic operator: {expr.op}")

        # Array Theory expressions
        elif isinstance(expr, ArraySelect):
            # (select array index)
            array_z3 = self._encode_array_expr(expr.array, prefix=prefix)
            index_z3 = self.encode_expr(expr.index, prefix=prefix)
            return z3.Select(array_z3, index_z3)

        elif isinstance(expr, ArrayStore):
            # (store array index value)
            array_z3 = self._encode_array_expr(expr.array, prefix=prefix)
            index_z3 = self.encode_expr(expr.index, prefix=prefix)
            value_z3 = self.encode_expr(expr.value, prefix=prefix)
            return z3.Store(array_z3, index_z3, value_z3)

        elif isinstance(expr, ArrayConst):
            # Constant array with all elements = default_value
            default_z3 = self.encode_expr(expr.default_value, prefix=prefix)
            # Create constant array (all indices map to default_value)
            return z3.K(self.ArrayIntIntSort, default_z3)

        # Bitvector Theory expressions
        elif isinstance(expr, BitVecVal):
            # Bitvector constant
            return z3.BitVecVal(expr.value, expr.width)

        elif isinstance(expr, BitVecExpr):
            # Bitvector operations
            return self._encode_bitvec_op(expr, prefix=prefix)

        else:
            raise ValueError(f"Unsupported expression type: {type(expr)}")

    def _encode_array_expr(self, expr: Expr, prefix: str = "") -> z3.ArrayRef:
        """Encode an expression as an array

        Args:
            expr: Expression to encode
            prefix: Variable prefix for scoping

        Returns:
            Z3 array expression
        """
        if isinstance(expr, Var):
            # Array variable
            cache_key = f"{prefix}{expr.name}"
            if cache_key not in self.array_var_cache:
                self.array_var_cache[cache_key] = z3.Array(cache_key, z3.IntSort(), z3.IntSort())
            return self.array_var_cache[cache_key]
        elif isinstance(expr, ArrayStore):
            # Recursively encode store operations
            array_z3 = self._encode_array_expr(expr.array, prefix=prefix)
            index_z3 = self.encode_expr(expr.index, prefix=prefix)
            value_z3 = self.encode_expr(expr.value, prefix=prefix)
            return z3.Store(array_z3, index_z3, value_z3)
        elif isinstance(expr, ArrayConst):
            # Constant array
            default_z3 = self.encode_expr(expr.default_value, prefix=prefix)
            return z3.K(self.ArrayIntIntSort, default_z3)
        else:
            # Try regular encoding and hope it's an array
            return self.encode_expr(expr, prefix=prefix)

    def _encode_bitvec_op(self, expr: BitVecExpr, prefix: str = "") -> z3.BitVecRef:
        """Encode a bitvector operation

        Args:
            expr: Bitvector expression
            prefix: Variable prefix for scoping

        Returns:
            Z3 bitvector expression
        """
        # Encode operands
        operands_z3 = []
        for op in expr.operands:
            if isinstance(op, Var):
                # Bitvector variable
                cache_key = (f"{prefix}{op.name}", expr.width)
                if cache_key not in self.bitvec_var_cache:
                    self.bitvec_var_cache[cache_key] = z3.BitVec(f"{prefix}{op.name}", expr.width)
                operands_z3.append(self.bitvec_var_cache[cache_key])
            else:
                operands_z3.append(self.encode_expr(op, prefix=prefix))

        # Apply operation
        op = expr.op
        ops = operands_z3

        # Arithmetic operations
        if op == 'bvadd':
            return ops[0] + ops[1]
        elif op == 'bvsub':
            return ops[0] - ops[1]
        elif op == 'bvmul':
            return ops[0] * ops[1]
        elif op == 'bvudiv':
            return z3.UDiv(ops[0], ops[1])
        elif op == 'bvurem':
            return z3.URem(ops[0], ops[1])
        elif op == 'bvsdiv':
            return ops[0] / ops[1]
        elif op == 'bvsrem':
            return z3.SRem(ops[0], ops[1])

        # Bitwise operations
        elif op == 'bvand':
            return ops[0] & ops[1]
        elif op == 'bvor':
            return ops[0] | ops[1]
        elif op == 'bvxor':
            return ops[0] ^ ops[1]
        elif op == 'bvnot':
            return ~ops[0]
        elif op == 'bvshl':
            return ops[0] << ops[1]
        elif op == 'bvlshr':
            return z3.LShR(ops[0], ops[1])
        elif op == 'bvashr':
            return ops[0] >> ops[1]

        # Comparison operations (return Bool, not BitVec)
        elif op == 'bvult':
            return z3.ULT(ops[0], ops[1])
        elif op == 'bvule':
            return z3.ULE(ops[0], ops[1])
        elif op == 'bvugt':
            return z3.UGT(ops[0], ops[1])
        elif op == 'bvuge':
            return z3.UGE(ops[0], ops[1])
        elif op == 'bvslt':
            return ops[0] < ops[1]
        elif op == 'bvsle':
            return ops[0] <= ops[1]
        elif op == 'bvsgt':
            return ops[0] > ops[1]
        elif op == 'bvsge':
            return ops[0] >= ops[1]

        else:
            raise ValueError(f"Unsupported bitvector operation: {op}")

    def encode_heap_assertion(self, formula: Formula, heap_var: z3.ExprRef,
                             domain_set: Set[z3.ExprRef],
                             forbidden_domain: Optional[Set[z3.ExprRef]] = None,
                             distribution_depth: int = 0,
                             prefix: str = "") -> Tuple[z3.BoolRef, Set[z3.ExprRef]]:
        """
        Encode a spatial formula to Z3 constraints.
        Delegates to SpatialEncoder.

        Args:
            formula: The formula to encode
            heap_var: The heap array variable
            domain_set: Current domain being built
            forbidden_domain: Locations that should NOT be in this formula's domain
            distribution_depth: Depth of Or-distribution for precise domain tracking
            prefix: Variable prefix for scoping

        Returns:
            (constraints, domain): Z3 constraints and set of domain locations
        """
        return self._spatial_encoder.encode_heap_assertion(
            formula, heap_var, domain_set, forbidden_domain, distribution_depth, prefix
        )

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
            if self._is_string_expr(formula.left) or self._is_string_expr(formula.right):
                # Encode both sides as strings
                left = self.encode_string_expr(formula.left, prefix=prefix)
                right = self.encode_string_expr(formula.right, prefix=prefix)
            else:
                # Regular (integer/location) equality
                left = self.encode_expr(formula.left, prefix=prefix)
                right = self.encode_expr(formula.right, prefix=prefix)
            return left == right

        elif isinstance(formula, Neq):
            left = self.encode_expr(formula.left, prefix=prefix)
            right = self.encode_expr(formula.right, prefix=prefix)
            return left != right

        elif isinstance(formula, Lt):
            left = self.encode_expr(formula.left, prefix=prefix)
            right = self.encode_expr(formula.right, prefix=prefix)
            return left < right

        elif isinstance(formula, Le):
            left = self.encode_expr(formula.left, prefix=prefix)
            right = self.encode_expr(formula.right, prefix=prefix)
            return left <= right

        elif isinstance(formula, Gt):
            left = self.encode_expr(formula.left, prefix=prefix)
            right = self.encode_expr(formula.right, prefix=prefix)
            return left > right

        elif isinstance(formula, Ge):
            left = self.encode_expr(formula.left, prefix=prefix)
            right = self.encode_expr(formula.right, prefix=prefix)
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
            haystack = self.encode_string_expr(formula.haystack, prefix=prefix)
            needle = self.encode_string_expr(formula.needle, prefix=prefix)
            return z3.Contains(haystack, needle)

        elif isinstance(formula, StrMatches):
            string = self.encode_string_expr(formula.string, prefix=prefix)
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
                return z3.IsMember(z3.StringVal(var_name), self.taint_set)
            else:
                # Complex expression - conservatively assume not tainted
                return z3.BoolVal(False)

        elif isinstance(formula, Sanitized):
            # Sanitized(var) means var is NOT in the taint set
            var_name = self._get_var_name(formula.var)
            if var_name:
                return z3.Not(z3.IsMember(z3.StringVal(var_name), self.taint_set))
            else:
                # Complex expression - conservatively assume sanitized
                return z3.BoolVal(True)

        elif isinstance(formula, Source):
            # Source(var, type) tracks taint source
            var_name = self._get_var_name(formula.var)
            if var_name:
                self.sources[var_name] = formula.source_type
                # Also mark as tainted
                return z3.IsMember(z3.StringVal(var_name), self.taint_set)
            return z3.BoolVal(True)

        elif isinstance(formula, Sink):
            # Sink(var, type) tracks taint sink
            var_name = self._get_var_name(formula.var)
            if var_name:
                self.sinks[var_name] = formula.sink_type
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
            var_z3 = self.encode_expr(formula.var, prefix=prefix)
            return var_z3 == z3.IntVal(self.nil)

        elif isinstance(formula, UseAfterFree):
            # use_after_free(var) means var is in freed_set AND we try to access it
            # The dereference part is handled by spatial formulas
            # Here we just check if it's freed
            var_z3 = self.encode_expr(formula.var, prefix=prefix)
            return z3.IsMember(var_z3, self.freed_set)

        elif isinstance(formula, BufferOverflow):
            # buffer_overflow(arr, index, size) means index >= size
            index_z3 = self.encode_expr(formula.index, prefix=prefix)
            size_z3 = self.encode_expr(formula.size, prefix=prefix)
            return index_z3 >= size_z3

        # Heap lifecycle predicates
        elif isinstance(formula, Allocated):
            # allocated(ptr) means ptr is in allocated_set (and not in freed_set)
            ptr_z3 = self.encode_expr(formula.ptr, prefix=prefix)
            return z3.And(
                z3.IsMember(ptr_z3, self.allocated_set),
                z3.Not(z3.IsMember(ptr_z3, self.freed_set))
            )

        elif isinstance(formula, Freed):
            # freed(ptr) means ptr is in freed_set (and not in allocated_set)
            ptr_z3 = self.encode_expr(formula.ptr, prefix=prefix)
            return z3.And(
                z3.IsMember(ptr_z3, self.freed_set),
                z3.Not(z3.IsMember(ptr_z3, self.allocated_set))
            )

        elif isinstance(formula, ArrayBounds):
            # bounds(array, size) constrains the size of an array
            array_z3 = self.encode_expr(formula.array, prefix=prefix)
            size_z3 = self.encode_expr(formula.size, prefix=prefix)
            return self.array_bounds(array_z3) == size_z3

        # Array and bitvector security predicates
        elif isinstance(formula, TaintedArray):
            # TaintedArray(arr, indices) means some array elements are tainted
            # We track this by checking if ANY of the specified indices contain tainted data
            array_z3 = self._encode_array_expr(formula.array, prefix=prefix)

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
                    idx_z3 = self.encode_expr(idx, prefix=prefix)
                    value_z3 = z3.Select(array_z3, idx_z3)
                    # Value is tainted (implementation-specific)
                    # For now, we mark it in a separate tracking structure
                    constraints.append(z3.BoolVal(True))  # Placeholder
                return z3.Or(*constraints) if constraints else z3.BoolVal(False)

        elif isinstance(formula, BufferOverflowCheck):
            # BufferOverflowCheck(arr, index, size) verifies: 0 <= index < size
            index_z3 = self.encode_expr(formula.index, prefix=prefix)
            size_z3 = self.encode_expr(formula.size, prefix=prefix)

            # Safe access: index in bounds
            in_bounds = z3.And(
                index_z3 >= 0,
                index_z3 < size_z3
            )
            return in_bounds

        elif isinstance(formula, IntegerOverflow):
            # IntegerOverflow(op, operands, width, signed) detects overflow
            ops_z3 = [self.encode_expr(op, prefix=prefix) for op in formula.operands]
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
                        z3.IsMember(z3.StringVal(left_var), self.taint_set)
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
        top_heap_id = self.fresh_heap_id("H0")

        # Separate pure and spatial parts
        pure_part = self.extract_pure_part(formula)
        spatial_part = self.extract_spatial_part(formula)

        # Encode pure part
        pure_constraints = self.encode_pure(pure_part)

        # Encode spatial part with heap-relative semantics
        if spatial_part is not None:
            spatial_constraints, domain = self._spatial_encoder.encode_heap_assertion(
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
        heap_id = self.fresh_heap_id("Hent")

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
            ante_heap_constraints, ante_domain = self.encode_heap_assertion(
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
            cons_heap_constraints, cons_domain = self.encode_heap_assertion(
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
