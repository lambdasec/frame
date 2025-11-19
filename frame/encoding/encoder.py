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
from frame.encoding._bitvec import BitVecEncoder
from frame.encoding._string import StringEncoder
from frame.encoding._pure import PureEncoder


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

        # Bitvector encoder (delegate for bitvector theory encoding)
        self._bitvec_encoder = BitVecEncoder(self)

        # String encoder (delegate for string theory encoding)
        self._string_encoder = StringEncoder(self)

        # Pure encoder (delegate for pure formula and high-level encoding)
        self._pure_encoder = PureEncoder(self)

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
        # Function to map array base pointers to their sizes
        # This allows Z3 to infer that if arr1 = arr2, then array_size(arr1) = array_size(arr2)
        self.array_size_fn = z3.Function('array_size', z3.IntSort(), z3.IntSort())
        # Default array sort: Array from Int to Int (can be parameterized later)
        self.ArrayIntIntSort = z3.ArraySort(z3.IntSort(), z3.IntSort())
        # Array from Int to String (for string arrays)
        self.ArrayIntStringSort = z3.ArraySort(z3.IntSort(), z3.StringSort())

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
        """Delegate to string encoder"""
        return self._string_encoder.is_string_expr(expr)

    def _is_bitvec_expr(self, expr: Expr) -> bool:
        """Delegate to bitvector encoder"""
        return self._bitvec_encoder.is_bitvec_expr(expr)

    def _get_bitvec_width(self, expr: Expr) -> Optional[int]:
        """Delegate to bitvector encoder"""
        return self._bitvec_encoder.get_bitvec_width(expr)

    def encode_bitvec_expr(self, expr: Expr, width: int, prefix: str = "") -> z3.BitVecRef:
        """Delegate to bitvector encoder"""
        return self._bitvec_encoder.encode_bitvec_expr(expr, width, prefix)

    def encode_string_expr(self, expr: Expr, prefix: str = "") -> z3.SeqRef:
        """Delegate to string encoder"""
        return self._string_encoder.encode_string_expr(expr, prefix)

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
                # Variables default to integer (location) sort
                # Arrays are explicitly handled through ArraySelect/ArrayStore operations
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
            # Convert bitvector indices to integers (arrays expect IntSort indices)
            if self._is_bitvec_expr(expr.index):
                index_z3 = z3.BV2Int(index_z3)
            return z3.Select(array_z3, index_z3)

        elif isinstance(expr, ArrayStore):
            # (store array index value)
            array_z3 = self._encode_array_expr(expr.array, prefix=prefix)
            index_z3 = self.encode_expr(expr.index, prefix=prefix)
            # Convert bitvector indices to integers (arrays expect IntSort indices)
            if self._is_bitvec_expr(expr.index):
                index_z3 = z3.BV2Int(index_z3)
            value_z3 = self.encode_expr(expr.value, prefix=prefix)
            return z3.Store(array_z3, index_z3, value_z3)

        elif isinstance(expr, ArrayConst):
            # Constant array with all elements = default_value
            # Ensure default value is encoded as integer
            if isinstance(expr.default_value, Const):
                default_z3 = z3.IntVal(expr.default_value.value if expr.default_value.value is not None else 0)
            else:
                default_z3 = self.encode_expr(expr.default_value, prefix=prefix)
                # Ensure it's integer sort
                if isinstance(default_z3, z3.ArithRef):
                    pass  # Already arithmetic
                else:
                    default_z3 = z3.IntVal(0)  # Fallback
            # Create constant array (all indices map to default_value)
            # z3.K(domain_sort, value) creates Array(domain_sort, value_sort)
            return z3.K(z3.IntSort(), default_z3)

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
            # Constant array - ensure default value is properly typed as integer
            if isinstance(expr.default_value, Const):
                default_z3 = z3.IntVal(expr.default_value.value if expr.default_value.value is not None else 0)
            else:
                default_z3 = self.encode_expr(expr.default_value, prefix=prefix)
                # Ensure it's integer sort
                if not isinstance(default_z3, z3.ArithRef):
                    default_z3 = z3.IntVal(0)  # Fallback
            # z3.K(domain_sort, value) creates Array(domain_sort, value_sort)
            return z3.K(z3.IntSort(), default_z3)
        else:
            raise ValueError(f"Cannot encode expression as array: {type(expr)}")

    def _encode_bitvec_op(self, expr: BitVecExpr, prefix: str = "") -> z3.BitVecRef:
        """Delegate to bitvector encoder"""
        return self._bitvec_encoder.encode_bitvec_op(expr, prefix)

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

    # Delegate pure encoding and high-level methods to PureEncoder
    def encode_pure(self, formula: Formula, prefix: str = "") -> z3.BoolRef:
        """Delegate to pure encoder"""
        return self._pure_encoder.encode_pure(formula, prefix)

    def encode_formula(self, formula: Formula) -> Tuple[z3.BoolRef, z3.ExprRef, Set[z3.ExprRef]]:
        """Delegate to pure encoder"""
        return self._pure_encoder.encode_formula(formula)

    def extract_pure_part(self, formula: Formula) -> Formula:
        """Delegate to pure encoder"""
        return self._pure_encoder.extract_pure_part(formula)

    def extract_spatial_part(self, formula: Formula) -> Formula:
        """Delegate to pure encoder"""
        return self._pure_encoder.extract_spatial_part(formula)

    def _has_existentials(self, formula: Formula) -> bool:
        """Delegate to pure encoder"""
        return self._pure_encoder._has_existentials(formula)

    def encode_entailment(self, antecedent: Formula, consequent: Formula) -> z3.BoolRef:
        """Delegate to pure encoder"""
        return self._pure_encoder.encode_entailment(antecedent, consequent)

    def _has_syntactic_allocations(self, formula: Formula) -> bool:
        """Delegate to pure encoder"""
        return self._pure_encoder._has_syntactic_allocations(formula)
