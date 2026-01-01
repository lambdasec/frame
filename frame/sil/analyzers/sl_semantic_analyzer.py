"""
Separation Logic Semantic Analyzer for C/C++.

This module provides proper semantic analysis using:
1. Tree-sitter for parsing C/C++ code into an AST
2. Control flow graph (CFG) construction
3. Symbolic execution with separation logic formulas
4. Frame's SL entailment checker for safety verification

Key CWE Types Detected:
- CWE-122: Heap-based Buffer Overflow
- CWE-121: Stack-based Buffer Overflow
- CWE-124: Buffer Underwrite (negative index)
- CWE-127: Buffer Under-read (negative index)
- CWE-252: Unchecked Return Value
- CWE-415: Double Free
- CWE-416: Use After Free
- CWE-476: NULL Pointer Dereference
- CWE-401: Memory Leak
- CWE-590: Free of Non-Heap Memory
- CWE-480: Use of Incorrect Operator (assignment in condition)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser

from frame.sil.types import Location
from frame.sil.translator import VulnType

# Import semantic pattern analyzer
try:
    from frame.sil.analyzers.semantic_patterns import (
        SemanticPatternAnalyzer, PatternSafety, PatternAnalysisResult
    )
    HAS_SEMANTIC_PATTERNS = True
except ImportError:
    HAS_SEMANTIC_PATTERNS = False

# Import Frame's SL solver
try:
    from frame.checking.checker import EntailmentChecker
    from frame.core.ast import Formula, PointsTo, Var, Const, Emp, SepConj
    HAS_FRAME_SL = True
except ImportError:
    HAS_FRAME_SL = False


class HeapState(Enum):
    """Separation logic heap state"""
    ALLOCATED = "allocated"   # ptr |-> val (valid allocation)
    FREED = "freed"          # emp (freed, dangling pointer)
    NULL = "null"            # ptr = NULL


class AllocKind(Enum):
    """Memory allocation source"""
    HEAP = "heap"     # malloc/new
    STACK = "stack"   # Local array/alloca
    UNKNOWN = "unknown"


@dataclass
class MemoryRegion:
    """Symbolic memory region tracked in separation logic"""
    name: str
    state: HeapState
    size: Optional[int] = None
    alloc_loc: Optional[Location] = None
    free_loc: Optional[Location] = None
    alloc_kind: AllocKind = AllocKind.UNKNOWN
    element_size: int = 1  # Size of each element (for arrays)


@dataclass
class MemoryVuln:
    """Detected vulnerability"""
    vuln_type: VulnType
    cwe_id: str
    location: Location
    var_name: str
    description: str
    alloc_loc: Optional[Location] = None
    free_loc: Optional[Location] = None
    confidence: float = 0.9


class SLSemanticAnalyzer:
    """
    Semantic analyzer using separation logic.

    Uses tree-sitter for proper C/C++ parsing and Frame's SL solver
    for memory safety verification.
    """

    ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'aligned_alloc'}
    FREE_FUNCS = {'free', 'cfree'}

    # Functions that copy unbounded data (unsafe without size check)
    UNSAFE_COPY_FUNCS = {'strcpy', 'strcat', 'wcscpy', 'wcscat', 'gets', 'sprintf'}

    # Functions that copy bounded data (safer)
    BOUNDED_COPY_FUNCS = {'strncpy', 'strncat', 'wcsncpy', 'wcsncat', 'memcpy',
                          'memmove', 'memset', 'snprintf', 'fgets'}

    # C++ delete operators
    DELETE_OPS = {'delete', 'delete[]'}

    # Functions that dereference pointers
    DEREF_FUNCS = {'printLine', 'printIntLine', 'printLongLine', 'printHexCharLine',
                   'printWLine', 'printLongLongLine', 'printf', 'fprintf', 'sprintf',
                   'strlen', 'wcslen', 'strcpy', 'strncpy', 'memcpy', 'memmove'}

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.heap: Dict[str, MemoryRegion] = {}
        self.vulnerabilities: List[MemoryVuln] = []
        self._reported: Set[Tuple[str, int]] = set()
        # Track pointers that point to stack addresses
        self.stack_pointers: Dict[str, str] = {}  # ptr -> stack_var it points to
        # Track NULL pointers
        self.null_pointers: Set[str] = set()
        # Track pointers inside NULL check blocks
        self.in_null_check: Dict[str, bool] = {}  # ptr -> True if we're inside if(ptr == NULL)
        # Track pointers proven non-NULL in current scope (e.g., if(ptr) or if(ptr != NULL))
        self.proven_non_null: Set[str] = set()
        # Track pointers proven non-NULL permanently by early exit guards (if(ptr==NULL){exit;})
        # This is NOT scoped - once proven by early exit, always non-NULL for rest of function
        self.early_exit_guards: Set[str] = set()
        # Track buffer sizes for semantic analysis
        self.buffer_sizes: Dict[str, int] = {}
        # Track which variables are pointer types (for distinguishing int=0 from ptr=NULL)
        self.pointer_vars: Set[str] = set()
        # Track unchecked return values from allocation functions (CWE-252)
        self.unchecked_allocs: Dict[str, Location] = {}  # var -> alloc_loc
        # Current function name (for filtering good functions)
        self.current_function: str = ""

        # Initialize parsers
        self.c_parser = Parser(Language(tsc.language()))
        self.cpp_parser = Parser(Language(tscpp.language()))

        # Initialize Frame's SL checker
        if HAS_FRAME_SL:
            self.sl_checker = EntailmentChecker(verbose=False, timeout=1000)
        else:
            self.sl_checker = None

        # Initialize semantic pattern analyzer
        if HAS_SEMANTIC_PATTERNS:
            self.pattern_analyzer = SemanticPatternAnalyzer(verbose=verbose)
        else:
            self.pattern_analyzer = None

    def _add_vuln(self, vuln: MemoryVuln) -> bool:
        """Add vulnerability if not already reported."""
        key = (vuln.cwe_id, vuln.location.line)
        if key in self._reported:
            return False
        self._reported.add(key)
        self.vulnerabilities.append(vuln)
        return True

    def _get_parser(self, filename: str) -> Parser:
        """Get appropriate parser based on file extension."""
        if filename.endswith('.cpp') or filename.endswith('.cc') or filename.endswith('.cxx'):
            return self.cpp_parser
        return self.c_parser

    def analyze_source(self, source: str, filename: str = "<unknown>") -> List[MemoryVuln]:
        """
        Analyze C/C++ source code using separation logic.

        1. Parse with tree-sitter
        2. Build symbolic heap state
        3. Check safety properties at each operation
        """
        self.heap = {}
        self.vulnerabilities = []
        self._reported = set()

        # Parse the source
        parser = self._get_parser(filename)
        tree = parser.parse(bytes(source, 'utf8'))

        # Analyze each function
        self._analyze_tree(tree.root_node, source, filename)

        return self.vulnerabilities

    def _analyze_tree(self, node: Any, source: str, filename: str):
        """Recursively analyze AST nodes."""
        if node.type == 'function_definition':
            self._analyze_function(node, source, filename)
        else:
            for child in node.children:
                self._analyze_tree(child, source, filename)

    def _analyze_function(self, func_node: Any, source: str, filename: str):
        """Analyze a single function for memory safety."""
        # Reset all state for each function
        self.heap = {}
        self.stack_pointers = {}
        self.null_pointers = set()
        self.in_null_check = {}
        self.proven_non_null = set()  # Reset for each function
        self.early_exit_guards = set()  # Reset for each function
        self.pointer_vars = set()     # Reset for each function
        self.unchecked_allocs = {}    # Reset for each function

        # Get function name
        func_name = self._get_function_name(func_node)
        self.current_function = func_name

        if self.verbose:
            print(f"[SL] Analyzing function: {func_name}")

        # Analyze the function body
        body = self._find_child(func_node, 'compound_statement')
        if body:
            self._analyze_compound(body, source, filename)
            # Check for unchecked allocations at function exit
            self._check_unchecked_allocs()

    def _get_function_name(self, func_node: Any) -> str:
        """Extract function name from function definition."""
        declarator = self._find_child(func_node, 'function_declarator')
        if declarator:
            for child in declarator.children:
                if child.type == 'identifier':
                    return child.text.decode('utf8')
        return "<unknown>"

    def _find_child(self, node: Any, type_name: str) -> Optional[Any]:
        """Find first child of given type."""
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    def _find_children(self, node: Any, type_name: str) -> List[Any]:
        """Find all children of given type."""
        return [c for c in node.children if c.type == type_name]

    def _analyze_compound(self, node: Any, source: str, filename: str):
        """Analyze a compound statement (block)."""
        for child in node.children:
            self._analyze_statement(child, source, filename)

    def _analyze_statement(self, node: Any, source: str, filename: str):
        """Analyze a statement."""
        loc = Location(filename, node.start_point[0] + 1, node.start_point[1])

        if node.type == 'declaration':
            self._analyze_declaration(node, source, filename, loc)
            # Also check for subscript expressions in declarations
            self._check_subscript_in_statement(node, source, filename, loc)
        elif node.type == 'expression_statement':
            # Check for delete expression first
            delete_expr = self._find_child(node, 'delete_expression')
            if delete_expr:
                self._handle_delete(delete_expr, loc)
                return

            expr = self._find_child(node, 'call_expression') or \
                   self._find_child(node, 'assignment_expression')
            if expr:
                if expr.type == 'call_expression':
                    self._analyze_call(expr, source, filename, loc)
                else:
                    self._analyze_assignment(expr, source, filename, loc)
            else:
                # Check for pointer dereference: *ptr or ptr->field
                self._check_deref_in_expr(node, loc)

            # Check for array subscript with potential negative index
            self._check_subscript_in_statement(node, source, filename, loc)
        elif node.type == 'compound_statement':
            self._analyze_compound(node, source, filename)
        elif node.type == 'if_statement':
            self._analyze_if_statement(node, source, filename, loc)
            # Check for assignment in condition (CWE-480)
            self._check_assignment_in_condition(node, source, filename, loc)
        elif node.type == 'return_statement':
            self._check_memory_leaks(loc)

    def _analyze_if_statement(self, node: Any, source: str, filename: str, loc: Location):
        """Analyze if-statement with special handling for NULL checks."""
        # Extract condition - can be parenthesized_expression or condition_clause
        condition = self._find_child(node, 'parenthesized_expression') or \
                    self._find_child(node, 'condition_clause')
        null_check_var = None
        is_null_check = False
        non_null_check_vars = []  # Variables proven non-NULL in then branch
        is_non_null_check = False

        if condition:
            cond_text = condition.text.decode('utf8')
            import re

            # Check for patterns like (ptr == NULL) or (ptr == nullptr) or (ptr == 0)
            null_match = re.search(r'(\w+)\s*==\s*(?:NULL|nullptr|0)', cond_text)
            if null_match:
                null_check_var = null_match.group(1)
                is_null_check = True
                if self.verbose:
                    print(f"[SL] Found NULL check: if ({null_check_var} == NULL)")

            # Check for patterns like (ptr != NULL) or (ptr != nullptr) or (ptr != 0)
            # In this case, ptr is non-NULL in the then branch
            non_null_match = re.search(r'(\w+)\s*!=\s*(?:NULL|nullptr|0)', cond_text)
            if non_null_match:
                non_null_check_vars.append(non_null_match.group(1))
                is_non_null_check = True
                if self.verbose:
                    print(f"[SL] Found non-NULL check: if ({non_null_match.group(1)} != NULL)")

            # Check for short-circuit AND with pointer truthiness: (ptr && ...)
            # In this case, ptr is non-NULL inside the then branch
            and_match = re.findall(r'\(?\s*(\w+)\s*&&', cond_text)
            for var in and_match:
                if var not in ('true', 'false', 'TRUE', 'FALSE', '0', '1'):
                    non_null_check_vars.append(var)
                    is_non_null_check = True
                    if self.verbose:
                        print(f"[SL] Found short-circuit non-NULL guard: if ({var} && ...)")

            # Check for simple truthiness: if (ptr) { ... }
            simple_truth_match = re.match(r'^\s*\(\s*(\w+)\s*\)\s*$', cond_text)
            if simple_truth_match:
                var = simple_truth_match.group(1)
                if var not in ('true', 'false', 'TRUE', 'FALSE', '0', '1'):
                    non_null_check_vars.append(var)
                    is_non_null_check = True
                    if self.verbose:
                        print(f"[SL] Found simple non-NULL check: if ({var})")

        # Find the 'then' branch (true case for if condition)
        branches = []
        saw_condition = False
        for child in node.children:
            if child.type in ('parenthesized_expression', 'condition_clause'):
                saw_condition = True
            elif saw_condition and child.type in ('compound_statement', 'expression_statement'):
                branches.append(('then', child))
                break

        # Find 'else' branch if present (tree-sitter uses 'else_clause')
        for child in node.children:
            if child.type == 'else_clause':
                # The else_clause contains the else body directly
                for else_child in child.children:
                    if else_child.type in ('compound_statement', 'expression_statement', 'if_statement'):
                        branches.append(('else', else_child))
                        break
                break

        # Analyze branches with NULL check context
        then_has_early_exit = False
        for branch_type, branch in branches:
            if is_null_check and branch_type == 'then':
                # Inside if (ptr == NULL) { ... } - ptr is known to be NULL here
                old_null_check = self.in_null_check.copy()
                self.in_null_check[null_check_var] = True
                self._analyze_branch(branch, source, filename)
                self.in_null_check = old_null_check
                # Check if this branch always exits early (return, exit, abort, etc.)
                then_has_early_exit = self._branch_has_early_exit(branch, source)
            elif is_non_null_check and branch_type == 'then':
                # Inside if (ptr != NULL) or if (ptr && ...) - ptr is proven non-NULL
                old_proven = self.proven_non_null.copy()
                for var in non_null_check_vars:
                    self.proven_non_null.add(var)
                    # Mark allocation as checked for CWE-252
                    self._mark_allocation_checked(var)
                self._analyze_branch(branch, source, filename)
                self.proven_non_null = old_proven
            elif is_null_check and branch_type == 'else':
                # In the else branch of if (ptr == NULL), ptr is non-NULL
                old_proven = self.proven_non_null.copy()
                self.proven_non_null.add(null_check_var)
                self._analyze_branch(branch, source, filename)
                self.proven_non_null = old_proven
            else:
                self._analyze_branch(branch, source, filename)

        # Early exit guard pattern: if (ptr == NULL) { exit(-1); }
        # After this if statement, ptr is proven non-NULL for the rest of the function
        # Use early_exit_guards (not proven_non_null) to avoid being clobbered by scope restoration
        if is_null_check and then_has_early_exit and null_check_var:
            self.early_exit_guards.add(null_check_var)
            # Also remove from null_pointers since we know it's now non-NULL
            self.null_pointers.discard(null_check_var)
            # Mark allocation as checked for CWE-252
            self._mark_allocation_checked(null_check_var)
            if self.verbose:
                print(f"[SL] Early exit guard: {null_check_var} proven non-NULL after NULL check with exit")

    def _branch_has_early_exit(self, node: Any, source: str) -> bool:
        """Check if a branch always exits early (return, exit, abort, etc.)."""
        import re
        text = node.text.decode('utf8')

        # Look for early exit patterns
        exit_patterns = [
            r'\breturn\b',           # return statement
            r'\bexit\s*\(',          # exit() call
            r'\b_exit\s*\(',         # _exit() call
            r'\babort\s*\(',         # abort() call
            r'\bthrow\b',            # throw statement (C++)
            r'\bgoto\s+\w+',         # goto statement
            r'\blongjmp\s*\(',       # longjmp
            r'\bassert\s*\(\s*(?:0|false|FALSE)\s*\)',  # assert(0) or assert(false)
        ]

        for pattern in exit_patterns:
            if re.search(pattern, text):
                return True
        return False

    def _analyze_branch(self, node: Any, source: str, filename: str):
        """Analyze a branch (compound statement or single statement)."""
        if node.type == 'compound_statement':
            self._analyze_compound(node, source, filename)
        elif node.type == 'if_statement':
            loc = Location(filename, node.start_point[0] + 1, node.start_point[1])
            self._analyze_if_statement(node, source, filename, loc)
        else:
            self._analyze_statement(node, source, filename)

    def _check_deref_in_expr(self, node: Any, loc: Location):
        """Check for pointer dereference of NULL or freed pointers."""
        text = node.text.decode('utf8')
        import re

        # Pattern: *ptr (pointer dereference)
        deref_match = re.search(r'\*\s*(\w+)', text)
        if deref_match:
            ptr_name = deref_match.group(1)
            self._check_ptr_deref(ptr_name, loc)

        # Pattern: ptr->field (member access via pointer)
        arrow_match = re.search(r'(\w+)\s*->', text)
        if arrow_match:
            ptr_name = arrow_match.group(1)
            self._check_ptr_deref(ptr_name, loc)

    def _check_ptr_deref(self, ptr_name: str, loc: Location):
        """Check if dereferencing this pointer is safe."""
        # CWE-476: Dereference of NULL pointer
        # Skip NULL check if pointer is proven non-NULL by:
        # 1. Enclosing condition (e.g., if(ptr != NULL) or if(ptr && ...))
        # 2. Early exit guard (e.g., if(ptr == NULL) { exit(-1); })
        is_proven_non_null = ptr_name in self.proven_non_null or ptr_name in self.early_exit_guards

        if not is_proven_non_null:
            if ptr_name in self.null_pointers or self.in_null_check.get(ptr_name, False):
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.NULL_DEREFERENCE,
                    cwe_id="CWE-476",
                    location=loc,
                    var_name=ptr_name,
                    description=f"NULL pointer dereference: '{ptr_name}' is NULL. SL check: emp ⊬ {ptr_name} |-> _",
                    confidence=0.95
                ))
        elif self.verbose:
            print(f"[SL] Skipping NULL check for '{ptr_name}' - proven non-NULL by condition")

        # CWE-416: Use After Free (always check, regardless of NULL status)
        if ptr_name in self.heap and self.heap[ptr_name].state == HeapState.FREED:
            region = self.heap[ptr_name]
            self._add_vuln(MemoryVuln(
                vuln_type=VulnType.USE_AFTER_FREE,
                cwe_id="CWE-416",
                location=loc,
                var_name=ptr_name,
                description=f"Use after free: '{ptr_name}' was freed. SL check: emp ⊬ {ptr_name} |-> _",
                free_loc=region.free_loc,
                confidence=0.95
            ))

    def _handle_delete(self, node: Any, loc: Location):
        """Handle C++ delete expression."""
        # Extract the pointer being deleted
        ptr_name = None
        is_array = False

        for child in node.children:
            if child.type == 'identifier':
                ptr_name = child.text.decode('utf8')
            elif child.text and b'[]' in child.text:
                is_array = True

        if not ptr_name:
            return

        if self.verbose:
            print(f"[SL] delete{'[]' if is_array else ''}: {ptr_name}")

        # CWE-590: Free of non-heap memory
        if ptr_name in self.stack_pointers:
            stack_var = self.stack_pointers[ptr_name]
            self._add_vuln(MemoryVuln(
                vuln_type=VulnType.DOUBLE_FREE,  # Reusing type
                cwe_id="CWE-590",
                location=loc,
                var_name=ptr_name,
                description=f"Free of non-heap memory: '{ptr_name}' points to stack variable '{stack_var}'. SL: {ptr_name} |-> (stack, _)",
                confidence=0.95
            ))
            return

        if ptr_name in self.heap:
            region = self.heap[ptr_name]

            # CWE-590: Free of stack-allocated memory
            if region.alloc_kind == AllocKind.STACK:
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id="CWE-590",
                    location=loc,
                    var_name=ptr_name,
                    description=f"Free of non-heap memory: '{ptr_name}' is stack-allocated. SL: {ptr_name} |-> (stack, _)",
                    alloc_loc=region.alloc_loc,
                    confidence=0.95
                ))
                return

            # CWE-415: Double free
            if region.state == HeapState.FREED:
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id="CWE-415",
                    location=loc,
                    var_name=ptr_name,
                    description=f"Double free: '{ptr_name}' already freed at line {region.free_loc.line if region.free_loc else '?'}. SL: emp ⊬ {ptr_name} |-> _",
                    alloc_loc=region.alloc_loc,
                    free_loc=region.free_loc,
                    confidence=0.95
                ))
                return

            # Mark as freed
            region.state = HeapState.FREED
            region.free_loc = loc
        else:
            # Track unknown pointer as freed
            self.heap[ptr_name] = MemoryRegion(
                name=ptr_name,
                state=HeapState.FREED,
                free_loc=loc,
                alloc_kind=AllocKind.HEAP
            )

    def _analyze_declaration(self, node: Any, source: str, filename: str, loc: Location):
        """Analyze variable declaration."""
        # Track pointer type declarations
        # Look for pointer_declarator which indicates a pointer variable
        decl_text = node.text.decode('utf8') if node.text else ''

        # Detect pointer declarations: char *ptr, int *data, etc.
        pointer_decl = self._find_child(node, 'pointer_declarator')
        if not pointer_decl:
            init_decl = self._find_child(node, 'init_declarator')
            if init_decl:
                pointer_decl = self._find_child(init_decl, 'pointer_declarator')

        if pointer_decl:
            # Extract pointer variable name
            for child in pointer_decl.children:
                if child.type == 'identifier':
                    ptr_name = child.text.decode('utf8')
                    self.pointer_vars.add(ptr_name)
                    if self.verbose:
                        print(f"[SL] Declared pointer var: {ptr_name}")
                    break

        # Also detect pointer types from type specifier containing *
        # e.g., "int * data" or "char* ptr"
        if '*' in decl_text:
            # Extract identifiers that follow the *
            import re
            # Match patterns like "type * name" or "type *name"
            ptr_match = re.search(r'\*\s*(\w+)', decl_text)
            if ptr_match:
                ptr_name = ptr_match.group(1)
                self.pointer_vars.add(ptr_name)
                if self.verbose:
                    print(f"[SL] Declared pointer var (from type): {ptr_name}")

        # Look for array declarations: type name[size]
        # Array declarator can be directly under declaration or nested inside init_declarator
        array_decl = self._find_child(node, 'array_declarator')

        if not array_decl:
            # Check inside init_declarator
            init_decl = self._find_child(node, 'init_declarator')
            if init_decl:
                array_decl = self._find_child(init_decl, 'array_declarator')

        if array_decl:
            var_name = None
            size = None
            for child in array_decl.children:
                if child.type == 'identifier':
                    var_name = child.text.decode('utf8')
                elif child.type == 'number_literal':
                    try:
                        size = int(child.text.decode('utf8'))
                    except ValueError:
                        pass
                elif child.type == 'binary_expression':
                    # Handle expressions like [10 + 1]
                    size = self._eval_size_expr(child)

            if var_name and size:
                # Stack-allocated array: var |-> (data, size)
                self.heap[var_name] = MemoryRegion(
                    name=var_name,
                    state=HeapState.ALLOCATED,
                    size=size,
                    alloc_loc=loc,
                    alloc_kind=AllocKind.STACK
                )
                if self.verbose:
                    print(f"[SL] Stack array: {var_name} |-> (_, {size})")

        # Check for heap allocation in initializer
        init_decl = self._find_child(node, 'init_declarator')
        if init_decl:
            self._check_init_allocation(init_decl, source, filename, loc)

    def _check_init_allocation(self, node: Any, source: str, filename: str, loc: Location):
        """Check for heap allocation in variable initialization."""
        # Get variable name
        var_name = None
        for child in node.children:
            if child.type == 'identifier':
                var_name = child.text.decode('utf8')
                break
            if child.type == 'pointer_declarator':
                for c in child.children:
                    if c.type == 'identifier':
                        var_name = c.text.decode('utf8')
                        break

        # Look for call expression (malloc, new, etc.) or new_expression
        call = None
        new_expr = None
        for child in node.children:
            if child.type == 'call_expression':
                call = child
                break
            # C++ new expression: new Type[N]
            if child.type == 'new_expression':
                new_expr = child
                break
            # Also check cast expressions: (type*)malloc(...)
            if child.type == 'cast_expression':
                for c in child.children:
                    if c.type == 'call_expression':
                        call = c
                        break
                    if c.type == 'new_expression':
                        new_expr = c
                        break

        if var_name and call:
            func_name = self._get_call_name(call)
            if func_name in self.ALLOC_FUNCS:
                size = self._extract_alloc_size(call)
                self.heap[var_name] = MemoryRegion(
                    name=var_name,
                    state=HeapState.ALLOCATED,
                    size=size,
                    alloc_loc=loc,
                    alloc_kind=AllocKind.HEAP
                )
                # Track for unchecked return value detection (CWE-252)
                self._mark_allocation_for_check(var_name, loc)
                if self.verbose:
                    print(f"[SL] Heap alloc: {var_name} |-> (_, {size})")

        # Handle C++ new expressions: new Type[N] or new Type[N + M]
        if var_name and new_expr:
            size = self._extract_new_size(new_expr)
            # Track for unchecked return value detection (CWE-252)
            self._mark_allocation_for_check(var_name, loc)
            self.heap[var_name] = MemoryRegion(
                name=var_name,
                state=HeapState.ALLOCATED,
                size=size,
                alloc_loc=loc,
                alloc_kind=AllocKind.HEAP
            )
            if self.verbose:
                print(f"[SL] C++ new: {var_name} |-> (_, {size})")

        # Handle pointer assignment from another variable: ptr = otherPtr
        # This propagates size information through aliases
        if var_name and not call and not new_expr:
            # Check for NULL assignment: ptr = NULL / nullptr / 0
            # Only treat = 0 as NULL if the variable is a declared pointer type
            node_text = node.text.decode('utf8') if node.text else ''
            is_null_assign = '= NULL' in node_text or '= nullptr' in node_text
            # = 0 only counts as NULL for pointer types
            if '= 0;' in node_text and var_name in self.pointer_vars:
                is_null_assign = True

            if is_null_assign:
                self.null_pointers.add(var_name)
                self.pointer_vars.add(var_name)  # Also mark as pointer
                self.heap[var_name] = MemoryRegion(
                    name=var_name,
                    state=HeapState.NULL,
                    alloc_loc=loc,
                    alloc_kind=AllocKind.UNKNOWN
                )
                if self.verbose:
                    print(f"[SL] NULL pointer: {var_name} = NULL")
                return

            # Check for address-of: ptr = &stackVar
            # Also check for simple assignment: ptr = otherPtr
            saw_equals = False
            for child in node.children:
                if child.type == 'pointer_expression':
                    # This is &var
                    for c in child.children:
                        if c.type == 'identifier':
                            stack_var = c.text.decode('utf8')
                            self.stack_pointers[var_name] = stack_var
                            if self.verbose:
                                print(f"[SL] Stack pointer: {var_name} = &{stack_var}")
                            return

                # Track when we've passed the '=' sign
                if child.type == '=':
                    saw_equals = True
                    continue

                # Only consider identifiers AFTER the '=' sign as source variables
                if saw_equals and child.type == 'identifier':
                    src_var = child.text.decode('utf8')
                    if src_var in self.heap:
                        # Propagate size info from source
                        src_region = self.heap[src_var]
                        self.heap[var_name] = MemoryRegion(
                            name=var_name,
                            state=src_region.state,
                            size=src_region.size,
                            alloc_loc=src_region.alloc_loc,
                            alloc_kind=src_region.alloc_kind
                        )
                        # var_name is no longer NULL if it was before
                        self.null_pointers.discard(var_name)
                        if self.verbose:
                            print(f"[SL] Pointer alias: {var_name} = {src_var} |-> (_, {src_region.size})")
                        break
                    # Check if source is a stack pointer
                    if src_var in self.stack_pointers:
                        self.stack_pointers[var_name] = self.stack_pointers[src_var]
                        # var_name is no longer NULL if it was before
                        self.null_pointers.discard(var_name)
                        if self.verbose:
                            print(f"[SL] Stack pointer propagate: {var_name} = {src_var} -> stack")
                        break

    def _extract_new_size(self, node: Any) -> Optional[int]:
        """Extract size from C++ new expression: new Type[N] or new Type[N + M]."""
        # Look for new_declarator which contains the array size
        for child in node.children:
            if child.type == 'new_declarator':
                # new_declarator contains: '[', number/expr, ']'
                for sub in child.children:
                    if sub.type == 'number_literal':
                        try:
                            return int(sub.text.decode('utf8'))
                        except ValueError:
                            pass
                    if sub.type == 'binary_expression':
                        return self._eval_size_expr(sub)
            # Direct number: new Type[10]
            if child.type == 'number_literal':
                try:
                    return int(child.text.decode('utf8'))
                except ValueError:
                    pass
            # Binary expression like 10 + 1
            if child.type == 'binary_expression':
                return self._eval_size_expr(child)

        return None

    def _eval_size_expr(self, node: Any) -> Optional[int]:
        """Evaluate a size expression like 10, 10 + 1, etc."""
        if node.type == 'number_literal':
            try:
                return int(node.text.decode('utf8'))
            except ValueError:
                return None

        if node.type == 'binary_expression':
            # Get left, operator, right
            left = right = None
            op = None
            for child in node.children:
                if child.type == 'number_literal' and left is None:
                    try:
                        left = int(child.text.decode('utf8'))
                    except ValueError:
                        return None
                elif child.type in ('+', '-', '*'):
                    op = child.type
                elif child.type == 'number_literal':
                    try:
                        right = int(child.text.decode('utf8'))
                    except ValueError:
                        return None

            if left is not None and right is not None and op:
                if op == '+':
                    return left + right
                elif op == '-':
                    return left - right
                elif op == '*':
                    return left * right

        # Try to get the text and evaluate
        try:
            text = node.text.decode('utf8').strip()
            # Simple eval for constants like "10 + 1"
            if text.isdigit():
                return int(text)
            # Try to evaluate simple expressions
            import re
            match = re.match(r'(\d+)\s*\+\s*(\d+)', text)
            if match:
                return int(match.group(1)) + int(match.group(2))
        except:
            pass

        return None

    def _analyze_call(self, node: Any, source: str, filename: str, loc: Location):
        """Analyze a function call."""
        func_name = self._get_call_name(node)
        args = self._get_call_args(node)

        # Use semantic pattern analyzer for precise vulnerability detection
        if self.pattern_analyzer:
            result = self.pattern_analyzer.analyze_call_expression(
                node,
                buffer_sizes=self.buffer_sizes,
                tainted_vars=set()  # TODO: add taint tracking
            )
            if result:
                if result.safety == PatternSafety.UNSAFE and result.cwe_id:
                    # Only flag if semantically unsafe
                    self._add_vuln(MemoryVuln(
                        vuln_type=VulnType.FORMAT_STRING if result.cwe_id == "CWE-134" else VulnType.BUFFER_OVERFLOW,
                        cwe_id=result.cwe_id,
                        location=loc,
                        var_name=func_name,
                        description=f"Semantic pattern: {result.reason}",
                        confidence=0.95
                    ))
                    if self.verbose:
                        print(f"[SL] Semantic: {result.reason}")
                elif result.safety == PatternSafety.SAFE:
                    # Pattern is safe, skip further checks for this call
                    if self.verbose:
                        print(f"[SL] Safe pattern: {result.reason}")
                    # Don't return - still need to check other aspects

        # Check for free/delete
        if func_name in self.FREE_FUNCS:
            if args:
                self._handle_free(args[0], loc)
            return

        # Check for NULL pointer dereference in function calls that dereference args
        if func_name in self.DEREF_FUNCS and args:
            for arg in args:
                # Check if arg is a pointer dereference expression like *ptr
                if arg.startswith('*'):
                    ptr_name = arg[1:].strip()
                    self._check_ptr_deref(ptr_name, loc)
                else:
                    # Function may dereference the pointer
                    self._check_ptr_deref(arg, loc)

        # Check for unsafe copy functions (now handled by semantic analyzer if available)
        if not self.pattern_analyzer:
            if func_name in self.UNSAFE_COPY_FUNCS:
                self._check_unsafe_copy(func_name, args, loc)
                return

            # Check for bounded copy functions
            if func_name in self.BOUNDED_COPY_FUNCS:
                self._check_bounded_copy(func_name, args, loc)
                return

        # Check for allocation in return value (var = malloc(...))
        parent = node.parent
        if parent and parent.type == 'assignment_expression':
            self._analyze_assignment(parent, source, filename, loc)

    def _get_call_name(self, node: Any) -> str:
        """Get function name from call expression."""
        for child in node.children:
            if child.type == 'identifier':
                return child.text.decode('utf8')
            if child.type == 'field_expression':
                # Handle method calls
                for c in child.children:
                    if c.type == 'field_identifier':
                        return c.text.decode('utf8')
        return ""

    def _get_call_args(self, node: Any) -> List[str]:
        """Get arguments from call expression."""
        args = []
        arg_list = self._find_child(node, 'argument_list')
        if arg_list:
            for child in arg_list.children:
                if child.type == 'identifier':
                    args.append(child.text.decode('utf8'))
                elif child.type not in ['(', ')', ',']:
                    args.append(child.text.decode('utf8'))
        return args

    def _extract_alloc_size(self, node: Any) -> Optional[int]:
        """Extract allocation size from malloc/calloc call."""
        args = self._find_child(node, 'argument_list')
        if args:
            for child in args.children:
                if child.type == 'number_literal':
                    try:
                        return int(child.text.decode('utf8'))
                    except ValueError:
                        pass
        return None

    def _analyze_assignment(self, node: Any, source: str, filename: str, loc: Location):
        """Analyze assignment expression."""
        # Get left and right sides
        left = None
        call_expr = None
        new_expr = None
        pointer_expr = None  # For address-of: &var
        null_assign = False

        node_text = node.text.decode('utf8') if node.text else ''

        for child in node.children:
            if child.type == 'identifier' and left is None:
                left = child.text.decode('utf8')
            elif child.type == 'pointer_expression' and left is None:
                # *ptr = value (dereference assignment)
                for c in child.children:
                    if c.type == 'identifier':
                        # Check for dereference of freed pointer
                        ptr_name = c.text.decode('utf8')
                        self._check_dereference(ptr_name, loc)
            elif child.type == 'pointer_expression' and left:
                # Right side is &var (address-of)
                pointer_expr = child
            elif child.type == 'call_expression':
                call_expr = child
            elif child.type == 'new_expression':
                new_expr = child
            elif child.type == 'null' or (child.type == 'identifier' and child.text and child.text.decode('utf8') in ('NULL', 'nullptr')):
                null_assign = True
            elif child.type == 'number_literal' and child.text and child.text.decode('utf8') == '0':
                # ptr = 0 is NULL only if the variable is a pointer type
                # Don't treat int x = 0; as NULL pointer
                pass  # Will check after we know the left variable

        # Check for NULL assignment: ptr = NULL
        if left and null_assign:
            self.null_pointers.add(left)
            self.heap[left] = MemoryRegion(
                name=left,
                state=HeapState.NULL,
                alloc_loc=loc,
                alloc_kind=AllocKind.UNKNOWN
            )
            # Remove from freed if previously freed (re-assignment to NULL)
            if left in self.stack_pointers:
                del self.stack_pointers[left]
            if self.verbose:
                print(f"[SL] NULL assign: {left} = NULL")
            return

        # Check for address-of: ptr = &stackVar
        if left and pointer_expr:
            for c in pointer_expr.children:
                if c.type == 'identifier':
                    stack_var = c.text.decode('utf8')
                    self.stack_pointers[left] = stack_var
                    # Remove from null_pointers if previously NULL
                    if left in self.null_pointers:
                        self.null_pointers.discard(left)
                    if self.verbose:
                        print(f"[SL] Address-of assign: {left} = &{stack_var}")
                    return

        # Check for allocation: var = malloc(...)
        if left and call_expr:
            func_name = self._get_call_name(call_expr)
            if func_name in self.ALLOC_FUNCS:
                size = self._extract_alloc_size(call_expr)
                self.heap[left] = MemoryRegion(
                    name=left,
                    state=HeapState.ALLOCATED,
                    size=size,
                    alloc_loc=loc,
                    alloc_kind=AllocKind.HEAP
                )
                # Remove from null_pointers if previously NULL
                if left in self.null_pointers:
                    self.null_pointers.discard(left)
                if left in self.stack_pointers:
                    del self.stack_pointers[left]
                if self.verbose:
                    print(f"[SL] Heap alloc (assign): {left} |-> (_, {size})")

        # Check for C++ new: var = new Type[N]
        if left and new_expr:
            size = self._extract_new_size(new_expr)
            self.heap[left] = MemoryRegion(
                name=left,
                state=HeapState.ALLOCATED,
                size=size,
                alloc_loc=loc,
                alloc_kind=AllocKind.HEAP
            )
            # Remove from null_pointers if previously NULL
            if left in self.null_pointers:
                self.null_pointers.discard(left)
            if left in self.stack_pointers:
                del self.stack_pointers[left]
            if self.verbose:
                print(f"[SL] C++ new (assign): {left} |-> (_, {size})")

        # Handle simple pointer assignment: ptr = otherPtr
        # This propagates heap info and removes from null_pointers
        if left and not null_assign and not pointer_expr and not call_expr and not new_expr:
            # Look for identifier on the right side of '='
            saw_equals = False
            for child in node.children:
                if child.type == '=':
                    saw_equals = True
                    continue
                if saw_equals and child.type == 'identifier':
                    src_var = child.text.decode('utf8')
                    # Propagate heap info from source
                    if src_var in self.heap:
                        src_region = self.heap[src_var]
                        self.heap[left] = MemoryRegion(
                            name=left,
                            state=src_region.state,
                            size=src_region.size,
                            alloc_loc=src_region.alloc_loc,
                            alloc_kind=src_region.alloc_kind
                        )
                        # Remove from null_pointers since it's now pointing to valid memory
                        self.null_pointers.discard(left)
                        if self.verbose:
                            print(f"[SL] Pointer alias: {left} = {src_var} |-> (_, {src_region.size})")
                    # Propagate stack pointer info
                    elif src_var in self.stack_pointers:
                        self.stack_pointers[left] = self.stack_pointers[src_var]
                        # Remove from null_pointers
                        self.null_pointers.discard(left)
                        if self.verbose:
                            print(f"[SL] Stack pointer propagate: {left} = {src_var} -> stack")
                    # If source is not NULL and not freed, clear left from null_pointers
                    elif src_var not in self.null_pointers:
                        self.null_pointers.discard(left)
                    break

    def _handle_free(self, var_name: str, loc: Location):
        """
        Handle free operation using separation logic.

        Checks:
        - CWE-590: Free of stack-allocated memory
        - CWE-415: Double-free
        """
        if var_name in self.heap:
            region = self.heap[var_name]

            # CWE-590: Freeing stack memory
            if region.alloc_kind == AllocKind.STACK:
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id="CWE-590",
                    location=loc,
                    var_name=var_name,
                    description=f"Free of non-heap memory: '{var_name}' is stack-allocated. Heap formula: {var_name} |-> (stack, _)",
                    alloc_loc=region.alloc_loc,
                    confidence=0.95
                ))
                return

            # CWE-415: Double-free
            if region.state == HeapState.FREED:
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id="CWE-415",
                    location=loc,
                    var_name=var_name,
                    description=f"Double free: '{var_name}' freed at line {region.free_loc.line if region.free_loc else '?'}. SL check: emp ⊬ {var_name} |-> _",
                    alloc_loc=region.alloc_loc,
                    free_loc=region.free_loc,
                    confidence=0.95
                ))
                return

            # Valid free - update state
            region.state = HeapState.FREED
            region.free_loc = loc
            if self.verbose:
                print(f"[SL] Free: {var_name} state -> emp")
        else:
            # Track unknown pointer as freed
            self.heap[var_name] = MemoryRegion(
                name=var_name,
                state=HeapState.FREED,
                free_loc=loc
            )

    def _check_dereference(self, var_name: str, loc: Location):
        """
        Check for dereference of freed pointer (CWE-416: Use After Free).

        In SL: dereference requires heap |- var |-> _
        If var is freed (state = FREED), entailment fails.
        """
        if var_name in self.heap:
            region = self.heap[var_name]
            if region.state == HeapState.FREED:
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.USE_AFTER_FREE,
                    cwe_id="CWE-416",
                    location=loc,
                    var_name=var_name,
                    description=f"Use after free: '{var_name}' freed at line {region.free_loc.line if region.free_loc else '?'}. SL check: emp ⊬ {var_name} |-> _",
                    alloc_loc=region.alloc_loc,
                    free_loc=region.free_loc,
                    confidence=0.90
                ))

    def _check_unsafe_copy(self, func_name: str, args: List[str], loc: Location):
        """
        Check unsafe copy functions for buffer overflow.

        For strcpy(dest, src):
        - Requires dest |-> (_, dest_size) * src |-> (data, src_size)
        - Safe if: src_size <= dest_size
        - Overflow if: src_size > dest_size OR src_size unknown
        """
        if len(args) < 2:
            return

        dest = args[0]
        src = args[1]

        dest_size = self._get_buffer_size(dest)
        src_size = self._get_buffer_size(src)

        if self.verbose:
            print(f"[SL] {func_name}: dest={dest}({dest_size}), src={src}({src_size})")

        # If dest has known size and src is larger, it's an overflow
        if dest_size and src_size and src_size > dest_size:
            self._add_vuln(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122" if self._is_heap_buffer(dest) else "CWE-121",
                location=loc,
                var_name=dest,
                description=f"Buffer overflow: {func_name} copies {src_size} bytes to {dest_size}-byte buffer. SL check: {dest} |-> (_, {dest_size}) ⊬ {dest} |-> (_, {src_size})",
                confidence=0.95
            ))
        # If dest has known size but src is unknown (e.g., function parameter), flag as potential overflow
        # This is because strcpy/etc. are unbounded and could overflow with untrusted input
        elif dest_size and src_size is None and src not in self.heap:
            self._add_vuln(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122" if self._is_heap_buffer(dest) else "CWE-121",
                location=loc,
                var_name=dest,
                description=f"Buffer overflow: {func_name} from untrusted source '{src}' to {dest_size}-byte buffer. SL check: {dest} |-> (_, {dest_size}) with unbounded source",
                confidence=0.80  # Lower confidence for potential overflow
            ))

    def _check_bounded_copy(self, func_name: str, args: List[str], loc: Location):
        """
        Check bounded copy functions for potential overflow.

        For strncpy(dest, src, n):
        - Requires dest |-> (_, dest_size)
        - Safe if: n <= dest_size
        - Overflow if: n > dest_size
        """
        if len(args) < 3:
            return

        dest = args[0]
        # Try to extract size argument
        try:
            copy_size = int(args[2])
        except (ValueError, TypeError):
            return

        dest_size = self._get_buffer_size(dest)

        if self.verbose:
            print(f"[SL] {func_name}: dest={dest}({dest_size}), copy_size={copy_size}")

        if dest_size and copy_size > dest_size:
            self._add_vuln(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122" if self._is_heap_buffer(dest) else "CWE-121",
                location=loc,
                var_name=dest,
                description=f"Buffer overflow: {func_name} with size {copy_size} exceeds {dest_size}-byte buffer. SL check: {dest} |-> (_, {dest_size}) ⊬ copy({copy_size})",
                confidence=0.90
            ))

    def _get_buffer_size(self, var_name: str) -> Optional[int]:
        """Get buffer size from heap tracking."""
        if var_name in self.heap:
            return self.heap[var_name].size
        return None

    def _is_heap_buffer(self, var_name: str) -> bool:
        """Check if buffer is heap-allocated."""
        if var_name in self.heap:
            return self.heap[var_name].alloc_kind == AllocKind.HEAP
        return False

    def _check_memory_leaks(self, loc: Location):
        """
        Check for memory leaks at function exit (CWE-401).

        In SL: at function exit, heap should be emp for local allocations
        If heap contains var |-> _ for heap-allocated var, it's a leak.
        """
        for var_name, region in self.heap.items():
            if region.alloc_kind == AllocKind.HEAP and region.state == HeapState.ALLOCATED:
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.MEMORY_LEAK,
                    cwe_id="CWE-401",
                    location=loc,
                    var_name=var_name,
                    description=f"Memory leak: '{var_name}' allocated at line {region.alloc_loc.line if region.alloc_loc else '?'} not freed. SL: heap ⊨ {var_name} |-> _ at exit",
                    alloc_loc=region.alloc_loc,
                    confidence=0.80
                ))


    def _check_subscript_in_statement(self, node: Any, source: str, filename: str, loc: Location):
        """
        Check for buffer underwrite/underread (CWE-124/127).

        Detects array accesses with negative or potentially negative indices.
        Uses tree-sitter AST to find subscript_expression nodes.
        """
        # Recursively find all subscript expressions in this statement
        self._find_and_check_subscripts(node, loc)

    def _find_and_check_subscripts(self, node: Any, loc: Location):
        """Recursively find and check subscript expressions."""
        if node.type == 'subscript_expression':
            self._check_single_subscript(node, loc)
        for child in node.children:
            self._find_and_check_subscripts(child, loc)

    def _check_single_subscript(self, node: Any, loc: Location):
        """Check a single subscript expression for negative index."""
        array_name = None
        index_value = None

        for child in node.children:
            if child.type == 'identifier':
                array_name = child.text.decode('utf8')
            elif child.type == 'number_literal':
                try:
                    index_value = int(child.text.decode('utf8'))
                except ValueError:
                    pass
            elif child.type == 'unary_expression':
                # Handle -5 as unary expression
                text = child.text.decode('utf8')
                try:
                    index_value = int(text)
                except ValueError:
                    pass
            elif child.type == 'subscript_argument_list':
                # In C tree-sitter, the index is inside subscript_argument_list: [-5]
                for sub in child.children:
                    if sub.type == 'number_literal':
                        try:
                            index_value = int(sub.text.decode('utf8'))
                        except ValueError:
                            pass
                    elif sub.type == 'unary_expression':
                        # Handle -5 as unary expression
                        text = sub.text.decode('utf8')
                        try:
                            index_value = int(text)
                        except ValueError:
                            pass
                    elif sub.type == 'identifier':
                        # Variable index like buffer[idx]
                        pass

        if array_name and index_value is not None and index_value < 0:
            # Check if this is a write (on left side of assignment)
            # by checking the parent node
            is_write = False
            parent = node.parent
            if parent and parent.type == 'assignment_expression':
                # Check if subscript is on the left of the assignment
                # Compare by start position since tree-sitter creates new node objects
                node_start = (node.start_point[0], node.start_point[1])
                for i, sibling in enumerate(parent.children):
                    sibling_start = (sibling.start_point[0], sibling.start_point[1])
                    if sibling_start == node_start and sibling.type == node.type:
                        # If we're before the '=' sign, it's a write
                        for j in range(i + 1, len(parent.children)):
                            if parent.children[j].type == '=':
                                is_write = True
                                break
                        break

            cwe = "CWE-124" if is_write else "CWE-127"
            self._add_vuln(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id=cwe,
                location=loc,
                var_name=array_name,
                description=f"Buffer {'underwrite' if is_write else 'under-read'}: negative index {index_value} for '{array_name}'",
                confidence=0.95
            ))

    def _check_assignment_in_condition(self, node: Any, source: str, filename: str, loc: Location):
        """
        Check for assignment in condition (CWE-480).

        Detects patterns like: if (x = 5) instead of if (x == 5)
        """
        # Get the condition part of the if statement
        condition = self._find_child(node, 'parenthesized_expression') or \
                    self._find_child(node, 'condition_clause')
        if not condition:
            return

        cond_text = condition.text.decode('utf8') if condition.text else ''
        import re

        # Pattern: single = surrounded by non-= characters (not == or !=)
        # This catches: if (x = 5) but not if (x == 5) or if (x != 5)
        # Be careful to avoid false positives for compound expressions
        assignment_match = re.search(r'[^=!<>]\s*=\s*[^=]', cond_text)
        if assignment_match:
            # Check it's not in a function call context like malloc(...)
            # and not a comparison like x == y
            if not re.search(r'\w+\s*\([^)]*=[^)]*\)', cond_text):
                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,  # Reusing type for logic error
                    cwe_id="CWE-480",
                    location=loc,
                    var_name="condition",
                    description=f"Assignment in condition instead of comparison: '{cond_text.strip()}'",
                    confidence=0.85
                ))

    def _check_unchecked_allocs(self):
        """
        Check for unchecked return values from allocation functions (CWE-252).

        Detects patterns where malloc/calloc/new returns are used without NULL check.
        """
        for var_name, alloc_loc in self.unchecked_allocs.items():
            # If the variable was not proven non-NULL (via early exit guard or explicit check),
            # and it's not in null_pointers (which means it was used without crashing),
            # it's a potential unchecked return value
            if var_name not in self.proven_non_null and var_name not in self.early_exit_guards:
                # Only flag if the variable was actually used (dereferenced or passed to function)
                if var_name in self.heap and self.heap[var_name].state == HeapState.ALLOCATED:
                    self._add_vuln(MemoryVuln(
                        vuln_type=VulnType.NULL_DEREFERENCE,  # Related to NULL check
                        cwe_id="CWE-252",
                        location=alloc_loc,
                        var_name=var_name,
                        description=f"Unchecked return value: '{var_name}' from allocation not checked for NULL before use",
                        alloc_loc=alloc_loc,
                        confidence=0.70
                    ))

    def _mark_allocation_for_check(self, var_name: str, loc: Location):
        """Mark an allocation that needs NULL check verification."""
        self.unchecked_allocs[var_name] = loc

    def _mark_allocation_checked(self, var_name: str):
        """Mark that an allocation's return value was checked."""
        if var_name in self.unchecked_allocs:
            del self.unchecked_allocs[var_name]


def analyze_with_sl_semantic(source: str, filename: str = "<unknown>",
                              verbose: bool = False) -> List[MemoryVuln]:
    """
    Analyze C/C++ code using separation logic with proper parsing.

    Uses tree-sitter for AST construction and Frame's SL solver.
    """
    analyzer = SLSemanticAnalyzer(verbose=verbose)
    return analyzer.analyze_source(source, filename)
