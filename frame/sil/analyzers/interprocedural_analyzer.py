"""
Inter-procedural Memory Safety Analyzer for C/C++ using Separation Logic.

This module implements full inter-procedural analysis to detect memory safety
vulnerabilities across function boundaries, class methods, and file boundaries.

Key capabilities:
1. Class member tracking across constructor/destructor/methods
2. Function summaries for call graph analysis
3. Parameter and return value data flow tracking
4. Alias analysis for pointer relationships

Uses Frame's separation logic foundation for precise heap reasoning.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
import re

from frame.sil.types import Location
from frame.sil.translator import VulnType
from frame.sil.analyzers.sl_memory_analyzer import SLMemoryAnalyzer, MemoryVuln as SLMemoryVuln

# A C integer literal with its suffixes: 20, 1u, 0x1UL.
_C_INT_LITERAL = re.compile(r'(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*$')


class HeapEffect(Enum):
    """Effect a function has on heap state"""
    ALLOCATE = "allocate"      # Allocates memory
    FREE = "free"              # Frees memory
    READ = "read"              # Reads from pointer
    WRITE = "write"            # Writes to pointer
    RETURN_ALLOC = "return_alloc"  # Returns allocated memory
    STORE_MEMBER = "store_member"  # Stores to class member


@dataclass
class HeapOperation:
    """A single heap operation"""
    effect: HeapEffect
    var_name: str
    location: Location
    size: Optional[int] = None
    target_member: Optional[str] = None  # For store to member


@dataclass
class FunctionSummary:
    """Summary of a function's effects on heap state"""
    name: str
    class_name: Optional[str] = None  # For class methods
    is_constructor: bool = False
    is_destructor: bool = False
    parameters: List[str] = field(default_factory=list)
    heap_ops: List[HeapOperation] = field(default_factory=list)
    # Which parameters are freed
    frees_params: Set[int] = field(default_factory=set)
    # Which parameters are dereferenced
    derefs_params: Set[int] = field(default_factory=set)
    # Returns allocated memory
    returns_allocated: bool = False
    # Modifies which member variables
    modifies_members: Set[str] = field(default_factory=set)
    # Frees which member variables
    frees_members: Set[str] = field(default_factory=set)


@dataclass
class ClassDefinition:
    """Parsed class definition"""
    name: str
    member_vars: Dict[str, str] = field(default_factory=dict)  # name -> type
    methods: List[str] = field(default_factory=list)
    has_constructor: bool = False
    has_destructor: bool = False
    has_copy_constructor: bool = False  # Explicit copy constructor
    has_operator_equals: bool = False   # operator= defined
    has_self_assignment_check: bool = False  # operator= checks for self-assignment
    base_classes: List[str] = field(default_factory=list)


@dataclass
class MemberState:
    """State of a class member variable"""
    name: str
    is_allocated: bool = False
    is_freed: bool = False
    alloc_location: Optional[Location] = None
    free_location: Optional[Location] = None


@dataclass
class MemoryVuln:
    """Detected vulnerability"""
    vuln_type: VulnType
    cwe_id: str
    location: Location
    var_name: str
    description: str
    alloc_location: Optional[Location] = None
    free_location: Optional[Location] = None
    confidence: float = 0.9


class InterproceduralAnalyzer:
    """
    Inter-procedural memory safety analyzer using separation logic.

    Analysis phases:
    1. Parse classes and extract member variables
    2. Build function summaries for all functions
    3. Analyze each function with inter-procedural context
    4. Track member state across class lifecycle
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.classes: Dict[str, ClassDefinition] = {}
        self.functions: Dict[str, FunctionSummary] = {}
        self.vulnerabilities: List[MemoryVuln] = []
        self._reported: Set[Tuple[str, int]] = set()

    def _add_vuln(self, vuln: MemoryVuln) -> bool:
        """Add vulnerability if not already reported."""
        key = (vuln.cwe_id, vuln.location.line)
        if key in self._reported:
            return False
        self._reported.add(key)
        self.vulnerabilities.append(vuln)
        return True

    def analyze_source(self, source: str, filename: str = "<unknown>") -> List[MemoryVuln]:
        """
        Perform full inter-procedural analysis on C/C++ source.

        Args:
            source: Source code to analyze
            filename: Filename for reporting

        Returns:
            List of detected vulnerabilities
        """
        self.vulnerabilities = []
        self._reported = set()

        lines = source.split('\n')

        # Phase 1: Parse class definitions
        self._parse_classes(lines, filename)

        # Phase 2: Build function summaries
        self._build_function_summaries(lines, filename)

        # Phase 3: Analyze class lifecycles for member variable issues
        self._analyze_class_lifecycles(lines, filename)

        # Phase 4: Analyze individual functions with inter-procedural context
        self._analyze_functions_interprocedural(lines, filename)

        return self.vulnerabilities

    def _parse_classes(self, lines: List[str], filename: str):
        """Parse class definitions and extract member variables."""
        self.classes = {}

        # Also track inline destructor info for later summary building
        self._inline_dtor_frees: Dict[str, Set[str]] = {}  # class_name -> freed members

        in_class = False
        current_class = None
        brace_depth = 0
        access_specifier = "private"  # Default for class

        # For inline method body parsing
        in_inline_method = False
        inline_method_type = None  # 'ctor', 'dtor', 'operator='
        inline_method_depth = 0
        inline_local_vars: Set[str] = set()  # Track locally declared variables

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith('//'):
                continue

            # Detect class/struct definition
            class_match = re.match(r'^(?:class|struct)\s+(\w+)(?:\s*:\s*(?:public|private|protected)?\s*(\w+))?\s*\{?', stripped)
            if class_match:
                class_name = class_match.group(1)
                base_class = class_match.group(2)

                current_class = ClassDefinition(
                    name=class_name,
                    base_classes=[base_class] if base_class else []
                )
                self.classes[class_name] = current_class
                self._inline_dtor_frees[class_name] = set()
                in_class = True
                brace_depth = stripped.count('{') - stripped.count('}')
                access_specifier = "private" if "class" in stripped else "public"

                if self.verbose:
                    print(f"[IPA] Found class: {class_name}")
                continue

            if in_class and current_class:
                # Handle inline method body tracking
                if in_inline_method:
                    # Update depth
                    old_depth = inline_method_depth
                    inline_method_depth += stripped.count('{') - stripped.count('}')

                    # Track local variable declarations in method body
                    # Pattern: Type* var = ... or Type *var = ... or Type var = ...
                    local_decl = re.search(r'^(?:const\s+)?(?:\w+)\s*\*?\s*(\w+)\s*=', stripped)
                    if local_decl and old_depth > 0:
                        inline_local_vars.add(local_decl.group(1))

                    # Check for free/delete in destructor body (only inside the body)
                    if inline_method_type == 'dtor' and (old_depth > 0 or '{' in stripped):
                        # Check for explicit this-> frees first
                        this_free_match = re.search(r'(?:delete\s*(?:\[\s*\])?\s*|free\s*\(\s*)this->(\w+)', stripped)
                        if this_free_match:
                            freed_var = this_free_match.group(1)
                            self._inline_dtor_frees[current_class.name].add(freed_var)
                            if self.verbose:
                                print(f"[IPA] Inline destructor frees member: {current_class.name}::this->{freed_var}")
                        else:
                            # Check for implicit member frees (not local variables)
                            free_match = re.search(r'(?:delete\s*(?:\[\s*\])?\s*|free\s*\(\s*)(\w+)', stripped)
                            if free_match:
                                freed_var = free_match.group(1)
                                # Track all freed vars that aren't local variables
                                # (member_vars may not be fully populated yet, will verify later)
                                if freed_var not in inline_local_vars:
                                    self._inline_dtor_frees[current_class.name].add(freed_var)
                                    if self.verbose:
                                        print(f"[IPA] Inline destructor frees: {current_class.name}::{freed_var}")

                    if inline_method_depth <= 0 and old_depth > 0:
                        in_inline_method = False
                        inline_method_type = None
                        inline_local_vars.clear()  # Reset for next method
                    continue

                brace_depth += stripped.count('{') - stripped.count('}')

                if brace_depth <= 0:
                    in_class = False
                    current_class = None
                    continue

                # Track access specifiers
                if stripped in ('public:', 'private:', 'protected:'):
                    access_specifier = stripped[:-1]
                    continue

                # Detect copy constructor FIRST: ClassName(const ClassName& ...) or ClassName(ClassName& ...)
                # Must check before regular constructor since ctor pattern also matches
                copy_ctor_match = re.match(
                    rf'^{current_class.name}\s*\(\s*(?:const\s+)?{current_class.name}\s*&',
                    stripped
                )
                if copy_ctor_match:
                    current_class.has_copy_constructor = True
                    current_class.has_constructor = True  # Also a constructor
                    if self.verbose:
                        print(f"[IPA] Found copy constructor: {current_class.name}")
                    # Handle inline body
                    if '{' in stripped:
                        in_inline_method = True
                        inline_method_type = 'ctor'
                        inline_method_depth = stripped.count('{') - stripped.count('}')
                    continue

                # Detect constructor (after copy constructor check)
                ctor_match = re.match(rf'^{current_class.name}\s*\([^)]*\)', stripped)
                if ctor_match:
                    current_class.has_constructor = True
                    current_class.methods.append(f"{current_class.name}::{current_class.name}")
                    # Check if inline body starts
                    if '{' in stripped:
                        in_inline_method = True
                        inline_method_type = 'ctor'
                        inline_method_depth = stripped.count('{') - stripped.count('}')
                    continue

                # Detect destructor - with inline body parsing
                dtor_match = re.match(rf'^~{current_class.name}\s*\([^)]*\)', stripped)
                if dtor_match:
                    current_class.has_destructor = True
                    current_class.methods.append(f"{current_class.name}::~{current_class.name}")
                    inline_local_vars.clear()  # Reset local vars for new method
                    # Check if inline body starts (on same line or expect on next line)
                    if '{' in stripped:
                        in_inline_method = True
                        inline_method_type = 'dtor'
                        inline_method_depth = stripped.count('{') - stripped.count('}')
                        # Check for explicit this-> frees on same line
                        this_free_match = re.search(r'(?:delete\s*(?:\[\s*\])?\s*|free\s*\(\s*)this->(\w+)', stripped)
                        if this_free_match:
                            freed_var = this_free_match.group(1)
                            self._inline_dtor_frees[current_class.name].add(freed_var)
                            if self.verbose:
                                print(f"[IPA] Inline destructor frees member: {current_class.name}::this->{freed_var}")
                        else:
                            # Check for known member frees
                            free_match = re.search(r'(?:delete\s*(?:\[\s*\])?\s*|free\s*\(\s*)(\w+)', stripped)
                            if free_match:
                                freed_var = free_match.group(1)
                                if freed_var in current_class.member_vars:
                                    self._inline_dtor_frees[current_class.name].add(freed_var)
                                    if self.verbose:
                                        print(f"[IPA] Inline destructor frees member: {current_class.name}::{freed_var}")
                    else:
                        # Body starts on next line - mark as pending
                        in_inline_method = True
                        inline_method_type = 'dtor'
                        inline_method_depth = 0  # Will be updated when we see '{'
                    continue

                # Detect operator=
                op_eq_match = re.match(r'^\s*(?:\w+(?:\s*&)?\s+)?operator\s*=', stripped)
                if op_eq_match:
                    current_class.has_operator_equals = True
                    if self.verbose:
                        print(f"[IPA] Found operator= in {current_class.name}")
                    # Check if inline body starts
                    if '{' in stripped:
                        in_inline_method = True
                        inline_method_type = 'operator='
                        inline_method_depth = stripped.count('{') - stripped.count('}')
                    continue

                # Detect member variables (pointer types are most important)
                # Handle multiple patterns:
                # - "char* data;"  (pointer with type)
                # - "char *data;" (pointer with name)
                # - "int count;"  (non-pointer)
                member_match = re.match(r'^(\w+)\s*(\*?)\s*(\w+)\s*;', stripped)
                if member_match:
                    base_type = member_match.group(1)
                    ptr_marker = member_match.group(2)
                    member_name = member_match.group(3)
                    # Filter out reserved words and common false positives
                    if member_name not in ('this', 'return', 'if', 'else', 'while', 'for'):
                        member_type = f"{base_type}{ptr_marker}" if ptr_marker else base_type
                        current_class.member_vars[member_name] = member_type

                        if self.verbose:
                            print(f"[IPA] Found member: {current_class.name}::{member_name} ({member_type})")

                # Detect method declarations
                method_match = re.match(r'^(?:virtual\s+)?(?:\w+(?:\s*[*&])?\s+)?(\w+)\s*\([^)]*\)', stripped)
                if method_match and not ctor_match and not dtor_match:
                    method_name = method_match.group(1)
                    if method_name not in ('if', 'while', 'for', 'switch', 'return'):
                        current_class.methods.append(f"{current_class.name}::{method_name}")

    def _build_function_summaries(self, lines: List[str], filename: str):
        """Build summaries of each function's heap effects."""
        self.functions = {}

        in_function = False
        current_func = None
        brace_depth = 0
        func_start_line = 0
        func_local_vars: Set[str] = set()  # Track local variables in current function

        # Also track inferred classes from method implementations
        # (when class definition is in a header file)
        inferred_classes: Dict[str, ClassDefinition] = {}

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            if not stripped or stripped.startswith('//'):
                continue

            # Detect function definition (including class methods)
            # Pattern: [return_type] [class::]name(params) [const] {
            # Also handles: ClassName::ClassName (constructor) and ClassName::~ClassName (destructor)
            #
            # IMPORTANT: Must distinguish function DEFINITIONS from function CALLS:
            # - Definition: void foo() { ... }  or  Class::foo() { ... }
            # - Call: foo(arg);  or  free(ptr);
            #
            # Key difference: definitions have { or end of line, calls end with );
            func_match = re.match(
                r'^(?:virtual\s+)?(?:(\w+(?:\s*[*&])?)\s+)?(?:(\w+)::)?(~?\w+)\s*\(([^)]*)\)\s*(?:const)?\s*(\{)?',
                stripped
            )

            # Only treat as function definition if:
            # 1. Has opening brace on same line, OR
            # 2. Has a return type, OR
            # 3. Has class:: prefix (method implementation)
            # Exclude: plain function calls like free(data);
            is_definition = False
            if func_match:
                has_return_type = func_match.group(1) is not None
                has_class_prefix = func_match.group(2) is not None
                has_brace = func_match.group(5) is not None
                ends_with_semicolon = stripped.rstrip().endswith(';')

                is_definition = (has_brace or has_return_type or has_class_prefix) and not ends_with_semicolon

            if is_definition and func_match and not any(kw in stripped.split()[0] for kw in ['if', 'while', 'for', 'switch']):
                return_type = func_match.group(1) or 'void'
                class_name = func_match.group(2)

                # If we see ClassName::method, infer the class exists
                if class_name and class_name not in self.classes:
                    if class_name not in inferred_classes:
                        inferred_classes[class_name] = ClassDefinition(name=class_name)
                        if self.verbose:
                            print(f"[IPA] Inferred class from method: {class_name}")
                func_name = func_match.group(3)
                params_str = func_match.group(4)

                # Parse parameters
                params = []
                if params_str.strip():
                    for param in params_str.split(','):
                        param = param.strip()
                        param_match = re.search(r'(\w+)\s*$', param)
                        if param_match:
                            params.append(param_match.group(1))

                # Create function summary
                full_name = f"{class_name}::{func_name}" if class_name else func_name

                # Handle destructor: func_name is "~ClassName"
                is_dtor = func_name.startswith('~') and class_name and func_name == f"~{class_name}"
                is_ctor = class_name and func_name == class_name

                if self.verbose and (is_ctor or is_dtor):
                    print(f"[IPA] {'Constructor' if is_ctor else 'Destructor'}: {full_name}")

                current_func = FunctionSummary(
                    name=full_name,
                    class_name=class_name,
                    is_constructor=is_ctor,
                    is_destructor=is_dtor,
                    parameters=params,
                )

                # Track constructor/destructor in inferred class
                if class_name and class_name in inferred_classes:
                    if is_ctor:
                        inferred_classes[class_name].has_constructor = True
                        inferred_classes[class_name].methods.append(full_name)
                    if is_dtor:
                        inferred_classes[class_name].has_destructor = True
                        inferred_classes[class_name].methods.append(full_name)

                self.functions[full_name] = current_func
                in_function = True
                brace_depth = stripped.count('{') - stripped.count('}')
                func_start_line = line_num
                func_local_vars.clear()  # Reset local vars for new function
                # Add parameters as locals
                func_local_vars.update(params)

                if self.verbose:
                    print(f"[IPA] Analyzing function: {full_name}")
                continue

            if in_function and current_func:
                brace_depth += stripped.count('{') - stripped.count('}')

                if brace_depth <= 0:
                    in_function = False
                    current_func = None
                    func_local_vars.clear()
                    continue

                loc = Location(file=filename, line=line_num, column=0)

                # Track local variable declarations
                # Pattern: Type* var = ... or Type *var = ... or Type var = ... or Type var;
                local_decl = re.search(r'^(?:const\s+)?(?:\w+)\s*\*?\s*(\w+)\s*(?:=|;)', stripped)
                if local_decl:
                    func_local_vars.add(local_decl.group(1))

                # Track heap operations in this function
                self._analyze_line_for_summary(stripped, loc, current_func, inferred_classes, func_local_vars)

        # Merge inferred classes into main classes dict
        for class_name, class_def in inferred_classes.items():
            if class_name not in self.classes:
                self.classes[class_name] = class_def
                if self.verbose:
                    print(f"[IPA] Added inferred class: {class_name} with members: {list(class_def.member_vars.keys())}")

    def _analyze_line_for_summary(self, line: str, loc: Location, func: FunctionSummary,
                                    inferred_classes: Dict[str, ClassDefinition] = None,
                                    local_vars: Set[str] = None):
        """Analyze a line and update function summary."""
        if inferred_classes is None:
            inferred_classes = {}
        if local_vars is None:
            local_vars = set()

        # Helper to add inferred member variable
        def infer_member(class_name: str, member_name: str, member_type: str = 'void*'):
            if class_name in inferred_classes:
                if member_name not in inferred_classes[class_name].member_vars:
                    inferred_classes[class_name].member_vars[member_name] = member_type
                    if self.verbose:
                        print(f"[IPA] Inferred member: {class_name}::{member_name}")

        # Detect allocations: var = malloc/new
        alloc_match = re.search(r'^\s*(\w+)\s*=\s*(?:\([^)]*\))?\s*(?:malloc|calloc|new)\s*', line)
        if alloc_match:
            var_name = alloc_match.group(1)

            # Skip if var_name is a known non-member (e.g., parameters, common locals)
            if var_name in func.parameters:
                pass  # It's a parameter, not a member
            elif var_name in ('temp', 'tmp', 'result', 'ret', 'ptr', 'p', 'i', 'j', 'k', 'n'):
                pass  # Common local variable names
            else:
                func.heap_ops.append(HeapOperation(
                    effect=HeapEffect.ALLOCATE,
                    var_name=var_name,
                    location=loc
                ))

                # Check if storing to member (this->member or just member for class method)
                if func.class_name:
                    # Could be storing to class member
                    if 'this->' in line:
                        member_match = re.search(r'this->(\w+)\s*=', line)
                        if member_match:
                            member_name = member_match.group(1)
                            func.modifies_members.add(member_name)
                            infer_member(func.class_name, member_name)
                            func.heap_ops.append(HeapOperation(
                                effect=HeapEffect.STORE_MEMBER,
                                var_name=var_name,
                                location=loc,
                                target_member=member_name
                            ))
                    else:
                        # Direct assignment to member without this->
                        # Only infer if it looks like a reasonable member name
                        if len(var_name) > 1 and not var_name[0].isupper():
                            func.modifies_members.add(var_name)
                            infer_member(func.class_name, var_name)
                            func.heap_ops.append(HeapOperation(
                                effect=HeapEffect.STORE_MEMBER,
                                var_name=var_name,
                                location=loc,
                                target_member=var_name
                            ))

        # Detect frees: free(var) or delete var
        # First check for explicit this-> frees
        this_free_match = re.search(r'(?:free|delete(?:\s*\[\])?)\s*\(?\s*this->(\w+)', line)
        if this_free_match:
            member_name = this_free_match.group(1)
            func.heap_ops.append(HeapOperation(
                effect=HeapEffect.FREE,
                var_name=member_name,
                location=loc
            ))
            if func.class_name:
                func.frees_members.add(member_name)
                infer_member(func.class_name, member_name)
        else:
            # Check for non-this free
            free_match = re.search(r'(?:free|delete(?:\s*\[\])?)\s*\(?\s*(\w+)', line)
            if free_match:
                var_name = free_match.group(1)
                func.heap_ops.append(HeapOperation(
                    effect=HeapEffect.FREE,
                    var_name=var_name,
                    location=loc
                ))

                # Only flag as member free if:
                # 1. It's NOT a local variable, AND
                # 2. It's a known member from the class definition
                if func.class_name and var_name not in local_vars:
                    # Check if var is a known member of the class
                    class_def = self.classes.get(func.class_name) or inferred_classes.get(func.class_name)
                    if class_def and var_name in class_def.member_vars:
                        func.frees_members.add(var_name)
                        # Don't infer - only use known members

                # Check if freeing parameter
                for i, param in enumerate(func.parameters):
                    if param == var_name or var_name == param:
                        func.frees_params.add(i)

        # Detect dereferences
        deref_match = re.search(r'(?:\*\s*(\w+)|(\w+)\s*->|(\w+)\s*\[)', line)
        if deref_match:
            var_name = deref_match.group(1) or deref_match.group(2) or deref_match.group(3)
            func.heap_ops.append(HeapOperation(
                effect=HeapEffect.READ,
                var_name=var_name,
                location=loc
            ))

            # Check if dereferencing parameter
            for i, param in enumerate(func.parameters):
                if param == var_name:
                    func.derefs_params.add(i)

    def _analyze_class_lifecycles(self, lines: List[str], filename: str):
        """
        Analyze class member variable lifecycles across all methods.

        This is the key inter-procedural analysis:
        - Track what constructor does to members
        - Track what destructor does to members
        - Detect double-free when both free the same member
        - Detect UAF when member is freed in one method, used in another
        """
        for class_name, class_def in self.classes.items():
            if self.verbose:
                print(f"[IPA] Analyzing class lifecycle: {class_name}")

            member_states: Dict[str, MemberState] = {}

            # Initialize member states
            for member_name in class_def.member_vars:
                member_states[member_name] = MemberState(name=member_name)

            # Find constructor and destructor summaries
            ctor_name = f"{class_name}::{class_name}"
            dtor_name = f"{class_name}::~{class_name}"

            ctor_summary = self.functions.get(ctor_name)
            dtor_summary = self.functions.get(dtor_name)

            # Track what constructor does to members
            if ctor_summary:
                for member in ctor_summary.modifies_members:
                    if member in member_states:
                        member_states[member].is_allocated = True
                        # Find allocation location
                        for op in ctor_summary.heap_ops:
                            if op.effect == HeapEffect.STORE_MEMBER and op.target_member == member:
                                member_states[member].alloc_location = op.location

                for member in ctor_summary.frees_members:
                    if member in member_states:
                        member_states[member].is_freed = True
                        # Find free location
                        for op in ctor_summary.heap_ops:
                            if op.effect == HeapEffect.FREE and member in op.var_name:
                                member_states[member].free_location = op.location

            # Check destructor for double-free
            if dtor_summary:
                for member in dtor_summary.frees_members:
                    if member in member_states:
                        state = member_states[member]

                        # If already freed in constructor, this is a double-free
                        if state.is_freed:
                            # Find the free location in destructor
                            dtor_free_loc = None
                            for op in dtor_summary.heap_ops:
                                if op.effect == HeapEffect.FREE and member in op.var_name:
                                    dtor_free_loc = op.location
                                    break

                            if dtor_free_loc:
                                self._add_vuln(MemoryVuln(
                                    vuln_type=VulnType.DOUBLE_FREE,
                                    cwe_id="CWE-415",
                                    location=dtor_free_loc,
                                    var_name=member,
                                    description=f"Double free: '{class_name}::{member}' freed in constructor (line {state.free_location.line if state.free_location else '?'}), freed again in destructor",
                                    alloc_location=state.alloc_location,
                                    free_location=state.free_location,
                                    confidence=0.95,
                                ))

                                if self.verbose:
                                    print(f"[IPA] DOUBLE FREE: {class_name}::{member}")

            # Check for use-after-free across methods
            self._check_uaf_across_methods(class_name, class_def, member_states, filename)

            # Check for missing copy constructor (only when copy construction is actually used)
            self._check_missing_copy_constructor(class_name, class_def, dtor_summary, filename, lines)

            # Check for self-assignment UAF in operator=
            self._check_operator_equals_uaf(class_name, class_def, lines, filename)

    def _check_uaf_across_methods(self, class_name: str, class_def: ClassDefinition,
                                   member_states: Dict[str, MemberState], filename: str):
        """Check for use-after-free across class methods."""

        # For each method, check if it uses a member that was freed elsewhere
        for method_name in class_def.methods:
            method_summary = self.functions.get(method_name)
            if not method_summary:
                continue

            # Check each heap operation in this method
            for op in method_summary.heap_ops:
                if op.effect in (HeapEffect.READ, HeapEffect.WRITE):
                    var_name = op.var_name.replace('this->', '')

                    if var_name in member_states:
                        state = member_states[var_name]

                        # If member was freed (in constructor or another method)
                        # and this method dereferences it, it's UAF
                        if state.is_freed and op.effect == HeapEffect.READ:
                            # Don't flag if this IS the method that frees it
                            if var_name not in method_summary.frees_members:
                                self._add_vuln(MemoryVuln(
                                    vuln_type=VulnType.USE_AFTER_FREE,
                                    cwe_id="CWE-416",
                                    location=op.location,
                                    var_name=var_name,
                                    description=f"Use after free: '{class_name}::{var_name}' freed at line {state.free_location.line if state.free_location else '?'}, used in {method_name}",
                                    alloc_location=state.alloc_location,
                                    free_location=state.free_location,
                                    confidence=0.90,
                                ))

    def _check_missing_copy_constructor(self, class_name: str, class_def: ClassDefinition,
                                         dtor_summary: Optional[FunctionSummary], filename: str,
                                         lines: List[str] = None):
        """
        Detect missing copy constructor leading to double-free.

        Pattern: Class has destructor that frees member but no explicit copy constructor.
        Using default (shallow) copy constructor leads to double-free when both
        original and copy are destroyed.

        Separation Logic reasoning:
        - Original: ptr |-> val
        - After shallow copy: ptr |-> val * ptr |-> val (invalid!)
        - When both destruct: double free on ptr

        Key improvement: Only flag if copy construction is actually used in the code,
        to reduce false positives on wrapper classes that are never copied.
        """
        # Get freed members from either out-of-class destructor or inline destructor
        freed_members = set()
        free_loc = None

        # Check out-of-class destructor summary
        if dtor_summary and dtor_summary.frees_members:
            freed_members.update(dtor_summary.frees_members)
            for op in dtor_summary.heap_ops:
                if op.effect == HeapEffect.FREE:
                    free_loc = op.location
                    break

        # Check inline destructor frees
        if hasattr(self, '_inline_dtor_frees') and class_name in self._inline_dtor_frees:
            inline_frees = self._inline_dtor_frees[class_name]
            if inline_frees:
                # Filter to only include actual member variables
                # (during parsing, we tracked all frees; now verify against member_vars)
                verified_frees = {f for f in inline_frees if f in class_def.member_vars}
                freed_members.update(verified_frees)
                # Find destructor line for location
                if not free_loc and verified_frees:
                    # Default to class definition location
                    free_loc = Location(file=filename, line=1, column=0)

        # Only flag if destructor frees members AND no copy constructor AND copy is used
        if freed_members and not class_def.has_copy_constructor:
            # Look for actual copy construction usage in the code
            copy_found = False
            copy_line_num = None

            if lines:
                for line_num, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    # Skip comments
                    if stripped.startswith('//') or stripped.startswith('/*'):
                        continue

                    # Look for copy construction: ClassName obj2(obj1)
                    # Pattern: ClassName identifier(identifier)
                    copy_match = re.search(
                        rf'\b{class_name}\s+(\w+)\s*\(\s*(\w+)\s*\)',
                        stripped
                    )
                    if copy_match:
                        new_obj = copy_match.group(1)
                        source_obj = copy_match.group(2)
                        # Exclude constructor calls with literal args like ClassName obj("string")
                        if not source_obj.startswith('"') and source_obj != 'NULL' and source_obj != 'nullptr':
                            # Make sure source_obj is not a string literal or number
                            if not re.match(r'^[0-9"\']+', source_obj):
                                copy_found = True
                                copy_line_num = line_num
                                break

                    # Also look for: ClassName obj2 = obj1 (copy initialization)
                    copy_init_match = re.search(
                        rf'\b{class_name}\s+(\w+)\s*=\s*(\w+)\s*;',
                        stripped
                    )
                    if copy_init_match:
                        new_obj = copy_init_match.group(1)
                        source_obj = copy_init_match.group(2)
                        if not source_obj.startswith('"') and source_obj != 'NULL' and source_obj != 'nullptr':
                            if not re.match(r'^[0-9"\']+', source_obj):
                                copy_found = True
                                copy_line_num = line_num
                                break

            if copy_found:
                freed_member = next(iter(freed_members))

                # Use copy location if we found it, otherwise use destructor free location
                loc = Location(file=filename, line=copy_line_num, column=0) if copy_line_num else free_loc

                self._add_vuln(MemoryVuln(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id="CWE-415",
                    location=loc if loc else Location(file=filename, line=1, column=0),
                    var_name=freed_member,
                    description=f"Missing copy constructor: '{class_name}' has destructor freeing '{freed_member}' but no copy constructor - shallow copy leads to double free",
                    confidence=0.90,
                ))

                if self.verbose:
                    print(f"[IPA] MISSING COPY CTOR: {class_name} - double free risk")

    def _check_operator_equals_uaf(self, class_name: str, class_def: ClassDefinition,
                                    lines: List[str], filename: str):
        """
        Detect use-after-free in operator= due to missing self-assignment check.

        Pattern: In operator=, if we delete this->member then access other.member
        without checking for self-assignment (this != &other), self-assignment
        leads to UAF.

        Separation Logic reasoning:
        - Before: this->ptr |-> val (and other.ptr is same if self-assign)
        - After delete: emp (ptr is dangling)
        - Access other.ptr: INVALID - use after free
        """
        if not class_def.has_operator_equals:
            return

        # Look for operator= implementation in the source
        in_operator_equals = False
        brace_depth = 0
        has_self_check = False
        delete_line = None
        delete_var = None
        access_after_delete = None
        access_line = None

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Detect operator= start
            if re.search(rf'\b{class_name}\s*&\s*(?:{class_name}::)?operator\s*=', stripped) or \
               (in_operator_equals is False and re.search(r'\boperator\s*=\s*\(', stripped)):
                # Check if this is for our class
                if class_name in stripped or in_operator_equals is False:
                    in_operator_equals = True
                    brace_depth = stripped.count('{') - stripped.count('}')
                    has_self_check = False
                    delete_line = None
                    delete_var = None
                    continue

            if in_operator_equals:
                brace_depth += stripped.count('{') - stripped.count('}')

                if brace_depth <= 0:
                    # End of operator=
                    # If we found delete but no self-check, it's a potential UAF
                    if delete_line and not has_self_check:
                        loc = Location(file=filename, line=delete_line, column=0)
                        self._add_vuln(MemoryVuln(
                            vuln_type=VulnType.USE_AFTER_FREE,
                            cwe_id="CWE-416",
                            location=loc,
                            var_name=delete_var or "member",
                            description=f"Self-assignment UAF: '{class_name}::operator=' deletes member without self-assignment check - self-assignment causes use-after-free",
                            confidence=0.90,
                        ))

                        if self.verbose:
                            print(f"[IPA] SELF-ASSIGNMENT UAF: {class_name}::operator=")

                    in_operator_equals = False
                    continue

                # Check for self-assignment check: if (this != &other) or if (&other != this)
                if re.search(r'if\s*\(\s*(?:this\s*!=|&\w+\s*!=\s*this|this\s*==|&\w+\s*==\s*this)', stripped):
                    has_self_check = True

                # Check for delete operation
                delete_match = re.search(r'delete\s*(?:\[\s*\])?\s*(?:this->)?(\w+)', stripped)
                if delete_match:
                    delete_line = line_num
                    delete_var = delete_match.group(1)

    def _analyze_functions_interprocedural(self, lines: List[str], filename: str):
        """
        Analyze functions with inter-procedural context.

        Uses function summaries to track data flow across calls.
        """
        in_function = False
        current_func_name = None
        brace_depth = 0

        # Track local heap state during analysis
        local_heap: Dict[str, str] = {}  # var -> state ('allocated', 'freed', 'null')

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            if not stripped or stripped.startswith('//'):
                continue

            # Detect function start
            func_match = re.match(
                r'^(?:virtual\s+)?(?:\w+(?:\s*[*&])?\s+)?(?:(\w+)::)?(\w+)\s*\([^)]*\)\s*(?:const)?\s*\{?',
                stripped
            )

            if func_match and not any(kw in stripped.split()[0] for kw in ['if', 'while', 'for', 'switch']):
                class_name = func_match.group(1)
                func_name = func_match.group(2)
                current_func_name = f"{class_name}::{func_name}" if class_name else func_name
                in_function = True
                brace_depth = stripped.count('{') - stripped.count('}')
                local_heap = {}
                continue

            if in_function:
                brace_depth += stripped.count('{') - stripped.count('}')

                if brace_depth <= 0:
                    in_function = False
                    current_func_name = None
                    local_heap = {}
                    continue

                loc = Location(file=filename, line=line_num, column=0)

                # Strip comments to avoid false positives from comments like "delete data in the..."
                code_only = re.sub(r'/\*.*?\*/', '', stripped)  # Remove C block comments
                code_only = re.sub(r'//.*$', '', code_only)  # Remove C++ line comments

                # Track allocations
                alloc_match = re.search(r'(\w+)\s*=\s*(?:\([^)]*\))?\s*(?:malloc|calloc|new)\s*', code_only)
                if alloc_match:
                    var_name = alloc_match.group(1)
                    local_heap[var_name] = 'allocated'

                # Track frees and detect double-free
                free_match = re.search(r'(?:free|delete(?:\s*\[\])?)\s*\(?\s*(\w+)', code_only)
                if free_match:
                    var_name = free_match.group(1)

                    if var_name in local_heap and local_heap[var_name] == 'freed':
                        self._add_vuln(MemoryVuln(
                            vuln_type=VulnType.DOUBLE_FREE,
                            cwe_id="CWE-415",
                            location=loc,
                            var_name=var_name,
                            description=f"Double free: '{var_name}' already freed",
                            confidence=0.95,
                        ))
                    else:
                        local_heap[var_name] = 'freed'

                # Track dereferences and detect UAF
                for var_name, state in list(local_heap.items()):
                    if state == 'freed':
                        deref_patterns = [
                            rf'\*\s*{re.escape(var_name)}\b',
                            rf'\b{re.escape(var_name)}\s*->',
                            rf'\b{re.escape(var_name)}\s*\[',
                        ]

                        for pattern in deref_patterns:
                            if re.search(pattern, stripped):
                                # Exclude free/delete calls
                                if f'free({var_name})' in stripped or f'delete' in stripped:
                                    continue

                                self._add_vuln(MemoryVuln(
                                    vuln_type=VulnType.USE_AFTER_FREE,
                                    cwe_id="CWE-416",
                                    location=loc,
                                    var_name=var_name,
                                    description=f"Use after free: '{var_name}' was freed",
                                    confidence=0.90,
                                ))
                                break

                # Analyze function calls for inter-procedural effects
                self._analyze_call_site(stripped, loc, local_heap)

    def _analyze_call_site(self, line: str, loc: Location, local_heap: Dict[str, str]):
        """
        Analyze a function call site using function summaries.

        If we call a function that frees its parameter, and we pass
        a local variable, that variable becomes freed.
        """
        # Look for function calls: func(args) or obj.method(args) or obj->method(args)
        call_match = re.search(r'(?:(\w+)(?:\.|\->))?(\w+)\s*\(([^)]*)\)', line)
        if call_match:
            obj_name = call_match.group(1)
            func_name = call_match.group(2)
            args_str = call_match.group(3)

            # Parse arguments
            args = [a.strip() for a in args_str.split(',') if a.strip()]

            # Look up function summary
            summary = self.functions.get(func_name)
            if not summary:
                # Try with class prefix if we have object
                for full_name, s in self.functions.items():
                    if full_name.endswith(f"::{func_name}"):
                        summary = s
                        break

            if summary:
                # Apply function effects
                for param_idx in summary.frees_params:
                    if param_idx < len(args):
                        arg_name = args[param_idx]
                        if arg_name in local_heap:
                            local_heap[arg_name] = 'freed'
                            if self.verbose:
                                print(f"[IPA] Call to {func_name} frees arg {arg_name}")


def analyze_interprocedural(source: str, filename: str = "<unknown>",
                            verbose: bool = False) -> List[MemoryVuln]:
    """
    Interprocedural analysis using separation logic.

    Analysis phases:
    1. SLSemanticAnalyzer: Tree-sitter parsed, separation logic verified
       - CWE-122/121: Buffer Overflow (via size tracking)
       - CWE-415: Double Free
       - CWE-416: Use After Free
       - CWE-590: Free of non-heap memory
       - CWE-401: Memory Leak
    2. SLMemoryAnalyzer: Additional heap state tracking
    3. InterproceduralAnalyzer: Class lifecycle analysis
    """
    # Track unique vulnerabilities by (cwe_id, line) to avoid duplicates
    seen_vulns: Set[Tuple[str, int]] = set()
    vulns: List[MemoryVuln] = []

    def add_unique_vuln(vuln: MemoryVuln):
        """Add vulnerability only if not already detected at this location."""
        key = (vuln.cwe_id, vuln.location.line)
        if key not in seen_vulns:
            seen_vulns.add(key)
            vulns.append(vuln)

    # Phase 1: PRIMARY - SL Semantic Analyzer with tree-sitter parsing
    # This uses proper AST parsing and separation logic for verification
    try:
        from frame.sil.analyzers.sl_semantic_analyzer import SLSemanticAnalyzer
        sl_semantic = SLSemanticAnalyzer(verbose=verbose)
        for sl_vuln in sl_semantic.analyze_source(source, filename):
            vuln = MemoryVuln(
                vuln_type=sl_vuln.vuln_type,
                cwe_id=sl_vuln.cwe_id,
                location=sl_vuln.location,
                var_name=sl_vuln.var_name,
                description=sl_vuln.description,
                alloc_location=sl_vuln.alloc_loc,
                free_location=sl_vuln.free_loc,
                confidence=sl_vuln.confidence,
            )
            add_unique_vuln(vuln)
    except ImportError as e:
        if verbose:
            print(f"[WARN] SLSemanticAnalyzer not available: {e}")

    # Phase 2: SL Memory Analyzer (regex-based, for additional coverage)
    sl_analyzer = SLMemoryAnalyzer(verbose=verbose)
    for sl_vuln in sl_analyzer.analyze_source(source, filename):
        vuln = MemoryVuln(
            vuln_type=sl_vuln.vuln_type,
            cwe_id=sl_vuln.cwe_id,
            location=sl_vuln.location,
            var_name=sl_vuln.var_name,
            description=sl_vuln.description,
            alloc_location=sl_vuln.alloc_loc,
            free_location=sl_vuln.free_loc,
            confidence=sl_vuln.confidence,
        )
        add_unique_vuln(vuln)

    # Phase 3: Inter-procedural analysis (class lifecycles, cross-function)
    analyzer = InterproceduralAnalyzer(verbose=verbose)
    for vuln in analyzer.analyze_source(source, filename):
        add_unique_vuln(vuln)

    # The line-based fallback that used to follow (`_detect_semantic_cwes`, 2,900 lines of
    # regexes keyed largely on Juliet's variable name `data`) is gone: each of its CWEs is a
    # structural rule now (spec rows, solver-backed range and path checks, syntax-tree checks) or
    # was a heuristic and is not reported (roadmap Phase 1, step 7).
    return vulns

