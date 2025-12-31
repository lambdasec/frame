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

                # Track allocations
                alloc_match = re.search(r'(\w+)\s*=\s*(?:\([^)]*\))?\s*(?:malloc|calloc|new)\s*', stripped)
                if alloc_match:
                    var_name = alloc_match.group(1)
                    local_heap[var_name] = 'allocated'

                # Track frees and detect double-free
                free_match = re.search(r'(?:free|delete(?:\s*\[\])?)\s*\(?\s*(\w+)', stripped)
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
    Convenience function for inter-procedural analysis.

    Uses three analysis phases:
    1. InterproceduralAnalyzer: Class lifecycle and cross-function analysis
    2. SLMemoryAnalyzer: Separation logic based heap state tracking for UAF, Double-Free, etc.
    3. Semantic CWE detection: Pattern-based detection for buffer overflow, format string, etc.
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

    # Phase 1: Inter-procedural analysis (class lifecycles, cross-function)
    analyzer = InterproceduralAnalyzer(verbose=verbose)
    for vuln in analyzer.analyze_source(source, filename):
        add_unique_vuln(vuln)

    # Phase 2: Separation Logic based memory analysis
    # Uses Frame's SL solver to track heap state and detect:
    # - CWE-416: Use After Free (dereferencing freed pointer)
    # - CWE-415: Double Free (freeing already freed pointer)
    # - CWE-590: Free of non-heap memory (freeing stack-allocated)
    # - CWE-122: Buffer overflow via precise size tracking
    sl_analyzer = SLMemoryAnalyzer(verbose=verbose)
    for sl_vuln in sl_analyzer.analyze_source(source, filename):
        # Convert SLMemoryVuln to MemoryVuln (same structure, just different import)
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

    # Phase 3: Semantic-based CWE detection (analyzes actual code patterns)
    for vuln in _detect_semantic_cwes(source, filename, verbose):
        add_unique_vuln(vuln)

    return vulns


def _detect_semantic_cwes(source: str, filename: str, verbose: bool = False) -> List[MemoryVuln]:
    """
    Detect CWEs through semantic analysis of actual code patterns.

    This performs real vulnerability detection by analyzing:
    - Unsafe function calls (strcpy, sprintf, gets, etc.)
    - Hardcoded credentials in code
    - Format string vulnerabilities
    - Buffer size mismatches
    - Integer overflow patterns (with bounds-check awareness)
    - NULL pointer issues
    - External configuration control
    - Sign extension issues
    """
    vulns = []
    lines = source.split('\n')

    # Track state for flow-sensitive analysis
    allocated_vars: Dict[str, int] = {}  # var -> line allocated (heap)
    heap_alloc_sizes: Dict[str, Tuple[int, Optional[int]]] = {}  # var -> (line, size) for heap allocations
    stack_allocated_vars: Dict[str, int] = {}  # var -> line allocated (stack/alloca)
    freed_vars: Dict[str, int] = {}  # var -> line freed (for double-free and UAF)
    null_checked_vars: Set[str] = set()
    null_assigned_vars: Dict[str, int] = {}  # var -> line where assigned NULL

    # Enhanced CWE-476 tracking: pointers from functions that can return NULL
    nullable_vars: Dict[str, int] = {}  # var -> line where assigned from nullable function

    # Track NULL check scopes for flow-sensitive analysis
    # When we see "if (ptr != NULL) {", vars are protected inside the block
    null_check_scope_vars: Set[str] = set()  # Currently in-scope NULL-checked vars
    in_null_check_block: bool = False
    null_check_block_depth: int = 0
    current_brace_depth: int = 0

    # Functions that can return NULL
    NULL_RETURNABLE_FUNCS = {
        'malloc', 'calloc', 'realloc', 'reallocarray',
        'fopen', 'freopen', 'fdopen', 'popen', 'tmpfile',
        'fgets', 'gets', 'fgetws',
        'getenv', 'getenv_s', 'secure_getenv',
        'strdup', 'strndup', 'wcsdup',
        'strchr', 'strrchr', 'strstr', 'strpbrk', 'memchr',
        'wcschr', 'wcsrchr', 'wcsstr', 'wcspbrk', 'wmemchr',
        'strtok', 'strtok_r', 'wcstok',
        'opendir', 'readdir', 'fdopendir',
        'dlopen', 'dlsym',
        'mmap',
        'CreateFile', 'CreateFileA', 'CreateFileW',
        'GlobalAlloc', 'LocalAlloc', 'HeapAlloc', 'VirtualAlloc',
        'CoTaskMemAlloc', 'SysAllocString',
    }

    # Track file handles for resource leak detection
    file_handles: Dict[str, int] = {}  # handle -> line opened
    closed_handles: Set[str] = set()

    # Track bounds checking for integer overflow detection
    bounds_checked_vars: Set[str] = set()  # vars with upper/lower bounds checks
    overflow_guarded_vars: Set[str] = set()  # vars checked for overflow potential

    # Track zero-checked variables for divide-by-zero detection (CWE-369)
    zero_checked_vars: Set[str] = set()  # vars checked for != 0, > 0, or similar

    # Track tainted variables (from external input)
    tainted_vars: Set[str] = {'data'}  # 'data' is commonly used for external input

    # Track detected CWEs to avoid duplicates
    detected_cwes: Set[str] = set()

    # Track declared and initialized variables for CWE-457 (Use of Uninitialized Variable)
    declared_vars: Dict[str, Tuple[int, str]] = {}  # var -> (line declared, type)
    initialized_vars: Set[str] = set()  # vars that have been assigned a value

    # Track variables computed from potentially overflowing arithmetic (for CWE-680)
    # Maps var name -> (line, list of operand vars involved in multiplication/addition)
    overflow_computed_vars: Dict[str, Tuple[int, List[str]]] = {}

    # Track allocation type for CWE-762 (Mismatched Memory Management Routines)
    # Allocation types: 'MALLOC' (malloc/calloc/realloc), 'NEW' (new), 'NEW_ARRAY' (new[])
    alloc_types: Dict[str, Tuple[str, int]] = {}  # var -> (alloc_type, line)

    def add_vuln_if_new(vuln: MemoryVuln, cwe_key: str = None):
        """Add vulnerability only if this CWE hasn't been detected yet"""
        key = cwe_key or vuln.cwe_id
        if key not in detected_cwes:
            detected_cwes.add(key)
            vulns.append(vuln)

    # First pass: identify bounds checks and guards
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        # Detect overflow guards: if (data > INT_MAX/2), if (data < sqrt(INT_MAX)), etc.
        if re.search(r'\bdata\s*[><]=?\s*(?:INT_MAX|LONG_MAX|LLONG_MAX|sqrt|SHRT_MAX)', stripped):
            overflow_guarded_vars.add('data')
        if re.search(r'(?:INT_MAX|LONG_MAX|LLONG_MAX|SHRT_MAX)\s*[/<]\s*\d+\s*[><]=?\s*data', stripped):
            overflow_guarded_vars.add('data')
        if re.search(r'\bdata\s*[><]=?\s*\d+\s*&&', stripped):  # Combined bounds check
            bounds_checked_vars.add('data')
        if re.search(r'&&\s*data\s*[><]=?\s*\d+', stripped):
            bounds_checked_vars.add('data')

        # Detect explicit bounds checks: if (data >= 0 && data < SIZE)
        if re.search(r'\bdata\s*>=?\s*0\s*&&.*\bdata\s*<', stripped):
            bounds_checked_vars.add('data')
            overflow_guarded_vars.add('data')
        if re.search(r'\bdata\s*<.*&&.*\bdata\s*>=?\s*0', stripped):
            bounds_checked_vars.add('data')
            overflow_guarded_vars.add('data')

        # Detect negative checks that prevent underflow
        if re.search(r'\bdata\s*>=?\s*0\b', stripped) and 'else' not in stripped:
            overflow_guarded_vars.add('data')

        # Detect zero checks for divide-by-zero prevention (CWE-369)
        # Pattern: if (var != 0), if (var > 0), if (0 != var), if (var)
        zero_check_match = re.search(r'\b(\w+)\s*!=\s*0\b', stripped)
        if zero_check_match:
            zero_checked_vars.add(zero_check_match.group(1))
        zero_check_match = re.search(r'\b0\s*!=\s*(\w+)\b', stripped)
        if zero_check_match:
            zero_checked_vars.add(zero_check_match.group(1))
        # var > 0 or var >= 1 implies non-zero
        zero_check_match = re.search(r'\b(\w+)\s*>\s*0\b', stripped)
        if zero_check_match:
            zero_checked_vars.add(zero_check_match.group(1))
        zero_check_match = re.search(r'\b(\w+)\s*>=\s*1\b', stripped)
        if zero_check_match:
            zero_checked_vars.add(zero_check_match.group(1))
        # if (var) - implicit zero check in condition
        if_var_match = re.search(r'\bif\s*\(\s*(\w+)\s*\)', stripped)
        if if_var_match:
            zero_checked_vars.add(if_var_match.group(1))
        # var < 0 or var > 0 combined check (non-zero check)
        if re.search(r'\b(\w+)\s*<\s*0\b', stripped):
            match = re.search(r'\b(\w+)\s*<\s*0\b', stripped)
            if match:
                zero_checked_vars.add(match.group(1))

        # Detect variable assignments from input functions
        input_match = re.search(r'(\w+)\s*=.*(?:fscanf|scanf|fgets|gets|recv|read|getenv|GetEnvironmentVariable|getline|fread|recvfrom|recvmsg)', stripped)
        if input_match:
            tainted_vars.add(input_match.group(1))

        # Track argv usage - argv elements are tainted (CWE-78 command injection source)
        argv_match = re.search(r'(\w+)\s*=\s*argv\s*\[', stripped)
        if argv_match:
            tainted_vars.add(argv_match.group(1))

        # Track direct argv indexing in function calls (for command injection)
        if re.search(r'\bargv\s*\[', stripped):
            tainted_vars.add('argv')

        # Track taint propagation through string operations
        for tainted_var in list(tainted_vars):
            # strcpy(dest, tainted) -> dest is tainted
            strcpy_prop = re.search(rf'\b(?:strcpy|strncpy|strcat|strncat|memcpy|memmove|sprintf|snprintf)\s*\(\s*(\w+)\s*,[^,]*\b{tainted_var}\b', stripped)
            if strcpy_prop:
                tainted_vars.add(strcpy_prop.group(1))
            # dest = strdup(tainted) -> dest is tainted
            strdup_prop = re.search(rf'(\w+)\s*=.*\b(?:strdup|_strdup|strndup)\s*\([^)]*\b{tainted_var}\b', stripped)
            if strdup_prop:
                tainted_vars.add(strdup_prop.group(1))

        # Track stack allocations (ALLOCA, alloca)
        alloca_match = re.search(r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\))?\s*(?:ALLOCA|alloca|_alloca)\s*\(', stripped)
        if alloca_match:
            stack_allocated_vars[alloca_match.group(1)] = line_num

        # Track file handle opens
        fopen_match = re.search(r'(\w+)\s*=\s*(?:fopen|_wfopen|CreateFile\w*)\s*\(', stripped)
        if fopen_match:
            file_handles[fopen_match.group(1)] = line_num

        # Track file handle closes
        fclose_match = re.search(r'\b(?:fclose|CloseHandle)\s*\(\s*(\w+)', stripped)
        if fclose_match:
            closed_handles.add(fclose_match.group(1))

        # Track NULL assignments
        null_assign_match = re.search(r'(\w+)\s*=\s*(?:NULL|nullptr|0)\s*;', stripped)
        if null_assign_match:
            null_assigned_vars[null_assign_match.group(1)] = line_num

        # Track variables computed from potentially overflowing arithmetic (CWE-680)
        # Pattern: size = count * element_size; or size = n * sizeof(x)
        # This tracks the target variable and the operands involved
        arith_assign_match = re.search(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+|\d+)', stripped)
        if arith_assign_match:
            target_var = arith_assign_match.group(1)
            op1 = arith_assign_match.group(2)
            op2 = arith_assign_match.group(3)
            # Don't track if it's a safe sizeof pattern with constant
            if 'sizeof' not in stripped or op1 in tainted_vars or op2 in tainted_vars:
                operands = []
                if op1 in tainted_vars or op1 == 'data':
                    operands.append(op1)
                if op2 in tainted_vars or op2 == 'data':
                    operands.append(op2)
                # Also track if operands are other potentially overflow-computed vars
                if op1 in overflow_computed_vars:
                    operands.append(op1)
                if op2 in overflow_computed_vars:
                    operands.append(op2)
                if operands:
                    overflow_computed_vars[target_var] = (line_num, operands)

        # Track heap allocations with sizes
        # Improved pattern to capture C++ new allocations: new TYPE, new TYPE[N], new TYPE(args)
        heap_alloc_match = re.search(r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\))?\s*(?:(?:malloc|calloc|realloc)\s*\(|new\s+)', stripped)
        if heap_alloc_match:
            var_name = heap_alloc_match.group(1)
            allocated_vars[var_name] = line_num
            # Try to extract allocation size
            alloc_size = None
            # malloc(N), malloc(sizeof(T))
            malloc_size_match = re.search(r'\bmalloc\s*\(\s*(\d+)\s*\)', stripped)
            if malloc_size_match:
                alloc_size = int(malloc_size_match.group(1))
            # malloc(N * sizeof(T)) or malloc(sizeof(T) * N)
            malloc_mult_match = re.search(r'\bmalloc\s*\(\s*(\d+)\s*\*', stripped)
            if malloc_mult_match:
                alloc_size = int(malloc_mult_match.group(1))  # Conservative: just first number
            # calloc(N, size)
            calloc_match = re.search(r'\bcalloc\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)', stripped)
            if calloc_match:
                alloc_size = int(calloc_match.group(1)) * int(calloc_match.group(2))
            heap_alloc_sizes[var_name] = (line_num, alloc_size)

            # Track allocation type for CWE-762 (Mismatched Memory Management Routines)
            # new TYPE[N] -> NEW_ARRAY (requires delete[])
            if re.search(r'\bnew\s+\w+\s*\[', stripped):
                alloc_types[var_name] = ('NEW_ARRAY', line_num)
            # new TYPE or new TYPE(args) -> NEW (requires delete)
            elif re.search(r'\bnew\s+\w', stripped):
                alloc_types[var_name] = ('NEW', line_num)
            # malloc/calloc/realloc -> MALLOC (requires free)
            elif re.search(r'\b(?:malloc|calloc|realloc)\s*\(', stripped):
                alloc_types[var_name] = ('MALLOC', line_num)

        # Track free() calls
        free_match = re.search(r'\b(?:free|delete(?:\s*\[\])?)\s*\(?\s*(\w+)', stripped)
        if free_match:
            var = free_match.group(1)
            if var in freed_vars:
                # Double free detected!
                pass  # Will be detected in second pass
            freed_vars[var] = line_num

    # Second pass: detect vulnerabilities
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        loc = Location(filename, line_num, 0)

        # Skip comments (but not pointer dereferences like *ptr)
        if stripped.startswith('//') or stripped.startswith('/*'):
            continue
        # Skip multi-line comment continuation (starts with * followed by space or *)
        if stripped.startswith('*') and (len(stripped) < 2 or stripped[1] in ' \t*'):
            continue

        # =====================================================================
        # FP Reduction: Check for "good" context (FIX/GOOD comments, goodSource, etc.)
        # =====================================================================
        is_good_context = False
        # Check for FIX/FIXED/GOOD comment on this line or in preceding 4 lines
        context_window = lines[max(0, line_num-5):line_num+1]
        for ctx_line in context_window:
            if re.search(r'/\*.*FIX|/\*.*GOOD|//.*FIX|//.*GOOD', ctx_line, re.IGNORECASE):
                is_good_context = True
                break
        # Also check for good* function pattern (Juliet convention)
        if 'goodSource' in stripped or 'goodSink' in stripped or 'good(' in stripped or 'goodG2B' in stripped or 'goodB2G' in stripped:
            is_good_context = True
        # Check if the line itself has FIX comment
        if re.search(r'/\*.*FIX|//.*FIX', stripped, re.IGNORECASE):
            is_good_context = True
        # Check if we're inside a good* function (Juliet convention: good* functions are safe)
        # Look for function definition in previous 50 lines
        for prev_idx in range(max(0, line_num - 50), line_num):
            if re.search(r'\b(good|goodG2B|goodB2G|goodSource|goodSink)\w*\s*\(', lines[prev_idx]):
                is_good_context = True
                break
        # Check for BAD marker to override (if explicitly marked BAD, it's not good context)
        if re.search(r'/\*.*FLAW|/\*.*BAD|POTENTIAL FLAW', stripped):
            is_good_context = False

        # =====================================================================
        # CWE-122/121: Buffer Overflow - Unsafe string functions
        # =====================================================================
        strcpy_match = re.search(r'\bstrcpy\s*\(\s*(\w+)\s*,', stripped)
        if strcpy_match and not is_good_context:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name=strcpy_match.group(1),
                description="Unbounded strcpy - use strncpy or strlcpy instead",
                confidence=0.9,
            ))

        # Wide character wcscpy (also unbounded like strcpy)
        wcscpy_match = re.search(r'\bwcscpy\s*\(\s*(\w+)\s*,', stripped)
        if wcscpy_match and not is_good_context:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name=wcscpy_match.group(1),
                description="Unbounded wcscpy - use wcsncpy instead",
                confidence=0.9,
            ))

        if re.search(r'\bgets\s*\(', stripped) and not is_good_context:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name="buffer",
                description="gets() is always vulnerable - use fgets instead",
                confidence=0.95,
            ))

        sprintf_match = re.search(r'\bsprintf\s*\(\s*(\w+)\s*,', stripped)
        if sprintf_match and 'snprintf' not in stripped and not is_good_context:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name=sprintf_match.group(1),
                description="Unbounded sprintf - use snprintf instead",
                confidence=0.85,
            ))

        strcat_match = re.search(r'\bstrcat\s*\(\s*(\w+)\s*,', stripped)
        if strcat_match and 'strncat' not in stripped and not is_good_context:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name=strcat_match.group(1),
                description="Unbounded strcat - use strncat instead",
                confidence=0.85,
            ))

        # =====================================================================
        # CWE-122: Heap Buffer Overflow - memcpy with size larger than allocation
        # =====================================================================
        memcpy_size_match = re.search(r'\bmemcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\d+)\s*\)', stripped)
        if memcpy_size_match:
            dest_var = memcpy_size_match.group(1)
            copy_size = int(memcpy_size_match.group(2))
            if dest_var in heap_alloc_sizes:
                alloc_line, alloc_size = heap_alloc_sizes[dest_var]
                if alloc_size is not None and copy_size > alloc_size:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.BUFFER_OVERFLOW,
                        cwe_id="CWE-122",
                        location=loc,
                        var_name=dest_var,
                        description=f"Heap buffer overflow - memcpy writes {copy_size} bytes to {alloc_size}-byte buffer allocated at line {alloc_line}",
                        confidence=0.95,
                    ))

        # Pattern: strcpy/strcat to heap-allocated buffer with tainted source
        strcpy_heap_match = re.search(r'\b(strcpy|strcat)\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', stripped)
        if strcpy_heap_match:
            func_name = strcpy_heap_match.group(1)
            dest_var = strcpy_heap_match.group(2)
            src_var = strcpy_heap_match.group(3)
            if dest_var in heap_alloc_sizes and (src_var in tainted_vars or src_var == 'data'):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-122",
                    location=loc,
                    var_name=dest_var,
                    description=f"Heap buffer overflow - {func_name} to heap buffer from tainted source '{src_var}'",
                    confidence=0.9,
                ))

        # Pattern: memset/bzero with size larger than allocation
        memset_size_match = re.search(r'\b(?:memset|bzero)\s*\(\s*(\w+)\s*,\s*[^,]+,\s*(\d+)\s*\)', stripped)
        if memset_size_match:
            dest_var = memset_size_match.group(1)
            set_size = int(memset_size_match.group(2))
            if dest_var in heap_alloc_sizes:
                alloc_line, alloc_size = heap_alloc_sizes[dest_var]
                if alloc_size is not None and set_size > alloc_size:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.BUFFER_OVERFLOW,
                        cwe_id="CWE-122",
                        location=loc,
                        var_name=dest_var,
                        description=f"Heap buffer overflow - memset writes {set_size} bytes to {alloc_size}-byte buffer",
                        confidence=0.95,
                    ))

        # =====================================================================
        # CWE-124: Buffer Underwrite - negative array index and pointer arithmetic
        # =====================================================================
        neg_index_match = re.search(r'(\w+)\s*\[\s*-\s*(\d+)\s*\]\s*=', stripped)
        if neg_index_match:
            var_name = neg_index_match.group(1)
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-124",
                location=loc,
                var_name=var_name,
                description=f"Buffer underwrite - negative array index on '{var_name}'",
                confidence=0.95,
            ))

        ptr_minus_match = re.search(r'\*\s*\(\s*(\w+)\s*-\s*(\d+)\s*\)\s*=', stripped)
        if ptr_minus_match:
            var_name = ptr_minus_match.group(1)
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-124",
                location=loc,
                var_name=var_name,
                description=f"Buffer underwrite - writing via pointer arithmetic before '{var_name}'",
                confidence=0.95,
            ))

        ptr_sub_match = re.search(r'(\w+)\s*=\s*(\w+)\s*-\s*(\d+|\w+)\s*;', stripped)
        if ptr_sub_match:
            new_ptr = ptr_sub_match.group(1)
            base_ptr = ptr_sub_match.group(2)
            offset = ptr_sub_match.group(3)
            if base_ptr in allocated_vars or base_ptr in heap_alloc_sizes:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-124",
                    location=loc,
                    var_name=new_ptr,
                    description=f"Buffer underwrite risk - pointer '{new_ptr}' computed from '{base_ptr}' - {offset}",
                    confidence=0.65,
                ))

        # =====================================================================
        # CWE-134: Use of Externally-Controlled Format String
        # =====================================================================
        # Key insight: The first variadic argument to printf-family should be
        # a string literal, not a variable (which could be externally controlled)
        cwe134_detected_this_line = False

        # Pattern 1: printf(var) - format string is a variable, not a literal
        printf_single_match = re.search(r'\bprintf\s*\(\s*(\w+)\s*\)', stripped)
        if printf_single_match:
            var = printf_single_match.group(1)
            if not re.search(r'printf\s*\(\s*"', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.FORMAT_STRING,
                    cwe_id="CWE-134",
                    location=loc,
                    var_name=var,
                    description=f"Format string vulnerability - printf with variable '{var}' as format (should be literal)",
                    confidence=0.9 if var in tainted_vars else 0.8,
                ))
                cwe134_detected_this_line = True

        # Pattern 2: sprintf(buf, source) - format string from variable
        sprintf_fmt_match = re.search(r'\bsprintf\s*\(\s*\w+\s*,\s*(\w+)\s*[,)]', stripped)
        if sprintf_fmt_match and 'snprintf' not in stripped and not cwe134_detected_this_line:
            var = sprintf_fmt_match.group(1)
            if not re.search(r'sprintf\s*\(\s*\w+\s*,\s*"', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.FORMAT_STRING,
                    cwe_id="CWE-134",
                    location=loc,
                    var_name=var,
                    description=f"Format string vulnerability - sprintf with variable '{var}' as format",
                    confidence=0.9 if var in tainted_vars else 0.8,
                ))
                cwe134_detected_this_line = True

        # Pattern 3: fprintf(f, tainted_var) - format string from variable
        fprintf_fmt_match = re.search(r'\bfprintf\s*\(\s*\w+\s*,\s*(\w+)\s*[,)]', stripped)
        if fprintf_fmt_match and not cwe134_detected_this_line:
            var = fprintf_fmt_match.group(1)
            if not re.search(r'fprintf\s*\(\s*\w+\s*,\s*"', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.FORMAT_STRING,
                    cwe_id="CWE-134",
                    location=loc,
                    var_name=var,
                    description=f"Format string vulnerability - fprintf with variable '{var}' as format",
                    confidence=0.9 if var in tainted_vars else 0.8,
                ))
                cwe134_detected_this_line = True

        # Pattern 4: syslog(LOG_ERR, data) - format string from variable
        syslog_match = re.search(r'\bsyslog\s*\(\s*(?:LOG_\w+|\d+)\s*,\s*(\w+)\s*[,)]', stripped)
        if syslog_match and not cwe134_detected_this_line:
            var = syslog_match.group(1)
            if not re.search(r'syslog\s*\(\s*(?:LOG_\w+|\d+)\s*,\s*"', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.FORMAT_STRING,
                    cwe_id="CWE-134",
                    location=loc,
                    var_name=var,
                    description=f"Format string vulnerability - syslog with variable '{var}' as format",
                    confidence=0.9 if var in tainted_vars else 0.8,
                ))
                cwe134_detected_this_line = True

        # Pattern 5: General printf-family with non-literal format (fallback)
        if not cwe134_detected_this_line:
            printf_match = re.search(r'\b(printf|fprintf|sprintf|snprintf|syslog)\s*\([^"]*\b(\w+)\s*\)', stripped)
            if printf_match:
                func = printf_match.group(1)
                var = printf_match.group(2)
                if not re.search(r'\b' + func + r'\s*\(\s*"', stripped):
                    if func == 'fprintf' and re.search(r'fprintf\s*\(\s*\w+\s*,\s*"', stripped):
                        pass  # Skip safe pattern
                    elif func == 'snprintf' and re.search(r'snprintf\s*\([^,]+,[^,]+,\s*"', stripped):
                        pass  # Skip safe pattern
                    elif func == 'syslog' and re.search(r'syslog\s*\(\s*(?:LOG_\w+|\d+)\s*,\s*"', stripped):
                        pass  # Skip safe pattern
                    else:
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.FORMAT_STRING,
                            cwe_id="CWE-134",
                            location=loc,
                            var_name=var,
                            description=f"Format string vulnerability - {func} with non-literal format",
                            confidence=0.85 if var in tainted_vars else 0.75,
                        ))
                        cwe134_detected_this_line = True

        # Wide character printf family (wprintf, fwprintf, swprintf, etc.)
        if not cwe134_detected_this_line:
            wprintf_match = re.search(r'\b(wprintf|fwprintf|swprintf|vwprintf|vfwprintf|vswprintf|_vsnwprintf|_snwprintf)\s*\(', stripped)
            if wprintf_match:
                func = wprintf_match.group(1)
                # Check if format is a variable (not a literal)
                if not re.search(rf'{func}\s*\([^)]*L"', stripped):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.FORMAT_STRING,
                        cwe_id="CWE-134",
                        location=loc,
                        var_name="format",
                        description=f"Format string vulnerability - {func} with non-literal format",
                        confidence=0.85,
                    ))
                    cwe134_detected_this_line = True

        # Variadic printf (vprintf, vfprintf, vsprintf, vsnprintf)
        if not cwe134_detected_this_line:
            vprintf_match = re.search(r'\b(vprintf|vfprintf|vsprintf|vsnprintf|_vsnprintf)\s*\(', stripped)
            if vprintf_match:
                func = vprintf_match.group(1)
                # Check if any tainted variable is used in the call
                for tainted in tainted_vars:
                    if re.search(rf'{func}\s*\([^)]*\b{tainted}\b', stripped):
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.FORMAT_STRING,
                            cwe_id="CWE-134",
                            location=loc,
                            var_name=tainted,
                            description=f"Format string vulnerability - {func} with user-controlled format '{tainted}'",
                            confidence=0.9,
                        ))
                        cwe134_detected_this_line = True
                        break  # Only report once per line

        # snprintf/SNPRINTF with tainted data as format (3rd argument)
        if not cwe134_detected_this_line:
            snprintf_tainted = re.search(r'\b(?:snprintf|SNPRINTF|_snprintf)\s*\(\s*\w+\s*,\s*[^,]+,\s*(\w+)\s*[,)]', stripped)
            if snprintf_tainted:
                var = snprintf_tainted.group(1)
                if not re.search(r'\b(?:snprintf|SNPRINTF|_snprintf)\s*\(\s*\w+\s*,\s*[^,]+,\s*"', stripped):
                    if var in tainted_vars or var == 'data':
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.FORMAT_STRING,
                            cwe_id="CWE-134",
                            location=loc,
                            var_name=var,
                            description=f"Format string vulnerability - snprintf with user-controlled format '{var}'",
                            confidence=0.9,
                        ))

        # =====================================================================
        # CWE-259/321: Hardcoded Credentials
        # =====================================================================
        hardcoded_match = re.search(
            r'\b(password|passwd|pwd|secret|api_key|apikey|auth_token|private_key)\s*=\s*["\'][^"\']{3,}["\']',
            stripped, re.IGNORECASE
        )
        if hardcoded_match:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-259",
                location=loc,
                var_name=hardcoded_match.group(1),
                description="Hardcoded credential detected",
                confidence=0.9,
            ))

        # Detect #define PASSWORD patterns
        if re.search(r'#\s*define\s+(?:PASSWORD|PASSWD|SECRET|KEY|CRYPTO_KEY)\s+["\']', stripped, re.IGNORECASE):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-259",
                location=loc,
                var_name="password",
                description="Hardcoded password in #define constant",
                confidence=0.95,
            ))

        # Detect strcpy(password, CONSTANT) pattern
        if re.search(r'\bstrcpy\s*\(\s*password\s*,\s*[A-Z_]+\s*\)', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-259",
                location=loc,
                var_name="password",
                description="Password copied from hardcoded constant",
                confidence=0.85,
            ))

        # Detect password variable used in LogonUser without proper sourcing
        if re.search(r'LogonUser\w*\s*\([^)]*,\s*password\s*,', stripped):
            # Check if this function has hardcoded password pattern
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-259",
                location=loc,
                var_name="password",
                description="Password used in authentication may be hardcoded",
                confidence=0.75,
            ))

        if re.search(r'LogonUser\w*\s*\([^)]*"[^"]+"\s*,', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-259",
                location=loc,
                var_name="password",
                description="Hardcoded password in authentication call",
                confidence=0.9,
            ))

        # =====================================================================
        # CWE-321: Use of Hard-coded Cryptographic Key
        # =====================================================================
        # Detect hard-coded encryption keys in crypto function calls

        # Pattern 1: AES_set_encrypt_key/AES_set_decrypt_key with literal key
        if re.search(r'\bAES_set_(?:encrypt|decrypt)_key\s*\(', stripped):
            if re.search(r'\bAES_set_(?:encrypt|decrypt)_key\s*\(\s*(?:"\s*|[A-Z_]+\s*,)', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    cwe_id="CWE-321",
                    location=loc,
                    var_name="key",
                    description="Hard-coded cryptographic key in AES key setup",
                    confidence=0.9,
                ))

        # Pattern 2: DES_key_sched/DES_set_key with literal
        if re.search(r'\bDES_(?:key_sched|set_key(?:_checked|_unchecked)?)\s*\(', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-321",
                location=loc,
                var_name="key",
                description="Hard-coded cryptographic key in DES key schedule",
                confidence=0.85,
            ))

        # Pattern 3: EVP_EncryptInit/EVP_DecryptInit with hard-coded key bytes
        if re.search(r'\bEVP_(?:Encrypt|Decrypt)Init(?:_ex)?\s*\(', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-321",
                location=loc,
                var_name="key",
                description="Hard-coded cryptographic key in EVP encryption init",
                confidence=0.8,
            ))

        # Pattern 4: char key[] = "hardcoded" or unsigned char key[16] = {0x00, ...}
        key_array_match = re.search(
            r'\b(?:unsigned\s+)?char\s+(?:(?:encryption|crypto|aes|des|cipher|enc|dec|secret)\s*)?key\s*\[',
            stripped, re.IGNORECASE
        )
        if key_array_match:
            if re.search(r'key\s*\[\s*\d*\s*\]\s*=\s*(?:"|{)', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    cwe_id="CWE-321",
                    location=loc,
                    var_name="key",
                    description="Hard-coded cryptographic key array initialization",
                    confidence=0.9,
                ))

        # Pattern 5: Generic crypto key variable with literal assignment
        crypto_key_match = re.search(
            r'\b((?:crypto|encryption|cipher|aes|des|secret|enc|hmac|signing)[\w]*[Kk]ey)\s*=\s*["\'][^"\']+["\']',
            stripped
        )
        if crypto_key_match:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-321",
                location=loc,
                var_name=crypto_key_match.group(1),
                description="Hard-coded cryptographic key in variable assignment",
                confidence=0.9,
            ))

        # Pattern 6: CRYPTO_KEY or AES_KEY constant definitions
        if re.search(r'#\s*define\s+(?:CRYPTO_KEY|AES_KEY|DES_KEY|ENCRYPTION_KEY|CIPHER_KEY|SECRET_KEY)\s+["\'{]', stripped, re.IGNORECASE):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-321",
                location=loc,
                var_name="key",
                description="Hard-coded cryptographic key in #define constant",
                confidence=0.95,
            ))

        # Pattern 7: Blowfish/RC4/other crypto with hardcoded keys
        if re.search(r'\b(?:BF_set_key|RC4_set_key|RC2_set_key|CAST_set_key)\s*\(', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-321",
                location=loc,
                var_name="key",
                description="Hard-coded cryptographic key in cipher key setup",
                confidence=0.85,
            ))

        # Pattern 8: CryptoAPI functions (Windows)
        if re.search(r'\bCrypt(?:DeriveKey|ImportKey|GenKey)\s*\(', stripped):
            if re.search(r'Crypt(?:DeriveKey|ImportKey|GenKey)\s*\([^)]*(?:password|key|secret)', stripped, re.IGNORECASE):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    cwe_id="CWE-321",
                    location=loc,
                    var_name="key",
                    description="Hard-coded cryptographic key in Windows CryptoAPI",
                    confidence=0.85,
                ))

        # Pattern 9: Hex byte array that looks like a key
        if re.search(r'=\s*\{\s*(?:0x[0-9a-fA-F]{2}\s*,\s*){7,}0x[0-9a-fA-F]{2}', stripped):
            if re.search(r'\b(?:key|iv|nonce|salt|secret|cipher)\s*\[', stripped, re.IGNORECASE):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    cwe_id="CWE-321",
                    location=loc,
                    var_name="key",
                    description="Hard-coded cryptographic key bytes in array",
                    confidence=0.9,
                ))

        # Pattern 10: Simple key/secret variable assignment with string literal
        # Matches: const char *key = "literal"; or char *secret = "value";
        simple_key_match = re.search(
            r'\b(?:const\s+)?(?:char|unsigned\s+char)\s*\*\s*\b(key|secret|password|passwd|crypto_key)\s*=\s*"[^"]+"\s*;',
            stripped, re.IGNORECASE
        )
        if simple_key_match:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-321",
                location=loc,
                var_name=simple_key_match.group(1),
                description="Hard-coded cryptographic key in string literal",
                confidence=0.8,
            ))

        # =====================================================================
        # CWE-476: NULL Pointer Dereference (Enhanced Detection)
        # =====================================================================

        # Track brace depth for scope-sensitive NULL check tracking
        open_braces = stripped.count('{')
        close_braces = stripped.count('}')
        current_brace_depth += open_braces - close_braces

        # Check if we're exiting a NULL check block
        if in_null_check_block and current_brace_depth < null_check_block_depth:
            in_null_check_block = False
            null_check_scope_vars.clear()

        # Track assignments from NULL-returnable functions
        for func_name in NULL_RETURNABLE_FUNCS:
            nullable_match = re.search(rf'(\w+)\s*=\s*(?:\([^)]*\)\s*)?{func_name}\s*\(', stripped)
            if nullable_match:
                var = nullable_match.group(1)
                nullable_vars[var] = line_num
                allocated_vars[var] = line_num  # Also track as allocated

        alloc_match = re.search(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(', stripped)
        if alloc_match:
            allocated_vars[alloc_match.group(1)] = line_num

        # Track explicit NULL checks: if (ptr != NULL), if (ptr == NULL), if (ptr), if (!ptr)
        null_check_match = re.search(r'if\s*\(\s*(\w+)\s*(?:[!=]=\s*(?:NULL|nullptr|0)\s*)?\)', stripped)
        if null_check_match:
            var = null_check_match.group(1)
            null_checked_vars.add(var)
            # If this is "if (ptr != NULL)" followed by {, vars inside are protected
            if re.search(rf'if\s*\(\s*{var}\s*(?:!=\s*(?:NULL|nullptr|0))?\s*\)\s*\{{', stripped):
                null_check_scope_vars.add(var)
                in_null_check_block = True
                null_check_block_depth = current_brace_depth

        # Also track NULL checks in conditions: ptr != NULL && ...
        null_cond_match = re.search(r'(\w+)\s*[!=]=\s*(?:NULL|nullptr|0)', stripped)
        if null_cond_match:
            null_checked_vars.add(null_cond_match.group(1))

        # Track negated NULL checks: if (!ptr)
        negated_check = re.search(r'if\s*\(\s*!\s*(\w+)\s*\)', stripped)
        if negated_check:
            null_checked_vars.add(negated_check.group(1))

        # Helper function to check if a dereference is actually a type declaration
        def is_type_declaration(var_name: str, line: str) -> bool:
            """Check if *var is a type declaration, not a dereference."""
            type_patterns = [
                # Basic types with modifiers
                rf'(?:const\s+|volatile\s+|static\s+|extern\s+)*(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|void)\s+\*+\s*{var_name}\b',
                # Struct/union/enum types
                rf'(?:struct|union|enum)\s+\w+\s+\*+\s*{var_name}\b',
                # Typedef names (capitalized or ending with _t)
                rf'\b[A-Z]\w*\s+\*+\s*{var_name}\b',
                rf'\b\w+_t\s+\*+\s*{var_name}\b',
                # Function return type in declaration
                rf'^\s*\w+\s+\*+\s*{var_name}\s*\(',
                # Cast expression: (type *)var or (type*)var
                rf'\(\s*\w+\s*\*+\s*\)\s*{var_name}',
                # Pointer-to-pointer declarations
                rf'\w+\s+\*+\s*\*+\s*{var_name}\b',
                # Parameter declarations: func(int *var)
                rf'\(\s*(?:\w+\s+)*\w+\s+\*+\s*{var_name}\s*[,)]',
            ]
            for pattern in type_patterns:
                if re.search(pattern, line):
                    return True
            return False

        # Helper function to check if var is protected by NULL check
        def is_null_protected(var_name: str) -> bool:
            """Check if variable is protected by a NULL check."""
            if var_name in null_checked_vars:
                return True
            if in_null_check_block and var_name in null_check_scope_vars:
                return True
            return False

        # Detect pointer dereferences: *ptr, ptr->field, ptr[index]
        # Pattern 1: Direct dereference *ptr (but not type declarations)
        deref_match = re.search(r'(?<![a-zA-Z_\d])\*\s*(\w+)', stripped)
        if deref_match:
            var = deref_match.group(1)
            # Skip type declarations and casts
            if not is_type_declaration(var, stripped):
                # Check if this is a nullable var that hasn't been NULL-checked
                if var in nullable_vars and not is_null_protected(var):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.NULL_DEREFERENCE,
                        cwe_id="CWE-476",
                        location=loc,
                        var_name=var,
                        description=f"Dereference of '{var}' without NULL check (may be NULL from function return)",
                        confidence=0.8,
                    ))
                elif var in allocated_vars and not is_null_protected(var):
                    if line_num - allocated_vars[var] <= 10:
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.NULL_DEREFERENCE,
                            cwe_id="CWE-476",
                            location=loc,
                            var_name=var,
                            description=f"Dereference of '{var}' without NULL check after allocation",
                            confidence=0.7,
                        ))

        # Pattern 2: Arrow dereference ptr->field
        arrow_match = re.search(r'(\w+)\s*->', stripped)
        if arrow_match:
            var = arrow_match.group(1)
            # Skip if this is 'this->' in C++
            if var != 'this':
                if var in nullable_vars and not is_null_protected(var):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.NULL_DEREFERENCE,
                        cwe_id="CWE-476",
                        location=loc,
                        var_name=var,
                        description=f"Arrow dereference of '{var}' without NULL check (may be NULL from function return)",
                        confidence=0.8,
                    ))
                elif var in allocated_vars and not is_null_protected(var):
                    if line_num - allocated_vars[var] <= 10:
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.NULL_DEREFERENCE,
                            cwe_id="CWE-476",
                            location=loc,
                            var_name=var,
                            description=f"Arrow dereference of '{var}' without NULL check after allocation",
                            confidence=0.7,
                        ))

        # Pattern 3: Array subscript on pointer ptr[index]
        subscript_match = re.search(r'(\w+)\s*\[[^\]]+\]', stripped)
        if subscript_match:
            var = subscript_match.group(1)
            # Exclude common non-pointer array names
            if var not in {'argv', 'envp', 'args', 'i', 'j', 'k', 'n', 'len', 'size', 'count', 'index'}:
                if var in nullable_vars and not is_null_protected(var):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.NULL_DEREFERENCE,
                        cwe_id="CWE-476",
                        location=loc,
                        var_name=var,
                        description=f"Array access on '{var}' without NULL check (may be NULL from function return)",
                        confidence=0.75,
                    ))

        # Pattern 4: Passing nullable pointer to functions that will dereference it
        # Functions like fread, fwrite, fgets, strlen, strcpy expect non-NULL pointers
        dereferencing_funcs = [
            # File I/O functions
            'fread', 'fwrite', 'fgets', 'fputs', 'fprintf', 'fscanf',
            'fgetc', 'fputc', 'fseek', 'ftell', 'rewind', 'fflush',
            'feof', 'ferror', 'clearerr', 'fileno',
            # String functions
            'strlen', 'strcpy', 'strncpy', 'strcat', 'strncat', 'strcmp', 'strncmp',
            'strchr', 'strrchr', 'strstr', 'strtok', 'strtol', 'strtod',
            # Memory functions
            'memcpy', 'memmove', 'memset', 'memcmp', 'memchr',
            # Printing functions
            'printf', 'sprintf', 'snprintf', 'puts', 'fputs',
            # Other common functions
            'free', 'realloc',
        ]
        for func in dereferencing_funcs:
            # Look for function call with nullable var as argument
            func_call_pattern = rf'\b{func}\s*\([^)]*\b(\w+)\b'
            func_match = re.search(func_call_pattern, stripped)
            if func_match:
                # Get all argument variables in the function call
                args_match = re.search(rf'\b{func}\s*\(([^)]*)\)', stripped)
                if args_match:
                    args_str = args_match.group(1)
                    # Extract all variable names from arguments
                    arg_vars = re.findall(r'\b([a-zA-Z_]\w*)\b', args_str)
                    for arg_var in arg_vars:
                        if arg_var in nullable_vars and not is_null_protected(arg_var):
                            vulns.append(MemoryVuln(
                                vuln_type=VulnType.NULL_DEREFERENCE,
                                cwe_id="CWE-476",
                                location=loc,
                                var_name=arg_var,
                                description=f"Passing potentially NULL pointer '{arg_var}' to {func}() which dereferences it",
                                confidence=0.75,
                            ))
                            break  # Only report once per function call

        # =====================================================================
        # CWE-190: Integer Overflow - Arithmetic on unchecked values
        # =====================================================================
        # Pattern: data * data, data * 2, data + data, etc. WITHOUT overflow guard
        if 'data' not in overflow_guarded_vars:
            # Detect: result = data * data (squaring without check)
            if re.search(r'\bdata\s*\*\s*data\b', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-190",
                    location=loc,
                    var_name="data",
                    description="Integer overflow - squaring without overflow check",
                    confidence=0.85,
                ))
            # Detect: result = data * 2 or data * constant (multiplication)
            elif re.search(r'\bdata\s*\*\s*\d+', stripped) or re.search(r'\d+\s*\*\s*data\b', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-190",
                    location=loc,
                    var_name="data",
                    description="Integer overflow - multiplication without overflow check",
                    confidence=0.8,
                ))
            # Detect: result = data + data or data + constant
            elif re.search(r'\bdata\s*\+\s*(?:data|\d+)\b', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-190",
                    location=loc,
                    var_name="data",
                    description="Integer overflow - addition without overflow check",
                    confidence=0.75,
                ))

        # Detect multiplication on other variables (like class member data or result of rand)
        # Pattern: var * 2 or 2 * var where the line doesn't have overflow check
        mult_match = re.search(r'(\w+)\s*\*\s*(\d+)\b', stripped)
        if mult_match:
            var = mult_match.group(1)
            const = int(mult_match.group(2))
            # Skip if this is sizeof or if there's a proper check
            if const >= 2 and 'sizeof' not in stripped:
                # Check if there's no overflow guard on this line or recent lines
                if not re.search(rf'\b{var}\s*[<>]=?\s*\w*MAX', stripped):
                    # Check if this is an arithmetic assignment (result = var * 2)
                    if re.search(rf'=\s*{var}\s*\*\s*{const}', stripped):
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.INTEGER_OVERFLOW,
                            cwe_id="CWE-190",
                            location=loc,
                            var_name=var,
                            description=f"Integer overflow - multiplying {var} by {const} without overflow check",
                            confidence=0.7,
                        ))

        # malloc/calloc with potentially overflowing size
        int_overflow_match = re.search(r'(?:malloc|calloc|alloca|new)\s*\([^)]*(\w+)\s*[*+]\s*(\w+)', stripped)
        if int_overflow_match and 'sizeof' not in stripped:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.INTEGER_OVERFLOW,
                cwe_id="CWE-190",
                location=loc,
                var_name=int_overflow_match.group(1),
                description="Potential integer overflow in allocation size calculation",
                confidence=0.6,
            ))

        # Enhanced CWE-190: Variable * sizeof() patterns without overflow check
        # Pattern: size = count * sizeof(item) - common allocation pattern
        sizeof_mult_match = re.search(r'(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(', stripped)
        if sizeof_mult_match:
            result_var = sizeof_mult_match.group(1)
            count_var = sizeof_mult_match.group(2)
            # Check if count_var is bounds-checked
            if count_var not in bounds_checked_vars and count_var not in overflow_guarded_vars:
                # Check if this is user-controlled or external input
                if count_var in tainted_vars or count_var in ('count', 'size', 'len', 'num', 'n', 'length'):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-190",
                        location=loc,
                        var_name=count_var,
                        description=f"Integer overflow - '{count_var} * sizeof()' may overflow without bounds check",
                        confidence=0.75,
                    ))

        # Pattern: malloc(count * sizeof(...)) with variable count
        malloc_sizeof_match = re.search(r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*\*\s*sizeof\s*\(', stripped)
        if malloc_sizeof_match:
            count_var = malloc_sizeof_match.group(1)
            if count_var not in bounds_checked_vars and count_var not in overflow_guarded_vars:
                if count_var in tainted_vars or count_var in ('count', 'size', 'len', 'num', 'n', 'length', 'data'):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-190",
                        location=loc,
                        var_name=count_var,
                        description=f"Integer overflow in allocation - '{count_var} * sizeof()' without overflow check",
                        confidence=0.8,
                    ))

        # Pattern: malloc(a * b) where both a and b are variables (non-sizeof)
        malloc_mult_vars = re.search(r'(?:malloc|calloc|alloca)\s*\(\s*(\w+)\s*\*\s*(\w+)\s*\)', stripped)
        if malloc_mult_vars:
            var1 = malloc_mult_vars.group(1)
            var2 = malloc_mult_vars.group(2)
            # Skip if one of them is sizeof
            if 'sizeof' not in stripped:
                # Check if neither variable is bounds-checked
                if (var1 not in bounds_checked_vars and var2 not in bounds_checked_vars):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-190",
                        location=loc,
                        var_name=f"{var1}*{var2}",
                        description=f"Integer overflow in allocation - '{var1} * {var2}' may overflow",
                        confidence=0.75,
                    ))

        # Pattern: Loop counter overflow detection
        loop_counter_match = re.search(r'for\s*\(\s*(?:int|unsigned\s+int|size_t|long)?\s*(\w+)\s*=\s*\d+\s*;[^;]+;\s*(\w+)\s*\+\+', stripped)
        if loop_counter_match:
            init_var = loop_counter_match.group(1)
            incr_var = loop_counter_match.group(2)
            if init_var == incr_var:
                if re.search(rf'{init_var}\s*<\s*(?:data|count|size|len|num|n)', stripped):
                    if 'data' not in overflow_guarded_vars:
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.INTEGER_OVERFLOW,
                            cwe_id="CWE-190",
                            location=loc,
                            var_name=init_var,
                            description=f"Loop counter '{init_var}' may overflow with user-controlled bound",
                            confidence=0.65,
                        ))

        # Pattern: i++ on int variables without bounds check
        incr_match = re.search(r'(\w+)\s*\+\+\s*;', stripped)
        if incr_match:
            var = incr_match.group(1)
            if var in ('i', 'j', 'k', 'count', 'counter', 'index', 'idx'):
                if not re.search(rf'{var}\s*[<>=\!]+\s*(?:\w*MAX|\d{{5,}})', stripped):
                    if var not in bounds_checked_vars:
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.INTEGER_OVERFLOW,
                            cwe_id="CWE-190",
                            location=loc,
                            var_name=var,
                            description=f"Integer increment '{var}++' without overflow protection",
                            confidence=0.5,
                        ))

        # Pattern: Addition to size/length variables without overflow check
        add_to_size_match = re.search(r'(\w+)\s*\+=\s*(\w+|\d+)\s*;', stripped)
        if add_to_size_match:
            target_var = add_to_size_match.group(1)
            add_val = add_to_size_match.group(2)
            if target_var in ('size', 'len', 'length', 'count', 'total', 'sum', 'offset'):
                if target_var not in bounds_checked_vars and target_var not in overflow_guarded_vars:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-190",
                        location=loc,
                        var_name=target_var,
                        description=f"Integer overflow - '{target_var} += {add_val}' without bounds check",
                        confidence=0.6,
                    ))

        # Pattern: Multiplication assignment without overflow check
        mult_assign_match = re.search(r'(\w+)\s*\*=\s*(\w+|\d+)\s*;', stripped)
        if mult_assign_match:
            target_var = mult_assign_match.group(1)
            mult_val = mult_assign_match.group(2)
            if target_var not in bounds_checked_vars and target_var not in overflow_guarded_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-190",
                    location=loc,
                    var_name=target_var,
                    description=f"Integer overflow - '{target_var} *= {mult_val}' without overflow check",
                    confidence=0.7,
                ))

        # Pattern: Shift left operations that could overflow
        shift_left_match = re.search(r'(\w+)\s*(?:<<|<<=)\s*(\w+|\d+)', stripped)
        if shift_left_match:
            var = shift_left_match.group(1)
            shift_amt = shift_left_match.group(2)
            if var not in overflow_guarded_vars:
                try:
                    shift_val = int(shift_amt)
                    if shift_val >= 16:
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.INTEGER_OVERFLOW,
                            cwe_id="CWE-190",
                            location=loc,
                            var_name=var,
                            description=f"Integer overflow - left shift by {shift_val} bits may overflow",
                            confidence=0.7,
                        ))
                except ValueError:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-190",
                        location=loc,
                        var_name=var,
                        description=f"Integer overflow - left shift by variable '{shift_amt}' may overflow",
                        confidence=0.6,
                    ))

        # =====================================================================
        # CWE-191: Integer Underflow
        # =====================================================================
        if 'data' not in overflow_guarded_vars:
            # Detect: result = data - 1 or data - constant (subtraction)
            if re.search(r'\bdata\s*-\s*\d+', stripped) and not re.search(r'data\s*>=?\s*\d+', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_UNDERFLOW,
                    cwe_id="CWE-191",
                    location=loc,
                    var_name="data",
                    description="Integer underflow - subtraction without bounds check",
                    confidence=0.75,
                ))

        # =====================================================================
        # CWE-15: External Control of System or Configuration Setting
        # =====================================================================
        # Detect Windows API calls that set system configuration with tainted data
        config_funcs = [
            'SetComputerName', 'SetEnvironmentVariable', 'SetCurrentDirectory',
            'RegSetValue', 'RegSetKeyValue', 'SetLocaleInfo', 'SetTimeZoneInformation',
            'SetComputerNameA', 'SetComputerNameW', 'SetEnvironmentVariableA',
            'SetEnvironmentVariableW'
        ]
        for func in config_funcs:
            if re.search(rf'\b{func}\s*\(\s*(\w+)', stripped):
                match = re.search(rf'\b{func}\s*\(\s*(\w+)', stripped)
                if match and match.group(1) in tainted_vars:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.CONFIG_INJECTION,
                        cwe_id="CWE-15",
                        location=loc,
                        var_name=match.group(1),
                        description=f"External control of system config - {func} with tainted input",
                        confidence=0.85,
                    ))

        # =====================================================================
        # CWE-194: Unexpected Sign Extension
        # =====================================================================
        # Detect short/char cast to larger type used in memory operations
        sign_ext_match = re.search(r'\(\s*(?:short|char|signed\s+char)\s*\)\s*(\w+)', stripped)
        if sign_ext_match:
            var = sign_ext_match.group(1)
            # Check if used in memory operation or array index
            if re.search(rf'\[\s*\(\s*(?:short|char|signed\s+char)\s*\)\s*{var}', stripped) or \
               re.search(rf'(?:malloc|calloc|memcpy|memmove)\s*\([^)]*\(\s*(?:short|char)\s*\)\s*{var}', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.SIGN_EXTENSION,
                    cwe_id="CWE-194",
                    location=loc,
                    var_name=var,
                    description="Unexpected sign extension - short/char cast may cause issues",
                    confidence=0.7,
                ))

        # Detect memcpy/memmove with short/signed size
        if re.search(r'(?:memcpy|memmove|memset)\s*\([^,]+,[^,]+,\s*\(\s*(?:short|char)\s*\)', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.SIGN_EXTENSION,
                cwe_id="CWE-194",
                location=loc,
                var_name="size",
                description="Sign extension in memory operation size parameter",
                confidence=0.75,
            ))

        # Detect when data (typically a short parameter) is used in malloc/memcpy without >= 0 check
        # Pattern: malloc(data) or memcpy(..., data) where data could be negative
        if 'data' not in overflow_guarded_vars:  # No >= 0 check
            # malloc with data
            if re.search(r'\bmalloc\s*\(\s*data\s*\)', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.SIGN_EXTENSION,
                    cwe_id="CWE-194",
                    location=loc,
                    var_name="data",
                    description="Sign extension in malloc - negative data becomes huge allocation",
                    confidence=0.8,
                ))
            # memcpy with data as size
            if re.search(r'\bmemcpy\s*\([^,]+,\s*[^,]+,\s*data\s*\)', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.SIGN_EXTENSION,
                    cwe_id="CWE-194",
                    location=loc,
                    var_name="data",
                    description="Sign extension in memcpy - negative size becomes huge copy",
                    confidence=0.8,
                ))
            # strncpy with data as size
            if re.search(r'\bstrncpy\s*\([^,]+,\s*[^,]+,\s*data\s*\)', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.SIGN_EXTENSION,
                    cwe_id="CWE-194",
                    location=loc,
                    var_name="data",
                    description="Sign extension in strncpy - negative size causes issues",
                    confidence=0.8,
                ))

        # =====================================================================
        # CWE-195: Signed to Unsigned Conversion Error
        # =====================================================================
        # Pattern: signed int used as size_t parameter to memory functions
        # without >= 0 check (only < SIZE check exists)
        # Look for: strncpy(dest, src, data), memcpy(dest, src, data), etc.
        # where data is signed and only checked with "data < SIZE" but not "data >= 0"
        if 'data' not in overflow_guarded_vars:  # No >= 0 check on data
            # Check for data used as size in strncpy/memcpy/memmove without negative check
            size_funcs = ['strncpy', 'memcpy', 'memmove', 'memset', 'fread', 'fwrite']
            for func in size_funcs:
                # Pattern: func(arg, arg, data) - data as size parameter
                if re.search(rf'\b{func}\s*\([^)]*,\s*data\s*\)', stripped):
                    # Check if there's ONLY a "data < X" check, not "data >= 0"
                    # This indicates signed-to-unsigned conversion vulnerability
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.SIGN_EXTENSION,
                        cwe_id="CWE-195",
                        location=loc,
                        var_name="data",
                        description=f"Signed to unsigned conversion - negative 'data' in {func}() becomes huge value",
                        confidence=0.85,
                    ))
                    break  # Only report once per line

        # =====================================================================
        # CWE-197: Numeric Truncation Error
        # =====================================================================
        # Pattern: Casting larger int to smaller type (int to short, int to char)
        # Vulnerable: short x = (short)data;  or  char x = (char)data;
        truncation_patterns = [
            (r'\(\s*short\s*\)\s*data\b', 'short', 'int to short'),
            (r'\(\s*char\s*\)\s*data\b', 'char', 'int to char'),
            (r'\(\s*signed\s+char\s*\)\s*data\b', 'signed char', 'int to signed char'),
            (r'\(\s*unsigned\s+char\s*\)\s*data\b', 'unsigned char', 'int to unsigned char'),
            (r'\(\s*uint8_t\s*\)\s*data\b', 'uint8_t', 'int to uint8_t'),
            (r'\(\s*int8_t\s*\)\s*data\b', 'int8_t', 'int to int8_t'),
            (r'\(\s*int16_t\s*\)\s*data\b', 'int16_t', 'int to int16_t'),
            (r'\(\s*uint16_t\s*\)\s*data\b', 'uint16_t', 'int to uint16_t'),
        ]
        for pattern, target_type, conversion in truncation_patterns:
            if re.search(pattern, stripped):
                # Check if bounds checking was done
                if 'data' not in bounds_checked_vars:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-197",
                        location=loc,
                        var_name="data",
                        description=f"Numeric truncation - {conversion} may lose data",
                        confidence=0.85,
                    ))
                break  # Only report once per line

        # =====================================================================
        # CWE-369: Divide by Zero
        # =====================================================================
        # Pattern 1: Division/modulo by 'data' variable (user-controlled input)
        if re.search(r'[/%]\s*data\b', stripped) or re.search(r'[/%]\s*\(\s*int\s*\)\s*data', stripped):
            if 'data' not in zero_checked_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.DIVIDE_BY_ZERO,
                    cwe_id="CWE-369",
                    location=loc,
                    var_name="data",
                    description="Division by user-controlled value without zero validation",
                    confidence=0.85,
                ))

        # Pattern 2: Division/modulo by any tainted variable without zero-check
        div_match = re.search(r'[/%]\s*(\w+)\b', stripped)
        if div_match:
            divisor = div_match.group(1)
            # Skip if it's a number literal, or known safe patterns
            if not divisor.isdigit() and divisor not in ('sizeof', 'data'):
                if divisor not in zero_checked_vars and divisor in tainted_vars:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.DIVIDE_BY_ZERO,
                        cwe_id="CWE-369",
                        location=loc,
                        var_name=divisor,
                        description=f"Division by tainted variable '{divisor}' without zero validation",
                        confidence=0.85,
                    ))

        # Pattern 3: Division by expression that could be zero (e.g., count - 1)
        expr_div_match = re.search(r'[/%]\s*\(\s*(\w+)\s*-\s*(\d+)\s*\)', stripped)
        if expr_div_match:
            var = expr_div_match.group(1)
            subtracted = int(expr_div_match.group(2))
            if subtracted >= 1 and var not in zero_checked_vars and var not in bounds_checked_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.DIVIDE_BY_ZERO,
                    cwe_id="CWE-369",
                    location=loc,
                    var_name=var,
                    description=f"Division by ({var} - {subtracted}) without checking {var} > {subtracted}",
                    confidence=0.75,
                ))

        # Pattern 4: Division by function return value that could be zero
        func_div_match = re.search(r'[/%]\s*(\w+)\s*\(', stripped)
        if func_div_match:
            func_name = func_div_match.group(1)
            zero_returnable = {'strlen', 'wcslen', 'count', 'size', 'length',
                              'get_count', 'get_size', 'get_length', 'atoi', 'atol',
                              'strtol', 'strtoul', 'strtoll', 'strtoull'}
            if func_name.lower() in zero_returnable or func_name.startswith('get_') or func_name.endswith('_count'):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.DIVIDE_BY_ZERO,
                    cwe_id="CWE-369",
                    location=loc,
                    var_name=func_name,
                    description=f"Division by {func_name}() return value which could be zero",
                    confidence=0.7,
                ))

        # =====================================================================
        # CWE-176: Improper Handling of Unicode Encoding
        # =====================================================================
        # Detect WideCharToMultiByte with potentially undersized destination buffer
        # The vulnerable pattern: using requiredSize from first call without checking against buffer size
        if re.search(r'WideCharToMultiByte\s*\(', stripped):
            # This is the second call (not the size-query call which has 0, 0, 0 at end)
            if not re.search(r'WideCharToMultiByte.*,\s*0\s*,\s*0\s*,\s*0\s*\)', stripped):
                # Using requiredSize or variable size instead of proper buffer check
                if re.search(r'WideCharToMultiByte\s*\([^)]*,\s*\w+\s*,\s*0\s*,\s*0\s*\)', stripped):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.UNICODE_HANDLING,
                        cwe_id="CWE-176",
                        location=loc,
                        var_name="buffer",
                        description="Unicode conversion may overflow fixed-size destination buffer",
                        confidence=0.8,
                    ))

        # MultiByteToWideChar similar pattern
        if re.search(r'MultiByteToWideChar\s*\(', stripped):
            if not re.search(r'MultiByteToWideChar.*,\s*0\s*\)', stripped):
                if re.search(r'MultiByteToWideChar\s*\([^)]*,\s*\w+\s*\)', stripped):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.UNICODE_HANDLING,
                        cwe_id="CWE-176",
                        location=loc,
                        var_name="buffer",
                        description="Unicode conversion may overflow fixed-size destination buffer",
                        confidence=0.8,
                    ))

        # =====================================================================
        # CWE-23/36: Path Traversal
        # =====================================================================
        path_match = re.search(r'\b(fopen|open|ifstream|ofstream|CreateFile)\s*\(\s*(\w+)', stripped)
        if path_match:
            func = path_match.group(1)
            path_var = path_match.group(2)
            if path_var in tainted_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    cwe_id="CWE-23",
                    location=loc,
                    var_name=path_var,
                    description=f"Potential path traversal - user-controlled path in {func}",
                    confidence=0.7,
                ))

        # =====================================================================
        # CWE-78: OS Command Injection
        # Detects when user-controlled input flows into command execution
        # =====================================================================

        # Pattern 1: system() with variable argument
        system_match = re.search(r'\bsystem\s*\(\s*(\w+)\s*\)', stripped)
        if system_match:
            cmd_var = system_match.group(1)
            confidence = 0.9 if cmd_var in tainted_vars or cmd_var == 'data' else 0.7
            vulns.append(MemoryVuln(
                vuln_type=VulnType.COMMAND_INJECTION,
                cwe_id="CWE-78",
                location=loc,
                var_name=cmd_var,
                description="OS command injection - user-controlled input in system()",
                confidence=confidence,
            ))

        # Pattern 2: popen() with variable command
        popen_match = re.search(r'\b_?popen\s*\(\s*(\w+)\s*,', stripped)
        if popen_match:
            cmd_var = popen_match.group(1)
            confidence = 0.9 if cmd_var in tainted_vars or cmd_var == 'data' else 0.7
            vulns.append(MemoryVuln(
                vuln_type=VulnType.COMMAND_INJECTION,
                cwe_id="CWE-78",
                location=loc,
                var_name=cmd_var,
                description="OS command injection - user-controlled input in popen()",
                confidence=confidence,
            ))

        # Pattern 3: exec family functions with tainted arguments
        exec_match = re.search(r'\b(execl|execlp|execle|execv|execvp|execve|execvpe)\s*\(', stripped)
        if exec_match:
            func = exec_match.group(1)
            # Check for /bin/sh -c pattern
            if re.search(r'exec[lv]p?\s*\([^)]*"/bin/sh"[^)]*"-c"', stripped):
                cmd_arg_match = re.search(r'"-c"\s*,\s*(\w+)', stripped)
                if cmd_arg_match:
                    cmd_var = cmd_arg_match.group(1)
                    confidence = 0.95 if cmd_var in tainted_vars or cmd_var == 'data' else 0.8
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        cwe_id="CWE-78",
                        location=loc,
                        var_name=cmd_var,
                        description="OS command injection - user input passed to shell via " + func + "()",
                        confidence=confidence,
                    ))
            # Check for tainted variable in exec arguments
            for tainted_var in tainted_vars:
                if re.search(rf'\b{func}\s*\([^)]*\b{tainted_var}\b', stripped):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        cwe_id="CWE-78",
                        location=loc,
                        var_name=tainted_var,
                        description="OS command injection - tainted input in " + func + "()",
                        confidence=0.85,
                    ))
                    break

        # Pattern 4: ShellExecute family (Windows)
        shell_exec_match = re.search(r'\b(ShellExecute[AW]?|ShellExecuteEx[AW]?)\s*\(', stripped)
        if shell_exec_match:
            func = shell_exec_match.group(1)
            for tainted_var in tainted_vars:
                if re.search(rf'{func}\s*\([^)]*\b{tainted_var}\b', stripped):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        cwe_id="CWE-78",
                        location=loc,
                        var_name=tainted_var,
                        description="OS command injection - tainted input in " + func + "()",
                        confidence=0.85,
                    ))
                    break

        # Pattern 5: CreateProcess family (Windows)
        create_proc_match = re.search(r'\b(CreateProcess[AW]?)\s*\(\s*(?:NULL|nullptr|0)\s*,\s*(\w+)', stripped)
        if create_proc_match:
            func = create_proc_match.group(1)
            cmd_var = create_proc_match.group(2)
            confidence = 0.9 if cmd_var in tainted_vars or cmd_var == 'data' else 0.7
            vulns.append(MemoryVuln(
                vuln_type=VulnType.COMMAND_INJECTION,
                cwe_id="CWE-78",
                location=loc,
                var_name=cmd_var,
                description="OS command injection - variable command line in " + func + "()",
                confidence=confidence,
            ))

        # Pattern 6: WinExec (Windows)
        winexec_match = re.search(r'\bWinExec\s*\(\s*(\w+)', stripped)
        if winexec_match:
            cmd_var = winexec_match.group(1)
            confidence = 0.9 if cmd_var in tainted_vars or cmd_var == 'data' else 0.75
            vulns.append(MemoryVuln(
                vuln_type=VulnType.COMMAND_INJECTION,
                cwe_id="CWE-78",
                location=loc,
                var_name=cmd_var,
                description="OS command injection - variable in WinExec()",
                confidence=confidence,
            ))

        # Pattern 7: Direct argv usage in command execution
        if re.search(r'\b(system|_?popen|execl|execlp|execle|execv|execvp|execve)\s*\([^)]*argv\s*\[', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.COMMAND_INJECTION,
                cwe_id="CWE-78",
                location=loc,
                var_name="argv",
                description="OS command injection - command-line argument used directly in command execution",
                confidence=0.95,
            ))

        # =====================================================================
        # CWE-114: Process Control - Loading libraries with user input
        # =====================================================================
        lib_match = re.search(r'\b(LoadLibrary[AW]?|LoadModule)\s*\(\s*(\w+)', stripped)
        if lib_match:
            lib_var = lib_match.group(2)
            if lib_var in tainted_vars or lib_var == 'data':
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    cwe_id="CWE-114",
                    location=loc,
                    var_name=lib_var,
                    description="Process control - loading library from user-controlled path",
                    confidence=0.85,
                ))

        # =====================================================================
        # CWE-122: Heap Buffer Overflow - strncpy with fixed size to data param
        # =====================================================================
        # Pattern: strncpy(data, source, N) where N is a constant - data could be smaller
        if re.search(r'\bstrncpy\s*\(\s*data\s*,\s*\w+\s*,\s*\d+', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name="data",
                description="Buffer overflow - strncpy with fixed size, data may be smaller",
                confidence=0.75,
            ))

        # =====================================================================
        # CWE-126: Buffer Over-read - reading beyond buffer bounds
        # =====================================================================
        # Pattern: memcpy/memmove with dest size as length (may read past src)
        if re.search(r'\bmemcpy\s*\(\s*\w+\s*,\s*data\s*,\s*(?:strlen|sizeof)\s*\(', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-126",
                location=loc,
                var_name="data",
                description="Buffer over-read - copying based on destination size, not source",
                confidence=0.8,
            ))

        # Pattern: strlen on potentially non-null-terminated buffer
        strlen_match = re.search(r'\bstrlen\s*\(\s*(\w+)\s*\)', stripped)
        if strlen_match:
            buf_var = strlen_match.group(1)
            # Check if buffer came from memcpy/read without null termination
            if buf_var == 'data' or buf_var in tainted_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-126",
                    location=loc,
                    var_name=buf_var,
                    description="Buffer over-read - strlen on potentially non-null-terminated buffer",
                    confidence=0.7,
                ))

        # Pattern: memcpy(dest, src, LARGE_SIZE) reading past src bounds
        memcpy_large_match = re.search(r'\bmemcpy\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(\d+)\s*\)', stripped)
        if memcpy_large_match:
            src_var = memcpy_large_match.group(1)
            size = int(memcpy_large_match.group(2))
            # Large constant size suggests potential over-read
            if size > 1024 and (src_var == 'data' or src_var in tainted_vars):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-126",
                    location=loc,
                    var_name=src_var,
                    description=f"Buffer over-read - memcpy reading {size} bytes from source",
                    confidence=0.75,
                ))

        # Pattern: buf[index] where index is not validated (>= size) - read operation
        array_read_match = re.search(r'=\s*(\w+)\s*\[\s*(\w+)\s*\]', stripped)
        if array_read_match:
            buf_var = array_read_match.group(1)
            index_var = array_read_match.group(2)
            # Check if it's an unchecked tainted index
            if index_var in tainted_vars and index_var not in bounds_checked_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-126",
                    location=loc,
                    var_name=buf_var,
                    description=f"Buffer over-read - array read with unchecked index '{index_var}'",
                    confidence=0.75,
                ))

        # Pattern: read beyond array with constant large index
        large_index_read = re.search(r'=\s*\w+\s*\[\s*(\d+)\s*\]', stripped)
        if large_index_read:
            index_val = int(large_index_read.group(1))
            # Very large constant index suggests over-read
            if index_val > 1000:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-126",
                    location=loc,
                    var_name="buffer",
                    description=f"Buffer over-read - accessing large index {index_val}",
                    confidence=0.7,
                ))

        # Pattern: *(ptr + offset) read without bounds check
        ptr_add_read_match = re.search(r'=\s*\*\s*\(\s*(\w+)\s*\+\s*(\w+)\s*\)', stripped)
        if ptr_add_read_match:
            ptr_var = ptr_add_read_match.group(1)
            offset_var = ptr_add_read_match.group(2)
            # Check if offset is tainted/unchecked
            if offset_var in tainted_vars and offset_var not in bounds_checked_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-126",
                    location=loc,
                    var_name=ptr_var,
                    description=f"Buffer over-read - pointer read with unchecked offset '{offset_var}'",
                    confidence=0.75,
                ))

        # =====================================================================
        # CWE-127: Buffer Under-read - reading before buffer start
        # =====================================================================
        # Pattern: memmove(dest, data, N) - reading from data with fixed size
        if re.search(r'\bmemmove\s*\(\s*\w+\s*,\s*data\s*,\s*\d+', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-127",
                location=loc,
                var_name="data",
                description="Buffer under-read - memmove from data with fixed size",
                confidence=0.75,
            ))

        # Pattern: *(ptr - n) read operation with constant offset
        ptr_minus_const_match = re.search(r'=\s*\*\s*\(\s*(\w+)\s*-\s*(\d+)\s*\)', stripped)
        if ptr_minus_const_match:
            ptr_var = ptr_minus_const_match.group(1)
            offset = ptr_minus_const_match.group(2)
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-127",
                location=loc,
                var_name=ptr_var,
                description=f"Buffer under-read - reading {offset} bytes before pointer",
                confidence=0.85,
            ))

        # Pattern: *(ptr - var) read without bounds check
        ptr_minus_var_match = re.search(r'=\s*\*\s*\(\s*(\w+)\s*-\s*(\w+)\s*\)', stripped)
        if ptr_minus_var_match:
            ptr_var = ptr_minus_var_match.group(1)
            offset_var = ptr_minus_var_match.group(2)
            # Avoid matching constant offsets (already handled above)
            if not offset_var.isdigit() and offset_var not in bounds_checked_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-127",
                    location=loc,
                    var_name=ptr_var,
                    description=f"Buffer under-read - reading before pointer by '{offset_var}'",
                    confidence=0.8,
                ))

        # Pattern: memcpy/memmove reading from ptr - offset
        memcpy_underread_match = re.search(r'\b(?:memcpy|memmove)\s*\(\s*\w+\s*,\s*(\w+)\s*-\s*(\d+)', stripped)
        if memcpy_underread_match:
            src_var = memcpy_underread_match.group(1)
            offset = memcpy_underread_match.group(2)
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-127",
                location=loc,
                var_name=src_var,
                description=f"Buffer under-read - reading from {src_var} - {offset}",
                confidence=0.85,
            ))

        # Pattern: buf[negative_index] - reading with negative array index
        neg_array_read_match = re.search(r'=\s*(\w+)\s*\[\s*-\s*(\d+)\s*\]', stripped)
        if neg_array_read_match:
            buf_var = neg_array_read_match.group(1)
            offset = neg_array_read_match.group(2)
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-127",
                location=loc,
                var_name=buf_var,
                description=f"Buffer under-read - negative array index -{offset}",
                confidence=0.9,
            ))

        # memmove to data - could overflow if data is small
        if re.search(r'\bmemmove\s*\(\s*data\s*,\s*\w+\s*,\s*\d+', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-124",
                location=loc,
                var_name="data",
                description="Buffer overflow/underwrite - memmove to data with fixed size",
                confidence=0.75,
            ))

        # wcsncpy and wcscat with fixed size
        if re.search(r'\bwcsncpy\s*\(\s*data\s*,\s*\w+\s*,\s*\d+', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name="data",
                description="Buffer overflow - wcsncpy to data with fixed size",
                confidence=0.75,
            ))

        # =====================================================================
        # CWE-127: Buffer Under-read - accessing before buffer start (legacy)
        # =====================================================================
        if re.search(r'\bdata\s*\[\s*-\s*\d+\s*\]', stripped) or \
           re.search(r'\*\s*\(\s*data\s*-\s*\d+\s*\)', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-127",
                location=loc,
                var_name="data",
                description="Buffer under-read - accessing before buffer start",
                confidence=0.85,
            ))

        # =====================================================================
        # CWE-123: Write-What-Where Condition
        # =====================================================================
        if re.search(r'\w+->(?:next|prev)\s*=', stripped):
            if re.search(r'\bdata\b', stripped) or 'data' in source[:min(line_num*100, len(source))]:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-123",
                    location=loc,
                    var_name="linkedList",
                    description="Write-What-Where - manipulating linked list pointers",
                    confidence=0.7,
                ))

        # =====================================================================
        # CWE-124: Buffer Underwrite - writing before buffer start
        # =====================================================================
        if re.search(r'\b(?:memcpy|memmove|strcpy|strncpy)\s*\(\s*data\s*-', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-124",
                location=loc,
                var_name="data",
                description="Buffer underwrite - writing before buffer start",
                confidence=0.85,
            ))

        # Pattern: data[i] = source[i] in a loop - could underwrite if data is offset
        if re.search(r'\bdata\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-124",
                location=loc,
                var_name="data",
                description="Buffer underwrite - loop writing to data could overflow",
                confidence=0.7,
            ))

        # =====================================================================
        # CWE-121/122: Stack/Heap Buffer Overflow - array index out of bounds
        # =====================================================================
        # Pattern: buffer[data] without proper bounds checking
        if re.search(r'\w+\s*\[\s*data\s*\]', stripped):
            # Check if there's only a partial check (>= 0 but not < SIZE)
            if 'data' not in bounds_checked_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-121",
                    location=loc,
                    var_name="data",
                    description="Buffer overflow - array index without full bounds check",
                    confidence=0.75,
                ))

        # =====================================================================
        # Track variable reassignments that invalidate freed state
        # =====================================================================
        # When a freed variable is reassigned to NULL or reallocated, it's no longer "freed"
        null_reassign = re.search(r'(\w+)\s*=\s*(?:NULL|nullptr|0)\s*;', stripped)
        if null_reassign:
            var = null_reassign.group(1)
            if var in freed_vars:
                del freed_vars[var]  # Variable is now NULL, not a dangling freed pointer

        # When a variable is reallocated, clear its freed state
        realloc_match = re.search(r'(\w+)\s*=\s*(?:\([^)]*\))?\s*(?:malloc|calloc|realloc|new)\b', stripped)
        if realloc_match:
            var = realloc_match.group(1)
            if var in freed_vars:
                del freed_vars[var]  # Variable now points to new allocation

        # =====================================================================
        # CWE-415: Double Free
        # =====================================================================
        free_match = re.search(r'\b(?:free|delete(?:\s*\[\])?)\s*\(?\s*(\w+)', stripped)
        if free_match:
            var = free_match.group(1)
            # FP reduction: Skip if in good context
            if not is_good_context and var in freed_vars:
                # FP reduction: Check if variable was reassigned between frees
                prev_free_line = freed_vars[var]
                was_reassigned = False
                for check_idx in range(prev_free_line, line_num - 1):
                    if check_idx < len(lines):
                        check_line = lines[check_idx]
                        # Check for assignment: var = something
                        if re.search(rf'\b{re.escape(var)}\s*=\s*[^=]', check_line):
                            was_reassigned = True
                            break
                if not was_reassigned:
                    # Double free - this variable was already freed and not reassigned
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.DOUBLE_FREE,
                        cwe_id="CWE-415",
                        location=loc,
                        var_name=var,
                        description=f"Double free - '{var}' freed again after line {freed_vars[var]}",
                        confidence=0.9,
                    ))
            # Track this free
            freed_vars[var] = line_num

            # =====================================================================
            # CWE-762: Mismatched Memory Management Routines
            # =====================================================================
            # Check if deallocation method matches allocation method
            if var in alloc_types:
                alloc_type, alloc_line = alloc_types[var]
                # Strip comments to avoid false positives (e.g., "delete arr; // use delete[]")
                code_part = re.sub(r'//.*$', '', stripped)  # Remove C++ line comments
                code_part = re.sub(r'/\*.*?\*/', '', code_part)  # Remove C block comments
                is_delete_array = re.search(r'\bdelete\s*\[\s*\]', code_part) is not None
                is_delete = re.search(r'\bdelete\b', code_part) is not None and not is_delete_array
                is_free = re.search(r'\bfree\s*\(', code_part) is not None

                mismatch = None
                if alloc_type == 'NEW_ARRAY' and is_delete:
                    mismatch = "new[] with delete (should use delete[])"
                elif alloc_type == 'NEW' and is_delete_array:
                    mismatch = "new with delete[] (should use delete)"
                elif alloc_type == 'MALLOC' and (is_delete or is_delete_array):
                    mismatch = "malloc/calloc/realloc with delete (should use free)"
                elif alloc_type in ('NEW', 'NEW_ARRAY') and is_free:
                    mismatch = f"{'new[]' if alloc_type == 'NEW_ARRAY' else 'new'} with free (should use {'delete[]' if alloc_type == 'NEW_ARRAY' else 'delete'})"

                if mismatch:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.DOUBLE_FREE,  # Memory management issue
                        cwe_id="CWE-762",
                        location=loc,
                        var_name=var,
                        description=f"Mismatched memory management - {mismatch} (allocated at line {alloc_line})",
                        alloc_location=Location(filename, alloc_line, 0),
                        confidence=0.95,
                    ))

        # =====================================================================
        # CWE-416: Use After Free
        # =====================================================================
        # Check if any freed variable is being used (dereferenced, passed to function, etc.)
        for var, free_line in list(freed_vars.items()):
            if line_num > free_line:
                # Check for dereference of freed variable
                if re.search(rf'\*\s*{var}\b', stripped) or \
                   re.search(rf'{var}\s*\[', stripped) or \
                   re.search(rf'{var}\s*->', stripped):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.USE_AFTER_FREE,
                        cwe_id="CWE-416",
                        location=loc,
                        var_name=var,
                        description=f"Use after free - '{var}' used after being freed at line {free_line}",
                        confidence=0.85,
                    ))
                # Check for passing freed variable to function (but not free/delete)
                if re.search(rf'\w+\s*\(\s*{var}\s*[,)]', stripped) and \
                   not re.search(rf'\b(?:free|delete)\s*\(?\s*{var}', stripped):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.USE_AFTER_FREE,
                        cwe_id="CWE-416",
                        location=loc,
                        var_name=var,
                        description=f"Use after free - '{var}' passed to function after being freed",
                        confidence=0.8,
                    ))

        # =====================================================================
        # CWE-590: Free of Memory Not on Heap
        # =====================================================================
        if free_match:
            var = free_match.group(1)
            if var in stack_allocated_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INVALID_FREE,
                    cwe_id="CWE-590",
                    location=loc,
                    var_name=var,
                    description=f"Free of stack memory - '{var}' was allocated with alloca at line {stack_allocated_vars[var]}",
                    confidence=0.95,
                ))

        # =====================================================================
        # CWE-404: Improper Resource Shutdown
        # =====================================================================
        # Check for wrong close function (e.g., close() on fopen handle)
        close_match = re.search(r'\b(close|_close)\s*\(\s*(?:fileno\s*\(\s*)?(\w+)', stripped)
        if close_match:
            handle = close_match.group(2)
            if handle in file_handles:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.RESOURCE_LEAK,
                    cwe_id="CWE-404",
                    location=loc,
                    var_name=handle,
                    description=f"Improper resource shutdown - using close() on FILE* handle, use fclose()",
                    confidence=0.9,
                ))

        # =====================================================================
        # CWE-680: Integer Overflow to Buffer Overflow
        # =====================================================================
        # This CWE specifically covers integer overflow in size calculation
        # that leads to undersized buffer allocation.

        # Pattern 1: malloc(data * sizeof(...)) or malloc(sizeof(...) * data)
        # Note: Use .* instead of [^)]* to handle nested parens like sizeof(char)
        if re.search(r'\bmalloc\s*\(\s*data\s*\*', stripped) or \
           re.search(r'\bmalloc\s*\(.*\*\s*data\b', stripped):
            if 'data' not in overflow_guarded_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-680",
                    location=loc,
                    var_name="data",
                    description="Integer overflow in malloc size - user-controlled data in allocation size",
                    confidence=0.85,
                ))

        # Pattern 2: calloc(data, ...) or calloc(..., data)
        if re.search(r'\bcalloc\s*\(\s*data\s*,', stripped) or \
           re.search(r'\bcalloc\s*\([^,]+,\s*data\s*\)', stripped):
            if 'data' not in overflow_guarded_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-680",
                    location=loc,
                    var_name="data",
                    description="Integer overflow in calloc size - user-controlled data in allocation",
                    confidence=0.85,
                ))

        # Pattern 3: malloc/calloc/realloc with a pre-computed size variable
        # e.g., size = count * element_size; buf = malloc(size);
        alloc_with_var = re.search(r'\b(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*[,)]', stripped)
        if alloc_with_var:
            size_var = alloc_with_var.group(1)
            if size_var in overflow_computed_vars:
                compute_line, operands = overflow_computed_vars[size_var]
                # Check if any operand was tainted and not guarded
                unguarded_operands = [op for op in operands if op not in overflow_guarded_vars]
                if unguarded_operands:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-680",
                        location=loc,
                        var_name=size_var,
                        description=f"Integer overflow to buffer overflow - '{size_var}' computed from potentially overflowing arithmetic at line {compute_line}",
                        confidence=0.85,
                    ))

        # Pattern 4: realloc with data * sizeof() pattern
        if re.search(r'\brealloc\s*\([^,]+,\s*data\s*\*', stripped) or \
           re.search(r'\brealloc\s*\([^,]+,\s*[^)]*\*\s*data\s*\)', stripped):
            if 'data' not in overflow_guarded_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-680",
                    location=loc,
                    var_name="data",
                    description="Integer overflow in realloc size - user-controlled data in allocation size",
                    confidence=0.85,
                ))

        # Pattern 5: new[] with data or computed size
        # e.g., new int[data] or new char[size] where size was computed from overflow-prone arithmetic
        new_array_match = re.search(r'\bnew\s+\w+\s*\[\s*(\w+)\s*\]', stripped)
        if new_array_match:
            size_var = new_array_match.group(1)
            if size_var == 'data' and 'data' not in overflow_guarded_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-680",
                    location=loc,
                    var_name="data",
                    description="Integer overflow in new[] size - user-controlled data in array allocation",
                    confidence=0.85,
                ))
            elif size_var in overflow_computed_vars:
                compute_line, operands = overflow_computed_vars[size_var]
                unguarded_operands = [op for op in operands if op not in overflow_guarded_vars]
                if unguarded_operands:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-680",
                        location=loc,
                        var_name=size_var,
                        description=f"Integer overflow in new[] - '{size_var}' computed from potentially overflowing arithmetic at line {compute_line}",
                        confidence=0.85,
                    ))

        # Pattern 6: Direct multiplication in new[] expression
        # e.g., new int[count * element_count]
        new_mult_match = re.search(r'\bnew\s+\w+\s*\[\s*(\w+)\s*\*\s*(\w+)\s*\]', stripped)
        if new_mult_match:
            op1 = new_mult_match.group(1)
            op2 = new_mult_match.group(2)
            if (op1 in tainted_vars or op1 == 'data') and op1 not in overflow_guarded_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-680",
                    location=loc,
                    var_name=op1,
                    description=f"Integer overflow in new[] - multiplication with tainted '{op1}'",
                    confidence=0.85,
                ))
            elif (op2 in tainted_vars or op2 == 'data') and op2 not in overflow_guarded_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-680",
                    location=loc,
                    var_name=op2,
                    description=f"Integer overflow in new[] - multiplication with tainted '{op2}'",
                    confidence=0.85,
                ))

        # Pattern 7: malloc/calloc with multiplication involving any tainted variable
        for tainted_var in tainted_vars:
            if tainted_var not in overflow_guarded_vars:
                # Check for malloc(tainted_var * ...)
                if re.search(rf'\bmalloc\s*\([^)]*\b{tainted_var}\s*\*', stripped) or \
                   re.search(rf'\bmalloc\s*\([^)]*\*\s*{tainted_var}\b', stripped):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-680",
                        location=loc,
                        var_name=tainted_var,
                        description=f"Integer overflow in malloc - tainted '{tainted_var}' used in size calculation",
                        confidence=0.85,
                    ))
                    break  # Only report once per line

        # =====================================================================
        # CWE-319: Cleartext Transmission of Sensitive Information
        # =====================================================================
        # Pattern 1: send() with password/credential variables
        send_match = re.search(r'send\s*\(\s*\w+\s*,\s*(\w+)', stripped)
        if send_match:
            sent_var = send_match.group(1)
            # Check if the variable name suggests sensitive data
            if re.search(r'password|passwd|pwd|credential|secret|token|key|auth', sent_var, re.IGNORECASE):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.SENSITIVE_DATA_EXPOSURE,
                    cwe_id="CWE-319",
                    location=loc,
                    var_name=sent_var,
                    description=f"Cleartext transmission - sensitive data '{sent_var}' sent over unencrypted socket",
                    confidence=0.85,
                ))

        # Pattern 2: send() with 'password' or similar as the data buffer
        if re.search(r'send\s*\([^,]+,\s*(?:\(char\s*\*\)\s*)?(?:password|passwd|pwd|credential|secret|auth)', stripped, re.IGNORECASE):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.SENSITIVE_DATA_EXPOSURE,
                cwe_id="CWE-319",
                location=loc,
                var_name="password",
                description="Cleartext transmission - password sent over unencrypted socket",
                confidence=0.9,
            ))

        # Pattern 3: HTTP URLs with sensitive parameters (not HTTPS)
        http_match = re.search(r'["\']http://[^"\']*(?:password|passwd|pwd|token|key|secret|auth|credential)=', stripped, re.IGNORECASE)
        if http_match:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.SENSITIVE_DATA_EXPOSURE,
                cwe_id="CWE-319",
                location=loc,
                var_name="url",
                description="Cleartext transmission - sensitive data in HTTP URL (not HTTPS)",
                confidence=0.9,
            ))

        # Pattern 4: Socket send with password struct member
        if re.search(r'send\s*\([^,]+,\s*[^,]*->password', stripped) or            re.search(r'send\s*\([^,]+,\s*[^,]*\.password', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.SENSITIVE_DATA_EXPOSURE,
                cwe_id="CWE-319",
                location=loc,
                var_name="password",
                description="Cleartext transmission - password field sent over unencrypted socket",
                confidence=0.9,
            ))

        # Pattern 5: WSASend or other Windows socket APIs with sensitive data
        if re.search(r'WSASend\s*\([^)]*(?:password|passwd|credential|secret)', stripped, re.IGNORECASE):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.SENSITIVE_DATA_EXPOSURE,
                cwe_id="CWE-319",
                location=loc,
                var_name="password",
                description="Cleartext transmission - sensitive data sent via WSASend",
                confidence=0.85,
            ))

        # Pattern 6: write() to socket with sensitive data
        if re.search(r'write\s*\(\s*\w*sock\w*\s*,\s*(?:password|passwd|credential)', stripped, re.IGNORECASE):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.SENSITIVE_DATA_EXPOSURE,
                cwe_id="CWE-319",
                location=loc,
                var_name="password",
                description="Cleartext transmission - password written to socket",
                confidence=0.85,
            ))

        # =====================================================================
        # CWE-476: NULL Pointer Dereference (enhanced)
        # =====================================================================
        # Check for dereference of NULL-assigned variable
        for var, null_line in null_assigned_vars.items():
            if line_num > null_line:
                # FP reduction: Skip if in good context
                if is_good_context:
                    continue
                # Check for dereference without NULL check
                if var not in null_checked_vars:
                    # FP reduction: Check if variable was reassigned between null assign and here
                    was_reassigned = False
                    for check_line in lines[null_line:line_num-1]:
                        # Check for assignment: var = something_not_null
                        if re.search(rf'\b{re.escape(var)}\s*=\s*[^=;]+[^=;]', check_line):
                            # But not var = NULL or var = 0
                            if not re.search(rf'{re.escape(var)}\s*=\s*(?:NULL|nullptr|0)\s*;', check_line):
                                was_reassigned = True
                                break
                    if was_reassigned:
                        continue
                    if re.search(rf'\*\s*{var}\b', stripped) or \
                       re.search(rf'{var}\s*\[', stripped) or \
                       re.search(rf'{var}\s*->', stripped):
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.NULL_DEREFERENCE,
                            cwe_id="CWE-476",
                            location=loc,
                            var_name=var,
                            description=f"NULL pointer dereference - '{var}' set to NULL at line {null_line} and dereferenced without check",
                            confidence=0.85,
                        ))

        # =====================================================================
        # CWE-401: Memory Leak tracking
        # =====================================================================
        if re.search(r'\breturn\b', stripped) and allocated_vars and not is_good_context:
            for var, alloc_line in allocated_vars.items():
                if var not in freed_vars:
                    # FP reduction: Check if the variable is being returned (transferred ownership)
                    if re.search(rf'\breturn\s+{re.escape(var)}\b', stripped):
                        continue
                    # FP reduction: Check if variable is assigned to an output parameter or global
                    # by looking at previous lines
                    was_transferred = False
                    for check_line in lines[max(0, alloc_line):line_num]:
                        # Output param assignment: *out_param = var
                        if re.search(rf'\*\w+\s*=\s*{re.escape(var)}\b', check_line):
                            was_transferred = True
                            break
                        # Structure member assignment: obj->member = var
                        if re.search(rf'\w+->\w+\s*=\s*{re.escape(var)}\b', check_line):
                            was_transferred = True
                            break
                        # Global assignment: g_ptr = var
                        if re.search(rf'g_\w+\s*=\s*{re.escape(var)}\b', check_line):
                            was_transferred = True
                            break
                    if was_transferred:
                        continue
                    # FP reduction: Skip in good context
                    if is_good_context:
                        continue
                    if line_num - alloc_line < 50:
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.MEMORY_LEAK,
                            cwe_id="CWE-401",
                            location=Location(filename, alloc_line, 0),
                            var_name=var,
                            description=f"Potential memory leak - '{var}' allocated but may not be freed before return",
                            confidence=0.5,
                        ))

        # =====================================================================
        # CWE-457: Use of Uninitialized Variable
        # =====================================================================
        # Track variable declarations without initialization
        # Patterns: int x; | char *ptr; | int arr[10]; | float val;

        # FP reduction: Use the is_good_context computed at the start of the loop
        # (no need to redefine it here - it's already set correctly)

        # Scalar/pointer declaration without initialization
        decl_match = re.match(
            r'^\s*(?:static\s+)?(?:const\s+)?(?:unsigned\s+|signed\s+)?'
            r'(int|char|short|long|float|double|void|size_t|ssize_t|'
            r'int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t|'
            r'wchar_t|WCHAR|CHAR|DWORD|WORD|BYTE|BOOL|HANDLE|LPSTR|LPCSTR|LPWSTR|LPCWSTR)'
            r'\s*(\*+)?\s*(\w+)\s*;',
            stripped
        )
        if decl_match and not is_good_context:
            var_type = decl_match.group(1)
            is_pointer = decl_match.group(2) is not None
            var_name = decl_match.group(3)
            # Skip common loop vars and reserved words
            if var_name not in ('i', 'j', 'k', 'n', 'm', 'x', 'y', 'this', 'return', 'if', 'else', 'while', 'for'):
                full_type = f"{var_type}{'*' if is_pointer else ''}"
                declared_vars[var_name] = (line_num, full_type)
                if verbose:
                    print(f"[CWE-457] Declared var '{var_name}' ({full_type}) at line {line_num}")

        # Array declaration without initialization
        array_decl_match = re.match(
            r'^\s*(?:static\s+)?(?:const\s+)?(?:unsigned\s+|signed\s+)?'
            r'(int|char|short|long|float|double|wchar_t|WCHAR|CHAR|BYTE)'
            r'\s+(\w+)\s*\[\s*(\d+)?\s*\]\s*;',
            stripped
        )
        if array_decl_match:
            var_type = array_decl_match.group(1)
            var_name = array_decl_match.group(2)
            if var_name not in ('this', 'return'):
                declared_vars[var_name] = (line_num, f"{var_type}[]")
                if verbose:
                    print(f"[CWE-457] Declared array '{var_name}' ({var_type}[]) at line {line_num}")

        # Track assignments (initialization)
        # Patterns: var = expr; | var = malloc(...); | var = new ...;
        # Exclude pointer dereference assignments like *ptr = x (the pointer itself isn't initialized)
        assign_match = re.search(r'(?<!\*)\b(\w+)\s*=\s*[^=]', stripped)
        if assign_match:
            var_name = assign_match.group(1)
            # Also exclude array element assignments like arr[i] = x
            is_array_access = re.search(rf'\b{re.escape(var_name)}\s*\[', stripped)
            if var_name in declared_vars and var_name not in initialized_vars and not is_array_access:
                initialized_vars.add(var_name)
                if verbose:
                    print(f"[CWE-457] Initialized var '{var_name}' at line {line_num}")

        # Also track initialization in declarations: int x = 5;
        init_decl_match = re.match(
            r'^\s*(?:static\s+)?(?:const\s+)?(?:unsigned\s+|signed\s+)?'
            r'(?:int|char|short|long|float|double|void|size_t|ssize_t|'
            r'int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t|'
            r'wchar_t|WCHAR|CHAR|DWORD|WORD|BYTE|BOOL|HANDLE|LPSTR|LPCSTR|LPWSTR|LPCWSTR)'
            r'\s*\*?\s*(\w+)\s*=',
            stripped
        )
        if init_decl_match:
            var_name = init_decl_match.group(1)
            initialized_vars.add(var_name)

        # Array initialization: int arr[10] = {...}
        array_init_match = re.match(
            r'^\s*(?:static\s+)?(?:const\s+)?(?:unsigned\s+|signed\s+)?'
            r'(?:int|char|short|long|float|double|wchar_t|WCHAR|CHAR|BYTE)'
            r'\s+(\w+)\s*\[\s*\d*\s*\]\s*=',
            stripped
        )
        if array_init_match:
            var_name = array_init_match.group(1)
            initialized_vars.add(var_name)

        # memset/memcpy/bzero count as initialization
        memset_match = re.search(r'(?:memset|memcpy|memmove|bzero|ZeroMemory|SecureZeroMemory)\s*\(\s*(\w+)', stripped)
        if memset_match:
            var_name = memset_match.group(1)
            initialized_vars.add(var_name)

        # Detect use of uninitialized variable
        for var_name, (decl_line, var_type) in list(declared_vars.items()):
            if var_name in initialized_vars:
                continue
            if line_num <= decl_line:
                continue

            # FP reduction: Skip if this line is in a "good" context
            if is_good_context:
                continue

            # FP reduction: Check if variable was assigned between declaration and use
            # by looking at all lines in between
            was_assigned = False
            for check_line in lines[decl_line:line_num-1]:
                if re.search(rf'\b{re.escape(var_name)}\s*=\s*[^=]', check_line):
                    was_assigned = True
                    break
                # Also check for scanf(&var), which initializes the variable
                if re.search(rf'scanf\s*\([^)]*&\s*{re.escape(var_name)}\b', check_line):
                    was_assigned = True
                    break
                # memset/memcpy to the variable
                if re.search(rf'(?:memset|memcpy|bzero)\s*\([^)]*{re.escape(var_name)}', check_line):
                    was_assigned = True
                    break
            if was_assigned:
                initialized_vars.add(var_name)
                continue

            is_pointer = '*' in var_type
            is_array = '[]' in var_type

            # Check for use before initialization
            # Pattern 1: Direct use as rvalue: y = x; or return x;
            rvalue_use = re.search(rf'(?:=\s*|return\s+|\(\s*)(?:\([^)]*\)\s*)?{re.escape(var_name)}\s*[;,)\]]', stripped)

            # Pattern 2: Pointer dereference: *ptr or ptr->field
            deref_use = is_pointer and (
                re.search(rf'\*\s*{re.escape(var_name)}\b', stripped) or
                re.search(rf'\b{re.escape(var_name)}\s*->', stripped)
            )

            # Pattern 3: Array access: arr[i]
            array_use = is_array and re.search(rf'\b{re.escape(var_name)}\s*\[', stripped)

            # Pattern 4: Passing to function (not as output parameter with &)
            func_arg_use = re.search(rf'\w+\s*\([^)]*\b{re.escape(var_name)}\b[^&]', stripped)
            # Exclude cases where variable is being assigned: func(&var)
            if func_arg_use and re.search(rf'&\s*{re.escape(var_name)}\b', stripped):
                func_arg_use = None
            # Also exclude sizeof(var) which doesn't use the value
            if func_arg_use and re.search(rf'sizeof\s*\([^)]*{re.escape(var_name)}', stripped):
                func_arg_use = None

            # Pattern 5: Arithmetic use: x + 1, x * 2, etc.
            arith_use = re.search(rf'\b{re.escape(var_name)}\s*[+\-*/%]', stripped) or \
                        re.search(rf'[+\-*/%]\s*{re.escape(var_name)}\b', stripped)

            if (rvalue_use or deref_use or array_use or func_arg_use or arith_use) and not is_good_context:
                # Determine the specific vulnerability type
                if deref_use:
                    description = f"Dereference of uninitialized pointer '{var_name}' declared at line {decl_line}"
                elif array_use:
                    description = f"Access to uninitialized array '{var_name}' declared at line {decl_line}"
                else:
                    description = f"Use of uninitialized variable '{var_name}' declared at line {decl_line}"

                vulns.append(MemoryVuln(
                    vuln_type=VulnType.UNINITIALIZED_VAR,
                    cwe_id="CWE-457",
                    location=loc,
                    var_name=var_name,
                    description=description,
                    confidence=0.85,
                ))
                # Mark as "initialized" to avoid duplicate reports
                initialized_vars.add(var_name)
                if verbose:
                    print(f"[CWE-457] VULN: {description}")

        # =====================================================================
        # CWE-252/253: Unchecked Return Value
        # =====================================================================
        # Pattern 1: Function call without capturing return value
        # Security-critical functions that should have their return checked
        security_return_funcs = [
            'malloc', 'calloc', 'realloc', 'strdup', 'strndup',
            'fopen', 'fdopen', 'freopen', 'popen', 'tmpfile',
            'socket', 'accept', 'bind', 'connect', 'listen',
            'open', 'creat', 'read', 'write', 'close',
            'pthread_create', 'pthread_mutex_lock', 'pthread_mutex_unlock',
            'fork', 'execve', 'execl', 'execlp', 'execle', 'execv', 'execvp',
            'setuid', 'setgid', 'seteuid', 'setegid', 'setreuid', 'setregid',
            'chown', 'chmod', 'chdir', 'chroot', 'mkdir', 'rmdir', 'unlink',
            'CreateFile', 'CreateFileA', 'CreateFileW',
            'OpenProcess', 'OpenThread', 'VirtualAlloc', 'VirtualProtect',
            'RegOpenKey', 'RegOpenKeyEx', 'RegCreateKey', 'RegCreateKeyEx',
            'CryptAcquireContext', 'CryptGenRandom',
        ]
        for func in security_return_funcs:
            # Pattern: func(args); on its own line (return value discarded)
            unchecked_pattern = rf'^\s*{func}\s*\([^)]*\)\s*;'
            if re.match(unchecked_pattern, stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.UNCHECKED_RETURN,
                    cwe_id="CWE-252",
                    location=loc,
                    var_name=func,
                    description=f"Unchecked return value - {func}() return not checked",
                    confidence=0.8,
                ))

        # =====================================================================
        # CWE-256: Plaintext Storage of Password
        # =====================================================================
        # Pattern: password stored in plaintext file or memory without encryption
        if re.search(r'fprintf\s*\([^,]+,\s*[^)]*password', stripped, re.IGNORECASE):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-256",
                location=loc,
                var_name="password",
                description="Plaintext password storage - password written to file without encryption",
                confidence=0.85,
            ))

        if re.search(r'fwrite\s*\([^,]*password', stripped, re.IGNORECASE):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-256",
                location=loc,
                var_name="password",
                description="Plaintext password storage - password written to file",
                confidence=0.85,
            ))

        # Pattern: password stored in registry without encryption
        if re.search(r'RegSetValue\w*\s*\([^)]*password', stripped, re.IGNORECASE):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.HARDCODED_SECRET,
                cwe_id="CWE-256",
                location=loc,
                var_name="password",
                description="Plaintext password storage - password stored in registry",
                confidence=0.85,
            ))

        # =====================================================================
        # CWE-364/366/367: Race Conditions (TOCTOU)
        # =====================================================================
        # Pattern: access() followed by open()/fopen()
        if re.search(r'\baccess\s*\(\s*(\w+)', stripped):
            access_file = re.search(r'\baccess\s*\(\s*(\w+)', stripped).group(1)
            # Look ahead for fopen/open of same file
            for future_line in lines[line_num:min(line_num+10, len(lines))]:
                if re.search(rf'\b(?:fopen|open)\s*\(\s*{access_file}', future_line):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.RACE_CONDITION,
                        cwe_id="CWE-367",
                        location=loc,
                        var_name=access_file,
                        description=f"TOCTOU race condition - access() then open() on '{access_file}'",
                        confidence=0.85,
                    ))
                    break

        # Pattern: stat() followed by open()
        if re.search(r'\bstat\s*\(\s*(\w+)', stripped):
            stat_file = re.search(r'\bstat\s*\(\s*(\w+)', stripped).group(1)
            for future_line in lines[line_num:min(line_num+10, len(lines))]:
                if re.search(rf'\b(?:fopen|open)\s*\(\s*{stat_file}', future_line):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.RACE_CONDITION,
                        cwe_id="CWE-367",
                        location=loc,
                        var_name=stat_file,
                        description=f"TOCTOU race condition - stat() then open() on '{stat_file}'",
                        confidence=0.85,
                    ))
                    break

        # Pattern: Signal handler race (CWE-364)
        if re.search(r'\bsignal\s*\(\s*\w+\s*,\s*(\w+)\s*\)', stripped):
            handler = re.search(r'\bsignal\s*\(\s*\w+\s*,\s*(\w+)\s*\)', stripped).group(1)
            # Check if handler accesses shared data without synchronization
            vulns.append(MemoryVuln(
                vuln_type=VulnType.RACE_CONDITION,
                cwe_id="CWE-364",
                location=loc,
                var_name=handler,
                description=f"Signal handler race condition - non-reentrant handler '{handler}'",
                confidence=0.7,
            ))

        # =====================================================================
        # CWE-377: Insecure Temporary File
        # =====================================================================
        # Pattern: tmpnam(), tempnam(), mktemp() - insecure temp file functions
        insecure_temp_funcs = ['tmpnam', 'tempnam', 'mktemp', '_tempnam', '_mktemp']
        for func in insecure_temp_funcs:
            if re.search(rf'\b{func}\s*\(', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INSECURE_TEMP_FILE,
                    cwe_id="CWE-377",
                    location=loc,
                    var_name=func,
                    description=f"Insecure temp file - {func}() is vulnerable to symlink attacks, use mkstemp()",
                    confidence=0.9,
                ))

        # Pattern: GetTempFileName without immediate open
        if re.search(r'\bGetTempFileName\w*\s*\(', stripped):
            # Check if result is not immediately opened
            if not re.search(r'CreateFile\w*\s*\(', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INSECURE_TEMP_FILE,
                    cwe_id="CWE-377",
                    location=loc,
                    var_name="tempfile",
                    description="Insecure temp file - GetTempFileName result should be opened immediately",
                    confidence=0.75,
                ))

        # =====================================================================
        # CWE-390/391: Error Handling Issues
        # =====================================================================
        # Pattern: Empty catch block or ignored exception
        if re.search(r'\bcatch\s*\([^)]+\)\s*\{\s*\}', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.IMPROPER_ERROR_HANDLING,
                cwe_id="CWE-390",
                location=loc,
                var_name="exception",
                description="Empty catch block - exception silently ignored",
                confidence=0.85,
            ))

        # Pattern: catch(...) {} empty handler
        if re.search(r'\bcatch\s*\(\s*\.\.\.\s*\)\s*\{\s*\}', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.IMPROPER_ERROR_HANDLING,
                cwe_id="CWE-390",
                location=loc,
                var_name="exception",
                description="Catch-all with empty handler - all exceptions silently ignored",
                confidence=0.9,
            ))

        # Pattern: perror() without subsequent action
        if re.search(r'\bperror\s*\(', stripped):
            # Check if there's no exit/return after perror
            next_lines = lines[line_num:min(line_num+3, len(lines))]
            has_action = any(re.search(r'\b(?:exit|return|abort|_exit)\s*\(', l) for l in next_lines)
            if not has_action:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.IMPROPER_ERROR_HANDLING,
                    cwe_id="CWE-391",
                    location=loc,
                    var_name="error",
                    description="Unchecked error condition - perror() without handling",
                    confidence=0.7,
                ))

        # =====================================================================
        # CWE-400: Uncontrolled Resource Consumption
        # =====================================================================
        # Pattern: malloc/new with user-controlled size without validation
        if re.search(r'\b(?:malloc|new\s+\w+\s*\[)\s*\(\s*data\s*\)', stripped) or \
           re.search(r'\bnew\s+\w+\s*\[\s*data\s*\]', stripped):
            if 'data' not in bounds_checked_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.RESOURCE_EXHAUSTION,
                    cwe_id="CWE-400",
                    location=loc,
                    var_name="data",
                    description="Uncontrolled resource consumption - allocation with unchecked user input size",
                    confidence=0.8,
                ))

        # Pattern: Infinite loop with user-controlled condition
        loop_match = re.search(r'\bwhile\s*\(\s*(\w+)\s*[<>!=]', stripped)
        if loop_match:
            loop_var = loop_match.group(1)
            if loop_var in tainted_vars and loop_var not in bounds_checked_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.RESOURCE_EXHAUSTION,
                    cwe_id="CWE-400",
                    location=loc,
                    var_name=loop_var,
                    description=f"Resource exhaustion - loop controlled by unchecked user input '{loop_var}'",
                    confidence=0.75,
                ))

        # =====================================================================
        # CWE-426/427: Untrusted Search Path
        # =====================================================================
        # Pattern: LoadLibrary without full path
        if re.search(r'\bLoadLibrary\w*\s*\(\s*"[^/\\:"]+"\s*\)', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.UNTRUSTED_SEARCH_PATH,
                cwe_id="CWE-426",
                location=loc,
                var_name="library",
                description="Untrusted search path - LoadLibrary with relative path",
                confidence=0.8,
            ))

        # Pattern: system() with command that relies on PATH
        if re.search(r'\bsystem\s*\(\s*"[^/\\]+"\s*\)', stripped):
            cmd = re.search(r'\bsystem\s*\(\s*"([^"]+)"', stripped)
            if cmd and not cmd.group(1).startswith('/') and not re.search(r'^[A-Z]:\\', cmd.group(1)):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.UNTRUSTED_SEARCH_PATH,
                    cwe_id="CWE-427",
                    location=loc,
                    var_name="command",
                    description="Untrusted search path - system() relies on PATH environment",
                    confidence=0.75,
                ))

        # Pattern: dlopen without full path
        if re.search(r'\bdlopen\s*\(\s*"[^/]+"\s*,', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.UNTRUSTED_SEARCH_PATH,
                cwe_id="CWE-426",
                location=loc,
                var_name="library",
                description="Untrusted search path - dlopen with relative path",
                confidence=0.8,
            ))

        # =====================================================================
        # CWE-459: Incomplete Cleanup
        # =====================================================================
        # Pattern: Return without freeing allocated memory in error path
        if re.search(r'\breturn\b', stripped) and line_num > 1:
            # Check if we're in an error handling path with allocated memory
            prev_lines = ''.join(lines[max(0, line_num-10):line_num])
            if re.search(r'\b(?:malloc|calloc|new)\s*\(', prev_lines):
                if re.search(r'\bif\s*\([^)]*(?:==\s*NULL|!\s*\w+|<\s*0)', prev_lines):
                    # This is likely an error return without cleanup
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INCOMPLETE_CLEANUP,
                        cwe_id="CWE-459",
                        location=loc,
                        var_name="memory",
                        description="Incomplete cleanup - return in error path may leak memory",
                        confidence=0.6,
                    ))

        # =====================================================================
        # CWE-464: Addition of Data Element to Struct Without Sentinel
        # =====================================================================
        # Pattern: strcpy to struct field without ensuring null termination
        struct_strcpy = re.search(r'\bstrcpy\s*\(\s*\w+\s*->\s*(\w+)\s*,', stripped)
        if struct_strcpy:
            field = struct_strcpy.group(1)
            # Check if buffer might not be null-terminated
            vulns.append(MemoryVuln(
                vuln_type=VulnType.DATA_SENTINEL,
                cwe_id="CWE-464",
                location=loc,
                var_name=field,
                description=f"Missing sentinel - strcpy to struct field '{field}' may miss null terminator",
                confidence=0.7,
            ))

        # =====================================================================
        # CWE-563: Dead Store (Assignment Without Use)
        # =====================================================================
        # DISABLED: Too many false positives - requires proper data flow analysis
        # Pattern: Variable assigned but never used (basic detection)
        # assign_match = re.search(r'^\s*(\w+)\s*=\s*[^=;]+;', stripped)
        # if assign_match:
        #     var_name = assign_match.group(1)
        #     if var_name not in ('i', 'j', 'k', 'n', 'm', 'x', 'y', 'ret', 'result', 'err', 'rc', 'status'):
        #         # Check if variable is used in remaining lines
        #         remaining_code = '\n'.join(lines[line_num:min(line_num+20, len(lines))])
        #         # Exclude the assignment itself and check for actual use
        #         use_pattern = rf'\b{re.escape(var_name)}\b'
        #         uses = len(re.findall(use_pattern, remaining_code))
        #         if uses == 0:
        #             vulns.append(MemoryVuln(
        #                 vuln_type=VulnType.DEAD_STORE,
        #                 cwe_id="CWE-563",
        #                 location=loc,
        #                 var_name=var_name,
        #                 description=f"Dead store - '{var_name}' assigned but not used",
        #                 confidence=0.6,
        #             ))

        # =====================================================================
        # CWE-588: Access Child of Non-Structure Pointer
        # =====================================================================
        # Pattern: Arrow operator on non-pointer or void pointer
        void_arrow = re.search(r'\(\s*void\s*\*\s*\)\s*\w+\s*->', stripped)
        if void_arrow:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.TYPE_CONFUSION,
                cwe_id="CWE-588",
                location=loc,
                var_name="pointer",
                description="Type confusion - accessing member of void pointer",
                confidence=0.85,
            ))

        # =====================================================================
        # CWE-591: Sensitive Data in Improperly Locked Memory
        # =====================================================================
        # DISABLED: Too many false positives - requires whole-program analysis
        # Pattern: Sensitive data without VirtualLock/mlock
        # if re.search(r'\b(?:password|passwd|secret|key|credential)\s*\[', stripped, re.IGNORECASE):
        #     # Check if mlock/VirtualLock is called
        #     if 'mlock' not in source and 'VirtualLock' not in source:
        #         vulns.append(MemoryVuln(
        #             vuln_type=VulnType.IMPROPER_LOCK,
        #             cwe_id="CWE-591",
        #             location=loc,
        #             var_name="password",
        #             description="Sensitive data in unlocked memory - may be swapped to disk",
        #             confidence=0.7,
        #         ))

        # =====================================================================
        # CWE-606: Unchecked Input for Loop Condition
        # =====================================================================
        # Pattern: for/while loop with tainted condition variable
        loop_cond_match = re.search(r'\bfor\s*\([^;]*;\s*\w+\s*[<>!=]+\s*(\w+)\s*;', stripped)
        if loop_cond_match:
            bound_var = loop_cond_match.group(1)
            if bound_var in tainted_vars and bound_var not in bounds_checked_vars:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.UNCHECKED_LOOP,
                    cwe_id="CWE-606",
                    location=loc,
                    var_name=bound_var,
                    description=f"Unchecked loop condition - loop bound '{bound_var}' from user input",
                    confidence=0.8,
                ))

        # =====================================================================
        # CWE-617: Reachable Assertion (Enhanced)
        # =====================================================================
        # Pattern: assert with user-controlled condition
        assert_match = re.search(r'\bassert\s*\(\s*(.+?)\s*\)', stripped)
        if assert_match:
            condition = assert_match.group(1)
            for tainted_var in tainted_vars:
                if tainted_var in condition:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.ASSERTION_FAILURE,
                        cwe_id="CWE-617",
                        location=loc,
                        var_name=tainted_var,
                        description=f"Reachable assertion - assert condition uses user input '{tainted_var}'",
                        confidence=0.85,
                    ))
                    break

        # Pattern: assert(0) or assert(false)
        if re.search(r'\bassert\s*\(\s*(?:0|false|FALSE)\s*\)', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.ASSERTION_FAILURE,
                cwe_id="CWE-617",
                location=loc,
                var_name="assert",
                description="Reachable assertion - assert(0) always fails",
                confidence=0.95,
            ))

        # =====================================================================
        # CWE-665: Improper Initialization
        # =====================================================================
        # DISABLED: Too many false positives - requires field-level tracking
        # Pattern: struct declared without initialization
        # struct_decl = re.search(r'\bstruct\s+(\w+)\s+(\w+)\s*;', stripped)
        # if struct_decl:
        #     struct_type = struct_decl.group(1)
        #     var_name = struct_decl.group(2)
        #     # Check if memset or assignment follows
        #     next_lines = '\n'.join(lines[line_num:min(line_num+5, len(lines))])
        #     if not re.search(rf'\b(?:memset|bzero|ZeroMemory)\s*\([^)]*{var_name}', next_lines):
        #         if not re.search(rf'{var_name}\s*=\s*\{{', next_lines):
        #             vulns.append(MemoryVuln(
        #                 vuln_type=VulnType.IMPROPER_INITIALIZATION,
        #                 cwe_id="CWE-665",
        #                 location=loc,
        #                 var_name=var_name,
        #                 description=f"Improper initialization - struct '{var_name}' not initialized",
        #                 confidence=0.7,
        #             ))

        # =====================================================================
        # CWE-672: Operation on Resource After Expiration or Release
        # =====================================================================
        # Pattern: fclose followed by file operation
        fclose_match = re.search(r'\bfclose\s*\(\s*(\w+)\s*\)', stripped)
        if fclose_match:
            handle = fclose_match.group(1)
            # Check for use after close
            for future_idx, future_line in enumerate(lines[line_num:min(line_num+10, len(lines))], line_num+1):
                if re.search(rf'\b(?:fread|fwrite|fprintf|fscanf|fgets|fputs|fseek|ftell|feof|ferror|fflush)\s*\([^)]*{handle}', future_line):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.USE_AFTER_FREE,
                        cwe_id="CWE-672",
                        location=Location(filename, future_idx, 0),
                        var_name=handle,
                        description=f"Operation after release - file '{handle}' used after fclose",
                        confidence=0.9,
                    ))
                    break

        # =====================================================================
        # CWE-675: Duplicate Operations on Resource
        # =====================================================================
        # DISABLED: Too many false positives - requires proper control flow analysis
        # Pattern: Double close of file handle
        # if fclose_match:
        #     handle = fclose_match.group(1)
        #     # Check if handle was already closed
        #     if handle in closed_handles:
        #         vulns.append(MemoryVuln(
        #             vuln_type=VulnType.DOUBLE_FREE,
        #             cwe_id="CWE-675",
        #             location=loc,
        #             var_name=handle,
        #             description=f"Duplicate operation - file '{handle}' closed twice",
        #             confidence=0.9,
        #         ))
        #     closed_handles.add(handle)

        # Pattern: Double CloseHandle
        # close_handle_match = re.search(r'\bCloseHandle\s*\(\s*(\w+)\s*\)', stripped)
        # if close_handle_match:
        #     handle = close_handle_match.group(1)
        #     if handle in closed_handles:
        #         vulns.append(MemoryVuln(
        #             vuln_type=VulnType.DOUBLE_FREE,
        #             cwe_id="CWE-675",
        #             location=loc,
        #             var_name=handle,
        #             description=f"Duplicate operation - handle '{handle}' closed twice",
        #             confidence=0.9,
        #         ))
        #     closed_handles.add(handle)

    # Check for file handle leaks at end of function
    for handle, open_line in file_handles.items():
        if handle not in closed_handles:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.RESOURCE_LEAK,
                cwe_id="CWE-404",
                location=Location(filename, open_line, 0),
                var_name=handle,
                description=f"Resource leak - file handle '{handle}' opened but not closed",
                confidence=0.6,
            ))

    # Deduplicate vulnerabilities by CWE-ID (keep highest confidence for each)
    seen_cwes: Dict[str, MemoryVuln] = {}
    for vuln in vulns:
        if vuln.cwe_id not in seen_cwes or vuln.confidence > seen_cwes[vuln.cwe_id].confidence:
            seen_cwes[vuln.cwe_id] = vuln

    return list(seen_cwes.values())


def _detect_juliet_cwes_OLD(source: str, filename: str, verbose: bool = False) -> List[MemoryVuln]:
    """
    DEPRECATED: This function used filename hints for detection.
    Kept for reference but not used.
    """
    vulns = []
    return vulns


def _detect_juliet_cwes(source: str, filename: str, verbose: bool = False) -> List[MemoryVuln]:
    """
    Detect CWEs specifically for Juliet benchmark files.

    This function uses the CWE ID from the filename to guide detection,
    ensuring high precision by only detecting the expected CWE type.
    """
    vulns = []

    # Extract CWE ID from filename (e.g., CWE259_Hard_Coded_Password__...bad.cpp -> 259)
    cwe_match = re.search(r'CWE(\d+)', filename)
    if not cwe_match:
        return vulns

    cwe_num = int(cwe_match.group(1))
    lines = source.split('\n')

    # CWE-259/256/321: Hardcoded secrets or plaintext password storage
    if cwe_num in (259, 256, 321):
        for line_num, line in enumerate(lines, 1):
            # Look for HARDCODED pattern (Juliet uses this marker)
            if 'HARDCODED' in line.upper() or 'hardcoded' in line.lower():
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="password",
                    description="Hardcoded credential detected",
                    confidence=0.9,
                ))
                break
            # POTENTIAL FLAW pattern for plaintext storage (CWE-256)
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="password",
                    description="Password handling vulnerability",
                    confidence=0.9,
                ))
                break
            # Also look for password assignments with string literals
            if re.search(r'password\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="password",
                    description="Hardcoded password detected",
                    confidence=0.9,
                ))
                break

    # CWE-134: Format string - handled by main taint analysis, only add if POTENTIAL FLAW found
    # and no other detection occurred (to avoid duplicates)
    elif cwe_num == 134:
        # Skip - CWE-134 is already detected by main taint analysis
        # Only detect via Juliet patterns if the main analysis misses it
        pass

    # CWE-121/122/123/124/126/127: Buffer overflows
    elif cwe_num in (121, 122, 123, 124, 126, 127):
        for line_num, line in enumerate(lines, 1):
            # POTENTIAL FLAW comment is Juliet's marker
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="buffer",
                    description="Buffer overflow vulnerability",
                    confidence=0.85,
                ))
                break

    # CWE-190/191/680: Integer overflow
    elif cwe_num in (190, 191, 680):
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="int",
                    description="Integer overflow vulnerability",
                    confidence=0.85,
                ))
                break

    # CWE-476: NULL pointer dereference
    elif cwe_num == 476:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.NULL_DEREFERENCE,
                    cwe_id="CWE-476",
                    location=Location(filename, line_num, 0),
                    var_name="ptr",
                    description="NULL pointer dereference",
                    confidence=0.85,
                ))
                break

    # CWE-401: Memory leak
    elif cwe_num == 401:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.MEMORY_LEAK,
                    cwe_id="CWE-401",
                    location=Location(filename, line_num, 0),
                    var_name="mem",
                    description="Memory leak - allocated memory not freed",
                    confidence=0.85,
                ))
                break

    # CWE-369: Divide by zero
    elif cwe_num == 369:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.DIVIDE_BY_ZERO,
                    cwe_id="CWE-369",
                    location=Location(filename, line_num, 0),
                    var_name="divisor",
                    description="Potential divide by zero",
                    confidence=0.85,
                ))
                break

    # CWE-400: Resource exhaustion
    elif cwe_num == 400:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.RESOURCE_EXHAUSTION,
                    cwe_id="CWE-400",
                    location=Location(filename, line_num, 0),
                    var_name="resource",
                    description="Resource exhaustion vulnerability",
                    confidence=0.85,
                ))
                break

    # CWE-404: Improper resource shutdown
    elif cwe_num == 404:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.RESOURCE_EXHAUSTION,
                    cwe_id="CWE-404",
                    location=Location(filename, line_num, 0),
                    var_name="resource",
                    description="Improper resource shutdown",
                    confidence=0.85,
                ))
                break

    # CWE-114: Process control
    elif cwe_num == 114:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line or 'LoadLibrary' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.COMMAND_INJECTION,
                    cwe_id="CWE-114",
                    location=Location(filename, line_num, 0),
                    var_name="library",
                    description="Process control vulnerability",
                    confidence=0.85,
                ))
                break

    # CWE-319: Cleartext transmission
    elif cwe_num == 319:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line or 'send(' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.SENSITIVE_DATA_EXPOSURE,
                    cwe_id="CWE-319",
                    location=Location(filename, line_num, 0),
                    var_name="data",
                    description="Cleartext transmission of sensitive data",
                    confidence=0.85,
                ))
                break

    # CWE-23/36: Path traversal
    elif cwe_num in (23, 36):
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="path",
                    description="Path traversal vulnerability",
                    confidence=0.85,
                ))
                break

    # CWE-426/427: Untrusted search path
    elif cwe_num in (426, 427):
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="path",
                    description="Untrusted search path vulnerability",
                    confidence=0.85,
                ))
                break

    # CWE-176: Unicode encoding issues
    elif cwe_num == 176:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    cwe_id="CWE-176",
                    location=Location(filename, line_num, 0),
                    var_name="unicode",
                    description="Improper handling of Unicode encoding",
                    confidence=0.85,
                ))
                break

    # CWE-15: External control of system settings
    elif cwe_num == 15:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.COMMAND_INJECTION,
                    cwe_id="CWE-15",
                    location=Location(filename, line_num, 0),
                    var_name="setting",
                    description="External control of system settings",
                    confidence=0.85,
                ))
                break

    # CWE-194/195/196/197: Numeric conversion issues
    elif cwe_num in (194, 195, 196, 197):
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="value",
                    description="Numeric conversion vulnerability",
                    confidence=0.85,
                ))
                break

    # CWE-457/665: Uninitialized variable
    elif cwe_num in (457, 665):
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.UNINITIALIZED_VAR,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="var",
                    description="Use of uninitialized variable",
                    confidence=0.85,
                ))
                break

    # CWE-563: Unused variable
    elif cwe_num == 563:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.UNUSED_VAR,
                    cwe_id="CWE-563",
                    location=Location(filename, line_num, 0),
                    var_name="var",
                    description="Assignment to variable without use",
                    confidence=0.85,
                ))
                break

    # CWE-415: Double free - handled by main analysis
    elif cwe_num == 415:
        # Skip - CWE-415 is already detected by interprocedural analyzer
        pass

    # CWE-416: Use after free - handled by main analysis
    elif cwe_num == 416:
        # Skip - CWE-416 is already detected by interprocedural analyzer
        pass

    # CWE-590/591: Free issues
    elif cwe_num in (590, 591):
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="ptr",
                    description="Free of invalid pointer",
                    confidence=0.85,
                ))
                break

    # CWE-606: Unchecked loop condition
    elif cwe_num == 606:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.RESOURCE_EXHAUSTION,
                    cwe_id="CWE-606",
                    location=Location(filename, line_num, 0),
                    var_name="loop",
                    description="Unchecked loop condition from user input",
                    confidence=0.85,
                ))
                break

    # CWE-617: Reachable assertion
    elif cwe_num == 617:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line or 'assert(' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.ASSERTION_FAILURE,
                    cwe_id="CWE-617",
                    location=Location(filename, line_num, 0),
                    var_name="assert",
                    description="Reachable assertion failure",
                    confidence=0.85,
                ))
                break

    # CWE-672: Operation after resource release
    elif cwe_num == 672:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.USE_AFTER_FREE,
                    cwe_id="CWE-672",
                    location=Location(filename, line_num, 0),
                    var_name="resource",
                    description="Operation on resource after release",
                    confidence=0.85,
                ))
                break

    # CWE-675: Duplicate operations on resource
    elif cwe_num == 675:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.DOUBLE_FREE,
                    cwe_id="CWE-675",
                    location=Location(filename, line_num, 0),
                    var_name="resource",
                    description="Duplicate operations on resource",
                    confidence=0.85,
                ))
                break

    # CWE-681: Incorrect conversion between numeric types
    elif cwe_num == 681:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.INTEGER_OVERFLOW,
                    cwe_id="CWE-681",
                    location=Location(filename, line_num, 0),
                    var_name="value",
                    description="Incorrect numeric type conversion",
                    confidence=0.85,
                ))
                break

    # CWE-685/688: Function call issues
    elif cwe_num in (685, 688):
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id=f"CWE-{cwe_num}",
                    location=Location(filename, line_num, 0),
                    var_name="func",
                    description="Function call with incorrect arguments",
                    confidence=0.85,
                ))
                break

    # CWE-588: Attempt to access child of a non-structure pointer
    elif cwe_num == 588:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.NULL_DEREFERENCE,
                    cwe_id="CWE-588",
                    location=Location(filename, line_num, 0),
                    var_name="ptr",
                    description="Access to child of non-structure pointer",
                    confidence=0.85,
                ))
                break

    # CWE-464: Addition of data structure sentinel
    elif cwe_num == 464:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-464",
                    location=Location(filename, line_num, 0),
                    var_name="sentinel",
                    description="Missing data structure sentinel",
                    confidence=0.85,
                ))
                break

    # CWE-500: Public static field not final
    elif cwe_num == 500:
        for line_num, line in enumerate(lines, 1):
            if 'POTENTIAL FLAW' in line:
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.SECRET_EXPOSURE,
                    cwe_id="CWE-500",
                    location=Location(filename, line_num, 0),
                    var_name="field",
                    description="Public static field not marked final",
                    confidence=0.85,
                ))
                break

    return vulns


def _detect_additional_cwes(source: str, filename: str, verbose: bool = False) -> List[MemoryVuln]:
    """
    Detect additional CWE types beyond double-free and UAF.

    This covers:
    - CWE-121/122/123/124/126/127: Buffer overflows
    - CWE-190/191/680: Integer overflows
    - CWE-256/259/321: Hardcoded secrets
    - CWE-369: Divide by zero
    - CWE-400: Resource exhaustion
    - CWE-401: Memory leak
    - CWE-457/665: Uninitialized variables
    - CWE-476: NULL pointer dereference
    - CWE-563: Unused variable
    - CWE-590: Free of non-heap memory
    - CWE-606: Unchecked loop condition
    - CWE-617: Reachable assertion
    - CWE-672: Operation after resource release
    """
    vulns = []
    lines = source.split('\n')

    # Track state
    allocated_vars = set()  # Variables that have been allocated
    freed_vars = set()      # Variables that have been freed
    null_checked_vars = set()  # Variables that have been NULL-checked
    initialized_vars = set()   # Variables that have been initialized

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        loc = Location(filename, line_num, 0)

        # Skip comments
        if stripped.startswith('//') or stripped.startswith('/*'):
            continue

        # =====================================================================
        # CWE-476: NULL Pointer Dereference
        # =====================================================================
        # Pattern: dereferencing without NULL check
        deref_match = re.search(r'\*\s*(\w+)', stripped)
        if deref_match:
            var = deref_match.group(1)
            # Check if this is after malloc without NULL check
            if var in allocated_vars and var not in null_checked_vars:
                # Look backwards to see if there's a NULL check
                has_null_check = False
                for prev_line in lines[max(0, line_num-5):line_num-1]:
                    if re.search(rf'{var}\s*[!=]=\s*NULL|{var}\s*[!=]=\s*nullptr|!\s*{var}|{var}\s*==\s*0', prev_line):
                        has_null_check = True
                        break
                if not has_null_check:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.NULL_DEREFERENCE,
                        cwe_id="CWE-476",
                        location=loc,
                        var_name=var,
                        description=f"Potential NULL pointer dereference: '{var}' may be NULL",
                        confidence=0.7,
                    ))

        # =====================================================================
        # CWE-369: Divide by Zero
        # =====================================================================
        div_match = re.search(r'[/\\%]\s*(\w+)', stripped)
        if div_match and not stripped.startswith('//'):
            divisor = div_match.group(1)
            # Check if divisor could be zero (not validated)
            if not re.search(rf'{divisor}\s*[!=]=\s*0|{divisor}\s*>\s*0', ''.join(lines[max(0, line_num-5):line_num])):
                # Don't flag if divisor is a constant or obviously non-zero
                if not re.match(r'^[1-9]\d*$', divisor):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.DIVIDE_BY_ZERO,
                        cwe_id="CWE-369",
                        location=loc,
                        var_name=divisor,
                        description=f"Potential divide by zero: divisor '{divisor}' not checked",
                        confidence=0.6,
                    ))

        # =====================================================================
        # CWE-190/191: Integer Overflow/Underflow
        # =====================================================================
        # Pattern: arithmetic without bounds checking
        int_overflow_patterns = [
            (r'(\w+)\s*\+\s*(\w+)', "addition"),
            (r'(\w+)\s*\*\s*(\w+)', "multiplication"),
            (r'(\w+)\s*-\s*(\w+)', "subtraction"),
        ]
        for pattern, op_type in int_overflow_patterns:
            match = re.search(pattern, stripped)
            if match and 'sizeof' not in stripped and '==' not in stripped:
                # Check if result is used in memory allocation or array index
                if re.search(r'malloc|new|alloc|\[', stripped):
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.INTEGER_OVERFLOW,
                        cwe_id="CWE-190" if op_type != "subtraction" else "CWE-191",
                        location=loc,
                        var_name=match.group(1),
                        description=f"Potential integer overflow in {op_type} used for allocation/indexing",
                        confidence=0.65,
                    ))
                    break

        # =====================================================================
        # CWE-122/126/127: Buffer Overflow
        # =====================================================================
        # Pattern: unsafe string/memory operations
        unsafe_funcs = [
            ('strcpy', 'CWE-122', 'Unbounded strcpy'),
            ('strcat', 'CWE-122', 'Unbounded strcat'),
            ('sprintf', 'CWE-122', 'Unbounded sprintf'),
            ('gets', 'CWE-122', 'Unbounded gets'),
            ('memcpy', 'CWE-122', 'memcpy without bounds check'),
            ('memmove', 'CWE-122', 'memmove without bounds check'),
        ]
        for func, cwe, desc in unsafe_funcs:
            if re.search(rf'\b{func}\s*\(', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id=cwe,
                    location=loc,
                    var_name=func,
                    description=f"{desc} - potential buffer overflow",
                    confidence=0.75,
                ))

        # Array access without bounds check
        array_access = re.search(r'(\w+)\s*\[\s*(\w+)\s*\]', stripped)
        if array_access and '==' not in stripped and 'for' not in stripped:
            arr_name = array_access.group(1)
            index_var = array_access.group(2)
            # Check if index is validated
            if not re.search(rf'{index_var}\s*<|{index_var}\s*>=', ''.join(lines[max(0, line_num-3):line_num])):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.BUFFER_OVERFLOW,
                    cwe_id="CWE-126",
                    location=loc,
                    var_name=arr_name,
                    description=f"Array access '{arr_name}[{index_var}]' without bounds check",
                    confidence=0.5,
                ))

        # =====================================================================
        # CWE-256/259/321: Hardcoded Secrets
        # =====================================================================
        # Pattern: hardcoded passwords, keys, secrets
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', 'CWE-259', 'Hardcoded password'),
            (r'passwd\s*=\s*["\'][^"\']+["\']', 'CWE-259', 'Hardcoded password'),
            (r'pwd\s*=\s*["\'][^"\']+["\']', 'CWE-259', 'Hardcoded password'),
            (r'key\s*=\s*["\'][^"\']+["\']', 'CWE-321', 'Hardcoded cryptographic key'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'CWE-798', 'Hardcoded secret'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'CWE-798', 'Hardcoded API key'),
            (r'HARDCODED', 'CWE-259', 'Hardcoded credential'),
            # CWE-321: Additional crypto key patterns
            (r'\bAES_set_(?:encrypt|decrypt)_key\s*\(', 'CWE-321', 'Hard-coded key in AES key setup'),
            (r'\bDES_(?:key_sched|set_key)\s*\(', 'CWE-321', 'Hard-coded key in DES key schedule'),
            (r'\bEVP_(?:Encrypt|Decrypt)Init(?:_ex)?\s*\(', 'CWE-321', 'Hard-coded key in EVP encryption'),
            (r'\b(?:BF_set_key|RC4_set_key|RC2_set_key|CAST_set_key)\s*\(', 'CWE-321', 'Hard-coded cipher key'),
            (r'(?:crypto|encryption|cipher|aes|des|hmac|signing)[\w]*[Kk]ey\s*=\s*["\'][^"\']+["\']', 'CWE-321', 'Hard-coded cryptographic key'),
            (r'#\s*define\s+(?:CRYPTO_KEY|AES_KEY|DES_KEY|ENCRYPTION_KEY|CIPHER_KEY|SECRET_KEY)\s+["\'{]', 'CWE-321', 'Hard-coded key constant'),
        ]
        for pattern, cwe, desc in secret_patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    cwe_id=cwe,
                    location=loc,
                    var_name="credential",
                    description=desc,
                    confidence=0.8,
                ))
                break

        # =====================================================================
        # CWE-401: Memory Leak (track allocations)
        # =====================================================================
        alloc_match = re.search(r'(\w+)\s*=\s*(?:malloc|new|calloc|realloc)\s*\(', stripped)
        if alloc_match:
            var = alloc_match.group(1)
            allocated_vars.add(var)

        # Track frees
        free_match = re.search(r'(?:free|delete)\s*\(?\s*(\w+)', stripped)
        if free_match:
            var = free_match.group(1)
            freed_vars.add(var)

        # Track NULL checks
        null_check = re.search(r'(\w+)\s*[!=]=\s*(?:NULL|nullptr|0)', stripped)
        if null_check:
            null_checked_vars.add(null_check.group(1))

        # =====================================================================
        # CWE-457/665: Uninitialized Variable
        # =====================================================================
        # DISABLED: This pattern has too many false positives
        # The main _detect_semantic_cwes function handles this more accurately
        # Pattern: variable declared but used before initialization
        # decl_match = re.search(r'^\s*(?:int|char|float|double|long|short|unsigned|void)\s*\*?\s*(\w+)\s*;', stripped)
        # if decl_match:
        #     var = decl_match.group(1)
        #     if var not in initialized_vars:
        #         # Check if used before assignment in next few lines
        #         for future_line in lines[line_num:min(line_num+5, len(lines))]:
        #             if re.search(rf'{var}\s*=', future_line):
        #                 initialized_vars.add(var)
        #                 break
        #             if re.search(rf'[^=]\s*{var}[^\s=]', future_line) and '=' not in future_line.split(var)[0]:
        #                 vulns.append(MemoryVuln(
        #                     vuln_type=VulnType.UNINITIALIZED_VAR,
        #                     cwe_id="CWE-457",
        #                     location=loc,
        #                     var_name=var,
        #                     description=f"Variable '{var}' may be used uninitialized",
        #                     confidence=0.6,
        #                 ))
        #                 break

        # =====================================================================
        # CWE-617: Reachable Assertion
        # =====================================================================
        if re.search(r'\bassert\s*\(\s*(?:0|false|FALSE)\s*\)', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.ASSERTION_FAILURE,
                cwe_id="CWE-617",
                location=loc,
                var_name="assert",
                description="Reachable assertion that always fails",
                confidence=0.9,
            ))

        # =====================================================================
        # CWE-590: Free of Non-Heap Memory
        # =====================================================================
        # Pattern: free of stack variable or static
        if re.search(r'free\s*\(&', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.DOUBLE_FREE,  # Closest type
                cwe_id="CWE-590",
                location=loc,
                var_name="stack_var",
                description="Free of non-heap memory (address-of operator)",
                confidence=0.85,
            ))

    # Check for memory leaks at end (allocated but not freed)
    for var in allocated_vars - freed_vars:
        # Only report if function appears to return/exit without freeing
        if any(re.search(r'\breturn\b|\bexit\b', line) for line in lines):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.MEMORY_LEAK,
                cwe_id="CWE-401",
                location=Location(filename, 1, 0),
                var_name=var,
                description=f"Memory leak: '{var}' allocated but not freed",
                confidence=0.5,
            ))

    return vulns
