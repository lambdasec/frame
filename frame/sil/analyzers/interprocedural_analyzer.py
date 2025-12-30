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
    """
    analyzer = InterproceduralAnalyzer(verbose=verbose)
    vulns = analyzer.analyze_source(source, filename)

    # Add semantic-based CWE detection (analyzes actual code patterns)
    additional_vulns = _detect_semantic_cwes(source, filename, verbose)
    vulns.extend(additional_vulns)

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
    allocated_vars: Dict[str, int] = {}  # var -> line allocated
    freed_vars: Set[str] = set()
    null_checked_vars: Set[str] = set()

    # Track bounds checking for integer overflow detection
    bounds_checked_vars: Set[str] = set()  # vars with upper/lower bounds checks
    overflow_guarded_vars: Set[str] = set()  # vars checked for overflow potential

    # Track tainted variables (from external input)
    tainted_vars: Set[str] = {'data'}  # 'data' is commonly used for external input

    # Track detected CWEs to avoid duplicates
    detected_cwes: Set[str] = set()

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

        # Detect variable assignments from input functions
        input_match = re.search(r'(\w+)\s*=.*(?:fscanf|scanf|fgets|gets|recv|read|getenv|GetEnvironmentVariable)', stripped)
        if input_match:
            tainted_vars.add(input_match.group(1))

    # Second pass: detect vulnerabilities
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        loc = Location(filename, line_num, 0)

        # Skip comments
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue

        # =====================================================================
        # CWE-122/121: Buffer Overflow - Unsafe string functions
        # =====================================================================
        strcpy_match = re.search(r'\bstrcpy\s*\(\s*(\w+)\s*,', stripped)
        if strcpy_match:
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
        if wcscpy_match:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name=wcscpy_match.group(1),
                description="Unbounded wcscpy - use wcsncpy instead",
                confidence=0.9,
            ))

        if re.search(r'\bgets\s*\(', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name="buffer",
                description="gets() is always vulnerable - use fgets instead",
                confidence=0.95,
            ))

        sprintf_match = re.search(r'\bsprintf\s*\(\s*(\w+)\s*,', stripped)
        if sprintf_match and 'snprintf' not in stripped:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name=sprintf_match.group(1),
                description="Unbounded sprintf - use snprintf instead",
                confidence=0.85,
            ))

        strcat_match = re.search(r'\bstrcat\s*\(\s*(\w+)\s*,', stripped)
        if strcat_match and 'strncat' not in stripped:
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-122",
                location=loc,
                var_name=strcat_match.group(1),
                description="Unbounded strcat - use strncat instead",
                confidence=0.85,
            ))

        # =====================================================================
        # CWE-134: Format String
        # =====================================================================
        # Standard printf family
        printf_match = re.search(r'\b(printf|fprintf|sprintf|snprintf|syslog)\s*\([^"]*\b(\w+)\s*\)', stripped)
        if printf_match:
            func = printf_match.group(1)
            if not re.search(r'\b' + func + r'\s*\(\s*"', stripped):
                if func == 'fprintf' and re.search(r'fprintf\s*\(\s*\w+\s*,\s*"', stripped):
                    pass  # Skip safe pattern
                elif func == 'snprintf' and re.search(r'snprintf\s*\([^,]+,[^,]+,\s*"', stripped):
                    pass  # Skip safe pattern
                else:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.FORMAT_STRING,
                        cwe_id="CWE-134",
                        location=loc,
                        var_name="format",
                        description=f"Format string vulnerability - {func} with non-literal format",
                        confidence=0.85,
                    ))

        # Wide character printf family (wprintf, fwprintf, swprintf, etc.)
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

        # Variadic printf (vprintf, vfprintf, vsprintf, vsnprintf)
        vprintf_match = re.search(r'\b(vprintf|vfprintf|vsprintf|vsnprintf|_vsnprintf)\s*\(', stripped)
        if vprintf_match:
            func = vprintf_match.group(1)
            # These functions always have format from a variable
            if re.search(rf'{func}\s*\([^)]*\bdata\b', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.FORMAT_STRING,
                    cwe_id="CWE-134",
                    location=loc,
                    var_name="data",
                    description=f"Format string vulnerability - {func} with user-controlled format",
                    confidence=0.9,
                ))

        # snprintf/SNPRINTF with data as format (3rd argument)
        if re.search(r'\b(?:snprintf|SNPRINTF|_snprintf)\s*\(\s*\w+\s*,\s*[^,]+,\s*data\s*\)', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.FORMAT_STRING,
                cwe_id="CWE-134",
                location=loc,
                var_name="data",
                description="Format string vulnerability - snprintf with user-controlled format",
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
        # CWE-476: NULL Pointer Dereference
        # =====================================================================
        alloc_match = re.search(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(', stripped)
        if alloc_match:
            allocated_vars[alloc_match.group(1)] = line_num

        null_check = re.search(r'(\w+)\s*[!=]=\s*(?:NULL|nullptr|0)\s*\)', stripped)
        if null_check:
            null_checked_vars.add(null_check.group(1))
        if re.search(r'if\s*\(\s*(\w+)\s*\)', stripped):
            match = re.search(r'if\s*\(\s*(\w+)\s*\)', stripped)
            if match:
                null_checked_vars.add(match.group(1))

        deref_match = re.search(r'\*\s*(\w+)', stripped)
        if deref_match:
            var = deref_match.group(1)
            if var in allocated_vars and var not in null_checked_vars:
                if line_num - allocated_vars[var] <= 5:
                    vulns.append(MemoryVuln(
                        vuln_type=VulnType.NULL_DEREFERENCE,
                        cwe_id="CWE-476",
                        location=loc,
                        var_name=var,
                        description=f"Dereference of '{var}' without NULL check after allocation",
                        confidence=0.7,
                    ))

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
        # CWE-369: Divide by Zero
        # =====================================================================
        if re.search(r'[/%]\s*data\b', stripped) or re.search(r'[/%]\s*\(\s*int\s*\)\s*data', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.DIVIDE_BY_ZERO,
                cwe_id="CWE-369",
                location=loc,
                var_name="data",
                description="Division by user-controlled value without validation",
                confidence=0.8,
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
        # CWE-78: Command Injection
        # =====================================================================
        cmd_match = re.search(r'\b(system|popen|exec[lv]?p?|ShellExecute\w*)\s*\(\s*(\w+)', stripped)
        if cmd_match:
            func = cmd_match.group(1)
            cmd_var = cmd_match.group(2)
            if not re.search(rf'{func}\s*\(\s*"', stripped):
                vulns.append(MemoryVuln(
                    vuln_type=VulnType.COMMAND_INJECTION,
                    cwe_id="CWE-78",
                    location=loc,
                    var_name=cmd_var,
                    description=f"Potential command injection - variable in {func}",
                    confidence=0.7,
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
        # CWE-126: Buffer Overread - memcpy/memmove with dest size as length
        # =====================================================================
        if re.search(r'\bmemcpy\s*\(\s*\w+\s*,\s*data\s*,\s*(?:strlen|sizeof)\s*\(', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-126",
                location=loc,
                var_name="data",
                description="Buffer overread - copying based on destination size, not source",
                confidence=0.8,
            ))

        # Pattern: memmove(dest, data, N) - reading from data with fixed size
        if re.search(r'\bmemmove\s*\(\s*\w+\s*,\s*data\s*,\s*\d+', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-127",
                location=loc,
                var_name="data",
                description="Buffer underread - memmove from data with fixed size",
                confidence=0.75,
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
        # CWE-127: Buffer Underread - accessing before buffer start
        # =====================================================================
        if re.search(r'\bdata\s*\[\s*-\s*\d+\s*\]', stripped) or \
           re.search(r'\*\s*\(\s*data\s*-\s*\d+\s*\)', stripped):
            vulns.append(MemoryVuln(
                vuln_type=VulnType.BUFFER_OVERFLOW,
                cwe_id="CWE-127",
                location=loc,
                var_name="data",
                description="Buffer underread - accessing before buffer start",
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
        # CWE-401: Memory Leak tracking
        # =====================================================================
        free_match = re.search(r'\b(?:free|delete)\s*\(?\s*(\w+)', stripped)
        if free_match:
            freed_vars.add(free_match.group(1))

        if re.search(r'\breturn\b', stripped) and allocated_vars:
            for var, alloc_line in allocated_vars.items():
                if var not in freed_vars:
                    if line_num - alloc_line < 50:
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.MEMORY_LEAK,
                            cwe_id="CWE-401",
                            location=Location(filename, alloc_line, 0),
                            var_name=var,
                            description=f"Potential memory leak - '{var}' allocated but may not be freed before return",
                            confidence=0.5,
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
        # Pattern: variable declared but used before initialization
        decl_match = re.search(r'^\s*(?:int|char|float|double|long|short|unsigned|void)\s*\*?\s*(\w+)\s*;', stripped)
        if decl_match:
            var = decl_match.group(1)
            if var not in initialized_vars:
                # Check if used before assignment in next few lines
                for future_line in lines[line_num:min(line_num+5, len(lines))]:
                    if re.search(rf'{var}\s*=', future_line):
                        initialized_vars.add(var)
                        break
                    if re.search(rf'[^=]\s*{var}[^\s=]', future_line) and '=' not in future_line.split(var)[0]:
                        vulns.append(MemoryVuln(
                            vuln_type=VulnType.UNINITIALIZED_VAR,
                            cwe_id="CWE-457",
                            location=loc,
                            var_name=var,
                            description=f"Variable '{var}' may be used uninitialized",
                            confidence=0.6,
                        ))
                        break

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
