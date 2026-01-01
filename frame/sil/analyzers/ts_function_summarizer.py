"""
Tree-Sitter Based Function Summarizer for C/C++.

This module provides accurate function summary extraction using tree-sitter AST
parsing, replacing the regex-based approach in the legacy interprocedural analyzer.

Key features:
1. Proper C/C++ AST parsing via tree-sitter
2. Handles complex C++ constructs (namespaces, templates, lambdas)
3. Tracks parameter and member effects through function bodies
4. Builds complete function summaries for inter-procedural analysis
"""

from typing import Dict, List, Optional, Set, Any, Tuple
import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser

from frame.sil.types import Location
from frame.sil.analyzers.function_summary import (
    FunctionSummary, ClassSummary, ParameterInfo, ParameterEffect,
    MemberEffect, ReturnSource, HeapEffect
)


class TreeSitterFunctionSummarizer:
    """
    Build function summaries using tree-sitter AST parsing.

    This replaces the regex-based approach in InterproceduralAnalyzer
    with proper AST traversal for accurate C/C++ analysis.
    """

    # Known allocation functions
    ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'strdup', 'strndup',
                   'aligned_alloc', 'valloc', 'pvalloc', 'memalign'}
    FREE_FUNCS = {'free', 'cfree'}

    # C++ operators
    CPP_NEW_OPS = {'new', 'new[]'}
    CPP_DELETE_OPS = {'delete', 'delete[]'}

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

        # Parsers
        self.c_parser = Parser(Language(tsc.language()))
        self.cpp_parser = Parser(Language(tscpp.language()))

        # Analysis state (reset per file)
        self._source: str = ""
        self._filename: str = ""
        self._lines: List[str] = []

        # Results
        self.function_summaries: Dict[str, FunctionSummary] = {}
        self.class_summaries: Dict[str, ClassSummary] = {}

        # Current context during traversal
        self._current_namespace: Optional[str] = None
        self._current_class: Optional[str] = None
        self._current_function: Optional[FunctionSummary] = None
        self._local_vars: Set[str] = set()
        self._class_members: Dict[str, str] = {}  # member -> type
        self._param_names: Dict[str, int] = {}    # param_name -> index

    def _get_parser(self, filename: str) -> Parser:
        """Get appropriate parser based on file extension."""
        cpp_exts = ('.cpp', '.cc', '.cxx', '.hpp', '.hxx', '.h++', '.C')
        if any(filename.endswith(ext) for ext in cpp_exts):
            return self.cpp_parser
        return self.c_parser

    def _get_text(self, node: Any) -> str:
        """Get text content of a node."""
        if node is None:
            return ""
        return node.text.decode('utf8')

    def _get_location(self, node: Any) -> Location:
        """Get source location from node."""
        line = node.start_point[0] + 1  # 1-indexed
        col = node.start_point[1] + 1
        return Location(file=self._filename, line=line, column=col)

    def analyze_source(self, source: str, filename: str) -> Dict[str, FunctionSummary]:
        """
        Analyze source code and build function summaries.

        Args:
            source: C/C++ source code
            filename: Filename for location tracking

        Returns:
            Dict mapping qualified function names to their summaries
        """
        self._source = source
        self._filename = filename
        self._lines = source.split('\n')
        self.function_summaries = {}
        self.class_summaries = {}

        parser = self._get_parser(filename)
        tree = parser.parse(bytes(source, 'utf8'))

        if self.verbose:
            print(f"[TS] Analyzing {filename}")

        # First pass: collect class definitions and member info
        self._collect_class_definitions(tree.root_node)

        # Second pass: analyze all functions
        self._analyze_node(tree.root_node)

        if self.verbose:
            print(f"[TS] Found {len(self.function_summaries)} functions, "
                  f"{len(self.class_summaries)} classes")

        return self.function_summaries

    # =========================================================================
    # Pass 1: Collect class definitions
    # =========================================================================

    def _collect_class_definitions(self, node: Any):
        """First pass: collect class/struct member information."""
        if node.type in ('class_specifier', 'struct_specifier'):
            self._process_class_definition(node)
        elif node.type == 'namespace_definition':
            old_ns = self._current_namespace
            name_node = node.child_by_field_name('name')
            ns_name = self._get_text(name_node) if name_node else ""
            self._current_namespace = f"{old_ns}::{ns_name}" if old_ns else ns_name

            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    self._collect_class_definitions(child)

            self._current_namespace = old_ns
        else:
            for child in node.children:
                self._collect_class_definitions(child)

    def _process_class_definition(self, node: Any):
        """Extract class name and member variables."""
        name_node = node.child_by_field_name('name')
        class_name = self._get_text(name_node) if name_node else None
        if not class_name:
            return

        qualified_name = f"{self._current_namespace}::{class_name}" \
            if self._current_namespace else class_name

        summary = ClassSummary(
            name=class_name,
            qualified_name=qualified_name,
            namespace=self._current_namespace
        )

        # Extract base classes
        for child in node.children:
            if child.type == 'base_class_clause':
                self._extract_base_classes(child, summary)

        # Extract members from body
        body = node.child_by_field_name('body')
        if body:
            for child in body.children:
                if child.type == 'field_declaration':
                    self._extract_member_from_field_decl(child, summary)

        self.class_summaries[qualified_name] = summary
        # Also store by simple name for lookup
        self.class_summaries[class_name] = summary

    def _extract_base_classes(self, clause: Any, summary: ClassSummary):
        """Extract base class names from base_class_clause."""
        for child in clause.children:
            if child.type == 'type_identifier':
                summary.base_classes.append(self._get_text(child))
            elif child.type == 'qualified_identifier':
                summary.base_classes.append(self._get_text(child))

    def _extract_member_from_field_decl(self, decl: Any, summary: ClassSummary):
        """Extract member variable from field_declaration."""
        type_node = decl.child_by_field_name('type')
        type_str = self._get_text(type_node) if type_node else "unknown"

        declarator = decl.child_by_field_name('declarator')
        if declarator:
            member_name = self._extract_var_name_from_declarator(declarator)
            if member_name:
                summary.members[member_name] = type_str
                # Check if it's a pointer
                if '*' in type_str or declarator.type == 'pointer_declarator':
                    summary.pointer_members.add(member_name)
                    summary.has_raw_pointer_members = True

    def _extract_var_name_from_declarator(self, declarator: Any) -> Optional[str]:
        """Extract variable name from a declarator node."""
        if declarator.type == 'identifier':
            return self._get_text(declarator)
        elif declarator.type == 'pointer_declarator':
            inner = declarator.child_by_field_name('declarator')
            if inner:
                return self._extract_var_name_from_declarator(inner)
        elif declarator.type == 'array_declarator':
            inner = declarator.child_by_field_name('declarator')
            if inner:
                return self._extract_var_name_from_declarator(inner)
        elif declarator.type == 'reference_declarator':
            inner = declarator.child_by_field_name('declarator') or \
                    next((c for c in declarator.children if c.type == 'identifier'), None)
            if inner:
                return self._extract_var_name_from_declarator(inner)

        # Fallback: find any identifier child
        for child in declarator.children:
            if child.type == 'identifier':
                return self._get_text(child)
        return None

    # =========================================================================
    # Pass 2: Analyze functions
    # =========================================================================

    def _analyze_node(self, node: Any):
        """Main recursive analysis entry point."""
        if node.type == 'function_definition':
            self._analyze_function(node)
        elif node.type in ('class_specifier', 'struct_specifier'):
            old_class = self._current_class
            name_node = node.child_by_field_name('name')
            self._current_class = self._get_text(name_node) if name_node else None

            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    self._analyze_node(child)

            self._current_class = old_class
        elif node.type == 'namespace_definition':
            old_ns = self._current_namespace
            name_node = node.child_by_field_name('name')
            ns_name = self._get_text(name_node) if name_node else ""
            self._current_namespace = f"{old_ns}::{ns_name}" if old_ns else ns_name

            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    self._analyze_node(child)

            self._current_namespace = old_ns
        elif node.type == 'template_declaration':
            # Handle template functions/classes
            for child in node.children:
                if child.type in ('function_definition', 'class_specifier'):
                    self._analyze_node(child)
        else:
            for child in node.children:
                self._analyze_node(child)

    def _analyze_function(self, node: Any):
        """Analyze a function definition and build summary."""
        declarator = node.child_by_field_name('declarator')
        if not declarator:
            return

        # Extract function info
        func_info = self._extract_function_info(declarator)
        if not func_info:
            return

        name, class_name, is_ctor, is_dtor = func_info

        # Determine class context
        if class_name:
            pass  # Already have class name from qualified identifier
        elif self._current_class:
            class_name = self._current_class

        # Build qualified name
        parts = []
        if self._current_namespace:
            parts.append(self._current_namespace)
        if class_name:
            parts.append(class_name)
        parts.append(name)
        qualified_name = '::'.join(parts)

        # Extract return type
        return_type = self._extract_return_type(node)

        # Extract parameters
        parameters = self._extract_parameters(declarator)

        # Create summary
        summary = FunctionSummary(
            name=name,
            qualified_name=qualified_name,
            class_name=class_name,
            namespace=self._current_namespace,
            is_constructor=is_ctor,
            is_destructor=is_dtor,
            return_type=return_type,
            parameters=parameters
        )

        # Set context for body analysis
        self._current_function = summary
        self._local_vars = {p.name for p in parameters}
        self._param_names = {p.name: p.index for p in parameters}

        # Initialize param effects
        for p in parameters:
            summary.param_effects[p.index] = ParameterEffect(
                param_index=p.index,
                param_name=p.name
            )

        # Get class members if this is a method
        if class_name:
            cls = self.class_summaries.get(class_name) or \
                  self.class_summaries.get(f"{self._current_namespace}::{class_name}"
                                           if self._current_namespace else class_name)
            if cls:
                self._class_members = cls.members.copy()
        else:
            self._class_members = {}

        # Analyze function body
        body = node.child_by_field_name('body')
        if body:
            self._analyze_compound_statement(body)

        # Store summary
        self.function_summaries[qualified_name] = summary

        # Also store by simple name for backward compatibility
        if name not in self.function_summaries:
            self.function_summaries[name] = summary

        if self.verbose:
            print(f"[TS] Function: {qualified_name} "
                  f"[alloc={summary.allocates}, free={summary.frees}]")

        self._current_function = None
        self._local_vars = set()
        self._param_names = {}
        self._class_members = {}

    def _extract_function_info(self, declarator: Any) -> Optional[Tuple[str, Optional[str], bool, bool]]:
        """
        Extract function name and class context from declarator.

        Returns: (name, class_name, is_constructor, is_destructor)
        """
        if declarator.type == 'function_declarator':
            inner = declarator.child_by_field_name('declarator')
            if inner:
                if inner.type == 'identifier':
                    name = self._get_text(inner)
                    return (name, None, False, False)
                elif inner.type == 'qualified_identifier':
                    return self._parse_qualified_identifier(inner)
                elif inner.type == 'destructor_name':
                    for child in inner.children:
                        if child.type == 'identifier':
                            class_name = self._get_text(child)
                            return (f"~{class_name}", class_name, False, True)
                elif inner.type == 'field_identifier':
                    name = self._get_text(inner)
                    return (name, None, False, False)
        elif declarator.type == 'pointer_declarator':
            inner = declarator.child_by_field_name('declarator')
            if inner:
                return self._extract_function_info(inner)
        elif declarator.type == 'reference_declarator':
            inner = declarator.child_by_field_name('declarator')
            if inner:
                return self._extract_function_info(inner)

        return None

    def _parse_qualified_identifier(self, node: Any) -> Tuple[str, Optional[str], bool, bool]:
        """Parse Class::method or namespace::Class::method."""
        parts = []
        current = node

        # Collect all parts of the qualified name
        while current:
            if current.type == 'qualified_identifier':
                name_node = current.child_by_field_name('name')
                scope_node = current.child_by_field_name('scope')

                if name_node:
                    name_text = self._get_text(name_node)
                    parts.insert(0, name_text)

                current = scope_node
            elif current.type in ('identifier', 'type_identifier', 'destructor_name'):
                parts.insert(0, self._get_text(current))
                break
            else:
                break

        if not parts:
            return ("unknown", None, False, False)

        name = parts[-1]
        class_name = parts[-2] if len(parts) >= 2 else None

        # Detect constructor: ClassName::ClassName
        is_ctor = class_name and name == class_name

        # Detect destructor: ClassName::~ClassName
        is_dtor = name.startswith('~') and class_name and name == f"~{class_name}"

        return (name, class_name, is_ctor, is_dtor)

    def _extract_return_type(self, func_node: Any) -> str:
        """Extract return type from function definition."""
        type_node = func_node.child_by_field_name('type')
        if type_node:
            return self._get_text(type_node)
        return "void"

    def _extract_parameters(self, func_declarator: Any) -> List[ParameterInfo]:
        """Extract parameter information from function declarator."""
        params = []
        param_list = func_declarator.child_by_field_name('parameters')
        if not param_list:
            return params

        idx = 0
        for child in param_list.children:
            if child.type == 'parameter_declaration':
                param_info = self._extract_param_info(child, idx)
                if param_info:
                    params.append(param_info)
                    idx += 1

        return params

    def _extract_param_info(self, param_decl: Any, idx: int) -> Optional[ParameterInfo]:
        """Extract ParameterInfo from parameter_declaration."""
        type_node = param_decl.child_by_field_name('type')
        type_str = self._get_text(type_node) if type_node else "unknown"

        declarator = param_decl.child_by_field_name('declarator')
        name = "param" + str(idx)
        is_pointer = False
        is_reference = False

        if declarator:
            extracted_name = self._extract_var_name_from_declarator(declarator)
            if extracted_name:
                name = extracted_name
            is_pointer = declarator.type == 'pointer_declarator' or '*' in type_str
            is_reference = declarator.type == 'reference_declarator' or '&' in type_str

        is_const = 'const' in type_str

        return ParameterInfo(
            index=idx,
            name=name,
            type_str=type_str,
            is_pointer=is_pointer,
            is_reference=is_reference,
            is_const=is_const
        )

    # =========================================================================
    # Body analysis
    # =========================================================================

    def _analyze_compound_statement(self, node: Any):
        """Analyze all statements in a compound statement."""
        for child in node.children:
            if child.type not in ('{', '}'):
                self._analyze_statement(child)

    def _analyze_statement(self, node: Any):
        """Analyze a single statement for heap effects."""
        if node.type == 'expression_statement':
            for child in node.children:
                self._analyze_expression_for_effects(child)
        elif node.type == 'declaration':
            self._analyze_declaration(node)
        elif node.type == 'return_statement':
            self._analyze_return_statement(node)
        elif node.type == 'compound_statement':
            self._analyze_compound_statement(node)
        elif node.type in ('if_statement', 'while_statement', 'for_statement',
                           'do_statement', 'switch_statement'):
            self._analyze_control_flow(node)
        elif node.type == 'delete_expression':
            self._handle_delete(node)

    def _analyze_control_flow(self, node: Any):
        """Analyze control flow statements."""
        for child in node.children:
            if child.type == 'compound_statement':
                self._analyze_compound_statement(child)
            elif child.type == 'expression_statement':
                for c in child.children:
                    self._analyze_expression_for_effects(c)
            elif child.type not in ('(', ')', '{', '}', 'if', 'while', 'for',
                                    'do', 'switch', 'else'):
                self._analyze_statement(child)

    def _analyze_declaration(self, node: Any):
        """Analyze variable declaration."""
        declarator = node.child_by_field_name('declarator')
        if declarator:
            # Track local variable
            var_name = self._extract_var_name_from_declarator(declarator)
            if var_name:
                self._local_vars.add(var_name)

            # Check for allocation in initializer
            for child in declarator.children:
                if child.type in ('call_expression', 'new_expression'):
                    self._analyze_expression_for_effects(child)

    def _analyze_expression_for_effects(self, node: Any):
        """Analyze expression for heap operations."""
        if node.type == 'call_expression':
            self._analyze_call_expression(node)
        elif node.type == 'assignment_expression':
            self._analyze_assignment_expression(node)
        elif node.type == 'delete_expression':
            self._handle_delete(node)
        elif node.type == 'new_expression':
            self._handle_new(node)
        elif node.type == 'pointer_expression':
            self._handle_dereference(node)
        elif node.type == 'field_expression':
            self._handle_field_access(node)

        # Recurse into children
        for child in node.children:
            self._analyze_expression_for_effects(child)

    def _analyze_call_expression(self, node: Any):
        """Analyze function call for heap effects."""
        func_node = node.child_by_field_name('function')
        args_node = node.child_by_field_name('arguments')

        if not func_node:
            return

        func_name = self._get_text(func_node)
        args = self._get_call_arguments(args_node) if args_node else []

        summary = self._current_function
        if not summary:
            return

        # Check for allocation functions
        if func_name in self.ALLOC_FUNCS:
            summary.allocates = True
            summary.has_heap_ops = True

        # Check for free functions
        elif func_name in self.FREE_FUNCS:
            summary.frees = True
            summary.has_heap_ops = True

            # Track what is freed
            if args:
                self._record_free_effect(args[0])

    def _handle_new(self, node: Any):
        """Handle C++ new expression."""
        summary = self._current_function
        if not summary:
            return

        summary.allocates = True
        summary.has_heap_ops = True
        summary.returns_allocated = True

    def _handle_delete(self, node: Any):
        """Handle C++ delete expression."""
        summary = self._current_function
        if not summary:
            return

        summary.frees = True
        summary.has_heap_ops = True

        # Find what's being deleted
        for child in node.children:
            if child.type == 'identifier':
                deleted_var = self._get_text(child)
                self._record_free_effect(deleted_var)
            elif child.type == 'field_expression':
                self._record_member_free_from_field_expr(child)
            elif child.type == 'pointer_expression':
                # delete *ptr
                arg = child.child_by_field_name('argument')
                if arg and arg.type == 'identifier':
                    self._record_free_effect(self._get_text(arg))

    def _handle_dereference(self, node: Any):
        """Handle pointer dereference for tracking."""
        summary = self._current_function
        if not summary:
            return

        # Get the dereferenced expression
        arg = node.child_by_field_name('argument')
        if arg and arg.type == 'identifier':
            var_name = self._get_text(arg)

            # Check if dereferencing a parameter
            if var_name in self._param_names:
                idx = self._param_names[var_name]
                if idx in summary.param_effects:
                    summary.param_effects[idx].is_dereferenced = True

            # Check if dereferencing a member
            if var_name in self._class_members:
                if var_name not in summary.member_effects:
                    summary.member_effects[var_name] = MemberEffect(
                        member_name=var_name,
                        member_type=self._class_members.get(var_name, 'unknown')
                    )
                summary.member_effects[var_name].is_dereferenced = True

    def _handle_field_access(self, node: Any):
        """Handle field/member access (obj.field or ptr->field)."""
        # This tracks access to class members through this->member
        argument = node.child_by_field_name('argument')
        field = node.child_by_field_name('field')

        if not field:
            return

        field_name = self._get_text(field)

        # Check if it's this->member
        if argument and self._get_text(argument) == 'this':
            if field_name in self._class_members:
                summary = self._current_function
                if summary and field_name not in summary.member_effects:
                    summary.member_effects[field_name] = MemberEffect(
                        member_name=field_name,
                        member_type=self._class_members.get(field_name, 'unknown')
                    )

    def _analyze_assignment_expression(self, node: Any):
        """Analyze assignment for effects."""
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')

        if not left or not right:
            return

        summary = self._current_function
        if not summary:
            return

        # Check if right side is allocation
        if right.type == 'call_expression':
            func_node = right.child_by_field_name('function')
            if func_node and self._get_text(func_node) in self.ALLOC_FUNCS:
                summary.allocates = True
                summary.has_heap_ops = True
        elif right.type == 'new_expression':
            summary.allocates = True
            summary.has_heap_ops = True

        # Check if left side is a member being modified
        if left.type == 'field_expression':
            arg = left.child_by_field_name('argument')
            field = left.child_by_field_name('field')
            if arg and self._get_text(arg) == 'this' and field:
                member_name = self._get_text(field)
                if member_name not in summary.member_effects:
                    summary.member_effects[member_name] = MemberEffect(
                        member_name=member_name,
                        member_type=self._class_members.get(member_name, 'unknown')
                    )
                summary.member_effects[member_name].is_modified = True

                # Check if allocation is stored to member
                if right.type in ('call_expression', 'new_expression'):
                    summary.member_effects[member_name].is_allocated = True

    def _analyze_return_statement(self, node: Any):
        """Analyze return statement for return value source."""
        summary = self._current_function
        if not summary:
            return

        # Find return expression
        for child in node.children:
            if child.type not in ('return', ';'):
                self._analyze_return_expr(child, summary)
                break

    def _analyze_return_expr(self, expr: Any, summary: FunctionSummary):
        """Analyze the expression being returned."""
        if expr.type == 'identifier':
            var_name = self._get_text(expr)
            # Check if returning a parameter
            if var_name in self._param_names:
                idx = self._param_names[var_name]
                summary.return_source = ReturnSource.PARAMETER
                summary.return_source_param_idx = idx
                if idx in summary.param_effects:
                    summary.param_effects[idx].is_returned = True
            # Check if returning a member
            elif var_name in self._class_members:
                summary.return_source = ReturnSource.MEMBER
                summary.return_source_member = var_name
        elif expr.type == 'call_expression':
            func_node = expr.child_by_field_name('function')
            if func_node and self._get_text(func_node) in self.ALLOC_FUNCS:
                summary.return_source = ReturnSource.ALLOCATION
                summary.returns_allocated = True
        elif expr.type == 'new_expression':
            summary.return_source = ReturnSource.ALLOCATION
            summary.returns_allocated = True
        elif expr.type in ('number_literal', 'string_literal', 'null', 'nullptr'):
            summary.return_source = ReturnSource.LITERAL

    def _get_call_arguments(self, args_node: Any) -> List[str]:
        """Extract argument expressions as text."""
        args = []
        for child in args_node.children:
            if child.type not in ('(', ')', ','):
                args.append(self._get_text(child))
        return args

    def _record_free_effect(self, var_name: str):
        """Record that a variable is freed."""
        summary = self._current_function
        if not summary:
            return

        # Strip this-> prefix
        clean_name = var_name.replace('this->', '')

        # Check if it's a parameter
        if clean_name in self._param_names:
            idx = self._param_names[clean_name]
            if idx in summary.param_effects:
                summary.param_effects[idx].is_freed = True

        # Check if it's a member
        if clean_name in self._class_members:
            if clean_name not in summary.member_effects:
                summary.member_effects[clean_name] = MemberEffect(
                    member_name=clean_name,
                    member_type=self._class_members.get(clean_name, 'unknown')
                )
            summary.member_effects[clean_name].is_freed = True

    def _record_member_free_from_field_expr(self, node: Any):
        """Record member free from field expression like this->member."""
        arg = node.child_by_field_name('argument')
        field = node.child_by_field_name('field')

        if field:
            member_name = self._get_text(field)
            self._record_free_effect(member_name)

    # =========================================================================
    # Class lifecycle analysis
    # =========================================================================

    def analyze_class_lifecycle(self, class_name: str) -> List[str]:
        """
        Analyze class lifecycle for potential memory issues.

        Returns list of potential issues found.
        """
        issues = []
        cls = self.class_summaries.get(class_name)
        if not cls:
            return issues

        # Find constructor and destructor summaries
        for name, summary in self.function_summaries.items():
            if summary.class_name == class_name:
                if summary.is_constructor:
                    cls.constructor_summaries.append(summary)
                    for member, effect in summary.member_effects.items():
                        if effect.is_allocated:
                            cls.members_allocated_in_ctor.add(member)
                elif summary.is_destructor:
                    cls.destructor_summary = summary
                    for member, effect in summary.member_effects.items():
                        if effect.is_freed:
                            cls.members_freed_in_dtor.add(member)

        # Check for rule of three violations
        if cls.has_raw_pointer_members and cls.destructor_summary:
            if not any('operator=' in name for name in self.function_summaries
                       if self.function_summaries[name].class_name == class_name):
                cls.missing_copy_assignment = True
                issues.append(f"{class_name}: Missing copy assignment with pointer members")

        # Check for double-free potential
        for member in cls.members_allocated_in_ctor:
            if member in cls.members_freed_in_dtor:
                # Check if freed elsewhere too
                for name, summary in self.function_summaries.items():
                    if summary.class_name == class_name and not summary.is_destructor:
                        if member in summary.frees_members:
                            cls.potential_double_free = True
                            issues.append(f"{class_name}::{member}: Potential double-free")

        return issues
