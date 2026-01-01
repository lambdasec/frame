"""
Interprocedural Taint Analysis for C/C++.

This module implements cross-function taint tracking using:
1. Call graph construction from AST
2. Function taint summaries (which params are sources/sinks)
3. Taint propagation through call sites

Key insight: Many Juliet tests have vulnerabilities that span function boundaries.
For example, main.cpp calls badSink(data) where data was tainted in badSource().
This requires tracking taint flow through function calls.
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser

from frame.sil.types import Location


class TaintKind(Enum):
    """Types of taint sources and sinks."""
    # Sources
    USER_INPUT = "user_input"       # stdin, fgets, scanf, etc.
    NETWORK = "network"             # recv, socket read
    FILE_READ = "file_read"         # fread, getline
    ENVIRONMENT = "environment"     # getenv
    COMMAND_LINE = "command_line"   # argv

    # Sinks
    BUFFER_WRITE = "buffer_write"   # strcpy, memcpy destination
    FORMAT_STRING = "format_string" # printf format arg
    SHELL_EXEC = "shell_exec"       # system, popen
    FILE_PATH = "file_path"         # fopen path
    SQL_QUERY = "sql_query"         # SQL execution
    MEMORY_ALLOC = "memory_alloc"   # malloc size
    ARRAY_INDEX = "array_index"     # array subscript
    CONFIG_SETTING = "config_setting"  # system configuration (CWE-15)


@dataclass
class TaintSummary:
    """Summary of a function's taint behavior."""
    name: str
    qualified_name: str

    # Parameters that are taint sources (e.g., first param of fgets is written to)
    param_sources: Dict[int, TaintKind] = field(default_factory=dict)

    # Parameters that are taint sinks (e.g., first param of strcpy is destination)
    param_sinks: Dict[int, TaintKind] = field(default_factory=dict)

    # Parameters whose taint propagates to return value
    params_to_return: Set[int] = field(default_factory=set)

    # Whether return value is tainted (e.g., malloc returns user-controlled size)
    return_tainted: bool = False
    return_taint_kind: Optional[TaintKind] = None

    # Parameters that are freed
    freed_params: Set[int] = field(default_factory=set)

    # Parameters that are dereferenced
    deref_params: Set[int] = field(default_factory=set)

    # Whether function allocates memory (for leak tracking)
    allocates: bool = False

    # Whether function frees memory
    frees: bool = False

    # Confidence in this summary (0.0-1.0)
    confidence: float = 0.5


@dataclass
class CallSite:
    """Represents a function call in the code."""
    callee: str                      # Function being called
    caller: str                      # Function making the call
    location: Location
    arguments: List[str]             # Argument expressions (as strings)
    return_var: Optional[str] = None # Variable receiving return value


@dataclass
class CallGraph:
    """Call graph for interprocedural analysis."""
    # Function name -> list of call sites in that function
    calls_from: Dict[str, List[CallSite]] = field(default_factory=dict)

    # Function name -> list of call sites that call it
    calls_to: Dict[str, List[CallSite]] = field(default_factory=dict)

    # All function definitions found
    defined_functions: Set[str] = field(default_factory=set)

    # External functions (called but not defined in this file)
    external_functions: Set[str] = field(default_factory=set)


class InterproceduralTaintAnalyzer:
    """
    Analyzes taint flow across function boundaries.

    Usage:
        analyzer = InterproceduralTaintAnalyzer()
        taint_info = analyzer.analyze(source, filename)
        # taint_info contains cross-function vulnerabilities
    """

    # Known taint source functions (function -> (param_idx, taint_kind))
    TAINT_SOURCES = {
        # User input sources
        'fgets': (0, TaintKind.USER_INPUT),    # First param receives input
        'gets': (0, TaintKind.USER_INPUT),
        'scanf': (1, TaintKind.USER_INPUT),    # Args after format are filled
        'fscanf': (2, TaintKind.USER_INPUT),
        'sscanf': (2, TaintKind.USER_INPUT),
        'fread': (0, TaintKind.USER_INPUT),
        'read': (1, TaintKind.USER_INPUT),     # Second param is buffer
        'recv': (1, TaintKind.NETWORK),
        'recvfrom': (1, TaintKind.NETWORK),
        'getenv': (-1, TaintKind.ENVIRONMENT), # Return value is tainted
        'getline': (0, TaintKind.USER_INPUT),
        'ReadFile': (1, TaintKind.USER_INPUT), # Windows
        'ReadConsole': (1, TaintKind.USER_INPUT),
        # Network
        'accept': (-1, TaintKind.NETWORK),     # Returns tainted socket
    }

    # Known taint sink functions (function -> (tainted_param_idx, sink_kind))
    # tainted_param_idx is the parameter that carries tainted data to the sink
    #
    # NOTE: We only include sinks where tainted DATA is the vulnerability.
    # Buffer operations like strcpy/memcpy are NOT included because:
    # - Tainted SOURCE data is not inherently dangerous
    # - The vulnerability is about destination SIZE vs copy amount
    # - That requires bounds analysis, not taint analysis
    #
    TAINT_SINKS = {
        # Format string - format param being tainted is CWE-134
        # This is when user controls the format string itself
        'printf': (0, TaintKind.FORMAT_STRING),
        'fprintf': (1, TaintKind.FORMAT_STRING),
        'sprintf': (1, TaintKind.FORMAT_STRING),    # sprintf(dest, fmt, ...) - fmt is dangerous
        'snprintf': (2, TaintKind.FORMAT_STRING),   # snprintf(dest, n, fmt, ...) - fmt is dangerous
        'syslog': (1, TaintKind.FORMAT_STRING),
        'vsprintf': (1, TaintKind.FORMAT_STRING),
        'vprintf': (0, TaintKind.FORMAT_STRING),
        'vfprintf': (1, TaintKind.FORMAT_STRING),
        # Shell execution - command is tainted = CWE-78
        'system': (0, TaintKind.SHELL_EXEC),
        'popen': (0, TaintKind.SHELL_EXEC),
        'execl': (0, TaintKind.SHELL_EXEC),
        'execle': (0, TaintKind.SHELL_EXEC),
        'execlp': (0, TaintKind.SHELL_EXEC),
        'execv': (0, TaintKind.SHELL_EXEC),
        'execve': (0, TaintKind.SHELL_EXEC),
        'execvp': (0, TaintKind.SHELL_EXEC),
        'ShellExecute': (2, TaintKind.SHELL_EXEC),  # Windows
        'ShellExecuteA': (2, TaintKind.SHELL_EXEC),
        'ShellExecuteW': (2, TaintKind.SHELL_EXEC),
        'CreateProcess': (1, TaintKind.SHELL_EXEC),  # Windows
        'CreateProcessA': (1, TaintKind.SHELL_EXEC),
        'CreateProcessW': (1, TaintKind.SHELL_EXEC),
        # File operations - path is tainted = CWE-22/CWE-73
        'fopen': (0, TaintKind.FILE_PATH),
        'open': (0, TaintKind.FILE_PATH),
        'CreateFile': (0, TaintKind.FILE_PATH),
        'CreateFileA': (0, TaintKind.FILE_PATH),
        'CreateFileW': (0, TaintKind.FILE_PATH),
        'remove': (0, TaintKind.FILE_PATH),
        'unlink': (0, TaintKind.FILE_PATH),
        'rename': (0, TaintKind.FILE_PATH),  # Old name
        # Memory allocation with tainted size = CWE-190/CWE-680
        'malloc': (0, TaintKind.MEMORY_ALLOC),
        'calloc': (0, TaintKind.MEMORY_ALLOC),
        'realloc': (1, TaintKind.MEMORY_ALLOC),
        'alloca': (0, TaintKind.MEMORY_ALLOC),
        # System configuration - CWE-15
        'SetComputerName': (0, TaintKind.CONFIG_SETTING),
        'SetComputerNameA': (0, TaintKind.CONFIG_SETTING),
        'SetComputerNameW': (0, TaintKind.CONFIG_SETTING),
        'SetEnvironmentVariable': (1, TaintKind.CONFIG_SETTING),
        'SetEnvironmentVariableA': (1, TaintKind.CONFIG_SETTING),
        'SetEnvironmentVariableW': (1, TaintKind.CONFIG_SETTING),
        'RegSetValue': (3, TaintKind.CONFIG_SETTING),
        'RegSetValueEx': (4, TaintKind.CONFIG_SETTING),
        'RegSetValueExA': (4, TaintKind.CONFIG_SETTING),
        'RegSetValueExW': (4, TaintKind.CONFIG_SETTING),
        'WritePrivateProfileString': (2, TaintKind.CONFIG_SETTING),
        'WritePrivateProfileStringA': (2, TaintKind.CONFIG_SETTING),
        'WritePrivateProfileStringW': (2, TaintKind.CONFIG_SETTING),
        # Library loading - CWE-114
        'LoadLibrary': (0, TaintKind.FILE_PATH),
        'LoadLibraryA': (0, TaintKind.FILE_PATH),
        'LoadLibraryW': (0, TaintKind.FILE_PATH),
        'LoadLibraryEx': (0, TaintKind.FILE_PATH),
        'LoadLibraryExA': (0, TaintKind.FILE_PATH),
        'LoadLibraryExW': (0, TaintKind.FILE_PATH),
        'dlopen': (0, TaintKind.FILE_PATH),
    }

    # Functions that propagate taint from params to return value
    TAINT_PROPAGATORS = {
        'strdup': [0],      # Returns copy of param 0
        'strndup': [0],
        'strstr': [0, 1],   # Returns pointer into param 0 if param 1 found
        'strchr': [0],
        'strrchr': [0],
        'strtok': [0],
        'memchr': [0],
        'atoi': [0],        # Returns int parsed from param 0
        'atol': [0],
        'atof': [0],
        'strtol': [0],
        'strtoul': [0],
    }

    # Functions that propagate taint from one argument to another (not return)
    # Format: function -> list of (src_param_idx, dest_param_idx) tuples
    TAINT_ARG_PROPAGATORS = {
        # String copy operations: src -> dest
        'strcpy': [(1, 0)],     # strcpy(dest, src) - src taints dest
        'strncpy': [(1, 0)],    # strncpy(dest, src, n)
        'strcat': [(1, 0)],     # strcat(dest, src)
        'strncat': [(1, 0)],    # strncat(dest, src, n)
        'memcpy': [(1, 0)],     # memcpy(dest, src, n)
        'memmove': [(1, 0)],    # memmove(dest, src, n)
        'wcscpy': [(1, 0)],
        'wcsncpy': [(1, 0)],
        'wcsncat': [(1, 0)],
        # sprintf writes to dest from format args
        'sprintf': [(2, 0)],    # sprintf(dest, fmt, arg) - arg taints dest
        'snprintf': [(3, 0)],   # snprintf(dest, n, fmt, arg)
        # sscanf reads from src to args
        'sscanf': [(0, 2)],     # sscanf(src, fmt, arg) - src taints arg
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

        # Parsers
        self.c_parser = Parser(Language(tsc.language()))
        self.cpp_parser = Parser(Language(tscpp.language()))

        # Analysis state
        self._source: str = ""
        self._filename: str = ""
        self._lines: List[str] = []

        # Results
        self.call_graph = CallGraph()
        self.taint_summaries: Dict[str, TaintSummary] = {}

        # Current context
        self._current_function: Optional[str] = None
        self._current_namespace: Optional[str] = None

        # Initialize with known library function summaries
        self._init_library_summaries()

    def _init_library_summaries(self):
        """Initialize taint summaries for known library functions."""
        # Add source functions
        for func, (param_idx, kind) in self.TAINT_SOURCES.items():
            summary = TaintSummary(name=func, qualified_name=func)
            if param_idx == -1:
                # Return value is tainted
                summary.return_tainted = True
                summary.return_taint_kind = kind
            else:
                summary.param_sources[param_idx] = kind
            summary.confidence = 1.0  # Known library function
            self.taint_summaries[func] = summary

        # Add sink functions
        for func, (param_idx, kind) in self.TAINT_SINKS.items():
            if func not in self.taint_summaries:
                summary = TaintSummary(name=func, qualified_name=func)
            else:
                summary = self.taint_summaries[func]
            summary.param_sinks[param_idx] = kind
            summary.confidence = 1.0
            self.taint_summaries[func] = summary

        # Add propagator functions
        for func, params in self.TAINT_PROPAGATORS.items():
            if func not in self.taint_summaries:
                summary = TaintSummary(name=func, qualified_name=func)
            else:
                summary = self.taint_summaries[func]
            summary.params_to_return = set(params)
            summary.confidence = 1.0
            self.taint_summaries[func] = summary

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

    def analyze(self, source: str, filename: str) -> Dict[str, Any]:
        """
        Analyze source for interprocedural taint flow.

        Returns dict with:
            - call_graph: CallGraph object
            - taint_summaries: Dict of function taint summaries
            - vulnerabilities: List of cross-function vulnerabilities found
        """
        self._source = source
        self._filename = filename
        self._lines = source.split('\n')
        self.call_graph = CallGraph()

        parser = self._get_parser(filename)
        tree = parser.parse(bytes(source, 'utf8'))

        if self.verbose:
            print(f"[IPA] Analyzing {filename}")

        # Pass 1: Find all function definitions and their call sites
        self._build_call_graph(tree.root_node)

        # Pass 2: Build taint summaries for defined functions
        self._build_taint_summaries(tree.root_node)

        # Pass 3: Propagate taint through call graph
        vulnerabilities = self._propagate_taint()

        if self.verbose:
            print(f"[IPA] Call graph: {len(self.call_graph.defined_functions)} functions, "
                  f"{sum(len(v) for v in self.call_graph.calls_from.values())} call sites")
            print(f"[IPA] Found {len(vulnerabilities)} cross-function vulnerabilities")

        return {
            'call_graph': self.call_graph,
            'taint_summaries': self.taint_summaries,
            'vulnerabilities': vulnerabilities
        }

    # =========================================================================
    # Pass 1: Build call graph
    # =========================================================================

    def _build_call_graph(self, node: Any):
        """Extract function definitions and call sites."""
        if node.type == 'function_definition':
            self._process_function_def(node)
        elif node.type == 'namespace_definition':
            old_ns = self._current_namespace
            name_node = node.child_by_field_name('name')
            ns_name = self._get_text(name_node) if name_node else ""
            self._current_namespace = f"{old_ns}::{ns_name}" if old_ns else ns_name

            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    self._build_call_graph(child)

            self._current_namespace = old_ns
        else:
            for child in node.children:
                self._build_call_graph(child)

    def _process_function_def(self, node: Any):
        """Process a function definition node."""
        # Get function name
        declarator = node.child_by_field_name('declarator')
        func_name = self._extract_function_name(declarator)

        if not func_name:
            return

        qualified_name = f"{self._current_namespace}::{func_name}" \
            if self._current_namespace else func_name

        self.call_graph.defined_functions.add(qualified_name)
        self.call_graph.defined_functions.add(func_name)  # Also add simple name

        # Process function body for call sites
        old_func = self._current_function
        self._current_function = qualified_name

        body = node.child_by_field_name('body')
        if body:
            self._find_call_sites(body)

        self._current_function = old_func

    def _extract_function_name(self, declarator: Any) -> Optional[str]:
        """Extract function name from declarator."""
        if declarator is None:
            return None

        if declarator.type == 'identifier':
            return self._get_text(declarator)
        elif declarator.type == 'function_declarator':
            inner = declarator.child_by_field_name('declarator')
            return self._extract_function_name(inner)
        elif declarator.type == 'pointer_declarator':
            inner = declarator.child_by_field_name('declarator')
            return self._extract_function_name(inner)
        elif declarator.type == 'qualified_identifier':
            # Get last identifier in qualified name
            for child in reversed(declarator.children):
                if child.type == 'identifier':
                    return self._get_text(child)

        # Fallback
        for child in declarator.children:
            if child.type == 'identifier':
                return self._get_text(child)

        return None

    def _find_call_sites(self, node: Any):
        """Find all function call sites in a node."""
        if node.type == 'call_expression':
            self._process_call_expr(node)

        for child in node.children:
            self._find_call_sites(child)

    def _process_call_expr(self, node: Any):
        """Process a function call expression."""
        func_node = node.child_by_field_name('function')
        if not func_node:
            return

        callee = self._get_text(func_node)

        # Handle qualified names (e.g., std::cout)
        if func_node.type == 'qualified_identifier':
            callee = self._get_text(func_node)
        elif func_node.type == 'field_expression':
            # Method call: obj.method() or obj->method()
            field = func_node.child_by_field_name('field')
            if field:
                callee = self._get_text(field)

        # Skip operators and built-ins
        if not callee or callee.startswith('operator'):
            return

        # Extract arguments
        args_node = node.child_by_field_name('arguments')
        arguments = []
        if args_node:
            for child in args_node.children:
                if child.type not in ('(', ')', ','):
                    arguments.append(self._get_text(child))

        # Create call site
        location = Location(
            file=self._filename,
            line=node.start_point[0] + 1,
            column=node.start_point[1] + 1
        )

        call_site = CallSite(
            callee=callee,
            caller=self._current_function or "<global>",
            location=location,
            arguments=arguments
        )

        # Check if this is an assignment (return value captured)
        parent = node.parent
        if parent and parent.type in ('assignment_expression', 'init_declarator'):
            # Find the variable being assigned
            if parent.type == 'assignment_expression':
                left = parent.child_by_field_name('left')
                if left:
                    call_site.return_var = self._get_text(left)
            elif parent.type == 'init_declarator':
                decl = parent.child_by_field_name('declarator')
                if decl:
                    call_site.return_var = self._extract_var_name(decl)

        # Add to call graph
        if self._current_function not in self.call_graph.calls_from:
            self.call_graph.calls_from[self._current_function] = []
        self.call_graph.calls_from[self._current_function].append(call_site)

        if callee not in self.call_graph.calls_to:
            self.call_graph.calls_to[callee] = []
        self.call_graph.calls_to[callee].append(call_site)

        # Track external functions
        if callee not in self.call_graph.defined_functions:
            self.call_graph.external_functions.add(callee)

    def _extract_var_name(self, declarator: Any) -> Optional[str]:
        """Extract variable name from declarator."""
        if declarator.type == 'identifier':
            return self._get_text(declarator)
        elif declarator.type in ('pointer_declarator', 'array_declarator'):
            inner = declarator.child_by_field_name('declarator')
            return self._extract_var_name(inner) if inner else None

        for child in declarator.children:
            if child.type == 'identifier':
                return self._get_text(child)
        return None

    # =========================================================================
    # Pass 2: Build taint summaries for defined functions
    # =========================================================================

    def _build_taint_summaries(self, node: Any):
        """Build taint summaries for user-defined functions."""
        if node.type == 'function_definition':
            self._analyze_function_taint(node)
        else:
            for child in node.children:
                self._build_taint_summaries(child)

    def _analyze_function_taint(self, node: Any):
        """Analyze a function's taint behavior."""
        declarator = node.child_by_field_name('declarator')
        func_name = self._extract_function_name(declarator)

        if not func_name:
            return

        qualified_name = f"{self._current_namespace}::{func_name}" \
            if self._current_namespace else func_name

        # Skip if already have a high-confidence summary (library function)
        if func_name in self.taint_summaries:
            if self.taint_summaries[func_name].confidence >= 0.9:
                return

        summary = TaintSummary(name=func_name, qualified_name=qualified_name)

        # Extract parameters
        params = self._extract_parameters(declarator)
        param_names = {name: idx for idx, (name, _) in enumerate(params)}

        # Analyze function body
        body = node.child_by_field_name('body')
        if body:
            self._analyze_body_taint(body, summary, param_names)

        summary.confidence = 0.7  # User-defined function
        self.taint_summaries[func_name] = summary
        self.taint_summaries[qualified_name] = summary

    def _extract_parameters(self, declarator: Any) -> List[Tuple[str, str]]:
        """Extract parameter names and types from function declarator."""
        params = []

        if declarator is None:
            return params

        if declarator.type == 'function_declarator':
            params_node = declarator.child_by_field_name('parameters')
            if params_node:
                for child in params_node.children:
                    if child.type == 'parameter_declaration':
                        type_node = child.child_by_field_name('type')
                        type_str = self._get_text(type_node) if type_node else "unknown"

                        decl = child.child_by_field_name('declarator')
                        name = self._extract_var_name(decl) if decl else None

                        if name:
                            params.append((name, type_str))

        return params

    def _analyze_body_taint(self, body: Any, summary: TaintSummary,
                           param_names: Dict[str, int]):
        """Analyze function body for taint sources, sinks, and propagation."""
        # Track local taint state
        tainted_vars: Set[str] = set()

        # Mark parameters that receive tainted data as initially tainted
        for param, idx in param_names.items():
            # Check if this param is used as source (written to by input function)
            # This is detected when we see calls like fgets(param, ...)
            pass  # Will be detected in call analysis below

        self._analyze_node_taint(body, summary, param_names, tainted_vars)

    def _analyze_node_taint(self, node: Any, summary: TaintSummary,
                           param_names: Dict[str, int], tainted_vars: Set[str]):
        """Recursively analyze taint in a node."""
        if node.type == 'call_expression':
            self._check_call_taint(node, summary, param_names, tainted_vars)
        elif node.type == 'return_statement':
            self._check_return_taint(node, summary, param_names, tainted_vars)
        elif node.type == 'assignment_expression':
            self._check_assignment_taint(node, summary, param_names, tainted_vars)

        for child in node.children:
            self._analyze_node_taint(child, summary, param_names, tainted_vars)

    def _check_call_taint(self, node: Any, summary: TaintSummary,
                         param_names: Dict[str, int], tainted_vars: Set[str]):
        """Check a call expression for taint effects."""
        func_node = node.child_by_field_name('function')
        if not func_node:
            return

        callee = self._get_text(func_node)

        # Get arguments
        args_node = node.child_by_field_name('arguments')
        args = []
        if args_node:
            for child in args_node.children:
                if child.type not in ('(', ')', ','):
                    args.append(self._get_text(child))

        # Check if callee is a known taint source
        if callee in self.TAINT_SOURCES:
            src_param, kind = self.TAINT_SOURCES[callee]
            if src_param == -1:
                # Return value is tainted - handled in assignment
                pass
            elif src_param < len(args):
                # The argument at src_param receives tainted input
                tainted_arg = args[src_param]
                tainted_vars.add(tainted_arg)

                # If this is a function parameter, mark it as a source
                if tainted_arg in param_names:
                    summary.param_sources[param_names[tainted_arg]] = kind

        # Check if passing tainted data to a sink
        if callee in self.TAINT_SINKS:
            sink_param, kind = self.TAINT_SINKS[callee]
            if sink_param < len(args):
                arg = args[sink_param]
                # Check if arg is tainted
                if arg in tainted_vars or arg in param_names:
                    # This function uses a parameter in a dangerous way
                    if arg in param_names:
                        summary.param_sinks[param_names[arg]] = kind

        # Check taint propagation through return value
        parent = node.parent
        if parent and parent.type in ('assignment_expression', 'init_declarator'):
            if callee in self.TAINT_PROPAGATORS:
                propagate_from = self.TAINT_PROPAGATORS[callee]
                for idx in propagate_from:
                    if idx < len(args):
                        arg = args[idx]
                        if arg in tainted_vars:
                            # Return value is tainted
                            if parent.type == 'assignment_expression':
                                left = parent.child_by_field_name('left')
                                if left:
                                    tainted_vars.add(self._get_text(left))
            elif callee in self.TAINT_SOURCES:
                src_param, kind = self.TAINT_SOURCES[callee]
                if src_param == -1:
                    # Return is tainted
                    if parent.type == 'assignment_expression':
                        left = parent.child_by_field_name('left')
                        if left:
                            tainted_vars.add(self._get_text(left))

    def _check_return_taint(self, node: Any, summary: TaintSummary,
                           param_names: Dict[str, int], tainted_vars: Set[str]):
        """Check if return value propagates taint from parameters."""
        for child in node.children:
            if child.type not in ('return', ';'):
                returned_expr = self._get_text(child)

                # Check if returning a tainted variable
                if returned_expr in tainted_vars:
                    summary.return_tainted = True

                # Check if returning a parameter
                if returned_expr in param_names:
                    summary.params_to_return.add(param_names[returned_expr])
                    summary.return_tainted = True

    def _check_assignment_taint(self, node: Any, summary: TaintSummary,
                                param_names: Dict[str, int], tainted_vars: Set[str]):
        """Track taint propagation through assignments."""
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')

        if left and right:
            left_name = self._get_text(left)
            right_name = self._get_text(right)

            # Propagate taint
            if right_name in tainted_vars:
                tainted_vars.add(left_name)

            # If assigning from a parameter, track the propagation
            if right_name in param_names:
                # This local var now has the parameter's value
                tainted_vars.add(left_name)

    # =========================================================================
    # Pass 3: Propagate taint through call graph
    # =========================================================================

    def _propagate_taint(self) -> List[Dict[str, Any]]:
        """
        Propagate taint through call graph and find vulnerabilities.

        Returns list of cross-function vulnerabilities.
        """
        vulnerabilities = []

        # For each call site, check if tainted data flows to a sink
        for caller, call_sites in self.call_graph.calls_from.items():
            # Get taint state in caller
            caller_tainted = self._get_tainted_vars_in_function(caller)

            for site in call_sites:
                callee = site.callee

                # Get callee's taint summary
                callee_summary = self.taint_summaries.get(callee)
                if not callee_summary:
                    continue

                # Check if passing tainted data to sink parameter
                for param_idx, sink_kind in callee_summary.param_sinks.items():
                    if param_idx < len(site.arguments):
                        arg = site.arguments[param_idx]

                        # Check if argument is tainted
                        if arg in caller_tainted or self._is_tainted_expression(arg, caller_tainted):
                            vuln = {
                                'type': 'cross_function_taint',
                                'sink_kind': sink_kind.value,
                                'callee': callee,
                                'caller': caller,
                                'argument': arg,
                                'param_index': param_idx,
                                'location': site.location,
                                'description': f"Tainted data '{arg}' passed to {callee}() "
                                              f"sink parameter {param_idx} ({sink_kind.value})"
                            }
                            vulnerabilities.append(vuln)

                # Track taint propagation through return value
                if site.return_var and callee_summary.return_tainted:
                    # The return variable becomes tainted
                    caller_tainted.add(site.return_var)

                # Check if any arg is a source and update caller's taint state
                for param_idx, src_kind in callee_summary.param_sources.items():
                    if param_idx < len(site.arguments):
                        arg = site.arguments[param_idx]
                        caller_tainted.add(arg)

        return vulnerabilities

    def _get_tainted_vars_in_function(self, func_name: str) -> Set[str]:
        """
        Get the set of tainted variables in a function by tracking
        taint sources and propagation through function calls.

        Uses iterative fixed-point analysis to handle propagation chains.
        """
        tainted = set()

        # Get call sites in this function
        call_sites = self.call_graph.calls_from.get(func_name, [])

        # Pass 1: Find direct taint sources
        for site in call_sites:
            callee = site.callee
            callee_summary = self.taint_summaries.get(callee)

            if callee_summary:
                # If callee returns tainted data and we capture it
                if site.return_var and callee_summary.return_tainted:
                    tainted.add(site.return_var)

                # If callee is a source function (writes to its argument)
                for param_idx, src_kind in callee_summary.param_sources.items():
                    if param_idx < len(site.arguments):
                        arg = site.arguments[param_idx]
                        tainted.add(arg)

            # Check if callee is a taint propagator that returns tainted data
            if callee in self.TAINT_PROPAGATORS:
                propagate_from = self.TAINT_PROPAGATORS[callee]
                for idx in propagate_from:
                    if idx < len(site.arguments):
                        arg = site.arguments[idx]
                        # If input is tainted, output is tainted
                        if self._is_tainted_expression(arg, tainted) or arg in tainted:
                            if site.return_var:
                                tainted.add(site.return_var)

        # Pass 2: Iteratively propagate taint through arg propagators
        # This handles chains like: getenv -> strcpy -> system
        changed = True
        max_iterations = 10  # Prevent infinite loops
        iterations = 0

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for site in call_sites:
                callee = site.callee

                # Check argument propagators (e.g., strcpy(dest, src))
                if callee in self.TAINT_ARG_PROPAGATORS:
                    for src_idx, dest_idx in self.TAINT_ARG_PROPAGATORS[callee]:
                        if src_idx < len(site.arguments) and dest_idx < len(site.arguments):
                            src_arg = site.arguments[src_idx]
                            dest_arg = site.arguments[dest_idx]

                            # If source is tainted, propagate to destination
                            if src_arg in tainted or self._is_tainted_expression(src_arg, tainted):
                                if dest_arg not in tainted:
                                    tainted.add(dest_arg)
                                    changed = True

                # Also check return value propagators in second pass
                if callee in self.TAINT_PROPAGATORS:
                    propagate_from = self.TAINT_PROPAGATORS[callee]
                    for idx in propagate_from:
                        if idx < len(site.arguments):
                            arg = site.arguments[idx]
                            if arg in tainted or self._is_tainted_expression(arg, tainted):
                                if site.return_var and site.return_var not in tainted:
                                    tainted.add(site.return_var)
                                    changed = True

        return tainted

    def _is_tainted_expression(self, expr: str, tainted_vars: Set[str]) -> bool:
        """Check if an expression contains tainted data."""
        # Skip string literals - they are constants, not tainted
        stripped = expr.strip()
        if stripped.startswith('"') or stripped.startswith("'"):
            return False
        if stripped.startswith('L"') or stripped.startswith("L'"):
            return False  # Wide string literals

        # Check for exact variable match or as part of compound expression
        # Use word boundary to avoid matching substrings inside identifiers
        for var in tainted_vars:
            if not var:
                continue
            # Check for exact match
            if expr == var:
                return True
            # Check with word boundary pattern (e.g., data in "data[i]" or "&data")
            pattern = r'\b' + re.escape(var) + r'\b'
            if re.search(pattern, expr):
                return True
        return False


def analyze_interprocedural_taint(source: str, filename: str,
                                   verbose: bool = False) -> Dict[str, Any]:
    """
    Convenience function for interprocedural taint analysis.

    Args:
        source: C/C++ source code
        filename: Filename for location tracking
        verbose: Enable verbose output

    Returns:
        Dict with call_graph, taint_summaries, and vulnerabilities
    """
    analyzer = InterproceduralTaintAnalyzer(verbose=verbose)
    return analyzer.analyze(source, filename)
