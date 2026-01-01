"""
Interprocedural Taint Analysis for C#.

This module implements cross-method taint tracking for ASP.NET and .NET applications using:
1. Call graph construction from AST
2. Method taint summaries (which params are sources/sinks)
3. Taint propagation through call sites
4. ASP.NET attribute detection ([FromQuery], [FromBody], etc.)

Key insight: Many C# vulnerabilities involve controller actions passing user input
through helper methods to dangerous sinks. This requires tracking taint flow
through method calls.
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re

try:
    import tree_sitter_c_sharp as ts_csharp
    from tree_sitter import Language, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

from frame.sil.types import Location


class TaintKind(Enum):
    """Types of taint sources and sinks in C#."""
    # Sources
    USER_INPUT = "user_input"           # FromQuery, FromBody, Request.*
    NETWORK = "network"                 # HttpClient response
    FILE_READ = "file_read"             # File.ReadAllText
    ENVIRONMENT = "environment"         # Environment.GetEnvironmentVariable
    COMMAND_LINE = "command_line"       # args[], Environment.CommandLine
    DATABASE = "database"               # Database query results

    # Sinks
    SQL_QUERY = "sql_query"             # ExecuteSqlRaw, SqlCommand
    COMMAND_EXEC = "command_exec"       # Process.Start
    FILE_PATH = "file_path"             # File operations with path
    DESERIALIZATION = "deserialization" # BinaryFormatter, etc.
    XXE = "xxe"                         # XmlDocument.Load
    SSRF = "ssrf"                       # HttpClient, WebClient
    CODE_INJECTION = "code_injection"   # AppDomain.ExecuteAssembly
    LDAP_QUERY = "ldap_query"           # DirectorySearcher
    XPATH_QUERY = "xpath_query"         # SelectNodes, SelectSingleNode
    LOG_INJECTION = "log_injection"     # Logger calls


@dataclass
class TaintSummary:
    """Summary of a method's taint behavior."""
    name: str
    qualified_name: str

    # Parameters that are taint sources
    param_sources: Dict[int, TaintKind] = field(default_factory=dict)

    # Parameters that are taint sinks
    param_sinks: Dict[int, TaintKind] = field(default_factory=dict)

    # Parameters whose taint propagates to return value
    params_to_return: Set[int] = field(default_factory=set)

    # Whether return value is tainted
    return_tainted: bool = False
    return_taint_kind: Optional[TaintKind] = None

    # ASP.NET specific: parameters with [FromQuery], [FromBody], etc.
    user_input_params: Set[int] = field(default_factory=set)

    # Confidence in this summary (0.0-1.0)
    confidence: float = 0.5


@dataclass
class CallSite:
    """Represents a method call in the code."""
    callee: str                      # Method being called
    caller: str                      # Method making the call
    location: Location
    arguments: List[str]             # Argument expressions (as strings)
    return_var: Optional[str] = None # Variable receiving return value
    is_member_call: bool = False     # obj.Method() call


@dataclass
class CallGraph:
    """Call graph for interprocedural analysis."""
    # Method name -> list of call sites in that method
    calls_from: Dict[str, List[CallSite]] = field(default_factory=dict)

    # Method name -> list of call sites that call it
    calls_to: Dict[str, List[CallSite]] = field(default_factory=dict)

    # All method definitions found
    defined_methods: Set[str] = field(default_factory=set)

    # External methods (called but not defined in this file)
    external_methods: Set[str] = field(default_factory=set)


class CSharpInterproceduralTaintAnalyzer:
    """
    Analyzes taint flow across method boundaries in C# code.

    Usage:
        analyzer = CSharpInterproceduralTaintAnalyzer()
        taint_info = analyzer.analyze(source, filename)
        # taint_info contains cross-method vulnerabilities
    """

    # ASP.NET taint source attributes
    ASPNET_SOURCE_ATTRIBUTES = {
        'FromQuery', 'FromBody', 'FromForm', 'FromHeader',
        'FromRoute', 'FromServices', 'BindProperty'
    }

    # Known taint source methods (method -> (param_idx, taint_kind))
    # param_idx == -1 means return value is tainted
    TAINT_SOURCES = {
        # Console input
        'Console.ReadLine': (-1, TaintKind.USER_INPUT),
        'Console.Read': (-1, TaintKind.USER_INPUT),
        'ReadLine': (-1, TaintKind.USER_INPUT),

        # Request data
        'Request.Query': (-1, TaintKind.USER_INPUT),
        'Request.Form': (-1, TaintKind.USER_INPUT),
        'Request.Cookies': (-1, TaintKind.USER_INPUT),
        'Request.Headers': (-1, TaintKind.USER_INPUT),

        # File reading
        'File.ReadAllText': (-1, TaintKind.FILE_READ),
        'File.ReadAllLines': (-1, TaintKind.FILE_READ),
        'StreamReader.ReadToEnd': (-1, TaintKind.FILE_READ),
        'StreamReader.ReadLine': (-1, TaintKind.FILE_READ),

        # Environment
        'Environment.GetEnvironmentVariable': (-1, TaintKind.ENVIRONMENT),
        'GetEnvironmentVariable': (-1, TaintKind.ENVIRONMENT),

        # Network
        'HttpClient.GetStringAsync': (-1, TaintKind.NETWORK),
        'WebClient.DownloadString': (-1, TaintKind.NETWORK),
    }

    # Known taint sink methods (method -> (tainted_param_idx, sink_kind))
    TAINT_SINKS = {
        # SQL Injection
        'FromSqlRaw': (0, TaintKind.SQL_QUERY),
        'ExecuteSqlRaw': (0, TaintKind.SQL_QUERY),
        'ExecuteSqlCommand': (0, TaintKind.SQL_QUERY),
        'SqlCommand': (0, TaintKind.SQL_QUERY),
        'CreateQuery': (0, TaintKind.SQL_QUERY),
        'ExecuteStoreCommand': (0, TaintKind.SQL_QUERY),
        'ExecuteStoreQuery': (0, TaintKind.SQL_QUERY),
        'FullTextSqlQuery': (0, TaintKind.SQL_QUERY),

        # Command Injection
        'Process.Start': (0, TaintKind.COMMAND_EXEC),
        'Start': (0, TaintKind.COMMAND_EXEC),  # ProcessStartInfo.Start

        # Path Traversal
        'File.ReadAllText': (0, TaintKind.FILE_PATH),
        'File.WriteAllText': (0, TaintKind.FILE_PATH),
        'File.Delete': (0, TaintKind.FILE_PATH),
        'File.Open': (0, TaintKind.FILE_PATH),
        'StreamReader': (0, TaintKind.FILE_PATH),
        'StreamWriter': (0, TaintKind.FILE_PATH),

        # Deserialization
        'BinaryFormatter.Deserialize': (0, TaintKind.DESERIALIZATION),
        'Deserialize': (0, TaintKind.DESERIALIZATION),
        'BinaryMessageFormatter': (0, TaintKind.DESERIALIZATION),

        # XXE
        'XmlDocument.LoadXml': (0, TaintKind.XXE),
        'XmlDocument.Load': (0, TaintKind.XXE),
        'LoadXml': (0, TaintKind.XXE),
        'WriteRaw': (0, TaintKind.XXE),

        # SSRF
        'HttpClient.GetAsync': (0, TaintKind.SSRF),
        'WebClient.DownloadString': (0, TaintKind.SSRF),
        'WebRequest.Create': (0, TaintKind.SSRF),

        # Code Injection
        'AppDomain.ExecuteAssembly': (0, TaintKind.CODE_INJECTION),
        'ExecuteAssembly': (0, TaintKind.CODE_INJECTION),
        'Razor.RunCompile': (0, TaintKind.CODE_INJECTION),
        'RunCompile': (0, TaintKind.CODE_INJECTION),

        # LDAP
        'DirectorySearcher.Filter': (0, TaintKind.LDAP_QUERY),

        # XPath
        'SelectNodes': (0, TaintKind.XPATH_QUERY),
        'SelectSingleNode': (0, TaintKind.XPATH_QUERY),
    }

    # Methods that propagate taint from params to return value
    TAINT_PROPAGATORS = {
        'ToString': [0],
        'Substring': [0],
        'ToLower': [0],
        'ToUpper': [0],
        'Trim': [0],
        'Replace': [0],
        'Format': [0, 1],
        'Concat': [0, 1],
    }

    # Methods that propagate taint from one argument to another
    TAINT_ARG_PROPAGATORS = {
        'CopyTo': [(0, 1)],
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

        # Parser
        if HAS_TREE_SITTER:
            self.parser = Parser(Language(ts_csharp.language()))
        else:
            self.parser = None

        # Analysis state
        self._source: str = ""
        self._filename: str = ""
        self._lines: List[str] = []

        # Results
        self.call_graph = CallGraph()
        self.taint_summaries: Dict[str, TaintSummary] = {}

        # Current context
        self._current_method: Optional[str] = None
        self._current_class: Optional[str] = None
        self._current_namespace: Optional[str] = None

        # Initialize with known library method summaries
        self._init_library_summaries()

    def _init_library_summaries(self):
        """Initialize taint summaries for known library methods."""
        # Add source methods
        for method, (param_idx, kind) in self.TAINT_SOURCES.items():
            summary = TaintSummary(name=method, qualified_name=method)
            if param_idx == -1:
                summary.return_tainted = True
                summary.return_taint_kind = kind
            else:
                summary.param_sources[param_idx] = kind
            summary.confidence = 1.0
            self.taint_summaries[method] = summary

        # Add sink methods
        for method, (param_idx, kind) in self.TAINT_SINKS.items():
            if method not in self.taint_summaries:
                summary = TaintSummary(name=method, qualified_name=method)
            else:
                summary = self.taint_summaries[method]
            summary.param_sinks[param_idx] = kind
            summary.confidence = 1.0
            self.taint_summaries[method] = summary

        # Add propagator methods
        for method, params in self.TAINT_PROPAGATORS.items():
            if method not in self.taint_summaries:
                summary = TaintSummary(name=method, qualified_name=method)
            else:
                summary = self.taint_summaries[method]
            summary.params_to_return = set(params)
            summary.confidence = 1.0
            self.taint_summaries[method] = summary

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
            - taint_summaries: Dict of method taint summaries
            - vulnerabilities: List of cross-method vulnerabilities found
        """
        if not HAS_TREE_SITTER:
            return {
                'call_graph': CallGraph(),
                'taint_summaries': {},
                'vulnerabilities': []
            }

        self._source = source
        self._filename = filename
        self._lines = source.split('\n')
        self.call_graph = CallGraph()

        tree = self.parser.parse(bytes(source, 'utf8'))

        if self.verbose:
            print(f"[IPA] Analyzing C# file: {filename}")

        # Pass 1: Find all method definitions and their call sites
        self._build_call_graph(tree.root_node)

        # Pass 2: Build taint summaries for defined methods
        self._build_taint_summaries(tree.root_node)

        # Pass 3: Propagate taint through call graph
        vulnerabilities = self._propagate_taint()

        if self.verbose:
            print(f"[IPA] Call graph: {len(self.call_graph.defined_methods)} methods, "
                  f"{sum(len(v) for v in self.call_graph.calls_from.values())} call sites")
            print(f"[IPA] Found {len(vulnerabilities)} cross-method vulnerabilities")

        return {
            'call_graph': self.call_graph,
            'taint_summaries': self.taint_summaries,
            'vulnerabilities': vulnerabilities
        }

    # =========================================================================
    # Pass 1: Build call graph
    # =========================================================================

    def _build_call_graph(self, node: Any):
        """Extract method definitions and call sites."""
        if node.type == 'namespace_declaration':
            old_ns = self._current_namespace
            name_node = node.child_by_field_name('name')
            if name_node:
                self._current_namespace = self._get_text(name_node)

            for child in node.children:
                self._build_call_graph(child)

            self._current_namespace = old_ns

        elif node.type == 'class_declaration':
            old_class = self._current_class
            name_node = node.child_by_field_name('name')
            if name_node:
                self._current_class = self._get_text(name_node)

            for child in node.children:
                self._build_call_graph(child)

            self._current_class = old_class

        elif node.type == 'method_declaration':
            self._process_method_def(node)

        elif node.type == 'constructor_declaration':
            self._process_method_def(node, is_constructor=True)

        else:
            for child in node.children:
                self._build_call_graph(child)

    def _process_method_def(self, node: Any, is_constructor: bool = False):
        """Process a method definition node."""
        # Get method name
        if is_constructor:
            method_name = self._current_class or "ctor"
        else:
            name_node = node.child_by_field_name('name')
            method_name = self._get_text(name_node) if name_node else None

        if not method_name:
            return

        # Build qualified name
        parts = []
        if self._current_namespace:
            parts.append(self._current_namespace)
        if self._current_class:
            parts.append(self._current_class)
        parts.append(method_name)
        qualified_name = ".".join(parts)

        self.call_graph.defined_methods.add(qualified_name)
        self.call_graph.defined_methods.add(method_name)  # Also add simple name

        # Check for ASP.NET controller attributes (taint sources)
        self._detect_aspnet_sources(node, method_name, qualified_name)

        # Process method body for call sites
        old_method = self._current_method
        self._current_method = qualified_name

        body = node.child_by_field_name('body')
        if body:
            self._find_call_sites(body)

        self._current_method = old_method

    def _detect_aspnet_sources(self, node: Any, method_name: str, qualified_name: str):
        """Detect ASP.NET controller attributes that indicate taint sources."""
        # Look for [FromQuery], [FromBody], etc. on parameters
        params_node = node.child_by_field_name('parameters')
        if not params_node:
            return

        summary = self.taint_summaries.get(method_name) or TaintSummary(
            name=method_name, qualified_name=qualified_name
        )

        param_idx = 0
        for child in params_node.children:
            if child.type == 'parameter':
                # Check for attribute_list
                for attr_child in child.children:
                    if attr_child.type == 'attribute_list':
                        attr_text = self._get_text(attr_child)
                        for source_attr in self.ASPNET_SOURCE_ATTRIBUTES:
                            if source_attr in attr_text:
                                summary.param_sources[param_idx] = TaintKind.USER_INPUT
                                summary.user_input_params.add(param_idx)
                                break
                param_idx += 1

        if summary.user_input_params or summary.param_sources:
            summary.confidence = 0.9
            self.taint_summaries[method_name] = summary
            self.taint_summaries[qualified_name] = summary

    def _find_call_sites(self, node: Any):
        """Find all method call sites in a node."""
        if node.type == 'invocation_expression':
            self._process_call_expr(node)
        elif node.type == 'object_creation_expression':
            self._process_object_creation(node)

        for child in node.children:
            self._find_call_sites(child)

    def _process_call_expr(self, node: Any):
        """Process a method call expression."""
        func_node = node.child_by_field_name('function')
        if not func_node:
            # Try to get the first child
            for child in node.children:
                if child.type in ('identifier', 'member_access_expression',
                                  'generic_name', 'qualified_name'):
                    func_node = child
                    break

        if not func_node:
            return

        callee = self._get_text(func_node)
        is_member_call = False

        # Handle member access (e.g., obj.Method())
        if func_node.type == 'member_access_expression':
            is_member_call = True
            name_node = func_node.child_by_field_name('name')
            if name_node:
                callee = self._get_text(name_node)

        if not callee:
            return

        # Extract arguments
        args_node = node.child_by_field_name('arguments')
        if not args_node:
            # Look for argument_list child
            for child in node.children:
                if child.type == 'argument_list':
                    args_node = child
                    break

        arguments = []
        if args_node:
            for child in args_node.children:
                if child.type == 'argument':
                    arguments.append(self._get_text(child))
                elif child.type not in ('(', ')', ','):
                    arguments.append(self._get_text(child))

        # Create call site
        location = Location(
            file=self._filename,
            line=node.start_point[0] + 1,
            column=node.start_point[1] + 1
        )

        call_site = CallSite(
            callee=callee,
            caller=self._current_method or "<global>",
            location=location,
            arguments=arguments,
            is_member_call=is_member_call
        )

        # Check if this is an assignment (return value captured)
        parent = node.parent
        if parent and parent.type in ('assignment_expression', 'variable_declarator',
                                       'equals_value_clause'):
            if parent.type == 'assignment_expression':
                left = parent.child_by_field_name('left')
                if left:
                    call_site.return_var = self._get_text(left)
            elif parent.type == 'variable_declarator':
                name_node = parent.child_by_field_name('name')
                if name_node:
                    call_site.return_var = self._get_text(name_node)

        # Add to call graph
        if self._current_method not in self.call_graph.calls_from:
            self.call_graph.calls_from[self._current_method] = []
        self.call_graph.calls_from[self._current_method].append(call_site)

        if callee not in self.call_graph.calls_to:
            self.call_graph.calls_to[callee] = []
        self.call_graph.calls_to[callee].append(call_site)

        # Track external methods
        if callee not in self.call_graph.defined_methods:
            self.call_graph.external_methods.add(callee)

    def _process_object_creation(self, node: Any):
        """Process new object creation (could be dangerous, e.g., new SqlCommand)."""
        type_node = node.child_by_field_name('type')
        if not type_node:
            return

        type_name = self._get_text(type_node)

        # Check for dangerous constructors
        dangerous_ctors = ['SqlCommand', 'ProcessStartInfo', 'BinaryFormatter',
                          'BinaryMessageFormatter', 'DirectorySearcher']

        if type_name in dangerous_ctors:
            # Extract arguments
            args_node = node.child_by_field_name('arguments')
            arguments = []
            if args_node:
                for child in args_node.children:
                    if child.type == 'argument':
                        arguments.append(self._get_text(child))
                    elif child.type not in ('(', ')', ','):
                        arguments.append(self._get_text(child))

            location = Location(
                file=self._filename,
                line=node.start_point[0] + 1,
                column=node.start_point[1] + 1
            )

            call_site = CallSite(
                callee=type_name,
                caller=self._current_method or "<global>",
                location=location,
                arguments=arguments,
                is_member_call=False
            )

            if self._current_method not in self.call_graph.calls_from:
                self.call_graph.calls_from[self._current_method] = []
            self.call_graph.calls_from[self._current_method].append(call_site)

    # =========================================================================
    # Pass 2: Build taint summaries for defined methods
    # =========================================================================

    def _build_taint_summaries(self, node: Any):
        """Build taint summaries for user-defined methods."""
        if node.type == 'method_declaration':
            self._analyze_method_taint(node)
        elif node.type == 'constructor_declaration':
            self._analyze_method_taint(node, is_constructor=True)
        else:
            for child in node.children:
                self._build_taint_summaries(child)

    def _analyze_method_taint(self, node: Any, is_constructor: bool = False):
        """Analyze a method's taint behavior."""
        if is_constructor:
            method_name = self._current_class or "ctor"
        else:
            name_node = node.child_by_field_name('name')
            method_name = self._get_text(name_node) if name_node else None

        if not method_name:
            return

        # Skip if already have a high-confidence summary
        if method_name in self.taint_summaries:
            if self.taint_summaries[method_name].confidence >= 0.9:
                return

        parts = []
        if self._current_namespace:
            parts.append(self._current_namespace)
        if self._current_class:
            parts.append(self._current_class)
        parts.append(method_name)
        qualified_name = ".".join(parts)

        summary = self.taint_summaries.get(method_name) or TaintSummary(
            name=method_name, qualified_name=qualified_name
        )

        # Extract parameters
        params_node = node.child_by_field_name('parameters')
        param_names: Dict[str, int] = {}
        if params_node:
            param_idx = 0
            for child in params_node.children:
                if child.type == 'parameter':
                    name_node = child.child_by_field_name('name')
                    if name_node:
                        param_name = self._get_text(name_node)
                        param_names[param_name] = param_idx
                    param_idx += 1

        # Analyze method body
        body = node.child_by_field_name('body')
        if body:
            self._analyze_body_taint(body, summary, param_names)

        summary.confidence = 0.7
        self.taint_summaries[method_name] = summary
        self.taint_summaries[qualified_name] = summary

    def _analyze_body_taint(self, body: Any, summary: TaintSummary,
                           param_names: Dict[str, int]):
        """Analyze method body for taint sources, sinks, and propagation."""
        tainted_vars: Set[str] = set()

        # Mark parameters that are known taint sources
        for param, idx in param_names.items():
            if idx in summary.param_sources or idx in summary.user_input_params:
                tainted_vars.add(param)

        self._analyze_node_taint(body, summary, param_names, tainted_vars)

    def _analyze_node_taint(self, node: Any, summary: TaintSummary,
                           param_names: Dict[str, int], tainted_vars: Set[str]):
        """Recursively analyze taint in a node."""
        if node.type == 'invocation_expression':
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
            for child in node.children:
                if child.type in ('identifier', 'member_access_expression'):
                    func_node = child
                    break

        if not func_node:
            return

        callee = self._get_text(func_node)
        if func_node.type == 'member_access_expression':
            name_node = func_node.child_by_field_name('name')
            if name_node:
                callee = self._get_text(name_node)

        # Get arguments
        args_node = node.child_by_field_name('arguments')
        if not args_node:
            for child in node.children:
                if child.type == 'argument_list':
                    args_node = child
                    break

        args = []
        if args_node:
            for child in args_node.children:
                if child.type == 'argument':
                    args.append(self._get_text(child))
                elif child.type not in ('(', ')', ','):
                    args.append(self._get_text(child))

        # Check if callee is a known taint source
        if callee in self.TAINT_SOURCES:
            src_param, kind = self.TAINT_SOURCES[callee]
            if src_param == -1:
                # Return value is tainted
                pass
            elif src_param < len(args):
                tainted_arg = args[src_param]
                tainted_vars.add(tainted_arg)
                if tainted_arg in param_names:
                    summary.param_sources[param_names[tainted_arg]] = kind

        # Check if passing tainted data to a sink
        if callee in self.TAINT_SINKS:
            sink_param, kind = self.TAINT_SINKS[callee]
            if sink_param < len(args):
                arg = args[sink_param]
                if arg in tainted_vars or arg in param_names:
                    if arg in param_names:
                        summary.param_sinks[param_names[arg]] = kind

    def _check_return_taint(self, node: Any, summary: TaintSummary,
                           param_names: Dict[str, int], tainted_vars: Set[str]):
        """Check if return value propagates taint from parameters."""
        for child in node.children:
            if child.type not in ('return', ';'):
                returned_expr = self._get_text(child)

                if returned_expr in tainted_vars:
                    summary.return_tainted = True

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

            if right_name in tainted_vars:
                tainted_vars.add(left_name)

            if right_name in param_names:
                tainted_vars.add(left_name)

    # =========================================================================
    # Pass 3: Propagate taint through call graph
    # =========================================================================

    def _propagate_taint(self) -> List[Dict[str, Any]]:
        """
        Propagate taint through call graph and find vulnerabilities.

        Returns list of cross-method vulnerabilities.
        """
        vulnerabilities = []

        for caller, call_sites in self.call_graph.calls_from.items():
            caller_tainted = self._get_tainted_vars_in_method(caller)

            for site in call_sites:
                callee = site.callee
                callee_summary = self.taint_summaries.get(callee)

                if not callee_summary:
                    continue

                # Check if passing tainted data to sink parameter
                for param_idx, sink_kind in callee_summary.param_sinks.items():
                    if param_idx < len(site.arguments):
                        arg = site.arguments[param_idx]

                        if arg in caller_tainted or self._is_tainted_expression(arg, caller_tainted):
                            vuln = {
                                'type': 'cross_method_taint',
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
                    caller_tainted.add(site.return_var)

                # Update taint state for source methods
                for param_idx, src_kind in callee_summary.param_sources.items():
                    if param_idx < len(site.arguments):
                        arg = site.arguments[param_idx]
                        caller_tainted.add(arg)

        return vulnerabilities

    def _get_tainted_vars_in_method(self, method_name: str) -> Set[str]:
        """Get the set of tainted variables in a method."""
        tainted = set()

        # Get method's own taint sources from its summary
        method_summary = self.taint_summaries.get(method_name)
        if method_summary:
            # Parameters that are ASP.NET user input sources
            for param_idx in method_summary.user_input_params:
                # We need to get the actual param name, but we don't have it here
                # This is tracked when the summary was built
                pass

        # Get call sites in this method
        call_sites = self.call_graph.calls_from.get(method_name, [])

        # Pass 1: Find direct taint sources
        for site in call_sites:
            callee = site.callee
            callee_summary = self.taint_summaries.get(callee)

            if callee_summary:
                if site.return_var and callee_summary.return_tainted:
                    tainted.add(site.return_var)

                for param_idx, src_kind in callee_summary.param_sources.items():
                    if param_idx < len(site.arguments):
                        arg = site.arguments[param_idx]
                        tainted.add(arg)

            # Check return value propagators
            if callee in self.TAINT_PROPAGATORS:
                propagate_from = self.TAINT_PROPAGATORS[callee]
                for idx in propagate_from:
                    if idx < len(site.arguments):
                        arg = site.arguments[idx]
                        if self._is_tainted_expression(arg, tainted) or arg in tainted:
                            if site.return_var:
                                tainted.add(site.return_var)

        # Pass 2: Iteratively propagate taint
        changed = True
        max_iterations = 10
        iterations = 0

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for site in call_sites:
                callee = site.callee

                if callee in self.TAINT_ARG_PROPAGATORS:
                    for src_idx, dest_idx in self.TAINT_ARG_PROPAGATORS[callee]:
                        if src_idx < len(site.arguments) and dest_idx < len(site.arguments):
                            src_arg = site.arguments[src_idx]
                            dest_arg = site.arguments[dest_idx]

                            if src_arg in tainted or self._is_tainted_expression(src_arg, tainted):
                                if dest_arg not in tainted:
                                    tainted.add(dest_arg)
                                    changed = True

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
        stripped = expr.strip()
        if stripped.startswith('"') or stripped.startswith("'"):
            return False
        if stripped.startswith('@"'):
            return False

        for var in tainted_vars:
            if not var:
                continue
            if expr == var:
                return True
            pattern = r'\b' + re.escape(var) + r'\b'
            if re.search(pattern, expr):
                return True

        return False


def analyze_csharp_taint(source: str, filename: str,
                         verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Convenience function for C# interprocedural taint analysis.

    Args:
        source: C# source code
        filename: Filename for location tracking
        verbose: Enable verbose output

    Returns:
        List of vulnerability dictionaries
    """
    analyzer = CSharpInterproceduralTaintAnalyzer(verbose=verbose)
    result = analyzer.analyze(source, filename)
    return result.get('vulnerabilities', [])
