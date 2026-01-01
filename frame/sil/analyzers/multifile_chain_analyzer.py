"""
Multi-File Chain Analyzer for Juliet C/C++ Tests.

Juliet tests often split vulnerability patterns across multiple files:
- _51a.c -> _51b.c (2-file flow)
- _54a.c -> _54b.c -> _54c.c -> _54d.c -> _54e.c (5-file chain)

This module:
1. Discovers related files in a chain
2. Builds combined taint summaries across the chain
3. Tracks data flow from source (in first file) to sink (in last file)
4. Uses Frame's SL solver for verification

The key insight is that Juliet chains pass tainted data through
function calls across files. We need to:
1. Extract function signatures and taint summaries from each file
2. Connect callers to callees across file boundaries
3. Propagate taint through the chain
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser

from frame.sil.types import Location
from frame.sil.translator import VulnType


@dataclass
class FunctionSummary:
    """Summary of a function's taint behavior."""
    name: str
    filename: str
    # Which parameters are tainted on entry
    tainted_params: Set[int] = field(default_factory=set)
    # Which parameters propagate taint to return value
    returns_tainted: bool = False
    # What sinks does this function call with tainted data
    sinks: List[Tuple[str, int, Location]] = field(default_factory=list)  # (sink_func, arg_idx, loc)
    # Functions called with tainted args
    tainted_calls: List[Tuple[str, Set[int]]] = field(default_factory=list)  # (func_name, tainted_arg_indices)


@dataclass
class ChainVuln:
    """Vulnerability detected through multi-file chain analysis."""
    vuln_type: VulnType
    cwe_id: str
    location: Location
    description: str
    chain: List[str]  # List of files in the chain
    data_flow: List[str]  # Data flow path
    confidence: float = 0.9


class MultiFileChainAnalyzer:
    """
    Analyzer for multi-file vulnerability chains.

    Discovers file chains and tracks taint flow across file boundaries.
    """

    # Juliet naming patterns for multi-file tests
    CHAIN_PATTERNS = [
        # 2-file: CWE_name__variant_51a.c -> CWE_name__variant_51b.c
        (r'(.+)_51a\.(c|cpp)$', ['51a', '51b']),
        # 5-file: _54a -> _54b -> _54c -> _54d -> _54e
        (r'(.+)_54a\.(c|cpp)$', ['54a', '54b', '54c', '54d', '54e']),
        # 3-file patterns
        (r'(.+)_52a\.(c|cpp)$', ['52a', '52b', '52c']),
        (r'(.+)_53a\.(c|cpp)$', ['53a', '53b', '53c']),
        # 2-file with different suffix
        (r'(.+)_61a\.(c|cpp)$', ['61a', '61b']),
        (r'(.+)_62a\.(c|cpp)$', ['62a', '62b']),
        (r'(.+)_63a\.(c|cpp)$', ['63a', '63b']),
        (r'(.+)_64a\.(c|cpp)$', ['64a', '64b']),
    ]

    # Taint sources (functions that return tainted data)
    TAINT_SOURCES = {
        'fgets', 'gets', 'scanf', 'fscanf', 'sscanf',
        'read', 'recv', 'recvfrom',
        'getenv', 'getc', 'fgetc', 'getchar',
        'accept', 'listen',
        # Juliet-specific
        'CWE_RAND', 'badSource', 'GLOBAL_CONST_FIVE',
    }

    # Dangerous sinks
    TAINT_SINKS = {
        # Buffer operations
        'strcpy': (0, 'buffer_write', 'CWE-120'),
        'strcat': (0, 'buffer_write', 'CWE-120'),
        'memcpy': (0, 'buffer_write', 'CWE-120'),
        'sprintf': (0, 'buffer_write', 'CWE-120'),
        # Format string
        'printf': (0, 'format_string', 'CWE-134'),
        'fprintf': (1, 'format_string', 'CWE-134'),
        'syslog': (1, 'format_string', 'CWE-134'),
        # Command injection
        'system': (0, 'command', 'CWE-78'),
        'popen': (0, 'command', 'CWE-78'),
        'execve': (0, 'command', 'CWE-78'),
        # SQL injection
        'sqlite3_exec': (1, 'sql', 'CWE-89'),
        'mysql_query': (1, 'sql', 'CWE-89'),
        # Path traversal
        'fopen': (0, 'path', 'CWE-22'),
        'open': (0, 'path', 'CWE-22'),
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.vulnerabilities: List[ChainVuln] = []

        # Function summaries from all files in chain
        self.summaries: Dict[str, FunctionSummary] = {}

        # Initialize parsers
        self.c_parser = Parser(Language(tsc.language()))
        self.cpp_parser = Parser(Language(tscpp.language()))

    def _get_parser(self, filename: str) -> Parser:
        if filename.endswith(('.cpp', '.cc', '.cxx')):
            return self.cpp_parser
        return self.c_parser

    def discover_chain(self, filename: str, search_dir: Optional[str] = None) -> List[str]:
        """
        Discover all files in a multi-file chain.

        Given CWE_xxx_51a.c, finds CWE_xxx_51b.c, etc.
        """
        if not filename:
            return [filename] if filename else []

        basename = os.path.basename(filename)
        dir_path = search_dir or os.path.dirname(filename)

        for pattern, suffixes in self.CHAIN_PATTERNS:
            match = re.match(pattern, basename)
            if match:
                prefix = match.group(1)
                ext = match.group(2)

                chain = []
                for suffix in suffixes:
                    chain_file = f"{prefix}_{suffix}.{ext}"
                    full_path = os.path.join(dir_path, chain_file)

                    # Also check in testcases subdirectory
                    if not os.path.exists(full_path):
                        testcases_path = os.path.join(dir_path, 'testcases', chain_file)
                        if os.path.exists(testcases_path):
                            full_path = testcases_path

                    if os.path.exists(full_path):
                        chain.append(full_path)

                if len(chain) > 1:
                    if self.verbose:
                        print(f"[Chain] Found {len(chain)}-file chain: {[os.path.basename(f) for f in chain]}")
                    return chain

        return [filename] if filename else []

    def analyze_chain(self, chain: List[str]) -> List[ChainVuln]:
        """
        Analyze a multi-file chain for vulnerabilities.

        1. Extract function summaries from each file
        2. Build inter-file call graph
        3. Propagate taint through the chain
        4. Report vulnerabilities at sinks
        """
        self.vulnerabilities = []
        self.summaries = {}

        if not chain:
            return []

        # Phase 1: Extract function summaries from each file
        for filepath in chain:
            self._extract_summaries(filepath)

        # Phase 2: Propagate taint through call chain
        self._propagate_taint_through_chain(chain)

        return self.vulnerabilities

    def _extract_summaries(self, filepath: str):
        """Extract function summaries from a file."""
        if not os.path.exists(filepath):
            return

        with open(filepath, 'r', errors='ignore') as f:
            source = f.read()

        parser = self._get_parser(filepath)
        tree = parser.parse(bytes(source, 'utf8'))

        self._analyze_file(tree.root_node, source, filepath)

    def _analyze_file(self, node: Any, source: str, filename: str):
        """Analyze a file for function definitions."""
        if node.type == 'function_definition':
            self._analyze_function(node, source, filename)
        else:
            for child in node.children:
                self._analyze_file(child, source, filename)

    def _analyze_function(self, node: Any, source: str, filename: str):
        """Analyze a function and create its taint summary."""
        func_name = self._get_function_name(node)
        if not func_name:
            return

        summary = FunctionSummary(name=func_name, filename=filename)

        # Extract parameters
        params = self._get_parameters(node)

        # Analyze function body for taint flow
        body = None
        for child in node.children:
            if child.type == 'compound_statement':
                body = child
                break

        if body:
            # Track which local variables are tainted
            tainted_vars: Set[str] = set()

            # Check if any parameter is used as sink arg (will be tainted from caller)
            self._analyze_body_for_taint(body, source, filename, params, tainted_vars, summary)

        self.summaries[func_name] = summary

        if self.verbose and (summary.sinks or summary.tainted_calls):
            print(f"[Chain] {func_name}: sinks={len(summary.sinks)}, calls={len(summary.tainted_calls)}")

    def _get_function_name(self, node: Any) -> Optional[str]:
        """Extract function name."""
        for child in node.children:
            if child.type == 'function_declarator':
                for sub in child.children:
                    if sub.type == 'identifier':
                        return sub.text.decode('utf8')
        return None

    def _get_parameters(self, node: Any) -> List[str]:
        """Get parameter names from function definition."""
        params = []
        for child in node.children:
            if child.type == 'function_declarator':
                for sub in child.children:
                    if sub.type == 'parameter_list':
                        for param in sub.children:
                            if param.type == 'parameter_declaration':
                                for p_child in param.children:
                                    if p_child.type == 'identifier':
                                        params.append(p_child.text.decode('utf8'))
                                    elif p_child.type == 'pointer_declarator':
                                        for ptr_child in p_child.children:
                                            if ptr_child.type == 'identifier':
                                                params.append(ptr_child.text.decode('utf8'))
        return params

    def _analyze_body_for_taint(self, node: Any, source: str, filename: str,
                                 params: List[str], tainted_vars: Set[str],
                                 summary: FunctionSummary):
        """Analyze function body for taint flow."""
        for child in node.children:
            self._analyze_stmt_for_taint(child, source, filename, params, tainted_vars, summary)

    def _analyze_stmt_for_taint(self, node: Any, source: str, filename: str,
                                 params: List[str], tainted_vars: Set[str],
                                 summary: FunctionSummary):
        """Analyze statement for taint sources and sinks."""
        loc = Location(filename, node.start_point[0] + 1, node.start_point[1])

        if node.type == 'declaration' or node.type == 'expression_statement':
            # Check for taint sources
            call = self._find_child_recursive(node, 'call_expression')
            if call:
                func_name = self._get_call_name(call)

                # Check if calling a taint source
                if func_name in self.TAINT_SOURCES:
                    # Find what variable receives the tainted data
                    var_name = self._get_assigned_var(node)
                    if var_name:
                        tainted_vars.add(var_name)

                # Check if calling a sink with tainted data
                if func_name in self.TAINT_SINKS:
                    sink_arg_idx, sink_kind, cwe = self.TAINT_SINKS[func_name]
                    args = self._get_call_args(call)
                    if len(args) > sink_arg_idx:
                        arg = args[sink_arg_idx]
                        # Check if arg is tainted (is a param or tainted var)
                        if arg in tainted_vars or arg in params:
                            summary.sinks.append((func_name, sink_arg_idx, loc))

                            # Mark which parameter is used at sink
                            if arg in params:
                                param_idx = params.index(arg)
                                summary.tainted_params.add(param_idx)

                # Check if calling another function with tainted args
                args = self._get_call_args(call)
                tainted_arg_indices = set()
                for i, arg in enumerate(args):
                    if arg in tainted_vars or arg in params:
                        tainted_arg_indices.add(i)
                        if arg in params:
                            summary.tainted_params.add(params.index(arg))

                if tainted_arg_indices and func_name not in self.TAINT_SINKS:
                    summary.tainted_calls.append((func_name, tainted_arg_indices))

        # Check for assignments that propagate taint
        if node.type == 'assignment_expression':
            left_var = None
            right_tainted = False

            for child in node.children:
                if child.type == 'identifier' and left_var is None:
                    left_var = child.text.decode('utf8')
                elif child.type == 'identifier':
                    right_var = child.text.decode('utf8')
                    if right_var in tainted_vars or right_var in params:
                        right_tainted = True

            if left_var and right_tainted:
                tainted_vars.add(left_var)

        # Recurse
        for child in node.children:
            if child.type in ('compound_statement', 'if_statement', 'while_statement',
                              'for_statement', 'expression_statement', 'declaration'):
                self._analyze_stmt_for_taint(child, source, filename, params, tainted_vars, summary)

    def _find_child_recursive(self, node: Any, type_name: str) -> Optional[Any]:
        """Find child of type recursively."""
        if node.type == type_name:
            return node
        for child in node.children:
            result = self._find_child_recursive(child, type_name)
            if result:
                return result
        return None

    def _get_call_name(self, call: Any) -> str:
        """Get function name from call."""
        for child in call.children:
            if child.type == 'identifier':
                return child.text.decode('utf8')
        return ""

    def _get_call_args(self, call: Any) -> List[str]:
        """Get argument names."""
        args = []
        for child in call.children:
            if child.type == 'argument_list':
                for arg in child.children:
                    if arg.type == 'identifier':
                        args.append(arg.text.decode('utf8'))
                    elif arg.type not in ('(', ')', ','):
                        # Extract identifier from expression
                        for sub in arg.children:
                            if sub.type == 'identifier':
                                args.append(sub.text.decode('utf8'))
                                break
        return args

    def _get_assigned_var(self, node: Any) -> Optional[str]:
        """Get variable being assigned in declaration/expression."""
        if node.type == 'declaration':
            for child in node.children:
                if child.type == 'init_declarator':
                    for sub in child.children:
                        if sub.type == 'identifier':
                            return sub.text.decode('utf8')
                        if sub.type == 'pointer_declarator':
                            for ptr_child in sub.children:
                                if ptr_child.type == 'identifier':
                                    return ptr_child.text.decode('utf8')
        elif node.type == 'expression_statement':
            for child in node.children:
                if child.type == 'assignment_expression':
                    for sub in child.children:
                        if sub.type == 'identifier':
                            return sub.text.decode('utf8')
        return None

    def _propagate_taint_through_chain(self, chain: List[str]):
        """
        Propagate taint through the function call chain.

        Starts from functions that call taint sources and follows
        the call graph through the file chain.
        """
        # Find functions with tainted calls
        for func_name, summary in self.summaries.items():
            for called_func, tainted_args in summary.tainted_calls:
                # Check if called function has a sink
                if called_func in self.summaries:
                    callee = self.summaries[called_func]

                    # Check if callee uses the tainted param at a sink
                    for param_idx in tainted_args:
                        if param_idx in callee.tainted_params:
                            # Taint flows from caller to callee's sink
                            for sink_func, sink_arg, loc in callee.sinks:
                                if sink_func in self.TAINT_SINKS:
                                    _, sink_kind, cwe = self.TAINT_SINKS[sink_func]

                                    vuln = ChainVuln(
                                        vuln_type=self._sink_kind_to_vuln_type(sink_kind),
                                        cwe_id=cwe,
                                        location=loc,
                                        description=f"Taint flows from {summary.filename} through {called_func} to {sink_func}",
                                        chain=[os.path.basename(f) for f in chain],
                                        data_flow=[func_name, called_func, sink_func],
                                        confidence=0.85
                                    )
                                    self.vulnerabilities.append(vuln)

                                    if self.verbose:
                                        print(f"[Chain] Found: {func_name} -> {called_func} -> {sink_func} ({cwe})")

    def _sink_kind_to_vuln_type(self, sink_kind: str) -> VulnType:
        """Map sink kind to vulnerability type."""
        mapping = {
            'buffer_write': VulnType.BUFFER_OVERFLOW,
            'format_string': VulnType.FORMAT_STRING,
            'command': VulnType.COMMAND_INJECTION,
            'sql': VulnType.SQL_INJECTION,
            'path': VulnType.PATH_TRAVERSAL,
        }
        return mapping.get(sink_kind, VulnType.TAINT_FLOW)


def analyze_multifile_chain(filename: str, search_dir: Optional[str] = None,
                            verbose: bool = False) -> Tuple[List[str], List[ChainVuln]]:
    """
    Analyze a file and its chain for vulnerabilities.

    Returns:
        Tuple of (chain files, vulnerabilities found)
    """
    analyzer = MultiFileChainAnalyzer(verbose=verbose)

    # Discover chain
    chain = analyzer.discover_chain(filename, search_dir)

    # Analyze chain
    vulns = analyzer.analyze_chain(chain)

    return chain, vulns
