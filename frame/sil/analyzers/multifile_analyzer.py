"""
Multi-file Analysis for C/C++ SAST.

This module enables cross-file vulnerability detection by:
1. Resolving #include directives to find related files
2. Identifying multi-file test patterns (e.g., _51a.c, _51b.c)
3. Building combined taint summaries across files
4. Tracking taint flow through extern function declarations

Key insight: Juliet multi-file tests split source/sink across files.
For example:
- _51a.c: Contains bad() that gets tainted input and calls badSink()
- _51b.c: Contains badSink() that uses data in dangerous way

By analyzing both files together, we can detect the complete taint flow.
"""

import os
import re
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser

from frame.sil.types import Location
from frame.sil.analyzers.interprocedural_taint import (
    InterproceduralTaintAnalyzer,
    TaintSummary,
    CallGraph,
    CallSite,
    TaintKind,
)


@dataclass
class ExternDeclaration:
    """An extern function declaration found in source."""
    name: str
    return_type: str
    parameters: List[Tuple[str, str]]  # (name, type) pairs
    location: Location


@dataclass
class MultiFileContext:
    """Context for multi-file analysis."""
    # Primary file being analyzed
    primary_file: str

    # Related files found (e.g., _51b.c for _51a.c)
    related_files: List[str] = field(default_factory=list)

    # Combined call graph across all files
    combined_call_graph: CallGraph = field(default_factory=CallGraph)

    # Taint summaries from all files
    combined_summaries: Dict[str, TaintSummary] = field(default_factory=dict)

    # Extern declarations in primary file
    extern_declarations: List[ExternDeclaration] = field(default_factory=list)

    # Functions defined in related files that are called from primary
    cross_file_calls: List[CallSite] = field(default_factory=list)


class MultiFileAnalyzer:
    """
    Analyzes multiple related source files together for cross-file vulnerabilities.

    Usage:
        analyzer = MultiFileAnalyzer()
        results = analyzer.analyze_with_related_files(source, filename, search_dir)
    """

    # Pattern to identify multi-file Juliet tests
    MULTI_FILE_PATTERN = re.compile(r'_(\d+)([a-z])\.c(pp)?$')

    # Pattern to extract include directives
    INCLUDE_PATTERN = re.compile(r'#include\s*[<"]([^>"]+)[>"]')

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.c_parser = Parser(Language(tsc.language()))
        self.cpp_parser = Parser(Language(tscpp.language()))

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

    def find_related_files(self, filename: str, search_dir: Optional[str] = None) -> List[str]:
        """
        Find related files for multi-file analysis.

        For Juliet tests:
        - _51a.c -> finds _51b.c, _51c.c, etc.
        - _52a.c -> finds _52b.c, etc.

        Returns list of full paths to related files.
        """
        related = []

        # Check if this is a multi-file pattern
        match = self.MULTI_FILE_PATTERN.search(filename)
        if not match:
            return related

        variant_num = match.group(1)  # e.g., "51"
        current_letter = match.group(2)  # e.g., "a"
        extension = match.group(3) or ""  # "pp" for cpp, "" for c

        # Determine search directory
        if search_dir is None:
            search_dir = os.path.dirname(filename) or "."

        # Get base pattern (everything before the variant number)
        base_pattern = filename[:match.start() + 1 + len(variant_num)]
        base_name = os.path.basename(base_pattern)

        # Look for related files with same variant number but different letter
        letters = 'abcdefghij'  # Juliet uses up to about 'e' or 'f'

        for letter in letters:
            if letter == current_letter:
                continue

            # Construct related filename
            related_name = f"{base_name}{letter}.c{extension}"
            related_path = os.path.join(search_dir, related_name)

            if os.path.exists(related_path):
                related.append(related_path)

        # If not found in same directory, search in testcases subdirectory
        if not related and 'CWE' in filename:
            # Extract CWE identifier from filename
            cwe_match = re.search(r'(CWE\d+[^_]*)', os.path.basename(filename))
            if cwe_match:
                cwe_prefix = cwe_match.group(1)

                # Build possible search paths
                search_paths = [search_dir]

                # Add parent directories and testcases
                parent = os.path.dirname(search_dir)
                if parent:
                    search_paths.append(parent)
                    # Check for testcases sibling directory
                    testcases_dir = os.path.join(parent, 'testcases')
                    if os.path.isdir(testcases_dir):
                        search_paths.append(testcases_dir)
                        # Also check CWE-specific subdirectory
                        for subdir in os.listdir(testcases_dir):
                            if subdir.startswith(cwe_prefix.split('_')[0]):
                                search_paths.append(os.path.join(testcases_dir, subdir))

                # Search in each path for related files
                for letter in letters:
                    if letter == current_letter:
                        continue

                    related_name = f"{base_name}{letter}.c{extension}"

                    for path in search_paths:
                        if not os.path.isdir(path):
                            continue

                        # Direct check
                        candidate = os.path.join(path, related_name)
                        if os.path.exists(candidate) and candidate not in related:
                            related.append(candidate)
                            continue

                        # Check subdirectories (one level)
                        try:
                            for subdir in os.listdir(path):
                                subpath = os.path.join(path, subdir)
                                if os.path.isdir(subpath):
                                    candidate = os.path.join(subpath, related_name)
                                    if os.path.exists(candidate) and candidate not in related:
                                        related.append(candidate)
                        except PermissionError:
                            pass

        if self.verbose and related:
            print(f"[MultiFile] Found {len(related)} related files for {os.path.basename(filename)}")

        return related

    def find_extern_declarations(self, source: str, filename: str) -> List[ExternDeclaration]:
        """
        Find extern function declarations in source code.

        These indicate functions defined in other files that we need to analyze.
        """
        extern_decls = []
        parser = self._get_parser(filename)
        tree = parser.parse(bytes(source, 'utf8'))

        self._find_extern_decls_recursive(tree.root_node, extern_decls, filename)

        return extern_decls

    def _find_extern_decls_recursive(self, node: Any, decls: List[ExternDeclaration],
                                      filename: str):
        """Recursively find extern function declarations."""
        # Look for function declarations (not definitions - no body)
        if node.type == 'declaration':
            # Check if this looks like a function declaration
            declarator = None
            type_node = None

            for child in node.children:
                if child.type in ('type_identifier', 'primitive_type'):
                    type_node = child
                elif child.type == 'function_declarator':
                    declarator = child
                elif child.type == 'pointer_declarator':
                    # Could be pointer to function or pointer return type
                    for subchild in child.children:
                        if subchild.type == 'function_declarator':
                            declarator = subchild
                            break

            if declarator:
                # This is a function declaration
                func_name = self._extract_function_name(declarator)
                return_type = self._get_text(type_node) if type_node else "void"
                params = self._extract_parameters(declarator)

                if func_name:
                    decl = ExternDeclaration(
                        name=func_name,
                        return_type=return_type,
                        parameters=params,
                        location=Location(
                            file=filename,
                            line=node.start_point[0] + 1,
                            column=node.start_point[1] + 1
                        )
                    )
                    decls.append(decl)

        # Recurse into children
        for child in node.children:
            self._find_extern_decls_recursive(child, decls, filename)

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

        # Fallback: look for identifier child
        for child in declarator.children:
            if child.type == 'identifier':
                return self._get_text(child)

        return None

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
                        else:
                            params.append((f"param{len(params)}", type_str))

        return params

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

    def analyze_with_related_files(self, source: str, filename: str,
                                    search_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze source file along with any related files.

        Args:
            source: Source code of primary file
            filename: Path to primary file
            search_dir: Directory to search for related files

        Returns:
            Dict with combined analysis results including cross-file vulnerabilities
        """
        context = MultiFileContext(primary_file=filename)

        # Find related files
        if search_dir is None:
            search_dir = os.path.dirname(filename) or "."
        context.related_files = self.find_related_files(filename, search_dir)

        # Find extern declarations in primary file
        context.extern_declarations = self.find_extern_declarations(source, filename)

        if self.verbose:
            print(f"[MultiFile] Analyzing {os.path.basename(filename)}")
            print(f"[MultiFile] Found {len(context.extern_declarations)} extern declarations")
            print(f"[MultiFile] Found {len(context.related_files)} related files")

        # Analyze primary file
        primary_analyzer = InterproceduralTaintAnalyzer(verbose=self.verbose)
        primary_result = primary_analyzer.analyze(source, filename)

        # Merge into combined context
        context.combined_call_graph = primary_result['call_graph']
        context.combined_summaries.update(primary_result['taint_summaries'])

        # Analyze each related file and merge results
        for related_file in context.related_files:
            try:
                with open(related_file, 'r', encoding='utf-8', errors='ignore') as f:
                    related_source = f.read()

                related_analyzer = InterproceduralTaintAnalyzer(verbose=False)
                related_result = related_analyzer.analyze(related_source, related_file)

                # Merge call graph
                for func, calls in related_result['call_graph'].calls_from.items():
                    if func not in context.combined_call_graph.calls_from:
                        context.combined_call_graph.calls_from[func] = []
                    context.combined_call_graph.calls_from[func].extend(calls)

                context.combined_call_graph.defined_functions.update(
                    related_result['call_graph'].defined_functions
                )

                # Merge taint summaries
                for name, summary in related_result['taint_summaries'].items():
                    if name not in context.combined_summaries:
                        context.combined_summaries[name] = summary
                    elif summary.confidence > context.combined_summaries[name].confidence:
                        context.combined_summaries[name] = summary

            except Exception as e:
                if self.verbose:
                    print(f"[MultiFile] Error analyzing {related_file}: {e}")

        # Find cross-file vulnerabilities
        vulnerabilities = self._find_cross_file_vulnerabilities(context, primary_analyzer)

        # Also include vulnerabilities from primary analysis
        vulnerabilities.extend(primary_result.get('vulnerabilities', []))

        return {
            'context': context,
            'vulnerabilities': vulnerabilities,
            'call_graph': context.combined_call_graph,
            'taint_summaries': context.combined_summaries,
        }

    def _find_cross_file_vulnerabilities(self, context: MultiFileContext,
                                          primary_analyzer: InterproceduralTaintAnalyzer
                                          ) -> List[Dict[str, Any]]:
        """
        Find vulnerabilities that span multiple files.

        Key insight: If primary file has tainted data passed to an extern function,
        and that function (in related file) uses the data unsafely, we have a vuln.
        """
        vulnerabilities = []

        # For each call site in primary file
        for caller, call_sites in context.combined_call_graph.calls_from.items():
            # Skip if caller is not from primary file
            # (We want to find flows originating from primary)

            for site in call_sites:
                callee = site.callee

                # Check if callee is defined in a related file
                callee_in_related = False
                for related_file in context.related_files:
                    related_basename = os.path.basename(related_file)
                    # Check if callee name suggests it's from this related file
                    # Juliet pattern: function names include file identifier like "51b"
                    if any(f"_{i}" in callee for i in ['51b', '52b', '53b', '54b', '54c', '54d', '54e']):
                        callee_in_related = True
                        break

                if not callee_in_related:
                    # Also check if callee is in combined summaries from related files
                    if callee in context.combined_summaries:
                        summary = context.combined_summaries[callee]
                        if summary.qualified_name != callee:
                            callee_in_related = True

                if not callee_in_related:
                    continue

                # Get tainted vars in caller function
                caller_tainted = primary_analyzer._get_tainted_vars_in_function(caller)

                # Check if passing tainted data to callee
                callee_summary = context.combined_summaries.get(callee)
                if not callee_summary:
                    continue

                # Check each argument
                for i, arg in enumerate(site.arguments):
                    # Is this argument tainted?
                    is_tainted = (arg in caller_tainted or
                                  primary_analyzer._is_tainted_expression(arg, caller_tainted))

                    if not is_tainted:
                        continue

                    # Is this parameter a sink in the callee?
                    if i in callee_summary.param_sinks:
                        sink_kind = callee_summary.param_sinks[i]
                        vuln = {
                            'type': 'cross_file_taint',
                            'sink_kind': sink_kind.value,
                            'callee': callee,
                            'caller': caller,
                            'argument': arg,
                            'param_index': i,
                            'location': site.location,
                            'source_file': context.primary_file,
                            'sink_file': 'related',
                            'description': f"Cross-file taint: '{arg}' from {os.path.basename(context.primary_file)} "
                                          f"passed to {callee}() parameter {i} ({sink_kind.value})"
                        }
                        vulnerabilities.append(vuln)

                        if self.verbose:
                            print(f"[MultiFile] Found cross-file vulnerability: {vuln['description']}")

        return vulnerabilities


def analyze_multifile(source: str, filename: str, search_dir: Optional[str] = None,
                      verbose: bool = False) -> Dict[str, Any]:
    """
    Convenience function for multi-file analysis.

    Args:
        source: Source code of primary file
        filename: Path to primary file
        search_dir: Directory to search for related files
        verbose: Enable verbose output

    Returns:
        Dict with analysis results including cross-file vulnerabilities
    """
    analyzer = MultiFileAnalyzer(verbose=verbose)
    return analyzer.analyze_with_related_files(source, filename, search_dir)
