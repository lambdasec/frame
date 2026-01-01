"""
Semantic Pattern Detection for Safe vs Unsafe Code Patterns.

This module provides semantic-level analysis to distinguish between
genuinely vulnerable code patterns and safe alternatives that may
look syntactically similar.

Key patterns detected:
1. Format String: printf(var) vs printf("%s", var)
2. Buffer Operations: strcpy vs strncpy with proper bounds
3. NULL Pointer: if(ptr==NULL){*ptr} vs if(ptr!=NULL){*ptr}
4. Integer Overflow: unbounded arithmetic vs bounded with checks

This is the core of achieving high precision - not flagging safe patterns.
"""

from typing import Any, Optional, List, Set, Dict, Tuple
from dataclasses import dataclass
from enum import Enum
import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser


class PatternSafety(Enum):
    """Classification of pattern safety"""
    SAFE = "safe"           # Pattern is safe, should NOT flag
    UNSAFE = "unsafe"       # Pattern is unsafe, SHOULD flag
    UNKNOWN = "unknown"     # Cannot determine


@dataclass
class PatternAnalysisResult:
    """Result of analyzing a code pattern"""
    safety: PatternSafety
    reason: str
    cwe_id: Optional[str] = None


class SemanticPatternAnalyzer:
    """
    Analyzes code patterns for semantic safety.

    This analyzer understands the MEANING of patterns, not just their syntax.
    For example, it knows that printf("%s", var) is safe while printf(var) is not.
    """

    # Printf-family functions (both regular and wide-char variants)
    PRINTF_FUNCS = {
        # Standard C printf family
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
        # Wide-char variants
        'wprintf', 'fwprintf', 'swprintf', '_snwprintf',
        'vwprintf', 'vfwprintf', 'vswprintf',
        # Windows-specific
        '_printf', '_fprintf', '_sprintf', '_snprintf',
        '_wprintf', '_fwprintf', '_swprintf',
        # Syslog
        'syslog', 'vsyslog',
    }

    # Buffer copy functions
    UNSAFE_COPY_FUNCS = {'strcpy', 'strcat', 'wcscpy', 'wcscat', 'gets', 'sprintf'}
    SAFE_COPY_FUNCS = {
        'strncpy': 2,      # Size is 3rd arg (index 2)
        'strncat': 2,
        'memcpy': 2,
        'memmove': 2,
        'memset': 2,
        'snprintf': 1,     # Size is 2nd arg (index 1)
        'fgets': 1,
        'wcsncpy': 2,
        'wcsncat': 2,
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.c_parser = Parser(Language(tsc.language()))
        self.cpp_parser = Parser(Language(tscpp.language()))

    def _get_parser(self, filename: str) -> Parser:
        """Get appropriate parser based on file extension."""
        cpp_exts = ('.cpp', '.cc', '.cxx', '.hpp', '.hxx', '.C')
        if any(filename.endswith(ext) for ext in cpp_exts):
            return self.cpp_parser
        return self.c_parser

    def _get_text(self, node: Any) -> str:
        """Get text content of a node."""
        if node is None:
            return ""
        return node.text.decode('utf8')

    # =========================================================================
    # Format String Pattern Analysis (CWE-134)
    # =========================================================================

    def analyze_format_string(self, call_node: Any) -> PatternAnalysisResult:
        """
        Analyze a printf-family call for format string safety.

        SAFE patterns:
        - printf("literal string")          - Format is string literal
        - printf("%s", var)                 - Format literal with specifiers
        - fprintf(f, "%d", num)             - Format literal with specifiers

        UNSAFE patterns:
        - printf(var)                       - Variable as format string
        - fprintf(f, data)                  - Variable as format string
        - sprintf(buf, user_input)          - Variable as format string

        Args:
            call_node: Tree-sitter call_expression node

        Returns:
            PatternAnalysisResult indicating safety
        """
        func_node = call_node.child_by_field_name('function')
        args_node = call_node.child_by_field_name('arguments')

        if not func_node or not args_node:
            return PatternAnalysisResult(PatternSafety.UNKNOWN, "Cannot parse call")

        func_name = self._get_text(func_node)

        # Check if it's a printf-family function
        base_name = func_name.split('.')[-1].split('::')[-1]
        if base_name not in self.PRINTF_FUNCS:
            return PatternAnalysisResult(PatternSafety.UNKNOWN, "Not a printf-family function")

        # Get arguments
        args = []
        for child in args_node.children:
            if child.type not in ('(', ')', ','):
                args.append(child)

        if not args:
            return PatternAnalysisResult(PatternSafety.UNKNOWN, "No arguments")

        # Determine which argument is the format string
        # fprintf/sprintf/snprintf: format is 2nd or 3rd arg
        # printf: format is 1st arg
        format_arg_idx = 0
        if base_name in ('fprintf', 'vfprintf', 'fwprintf', 'vfwprintf'):
            format_arg_idx = 1  # fprintf(file, format, ...)
        elif base_name in ('sprintf', 'vsprintf', 'swprintf', 'vswprintf'):
            format_arg_idx = 1  # sprintf(buf, format, ...)
        elif base_name in ('snprintf', 'vsnprintf'):
            format_arg_idx = 2  # snprintf(buf, size, format, ...)
        elif base_name == 'syslog':
            format_arg_idx = 1  # syslog(priority, format, ...)

        if format_arg_idx >= len(args):
            return PatternAnalysisResult(PatternSafety.UNKNOWN, "Format arg index out of range")

        format_arg = args[format_arg_idx]

        # Check if format argument is a string literal
        if self._is_string_literal(format_arg):
            # SAFE: Using a literal format string
            format_str = self._get_text(format_arg)
            if '%' in format_str:
                return PatternAnalysisResult(
                    PatternSafety.SAFE,
                    f"Format string is literal with specifiers: {format_str[:30]}..."
                )
            else:
                return PatternAnalysisResult(
                    PatternSafety.SAFE,
                    "Format string is literal without specifiers"
                )
        elif format_arg.type == 'identifier':
            # UNSAFE: Variable as format string
            return PatternAnalysisResult(
                PatternSafety.UNSAFE,
                f"Variable '{self._get_text(format_arg)}' used as format string",
                cwe_id="CWE-134"
            )
        elif format_arg.type == 'field_expression':
            # UNSAFE: Member variable as format string
            return PatternAnalysisResult(
                PatternSafety.UNSAFE,
                f"Field expression used as format string: {self._get_text(format_arg)}",
                cwe_id="CWE-134"
            )
        elif format_arg.type == 'subscript_expression':
            # UNSAFE: Array element as format string
            return PatternAnalysisResult(
                PatternSafety.UNSAFE,
                f"Array subscript used as format string: {self._get_text(format_arg)}",
                cwe_id="CWE-134"
            )
        elif format_arg.type == 'pointer_expression':
            # UNSAFE: Dereferenced pointer as format string
            return PatternAnalysisResult(
                PatternSafety.UNSAFE,
                f"Pointer dereference used as format string",
                cwe_id="CWE-134"
            )
        elif format_arg.type == 'call_expression':
            # Might be getenv() or similar - UNSAFE
            return PatternAnalysisResult(
                PatternSafety.UNSAFE,
                f"Function call result used as format string",
                cwe_id="CWE-134"
            )
        else:
            return PatternAnalysisResult(
                PatternSafety.UNKNOWN,
                f"Cannot determine format string source: {format_arg.type}"
            )

    def _is_string_literal(self, node: Any) -> bool:
        """Check if node is a string literal."""
        if node is None:
            return False
        if node.type == 'string_literal':
            return True
        if node.type == 'concatenated_string':
            return True
        # Check for L"..." wide string
        if node.type == 'char_literal':
            return False
        return False

    def _is_macro_identifier(self, name: str) -> bool:
        """
        Check if identifier looks like a C/C++ macro constant.

        Macros are typically ALL_CAPS or CAPS_WITH_UNDERSCORES.
        These are compile-time constants and not user-controlled input.

        Examples: BAD_OS_COMMAND, GOOD_SOURCE, MAX_SIZE, NULL
        """
        if not name:
            return False
        # Must contain at least one uppercase letter
        if not any(c.isupper() for c in name):
            return False
        # All letters must be uppercase (allow underscores and digits)
        for c in name:
            if c.isalpha() and not c.isupper():
                return False
        # Common macro patterns
        return True

    # =========================================================================
    # Buffer Operation Pattern Analysis (CWE-121/122)
    # =========================================================================

    def analyze_buffer_operation(self, call_node: Any,
                                  buffer_sizes: Dict[str, int] = None) -> PatternAnalysisResult:
        """
        Analyze buffer copy operation for safety.

        SAFE patterns:
        - strncpy(dest, src, sizeof(dest))      - Size-bounded
        - memcpy(dest, src, len) where len <= sizeof(dest)
        - strcpy(dest, "literal")               - Known literal fits

        UNSAFE patterns:
        - strcpy(dest, src)                     - No bounds checking
        - gets(buf)                             - Always unsafe

        Args:
            call_node: Tree-sitter call_expression node
            buffer_sizes: Optional dict of known buffer sizes

        Returns:
            PatternAnalysisResult indicating safety
        """
        if buffer_sizes is None:
            buffer_sizes = {}

        func_node = call_node.child_by_field_name('function')
        args_node = call_node.child_by_field_name('arguments')

        if not func_node or not args_node:
            return PatternAnalysisResult(PatternSafety.UNKNOWN, "Cannot parse call")

        func_name = self._get_text(func_node)
        base_name = func_name.split('.')[-1].split('::')[-1]

        # Get arguments
        args = []
        for child in args_node.children:
            if child.type not in ('(', ')', ','):
                args.append(child)

        # Check gets() - always unsafe
        if base_name == 'gets':
            return PatternAnalysisResult(
                PatternSafety.UNSAFE,
                "gets() is always unsafe - no bounds checking",
                cwe_id="CWE-242"
            )

        # Check unsafe copy functions
        if base_name in self.UNSAFE_COPY_FUNCS:
            # Check if source is safe (string literal or compile-time constant)
            if len(args) >= 2:
                src_arg = args[1]
                src_text = self._get_text(src_arg)

                # String literals are safe (known size at compile time)
                if self._is_string_literal(src_arg):
                    return PatternAnalysisResult(
                        PatternSafety.SAFE,
                        f"String literal source: {src_text}"
                    )

                # Macro identifiers (ALL_CAPS or CAPS_WITH_UNDERSCORES) are compile-time constants
                # These expand to string literals and are safe
                if src_arg.type == 'identifier' and self._is_macro_identifier(src_text):
                    return PatternAnalysisResult(
                        PatternSafety.SAFE,
                        f"Macro constant source: {src_text}"
                    )

                # Check for known safe buffer sources (local buffers initialized with literals)
                if src_arg.type == 'identifier':
                    # If destination has known size and is much larger than typical input,
                    # it's likely safe (heuristic to reduce FPs)
                    if len(args) >= 1:
                        dest_text = self._get_text(args[0])
                        dest_size = buffer_sizes.get(dest_text)
                        if dest_size and dest_size >= 100:
                            # Large buffers with unknown src need taint tracking
                            # Don't flag here - let taint analysis handle it
                            return PatternAnalysisResult(
                                PatternSafety.UNKNOWN,
                                f"Requires taint analysis: {base_name}({dest_text}, {src_text})"
                            )

            return PatternAnalysisResult(
                PatternSafety.UNSAFE,
                f"{base_name}() with untrusted source has no bounds checking",
                cwe_id="CWE-120"
            )

        # Check safe copy functions
        if base_name in self.SAFE_COPY_FUNCS:
            size_arg_idx = self.SAFE_COPY_FUNCS[base_name]

            if size_arg_idx < len(args):
                size_arg = args[size_arg_idx]
                size_text = self._get_text(size_arg)

                # Check if size uses sizeof() - SAFE pattern
                if 'sizeof' in size_text:
                    return PatternAnalysisResult(
                        PatternSafety.SAFE,
                        f"Size bounded by sizeof: {size_text}"
                    )

                # Check if it's a constant
                if size_arg.type == 'number_literal':
                    return PatternAnalysisResult(
                        PatternSafety.SAFE,
                        f"Size bounded by constant: {size_text}"
                    )

                # Check if it references known buffer size
                if len(args) > 0:
                    dest_name = self._get_text(args[0])
                    if dest_name in buffer_sizes:
                        return PatternAnalysisResult(
                            PatternSafety.SAFE,
                            f"Known buffer size for {dest_name}"
                        )

            return PatternAnalysisResult(
                PatternSafety.SAFE,
                f"{base_name}() is a bounded copy function"
            )

        return PatternAnalysisResult(PatternSafety.UNKNOWN, "Not a buffer operation")

    # =========================================================================
    # NULL Pointer Pattern Analysis (CWE-476)
    # =========================================================================

    def analyze_null_check_pattern(self, if_node: Any,
                                    then_branch: Any) -> PatternAnalysisResult:
        """
        Analyze NULL check pattern for dereference safety.

        SAFE patterns:
        - if (ptr != NULL) { *ptr = x; }    - Deref only when non-NULL
        - if (ptr) { *ptr = x; }            - Truthy check = non-NULL

        UNSAFE patterns:
        - if (ptr == NULL) { *ptr = x; }    - Deref when confirmed NULL
        - if (!ptr) { *ptr = x; }           - Deref when confirmed NULL

        Args:
            if_node: Tree-sitter if_statement node
            then_branch: The 'then' branch to check for dereferences

        Returns:
            PatternAnalysisResult indicating safety
        """
        condition = if_node.child_by_field_name('condition')
        if not condition:
            return PatternAnalysisResult(PatternSafety.UNKNOWN, "No condition")

        # Analyze the condition
        check_info = self._analyze_null_condition(condition)
        if check_info is None:
            return PatternAnalysisResult(PatternSafety.UNKNOWN, "Cannot parse condition")

        ptr_name, is_null_check = check_info  # is_null_check: True if (ptr == NULL)

        # Look for dereferences of ptr_name in then_branch
        derefs = self._find_dereferences(then_branch, ptr_name)

        if not derefs:
            return PatternAnalysisResult(PatternSafety.SAFE, f"No dereference of {ptr_name}")

        if is_null_check:
            # Condition checks ptr == NULL, dereferencing in then is UNSAFE
            return PatternAnalysisResult(
                PatternSafety.UNSAFE,
                f"Dereference of {ptr_name} after NULL check confirms NULL",
                cwe_id="CWE-476"
            )
        else:
            # Condition checks ptr != NULL (or just ptr), dereferencing is SAFE
            return PatternAnalysisResult(
                PatternSafety.SAFE,
                f"Dereference of {ptr_name} guarded by non-NULL check"
            )

    def _analyze_null_condition(self, condition: Any) -> Optional[Tuple[str, bool]]:
        """
        Analyze condition to determine NULL check pattern.

        Returns: (ptr_name, is_null_check) where:
          - ptr_name: Name of pointer being checked
          - is_null_check: True if (ptr == NULL), False if (ptr != NULL) or (ptr)
        """
        # Strip parentheses
        while condition.type == 'parenthesized_expression':
            for child in condition.children:
                if child.type not in ('(', ')'):
                    condition = child
                    break

        # Check for binary expression: ptr == NULL or ptr != NULL
        if condition.type == 'binary_expression':
            left = condition.child_by_field_name('left')
            op = condition.child_by_field_name('operator')
            right = condition.child_by_field_name('right')

            if not left or not op or not right:
                return None

            op_text = self._get_text(op)

            # Determine which side is the pointer and which is NULL
            ptr_node = None
            is_null_check = False

            if self._is_null_literal(right):
                ptr_node = left
                is_null_check = (op_text == '==')
            elif self._is_null_literal(left):
                ptr_node = right
                is_null_check = (op_text == '==')
            else:
                return None

            if ptr_node.type == 'identifier':
                return (self._get_text(ptr_node), is_null_check)

        # Check for unary !ptr expression
        elif condition.type == 'unary_expression':
            op = None
            arg = None
            for child in condition.children:
                if child.type == '!':
                    op = '!'
                elif child.type == 'identifier':
                    arg = child

            if op == '!' and arg:
                # !ptr is true when ptr == NULL
                return (self._get_text(arg), True)

        # Check for simple identifier: if (ptr)
        elif condition.type == 'identifier':
            # if (ptr) is true when ptr != NULL
            return (self._get_text(condition), False)

        return None

    def _is_null_literal(self, node: Any) -> bool:
        """Check if node represents NULL."""
        if node is None:
            return False
        text = self._get_text(node).lower()
        return text in ('null', 'nullptr', '0', 'nil')

    def _find_dereferences(self, node: Any, var_name: str) -> List[Any]:
        """Find all dereferences of var_name in node."""
        derefs = []

        if node is None:
            return derefs

        # Check pointer dereference: *ptr
        if node.type == 'pointer_expression':
            for child in node.children:
                if child.type == '*':
                    continue
                if child.type == 'identifier' and self._get_text(child) == var_name:
                    derefs.append(node)
                    break

        # Check arrow access: ptr->field
        if node.type == 'field_expression':
            op = node.child_by_field_name('operator')
            arg = node.child_by_field_name('argument')
            if op and self._get_text(op) == '->' and arg:
                if arg.type == 'identifier' and self._get_text(arg) == var_name:
                    derefs.append(node)

        # Check subscript: ptr[i]
        if node.type == 'subscript_expression':
            arg = node.child_by_field_name('argument')
            if arg and arg.type == 'identifier' and self._get_text(arg) == var_name:
                derefs.append(node)

        # Recurse
        for child in node.children:
            derefs.extend(self._find_dereferences(child, var_name))

        return derefs

    # =========================================================================
    # Integer Overflow Pattern Analysis (CWE-190)
    # =========================================================================

    def analyze_integer_arithmetic(self, expr: Any,
                                    tainted_vars: Set[str] = None) -> PatternAnalysisResult:
        """
        Analyze arithmetic expression for integer overflow potential.

        SAFE patterns:
        - i + 1 where i is bounded
        - size < MAX_SIZE before use
        - Constant arithmetic

        UNSAFE patterns:
        - user_input * sizeof(int) before allocation
        - Unbounded arithmetic on tainted values

        Args:
            expr: Tree-sitter expression node
            tainted_vars: Set of variables known to be tainted

        Returns:
            PatternAnalysisResult indicating safety
        """
        if tainted_vars is None:
            tainted_vars = set()

        # Check if expression involves tainted variables
        vars_in_expr = self._extract_variables(expr)
        tainted_in_expr = vars_in_expr & tainted_vars

        if not tainted_in_expr:
            return PatternAnalysisResult(
                PatternSafety.SAFE,
                "No tainted variables in arithmetic"
            )

        # Check for multiplication (most dangerous for overflow)
        if self._contains_multiplication(expr):
            return PatternAnalysisResult(
                PatternSafety.UNSAFE,
                f"Multiplication with tainted variable: {tainted_in_expr}",
                cwe_id="CWE-190"
            )

        return PatternAnalysisResult(
            PatternSafety.UNKNOWN,
            "Arithmetic with tainted values - needs bounds check"
        )

    def _extract_variables(self, node: Any) -> Set[str]:
        """Extract all variable names from expression."""
        vars_found = set()

        if node is None:
            return vars_found

        if node.type == 'identifier':
            vars_found.add(self._get_text(node))

        for child in node.children:
            vars_found |= self._extract_variables(child)

        return vars_found

    def _contains_multiplication(self, node: Any) -> bool:
        """Check if expression contains multiplication."""
        if node is None:
            return False

        if node.type == 'binary_expression':
            op = node.child_by_field_name('operator')
            if op and self._get_text(op) == '*':
                return True

        for child in node.children:
            if self._contains_multiplication(child):
                return True

        return False

    # =========================================================================
    # Main analysis entry point
    # =========================================================================

    def analyze_call_expression(self, call_node: Any,
                                 buffer_sizes: Dict[str, int] = None,
                                 tainted_vars: Set[str] = None) -> Optional[PatternAnalysisResult]:
        """
        Analyze a call expression for semantic safety.

        This is the main entry point for call analysis.

        Args:
            call_node: Tree-sitter call_expression node
            buffer_sizes: Optional dict of known buffer sizes
            tainted_vars: Optional set of tainted variable names

        Returns:
            PatternAnalysisResult if applicable, None if not a recognized pattern
        """
        func_node = call_node.child_by_field_name('function')
        if not func_node:
            return None

        func_name = self._get_text(func_node)
        base_name = func_name.split('.')[-1].split('::')[-1]

        # Check format string functions
        if base_name in self.PRINTF_FUNCS:
            return self.analyze_format_string(call_node)

        # Check buffer copy functions
        if base_name in self.UNSAFE_COPY_FUNCS or base_name in self.SAFE_COPY_FUNCS:
            return self.analyze_buffer_operation(call_node, buffer_sizes)

        return None
