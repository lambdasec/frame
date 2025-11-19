"""
Function definition parsing for SL-COMP parser

Internal module for parsing define-fun declarations and function expansion.
"""

import re
from typing import Dict, List, Tuple
from benchmarks._slcomp_utils import extract_balanced_parens


def parse_function_defs(content: str) -> Dict[str, Tuple[List[str], str]]:
    """
    Parse define-fun declarations (non-recursive function definitions/macros).

    Format: (define-fun func_name ((param1 Type1) (param2 Type2) ...) RetType body)

    These are stored as macros and expanded when encountered.

    Returns:
        Dictionary mapping function name to (param_names, body_text)
    """
    function_defs = {}
    idx = 0

    while idx < len(content):
        # Find next define-fun (but not define-fun-rec)
        start_idx = content.find('(define-fun ', idx)
        if start_idx == -1:
            break

        # Make sure this is not define-fun-rec
        if content[start_idx:start_idx+16] == '(define-fun-rec ':
            idx = start_idx + 16
            continue

        # Extract the full define-fun block
        full_def = None
        depth = 0
        i = start_idx
        while i < len(content):
            if content[i] == '(':
                depth += 1
            elif content[i] == ')':
                depth -= 1
                if depth == 0:
                    full_def = content[start_idx:i+1]
                    break
            i += 1

        if not full_def:
            idx = start_idx + 12
            continue

        # Parse the define-fun
        # Format: (define-fun name ((params...)) RetType body)
        inner = extract_balanced_parens(full_def)
        if not inner:
            idx = start_idx + 12
            continue

        # Strip outer parens and 'define-fun ' prefix
        if inner.startswith('(') and inner.endswith(')'):
            inner = inner[1:-1].strip()

        if inner.startswith('define-fun '):
            inner = inner[11:].strip()  # Skip 'define-fun '

        # Extract function name
        parts = inner.split(None, 1)
        if len(parts) < 2:
            idx = start_idx + 12
            continue

        func_name = parts[0]
        rest = parts[1].strip()

        # Extract parameters
        if not rest.startswith('('):
            idx = start_idx + 12
            continue

        params_text = extract_balanced_parens(rest)
        if not params_text:
            idx = start_idx + 12
            continue

        # Parse parameter names (skip types for now, just get names)
        param_names = []
        param_tokens = params_text.strip('()').split('(')
        for token in param_tokens:
            token = token.strip()
            if token:
                # Format: param_name Type)
                param_parts = token.split()
                if param_parts:
                    param_names.append(param_parts[0])

        # Skip past parameters to get body
        rest = rest[len(params_text) + 2:].strip()  # +2 for parentheses

        # Skip return type (next token)
        ret_type_parts = rest.split(None, 1)
        if len(ret_type_parts) < 2:
            idx = start_idx + 12
            continue

        body_text = ret_type_parts[1].strip()

        # Store the function definition
        function_defs[func_name] = (param_names, body_text)

        idx = start_idx + 12

    return function_defs


def expand_function_call(func_name: str, args: List[str], function_defs: Dict[str, Tuple[List[str], str]]) -> str:
    """
    Expand a function call by substituting arguments into the function body.

    Args:
        func_name: Name of the function to expand
        args: List of argument expressions (as strings)
        function_defs: Dictionary of function definitions

    Returns:
        The expanded body with arguments substituted, or None if expansion fails
    """
    if func_name not in function_defs:
        return None

    param_names, body_text = function_defs[func_name]

    if len(args) != len(param_names):
        return None

    # Perform substitution: replace each parameter with its argument
    # We need to be careful to do whole-word replacement
    result = body_text
    for param, arg in zip(param_names, args):
        # Use word boundary replacement to avoid partial matches
        # Simple approach: replace with regex word boundaries
        result = re.sub(r'\b' + re.escape(param) + r'\b', arg, result)

    return result
