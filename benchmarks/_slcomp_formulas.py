"""
Formula parsing for SL-COMP parser

Internal module for parsing logical formulas (and, or, sep, wand, exists, not).
"""

import re
from typing import Dict, List, Tuple, Optional, Callable
from frame.core.ast import *
from benchmarks._slcomp_utils import split_top_level, extract_balanced_parens, build_balanced_sepconj


def parse_and(text: str, variables: Dict[str, Var], parse_formula_fn: Callable, depth: int = 0) -> Formula:
    """Parse (and ...) into And formula"""
    # Extract arguments
    args_text = text[4:].strip()  # Remove '(and'
    if args_text.endswith(')'):
        args_text = args_text[:-1]  # Remove trailing )

    args = split_top_level(args_text)

    if len(args) == 0:
        return Emp()  # Empty and
    elif len(args) == 1:
        return parse_formula_fn(args[0], depth)
    else:
        # Build nested And, filtering out None values
        result = None
        for arg in args:
            parsed = parse_formula_fn(arg, depth)
            if parsed:
                if result is None:
                    result = parsed
                else:
                    result = And(result, parsed)
        return result if result is not None else Emp()


def parse_sep(text: str, variables: Dict[str, Var], parse_formula_fn: Callable, depth: int = 0) -> Formula:
    """Parse (sep ...) into SepConj formula"""
    # Extract arguments
    args_text = text[4:].strip()  # Remove '(sep'
    if args_text.endswith(')'):
        args_text = args_text[:-1]  # Remove trailing )

    args = split_top_level(args_text)

    if len(args) == 0:
        return Emp()
    elif len(args) == 1:
        return parse_formula_fn(args[0], depth)
    else:
        # Parse all arguments first
        parsed_args = []
        for arg in args:
            parsed = parse_formula_fn(arg, depth)
            if parsed:
                parsed_args.append(parsed)

        if not parsed_args:
            return Emp()

        # Build balanced binary tree instead of left-associative tree
        # This improves Z3 performance and formula analysis
        return build_balanced_sepconj(parsed_args)


def parse_wand(text: str, variables: Dict[str, Var], parse_formula_fn: Callable, depth: int = 0) -> Optional[Formula]:
    """Parse (wand P Q) into Wand formula"""
    # Extract arguments
    args_text = text[5:].strip()  # Remove '(wand'
    if args_text.endswith(')'):
        args_text = args_text[:-1]  # Remove trailing )

    args = split_top_level(args_text)

    if len(args) < 2:
        # Malformed wand, return None
        return None

    # Parse left and right formulas
    left = parse_formula_fn(args[0], depth)
    right = parse_formula_fn(args[1], depth)

    if left and right:
        return Wand(left, right)

    return None


def parse_or(text: str, variables: Dict[str, Var], parse_formula_fn: Callable, depth: int = 0) -> Formula:
    """Parse (or ...) into Or formula"""
    # Extract arguments
    args_text = text[3:].strip()  # Remove '(or'
    if args_text.endswith(')'):
        args_text = args_text[:-1]  # Remove trailing )

    args = split_top_level(args_text)

    if len(args) == 0:
        return Emp()
    elif len(args) == 1:
        return parse_formula_fn(args[0], depth)
    else:
        # Build nested Or, filtering out None values
        result = None
        for arg in args:
            parsed = parse_formula_fn(arg, depth)
            if parsed:
                if result is None:
                    result = parsed
                else:
                    result = Or(result, parsed)
        return result if result is not None else Emp()


def parse_not(text: str, variables: Dict[str, Var], parse_formula_fn: Callable, depth: int = 0) -> Optional[Formula]:
    """Parse (not ...) into Not formula"""
    # Extract argument
    args_text = text[4:].strip()  # Remove '(not'
    if args_text.endswith(')'):
        args_text = args_text[:-1]  # Remove trailing )

    # Parse the inner formula
    inner = parse_formula_fn(args_text.strip(), depth)

    if inner:
        return Not(inner)

    return None


def parse_exists(text: str, variables: Dict[str, Var], parse_formula_fn: Callable, depth: int = 0) -> Optional[Formula]:
    """
    Parse (exists ((var1 Type1)(var2 Type2)...) body) into Exists formula.

    Note: We only support single variable exists for now, as that's what Exists AST node supports.
    For multiple variables, we nest multiple Exists nodes.
    """
    # Extract variables and body using balanced parenthesis matching
    # Format: (exists (vars...) body) or (exists ((vars...)) body)
    text = text.strip()
    if not text.startswith('(exists'):
        return None

    # Skip past '(exists' and whitespace
    idx = 7  # len('(exists')
    while idx < len(text) and text[idx] in ' \t\n':
        idx += 1

    if idx >= len(text) or text[idx] != '(':
        return None

    # Extract the variables section using balanced parens
    vars_text = extract_balanced_parens(text[idx:])
    if not vars_text:
        return None

    # Move idx past the variables section
    # Note: extract_balanced_parens already includes the outer parens
    idx += len(vars_text)

    # Skip whitespace
    while idx < len(text) and text[idx] in ' \t\n':
        idx += 1

    # Extract the body - everything until the final closing paren
    body_start = idx
    # Find the matching closing paren for the outermost '(exists'
    depth_counter = 1  # We're inside (exists already (renamed to avoid parameter collision)
    idx = 7  # Start from after '(exists'
    while idx < len(text) and depth_counter > 0:
        if text[idx] == '(':
            depth_counter += 1
        elif text[idx] == ')':
            depth_counter -= 1
        idx += 1

    body_text = text[body_start:idx-1].strip()  # -1 to exclude the final ')'

    # Parse variable names
    # Format: "var1 Type1)(var2 Type2" or "var1 Type1"
    var_names = []
    if ')' in vars_text:
        # Multiple variables
        var_parts = vars_text.split(')')
        for part in var_parts:
            part = part.strip().lstrip('(')
            if part:
                var_name = part.split()[0] if part.split() else ''
                if var_name:
                    var_names.append(var_name)
    elif vars_text:
        # Single variable
        var_name = vars_text.split()[0] if vars_text.split() else ''
        if var_name:
            var_names.append(var_name)

    # Parse body
    body_formula = parse_formula_fn(body_text, depth)
    if not body_formula:
        return None

    # Create nested Exists for each variable (innermost first)
    result = body_formula
    for var_name in reversed(var_names):
        result = Exists(var_name, result)

    return result
