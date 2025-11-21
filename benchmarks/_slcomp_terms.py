"""
Term parsing for SL-COMP parser

Internal module for parsing points-to, expressions, predicates, and comparisons.
"""

import re
from typing import Dict, Optional
from frame.core.ast import *
from benchmarks._slcomp_utils import split_top_level


def parse_pto(text: str, variables: Dict[str, Var]) -> Optional[PointsTo]:
    """Parse (pto x (c_Sll_t y)) or (pto x (node y1 y2)) or (pto x y) into PointsTo"""
    text = text.strip()

    # IMPORTANT: Check for (as nil Type) format FIRST before structured format
    # to avoid treating 'as' as a constructor name
    match_as = re.search(r'\(pto\s+(\w+)\s+(\(as\s+nil\s+[^)]+\))\s*\)', text)
    if match_as:
        var_name = match_as.group(1)
        var = variables.get(var_name, Var(var_name))
        return PointsTo(var, [Const(None)])

    # Try structured format: (pto x (Constructor y1 y2 ...))
    # Constructor can be: c_Type (old format) or just a name like 'node' (BSL format)
    # Handle values that can be: variable names, or (as nil Type)
    match = re.match(r'\(pto\s+(\w+)\s+\((?:c_)?(?:\w+)\s+(.+)\)\s*\)', text, re.DOTALL)
    if match:
        var_name = match.group(1)
        vals_text = match.group(2).strip()

        var = variables.get(var_name, Var(var_name))
        vals = []

        # Parse values - they can be simple variables or (as nil Type)
        # Use a simple state machine to handle nested parens
        i = 0
        current = []
        depth = 0
        while i < len(vals_text):
            ch = vals_text[i]
            if ch == '(':
                depth += 1
                current.append(ch)
            elif ch == ')':
                depth -= 1
                current.append(ch)
                if depth == 0 and current:
                    # Completed a value
                    val_text = ''.join(current).strip()
                    if 'nil' in val_text or val_text.startswith('(as'):
                        vals.append(Const(None))
                    else:
                        vals.append(variables.get(val_text, Var(val_text)))
                    current = []
            elif ch.isspace() and depth == 0:
                # Whitespace at top level - possible separator
                if current:
                    val_text = ''.join(current).strip()
                    if val_text:
                        if 'nil' in val_text or val_text.startswith('(as'):
                            vals.append(Const(None))
                        else:
                            vals.append(variables.get(val_text, Var(val_text)))
                    current = []
            else:
                current.append(ch)
            i += 1

        # Don't forget the last value
        if current:
            val_text = ''.join(current).strip()
            if val_text:
                if 'nil' in val_text or val_text.startswith('(as'):
                    vals.append(Const(None))
                else:
                    vals.append(variables.get(val_text, Var(val_text)))

        return PointsTo(var, vals)

    # Try simple format: (pto x y)
    match = re.search(r'\(pto\s+(\w+)\s+(\w+)\s*\)', text)
    if match:
        var_name = match.group(1)
        val_name = match.group(2)

        var = variables.get(var_name, Var(var_name))
        val = variables.get(val_name, Var(val_name))

        return PointsTo(var, [val])

    # Try format with (as nil Type)
    match = re.search(r'\(pto\s+(\w+)\s+(\(as nil [^)]+\))\s*\)', text)
    if match:
        var_name = match.group(1)
        var = variables.get(var_name, Var(var_name))
        return PointsTo(var, [Const(None)])

    return None


def parse_predicate_call(text: str, variables: Dict[str, Var]) -> Optional[PredicateCall]:
    """Parse (ls x y) or (dll x y (as nil Type) z) into PredicateCall"""
    # Extract predicate name and arguments
    text = text.strip()
    if not text.startswith('('):
        return None

    # Find the predicate name
    match = re.match(r'\((\w+)\s+(.+)\)', text, re.DOTALL)
    if match:
        pred_name = match.group(1)
        args_text = match.group(2).strip()
        if args_text.endswith(')'):
            args_text = args_text[:-1]  # Remove trailing paren from group match

        # Split arguments properly, respecting parentheses for (as nil Type)
        arg_strings = split_top_level(args_text)

        args = []
        for arg_str in arg_strings:
            arg_str = arg_str.strip()
            # Check if this is (as nil Type) - if so, treat as nil
            if arg_str.startswith('(as nil') or arg_str == 'nil':
                args.append(Const(None))
            else:
                args.append(variables.get(arg_str, Var(arg_str)))

        return PredicateCall(pred_name, args)

    return None


def parse_expr(text: str, variables: Dict[str, Var]) -> Expr:
    """Parse an expression (variable, constant, or arithmetic expression)"""
    text = text.strip()

    # Handle nil
    if 'nil' in text or text.startswith('(as nil'):
        return Const(None)

    # Handle arithmetic operators: +, -, *, div, mod
    if text.startswith('('):
        # Check for arithmetic operators
        arith_ops = {'+': '+', '-': '-', '*': '*', 'div': 'div', 'mod': 'mod'}
        for op_name, op_symbol in arith_ops.items():
            if text.startswith(f'({op_name} ') or text.startswith(f'({op_name}\t'):
                # Extract operands
                inner = text[len(op_name)+1:].strip()
                if inner.endswith(')'):
                    inner = inner[:-1]

                parts = split_top_level(inner)
                if len(parts) >= 2:
                    left = parse_expr(parts[0], variables)
                    right = parse_expr(parts[1], variables)
                    return ArithExpr(op_symbol, left, right)

    # Handle integer constants
    try:
        int_val = int(text)
        return Const(int_val)
    except ValueError:
        pass

    # Handle variables
    return variables.get(text, Var(text))


def parse_equality(text: str, variables: Dict[str, Var]) -> Optional[Eq]:
    """Parse (= x y) or (= (- x 1) 0) into Eq"""
    text = text.strip()
    if text.startswith('(='):
        # Extract the two arguments
        inner = text[2:].strip()
        if inner.endswith(')'):
            inner = inner[:-1]

        # Split into two parts
        parts = split_top_level(inner)
        if len(parts) >= 2:
            left = parse_expr(parts[0], variables)
            right = parse_expr(parts[1], variables)
            return Eq(left, right)

    return None


def parse_distinct(text: str, variables: Dict[str, Var]) -> Optional[Formula]:
    """Parse (distinct x y) into Neq"""
    text = text.strip()
    if text.startswith('(distinct'):
        # Extract the two arguments
        inner = text[9:].strip()  # Skip '(distinct'
        if inner.endswith(')'):
            inner = inner[:-1]

        # Split into two parts
        parts = split_top_level(inner)
        if len(parts) >= 2:
            left = parse_expr(parts[0], variables)
            right = parse_expr(parts[1], variables)
            return Neq(left, right)

    return None


def parse_comparison(text: str, op: str, variables: Dict[str, Var]) -> Optional[Formula]:
    """Parse comparison operators: (<, >, <=, >=) into Lt, Gt, Le, Ge"""
    text = text.strip()
    op_len = len(op) + 1  # Length of '(op' (e.g., '(<' is 2 chars)

    if text.startswith(f'({op}'):
        # Extract the two arguments
        inner = text[op_len:].strip()
        if inner.endswith(')'):
            inner = inner[:-1]

        # Split into two parts
        parts = split_top_level(inner)
        if len(parts) >= 2:
            left = parse_expr(parts[0], variables)
            right = parse_expr(parts[1], variables)

            if op == '<':
                return Lt(left, right)
            elif op == '<=':
                return Le(left, right)
            elif op == '>':
                return Gt(left, right)
            elif op == '>=':
                return Ge(left, right)

    return None
