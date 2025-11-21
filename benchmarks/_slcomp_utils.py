"""
Utility functions for SL-COMP parser

Internal helper module for string manipulation and tree building.
"""

from typing import List, Tuple
from frame.core.ast import Formula, SepConj, Emp


def split_top_level(text: str) -> List[str]:
    """Split text at top-level spaces (not inside parens)"""
    result = []
    current = ""
    depth = 0

    for char in text:
        if char == '(':
            depth += 1
            current += char
        elif char == ')':
            depth -= 1
            current += char
        elif char.isspace() and depth == 0:
            if current.strip():
                result.append(current.strip())
            current = ""
        else:
            current += char

    if current.strip():
        result.append(current.strip())

    return result


def extract_balanced_parens(text: str) -> str:
    """Extract content inside balanced parentheses, including the parens"""
    text = text.strip()
    if not text.startswith('('):
        return text

    depth = 0
    for i, char in enumerate(text):
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return text[:i+1]  # Include opening and closing parens

    return text


def extract_balanced_parens_at_index(text: str, start_idx: int) -> Tuple[str, int]:
    """
    Extract content between balanced parentheses starting at start_idx.

    Args:
        text: Full text
        start_idx: Index of opening '('

    Returns:
        (content_without_outer_parens, index_after_closing_paren)
    """
    if start_idx >= len(text) or text[start_idx] != '(':
        return '', start_idx

    depth = 0
    idx = start_idx

    while idx < len(text):
        if text[idx] == '(':
            depth += 1
        elif text[idx] == ')':
            depth -= 1
            if depth == 0:
                # Found matching closing paren
                # Return content without outer parens
                return text[start_idx + 1:idx], idx + 1

        idx += 1

    # Unmatched parens
    return text[start_idx + 1:], idx


def extract_predicate_bodies(bodies_text: str, count: int) -> List[str]:
    """Extract individual predicate bodies from the bodies section"""
    bodies = []
    depth = 0
    current_body = []

    i = 0
    while i < len(bodies_text) and len(bodies) < count:
        char = bodies_text[i]

        if char == '(':
            depth += 1
            current_body.append(char)
        elif char == ')':
            depth -= 1
            current_body.append(char)

            # If we've closed all parens, we have a complete body
            if depth == 0 and current_body:
                body_str = ''.join(current_body).strip()
                if body_str:
                    bodies.append(body_str)
                current_body = []
        elif depth > 0:
            current_body.append(char)

        i += 1

    return bodies


def build_balanced_sepconj(formulas: List[Formula]) -> Formula:
    r"""
    Build a balanced binary tree of SepConj nodes from a list of formulas.

    This creates a balanced tree instead of a left-associative chain, which
    improves Z3 performance and formula analysis.

    For example, [a, b, c, d, e, f] becomes:
            *
           / \
          *   *
         / \ / \
        *  * *  f
       / \   / \
      a  b  c  d

    Instead of the left-associative: ((((((a * b) * c) * d) * e) * f)

    Args:
        formulas: List of parsed formulas

    Returns:
        Balanced SepConj tree
    """
    if len(formulas) == 0:
        return Emp()
    elif len(formulas) == 1:
        return formulas[0]
    elif len(formulas) == 2:
        return SepConj(formulas[0], formulas[1])
    else:
        # Split into two halves and recursively build balanced subtrees
        mid = len(formulas) // 2
        left_tree = build_balanced_sepconj(formulas[:mid])
        right_tree = build_balanced_sepconj(formulas[mid:])
        return SepConj(left_tree, right_tree)
