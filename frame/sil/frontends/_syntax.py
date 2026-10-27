"""Shared helper: where a tree-sitter parse first went wrong.

tree-sitter recovers from a syntax error and still returns a tree, so a file
that does not parse is analysed best-effort. The scanner reports the first
error as a warning: findings past it may be missing.
"""

from typing import Optional


def first_syntax_error_line(root) -> Optional[int]:
    """1-based line of the first ERROR or MISSING node under `root`, or None
    when the file parsed cleanly."""
    if not root.has_error:
        return None
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            return node.start_point[0] + 1
        # Visit children in source order: the stack pops the last pushed first.
        stack.extend(reversed([c for c in node.children if c.has_error or c.is_missing]))
    return None
