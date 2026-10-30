"""C/C++ weaknesses that are facts of the syntax tree, read from tree-sitter (never from lines of
text): a `case` that runs into the next one (CWE-484) and a pointer given a fixed numeric address
(CWE-587). Each check names exactly the construct; nothing depends on a variable's name."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterator, List, Optional

from frame.sil import c_facts


@dataclass(frozen=True)
class SyntaxFinding:
    cwe_id: str
    line: int
    column: int
    description: str


@lru_cache(maxsize=None)
def _parser(language: str):
    from tree_sitter import Language, Parser
    if language == "cpp":
        import tree_sitter_cpp as grammar
    else:
        import tree_sitter_c as grammar
    return Parser(Language(grammar.language()))


# GCC's -Wimplicit-fallthrough accepts a comment saying so (`/* fall through */`, `// FALLTHRU`).
_FALLTHROUGH_COMMENT = re.compile(r"(?i)\bfall(?:s|ing)?[\s-]*thr(?:ough|u)\b")
_JUMPS = {"break_statement", "return_statement", "continue_statement", "goto_statement", "throw_statement"}


def _text(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _walk(node) -> Iterator:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _statements(case) -> List:
    """The statements of a `case` / `default` label (after the colon), comments excluded."""
    body, seen_colon = [], False
    for c in case.children:
        if c.type == ":":
            seen_colon = True
        elif seen_colon and c.type != "comment":
            body.append(c)
    return body


def _ends_path(stmt, noreturn) -> bool:
    """Does control never leave this statement normally (so the next `case` is not reached)?"""
    if stmt is None:
        return False
    if stmt.type in _JUMPS:
        return True
    if stmt.type == "compound_statement":
        inner = [c for c in stmt.named_children if c.type != "comment"]
        return bool(inner) and _ends_path(inner[-1], noreturn)
    if stmt.type == "if_statement":
        alt = stmt.child_by_field_name("alternative")
        if alt is None:
            return False
        alt_body = next((c for c in alt.named_children if c.type != "comment"), None) \
            if alt.type == "else_clause" else alt
        return _ends_path(stmt.child_by_field_name("consequence"), noreturn) and _ends_path(alt_body, noreturn)
    if stmt.type == "expression_statement":
        call = next((c for c in stmt.named_children), None)
        if call is not None and call.type == "call_expression":
            fn = call.child_by_field_name("function")
            return _text(fn).split("::")[-1] in noreturn
    if stmt.type == "attributed_statement":
        return "fallthrough" in _text(stmt)
    return False


def _marked_fallthrough(case, nxt) -> bool:
    """`[[fallthrough]];`, `__attribute__((fallthrough));` or a fall-through comment between the
    last statement of `case` and the next label."""
    for c in case.children:
        if c.type in ("attributed_statement", "expression_statement") and "fallthrough" in _text(c):
            return True
        if c.type == "comment" and _FALLTHROUGH_COMMENT.search(_text(c)):
            return True
    between = case.next_sibling
    while between is not None and between is not nxt:
        if between.type == "comment" and _FALLTHROUGH_COMMENT.search(_text(between)):
            return True
        between = between.next_sibling
    return False


def _fallthroughs(root, noreturn) -> Iterator[SyntaxFinding]:
    for node in _walk(root):
        if node.type != "switch_statement":
            continue
        body = node.child_by_field_name("body")
        cases = [c for c in (body.named_children if body is not None else ()) if c.type == "case_statement"]
        for case, nxt in zip(cases, cases[1:]):
            stmts = _statements(case)
            if not stmts or _ends_path(stmts[-1], noreturn) or _marked_fallthrough(case, nxt):
                continue
            label = "default" if nxt.child_by_field_name("value") is None else \
                f"case {_text(nxt.child_by_field_name('value'))}"
            yield SyntaxFinding("CWE-484", nxt.start_point[0] + 1, nxt.start_point[1],
                                f"Omitted break: the case before '{label}' runs into it "
                                "(no break, return or fall-through mark)")


def _unwrap(node):
    while node is not None and node.type == "parenthesized_expression":
        node = next((c for c in node.named_children), None)
    return node


def _fixed_address(value) -> Optional[str]:
    """`(char *)0x400000`: a cast to a pointer type of a non-zero integer literal."""
    value = _unwrap(value)
    if value is None or value.type != "cast_expression":
        return None
    typ, operand = value.child_by_field_name("type"), _unwrap(value.child_by_field_name("value"))
    if typ is None or operand is None or operand.type != "number_literal":
        return None
    if not any(n.type == "abstract_pointer_declarator" for n in _walk(typ)):
        return None
    literal = _text(operand).rstrip("uUlL")
    try:
        number = int(literal, 0)
    except ValueError:
        return None
    return literal if number != 0 else None


def _fixed_addresses(root) -> Iterator[SyntaxFinding]:
    for node in _walk(root):
        if node.type == "init_declarator":
            value = node.child_by_field_name("value")
        elif node.type == "assignment_expression":
            value = node.child_by_field_name("right")
        else:
            continue
        literal = _fixed_address(value)
        if literal is not None:
            yield SyntaxFinding("CWE-587", node.start_point[0] + 1, node.start_point[1],
                                f"Fixed address {literal} assigned to a pointer")


def check(source: str, language: str) -> List[SyntaxFinding]:
    root = _parser("cpp" if language == "cpp" else "c").parse(source.encode("utf-8")).root_node
    noreturn = c_facts.noreturn()
    return list(_fallthroughs(root, noreturn)) + list(_fixed_addresses(root))


__all__ = ["SyntaxFinding", "check"]
