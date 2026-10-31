"""C / C++ functions that escape text for HTML, recognised by what they do (never by name).

An escaper walks its input one character at a time and, for a character that makes markup,
appends a character reference instead of the character:

    for (char c : in) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        ...
        default: out += c;
        }
    }

`escapers(tree, source)` maps each function defined in a translation unit to the characters it
neutralises that way. In C and C++ a function with external linkage is its symbol name across
translation units (the linker resolves it by name), so a directory scan can carry what one file
defines to the calls in another (`scanner.FrameScanner.scan_directory`)."""

from __future__ import annotations

import re
from typing import Dict, Iterator, Optional, Set

# Characters that make text markup: neutralising all of them makes text safe in HTML text and
# in quoted attributes (the same rule as translator._HTML_SIGNIFICANT).
HTML_SIGNIFICANT = frozenset("&<>\"'")
_CHAR_REFERENCE = re.compile(r"&(?:[A-Za-z][A-Za-z0-9]*|#[0-9]+|#[xX][0-9A-Fa-f]+);")
_CHAR_ESCAPES = {"\\'": "'", '\\"': '"', "\\\\": "\\"}


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk(node) -> Iterator:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _char_literal(node, source: bytes) -> Optional[str]:
    """The character a `'x'` literal denotes (simple escapes only)."""
    if node is None or node.type != "char_literal":
        return None
    body = _text(node, source)[1:-1]
    if len(body) == 1:
        return body
    return _CHAR_ESCAPES.get(body)


def _string_literal(node, source: bytes) -> Optional[str]:
    if node is None or node.type != "string_literal":
        return None
    text = _text(node, source)
    return text[1:-1] if len(text) >= 2 and text[0] == text[-1] == '"' else None


def _appended(stmt, source: bytes, out: str) -> Optional[str]:
    """What a statement appends to `out`: the literal of `out += "..."` / `out.append("...")`,
    "" for the loop's own character (anything else appended), None when it appends nothing."""
    for n in _walk(stmt):
        if n.type == "assignment_expression" and _text(n.child_by_field_name("left"), source) == out \
                and any(c.type == "+=" for c in n.children):
            lit = _string_literal(n.child_by_field_name("right"), source)
            return lit if lit is not None else ""
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn is not None and fn.type == "field_expression" and \
                    _text(fn.child_by_field_name("argument"), source) == out and \
                    _text(fn.child_by_field_name("field"), source) in ("append", "push_back", "operator+="):
                args = [a for a in n.child_by_field_name("arguments").named_children]
                lit = _string_literal(args[0], source) if len(args) == 1 else None
                return lit if lit is not None else ""
    return None


def _neutralized(switch, source: bytes, out: str) -> Set[str]:
    """The characters a `switch` over the input's character replaces by a character reference
    (or drops): each `case 'x':` whose statements append a reference, never the character."""
    done: Set[str] = set()
    body = switch.child_by_field_name("body")
    cases = [c for c in (body.named_children if body is not None else ()) if c.type == "case_statement"]
    pending: Set[str] = set()                        # labels falling through to the next statements
    for case in cases:
        ch = _char_literal(case.child_by_field_name("value"), source)
        if ch is not None:
            pending.add(ch)
        stmts = [s for s in case.named_children if s is not case.child_by_field_name("value")]
        if not stmts:
            continue
        appended = [_appended(s, source, out) for s in stmts]
        appended = [a for a in appended if a is not None]
        if pending and all(a == "" or _CHAR_REFERENCE.fullmatch(a) for a in appended) \
                and "" not in appended:
            done |= pending
        pending = set()
    return done


def escapers(tree, source: bytes) -> Dict[str, Set[str]]:
    """Function name -> the characters it neutralises (only functions that neutralise some)."""
    out: Dict[str, Set[str]] = {}
    for fn in _walk(tree.root_node):
        if fn.type != "function_definition":
            continue
        decl = fn.child_by_field_name("declarator")
        while decl is not None and decl.type in ("pointer_declarator", "reference_declarator"):
            decl = decl.child_by_field_name("declarator") or (decl.named_children[-1] if decl.named_children else None)
        if decl is None or decl.type != "function_declarator":
            continue
        name_node = decl.child_by_field_name("declarator")
        name = _text(name_node, source) if name_node is not None else ""
        if not name or any(c.type == "storage_class_specifier" and _text(c, source) == "static" for c in fn.children):
            continue                                 # a static function is its own file's only
        chars: Set[str] = set()
        for loop in _walk(fn):
            if loop.type != "for_range_loop":
                continue
            var = loop.child_by_field_name("declarator")
            var_name = _text(var, source).lstrip("&*") if var is not None else ""
            for sw in _walk(loop):
                if sw.type != "switch_statement":
                    continue
                cond = sw.child_by_field_name("condition")
                cond_text = _text(cond, source).strip("() ") if cond is not None else ""
                if cond_text != var_name:
                    continue
                for n in _walk(sw):                   # what the switch appends to
                    if n.type == "assignment_expression" and any(c.type == "+=" for c in n.children):
                        target = _text(n.child_by_field_name("left"), source)
                        chars |= _neutralized(sw, source, target)
                        break
        if chars:
            out[name] = chars
    return out


__all__ = ["HTML_SIGNIFICANT", "escapers"]
