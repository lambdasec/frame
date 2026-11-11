"""Credential-storage sinks read from the syntax tree, shared by the Python and JS/TS frontends.

A call written with a SQL statement as its first argument and the statement's parameters as the
second (`db.execute("INSERT INTO users (name, password) VALUES (?, ?)", (n, pw))`,
`run('UPDATE users SET token = ? WHERE id = ?', [t, id])`): the parameter a credential column
takes (`frame.sil.sql_credentials`) is a `SinkKind.PASSWORD_STORE` sink, emitted before the
statement, so a credential stored with no hash function in between is reported. The callee does
not matter (applications wrap their driver in helpers): the statement text says what is stored.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Optional, Tuple

from frame.sil.instructions import Instr, SinkKind, TaintSink
from frame.sil.sql_credentials import credential_parameters


def _sinks(fe: Any, picked: Iterable[Tuple[Any, str]]) -> List[Instr]:
    return [TaintSink(loc=fe._get_location(elem), exp=fe._translate_expression(elem), kind=SinkKind.PASSWORD_STORE,
                      description=f"Credential stored in column '{col}' without hashing")
            for elem, col in picked]


def _pick(columns: dict, positional: Optional[list], named: Optional[dict]) -> List[Tuple[Any, str]]:
    out = []
    for key, col in columns.items():
        if isinstance(key, int) and positional is not None and key < len(positional):
            out.append((positional[key], col))
        elif isinstance(key, str) and named is not None and named.get(key) is not None:
            out.append((named[key], col))
    return out


def python_sinks(fe: Any, stmt: Any) -> List[Instr]:
    out: List[Instr] = []
    stack = [stmt]
    while stack:
        n = stack.pop()
        if n.type in ("function_definition", "lambda", "class_definition"):
            continue
        stack.extend(reversed(n.children))
        if n.type != "call":
            continue
        args_node = n.child_by_field_name("arguments")
        args = [a for a in (args_node.named_children if args_node is not None else ())
                if a.type not in ("keyword_argument", "comment")]
        if len(args) < 2:
            continue
        parts = args[0].named_children if args[0].type == "concatenated_string" else [args[0]]
        texts = [fe._literal_text(p) for p in parts]
        if any(t is None for t in texts):
            continue
        columns = credential_parameters("".join(texts))
        if not columns:
            continue
        params = args[1]
        if params.type in ("tuple", "list"):
            out += _sinks(fe, _pick(columns, [e for e in params.named_children if e.type != "comment"], None))
        elif params.type == "dictionary":
            named = {fe._literal_text(p.child_by_field_name("key")): p.child_by_field_name("value")
                     for p in params.named_children if p.type == "pair"}
            out += _sinks(fe, _pick(columns, None, named))
    return out


_JS_SCOPES = frozenset({"arrow_function", "function_expression", "function", "function_declaration",
                        "generator_function", "generator_function_declaration", "method_definition",
                        "class", "class_declaration"})


def _js_literal(fe: Any, node: Any) -> Optional[str]:
    """The text of a JS string literal or a template literal without substitutions."""
    if node is None:
        return None
    if node.type == "string":
        return "".join(fe._get_text(c) for c in node.named_children if c.type in ("string_fragment", "escape_sequence"))
    if node.type == "template_string" and not any(c.type == "template_substitution" for c in node.named_children):
        return fe._get_text(node)[1:-1]
    return None


def javascript_sinks(fe: Any, stmt: Any) -> List[Instr]:
    out: List[Instr] = []
    stack = [stmt]
    while stack:
        n = stack.pop()
        if n.type in _JS_SCOPES:
            continue
        stack.extend(reversed(n.children))
        if n.type != "call_expression":
            continue
        args_node = n.child_by_field_name("arguments")
        args = [a for a in (args_node.named_children if args_node is not None else ()) if a.type != "comment"]
        if len(args) < 2:
            continue
        text = _js_literal(fe, args[0])
        columns = credential_parameters(text) if text is not None else {}
        if not columns:
            continue
        params = args[1]
        if params.type == "array":
            out += _sinks(fe, _pick(columns, [e for e in params.named_children if e.type != "comment"], None))
        elif params.type == "object":
            named = {}
            for p in params.named_children:
                if p.type == "pair":
                    key = p.child_by_field_name("key")
                    k = _js_literal(fe, key) if key is not None and key.type == "string" else \
                        (fe._get_text(key) if key is not None else None)
                    if k:
                        named[k.lstrip("$:@")] = p.child_by_field_name("value")
            out += _sinks(fe, _pick(columns, None, named))
    return out


__all__ = ["javascript_sinks", "python_sinks"]
