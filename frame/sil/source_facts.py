"""Facts read straight from source text that the SIL does not keep.

Today: module- or class-level compiled-regex constants (`HOST = re.compile(r"[a-z.]+")`,
`static final Pattern HOST = Pattern.compile("[a-z.]+")`, `const HOST = /^[a-z.]+$/`,
`static readonly Regex Host = new Regex("^[a-z.]+$")`). A guard such as
`if not HOST.fullmatch(x)` can only be judged by the pattern's text, which lives in
the constant's initialiser, not in the branch condition.
"""

from __future__ import annotations

import re
from typing import Dict

_PY = re.compile(r"""^[ \t]*([A-Za-z_]\w*)\s*=\s*(?:re\.)?compile\(\s*[rRuU]?(\"\"\"|'''|"|')(.*?)\2""",
                 re.M | re.S)
_JAVA = re.compile(r'''\bPattern\s+(\w+)\s*=\s*Pattern\.compile\(\s*"((?:\\.|[^"\\\n])*)"''')
_JS = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*/((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+)/([a-z]*)\s*[;\n]""")
_CS = re.compile(r'''\bRegex\s+(\w+)\s*=\s*new\s+Regex\(\s*@?"((?:""|\\.|[^"\\\n])*)"''')


def constant_regexes(source: str, language: str) -> Dict[str, str]:
    """{constant name: regex text}; a name bound to two different patterns is dropped."""
    found: Dict[str, str] = {}
    conflicts = set()

    def add(name: str, pattern: str) -> None:
        if name in found and found[name] != pattern:
            conflicts.add(name)
        found[name] = pattern

    if language == "python":
        for m in _PY.finditer(source):
            add(m.group(1), m.group(3))
    elif language == "java":
        for m in _JAVA.finditer(source):
            add(m.group(1), m.group(2).replace("\\\\", "\\"))
    elif language in ("javascript", "typescript"):
        for m in _JS.finditer(source):
            if "m" not in m.group(3):               # the m flag moves ^ and $ to every line
                add(m.group(1), m.group(2))
    elif language == "csharp":
        for m in _CS.finditer(source):
            add(m.group(1), m.group(2).replace('""', '"'))
    for c in conflicts:
        found.pop(c, None)
    return found


# ---------------------------------------------------------------------------------------------
# Constant tables: a name bound exactly once in the file, to a dict / object / list / tuple / set
# literal whose every key and value is itself a literal, and never written into. Looking a key up
# in one (`TABLE[key]`, `TABLE.get(key)`) yields one of the table's constants, whatever the key,
# so the key's taint does not reach the result. Read from the syntax tree (tree-sitter), and
# conservative: any other binding of the name anywhere in the file, any write into it, or passing
# it to a call that is not known to only read it, and it is not a constant table.

_PY_LITERALS = {"string", "integer", "float", "true", "false", "none", "concatenated_string"}
_PY_COLLECTIONS = {"dictionary", "list", "tuple", "set"}
_PY_MUTATORS = {"update", "setdefault", "pop", "popitem", "clear", "append", "extend", "insert", "remove",
                "add", "discard", "sort", "reverse", "__setitem__", "__delitem__", "difference_update",
                "intersection_update", "symmetric_difference_update", "__ior__"}
_PY_READERS = {"len", "sorted", "list", "tuple", "set", "frozenset", "dict", "str", "repr", "print", "any", "all",
               "min", "max", "sum", "enumerate", "iter", "isinstance", "bool", "json.dumps", "reversed"}
_JS_LITERALS = {"string", "number", "true", "false", "null", "undefined"}
_JS_COLLECTIONS = {"object", "array"}
_JS_MUTATORS = {"push", "pop", "shift", "unshift", "splice", "sort", "reverse", "fill", "copyWithin", "set",
                "delete", "clear", "add"}
_JS_READERS = {"JSON.stringify", "Object.keys", "Object.values", "Object.entries", "Array.isArray", "String",
               "console.log", "Object.freeze", "Object.prototype.hasOwnProperty.call", "Object.hasOwn"}
_JS_WRITERS = {"Object.assign", "Object.defineProperty", "Object.defineProperties", "Reflect.set",
               "Reflect.defineProperty", "Reflect.deleteProperty", "Object.setPrototypeOf"}


def _text(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _walk(root):
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _py_literal(n) -> bool:
    if n.type in _PY_LITERALS:
        return not any(c.type == "interpolation" for c in _walk(n))        # f-strings are not constant
    if n.type == "parenthesized_expression":
        return all(_py_literal(c) for c in n.named_children)
    if n.type == "unary_operator":
        return all(_py_literal(c) for c in n.named_children)
    if n.type in _PY_COLLECTIONS:
        for c in n.named_children:
            if c.type == "pair":
                if not (_py_literal(c.child_by_field_name("key")) and _py_literal(c.child_by_field_name("value"))):
                    return False
            elif c.type == "comment":
                continue
            elif not _py_literal(c):
                return False                                                # splats, comprehensions, names
        return True
    return False


def _js_literal(n) -> bool:
    if n.type in _JS_LITERALS:
        return True
    if n.type == "template_string":
        return not any(c.type == "template_substitution" for c in n.named_children)
    if n.type in ("parenthesized_expression", "unary_expression"):
        return all(_js_literal(c) for c in n.named_children)
    if n.type in _JS_COLLECTIONS:
        for c in n.named_children:
            if c.type == "pair":
                key, value = c.child_by_field_name("key"), c.child_by_field_name("value")
                if key is None or key.type not in ("property_identifier", "string", "number") or not _js_literal(value):
                    return False                                            # computed keys, methods
            elif c.type == "comment":
                continue
            elif not _js_literal(c):
                return False                                                # spreads, shorthand, names
        return True
    return False


def _parse(source: str, language: str):
    try:
        import tree_sitter
        if language == "python":
            import tree_sitter_python as g
            lang = tree_sitter.Language(g.language())
        else:
            import tree_sitter_javascript as g
            lang = tree_sitter.Language(g.language())
        try:
            parser = tree_sitter.Parser(lang)
        except TypeError:                                   # older bindings
            parser = tree_sitter.Parser()
            parser.set_language(lang)
        return parser.parse(source.encode("utf-8")).root_node
    except Exception:
        return None


def _call_name(n) -> str:
    f = n.child_by_field_name("function")
    return _text(f)


def constant_tables(source: str, language: str) -> set:
    """Names of the file's constant tables (Python, JavaScript; TypeScript reads as JS)."""
    if language not in ("python", "javascript", "typescript"):
        return set()
    root = _parse(source, "python" if language == "python" else "javascript")
    if root is None:
        return set()
    literal_bindings: Dict[str, int] = {}
    other_bindings: set = set()
    disqualified: set = set()
    py = language == "python"
    for n in _walk(root):
        t = n.type
        if py:
            if t == "assignment":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and left.type == "identifier" and right is not None and \
                        right.type in _PY_COLLECTIONS and _py_literal(right) and n.child_by_field_name("type") is None:
                    literal_bindings[_text(left)] = literal_bindings.get(_text(left), 0) + 1
                    continue
                for c in _walk(left) if left is not None else ():
                    if c.type == "identifier" and c.parent is not None and c.parent.type not in ("attribute", "subscript"):
                        other_bindings.add(_text(c))
                    if c.type == "subscript" and c.child_by_field_name("value") is not None:
                        disqualified.add(_text(c.child_by_field_name("value")))
                    if c.type == "attribute" and c.child_by_field_name("object") is not None:
                        disqualified.add(_text(c.child_by_field_name("object")))
            elif t == "augmented_assignment":
                left = n.child_by_field_name("left")
                base = left.child_by_field_name("value") if left is not None and left.type == "subscript" else left
                disqualified.add(_text(base))
            elif t == "delete_statement":
                for c in _walk(n):
                    if c.type == "subscript":
                        disqualified.add(_text(c.child_by_field_name("value")))
            elif t in ("for_statement", "for_in_clause"):
                for c in _walk(n.child_by_field_name("left")):
                    if c.type == "identifier":
                        other_bindings.add(_text(c))
            elif t in ("parameters", "lambda_parameters"):
                for c in _walk(n):
                    if c.type == "identifier":
                        other_bindings.add(_text(c))
            elif t in ("as_pattern_target", "named_expression", "global_statement", "nonlocal_statement",
                       "aliased_import", "dotted_name"):
                if t == "named_expression":
                    other_bindings.add(_text(n.child_by_field_name("name")))
                elif t in ("global_statement", "nonlocal_statement"):
                    other_bindings.update(_text(c) for c in n.named_children)
                elif t == "as_pattern_target":
                    other_bindings.add(_text(n))
                elif t == "aliased_import":
                    other_bindings.add(_text(n.child_by_field_name("alias")))
            elif t in ("function_definition", "class_definition"):
                other_bindings.add(_text(n.child_by_field_name("name")))
            elif t == "call":
                fn = n.child_by_field_name("function")
                if fn is not None and fn.type == "attribute":
                    attr = _text(fn.child_by_field_name("attribute"))
                    if attr in _PY_MUTATORS:
                        disqualified.add(_text(fn.child_by_field_name("object")))
                args = n.child_by_field_name("arguments")
                if _call_name(n) not in _PY_READERS and args is not None:
                    for a in args.named_children:
                        if a.type == "identifier":
                            disqualified.add(_text(a))
        else:
            if t == "variable_declarator":
                name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
                if name is not None and name.type == "identifier" and value is not None and \
                        value.type in _JS_COLLECTIONS and _js_literal(value):
                    literal_bindings[_text(name)] = literal_bindings.get(_text(name), 0) + 1
                    continue
                for c in _walk(name) if name is not None else ():
                    if c.type in ("identifier", "shorthand_property_identifier_pattern"):
                        other_bindings.add(_text(c))
            elif t in ("assignment_expression", "augmented_assignment_expression"):
                left = n.child_by_field_name("left")
                if left is not None and left.type == "identifier":
                    other_bindings.add(_text(left))
                elif left is not None and left.type in ("subscript_expression", "member_expression"):
                    disqualified.add(_text(left.child_by_field_name("object")))
            elif t == "update_expression":
                arg = n.child_by_field_name("argument")
                if arg is not None and arg.type in ("subscript_expression", "member_expression"):
                    disqualified.add(_text(arg.child_by_field_name("object")))
            elif t == "unary_expression" and _text(n.child_by_field_name("operator")) == "delete":
                arg = n.child_by_field_name("argument")
                if arg is not None and arg.type in ("subscript_expression", "member_expression"):
                    disqualified.add(_text(arg.child_by_field_name("object")))
            elif t in ("formal_parameters", "catch_clause", "for_in_statement", "import_specifier",
                       "namespace_import", "import_clause"):
                for c in _walk(n):
                    if c.type in ("identifier", "shorthand_property_identifier_pattern"):
                        other_bindings.add(_text(c))
            elif t in ("function_declaration", "class_declaration", "generator_function_declaration"):
                other_bindings.add(_text(n.child_by_field_name("name")))
            elif t in ("arrow_function",):
                p = n.child_by_field_name("parameter")
                if p is not None:
                    other_bindings.add(_text(p))
            elif t == "call_expression":
                fn = n.child_by_field_name("function")
                name = _call_name(n)
                if fn is not None and fn.type == "member_expression" and \
                        _text(fn.child_by_field_name("property")) in _JS_MUTATORS:
                    disqualified.add(_text(fn.child_by_field_name("object")))
                args = n.child_by_field_name("arguments")
                if args is not None and name not in _JS_READERS:
                    for a in args.named_children:
                        if a.type == "identifier":
                            disqualified.add(_text(a))
                if name in _JS_WRITERS and args is not None and args.named_children:
                    disqualified.add(_text(args.named_children[0]))
    return {name for name, count in literal_bindings.items()
            if count == 1 and name not in other_bindings and name not in disqualified}
