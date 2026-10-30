"""HCL (Terraform's configuration language): files read with tree-sitter-hcl into bodies,
attributes and blocks, and expressions evaluated as HashiCorp's hclsyntax evaluates them.

The contract is soundness: an expression evaluates either to the value HCL gives it or to
`Unknown`, never to a different value. What the evaluator does not model (most functions, a
type conversion it cannot be sure of, anything HCL would reject) is unknown. Values are plain
Python: str, int/float (cty numbers), bool, None (null), list (tuples, lists and sets), dict
(objects and maps). `tests/iac_real/hcl` evaluates every attribute of the Terraform fixtures with
HashiCorp's own library and go-cty's functions, and `tests/test_iac_terraform.py` compares.

Template text is read from the source between interpolations (tree-sitter-hcl's literal tokens
drop characters), escapes as hclsyntax decodes them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, List, Optional, Tuple

from .engine import Unknown


class HclError(ValueError):
    """An expression HCL would reject, or one this evaluator does not decide."""


# --- syntax ------------------------------------------------------------------------------------

@dataclass
class Expr:
    kind: str                          # lit tmpl tuple obj ref call cond unary binary for paren
    node: Any = None                   # the tree-sitter node (for its text and line)
    value: Any = None                  # lit: the value; ref: root name; call: name; unary/binary: op
    parts: List[Any] = field(default_factory=list)
    steps: List[Tuple] = field(default_factory=list)     # ref: ("attr", n) / ("index", Expr) / ("splat", steps)
    src: Optional["Source"] = None     # its own source text (an expression from a JSON file)

    @property
    def line(self) -> int:
        return self.node.start_point[0] + 1 if self.node is not None else 0


@dataclass
class Attribute:
    name: str
    expr: Expr
    line: int


@dataclass
class Block:
    type: str
    labels: List[str]
    body: "Body"
    line: int


@dataclass
class Body:
    attributes: Dict[str, Attribute] = field(default_factory=dict)
    blocks: List[Block] = field(default_factory=list)


class Source:
    def __init__(self, data: bytes):
        self.data = data

    def text(self, node) -> str:
        return self.data[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


_PARSER = None


def _parser():
    global _PARSER
    if _PARSER is None:
        import tree_sitter as ts
        import tree_sitter_hcl
        _PARSER = ts.Parser(ts.Language(tree_sitter_hcl.language()))
    return _PARSER


def parse(text: str) -> Tuple[Body, Source]:
    """A file's top-level body. Raises HclError when the file does not parse."""
    data = text.encode("utf-8")
    tree = _parser().parse(data)
    src = Source(data)
    if tree.root_node.has_error:
        bad = _first_error(tree.root_node)
        raise HclError(f"line {bad.start_point[0] + 1}: syntax error")
    body = next((c for c in tree.root_node.children if c.type == "body"), None)
    return (_body(body, src) if body is not None else Body()), src


def _first_error(node):
    if node.type == "ERROR" or node.is_missing:
        return node
    for c in node.children:
        if c.has_error:
            return _first_error(c)
    return node


def _body(node, src: Source) -> Body:
    out = Body()
    for c in node.children:
        if c.type == "attribute":
            name = src.text(c.children[0])
            expr = next(x for x in c.children if x.type == "expression")
            try:
                e = _expr(expr, src)
            except (HclError, StopIteration, IndexError):
                e = Expr("opaque", expr)           # a construct not modelled: its value is unknown
            out.attributes[name] = Attribute(name, e, c.start_point[0] + 1)
        elif c.type == "block":
            btype = src.text(c.children[0])
            labels = []
            inner = None
            for x in c.children[1:]:
                if x.type == "string_lit":
                    labels.append(_string_lit(x, src))
                elif x.type == "identifier":
                    labels.append(src.text(x))
                elif x.type == "body":
                    inner = x
            out.blocks.append(Block(btype, labels, _body(inner, src) if inner is not None else Body(),
                                    c.start_point[0] + 1))
    return out


def _string_lit(node, src: Source) -> str:
    inner = src.data[node.start_byte + 1:node.end_byte - 1].decode("utf-8", errors="replace")
    return _unescape(inner, quoted=True)


_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


def _unescape(s: str, quoted: bool) -> str:
    """A template literal's text: `$${` and `%%{` always; backslash escapes in quoted templates."""
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if quoted and c == "\\" and i + 1 < n:
            e = s[i + 1]
            if e in _ESCAPES:
                out.append(_ESCAPES[e])
                i += 2
                continue
            if e in ("u", "U"):
                width = 4 if e == "u" else 8
                hexd = s[i + 2:i + 2 + width]
                if len(hexd) == width and all(h in "0123456789abcdefABCDEF" for h in hexd):
                    out.append(chr(int(hexd, 16)))
                    i += 2 + width
                    continue
            raise HclError(f"invalid escape sequence \\{e}")
        if c in ("$", "%") and s.startswith(c + c + "{", i):
            out.append(c + "{")
            i += 3
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _term(kids, node, src: Source) -> Expr:
    """A primary expression followed by its accessors (`var.a[0].b`), as tree-sitter-hcl lays
    them out: siblings, inside an `expression` or an operator's operand."""
    kids = [k for k in kids if k.type != "comment"]
    if not kids:
        raise HclError("empty expression")
    if kids[0].type == "(":                           # ( expression ) followed by accessors
        base = Expr("paren", node, parts=[_expr(kids[1], src)])
        rest = kids[3:]
    else:
        base = _expr(kids[0], src)
        rest = kids[1:]
    if rest:
        return Expr("ref", node, value=base, steps=_steps(rest, src))
    return base


def _expr(node, src: Source) -> Expr:
    if node.type == "expression":
        return _term(list(node.children), node, src)
    t = node.type
    if t == "literal_value":
        return _literal(node.children[0], src)
    if t == "variable_expr":
        return Expr("ref", node, value=src.text(node.children[0]), steps=[])
    if t == "collection_value":
        coll = node.children[0]
        if coll.type == "tuple":
            return Expr("tuple", node, parts=[_expr(c, src) for c in coll.children if c.type == "expression"])
        items = []
        for el in coll.children:
            if el.type != "object_elem":
                continue
            key = el.child_by_field_name("key")
            val = el.child_by_field_name("val")
            items.append((_object_key(key, src), _expr(val, src)))
        return Expr("obj", node, parts=items)
    if t == "template_expr":
        return _template(node.children[0], src)
    if t == "function_call":
        name = src.text(node.children[0])
        args, expand = [], False
        fa = next((c for c in node.children if c.type == "function_arguments"), None)
        if fa is not None:
            for c in fa.children:
                if c.type == "expression":
                    args.append(_expr(c, src))
                elif c.type == "ellipsis":
                    expand = True
        e = Expr("call", node, value=name, parts=args)
        e.steps = [("expand", expand)]
        return e
    if t == "conditional":
        exprs = [c for c in node.children if c.type == "expression"]
        return Expr("cond", node, parts=[_expr(x, src) for x in exprs])
    if t == "operation":
        return _expr(node.children[0], src)
    if t == "unary_operation":
        kids = list(node.children)
        return Expr("unary", node, value=src.text(kids[0]), parts=[_term(kids[1:], node, src)])
    if t == "binary_operation":
        kids = list(node.children)
        i = next(j for j, c in enumerate(kids) if not c.is_named and c.type not in ("(", ")") and j > 0)
        return Expr("binary", node, value=src.text(kids[i]),
                    parts=[_term(kids[:i], node, src), _term(kids[i + 1:], node, src)])
    if t == "for_expr":
        return _for(node.children[0], src)
    if t in ("tuple", "object"):
        return _expr_wrap(node, src)
    raise HclError(f"unsupported expression {t}")


def _expr_wrap(node, src):
    fake = type("N", (), {"children": [node], "type": "collection_value"})
    return _expr(fake, src)


def _object_key(node, src: Source):
    """('name', str) for an identifier key, which is taken literally; else ('expr', Expr)."""
    kids = node.children
    if len(kids) == 1 and kids[0].type == "variable_expr":
        return ("name", src.text(kids[0].children[0]))
    if kids and kids[0].type == "(":
        return ("expr", _expr(kids[1], src))
    return ("expr", _expr(node, src))


def _literal(node, src: Source) -> Expr:
    t = node.type
    if t == "numeric_lit":
        return Expr("lit", node, value=_number(src.text(node)))
    if t == "bool_lit":
        return Expr("lit", node, value=src.text(node) == "true")
    if t == "null_lit":
        return Expr("lit", node, value=None)
    if t == "string_lit":
        return Expr("lit", node, value=_string_lit(node, src))
    raise HclError(f"unsupported literal {t}")


def _number(text: str):
    try:
        d = Decimal(text)
    except InvalidOperation:
        raise HclError(f"bad number {text}") from None
    return int(d) if d == d.to_integral_value() else float(d)


def _steps(nodes, src: Source) -> List[Tuple]:
    out: List[Tuple] = []
    for n in nodes:
        if n.type == "get_attr":
            out.append(("attr", src.text(n.children[-1])))
        elif n.type == "index":
            idx = n.children[0]
            if idx.type == "new_index":
                out.append(("index", _expr(next(c for c in idx.children if c.type == "expression"), src)))
            else:                                       # legacy_index: .0
                out.append(("index", Expr("lit", idx, value=int(src.text(idx)[1:]))))
        elif n.type == "splat":
            sp = n.children[0]
            inner = [c for c in sp.children if c.type in ("get_attr", "index")]
            out.append(("splat", sp.type, _steps(inner, src)))
        else:
            raise HclError(f"unsupported accessor {n.type}")
    return out


def _template(node, src: Source) -> Expr:
    """A quoted or heredoc template: parts are literal text and Exprs (directives unsupported)."""
    quoted = node.type == "quoted_template"
    kids = list(node.children)
    if quoted:
        start, end = kids[0].end_byte, kids[-1].start_byte
        inner_nodes = kids[1:-1]
    else:
        ident = [k for k in kids if k.type == "heredoc_identifier"]
        flush = src.text(kids[0]).endswith("-")
        line_end = src.data.index(b"\n", ident[0].end_byte)
        start = line_end + 1
        close = ident[-1]
        end = src.data.rfind(b"\n", 0, close.start_byte) + 1
        inner_nodes = kids[1:]
    parts: List[Any] = []
    pos = start
    for k in inner_nodes:
        if k.type == "template_interpolation":
            if k.start_byte > pos:
                parts.append(src.data[pos:k.start_byte].decode("utf-8", errors="replace"))
            inner = [c for c in k.children if c.type == "expression"]
            strip = (src.text(k.children[0]).endswith("~"), src.text(k.children[-1]).startswith("~"))
            if strip != (False, False):
                raise HclError("template strip markers are not modelled")
            parts.append(_expr(inner[0], src))
            pos = k.end_byte
        elif k.type == "template_directive":
            raise HclError("template directives are not modelled")
    if end > pos:
        parts.append(src.data[pos:end].decode("utf-8", errors="replace"))
    texts = []
    for p in parts:
        texts.append(_unescape(p, quoted) if isinstance(p, str) else p)
    if not quoted and flush:
        texts = _flush(texts)
    e = Expr("tmpl", node, parts=[p for p in texts if p != ""])
    e.value = quoted
    return e


def _flush(parts: List[Any]) -> List[Any]:
    """`<<-`: the least indentation of the lines (blank lines aside) is removed from each."""
    lines_start = True
    widths = []
    for p in parts:
        if isinstance(p, str):
            segs = p.split("\n")
            for i, seg in enumerate(segs):
                at_start = lines_start if i == 0 else True
                last = i == len(segs) - 1
                if at_start:
                    stripped = seg.lstrip(" \t")
                    if not (stripped == "" and not last):
                        if stripped or last:
                            widths.append(len(seg) - len(stripped))
                lines_start = False
            lines_start = p.endswith("\n")
        else:
            lines_start = False
    if any(not isinstance(p, str) for p in parts):
        raise HclError("flush heredocs with interpolations are not modelled")
    text = "".join(parts)
    lines = text.split("\n")
    body = [ln for ln in lines[:-1] if ln.strip(" \t")]
    if not body:
        return [text]
    m = min(len(ln) - len(ln.lstrip(" \t")) for ln in body)
    return ["\n".join(ln[m:] if ln.strip(" \t") else ln.lstrip(" \t") for ln in lines)]


def _for(node, src: Source) -> Expr:
    intro = next(c for c in node.children if c.type == "for_intro")
    names = [src.text(c) for c in intro.children if c.type == "identifier"]
    coll = _expr(next(c for c in intro.children if c.type == "expression"), src)
    exprs = [c for c in node.children if c.type == "expression"]
    cond = next((c for c in node.children if c.type == "for_cond"), None)
    cond_e = _expr(next(c for c in cond.children if c.type == "expression"), src) if cond is not None else None
    grouping = any(c.type == "ellipsis" for c in node.children)
    e = Expr("for", node, value=node.type == "for_object_expr",
             parts=[coll] + [_expr(x, src) for x in exprs])
    e.steps = [("names", names), ("cond", cond_e), ("group", grouping)]
    return e


# --- values ------------------------------------------------------------------------------------

def is_unknown(v) -> bool:
    return isinstance(v, Unknown)


def contains_unknown(v) -> bool:
    if isinstance(v, Unknown):
        return True
    if isinstance(v, list):
        return any(contains_unknown(x) for x in v)
    if isinstance(v, dict):
        return any(contains_unknown(x) for x in v.values())
    return False


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def num_text(v) -> str:
    """A number as cty prints it (big.Float 'f' format)."""
    if isinstance(v, int):
        return str(v)
    if v == int(v):
        return str(int(v))
    return format(Decimal(repr(v)), "f")


def to_string(v):
    if isinstance(v, Unknown):
        return v
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if _is_num(v):
        return num_text(v)
    if v is None:
        raise HclError("null value cannot be used as a string")
    raise HclError("cannot convert a collection to a string")


def to_number(v):
    if isinstance(v, Unknown) or _is_num(v):
        return v
    if isinstance(v, str):
        if re.fullmatch(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?", v):
            return _number(v)
        raise HclError(f"cannot convert {v!r} to a number")
    raise HclError("not a number")


def to_bool(v):
    if isinstance(v, Unknown) or isinstance(v, bool):
        return v
    if v == "true":
        return True
    if v == "false":
        return False
    raise HclError("not a bool")


def _norm(v):
    if isinstance(v, float) and v == int(v) and abs(v) < 2 ** 63:
        return int(v)
    return v


def _equal(a, b) -> bool:
    """cty equality for known values: no conversion between types."""
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_num(a) and _is_num(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    return False


# --- evaluation ------------------------------------------------------------------------------

class Scope:
    """Names an expression can read: `lookup(root)` gives the value of `var`, `local`, a
    resource type, ...; `fn(name)` a function or None (an unmodelled function is unknown)."""

    def __init__(self, roots: Dict[str, Any], functions: Optional[Dict[str, Callable]] = None,
                 key_prefix: str = ""):
        self.roots = roots
        self.functions = functions if functions is not None else FUNCTIONS
        self.key_prefix = key_prefix

    def child(self, extra: Dict[str, Any]) -> "Scope":
        s = Scope({**self.roots, **extra}, self.functions, self.key_prefix)
        return s


def _unknown(e: Expr, src_text: str, scope: Scope) -> Unknown:
    return Unknown(f"{scope.key_prefix}{src_text}", src_text)


def evaluate(e: Expr, scope: Scope, src: Source):
    """The value of `e`, or an Unknown. HclError where HCL would report an error."""
    if e.src is not None:
        src = e.src
    k = e.kind
    if k == "lit":
        return e.value
    if k == "paren":
        return evaluate(e.parts[0], scope, src)
    if k == "tmpl":
        vals = [p if isinstance(p, str) else evaluate(p, scope, src) for p in e.parts]
        if len(e.parts) == 1 and not isinstance(e.parts[0], str):
            v = vals[0]                                 # "${x}" is x itself
            return v
        if not e.parts:
            return ""
        if any(isinstance(v, Unknown) for v in vals):
            return _unknown(e, src.text(e.node), scope)
        return "".join(to_string(v) for v in vals)
    if k == "tuple":
        return [evaluate(p, scope, src) for p in e.parts]
    if k == "obj":
        out: Dict[str, Any] = {}
        for (kind, key), val in e.parts:
            if kind == "name":
                name = key
            else:
                kv = evaluate(key, scope, src)
                if isinstance(kv, Unknown):
                    return _unknown(e, src.text(e.node), scope)
                name = to_string(kv)
            out[name] = evaluate(val, scope, src)
        return out
    if k == "ref":
        return _traverse(e, scope, src)
    if k == "cond":
        c = to_bool(evaluate(e.parts[0], scope, src))
        a = evaluate(e.parts[1], scope, src)
        b = evaluate(e.parts[2], scope, src)
        if isinstance(c, Unknown):
            return _unknown(e, src.text(e.node), scope)
        chosen, other = (a, b) if c else (b, a)
        # HCL converts both results to one type; decided only where that changes nothing
        if chosen is None or other is None or (_type_sig(chosen) == _type_sig(other) and _type_sig(chosen)):
            return chosen
        return _unknown(e, src.text(e.node), scope)
    if k == "unary":
        v = evaluate(e.parts[0], scope, src)
        if e.value == "!":
            v = to_bool(v)
            return v if isinstance(v, Unknown) else (not v)
        v = to_number(v)
        return v if isinstance(v, Unknown) else _norm(-v)
    if k == "binary":
        return _binary(e, scope, src)
    if k == "call":
        return _call(e, scope, src)
    if k == "for":
        return _for_value(e, scope, src)
    if k == "opaque":
        return _unknown(e, src.text(e.node), scope)
    raise HclError(f"cannot evaluate {k}")


def _type_sig(v):
    """A known value's type, enough to tell when HCL's type unification would convert it; None
    when it cannot be told (an unknown or a null inside)."""
    if isinstance(v, Unknown) or v is None:
        return None
    if isinstance(v, bool):
        return "bool"
    if _is_num(v):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        parts = [_type_sig(x) for x in v]
        return None if None in parts else ("tuple", tuple(parts))
    if isinstance(v, dict):
        parts = {k: _type_sig(x) for k, x in v.items()}
        return None if None in parts.values() else ("object", tuple(sorted(parts.items())))
    return None


def _same_kind(a, b) -> bool:
    sa, sb = _type_sig(a), _type_sig(b)
    return sa is not None and sa == sb


_ARITH = {"+", "-", "*", "/", "%"}
_ORDER = {"<", "<=", ">", ">="}


def _binary(e: Expr, scope: Scope, src: Source):
    op = e.value
    a = evaluate(e.parts[0], scope, src)
    b = evaluate(e.parts[1], scope, src)
    if op in ("&&", "||"):
        a, b = to_bool(a), to_bool(b)
        control = op == "||"
        if a is control or b is control:
            return control
        if isinstance(a, Unknown) or isinstance(b, Unknown):
            return _unknown(e, src.text(e.node), scope)
        return (a or b) if control else (a and b)
    if op in ("==", "!="):
        if contains_unknown(a) or contains_unknown(b):
            return _unknown(e, src.text(e.node), scope)
        r = _equal(a, b)
        return r if op == "==" else (not r)
    a, b = to_number(a), to_number(b)
    if isinstance(a, Unknown) or isinstance(b, Unknown):
        return _unknown(e, src.text(e.node), scope)
    if op in _ORDER:
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    if op == "+":
        return _norm(a + b)
    if op == "-":
        return _norm(a - b)
    if op == "*":
        return _norm(a * b)
    if op == "/":
        if b == 0:
            raise HclError("division by zero")
        q = Decimal(num_text(a)) / Decimal(num_text(b))
        return int(q) if q == q.to_integral_value() else _unknown(e, src.text(e.node), scope)
    if op == "%":
        if b == 0:
            raise HclError("modulo by zero")
        if isinstance(a, int) and isinstance(b, int):
            return int(Decimal(a) % Decimal(b))      # Go's remainder takes the dividend's sign
        return _unknown(e, src.text(e.node), scope)
    raise HclError(f"unknown operator {op}")


def _get_attr(v, name: str, e: Expr, src: Source, scope: Scope):
    if isinstance(v, Unknown):
        return v.child(name)
    if isinstance(v, dict):
        if name in v:
            return v[name]
        raise HclError(f"unsupported attribute {name!r}")
    if v is None:
        raise HclError("attempt to get an attribute from a null value")
    raise HclError(f"cannot get attribute {name!r} of a {type(v).__name__}")


def _index(v, i, e: Expr, src: Source, scope: Scope):
    if hasattr(v, "resolved"):              # a resource with count or for_each (terraform.py)
        v = v.resolved()
    if isinstance(v, Unknown):
        return v.child(i if isinstance(i, (int, str)) and not isinstance(i, Unknown) else "?")
    if isinstance(i, Unknown):
        return _unknown(e, src.text(e.node), scope)
    if isinstance(v, list):
        n = to_number(i)
        if not isinstance(n, int) or isinstance(n, bool):
            raise HclError("list index must be a whole number")
        if 0 <= n < len(v):
            return v[n]
        raise HclError("index out of range")
    if isinstance(v, dict):
        key = to_string(i)
        if key in v:
            return v[key]
        raise HclError(f"no element {key!r}")
    raise HclError("cannot index a value of this type")


def _apply(v, steps, e: Expr, scope: Scope, src: Source):
    for i, step in enumerate(steps):
        if step[0] == "attr":
            v = _get_attr(v, step[1], e, src, scope)
        elif step[0] == "index":
            v = _index(v, evaluate(step[1], scope, src), e, src, scope)
        else:                                            # splat: the rest applies to each element
            _, kind, inner = step
            rest = list(inner) + list(steps[i + 1:]) if kind == "full_splat" else list(inner)
            after = [] if kind == "full_splat" else list(steps[i + 1:])
            if hasattr(v, "resolved"):
                v = v.resolved()
            if isinstance(v, Unknown):
                return _unknown(e, src.text(e.node), scope)
            if v is None:
                items: List[Any] = []
            elif isinstance(v, list):
                items = v
            else:
                items = [v]
            out = [_apply(x, rest, e, scope, src) for x in items]
            if kind == "full_splat":
                return out
            return _apply(out, after, e, scope, src)
    return v


def _traverse(e: Expr, scope: Scope, src: Source):
    base = e.value
    if isinstance(base, Expr):
        v = evaluate(base, scope, src)
    else:
        if base not in scope.roots:
            raise HclError(f"unknown name {base!r}")
        v = scope.roots[base]
    return _apply(v, e.steps, e, scope, src)


def _for_value(e: Expr, scope: Scope, src: Source):
    names = dict(e.steps)["names"]
    cond = dict(e.steps)["cond"]
    group = dict(e.steps)["group"]
    coll = evaluate(e.parts[0], scope, src)
    if isinstance(coll, Unknown):
        return _unknown(e, src.text(e.node), scope)
    if isinstance(coll, dict):
        pairs = [(k, coll[k]) for k in sorted(coll)]
    elif isinstance(coll, list):
        pairs = list(enumerate(coll))
    else:
        raise HclError("for expression needs a collection")
    is_obj = e.value
    out_list: List[Any] = []
    out_obj: Dict[str, Any] = {}
    for k, v in pairs:
        bind = {names[-1]: v} if len(names) == 1 else {names[0]: k, names[1]: v}
        inner = scope.child(bind)
        if cond is not None:
            c = to_bool(evaluate(cond, inner, src))
            if isinstance(c, Unknown):
                return _unknown(e, src.text(e.node), scope)
            if not c:
                continue
        if is_obj:
            key = evaluate(e.parts[1], inner, src)
            val = evaluate(e.parts[2], inner, src)
            if isinstance(key, Unknown):
                return _unknown(e, src.text(e.node), scope)
            key = to_string(key)
            if group:
                out_obj.setdefault(key, []).append(val)
            elif key in out_obj:
                raise HclError(f"duplicate key {key!r} in for expression")
            else:
                out_obj[key] = val
        else:
            out_list.append(evaluate(e.parts[1], inner, src))
    return out_obj if is_obj else out_list


def _call(e: Expr, scope: Scope, src: Source):
    name = e.value
    args = [evaluate(a, scope, src) for a in e.parts]
    if dict(e.steps).get("expand"):
        last = args.pop() if args else None
        if isinstance(last, Unknown):
            return _unknown(e, src.text(e.node), scope)
        if not isinstance(last, list):
            raise HclError("expanding argument must be a list")
        args += last
    fn = scope.functions.get(name)
    if fn is None:
        return _unknown(e, src.text(e.node), scope)
    try:
        return fn(*args)
    except _Undecided:
        return _unknown(e, src.text(e.node), scope)
    except TypeError:
        raise HclError(f"wrong number of arguments to {name}") from None


class _Undecided(Exception):
    """A function argument this implementation cannot decide on (an unknown, an edge case)."""


# --- functions (go-cty's stdlib, as Terraform registers them) ----------------------------------

def _known(*vals):
    for v in vals:
        if contains_unknown(v):
            raise _Undecided()


def _f_jsonencode(v):
    _known(v)
    return _json_text(v)


def _json_string(s: str) -> str:
    # Go's encoding/json: UTF-8 kept, <, >, & and U+2028/U+2029 escaped
    out = json.dumps(s, ensure_ascii=False)
    for ch, esc in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                    ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        out = out.replace(ch, esc)
    return out


def _json_text(v) -> str:
    """ctyjson's encoding: object keys sorted, numbers as cty prints them."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if _is_num(v):
        return num_text(v)
    if isinstance(v, str):
        return _json_string(v)
    if isinstance(v, list):
        return "[" + ",".join(_json_text(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(_json_string(k) + ":" + _json_text(v[k]) for k in sorted(v)) + "}"
    raise _Undecided()


def _f_jsondecode(s):
    _known(s)
    try:
        v = json.loads(to_string(s))
    except ValueError:
        raise HclError("invalid JSON") from None
    return _from_json(v)


def _from_json(v):
    if isinstance(v, float):
        return _norm(v)
    if isinstance(v, list):
        return [_from_json(x) for x in v]
    if isinstance(v, dict):
        return {k: _from_json(x) for k, x in v.items()}
    return v


def _string_fn(f):
    def call(s):
        _known(s)
        s = to_string(s)
        if not s.isascii():
            raise _Undecided()             # Go's Unicode case mapping, not Python's
        return f(s)
    return call


def _shallow(*vals):
    """Only the values themselves must be known (their elements may not be)."""
    for v in vals:
        if isinstance(v, Unknown):
            raise _Undecided()


def _f_concat(*lists):
    _shallow(*lists)
    out = []
    for x in lists:
        if not isinstance(x, list):
            raise HclError("concat takes lists")
        out += x
    return out


def _f_merge(*maps):
    _shallow(*maps)
    out: Dict[str, Any] = {}
    for m in maps:
        if m is None:
            continue
        if not isinstance(m, dict):
            raise HclError("merge takes maps")
        out.update(m)
    return out


def _f_lookup(m, key, *default):
    _shallow(m)
    _known(key)
    if not isinstance(m, dict):
        raise HclError("lookup takes a map")
    k = to_string(key)
    if k in m:
        return m[k]
    if default:
        return default[0]
    raise HclError(f"lookup failed to find {k!r}")


def _f_length(v):
    _shallow(v)
    if isinstance(v, (list, dict)):
        return len(v)
    if isinstance(v, str) and v.isascii():
        return len(v)                      # grapheme clusters, which ASCII text counts as characters
    raise _Undecided()


def _f_contains(lst, v):
    _known(lst, v)
    if not isinstance(lst, list):
        raise HclError("contains takes a list")
    if not all(_same_kind(x, v) for x in lst):
        raise _Undecided()                 # the value is converted to the element type first
    return any(_equal(x, v) for x in lst)


def _f_coalesce(*vals):
    _known(*vals)
    for v in vals:
        if v is not None and v != "":
            if not all(_same_kind(v, w) for w in vals if w is not None and w != ""):
                raise _Undecided()         # coalesce unifies the arguments' types
            return v
    raise HclError("no non-null, non-empty argument")


def _f_compact(lst):
    _known(lst)
    if not isinstance(lst, list) or not all(isinstance(x, str) or x is None for x in lst):
        raise _Undecided()
    return [x for x in lst if x not in (None, "")]


def _f_flatten(lst):
    _shallow(lst)
    if not isinstance(lst, list):
        raise HclError("flatten takes a list")
    out = []
    for x in lst:
        if isinstance(x, Unknown):
            raise _Undecided()             # it may be a list, to flatten too
        out += _f_flatten(x) if isinstance(x, list) else [x]
    return out


def _f_join(sep, *lists):
    _known(sep, *lists)
    items = []
    for lst in lists:
        if not isinstance(lst, list):
            raise HclError("join takes lists")
        items += lst
    if any(x is None for x in items):
        raise HclError("join of a null element")
    return to_string(sep).join(to_string(x) for x in items)


def _f_split(sep, s):
    _known(sep, s)
    sep, s = to_string(sep), to_string(s)
    if sep == "":
        raise _Undecided()
    return s.split(sep)


def _f_keys(m):
    _shallow(m)
    if not isinstance(m, dict):
        raise HclError("keys takes a map")
    return sorted(m)


def _f_values(m):
    _shallow(m)
    if not isinstance(m, dict):
        raise HclError("values takes a map")
    return [m[k] for k in sorted(m)]


def _f_tostring(v):
    if v is None:
        return None
    _known(v)
    return to_string(v)


def _f_tonumber(v):
    if v is None:
        return None
    _known(v)
    return to_number(v)


def _f_tobool(v):
    if v is None:
        return None
    _known(v)
    return to_bool(v)


def _f_tolist(v):
    _known(v)
    if not isinstance(v, list) or not all(_same_kind(v[0], x) for x in v[1:]):
        raise _Undecided()
    return list(v)


def _f_element(lst, i):
    _shallow(lst)
    _known(i)
    if not isinstance(lst, list) or not lst:
        raise HclError("element of an empty or non-list value")
    n = to_number(i)
    if not isinstance(n, int) or n < 0:
        raise _Undecided()
    return lst[n % len(lst)]


def _f_try(*vals):
    raise _Undecided()                     # needs lazy evaluation of its arguments


FUNCTIONS: Dict[str, Callable] = {
    "jsonencode": _f_jsonencode, "jsondecode": _f_jsondecode,
    "lower": _string_fn(str.lower), "upper": _string_fn(str.upper),
    "concat": _f_concat, "merge": _f_merge, "lookup": _f_lookup, "length": _f_length,
    "contains": _f_contains, "coalesce": _f_coalesce, "compact": _f_compact, "flatten": _f_flatten,
    "join": _f_join, "split": _f_split, "keys": _f_keys, "values": _f_values,
    "tostring": _f_tostring, "tonumber": _f_tonumber, "tobool": _f_tobool, "tolist": _f_tolist,
    "element": _f_element,
}


__all__ = ["Attribute", "Block", "Body", "Expr", "FUNCTIONS", "HclError", "Scope", "Source", "contains_unknown",
           "evaluate", "is_unknown", "num_text", "parse", "to_string"]


# --- type constraints (a variable's `type`) --------------------------------------------------

def type_constraint(e: Expr, src: Source):
    """A `type` expression as a structure: "string" / "number" / "bool" / "any",
    ("list"|"set"|"map", T), ("tuple", [T]), ("object", {name: (T, optional, default Expr)}).
    HclError for what is not a type."""
    if e.kind == "ref" and not e.steps and isinstance(e.value, str):
        if e.value in ("string", "number", "bool", "any"):
            return e.value
        raise HclError(f"unknown type {e.value}")
    if e.kind == "call":
        name, args = e.value, e.parts
        if name in ("list", "set", "map") and len(args) == 1:
            return (name, type_constraint(args[0], src))
        if name == "tuple" and len(args) == 1 and args[0].kind == "tuple":
            return ("tuple", [type_constraint(a, src) for a in args[0].parts])
        if name == "object" and len(args) == 1 and args[0].kind == "obj":
            attrs = {}
            for (kind, key), val in args[0].parts:
                if kind != "name":
                    if key.kind == "lit" and isinstance(key.value, str):
                        key = key.value
                    elif key.kind == "tmpl" and len(key.parts) == 1 and isinstance(key.parts[0], str):
                        key = key.parts[0]
                    else:
                        raise HclError("object attribute names must be literal")
                optional, default = False, None
                if val.kind == "call" and val.value == "optional" and 1 <= len(val.parts) <= 2:
                    optional = True
                    default = val.parts[1] if len(val.parts) == 2 else None
                    val = val.parts[0]
                attrs[key] = (type_constraint(val, src), optional, default)
            return ("object", attrs)
    raise HclError("not a type constraint")


def convert(v, t, src: Source, scope: Optional[Scope] = None):
    """`v` converted to type `t` as cty's convert (with typeexpr's optional-attribute defaults)
    does it. An Unknown stays unknown; HclError where the conversion fails; what is not decided
    here (sets of non-primitive values) becomes unknown."""
    if isinstance(v, Unknown):
        return v
    if v is None or t == "any":
        return v
    if t == "string":
        return to_string(v)
    if t == "number":
        return to_number(v)
    if t == "bool":
        return to_bool(v)
    kind = t[0]
    if kind in ("list", "set"):
        if not isinstance(v, list):
            raise HclError(f"a {kind} is required")
        items = [convert(x, t[1], src, scope) for x in v]
        if kind == "set":
            if not all(isinstance(x, str) for x in items) and not all(_is_num(x) for x in items):
                raise _SetUndecided()
            items = sorted(set(items))
        return items
    if kind == "map":
        if not isinstance(v, dict):
            raise HclError("a map is required")
        return {k: convert(x, t[1], src, scope) for k, x in v.items()}
    if kind == "tuple":
        if not isinstance(v, list) or len(v) != len(t[1]):
            raise HclError("a tuple of the right length is required")
        return [convert(x, et, src, scope) for x, et in zip(v, t[1])]
    if kind == "object":
        if not isinstance(v, dict):
            raise HclError("an object is required")
        out = {}
        for name, (at, optional, default) in t[1].items():
            if name in v and v[name] is not None:
                out[name] = convert(v[name], at, src, scope)
            elif optional:
                if default is not None:
                    out[name] = convert(evaluate(default, scope or Scope({}), src), at, src, scope)
                else:
                    out[name] = None
            elif name in v:
                out[name] = None
            else:
                raise HclError(f"attribute {name!r} is required")
        return out
    raise HclError("unknown type")


class _SetUndecided(HclError):
    pass


__all__ += ["convert", "type_constraint"]


# --- Terraform's JSON syntax (developer.hashicorp.com/terraform/language/syntax/json) ----------

_JSON_BLOCKS = {"resource": 2, "data": 2, "module": 1, "variable": 1, "output": 1, "provider": 1}


def _quoted(text: str) -> str:
    """A JSON string's text as an HCL quoted template: the same template, escaped for quotes."""
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _snippet(hcl_text: str) -> Expr:
    body, src = parse(f"x = {hcl_text}\n")
    e = body.attributes["x"].expr
    e.src = src
    return e


def _json_expr(value, template: bool = True) -> Expr:
    """A JSON value as an expression: a string is a template (or, outside an expression
    context, literal text); arrays and objects hold expressions."""
    if isinstance(value, str):
        return _snippet(_quoted(value)) if template else Expr("lit", value=value)
    if isinstance(value, list):
        return Expr("tuple", parts=[_json_expr(v, template) for v in value])
    if isinstance(value, dict):
        return Expr("obj", parts=[(("name", k), _json_expr(v, template)) for k, v in value.items() if k != "//"])
    if isinstance(value, float) and value == int(value):
        value = int(value)
    return Expr("lit", value=value)


def _json_body(obj, lines, path, kind: str = "") -> "Body":
    body = Body()
    if not isinstance(obj, dict):
        return body
    for k, v in obj.items():
        if k == "//":
            continue
        line = lines.get(path + (k,), 0)
        if kind == "variable" and k in ("default",):
            body.attributes[k] = Attribute(k, _json_expr(v, template=False), line)
        elif kind == "variable" and k == "type" and isinstance(v, str):
            try:
                body.attributes[k] = Attribute(k, _snippet(v), line)
            except HclError:
                continue
        else:
            body.attributes[k] = Attribute(k, _json_expr(v), line)
    return body


def parse_json(text: str) -> Tuple["Body", "Source"]:
    """A `.tf.json` file as the same bodies and blocks `parse` makes. A nested object is read as
    an attribute (a block's schema, which the JSON syntax leaves to the provider, is not known),
    so a nested block written as one object is a map, and as an array of objects a list of them,
    which is how block lists are read from HCL."""
    from .yaml_doc import YamlError, load_all
    try:
        docs = list(load_all(text))
    except YamlError as e:
        raise HclError(f"not valid JSON: {e}") from None
    if len(docs) != 1 or not isinstance(docs[0][0], dict):
        raise HclError("a Terraform JSON file is one object")
    top, lines, _ = docs[0]
    out = Body()
    for btype, content in top.items():
        if btype == "locals":
            for i, obj in enumerate(content if isinstance(content, list) else [content]):
                path = ("locals", i) if isinstance(content, list) else ("locals",)
                out.blocks.append(Block("locals", [], _json_body(obj, lines, path), lines.get(path, 1)))
            continue
        depth = _JSON_BLOCKS.get(btype)
        if depth is None:
            continue

        def walk(value, labels, path):
            if len(labels) == depth:
                items = value if isinstance(value, list) else [value]
                for i, item in enumerate(items):
                    p = path + ((i,) if isinstance(value, list) else ())
                    out.blocks.append(Block(btype, list(labels), _json_body(item, lines, p, btype), lines.get(p, 1)))
                return
            if isinstance(value, dict):
                for k, v in value.items():
                    if k != "//":
                        walk(v, labels + [k], path + (k,))
        walk(content, [], (btype,))
    return out, Source(text.encode("utf-8"))


__all__ += ["parse_json"]
