"""The policy language: what a `[[policy]]` entry's `when` says, parsed into a small tree.

A policy describes a misconfiguration as a formula over a resource's values:

    some c in containers: default(c.securityContext.privileged, false) == true
    pod.hostNetwork == true or pod.hostPID == true
    some v in pod.volumes: present(v.hostPath)
    some (k, v) in podmeta.annotations: starts_with(k, "container.apparmor.security.beta.kubernetes.io/")
        and not (v == "" or v == "runtime/default" or starts_with(v, "localhost/"))

Grammar (keywords are lower case; `#` starts a comment):

    expr       := and ('or' and)*
    and        := unary ('and' unary)*
    unary      := 'not' unary | quantifier | '(' expr ')' | atom
    quantifier := ('some' | 'every') binder 'in' collection ':' expr   -- the body extends as far
                                                                     -- right as it can
    binder     := NAME | '(' NAME ',' NAME ')'          -- (key, value) over a map
    collection := path ('+' path)*                      -- lists are concatenated
    atom       := 'present' '(' path ')' | 'absent' '(' path ')'
                | 'starts_with' '(' operand ',' STRING ')'
                | operand OP operand                    -- == != < <= > >= in, not in
    operand    := path | literal | 'default' '(' path ',' literal ')'
    path       := NAME ('.' NAME | '[' STRING ']' | '[' INT ']')*
    literal    := STRING | NUMBER | 'true' | 'false' | '[' literal (',' literal)* ']'

A path starts at a name the evaluator binds: a quantifier's variable, or one of the resource's
views (`pod`, `podmeta`, `self`, ...; frame/iac/formats). A view that is a list of paths (the
Kubernetes `containers`) is a collection. A comparison with a missing value is false (`==` and
`!=` alike): write `default(path, value)` for the value a missing field takes, as the platform
defines it (Go's zero values for Kubernetes), and `present`/`absent` to ask about presence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Tuple, Union


class PolicyError(ValueError):
    """A `when` expression that does not parse."""


# --- syntax tree -------------------------------------------------------------------------

@dataclass(frozen=True)
class Path:
    root: str
    steps: Tuple[Union[str, int], ...] = ()

    def __str__(self) -> str:
        out = self.root
        for s in self.steps:
            out += f"[{s}]" if isinstance(s, int) else (f".{s}" if s.replace("_", "").isalnum() else f'["{s}"]')
        return out


@dataclass(frozen=True)
class Literal:
    value: Any                       # str, int, float, bool, or a tuple of literals


@dataclass(frozen=True)
class Default:
    path: Path
    value: Any


Operand = Union[Path, Literal, Default]


@dataclass(frozen=True)
class Compare:
    op: str                          # == != < <= > >= in notin
    left: Operand
    right: Operand


@dataclass(frozen=True)
class Present:
    path: Path
    negate: bool = False             # absent(...)


@dataclass(frozen=True)
class StartsWith:
    operand: Operand
    prefix: str


@dataclass(frozen=True)
class Internet:
    """`internet(x)`: x is a CIDR (or address) that contains an address the internet can send
    from (frame/iac/addresses.py); `internet(x, 4)` / `internet(x, 6)`: and of that IP version
    (a field that takes only IPv4 networks makes nothing of an IPv6 one)."""
    operand: "Operand"
    family: int = 0


@dataclass(frozen=True)
class Call:
    """`name(args)`: a pack's [[define]], inlined when the pack is loaded."""
    name: str
    args: Tuple["Operand", ...]


@dataclass(frozen=True)
class Not:
    expr: "Expr"


@dataclass(frozen=True)
class BoolOp:
    op: str                          # and / or
    parts: Tuple["Expr", ...]


@dataclass(frozen=True)
class Quantifier:
    kind: str                        # some / every
    names: Tuple[str, ...]           # (x,) over a list, (k, v) over a map
    collection: Tuple[Path, ...]
    body: "Expr"


Expr = Union[Compare, Present, StartsWith, Internet, Call, Not, BoolOp, Quantifier]


# --- tokenizer ---------------------------------------------------------------------------

_KEYWORDS = {"and", "or", "not", "some", "every", "in", "true", "false", "present", "absent",
             "default", "starts_with", "internet"}
_OPERATORS = ("==", "!=", "<=", ">=", "<", ">")
_PUNCT = "().,[]:+"


def _tokens(text: str) -> List[Tuple[str, Any, int]]:
    """(kind, value, offset) with kind NAME / KW / STR / NUM / OP / P."""
    out: List[Tuple[str, Any, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c == '"':
            j, buf = i + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    esc = text[j + 1]
                    buf.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(esc))
                    if buf[-1] is None:
                        raise PolicyError(f"unknown escape \\{esc} at offset {j}")
                    j += 2
                else:
                    buf.append(text[j])
                    j += 1
            if j >= n:
                raise PolicyError(f"unterminated string at offset {i}")
            out.append(("STR", "".join(buf), i))
            i = j + 1
        elif c.isdigit() or (c == "-" and i + 1 < n and text[i + 1].isdigit()):
            j = i + 1
            while j < n and (text[j].isdigit() or text[j] == "."):
                j += 1
            raw = text[i:j]
            try:
                out.append(("NUM", float(raw) if "." in raw else int(raw), i))
            except ValueError:
                raise PolicyError(f"bad number {raw!r} at offset {i}") from None
            i = j
        elif c.isalpha() or c == "_":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            word = text[i:j]
            out.append(("KW" if word in _KEYWORDS else "NAME", word, i))
            i = j
        else:
            op = next((o for o in _OPERATORS if text.startswith(o, i)), None)
            if op:
                out.append(("OP", op, i))
                i += len(op)
            elif c in _PUNCT:
                out.append(("P", c, i))
                i += 1
            else:
                raise PolicyError(f"unexpected character {c!r} at offset {i}")
    out.append(("END", None, n))
    return out


# --- parser ------------------------------------------------------------------------------

class _Parser:
    def __init__(self, text: str):
        self.toks = _tokens(text)
        self.i = 0

    def peek(self, k: int = 0):
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def take(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def at(self, kind: str, value: Any = None, k: int = 0) -> bool:
        t = self.peek(k)
        return t[0] == kind and (value is None or t[1] == value)

    def expect(self, kind: str, value: Any = None):
        t = self.take()
        if t[0] != kind or (value is not None and t[1] != value):
            want = value if value is not None else kind
            got = t[1] if t[1] is not None else "end of expression"
            raise PolicyError(f"expected {want!r} at offset {t[2]}, found {got!r}")
        return t

    def parse(self) -> Expr:
        e = self.expr()
        self.expect("END")
        return e

    def expr(self) -> Expr:
        parts = [self.conj()]
        while self.at("KW", "or"):
            self.take()
            parts.append(self.conj())
        return parts[0] if len(parts) == 1 else BoolOp("or", tuple(parts))

    def conj(self) -> Expr:
        parts = [self.unary()]
        while self.at("KW", "and"):
            self.take()
            parts.append(self.unary())
        return parts[0] if len(parts) == 1 else BoolOp("and", tuple(parts))

    def unary(self) -> Expr:
        if self.at("KW", "not") and not self.at("KW", "in", 1):
            self.take()
            return Not(self.unary())
        if self.at("KW", "some") or self.at("KW", "every"):
            return self.quantifier()
        if self.at("P", "("):
            self.take()
            e = self.expr()
            self.expect("P", ")")
            return e
        return self.atom()

    def quantifier(self) -> Quantifier:
        kind = self.take()[1]
        if self.at("P", "("):
            self.take()
            k = self.expect("NAME")[1]
            self.expect("P", ",")
            v = self.expect("NAME")[1]
            self.expect("P", ")")
            names: Tuple[str, ...] = (k, v)
        else:
            names = (self.expect("NAME")[1],)
        self.expect("KW", "in")
        coll = [self.path()]
        while self.at("P", "+"):
            self.take()
            coll.append(self.path())
        self.expect("P", ":")
        return Quantifier(kind, names, tuple(coll), self.expr())

    def atom(self) -> Expr:
        if self.at("KW", "present") or self.at("KW", "absent"):
            negate = self.take()[1] == "absent"
            self.expect("P", "(")
            p = self.path()
            self.expect("P", ")")
            return Present(p, negate)
        if self.at("KW", "internet"):
            self.take()
            self.expect("P", "(")
            operand = self.operand()
            family = 0
            if self.at("P", ","):
                self.take()
                t = self.expect("NUM")
                if t[1] not in (4, 6):
                    raise PolicyError(f"internet(): the IP version is 4 or 6, not {t[1]}")
                family = t[1]
            self.expect("P", ")")
            return Internet(operand, family)
        if self.at("NAME") and self.at("P", "(", 1):
            name = self.take()[1]
            self.take()
            args: List[Operand] = []
            if not self.at("P", ")"):
                args.append(self.operand())
                while self.at("P", ","):
                    self.take()
                    args.append(self.operand())
            self.expect("P", ")")
            return Call(name, tuple(args))
        if self.at("KW", "starts_with"):
            self.take()
            self.expect("P", "(")
            operand = self.operand()
            self.expect("P", ",")
            prefix = self.expect("STR")[1]
            self.expect("P", ")")
            return StartsWith(operand, prefix)
        left = self.operand()
        if self.at("OP"):
            op = self.take()[1]
        elif self.at("KW", "in"):
            self.take()
            op = "in"
        elif self.at("KW", "not") and self.at("KW", "in", 1):
            self.take()
            self.take()
            op = "notin"
        else:
            t = self.peek()
            raise PolicyError(f"expected a comparison at offset {t[2]}")
        return Compare(op, left, self.operand())

    def operand(self) -> Operand:
        if self.at("KW", "default"):
            self.take()
            self.expect("P", "(")
            p = self.path()
            self.expect("P", ",")
            v = self.literal()
            self.expect("P", ")")
            return Default(p, v)
        if self.at("NAME"):
            return self.path()
        return Literal(self.literal())

    def literal(self) -> Any:
        t = self.take()
        if t[0] in ("STR", "NUM"):
            return t[1]
        if t[0] == "KW" and t[1] in ("true", "false"):
            return t[1] == "true"
        if t[0] == "P" and t[1] == "[":
            items = []
            if not self.at("P", "]"):
                items.append(self.literal())
                while self.at("P", ","):
                    self.take()
                    items.append(self.literal())
            self.expect("P", "]")
            return tuple(items)
        raise PolicyError(f"expected a literal at offset {t[2]}, found {t[1]!r}")

    def path(self) -> Path:
        root = self.expect("NAME")[1]
        steps: List[Union[str, int]] = []
        while True:
            if self.at("P", "."):
                self.take()
                t = self.take()
                if t[0] not in ("NAME", "KW"):
                    raise PolicyError(f"expected a field name at offset {t[2]}")
                steps.append(t[1])
            elif self.at("P", "["):
                self.take()
                t = self.take()
                if t[0] == "STR" or (t[0] == "NUM" and isinstance(t[1], int)):
                    steps.append(t[1])
                else:
                    raise PolicyError(f"expected a string or an index at offset {t[2]}")
                self.expect("P", "]")
            else:
                return Path(root, tuple(steps))


def parse(text: str) -> Expr:
    """Parse a `when` expression; PolicyError names the offset of the problem."""
    return _Parser(text).parse()


def roots(expr: Expr, bound: Tuple[str, ...] = ()) -> set:
    """The free root names of an expression: the views it needs from a resource."""
    out: set = set()

    def operand(o: Optional[Operand], b) -> None:
        p = o.path if isinstance(o, Default) else o
        if isinstance(p, Path) and p.root not in b:
            out.add(p.root)

    def walk(e: Expr, b) -> None:
        if isinstance(e, Compare):
            operand(e.left, b)
            operand(e.right, b)
        elif isinstance(e, Present):
            operand(e.path, b)
        elif isinstance(e, (StartsWith, Internet)):
            operand(e.operand, b)
        elif isinstance(e, Call):
            for a in e.args:
                operand(a, b)
        elif isinstance(e, Not):
            walk(e.expr, b)
        elif isinstance(e, BoolOp):
            for p in e.parts:
                walk(p, b)
        elif isinstance(e, Quantifier):
            for p in e.collection:
                operand(p, b)
            walk(e.body, b + e.names)

    walk(expr, bound)
    return out


# --- defines -----------------------------------------------------------------------------

def inline(expr: Expr, defines: dict) -> Expr:
    """`expr` with every call to a define (name -> (params, body)) replaced by the define's
    body, its parameters substituted (a path argument extends the paths that start at the
    parameter; a literal replaces a parameter used whole) and its own bound names renamed so a
    caller's names cannot be captured. PolicyError for an unknown name or a bad argument."""
    counter = [0]

    def sub_operand(o, env):
        p = o.path if isinstance(o, Default) else o
        if not isinstance(p, Path) or p.root not in env:
            return o
        arg = env[p.root]
        if isinstance(arg, Path):
            new = Path(arg.root, arg.steps + p.steps)
        elif isinstance(arg, Literal) and not p.steps and not isinstance(o, Default):
            return arg
        else:
            raise PolicyError(f"argument for {p.root!r} cannot be used as {p}")
        return Default(new, o.value) if isinstance(o, Default) else new

    def walk(e: Expr, env: dict, stack: tuple) -> Expr:
        if isinstance(e, Compare):
            return Compare(e.op, sub_operand(e.left, env), sub_operand(e.right, env))
        if isinstance(e, Present):
            new = sub_operand(e.path, env)
            if not isinstance(new, Path):
                raise PolicyError("present()/absent() need a path")
            return Present(new, e.negate)
        if isinstance(e, StartsWith):
            return StartsWith(sub_operand(e.operand, env), e.prefix)
        if isinstance(e, Internet):
            return Internet(sub_operand(e.operand, env), e.family)
        if isinstance(e, Not):
            return Not(walk(e.expr, env, stack))
        if isinstance(e, BoolOp):
            return BoolOp(e.op, tuple(walk(x, env, stack) for x in e.parts))
        if isinstance(e, Quantifier):
            coll = tuple(sub_operand(c, env) for c in e.collection)
            inner = dict(env)
            names = []
            for n in e.names:
                counter[0] += 1
                fresh = f"{n}${counter[0]}"
                inner[n] = Path(fresh)
                names.append(fresh)
            return Quantifier(e.kind, tuple(names), coll, walk(e.body, inner, stack))
        if isinstance(e, Call):
            if e.name not in defines:
                raise PolicyError(f"unknown function {e.name}()")
            if e.name in stack:
                raise PolicyError(f"{e.name}() calls itself")
            params, body = defines[e.name]
            if len(params) != len(e.args):
                raise PolicyError(f"{e.name}() takes {len(params)} argument(s)")
            args = [sub_operand(a, env) for a in e.args]
            return walk(body, dict(zip(params, args)), stack + (e.name,))
        return e

    return walk(expr, {}, ())


__all__ = ["BoolOp", "Call", "Compare", "Default", "Expr", "Internet", "Literal", "Not", "Path", "PolicyError",
           "Present", "Quantifier", "StartsWith", "inline", "parse", "roots"]
