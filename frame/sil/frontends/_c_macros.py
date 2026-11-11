"""Function-like macro expansion for the C/C++ frontend.

A call `RUN(q)` of a macro `#define RUN(x) system(x)` defined in the file is what the
preprocessor makes of it: the body with each parameter replaced by its argument's tokens, then
rescanned for further macro calls. Lowered as a call of an unknown `RUN`, the `system` call it
stands for was never seen. This module is the token-level part of that (C11 6.10.3): argument
collection, `#` stringizing, `##` pasting, `__VA_ARGS__`, and the rescan with the macros being
expanded switched off (a macro never expands inside its own expansion), bounded in depth. The
frontend parses the result and lowers it in place of the call.

Only macros defined exactly once in the file and never `#undef`ed are expanded: with two
definitions the file does not say which one applies.
"""

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Tuple

MAX_DEPTH = 8          # nested expansions; deeper calls are left as written
MAX_LENGTH = 20000     # characters of expanded text; a larger expansion is not attempted

_TOKEN = re.compile(r"""
    (?P<ws>\s+|/\*.*?\*/|//[^\n]*)
  | (?P<str>[LuU8]*"(?:[^"\\\n]|\\.)*"|[LuU8]*'(?:[^'\\\n]|\\.)*')
  | (?P<id>[A-Za-z_]\w*)
  | (?P<num>\.?\d(?:[eEpP][+-]|[\w.])*)
  | (?P<op>\#\#|\#|\.\.\.|->|<<=|>>=|[-+*/%&|^<>=!]=|\+\+|--|&&|\|\||<<|>>|::|.)
""", re.S | re.X)


@dataclass(frozen=True)
class FunctionMacro:
    params: Tuple[str, ...]
    variadic: bool
    body: str


def tokens(text: str) -> List[Tuple[str, str]]:
    """(kind, text) pairs; whitespace and comments are one `ws` token each."""
    out = []
    for m in _TOKEN.finditer(text):
        kind = m.lastgroup
        out.append((kind, " " if kind == "ws" else m.group()))
    return out


def _collect_args(toks: List[Tuple[str, str]], i: int) -> Optional[Tuple[List[List[Tuple[str, str]]], int]]:
    """Arguments of the call whose `(` is at toks[i]: lists of tokens split at top-level commas,
    and the index after the closing `)`; None when the parentheses do not close."""
    depth, args, cur = 0, [], []
    j = i
    while j < len(toks):
        kind, text = toks[j]
        if text == "(":
            depth += 1
            if depth > 1:
                cur.append(toks[j])
        elif text == ")":
            depth -= 1
            if depth == 0:
                args.append(cur)
                return args, j + 1
            cur.append(toks[j])
        elif text == "," and depth == 1:
            args.append(cur)
            cur = []
        else:
            cur.append(toks[j])
        j += 1
    return None


def _strip(toks: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    start, end = 0, len(toks)
    while start < end and toks[start][0] == "ws":
        start += 1
    while end > start and toks[end - 1][0] == "ws":
        end -= 1
    return toks[start:end]


def _text(toks: List[Tuple[str, str]]) -> str:
    return "".join(t for _, t in toks)


def _stringize(toks: List[Tuple[str, str]]) -> str:
    body = " ".join(_text(_strip(toks)).split())
    return '"' + body.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _substitute(macro: FunctionMacro, args: List[List[Tuple[str, str]]], macros: Dict[str, FunctionMacro],
                active: FrozenSet[str], depth: int) -> Optional[List[Tuple[str, str]]]:
    names = list(macro.params)
    bound: Dict[str, List[Tuple[str, str]]] = {}
    if macro.variadic:
        fixed = len(names)
        if len(args) < fixed:
            return None
        rest: List[Tuple[str, str]] = []
        for k, a in enumerate(args[fixed:]):
            if k:
                rest.append(("op", ","))
            rest.extend(a)
        args = args[:fixed]
        bound["__VA_ARGS__"] = rest
    else:
        if len(args) == 1 and not names and not _strip(args[0]):
            args = []
        if len(args) != len(names):
            return None
    for name, a in zip(names, args):
        bound[name] = _strip(a)
    body = _strip(tokens(macro.body))
    out: List[Tuple[str, str]] = []
    i = 0
    while i < len(body):
        kind, text = body[i]
        nxt = next((k for k in range(i + 1, len(body)) if body[k][0] != "ws"), None)
        prev = next((k for k in range(len(out) - 1, -1, -1) if out[k][0] != "ws"), None)
        if text == "#" and nxt is not None and body[nxt][1] in bound:
            out.append(("str", _stringize(bound[body[nxt][1]])))
            i = nxt + 1
            continue
        if text == "##" and prev is not None and nxt is not None:
            del out[prev + 1:]
            right = bound.get(body[nxt][1], [body[nxt]]) if body[nxt][0] == "id" else [body[nxt]]
            right = _strip(right)
            if right:
                pasted = out[prev][1] + right[0][1]
                out[prev] = (tokens(pasted)[0][0] if tokens(pasted) else "op", pasted)
                out.extend(right[1:])
            i = nxt + 1
            continue
        if kind == "id" and text in bound:
            pasting = nxt is not None and body[nxt][1] == "##"
            arg = bound[text]
            # an argument is macro-expanded before substitution unless it is an operand of ##
            out.extend(arg if pasting else (expand_tokens(arg, macros, active, depth + 1) or arg))
            i += 1
            continue
        out.append((kind, text))
        i += 1
    return out


def expand_tokens(toks: List[Tuple[str, str]], macros: Dict[str, FunctionMacro],
                  active: FrozenSet[str] = frozenset(), depth: int = 0) -> Optional[List[Tuple[str, str]]]:
    """The tokens with every call of a macro in `macros` (not in `active`) expanded and
    rescanned; None when an expansion is malformed or the bounds are exceeded."""
    if depth > MAX_DEPTH:
        return None
    out: List[Tuple[str, str]] = []
    i = 0
    while i < len(toks):
        kind, text = toks[i]
        if kind == "id" and text in macros and text not in active:
            j = i + 1
            while j < len(toks) and toks[j][0] == "ws":
                j += 1
            if j < len(toks) and toks[j][1] == "(":
                collected = _collect_args(toks, j)
                if collected is None:
                    return None
                args, after = collected
                body = _substitute(macros[text], args, macros, active, depth)
                if body is None:
                    return None
                rescanned = expand_tokens(body, macros, active | {text}, depth + 1)
                if rescanned is None:
                    return None
                out.extend(rescanned)
                if sum(len(t) for _, t in out) > MAX_LENGTH:
                    return None
                i = after
                continue
        out.append((kind, text))
        i += 1
    return out


def expand(text: str, macros: Dict[str, FunctionMacro]) -> Optional[str]:
    """`text` with the file's function-like macros expanded (None if it cannot be)."""
    result = expand_tokens(tokens(text), macros)
    return None if result is None else _text(result)


def parse_definition(params_text: str, body: str) -> Optional[FunctionMacro]:
    """A `#define NAME(params) body` definition, or None for a parameter list it cannot read."""
    inner = params_text.strip()
    if not (inner.startswith("(") and inner.endswith(")")):
        return None
    parts = [p.strip() for p in inner[1:-1].split(",")] if inner[1:-1].strip() else []
    variadic = bool(parts) and parts[-1] == "..."
    if variadic:
        parts = parts[:-1]
    if not all(re.fullmatch(r"[A-Za-z_]\w*", p) for p in parts) or len(set(parts)) != len(parts):
        return None
    body = re.sub(r"\\\r?\n", " ", body or "")
    return FunctionMacro(tuple(parts), variadic, body.strip())
