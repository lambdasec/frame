"""Hardening findings: configuration that switches a protection off.

These are not data flows. A debug server, a session cookie declared `secure: false` -- the
source says so outright, which is why they are read from the syntax tree and reported in their
own `category = "hardening"` so they never mix with taint findings in precision numbers.

What counts is data: a pack's `[[setting]]` entries (`frame/sil/packs/data/*/`) name the keys,
the literal that switches the protection off, and where the key is written (a keyword
argument, a module-level or attribute assignment, a subscript, an object-literal property).
This module only matches them against the tree. Only an explicit off switch counts: an
option that is merely absent is not reported (defaults differ per library).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Iterable, List

from frame.sil.packs.schema import Setting

CATEGORY = "hardening"


@dataclass
class HardeningFinding:
    kind: str            # "debug" | "cookie_secure" | "cookie_httponly"
    line: int
    column: int
    description: str


def _text(n: Any) -> str:
    return n.text.decode("utf-8", errors="replace") if n is not None else ""


def _walk(root: Any):
    stack = [root]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


@lru_cache(maxsize=None)
def _pattern(glob: str) -> "re.Pattern[str]":
    from frame.sil.packs.apply import _glob_to_regex      # `*` inside one dotted segment, `**` across
    return re.compile(_glob_to_regex(glob))


def _matches(globs: Iterable[str], text: str) -> bool:
    return any(_pattern(g).fullmatch(text) for g in globs)


def _is(value: Any, want: bool) -> bool:
    return value is not None and value.type == ("true" if want else "false")


def _module_level(n: Any) -> bool:
    return n.parent is not None and n.parent.parent is not None and n.parent.parent.type == "module"


def _describe(s: Setting, what: str) -> str:
    return f"{s.description}: {what}" if s.description else what


def scan_python(root: Any, settings: List[Setting]) -> List[HardeningFinding]:
    out: List[HardeningFinding] = []
    by_place = {p: [s for s in settings if s.at == p] for p in ("kwarg", "assignment", "attribute", "subscript")}

    def add(s: Setting, node: Any, what: str) -> None:
        out.append(HardeningFinding(s.kind, node.start_point[0] + 1, node.start_point[1], _describe(s, what)))

    for n in _walk(root):
        if n.type == "call" and by_place["kwarg"]:
            fn = _text(n.child_by_field_name("function"))
            args = n.child_by_field_name("arguments")
            if args is None:
                continue
            for a in args.named_children:
                if a.type != "keyword_argument":
                    continue
                key, value = _text(a.child_by_field_name("name")), a.child_by_field_name("value")
                for s in by_place["kwarg"]:
                    if key in s.keys and _is(value, s.value) and _matches(s.call, fn):
                        add(s, n, f"{fn}({key}={_text(value)})")
        elif n.type == "assignment":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is None:
                continue
            lt = _text(left)
            if left.type == "subscript":                      # app.config['SESSION_COOKIE_SECURE'] = False
                key = _text(left.child_by_field_name("subscript")).strip("'\"")
                obj = _text(left.child_by_field_name("value"))
                for s in by_place["subscript"]:
                    if key in s.keys and _is(right, s.value) and _matches(s.receiver, obj):
                        add(s, n, f"{lt} = {_text(right)}")
            elif left.type == "attribute":                    # app.debug = True
                key = _text(left.child_by_field_name("attribute"))
                obj = _text(left.child_by_field_name("object"))
                for s in by_place["attribute"]:
                    if key in s.keys and _is(right, s.value) and (not s.receiver or _matches(s.receiver, obj)):
                        add(s, n, f"{lt} = {_text(right)}")
            elif left.type == "identifier" and _module_level(n):     # DEBUG = True in a settings module
                for s in by_place["assignment"]:
                    if lt in s.keys and _is(right, s.value):
                        add(s, n, f"{lt} = {_text(right)}")
    return out


def scan_javascript(root: Any, settings: List[Setting]) -> List[HardeningFinding]:
    out: List[HardeningFinding] = []
    props = [s for s in settings if s.at == "property"]
    if not props:
        return out
    for n in _walk(root):
        if n.type != "pair":
            continue
        key = _text(n.child_by_field_name("key")).strip("'\"")
        value = n.child_by_field_name("value")
        cands = [s for s in props if key in s.keys and _is(value, s.value)]
        if not cands:
            continue
        cur, hops = n.parent, 0                               # the call the options are passed to
        while cur is not None and hops < 6:
            if cur.type == "call_expression":
                callee = _text(cur.child_by_field_name("function"))
                for s in cands:
                    if _matches(s.call, callee):
                        out.append(HardeningFinding(s.kind, n.start_point[0] + 1, n.start_point[1],
                                                    _describe(s, f"{key}: {_text(value)} in {callee}(...)")))
                break
            cur, hops = cur.parent, hops + 1
    return out
