"""Hardening findings: configuration that switches a protection off.

These are not data flows. A debug server, a session cookie declared `secure: false` -- the
source says so outright, which is why they are read from the syntax tree and reported in their
own `category = "hardening"` so they never mix with taint findings in precision numbers.

Only an explicit off switch counts. A cookie option that is merely absent is not reported: the
defaults differ per library and "missing" is a policy question, not a vulnerability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List

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


_PY_SECURE = re.compile(r"^(?:SESSION|CSRF|LANGUAGE)_COOKIE_SECURE$")
_PY_HTTPONLY = re.compile(r"^(?:SESSION|CSRF)_COOKIE_HTTPONLY$")


def _py_is_false(n: Any) -> bool:
    return n is not None and n.type == "false"


def _py_is_true(n: Any) -> bool:
    return n is not None and n.type == "true"


def scan_python(source: str, root: Any, filename: str = "") -> List[HardeningFinding]:
    out: List[HardeningFinding] = []
    flaskish = bool(re.search(r"\bflask\b|\bFlask\s*\(|\bQuart\s*\(", source, re.I))
    base = Path(filename).name.lower()
    settingsish = (base.startswith("settings") or "INSTALLED_APPS" in source or "ALLOWED_HOSTS" in source
                   or "MIDDLEWARE" in source)

    def add(kind: str, node: Any, description: str) -> None:
        out.append(HardeningFinding(kind, node.start_point[0] + 1, node.start_point[1], description))

    for n in _walk(root):
        if n.type == "call" and flaskish:
            fn = _text(n.child_by_field_name("function"))
            args = n.child_by_field_name("arguments")
            if args is not None:
                kw = {_text(a.child_by_field_name("name")): a.child_by_field_name("value")
                      for a in args.named_children if a.type == "keyword_argument"}
                if fn.endswith(".run") and _py_is_true(kw.get("debug")):
                    add("debug", n, f"Debug mode enabled: {fn}(debug=True) exposes an interactive debugger")
                if fn.endswith("config.update"):
                    for key, value in kw.items():
                        if _PY_SECURE.match(key) and _py_is_false(value):
                            add("cookie_secure", n, f"Session cookie not marked Secure: {key}=False")
                        elif _PY_HTTPONLY.match(key) and _py_is_false(value):
                            add("cookie_httponly", n, f"Session cookie not marked HttpOnly: {key}=False")
        elif n.type == "assignment":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            lt = _text(left)
            if left is not None and left.type == "subscript":          # app.config['SESSION_COOKIE_SECURE'] = False
                key = _text(left.child_by_field_name("subscript")).strip("'\"")
                if "config" in _text(left.child_by_field_name("value")):
                    if _PY_SECURE.match(key) and _py_is_false(right):
                        add("cookie_secure", n, f"Session cookie not marked Secure: config['{key}'] = False")
                    elif _PY_HTTPONLY.match(key) and _py_is_false(right):
                        add("cookie_httponly", n, f"Session cookie not marked HttpOnly: config['{key}'] = False")
                    elif key == "DEBUG" and _py_is_true(right):
                        add("debug", n, "Debug mode enabled: config['DEBUG'] = True")
            elif lt == "DEBUG" and _py_is_true(right) and settingsish and n.parent is not None \
                    and n.parent.parent is not None and n.parent.parent.type == "module":
                add("debug", n, "Debug mode enabled: DEBUG = True in settings")
            elif lt.endswith(".debug") and _py_is_true(right) and flaskish:
                add("debug", n, f"Debug mode enabled: {lt} = True")
            elif n.parent is not None and n.parent.parent is not None and n.parent.parent.type == "module":
                if _PY_SECURE.match(lt) and _py_is_false(right):
                    add("cookie_secure", n, f"Session cookie not marked Secure: {lt} = False")
                elif _PY_HTTPONLY.match(lt) and _py_is_false(right):
                    add("cookie_httponly", n, f"Session cookie not marked HttpOnly: {lt} = False")
    return out


_JS_COOKIE_CALLEE = re.compile(r"(?:^|\.)(?:session|cookieSession|cookie|setCookie|createSession|fastifySession)$")
_JS_FALSE_KEYS = {"secure": "cookie_secure", "httpOnly": "cookie_httponly", "httponly": "cookie_httponly"}


def scan_javascript(source: str, root: Any, filename: str = "") -> List[HardeningFinding]:
    out: List[HardeningFinding] = []
    for n in _walk(root):
        if n.type != "pair":
            continue
        key = _text(n.child_by_field_name("key")).strip("'\"")
        value = n.child_by_field_name("value")
        kind = _JS_FALSE_KEYS.get(key)
        if kind is None or value is None or value.type != "false":
            continue
        cur, hops = n.parent, 0
        while cur is not None and hops < 6:
            if cur.type == "call_expression":
                callee = _text(cur.child_by_field_name("function"))
                if _JS_COOKIE_CALLEE.search(callee):
                    flag = "Secure" if kind == "cookie_secure" else "HttpOnly"
                    out.append(HardeningFinding(
                        kind, n.start_point[0] + 1, n.start_point[1],
                        f"Cookie not marked {flag}: {key}: false in {callee}(...)"))
                break
            cur, hops = cur.parent, hops + 1
    return out
