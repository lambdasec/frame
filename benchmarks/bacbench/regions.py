#!/usr/bin/env python3
"""The code regions a BAC-Bench case's disclosed defect lives in, for the deterministic matcher.

A case records its defect as line ranges (`sink_locations`). A finding about the same defect is
often cited a little elsewhere: at the handler that reaches a vulnerable helper (langflow's
`update_flow` over `_read_flow`, two lines outside a 40-line window), or at the helper a handler
delegates to in another file (aegra's `_prepare_run`). The window alone scores those as misses.
This reads the checkouts' syntax trees (tree-sitter; no Frame analysis, no model) and returns,
per checkout, the regions where such a finding is about the recorded code:

  enclosing  the innermost function holding a recorded line range;
  caller     a function in the same file that calls an enclosing function directly by name;
  callee     a function an enclosing one calls directly as a plain function (not a method call),
             when exactly one non-test function of that name is defined in the repository (an
             ambiguous name is never guessed).

A region is a function's OWN code: the functions nested in it are holes, so a route-registration
wrapper around every handler is not one region. Enclosing functions are found on the vulnerable
checkout and looked up by name on the fixed one (its lines moved); an anonymous function is named
after the call it is passed to (`app.post('/x')`) when that call has a literal first argument,
else it is not mapped. Kept free of Frame imports apart from the grammars.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

_EXTS = {"python": (".py",), "javascript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
         "typescript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")}
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__", "vendor",
              "site-packages", ".next", "coverage"}
_MAX_BYTES = 1_000_000
VERSION = 2


@dataclass
class Fn:
    name: str                     # qualified (`Cls.method`, `app.post('/x')`), "" when anonymous
    simple: str
    start: int
    end: int
    holes: List[Tuple[int, int]] = field(default_factory=list)
    calls: set = field(default_factory=set)

    def own(self, line: int) -> bool:
        return self.start <= line <= self.end and not any(a <= line <= b for a, b in self.holes)

    def region(self, file: str, relation: str) -> dict:
        return {"file": file, "name": self.name, "start": self.start, "end": self.end,
                "holes": [list(h) for h in self.holes], "relation": relation}


def _parser(path: str):
    from tree_sitter import Language, Parser
    if path.endswith(".py"):
        import tree_sitter_python as g
        lang = Language(g.language())
    elif path.endswith(".tsx"):
        import tree_sitter_typescript as g
        lang = Language(g.language_tsx())
    elif path.endswith(".ts"):
        import tree_sitter_typescript as g
        lang = Language(g.language_typescript())
    else:
        import tree_sitter_javascript as g
        lang = Language(g.language())
    return Parser(lang)


_FN_TYPES = {"function_definition", "function_declaration", "method_definition", "arrow_function",
             "function_expression", "function", "generator_function_declaration", "method_signature"}
_CLASS_TYPES = {"class_definition", "class_declaration", "class"}
_CALL_TYPES = {"call", "call_expression"}


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _callee_simple(call, src: bytes) -> str:
    """The name of a PLAIN function call (`prepare_run(...)`). A method call (`self.get_object()`,
    `db.exec()`) is not resolved by name: its receiver's class decides which method runs, and a
    name defined once in the repository is often an unrelated class's method of that name."""
    fn = call.child_by_field_name("function")
    if fn is not None and fn.type == "await":
        fn = fn.named_children[0] if fn.named_children else None
    return _text(fn, src) if fn is not None and fn.type == "identifier" else ""


_TEST_PARTS = ("test", "tests", "__tests__", "spec", "specs", "testing", "fixtures")


def _is_test_path(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    base = parts[-1]
    return any(p in _TEST_PARTS for p in parts[:-1]) or base.startswith("test_") or \
        ".test." in base or ".spec." in base or base.endswith("_test.py")


def _anonymous_name(node, src: bytes) -> str:
    """`app.post('/x', (req, res) => ...)`: the function is named after the call it is passed
    to, with that call's literal first argument; a variable it is bound to names it too."""
    parent = node.parent
    if parent is not None and parent.type == "variable_declarator":
        n = parent.child_by_field_name("name")
        return _text(n, src) if n is not None else ""
    if parent is not None and parent.type in ("pair", "assignment_expression"):
        k = parent.child_by_field_name("key") or parent.child_by_field_name("left")
        return _text(k, src) if k is not None else ""
    if parent is not None and parent.type == "arguments" and parent.parent is not None \
            and parent.parent.type in _CALL_TYPES:
        call = parent.parent
        args = [c for c in parent.named_children]
        if args and args[0].type in ("string", "template_string") and args[0] is not node:
            fn = call.child_by_field_name("function")
            return f"{_text(fn, src)}({_text(args[0], src)})" if fn is not None else ""
    return ""


def functions(path: str) -> List[Fn]:
    """Every function in a file with its own-code holes and the simple names it calls."""
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            return []
        src = open(path, "rb").read()
        tree = _parser(path).parse(src)
    except (OSError, ValueError, ImportError):
        return []
    out: List[Fn] = []

    def walk(node, cls: str, stack: List[Fn]) -> None:
        cur = stack
        if node.type in _CLASS_TYPES:
            n = node.child_by_field_name("name")
            cls = _text(n, src) if n is not None else cls
        elif node.type in _FN_TYPES:
            n = node.child_by_field_name("name")
            simple = _text(n, src) if n is not None else ""
            name = simple or _anonymous_name(node, src)
            if simple and cls and node.type in ("function_definition", "method_definition"):
                name = f"{cls}.{simple}"
            fn = Fn(name=name, simple=simple or name, start=node.start_point[0] + 1,
                    end=node.end_point[0] + 1)
            if stack:
                stack[-1].holes.append((fn.start, fn.end))
            out.append(fn)
            cur = stack + [fn]
            cls = ""                      # names inside a function are not the class's methods
        elif node.type in _CALL_TYPES and stack:
            name = _callee_simple(node, src)
            if name:
                stack[-1].calls.add(name)
        for c in node.children:
            walk(c, cls, cur)

    walk(tree.root_node, "", [])
    return out


def _files(root: str, language: str) -> Iterable[str]:
    exts = _EXTS.get(language, _EXTS["javascript"])
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in _SKIP_DIRS and not x.startswith(".")]
        for n in names:
            if n.endswith(exts) and not n.endswith((".min.js", ".d.ts")):
                yield os.path.join(d, n)


def _rel(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace("\\", "/")


def _innermost(fns: List[Fn], line: int) -> Optional[Fn]:
    hits = [f for f in fns if f.start <= line <= f.end]
    return min(hits, key=lambda f: f.end - f.start) if hits else None


def regions_for(root: str, language: str, anchors: List[Tuple[str, Optional[int], Optional[str]]],
                defs: Optional[Dict[str, List[Tuple[str, Fn]]]] = None) -> Tuple[List[dict], List[Tuple[str, str]]]:
    """The regions of one checkout. `anchors` are (file, line, None) for recorded line ranges,
    or (file, None, name) for an enclosing function found on another checkout. Returns the
    regions and the (file, name) of the enclosing functions (to look up on the other one)."""
    per_file: Dict[str, List[Fn]] = {}

    def fns_of(rel: str) -> List[Fn]:
        if rel not in per_file:
            per_file[rel] = functions(os.path.join(root, rel))
        return per_file[rel]

    enclosing: List[Tuple[str, Fn]] = []
    for rel, line, name in anchors:
        fns = fns_of(rel)
        if line is not None:
            f = _innermost(fns, line)
        else:
            same = [x for x in fns if x.name == name]
            f = same[0] if len(same) == 1 else None
        if f is not None and all(f is not g for _, g in enclosing):
            enclosing.append((rel, f))
    out = [f.region(rel, "enclosing") for rel, f in enclosing]
    names = [(rel, f.name) for rel, f in enclosing if f.name]

    # callers: same file, a direct call by the enclosing function's name (unique in that file)
    for rel, f in enclosing:
        fns = fns_of(rel)
        if not f.simple or sum(1 for x in fns if x.simple == f.simple) != 1:
            continue
        for g in fns:
            if g is not f and f.simple in g.calls and all(g is not e for _, e in enclosing):
                out.append(g.region(rel, "caller"))

    # callees: a direct call to a name exactly one function in the repository defines
    wanted = {c for _, f in enclosing for c in f.calls}
    if wanted:
        if defs is None:
            defs = {}
            for p in _files(root, language):
                rel = _rel(p, root)
                if _is_test_path(rel):
                    continue
                for g in (per_file.get(rel) or functions(p)):
                    if g.simple in wanted:
                        defs.setdefault(g.simple, []).append((rel, g))
        for rel, f in enclosing:
            for c in sorted(f.calls):
                hits = defs.get(c) or []
                if len(hits) == 1 and hits[0][1].name != f.name:
                    out.append(hits[0][1].region(hits[0][0], "callee"))
    return out, names


def case_regions(case: dict, checkouts: Dict[str, str]) -> Dict[str, List[dict]]:
    """{checkout: regions} for one case: anchored on its recorded ranges in the vulnerable
    checkout, then on the same functions by name in the others."""
    language = str(case.get("language") or "python")
    anchors = []
    for loc in case.get("sink_locations") or []:
        a, b = int(loc.get("line_start") or 0), int(loc.get("line_end") or loc.get("line_start") or 0)
        for line in sorted({a, b} - {0}):
            anchors.append((loc.get("file", ""), line, None))
    out: Dict[str, List[dict]] = {}
    vuln = checkouts.get("vulnerable")
    if not vuln or not os.path.isdir(vuln) or not anchors:
        return out
    regs, names = regions_for(vuln, language, anchors)
    out["vulnerable"] = regs
    for which, root in checkouts.items():
        if which != "vulnerable" and os.path.isdir(root):
            out[which] = regions_for(root, language, [(f, None, n) for f, n in names])[0]
    return out
