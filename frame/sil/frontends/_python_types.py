"""Light-weight "what library object is this variable" inference for Python.

The frontend does not infer types, so `cur = conn.cursor()` and `session = requests.Session()`
leave `cur.execute(...)` / `session.get(...)` without a canonical id and a framework pack can
only match them by textual name. This pass gives such calls a *derived canonical id*: the
canonical id of the library callable the receiver variable was built from, followed by the
attribute path.

    client = MongoClient(uri); db = client["app"]; db.users.find(q)
        -> pymongo.MongoClient.[].users.find
    conn = psycopg2.connect(dsn); cur = conn.cursor(); cur.execute(q)
        -> psycopg2.connect.cursor.execute
    self.http = requests.Session(); self.http.get(u)
        -> requests.Session.get

A subscript segment is written `[]`. Pack rules match these ids with globs
(`pymongo.MongoClient.**.find`). Only evidence in the file is used and nothing is guessed: a
name assigned two different values has no type, calls of functions the file defines are never
typed, and only `Call.canonical is None` is filled.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

_BRACKETS = re.compile(r"\[[^\[\]]+\]")
_FUNCS = ("function_definition",)


def _norm(func: str) -> str:
    """`db["users"].find` -> `db.[].find`."""
    for _ in range(8):                      # nested brackets: db[x[0]]["c"]
        out = _BRACKETS.sub(".[]", func)
        if out == func:
            break
        func = out
    return func.replace("..", ".")


class _Scope:
    def __init__(self, parent: Optional["_Scope"] = None) -> None:
        self.parent = parent
        self.types: Dict[str, Optional[str]] = {}

    def bind(self, name: str, typ: Optional[str]) -> None:
        if name in self.types and self.types[name] != typ:
            self.types[name] = None                    # conflicting evidence: unknown
        else:
            self.types[name] = typ

    def lookup(self, name: str) -> Optional[str]:
        s: Optional[_Scope] = self
        while s is not None:
            if name in s.types:
                return s.types[name]
            s = s.parent
        return None


class PythonTypeInference:
    def __init__(self, root, table, text: Callable, local_functions: set) -> None:
        self.root, self.table, self.text = root, table, text
        self.local = local_functions
        self.module = _Scope()
        self.class_attrs: Dict[str, Dict[str, Optional[str]]] = {}
        self.funcs: List[Tuple[int, int, object, _Scope, Optional[str]]] = []

    # -- expression typing ----------------------------------------------------

    def _dotted(self, node) -> Optional[str]:
        if node is None:
            return None
        if node.type == "identifier":
            return self.text(node)
        if node.type == "attribute":
            base = self._dotted(node.child_by_field_name("object"))
            attr = node.child_by_field_name("attribute")
            return f"{base}.{self.text(attr)}" if base and attr is not None else None
        return None

    def type_of(self, node, scope: _Scope, cls: Optional[str]) -> Optional[str]:
        if node is None:
            return None
        t = node.type
        if t in ("await", "parenthesized_expression") and node.named_children:
            return self.type_of(node.named_children[-1], scope, cls)
        if t == "identifier":
            return scope.lookup(self.text(node))
        if t == "attribute":
            obj = node.child_by_field_name("object")
            attr = node.child_by_field_name("attribute")
            if obj is None or attr is None:
                return None
            if obj.type == "identifier" and self.text(obj) == "self" and cls:
                return self.class_attrs.get(cls, {}).get(self.text(attr))
            base = self.type_of(obj, scope, cls)
            return f"{base}.{self.text(attr)}" if base else None
        if t == "subscript":
            base = self.type_of(node.child_by_field_name("value"), scope, cls)
            return f"{base}.[]" if base else None
        if t == "call":
            return self._callee_type(node.child_by_field_name("function"), scope, cls)
        return None

    def _callee_type(self, fn, scope: _Scope, cls: Optional[str]) -> Optional[str]:
        """Type of the value a call to `fn` returns: the callee's own canonical id."""
        if fn is None:
            return None
        if fn.type == "identifier":
            name = self.text(fn)
            if name in self.local or scope.lookup(name) is not None:
                return None
            return self.table.resolve(name)
        if fn.type == "attribute":
            obj = fn.child_by_field_name("object")
            attr = fn.child_by_field_name("attribute")
            if obj is None or attr is None:
                return None
            base = self.type_of(obj, scope, cls)
            if base:
                return f"{base}.{self.text(attr)}"
            dotted = self._dotted(fn)
            head = dotted.split(".", 1)[0] if dotted else ""
            if dotted and head not in self.local and head not in ("self", "cls") \
                    and scope.lookup(head) is None:
                return self.table.resolve(dotted)
        return None

    def annotation_type(self, text: str) -> Optional[str]:
        text = text.strip().strip("'\"")
        m = re.fullmatch(r"(?:Optional|typing\.Optional)\[(.+)\]", text)
        if m:
            text = m.group(1)
        if not re.fullmatch(r"[A-Za-z_][\w.]*", text) or text in self.local:
            return None
        return self.table.resolve(text)

    # -- scope building -------------------------------------------------------

    def _enclosing_class(self, node) -> Optional[str]:
        cur = node.parent
        while cur is not None:
            if cur.type == "class_definition":
                nm = cur.child_by_field_name("name")
                return self.text(nm) if nm is not None else None
            cur = cur.parent
        return None

    def _bind_statements(self, body, scope: _Scope, cls: Optional[str], *, attrs: bool) -> None:
        stack = [body]
        while stack:
            n = stack.pop()
            for c in reversed(n.children):
                if c.type in (*_FUNCS, "class_definition", "lambda"):
                    continue
                stack.append(c)
            if n.type == "assignment":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                ann = n.child_by_field_name("type")
                typ = self.annotation_type(self.text(ann)) if ann is not None else None
                if typ is None:
                    typ = self.type_of(right, scope, cls) if right is not None else None
                self._bind_target(left, typ, scope, cls, attrs)
            elif n.type == "with_item":
                val = n.child_by_field_name("value")
                if val is not None and val.type == "as_pattern":
                    inner = val.named_children[0] if val.named_children else None
                    alias = val.child_by_field_name("alias")
                    target = alias.named_children[0] if alias is not None and alias.named_children else alias
                    self._bind_target(target, self.type_of(inner, scope, cls), scope, cls, attrs)

    def _bind_target(self, target, typ: Optional[str], scope: _Scope, cls: Optional[str],
                     attrs: bool) -> None:
        if target is None:
            return
        if target.type == "identifier":
            scope.bind(self.text(target), typ)
        elif target.type == "attribute" and attrs and cls:
            obj, attr = target.child_by_field_name("object"), target.child_by_field_name("attribute")
            if obj is not None and attr is not None and obj.type == "identifier" and self.text(obj) == "self":
                slot = self.class_attrs.setdefault(cls, {})
                name = self.text(attr)
                if name in slot and slot[name] != typ:
                    slot[name] = None
                else:
                    slot[name] = typ
        elif target.type in ("pattern_list", "tuple_pattern"):
            for c in target.named_children:
                self._bind_target(c, None, scope, cls, attrs)

    def _param_types(self, fn, scope: _Scope) -> None:
        params = fn.child_by_field_name("parameters")
        for p in (params.named_children if params is not None else ()):
            name, ann = None, None
            if p.type == "identifier":
                name = self.text(p)
            elif p.type in ("typed_parameter", "typed_default_parameter"):
                first = p.named_children[0] if p.named_children else None
                nm = p.child_by_field_name("name") or first
                name = self.text(nm) if nm is not None and nm.type == "identifier" else None
                ann = p.child_by_field_name("type")
            elif p.type == "default_parameter":
                nm = p.child_by_field_name("name")
                name = self.text(nm) if nm is not None else None
            if name:
                scope.bind(name, self.annotation_type(self.text(ann)) if ann is not None else None)

    def build(self) -> None:
        self._bind_statements(self.root, self.module, None, attrs=False)
        fns = []
        stack = [self.root]
        while stack:
            n = stack.pop()
            if n.type in _FUNCS:
                fns.append(n)
            stack.extend(n.children)
        fns.sort(key=lambda f: f.start_point)
        # methods first-to-last so `self.x = ...` in __init__ is known to the others
        for fn in sorted(fns, key=lambda f: (self._enclosing_class(f) is None,
                                              self.text(f.child_by_field_name("name")) != "__init__")):
            cls = self._enclosing_class(fn)
            scope = _Scope(self.module)
            self._param_types(fn, scope)
            body = fn.child_by_field_name("body")
            if body is not None:
                self._bind_statements(body, scope, cls, attrs=True)
            self.funcs.append((fn.start_point[0] + 1, fn.end_point[0] + 1, fn, scope, cls))

    # -- application ----------------------------------------------------------

    def scope_at(self, line: int) -> Tuple[_Scope, Optional[str]]:
        best = None
        for start, end, _fn, scope, cls in self.funcs:
            if start <= line <= end and (best is None or start >= best[0]):
                best = (start, scope, cls)
        return (best[1], best[2]) if best else (self.module, None)

    def derive(self, func: str, line: int) -> Optional[str]:
        func = _norm(func)
        if func.startswith("<") or "." not in func:
            return None
        scope, cls = self.scope_at(line)
        parts = func.split(".")
        if parts[0] == "self" and cls and len(parts) >= 3:
            typ = self.class_attrs.get(cls, {}).get(parts[1])
            rest = parts[2:]
        else:
            typ = scope.lookup(parts[0])
            rest = parts[1:]
        if not typ or not rest:
            return None
        return ".".join([typ, *rest])


def infer_canonicals(root, program, table, text: Callable) -> None:
    from ..instructions import Call
    local = {n.split("#", 1)[0] for n in program.procedures}
    local |= {n.rsplit(".", 1)[-1].split("#", 1)[0] for n in program.procedures}
    inf = PythonTypeInference(root, table, text, local)
    inf.build()
    for proc in program.procedures.values():
        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call) or instr.canonical is not None:
                    continue
                func = str(getattr(instr.func, "value", instr.func))
                head = func.split(".", 1)[0].split("[", 1)[0]
                if head in table.names:               # an imported name: the import table decides
                    continue
                canon = inf.derive(func, instr.loc.line if instr.loc else 0)
                if canon:
                    instr.canonical = canon
