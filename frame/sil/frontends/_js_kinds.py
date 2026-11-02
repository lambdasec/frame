"""What kind of value a JavaScript / TypeScript variable holds where it is used, decided by Z3 over
the conditions that must hold to reach the use.

Every value has one kind (`KINDS`). A type test is a formula over its operand's kind:
`Array.isArray(x)`, `x instanceof Array|Map|Set`, `Object.prototype.toString.call(x) === "[object T]"`,
`typeof x === "t"`, combined with `!`, `&&`, `||`, `??`. A call to a helper the file defines or
imports from a relative module is its returned expression with the arguments substituted, also
through a dispatch on a constant key (`{array: isArray, map: isMap}?.[type]?.(x)` with `type` a
literal at the call). The facts at a use are what its path requires: an enclosing `if (C)` (or the
`else` of one), a ternary branch, the right side of `&&` / `||`, and an earlier `if (C) return|throw`
in an enclosing block. A variable's kind is decided only if the facts entail it; a condition the
model does not understand is a free boolean, so it never proves anything.

Used for prototype pollution: the index an Array iteration callback receives is a number, so it is
never `__proto__` (javascript-types.toml [array_index_params]); a Map's forEach hands its key there.
"""

from __future__ import annotations

import itertools
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

KINDS = ("Array", "Map", "Set", "Object", "Function", "String", "Number", "Boolean", "Null", "Undefined",
         "Other")
_TYPEOF = {"string": ("String",), "number": ("Number",), "boolean": ("Boolean",), "function": ("Function",),
           "undefined": ("Undefined",), "object": ("Array", "Map", "Set", "Object", "Other", "Null")}
# Object.prototype.toString's tags (ECMAScript 20.1.3.6): an instance of a user class is "[object Object]".
_TAGS = {"Array": ("Array",), "Map": ("Map",), "Set": ("Set",), "Object": ("Object", "Other"),
         "Function": ("Function",), "String": ("String",), "Number": ("Number",), "Boolean": ("Boolean",),
         "Null": ("Null",), "Undefined": ("Undefined",)}
_INSTANCEOF = {"Array": ("Array",), "Map": ("Map",), "Set": ("Set",), "Function": ("Function",)}
_FUNCS = ("function_declaration", "generator_function_declaration", "function_expression", "function",
          "arrow_function", "method_definition", "generator_function")
_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
_DEPTH = 6


def _text(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _strip(n):
    while n is not None and n.type == "parenthesized_expression" and n.named_child_count == 1:
        n = n.named_children[0]
    return n


def _string(n) -> Optional[str]:
    n = _strip(n)
    if n is not None and n.type == "string":
        return _text(n)[1:-1]
    if n is not None and n.type == "template_string" and not any(c.type == "template_substitution" for c in n.children):
        return _text(n)[1:-1]
    return None


@lru_cache(maxsize=1)
def _sort():
    import z3
    return z3.EnumSort("JsKind", KINDS)


def _kind(name: str):
    import z3
    return z3.Const(name, _sort()[0])


def _is(var, kinds) -> "object":
    import z3
    sort, values = _sort()
    return z3.Or(*[var == values[KINDS.index(k)] for k in kinds])


# -- modules: a file's top-level bindings and its relative imports ----------------------------------

class Module:
    def __init__(self, root, path: str):
        self.root, self.path = root, path
        self.bindings: Dict[str, object] = {}         # name -> value node (a function, an expression)
        self.imports: Dict[str, Tuple[str, str]] = {}  # local name -> (relative specifier, exported name)
        for st in root.named_children:
            self._statement(st)

    def _statement(self, st):
        if st.type == "export_statement":
            decl = st.child_by_field_name("declaration")
            if decl is not None:
                self._statement(decl)
            return
        if st.type in ("function_declaration", "generator_function_declaration"):
            name = st.child_by_field_name("name")
            if name is not None:
                self._bind(_text(name), st)
        elif st.type in ("lexical_declaration", "variable_declaration"):
            for d in st.named_children:
                if d.type == "variable_declarator":
                    name, value = d.child_by_field_name("name"), d.child_by_field_name("value")
                    if name is not None and name.type == "identifier" and value is not None:
                        self._bind(_text(name), value)
        elif st.type == "import_statement":
            source = _string(st.child_by_field_name("source"))
            if not source or not source.startswith("."):
                return
            for clause in st.named_children:
                if clause.type != "import_clause":
                    continue
                for part in clause.named_children:
                    if part.type == "named_imports":
                        for spec in part.named_children:
                            if spec.type == "import_specifier":
                                name, alias = spec.child_by_field_name("name"), spec.child_by_field_name("alias")
                                self.imports[_text(alias or name)] = (source, _text(name))

    def _bind(self, name: str, value) -> None:
        if name in self.bindings:
            self.bindings[name] = None                 # bound twice: unknown
        else:
            self.bindings[name] = value


@lru_cache(maxsize=256)
def _load(path: str) -> Optional[Module]:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError:
        return None
    try:
        from tree_sitter import Language, Parser
        if p.suffix in (".ts", ".tsx"):
            import tree_sitter_typescript as tst
            lang = Language(tst.language_tsx() if p.suffix == ".tsx" else tst.language_typescript())
        else:
            import tree_sitter_javascript as tsj
            lang = Language(tsj.language())
    except ImportError:
        return None
    return Module(Parser(lang).parse(data).root_node, str(p))


def _resolve_import(mod: Module, specifier: str) -> Optional[Module]:
    base = Path(mod.path).parent / specifier
    for cand in [base] + [base.with_name(base.name + s) for s in _SUFFIXES] + [base / f"index{s}" for s in _SUFFIXES]:
        if cand.is_file():
            return _load(str(cand.resolve()))
    return None


def _function(value):
    """(params, returned expression) of a function whose body is one expression or one return."""
    value = _strip(value)
    if value is None or value.type not in _FUNCS:
        return None
    params = value.child_by_field_name("parameters") or value.child_by_field_name("parameter")
    names = []
    for p in ([params] if params is not None and params.type == "identifier" else
              (params.named_children if params is not None else [])):
        if p.type == "identifier":
            names.append(_text(p))
        elif p.type in ("required_parameter", "optional_parameter") and p.child_by_field_name("pattern") is not None \
                and p.child_by_field_name("pattern").type == "identifier":
            names.append(_text(p.child_by_field_name("pattern")))
        elif p.type != "comment":
            names.append(None)                         # a pattern or default: not substituted
    body = value.child_by_field_name("body")
    if body is None:
        return None
    if body.type != "statement_block":
        return names, body
    stmts = [s for s in body.named_children if s.type != "comment"]
    if len(stmts) == 1 and stmts[0].type == "return_statement" and stmts[0].named_child_count == 1:
        return names, stmts[0].named_children[0]
    return None


# -- formulas ---------------------------------------------------------------------------------------

class Kinds:
    """Formulas over the kinds of one file's variables (`module` is that file)."""

    def __init__(self, module: Module):
        self.module = module
        self._fresh = itertools.count()

    def _unknown(self):
        import z3
        return z3.Bool(f"?js{next(self._fresh)}")

    # A variable at the use site is keyed by the scope that declares it, so two variables of one name
    # in different functions are different unknowns.
    def var_key(self, ident) -> str:
        name = _text(ident)
        cur = ident.parent
        while cur is not None:
            if cur.type in _FUNCS and name in _declared(cur):
                return f"{cur.start_byte}:{name}"
            cur = cur.parent
        return f"module:{name}"

    def kind_of(self, node, mod: Module, env: dict):
        """The Z3 kind of an expression that names a variable, or None."""
        node = _strip(node)
        if node is None or node.type != "identifier":
            return None
        bound = env.get(_text(node))
        if bound is not None:
            arg, amod, aenv = bound
            return self.kind_of(arg, amod, aenv)
        if mod is not self.module:
            return None                                 # a name inside a helper that is not its parameter
        return _kind(self.var_key(node))

    def formula(self, node, mod: Optional[Module] = None, env: Optional[dict] = None, depth: int = 0):
        import z3
        mod = mod or self.module
        env = env if env is not None else {}
        node = _strip(node)
        if node is None or depth > _DEPTH:
            return self._unknown()
        t = node.type
        if t == "true":
            return z3.BoolVal(True)
        if t == "false":
            return z3.BoolVal(False)
        if t == "unary_expression" and _text(node.child_by_field_name("operator")) == "!":
            return z3.Not(self.formula(node.child_by_field_name("argument"), mod, env, depth + 1))
        if t == "binary_expression":
            op = _text(node.child_by_field_name("operator"))
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if op == "&&":
                return z3.And(self.formula(left, mod, env, depth + 1), self.formula(right, mod, env, depth + 1))
            if op == "||":
                return z3.Or(self.formula(left, mod, env, depth + 1), self.formula(right, mod, env, depth + 1))
            if op == "??":
                return self._nullish(left, right, mod, env, depth)
            if op in ("===", "==", "!==", "!="):
                f = self._comparison(left, right, mod, env)
                if f is None:
                    f = self._comparison(right, left, mod, env)
                if f is None:
                    return self._unknown()
                return f if op in ("===", "==") else z3.Not(f)
            if op == "instanceof":
                kinds = _INSTANCEOF.get(_text(right))
                var = self.kind_of(left, mod, env)
                return _is(var, kinds) if kinds and var is not None else self._unknown()
            return self._unknown()
        if t == "identifier":
            bound = env.get(_text(node))
            if bound is not None:
                return self.formula(bound[0], bound[1], bound[2], depth + 1)
            return self._unknown()
        if t == "call_expression":
            return self._call(node, mod, env, depth)
        return self._unknown()

    def _comparison(self, subject, literal, mod, env):
        value = _string(literal)
        subject = _strip(subject)
        if value is None or subject is None:
            return None
        if subject.type == "unary_expression" and _text(subject.child_by_field_name("operator")) == "typeof":
            var = self.kind_of(subject.child_by_field_name("argument"), mod, env)
            kinds = _TYPEOF.get(value)
            if var is None:
                return None
            import z3
            return _is(var, kinds) if kinds else z3.BoolVal(False)
        if subject.type == "call_expression" and _text(subject.child_by_field_name("function")) == \
                "Object.prototype.toString.call":
            args = [a for a in subject.child_by_field_name("arguments").named_children if a.type != "comment"]
            var = self.kind_of(args[0], mod, env) if len(args) == 1 else None
            if var is None or not (value.startswith("[object ") and value.endswith("]")):
                return None
            kinds = _TAGS.get(value[len("[object "):-1], ("Other",))
            return _is(var, kinds)
        return None

    def _nullish(self, left, right, mod, env, depth):
        """`A ?? B`: B when A is undefined. A dispatch on a constant key that is absent is undefined;
        a helper whose returned expression is a boolean test is never nullish."""
        target = self._dispatch_target(_strip(left), mod, env)
        if target == "absent":
            return self.formula(right, mod, env, depth + 1)
        if target is not None or self._returns_test(_strip(left), mod, env):
            return self.formula(left, mod, env, depth + 1)
        return self._unknown()

    def _returns_test(self, call, mod, env) -> bool:
        if call is None or call.type != "call_expression":
            return False
        if _text(call.child_by_field_name("function")) == "Array.isArray":
            return True
        fn = self._callee(call.child_by_field_name("function"), mod, env)
        return fn is not None and _strip(fn[1][1]).type in ("binary_expression", "unary_expression", "call_expression")

    def _dispatch_target(self, call, mod, env):
        """For `{k: f, ...}?.[key]?.(args)` with key a constant: (value node, module), "absent" when
        the object has no such key, None for anything else."""
        if call is None or call.type != "call_expression":
            return None
        fn = _strip(call.child_by_field_name("function"))
        if fn is None or fn.type != "subscript_expression":
            return None
        obj, index = _strip(fn.child_by_field_name("object")), fn.child_by_field_name("index")
        if obj is None or obj.type != "object":
            return None
        key = self._constant(index, mod, env)
        if key is None:
            return None
        for pair in obj.named_children:
            if pair.type == "pair" and (_string(pair.child_by_field_name("key")) or
                                        _text(pair.child_by_field_name("key"))) == key:
                return pair.child_by_field_name("value"), mod
            if pair.type == "shorthand_property_identifier" and _text(pair) == key:
                return pair, mod
            if pair.type == "spread_element":
                return None                              # a spread could bring the key
        return "absent"

    def _constant(self, node, mod, env) -> Optional[str]:
        node = _strip(node)
        s = _string(node)
        if s is not None:
            return s
        if node is not None and node.type == "identifier" and _text(node) in env:
            arg, amod, aenv = env[_text(node)]
            return self._constant(arg, amod, aenv)
        return None

    def _callee(self, fn, mod: Module, env: dict):
        """(module, (params, returned expression)) of a callee that is a helper the files define."""
        fn = _strip(fn)
        if fn is None or fn.type not in ("identifier", "shorthand_property_identifier"):
            return None
        name = _text(fn)
        if name in env:
            return None                                  # a function passed in: unknown
        if name in mod.bindings:
            value = mod.bindings[name]
            if value is not None and _strip(value).type == "identifier":
                return self._callee(value, mod, {})      # `const isA = isArray`
            f = _function(value)
            return (mod, f) if f is not None else None
        if name in mod.imports:
            spec, exported = mod.imports[name]
            other = _resolve_import(mod, spec)
            if other is not None and exported in other.bindings:
                value = other.bindings[exported]
                if value is not None and _strip(value).type == "identifier":
                    return self._callee(value, other, {})
                f = _function(value)
                return (other, f) if f is not None else None
        return None

    def _call(self, call, mod, env, depth):
        fn = call.child_by_field_name("function")
        args = [a for a in (call.child_by_field_name("arguments").named_children
                            if call.child_by_field_name("arguments") is not None else []) if a.type != "comment"]
        if _text(fn) == "Array.isArray" and len(args) == 1:
            var = self.kind_of(args[0], mod, env)
            return _is(var, ("Array",)) if var is not None else self._unknown()
        target = self._dispatch_target(call, mod, env)
        if target == "absent":
            return self._unknown()                       # undefined: falsy, but `?? x` is handled above
        if target is not None:
            value, tmod = target
            callee = self._callee(value, tmod, {})
        else:
            callee = self._callee(fn, mod, env)
        if callee is None:
            return self._unknown()
        cmod, (params, returned) = callee
        new_env = {p: (a, mod, env) for p, a in zip(params, args) if p is not None}
        return self.formula(returned, cmod, new_env, depth + 1)

    # -- facts on the path to a use -------------------------------------------------------------

    def path_facts(self, use, stop) -> list:
        """The conditions that hold whenever `use` runs, up to and including the function `stop`."""
        import z3
        facts = []
        cur = use
        while cur is not None and cur.parent is not None:
            parent = cur.parent
            if parent.type == "if_statement":
                cond = parent.child_by_field_name("condition")
                if cur == parent.child_by_field_name("consequence"):
                    facts.append(self.formula(cond))
                elif cur == parent.child_by_field_name("alternative"):
                    facts.append(z3.Not(self.formula(cond)))
            elif parent.type == "else_clause" and parent.parent is not None and parent.parent.type == "if_statement":
                facts.append(z3.Not(self.formula(parent.parent.child_by_field_name("condition"))))
            elif parent.type == "ternary_expression":
                cond = parent.child_by_field_name("condition")
                if cur == parent.child_by_field_name("consequence"):
                    facts.append(self.formula(cond))
                elif cur == parent.child_by_field_name("alternative"):
                    facts.append(z3.Not(self.formula(cond)))
            elif parent.type == "binary_expression" and cur == parent.child_by_field_name("right"):
                op = _text(parent.child_by_field_name("operator"))
                if op == "&&":
                    facts.append(self.formula(parent.child_by_field_name("left")))
                elif op == "||":
                    facts.append(z3.Not(self.formula(parent.child_by_field_name("left"))))
            elif parent.type == "statement_block":
                for st in parent.named_children:
                    if st.start_byte >= cur.start_byte:
                        break
                    if st.type == "if_statement" and st.child_by_field_name("alternative") is None \
                            and _leaves(st.child_by_field_name("consequence")):
                        facts.append(z3.Not(self.formula(st.child_by_field_name("condition"))))
            if parent == stop:
                break
            cur = parent
        return facts

    def entails_kind(self, ident, kind: str, stop) -> bool:
        """Do the facts on the path to `ident` entail that it holds a value of `kind`?"""
        import z3
        try:
            var = self.kind_of(ident, self.module, {})
            if var is None:
                return False
            s = z3.Solver()
            s.set("timeout", 2000)
            s.add(*self.path_facts(ident, stop))
            s.add(z3.Not(_is(var, (kind,))))
            return s.check() == z3.unsat
        except (z3.Z3Exception, RecursionError, ValueError, TypeError, AttributeError):
            return False                                # not decided: nothing is proven


def _leaves(block) -> bool:
    if block is None:
        return False
    if block.type == "statement_block":
        stmts = [s for s in block.named_children if s.type != "comment"]
        return bool(stmts) and stmts[-1].type in ("return_statement", "throw_statement")
    return block.type in ("return_statement", "throw_statement")


def _declared(fn) -> set:
    """Names a function declares as parameters or in its own body (not in nested functions)."""
    names = set()
    params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
    stack = [params] if params is not None else []
    while stack:
        n = stack.pop()
        if n.type == "identifier":
            names.add(_text(n))
        elif n.type not in _FUNCS:
            stack.extend(c for c in n.named_children
                         if not (n.type in ("assignment_pattern", "optional_parameter", "required_parameter")
                                 and c == n.child_by_field_name("value")))
    body = fn.child_by_field_name("body")
    stack = [body] if body is not None else []
    while stack:
        n = stack.pop()
        if n.type in _FUNCS:
            continue
        if n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                names.add(_text(name))
        stack.extend(n.named_children)
    return names


__all__ = ["KINDS", "Kinds", "Module"]
