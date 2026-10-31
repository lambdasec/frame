"""Value origins: the call a variable's value comes from, so a later call on it has a callee id.

`const c = mysql.createConnection(o); c.query(q)` makes `c.query` the call
`mysql.createConnection.query`, as Python's frontend already names `conn.execute` after
`conn = sqlite3.connect(...)`. A name counts only when it is bound exactly once in its procedure
(never a parameter), or once at module level and never in the procedure that reads it; a copy
`d = c` carries the origin. Nothing is guessed: a name bound twice, or to anything but a call
with an id, has no origin, and its calls keep `canonical = None`.

What those calls return is data (`specs/data/value-types.toml`, `typed_names`): `sqlite3.connect`
returns a `sqlite3.Connection`, whose `cursor()` returns a `sqlite3.Cursor`, so
`sqlite3.connect.cursor.execute` is looked up as `sqlite3.Cursor.execute` and under the spec
table's receiver names for that type (`cursor.execute`)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from .instructions import Assign, Call
from .types import ExpCall, ExpConst, ExpVar

MODULE = "<module>"
PATH = Path(__file__).parent / "specs" / "data" / "value-types.toml"


def _call_text(call: Call) -> Optional[str]:
    f = call.func
    if isinstance(f, ExpConst) and isinstance(f.value, str):
        return f.value
    if isinstance(f, ExpVar):
        return str(f.var)
    return None


def _ret_name(call: Call) -> Optional[str]:
    ret = call.ret
    if not ret:
        return None
    ident = ret[0] if isinstance(ret, tuple) else ret
    return str(ident)                                  # `$app_1`: a temporary, not the variable app


def _instrs(proc):
    for node in proc.nodes.values():
        yield from node.instrs


def _required_module(call: Call, proc) -> Optional[str]:
    """`require("express")`: the value is the module itself (CommonJS), named by its specifier."""
    if _call_text(call) != "require" or len(call.args) != 1:
        return None
    arg = call.args[0][0] if isinstance(call.args[0], tuple) else call.args[0]
    if isinstance(arg, ExpConst) and isinstance(arg.value, str) and arg.value \
            and not arg.value.startswith((".", "/")):        # a project file: link_modules gives what it exports
        return arg.value
    return None


def _module_qualified(text: Optional[str], modules: Set[str]) -> Optional[str]:
    """A call the frontend already names after an imported module (`@hapi/hapi.server` for
    `Hapi.server(...)` with `Hapi = require("@hapi/hapi")`): that name is what it is."""
    if not text:
        return None
    for m in modules:
        if text == m or text.startswith(m + "."):
            return text
    return None


def _definitions(proc) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for p, _ in proc.params:
        counts[str(p)] = 2        # a parameter is never single-bound
    for i in _instrs(proc):
        name = _ret_name(i) if isinstance(i, Call) else str(i.id) \
            if isinstance(i, Assign) else None
        if name:
            counts[name] = counts.get(name, 0) + 1
    return counts


def _expression_call_origin(exp, imports: Dict[str, str], returning: Optional[Dict[str, str]] = None) -> Optional[str]:
    """`new Pool(o)` / `mysql.createPool(o)` written as an expression (no Call instruction): the
    class or the call id, through the file's imports; a call of a function whose returns are one
    value (`returning`) is that value."""
    if not isinstance(exp, ExpCall):
        return None
    text = _call_text(exp)
    if not text:
        return None
    if returning and text in returning:
        return returning[text]
    new = text.startswith("new ")
    name = text[4:] if new else text
    head, _, rest = name.partition(".")
    qualified = imports.get(head)
    if qualified is None or not head.isidentifier():
        return None
    return f"{qualified}.{rest}" if rest else qualified


def _origins(proc, outer: Dict[str, str], fill: bool, imports: Optional[Dict[str, str]] = None,
             params: Optional[Dict[str, str]] = None, python: bool = False,
             returning: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Origins of the names bound once in `proc`; with `fill`, also give unresolved calls on
    them their callee id. `params`: origins of parameters every caller agrees on (a project's
    `require("./routes")(app)` with `app = express()`), else a parameter has none."""
    imports = imports or {}
    imported_modules = {v for v in imports.values() if v}
    defs = _definitions(proc)
    origin: Dict[str, str] = dict(params or {})
    through = passes("python") if python else {}
    receivers_ = {p.split(".", 1)[0] for p in origin if "." in p}          # `self` of `self.conn`
    if python:                                          # a parameter declared as a library type
        for name, text in (getattr(proc, "param_types", None) or {}).items():
            head, _, rest = text.partition(".")
            if name not in origin and head.isidentifier() and head in imports:
                origin[name] = f"{imports[head]}.{rest}" if rest else imports[head]
    modules: Set[str] = set()          # names holding a module itself (`require("express")`), not a call's result

    def of(name: str) -> Optional[str]:
        if name in origin:
            return origin[name]
        return outer.get(name) if name not in defs else None

    for _ in range(8):                                  # chains `a = f(); b = a.g(); b.h()`
        changed = False
        for i in _instrs(proc):
            if isinstance(i, Call):
                text = _call_text(i)
                receiver_given = text and text.split(".", 1)[0] in (params or {})   # an entry point's `receiver`
                if fill and python and text and "." in text and i.canonical is not None:
                    head, rest = text.split(".", 1)        # an imported name whose project value is known
                    known = of(head)
                    if known and head in imports and known != imports[head] \
                            and i.canonical == f"{imports[head]}.{rest}":
                        i.canonical = None
                parts_ = text.split(".") if text else []
                field_head = ".".join(parts_[:2]) if len(parts_) > 2 and parts_[0] in receivers_ else None
                if i.canonical is None and fill and text and field_head and field_head in origin:
                    _set(i, f"{origin[field_head]}.{'.'.join(parts_[2:])}")   # `self.conn.cursor()`
                    changed = True
                elif i.canonical is None and fill and text and "." in text \
                        and (receiver_given or not text.startswith(("this.", "self."))):
                    head, rest = text.split(".", 1)
                    o = of(head)
                    if o is not None and head.replace("$", "_").isidentifier():
                        _set(i, f"{o}.{rest}")
                        changed = True
                elif i.canonical is None and fill and text and text in modules:
                    _set(i, origin[text])                 # `require("express")()`: calling the module value
                    changed = True
                r = _ret_name(i)
                required = _required_module(i, proc)
                produced = i.canonical or required or _module_qualified(text, imported_modules)
                if python and text and returning and text in returning:     # a function returning one value
                    produced = returning[text]
                if python and produced and produced in through and i.args:  # `contextlib.closing(x)` is x
                    arg = i.args[through[produced]][0] if through[produced] < len(i.args) else None
                    produced = (of(str(arg.var)) if isinstance(arg, ExpVar) else
                                _expression_call_origin(arg, imports, returning) if arg is not None else None)
                if r and defs.get(r) == 1 and produced and origin.get(r) != produced:
                    origin[r] = produced
                    changed = True
                if r and required and defs.get(r) == 1:
                    modules.add(r)
            elif isinstance(i, Assign) and isinstance(i.exp, (ExpVar, ExpCall)):
                x = str(i.id)
                o = of(str(i.exp.var)) if isinstance(i.exp, ExpVar) else _expression_call_origin(i.exp, imports, returning)
                if o is not None and defs.get(x) == 1 and origin.get(x) != o:
                    origin[x] = o
                    changed = True
                if isinstance(i.exp, ExpVar) and str(i.exp.var) in modules and defs.get(x) == 1:
                    modules.add(x)
        if not changed:
            break
    if fill and python:
        _fill_by_latest_binding(proc, origin, imports, returning)
    return origin


def _set(call, canonical: str) -> None:
    """A callee id value origins gave: recomputed whenever the origins are (`_reset_filled`)."""
    call.canonical = canonical
    call.canonical_by_origin = canonical


def _reset_filled(program) -> None:
    """Before origins are recomputed: the ids they gave go, so better-known origins (a project's
    imports learned late) rename the calls. A call whose id changes loses the pack spec matched on
    the old one (`packs.apply.reapply_rules` matches it again)."""
    for proc in program.procedures.values():
        for i in _instrs(proc):
            given = getattr(i, "canonical_by_origin", None)
            if given is not None and i.canonical == given:
                i.canonical = None
                i.canonical_by_origin = None
                i.stale_pack_spec = getattr(i, "pack_spec", None) is not None


def _settle_filled(program) -> bool:
    """After: drop the pack spec of a call whose id moved. Returns whether any id moved."""
    moved = False
    for proc in program.procedures.values():
        for i in _instrs(proc):
            if getattr(i, "stale_pack_spec", None) is not None:
                if i.stale_pack_spec and getattr(i, "canonical_by_origin", None) != getattr(i, "_prev_origin_id", None):
                    i.pack_spec = None
                    moved = True
                i.stale_pack_spec = None
    return moved


def _fill_by_latest_binding(proc, origin: Dict[str, str], imports: Dict[str, str],
                            returning: Optional[Dict[str, str]]) -> None:
    """A name bound more than once (`RESPONSE = ""` ... `RESPONSE = make_response(RESPONSE)`):
    a call on it takes the origin of the binding that reaches it, when that is the latest one
    in the same block (straight-line code, no path between them rebinding it)."""
    defs = _definitions(proc)
    through = passes("python")
    for node in proc.nodes.values():
        latest: Dict[str, Optional[str]] = {}
        for i in node.instrs:
            if isinstance(i, Call):
                text = _call_text(i)
                if i.canonical is None and text and "." in text:
                    head, rest = text.split(".", 1)
                    if defs.get(head, 0) > 1 and latest.get(head):
                        _set(i, f"{latest[head]}.{rest}")
                r = _ret_name(i)
                if r:
                    produced = i.canonical or (returning or {}).get(text or "")
                    if produced in through:                 # `closing(x)` is x
                        idx = through[produced]
                        arg = i.args[idx][0] if idx < len(i.args) else None
                        produced = (latest.get(str(arg.var)) or origin.get(str(arg.var))) \
                            if isinstance(arg, ExpVar) else None
                    latest[r] = produced
            elif type(i).__name__ == "Assign":
                x = str(i.id)
                if isinstance(i.exp, ExpVar):
                    v = str(i.exp.var)
                    latest[x] = latest.get(v) or origin.get(v)
                elif isinstance(i.exp, ExpCall):
                    latest[x] = _expression_call_origin(i.exp, imports, returning)
                else:
                    latest[x] = None


def _module_params(program, param_origins, imports: Dict[str, str]) -> Dict[str, str]:
    """Module-level origins given from outside (a project's imported names), and, in Python, each
    class of the file whose base has an origin (`class Order(db.Model)` with `db = SQLAlchemy()`,
    `class Order(models.Model)`): the class is a kind of that base (its class attributes, such as a
    model's `query` or `objects`, are the base's)."""
    out = dict(param_origins.get(MODULE) or {})
    if (getattr(program, "language", "") or "") != "python":
        return out
    module = program.procedures.get(MODULE)
    module_origins: Dict[str, str] = {}
    if module is not None:
        module_origins = _origins(module, {}, fill=False, imports=imports, params=dict(out))
    for name, info in (getattr(program, "class_info", None) or {}).items():
        if name in out:
            continue
        for base in getattr(info, "bases", ()) or ():
            head, _, rest = base.partition(".")
            o = module_origins.get(head) or out.get(head) or imports.get(head)
            if o and head.isidentifier():
                out[name] = f"{o}.{rest}" if rest else o
                break
    return out


def annotate(program, param_origins: Optional[Dict[str, Dict[str, str]]] = None) -> None:
    """Fill `Call.canonical` from value origins (calls whose callee id the frontend left unset),
    and record each procedure's origins (`Program.value_origins`: procedure -> name -> origin,
    a nested function seeing its enclosing functions' names). Idempotent; run again with
    `param_origins` (procedure -> parameter -> origin) once callers are known."""
    imports = {k: str(v) for k, v in (getattr(program, "imports", None) or {}).items()}
    python = (getattr(program, "language", "") or "") == "python"
    if python:
        for proc in program.procedures.values():
            for i in _instrs(proc):
                if isinstance(i, Call):
                    i._prev_origin_id = getattr(i, "canonical_by_origin", None)
    param_origins = param_origins or getattr(program, "param_origins", None) or {}
    program.param_origins = param_origins
    returning: Dict[str, str] = dict(getattr(program, "call_origins", None) or {}) if python else {}
    for _ in range(3 if python else 1):         # a function returning what another returns
        scopes = _annotate_scopes(program, param_origins, imports, python, returning)
        if not python:
            break
        fields = _init_field_origins(program, scopes)
        merged = {k: dict(v) for k, v in param_origins.items()}
        for name, extra in fields.items():
            merged.setdefault(name, {}).update({k: v for k, v in extra.items() if k not in merged.get(name, {})})
        if merged != param_origins:
            param_origins = merged
            program.param_origins = merged
            scopes = _annotate_scopes(program, param_origins, imports, python, returning)
        found = dict(returning)
        for name, proc in program.procedures.items():
            if name == MODULE or proc.is_method or "#" in name:
                continue
            values = {scopes.get(name, {}).get(str(i.value.var)) for n in proc.nodes.values() for i in n.instrs
                      if type(i).__name__ == "Return" and isinstance(getattr(i, "value", None), ExpVar)}
            if len(values) == 1 and None not in values:
                found[name] = next(iter(values))
        if found == returning:
            break
        returning = found
    program.return_origins = {k: v for k, v in returning.items() if k in program.procedures}
    program.value_origins = scopes
    if python:
        program.origins_moved = _settle_filled(program) or getattr(program, "origins_moved", False)
    program.export_origin = scopes.get(MODULE, {}).get("module.exports")


def _init_field_origins(program, scopes) -> Dict[str, Dict[str, str]]:
    """Python: a field a class's `__init__` sets from a value with an origin (`self.conn = conn`,
    conn handed a connection by every caller) has it in the class's other methods, under their
    own receiver's name (`self.conn`)."""
    out: Dict[str, Dict[str, str]] = {}
    for init in program.procedures.values():
        if not init.is_method or init.simple_name != "__init__" or not init.params or not init.class_name:
            continue
        receiver = init.params[0][0].name
        found: Dict[str, str] = {}
        for i in _instrs(init):
            target = str(i.id) if type(i).__name__ == "Assign" else ""
            if target.startswith(receiver + ".") and target.count(".") == 1 and isinstance(i.exp, ExpVar):
                o = scopes.get(init.name, {}).get(str(i.exp.var))
                if o:
                    found[target[len(receiver) + 1:]] = o
        if not found:
            continue
        for proc in program.procedures.values():
            if proc is init or not proc.is_method or proc.class_name != init.class_name or not proc.params:
                continue
            recv = proc.params[0][0].name
            out[proc.name] = {f"{recv}.{f}": o for f, o in found.items()}
    return out


def _annotate_scopes(program, param_origins, imports, python, returning) -> Dict[str, Dict[str, str]]:
    if python:
        _reset_filled(program)
    module = program.procedures.get(MODULE)
    scopes: Dict[str, Dict[str, str]] = {}
    outer = _origins(module, {}, fill=True, imports=imports, params=_module_params(program, param_origins, imports),
                     python=python, returning=returning) \
        if module is not None else _module_params(program, param_origins, imports)
    scopes[MODULE] = outer

    def visible(name: str, seen: Set[str]) -> Dict[str, str]:
        """What a procedure sees from outside: the module's names and its enclosing functions'."""
        proc = program.procedures.get(name)
        parent = getattr(proc, "parent", None) if proc is not None else None
        if not parent or parent not in program.procedures or parent in seen:
            return dict(outer)
        out = visible(parent, seen | {name})
        if parent not in scopes:
            scopes[parent] = _origins(program.procedures[parent], out, fill=True, imports=imports,
                                      params=param_origins.get(parent), python=python, returning=returning)
        out.update(scopes[parent])
        return out

    for name, proc in program.procedures.items():
        if name != MODULE and name not in scopes:
            scopes[name] = _origins(proc, visible(name, set()), fill=True, imports=imports, python=python,
                                    params=param_origins.get(name), returning=returning)
    return scopes


def origin_in_scope(program, proc_name: str, name: str, imports: bool = True) -> Optional[str]:
    """The origin of `name` as procedure `proc_name` sees it (its own binding, an enclosing
    function's, the module's), else the file's import of that name."""
    scopes = getattr(program, "value_origins", None) or {}
    seen: Set[str] = set()
    cur: Optional[str] = proc_name
    while cur and cur not in seen:
        seen.add(cur)
        found = scopes.get(cur, {}).get(name)
        if found is not None:
            return found
        proc = program.procedures.get(cur)
        if proc is not None and cur != MODULE and name in _definitions(proc):
            return None                                   # bound here, without an origin
        cur = getattr(proc, "parent", None) if proc is not None else None
        if not cur and proc_name != MODULE and MODULE not in seen:
            cur = MODULE
    if not imports:
        return None
    imported = (getattr(program, "imports", None) or {}).get(name)
    return str(imported) if imported is not None else None


def same_file_parameter_origins(program) -> Dict[str, Dict[str, str]]:
    """Within one file: a function's parameter that every call of it (by its plain name) passes a
    value of the same origin (a handler handing its response to `send(res, x)`): procedure ->
    parameter -> origin. A parameter some call passes something else has none."""
    seen: Dict[Tuple[str, int], Set[Optional[str]]] = {}
    for proc in program.procedures.values():
        for i in _instrs(proc):
            if not isinstance(i, Call) or not i.args:
                continue
            callee = program.procedures.get(_call_text(i) or "")
            if callee is None or callee is proc:
                continue
            for n, (arg, _) in enumerate(i.args):
                origin = origin_in_scope(program, proc.name, str(arg.var)) if isinstance(arg, ExpVar) else None
                seen.setdefault((callee.name, n), set()).add(origin)
    out: Dict[str, Dict[str, str]] = {}
    for (name, n), origins in seen.items():
        proc = program.procedures[name]
        if len(origins) == 1 and None not in origins and n < len(proc.params):
            out.setdefault(name, {})[proc.params[n][0].name] = next(iter(origins))
    return out


def link_python_modules(programs: Dict[str, object], bindings) -> None:
    """In a project: a name a Python file imports from another project file (`from app import
    app`) has the origin that file's module level binds it to (`app = Flask(__name__)`), through
    re-exports. `bindings(key)` gives a file's local name -> (file, symbol) imports."""
    for _ in range(4):                                  # a name re-exported by an `__init__`
        changed = False
        for key, program in programs.items():
            if (getattr(program, "language", "") or "") != "python":
                continue
            found: Dict[str, str] = {}
            calls: Dict[str, str] = {}
            for local, (file, symbol) in bindings(key).items():
                target = programs.get(file)
                scopes = getattr(target, "value_origins", None) or {} if target is not None else {}
                origin = scopes.get(MODULE, {}).get(symbol)
                if origin and local not in program.procedures:
                    found[local] = origin
                returned = (getattr(target, "return_origins", None) or {}).get(symbol) if target is not None else None
                if returned and local not in program.procedures:
                    calls[local] = returned          # an imported function returning one value
            if calls != (getattr(program, "call_origins", None) or {}):
                program.call_origins = calls
                annotate(program, getattr(program, "param_origins", None) or {})
                changed = True
            current = getattr(program, "param_origins", None) or {}
            merged = {k: dict(v) for k, v in current.items()}
            module = merged.setdefault(MODULE, {})
            new = {k: v for k, v in found.items() if module.get(k) != v}
            if new:
                module.update(new)
                annotate(program, merged)
                changed = True
        if not changed:
            break


def link_modules(programs: Dict[str, object], resolve) -> None:
    """In a project: a call on a module another file of the project is (`../db.query`, the JS
    frontend's name for `db.query` after `const db = require("../db")`) takes the origin of the
    value that file exports (`module.exports = mysql.createPool(...)`). `resolve(key, specifier)`
    gives the file a specifier names, or None."""
    for key, program in programs.items():
        for proc in program.procedures.values():
            for i in _instrs(proc):
                if not isinstance(i, Call) or i.canonical is not None:
                    continue
                text = _call_text(i)
                if not text or not text.startswith("."):
                    continue
                cut = len(text)
                while True:
                    cut = text.rfind(".", 0, cut)
                    if cut <= 0:
                        break
                    target = resolve(key, text[:cut])
                    if target is not None:
                        origin = getattr(programs.get(target), "export_origin", None)
                        if origin:
                            i.canonical = f"{origin}.{text[cut + 1:]}"
                        break


# -- what library calls return ------------------------------------------------------------------

_PASSES: Dict[str, Dict[str, int]] = {}


def passes(language: str) -> Dict[str, int]:
    """Call id -> the position of the argument the call returns (`contextlib.closing(x)` is x)."""
    load()
    return _PASSES.get("javascript" if (language or "").lower() == "typescript" else (language or "").lower(), {})


@lru_cache(maxsize=None)
def load(path: Path = PATH) -> Dict[str, Tuple[Dict[str, str], Dict[str, Tuple[str, ...]]]]:
    """language -> (call id -> returned type, type or class -> spec receiver names)."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for lang, table in data.items():
        if not isinstance(table, dict) or set(table) - {"returns", "receivers", "passes"}:
            raise ValueError(f"{Path(path).name}: [{lang}] holds only returns, receivers and passes")
        passes = table.get("passes", {})
        if not all(isinstance(k, str) and isinstance(v, int) and v >= 0 for k, v in passes.items()):
            raise ValueError(f"{Path(path).name}: [{lang}.passes] maps call ids to the argument they return")
        _PASSES[lang] = dict(passes)
        returns, receivers = table.get("returns", {}), table.get("receivers", {})
        if not all(isinstance(k, str) and isinstance(v, str) and v for k, v in returns.items()):
            raise ValueError(f"{Path(path).name}: [{lang}.returns] maps call ids to a type name")
        if not all(isinstance(v, list) and v and all(isinstance(n, str) and n for n in v)
                   for v in receivers.values()):
            raise ValueError(f"{Path(path).name}: [{lang}.receivers] maps a type to spec receiver names")
        out[lang] = (dict(returns), {k: tuple(v) for k, v in receivers.items()})
    return out


def _without_arguments(text: str) -> str:
    """`sqlite3.connect("x").execute` -> `sqlite3.connect.execute`: a chained call's id is
    written with the argument text of the calls in it."""
    out, depth, quote = [], 0, ""
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
            continue
        if depth and ch in "\"'`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif not depth:
            out.append(ch)
    return "".join(out)


def stand_ins(language: str) -> frozenset:
    """The receiver names the language's spec table writes typed rows under (`cursor`, `logger`):
    a row under one applies to a value of a type that names it, never to a variable so called."""
    lang = "javascript" if (language or "").lower() == "typescript" else (language or "").lower()
    _, receivers = load().get(lang, ({}, {}))
    return frozenset(n for names in receivers.values() for n in names)


def typed_names(canonical: str, language: str, extra: Optional[Dict[str, str]] = None) -> List[str]:
    """Spec keys for a call id whose receiver is a typed library value (most specific first);
    empty when no part of the id is a call whose return type is known. `extra`: more call id ->
    type facts (a pack's `[[returns]]`: what a project's own helper returns)."""
    lang = "javascript" if (language or "").lower() == "typescript" else (language or "").lower()
    returns, receivers = load().get(lang, ({}, {}))
    if extra:
        returns = {**returns, **extra}
    parts = _without_arguments(canonical).split(".")
    typ: Optional[str] = None
    i = 0
    while i < len(parts) - 1:                           # the last part is the method called
        for j in range(len(parts) - 1, i, -1):          # longest call id first
            key = ".".join(([typ] if typ else []) + parts[i:j]) if typ else ".".join(parts[i:j])
            if key in returns:
                typ, i = returns[key], j
                break
        else:
            if typ is None:                             # an instance of a class (`new pg.Pool()`)
                cls = next((".".join(parts[:j]) for j in range(len(parts) - 1, 0, -1)
                            if ".".join(parts[:j]) in receivers), None)
                if cls is None:
                    return []
                typ, i = cls, len(cls.split("."))
                continue
            break
    if typ is None or i != len(parts) - 1:
        return []
    method = parts[-1]
    return [f"{typ}.{method}"] + [f"{r}.{method}" for r in receivers.get(typ, ())]


__all__ = ["annotate", "load", "origin_in_scope", "same_file_parameter_origins", "stand_ins", "typed_names"]
