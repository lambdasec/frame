"""Handler registrations across a project: `app.get(path, handler)` where `app` is a parameter the
module's callers pass an `express()` application in, or where `handler` is a function another
file defines (`router.get("/", controller.list)`, `app.get("/", users.show)` with `users = new
UsersHandler(db)`, Django's `path("x/", views.show)` in urls.py). JavaScript, TypeScript and
Python programs take part.

The frontend records each call that passes a function or a reference to one (`Registration`):
where it is, its callee as a chain from a name (`app` + `get`), and the handler (a procedure of
the file, or the reference as written). Within one file, the frontend already names the callee
by value origin (`express.get`) and packs match it. In a project this step adds what one file
cannot know:

1. parameter origins: a parameter every resolved caller passes the same kind of value (all
   `require("./routes")(app)` calls pass `app = express()`) has that origin, so the calls on it
   are named after it (value_origins.annotate with `param_origins`), to a fixpoint;
2. registrations: each registration's callee by the origins now known, and its handler
   resolved through the project index (imports, class evidence: `ProjectIndex.resolve_call`).
   The handler procedure gets the callee among its `registered_via`, and the packs' entry points
   are applied to it in its own file.

Nothing is guessed: a parameter that callers pass different values, or that no resolved caller
passes, has no origin; a reference the index does not resolve is not a handler."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from fnmatch import fnmatchcase
from pathlib import Path

from .instructions import Call
from .types import ExpVar
from .value_origins import annotate, origin_in_scope


@dataclass(frozen=True)
class Registration:
    scope: str                          # the procedure the call is written in
    callee_text: str                    # `app.get`, as written
    root: Optional[str]                 # `app`: the name the callee chain starts from
    rest: Tuple[str, ...]               # `("get",)`, `("route", "get")`: what follows it
    arg_index: int
    target: Optional[str] = None        # the handler, a procedure of this file
    ref: Optional[str] = None           # the handler as written when it is not (`controller.list`)
    event: Optional[str] = None         # the call's first argument when it is a literal (`"connection"`)
    module: Optional[str] = None        # the handler is `require("<module>")`, a file's export


def _instrs(proc):
    for node in proc.nodes.values():
        yield from node.instrs


def _parameter_origins(ctx, index, programs: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, str]]:
    """(file, procedure) -> parameter -> the origin every resolved caller passes for it."""
    from .value_origins import _expression_call_origin, call_sites
    seen: Dict[Tuple[str, str, int], Set[Optional[str]]] = {}
    resolved: Dict[Tuple[str, str], Optional[Tuple[str, str]]] = {}
    for key, program in programs.items():
        imports = {k: str(v) for k, v in (getattr(program, "imports", None) or {}).items()}
        returning = getattr(program, "return_origins", None) or {}
        for proc in program.procedures.values():
            for name, args in call_sites(proc):
                if not args or not name:
                    continue
                if (key, name) not in resolved:
                    resolved[(key, name)] = ctx.resolve_call(key, name) or _constructor(ctx, index, programs, key, name)
                ref = resolved[(key, name)]
                if ref is None:
                    continue
                target = programs.get(ref[0])
                callee = target.procedures.get(ref[1]) if target is not None else None
                shift = 1 if callee is not None and _bound(target, callee) else 0   # Python: past `self`
                for n, arg in enumerate(args):               # every resolved caller votes, unknown ones too
                    if callee is proc and isinstance(arg, ExpVar) and n + shift < len(proc.params) \
                            and str(arg.var) == str(proc.params[n + shift][0]):
                        continue                             # `return new UserDAO(db)` inside UserDAO: no new value
                    origin = origin_in_scope(program, proc.name, str(arg.var)) if isinstance(arg, ExpVar) else \
                        _expression_call_origin(arg, imports, returning,
                                                lambda n, p=proc.name: origin_in_scope(program, p, n, imports=False))
                    seen.setdefault((ref[0], ref[1], n + shift), set()).add(origin)
    out: Dict[Tuple[str, str], Dict[str, str]] = {}
    for (file, name, n), origins in seen.items():
        if len(origins) != 1 or None in origins:
            continue
        program = programs.get(file)
        proc = program.procedures.get(name) if program is not None else None
        if proc is None or n >= len(proc.params):
            continue
        out.setdefault((file, name), {})[proc.params[n][0].name] = next(iter(origins))
    return out


def _bound(program, proc) -> bool:
    from .packs.apply import bound_receiver
    return bound_receiver(proc, program) is not None


def _constructor(ctx, index, programs: Dict[str, Any], key: str, name: str) -> Optional[Tuple[str, str]]:
    """Python: `SqlDao(conn)` names the `__init__` of the class SqlDao is (this file's, or the one
    an import binds), when it defines one; JS/TS: `new SqlDao(conn)` its `constructor`."""
    from .value_origins import constructed_class
    program = programs.get(key)
    if program is None:
        return None
    python = (program.language or "") == "python"
    if not python:
        name = constructed_class(name) or ""
    if not name or "." in name:
        return None
    target: Optional[Tuple[str, str]] = None
    if name in (getattr(program, "class_info", None) or {}):
        target = (key, name)
    else:
        mod = index.modules.get(key)
        b = mod.bindings.get(name) if mod is not None else None
        if b is not None and b.symbol is not None:
            target = index.lookup_class(b.file, b.symbol)
        elif b is not None and b.file and not python:     # `const C = require("./c")`: its default export
            from .project import DEFAULT
            target = index.lookup_class(b.file, DEFAULT)
        if target is None and b is not None and b.file and not python:
            from .project import DEFAULT                   # an exported constructor function
            ref = index.lookup_symbol(b.file, b.symbol or DEFAULT)
            target = (ref[0], ref[1]) if ref is not None else None
        if target is None and not python and name in programs[key].procedures:
            target = (key, name)                           # this file's constructor function
    for _ in range(8):                                  # the nearest class of the hierarchy defining __init__
        if target is None or target[0] not in programs:
            return None
        init = f"{target[1]}.{'__init__' if python else 'constructor'}"
        if init in programs[target[0]].procedures:
            return target[0], init
        if not python and target[1] in programs[target[0]].procedures:
            return target                                  # a constructor function: `function C(db) {...}`
        info = (getattr(programs[target[0]], "class_info", None) or {}).get(target[1])
        bases = [b for b in (info.bases if info is not None else ()) if b.isidentifier()]
        if not bases:
            return None
        base, owner = bases[0], target[0]
        if base in (getattr(programs[owner], "class_info", None) or {}):
            target = (owner, base)
        else:
            mod = index.modules.get(owner)
            b = mod.bindings.get(base) if mod is not None else None
            target = index.lookup_class(b.file, b.symbol) if b is not None and b.symbol is not None else None
    return None


def registration_vias(program, reg: Registration) -> List[str]:
    """The registration's callee, as written and by the origin of the name it is reached from."""
    vias = [reg.callee_text]
    if reg.root is not None:
        origin = origin_in_scope(program, reg.scope, reg.root)
        if origin:
            vias.append(".".join((origin,) + reg.rest))
        elif reg.rest:                                   # a field: `this.route.queryParams.subscribe`
            origin = origin_in_scope(program, reg.scope, f"{reg.root}.{reg.rest[0]}", imports=False)
            if origin:
                vias.append(".".join((origin,) + reg.rest[1:]))
    return vias


def refresh_registered_via(program) -> None:
    """Once value origins are known: every registration's handler also lists the callee by origin."""
    for reg in getattr(program, "registrations", ()) or ():
        proc = program.procedures.get(reg.target) if reg.target else None
        if proc is None:
            continue
        for v in registration_vias(program, reg):
            if v not in proc.registered_via:
                proc.registered_via.append(v)


def _callback_origins(program, target_program, reg: Registration, target_name: str,
                      callbacks) -> Dict[str, str]:
    """What the packs' [[callback_param]] entries say the framework hands this registration's
    handler: parameter -> origin."""
    proc = target_program.procedures.get(target_name)
    if proc is None:
        return {}
    vias = registration_vias(program, reg)
    out: Dict[str, str] = {}
    for cb in callbacks:
        if cb.event and reg.event not in cb.event:
            continue
        if any(fnmatchcase(v, g) for g in cb.registered_via for v in vias) and cb.position < len(proc.params):
            out[proc.params[cb.position][0].name] = cb.origin
    return out


def apply_callback_params(program, packs) -> None:
    """Within one file: give the parameters frameworks hand registered callbacks their origin
    (Socket.IO's connection socket, a Fastify plugin's instance), to a fixpoint (a callback
    registered on such a parameter can receive one in turn), and record the registrations this
    names among the handlers' `registered_via`."""
    callbacks = [cb for p in packs for cb in getattr(p, "callback_params", ())]
    for _ in range(4):
        found: Dict[str, Dict[str, str]] = {}
        for reg in getattr(program, "registrations", ()) or ():
            if reg.target is not None and callbacks:
                params = _callback_origins(program, program, reg, reg.target, callbacks)
                if params:
                    found.setdefault(reg.target, {}).update(params)
        merged = {k: dict(v) for k, v in (getattr(program, "param_origins", None) or {}).items()}
        for k, v in found.items():
            merged.setdefault(k, {}).update(v)
        changed = merged != (getattr(program, "param_origins", None) or {})
        if changed:
            annotate(program, merged)
        for reg in getattr(program, "registrations", ()) or ():
            proc = program.procedures.get(reg.target) if reg.target else None
            if proc is None:
                continue
            for v in registration_vias(program, reg):
                if v not in proc.registered_via:
                    proc.registered_via.append(v)
        if not changed:
            break


def _target_of(ctx, index, key: str, programs: Dict[str, Any], reg: Registration) -> Optional[Tuple[str, str]]:
    """The procedure a registration hands over: one of the file's, the default export of a
    required project file, or what the index resolves the written reference to."""
    if reg.target is not None:
        return key, reg.target
    if reg.module is not None:
        mod = index.modules.get(key)
        other = index._resolve_js(mod, reg.module) if mod is not None and mod.family == "javascript" else None
        program = programs.get(other) if other else None
        proc = next((p for p in program.procedures.values() if "default" in p.exported_as), None) \
            if program is not None else None
        return (other, proc.name) if proc is not None else None
    if reg.ref is not None:
        return ctx.resolve_call(key, reg.ref)
    return None


def link_project(ctx, index, packs_for: Callable[[str], Any]) -> None:
    """Resolve parameter origins (what callers pass, what frameworks hand callbacks) and
    registrations over the project's programs, and apply the packs' entry points to handlers
    whose registration only the project shows."""
    from .packs.apply import apply_entrypoints_to
    programs: Dict[str, Any] = {k: p for k, p in ctx.programs.items()
                                if (p.language or "") in ("javascript", "typescript", "python")}
    if not programs:
        return
    callbacks: Dict[str, list] = {}

    def callbacks_for(language: str) -> list:
        if language not in callbacks:
            packs = packs_for(language)
            callbacks[language] = [cb for p in packs.for_language(language) for cb in p.callback_params]
        return callbacks[language]

    renamed: Set[str] = set()
    for _ in range(16):         # routes mounted from routes from the app; a value handed down a chain of constructors
        found = _parameter_origins(ctx, index, programs)
        for key, program in programs.items():
            cbs = callbacks_for(program.language)
            if not cbs:
                continue
            for reg in getattr(program, "registrations", ()) or ():
                where = _target_of(ctx, index, key, programs, reg)
                if where is not None and where[0] in programs:
                    params = _callback_origins(program, programs[where[0]], reg, where[1], cbs)
                    if params:
                        found.setdefault(where, {}).update(params)
        changed = False
        for key, program in programs.items():
            current = getattr(program, "param_origins", None) or {}
            merged = {k: dict(v) for k, v in current.items()}
            for (file, name), params in found.items():
                if file == key:
                    merged.setdefault(name, {}).update(params)
            if merged != current:
                annotate(program, merged)
                renamed.add(key)
                changed = True
        if not changed:
            break
    # calls renamed by what callers hand in (`after(res, url)` with `res` a response) meet the
    # packs' rules now
    from .packs.apply import _detected, reapply_rules
    for key in renamed:
        program = programs[key]
        reapply_rules(program, [p for p in packs_for(program.language).for_language(program.language)
                                if _detected(p, program)])
    targets: Dict[str, Set[str]] = {}
    for key, program in programs.items():
        for reg in getattr(program, "registrations", ()) or ():
            vias = registration_vias(program, reg)
            if len(vias) == 1:
                continue                                    # nothing a pack could name
            where = _target_of(ctx, index, key, programs, reg)
            if where is None or where[0] not in programs:
                continue
            proc = programs[where[0]].procedures.get(where[1])
            if proc is None:
                continue
            added = [v for v in vias if v not in proc.registered_via]
            if added:
                proc.registered_via.extend(added)
                targets.setdefault(where[0], set()).add(where[1])
    from .frontends.javascript_frontend import JavaScriptFrontend
    for key, names in targets.items():
        program = programs[key]
        apply_entrypoints_to(program, sorted(names), packs_for(program.language))
        if program.language in ("javascript", "typescript"):
            JavaScriptFrontend._entry_taint_into_closures(program)   # callbacks nested in the handlers


def link_openapi(ctx, index, packs_for: Callable[[str], Any]) -> None:
    """Python frameworks that dispatch an OpenAPI operation to the function its `operationId`
    names (a pack's `[[operation_dispatch]]`: connexion): read the project's OpenAPI documents,
    resolve each id as a dotted path the way the app's own file imports it (`api_views.users.
    update_password`, or the `x-openapi-router-controller` module plus the id), and register the
    function under the pack's id, so the pack's entry points apply to it."""
    from .openapi import documents, operations
    from .packs.apply import _detected, apply_entrypoints_to
    apps = []
    for key, program in ctx.programs.items():
        if (program.language or "") != "python":
            continue
        for pack in packs_for("python").for_language("python"):
            if pack.operation_dispatch and _detected(pack, program):
                apps.append((key, pack))
    if not apps or getattr(index, "root", None) is None:
        return
    ops = [op for doc in documents(Path(index.root)) for op in operations(doc)]
    targets: Dict[str, Set[str]] = {}
    for key, pack in apps:
        importer = index.modules.get(key)
        if importer is None:
            continue
        for controller_keys, registered_as in pack.operation_dispatch:
            for op in ops:
                controller = next((op.extensions[k] for k in controller_keys if k in op.extensions), None)
                dotted = f"{controller}.{op.operation_id}" if controller else op.operation_id
                parts = tuple(p for p in dotted.split(".") if p)
                if len(parts) < 2 or not all(p.isidentifier() for p in parts):
                    continue
                target = index._resolve_python(importer, parts[:-1], 0)
                program = ctx.programs.get(target) if target else None
                proc = program.procedures.get(parts[-1]) if program is not None else None
                if proc is None or proc.is_method:
                    continue
                if registered_as not in proc.registered_via:
                    proc.registered_via.append(registered_as)
                targets.setdefault(target, set()).add(proc.name)
    for key, names in targets.items():
        apply_entrypoints_to(ctx.programs[key], sorted(names), packs_for("python"))


def link_settings(ctx, index, packs_for: Callable[[str], Any]) -> None:
    """Python settings that register code by dotted path (a pack's `[[setting_registration]]`:
    Django's `MIDDLEWARE = ["app.middleware.Audit", ...]`): what each path names, resolved the
    way the settings file imports it. A class's methods are registered as the pack's id (the
    framework calls them on an instance), a function as the id and the function it returns
    (a middleware factory's inner function) as the id plus `()`."""
    from .packs.apply import apply_entrypoints_to
    from .types import ExpVar
    from .instructions import Return
    regs = []
    for pack in packs_for("python").for_language("python"):
        if pack.setting_registrations and any(
                (p.language or "") == "python" and pack in getattr(p, "active_packs", ()) for p in ctx.programs.values()):
            regs.extend(pack.setting_registrations)
    if not regs:
        return
    targets: Dict[str, Set[str]] = {}

    def register(key: str, proc, via: str) -> None:
        if via not in proc.registered_via:
            proc.registered_via.append(via)
        targets.setdefault(key, set()).add(proc.name)

    for key, program in ctx.programs.items():
        lists = getattr(program, "module_string_lists", None) or {}
        importer = index.modules.get(key)
        for setting, registered_as in regs:
            for dotted in lists.get(setting, ()):
                parts = tuple(dotted.split("."))
                if len(parts) < 2 or not all(p.isidentifier() for p in parts) or importer is None:
                    continue
                target = index._resolve_python(importer, parts[:-1], 0)
                found = ctx.programs.get(target) if target else None
                if found is None:
                    continue
                name = parts[-1]
                methods = [p for p in found.procedures.values() if p.is_method and p.class_name == name]
                for m in methods:
                    register(target, m, registered_as)
                factory = found.procedures.get(name)
                if methods or factory is None or factory.is_method:
                    continue
                register(target, factory, registered_as)
                returned = {str(i.value.var) for n in factory.nodes.values() for i in n.instrs
                            if isinstance(i, Return) and isinstance(i.value, ExpVar)}
                for p in found.procedures.values():
                    if p.parent == factory.name and p.simple_name in returned:
                        register(target, p, registered_as + "()")
    for key, names in targets.items():
        apply_entrypoints_to(ctx.programs[key], sorted(names), packs_for("python"))


__all__ = ["Registration", "apply_callback_params", "link_openapi", "link_project", "link_settings",
           "registration_vias"]
