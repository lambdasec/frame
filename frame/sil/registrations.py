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
    seen: Dict[Tuple[str, str, int], Set[Optional[str]]] = {}
    resolved: Dict[Tuple[str, str], Optional[Tuple[str, str]]] = {}
    for key, program in programs.items():
        for proc in program.procedures.values():
            for i in _instrs(proc):
                if not isinstance(i, Call) or not i.args:
                    continue
                name = i.get_full_name()
                if (key, name) not in resolved:
                    resolved[(key, name)] = ctx.resolve_call(key, name)
                ref = resolved[(key, name)]
                if ref is None:
                    continue
                for n, (arg, _) in enumerate(i.args):        # every resolved caller votes, unknown ones too
                    origin = origin_in_scope(program, proc.name, str(arg.var)) if isinstance(arg, ExpVar) else None
                    seen.setdefault((ref[0], ref[1], n), set()).add(origin)
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


def registration_vias(program, reg: Registration) -> List[str]:
    """The registration's callee, as written and by the origin of the name it is reached from."""
    vias = [reg.callee_text]
    if reg.root is not None:
        origin = origin_in_scope(program, reg.scope, reg.root)
        if origin:
            vias.append(".".join((origin,) + reg.rest))
    return vias


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
    for _ in range(4):                                    # routes mounted from routes mounted from the app
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


__all__ = ["Registration", "apply_callback_params", "link_openapi", "link_project", "registration_vias"]
