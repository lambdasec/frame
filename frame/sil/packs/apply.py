"""Apply framework packs to a translated Program.

Runs once at the end of every frontend's `translate`. It adds no instruction the
analysis did not already understand:

* rules become a `ProcSpec` on each matching `Call` (`Call.pack_spec`), merged over
  the built-in spec of that call, so the translator's existing source / sink /
  sanitizer / propagation machinery does the rest;
* entry points become `TaintSource` instructions at the top of the handler.
"""

from __future__ import annotations

import copy
import re
from dataclasses import replace
from fnmatch import fnmatchcase
from pathlib import PurePath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..instructions import Assign, Call, TaintKind, TaintSource
from ..metadata import ClassInfo, ImportTable, qualify_type
from ..procedure import Procedure, ProcSpec, Program
from ..types import PVar
from .loader import PackSet, builtin_packs
from .schema import Entrypoint, Pack, Rule

_DEFAULT: Optional[PackSet] = None

_SOURCE_KIND_VALUES = {"user_input": "user", "network_input": "network", "file_input": "file"}
_IMPLICIT_RECEIVERS = frozenset({"self", "cls", "this"})


def default_packs() -> PackSet:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = PackSet(builtin_packs())
    return _DEFAULT


def _glob(patterns: Iterable[str], *candidates: Optional[str]) -> bool:
    cands = [c for c in candidates if c]
    return any(fnmatchcase(c, p) for p in patterns for c in cands)


def _prefix(prefix: str, value: str) -> bool:
    if value == prefix:
        return True
    if prefix.endswith(("/", ".")):
        return value.startswith(prefix)
    return value.startswith((prefix + ".", prefix + "/", prefix + "::"))


def _import_values(program: Program) -> List[str]:
    return list(program.imports.values()) + list(program.import_wildcards)


_MANIFESTS: Dict[str, frozenset] = {}


def _declared_dependencies(program: Program) -> frozenset:
    """The npm packages the nearest package.json above the program's file declares (dependencies,
    devDependencies, peerDependencies, optionalDependencies): what the project says it is built on."""
    import json
    from pathlib import Path
    out: set = set()
    for f in getattr(program, "source_files", ()):
        d = Path(f).resolve().parent
        for parent in [d, *d.parents]:
            key = str(parent)
            if key in _MANIFESTS:
                out |= _MANIFESTS[key]
                break
            manifest = parent / "package.json"
            if manifest.is_file():
                try:
                    data = json.loads(manifest.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    data = {}
                names = frozenset(n for k in ("dependencies", "devDependencies", "peerDependencies",
                                              "optionalDependencies")
                                  for n in (data.get(k) or {} if isinstance(data, dict) else {}))
                _MANIFESTS[key] = names
                out |= names
                break
    return frozenset(out)


def _detected(pack: Pack, program: Program) -> bool:
    if not pack.has_detect:
        return True
    values = _import_values(program)
    if any(_prefix(p, v) for p in pack.detect_imports for v in values):
        return True
    # a file that uses the framework's values without importing it (handed `app` by its caller):
    # a call or a registration named after them by value origin (value_origins.py)
    if pack.detect_imports:
        used = {i.canonical for proc in program.procedures.values() for n in proc.nodes.values()
                for i in n.instrs if isinstance(i, Call) and i.canonical}
        used |= {v for proc in program.procedures.values() for v in proc.registered_via}
        if any(_prefix(p, v) for p in pack.detect_imports for v in used):
            return True
    if pack.detect_dependencies and set(pack.detect_dependencies) & _declared_dependencies(program):
        return True
    if pack.detect_annotations:
        names: List[str] = []
        for proc in program.procedures.values():
            for a in proc.annotations:
                names += [a.name, a.canonical or ""]
            for anns in proc.param_annotations.values():
                for a in anns:
                    names += [a.name, a.canonical or ""]
        for info in program.class_info.values():
            for a in info.annotations:
                names += [a.name, a.canonical or ""]
        if any(_glob(pack.detect_annotations, n) for n in names if n):
            return True
    if pack.detect_extends:
        for info in program.class_info.values():
            if _glob(pack.detect_extends, *info.bases, *info.canonical_bases):
                return True
    if pack.detect_files:
        names = [PurePath(f).name.lower() for f in getattr(program, "source_files", ())]
        if any(fnmatchcase(n, p.lower()) for p in pack.detect_files for n in names):
            return True
    if pack.detect_module_names:
        module = getattr(program, "procedures", {}).get("<module>")
        assigned = {str(i.id.name if isinstance(i.id, PVar) else i.id)
                    for i in (module.get_all_instrs() if module is not None else ()) if isinstance(i, Assign)}
        if assigned & set(pack.detect_module_names):
            return True
    return False


# -- call rules ---------------------------------------------------------------

class _RuleIndex:
    """Rules indexed for lookup by canonical id (exact, then glob) and by textual name."""

    def __init__(self) -> None:
        self.exact: Dict[str, List[Tuple[Pack, Rule]]] = {}
        self.globs: List[Tuple[re.Pattern, Pack, Rule]] = []
        self.names: List[Tuple[str, Pack, Rule]] = []

    def add(self, pack: Pack, rule: Rule) -> None:
        for c in rule.call:
            if any(ch in c for ch in "*?["):
                self.globs.append((re.compile(_glob_to_regex(c)), pack, rule))
            else:
                self.exact.setdefault(c, []).append((pack, rule))
        for n in rule.name:
            self.names.append((n, pack, rule))

    def match(self, canonical: Optional[str], func: str) -> List[Tuple[Pack, Rule]]:
        out: List[Tuple[Pack, Rule]] = []
        seen = set()

        def take(item):
            if id(item[1]) not in seen:
                seen.add(id(item[1]))
                out.append(item)
        if canonical:
            for item in self.exact.get(canonical, ()):
                take(item)
            for rx, pack, rule in self.globs:
                if rx.fullmatch(canonical):
                    take((pack, rule))
        if func:
            for n, pack, rule in self.names:
                if func == n or func.endswith("." + n):
                    take((pack, rule))
        return out


def _glob_to_regex(pattern: str) -> str:
    # `*` stays inside one dotted segment unless doubled: `a.*.get` vs `a.**`
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^.]*")
        elif c == "?":
            out.append("[^.]")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _func_text(call: Call) -> str:
    return str(getattr(call.func, "value", call.func))


def _arg_text(exp) -> str:
    return str(getattr(exp, "value", exp)).strip("'\"").lower()


def _resolve_sink_args(rule: Rule, call: Optional[Call]) -> Optional[List[int]]:
    """Argument positions a sink rule applies to for this call; None = the rule's
    `when_kwarg` condition does not hold. Without a call (registering a name-keyed
    spec) only unconditional, positional rules apply."""
    if call is None:
        return None if rule.when_kwarg is not None else sorted(set(rule.args))
    if rule.when_kwarg is not None:
        name, value = rule.when_kwarg
        names = call.kwarg_names or []
        hit = [i for i, n in enumerate(names) if n == name]
        if not hit or _arg_text(call.args[hit[0]][0]) != value.strip("'\"").lower():
            return None
    args = list(rule.args)
    if rule.arg_names and call.kwarg_names:
        args += [i for i, n in enumerate(call.kwarg_names) if n in rule.arg_names]
    if not call.args:
        return sorted(set(args))
    resolved = sorted(set(a for a in args if a < len(call.args)))
    # a rule that names argument positions this call does not have (a variadic sink called
    # with fewer arguments) does not apply: an empty list would read as "the call itself is
    # the vulnerability" to the translator
    return resolved if resolved or not args else None


def _merge_spec(base: Optional[ProcSpec], matches: Sequence[Tuple[Pack, Rule]],
                call: Optional[Call]) -> Optional[ProcSpec]:
    spec = copy.copy(base) if base is not None else ProcSpec()
    changed = False
    for pack, rule in matches:
        desc = rule.description or f"{pack.name} {rule.role}"
        if rule.role == "source":
            spec.is_source = _SOURCE_KIND_VALUES.get(rule.kind, rule.kind)
            if rule.out_args:
                spec.taint_out_args = sorted(set(spec.taint_out_args) | set(rule.out_args))
            changed = True
        elif rule.role == "sink":
            if rule.only_if_not_sink and spec.is_sink:
                continue
            args = _resolve_sink_args(rule, call)
            if args is None:
                continue
            spec.is_sink = rule.kind
            spec.sink_args = args
            spec.json_for_literals = spec.json_for_literals or rule.json_for_literals
            changed = True
        elif rule.role == "sanitizer":
            spec.is_sanitizer = sorted(set(spec.is_sanitizer) | set(rule.kinds))
            changed = True
        else:
            if rule.propagate_to == "return":
                spec.taint_propagates = sorted(set(spec.taint_propagates) | set(rule.propagate_from))
                spec.taint_from_receiver = spec.taint_from_receiver or rule.receiver
            else:
                spec.taint_to_dest = sorted(set(spec.taint_to_dest) | set(rule.propagate_from))
            changed = True
        spec.description = spec.description or desc
    if not changed:
        return None
    spec.__post_init__()
    return spec


def _apply_rules(program: Program, packs: Sequence[Pack]) -> None:
    index = _RuleIndex()
    for pack in packs:
        for rule in pack.rules:
            index.add(pack, rule)
    if not (index.exact or index.globs or index.names):
        return
    # Calls written inside an expression (`sink(source())`) have no Call instruction
    # of their own and are looked up by textual name: a name-keyed rule registers
    # its spec under that name, exactly as the built-in specs are keyed.
    for n, pack, rule in index.names:
        spec = _merge_spec(program.library_specs.get(n), [(pack, rule)], None)
        if spec is not None:
            program.library_specs[n] = spec
    # A canonical id is also written in this file under the names its imports give it
    # (`acme.text.sql_clean` as `text.sql_clean`, or `sql_clean` after a from-import).
    for pack in packs:
        for rule in pack.rules:
            for canon in rule.call:
                if any(ch in canon for ch in "*?["):
                    continue
                for local, qualified in program.imports.items():
                    if canon == qualified or canon.startswith(qualified + "."):
                        written = local + canon[len(qualified):]
                        if written in program.procedures:
                            continue
                        # a constructor is written `new SystemMessage(...)` (JS/TS, Java, C#)
                        for name in (written, f"new {written}") if written[:1].isupper() or "." in written else (written,):
                            spec = _merge_spec(program.library_specs.get(name), [(pack, rule)], None)
                            if spec is not None:
                                program.library_specs[name] = spec
    for proc in program.procedures.values():
        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call) or instr.pack_spec is not None:
                    continue
                func = _func_text(instr)
                matches = index.match(instr.canonical, func)
                if not matches:
                    continue
                spec = _merge_spec(program.spec_for_call(instr), matches, instr)
                if spec is None:
                    continue
                instr.pack_spec = spec
                # The same call written inside an expression (no Call instruction) is
                # looked up by name: make that name resolve to the same spec.
                # A conditional rule (`when_kwarg`) holds for this call only: registering its spec
                # by name would hand it to every other call of the same name.
                if func and func not in program.library_specs and instr.canonical \
                        and ":" not in instr.canonical and func not in program.procedures \
                        and not any(r.when_kwarg is not None for _, r in matches):
                    program.library_specs[func] = spec


# -- entry points -------------------------------------------------------------

def _import_table(program: Program) -> ImportTable:
    t = ImportTable()
    t.names.update(program.imports)
    t.wildcards.extend(program.import_wildcards)
    return t


def _bases_closure(program: Program, class_name: str) -> List[str]:
    seen, order, todo = set(), [], [class_name]
    while todo:
        cur = todo.pop()
        info = program.class_info.get(cur)
        if info is None:
            continue
        for b in [*info.bases, *info.canonical_bases]:
            if b not in seen:
                seen.add(b)
                order.append(b)
                todo.append(b.rsplit(".", 1)[-1].rsplit("::", 1)[-1])
    return order


def _simple_class(proc: Procedure) -> Optional[str]:
    return proc.class_name.rsplit(".", 1)[-1] if proc.class_name else None


def _simple_method(proc: Procedure) -> str:
    return proc.name.split("#", 1)[0].rsplit(".", 1)[-1]


def _path_glob(patterns: Sequence[str], path: str) -> bool:
    """A file path matches a glob over its trailing path segments (`**` any number of them):
    `**/pages/api/**` holds for `/srv/app/pages/api/users/[id].js`."""
    parts = PurePath(path).as_posix().split("/")
    for pattern in patterns:
        pat = pattern.split("/")

        def match(i: int, j: int) -> bool:
            if j == len(pat):
                return i == len(parts)
            if pat[j] == "**":
                return any(match(k, j + 1) for k in range(i, len(parts) + 1))
            return i < len(parts) and fnmatchcase(parts[i], pat[j]) and match(i + 1, j + 1)
        if any(match(start, 0) for start in range(len(parts))):
            return True
    return False


def _entry_matches(e: Entrypoint, proc: Procedure, program: Program) -> bool:
    cls = _simple_class(proc)
    if e.decorator and not any(_glob(e.decorator, a.name, a.canonical) for a in proc.annotations):
        return False
    if e.class_decorator:
        info = program.class_info.get(cls or "")
        if info is None or not any(_glob(e.class_decorator, a.name, a.canonical) for a in info.annotations):
            return False
    if e.extends:
        if not cls or not _glob(e.extends, *_bases_closure(program, cls)):
            return False
    if e.method and not _glob(e.method, _simple_method(proc)):
        return False
    if e.exclude_method and _glob(e.exclude_method, _simple_method(proc)):
        return False
    if e.registered_via and not any(_glob(e.registered_via, v) for v in proc.registered_via):
        return False
    if e.class_name and not (cls and _glob(e.class_name, cls)):
        return False
    if e.modifiers and not all(m in proc.modifiers for m in e.modifiers):
        return False
    if e.exclude_modifiers and any(m in proc.modifiers for m in e.exclude_modifiers):
        return False
    if e.exclude_decorator and any(_glob(e.exclude_decorator, a.name, a.canonical) for a in proc.annotations):
        return False
    if e.exports and not any(_glob(e.exports, x) for x in proc.exported_as):
        return False
    if e.directives and not set(e.directives) & set(getattr(program, "directives", ())):
        return False
    if e.body_directives and not set(e.body_directives) & set(getattr(proc, "directives", ())):
        return False
    if e.module_path and not any(_path_glob(e.module_path, f) for f in getattr(program, "source_files", ())):
        return False
    if e.arity and len(proc.params) not in e.arity:
        return False
    if e.exclude_arity and len(proc.params) in e.exclude_arity:
        return False
    if e.first_param:
        names = [p.name for p, _ in proc.params]
        if names[:1] in (["self"], ["cls"]):
            names = names[1:]
        if not names or not _glob(e.first_param, names[0]):
            return False
    return True


def _param_type_matches(program: Program, table: ImportTable, proc: Procedure, name: str,
                        patterns: Sequence[str]) -> bool:
    written = proc.param_types.get(name)
    if not written or not patterns:
        return False
    resolved = qualify_type(program.language, written, table)
    return _glob(patterns, written, written.split("<")[0], resolved)


def _split_top(text: str) -> List[str]:
    parts, depth, cur = [], 0, ""
    for ch in text:
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    return parts + [cur]


def bound_names(param: str) -> List[str]:
    """The names a parameter binds: itself, or for a destructuring pattern (`{ path }`,
    `{ opts: { depth } }`, `[a, b = 1]`, `{ ...rest }`) each name it binds, not the keys."""
    p = param.strip()
    if not p or p[0] not in "{[":
        return [p.split(":", 1)[0].split("=", 1)[0].strip()] if p else []
    inner = p[1:p.rfind("}" if p[0] == "{" else "]")] if p.rfind("}" if p[0] == "{" else "]") > 0 else p[1:]
    out: List[str] = []
    for part in _split_top(inner):
        part = part.strip()
        if not part:
            continue
        if part.startswith("..."):
            part = part[3:]
        if p[0] == "{" and ":" in part.split("=", 1)[0] and part.index(":") < (part.find("{") if "{" in part else len(part)):
            part = part.split(":", 1)[1]                      # `key: target` binds the target
        target = part.strip()
        if target[:1] in "{[":
            out.extend(bound_names(target.split("=", 1)[0] if not target.endswith(("}", "]")) else target))
        else:
            name = target.split("=", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                out.append(name)
    return out


def bound_keys(param: str, path: Tuple[str, ...] = ()) -> List[Tuple[Optional[Tuple[str, ...]], str]]:
    """(property path, name) for each name an object destructuring pattern binds (`{ body,
    query: q, headers: { host } }` -> (body) body, (query) q, (headers.host) host); the path is
    None for a `...rest` element or an array pattern's elements (not read by property)."""
    p = param.strip()
    if not p or p[0] != "{":
        return [(None, n) for n in bound_names(p)] if p and p[0] == "[" else []
    close = p.rfind("}")
    inner = p[1:close] if close > 0 else p[1:]
    out: List[Tuple[Optional[Tuple[str, ...]], str]] = []
    for part in _split_top(inner):
        part = part.strip()
        if not part:
            continue
        if part.startswith("..."):
            name = part[3:].split("=", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                out.append((None, name))
            continue
        head = part.split("=", 1)[0]
        if ":" in head and head.index(":") < (part.find("{") if "{" in part else len(part)):
            key, target = part.split(":", 1)
            key, target = key.strip().strip("'\""), target.strip()
        else:
            key = target = head.strip()
        if not re.fullmatch(r"[A-Za-z_$][\w$]*", key):
            continue
        if target[:1] == "{":
            out.extend(bound_keys(target if target.endswith("}") else target.split("=", 1)[0], path + (key,)))
        elif target[:1] == "[":
            out.extend((None, n) for n in bound_names(target))
        else:
            name = target.split("=", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                out.append((path + (key,), name))
    return out


def _request_sources(names: List[str], request, label: str, loc) -> List[TaintSource]:
    """The request-object entry for the selected parameters (`$argN` for a destructuring one:
    its bindings then read the request type's fields)."""
    return [TaintSource(loc=loc, var=PVar(n), kind=TaintKind.REQUEST, request=request,
                        description=f"{label} entry point (request object)") for n in names if "." not in n]


def _entry_params(e: Entrypoint, proc: Procedure, program: Program, table: ImportTable) -> List[str]:
    """What an entry point taints of a procedure: parameter names, and for a destructuring
    parameter (`$argN`, `Procedure.param_patterns`) either the whole parameter or, when names
    select, the property path each selected name is bound from (`$arg0.body`), so the binding
    at entry reads the taint."""
    out: List[str] = []
    for i, (p, _) in enumerate(proc.params):
        if (e.param_positions and i not in e.param_positions) or i < e.params_from:
            continue
        pattern = proc.param_patterns.get(p.name)
        if pattern is not None and isinstance(e.params, list):
            for path, name in bound_keys(pattern):
                if _glob(e.params, name) and not _glob(e.exclude_param, name):
                    out.append(f"{p.name}.{'.'.join(path)}" if path else p.name)
            continue
        n = p.name
        if n in _IMPLICIT_RECEIVERS or (pattern is None and _glob(e.exclude_param, n)):
            continue
        if _param_type_matches(program, table, proc, n, e.exclude_param_type):
            continue
        take = False
        if _param_type_matches(program, table, proc, n, e.tainted_param_type):
            take = True
        elif e.params == "all":
            take = True
        elif e.params == "annotated":
            take = any(_glob(e.param_annotation, a.name, a.canonical) for a in proc.param_annotations.get(n, ()))
        elif e.params == "typed":
            take = _param_type_matches(program, table, proc, n, e.param_type)
        elif isinstance(e.params, list):
            take = _glob(e.params, n)
        if take:
            out.append(n)
    return out


def entry_annotation_patterns(packs: Optional[PackSet], language: str) -> Tuple[str, ...]:
    """Every decorator/annotation pattern an entry point of a `language` pack names, whether or
    not the pack is detected in a file: what marks a framework's handler methods."""
    packs = packs if packs is not None else default_packs()
    return tuple(d for p in packs.for_language(language) for e in p.entrypoints for d in e.decorator)


def annotation_marks_entry(patterns: Sequence[str], name: str, canonical: Optional[str] = None) -> bool:
    return _glob(patterns, name, canonical)


def _entry_fields(e: Entrypoint, cls: ClassInfo) -> List[str]:
    if e.fields == "settable":
        return list(cls.settable_fields)
    if e.fields == "annotated":
        return [f for f in cls.fields
                if any(_glob(e.field_annotation, a.name, a.canonical) for a in cls.field_annotations.get(f, ()))]
    return list(cls.fields)


def _apply_entrypoints(program: Program, packs: Sequence[Pack], only: Optional[Sequence[str]] = None) -> None:
    entries = [(p, e) for p in packs for e in p.entrypoints]
    if not entries:
        return
    table = _import_table(program)
    procs = [program.procedures[n] for n in only if n in program.procedures] if only is not None \
        else list(program.procedures.values())
    for proc in procs:
        if proc.name.startswith("<") or "<clinit>" in proc.name or "<init>" in proc.name:
            continue
        entry = proc.nodes.get(proc.entry_node)
        if entry is None:
            continue
        cls = program.class_info.get(_simple_class(proc) or "")
        tainted: Dict[str, Tuple[Pack, Entrypoint]] = {}
        requests: List[TaintSource] = []
        for pack, e in entries:
            if not _entry_matches(e, proc, program):
                continue
            if f"{pack.name}:{e.id}" not in proc.entry_kinds:
                proc.entry_kinds.append(f"{pack.name}:{e.id}")
            if e.request_type:
                have = {str(r.var) for r in requests} | set(tainted)
                requests += [r for r in _request_sources(_entry_params(e, proc, program, table),
                                                         pack.request_types[e.request_type],
                                                         f"{pack.name}: {e.id}", proc.loc)
                             if str(r.var) not in have]
                continue
            for n in _entry_params(e, proc, program, table):
                tainted.setdefault(n, (pack, e))
            if e.fields and cls is not None:
                for f in _entry_fields(e, cls):
                    tainted.setdefault(f, (pack, e))
        present = {str(i.var) for i in entry.instrs if isinstance(i, TaintSource)}
        tainted = {n: v for n, v in tainted.items() if n not in present}
        requests = [r for r in requests if str(r.var) not in present]
        for n, (pack, e) in reversed(list(tainted.items())):
            kind = TaintKind(_SOURCE_KIND_VALUES.get(e.kind, e.kind))
            entry.instrs.insert(0, TaintSource(
                loc=proc.loc, var=PVar(n), kind=kind,
                description=f"{pack.name}: {e.id} entry point (attacker-controlled)"))
        for src in reversed([r for r in requests if str(r.var) not in tainted]):
            entry.instrs.insert(0, src)


def apply_entrypoints_to(program: Program, names: Sequence[str], packs: Optional[PackSet] = None) -> None:
    """Apply the entry points of the packs that hold for `program` now to the procedures `names`
    (a handler whose registration the project step found: frame/sil/registrations.py). A pack
    that holds only now (the file uses a framework's values it was handed) also gets its rules."""
    packs = packs if packs is not None else default_packs()
    active = [p for p in packs.for_language(program.language) if _detected(p, program)]
    known = {f"{p.language}/{p.name}" for p in getattr(program, "active_packs", ())}
    new = [p for p in active if f"{p.language}/{p.name}" not in known]
    if new:
        _apply_rules(program, new)
        program.active_packs = list(getattr(program, "active_packs", [])) + new
        program.packs_applied = list(program.packs_applied) + [f"{p.language}/{p.name}" for p in new]
    _apply_entrypoints(program, active, only=names)


def finish_program(program: Program, packs: Optional[PackSet] = None,
                   source: Optional[str] = None) -> Program:
    """Record source-level facts, then apply the packs for `program.language`.
    Idempotent per call instruction."""
    if source is not None:
        from ..source_facts import constant_regexes, constant_tables
        program.constant_regexes = constant_regexes(source, program.language)
        program.constant_tables = constant_tables(source, program.language)
    from ..value_origins import annotate as _value_origins
    _value_origins(program)             # callee ids for calls on values from library calls
    packs = packs if packs is not None else default_packs()
    active = [p for p in packs.for_language(program.language) if _detected(p, program)]
    if not active:
        return program
    _apply_rules(program, active)
    _apply_entrypoints(program, active)
    program.packs_applied = [f"{p.language}/{p.name}" for p in active]
    program.library_facts = {f.name: f for p in active for f in p.functions}   # a later pack wins
    program.active_packs = list(active)
    return program
