"""Attempt limits as an engine check (the business-logic hunt's `bruteforce` class).

`check(name, line, kind="attempt_limit")` at a function that compares a guess with a stored
secret asks whether one caller can send as many guesses as it likes:

  proved   a limiter covers the function: a rate-limit decorator / annotation / attribute on it or
           its class (`@ratelimit`, `@limiter.limit`, `@UseGuards(ThrottlerGuard)`,
           `[EnableRateLimiting]`), limiter middleware in its own route registration
           (`app.post("/login", limiter, h)`, `.RequireRateLimiting(...)`), a call in it or a
           function it calls that spends an attempt (`limiter.consume(ip)`), or every caller is
           so covered;
  refuted  it compares a guess with a stored secret, and nothing in it, its class, its route, its
           callers or the application's configuration limits attempts, and it writes no stored
           data a lockout could count with;
  unknown  anything else: no credential check, a limiter installed for the whole application
           (`app.use(limiter)`, a global guard, Flask-Limiter defaults, django-axes), a class
           attribute whose value the engine does not read, some callers covered and others not,
           a write of stored data or of a cache / Redis (`state`) on the path (an attempt counter
           the application keeps itself), a check made inside a function handed to a project
           function (`throttle.verify(() => check(pw))`: that function decides when it runs), or
           a check known only from a library base class (the library calls back into project
           code the engine does not follow: a form, a hook).

What limits attempts is pack data (`[[rate_limit]]`: kinds decorator / middleware / call /
global / exempt / attribute / state), so the check knows nothing about any library. A counter
kept in the session is not a limit (the caller drops the cookie), so sessions are not `state`. A limiter outside
the code (a proxy, an API gateway) is invisible to it: `refuted` is a claim about the
application. Never changes a finding.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

KINDS = ("decorator", "middleware", "call", "global", "exempt", "attribute", "state")
PROTECTS = ("decorator", "middleware", "call")
CALLER_DEPTH = 2
CALLEE_DEPTH = 2
_BUILTIN: Dict[str, List[Dict[str, Any]]] = {}
_IDENT = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")


def entries(program) -> List[Dict[str, Any]]:
    """The `[[rate_limit]]` entries for this program: every built-in pack of its language (ids are
    library-qualified, and the file that configures a limiter need not import the framework a
    pack detects) plus the packs applied to it (a project's own)."""
    lang = getattr(program, "language", "") or ""
    family = "javascript" if lang in ("javascript", "typescript") else lang
    if family not in _BUILTIN:
        from frame.sil.packs.loader import builtin_packs
        try:
            packs = list(builtin_packs())
        except Exception:
            packs = []
        _BUILTIN[family] = [e for p in packs if getattr(p, "language", "") == family
                            for e in (getattr(p, "rate_limits", None) or [])]
    out = list(_BUILTIN[family])
    for pack in getattr(program, "active_packs", None) or []:
        out += list(getattr(pack, "rate_limits", None) or [])
    return out


# -- naming ---------------------------------------------------------------------------------

def _qualified(program, scope: str, names: Iterable[str]) -> List[str]:
    """The ids `names` answer to in `scope`: as written, with the head resolved through the
    file's imports or its value origin (`limiter.limit` with `limiter = Limiter(...)` is
    `flask_limiter.Limiter.limit`), and, for a bare name, under each on-demand import (`using
    Microsoft.AspNetCore.RateLimiting;` with `[EnableRateLimiting]`, `...Attribute` too)."""
    imports = {k: str(v) for k, v in (getattr(program, "imports", None) or {}).items()}
    wildcards = [str(w).rstrip(".*") for w in (getattr(program, "import_wildcards", None) or [])]
    out: List[str] = []
    for n in names:
        n = str(n or "").strip().strip('"').lstrip("@")
        if not n:
            continue
        out.append(n)
        head, _, rest = n.partition(".")
        tail = f".{rest}" if rest else ""
        if head in imports:
            out.append(imports[head] + tail)
        try:
            from frame.sil.value_origins import origin_in_scope
            origin = origin_in_scope(program, scope, head, imports=False)
        except Exception:
            origin = None
        if origin:
            out.append(str(origin) + tail)
        if not rest:
            for ns in wildcards:
                out += [f"{ns}.{n}", f"{ns}.{n}Attribute"]
    return out


def _match(program, scope: str, names: Iterable[str], table, kinds) -> Optional[Dict[str, Any]]:
    from frame.sil.packs.apply import _glob
    names = [str(n) for n in names if n]
    if not names:
        return None
    qualified = _qualified(program, scope, names)
    last = {n.rsplit(".", 1)[-1] for n in names}
    for e in table:
        if e["kind"] not in kinds:
            continue
        if e.get("call") and _glob(e["call"], *qualified):
            return e
        if e.get("name") and last & set(e["name"]):
            return e
    return None


def _exp_names(exp, depth: int = 0) -> Iterable[str]:
    """Names a value refers to: variables and called functions, nested anywhere in it."""
    if exp is None or depth > 12:
        return
    if isinstance(exp, (list, tuple)):
        for e in exp:
            yield from _exp_names(e, depth + 1)
        return
    kind = type(exp).__name__
    if kind == "ExpVar":
        v = getattr(exp, "var", None)
        yield str(getattr(v, "name", v) or "")
        return
    if kind == "ExpCall":
        func = getattr(exp, "func", None)
        name = str(getattr(func, "value", func) or "")
        if name and "(" not in name:
            yield name.strip('"')
        yield from _exp_names(func, depth + 1)
        for a in getattr(exp, "args", []) or []:
            yield from _exp_names(a, depth + 1)
        return
    for attr in ("left", "right", "exp", "operand", "value", "base", "index", "then_exp", "else_exp",
                 "cond", "parts", "elements", "args"):
        sub = getattr(exp, attr, None)
        if isinstance(sub, (list, tuple)):
            for s in sub:
                yield from _exp_names(s, depth + 1)
        elif sub is not None and type(sub).__name__.startswith("Exp"):
            yield from _exp_names(sub, depth + 1)


def _string_constants(exp, depth: int = 0) -> Iterable[str]:
    if exp is None or depth > 12:
        return
    if isinstance(exp, (list, tuple)):
        for e in exp:
            yield from _string_constants(e, depth + 1)
        return
    if type(exp).__name__ == "ExpConst":
        v = getattr(exp, "value", None)
        if isinstance(v, str):
            yield v
        return
    for attr in ("left", "right", "exp", "operand", "value", "args", "parts", "elements"):
        sub = getattr(exp, attr, None)
        if isinstance(sub, (list, tuple)) or (sub is not None and type(sub).__name__.startswith("Exp")):
            yield from _string_constants(sub, depth + 1)


def _calls(proc) -> Iterable[Any]:
    for ins in _instrs(proc):
        if type(ins).__name__ == "Call":
            yield ins


def _instrs(proc) -> Iterable[Any]:
    """Every instruction: calls, and those whose expressions hold calls (a branch condition,
    `if (bucket.tryConsume(1))`; an assigned value)."""
    for node in (getattr(proc, "nodes", {}) or {}).values():
        yield from getattr(node, "instrs", []) or []


def _line(ins) -> int:
    return int(getattr(getattr(ins, "loc", None), "line", 0) or 0)


def _call_names(program, ins) -> List[str]:
    out = []
    if getattr(ins, "canonical", None):
        out.append(str(ins.canonical))
    func = getattr(ins, "func", None)
    text = str(getattr(func, "value", func) or "").strip('"')
    if text:
        out.append(text)
        rtype = getattr(ins, "receiver_type", None)       # Java/C#: `bucket.tryConsume` on a Bucket
        if rtype and "." in text:
            out.append(f"{rtype}.{text.rsplit('.', 1)[-1]}")
    return out


def _typed_names(program, proc, names: Iterable[str]) -> List[str]:
    """`names` and, for a call on a name the function or its class declares with a library type
    (Java / C# `_users.CheckPasswordAsync` with `UserManager<AppUser> _users`), the type's id plus
    the method: calls written inside an expression carry no receiver type of their own."""
    from frame.sil.concurrency import _receiver_types, _type_ids, _type_name
    out = [n for n in names if n]
    for n in list(out):
        head, _, rest = n.removeprefix("this.").partition(".")
        if not rest or "(" in rest:
            continue
        typed = _receiver_types(program, proc, head)
        cls = _class_of(program, getattr(proc, "name", "") or "")
        written = (getattr(cls, "field_types", None) or {}).get(head) if cls is not None and not typed else None
        name = _type_name(written) if written else ""
        if name and name not in (getattr(program, "class_info", None) or {}):
            typed = _type_ids(program, name)          # a field of the class (Java `Bucket bucket`)
        out += [f"{t}.{rest}" for t in typed]
    return out


def _annotation_names(ann) -> List[str]:
    return [n for n in (getattr(ann, "canonical", None), getattr(ann, "name", None)) if n]


def _annotation_values(ann) -> List[str]:
    """Identifiers written in an annotation's arguments (`UseGuards(ThrottlerGuard)`,
    `method_decorator(ratelimit(key="ip"))`, `throttle_classes([AnonRateThrottle])`)."""
    out: List[str] = []
    for v in (getattr(ann, "args", None) or {}).values():
        text = re.sub(r"(['\"]).*?\1", " ", str(v or ""))     # quoted text is not a name
        out += _IDENT.findall(text)
    return out


# -- the facts about one function ------------------------------------------------------------

def _class_of(program, proc_name: str):
    if "." not in proc_name and "::" not in proc_name:
        return None
    cls = proc_name.split("#", 1)[0].replace("::", ".").rsplit(".", 1)[0].rsplit(".", 1)[-1]
    return (getattr(program, "class_info", None) or {}).get(cls)


def _lineage_names(ctx, program, name: str) -> List[str]:
    """`name` and, when it is a class of the project (`class LoginThrottle(AnonRateThrottle)`),
    what it is built on."""
    out = [name]
    simple = name.rsplit(".", 1)[-1]
    for prog in [program] + [p for p in getattr(ctx, "programs", []) or [] if p is not program]:
        info = (getattr(prog, "class_info", None) or {}).get(simple)
        if info is not None:
            out += [str(b) for b in (list(getattr(info, "canonical_bases", None) or [])
                                     + list(getattr(info, "project_bases", None) or []))]
            break
    return out


def _annotation_protection(ctx, program, scope: str, anns, table) -> Optional[Tuple[str, str]]:
    """(kind, what) for the first annotation that limits, exempts or leaves it to a class
    attribute."""
    for ann in anns:
        e = _match(program, scope, _annotation_names(ann), table, ("exempt",))
        if e is not None:
            return "exempt", getattr(ann, "name", "")
    for ann in anns:
        e = _match(program, scope, _annotation_names(ann), table, ("decorator",))
        if e is not None:
            return "decorator", getattr(ann, "name", "")
        values = [n for v in _annotation_values(ann) for n in _lineage_names(ctx, program, v)]
        e = _match(program, scope, values, table, ("decorator", "middleware"))
        if e is not None:
            return "decorator", f"{getattr(ann, 'name', '')}({', '.join(_annotation_values(ann))})"
    return None


def _own_protection(ctx, program, file: str, proc_name: str, table) -> Dict[str, Any]:
    """What covers the function itself: {"protected": what or None, "exempt": bool,
    "attribute": name or None}."""
    proc = (getattr(program, "procedures", {}) or {}).get(proc_name)
    out: Dict[str, Any] = {"protected": None, "exempt": False, "attribute": None, "undecided": []}
    if proc is None:
        return out
    here = _annotation_protection(ctx, program, proc_name, list(getattr(proc, "annotations", None) or []), table)
    if here and here[0] == "exempt":
        out["exempt"] = True
    elif here:
        out["protected"] = f"{here[1]} on {proc_name}"
        return out
    cls = _class_of(program, proc_name)
    if cls is not None:
        if not out["exempt"]:                         # a method's exemption beats its class's limiter
            there = _annotation_protection(ctx, program, proc_name, list(getattr(cls, "annotations", None) or []), table)
            if there and there[0] == "exempt":
                out["exempt"] = True
            elif there:
                out["protected"] = f"{there[1]} on class {cls.name}"
                return out
        for f in getattr(cls, "fields", None) or []:
            if _match(program, proc_name, [f], table, ("attribute",)):
                out["attribute"] = f
    route = _route_protection(ctx, program, file, proc_name, table)
    if route:
        out["protected"] = route
        return out
    undecided: List[str] = []
    spent = _spends_attempt(ctx, program, file, proc_name, table, undecided=undecided)
    if spent:
        out["protected"] = spent
    out["undecided"] = undecided
    return out


def _registrations_of(ctx, file: str, proc_name: str):
    """(program, registration) of every route registration that hands this function over: in
    its own file by name, elsewhere by the reference resolving to it."""
    from frame.sil.hunt_tools import _program_file
    root = getattr(ctx, "repo_root", "")
    for prog in getattr(ctx, "programs", []) or []:
        pf = _program_file(prog, root)
        for reg in getattr(prog, "registrations", None) or []:
            if pf == file and reg.target == proc_name:
                yield prog, reg
            elif reg.ref and hasattr(ctx, "resolve_call"):
                try:
                    d = ctx.resolve_call(pf, reg.scope, reg.ref)
                except Exception:
                    d = None
                if d is not None and d["file"] == file and d["name"] == proc_name:
                    yield prog, reg


def _registration_calls(program, reg) -> List[Any]:
    """The registering call and the calls chained on it (`MapPost(...).RequireRateLimiting(...)`)."""
    proc = (getattr(program, "procedures", {}) or {}).get(reg.scope)
    if proc is None or not getattr(reg, "line", 0):
        return []
    out = []
    for ins in _calls(proc):
        if _line(ins) != reg.line:
            continue
        func = getattr(ins, "func", None)
        text = str(getattr(func, "value", func) or "").strip('"')
        if text == reg.callee_text or text.startswith(reg.callee_text + "("):
            out.append(ins)
    return out


def _route_protection(ctx, program, file: str, proc_name: str, table) -> Optional[str]:
    for prog, reg in _registrations_of(ctx, file, proc_name):
        for ins in _registration_calls(prog, reg):
            func = getattr(ins, "func", None)
            text = str(getattr(func, "value", func) or "").strip('"')
            if text != reg.callee_text:               # a call chained on the registration
                if _match(prog, reg.scope, [text.rsplit(".", 1)[-1]] + _call_names(prog, ins), table,
                          ("middleware",)):
                    return f"{text.rsplit('.', 1)[-1]} on the route registered at line {reg.line}"
                continue
            for i, arg in enumerate(getattr(ins, "args", []) or []):
                if i == reg.arg_index:
                    continue
                names = list(_exp_names(arg))
                if _match(prog, reg.scope, names, table, ("middleware", "decorator")):
                    return f"{names[0] if names else 'a limiter'} in the route registered at line {reg.line}"
    return None


def _arg_value(ins, position: Optional[int], name: Optional[str]):
    """The argument of a call at a named / keyword `name`, else at positional `position` (C# lists a
    named argument's label before its value: the label is not an argument), or None."""
    args = [a[0] if isinstance(a, tuple) else a for a in getattr(ins, "args", None) or []]
    names = list(getattr(ins, "kwarg_names", None) or [])
    plain = []
    for i, a in enumerate(args):
        kw = names[i] if i < len(names) else None
        if kw:
            if name and kw == name:
                return a
            continue
        nxt = names[i + 1] if i + 1 < len(names) else None
        if nxt and type(a).__name__ == "ExpVar" and str(getattr(a.var, "name", a.var)) == nxt:
            continue                                   # `lockoutOnFailure:` itself
        plain.append(a)
    if position is not None and position < len(plain):
        return plain[position]
    return None


def _when_arg_holds(ins, cond: Dict[str, Any]) -> Optional[bool]:
    """Does the call pass `cond`'s literal value? None when the argument is not a literal (or the
    call is written inside an expression, whose arguments are not read here)."""
    if ins is None:
        return None
    a = _arg_value(ins, cond.get("position"), cond.get("name"))
    if a is None or type(a).__name__ != "ExpConst":
        return None
    v, want = getattr(a, "value", None), cond["value"]
    if isinstance(want, bool):
        if isinstance(v, bool):
            return v is want
        text = str(v).strip('"').lower()             # a frontend that keeps `true` as its text
        return text == str(want).lower() if text in ("true", "false") else None
    return str(v).strip('"') == str(want)


def _spends_attempt(ctx, program, file: str, proc_name: str, table, kinds=("call",),
                    undecided: Optional[List[str]] = None) -> Optional[str]:
    """A call of one of `kinds` (`call`: spends an attempt) in the function or a project function
    it calls (CALLEE_DEPTH deep). A call that spends one only for an argument's value
    (`when_arg`) counts when it passes that literal; one passing a value the engine does not know
    is added to `undecided`."""
    seen = {(file, proc_name)}
    frontier = [(program, file, proc_name)]
    for _ in range(CALLEE_DEPTH + 1):
        nxt = []
        for prog, f, name in frontier:
            proc = (getattr(prog, "procedures", {}) or {}).get(name)
            if proc is None:
                continue
            for ins in _instrs(proc):
                from frame.sil.hunt_tools import _nested_call_names
                nested = _typed_names(prog, proc, _nested_call_names(ins))
                is_call = type(ins).__name__ == "Call"
                for e, call, what in ((_match(prog, name, _call_names(prog, ins), table, kinds) if is_call else None,
                                       ins, (_call_names(prog, ins) or ["?"])[-1] if is_call else ""),
                                      (_match(prog, name, nested, table, kinds) if nested else None, None,
                                       nested[0] if nested else "")):
                    if e is None:
                        continue
                    cond = e.get("when_arg")
                    holds = True if not cond else _when_arg_holds(call, cond)
                    if holds and not cond:
                        return f"{what} at line {_line(ins)} of {name}"
                    arg = cond.get("name") or f"argument {cond['position']}"
                    if holds:
                        shown = str(cond["value"]).lower() if isinstance(cond["value"], bool) else cond["value"]
                        return f"{what} with {arg} = {shown} at line {_line(ins)} of {name}"
                    if holds is None and undecided is not None:
                        undecided.append(f"{what} at line {_line(ins)} of {name} passes {arg} "
                                         "as a value the engine does not know")
            if not hasattr(ctx, "graph"):
                continue
            try:
                _, calls = ctx.graph()
                for callee, _ln in (calls.get((f, name)) or [])[:40]:
                    d = ctx.resolve_call(f, name, callee)
                    if d is None or (d["file"], d["name"]) in seen:
                        continue
                    seen.add((d["file"], d["name"]))
                    loc = ctx.locate(d["name"], d["file"] or None)
                    if loc is not None and loc.get("program") is not None:
                        nxt.append((loc["program"], d["file"], loc["proc"]))
            except Exception:
                continue
        frontier = nxt
    return None


# -- the application ---------------------------------------------------------------------

def application_limiters(ctx) -> List[Dict[str, Any]]:
    """Limiters installed for more than one route: a `global` entry called or named in settings
    (`MIDDLEWARE`, `DEFAULT_THROTTLE_CLASSES`), and limiter middleware handed to a call that
    registers no project function (`app.use(limiter)`) or to an annotation on a class with no
    methods (a module's global guard). Memoised on the context."""
    progs = list(getattr(ctx, "programs", []) or [])
    key = tuple(id(p) for p in progs)
    memo = ctx.__dict__.get("_rate_limit_globals")
    if memo is not None and memo[0] == key:
        return memo[1]
    from frame.sil.hunt_tools import _program_file
    root = getattr(ctx, "repo_root", "")
    found: List[Dict[str, Any]] = []
    for prog in progs:
        table = entries(prog)
        if not table:
            continue
        pf = _program_file(prog, root)
        for values in (getattr(prog, "module_string_lists", None) or {}).values():
            for v in values:
                if _match(prog, "<module>", [v], table, ("global",)):
                    found.append({"file": pf, "line": 0, "what": v})
        route_lines: Set[Tuple[str, int]] = set()
        for reg in getattr(prog, "registrations", None) or []:
            handler = reg.target is not None
            if not handler and reg.ref and hasattr(ctx, "resolve_call"):
                try:
                    handler = ctx.resolve_call(pf, reg.scope, reg.ref) is not None
                except Exception:
                    handler = False
            if handler and getattr(reg, "line", 0):
                route_lines.add((reg.scope, reg.line))
        for pname, proc in (getattr(prog, "procedures", {}) or {}).items():
            for ins in _calls(proc):
                ln = _line(ins)
                if _match(prog, pname, _call_names(prog, ins), table, ("global",)):
                    found.append({"file": pf, "line": ln, "what": _call_names(prog, ins)[-1]})
                    continue
                consts = list(_string_constants(getattr(ins, "args", None)))
                hit = next((c for c in consts if _match(prog, pname, [c], table, ("global",))), None)
                if hit:
                    found.append({"file": pf, "line": ln, "what": hit})
                    continue
                if (pname, ln) in route_lines:
                    continue
                names = list(_exp_names(getattr(ins, "args", None)))
                if names and _match(prog, pname, names, table, ("middleware",)):
                    found.append({"file": pf, "line": ln,
                                  "what": f"{_call_names(prog, ins)[-1]}({names[0]})"})
        methods = {n.split("#", 1)[0].replace("::", ".").rsplit(".", 1)[0].rsplit(".", 1)[-1]
                   for n in (getattr(prog, "procedures", {}) or {}) if "." in n or "::" in n}
        for cname, info in (getattr(prog, "class_info", None) or {}).items():
            if cname in methods:
                continue
            for ann in getattr(info, "annotations", None) or []:
                values = [n for v in _annotation_values(ann) for n in _lineage_names(ctx, prog, v)]
                if _match(prog, "<module>", values, table, ("middleware",)):
                    found.append({"file": pf, "line": getattr(info, "line", 0) or 0,
                                  "what": f"{getattr(ann, 'name', '')} on class {cname}"})
    ctx.__dict__["_rate_limit_globals"] = (key, found)
    return found


def _credential_line(ctx, program, file: str, proc_name: str) -> Optional[Tuple[int, str]]:
    """(line, how) where the function compares a guess with a stored secret: `call` (itself or
    through a project call) or `inherited` (a method of a class built on a library class that
    checks one), or None when it does not."""
    from frame.sil.hunt_classes import (_callee_credential, _checks_credential_itself,
                                        _inherits_credential_check, credential_checks, _lang)
    proc = (getattr(program, "procedures", {}) or {}).get(proc_name)
    if proc is None:
        return None
    ids = credential_checks().get(_lang(program)) or ()
    from frame.sil.hunt_tools import _nested_call_names
    for ins in _instrs(proc):
        own = _call_names(program, ins) if type(ins).__name__ == "Call" else []
        for n in own + _typed_names(program, proc, _nested_call_names(ins)):
            if any(n == i or n.endswith("." + i) for i in ids):
                return _line(ins), "call"
    if hasattr(ctx, "graph"):
        try:
            _, calls = ctx.graph()
            for callee, ln in (calls.get((file, proc_name)) or [])[:40]:
                if any(q == i or q.endswith("." + i) for q in _qualified(program, proc_name, [callee])
                       for i in ids):
                    return ln, "call"
                d = ctx.resolve_call(file, proc_name, callee)
                if d is not None and (_checks_credential_itself(ctx, (d["file"], d["name"]))
                                      or _callee_credential(ctx, d["file"], d["name"])):
                    return ln, "call"
        except Exception:
            pass
    for name, other in (getattr(program, "procedures", {}) or {}).items():   # a closure it writes
        if name != proc_name and getattr(other, "parent", None) and _nested_in(program, name, proc_name):
            found = _credential_line(ctx, program, file, name)
            if found is not None and found[1] == "call":
                return found
    if _inherits_credential_check(program, proc_name):
        loc = getattr(proc, "loc", None)
        return (int(getattr(loc, "line", 0) or 0) or 1), "inherited"
    return None


def _nested_in(program, name: str, outer: str) -> bool:
    """Is procedure `name` `outer` or a closure written inside it (any depth)?"""
    seen: Set[str] = set()
    while name and name not in seen:
        if name == outer:
            return True
        seen.add(name)
        proc = (getattr(program, "procedures", {}) or {}).get(name)
        name = getattr(proc, "parent", None) if proc is not None else None
    return False


def _wrapped_check(ctx, program, file: str, proc_name: str) -> Optional[Tuple[str, int]]:
    """(callee, line) when a closure written in the function compares the guess and is handed to
    a project function (`loginThrottle.VerifyAsync(() => VerifyPassword(pw))`): that function
    decides whether and when the check runs, so it may limit attempts."""
    defs = ctx.graph()[0] if hasattr(ctx, "graph") else {}
    from frame.sil.hunt_units import simple_name
    for reg in getattr(program, "registrations", None) or []:
        target = getattr(reg, "target", None)
        if not target or target == proc_name or not _nested_in(program, target, proc_name):
            continue
        if not defs.get(simple_name(reg.callee_text)):
            continue                                  # a library call: it runs the closure as given
        if _credential_line(ctx, program, file, target) is not None:
            return reg.callee_text, getattr(reg, "line", 0) or 0
    return None


def _writes_stored_data(ctx, program, file: str, proc_name: str) -> bool:
    vf = (getattr(program, "value_facts", None) or {}).get(proc_name) or {}
    if vf.get("writes") or vf.get("may_write"):
        return True
    try:
        from frame.sil.hunt_classes import _callee_data
        return bool(_callee_data(ctx, file, proc_name)[2])
    except Exception:
        return False


def check_attempt_limit(ctx, program, proc_name: str, file: str) -> Dict[str, Any]:
    """The `attempt_limit` verdict for `proc_name` (see the module docstring)."""
    unknown = {"verdict": "unknown", "witness": []}
    proc = (getattr(program, "procedures", {}) or {}).get(proc_name)
    if proc is None:
        return {**unknown, "reason": f"no procedure {proc_name!r}"}
    table = entries(program)
    if not any(e["kind"] in PROTECTS for e in table):
        return {**unknown, "reason": "no [[rate_limit]] facts for this language, so the engine "
                "cannot tell a limiter from any other call"}
    own = _own_protection(ctx, program, file, proc_name, table)
    if own["protected"]:
        return {"verdict": "proved", "witness": [], "reason": f"attempts are limited: {own['protected']}"}
    covered, uncovered = [], []
    if hasattr(ctx, "callers_of"):
        frontier, seen = [(file, proc_name)], {(file, proc_name)}
        for _ in range(CALLER_DEPTH):
            nxt = []
            for key in frontier:
                for ckey in ctx.callers_of(*key)[:40]:
                    if ckey in seen:
                        continue
                    seen.add(ckey)
                    loc = ctx.locate(ckey[1], ckey[0] or None)
                    if loc is None or loc.get("program") is None:
                        continue
                    c = _own_protection(ctx, loc["program"], ckey[0], loc["proc"], entries(loc["program"]))
                    (covered if c["protected"] else uncovered).append(ckey[1])
                    if not c["protected"]:
                        nxt.append(ckey)
            frontier = nxt
    if covered and not uncovered:
        return {"verdict": "proved", "witness": [],
                "reason": f"every caller limits attempts ({', '.join(covered[:3])})"}
    seen_callers = [k for k in (seen if hasattr(ctx, "callers_of") else set()) if k != (file, proc_name)]
    cred = _credential_line(ctx, program, file, proc_name)
    if cred is None:
        return {**unknown, "reason": f"{proc_name} does not compare a guess with a stored secret the "
                "engine recognises: ask at the function that does"}
    if covered:
        return {**unknown, "reason": f"some callers limit attempts ({', '.join(covered[:3])}) and "
                f"others do not ({', '.join(uncovered[:3])}): check which routes reach it"}
    if cred[1] == "inherited":
        return {**unknown, "reason": f"{proc_name} checks the credential through the library class it "
                "is built on, which calls back into project code (a form, a hook) the engine does not "
                "follow: read what it calls"}
    wrapped = _wrapped_check(ctx, program, file, proc_name)
    if wrapped:
        return {**unknown, "reason": f"the guess is checked inside a function handed to {wrapped[0]} "
                f"(line {wrapped[1]}), which decides when it runs and may limit attempts: read it"}
    if own["attribute"]:
        return {**unknown, "reason": f"the class sets `{own['attribute']}`: read its value (an empty "
                "list turns throttling off)"}
    if not own["exempt"]:
        apps = application_limiters(ctx)
        if apps:
            a = apps[0]
            return {**unknown, "reason": f"a limiter is installed for the application ({a['what']} at "
                    f"{a['file']}:{a['line']}); the engine cannot tell whether it covers this route"}
    for f, name in [(file, proc_name)] + [(c[0], c[1]) for c in seen_callers]:
        loc = ctx.locate(name, f or None) if name != proc_name else {"program": program, "proc": proc_name}
        if loc is None or loc.get("program") is None:
            continue
        kept = _spends_attempt(ctx, loc["program"], f, loc["proc"], entries(loc["program"]), kinds=("state",))
        if kept:
            return {**unknown, "reason": f"{kept} keeps data across requests outside the database: it "
                    "may count failed attempts (a throttle the application keeps itself); read it"}
    if own.get("undecided"):
        return {**unknown, "reason": f"{own['undecided'][0]}: whether the call counts the failure "
                "depends on it; read where it comes from"}
    if _writes_stored_data(ctx, program, file, proc_name):
        return {**unknown, "reason": f"{proc_name} writes stored data: it may count failed attempts "
                "itself (a lockout); read it"}
    exempt = " (its limiter is switched off)" if own["exempt"] else ""
    return {"verdict": "refuted",
            "witness": [{"line": cred[0], "event": "compares a guess with a stored secret"},
                        {"line": int(getattr(getattr(proc, "loc", None), "line", 0) or 0),
                         "event": "no rate limit, lockout or limiter middleware covers it" + exempt}],
            "reason": f"{proc_name} compares a guess with a stored secret at line {cred[0]}, and nothing in "
                      "it, its class, its route, its callers or the application's configuration limits "
                      "attempts (a proxy in front of the application is not visible to the engine)"}
