"""Invariants as data: a rule of the application, checked by the engine on every scan with no model.

A business-logic hunt learns what the application means to hold ("an order's quantity is at least
1", "an order is shipped only once it is paid") and proves it broken with an engine check. Saved
as a pack entry, the rule is checked again on every later scan, so what an agent learned once is
enforced in CI:

    [[invariant]]
    id = "order-quantity-positive"
    kind = "bound"              # a bound on a stored field
    field = "quantity"
    model = "Order"             # optional: only writes of this class's field
    min = 1                     # and/or max
    function = ["place"]        # optional: only in these functions

    [[invariant]]
    id = "ship-after-payment"
    kind = "guarded"            # a state a write requires
    field = "status"
    value = "shipped"           # optional: only writes of this literal
    guarded_by = "paid"         # a condition every path to the write passes (as `check guarded_by`)

A `guarded` entry may name `call` globs (call ids or names, `*.refund`) instead of a field.

Where a field is written (`sites`): an assignment to a path ending in the field (`order.quantity =
q`), a keyword / named argument of that name (`Order.objects.create(quantity=q)`), a setter
(`order.setQuantity(q)`, `set_quantity`), and a JS object literal holding only that key
(`Order.create({quantity: q})`; with several keys the lowering keeps no value per key). `model`
holds when the written object is of that class by evidence: a declared type, the class of
`self` / `this`, the call that produced it (`Order.objects.get(...)`), a call's own name or id.

The verdicts are the hunt's own checks (`logic_facts.check_bound`, `authz_guards.check_claim`):
refuted is a finding (a client-chosen value outside the bound, with the value that gets through;
a feasible path that reaches the write without the guard), unknown is a warning (the engine
cannot decide, so CI says so), proved is silent. Nothing here changes another finding."""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple

KINDS = ("bound", "guarded")
DEFAULT_CWE = {"bound": "CWE-1284", "guarded": "CWE-841"}
# Languages whose translator records the value facts the checks read (not C / C++).
LANGUAGES = ("python", "javascript", "typescript", "java", "csharp")


class Site(NamedTuple):
    line: int
    var: str            # the stored value as the engine names it ("" for a guarded call)
    what: str           # the write, for messages


class Result(NamedTuple):
    entry: Dict[str, Any]
    procedure: str
    line: int
    verdict: str        # refuted / unknown
    reason: str
    witness: List[Any]


def entries(program) -> List[Dict[str, Any]]:
    """The `[[invariant]]` entries of the packs applied to this program (a project's own)."""
    out: List[Dict[str, Any]] = []
    for pack in getattr(program, "active_packs", None) or []:
        out += list(getattr(pack, "invariants", None) or [])
    return out


def has_entries(packs: Iterable[Any], language: str) -> bool:
    def fam(x: str) -> str:
        return "javascript" if x in ("javascript", "typescript") else x
    return any(getattr(p, "invariants", None) and fam(getattr(p, "language", "") or "") == fam(language)
               for p in packs or [])


def _simple_type(text: str) -> str:
    t = str(text or "").split("<", 1)[0].strip().rstrip("?[]")
    return t.rsplit(".", 1)[-1]


def _segments(name: str) -> List[str]:
    return [s for s in re.split(r"[.:\s]+", str(name or "").replace("new ", "")) if s]


def _call_names(ins) -> List[str]:
    out = []
    func = str(getattr(ins, "func", "") or "").strip('"')
    if func:
        out.append(func)
    for attr in ("canonical",):
        v = getattr(ins, attr, None)
        if v:
            out.append(str(v))
    rt = getattr(ins, "receiver_type", None)
    if rt and str(rt) != "Unknown" and func:
        out.append(_simple_type(str(rt)) + "." + func.rsplit(".", 1)[-1])
    return out


def _receiver_head(ins) -> str:
    func = str(getattr(ins, "func", "") or "").strip('"')
    return func.rsplit(".", 1)[0] if "." in func else ""


def _head_types(program, proc, head: str, defs: Dict[str, list], calls: List[Any]) -> set:
    """What the object `head` is, by evidence: its declared type, the class of `self` / `this`,
    the type the frontend gave it as a call receiver, and the calls it was produced by."""
    out: set = set()
    for table in ("param_types", "var_types", "local_types"):
        t = (getattr(proc, table, None) or {}).get(head)
        if t:
            out.add(_simple_type(str(t)))
    if head in ("self", "this", "cls") and getattr(proc, "class_name", None):
        out.add(_simple_type(str(proc.class_name)))
    for c in calls:
        rt = getattr(c, "receiver_type", None)
        if rt and str(rt) != "Unknown" and _receiver_head(c) == head:
            out.add(_simple_type(str(rt)))
    name, hops = head, 0
    while name and hops < 4:
        hops += 1
        nxt = ""
        for d in defs.get(name) or []:
            if d[0] == "copy":
                nxt = str(d[1])
            elif d[0] == "call":
                out.update(_segments(d[1]))
        name = nxt
    return out


def _in_scope(proc, entry: Dict[str, Any]) -> bool:
    funcs = entry.get("function") or []
    if not funcs:
        return True
    name = str(getattr(proc, "name", "") or "")
    base = name.split("#")[0]
    simple = base.split("::")[-1].rsplit(".", 1)[-1]
    return any(f in (base, simple) or base.endswith("." + f) or base.endswith("::" + f) for f in funcs)


def _literal(exp) -> Optional[str]:
    from frame.sil.types import ExpConst
    if isinstance(exp, ExpConst):
        return str(getattr(exp, "value", "")).strip("'\"")
    return None


def _var_name(exp) -> str:
    from frame.sil.types import ExpFieldAccess, ExpVar
    if isinstance(exp, ExpVar):
        return str(exp.var)
    if isinstance(exp, ExpFieldAccess):
        return str(exp)
    return ""


def _setter_field(method: str) -> str:
    if method.startswith("set_") and len(method) > 4:
        return method[4:]
    if method.startswith("set") and len(method) > 3 and method[3].isupper():
        return method[3].lower() + method[4:]
    return ""


def sites(program, proc, entry: Dict[str, Any], defs: Optional[Dict[str, list]] = None) -> List[Site]:
    """The writes of `proc` the entry is about (see the module docstring)."""
    from frame.sil.instructions import Assign, Call
    defs = defs or {}
    field = entry.get("field") or ""
    model = entry.get("model") or ""
    want_value = entry.get("value")
    globs = entry.get("call") or []
    instrs = [ins for node in proc.nodes.values() for ins in node.instrs]
    calls = [ins for ins in instrs if isinstance(ins, Call)]
    out: List[Site] = []

    def model_ok(head: str = "", names: Iterable[str] = ()) -> bool:
        if not model:
            return True
        if any(model in _segments(n) for n in names):
            return True
        return bool(head) and model in _head_types(program, proc, head, defs, calls)

    def value_ok(exp) -> bool:
        return want_value is None or _literal(exp) == str(want_value)

    for ins in instrs:
        line = getattr(getattr(ins, "loc", None), "line", 0) or 0
        if not line:
            continue
        if field and isinstance(ins, Assign):
            target = str(ins.id)
            if "." in target and target.rsplit(".", 1)[1] == field:
                head = target.rsplit(".", 1)[0]
                if model_ok(head) and value_ok(ins.exp):
                    out.append(Site(line, target, f"{target} = {ins.exp}"))
            continue
        if not isinstance(ins, Call):
            continue
        names = _call_names(ins)
        args = [a for a, _ in (ins.args or [])]
        if globs:
            if any(fnmatchcase(n, g) for n in names for g in globs):
                out.append(Site(line, "", f"{names[0]}(...)"))
            continue
        if not field:
            continue
        kw = list(getattr(ins, "kwarg_names", None) or [])
        hit: Optional[Any] = None
        for i, k in enumerate(kw):
            if k == field and i < len(args):
                hit = args[i]
        method = names[0].rsplit(".", 1)[-1] if names else ""
        head = _receiver_head(ins)
        if hit is None and len(args) == 1 and _setter_field(method) == field:
            hit = args[0]
        if hit is None and len(args) == 1 and list(getattr(ins, "literal_keys", None) or []) == [f"0.{field}"]:
            hit = args[0]
            head = ""
        if hit is None:
            continue
        if not model_ok(head, names if not _setter_field(method) else ()) or not value_ok(hit):
            continue
        var = _var_name(hit)
        if var or want_value is not None:
            out.append(Site(line, var, f"{names[0]}({field}={hit})"))
    seen, uniq = set(), []
    for s in out:
        if (s.line, s.var) not in seen:
            seen.add((s.line, s.var))
            uniq.append(s)
    return uniq


def _decide(program, proc_name: str, entry: Dict[str, Any], site: Site) -> Optional[Result]:
    if entry["kind"] == "bound":
        from frame.sil.logic_facts import check_bound
        for op, key in (("lower_bound", "min"), ("upper_bound", "max")):
            if entry.get(key) is None:
                continue
            r = check_bound(program, proc_name, site.line, site.var, op, entry[key])
            if r.get("verdict") in ("refuted", "unknown"):
                return Result(entry, proc_name, site.line, r["verdict"], str(r.get("reason") or ""),
                              list(r.get("witness") or []))
        return None
    from frame.sil.authz_guards import check_claim
    r = check_claim(program, proc_name, site.line, {"kind": "guarded_by", "pattern": entry["guarded_by"]})
    if r.get("verdict") in ("refuted", "unknown"):
        return Result(entry, proc_name, site.line, r["verdict"], str(r.get("reason") or ""),
                      list(r.get("witness") or []))
    return None


def check_program(program, table: Optional[List[Dict[str, Any]]] = None
                  ) -> Tuple[List[Result], set]:
    """Every invariant against every write it is about in `program`: the refuted and undecided
    results, and the ids of the entries that met a write (an entry that meets none is stale)."""
    table = entries(program) if table is None else table
    if not table:
        return [], set()
    vf = getattr(program, "value_facts", None) or {}
    out: List[Result] = []
    met: set = set()
    for proc in list((getattr(program, "procedures", None) or {}).values()):
        rec = vf.get(proc.name) or {}
        for entry in table:
            if not _in_scope(proc, entry):
                continue
            try:
                found = sites(program, proc, entry, rec.get("defs") or {})
            except Exception:
                continue
            for site in found:
                met.add(entry["id"])
                if entry["kind"] == "bound" and not site.var:
                    continue
                try:
                    r = _decide(program, proc.name, entry, site)
                except Exception as exc:
                    r = Result(entry, proc.name, site.line, "unknown",
                               f"engine could not decide: {type(exc).__name__}", [])
                if r is not None:
                    out.append(r._replace(reason=f"{site.what}: {r.reason}"))
    return out, met


def describe(r: Result) -> str:
    e = r.entry
    if e["kind"] == "bound":
        rule = " and ".join(x for x in (
            f"{e.get('model') + '.' if e.get('model') else ''}{e['field']} >= {e['min']}" if e.get("min") is not None else "",
            f"{e.get('model') + '.' if e.get('model') else ''}{e['field']} <= {e['max']}" if e.get("max") is not None else "") if x)
    else:
        what = e.get("field") or ", ".join(e.get("call") or [])
        rule = f"{what} is written only past a check matching {e['guarded_by']!r}"
    lead = f"invariant {e['id']} ({rule})"
    if e.get("description"):
        lead += f": {e['description']}"
    return f"{lead}. {'Broken' if r.verdict == 'refuted' else 'Undecided'} in {r.procedure}: {r.reason}"


# ---- learning from a hunt ----------------------------------------------------------------

def learn(program, proc_name: str, check: Dict[str, Any], finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The invariant a hunt finding's refuted engine check states, as an entry, when the check
    names a write the entry can find again: a bound on the field the checked value is stored in,
    or a guard on that write. Scoped to the function the agent checked (a rule it established
    there; drop `function` to hold it everywhere). None when the checked line is not such a write."""
    from frame.sil.hunt_units import simple_name
    kind = str(check.get("kind") or "")
    try:
        line = int(check.get("line") or 0)
    except (TypeError, ValueError):
        return None
    proc = (getattr(program, "procedures", None) or {}).get(proc_name)
    if proc is None or not line:
        return None
    defs = ((getattr(program, "value_facts", None) or {}).get(proc_name) or {}).get("defs") or {}
    probe = {"id": "", "kind": "bound", "field": "", "function": []}
    candidates: List[Tuple[str, Site]] = []
    from frame.sil.instructions import Assign, Call
    for node in proc.nodes.values():
        for ins in node.instrs:
            ln = getattr(getattr(ins, "loc", None), "line", 0) or 0
            if ln not in (line, line + 1, line - 1):
                continue
            fields: List[str] = []
            if isinstance(ins, Assign) and "." in str(ins.id):
                fields.append(str(ins.id).rsplit(".", 1)[1])
            elif isinstance(ins, Call):
                fields += [k for k in (getattr(ins, "kwarg_names", None) or []) if k]
                names = _call_names(ins)
                sf = _setter_field(names[0].rsplit(".", 1)[-1]) if names else ""
                if sf:
                    fields.append(sf)
                keys = list(getattr(ins, "literal_keys", None) or [])
                if len(keys) == 1 and keys[0].startswith("0.") and keys[0].count(".") == 1:
                    fields.append(keys[0][2:])
            for f in fields:
                for s in sites(program, proc, {**probe, "field": f}, defs):
                    if s.line == ln:
                        candidates.append((f, s))
    if kind in ("lower_bound", "upper_bound"):
        var = str(check.get("var") or "")
        chosen = None
        for f, s in candidates:
            if s.line == line and (not var or s.var == var or s.var.endswith("." + var)
                                   or _stores(defs, s.var, var)):
                chosen = (f, s)
                break
        if chosen is None:
            return None
        try:
            bound = float(check.get("bound"))
            bound = int(bound) if bound == int(bound) else bound
        except (TypeError, ValueError):
            return None
        entry = {"id": "", "kind": "bound", "field": chosen[0],
                 ("min" if kind == "lower_bound" else "max"): bound}
    elif kind == "guarded_by" and check.get("pattern"):
        chosen = next(((f, s) for f, s in candidates if s.line == line), None)
        if chosen is None:
            return None
        entry = {"id": "", "kind": "guarded", "field": chosen[0], "guarded_by": str(check["pattern"])}
    else:
        return None
    entry["function"] = [simple_name(proc_name)]
    mech = str(finding.get("mechanism") or "")
    entry["cwe"] = str(finding.get("cwe") or "") or DEFAULT_CWE[entry["kind"]]
    entry["description"] = str(finding.get("invariant") or "")[:300]
    base = re.sub(r"[^a-z0-9]+", "-", f"{simple_name(proc_name)}-{entry['field']}-{mech or entry['kind']}".lower()).strip("-")
    entry["id"] = base or "invariant"
    return entry


def _stores(defs: Dict[str, list], target: str, var: str) -> bool:
    """`target` holds `var` through copies (`order.quantity = qty`)."""
    name, hops = target, 0
    while name and hops < 6:
        hops += 1
        nxt = ""
        for d in defs.get(name) or []:
            if d[0] == "copy":
                nxt = str(d[1])
        if nxt == var:
            return True
        name = nxt
    return False


def to_toml(rows: List[Dict[str, Any]], language: str) -> str:
    """A pack holding the entries, for `.frame/packs/` (`--save-invariants`)."""
    def val(v: Any) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return repr(v)
        if isinstance(v, list):
            return "[" + ", ".join(val(x) for x in v) + "]"
        s = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
        return f'"{s}"'
    fam = "javascript" if language in ("javascript", "typescript") else language
    lines = ["[pack]", 'name = "invariants"', f'language = "{fam}"',
             'description = "Invariants a hunt proved broken, checked by the engine on every scan"', ""]
    order = ("id", "kind", "model", "field", "value", "call", "min", "max", "guarded_by", "function",
             "cwe", "severity", "description", "references")
    for e in rows:
        lines.append("[[invariant]]")
        for k in order:
            if e.get(k) not in (None, "", []):
                lines.append(f"{k} = {val(e[k])}")
        lines.append("")
    return "\n".join(lines)


__all__ = ["DEFAULT_CWE", "KINDS", "LANGUAGES", "Result", "Site", "check_program", "describe", "entries",
           "has_entries", "learn", "sites", "to_toml"]
