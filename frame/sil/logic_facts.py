"""Value facts for the business-logic hunt: bounds on the numbers a caller chooses, decided by Z3.

A missing limit (a negative quantity, a refund above the price, a discount over 100%) is a flaw
of intent, but whether a bound HOLDS is not: on every feasible path to the line that stores a
value, either the path conditions entail `v >= lo` or a path lets a smaller value through. The
engine walks those paths already; this module keeps, on the reporting pass only, what each line
of a procedure knew, and answers a hunt agent's question about one value at one line:

  proved    every feasible path to the line entails the bound
  refuted   a feasible path reaches the line with the value outside the bound, the value is
            chosen by the caller (a request read, copied or converted to a number, nothing else),
            and a witness says which value gets through (`-1`, or `NaN` past a guard written as
            `if (v < 1) reject`, which NaN fails like every ordered comparison)
  unknown   the engine cannot tell (the value is computed, read from storage, assigned twice, or
            the line was never walked)

What the engine records per procedure (`note`, `finish`, called by the translator):
  - the path condition at each line on each visit (formulas over program variables; a guard is
    dropped once a variable it reads is written, so a stale check never bounds a new value),
  - which variables hold client data there (taint of kind user / network input),
  - every definition of every variable (`x = y`, `x = f(y)`, `x = <expr>`), to follow a value
    back to the request through copies and the conversions in `specs/data/numbers.toml`.

Pure bookkeeping: the analysis never reads it, so no finding depends on it, and every query
returns "unknown" instead of raising."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

NUMBERS_PATH = Path(__file__).parent / "specs" / "data" / "numbers.toml"
MAX_SNAPSHOTS = 24          # path conditions kept per line (more: a "proved" is not claimed)
MAX_CHAIN = 12              # definitions followed back from the asked value


class Conversion(NamedTuple):
    integer: bool
    nan: bool


class Numbers(NamedTuple):
    calls: Dict[str, Dict[str, Conversion]]      # language -> callee name -> what it returns
    raw: Dict[str, Conversion]                   # language -> a client value used as is
    types: Dict[str, Dict[str, Conversion]]      # language -> declared type -> what it holds


def _language(lang: str) -> str:
    lang = (lang or "").lower()
    return "javascript" if lang in ("typescript", "javascript", "js", "ts") else lang


@lru_cache(maxsize=None)
def numbers(path: Path = NUMBERS_PATH) -> Numbers:
    """The conversion table, validated strictly (an unknown key is an error naming the file)."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    if set(data) - {"conversion", "raw", "types"}:
        raise ValueError(f"{Path(path).name}: unknown table(s) {sorted(set(data) - {'conversion', 'raw', 'types'})}")
    calls: Dict[str, Dict[str, Conversion]] = {}
    for i, row in enumerate(data.get("conversion") or []):
        extra = set(row) - {"language", "calls", "integer", "nan"}
        if extra or not isinstance(row.get("language"), str) or not row.get("calls") \
                or not all(isinstance(c, str) and c for c in row["calls"]):
            raise ValueError(f"{Path(path).name}: conversion #{i + 1} needs language and calls"
                             + (f" (unknown {sorted(extra)})" if extra else ""))
        conv = Conversion(bool(row.get("integer", False)), bool(row.get("nan", False)))
        table = calls.setdefault(_language(row["language"]), {})
        for c in row["calls"]:
            if c in table:
                raise ValueError(f"{Path(path).name}: {c!r} listed twice for {row['language']}")
            table[c] = conv
    raw = {}
    for lang, row in (data.get("raw") or {}).items():
        if not isinstance(row, dict) or set(row) - {"integer", "nan"}:
            raise ValueError(f"{Path(path).name}: raw.{lang} takes only integer / nan")
        raw[_language(lang)] = Conversion(bool(row.get("integer", False)), bool(row.get("nan", False)))
    types: Dict[str, Dict[str, Conversion]] = {}
    for lang, row in (data.get("types") or {}).items():
        if not isinstance(row, dict) or set(row) - {"integer", "nan", "other"} or \
                not all(isinstance(v, list) and all(isinstance(t, str) and t for t in v) for v in row.values()):
            raise ValueError(f"{Path(path).name}: types.{lang} takes lists integer / nan / other")
        t = types.setdefault(_language(lang), {})
        for key, conv in (("integer", Conversion(True, False)), ("nan", Conversion(False, True)),
                          ("other", Conversion(False, False))):
            for name in row.get(key) or []:
                t[name] = conv
    return Numbers(calls, raw, types)


def declared(language: str, type_name: str) -> Optional[Conversion]:
    """What a value of declared type `type_name` holds, when it is a number."""
    t = (type_name or "").strip().rsplit(".", 1)[-1].rstrip("?")
    return (numbers().types.get(_language(language)) or {}).get(t)


def conversion(language: str, callee: str) -> Optional[Conversion]:
    """What `callee` returns when it turns text into a number in `language`, else None."""
    table = numbers().calls.get(_language(language)) or {}
    name = (callee or "").strip('"')
    if name in table:
        return table[name]
    # a qualified id of a qualified row (`java.lang.Integer.parseInt` is `Integer.parseInt`);
    # a plain row (`int`) never matches a member call (`self.int`)
    hits = [conv for key, conv in table.items() if "." in key and name.endswith("." + key)]
    return hits[0] if hits else None


# ---- recording (called by the translator on its reporting pass) ----------------------------

def new_record() -> Dict[str, Any]:
    return {"pc": {}, "seen": {}, "client": {}, "capped": set()}


def note(rec: Dict[str, Any], instr, state, client_kinds) -> None:
    """Before `instr` runs on `state`: the path condition at its line (once per distinct
    condition) and the client-data variables there. Never raises into the walk."""
    try:
        line = getattr(getattr(instr, "loc", None), "line", 0) or 0
        if not line:
            return
        pc = state.feasibility_constraints
        key = tuple(id(f) for f in pc)
        seen = rec["seen"].setdefault(line, set())
        if key not in seen:
            seen.add(key)
            snaps = rec["pc"].setdefault(line, [])
            if len(snaps) < MAX_SNAPSHOTS:
                snaps.append(list(pc))
            else:
                rec["capped"].add(line)
        client = rec["client"].setdefault(line, {})
        for name, info in state.tainted.items():
            if info.source_kind in client_kinds and name not in client:
                read = tuple(getattr(info, "read", ()) or ())
                src = str(info.source_var or "")
                client[name] = (src.split(".", 1)[0] + "." + ".".join(read)) if read and src else src
    except Exception:
        pass


def _callee(exp) -> str:
    return str(getattr(exp, "func", "") or "").strip('"')


def finish(proc, rec: Dict[str, Any]) -> Dict[str, Any]:
    """The procedure's value facts: the per-line record plus every definition of every name
    (`copy` of a name, `call` of a callee on its first argument, `other`)."""
    from frame.sil.instructions import Assign, Call
    from frame.sil.types import ExpCall, ExpFieldAccess, ExpVar
    try:
        from frame.sil.types import ExpIndex
    except ImportError:                     # pragma: no cover
        ExpIndex = ExpFieldAccess           # type: ignore[misc,assignment]
    defs: Dict[str, List[Tuple]] = {}
    arith: set = set()          # names used as operands of - * / % (computed with as numbers)
    try:
        from frame.sil.types import ExpBinOp

        def _arith(e, depth=0):
            if e is None or depth > 12:
                return
            if isinstance(e, ExpBinOp):
                if e.op in ("-", "*", "/", "%"):
                    for side in (e.left, e.right):
                        if isinstance(side, (ExpVar, ExpFieldAccess)):
                            arith.add(str(side.var) if isinstance(side, ExpVar) else str(side))
                _arith(e.left, depth + 1)
                _arith(e.right, depth + 1)
            elif isinstance(e, ExpCall):
                for a in getattr(e, "args", None) or []:
                    _arith(a, depth + 1)

        for node in proc.nodes.values():
            for ins in node.instrs:
                line = getattr(getattr(ins, "loc", None), "line", 0) or 0
                if isinstance(ins, Assign):
                    target, exp = str(ins.id), ins.exp
                    _arith(exp)
                    if isinstance(exp, ExpVar):
                        d = ("copy", str(exp.var), line)
                    elif isinstance(exp, (ExpFieldAccess, ExpIndex)):
                        d = ("read", str(exp), line)        # a path read: `req.body.amount`
                    elif isinstance(exp, ExpCall):
                        args = list(getattr(exp, "args", None) or [])
                        d = ("call", _callee(exp), args[0] if args else None, line)
                    else:
                        d = ("other", str(exp), line)
                    defs.setdefault(target, []).append(d)
                elif isinstance(ins, Call) and ins.ret is not None:
                    target = str(ins.ret[0])
                    name = ins.get_full_name().strip('"') if hasattr(ins, "get_full_name") else _callee(ins)
                    args = [a for a, _ in (ins.args or [])]
                    defs.setdefault(target, []).append(("call", name, args[0] if args else None, line))
    except Exception:
        pass
    # The parameters an entry point marks as client data (a TaintSource at the entry), even when
    # the taint analysis drops them (an int cannot carry an injection, a number can break a rule).
    entry_names: Dict[str, str] = {}
    types: Dict[str, str] = {}
    try:
        from frame.sil.instructions import TaintKind, TaintSource
        entry = proc.nodes.get(proc.entry_node)
        for ins in (entry.instrs if entry is not None else []):
            if isinstance(ins, TaintSource) and ins.kind in (TaintKind.USER_INPUT, TaintKind.NETWORK_INPUT):
                entry_names[str(ins.var)] = str(getattr(ins, "description", "") or "entry point").split(":")[0]
        types.update({str(k): str(v) for k, v in (getattr(proc, "var_types", None) or {}).items()})
        types.update({str(k): str(v) for k, v in (getattr(proc, "param_types", None) or {}).items()})
        # An entry point's parameter of a number type is bound from the request (a route or form
        # value): the framework injects services, never numbers. C# and Java drop such parameters
        # as taint sources (a number carries no injection), so they are named here.
        if getattr(proc, "entry_kinds", None):
            for pname, ptype in (getattr(proc, "param_types", None) or {}).items():
                if str(pname) not in entry_names and any(
                        declared(lg, str(ptype)) is not None for lg in ("java", "csharp", "javascript")):
                    entry_names[str(pname)] = "entry point"
    except Exception:
        pass
    return {"pc": rec["pc"], "client": rec["client"], "capped": set(rec["capped"]), "defs": defs,
            "entry": entry_names, "types": types, "arith": arith}


# ---- queries (called by the hunt) ---------------------------------------------------------

def _record(program, proc_name: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    vf = getattr(program, "value_facts", None) or {}
    if proc_name in vf:
        return proc_name, vf[proc_name]
    simple = (proc_name or "").rsplit("::", 1)[-1].rsplit(".", 1)[-1]
    hits = [n for n in vf if n.rsplit("::", 1)[-1].rsplit(".", 1)[-1] == simple
            or n.endswith("." + proc_name) or n.endswith("::" + proc_name)]
    return (hits[0], vf[hits[0]]) if len(hits) == 1 else (None, None)


def _resolve_line(rec, line: int) -> Optional[int]:
    for ln in (line, line - 1, line - 2):
        if ln in rec["pc"]:
            return ln
    return None


class Origin(NamedTuple):
    names: List[str]                 # the asked value and every copy it came from (all equal)
    number: Optional[Conversion]     # what kind of number it is, None when not known
    direct: bool                     # copies / one conversion of a client read, nothing else
    how: str                         # the chain, for the reason text


def _name_of(exp) -> str:
    from frame.sil.types import ExpVar
    if isinstance(exp, ExpVar):
        return str(exp.var)
    return str(exp) if exp is not None else ""


def _ordered_atoms(f):
    """The ordered comparisons (`<`, `<=`, `>`, `>=`) inside a path-condition formula."""
    from frame.core.ast import And, Ge, Gt, Le, Lt, Not, Or
    if isinstance(f, (And, Or)):
        yield from _ordered_atoms(f.left)
        yield from _ordered_atoms(f.right)
    elif isinstance(f, Not):
        yield from _ordered_atoms(f.formula)
    elif isinstance(f, (Lt, Le, Gt, Ge)):
        yield f


def used_as_number(rec: Dict[str, Any], names) -> bool:
    """Does the procedure compute with one of `names` (`-`, `*`, `/`, `%`) or compare it with `<`,
    `<=`, `>` or `>=` anywhere? A raw
    client value (no conversion, no declared type) is a number only when the code treats it as
    one: an id the code only tests for presence or equality is text, not a quantity."""
    want = set(names)
    if want & set(rec.get("arith") or ()):
        return True
    for snaps in (rec.get("pc") or {}).values():
        for pc in snaps:
            for f in pc:
                if any(a.free_vars() & want for a in _ordered_atoms(f)):
                    return True
    return False


def _raw_number(rec: Dict[str, Any], names, language: str) -> Optional[Conversion]:
    raw = numbers().raw.get(_language(language))
    return raw if raw is not None and used_as_number(rec, names) else None


def origin(rec: Dict[str, Any], var: str, language: str, client: Dict[str, str]) -> Origin:
    """Follow `var` back through single definitions: copies keep the value, a conversion from
    `numbers.toml` fixes its kind; anything else, or a name assigned twice, ends the chain as
    computed. A chain that ends at client data (tainted there, or a request read written inline)
    is direct."""
    defs = rec.get("defs") or {}
    names, how = [var], [var]
    number: Optional[Conversion] = None
    cur, converted = var, False
    for _ in range(MAX_CHAIN):
        ds = defs.get(cur) or []
        if len(ds) != 1:
            if cur in client:
                break                       # an entry parameter or field the framework fills
            return Origin(names, number, False,
                          " <- ".join(how) + (" (assigned more than once)" if ds else " (no definition)"))
        d = ds[0]
        if d[0] == "copy":
            if len(defs.get(d[1]) or []) > 1:
                # copied from a name assigned again elsewhere: the copy is not equal to whatever
                # that name holds at the asked line, so the chain stops before it
                return Origin(names, number, False,
                              " <- ".join(how + [d[1]]) + " (assigned more than once)")
            cur = d[1]
            names.append(cur)
            how.append(cur)
            continue
        if d[0] == "read":
            # a client read written as a path (`const tip = req.body.tip`): the value as sent
            how.append(d[1])
            if not any(n in client for n in names):
                return Origin(names, number, False, " <- ".join(how) + " (not client data here)")
            return Origin(names, number if converted else _raw_number(rec, names, language),
                          True, " <- ".join(how))
        if d[0] == "call":
            conv = conversion(language, d[1])
            if conv is None or converted:
                return Origin(names, number, False, " <- ".join(how) + f" <- {d[1]}(...) (computed)")
            converted, number = True, conv
            src = _name_of(d[2])
            how.append(f"{d[1]}({src})")
            if src in defs or src in client:
                cur = src
                continue
            # a request read written inline (`int(request.form["q"])`): the converted value is
            # client data when the call's result is
            if any(n in client for n in names):
                return Origin(names, number, True, " <- ".join(how))
            return Origin(names, number, False, " <- ".join(how) + " (the converted value is not client data)")
        return Origin(names, number, False, " <- ".join(how) + f" <- {d[1]} (computed)")
    is_client = any(n in client for n in names) or cur in client
    if number is None:
        types = rec.get("types") or {}
        number = next((declared(language, types[n]) for n in reversed(names) if n in types
                       and declared(language, types[n]) is not None), None)
        if number is not None:
            how.append(f"declared {types.get(cur) or next(types[n] for n in names if n in types)}")
    if number is None and is_client:
        number = _raw_number(rec, names, language)
    return Origin(names, number, is_client, " <- ".join(how))


def _nan_rewrite(f, names: set, flag: str):
    """IEEE comparison semantics for a value that may be NaN: an ordered comparison or `==`
    mentioning it is false when it is NaN, `!=` is true."""
    from frame.core.ast import And, Const, Eq, Ge, Gt, Le, Lt, Neq, Not, Or
    if isinstance(f, (And, Or)):
        return type(f)(_nan_rewrite(f.left, names, flag), _nan_rewrite(f.right, names, flag))
    if isinstance(f, Not):
        return Not(_nan_rewrite(f.formula, names, flag))
    if isinstance(f, (Lt, Le, Gt, Ge, Eq, Neq)) and (f.free_vars() & names):
        from frame.core.ast import Var
        is_nan = Eq(Var(flag), Const(1))
        if isinstance(f, Neq):
            return Or(is_nan, f)
        return And(Not(is_nan), f)
    return f


def _conj(parts):
    from frame.core.ast import And, True_
    out = None
    for p in parts:
        out = p if out is None else And(out, p)
    return out if out is not None else True_()


def _connected(names: set, pc: list) -> list:
    want, chosen, changed = set(names), set(), True
    while changed:
        changed = False
        for i, f in enumerate(pc):
            if i not in chosen and f.free_vars() & want:
                chosen.add(i)
                want |= f.free_vars()
                changed = True
    return [pc[i] for i in sorted(chosen)]


def check_bound(program, proc_name: str, line: int, var: str, op: str, bound: Any,
                checker=None) -> Dict[str, Any]:
    """Decide `var >= bound` (op "lower_bound") or `var <= bound` ("upper_bound") at `line` of
    `proc_name` over the engine's feasible paths. See the module docstring for the verdicts."""
    from frame.core.ast import Const, Eq, Ge, Le, Not, Or, Var
    unknown = {"verdict": "unknown", "witness": []}
    try:
        name, rec = _record(program, proc_name)
        if rec is None:
            return {**unknown, "reason": f"no value facts for procedure {proc_name!r}"}
        ln = _resolve_line(rec, int(line))
        if ln is None:
            return {**unknown, "reason": f"no instruction the engine walked at line {line}"}
        try:
            b = float(bound)
            b = int(b) if b == int(b) else b
        except (TypeError, ValueError):
            return {**unknown, "reason": f"bound {bound!r} is not a number"}
        var = str(var or "").strip()
        if not var:
            return {**unknown, "reason": "`var` is required (the value as the code names it, e.g. qty or order.quantity)"}
        client = dict(rec["client"].get(ln) or {})
        for n, how in (rec.get("entry") or {}).items():
            if n not in (rec.get("defs") or {}):          # still the value the request carried
                client.setdefault(n, f"{n} ({how} parameter)")
        lang = getattr(program, "language", "") or ""
        known = set(rec.get("defs") or {}) | set(client)
        if var not in known:
            alts = sorted(n for n in known if n.endswith("." + var) or n.split(".")[-1] == var)
            if len(alts) == 1:
                var = alts[0]
            else:
                return {**unknown, "reason": f"the engine has no value named {var!r} in {name}"
                        + (f" (did you mean one of {alts[:6]}?)" if alts else "")}
        org = origin(rec, var, lang, client)
        names = set(org.names)
        v = Var(var)
        want = Ge(v, Const(b)) if op == "lower_bound" else Le(v, Const(b))
        flag = f"{var}#nan"
        nan = bool(org.number and org.number.nan)
        holds = Not(Eq(Var(flag), Const(1))) if nan else None
        bounded = want if holds is None else _conj([holds, want])
        eqs = [Eq(Var(org.names[i]), Var(org.names[i + 1])) for i in range(len(org.names) - 1)
               if "(" not in org.names[i + 1]]
        if checker is None:
            from frame.checking.checker import EntailmentChecker
            checker = EntailmentChecker()
        snaps = rec["pc"].get(ln) or [[]]
        witness_path = None
        for pc in snaps:
            written = _connected(names, list(pc))
            facts = [_nan_rewrite(f, names, flag) for f in written] if nan else written
            query = _conj(facts + eqs + [Not(bounded)])
            if checker.is_satisfiable(query):
                model = checker.satisfying_model(query) or {}
                witness_path = (written, model)      # the conditions as the code writes them
                break
        rel = ">=" if op == "lower_bound" else "<="
        if witness_path is None:
            if ln in rec["capped"]:
                return {**unknown, "reason": f"line {ln} has more paths than the engine kept; no "
                        f"violating path among them, but not every path was checked"}
            held = [str(f) for f in _connected(names, list(snaps[0]))][:6]
            return {"verdict": "proved", "witness": [],
                    "reason": f"every feasible path to line {ln} entails {var} {rel} {b}"
                    + (f" (from: {'; '.join(held)})" if held else ""), "origin": org.how}
        facts, model = witness_path
        if not org.direct or org.number is None:
            why = ("it is not used as a number (no conversion, no number type, and the code never "
                   "computes with it or compares it with < or >)" if org.direct else f"it is computed or stored ({org.how})")
            return {**unknown, "reason": f"a feasible path reaches line {ln} with {var} {'<' if rel == '>=' else '>'} {b} "
                    f"allowed by its conditions, but the engine cannot say the caller chooses it: {why}",
                    "origin": org.how}
        if nan and model.get(flag) == 1:
            value: Any = "NaN"
        else:
            value = model.get(var)
            if value is None:
                value = (b - 1) if rel == ">=" else (b + 1)
        source = next((client[n] for n in org.names if n in client), "")
        conds = [str(f) for f in facts][:6]
        return {"verdict": "refuted",
                "witness": [{"value": var, "equals": value, "from": source or "client data"}],
                "reason": f"a feasible path reaches line {ln} with {var} = {value}"
                          + (f" (it passes: {'; '.join(conds)})" if conds else " (no condition on it on that path)"),
                "origin": org.how}
    except Exception as exc:
        return {**unknown, "reason": f"engine could not decide: {type(exc).__name__}"}


__all__ = ["Conversion", "NUMBERS_PATH", "Numbers", "Origin", "check_bound", "conversion",
           "declared", "finish", "new_record", "note", "numbers", "origin", "used_as_number"]
