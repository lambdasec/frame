"""Read-then-write races as an engine check (the business-logic hunt's `race` class).

`check(name, line, kind="atomic_write")` at a write of stored data asks whether two requests
running it at the same moment can both act on the same old value:

  proved   the write is atomic (`F("n") + 1`, `increment(...)`, an update operator written as data
           such as `{ $inc: ... }`, a SQL `UPDATE ... SET n = n - 1` or one whose WHERE tests a
           column it sets) or a lock is taken before it in the function (`select_for_update`,
           `with_for_update`, `EntityManager.lock`, a SQL read `... FOR UPDATE`);
  refuted  the function reads stored data before the write, and neither it nor any function that
           calls it takes a lock, versions the row or writes atomically;
  unknown  anything else: no write the engine recognises at the line, no read before it, or a
           protection somewhere the engine cannot place (a caller of the same name).

What protects is pack data (`[[concurrency]]`: `kind` lock / atomic / version, `call` ids, and
`keys` an object literal in the arguments must hold), so the check knows nothing about any
library; SQL text is read for what the statement itself guarantees. A transaction alone is not a protection: at the
default isolation level the second request still reads the old value. Never changes a finding.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

READS = frozenset({"resource_select", "sql", "nosql", "orm", "resource_modify"})
WRITES = frozenset({"resource_modify", "sql", "nosql", "orm"})
KINDS = ("lock", "atomic", "version", "read", "write")
PROTECTIONS = ("lock", "atomic", "version")
_BUILTIN: Dict[str, List[Dict[str, Any]]] = {}


def entries(program) -> List[Dict[str, Any]]:
    """The `[[concurrency]]` entries for this program: every built-in pack of its language (an entry
    names library-qualified call ids, so it cannot match another library's call, and a service
    file that imports only the project's models is not where a framework pack is detected) plus
    the packs applied to it (a project's own)."""
    lang = getattr(program, "language", "") or ""
    family = "javascript" if lang in ("javascript", "typescript") else lang
    if family not in _BUILTIN:
        from frame.sil.packs.loader import builtin_packs
        try:
            packs = list(builtin_packs())
        except Exception:
            packs = []
        _BUILTIN[family] = [e for p in packs if getattr(p, "language", "") == family
                            for e in (getattr(p, "concurrency", None) or [])]
    out = list(_BUILTIN[family])
    for pack in getattr(program, "active_packs", None) or []:      # a project's packs (built-ins repeat)
        out += list(getattr(pack, "concurrency", None) or [])
    return out


def _calls(proc) -> Iterable[Any]:
    for node in (getattr(proc, "nodes", {}) or {}).values():
        for ins in getattr(node, "instrs", []) or []:
            if type(ins).__name__ == "Call":
                yield ins


def _line(ins) -> int:
    loc = getattr(ins, "loc", None)
    return int(getattr(loc, "line", 0) or 0)


def _names(ins) -> List[str]:
    """The ids a call answers to: its callee id and the name it is written with."""
    out = []
    canonical = getattr(ins, "canonical", None)
    if canonical:
        out.append(str(canonical))
    func = getattr(ins, "func", None)
    text = str(getattr(func, "value", func) or "").strip('"')
    if text:
        out.append(text)
    return out


def _nested_calls(exp, depth: int = 0) -> Iterable[str]:
    """Names of calls written inside an argument (`F("n") + 1` in `update(n=...)`)."""
    if exp is None or depth > 12:
        return
    if isinstance(exp, (list, tuple)):              # a Call's arguments are (exp, type) pairs
        for e in exp:
            yield from _nested_calls(e, depth + 1)
        return
    if type(exp).__name__ == "ExpCall":
        func = getattr(exp, "func", None)
        name = str(getattr(func, "value", func) or getattr(exp, "name", "") or "")
        # a method called on a call's result (`db.update(t).set(..)`) has no name of its own;
        # the call it is chained on does
        if name and "(" not in name:
            yield name.strip('"')
        if type(func).__name__ == "ExpFieldAccess":
            yield from _nested_calls(getattr(func, "base", None), depth + 1)
        for a in getattr(exp, "args", []) or []:
            yield from _nested_calls(a, depth + 1)
        return
    for attr in ("left", "right", "exp", "operand", "value", "base", "index", "then_exp", "else_exp",
                 "cond", "parts", "elements", "args"):
        sub = getattr(exp, attr, None)
        if isinstance(sub, (list, tuple)):
            for s in sub:
                yield from _nested_calls(s, depth + 1)
        elif sub is not None and hasattr(sub, "__dict__") and type(sub).__name__.startswith("Exp"):
            yield from _nested_calls(sub, depth + 1)


def _bound_names(proc) -> set:
    """Names the procedure binds: its parameters and every local it assigns."""
    out = {str(p) for p, _ in (getattr(proc, "params", None) or [])}
    for node in (getattr(proc, "nodes", {}) or {}).values():
        for ins in getattr(node, "instrs", []) or []:
            if type(ins).__name__ == "Assign":
                out.add(str(getattr(ins, "id", "")).split(".", 1)[0])
            ret = getattr(ins, "ret", None)
            if ret:
                out.add(str(ret[0]))
    return out


def _self_referencing(call, proc=None) -> bool:
    """Does a keyword argument's value read the attribute it is named after through a name the
    function does not bind (`values(balance=Wallet.balance - amt)`, the model class): a column
    the database computes from itself? `w.balance` of a row loaded earlier is a stale value."""
    names = getattr(call, "kwarg_names", None) or []
    bound = _bound_names(proc) if proc is not None else set()
    for arg, kw in zip(getattr(call, "args", []) or [], names):
        exp = arg[0] if isinstance(arg, tuple) else arg
        for n in _value_names(exp):
            head, _, attr = str(n).rpartition(".")
            if kw and attr == kw and head and head.split(".", 1)[0] not in bound:
                return True
    return False


def _chain_name(exp, depth: int = 0) -> Optional[str]:
    """`update(T).where(c).values(n=...)` as `update.where.values`: the dotted name of a call
    chained on calls, read through the chain (None when a link is not a name)."""
    if depth > 12:
        return None
    kind = type(exp).__name__
    if kind == "ExpVar":
        return str(getattr(exp, "var", "")) or None
    if kind == "ExpCall":
        return _chain_name(getattr(exp, "func", None), depth + 1)
    if kind == "ExpFieldAccess":
        base = _chain_name(getattr(exp, "base", None), depth + 1)
        field = getattr(exp, "field_name", None)
        return f"{base}.{field}" if base and field else None
    if kind == "ExpConst" and isinstance(getattr(exp, "value", None), str):
        return exp.value.strip('"') or None
    return None


def _nested_chain_calls(exp, depth: int = 0) -> Iterable[Tuple[str, Any]]:
    """(dotted name, call) of every call written inside an argument, chained ones named by
    their chain."""
    if exp is None or depth > 12:
        return
    if isinstance(exp, (list, tuple)):
        for e in exp:
            yield from _nested_chain_calls(e, depth + 1)
        return
    if type(exp).__name__ == "ExpCall":
        name = _chain_name(exp)
        if name:
            yield name, exp
        func = getattr(exp, "func", None)
        if type(func).__name__ == "ExpFieldAccess":
            yield from _nested_chain_calls(getattr(func, "base", None), depth + 1)
        for a in getattr(exp, "args", []) or []:
            yield from _nested_chain_calls(a, depth + 1)
        return
    for attr in ("left", "right", "exp", "operand", "value", "base", "then_exp", "else_exp", "parts", "args"):
        sub = getattr(exp, attr, None)
        for s_ in (sub if isinstance(sub, (list, tuple)) else [sub]):
            if s_ is not None and type(s_).__name__.startswith("Exp"):
                yield from _nested_chain_calls(s_, depth + 1)


def _value_names(exp, depth: int = 0) -> Iterable[str]:
    """Variable and attribute names read by an expression (`Wallet.balance`, `balance`)."""
    if exp is None or depth > 12:
        return
    kind = type(exp).__name__
    if kind == "ExpVar":
        yield str(getattr(exp, "var", ""))
        return
    if kind == "ExpFieldAccess":
        base = _chain_name(getattr(exp, "base", None))
        field = getattr(exp, "field_name", "")
        yield f"{base}.{field}" if base else str(field)
    for attr in ("left", "right", "exp", "operand", "base", "then_exp", "else_exp", "parts", "args"):
        sub = getattr(exp, attr, None)
        for s in (sub if isinstance(sub, (list, tuple)) else [sub]):
            if isinstance(s, tuple):
                s = s[0]
            if s is not None and type(s).__name__.startswith("Exp"):
                yield from _value_names(s, depth + 1)


def _kind_of(program, names: List[str], table: List[Dict[str, Any]],
             keys: Optional[Iterable[str]] = None, call=None, proc=None) -> Optional[str]:
    """The kind of the first entry `names` match; an entry with `keys` only when `keys` (the
    call's literal keys) holds one of them, one with `self_reference` only when `call` computes
    a column from itself."""
    from frame.sil.packs.apply import _glob
    held = set(keys or ())
    imports = {k: str(v) for k, v in (getattr(program, "imports", None) or {}).items()}
    qualified = list(names)
    for n in names:                                  # `F("n")` with `from django.db.models import F`
        head, _, rest = n.partition(".")
        if head in imports:
            qualified.append(f"{imports[head]}.{rest}" if rest else imports[head])
    for e in table:
        if e.get("keys") and not (held & set(e["keys"])):
            continue
        if e.get("self_reference") and (call is None or not _self_referencing(call, proc)):
            continue
        if _glob(e.get("call", []), *qualified):
            return e["kind"]
    return None


# -- SQL text: what a statement guarantees by itself -------------------------------------------

_FOR_UPDATE = re.compile(r"\bFOR\s+(?:NO\s+KEY\s+)?UPDATE\b|\bWITH\s*\(\s*(?:ROWLOCK\s*,\s*)?UPDLOCK\b",
                         re.IGNORECASE)
_UPSERT_SET = re.compile(r"\bON\s+(?:CONFLICT\b.*?\bDO\s+UPDATE\s+SET|DUPLICATE\s+KEY\s+UPDATE)\s+",
                         re.IGNORECASE | re.DOTALL)
_IDENT_RE = re.compile(r"[A-Za-z_][\w$]*")


def _assignments(sql: str, start: int) -> Optional[List[Tuple[str, str]]]:
    """(column, expression) pairs of a SET list starting at `start`, up to WHERE / RETURNING /
    FROM / the end; None when it cannot be read."""
    from frame.sil.sql_credentials import _WHERE, _column, _split_top
    rest = sql[start:]
    end = _WHERE.search(rest)
    parts = _split_top(rest[:end.start()] if end else rest)
    if not parts:
        return None
    out = []
    for part in parts:
        col, eq, exp = part.partition("=")
        if not eq or not col.strip():
            return None
        out.append((_column(col.strip()).lower(), exp.strip()))
    return out


def _reads_column(exp: str, column: str) -> bool:
    """Does a SQL expression read `column` (bare, or qualified: `t.n`, `"n"`, `excluded.n` is the
    new row and does not count)?"""
    text = re.sub(r"'[^']*'", " ", exp)
    for m in re.finditer(r"((?:[\w\"`\[\]]+\.)?)([\"`\[]?)([A-Za-z_]\w*)[\"`\]]?", text):
        if m.group(3).lower() == column and m.group(1).strip(".").strip('"`[]').lower() not in ("excluded",):
            return True
    return False


def sql_guarantee(sql: str) -> Optional[str]:
    """What a SQL statement guarantees against a concurrent request by itself: `atomic` for an
    UPDATE (or an upsert's update) that computes a column from its current value (`SET n = n - 1`)
    or whose WHERE tests a column it sets (`SET used = 1 WHERE id = ? AND used = 0`: the database
    re-checks the row it writes), `lock` for a read that locks the rows it returns
    (`SELECT ... FOR UPDATE`, SQL Server's `WITH (UPDLOCK)`), else None. A statement this cannot
    read guarantees nothing."""
    from frame.sil.sql_credentials import _UPDATE, _WHERE
    if not sql:
        return None
    m = _UPDATE.match(sql) or _UPSERT_SET.search(sql)
    if m:
        pairs = _assignments(sql, m.end())
        if pairs:
            if any(_reads_column(exp, col) for col, exp in pairs):
                return "atomic"
            where = _WHERE.search(sql, m.end())
            if where and where.group(0).strip().upper() == "WHERE":
                cond = sql[where.end():]
                if any(_reads_column(cond, col) for col, _ in pairs):
                    return "atomic"
        return None
    if re.match(r"\s*(?:\(\s*)?SELECT\b", sql, re.IGNORECASE) and _FOR_UPDATE.search(sql):
        return "lock"
    return None


def _sql_text(proc, exp, depth: int = 0) -> str:
    """The statement text a SQL argument holds: a literal, literal parts joined (`?` for the
    rest), or a local bound once in the procedure to one of those."""
    kind = type(exp).__name__
    if kind == "ExpConst" and isinstance(getattr(exp, "value", None), str):
        return exp.value
    if kind == "ExpStringConcat":
        return "".join(_sql_text(proc, p, depth + 1) or "?" for p in getattr(exp, "parts", []) or [])
    if kind == "ExpVar" and depth < 2 and proc is not None:
        name = str(getattr(exp, "var", ""))
        defs = [ins for node in (getattr(proc, "nodes", {}) or {}).values()
                for ins in getattr(node, "instrs", []) or []
                if type(ins).__name__ == "Assign" and str(getattr(ins, "id", "")) == name]
        if len(defs) == 1:
            return _sql_text(proc, defs[0].exp, depth + 1)
    return ""


def _sql_kind(program, proc, ins) -> Optional[str]:
    """`sql_guarantee` of a SQL call's statement (its first argument)."""
    if _data_kind(program, ins) != "sql":
        return None
    args = getattr(ins, "args", []) or []
    if not args:
        return None
    first = args[0][0] if isinstance(args[0], tuple) else args[0]
    return sql_guarantee(_sql_text(proc, first))


def _data_kind(program, ins) -> Optional[str]:
    try:
        spec = program.spec_for_call(ins)
    except Exception:
        spec = None
    kind = getattr(spec, "is_sink", None) if spec is not None else None
    return getattr(kind, "value", kind)


def _protections(program, proc, table) -> List[Tuple[int, str]]:
    found = []
    for ins in _calls(proc):
        kind = _kind_of(program, _names(ins), table, getattr(ins, "literal_keys", None), ins, proc) \
            or _sql_kind(program, proc, ins)
        if kind:
            found.append((_line(ins), kind))
        for a in getattr(ins, "args", []) or []:
            k = _kind_of(program, list(_nested_calls(a)), table)
            if not k:
                for name, call in _nested_chain_calls(a):
                    k = _kind_of(program, [name], table, call=call, proc=proc)
                    if k:
                        break
            if k:
                found.append((_line(ins), k))
    for ann in getattr(proc, "annotations", None) or []:          # `@Lock(PESSIMISTIC_WRITE)`
        kind = _kind_of(program, [n for n in (ann.canonical, ann.name) if n], table)
        if kind:
            found.append((0, kind))
    return found


def check_atomic_write(program, proc_name: str, line: int,
                       callers: Optional[List[Tuple[Any, Any]]] = None) -> Dict[str, Any]:
    """The `atomic_write` verdict at `line` in `proc_name` (see the module docstring). `callers` are
    (program, procedure) pairs that may call it: a lock or version taken there makes the answer
    unknown rather than refuted, since the engine cannot tell which caller runs."""
    unknown = {"verdict": "unknown", "witness": []}
    proc = (getattr(program, "procedures", {}) or {}).get(proc_name)
    if proc is None:
        return {**unknown, "reason": f"no procedure {proc_name!r}"}
    table = entries(program)
    here = _protections(program, proc, table)
    marked = {ln for ln, k in here if k in ("write", "atomic")}     # an atomic call is a write
    writes = [ins for ins in _calls(proc) if _line(ins) == int(line) and (
        _data_kind(program, ins) in WRITES or _line(ins) in marked)]
    if not writes:
        return {**unknown, "reason": f"no write of stored data the engine recognises at line {line}"}
    atomic = [ln for ln, k in here if k == "atomic" and ln == int(line)]
    if atomic:
        return {"verdict": "proved", "witness": [],
                "reason": f"the write at line {line} is atomic (computed by the database)"}
    earlier_atomic = [ln for ln, k in here if k == "atomic" and 0 < ln < int(line)]
    locks = [ln for ln, k in here if k in ("lock", "version") and ln <= int(line)]
    if locks:
        return {"verdict": "proved", "witness": [],
                "reason": f"a lock or version check at line {min(locks) or 'the declaration'} comes before "
                          f"the write at line {line}"}
    reads = sorted({ln for ln, k in here if k == "read" and 0 < ln < int(line)} |
                   {_line(ins) for ins in _calls(proc)
                    if 0 < _line(ins) < int(line) and _data_kind(program, ins) in READS})
    if not reads:
        return {**unknown, "reason": f"no read of stored data before line {line} in {proc_name} "
                "(it may come from a caller: check the caller)"}
    if earlier_atomic:
        return {**unknown, "reason": f"an atomic expression at line {earlier_atomic[0]} may compute "
                f"the value written at line {line}: read it"}
    for cprog, cproc in callers or []:
        if any(k in ("lock", "version") for _, k in _protections(cprog, cproc, entries(cprog))):
            return {**unknown, "reason": f"{proc_name} reads at line {reads[0]} and writes at line {line} "
                    f"with no lock, but a caller ({getattr(cproc, 'name', '?')}) takes one"}
    if not any(e["kind"] in PROTECTIONS for e in table):
        return {**unknown, "reason": "no [[concurrency]] facts for this language, so the engine "
                "cannot tell a lock from any other call"}
    return {"verdict": "refuted",
            "witness": [{"line": reads[0], "event": "reads stored data"},
                        {"line": int(line), "event": "writes it back, no lock, version or atomic update"}],
            "reason": f"{proc_name} reads stored data at line {reads[0]} and writes at line {line}; "
                      "nothing in it or its callers locks the row, checks a version or writes atomically"}


def _heads(names) -> set:
    return {str(n).split(".", 1)[0].split("[", 1)[0] for n in names}


def _instrs_in_order(proc) -> List[Any]:
    out = []
    for node in (getattr(proc, "nodes", {}) or {}).values():
        out += list(getattr(node, "instrs", []) or [])
    return sorted(out, key=_line)


def decided_read_writes(program, proc_name: str) -> List[Tuple[int, int, int]]:
    """(read, decision, write) lines: an unprotected read-then-write whose code branches on the
    value it read before writing (`c = get(...)`; `if c.uses < c.limit:`; `c.save()`), the
    check-then-act shape two concurrent requests both pass. The read's value is followed
    through copies and values computed from it (`left = c.limit - c.uses`)."""
    pairs = unprotected_read_writes(program, proc_name)
    if not pairs:
        return []
    proc = (getattr(program, "procedures", {}) or {}).get(proc_name)
    order = _instrs_in_order(proc)
    out = []
    for r, w in pairs:
        held: set = set()
        decision = 0
        for ins in order:
            ln = _line(ins)
            if ln < r or ln >= w:
                continue
            kind = type(ins).__name__
            if kind == "Call" and ln == r and getattr(ins, "ret", None):
                held.add(str(ins.ret[0]))
            elif kind == "Assign" and held:
                try:
                    used = _heads(ins.exp.free_vars())
                except Exception:
                    used = set()
                if used & held:
                    held.add(str(ins.id).split(".", 1)[0])
            elif kind == "Prune" and held:
                try:
                    used = _heads(ins.condition.free_vars())
                except Exception:
                    used = set()
                if used & held:
                    decision = ln
                    break
        if decision:
            out.append((r, decision, w))
    return out


def unprotected_read_writes(program, proc_name: str) -> List[Tuple[int, int]]:
    """(read line, write line) pairs in `proc_name` that `check_atomic_write` would refute when no
    caller protects them: what the hunt's `race` class ranks a unit by. Callers are not asked
    (ranking only; the check itself asks them)."""
    proc = (getattr(program, "procedures", {}) or {}).get(proc_name)
    if proc is None:
        return []
    table = entries(program)
    if not any(e["kind"] in PROTECTIONS for e in table):
        return []
    here = _protections(program, proc, table)
    if any(k in ("lock", "version") for _, k in here):
        return []
    atomic = {ln for ln, k in here if k == "atomic"}
    reads = sorted({ln for ln, k in here if k == "read" and ln > 0} |
                   {_line(i) for i in _calls(proc) if _line(i) > 0 and _data_kind(program, i) in READS})
    out = []
    marked = {ln for ln, k in here if k == "write" and ln > 0}
    for w in sorted({_line(i) for i in _calls(proc) if _data_kind(program, i) in WRITES} | marked):
        if w in atomic or any(a < w for a in atomic):
            continue
        earlier = [r for r in reads if r < w]
        if earlier:
            out.append((earlier[0], w))
    return out
