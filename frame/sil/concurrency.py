"""Read-then-write races as an engine check (the business-logic hunt's `race` class).

`check(name, line, kind="atomic_write")` at a write of stored data asks whether two requests
running it at the same moment can both act on the same old value:

  proved   a lock or version check comes before the reads (`select_for_update`, `with_for_update`,
           `EntityManager.lock`, `SELECT ... FOR UPDATE`), the write re-checks in its own condition
           the value it changes (a compare-and-set: `UPDATE ... SET used = 1 WHERE used = 0`,
           Prisma `where: { uses: { lt: max } }` beside `data: { uses: ... }`, a Mongo filter on the
           field it `$inc`s, Drizzle `.where(lt(t.n, ...))` after `.set({ n })`), or the write is
           computed from the stored value (`F("n") + 1`, `increment`, `$inc`, `SET n = n - 1`) and
           nothing decides on that field's old value before it;
  refuted  the function reads stored data before the write, nothing in it or its callers locks,
           versions or re-checks, and the write is plain -- or it is computed from the stored
           value but the code decided on that field's old value first (`if c.uses < c.limit`
           then an atomic `uses + 1`: two requests both pass the check);
  unknown  anything else: no write the engine recognises at the line, no read before it, a lock
           taken only after the reads, an atomic write after a decision on values the engine
           cannot relate to the field it changes, or a protection somewhere the engine cannot
           place (a caller of the same name).

Reads, writes and locks made through the project's own functions count where they are called
(a repository method that writes is a write at its call; summaries follow up to SUMMARY_DEPTH
calls when a `HuntContext` resolves them). A write's chained calls are one statement
(`db.update(t).set({...}).where(...)`).

What protects is pack data (`[[concurrency]]`: `kind` lock / atomic / version / read / write,
`call` ids, `keys` an object literal in the arguments must hold, `self_reference`, and `filter` /
`update` selectors naming where a write states its condition and its new values), so the check
knows nothing about any library; SQL text is read for what the statement itself guarantees. A transaction alone is not a protection: at the
default isolation level the second request still reads the old value. Never changes a finding.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

READS = frozenset({"resource_select", "sql", "nosql", "orm", "resource_modify"})
WRITES = frozenset({"resource_modify", "sql", "nosql", "orm"})
KINDS = ("lock", "atomic", "version", "read", "write")
PROTECTIONS = ("lock", "atomic", "version")
SUMMARY_DEPTH = 5
MAX_CALLS = 600        # calls of one function followed into the project's functions
STRENGTH = {"plain": 0, "atomic": 1, "conditional": 2}
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
    """Does a value the call writes read the attribute it is stored under through a name the
    function does not bind: a keyword argument (`values(balance=Wallet.balance - amt)`, the model
    class) or an object-literal entry (`set({ n: sql`${t.n} + 1` })`, the table)? That is a
    column the database computes from itself; `w.balance` of a row loaded earlier is stale."""
    bound = _bound_names(proc) if proc is not None else set()

    def reads_itself(key, names) -> bool:
        for n in names:
            head, _, attr = str(n).rpartition(".")
            if key and attr == key and head and head.split(".", 1)[0] not in bound:
                return True
        return False
    names = getattr(call, "kwarg_names", None) or []
    for arg, kw in zip(getattr(call, "args", []) or [], names):
        exp = arg[0] if isinstance(arg, tuple) else arg
        if reads_itself(kw, _value_names(exp)):
            return True
    for path, reads in (getattr(call, "literal_reads", None) or {}).items():
        if reads_itself(str(path).rsplit(".", 1)[-1], reads):
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
    for attr in ("left", "right", "exp", "operand", "base", "then_exp", "else_exp", "parts", "args",
                 "condition", "true_exp", "false_exp"):
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
    held = _held_keys(call) if call is not None else {c for k in (keys or ()) for c in str(k).split(".")}
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
# advisory locks that serialize the transactions taking them: PostgreSQL's
# pg_advisory_lock / pg_advisory_xact_lock (not the try_ or shared forms), MySQL's GET_LOCK
_ADVISORY_LOCK = re.compile(r"\b(?:pg_advisory_(?:xact_)?lock|GET_LOCK)\s*\(", re.IGNORECASE)
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


def sql_effect(sql: str) -> Dict[str, Any]:
    """What a SQL statement is and guarantees by itself: {"write": bool | None (None when the text
    is not read), "read": bool | None, "guarantee": "atomic" | "conditional" | "lock" | None,
    "columns": the columns an UPDATE / upsert sets}. `atomic`: a column computed from its current
    value (`SET n = n - 1`); `conditional`: the WHERE tests a column the statement sets (`SET used
    = 1 WHERE id = ? AND used = 0`: the database re-checks the row it writes), or an insert that
    does nothing on a conflict (`ON CONFLICT DO NOTHING`, `INSERT IGNORE`: one request claims the
    key); `lock`: a read that locks the rows it returns (`SELECT ... FOR UPDATE`, SQL Server's
    `WITH (UPDLOCK)`). A statement this cannot read guarantees nothing."""
    from frame.sil.sql_credentials import _UPDATE, _WHERE
    out: Dict[str, Any] = {"write": None, "read": None, "guarantee": None, "columns": set()}
    if not sql or not sql.strip():
        return out
    verb = re.match(r"\s*\(?\s*(\w+)", sql)
    word = verb.group(1).upper() if verb else ""
    if word in ("SET", "RESET", "BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "LOCK"):
        out.update(write=False, read=False)      # session settings and transaction control
        if word == "LOCK":                        # `LOCK TABLE t IN EXCLUSIVE MODE`
            out["guarantee"] = "lock"
        return out
    if word in ("SELECT", "WITH", "SHOW", "EXPLAIN"):
        out.update(write=False, read=True)
        if word == "SELECT" and (_FOR_UPDATE.search(sql) or _ADVISORY_LOCK.search(sql)):
            out["guarantee"] = "lock"
        return out
    if word in ("UPDATE", "INSERT", "DELETE", "REPLACE", "MERGE", "UPSERT"):
        out.update(write=True, read=False)
    m = _UPDATE.match(sql) or _UPSERT_SET.search(sql)
    if m:
        pairs = _assignments(sql, m.end())
        if pairs:
            out["columns"] = {col for col, _ in pairs}
            if any(_reads_column(exp, col) for col, exp in pairs):
                out["guarantee"] = "atomic"
            where = _WHERE.search(sql, m.end())
            if where and where.group(0).strip().upper() == "WHERE":
                cond = sql[where.end():]
                if any(_reads_column(cond, col) for col, _ in pairs):
                    out["guarantee"] = "conditional"
        return out
    if re.search(r"\bON\s+CONFLICT\b[^;]*\bDO\s+NOTHING\b|^\s*INSERT\s+(?:OR\s+)?IGNORE\b", sql, re.IGNORECASE):
        out["guarantee"] = "conditional"
    return out


def sql_guarantee(sql: str) -> Optional[str]:
    """`sql_effect(sql)["guarantee"]`: atomic, conditional, lock or None."""
    return sql_effect(sql)["guarantee"]


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


def _sql_of(program, proc, ins) -> Optional[Dict[str, Any]]:
    """`sql_effect` of a SQL call's statement (its first argument), or None for another call."""
    if _data_kind(program, ins) != "sql":
        return None
    args = getattr(ins, "args", []) or []
    if not args:
        return None
    first = args[0][0] if isinstance(args[0], tuple) else args[0]
    return sql_effect(_sql_text(proc, first))


def _data_kind(program, ins) -> Optional[str]:
    try:
        spec = program.spec_for_call(ins)
    except Exception:
        spec = None
    kind = getattr(spec, "is_sink", None) if spec is not None else None
    return getattr(kind, "value", kind)


# -- the entries a call meets, and the statement it belongs to -------------------------------

def _qualified(program, names: List[str]) -> List[str]:
    imports = {k: str(v) for k, v in (getattr(program, "imports", None) or {}).items()}
    wildcards = [str(w).rstrip(".*") for w in (getattr(program, "import_wildcards", None) or [])]
    out = list(names)
    for n in names:                                  # `F("n")` with `from django.db.models import F`
        head, _, rest = n.partition(".")
        if head in imports:
            out.append(f"{imports[head]}.{rest}" if rest else imports[head])
        elif not rest:                               # `[ConcurrencyCheck]` under `using System...;`
            out += [f"{ns}.{n}" for ns in wildcards] + [f"{ns}.{n}Attribute" for ns in wildcards]
    return out


_OFF = frozenset({"false", "null", "undefined", "0"})


def _held_keys(call) -> set:
    """The components of a call's literal key paths (`0.data.uses.increment` -> 0, data, uses,
    increment), leaving out a key whose literal value switches it off (`{ lock: false }`)."""
    values = getattr(call, "literal_values", None) or {}
    return {c for k in (getattr(call, "literal_keys", None) or ())
            if str(values.get(k, "")).lower() not in _OFF for c in str(k).split(".")}


def _typed(program, names: List[str]) -> List[str]:
    """The ids a call id answers to through the library types its parts return (value-types.toml:
    `...SqlEntityManager.getTransactionContext().whereIn.forUpdate` is a knex builder's
    `knex.whereIn.forUpdate`)."""
    lang = getattr(program, "language", "") or ""
    out: List[str] = []
    for n in names:
        if n.count(".") >= 2:
            out += [t for t in _typed_ids(n, lang) if t not in names]
    return out


_TYPED: Dict[Tuple[str, str], Tuple[str, ...]] = {}


def _typed_ids(name: str, lang: str) -> Tuple[str, ...]:
    """`value_origins.typed_names`, memoised."""
    key = (name, lang)
    if key not in _TYPED:
        try:
            from frame.sil.value_origins import typed_names
            _TYPED[key] = tuple(typed_names(name, lang))
        except Exception:
            _TYPED[key] = ()
        if len(_TYPED) > 200000:
            _TYPED.clear()
    return _TYPED[key]


_PATTERNS: Dict[Tuple[str, ...], Any] = {}


def _pattern(calls: Iterable[str]):
    """An entry's call globs as one compiled pattern (fnmatch's syntax, as `packs.apply._glob`)."""
    key = tuple(calls)
    if key not in _PATTERNS:
        import fnmatch
        _PATTERNS[key] = re.compile("|".join(f"(?:{fnmatch.translate(c)})" for c in key) or "(?!)")
    return _PATTERNS[key]


def _matching(program, names: List[str], table, call=None, proc=None) -> List[Dict[str, Any]]:
    """Every entry the call meets (`keys`, `self_reference` checked against it)."""
    qualified = _qualified(program, [n for n in names if n])
    qualified += _typed(program, qualified)
    held = _held_keys(call)
    out = []
    for e in table:
        if e.get("keys") and not (held & set(e["keys"])):
            continue
        if e.get("self_reference") and (call is None or not _self_referencing(call, proc)):
            continue
        pattern = _pattern(e.get("call", []))
        if any(pattern.match(n) for n in qualified):
            out.append(e)
    return out


def _method(call) -> str:
    """The method a call or a nested chain link names (`$c.set` and `update(T).where` -> set, where)."""
    func = getattr(call, "func", None)
    if type(func).__name__ == "ExpFieldAccess":
        return str(getattr(func, "field_name", "") or "")
    if type(func).__name__ == "ExpVar":
        return str(getattr(func, "var", "")).rsplit(".", 1)[-1]
    return str(getattr(func, "value", func) or "").strip('"').rsplit(".", 1)[-1]


def _ret_name(call) -> Optional[str]:
    ret = getattr(call, "ret", None)
    return str(ret[0]) if ret else None


_TEMPORARY = re.compile(r"^(?:\$[a-z]+\d+|__nested_\d+)$")


def _result_names(proc, calls: List[Any]) -> Dict[str, Any]:
    """Name -> the call whose result it holds: the call's return identifier, and a frontend
    temporary it is copied into (`$chain2 = <ret>`, `__nested_1 = <ret>`), which the next link of
    a chained expression calls through. A variable the code names (`c = get(...)`) is not one."""
    by_ret = {}
    for c in calls:
        r = _ret_name(c)
        if r:
            by_ret[r] = c
    for node in (getattr(proc, "nodes", {}) or {}).values():
        for ins in getattr(node, "instrs", []) or []:
            if type(ins).__name__ == "Assign" and type(getattr(ins, "exp", None)).__name__ == "ExpVar" \
                    and _TEMPORARY.match(str(ins.id)):
                src = by_ret.get(str(ins.exp.var))
                if src is not None:
                    by_ret.setdefault(str(ins.id), src)
    return by_ret


def _chains(calls: List[Any], proc=None) -> Dict[int, List[Any]]:
    """id(call) -> the calls of its statement chain (`db.update(t)` -> `$c.set(...)` ->
    `$c2.where(...)`), in order: a call whose receiver is another call's result is linked to it."""
    by_ret = _result_names(proc, calls)
    parent: Dict[int, int] = {id(c): id(c) for c in calls}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for c in calls:
        func = getattr(c, "func", None)
        head = str(getattr(func, "value", func) or "").strip('"').split(".", 1)[0]
        other = by_ret.get(head)
        if other is not None and other is not c:
            parent[find(id(c))] = find(id(other))
    texts = {id(c): str(getattr(getattr(c, "func", None), "value", getattr(c, "func", None)) or "").strip('"')
             for c in calls}
    for c in calls:                     # C#: `a.Where(...).ExecuteUpdate` written after `a.Where`
        for o in calls:
            if o is not c and _line(o) == _line(c) and texts[id(o)] and \
                    texts[id(c)].startswith(texts[id(o)] + "("):
                parent[find(id(c))] = find(id(o))
    groups: Dict[int, List[Any]] = {}
    for c in calls:
        groups.setdefault(find(id(c)), []).append(c)
    return {id(c): groups[find(id(c))] for c in calls}


def _tail(chain: List[Any], proc=None) -> Any:
    """The chain's last link: the call no other link is called on (its result is the value)."""
    by_ret = _result_names(proc, chain)
    used = set()
    for c in chain:
        func = getattr(c, "func", None)
        head = str(getattr(func, "value", func) or "").strip('"').split(".", 1)[0]
        if head in by_ret:
            used.add(id(by_ret[head]))
    rest = [c for c in chain if id(c) not in used]
    return rest[-1] if rest else chain[-1]


def _string_args(call) -> set:
    out = set()
    for a in getattr(call, "args", []) or []:
        exp = a[0] if isinstance(a, tuple) else a
        v = getattr(exp, "value", None)
        if type(exp).__name__ == "ExpConst" and isinstance(v, str) and re.fullmatch(r"[A-Za-z_]\w*", v):
            out.add(v)
    return out


def _call_fields(call) -> set:
    """Every field a call names: its object / dict literal keys (below the argument), keyword
    arguments (a Django lookup `uses__lt` is `uses`), attributes read in its arguments
    (`lt(t.uses, t.limit)`), and identifier-like string arguments (`increment('uses')`)."""
    out = set()
    for path in getattr(call, "literal_keys", None) or []:
        out |= set(str(path).split(".")[1:])
    for kw in getattr(call, "kwarg_names", None) or []:
        if kw:
            out.add(str(kw).split("__", 1)[0])
    for a in getattr(call, "args", []) or []:
        exp = a[0] if isinstance(a, tuple) else a
        for n in _value_names(exp):
            if "." in str(n):
                out.add(str(n).rsplit(".", 1)[-1])
    return (out | _string_args(call)) - {""}


def _selected_fields(selectors: Iterable[str], call, chain: List[Any], proc=None) -> set:
    """The fields a write states under `selectors`: an argument position (`"1"`: the update
    document of `update_one(filter, update)`; a local there is read through the calls that
    built it, `Update update = new Update().setOnInsert("_id", ID)`), a key at the top of an
    object argument (`"where"`, `"data"`), or, with a leading dot, a call of the chain by its
    method (`".set"`, `".where"`)."""
    out: set = set()
    args = [a[0] if isinstance(a, tuple) else a for a in getattr(call, "args", []) or []]
    for s in selectors:
        if s.startswith("."):
            for link in _links(s[1:], chain):
                out |= _call_fields(link)
            continue
        if s.isdigit() and int(s) < len(args) and proc is not None:
            out |= _built_fields(proc, args[int(s)])
        for path in getattr(call, "literal_keys", None) or []:
            comps = str(path).split(".")
            if comps[0] == s:
                out |= set(comps[1:])
            elif len(comps) > 1 and comps[1] == s:
                out |= set(comps[2:])
    return {f for f in out if f and not f.startswith("$") and not f.isdigit()}


def _const_names(exp, depth: int = 0) -> set:
    """Identifier-like string constants passed to calls written in an expression
    (`Criteria.where("_id").is(ID)` -> _id)."""
    out: set = set()
    if exp is None or depth > 8:
        return out
    if type(exp).__name__ == "ExpCall":
        out |= _string_args(exp)
        func = getattr(exp, "func", None)
        if type(func).__name__ == "ExpFieldAccess":
            out |= _const_names(getattr(func, "base", None), depth + 1)
        for a in getattr(exp, "args", []) or []:
            out |= _const_names(a[0] if isinstance(a, tuple) else a, depth + 1)
    return out


def _built_fields(proc, exp) -> set:
    """The fields a local argument was built with: the string constants of the calls of the
    statement that defines it, once (`Query q = new Query(Criteria.where("_id").is(K))`), followed
    through the temporaries of a chain (`new Update().setOnInsert("_id", K).setOnInsert(..)`)."""
    if type(exp).__name__ != "ExpVar":
        return set()
    name = str(exp.var)
    calls = list(_calls(proc))
    by_ret = _result_names(proc, calls)
    assigns = [i for n in (getattr(proc, "nodes", {}) or {}).values() for i in getattr(n, "instrs", []) or []
               if type(i).__name__ == "Assign" and str(getattr(i, "id", "")) == name]
    defs = [c for c in calls if _ret_name(c) == name]
    if len(assigns) + len(defs) > 2:
        return set()                                   # bound more than once: no single value
    out: set = set()
    seeds = defs + [by_ret.get(str(i.exp.var)) for i in assigns if type(i.exp).__name__ == "ExpVar"]
    for i in assigns:
        out |= _const_names(i.exp)
    chains = _chains(calls, proc)
    todo, seen = [c for c in seeds if c is not None], set()
    while todo and len(seen) < 64:
        seed = todo.pop()
        if id(seed) in seen:
            continue
        seen.add(id(seed))
        for link in chains.get(id(seed), [seed]):
            out |= _string_args(link)
            for a in getattr(link, "args", []) or []:
                a = a[0] if isinstance(a, tuple) else a
                out |= _const_names(a)
                if type(a).__name__ == "ExpVar" and _TEMPORARY.match(str(a.var)) and str(a.var) in by_ret:
                    todo.append(by_ret[str(a.var)])      # `new Query($ch)` with `$ch = where("_id").is(K)`
    return out


def _links(selector: str, chain: List[Any]) -> List[Any]:
    """The calls a `.method` selector names: links of the chain, and calls nested in their
    arguments (`ExecuteUpdate(s => s.SetProperty(...))`)."""
    out = []
    for link in chain:
        if _method(link) == selector:
            out.append(link)
        for a in getattr(link, "args", []) or []:
            for _name, call in _nested_chain_calls(a[0] if isinstance(a, tuple) else a):
                if _method(call) == selector:
                    out.append(call)
    return out


def _update_pairs(selectors: Iterable[str], call, chain: List[Any]) -> List[Tuple[str, List[str]]]:
    """(column, names its new value reads) for what a write sets under its `update` selectors:
    object-literal entries (`data: { n: ... }`, `.set({ n: ... })`), keyword arguments
    (`.update(n=...)`), and a column / value pair (`SetProperty(x => x.N, x => x.N - 1)`)."""
    out: List[Tuple[str, List[str]]] = []

    def from_call(c, prefix: Optional[str]) -> None:
        for path, reads in (getattr(c, "literal_reads", None) or {}).items():
            comps = str(path).split(".")
            if prefix is None or comps[0] == prefix or (len(comps) > 1 and comps[1] == prefix):
                out.append((comps[-1], list(reads)))
        for arg, kw in zip(getattr(c, "args", []) or [], getattr(c, "kwarg_names", None) or []):
            if kw:
                out.append((str(kw), list(_value_names(arg[0] if isinstance(arg, tuple) else arg))))
        args = [a[0] if isinstance(a, tuple) else a for a in getattr(c, "args", []) or []]
        if prefix is None and len(args) == 2 and type(args[0]).__name__ in ("ExpFieldAccess", "ExpVar"):
            column = str(next(iter(_value_names(args[0])), "")).rsplit(".", 1)[-1]
            if column:
                out.append((column, list(_value_names(args[1]))))
    for s in selectors:
        if s.startswith("."):
            for link in _links(s[1:], chain):
                from_call(link, None)
        else:
            from_call(call, s)
    return out


def _computed_from_itself(pairs: List[Tuple[str, List[str]]], proc) -> bool:
    """Does a new value read its own column through a name the function does not bind (the
    table, the model class, a query lambda's row): computed by the database?"""
    bound = _bound_names(proc) if proc is not None else set()
    for column, reads in pairs:
        for n in reads:
            head, _, attr = str(n).rpartition(".")
            if attr == column and head and head.split(".", 1)[0] not in bound:
                return True
    return False


def _origin_names(program, proc, name: str) -> List[str]:
    """`this.db.update.set` named after the value its longest known head holds
    (`drizzle-orm/mysql2.MySql2Database.update.set`): a chain written inside an argument has no
    callee id of its own."""
    parts = str(name).split(".")
    try:
        from frame.sil.value_origins import origin_in_scope
    except Exception:
        return []
    for k in range(len(parts) - 1, 0, -1):
        try:
            origin = origin_in_scope(program, getattr(proc, "name", "<module>"), ".".join(parts[:k]))
        except Exception:
            origin = None
        if origin:
            return [".".join([str(origin)] + parts[k:])]
    return []


def _nested_entries(program, proc, exp, table) -> List[Dict[str, Any]]:
    """Entries met by calls written inside an expression (`F("n") + 1`, `update(T).values(...)`),
    with the fields of a nested chain the entry selects."""
    found = []
    names = [n for n in _nested_calls(exp) if n]
    found += [dict(e, _chain=[]) for e in _matching(program, names, table)]
    chains: Dict[int, List[Any]] = {}
    for name, call in _nested_chain_calls(exp):
        if id(call) not in chains:                   # the outermost link: its chain, down to the base
            chain = []
            cur = call
            while type(cur).__name__ == "ExpCall":   # `values` -> `where` -> `update`
                chain.append(cur)
                func = getattr(cur, "func", None)
                cur = getattr(func, "base", None) if type(func).__name__ == "ExpFieldAccess" else None
            for link in chain:
                chains.setdefault(id(link), chain)
        for e in _matching(program, [name] + _origin_names(program, proc, name), table, call=call, proc=proc):
            found.append(dict(e, _chain=chains[id(call)], _call=call))
    return found


class _Write:
    """A write of stored data: how strong (plain / atomic / conditional), the fields it sets, what
    it is, and whether it saves the changes the session tracks on entities it loaded (`tracked`:
    EF Core's `SaveChanges()`, a unit of work's `commit`)."""
    __slots__ = ("how", "fields", "what", "tracked")

    def __init__(self, how: str, fields: set, what: str, tracked: bool = False):
        self.how, self.fields, self.what, self.tracked = how, set(fields), what, tracked

    def merge(self, other: "_Write") -> None:
        if STRENGTH[other.how] > STRENGTH[self.how]:
            self.how, self.what = other.how, other.what
        self.fields |= other.fields
        self.tracked = self.tracked or other.tracked


class _Events:
    """What a function does with stored data, by line: reads, writes (how strong, which fields),
    locks (0 is the declaration), and atomic expressions not at a write (`n = F("n") + 1`)."""

    def __init__(self):
        self.reads: Dict[int, str] = {}
        self.writes: Dict[int, _Write] = {}
        self.locks: Dict[int, str] = {}
        self.atomic_exprs: Dict[int, str] = {}
        self.decides: Dict[int, set] = {}      # line of a call -> fields the callee branches on
        self.lock_lines: set = set()           # every line of a statement that takes a lock
        # lambdas / nested functions the function calls, folded in at their own lines: (the call
        # that runs it, its procedure)
        self.inlined: List[Tuple[Any, Any]] = []

    def write(self, line: int, w: _Write) -> None:
        if line in self.writes:
            self.writes[line].merge(w)
        else:
            self.writes[line] = w


def _statement(program, proc, ins, chain, table, ctx=None, file: str = "") \
        -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]], Dict[int, List[str]]]:
    """The entries a call's statement meets (every call of its chain, and calls nested in their
    arguments) and the SQL effect of its own statement text."""
    found = []
    classes = _class_table(ctx, program) if any(
        getattr(c, "canonical", None) is None for c in chain) else {}
    ids = _link_ids(program, proc, chain, ctx, file) if len(chain) > 1 or classes else {}
    for link in chain:
        typed = _typed_names(program, proc, link, classes) + ids.get(id(link), [])
        ids[id(link)] = typed
        names = _names(link) + typed
        found += [dict(e, _chain=chain, _call=link)
                  for e in _matching(program, names, table, call=link, proc=proc)]
        for a in getattr(link, "args", []) or []:
            found += _nested_entries(program, proc, a[0] if isinstance(a, tuple) else a, table)
    return found, _sql_of(program, proc, ins), ids


def _func_text(call) -> str:
    func = getattr(call, "func", None)
    return str(getattr(func, "value", func) or "").strip('"')


def _receiver_types(program, proc, head: str, classes=None) -> List[str]:
    """Ids of the declared type of a name the function or its class declares (Java / C#
    `ModelBuilder modelBuilder`, a field `IRepository<T> _repo`), qualified through the file's
    imports; [] when undeclared."""
    written = (getattr(proc, "param_types", None) or {}).get(head) or \
        (getattr(proc, "var_types", None) or {}).get(head)
    if not written:
        return []
    name = _type_name(written)
    if not name or name in (getattr(program, "class_info", None) or {}) or name in (classes or {}):
        return []                                   # a project class: its own calls are resolved
    return _type_ids(program, name)


def _type_ids(program, name: str) -> List[str]:
    """A type's simple name qualified through the file's imports and usings: the one namespace the
    curated namespace tables list it under when there is one, else every candidate."""
    out = [q for q in _qualified(program, [name]) if "." in q and not q.endswith(name + "Attribute")]
    try:
        from frame.sil.metadata import _wildcard_types
        listed = _wildcard_types().get(getattr(program, "language", "") or "", {})
    except Exception:
        listed = {}
    known = [q for q in out if name in listed.get(q.rsplit(".", 1)[0], ())]
    return known if len(known) == 1 else out


def _link_ids(program, proc, chain: List[Any], ctx=None, file: str = "") -> Dict[int, List[str]]:
    """id(call) -> ids a chained call answers to when the frontend left it unnamed: the id of the
    value the link it is called on returns, followed by its method (`_repo.Query().Where(..)`
    with Query returning a `DbSet<T>` member -> `Microsoft.EntityFrameworkCore.DbSet.Where`;
    `modelBuilder.Entity<P>().Property(..).IsRowVersion()` ->
    `Microsoft.EntityFrameworkCore.ModelBuilder.Entity.Property.IsRowVersion`). A link's value is
    its callee id, the declared type of its receiver plus its method, or, for a project
    function, the type of what it returns."""
    by_ret = _result_names(proc, chain)
    texts = {id(c): _strip_arguments(_func_text(c)) for c in chain}
    classes = _class_table(ctx, program) if ctx is not None else {}
    produced: Dict[int, List[str]] = {}
    out: Dict[int, List[str]] = {}
    for _ in range(len(chain) + 1):
        changed = False
        for c in chain:
            if id(c) in produced:
                continue
            canonical = getattr(c, "canonical", None)
            text = _func_text(c)
            head = text.split(".", 1)[0]
            src = by_ret.get(head)
            prefix = max((o for o in chain if o is not c and texts[id(o)] and
                          text.startswith(_func_text(o) + "(")),
                         key=lambda o: len(_func_text(o)), default=None)    # C#: `a.Entity().Property`
            base = src if src is not None and src is not c else prefix
            if canonical:
                produced[id(c)] = [str(canonical)]
            elif base is not None:
                if id(base) not in produced:
                    continue
                produced[id(c)] = out[id(c)] = [f"{b}.{_method(c)}" for b in produced[id(base)]]
            else:
                returned = _project_return(ctx, file, proc, c) if ctx is not None else None
                typed = _receiver_types(program, proc, head, classes) if "." in text and returned is None else []
                rest = ".".join(texts[id(c)].split(".")[1:])
                if typed and rest:
                    produced[id(c)] = out[id(c)] = [f"{t}.{rest}" for t in typed]
                else:
                    produced[id(c)] = returned or []
            changed = True
        if not changed:
            break
    return out


def _project_return(ctx, file: str, proc, call) -> Optional[List[str]]:
    """Ids of what a project function a call resolves to returns, when every return agrees (None
    when the call is not one of the project's functions):
    a member of its class whose declared type is a library type (`return DbSet;` with `DbSet<T>
    DbSet`), or the result of a library call (`return template.find(q)`). Memoised."""
    try:
        d = ctx.resolve_call(file, proc.name, call.get_func_name())
    except Exception:
        d = None
    if d is None:
        return None
    memo = ctx.__dict__.setdefault("_race_returns", {})
    key = (d["file"], d["name"])
    if key in memo:
        return memo[key]
    memo[key] = []
    loc = ctx.locate(d["name"], d["file"] or None)
    prog = loc.get("program") if loc else None
    callee = (getattr(prog, "procedures", {}) or {}).get(loc["proc"]) if prog is not None else None
    if callee is None:
        return []
    classes = _class_table(ctx, prog)
    cls = callee.name.split("#", 1)[0].replace("::", ".").rsplit(".", 1)[0].rsplit(".", 1)[-1] \
        if "." in callee.name else ""
    own = classes.get(cls, (None, None))[1]
    results = {_ret_name(c): c for c in _calls(callee) if _ret_name(c)}
    copies = {str(i.id): str(i.exp.var) for n in (getattr(callee, "nodes", {}) or {}).values()
              for i in getattr(n, "instrs", []) or []
              if type(i).__name__ == "Assign" and type(getattr(i, "exp", None)).__name__ == "ExpVar"}
    found = set()
    for node in (getattr(callee, "nodes", {}) or {}).values():
        for ins in getattr(node, "instrs", []) or []:
            if type(ins).__name__ != "Return" or getattr(ins, "value", None) is None:
                continue
            names = list(_value_names(ins.value))
            name = names[0] if len(names) == 1 and type(ins.value).__name__ in ("ExpVar", "ExpFieldAccess") else ""
            name = name[5:] if name.startswith("this.") else name
            for _ in range(3):
                name = copies.get(name, name) if name not in results else name
            if name in results and getattr(results[name], "canonical", None):
                found.add((str(results[name].canonical),))
            elif own is not None and name in (getattr(own, "field_types", None) or {}):
                found.add(tuple(_type_ids(prog, _type_name(own.field_types[name]))))
            else:
                found.add(())
    out = list(next(iter(found))) if len(found) == 1 else []
    memo[key] = out
    return out


# -- version columns: an optimistic lock on the entity a write saves ----------------------------

def _class_table(ctx, program) -> Dict[str, Tuple[Any, Any]]:
    """Simple class name -> (program, ClassInfo), this program's first, then the project's."""
    memo = ctx.__dict__.setdefault("_race_classes", None) if ctx is not None else None
    if memo is not None and memo[0] is program:
        return memo[1]
    out: Dict[str, Tuple[Any, Any]] = {}
    for prog in [program] + list(getattr(ctx, "programs", []) or []):
        for name, info in (getattr(prog, "class_info", None) or {}).items():
            out.setdefault(name, (prog, info))
    if ctx is not None:
        ctx.__dict__["_race_classes"] = (program, out)
    return out


def _type_name(text: str) -> str:
    """`DbSet<Product>` -> DbSet, `List<A>` -> List, `a.b.C` -> C."""
    return str(text).split("<", 1)[0].rsplit(".", 1)[-1].strip("?[] ")


def _type_args(text: str) -> List[str]:
    inner = str(text).partition("<")[2].rpartition(">")[0]
    return [_type_name(t) for t in inner.split(",") if t.strip()]


def _versioned(classes, name: str, configured: Optional[set] = None) -> bool:
    """Does class `name` carry a field with a version annotation of the packs (`@Version`,
    `[ConcurrencyCheck]`, `[Timestamp]`), or a version property the project configures in code
    (`configured`: EF Core's `Property(p => p.Version).IsRowVersion()`)?"""
    if configured and name in configured:
        return True
    held = classes.get(name)
    if held is None:
        return False
    prog, info = held
    table = [e for e in entries(prog) if e["kind"] == "version"]
    for anns in (getattr(info, "field_annotations", None) or {}).values():
        for a in anns:
            if _matching(prog, [n for n in (a.canonical, a.name) if n], table):
                return True
    return False


def _typed_names(program, proc, ins, classes) -> List[str]:
    """Ids for a call on a member chain of the function's own class the frontend left unnamed:
    `_db.Products.Find` with `_db` a `ShopContext` whose `Products` is `DbSet<Product>` is
    `Microsoft.EntityFrameworkCore.DbSet.Find`, the type qualified in the file declaring it."""
    if getattr(ins, "canonical", None) or not classes or "." not in proc.name:
        return []
    func = getattr(ins, "func", None)
    parts = _strip_arguments(str(getattr(func, "value", func) or "").strip('"')).split(".")
    if parts and parts[0] == "this":
        parts = parts[1:]
    if len(parts) < 2:
        return []
    cls = proc.name.split("#", 1)[0].replace("::", ".").rsplit(".", 1)[0].rsplit(".", 1)[-1]
    holder = classes.get(cls)
    if holder is None:
        return []
    prog, info = holder
    for k, member in enumerate(parts[:-1]):
        written = (getattr(info, "field_types", None) or {}).get(member)
        if not written:
            return []
        name = _type_name(written)
        rest = ".".join(parts[k + 1:])             # `Where.ExecuteUpdate` after `Products`
        if name in classes and k + 1 < len(parts) - 1 and \
                parts[k + 1] in (getattr(classes[name][1], "field_types", None) or {}):
            prog, info = classes[name]
            continue
        if name in classes:                       # a project type: its library base names the call
            bases = [str(b) for b in (getattr(classes[name][1], "canonical_bases", None) or [])]
            return [f"{b}.{rest}" for b in bases]
        return [f"{q}.{rest}" for q in _qualified(prog, [name]) if "." in q]
    return []


def _strip_arguments(text: str) -> str:
    """`_db.Products.Where(x => x.Id == id).ExecuteUpdate` -> `_db.Products.Where.ExecuteUpdate`."""
    out, depth = [], 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _read_entities(proc, classes) -> set:
    """Entity classes the function reads through a member holding a typed collection
    (`_db.Products.Find(id)` with `_db` a `ShopContext` whose `Products` is `DbSet<Product>`)."""
    cls = proc.name.split("#", 1)[0].replace("::", ".").rsplit(".", 1)[0].rsplit(".", 1)[-1] \
        if "." in proc.name else ""
    own = classes.get(cls, (None, None))[1]
    out = set()
    for ins in _calls(proc):
        func = getattr(ins, "func", None)
        parts = str(getattr(func, "value", func) or "").strip('"').split(".")
        if parts and parts[0] == "this":
            parts = parts[1:]
        if len(parts) < 3 or own is None:
            continue
        holder = (getattr(own, "field_types", None) or {}).get(parts[0])
        info = classes.get(_type_name(holder or ""), (None, None))[1]
        member = (getattr(info, "field_types", None) or {}).get(parts[1]) if info is not None else None
        out |= {t for t in _type_args(member or "") if t in classes}
    return out


def _version_protected(proc, chain, classes, configured: Optional[set] = None) -> Optional[set]:
    """The entities a write saves, when every one carries a version field: the class-typed
    arguments of its calls (`repo.save(coupon)`), else, for a call that saves the tracked
    entities (`SaveChanges()`), the entities the function read. None when not protected."""
    saved = {t for c in chain for t in (getattr(c, "arg_types", None) or []) if t and _type_name(t) in classes}
    saved = {_type_name(t) for t in saved}
    if not saved and not any(getattr(c, "args", None) for c in chain):
        saved = _read_entities(proc, classes)
    if saved and all(_versioned(classes, s, configured) for s in saved):
        return saved
    return None


def _handed_type_arg(program, proc) -> str:
    """The first type argument of the call that hands this lambda over (`modelBuilder.Entity<P>(b
    => ...)` for the lambda's body), "" when none."""
    parent = (getattr(program, "procedures", {}) or {}).get(getattr(proc, "parent", None) or "")
    if parent is None:
        return ""
    for reg in getattr(program, "registrations", ()) or ():
        if reg.target != proc.name:
            continue
        for c in _calls(parent):
            if c.get_func_name() == reg.callee_text and (not reg.line or _line(c) == reg.line) \
                    and getattr(c, "type_args", None):
                return str(c.type_args[0])
    return ""


def _configured_versions(ctx, program) -> set:
    """Entity classes the project gives a version property in code: a chain whose last call is a
    `version` entry (`modelBuilder.Entity<Product>().Property(p => p.Version).IsRowVersion()`,
    `builder.Property(c => c.Rev).IsConcurrencyToken()` in `Configure(EntityTypeBuilder<Coupon>
    builder)`), the entity named by the chain's type argument or its receiver's. Memoised."""
    memo = ctx.__dict__.get("_race_configured") if ctx is not None else None
    if memo is not None:
        return memo
    out: set = set()
    for prog in (list(getattr(ctx, "programs", []) or []) if ctx is not None else [program]):
        table = [e for e in entries(prog) if e["kind"] == "version"]
        if not table:
            continue
        methods = {c.rsplit(".", 1)[-1] for e in table for c in e.get("call", [])}
        for proc in (getattr(prog, "procedures", {}) or {}).values():
            calls = list(_calls(proc))
            if not any(_method(c) in methods for c in calls):
                continue
            chains = _chains(calls, proc)
            for c in calls:
                chain = chains.get(id(c), [c])
                ids = _link_ids(prog, proc, chain)
                if not any(_matching(prog, _names(link) + ids.get(id(link), []), table) for link in chain):
                    continue
                entity = next((str(t) for link in chain for t in (getattr(link, "type_args", None) or [])[:1]), "")
                if not entity:
                    head = _func_text(chain[0]).split(".", 1)[0]
                    entity = next(iter((getattr(proc, "param_type_args", None) or {}).get(head) or []), "")
                if not entity:
                    entity = _handed_type_arg(prog, proc)
                if entity:
                    out.add(_type_name(entity))
    if ctx is not None:
        ctx.__dict__["_race_configured"] = out
    return out


def _direct_events(program, proc, table, ctx=None, file: str = "") -> Tuple[_Events, Dict[int, Any]]:
    """The function's own events (no callee followed), and the call each written line holds
    (for a decision's read value)."""
    ev = _Events()
    calls = list(_calls(proc))
    chains = _chains(calls, proc)
    seen_chains: set = set()
    at: Dict[int, Any] = {}
    atomic_fields: Dict[int, set] = {}
    for ins in calls:
        ln = _line(ins)
        chain = chains.get(id(ins), [ins])
        key = id(chain[0])
        dk = _data_kind(program, ins)
        sql = _sql_of(program, proc, ins)
        if dk in READS and not (sql and sql["read"] is False):
            ev.reads.setdefault(ln, _names(ins)[-1] if _names(ins) else "a read")
            at.setdefault(ln, ins)
        if key in seen_chains:
            continue
        seen_chains.add(key)
        found, _, ids = _statement(program, proc, ins, chain, table, ctx, file)
        kinds = {e["kind"] for e in found}
        lines = sorted({_line(c) for c in chain if _line(c)}) or [ln]
        sqls = [x for x in (_sql_of(program, proc, c) for c in chain) if x]
        for e in found:                              # a raw statement a pack says to read
            stmt_args = getattr(e.get("_call"), "args", None) or [] if e.get("statement") else []
            if stmt_args:
                first = stmt_args[0][0] if isinstance(stmt_args[0], tuple) else stmt_args[0]
                sqls.append(sql_effect(_sql_text(proc, first)))
        if kinds & {"lock", "version"} or any(x["guarantee"] == "lock" for x in sqls):
            ev.locks.setdefault(lines[0], _names(ins)[-1] if _names(ins) else "a lock")
            ev.lock_lines.update(lines)
        tail = _tail(chain, proc)
        if "read" in kinds or any(x in ev.reads for x in lines):
            label = (([str(tail.canonical)] if getattr(tail, "canonical", None) else []) +
                     ids.get(id(tail), [])[:1] + _names(tail) + ["a read"])[0]   # its callee id when known
            for x in lines:
                ev.reads[x] = label
                at[x] = tail                          # the value read is the chain's result
        writes_here = any(_data_kind(program, c) in WRITES and not (
            (_sql_of(program, proc, c) or {}).get("write") is False) for c in chain) \
            or bool(kinds & {"write", "atomic"}) \
            or any(x["write"] or x["guarantee"] in ("atomic", "conditional") for x in sqls)
        if not writes_here:
            if "atomic" in kinds:
                for x in lines:
                    ev.atomic_exprs.setdefault(x, "an atomic expression")
                    atomic_fields.setdefault(x, set()).update(
                        f for e in found if e["kind"] == "atomic" for f in _string_args(e.get("_call") or ins))
            continue
        how, fields = "plain", set()
        for x in sqls:
            fields |= x["columns"]
            if x["guarantee"] in ("atomic", "conditional") and STRENGTH[x["guarantee"]] > STRENGTH[how]:
                how = x["guarantee"]
        for e in found:
            sel_chain = e.get("_chain") or chain
            call = e.get("_call") or ins
            if e.get("update"):
                fields |= _selected_fields(e["update"], call, sel_chain, proc)
            if e["kind"] == "atomic":
                fields |= {str(k).split("__", 1)[0] for k in (getattr(call, "kwarg_names", None) or []) if k}
                fields |= _string_args(call)
                for path in getattr(call, "literal_reads", None) or {}:
                    fields.add(str(path).rsplit(".", 1)[-1])
                if STRENGTH["atomic"] > STRENGTH[how]:
                    how = "atomic"
            if e.get("update"):
                pairs = _update_pairs(e["update"], call, sel_chain)
                if _computed_from_itself(pairs, proc) and STRENGTH["atomic"] > STRENGTH[how]:
                    how = "atomic"
                    fields |= {c for c, _ in pairs}
            if e.get("filter") and e.get("update"):
                if _selected_fields(e["filter"], call, sel_chain, proc) & _selected_fields(e["update"], call, sel_chain, proc):
                    how = "conditional"
        w = _Write(how, fields, _names(ins)[-1] if _names(ins) else "a write",
                   tracked=any(e.get("tracked") for e in found if e["kind"] == "write"))
        if how != "conditional" and any(e["kind"] == "version" for e in table):
            versioned = _version_protected(proc, chain, _class_table(ctx, program),
                                           _configured_versions(ctx, program))
            if versioned:
                w.how = "conditional"
                w.what = f"{w.what} (optimistic lock: {', '.join(sorted(versioned))} carries a version field)"
        for x in lines:
            ev.write(x, _Write(w.how, w.fields, w.what, w.tracked))
            at.setdefault(x, ins)
    for node in (getattr(proc, "nodes", {}) or {}).values():         # `c.uses = F("uses") + 1`
        for ins in getattr(node, "instrs", []) or []:
            if type(ins).__name__ == "Assign":
                if any(e["kind"] == "atomic" for e in _nested_entries(program, proc, getattr(ins, "exp", None), table)):
                    ev.atomic_exprs.setdefault(_line(ins), "an atomic expression")
    for ln, w in ev.writes.items():               # `update(uses=F("uses") + 1)`: F is its own call
        if ln in ev.atomic_exprs and w.how == "plain":
            w.how = "atomic"
            w.fields |= atomic_fields.get(ln, set())
    for ann in getattr(proc, "annotations", None) or []:          # `@Lock(PESSIMISTIC_WRITE)`
        if any(e["kind"] in ("lock", "version")
               for e in _matching(program, [n for n in (ann.canonical, ann.name) if n], table)):
            ev.locks[0] = getattr(ann, "name", "an annotation")
    return ev, at


# -- across the project's own functions ----------------------------------------------------------

def _summary(ctx, file: str, name: str, depth: int) -> Optional[Dict[str, Any]]:
    """What calling a project function does with stored data: {"reads", "write": a _Write or
    None (the weakest of its writes, conditional when it locks first), "lock": it takes a lock and
    writes nothing}. Memoised on the context."""
    memo = ctx.__dict__.setdefault("_race_summaries", {})
    key = (file, name)
    if key in memo:
        return memo[key]
    memo[key] = None                                   # a cycle summarises to nothing
    loc = ctx.locate(name, file or None)
    if loc is None or loc.get("program") is None:
        return None
    program = loc["program"]
    proc = (getattr(program, "procedures", {}) or {}).get(loc["proc"])
    if proc is None:
        return None
    ev, _ = events(program, proc, ctx=ctx, file=loc.get("file") or file, depth=depth)
    first_lock = min(ev.locks) if ev.locks else None
    write = None
    for ln in sorted(ev.writes):
        w = ev.writes[ln]
        how = "conditional" if first_lock is not None and first_lock <= ln else w.how
        cur = _Write(how, w.fields, f"{name} ({w.what})", w.tracked)
        if write is None or STRENGTH[cur.how] < STRENGTH[write.how]:
            fields = (write.fields if write else set()) | cur.fields
            write = cur
            write.fields = fields
        else:
            write.fields |= cur.fields
            write.tracked = write.tracked or cur.tracked
    # the fields it (and what it calls) branches on: a value it returns may carry the outcome of
    # such a check (`checkLink` comparing `link.nbAccess` with `link.limitAccess`)
    decides = set(_branch_fields(proc))
    for _, nested in ev.inlined:
        decides |= _branch_fields(nested)
    for fields in ev.decides.values():
        decides |= fields
    out = {"reads": bool(ev.reads), "write": write, "lock": bool(ev.locks) and not ev.writes,
           "name": name, "decides": decides}
    memo[key] = out
    return out


def _branch_fields(proc) -> set:
    """Attribute names read by the function's branch conditions (`link.nbAccess >= link.limitAccess`
    -> nbAccess, limitAccess)."""
    out = set()
    for node in (getattr(proc, "nodes", {}) or {}).values():
        for ins in getattr(node, "instrs", []) or []:
            if type(ins).__name__ == "Prune":
                for n in _value_names(getattr(ins, "condition", None)):
                    if "." in str(n):
                        out.add(str(n).rsplit(".", 1)[-1])
    return out


def events(program, proc, ctx=None, file: str = "", depth: int = 0) -> Tuple[_Events, Dict[int, Any]]:
    """The function's events, with the project functions it calls folded in at their calls when
    a context resolves them (SUMMARY_DEPTH deep)."""
    table = entries(program)
    ev, at = _direct_events(program, proc, table, ctx, file)
    if ctx is None or depth >= SUMMARY_DEPTH or not hasattr(ctx, "graph"):
        _tracked_changes(proc, ev, at)
        _versioned_documents(program, proc, ev, at, ctx, file)
        return ev, at
    try:
        _, calls = ctx.graph()
        listed = calls.get((file, proc.name)) or []
    except Exception:
        listed = []
    by_line: Dict[int, Any] = {}
    by_callee: Dict[Tuple[str, int], Any] = {}
    for ins in _calls(proc):
        by_line.setdefault(_line(ins), ins)
        by_callee.setdefault((ins.get_func_name(), _line(ins)), ins)

    def fold(ln: int, s: Dict[str, Any], ins) -> None:
        if ins is not None and (s["reads"] or s["write"] is not None or s.get("decides")):
            at.setdefault(ln, ins)
        if s["reads"]:
            ev.reads.setdefault(ln, s["name"])
        if s["write"] is not None:
            ev.write(ln, _Write(s["write"].how, s["write"].fields, s["write"].what, s["write"].tracked))
        if s["lock"]:
            ev.locks.setdefault(ln, s["name"])
            ev.lock_lines.add(ln)
        if s.get("decides"):
            ev.decides.setdefault(ln, set()).update(s["decides"])

    for callee, ln in listed[:MAX_CALLS]:
        ins = by_callee.get((callee, ln))
        try:
            d = ctx.resolve_call(file, proc.name, callee,
                                 len(getattr(ins, "args", None) or []) if ins is not None else None)
        except Exception:
            d = None
        if d is None or (d["file"], d["name"]) == (file, proc.name):
            continue
        nested = (getattr(program, "procedures", {}) or {}).get(d["name"]) if d["file"] == file else None
        if nested is not None and getattr(nested, "parent", None) == proc.name \
                and (callee, ln) in by_callee:
            _inline(ev, at, events(program, nested, ctx=ctx, file=file, depth=depth), by_callee[(callee, ln)], nested)
            continue
        s = _summary(ctx, d["file"], d["name"], depth + 1)
        if s:
            fold(ln, s, by_line.get(ln))
    for call, d in _fluent_links(ctx, file, proc):
        s = _summary(ctx, d["file"], d["name"], depth + 1)
        if s:
            fold(_line(call), s, call)
    _tracked_changes(proc, ev, at)
    _versioned_documents(program, proc, ev, at, ctx, file)
    return ev, at


def _owner(name: str) -> str:
    return str(name).split("#", 1)[0].rsplit(".", 1)[0].rsplit(".", 1)[-1]


def _returned_class(ctx, d: Dict[str, Any]) -> Optional[str]:
    """The project class a project function's declared return type names (`QueryAllParams<T>
    queryBuilder()` -> QueryAllParams), or None. Memoised."""
    memo = ctx.__dict__.setdefault("_race_returned_class", {})
    key = (d["file"], d["name"])
    if key not in memo:
        memo[key] = None
        loc = ctx.locate(d["name"], d["file"] or None)
        prog = loc.get("program") if loc else None
        callee = (getattr(prog, "procedures", {}) or {}).get(loc["proc"]) if prog is not None else None
        written = (getattr(callee, "ret_type_name", None) or getattr(callee, "return_type", "") or "") \
            if callee is not None else ""
        name = _type_name(str(written)) if written else ""
        if name and name in ctx._class_index():
            memo[key] = name
    return memo[key]


def _method_of(ctx, cls: str, method: str, n_args: int) -> Optional[Dict[str, Any]]:
    """The method a call of `method` with `n_args` arguments names on a project class: the
    class's own, else the nearest ancestor's that has one; overloads chosen by arity, None when
    that leaves more than one."""
    defs, _ = ctx.graph()
    ds = defs.get(method) or []
    if not ds:
        return None

    def arity_ok(d) -> bool:
        return d.get("params") == n_args
    ctx._class_bases()
    order = [cls]
    seen = {cls}
    frontier = [cls]
    while frontier:                     # breadth first: the nearest ancestor declaring it wins
        nxt = []
        for c in frontier:
            for b in sorted(getattr(ctx, "_supertypes", {}).get(c, ())):
                if b not in seen:
                    seen.add(b)
                    order.append(b)
                    nxt.append(b)
        frontier = nxt
    for c in order:
        hit = [d for d in ds if _owner(d["name"]) == c and arity_ok(d)]
        if hit:
            return hit[0] if len(hit) == 1 else None
    return None


def _fluent_links(ctx, file: str, proc) -> List[Tuple[Any, Dict[str, Any]]]:
    """Links of a chain called on what a project method returns when that is a project class (a
    fluent builder: `queryBuilder().criteria(..).limit(1).all(..)` with `queryBuilder` declared
    to return `QueryAllParams<T>`), each with the method of that class it calls; the result of a
    link typed the same way carries the chain on (`criteria` returns `QueryAllParams<T>`), one
    of a library type (`all` returning `Flux<P>`) ends it."""
    if not hasattr(ctx, "_class_index"):
        return []
    calls = list(_calls(proc))
    by_ret = _result_names(proc, calls)
    typed: Dict[int, str] = {}
    out: List[Tuple[Any, Dict[str, Any]]] = []
    done: set = set()
    ctx._class_bases()
    for _ in range(len(calls) + 1):
        changed = False
        for c in calls:
            if id(c) in done:
                continue
            text = _func_text(c)
            head = text.split(".", 1)[0]
            src = by_ret.get(head) if _TEMPORARY.match(head) else None
            if src is not None and src is not c:
                if id(src) not in done:
                    continue
                done.add(id(c))
                changed = True
                cls = typed.get(id(src))
                d = _method_of(ctx, cls, _method(c), len(getattr(c, "args", None) or [])) if cls else None
                if d is None:
                    continue
                out.append((c, d))
                ret = _returned_class(ctx, d)
                if ret:
                    typed[id(c)] = ret
                continue
            done.add(id(c))
            changed = True
            if text.startswith("$"):
                continue
            try:
                d = ctx.resolve_call(file, proc.name, c.get_func_name())
            except Exception:
                d = None
            ret = _returned_class(ctx, d) if d is not None else None
            if ret:
                typed[id(c)] = ret
        if not changed:
            break
    return out


# -- documents of a versioned model: Mongoose's optimisticConcurrency ---------------------------

def _schema_versioned(program, exp_or_call, table) -> bool:
    """Does a schema construction (`new mongoose.Schema({...}, { optimisticConcurrency: true })`)
    meet a `version` entry with `keys`?"""
    name = _func_text(exp_or_call).removeprefix("new ").strip()
    return bool(name) and any(e.get("keys") for e in _matching(program, [name], table, call=exp_or_call))


def _model_bindings(program, table) -> set:
    """Names this file binds to a model whose schema is versioned (`module.exports =
    mongoose.model("Coupon", couponSchema)` -> module.exports; `const Coupon = model(...)`): the
    schema as a local bound once to such a construction, or written inline, or switched on with
    `schema.set("optimisticConcurrency", true)`."""
    schemas: set = set()
    models: List[Tuple[str, Any]] = []
    for proc in (getattr(program, "procedures", {}) or {}).values():
        for node in (getattr(proc, "nodes", {}) or {}).values():
            for ins in getattr(node, "instrs", []) or []:
                kind = type(ins).__name__
                exp = getattr(ins, "exp", None) if kind == "Assign" else None
                if kind == "Assign" and type(exp).__name__ == "ExpCall" and _schema_versioned(program, exp, table):
                    schemas.add(str(ins.id))
                if kind != "Call":
                    continue
                args = [a[0] if isinstance(a, tuple) else a for a in getattr(ins, "args", []) or []]
                text = _func_text(ins)
                if _schema_versioned(program, ins, table) and _ret_name(ins):
                    schemas.add(_ret_name(ins))
                elif text.endswith(".set") and len(args) >= 2 and getattr(args[0], "value", None) in (
                        "optimisticConcurrency", '"optimisticConcurrency"') and getattr(args[1], "value", None) is True:
                    schemas.add(text[:-4])
                if str(getattr(ins, "canonical", "") or "").endswith(".model") and len(args) >= 2:
                    models.append((_ret_name(ins) or "", args[1]))
    out = set()
    copies = {str(i.id): str(i.exp.var) for p in (getattr(program, "procedures", {}) or {}).values()
              for n in (getattr(p, "nodes", {}) or {}).values() for i in getattr(n, "instrs", []) or []
              if type(i).__name__ == "Assign" and type(getattr(i, "exp", None)).__name__ == "ExpVar"}
    for ret, schema in models:
        versioned = (type(schema).__name__ == "ExpVar" and str(schema.var) in schemas) or \
            (type(schema).__name__ == "ExpCall" and _schema_versioned(program, schema, table))
        if versioned and ret:
            out.add(ret)
            out |= {dst for dst, src in copies.items() if src == ret}       # `module.exports = $m`
    return out


def _versioned_models(ctx, program) -> Dict[str, set]:
    """File -> the names it binds to a versioned model (`_model_bindings`). Memoised."""
    memo = ctx.__dict__.get("_race_models") if ctx is not None else None
    if memo is not None:
        return memo
    from frame.sil.hunt_tools import _program_file
    root = getattr(ctx, "repo_root", "") if ctx is not None else ""
    out: Dict[str, set] = {}
    for prog in (list(getattr(ctx, "programs", []) or []) if ctx is not None else [program]):
        if (getattr(prog, "language", "") or "") not in ("javascript", "typescript"):
            continue
        table = [e for e in entries(prog) if e["kind"] == "version" and e.get("keys")]
        if table and any(str(getattr(c, "canonical", "") or "").endswith(".model")
                         for p in (getattr(prog, "procedures", {}) or {}).values() for c in _calls(p)):
            names = _model_bindings(prog, table)
            if names:
                out[_program_file(prog, root) if ctx is not None else ""] = names
    if ctx is not None:
        ctx.__dict__["_race_models"] = out
    return out


def _module_file(file: str, spec: str, files) -> Optional[str]:
    """The project file a relative module specifier names from `file` (`./models/coupon` ->
    `models/coupon.js`), among `files`."""
    import posixpath
    if not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(file), spec))
    for cand in (base, *(base + e for e in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")),
                 *(base + "/index" + e for e in (".js", ".ts"))):
        if cand in files:
            return cand
    return None


def _versioned_documents(program, proc, ev: _Events, at: Dict[int, Any], ctx, file: str) -> None:
    """A plain write that saves a document read through a versioned model (`doc = await
    Coupon.findOne(...)`; `doc.save()`, the Coupon schema setting optimisticConcurrency) is checked
    against the version it read: conditional."""
    plain = [ln for ln, w in ev.writes.items() if w.how == "plain" and ln > 0]
    if not plain or (getattr(program, "language", "") or "") not in ("javascript", "typescript"):
        return
    models = _versioned_models(ctx, program)
    if not models:
        return
    here = models.get(file, set())
    instrs = _instrs_in_order(proc, ev)
    for read in sorted(ln for ln in ev.reads if 0 < ln < max(plain)):
        call = at.get(read)
        ret = _ret_name(call) if call is not None else None
        text = _func_text(call) if call is not None else ""
        model = text.rpartition(".")[0]
        versioned = model in here or ("module.exports" in models.get(_module_file(file, model, models) or "", set()))
        if not ret or not versioned:
            continue
        held = {ret}
        for ins in instrs:
            ln = _line(ins)
            if ln < read:
                continue
            if type(ins).__name__ == "Assign" and "." not in str(ins.id) and \
                    _entity_path(getattr(ins, "exp", None), held):
                held.add(str(ins.id))
            if type(ins).__name__ == "Call" and ln in plain and _func_text(ins).split(".", 1)[0] in held:
                w = ev.writes[ln]
                w.how = "conditional"
                w.what = f"{w.what} (optimistic lock: the model {model.rsplit('/', 1)[-1]} read at line {read} " \
                         "sets optimisticConcurrency)"


def _inline(ev: _Events, at: Dict[int, Any], inner: Tuple[_Events, Dict[int, Any]], call, nested) -> None:
    """Fold a lambda's events into its enclosing function's at their own lines (`flatMap(x -> {
    if (...) ...; return repo.save(u); })` runs where it is written, once its receiver has a
    value), so a read before it, a branch in it and a write in it are one sequence."""
    iev, iat = inner
    for ln, label in iev.reads.items():
        ev.reads.setdefault(ln, label)
    for ln, w in iev.writes.items():
        ev.write(ln, _Write(w.how, w.fields, w.what, w.tracked))
    for ln, label in iev.locks.items():
        if ln > 0:
            ev.locks.setdefault(ln, label)
    for ln, label in iev.atomic_exprs.items():
        ev.atomic_exprs.setdefault(ln, label)
    for ln, fields in iev.decides.items():
        ev.decides.setdefault(ln, set()).update(fields)
    ev.lock_lines |= iev.lock_lines
    for ln, c in iat.items():
        at.setdefault(ln, c)
    ev.inlined.append((call, nested))
    ev.inlined += iev.inlined


# frontends lower an element of an iterated collection as a call of one of these on it
# (C# `foreach`, Python `for`, ...): the element is part of the value iterated
_ELEMENT_OF = frozenset({"GetEnumerator.Current", "next", "__getitem__", "iter", "Iterator.next"})


def _entity_path(exp, held: set) -> bool:
    """Is `exp` a loaded entity or a part of one: a name holding it, a member path on it
    (`checkout.CheckoutItems`), an element of it, or an iterated element (`foreach (var i in
    checkout.Items)`)? Never a value computed from one."""
    kind = type(exp).__name__
    if kind == "ExpVar":
        return str(getattr(exp, "var", "")).split(".", 1)[0] in held
    if kind == "ExpFieldAccess":
        return _entity_path(getattr(exp, "base", None), held)
    if kind == "ExpIndex":
        return _entity_path(getattr(exp, "base", None), held)
    if kind == "ExpCall":
        func = getattr(exp, "func", None)
        name = str(getattr(func, "value", func) or "").strip('"')
        args = [a[0] if isinstance(a, tuple) else a for a in getattr(exp, "args", []) or []]
        return name in _ELEMENT_OF and len(args) == 1 and _entity_path(args[0], held)
    return False


def _tracked_changes(proc, ev: _Events, at: Dict[int, Any]) -> None:
    """A field assigned on an entity the function loaded (`item.Product.Stock = item.Product.Stock
    - n` after reading the checkout), followed by a call that saves the changes the session
    tracks (`SaveChanges()`): the assignment is the write. The entity is followed through names
    holding it, member paths, elements and iteration, never through values computed from it."""
    saves = sorted(ln for ln, w in ev.writes.items() if w.tracked and ln > 0)
    if not saves:
        return
    instrs = _instrs_in_order(proc, ev)
    for read in sorted(ln for ln in ev.reads if 0 < ln < saves[-1]):
        call = at.get(read)
        ret = _ret_name(call) if call is not None else None
        if not ret:
            continue
        held = {ret}
        for ins in instrs:
            ln = _line(ins)
            if ln < read or ln >= saves[-1] or type(ins).__name__ != "Assign":
                continue
            target = str(getattr(ins, "id", ""))
            head, dot, field = target.partition(".")
            if dot and head in held:
                save = next(x for x in saves if x > ln)
                sw = ev.writes[save]
                how = "conditional" if sw.how == "conditional" and "optimistic lock" in sw.what else "plain"
                what = sw.what if how == "conditional" else \
                    f"a change to {target} on the entity read at line {read}, saved at line {save} ({sw.what})"
                if ln not in ev.writes:
                    ev.writes[ln] = _Write(how, {field.rsplit(".", 1)[-1]}, what)
            elif not dot and _entity_path(getattr(ins, "exp", None), held):
                held.add(target)


# -- the verdict -------------------------------------------------------------------------------

def _decision(proc, at: Dict[int, Any], read: int, write: int,
              decides: Optional[Dict[int, set]] = None, prefer: Optional[set] = None,
              ev: Optional[_Events] = None) -> Optional[Tuple[int, set]]:
    """(line, fields) of the first branch between `read` and `write` on the value the read
    produced (followed through copies and values computed from it), with the attributes of it
    the branch reads (`c.uses < c.limit` -> uses, limit; `left > 0` with `left = c.limit - c.uses`
    -> limit, uses; `!c` -> none). With `prefer` (the fields the write sets), the first branch on
    one of those wins over an earlier one on others (`if c is None` before `if c.uses >= c.max`)."""
    call = at.get(read)
    ret = _ret_name(call) if call is not None else None
    if not ret:
        return None
    # a value a project function returns carries the fields it decided on (`linkEnv` returning
    # `ok` after `checkLink` compared nbAccess with limitAccess)
    held: Dict[str, set] = {ret: set((decides or {}).get(read, set()))}
    first: Optional[Tuple[int, set]] = None

    def touched(exp) -> Tuple[bool, set]:
        hit, fields = False, set()
        for n in _value_names(exp):
            parts = str(n).split(".")
            if parts[0] in held:
                hit = True
                fields |= held[parts[0]]
                if len(parts) > 1:
                    fields.add(parts[-1])
        return hit, fields
    params = _lambda_params(ev)
    for ins in _instrs_in_order(proc, ev):
        ln = _line(ins)
        if ln < read or ln >= write:
            continue
        kind = type(ins).__name__
        if kind == "Assign":
            hit, fields = touched(getattr(ins, "exp", None))
            if hit:
                name = str(ins.id).split(".", 1)[0]
                held[name] = held.get(name, set()) | fields
        elif kind == "Call" and id(ins) in params:          # a lambda handed the value read
            for p, a in zip(params[id(ins)], getattr(ins, "args", []) or []):
                hit, fields = touched(a[0] if isinstance(a, tuple) else a)
                if hit:
                    held[p] = held.get(p, set()) | fields
        elif kind == "Call" and _ret_name(ins) and ln > read:
            hit, fields = touched(getattr(ins, "args", None))
            if hit:
                held[_ret_name(ins)] = fields
        elif kind == "Prune":
            hit, fields = touched(getattr(ins, "condition", None))
            if hit:
                if not prefer or fields & prefer:
                    return ln, fields
                first = first or (ln, fields)
    return first


def _verdict(program, proc, line: int, ctx=None, file: str = "",
             callers: Optional[List[Tuple[Any, Any]]] = None, known=None) -> Dict[str, Any]:
    unknown = {"verdict": "unknown", "witness": []}
    name = getattr(proc, "name", "?")
    ev, at = known if known is not None else events(program, proc, ctx=ctx, file=file)
    w = ev.writes.get(int(line))
    if w is None:
        return {**unknown, "reason": f"no write of stored data the engine recognises at line {line}"}
    reads = sorted(ln for ln in ev.reads if 0 < ln < int(line))
    locks = sorted(ln for ln in ev.locks if ln <= int(line))
    if locks and (locks[0] == 0 or not reads or reads[0] >= locks[0]):
        where = locks[0] or "the declaration"
        return {"verdict": "proved", "witness": [],
                "reason": f"a lock or version check ({ev.locks[locks[0]]}) at line {where} comes before "
                          f"the reads the write at line {line} depends on"}
    claim = _claim(proc, ev, at, int(line))
    if claim is not None:
        return {"verdict": "proved", "witness": [],
                "reason": f"the write at line {claim[0]} ({ev.writes[claim[0]].what}) claims what it changes "
                          f"in one step and line {claim[1]} goes on only when it did: one request at a time "
                          f"reaches the reads and the write at line {line}"}
    if w.how == "conditional":
        if "optimistic lock" in w.what:
            return {"verdict": "proved", "witness": [],
                    "reason": f"the write at line {line} is checked against the version it read ({w.what}): "
                              "a concurrent change makes it fail"}
        return {"verdict": "proved", "witness": [],
                "reason": f"the write at line {line} re-checks in its own condition the value it changes "
                          "(the database tests and writes the row in one step)"}
    if not reads:
        return {**unknown, "reason": f"no read of stored data before line {line} in {name} "
                "(it may come from a caller: check the caller)"}
    if locks:
        again = [r for r in reads if r >= locks[0]]
        reread = _reread_under_lock(proc, ev, at, locks[0], int(line))
        if reread is not None:
            return {"verdict": "proved", "witness": [],
                    "reason": f"the lock at line {locks[0]} comes after the read at line {reads[0]}, but that "
                              f"read only chooses what to lock: line {reread} reads again under the lock and "
                              f"the write at line {line} uses only what was read there"}
        return {**unknown, "reason": f"the lock at line {locks[0]} comes after the read at line {reads[0]}"
                + (f"; line {again[0]} reads again under it, so the write is safe if it uses only what "
                   "was read under the lock" if again else ": a value read before it may be stale; re-read "
                   "under the lock")}
    decided = None
    for r in reads:
        decided = _decision(proc, at, r, int(line), ev.decides, prefer=w.fields, ev=ev)
        if decided:
            decided = (r,) + decided
            break
    if w.how == "atomic":
        if decided and decided[2] & w.fields:
            return {"verdict": "refuted",
                    "witness": [{"line": decided[0], "event": "reads stored data"},
                                {"line": decided[1], "event": "decides on " + ", ".join(sorted(decided[2] & w.fields))},
                                {"line": int(line), "event": "writes it atomically, without re-checking"}],
                    "reason": f"the write at line {line} is computed by the database, but line {decided[1]} "
                              f"decided on {', '.join(sorted(decided[2] & w.fields))} as read at line "
                              f"{decided[0]}: two requests can both pass that check (check-then-act); "
                              "make the condition part of the write or lock the row first"}
        if decided and decided[2] and not w.fields:
            return {**unknown, "reason": f"the write at line {line} is computed by the database, but line "
                    f"{decided[1]} decides on {', '.join(sorted(decided[2]))} read at line {decided[0]}; "
                    "if that is what the write changes, two requests can both pass the check"}
        return {"verdict": "proved", "witness": [],
                "reason": f"the write at line {line} is atomic (computed by the database)"}
    earlier_atomic = sorted(ln for ln in ev.atomic_exprs if 0 < ln < int(line))
    if earlier_atomic:
        return {**unknown, "reason": f"an atomic expression at line {earlier_atomic[0]} may compute "
                f"the value written at line {line}: read it"}
    for cprog, cproc in callers or []:
        for _ in range(8):           # a lambda's call is folded into the function it is written in
            parent = (getattr(cprog, "procedures", {}) or {}).get(getattr(cproc, "parent", None) or "")
            if parent is None:
                break
            cproc = parent
        cfile = ""
        if ctx is not None:
            from frame.sil.hunt_tools import _program_file
            cfile = _program_file(cprog, getattr(ctx, "repo_root", ""))
        cev, cat = events(cprog, cproc, ctx=ctx, file=cfile) if ctx is not None else events(cprog, cproc)
        if cev.locks or any(_claim(cproc, cev, cat, ln) for ln in cev.writes):
            return {**unknown, "reason": f"{name} reads at line {reads[0]} and writes at line {line} "
                    f"with no lock, but a caller ({getattr(cproc, 'name', '?')}) takes one or claims first"}
    if not any(e["kind"] in PROTECTIONS for e in entries(program)):
        return {**unknown, "reason": "no [[concurrency]] facts for this language, so the engine "
                "cannot tell a lock from any other call"}
    witness = [{"line": reads[0], "event": f"reads stored data ({ev.reads[reads[0]]})"}]
    if decided:
        on = sorted(decided[2] & w.fields)
        witness.append({"line": decided[1], "event": "decides on " + ", ".join(on) if on else "decides on the value read"})
    witness.append({"line": int(line), "event": "writes it back, no lock, version or atomic update"})
    return {"verdict": "refuted", "witness": witness,
            "reason": f"{name} reads stored data at line {reads[0]} and writes at line {line}; "
                      "nothing in it or its callers locks the row, checks a version or writes atomically"}


def _claim(proc, ev: _Events, at: Dict[int, Any], line: int) -> Optional[Tuple[int, int]]:
    """(claim line, branch line): a conditional write before `line` and before any read (an
    insert of a key only one request can make, a compare-and-set: `findAndModify` upserting a
    fixed id, `INSERT ... ON CONFLICT DO NOTHING`) whose result the code branches on before
    `line` (`if (!claimed) return error`). Only the request that won it goes on, so what follows
    runs one request at a time. None when there is none."""
    reads = [r for r in ev.reads if 0 < r < line]
    calls = [c for c in _calls(proc) if _ret_name(c)]
    for c in sorted(ln for ln, w in ev.writes.items() if 0 < ln < line and w.how == "conditional"
                    and "optimistic lock" not in w.what):
        if any(r < c for r in reads):
            continue
        for made in [at[c]] * (c in at) + [k for k in calls if _line(k) == c]:   # the call whose result says
            decided = _decision(proc, {**at, c: made}, c, line, ev=ev)
            if decided is not None:
                return c, decided[0]
    return None


def _read_names(ins) -> set:
    """Heads of the names an instruction reads: an assignment's value, a call's arguments and
    receiver, a branch's condition, a returned value."""
    kind = type(ins).__name__
    exps: List[Any] = []
    if kind == "Assign":
        exps = [getattr(ins, "exp", None)]
    elif kind == "Call":
        exps = [a[0] if isinstance(a, tuple) else a for a in getattr(ins, "args", []) or []]
    elif kind == "Prune":
        exps = [getattr(ins, "condition", None)]
    elif kind == "Return":
        exps = [getattr(ins, "value", None)]
    out = {str(n).split(".", 1)[0] for e in exps if e is not None for n in _value_names(e)}
    if kind == "Call":
        out.add(_func_text(ins).split(".", 1)[0])
    return out


def _reread_under_lock(proc, ev: _Events, at: Dict[int, Any], lock: int, write: int) -> Optional[int]:
    """The line of a read under the lock when the reads before it only choose what to lock (`ids =
    rows.map(r => r.id)`; lock those rows; read them again): every value read before the lock,
    and every value computed from one, is used after the lock only by the locking statement or
    replaced by a read under it, before the write. None otherwise."""
    before = [r for r in sorted(ev.reads) if 0 < r < lock]
    under = [r for r in sorted(ev.reads) if lock <= r < write and r not in ev.lock_lines]
    if not before or not under:
        return None
    stale: set = set()
    for r in before:
        call = at.get(r)
        ret = _ret_name(call) if call is not None else None
        if not ret:
            return None                               # a read whose value the engine cannot follow
        stale.add(ret)
    reread_rets = {_ret_name(at[r]) for r in under if at.get(r) is not None and _ret_name(at[r])}
    for ins in _instrs_in_order(proc, ev):
        ln = _line(ins)
        if ln < before[0] or ln >= write:
            continue
        kind = type(ins).__name__
        reads = _read_names(ins)
        target = str(getattr(ins, "id", "")).split(".", 1)[0] if kind == "Assign" else _ret_name(ins) or ""
        if ln < lock:
            if reads & stale and target:
                stale.add(target)                     # computed from a value read before the lock
            continue
        if ln in ev.lock_lines:
            continue
        if reads & stale:
            return None                               # a value read before the lock is used after it
        if target and target in stale and (ln in ev.reads or (kind == "Assign" and target in reread_rets)):
            stale.discard(target)                     # replaced by a read under the lock
    return under[0]


def check_atomic_write(program, proc_name: str, line: int,
                       callers: Optional[List[Tuple[Any, Any]]] = None, ctx=None,
                       file: str = "") -> Dict[str, Any]:
    """The `atomic_write` verdict at `line` in `proc_name` (see the module docstring). `callers` are
    (program, procedure) pairs that may call it: a lock or version taken there makes the answer
    unknown rather than refuted, since the engine cannot tell which caller runs. With `ctx` (a
    HuntContext) and the function's `file`, the project functions it calls are followed."""
    proc = (getattr(program, "procedures", {}) or {}).get(proc_name)
    if proc is None:
        return {"verdict": "unknown", "witness": [], "reason": f"no procedure {proc_name!r}"}
    return _verdict(program, proc, int(line), ctx=ctx, file=file, callers=callers)


def _heads(names) -> set:
    return {str(n).split(".", 1)[0].split("[", 1)[0] for n in names}


def _instrs_in_order(proc, ev: Optional[_Events] = None) -> List[Any]:
    """The function's instructions by line, with those of the lambdas folded into `ev`."""
    out = []
    for p in [proc] + [n for _, n in (ev.inlined if ev is not None else [])]:
        for node in (getattr(p, "nodes", {}) or {}).values():
            out += list(getattr(node, "instrs", []) or [])
    return sorted(out, key=_line)


def _lambda_params(ev: Optional[_Events]) -> Dict[int, List[str]]:
    """id(call) -> the parameter names of the lambda an inlined call runs."""
    return {id(c): [str(p) for p, _ in (getattr(n, "params", None) or [])] for c, n in (ev.inlined if ev else [])}


def _refuted_writes(program, proc_name: str, ctx=None, file: str = "") -> List[Dict[str, Any]]:
    proc = (getattr(program, "procedures", {}) or {}).get(proc_name)
    if proc is None or not any(e["kind"] in PROTECTIONS for e in entries(program)):
        return []
    known = events(program, proc, ctx=ctx, file=file)
    out = []
    for w in sorted(known[0].writes):
        if w <= 0:
            continue
        r = _verdict(program, proc, w, ctx=ctx, file=file, known=known)
        if r["verdict"] == "refuted":
            out.append(dict(r, line=w))
    return out


def unprotected_read_writes(program, proc_name: str, ctx=None, file: str = "") -> List[Tuple[int, int]]:
    """(read line, write line) pairs in `proc_name` that `check_atomic_write` would refute when no
    caller protects them: what the hunt's `race` class ranks a unit by. Callers are not asked
    (ranking only; the check itself asks them)."""
    return [(r["witness"][0]["line"], r["line"]) for r in _refuted_writes(program, proc_name, ctx, file)]


def decided_read_writes(program, proc_name: str, ctx=None, file: str = "") -> List[Tuple[int, int, int]]:
    """(read, decision, write) lines: an unprotected read-then-write whose code branches on the
    value it read before writing (`c = get(...)`; `if c.uses < c.limit:`; `c.save()`), the
    check-then-act shape two concurrent requests both pass. The read's value is followed
    through copies and values computed from it (`left = c.limit - c.uses`)."""
    out = []
    for r in _refuted_writes(program, proc_name, ctx, file):
        if len(r["witness"]) >= 3:
            out.append((r["witness"][0]["line"], r["witness"][1]["line"], r["line"]))
    return out
