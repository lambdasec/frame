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
SUMMARY_DEPTH = 3
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
    held = {c for k in (keys or ()) for c in str(k).split(".")}
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
    if word in ("SELECT", "WITH", "SHOW", "EXPLAIN"):
        out.update(write=False, read=True)
        if word == "SELECT" and _FOR_UPDATE.search(sql):
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


def _matching(program, names: List[str], table, call=None, proc=None) -> List[Dict[str, Any]]:
    """Every entry the call meets (`keys`, `self_reference` checked against it)."""
    from frame.sil.packs.apply import _glob
    qualified = _qualified(program, [n for n in names if n])
    held = {c for k in (getattr(call, "literal_keys", None) or ()) for c in str(k).split(".")}
    out = []
    for e in table:
        if e.get("keys") and not (held & set(e["keys"])):
            continue
        if e.get("self_reference") and (call is None or not _self_referencing(call, proc)):
            continue
        if _glob(e.get("call", []), *qualified):
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


def _selected_fields(selectors: Iterable[str], call, chain: List[Any]) -> set:
    """The fields a write states under `selectors`: an argument position (`"1"`: the update
    document of `update_one(filter, update)`), a key at the top of an object argument
    (`"where"`, `"data"`), or, with a leading dot, a call of the chain by its method
    (`".set"`, `".where"`)."""
    out: set = set()
    for s in selectors:
        if s.startswith("."):
            for link in _links(s[1:], chain):
                out |= _call_fields(link)
            continue
        for path in getattr(call, "literal_keys", None) or []:
            comps = str(path).split(".")
            if comps[0] == s:
                out |= set(comps[1:])
            elif len(comps) > 1 and comps[1] == s:
                out |= set(comps[2:])
    return {f for f in out if f and not f.startswith("$") and not f.isdigit()}


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
    __slots__ = ("how", "fields", "what")

    def __init__(self, how: str, fields: set, what: str):
        self.how, self.fields, self.what = how, set(fields), what

    def merge(self, other: "_Write") -> None:
        if STRENGTH[other.how] > STRENGTH[self.how]:
            self.how, self.what = other.how, other.what
        self.fields |= other.fields


class _Events:
    """What a function does with stored data, by line: reads, writes (how strong, which fields),
    locks (0 is the declaration), and atomic expressions not at a write (`n = F("n") + 1`)."""

    def __init__(self):
        self.reads: Dict[int, str] = {}
        self.writes: Dict[int, _Write] = {}
        self.locks: Dict[int, str] = {}
        self.atomic_exprs: Dict[int, str] = {}
        self.decides: Dict[int, set] = {}      # line of a call -> fields the callee branches on

    def write(self, line: int, w: _Write) -> None:
        if line in self.writes:
            self.writes[line].merge(w)
        else:
            self.writes[line] = w


def _statement(program, proc, ins, chain, table, ctx=None) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """The entries a call's statement meets (every call of its chain, and calls nested in their
    arguments) and the SQL effect of its own statement text."""
    found = []
    classes = _class_table(ctx, program) if any(
        getattr(c, "canonical", None) is None for c in chain) else {}
    for link in chain:
        names = _names(link) + _typed_names(program, proc, link, classes)
        found += [dict(e, _chain=chain, _call=link)
                  for e in _matching(program, names, table, call=link, proc=proc)]
        for a in getattr(link, "args", []) or []:
            found += _nested_entries(program, proc, a[0] if isinstance(a, tuple) else a, table)
    return found, _sql_of(program, proc, ins)


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


def _versioned(classes, name: str) -> bool:
    """Does class `name` carry a field with a version annotation of the packs (`@Version`,
    `[ConcurrencyCheck]`, `[Timestamp]`)?"""
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


def _version_protected(proc, chain, classes) -> Optional[set]:
    """The entities a write saves, when every one carries a version field: the class-typed
    arguments of its calls (`repo.save(coupon)`), else, for a call that saves the tracked
    entities (`SaveChanges()`), the entities the function read. None when not protected."""
    saved = {t for c in chain for t in (getattr(c, "arg_types", None) or []) if t and _type_name(t) in classes}
    saved = {_type_name(t) for t in saved}
    if not saved and not any(getattr(c, "args", None) for c in chain):
        saved = _read_entities(proc, classes)
    if saved and all(_versioned(classes, s) for s in saved):
        return saved
    return None


def _direct_events(program, proc, table, ctx=None) -> Tuple[_Events, Dict[int, Any]]:
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
        found, _ = _statement(program, proc, ins, chain, table, ctx)
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
        tail = _tail(chain, proc)
        if "read" in kinds or any(x in ev.reads for x in lines):
            label = _names(tail)[0] if _names(tail) else "a read"      # its callee id when known
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
                fields |= _selected_fields(e["update"], call, sel_chain)
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
                if _selected_fields(e["filter"], call, sel_chain) & _selected_fields(e["update"], call, sel_chain):
                    how = "conditional"
        w = _Write(how, fields, _names(ins)[-1] if _names(ins) else "a write")
        if how != "conditional" and any(e["kind"] == "version" for e in table):
            versioned = _version_protected(proc, chain, _class_table(ctx, program))
            if versioned:
                w.how = "conditional"
                w.what = f"{w.what} (optimistic lock: {', '.join(sorted(versioned))} carries a version field)"
        for x in lines:
            ev.write(x, _Write(w.how, w.fields, w.what))
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
        cur = _Write(how, w.fields, f"{name} ({w.what})")
        if write is None or STRENGTH[cur.how] < STRENGTH[write.how]:
            fields = (write.fields if write else set()) | cur.fields
            write = cur
            write.fields = fields
        else:
            write.fields |= cur.fields
    # the fields it (and what it calls) branches on: a value it returns may carry the outcome of
    # such a check (`checkLink` comparing `link.nbAccess` with `link.limitAccess`)
    decides = set(_branch_fields(proc))
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
    ev, at = _direct_events(program, proc, table, ctx)
    if ctx is None or depth >= SUMMARY_DEPTH or not hasattr(ctx, "graph"):
        return ev, at
    try:
        _, calls = ctx.graph()
        listed = calls.get((file, proc.name)) or []
    except Exception:
        listed = []
    by_line: Dict[int, Any] = {}
    for ins in _calls(proc):
        by_line.setdefault(_line(ins), ins)
    for callee, ln in listed[:80]:
        try:
            d = ctx.resolve_call(file, proc.name, callee)
        except Exception:
            d = None
        if d is None or (d["file"], d["name"]) == (file, proc.name):
            continue
        s = _summary(ctx, d["file"], d["name"], depth + 1)
        if not s:
            continue
        if s["reads"]:
            ev.reads.setdefault(ln, s["name"])
            if ln in by_line:
                at.setdefault(ln, by_line[ln])
        if s["write"] is not None:
            ev.write(ln, _Write(s["write"].how, s["write"].fields, s["write"].what))
        if s["lock"]:
            ev.locks.setdefault(ln, s["name"])
        if s.get("decides"):
            ev.decides.setdefault(ln, set()).update(s["decides"])
            if ln in by_line:
                at.setdefault(ln, by_line[ln])
    return ev, at


# -- the verdict -------------------------------------------------------------------------------

def _decision(proc, at: Dict[int, Any], read: int, write: int,
              decides: Optional[Dict[int, set]] = None) -> Optional[Tuple[int, set]]:
    """(line, fields) of the first branch between `read` and `write` on the value the read
    produced (followed through copies and values computed from it), with the attributes of it
    the branch reads (`c.uses < c.limit` -> uses, limit; `left > 0` with `left = c.limit - c.uses`
    -> limit, uses; `!c` -> none)."""
    call = at.get(read)
    ret = _ret_name(call) if call is not None else None
    if not ret:
        return None
    # a value a project function returns carries the fields it decided on (`linkEnv` returning
    # `ok` after `checkLink` compared nbAccess with limitAccess)
    held: Dict[str, set] = {ret: set((decides or {}).get(read, set()))}

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
    for ins in _instrs_in_order(proc):
        ln = _line(ins)
        if ln < read or ln >= write:
            continue
        kind = type(ins).__name__
        if kind == "Assign":
            hit, fields = touched(getattr(ins, "exp", None))
            if hit:
                name = str(ins.id).split(".", 1)[0]
                held[name] = held.get(name, set()) | fields
        elif kind == "Call" and _ret_name(ins) and ln > read:
            hit, fields = touched(getattr(ins, "args", None))
            if hit:
                held[_ret_name(ins)] = fields
        elif kind == "Prune":
            hit, fields = touched(getattr(ins, "condition", None))
            if hit:
                return ln, fields
    return None


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
        return {**unknown, "reason": f"the lock at line {locks[0]} comes after the read at line {reads[0]}"
                + (f"; line {again[0]} reads again under it, so the write is safe if it uses only what "
                   "was read under the lock" if again else ": a value read before it may be stale; re-read "
                   "under the lock")}
    decided = None
    for r in reads:
        decided = _decision(proc, at, r, int(line), ev.decides)
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
        cev, _ = events(cprog, cproc)
        if cev.locks:
            return {**unknown, "reason": f"{name} reads at line {reads[0]} and writes at line {line} "
                    f"with no lock, but a caller ({getattr(cproc, 'name', '?')}) takes one"}
    if not any(e["kind"] in PROTECTIONS for e in entries(program)):
        return {**unknown, "reason": "no [[concurrency]] facts for this language, so the engine "
                "cannot tell a lock from any other call"}
    witness = [{"line": reads[0], "event": f"reads stored data ({ev.reads[reads[0]]})"}]
    if decided:
        witness.append({"line": decided[1], "event": "decides on the value read"})
    witness.append({"line": int(line), "event": "writes it back, no lock, version or atomic update"})
    return {"verdict": "refuted", "witness": witness,
            "reason": f"{name} reads stored data at line {reads[0]} and writes at line {line}; "
                      "nothing in it or its callers locks the row, checks a version or writes atomically"}


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


def _instrs_in_order(proc) -> List[Any]:
    out = []
    for node in (getattr(proc, "nodes", {}) or {}).values():
        out += list(getattr(node, "instrs", []) or [])
    return sorted(out, key=_line)


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
