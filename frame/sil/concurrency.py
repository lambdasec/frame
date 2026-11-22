"""Read-then-write races as an engine check (the business-logic hunt's `race` class).

`check(name, line, kind="atomic_write")` at a write of stored data asks whether two requests
running it at the same moment can both act on the same old value:

  proved   the write is atomic (`F("n") + 1`, `increment(...)`) or a lock is taken before it in
           the function (`select_for_update`, `with_for_update`, `EntityManager.lock`);
  refuted  the function reads stored data before the write, and neither it nor any function that
           calls it takes a lock, versions the row or writes atomically;
  unknown  anything else: no write the engine recognises at the line, no read before it, or a
           protection somewhere the engine cannot place (a caller of the same name).

What protects is pack data (`[[concurrency]]`: `kind` lock / atomic / version, `call` ids), so
the check knows nothing about any library. A transaction alone is not a protection: at the
default isolation level the second request still reads the old value. Never changes a finding.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

READS = frozenset({"resource_select", "sql", "nosql", "orm", "resource_modify"})
WRITES = frozenset({"resource_modify", "sql", "nosql", "orm"})
KINDS = ("lock", "atomic", "version", "read")
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


def _kind_of(program, names: List[str], table: List[Dict[str, Any]]) -> Optional[str]:
    from frame.sil.packs.apply import _glob
    imports = {k: str(v) for k, v in (getattr(program, "imports", None) or {}).items()}
    qualified = list(names)
    for n in names:                                  # `F("n")` with `from django.db.models import F`
        head, _, rest = n.partition(".")
        if head in imports:
            qualified.append(f"{imports[head]}.{rest}" if rest else imports[head])
    for e in table:
        if _glob(e.get("call", []), *qualified):
            return e["kind"]
    return None


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
        kind = _kind_of(program, _names(ins), table)
        if kind:
            found.append((_line(ins), kind))
        for a in getattr(ins, "args", []) or []:
            k = _kind_of(program, list(_nested_calls(a)), table)
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
    writes = [ins for ins in _calls(proc) if _line(ins) == int(line) and (
        _data_kind(program, ins) in WRITES)]
    if not writes:
        return {**unknown, "reason": f"no write of stored data the engine recognises at line {line}"}
    here = _protections(program, proc, table)
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
    if not any(e["kind"] != "read" for e in table):
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
    if not any(e["kind"] != "read" for e in table):
        return []
    here = _protections(program, proc, table)
    if any(k in ("lock", "version") for _, k in here):
        return []
    atomic = {ln for ln, k in here if k == "atomic"}
    reads = sorted({ln for ln, k in here if k == "read" and ln > 0} |
                   {_line(i) for i in _calls(proc) if _line(i) > 0 and _data_kind(program, i) in READS})
    out = []
    for w in sorted({_line(i) for i in _calls(proc) if _data_kind(program, i) in WRITES}):
        if w in atomic or any(a < w for a in atomic):
            continue
        earlier = [r for r in reads if r < w]
        if earlier:
            out.append((earlier[0], w))
    return out
