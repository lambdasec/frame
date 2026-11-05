"""Guard facts for the agentic authorization hunt: which conditions hold on every feasible
path to a line, and whether a claim about them is proved or refuted.

The hunt agent used to read source text to decide whether a handler checks ownership before
it deletes. The engine already walks every feasible path; this module keeps what that walk saw
so the agent can ask instead of guess. The translator records, on its reporting pass only and
without touching any finding (`SILTranslator._record_path_guards`):

  - the CFG edges the walk followed (an edge the solver proved infeasible is never followed, so
    the facts below are over feasible paths),
  - the nodes where a path ended (`return`, `raise`, a never-returning call such as `abort`),
  - which branch conditions compared a resource's field with the authenticated caller,
  - for each resource operation, whether it was scoped by the caller's identity on every visit,
  - the procedure's authorization-gate decorators of an applied pack (`[[auth_gate]]`).

`summarise` turns that into a must-analysis over the followed edges: a branch condition holds at
a point only if it holds on EVERY incoming path (intersection at joins), and it stops holding once
a variable it reads is written. An early exit makes the opposite condition hold below it, which is
how `if doc.owner != user: abort(403)` guards the code after it. `guards_at` reads the per-line
facts; `check_claim` decides a claim by searching for a feasible path that avoids it.

Pure bookkeeping: nothing here is read by the analysis, so findings never depend on it. Every
query returns an empty / "unknown" answer instead of raising."""

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

MAX_ATOMS = 32              # facts kept per line
MAX_SEARCH_STATES = 20000   # bound on the witness search

KINDS = ("branch", "ownership", "identity_scope", "decorator", "noreturn_guard")


# ---- recording (called by the translator) -------------------------------------------------

def _strip_parens(text: str) -> str:
    """`(a != b)` -> `a != b`, only when the outer pair encloses the whole text."""
    if len(text) >= 2 and text[0] == "(" and text[-1] == ")":
        depth = 0
        for i, ch in enumerate(text):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0 and i < len(text) - 1:
                return text
        return text[1:-1]
    return text


def _exp_vars_and_calls(exp) -> Tuple[frozenset, Tuple[str, ...]]:
    """The variables a condition reads (its facts die when one is written) and the functions it
    calls (`has_perm`, so a claim can name the check by its function)."""
    from frame.sil.translator import SILTranslator
    from frame.sil.types import ExpCall
    try:
        names = set(exp.free_vars())
    except Exception:
        names = set()
    calls, stack, seen = [], [exp], 0
    while stack and seen < 2000:
        seen += 1
        e = stack.pop()
        if isinstance(e, ExpCall):
            fname = str(getattr(e, "func", "") or "").strip('"')
            if fname:
                calls.append(fname)
                calls.append(fname.rsplit(".", 1)[-1])
            stack.extend(a for a in (getattr(e, "args", None) or []) if a is not None)
            continue
        try:
            stack.extend(c for c in SILTranslator._walk_children(e) if c is not None)
        except Exception:
            break
    return frozenset(names), tuple(dict.fromkeys(calls))


def _exit_text(instr) -> str:
    """How a path ended: `return x`, or the never-returning call (`abort(403)`)."""
    from frame.sil.instructions import Call, Return
    if isinstance(instr, Return):
        v = getattr(instr, "value", None)
        return "return" + (f" {v}" if v is not None else "")
    if isinstance(instr, Call):
        name = instr.get_full_name().strip('"') if hasattr(instr, "get_full_name") else str(instr.func)
        args = ", ".join(str(a) for a, _ in (getattr(instr, "args", None) or []))
        return f"{name}({args})"
    return "exit"


def summarise(proc, walk: Dict[str, Any], edge_condition: Callable[[Any], Any]) -> Dict[str, Any]:
    """Per-line must-facts for one procedure from the translator's walk record (`walk`: the
    followed `edges` {(src, succ_index, dst)}, `terms` {node: instr index where the path ended},
    `owner` {(line, str(cond))} ownership comparisons, `scoped`/`resource` {line: ...}, `gates`).
    `edge_condition(node)` is the translator's clean-two-way-branch condition (or None)."""
    from frame.sil.instructions import Prune
    nodes = proc.nodes
    edges = walk.get("edges") or set()
    terms = walk.get("terms") or {}
    owner = walk.get("owner") or set()
    atoms: Dict[str, Dict[str, Any]] = {}

    def atom(cond, holds: bool, line: int, exit_txt: str = "") -> str:
        ct = _strip_parens(str(cond))
        key = f"{line}:{int(holds)}:{ct}"
        if key not in atoms:
            shown = ct if holds else f"not ({ct})"
            if exit_txt:
                # the branch NOT taken here ends the path: render the check the way it is written
                text = f"{ct if not holds else f'not ({ct})'} -> {exit_txt}"
                kind = "noreturn_guard"
            else:
                text, kind = shown, "branch"
            if (line, str(cond)) in owner:
                kind = "ownership"
            names, calls = _exp_vars_and_calls(cond)
            atoms[key] = {"line": line, "text": text, "kind": kind, "cond": ct,
                          "holds": holds, "vars": names, "calls": calls}
        return key

    def line_of(instr) -> int:
        return getattr(getattr(instr, "loc", None), "line", 0) or 0

    def ends_path(nid) -> str:
        """Exit text if the node `nid` ends every path through it, else ''."""
        if nid in terms and nid in nodes:
            ins = nodes[nid].instrs
            i = terms[nid]
            if 0 <= i < len(ins):
                return _exit_text(ins[i])
        return ""

    edge_atoms: Dict[Tuple[int, int], str] = {}
    for src, idx, _dst in edges:
        node = nodes.get(src)
        if node is None or idx not in (0, 1):
            continue
        cond = edge_condition(node)
        if cond is None:
            continue
        prune = next((i for i in node.instrs if isinstance(i, Prune)), None)
        line = line_of(prune) if prune is not None else 0
        succs = list(node.succs)
        other = succs[1 - idx] if len(succs) > 1 else None
        edge_atoms[(src, idx)] = atom(cond, idx == 0, line, ends_path(other) if other is not None else "")

    prune_atoms: Dict[Tuple[int, int], str] = {}
    for nid, node in nodes.items():
        if edge_condition(node) is not None:
            continue                    # a clean two-way branch: its conditions ride on the edges
        for i, ins in enumerate(node.instrs):
            if isinstance(ins, Prune):
                prune_atoms[(nid, i)] = atom(ins.condition, bool(ins.is_true_branch), line_of(ins))

    record = {"entry": proc.entry_node, "edges": sorted(edges), "terms": dict(terms),
              "atoms": atoms, "edge_atoms": edge_atoms, "prune_atoms": prune_atoms,
              "gates": list(walk.get("gates") or []), "scoped": dict(walk.get("scoped") or {}),
              "resource": dict(walk.get("resource") or {}), "lines": {},
              # Whether the walk saw the authenticated caller at all (translator._identity_in_proc).
              "identity_seen": bool(walk.get("identity_seen"))}

    # Must-analysis: IN[n] = intersection over followed incoming edges.
    out_edges = _out_edges(record)
    IN: Dict[int, frozenset] = {proc.entry_node: frozenset()}
    work = [proc.entry_node]
    steps = 0
    while work and steps < 100000:
        steps += 1
        n = work.pop()
        if n not in nodes:
            continue
        s, ended = _transfer(record, nodes[n], n, IN[n])
        if ended:
            continue
        for idx, d in out_edges.get(n, ()):
            k = edge_atoms.get((n, idx))
            s2 = s | {k} if k else s
            old = IN.get(d)
            new = s2 if old is None else (old & s2)
            if new != old:
                IN[d] = new
                work.append(d)

    lines: Dict[int, frozenset] = {}

    def note(line: int, facts: frozenset) -> None:
        if line:
            lines[line] = facts if line not in lines else (lines[line] & facts)

    for n, s in IN.items():
        if n in nodes:
            _transfer(record, nodes[n], n, s, note)
    record["lines"] = {ln: sorted(ks, key=lambda k: (atoms[k]["line"], k))[:MAX_ATOMS]
                       for ln, ks in lines.items()}
    return record


def _out_edges(record) -> Dict[int, List[Tuple[int, int]]]:
    out: Dict[int, List[Tuple[int, int]]] = {}
    for src, idx, dst in record["edges"]:
        out.setdefault(src, []).append((idx, dst))
    return out


def _written(instr) -> set:
    try:
        return set(instr.get_written_vars() or ())
    except Exception:
        return set()


def _transfer(record, node, nid, facts: frozenset,
              note: Optional[Callable[[int, frozenset], None]] = None) -> Tuple[frozenset, bool]:
    """Run one node over a fact set: report the facts before each instruction (`note`), drop the
    facts whose variables an instruction writes, add a single-edge prune's condition, stop where
    the path ends. Returns (facts at the node's exit, path ended)."""
    atoms = record["atoms"]
    end = record["terms"].get(nid)
    for i, ins in enumerate(node.instrs):
        if note is not None:
            note(getattr(getattr(ins, "loc", None), "line", 0) or 0, facts)
        w = _written(ins)
        if w:
            facts = frozenset(k for k in facts if not (atoms[k]["vars"] & w))
        pk = record["prune_atoms"].get((nid, i))
        if pk:
            facts = facts | {pk}
        if end == i:
            return facts, True
    return facts, False


# ---- queries (called by the hunt) ---------------------------------------------------------

def _record(program, proc_name: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """The recorded facts of `proc_name`, by exact name or, failing that, a unique match on the
    last part (`notifications` for `UserViewSet.notifications`)."""
    pg = getattr(program, "path_guards", None) or {}
    if proc_name in pg:
        return proc_name, pg[proc_name]
    simple = (proc_name or "").rsplit("::", 1)[-1].rsplit(".", 1)[-1]
    hits = [n for n in pg if n.rsplit("::", 1)[-1].rsplit(".", 1)[-1] == simple
            or n.endswith("." + proc_name) or n.endswith("::" + proc_name)]
    if len(hits) == 1:
        return hits[0], pg[hits[0]]
    return None, None


def _resolve_line(record, line: int) -> Optional[int]:
    """`line` if the walk saw an instruction there, else the closest one up to two lines above
    (a statement spanning lines is recorded at its first line)."""
    for ln in (line, line - 1, line - 2):
        if ln in record["lines"]:
            return ln
    return None


def _public(a: Dict[str, Any]) -> Dict[str, Any]:
    return {"line": a["line"], "text": a["text"], "kind": a["kind"]}


def guards_at(program, proc_name: str, line: int) -> List[Dict[str, Any]]:
    """The conditions that hold on every feasible path reaching `line` in `proc_name`: branch
    conditions (`kind` branch / ownership / noreturn_guard), the procedure's authorization-gate
    decorators (decorator), and the caller-identity scoping of a resource operation at that line
    (identity_scope). [] when the engine has no facts there."""
    try:
        _, rec = _record(program, proc_name)
        if rec is None:
            return []
        ln = _resolve_line(rec, int(line))
        if ln is None:
            return []
        out = [_public(rec["atoms"][k]) for k in rec["lines"][ln]]
        out += [dict(g) for g in rec["gates"]]
        if rec["scoped"].get(ln):
            out.append({"line": ln, "kind": "identity_scope",
                        "text": f"{rec['resource'].get(ln, 'resource operation')} is filtered by the caller's identity"})
        return out[:MAX_ATOMS]
    except Exception:
        return []


def sink_lines(program, proc_name: str) -> List[int]:
    """Lines of the procedure's taint sinks and resource operations, in order."""
    try:
        from frame.sil.instructions import TaintSink
        name, rec = _record(program, proc_name)
        proc = (getattr(program, "procedures", None) or {}).get(name or proc_name)
        out = set((rec or {}).get("resource", {}) or {})
        if proc is not None:
            for node in proc.nodes.values():
                for ins in node.instrs:
                    if isinstance(ins, TaintSink):
                        ln = getattr(getattr(ins, "loc", None), "line", 0)
                        if ln:
                            out.add(ln)
        return sorted(out)
    except Exception:
        return []


def _matcher(pattern: str) -> Callable[[str], bool]:
    p = (pattern or "").strip()
    try:
        rx = re.compile(p, re.IGNORECASE)
        return lambda s: bool(rx.search(s or "")) or p.lower() in (s or "").lower()
    except re.error:
        return lambda s: p.lower() in (s or "").lower()


def _matches(a: Dict[str, Any], m: Callable[[str], bool]) -> bool:
    return m(a["text"]) or m(a["cond"]) or any(m(c) for c in a["calls"])


def _search(program, proc_name: str, rec, target: int,
            guard: Callable[[str], bool]) -> Tuple[bool, Optional[List[Dict[str, Any]]]]:
    """Search the followed edges for a path that reaches `target` while no fact satisfying
    `guard` (a predicate over fact keys) holds. Returns (target reached at all, witness or None).
    The witness is the branch decisions along the path."""
    proc = (getattr(program, "procedures", None) or {}).get(proc_name)
    if proc is None:
        return False, None
    nodes, atoms = proc.nodes, rec["atoms"]
    out_edges = _out_edges(rec)
    start = (rec["entry"], frozenset(), ())
    seen = {(rec["entry"], frozenset())}
    queue = [start]
    reached = False
    while queue and len(seen) < MAX_SEARCH_STATES:
        nid, live, path = queue.pop(0)
        node = nodes.get(nid)
        if node is None:
            continue
        end = rec["terms"].get(nid)
        ended = False
        for i, ins in enumerate(node.instrs):
            if (getattr(getattr(ins, "loc", None), "line", 0) or 0) == target:
                reached = True
                if not live:
                    return True, list(path) + [{"line": target, "took": "reached"}]
            w = _written(ins)
            if w:
                live = frozenset(k for k in live if not (atoms[k]["vars"] & w))
            pk = rec["prune_atoms"].get((nid, i))
            if pk and guard(pk):
                live = live | {pk}
            if end == i:
                ended = True
                break
        if ended:
            continue
        for idx, d in out_edges.get(nid, ()):
            k = rec["edge_atoms"].get((nid, idx))
            live2 = live | {k} if (k and guard(k)) else live
            step = path + (({"line": atoms[k]["line"], "took": "then" if idx == 0 else "else",
                             "cond": atoms[k]["cond"]},) if k else ())
            if (d, live2) not in seen:
                seen.add((d, live2))
                queue.append((d, live2, step))
    return reached, None


def check_claim(program, proc_name: str, line: int, claim: Dict[str, Any]) -> Dict[str, Any]:
    """Decide a claim about `line` in `proc_name`:
      {"kind": "guarded_by", "pattern": p}: every feasible path to `line` passes a condition (or a
        gate decorator) whose text or called function matches `p` (case-insensitive regex or
        substring) -> proved; a feasible path avoids it -> refuted, with that path as witness.
      {"kind": "scoped_by_identity"}: the resource operation at `line` is filtered by the
        caller's identity -> proved; it is not -> refuted, but only when the engine saw the caller's
        identity in the procedure (otherwise it cannot tell, -> unknown).
    "unknown" when the engine has no facts at that line. Matching is by text: the facts carry
    their polarity (`not (...)`, `... -> abort(403)`), so read them, not just the verdict."""
    unknown = {"verdict": "unknown", "witness": []}
    try:
        name, rec = _record(program, proc_name)
        if rec is None:
            return {**unknown, "reason": f"no recorded facts for procedure {proc_name!r}"}
        ln = _resolve_line(rec, int(line))
        if ln is None:
            return {**unknown, "reason": f"no instruction the engine walked at line {line}"}
        kind = str((claim or {}).get("kind", ""))
        if kind == "scoped_by_identity":
            if ln not in rec["scoped"]:
                return {**unknown, "reason": f"no resource operation the engine recognises at line {ln}"}
            op = rec["resource"].get(ln, "resource operation")
            if rec["scoped"][ln]:
                return {"verdict": "proved", "witness": [],
                        "reason": f"{op} at line {ln} is filtered by the caller's identity on every path"}
            if not rec.get("identity_seen"):
                # The engine never saw how this app identifies the caller, so it cannot tell an
                # unscoped query from one filtered by an identity it does not recognise (aegra's
                # `RunORM.user_id == user.identity` from a FastAPI dependency read as "refuted").
                return {**unknown, "reason": f"{op} at line {ln}: the engine does not recognise how "
                        "this app identifies the caller (no identity source in this procedure); "
                        "read the filter, or teach an [[identity]] source"}
            _, witness = _search(program, name, rec, ln, lambda k: False)
            return {"verdict": "refuted", "witness": witness or [],
                    "reason": f"{op} at line {ln} is not filtered by the caller's identity"}
        if kind == "guarded_by":
            m = _matcher(str(claim.get("pattern", "")))
            gates = [g for g in rec["gates"] if m(g["text"])]
            if gates:
                return {"verdict": "proved", "witness": [],
                        "reason": f"gate decorator {gates[0]['text']} applies to the whole procedure"}
            guard = (lambda k: _matches(rec["atoms"][k], m))
            reached, witness = _search(program, name, rec, ln, guard)
            if witness is not None:
                return {"verdict": "refuted", "witness": witness,
                        "reason": f"a feasible path reaches line {ln} without a condition matching "
                                  f"{claim.get('pattern')!r}"}
            if not reached:
                return {**unknown, "reason": f"line {ln} is not reached on the paths the engine walked"}
            held = [rec["atoms"][k]["text"] for k in rec["lines"].get(ln, []) if guard(k)]
            return {"verdict": "proved", "witness": [],
                    "reason": "every feasible path to line %d passes %s" % (
                        ln, "; ".join(held) if held else f"a condition matching {claim.get('pattern')!r}")}
        return {**unknown, "reason": f"unsupported claim kind {kind!r} (guarded_by, scoped_by_identity)"}
    except Exception as exc:
        return {**unknown, "reason": f"engine could not decide: {type(exc).__name__}"}
