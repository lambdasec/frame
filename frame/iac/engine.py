"""Deciding a policy on a resource: its `when` formula over the resource's values, in Z3.

Values come from the configuration as written. Most are known (a YAML scalar, a Terraform
literal); some are not (`Unknown`: a Terraform variable with no value, an attribute another
resource computes). Each unknown is one Z3 constant, named by what it stands for, so the same
unknown in two places is the same value. A formula over known values folds to true or false
without the solver; otherwise the verdict is the solver's:

* ``fail``      the configuration entails the violation (unsat(C & not V)): whatever the unknowns
                are, the resource is misconfigured;
* ``undecided`` the violation is possible but not entailed (sat(C & V)): it depends on values the
                files do not give;
* ``pass``      the violation is impossible.

C is what the configuration says about its unknowns (none yet for Kubernetes). Only ``fail``
is a finding; ``undecided`` is reported apart, never as a finding.

Every result also carries the paths that decided it (the container that sets `privileged`, the
volume that is a `hostPath`), so a finding points at the line that causes it.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import z3

from .policy import (BoolOp, Compare, Default, Expr, Internet, Literal, Not, Path, Present, Quantifier,
                     StartsWith)

DocPath = Tuple[Union[str, int], ...]
RELATED = "resources"                # `some p in resources["aws_s3_bucket_acl"]: ...`


@dataclass(frozen=True)
class Unknown:
    """A value the configuration does not give. Equal keys are the same value."""
    key: str
    text: str = ""

    def child(self, step) -> "Unknown":
        return Unknown(f"{self.key}.{step}" if isinstance(step, str) else f"{self.key}[{step}]",
                       self.text)


@dataclass(frozen=True)
class _Absent:
    """A path with no value; `at` is its deepest ancestor that exists."""
    at: DocPath


@dataclass(frozen=True)
class _Bound:
    value: Any
    path: DocPath


@dataclass
class Subject:
    """What a policy is evaluated against: the resource's document and its named views (a view
    is a path into the document, or a list of paths for a collection such as `containers`)."""
    document: Any
    views: Dict[str, Union[DocPath, List[DocPath]]]
    constraints: List[Any] = field(default_factory=list)      # Z3 facts about the unknowns
    related: Dict[str, List[Any]] = field(default_factory=dict)   # `resources["type"]`: other documents


@dataclass
class Verdict:
    outcome: str                     # fail / undecided / pass
    evidence: str = "matched"        # matched (folded) or solver-verified (needed Z3)
    why: Tuple[DocPath, ...] = ()    # document paths that decided it
    unknowns: Tuple[str, ...] = ()   # what the solver had no value for (`var.partner_cidr`)


Val = Union[bool, z3.BoolRef]


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _get(doc: Any, path: DocPath) -> Any:
    for s in path:
        doc = doc[s]
    return doc


def _and(parts: Sequence[Val]) -> Val:
    sym = []
    for p in parts:
        if p is False:
            return False
        if p is not True:
            sym.append(p)
    return True if not sym else (sym[0] if len(sym) == 1 else z3.And(*sym))


def _or(parts: Sequence[Val]) -> Val:
    sym = []
    for p in parts:
        if p is True:
            return True
        if p is not False:
            sym.append(p)
    return False if not sym else (sym[0] if len(sym) == 1 else z3.Or(*sym))


def _not(v: Val) -> Val:
    return (not v) if isinstance(v, bool) else z3.Not(v)


def _sort_of(value):
    if isinstance(value, bool):
        return z3.BoolSort()
    if isinstance(value, int):
        return z3.IntSort()
    if isinstance(value, float):
        return z3.RealSort()
    if isinstance(value, str):
        return z3.StringSort()
    return None


def _z3_const(u: Unknown, sort) -> z3.ExprRef:
    return z3.Const(f"{u.key}:{sort}", sort)


def _z3_val(value, sort):
    if sort == z3.BoolSort():
        return z3.BoolVal(value)
    if sort == z3.IntSort():
        return z3.IntVal(value)
    if sort == z3.RealSort():
        return z3.RealVal(value)
    return z3.StringVal(value)


class _Evaluator:
    def __init__(self, subject: Subject):
        self.subject = subject
        self.fresh = itertools.count()
        self.unknowns: set = set()

    def _note(self, u: "Unknown") -> None:
        self.unknowns.add(u.text if u.text and u.text not in ("error", "cycle", "too deep") else u.key)

    # -- values ---------------------------------------------------------------------------

    def resolve(self, path: Path, env: Dict[str, Any]) -> Union[_Bound, _Absent, Unknown]:
        if path.root in env:
            start = env[path.root]
        else:
            view = self.subject.views.get(path.root)
            if view is None or isinstance(view, list):
                raise KeyError(path.root)
            start = self._at(view)
        cur = start
        for step in path.steps:
            if isinstance(cur, Unknown):
                cur = cur.child(step)
                continue
            if isinstance(cur, _Absent):
                return cur
            v = cur.value
            if isinstance(v, Unknown):
                cur = v.child(step)
                continue
            if isinstance(step, int):
                ok = isinstance(v, list) and -len(v) <= step < len(v)
            else:
                ok = isinstance(v, dict) and step in v
            if not ok:
                return _Absent(cur.path)
            nxt = v[step]
            cur = _Bound(nxt, cur.path + (step,)) if nxt is not None else _Absent(cur.path)
        if isinstance(cur, _Bound) and isinstance(cur.value, Unknown):
            return cur.value
        return cur

    def _at(self, path: DocPath) -> Union[_Bound, _Absent]:
        doc, walked = self.subject.document, ()
        for s in path:
            if isinstance(doc, dict) and s in doc and doc[s] is not None:
                doc, walked = doc[s], walked + (s,)
            elif isinstance(doc, list) and isinstance(s, int) and 0 <= s < len(doc):
                doc, walked = doc[s], walked + (s,)
            else:
                return _Absent(walked)
        return _Bound(doc, walked)

    def operand(self, o, env) -> Tuple[Any, Tuple[DocPath, ...]]:
        """(value, why): value is a Python value, an Unknown, or _ABSENT."""
        if isinstance(o, Literal):
            return o.value, ()
        if isinstance(o, Default):
            r = self.resolve(o.path, env)
            if isinstance(r, _Absent):
                return o.value, (r.at,)
            if isinstance(r, Unknown):
                self._note(r)
                return r, ()
            return r.value, (r.path,)
        r = self.resolve(o, env)
        if isinstance(r, _Absent):
            return _ABSENT, (r.at,)
        if isinstance(r, Unknown):
            self._note(r)
            return r, ()
        return r.value, (r.path,)

    # -- atoms ----------------------------------------------------------------------------

    def equal(self, a, b) -> Val:
        if a is _ABSENT or b is _ABSENT:
            return False
        if isinstance(a, Unknown) and isinstance(b, Unknown):
            if a.key == b.key:
                return True
            return _z3_const(a, z3.StringSort()) == _z3_const(b, z3.StringSort())
        if isinstance(b, Unknown):
            a, b = b, a
        if isinstance(a, Unknown):
            if isinstance(b, (list, dict, tuple)):
                return self.fresh_bool("cmp")
            sort = _sort_of(b)
            return _z3_const(a, sort) == _z3_val(b, sort) if sort is not None else False
        if isinstance(a, bool) or isinstance(b, bool):
            return isinstance(a, bool) and isinstance(b, bool) and a == b
        if _is_num(a) and _is_num(b):
            return a == b
        if isinstance(a, tuple):
            a = list(a)
        if isinstance(b, tuple):
            b = list(b)
        return type(a) is type(b) and a == b

    def order(self, op: str, a, b) -> Val:
        if a is _ABSENT or b is _ABSENT:
            return False
        if isinstance(a, Unknown) or isinstance(b, Unknown):
            known = b if isinstance(a, Unknown) else a
            if isinstance(a, Unknown) and isinstance(b, Unknown):
                x, y = _z3_const(a, z3.RealSort()), _z3_const(b, z3.RealSort())
            elif not _is_num(known):
                return False
            else:
                sort = z3.RealSort() if isinstance(known, float) else z3.IntSort()
                x = _z3_const(a, sort) if isinstance(a, Unknown) else _z3_val(a, sort)
                y = _z3_const(b, sort) if isinstance(b, Unknown) else _z3_val(b, sort)
        elif _is_num(a) and _is_num(b):
            x, y = a, b
        else:
            return False
        r = {"<": lambda: x < y, "<=": lambda: x <= y, ">": lambda: x > y, ">=": lambda: x >= y}[op]()
        return r if isinstance(r, bool) else r

    def members(self, coll) -> Optional[List[Any]]:
        if isinstance(coll, (list, tuple)):
            return list(coll)
        return None

    def compare(self, e: Compare, env) -> Tuple[Val, Tuple[DocPath, ...]]:
        a, wa = self.operand(e.left, env)
        b, wb = self.operand(e.right, env)
        why = wa + wb
        if e.op == "==":
            return self.equal(a, b), why
        if e.op == "!=":
            if a is _ABSENT or b is _ABSENT:
                return False, why
            return _not(self.equal(a, b)), why
        if e.op in ("in", "notin"):
            if a is _ABSENT or b is _ABSENT:
                return False, why
            if isinstance(b, Unknown):
                return self.fresh_bool("in"), why
            items = self.members(b)
            if items is None:
                return False, why
            hit = _or([self.equal(a, x) for x in items])
            return (hit if e.op == "in" else _not(hit)), why
        return self.order(e.op, a, b), why

    def fresh_bool(self, what: str) -> z3.BoolRef:
        return z3.Bool(f"?{what}#{next(self.fresh)}")

    # -- formulas -------------------------------------------------------------------------

    def ev(self, e: Expr, env) -> Tuple[Val, Tuple[DocPath, ...]]:
        if isinstance(e, Compare):
            return self.compare(e, env)
        if isinstance(e, Present):
            r = self.resolve(e.path, env)
            if isinstance(r, Unknown):
                self._note(r)
                v: Val = z3.Bool(f"present:{r.key}")
                why: Tuple[DocPath, ...] = ()
            elif isinstance(r, _Absent):
                v, why = False, (r.at,)
            else:
                v, why = True, (r.path,)
            return (_not(v) if e.negate else v), why
        if isinstance(e, StartsWith):
            a, why = self.operand(e.operand, env)
            if isinstance(a, Unknown):
                return z3.PrefixOf(z3.StringVal(e.prefix), _z3_const(a, z3.StringSort())), why
            return (isinstance(a, str) and a.startswith(e.prefix)), why
        if isinstance(e, Internet):
            from .addresses import may_reach
            a, why = self.operand(e.operand, env)
            if isinstance(a, Unknown):
                return z3.Bool(f"internet{e.family or ''}:{a.key}"), why
            return (isinstance(a, str) and may_reach(a, e.family)), why
        if isinstance(e, Not):
            v, why = self.ev(e.expr, env)
            return _not(v), why
        if isinstance(e, BoolOp):
            want = e.op == "or"                 # the value that decides the whole
            results = []
            for part in e.parts:
                v, why = self.ev(part, env)
                if v is want:
                    return want, why
                results.append((v, why))
            vals = [v for v, _ in results]
            all_why = tuple(p for _, w in results for p in w)
            return (_or(vals) if want else _and(vals)), all_why
        if isinstance(e, Quantifier):
            return self.quantify(e, env)
        raise TypeError(f"not a policy expression: {e!r}")

    def elements(self, e: Quantifier, env) -> Tuple[List[Tuple[Any, ...]], bool, Tuple[DocPath, ...]]:
        """The bindings a quantifier ranges over, whether some part of the collection is
        unknown, and the collection paths (for blame when it is empty)."""
        out: List[Tuple[Any, ...]] = []
        unknown = False
        paths: List[DocPath] = []
        coll_paths: List[Union[Path, DocPath]] = []
        for p in e.collection:
            if p.root == RELATED and p.root not in env and len(p.steps) == 1 and isinstance(p.steps[0], str):
                # another resource is a different document: its paths never name a line here
                for i, doc in enumerate(self.subject.related.get(p.steps[0], [])):
                    out.append((_Bound(doc, ("@", p.steps[0], i)),))
                continue
            view = self.subject.views.get(p.root) if p.root not in env else None
            if isinstance(view, list) and not p.steps:
                coll_paths.extend(view)
            else:
                coll_paths.append(p)
        for cp in coll_paths:
            r = self._at(cp) if isinstance(cp, tuple) else self.resolve(cp, env)
            if isinstance(r, Unknown):
                self._note(r)
                unknown = True
                continue
            if isinstance(r, _Absent):
                paths.append(r.at)
                continue
            paths.append(r.path)
            v = r.value
            if isinstance(v, Unknown):
                self._note(v)
                unknown = True
            elif len(e.names) == 2 and isinstance(v, dict):
                for k, item in v.items():
                    out.append((_Bound(k, r.path + (k,)), self._bound(item, r.path + (k,))))
            elif len(e.names) == 1 and isinstance(v, list):
                for i, item in enumerate(v):
                    out.append((self._bound(item, r.path + (i,)),))
        return out, unknown, tuple(paths)

    @staticmethod
    def _bound(value, path: DocPath):
        if isinstance(value, Unknown):
            return value
        return _Bound(value, path) if value is not None else _Absent(path[:-1])

    def quantify(self, e: Quantifier, env) -> Tuple[Val, Tuple[DocPath, ...]]:
        some = e.kind == "some"
        items, unknown, coll_why = self.elements(e, env)
        results = []
        for binding in items:
            inner = dict(env)
            inner.update(zip(e.names, binding))
            v, why = self.ev(e.body, inner)
            first = binding[0]
            where = (first.path,) if isinstance(first, _Bound) else ()
            if v is some:                       # a witness (some) or a counterexample (every)
                return some, where + why
            results.append(v)
        if unknown:
            results.append(self.fresh_bool("collection"))
        return (_or(results) if some else _and(results)), coll_why


_ABSENT = object()


def decide(expr: Expr, subject: Subject) -> Verdict:
    """The verdict of one policy formula on one subject."""
    ev = _Evaluator(subject)
    val, why = ev.ev(expr, {})
    if val is True:
        return Verdict("fail", "matched", why)
    if val is False:
        return Verdict("pass", "matched", why)
    s = z3.Solver()
    s.set("timeout", 5000)
    s.add(*subject.constraints)
    s.add(z3.Not(val))
    unknowns = tuple(sorted(ev.unknowns))
    if s.check() == z3.unsat:
        return Verdict("fail", "solver-verified", why, unknowns)
    s = z3.Solver()
    s.set("timeout", 5000)
    s.add(*subject.constraints)
    s.add(val)
    return Verdict("undecided" if s.check() != z3.unsat else "pass", "solver-verified", why, unknowns)


__all__ = ["DocPath", "RELATED", "Subject", "Unknown", "Verdict", "decide"]
