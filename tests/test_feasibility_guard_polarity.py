"""Branch-edge feasibility guards over `and` / `or` combinators.

The infeasible-path filter drops a finding only when the branch conditions on
its path are provably UNSAT. A bare call-result (or any atom the SL checker can
only see as a lone, spatial `Var`) inside `and` / `or` used to be encoded as
e.g. `Not(Or(Not(Var), Var))`, which the checker treats as UNSAT, so the sink on
the continuation of an early-exit guard was silently dropped. The guard now
pushes the edge polarity down through the combinator (De Morgan) so every
non-constant leaf gets the explicit truthiness-sentinel encoding; constant
leaves are encoded by their truthiness.
"""

from frame.sil import FrameScanner
from frame.sil.translator import SILTranslator
from frame.sil.types import ExpBinOp, ExpUnOp, ExpVar, PVar


def _sqli_lines(src):
    result = FrameScanner(language="python", verify=False).scan(src, "t.py")
    return [v.line for v in result.vulnerabilities if v.type.value == "sql_injection"]


def _handler(cond, tail=""):
    return (
        "from flask import request\n"
        "def h(db):\n"
        "    uid = request.args.get('id')\n"
        f"    if {cond}:\n"
        "        return 'no'\n"
        f"{tail}"
        "    db.execute('SELECT * FROM t WHERE id=' + uid)\n"
    )


def test_negated_disjunctive_guard_keeps_the_continuation_feasible():
    assert _sqli_lines(_handler("not check(uid) or other(uid)")) == [6]


def test_disjunctive_guard_keeps_the_continuation_feasible():
    assert _sqli_lines(_handler("check(uid) or other(uid)")) == [6]


def test_conjunctive_guard_keeps_the_continuation_feasible():
    assert _sqli_lines(_handler("check(uid) and other(uid)")) == [6]


def _contradictory_src():
    # False edge of `if uid or flag`: uid falsy and flag falsy. False edge of
    # `if not uid`: uid truthy. Together the sink's path is infeasible.
    return (
        "from flask import request\n"
        "def h(db, flag):\n"
        "    uid = request.args.get('id')\n"
        "    if uid or flag:\n"
        "        return 'no'\n"
        "    if not uid:\n"
        "        return 'x'\n"
        "    db.execute('SELECT * FROM t WHERE id=' + uid)\n"
    )


def test_contradiction_through_a_combinator_is_still_pruned():
    assert _sqli_lines(_contradictory_src()) == []


def test_contradiction_fixture_is_pruned_by_the_feasibility_filter(monkeypatch):
    # Non-vacuity: the finding exists and only the infeasible-path filter drops it.
    monkeypatch.setattr(SILTranslator, "_filter_infeasible_checks",
                        lambda self, checks: checks)
    assert _sqli_lines(_contradictory_src()) == [8]


def test_constant_leaf_in_disjunctive_guard_keeps_the_continuation_feasible():
    # The false edge of `uid or 0` is `uid falsy and 0 falsy`: satisfiable.
    assert _sqli_lines(_handler("uid or 0")) == [6]


def test_guard_pushes_polarity_through_combinators():
    t = SILTranslator.__new__(SILTranslator)
    a, b = ExpVar(PVar("a")), ExpVar(PVar("b"))
    exp = ExpBinOp("||", ExpUnOp("!", a), b)
    # False edge of `!a || b` is `a && !b`: both sides sentinel-encoded.
    assert t._feasibility_sat(t._feasibility_guard(exp, assume_true=False))
    assert t._feasibility_sat(t._feasibility_guard(exp, assume_true=True))


def test_javascript_disjunctive_guard_keeps_the_continuation_feasible():
    src = (
        "const express = require('express'); const app = express();\n"
        "app.get('/', (req, res) => {\n"
        "  const id = req.query.id;\n"
        "  if (!check(id) || other(id)) { return; }\n"
        "  db.query('SELECT * FROM t WHERE id=' + id);\n"
        "});\n"
    )
    result = FrameScanner(language="javascript", verify=False).scan(src, "t.js")
    assert [v.line for v in result.vulnerabilities
            if v.type.value == "sql_injection"] == [5]
