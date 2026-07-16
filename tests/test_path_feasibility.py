"""Post-hoc path-feasibility filtering.

Frame records the per-edge branch conditions assumed on the path to each taint
sink (as pure formulas) and, after the fact, drops any finding whose accumulated
path condition is provably unsatisfiable. This removes findings that sit on dead
code (a sink guarded by contradictory branches) without ever pruning execution,
so it composes with the state-merge fixpoint and never drops a reachable finding.

The soundness obligations these tests pin down:

* a contradictory-guard dead path is dropped,
* a genuinely reachable sink is always kept, including when the guarding
  variable is reassigned between branches (the conditions are not SSA form, so a
  guard on an old value must not conjoin with a guard on the new value), and
* a bare-variable truthiness guard is kept on its own (a lone Var is spatial in
  the SL checker, so its negation is spuriously unsatisfiable unless truthiness
  is modeled explicitly).
"""

from frame.sil import FrameScanner


def _sqli_lines(src):
    result = FrameScanner(language="python", verify=False).scan(src, "t.py")
    return [v.line for v in result.vulnerabilities if v.type.value == "sql_injection"]


def test_dead_path_after_contradictory_guards_is_dropped():
    # The sink is reached only after assuming `uid` both truthy and falsy, which
    # cannot happen: the path is infeasible, so no finding should be reported.
    src = (
        "from flask import request\n"
        "def h(db):\n"
        "    uid = request.args.get('id')\n"
        "    if uid:\n"
        "        return 'ok'\n"
        "    if not uid:\n"
        "        return 'no'\n"
        "    db.execute('SELECT * FROM t WHERE id=' + uid)\n"
    )
    assert _sqli_lines(src) == []


def test_guarded_live_sink_is_kept():
    # Sink inside `if uid:` -- a single satisfiable guard, genuinely reachable.
    src = (
        "from flask import request\n"
        "def h(db):\n"
        "    uid = request.args.get('id')\n"
        "    if uid:\n"
        "        db.execute('SELECT * FROM t WHERE id=' + uid)\n"
        "    return 'ok'\n"
    )
    assert _sqli_lines(src) == [5]


def test_plain_unguarded_sink_is_kept():
    src = (
        "from flask import request\n"
        "def h(db):\n"
        "    uid = request.args.get('id')\n"
        "    db.execute('SELECT * FROM t WHERE id=' + uid)\n"
    )
    assert _sqli_lines(src) == [4]


def test_sink_before_return_is_kept():
    src = (
        "from flask import request\n"
        "def h(db):\n"
        "    uid = request.args.get('id')\n"
        "    db.execute('SELECT * FROM t WHERE id=' + uid)\n"
        "    return 'x'\n"
    )
    assert _sqli_lines(src) == [4]


def test_reassigned_variable_guard_does_not_falsely_drop():
    # `if not p:` then `if p:` looks contradictory syntactically, but `p` is
    # reassigned between the two branches, so the guards constrain different
    # values. The tainted path (p stays truthy) reaches the sink and must be kept.
    src = (
        "from flask import request\n"
        "def h(db):\n"
        "    p = request.args.get('id')\n"
        "    if not p:\n"
        "        p = ''\n"
        "    if p:\n"
        "        db.execute('SELECT * FROM t WHERE id=' + p)\n"
    )
    assert _sqli_lines(src) == [7]


def test_bare_truthiness_falsy_guard_is_kept():
    # Sink guarded only by `if not q:` (a falsy truthiness test). Falsy on its own
    # is satisfiable, so the finding must survive.
    src = (
        "from flask import request\n"
        "def h(db):\n"
        "    q = request.args.get('id')\n"
        "    if not q:\n"
        "        db.execute('SELECT * FROM t WHERE id=' + q)\n"
    )
    assert _sqli_lines(src) == [5]


def test_sink_inside_loop_is_kept():
    # A loop lowers to branch nodes whose exit edge the frontend may guard with a
    # constant placeholder. Such constant guards must not make a real in-loop sink
    # look infeasible.
    src = (
        "from flask import request\n"
        "def h(db):\n"
        "    ids = request.args.getlist('id')\n"
        "    for i in ids:\n"
        "        db.execute('SELECT * FROM t WHERE id=' + i)\n"
    )
    assert _sqli_lines(src) == [5]


def test_truthiness_sentinel_sat_semantics():
    # The falsy-sentinel encoding used for bare-variable truthiness: each polarity
    # is individually satisfiable, and only both-at-once is a contradiction.
    from frame.checking.checker import EntailmentChecker
    from frame.core.ast import Var, Eq, Neq, Const, And

    checker = EntailmentChecker()
    truthy = Neq(Var("v"), Const(0))
    falsy = Eq(Var("v"), Const(0))
    assert checker.is_satisfiable(truthy)
    assert checker.is_satisfiable(falsy)
    assert not checker.is_satisfiable(And(truthy, falsy))
