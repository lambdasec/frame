"""No syntax silently loses data on its way to SIL (the class of bug behind GitHub issue #9).

A frontend lowers each expression node it knows; anything else falls back to a variable named
by the node's source text, so whatever data the node carried is lost without a trace. A chained
assignment, a keyword argument inside a nested call and a comprehension were all lowered that
way. The Python frontend now records every node type that reaches the fallback
(`Program.unlowered_syntax`); a syntax zoo of everyday forms must reach it only with node types
that carry no data. A new construct, or a refactor that breaks one, fails here instead of
quietly costing findings.
"""

from frame.sil.frontends.python_frontend import PythonFrontend

# Node types that may reach the fallback: they carry no data a finding could depend on.
PY_ALLOWED = {
    "slice",              # `q[1:5]`: the base carries the data
    "lambda",             # a function value
    "comment", "line_continuation", "ellipsis",
    "type_conversion",    # the `!r` of an f-string field
}

PY_ZOO = '''
import os, functools
def f(q, *args, **kwargs):
    a = b = q
    c, d = q, 1
    (e, (g, h)) = (q, (1, 2))
    i, *rest = [q, 2, 3]
    [j, k] = [q, 1]
    if (w := q):
        pass
    x1 = f"{q!r:>5}" + "%s" % q + "{}".format(q) + "{a}".format(a=q)
    x2 = [s.strip() for s in args if s]
    x3 = {s for s in args}
    x4 = {k: v for k, v in kwargs.items()}
    x5 = "".join(s for s in args)
    x6 = q[1:5] + q[::2]
    x7 = sorted(args, key=lambda s: s.lower())
    x8 = q if q else "x"
    x9 = q or "x"
    x10 = not q and q
    x11 = -len(q) + ~1
    x12 = {q, "a"}
    x13 = (q, 1)
    x14 = os.path.join(*args)
    x15 = dict(**kwargs)
    x16 = getattr(os, "sep", None)
    x17 = q.encode().decode()
    x18 = [*args, q]
    x19 = await_free = q
    os.system(q)
    print(f(q=q, *args, **kwargs))
    return q, 200
'''


def test_python_zoo_lowers_every_data_carrying_node():
    program = PythonFrontend().translate(PY_ZOO, "zoo.py")
    unexpected = {k: n for k, n in (program.unlowered_syntax or {}).items() if k not in PY_ALLOWED}
    assert not unexpected, f"node types lowered as their source text: {unexpected}"


def test_the_fallback_is_recorded():
    # The tripwire itself: a construct the frontend does not lower must show up.
    program = PythonFrontend().translate("def f(q):\n    x = q[1:2]\n", "t.py")
    assert "slice" in (program.unlowered_syntax or {})
