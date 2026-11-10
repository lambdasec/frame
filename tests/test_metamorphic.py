"""Metamorphic tests: a vulnerability rewritten without changing its meaning is still found.

GitHub issue #9 was an SQL injection that disappeared when the code was written another
ordinary way (the connection kept on `flask.g`, a chained assignment, `getattr`). Each such
rewrite exposed a construct the frontend lowered wrongly, and a test of the original shape
could never catch it. Here every seed flow (request data reaching a sink) is rewritten by
each transform in TRANSFORMS, and the finding must survive. The same transforms applied to
a constant must stay clean, so a fix cannot buy recall with noise.

A transform Frame does not handle yet is listed in KNOWN_GAPS with the reason, as a strict
xfail: fixing it makes the test pass and CI asks for the entry to be removed.
"""

import pytest

from frame.sil.scanner import FrameScanner

# ---- Python -------------------------------------------------------------------------------

PY_HEAD = """import os, sqlite3, urllib.request, contextlib, functools
from flask import Flask, request, g
app = Flask(__name__)
def ident(s):
    return s
class Box:
    def __init__(self, val):
        self.val = val
    def get(self):
        return self.val
"""
PY_HANDLER = """
@app.route('/x')
def x():
    q = request.args.get('q', '')
{body}
    return "ok"
"""
PY_SINKS = {
    "CWE-78": 'os.system("ping " + {v})',
    "CWE-89": "sqlite3.connect('x.db').execute(\"SELECT * FROM t WHERE n = '\" + {v} + \"'\")",
    "CWE-22": 'open("/srv/files/" + {v})',
    "CWE-918": "urllib.request.urlopen({v})",
}
# Each transform: statements that leave q's value in v.
PY_TRANSFORMS = {
    "plain": ["v = q"],
    "chained-assignment": ["v = w = q"],
    "tuple-unpacking": ["v, n = q, 1"],
    "tuple-swap": ["n, v = 1, q"],
    "nested-unpacking": ["(v, (a, b)) = (q, (1, 2))"],
    "starred": ["v, *rest = [q, 'a']"],
    "walrus": ["if (v := q):", "    pass"],
    "fstring": ['v = f"{q}"'],
    "fstring-spec": ['v = f"{q!s:>5}"'],
    "percent": ['v = "%s" % q'],
    "percent-dict": ['v = "%(a)s" % {"a": q}'],
    "format": ['v = "{}".format(q)'],
    "format-keyword": ['v = "{a}".format(a=q)'],
    "format-keyword-inline": None,          # the sink argument itself: see PY_INLINE
    "join": ['v = "".join([q])'],
    "strip": ["v = q.strip()"],
    "slice": ["v = q[:100]"],
    "str-call": ["v = str(q)"],
    "augmented": ['v = ""', "v += q"],
    "ternary": ["v = q if q else q"],
    "or-default": ["v = q or 'x'"],
    "list-index": ["v = [q][0]"],
    "dict-key": ['v = {"k": q}["k"]'],
    "dict-get": ['d = {"k": q}', 'v = d.get("k")'],
    "helper": ["v = ident(q)"],
    "lambda": ["v = (lambda s: s)(q)"],
    "for-loop": ["for v in [q]:", "    pass"],
    "comprehension": ["v = [s for s in [q]][0]"],
    "generator-join": ['v = "".join(s for s in [q])'],
    "object-attribute": ["b = Box(q)", "v = b.val"],
    "object-getter": ["b = Box(q)", "v = b.get()"],
    "setattr-literal": ["b = Box('')", "setattr(b, 'val', q)", "v = b.val"],
    "getattr-literal": ["b = Box(q)", "v = getattr(b, 'val')"],
    "with-as": ["with contextlib.nullcontext(q) as v:", "    pass"],
    "try-else": ["try:", "    v = q", "except Exception:", "    v = ''"],
    "while": ["v = ''", "while not v:", "    v = q"],
    "partial": ["v = functools.partial(ident, q)()"],
    "bytes-roundtrip": ["v = q.encode().decode()"],
}
PY_TRANSFORMS = {k: v for k, v in PY_TRANSFORMS.items() if v is not None}
# Sink arguments written inline (the value never passes through a variable).
PY_INLINE = {
    "format-keyword-inline": 'os.system("ping {h}".format(h=q))',
    "conditional-inline": 'os.system("ping " + (q if q else "x"))',
    "receiver-call-statement": "sqlite3.connect('x.db').cursor().execute(\"SELECT '\" + q + \"'\")",
}
PY_INLINE_CWE = {"format-keyword-inline": "CWE-78", "conditional-inline": "CWE-78",
                 "receiver-call-statement": "CWE-89"}

KNOWN_GAPS = {
    ("python", "dict-key"): "a dict literal lowers to null (no per-key values yet)",
    ("python", "dict-get"): "a dict literal lowers to null (no per-key values yet)",
    ("python", "partial"): "calling a functools.partial object written inline is not resolved",
    ("python", "conditional-inline"): "a conditional expression inside a sink argument carries no taint "
                                      "(_get_exp_vars has no ExpTernary case)",
}


def _scan(language, code, name):
    r = FrameScanner(language=language).scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def _py(lines):
    return PY_HEAD + PY_HANDLER.format(body="\n".join("    " + ln for ln in lines))


def _gap(language, transform):
    reason = KNOWN_GAPS.get((language, transform))
    return [pytest.mark.xfail(reason=reason, strict=True)] if reason else []


@pytest.mark.parametrize("transform,cwe", [
    pytest.param(t, c, id=f"{t}-{c}", marks=_gap("python", t))
    for t in PY_TRANSFORMS for c in PY_SINKS])
def test_python_flow_survives_the_rewrite(transform, cwe):
    sink = PY_SINKS[cwe].format(v="v")
    assert cwe in _scan("python", _py(PY_TRANSFORMS[transform] + [sink]), "app.py")


@pytest.mark.parametrize("transform", [
    pytest.param(t, id=t, marks=_gap("python", t)) for t in PY_INLINE])
def test_python_inline_flow_survives_the_rewrite(transform):
    assert PY_INLINE_CWE[transform] in _scan("python", _py([PY_INLINE[transform]]), "app.py")


def _constant(lines):
    """The transform applied to a constant instead of the request value."""
    return [ln.replace("q", "'localhost'") if "q" in ln else ln for ln in lines]


@pytest.mark.parametrize("transform", list(PY_TRANSFORMS))
def test_python_rewrite_of_a_constant_stays_clean(transform):
    sink = PY_SINKS["CWE-78"].format(v="v")
    assert "CWE-78" not in _scan("python", _py(_constant(PY_TRANSFORMS[transform]) + [sink]), "app.py")


# try / except / else / finally: whole handler bodies used to be dropped (their blocks have no
# field name in the grammar) and a raise inside a try did not end its path.
PY_CONTROL = {
    "sink-in-except": (["try:", "    n = int(q)", "except ValueError:", "    os.system('ping ' + q)"], "CWE-78"),
    "sink-in-else": (["try:", "    n = 1", "except ValueError:", "    pass", "else:",
                      "    os.system('ping ' + q)"], "CWE-78"),
    "sink-in-finally": (["try:", "    n = 1", "finally:", "    os.system('ping ' + q)"], "CWE-78"),
    "source-bound-in-handler": (["v = 'x'", "try:", "    n = 1", "except Exception:", "    v = q",
                                 "os.system('ping ' + v)"], "CWE-78"),
    "handler-swallows-the-raise": (["try:", "    if not q.isdigit():", "        raise ValueError",
                                    "except ValueError:", "    pass", "os.system('ping ' + q)"], "CWE-78"),
    "raise-guard-handler-returns": (["try:", "    if not q.isdigit():", "        raise ValueError",
                                     "except ValueError:", "    return 'bad', 400",
                                     "os.system('ping ' + q)"], None),
    "conversion-guarded-by-try": (["try:", "    n = int(q)", "except ValueError:", "    return 'bad', 400",
                                   "os.system('ping ' + str(n))"], None),
}


@pytest.mark.parametrize("case", list(PY_CONTROL))
def test_python_try_statement_is_control_flow(case):
    lines, cwe = PY_CONTROL[case]
    found = _scan("python", _py(lines), "app.py")
    assert (cwe in found) if cwe else ("CWE-78" not in found)


# Ways of obtaining the database connection: the sink must be recognised whichever is used.
PY_CONNECTIONS = {
    "local": "db = sqlite3.connect('x.db')",
    "cursor": "db = sqlite3.connect('x.db').cursor()",
    "closing": "db = contextlib.closing(sqlite3.connect('x.db'))",
    "flask-g": "g.conn = sqlite3.connect('x.db')\n    db = g.conn",
    "chained-on-g": "db = g.c2 = sqlite3.connect('x.db')",
    "getattr-on-g": "g.c3 = sqlite3.connect('x.db')\n    db = getattr(g, 'c3', None)",
}


@pytest.mark.parametrize("how", list(PY_CONNECTIONS))
def test_python_connection_obtained_any_way_is_a_sink(how):
    body = [PY_CONNECTIONS[how], "db.execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")"]
    assert "CWE-89" in _scan("python", _py(body), "app.py")
