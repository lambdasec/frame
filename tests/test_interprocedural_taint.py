"""Taint across the procedures of one file (Python, JS/TS).

A handler that passes attacker data to a helper, or returns a helper's result,
is one flow even though the source and sink sit in different procedures. Each
positive is paired with the nearest safe shape (a constant argument, a
sanitizing or value-dropping helper) so the cross-procedure reach does not turn
into noise. Java already taints String parameters; C/C++/C# have their own
interprocedural passes, so this is Python and JS/TS.
"""

import pytest

from frame.sil.scanner import FrameScanner


def cwes(code, language="python", name=None):
    name = name or ("t.py" if language == "python" else "t.js")
    r = FrameScanner(language=language).scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


# ---- argument into a helper's sink -------------------------------------------

HELPER_SINK = """
from flask import Flask, request
import sqlite3
app = Flask(__name__)

def run_query(q):
    sqlite3.connect("x").execute("SELECT * FROM u WHERE n = '%s'" % q)

@app.route("/u")
def u():
    run_query({arg})
    return "ok"
"""


def test_tainted_argument_reaches_helper_sink():
    assert "CWE-89" in cwes(HELPER_SINK.format(arg='request.args.get("n")'))


def test_constant_argument_to_helper_is_clean():
    assert "CWE-89" not in cwes(HELPER_SINK.format(arg='"bob"'))


def test_inline_request_argument_reaches_helper_sink():
    assert "CWE-89" in cwes(HELPER_SINK.format(arg='request.args["n"]'))


def test_method_helper_via_self():
    code = """
from flask import Flask, request
import os
app = Flask(__name__)

class Svc:
    def run(self, d):
        os.system("ls " + d)

    def handle(self):
        self.run(request.args.get("d"))
"""
    assert "CWE-78" in cwes(code)


def test_js_helper_sink():
    code = ("const express = require('express');\n"
            "const { exec } = require('child_process');\n"
            "const app = express();\n"
            "function runCmd(d) { exec('ls ' + d); }\n"
            "app.get('/a', (req, res) => { runCmd(req.query.dir); res.send('ok'); });")
    assert "CWE-78" in cwes(code, language="javascript")


def test_js_helper_constant_is_clean():
    code = ("const express = require('express');\n"
            "const { exec } = require('child_process');\n"
            "const app = express();\n"
            "function runCmd(d) { exec('ls ' + d); }\n"
            "app.get('/a', (req, res) => { runCmd('/tmp'); res.send('ok'); });")
    assert "CWE-78" not in cwes(code, language="javascript")


# ---- caller or helper sanitizes ----------------------------------------------

def test_caller_sanitizes_before_helper():
    assert "CWE-78" not in cwes("""
from flask import Flask, request
import os, shlex
app = Flask(__name__)

def run(d):
    os.system("ls " + d)

@app.route("/a")
def a():
    run(shlex.quote(request.args.get("d")))
    return "ok"
""")


def test_helper_does_not_use_the_argument():
    assert "CWE-78" not in cwes("""
from flask import Flask, request
import os
app = Flask(__name__)

def run(d):
    os.system("ls /tmp")

@app.route("/a")
def a():
    run(request.args.get("d"))
    return "ok"
""")


# ---- helper RETURNS the dangerous value --------------------------------------

def test_helper_returns_source():
    assert "CWE-78" in cwes("""
from flask import Flask, request
import os
app = Flask(__name__)

def get_dir():
    return request.args.get("d")

@app.route("/a")
def a():
    os.system("ls " + get_dir())
    return "ok"
""")


def test_helper_returns_sanitized_value_is_clean():
    assert "CWE-78" not in cwes("""
from flask import Flask, request
import os, shlex
app = Flask(__name__)

def clean(x):
    return shlex.quote(x)

@app.route("/a")
def a():
    os.system("ls " + clean(request.args.get("d")))
    return "ok"
""")


def test_helper_returns_argument_unchanged_still_flows():
    assert "CWE-78" in cwes("""
from flask import Flask, request
import os
app = Flask(__name__)

def ident(x):
    return x

@app.route("/a")
def a():
    os.system("ls " + ident(request.args.get("d")))
    return "ok"
""")


def test_helper_returns_constant_is_clean():
    assert "CWE-78" not in cwes("""
from flask import Flask, request
import os
app = Flask(__name__)

def fixed(x):
    return "/tmp"

@app.route("/a")
def a():
    d = request.args.get("d")
    os.system("ls " + fixed(d))
    return "ok"
""")


def test_js_getter_returns_request_field():
    code = ("const express = require('express');\n"
            "const { exec } = require('child_process');\n"
            "const app = express();\n"
            "function getDir(req) { return req.query.dir; }\n"
            "app.get('/a', (req, res) => { exec('ls ' + getDir(req)); res.send('ok'); });")
    assert "CWE-78" in cwes(code, language="javascript")


def test_js_numeric_conversion_is_clean():
    code = ("const express = require('express');\n"
            "const { exec } = require('child_process');\n"
            "const app = express();\n"
            "app.get('/a', (req, res) => { exec('kill ' + parseInt(req.query.id, 10)); res.send('ok'); });")
    assert "CWE-78" not in cwes(code, language="javascript")


# ---- termination and resilience ----------------------------------------------

def test_recursive_helper_terminates_and_flags():
    assert "CWE-78" in cwes("""
from flask import Flask, request
import os
app = Flask(__name__)

def walk(x, n):
    if n == 0:
        os.system("ls " + x)
        return
    walk(x, n - 1)

@app.route("/a")
def a():
    walk(request.args.get("d"), 3)
    return "ok"
""")


def test_mutually_recursive_helpers_terminate():
    # Must not loop forever building summaries.
    code = """
from flask import Flask, request
import os
app = Flask(__name__)

def ping(x, n):
    if n <= 0:
        os.system("ls " + x)
    else:
        pong(x, n - 1)

def pong(x, n):
    ping(x, n - 1)

@app.route("/a")
def a():
    ping(request.args.get("d"), 4)
    return "ok"
"""
    assert "CWE-78" in cwes(code)


# ---- a Python attribute named like a sink is not a sink ----------------------

def test_python_attribute_assignment_is_not_a_sink():
    # `response.raw = resp` must not match Django Manager.raw(); regression from
    # the requests library.
    code = """
class Response:
    pass

def build(resp, proxies):
    response = Response()
    response.raw = resp
    response.proxies = proxies
    return response
"""
    assert cwes(code) == set()


# ---- closures read their enclosing procedure's variables ----------------------

CLOSURE_DAO = """
const express = require('express');
const app = express();
function find(col, threshold) {{
  const criteria = () => {{
    if (threshold) {{ return {{ $where: "this.stocks > '" + threshold + "'" }}; }}
    return {{ ok: 1 }};
  }};
  return col.find(criteria());
}}
app.get('/a', (req, res) => {{ res.json(find(db.collection('a'), {arg})); }});
"""


def test_closure_returns_a_captured_parameter_into_a_sink():
    assert "CWE-943" in cwes(CLOSURE_DAO.format(arg="req.query.t"), language="javascript")


def test_closure_with_a_constant_argument_is_clean():
    assert "CWE-943" not in cwes(CLOSURE_DAO.format(arg="'5'"), language="javascript")


def test_closure_over_a_numerically_converted_parameter_is_clean():
    code = CLOSURE_DAO.format(arg="req.query.t").replace(
        'const criteria', 'threshold = parseInt(threshold, 10);\n  const criteria')
    assert "CWE-943" not in cwes(code, language="javascript")


def test_closure_that_does_not_return_the_captured_value_is_clean():
    code = CLOSURE_DAO.format(arg="req.query.t").replace(
        "\"this.stocks > '\" + threshold + \"'\"", "'this.stocks > 5'")
    assert "CWE-943" not in cwes(code, language="javascript")
