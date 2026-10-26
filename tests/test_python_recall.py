"""Recall regressions for Python found by probing real-world patterns.

Each positive case was a miss before; each negative pins a nearby safe shape so
the recall gain does not turn into noise.
"""

from frame.sil.frontends.python_frontend import PythonFrontend
from frame.sil.scanner import FrameScanner


def cwes(code, name="t.py"):
    r = FrameScanner(language="python").scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


# ---- type-annotated parameters are parameters ----------------------------

def test_typed_parameters_are_kept():
    src = "def f(a: str, b: int = 1, *c: str, **d: int):\n    pass\n"
    proc = PythonFrontend().translate(src, "t.py").procedures["f"]
    assert [p[0].name for p in proc.params] == ["a", "b", "c", "d"]


FASTAPI = """
from fastapi import FastAPI
import subprocess
app = FastAPI()

@app.get("/run")
def run(cmd: str):
    return subprocess.check_output({arg}, shell=True)
"""


def test_fastapi_typed_query_param_to_shell():
    assert "CWE-78" in cwes(FASTAPI.format(arg="cmd"))


def test_fastapi_constant_command_is_clean():
    assert "CWE-78" not in cwes(FASTAPI.format(arg="'uptime'"))


def test_typed_helper_param_is_not_a_source():
    # Not a handler: an annotated parameter of a plain helper is not attacker input.
    code = "import os\n\ndef run(cmd: str):\n    os.system(cmd)\n"
    assert "CWE-78" not in cwes(code)


# ---- inline subscript reads of request containers ------------------------

FLASK = """
from flask import Flask, request
import os, shlex
app = Flask(__name__)

@app.route("/a")
def a():
    os.system("ls " + {arg})
    return "ok"
"""


def test_inline_request_args_subscript_to_shell():
    assert "CWE-78" in cwes(FLASK.format(arg='request.args["d"]'))


def test_inline_request_form_subscript_to_sql():
    code = """
from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/a")
def a():
    db = sqlite3.connect("x")
    db.execute("select * from t where n='%s'" % request.form["n"])
    return "ok"
"""
    assert "CWE-89" in cwes(code)


def test_inline_subscript_as_sink_argument_to_ssrf():
    code = """
from flask import Flask, request
import requests
app = Flask(__name__)

@app.route("/a")
def a():
    return requests.get(request.args["url"]).text
"""
    assert "CWE-918" in cwes(code)


def test_inline_subscript_wrapped_in_sanitizer_is_clean():
    assert "CWE-78" not in cwes(FLASK.format(arg='shlex.quote(request.args["d"])'))


def test_inline_subscript_of_non_request_dict_is_clean():
    assert "CWE-78" not in cwes(FLASK.format(arg='CONFIG["d"]').replace(
        "app = Flask", 'CONFIG = {"d": "/tmp"}\napp = Flask'))
