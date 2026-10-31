"""Recall regressions for Python found by probing real-world patterns.

Each positive case was a miss before; each negative pins a nearby safe shape so
the recall gain does not turn into noise.
"""

import pytest

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


# ---- an inline source call under a sanitizer, and shell == command -------

def test_inline_source_call_wrapped_in_shlex_quote_is_clean():
    assert "CWE-78" not in cwes(FLASK.format(arg='shlex.quote(request.args.get("d"))'))


def test_shlex_quote_through_a_variable_covers_os_system():
    code = """
from flask import Flask, request
import os, shlex
app = Flask(__name__)

@app.route("/a")
def a():
    q = shlex.quote(request.args.get("d"))
    os.system("ls " + q)
    return "ok"
"""
    assert "CWE-78" not in cwes(code)


def test_unquoted_variable_to_os_system_still_flagged():
    code = """
from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/a")
def a():
    q = request.args.get("d")
    os.system("ls " + q)
    return "ok"
"""
    assert "CWE-78" in cwes(code)


def test_source_call_inside_returned_chained_sink_call():
    code = """
from flask import Flask, request
import requests
app = Flask(__name__)

@app.route("/a")
def a():
    return requests.get(request.args.get("url")).text
"""
    assert "CWE-918" in cwes(code)


# ---- Flask send_file, Django HttpResponse ---------------------------------

SEND_FILE = """
from flask import Flask, request, send_file
import os
app = Flask(__name__)

@app.route("/f")
def f():
    fn = {arg}
    return send_file(os.path.join("/srv/files", fn))
"""


def test_flask_send_file_path_traversal():
    assert "CWE-22" in cwes(SEND_FILE.format(arg='request.args.get("f")'))


def test_flask_send_file_constant_is_clean():
    assert "CWE-22" not in cwes(SEND_FILE.format(arg='"report.pdf"'))


DJANGO = """
from django.http import HttpResponse
from django.utils.html import escape
from django.urls import path
import json

def view(request):
    return {body}

urlpatterns = [path("v/", view)]
"""


def test_django_httpresponse_reflected_xss():
    assert "CWE-79" in cwes(DJANGO.format(body='HttpResponse("<p>" + request.GET["msg"] + "</p>")'))


def test_django_httpresponse_escaped_is_clean():
    assert "CWE-79" not in cwes(DJANGO.format(
        body='HttpResponse("<p>" + escape(request.GET.get("msg")) + "</p>")'))


def test_django_httpresponse_non_html_content_type_is_clean():
    assert "CWE-79" not in cwes(DJANGO.format(
        body='HttpResponse(json.dumps({"m": request.GET["msg"]}), content_type="application/json")'))


def test_django_request_user_is_server_state():
    assert "CWE-79" not in cwes(DJANGO.format(body='HttpResponse("Hello " + request.user.username)'))
    assert "CWE-79" in cwes(DJANGO.format(body='HttpResponse("Hello " + request.GET["username"])'))


# ---- await statements, `%` operands, aiohttp sources -----------------------------------------

def _py_cwes(code):
    from frame.sil.scanner import FrameScanner
    r = FrameScanner(language="python").scan(code, "t.py")
    return {v.cwe_id for v in r.vulnerabilities}


def test_awaited_statement_call_keeps_its_sink():
    code = ("from aiohttp.web import Request\n"
            "async def h(request: Request, cur):\n"
            "    data = await request.post()\n"
            "    await cur.execute(\"SELECT * FROM t WHERE n = '%s'\" % data['n'])\n")
    assert "CWE-89" in _py_cwes(code)


def test_percent_format_with_dict_and_tuple_operands_carries_taint():
    base = ("from flask import request\nimport sqlite3\n"
            "def h():\n    n = request.args.get('n')\n"
            "    sqlite3.connect('x').execute({q})\n")
    assert "CWE-89" in _py_cwes(base.format(q="\"SELECT '%(n)s'\" % {'n': n}"))
    assert "CWE-89" in _py_cwes(base.format(q="\"SELECT '%s' '%s'\" % (n, 'x')"))
    assert "CWE-89" not in _py_cwes(base.format(q="\"SELECT '%s'\" % ('x',)"))


def test_return_of_a_dict_carries_its_members_to_the_caller(tmp_path):
    (tmp_path / "filters.py").write_text("from flask import request\n\n\ndef read():\n    return {'n': request.args.get('n'), 'p': 1}\n")
    (tmp_path / "views.py").write_text("import sqlite3\nfrom filters import read\n\n\ndef u():\n    f = read()\n"
                                       "    return sqlite3.connect('a').execute(\"SELECT '%s'\" % f['n'])\n")
    from frame.sil.scanner import FrameScanner
    res = FrameScanner(verify=False).scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    assert any(v.cwe_id == "CWE-89" for r in res for v in r.vulnerabilities)


def test_python_membership_in_a_constant_set_clears_path_traversal():
    from frame.sil.scanner import FrameScanner
    tpl = ("from flask import Flask, request\nimport os\nALLOWED = {{'a.txt'}}\napp = Flask(__name__)\n"
           "@app.route('/f')\ndef f():\n    n = request.args.get('n')\n{g}\n"
           "    return open(os.path.join('docs', n)).read()\n")

    def paths(guard):
        r = FrameScanner(language="python").scan(tpl.format(g=guard), "a.py")
        return [v for v in r.vulnerabilities if v.cwe_id == "CWE-22"]
    assert not paths("    if n not in ALLOWED:\n        return 'no'")
    assert paths("    pass")


_REALPATH = '''import os
from flask import Flask, request
app = Flask(__name__)
BASE = os.path.realpath("/srv/files")

@app.route("/f")
def f():
    full = os.path.realpath(os.path.join(BASE, request.args.get("n", "")))
{guard}    return open(full).read()
'''


def test_realpath_alone_does_not_confine_a_path():
    # realpath("/srv/files/../../etc/passwd") is "/etc/passwd": normalising is not a check.
    assert "CWE-22" in cwes(_REALPATH.format(guard=""))


def test_realpath_then_startswith_base_confines_the_path():
    guard = "    if not full.startswith(BASE + os.sep):\n        return 'no', 400\n"
    assert "CWE-22" not in cwes(_REALPATH.format(guard=guard))


# --- match / case: each case is pruned by an equality with its literal(s), folded over constants ---

_MATCH = '''import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/r")
def r():
    param = request.args.get("p")
    guess = {guess!r}
    match guess:
        case "A":
            bar = "safe"
        case "C" | "D":
            bar = param
        case x:
            bar = "x"
    os.system("ls " + bar)
'''


@pytest.mark.parametrize("guess,reported", [("A", False), ("C", True), ("D", True), ("E", False)])
def test_match_case_folds_over_a_constant_subject(guess, reported):
    assert ("CWE-78" in cwes(_MATCH.format(guess=guess))) == reported


def test_a_capture_pattern_is_not_an_equality():
    program = PythonFrontend().translate(_MATCH.format(guess="A"), "a.py")
    conds = [str(i.condition) for p in program.procedures.values() for n in p.nodes.values()
             for i in n.instrs if type(i).__name__ == "Prune"]
    assert '(guess == "A")' in conds and '((guess == "C") || (guess == "D"))' in conds
    assert not any("== x" in c for c in conds)


# ---- a JWT decoded with its signature check off (CWE-347) -----------------------------------

@pytest.mark.parametrize("options, flagged", [
    ('algorithms=["HS256"]', False),                          # PyJWT verifies by default
    ('options={"verify_signature": False}', True),
    ('verify=False', True),                                   # PyJWT 1.x
    ('options={"verify_signature": True}, algorithms=["HS256"]', False),
])
def test_jwt_decode_without_verification(options, flagged):
    code = ("import jwt\nfrom flask import Flask, request\napp = Flask(__name__)\n\n@app.route('/x')\ndef x():\n"
            f"    return jwt.decode(request.headers['Authorization'], 'key', {options})['sub']\n")
    assert ("CWE-347" in _py_cwes(code)) == flagged
    assert "CWE-863" not in _py_cwes(code)
