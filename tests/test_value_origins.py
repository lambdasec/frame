"""Value origins (frame/sil/value_origins.py): a variable bound once to a library call gives the
calls on it a callee id, and what library calls return (specs/data/value-types.toml) types them,
so `cur.execute(q)` is a SQL sink because `cur` came from `sqlite3.connect(...).cursor()`, not
because of its name. Nothing is guessed: a name bound twice has no origin."""

import pytest

from frame.sil.frontends.javascript_frontend import JavaScriptFrontend
from frame.sil.frontends.python_frontend import PythonFrontend
from frame.sil.scanner import FrameScanner
from frame.sil.value_origins import load, typed_names


def _calls(program):
    return {i.get_full_name(): i for p in program.procedures.values() for n in p.nodes.values()
            for i in n.instrs if type(i).__name__ == "Call"}


def _cwes(code, lang, name):
    return {v.cwe_id for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities}


@pytest.mark.parametrize("canonical,lang,expected", [
    ("sqlite3.connect.cursor.execute", "python", ["sqlite3.Cursor.execute", "cursor.execute"]),
    ('sqlite3.connect("x").execute', "python", ["sqlite3.Connection.execute", "connection.execute"]),
    ("mysql.createPool.query", "typescript", ["mysql.Pool.query", "pool.query"]),
    ("pg.Pool.query", "javascript", ["pg.Pool.query", "pool.query"]),
    ("sqlite3.connect.foo.execute", "python", []),            # an unknown call in between: no type
    ("flask.request.args.get", "python", []),
])
def test_typed_names(canonical, lang, expected):
    assert typed_names(canonical, lang) == expected


def test_a_name_bound_once_gives_its_calls_an_id():
    program = JavaScriptFrontend().translate(
        "const mysql = require('mysql');\nconst c = mysql.createConnection({});\nconst express = require('express');\n"
        "const app = express();\nfunction f(n) { const d = c; d.query(n); }\napp.get('/x', f);\n", "a.js")
    calls = _calls(program)
    assert calls["d.query"].canonical == "mysql.createConnection.query"
    assert calls["app.get"].canonical == "express.get"
    assert program.spec_for_call(calls["d.query"]).is_sink == "sql"
    assert program.spec_for_call(calls["app.get"]) is None        # not the `request` client's SSRF sink


def test_a_name_bound_twice_has_no_origin():
    program = JavaScriptFrontend().translate(
        "const mysql = require('mysql');\nlet c = mysql.createConnection({});\nc = makeOther();\n"
        "function f(n) { c.query(n); }\n", "a.js")
    assert _calls(program)["c.query"].canonical is None


def test_a_parameter_has_no_origin():
    program = JavaScriptFrontend().translate(
        "const mysql = require('mysql');\nconst c = mysql.createConnection({});\nfunction f(c, n) { c.query(n); }\n",
        "a.js")
    assert _calls(program)["c.query"].canonical is None


def test_python_cursor_from_a_connection_is_a_sql_sink():
    code = ("import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n\n@app.route('/u')\ndef u():\n"
            "    conn = sqlite3.connect('x')\n    cur = conn.cursor()\n"
            "    cur.execute(\"SELECT * FROM u WHERE n = '%s'\" % request.args.get('n'))\n")
    assert "CWE-89" in _cwes(code, "python", "a.py")
    program = PythonFrontend().translate(code, "a.py")
    assert program.spec_for_call(_calls(program)["cur.execute"]).is_sink == "sql"


def test_a_module_exporting_a_pool_types_its_importers(tmp_path):
    (tmp_path / "db.js").write_text("const { Pool } = require('pg');\nmodule.exports = new Pool({});\n")
    (tmp_path / "app.js").write_text(
        "const express = require('express');\nconst db = require('./db');\nconst app = express();\n"
        "app.get('/o', async (req, res) => {\n"
        "  res.json(await db.query(\"SELECT * FROM o WHERE s = '\" + req.query.s + \"'\"));\n});\n")
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    assert ("app.js", "CWE-89") in {(r.filename.rsplit("/", 1)[-1], v.cwe_id) for r in results for v in r.vulnerabilities}


def test_value_types_load_strictly(tmp_path):
    assert "sqlite3.connect" in load()["python"][0]
    bad = tmp_path / "v.toml"
    bad.write_text('[python.returns]\n"a.b" = 1\n')
    with pytest.raises(ValueError, match="maps call ids"):
        load(bad)
    bad.write_text('[python]\nother = {}\n')
    with pytest.raises(ValueError, match="only returns and receivers"):
        load(bad)


def _spec_of(code, name, call):
    program = PythonFrontend().translate(code, name)
    calls = [i for p in program.procedures.values() for n in p.nodes.values() for i in n.instrs
             if type(i).__name__ == "Call" and i.get_full_name() == call]
    return [program.spec_for_call(c) for c in calls]


def test_a_handler_instance_is_its_framework_class():
    # `self.write` is a sink because self is a tornado RequestHandler, not because of its name
    tornado = ("import tornado.web\n\nclass H(tornado.web.RequestHandler):\n    def get(self):\n"
               "        self.write('<b>' + self.get_argument('n') + '</b>')\n")
    assert "CWE-79" in _cwes(tornado, "python", "a.py")
    other = tornado.replace("(tornado.web.RequestHandler)", "")
    assert "CWE-79" not in _cwes(other, "python", "a.py")


def test_a_custom_manager_runs_raw_sql_on_itself():
    code = ("from django.db import models\n\nclass M(models.Manager):\n    def find(self, t):\n"
            "        return self.raw('SELECT 1 WHERE n = ' + t)\n\nclass Plain:\n    def find(self, t):\n"
            "        return self.raw(t)\n")
    sinks = [s.is_sink if s else None for s in _spec_of(code, "m.py", "self.raw")]
    assert sinks == ["sql", None]                  # a `raw` method of any other class is not SQL
    plain = [p for p in PythonFrontend().translate(code, "m.py").procedures.values() if p.class_name == "Plain"]
    assert plain and all(i.canonical is None for p in plain for n in p.nodes.values() for i in n.instrs
                         if type(i).__name__ == "Call")


def test_aiohttp_client_session_by_value():
    code = ("import aiohttp\n\nasync def fetch(u):\n    async with aiohttp.ClientSession() as session:\n"
            "        async with session.get(u) as r:\n            return await r.text()\n")
    assert [s.is_sink for s in _spec_of(code, "c.py", "session.get")] == ["ssrf"]
