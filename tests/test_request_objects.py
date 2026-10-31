"""Which parts of a web request the client chose and which the server set are data
(`specs/data/request-objects.toml`): the JS frontend's destructured handler parameters and the
translator's Python `request.<server state>` rule read it."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.specs import request_objects


def test_the_shipped_file_loads():
    r = request_objects.load()
    assert "session" in r.server_state and "request" in r.python_request_names


def test_javascript_request_objects_are_pack_data():
    # what an Express handler's request holds is the express pack's [[request_type]], not a name list
    from frame.sil.packs.loader import PackSet
    express = next(p for p in PackSet.build(builtin=True).packs if p.name == "express")
    request = express.request_types["request"]
    assert request.is_client_field(("body",)) and not request.is_client_field(("session",))
    assert request.is_client_method(("get",)) and not request.is_client_method(("isAuthenticated",))


def test_unknown_keys_are_an_error(tmp_path):
    bad = tmp_path / "request-objects.toml"
    bad.write_text(request_objects.PATH.read_text() + '\nextra = ["x"]\n')
    with pytest.raises(ValueError, match="needs exactly"):
        request_objects.load(bad)


def _cwes(code, lang, name):
    return {v.cwe_id for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities}


_HANDLER = """const mysql = require('mysql');
const db = mysql.createConnection({});
require('express')().use(({ %s }, res, next) => {
  db.query("SELECT * FROM t WHERE n = '" + %s + "'");
  res.end();
});
"""


@pytest.mark.parametrize("prop, sqli", [("query", True), ("body", True), ("session", False)])
def test_destructured_request_properties(prop, sqli):
    assert ("CWE-89" in _cwes(_HANDLER % (prop, prop), "javascript", "h.js")) == sqli


_DJANGO = """from django.db import connection

def view(request):
    connection.cursor().execute("SELECT * FROM t WHERE n = '%%s'" %% request.%s)
"""


@pytest.mark.parametrize("attr, sqli", [("GET", True), ("user", False), ("session", False)])
def test_python_request_server_state(attr, sqli):
    assert ("CWE-89" in _cwes(_DJANGO % attr, "python", "views.py")) == sqli


# A module-level request proxy is pack data ([pack] request_objects), not the name `request`.
_HELPER = """%s
import sqlite3

def find(r):
    sqlite3.connect("x").execute("SELECT * FROM t WHERE n = '%%s'" %% r.args.get("n"))

@app.route("/f")
def f():
    find(request)
"""


def test_an_imported_request_proxy_passed_to_a_helper_is_client_data():
    flask = _HELPER % "from flask import Flask, request\napp = Flask(__name__)"
    assert "CWE-89" in _cwes(flask, "python", "a.py")


def test_request_objects_are_for_python_packs():
    from frame.sil.packs.schema import PackError, parse_pack
    with pytest.raises(PackError, match="request_objects"):
        parse_pack({"pack": {"name": "x", "language": "javascript", "request_objects": ["a.b"]}}, "x.toml")
    pack = parse_pack({"pack": {"name": "x", "language": "python", "request_objects": ["acme.request"]}}, "x.toml")
    assert pack.request_objects == ["acme.request"]
