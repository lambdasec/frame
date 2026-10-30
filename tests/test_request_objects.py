"""Which parts of a web request the client chose and which the server set are data
(`specs/data/request-objects.toml`): the JS frontend's destructured handler parameters and the
translator's Python `request.<server state>` rule read it."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.specs import request_objects


def test_the_shipped_file_loads():
    r = request_objects.load()
    assert "body" in r.client_properties and "session" not in r.client_properties
    assert "session" in r.server_state


def test_a_name_cannot_be_both(tmp_path):
    bad = tmp_path / "request-objects.toml"
    bad.write_text('client_properties = ["body", "session"]\nserver_state = ["session"]\n'
                   'js_request_names = ["req"]\njs_handler_names = ["res"]\njs_framework_modules = ["express"]\n'
                   'js_handler_decorators = ["Get"]\njs_request_types = ["Request"]\n')
    with pytest.raises(ValueError, match="both"):
        request_objects.load(bad)


def test_unknown_keys_are_an_error(tmp_path):
    bad = tmp_path / "request-objects.toml"
    bad.write_text(request_objects.PATH.read_text() + '\nextra = ["x"]\n')
    with pytest.raises(ValueError, match="needs exactly"):
        request_objects.load(bad)


def _cwes(code, lang, name):
    return {v.cwe_id for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities}


_HANDLER = """const db = require('./db');
module.exports = ({ %s }, res, next) => {
  db.query("SELECT * FROM t WHERE n = '" + %s + "'");
  res.end();
};
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
