"""Values reached through attribute paths and assignment shapes (GitHub issue #9).

A Flask app that keeps its database connection on `flask.g` (the `get_db()` pattern from
the Flask docs) lost the connection's type, and with it the `execute` sink, three ways:
`return g.db` (a function's return type was read from plain variables only), a chained
assignment `db = g._database = sqlite3.connect(...)` (lowered as source text), and
`getattr(g, "_database", None)` (an unknown call). Each positive here was a miss; each
negative pins the nearest shape that must stay unflagged, and every guard has a control
that proves the same file is caught without the guard.
"""

import pytest

from frame.sil.scanner import FrameScanner

HEAD = """import os, sqlite3
from flask import Flask, request, g
app = Flask(__name__)
"""


def cwes(body):
    r = FrameScanner(language="python").scan(HEAD + body, "app.py")
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def handler(call):
    return f"""
@app.route('/x')
def x():
    q = request.args.get('q', '')
    {call}
    return "ok"
"""


SQL = "{db}.execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")"

POSITIVES = {
    "return g.db": """
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('x.db')
    return g.db
""" + handler(SQL.format(db="get_db()")),

    "getattr and a chained assignment": """
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('x.db')
    return db
""" + handler(SQL.format(db="get_db()")),

    "a cursor from the shared connection": """
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('x.db')
    return g.db
""" + handler("cur = get_db().cursor()\n    " + SQL.format(db="cur")),

    "before_request stores g.conn, the handler reads it": """
@app.before_request
def open_db():
    g.conn = sqlite3.connect('x.db')
""" + handler(SQL.format(db="g.conn")),

    "setattr with a literal name": """
def get_db():
    setattr(g, 'db', sqlite3.connect('x.db'))
    return g.db
""" + handler(SQL.format(db="get_db()")),

    "a module-level object's attribute, read through a local": """
class State:
    pass
state = State()
state.conn = sqlite3.connect('x.db')
""" + handler("conn = state.conn\n    " + SQL.format(db="conn")),

    "a function returning a module-level connection": """
engine = sqlite3.connect('x.db')
def get_db():
    return engine
""" + handler(SQL.format(db="get_db()")),
}


@pytest.mark.parametrize("body", POSITIVES.values(), ids=POSITIVES.keys())
def test_sql_injection_through_a_shared_connection(body):
    assert "CWE-89" in cwes(body)


def test_parameterized_query_on_the_shared_connection_is_clean():
    body = POSITIVES["return g.db"].replace(SQL.format(db="get_db()"),
                                           "get_db().execute('SELECT * FROM t WHERE n = ?', (q,))")
    assert "CWE-89" not in cwes(body)


# ---- guards: a path gets a type only when every write agrees -----------------------------

FAKE = """
class Fake:
    def execute(self, sql):
        return []
"""
SHARED = """
def one():
    g.x = sqlite3.connect('x.db')
""" + handler(SQL.format(db="g.x"))


def test_control_a_single_kind_of_write_is_caught():
    assert "CWE-89" in cwes(FAKE + SHARED)


def test_conflicting_writes_give_the_path_no_type():
    assert "CWE-89" not in cwes(FAKE + SHARED + "\ndef two():\n    g.x = Fake()\n")


def test_an_unknown_write_gives_the_path_no_type():
    assert "CWE-89" not in cwes(FAKE + SHARED + "\ndef two(v):\n    g.x = v\n")


def test_setattr_with_a_computed_name_hides_the_objects_attributes():
    assert "CWE-89" not in cwes(FAKE + SHARED + "\ndef dyn(name):\n    setattr(g, name, Fake())\n")


GETATTR = """
def get_db():
    g.db = sqlite3.connect('x.db')
    return {read}
""" + handler(SQL.format(db="get_db()"))


def test_control_getattr_with_a_literal_name_is_the_attribute():
    assert "CWE-89" in cwes(GETATTR.format(read="getattr(g, 'db')"))


def test_getattr_with_a_computed_name_is_unknown():
    assert "CWE-89" not in cwes(GETATTR.format(read="getattr(g, 'd' + 'b')"))


def test_a_getattr_the_file_defines_is_not_the_builtin():
    assert "CWE-89" not in cwes("\ndef getattr(o, n, d=None):\n    return d\n"
                                + GETATTR.format(read="getattr(g, 'db')"))


# ---- assignment and statement shapes that used to drop taint ----------------------------

CMD = 'os.system("ping " + {v})'


@pytest.mark.parametrize("body", [
    handler("a = b = q\n    " + CMD.format(v="a")),                       # chained assignment
    handler("a = b = request.args.get('h')\n    " + CMD.format(v="b")),
    handler("d = {}\n    d['k'] = a = q\n    " + CMD.format(v="a")),         # with a subscript target
    handler("debug = False\n    debug or " + CMD.format(v="q")),            # boolean statement
    handler("[" + CMD.format(v="c") + " for c in [q]]"),                    # comprehension statement
], ids=["chain", "chain-source", "chain-subscript", "boolean-statement", "comprehension-statement"])
def test_command_injection_through_assignment_and_statement_shapes(body):
    assert "CWE-78" in cwes(body)


@pytest.mark.parametrize("body", [
    handler("a = b = 'localhost'\n    " + CMD.format(v="a")),               # a constant chain
    handler("lambda: " + CMD.format(v="q")),                                 # a lambda never called
], ids=["constant-chain", "uncalled-lambda"])
def test_safe_assignment_and_statement_shapes(body):
    assert "CWE-78" not in cwes(body)


# ---- a connection factory imported from another project file --------------------------

def test_a_factory_imported_from_the_project_types_its_result(tmp_path):
    # The Flask-tutorial layout without `g`: `get_db` in database.py. Type inference named
    # `db.execute` after the import (`app.database.get_db.execute`) while one file was
    # translated; the project's proof that get_db returns a sqlite3 connection now replaces it.
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "database.py").write_text(
        "import sqlite3\ndef get_db():\n    conn = sqlite3.connect('x.db')\n    return conn\n")
    (pkg / "views.py").write_text(
        "from flask import Flask, request\nfrom app.database import get_db\napp = Flask(__name__)\n"
        "@app.route('/a')\ndef a():\n    q = request.args.get('q', '')\n    db = get_db()\n"
        "    db.execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")\n    return 'ok'\n"
        "@app.route('/c')\ndef c():\n    q = request.args.get('q', '')\n"
        "    get_db().execute('SELECT * FROM t WHERE n = ?', (q,))\n    return 'ok'\n")
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    found = {(r.filename.rsplit("/", 1)[-1], v.procedure, v.cwe_id) for r in results for v in r.vulnerabilities}
    assert ("views.py", "a", "CWE-89") in found
    assert not any(proc == "c" for _, proc, _ in found)      # the parameterised query stays clean
