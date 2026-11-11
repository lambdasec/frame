"""Shapes small web services use that Frame missed or misread: a Flask view's return value as the
HTML response, a credential written to a database without a hash in between, adjacent string
literals with an f-string, re.sub / String.replace replacer functions and Array.map callbacks,
path containment proved by `path.relative`, and a constant equality beside a prefix test.

Each positive is paired with the nearest safe idiom as a negative.
"""

from frame.sil.scanner import FrameScanner
from frame.sil.sql_credentials import credential_parameters
from frame.sil.secret_names import is_credential_name


def cwes(code, language="python", name=None):
    name = name or ("t.py" if language == "python" else "t.js")
    r = FrameScanner(language=language).scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def py_xss(code):
    return "CWE-79" in cwes(code)


def py_cred(code):
    return "CWE-522" in cwes(code)


def js(code):
    return cwes(code, "javascript")


FLASK = '''
import sqlite3
from flask import Flask, request, jsonify, make_response
from markupsafe import escape

app = Flask(__name__)


def db():
    return sqlite3.connect("app.db")

'''


# ---- a Flask view's return value is the response -----------------------------------------------

def test_view_body_with_html_content_type_is_an_html_sink():
    assert py_xss(FLASK + '''
@app.route("/hello")
def hello():
    who = request.args.get("who", "")
    return who, 200, {"Content-Type": "text/html; charset=utf-8"}
''')


def test_view_body_with_another_content_type_is_not():
    assert not py_xss(FLASK + '''
@app.route("/hello")
def hello():
    who = request.args.get("who", "")
    return who, 200, {"Content-Type": "application/octet-stream"}
''')


def test_view_body_with_headers_as_a_list_of_pairs():
    assert py_xss(FLASK + '''
@app.route("/hello")
def hello():
    return request.args["who"], [("Content-Type", "text/html")]
''')


def test_escaped_view_body_is_clean():
    assert not py_xss(FLASK + '''
@app.route("/hello")
def hello():
    who = escape(request.args.get("who", ""))
    return "<p>" + who + "</p>", 200, {"Content-Type": "text/html"}
''')


def test_str_body_written_as_markup_takes_flasks_text_html_default():
    assert py_xss(FLASK + '''
@app.route("/hello")
def hello():
    who = request.args.get("who", "")
    page = "<h1>Hi</h1>"
    page += f"<p>{who}</p>"
    return page
''')


def test_str_body_without_markup_and_json_responses_are_not_html():
    assert not py_xss(FLASK + '''
@app.route("/count")
def count():
    return str(request.args.get("n"))


@app.route("/json")
def as_json():
    return jsonify({"who": request.args.get("who")})


@app.route("/dict")
def as_dict():
    return {"who": request.args.get("who")}
''')


def test_headers_held_in_a_variable_decide_nothing():
    assert not py_xss(FLASK + '''
@app.route("/hello")
def hello():
    headers = {"Content-Type": "text/plain"}
    return f"<p>{request.args['who']}</p>", 200, headers
''')


def test_a_function_that_is_not_a_view_returns_no_response():
    assert not py_xss(FLASK + '''
def render(name):
    return f"<p>{name}</p>", 200, {"Content-Type": "text/html"}
''')


def test_stored_row_rendered_as_html_is_reported():
    assert py_xss(FLASK + '''
@app.route("/notes/<int:nid>")
def note(nid):
    row = db().execute("SELECT body FROM notes WHERE id = ?", (nid,)).fetchone()
    html = "<article>{body}</article>".format(body=row["body"])
    return html, 200, {"Content-Type": "text/html"}
''')


def test_stored_row_escaped_before_rendering_is_clean():
    assert not py_xss(FLASK + '''
@app.route("/notes/<int:nid>")
def note(nid):
    row = db().execute("SELECT body FROM notes WHERE id = ?", (nid,)).fetchone()
    html = "<article>{body}</article>".format(body=escape(row["body"]))
    return html, 200, {"Content-Type": "text/html"}
''')


# ---- adjacent literals with an f-string are one string with its values -----------------------

def test_adjacent_literal_and_f_string_keep_the_interpolated_value():
    assert py_xss(FLASK + '''
@app.route("/hello")
def hello():
    who = request.args.get("who", "")
    page = (
        "<!doctype html><html><body>"
        f"<p>{who}</p>"
        "</body></html>"
    )
    return page, 200, {"Content-Type": "text/html"}
''')


def test_adjacent_plain_literals_are_one_constant():
    from frame.sil.frontends.python_frontend import PythonFrontend
    prog = PythonFrontend().translate('def f():\n    x = ("<p>" "a" \'b\')\n    return x\n', "t.py")
    assigns = [str(i) for n in prog.procedures["f"].nodes.values() for i in n.instrs]
    assert 'x = "<p>ab"' in assigns


# ---- credentials written to a database ----------------------------------------------------------

def test_sql_statement_columns_that_hold_credentials():
    assert credential_parameters("INSERT INTO users (id, name, password) VALUES (?, ?, ?)") == {2: "password"}
    assert credential_parameters("INSERT INTO t (a, b, api_key, n) VALUES (?, ?, ?, 1)") == {2: "api_key"}
    assert credential_parameters("UPDATE users SET name = %s, session_token = %s WHERE id = %s") == \
        {1: "session_token"}
    assert credential_parameters("INSERT INTO t (a, token) VALUES ($1, $2)") == {1: "token"}
    assert credential_parameters("INSERT INTO t (a, token) VALUES (:a, :token)") == {"token": "token"}
    assert credential_parameters("INSERT INTO users (name, password_hash) VALUES (?, ?)") == {}
    assert credential_parameters("SELECT * FROM users WHERE password = ?") == {}
    assert credential_parameters("INSERT INTO t (a, b) VALUES (?)") == {}


def test_credential_names_by_head_noun():
    assert is_credential_name("password") and is_credential_name("owner_token")
    assert is_credential_name("apiKey") and is_credential_name("client_secret")
    assert not is_credential_name("password_hash") and not is_credential_name("token_type")
    assert not is_credential_name("license_key") and not is_credential_name("username")


def test_password_from_the_request_stored_as_is():
    assert py_cred(FLASK + '''
@app.route("/register", methods=["POST"])
def register():
    body = request.get_json()
    conn = db()
    conn.execute("INSERT INTO users (name, password) VALUES (?, ?)", (body["name"], body["password"]))
    conn.commit()
    return jsonify({"ok": True})
''')


def test_password_hashed_before_storing_is_clean():
    assert not py_cred(FLASK.replace("import sqlite3", "import sqlite3\nfrom werkzeug.security import "
                                     "generate_password_hash") + '''
@app.route("/register", methods=["POST"])
def register():
    body = request.get_json()
    conn = db()
    conn.execute("INSERT INTO users (name, password) VALUES (?, ?)",
                 (body["name"], generate_password_hash(body["password"])))
    conn.commit()
    return jsonify({"ok": True})
''')


def test_generated_token_stored_as_is():
    assert py_cred(FLASK.replace("import sqlite3", "import sqlite3\nimport secrets") + '''
@app.route("/sessions", methods=["POST"])
def login():
    token = "tok_" + secrets.token_urlsafe(24)
    db().execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)", (1, token))
    return jsonify({"token": token})
''')


def test_generated_token_stored_as_its_digest_is_clean():
    assert not py_cred(FLASK.replace("import sqlite3", "import sqlite3\nimport secrets\nimport hashlib") + '''
@app.route("/sessions", methods=["POST"])
def login():
    token = secrets.token_urlsafe(24)
    db().execute("INSERT INTO sessions (user_id, token) VALUES (?, ?)",
                 (1, hashlib.sha256(token.encode()).hexdigest()))
    return jsonify({"token": token})
''')


def test_a_generated_secret_is_no_attacker_data_elsewhere():
    found = cwes(FLASK.replace("import sqlite3", "import sqlite3\nimport secrets\nimport os") + '''
@app.route("/x", methods=["POST"])
def x():
    token = secrets.token_hex(8)
    os.system("echo " + token)
    db().execute("SELECT * FROM t WHERE token = '" + token + "'")
    return "<p>" + token + "</p>"
''')
    assert not found & {"CWE-78", "CWE-89", "CWE-79", "CWE-522"}


def test_a_column_that_is_not_a_credential_is_not_a_sink():
    assert not py_cred(FLASK + '''
@app.route("/users", methods=["POST"])
def users():
    body = request.get_json()
    db().execute("INSERT INTO users (name, email) VALUES (?, ?)", (body["name"], body["email"]))
    return jsonify({"ok": True})
''')


EXPRESS = '''
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3');
const app = express();
app.use(express.json());
const db = new sqlite3.Database('app.db');

function run(sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, (err) => (err ? reject(err) : resolve())));
}
'''


def test_js_password_stored_through_a_helper():
    assert "CWE-522" in js(EXPRESS + '''
app.post('/register', async (req, res) => {
  await run('INSERT INTO users (name, password) VALUES (?, ?)', [req.body.name, req.body.password]);
  res.json({ ok: true });
});
''')


def test_js_password_hashed_inline_is_clean():
    assert "CWE-522" not in js(EXPRESS + '''
app.post('/register', async (req, res) => {
  await run('INSERT INTO users (name, password) VALUES (?, ?)', [req.body.name, await bcrypt.hash(req.body.password, 10)]);
  res.json({ ok: true });
});
''')


def test_js_generated_token_stored_as_is():
    assert "CWE-522" in js(EXPRESS + '''
app.post('/sessions', async (req, res) => {
  const token = `tok_${crypto.randomBytes(24).toString('hex')}`;
  await run('INSERT INTO sessions (user_id, token) VALUES (?, ?)', [1, token]);
  res.json({ token });
});
''')


def test_js_generated_token_stored_as_its_digest_is_clean():
    assert "CWE-522" not in js(EXPRESS + '''
app.post('/sessions', async (req, res) => {
  const token = crypto.randomBytes(24).toString('hex');
  await run('INSERT INTO sessions (user_id, token) VALUES (?, ?)',
            [1, crypto.createHash('sha256').update(token).digest('hex')]);
  res.json({ token });
});
''')


# ---- functions passed to re.sub / String.replace / Array.map -----------------------------------

def test_re_sub_keeps_the_string_and_the_replacement():
    assert py_xss(FLASK.replace("import sqlite3", "import sqlite3\nimport re") + '''
@app.route("/a")
def a():
    out = re.sub(r"\\s+", " ", request.args["q"])
    return f"<p>{out}</p>"
''')


def test_re_sub_replacer_returning_request_data():
    assert py_xss(FLASK.replace("import sqlite3", "import sqlite3\nimport re") + '''
@app.route("/a", methods=["POST"])
def a():
    values = request.get_json()["values"]

    def fill(m):
        return str(values.get(m.group(1), ""))

    page = re.sub(r"\\{\\{(\\w+)\\}\\}", fill, "<p>Hello {{name}}</p>")
    return page, 200, {"Content-Type": "text/html"}
''')


def test_re_sub_replacer_escaping_its_value_is_clean():
    assert not py_xss(FLASK.replace("import sqlite3", "import sqlite3\nimport re") + '''
@app.route("/a", methods=["POST"])
def a():
    values = request.get_json()["values"]

    def fill(m):
        return str(escape(values.get(m.group(1), "")))

    page = re.sub(r"\\{\\{(\\w+)\\}\\}", fill, "<p>Hello {{name}}</p>")
    return page, 200, {"Content-Type": "text/html"}
''')


def test_js_replacer_function_returning_request_data():
    assert "CWE-79" in js(EXPRESS + '''
app.post('/preview', (req, res) => {
  const values = req.body.values;
  const html = '<p>{{name}}</p>'.replace(/\\{\\{(\\w+)\\}\\}/g, (m, key) => values[key]);
  res.type('html').send(html);
});
''')


def test_js_replacer_function_escaping_its_value_is_clean():
    assert "CWE-79" not in js(EXPRESS + '''
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
app.post('/preview', (req, res) => {
  const values = req.body.values;
  const html = '<p>{{name}}</p>'.replace(/\\{\\{(\\w+)\\}\\}/g, (m, key) => esc(values[key]));
  res.type('html').send(html);
});
''')


def test_js_map_to_constant_placeholders_carries_no_request_data():
    assert "CWE-89" not in js(EXPRESS + '''
app.post('/find', (req, res) => {
  const names = [...new Set(req.body.names)];
  const marks = names.map(() => '?').join(', ');
  db.all(`SELECT * FROM assets WHERE name IN (${marks})`, names, (err, rows) => res.json(rows));
});
''')


def test_js_map_quoting_each_element_carries_it():
    assert "CWE-89" in js(EXPRESS + '''
app.post('/find', (req, res) => {
  const names = req.body.names;
  const list = names.map((n) => `'${n}'`).join(', ');
  db.all(`SELECT * FROM assets WHERE name IN (${list})`, (err, rows) => res.json(rows));
});
''')


# ---- path containment -------------------------------------------------------------------------

FILES = '''
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const ROOT = path.resolve(__dirname, 'files');
'''


def test_js_path_relative_containment_is_a_guard():
    assert "CWE-22" not in js(FILES + '''
function inside(name) {
  const full = path.resolve(ROOT, name);
  const rel = path.relative(ROOT, full);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return null;
  return full;
}
app.get('/f', (req, res) => {
  const p = inside(req.query.name);
  if (!p) return res.status(400).end();
  res.json({ data: fs.readFileSync(p, 'utf8') });
});
''')


def test_js_path_relative_without_the_absolute_test_is_not():
    # path.relative across drives (Windows) returns an absolute path, which does not start with ".."
    assert "CWE-22" in js(FILES + '''
app.get('/f', (req, res) => {
  const full = path.resolve(ROOT, req.query.name);
  const rel = path.relative(ROOT, full);
  if (rel.startsWith('..')) return res.status(400).end();
  res.json({ data: fs.readFileSync(full, 'utf8') });
});
''')


PY_FILES = '''
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

'''


def test_constant_equality_beside_a_containment_test():
    assert "CWE-22" not in cwes(PY_FILES + '''
@app.route("/f")
def f():
    real = os.path.realpath(os.path.join(BASE_DIR, request.args["p"]))
    if not real.startswith(BASE_DIR + os.sep) and real != BASE_DIR:
        return jsonify({"error": "outside"}), 400
    with open(real, "rb") as fh:
        return jsonify({"size": len(fh.read())})
''')


def test_containment_test_on_a_path_that_is_not_normalised_is_not():
    assert "CWE-22" in cwes(PY_FILES + '''
@app.route("/f")
def f():
    path = os.path.join(BASE_DIR, request.args["p"])
    if not path.startswith(BASE_DIR + os.sep) and path != BASE_DIR:
        return jsonify({"error": "outside"}), 400
    with open(path, "rb") as fh:
        return jsonify({"size": len(fh.read())})
''')
