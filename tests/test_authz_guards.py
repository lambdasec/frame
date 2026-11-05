"""Guard facts for the agentic hunt (frame/sil/authz_guards.py).

The translator records, on its reporting walk, which edges it followed and where paths ended;
`guards_at` answers which conditions hold on EVERY feasible path to a line and `check_claim`
proves a claim or refutes it with a path that avoids it. Real frontends on small snippets, Python
and JavaScript. The recording is bookkeeping only, so findings must not change (pinned below)."""

from frame.sil.authz_guards import check_claim, guards_at, sink_lines
from frame.sil.scanner import FrameScanner


def _scan(code, name="a.py", lang="python"):
    sc = FrameScanner(language=lang, verify=False, hunt_authz=True)
    sc._collecting_hunt_programs = True          # keep the translated program, as a hunt does
    result = sc.scan(code, name)
    return sc._hunt_programs[0], result


FLASK = """from flask import Flask, request, abort
from flask_login import current_user, login_required
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)
db = SQLAlchemy(app)
class Doc(db.Model): pass

@app.route('/d/<int:pk>', methods=['DELETE'])
def view(pk):
    doc = Doc.query.get(pk)
{body}
    db.session.delete(doc)
    return 'ok'
"""

def _flask(body):
    code = FLASK.format(body=body)
    line = code.splitlines().index("    db.session.delete(doc)") + 1
    prog, _ = _scan(code)
    return prog, line


def _kinds(prog, proc, line):
    return {(g["kind"], g["text"]) for g in guards_at(prog, proc, line)}


def test_ownership_check_with_abort_guards_the_delete():
    prog, line = _flask("    if doc.owner_id != current_user.id:\n        abort(403)")
    facts = guards_at(prog, "view", line)
    own = [g for g in facts if g["kind"] == "ownership"]
    assert own and own[0]["text"] == "doc.owner_id != current_user.id -> abort(403)"
    assert own[0]["line"] == line - 2
    v = check_claim(prog, "view", line, {"kind": "guarded_by", "pattern": "owner"})
    assert v["verdict"] == "proved" and v["witness"] == []


def test_without_the_check_the_claim_is_refuted_with_a_path():
    prog, line = _flask("    pass")
    assert not [g for g in guards_at(prog, "view", line) if "owner" in g["text"]]
    v = check_claim(prog, "view", line, {"kind": "guarded_by", "pattern": "owner"})
    assert v["verdict"] == "refuted"
    assert v["witness"] and v["witness"][-1] == {"line": line, "took": "reached"}


def test_a_guard_on_one_branch_does_not_hold_after_the_join():
    body = ("    if request.args.get('x'):\n"
            "        if doc.owner_id != current_user.id:\n"
            "            abort(403)")
    prog, line = _flask(body)
    v = check_claim(prog, "view", line, {"kind": "guarded_by", "pattern": "owner"})
    assert v["verdict"] == "refuted"
    # the witness takes the branch that skips the check
    assert any(step.get("took") == "else" for step in v["witness"])
    assert not [g for g in guards_at(prog, "view", line) if "owner" in g["text"]]


def test_a_check_on_both_branches_holds_after_the_join():
    body = ("    if request.args.get('x'):\n"
            "        if doc.owner_id != current_user.id:\n"
            "            abort(403)\n"
            "    else:\n"
            "        if doc.owner_id != current_user.id:\n"
            "            abort(404)")
    prog, line = _flask(body)
    # different checks on the two paths: no single fact holds everywhere, but every path passes
    # one matching the claim
    v = check_claim(prog, "view", line, {"kind": "guarded_by", "pattern": "owner_id"})
    assert v["verdict"] == "proved"


def test_reassigning_the_checked_object_kills_the_guard():
    body = ("    if doc.owner_id != current_user.id:\n"
            "        abort(403)\n"
            "    doc = Doc.query.get(request.args['other'])")
    prog, line = _flask(body)
    v = check_claim(prog, "view", line, {"kind": "guarded_by", "pattern": "owner"})
    assert v["verdict"] == "refuted"


def test_early_return_guard_on_a_permission():
    code = FLASK.replace("def view(pk):\n    doc = Doc.query.get(pk)\n{body}",
                         "def view(pk):\n    if not current_user.is_admin:\n        return 'no', 403\n"
                         "    doc = Doc.query.get(pk)")
    line = code.splitlines().index("    db.session.delete(doc)") + 1
    prog, _ = _scan(code)
    v = check_claim(prog, "view", line, {"kind": "guarded_by", "pattern": "is_admin"})
    assert v["verdict"] == "proved"
    assert ("noreturn_guard", "!(current_user.is_admin) -> return 'no', 403") in _kinds(prog, "view", line)


def test_an_auth_gate_decorator_is_a_fact_everywhere_in_the_handler():
    code = FLASK.replace("def view(pk):", "@login_required\ndef view(pk):").format(body="    pass")
    line = code.splitlines().index("    db.session.delete(doc)") + 1
    prog, _ = _scan(code)
    assert ("decorator", "@login_required") in _kinds(prog, "view", line)
    v = check_claim(prog, "view", line, {"kind": "guarded_by", "pattern": "login_required"})
    assert v["verdict"] == "proved"


SCOPED = """from flask import Flask, request
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)
db = SQLAlchemy(app)
class Order(db.Model): pass

@app.route('/a')
def a():
    order = Order.query.filter_by(owner_id=current_user.id, id=request.args['id']).first()
    return str(order)

@app.route('/b')
def b():
    order = Order.query.get(request.args['id'])
    return str(order)
"""

KNOWN_CALLER = """from flask import Flask, request
from flask_jwt_extended import get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)
db = SQLAlchemy(app)
class Order(db.Model): pass

@app.route('/c')
def c():
    me = get_jwt_identity()
    order = Order.query.get(request.args['id'])
    return str(order) + str(me)
"""


def test_scoped_by_identity_proved_for_a_caller_filtered_query():
    prog, _ = _scan(SCOPED)
    v = check_claim(prog, "a", 10, {"kind": "scoped_by_identity"})
    assert v["verdict"] == "proved"
    assert any(g["kind"] == "identity_scope" for g in guards_at(prog, "a", 10))


def test_scoped_by_identity_refuted_when_the_caller_is_known_but_not_used():
    # The handler reads the authenticated caller, yet looks the order up by id alone.
    prog, _ = _scan(KNOWN_CALLER)
    v = check_claim(prog, "c", 11, {"kind": "scoped_by_identity"})
    assert v["verdict"] == "refuted"
    assert 11 in sink_lines(prog, "c")


def test_scoped_by_identity_is_unknown_when_the_engine_never_sees_the_caller():
    # No identity the engine recognises anywhere in the handler: it cannot tell an unscoped
    # lookup from one filtered by an identity it does not model (aegra's dependency-injected
    # `user.identity` was refuted -- wrongly -- before this). Unknown, with what to do about it.
    prog, _ = _scan(SCOPED)
    v = check_claim(prog, "b", 15, {"kind": "scoped_by_identity"})
    assert v["verdict"] == "unknown" and "identifies the caller" in v["reason"]
    assert 15 in sink_lines(prog, "b")


EXPRESS = """const express = require('express');
const { Pool } = require('pg');
const pool = new Pool();
const app = express();
app.delete('/doc/:id', async (req, res) => {
  const doc = await pool.query('SELECT * FROM docs WHERE id = $1', [req.params.id]);
{body}
  await pool.query('DELETE FROM docs WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});
"""


def _express(body):
    code = EXPRESS.replace("{body}", body)
    line = code.splitlines().index("  await pool.query('DELETE FROM docs WHERE id = $1', [req.params.id]);") + 1
    prog, _ = _scan(code, "a.js", "javascript")
    proc = next(n for n in prog.path_guards if n != "<module>")
    return prog, proc, line


def test_express_ownership_check_with_early_return_is_proved():
    prog, proc, line = _express("  if (doc.ownerId !== req.user.id) return res.status(403).end();")
    v = check_claim(prog, proc, line, {"kind": "guarded_by", "pattern": "ownerId"})
    assert v["verdict"] == "proved"
    texts = [g["text"] for g in guards_at(prog, proc, line)]
    assert any(t.startswith("doc.ownerId !== req.user.id -> return") for t in texts)


def test_express_without_the_check_is_refuted():
    prog, proc, line = _express("")
    v = check_claim(prog, proc, line, {"kind": "guarded_by", "pattern": "ownerId"})
    assert v["verdict"] == "refuted" and v["witness"]


def test_unknown_procedure_or_line_is_unknown_and_never_raises():
    prog, line = _flask("    pass")
    assert guards_at(prog, "nope", line) == []
    assert guards_at(prog, "view", 9999) == []
    assert check_claim(prog, "nope", line, {"kind": "guarded_by", "pattern": "x"})["verdict"] == "unknown"
    assert check_claim(prog, "view", 9999, {"kind": "guarded_by", "pattern": "x"})["verdict"] == "unknown"
    assert check_claim(prog, "view", line, {"kind": "made_up"})["verdict"] == "unknown"
    # `return 'ok'` is no resource operation: nothing to scope
    assert check_claim(prog, "view", line + 1, {"kind": "scoped_by_identity"})["verdict"] == "unknown"
    # the delete is one, but nothing in the handler identifies the caller: the engine cannot
    # tell unscoped from scoped by an identity it does not model
    assert check_claim(prog, "view", line, {"kind": "scoped_by_identity"})["verdict"] == "unknown"
    # a program that was never translated with the recording on
    assert guards_at(object(), "view", line) == []
    assert check_claim(None, "view", line, {"kind": "guarded_by", "pattern": "x"})["verdict"] == "unknown"


def test_a_simple_name_finds_a_qualified_procedure():
    code = ("from flask import Flask, abort\nfrom flask.views import MethodView\n"
            "from flask_login import current_user\nfrom flask_sqlalchemy import SQLAlchemy\n"
            "app = Flask(__name__)\ndb = SQLAlchemy(app)\nclass Doc(db.Model): pass\n\n"
            "class DocView(MethodView):\n"
            "    def delete(self, pk):\n"
            "        doc = Doc.query.get(pk)\n"
            "        if doc.owner_id != current_user.id:\n"
            "            abort(403)\n"
            "        db.session.delete(doc)\n"
            "        return 'ok'\n")
    prog, _ = _scan(code)
    assert any(n.endswith("delete") for n in prog.path_guards)
    v = check_claim(prog, "delete", 14, {"kind": "guarded_by", "pattern": "owner"})
    assert v["verdict"] == "proved"


def test_recording_does_not_change_findings():
    # The same IDOR shapes test_identity pins: recording guard facts is bookkeeping only.
    _, result = _scan(SCOPED)
    assert sorted((v.line, v.cwe_id) for v in result.vulnerabilities if v.cwe_id == "CWE-639") == [(15, "CWE-639")]
