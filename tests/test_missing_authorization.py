"""Missing function-level authorization (CWE-862) by the application's own convention.

Among a program's entry-point handlers that touch a resource, when a clear majority are protected
(an authorization gate from an applied pack's `[[auth_gate]]`, or the authenticated caller used to
scope the access) and a minority are not, the unprotected handlers are the ones that skipped the
check their peers apply. This needs no notion of which endpoints are 'meant' to be public: it is
relative to the app's own norm, so an app with no authorization at all stays silent, and a handler
that already carries an idor finding is left to that finding rather than reported twice.

See frame/sil/translator.py `_missing_authorization_checks`, and the `[[auth_gate]]` pack entry
(frame/sil/packs/schema.py, populated in python/flask-auth.toml and python/django.toml)."""

from frame.sil.scanner import FrameScanner


def _cwes(code, name="a.py"):
    return sorted((v.line, v.cwe_id) for v in
                  FrameScanner(language="python", verify=False).scan(code, name).vulnerabilities
                  if v.cwe_id in ("CWE-862", "CWE-639"))


HEAD = ("from flask import Flask, request, jsonify\n"
        "from flask_login import login_required, current_user\n"
        "from flask_sqlalchemy import SQLAlchemy\n"
        "app = Flask(__name__)\n"
        "db = SQLAlchemy(app)\n"
        "class Doc(db.Model): pass\n")

SCOPED_A = ("\n@app.route('/a')\n@login_required\ndef a():\n"
            "    return jsonify(Doc.query.filter_by(owner_id=current_user.id).all())\n")
SCOPED_B = ("\n@app.route('/b')\n@login_required\ndef b():\n"
            "    return jsonify(Doc.query.filter_by(owner_id=current_user.id).all())\n")


def test_ungated_handler_is_flagged_when_peers_are_protected():
    deviant = ("\n@app.route('/c')\ndef c():\n"
               "    return jsonify(Doc.query.filter_by(status='public').all())\n")
    out = _cwes(HEAD + SCOPED_A + SCOPED_B + deviant)
    assert out == [(19, "CWE-862")]


def test_no_authorization_convention_stays_silent():
    # Every handler is ungated and none scopes by the caller: there is no norm to deviate from.
    body = "".join(
        f"\n@app.route('/{n}')\ndef {n}():\n    return jsonify(Doc.query.filter_by(status='x').all())\n"
        for n in ("a", "b", "c"))
    assert _cwes(HEAD + body) == []


def test_a_single_protected_peer_is_not_a_convention():
    # One protected handler is not a strong enough norm (needs >= 2 protected, a strict majority).
    deviant = ("\n@app.route('/c')\ndef c():\n"
               "    return jsonify(Doc.query.filter_by(status='public').all())\n")
    assert _cwes(HEAD + SCOPED_A + deviant) == []


def test_unprotected_majority_is_not_a_convention():
    # Protected handlers must be a strict majority; two ungated against one scoped is not a norm.
    ungated = "".join(
        f"\n@app.route('/u{n}')\ndef u{n}():\n    return jsonify(Doc.query.filter_by(status='x').all())\n"
        for n in (1, 2))
    assert _cwes(HEAD + SCOPED_A + ungated) == []


def test_an_idor_handler_is_not_double_reported():
    # The deviant handler is itself an idor (attacker id, unscoped): report CWE-639 once, not 862.
    idor = ("\n@app.route('/c')\ndef c():\n"
            "    return jsonify(Doc.query.get(request.args['id']))\n")
    out = _cwes(HEAD + SCOPED_A + SCOPED_B + idor)
    assert out == [(20, "CWE-639")]


def test_a_gate_decorator_counts_as_protected():
    # The convention can be established by the gate alone (no caller-scoping in the body).
    gated = ("\n@app.route('/a')\n@login_required\ndef a():\n"
             "    return jsonify(Doc.query.filter_by(status='x').all())\n"
             "\n@app.route('/b')\n@login_required\ndef b():\n"
             "    return jsonify(Doc.query.filter_by(status='y').all())\n")
    deviant = ("\n@app.route('/c')\ndef c():\n"
               "    return jsonify(Doc.query.filter_by(status='z').all())\n")
    out = _cwes(HEAD + gated + deviant)
    assert out == [(19, "CWE-862")]


def test_a_handler_touching_no_resource_is_not_flagged():
    # Only handlers that perform a resource / DB operation are compared; a plain endpoint is not.
    deviant = "\n@app.route('/c')\ndef c():\n    return jsonify({'ok': True})\n"
    assert _cwes(HEAD + SCOPED_A + SCOPED_B + deviant) == []


# -- the authorization gate is pack data, not hardcoded --------------------------------------------

import pytest  # noqa: E402

from frame.sil.packs.loader import load_pack_file  # noqa: E402
from frame.sil.packs.schema import PackError  # noqa: E402


def test_auth_gate_is_validated_strictly(tmp_path):
    p = tmp_path / "bad.toml"
    p.write_text('[pack]\nname = "x"\nlanguage = "python"\n\n[[auth_gate]]\ndecorator = ["a.b"]\nnope = 1\n')
    with pytest.raises(PackError):
        load_pack_file(p)


def test_an_auth_gate_needs_a_decorator(tmp_path):
    p = tmp_path / "empty.toml"
    p.write_text('[pack]\nname = "x"\nlanguage = "python"\n\n[[auth_gate]]\n')
    with pytest.raises(PackError):
        load_pack_file(p)


def test_a_project_defined_gate_establishes_the_convention(tmp_path):
    # A team's own authorization decorator, taught via a project pack, makes gated handlers count as
    # protected -- so the feature is driven by pack data, with no framework name special-cased.
    (tmp_path / ".frame" / "packs").mkdir(parents=True)
    (tmp_path / ".frame" / "packs" / "acme.toml").write_text(
        '[pack]\nname = "acme"\nlanguage = "python"\ndescription = "acme auth"\n\n'
        '[[auth_gate]]\ndecorator = ["acme.auth.require_user"]\n')
    app = ("from flask import Flask, jsonify\nfrom acme.auth import require_user\n"
           "from flask_sqlalchemy import SQLAlchemy\napp = Flask(__name__)\n"
           "db = SQLAlchemy(app)\nclass Doc(db.Model): pass\n"
           "@app.route('/a')\n@require_user\ndef a():\n    return jsonify(Doc.query.filter_by(k='a').all())\n"
           "@app.route('/b')\n@require_user\ndef b():\n    return jsonify(Doc.query.filter_by(k='b').all())\n"
           "@app.route('/c')\ndef c():\n    return jsonify(Doc.query.filter_by(k='c').all())\n")
    (tmp_path / "app.py").write_text(app)
    run = FrameScanner(language="python", verify=False).scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    cwes = [v.cwe_id for f in run for v in f.vulnerabilities if v.cwe_id == "CWE-862"]
    assert cwes == ["CWE-862"]       # only the ungated handler c deviates from the gated peers
