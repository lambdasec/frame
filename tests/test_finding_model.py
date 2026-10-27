"""Every finding carries a category (what kind of weakness) and an evidence level (how it
is proven), in the JSON and SARIF output alike."""

from frame.sil.findings import CATEGORIES, EVIDENCE_LEVELS, category_of, evidence_of_check
from frame.sil.scanner import FrameScanner


def findings(code: str, language: str, name: str):
    r = FrameScanner(language=language).scan(code, name)
    return {v.cwe_id: v.to_dict() for v in r.vulnerabilities}


def test_injection_is_taint_and_solver_verified():
    code = ("import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n"
            "@app.route('/u')\ndef u():\n    q = request.args.get('q')\n"
            "    sqlite3.connect('d').execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")\n    return 'ok'\n")
    f = findings(code, "python", "a.py")["CWE-89"]
    assert (f["category"], f["evidence"]) == ("taint", "solver-verified")


def test_weak_hash_is_crypto_and_matched():
    f = findings("import hashlib\nh = hashlib.md5(b'x').hexdigest()\n", "python", "a.py")["CWE-328"]
    assert (f["category"], f["evidence"]) == ("crypto", "matched")


def test_hardening_finding_keeps_its_category():
    code = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
    f = next(v for v in findings(code, "python", "a.py").values() if v.get("category") == "hardening")
    assert f["evidence"] == "matched"


def test_memory_findings_are_memory():
    assert category_of("use_after_free") == "memory" and category_of("oob_write") == "memory"


def test_vocabulary():
    assert category_of("sql_injection") == "taint" and category_of("idor") == "access-control"
    assert category_of("hardcoded_secret") == "secret" and category_of("anything", "iac") == "iac"
    assert evidence_of_check(True, True) == "solver-verified"
    assert evidence_of_check(False, True) == "data-flow" and evidence_of_check(True, False) == "matched"
    assert set(EVIDENCE_LEVELS) >= {"matched", "data-flow", "solver-verified", "exploit-confirmed"}
    assert {"taint", "memory", "dependency", "iac", "container"} <= set(CATEGORIES)
