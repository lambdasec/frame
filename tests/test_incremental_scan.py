"""Scanning what changed, against a baseline, and verifying fixes.

The guardrail loop an agent integration runs: record a baseline, scan only the
changed files and report only new findings, then confirm each one is fixed --
where "silenced with `frame: ignore`" and "moved" never count as fixed.
"""

import json
import subprocess

import pytest

from frame.cli import main as frame_main
from frame.sil.fingerprints import (
    assign_fingerprints, match_findings, normalize_procedure, project_root)
from frame.sil.scanner import FrameScanner

SQLI = """from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/q")
def q():
    name = request.args.get("name")
    sqlite3.connect("x").execute("SELECT * FROM u WHERE n = '%s'" % name)
    return "ok"
"""

SECOND_SQLI = """

@app.route("/p")
def p():
    pid = request.args.get("pid")
    sqlite3.connect("x").execute("SELECT * FROM p WHERE id = " + pid)
    return "ok"
"""

CMDI = """import os
from flask import request

def run():
    os.system("ls " + request.args.get("d"))
"""


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
                    *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    git(tmp_path, "init", "-q")
    (tmp_path / "app.py").write_text(SQLI)
    (tmp_path / "util.py").write_text("def add(a, b):\n    return a + b\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def scan(capsys, *args):
    rc = frame_main(["scan", *args, "--no-verify", "-f", "json"])
    captured = capsys.readouterr()
    scan.last_err = captured.err
    return rc, json.loads(captured.out) if captured.out.strip() else None


def new_findings(doc):
    return [(v["path"], v["cwe_id"], v["procedure"])
            for f in doc["files"] for v in f["vulnerabilities"]]


def shift_down(path, n=3):
    text = path.read_text().replace("app = Flask(__name__)\n",
                                    "app = Flask(__name__)\n" + "# pad\n" * n, 1)
    path.write_text(text)


# ---- fingerprints ---------------------------------------------------------------

def _fingerprinted(path):
    r = FrameScanner(language="python", verify=False).scan_file(str(path))
    assign_fingerprints([r], project_root(path))
    return r.vulnerabilities


def test_fingerprint_survives_lines_added_above(repo):
    before = _fingerprinted(repo / "app.py")
    shift_down(repo / "app.py")
    after = _fingerprinted(repo / "app.py")
    assert [v.fingerprint for v in before] == [v.fingerprint for v in after]
    assert before[0].line != after[0].line


def test_reformatted_line_matches_loosely(repo):
    before = _fingerprinted(repo / "app.py")
    (repo / "app.py").write_text(SQLI.replace(
        "sqlite3.connect(\"x\").execute(", "sqlite3.connect(\"x\").execute(  "))
    after = _fingerprinted(repo / "app.py")
    assert before[0].fingerprint != after[0].fingerprint
    prior = [{"fingerprint": v.fingerprint, "fingerprint_loose": v.fingerprint_loose,
              "line": v.line} for v in before]
    assert len(match_findings(prior, after).pairs) == 1


def test_second_instance_in_same_function_is_new(repo):
    before = _fingerprinted(repo / "app.py")
    # A separate statement block: same-CWE findings within a 5-line window are
    # merged as variants of one flow (`_deduplicate_vulnerabilities` phase 2).
    (repo / "app.py").write_text(SQLI.replace(
        '    return "ok"',
        '    log = []\n    log.append(name)\n    log.append("q")\n    log.append("done")\n'
        '    count = len(log)\n'
        '    sqlite3.connect("y").execute("DELETE FROM u WHERE n = \'%s\'" % name)\n'
        '    return "ok"'))
    prior = [{"fingerprint": v.fingerprint, "fingerprint_loose": v.fingerprint_loose,
              "line": v.line} for v in before]
    after = FrameScanner(language="python", verify=False).scan_file(str(repo / "app.py"))
    assign_fingerprints([after], repo)
    m = match_findings(prior, after.vulnerabilities)
    assert len(after.vulnerabilities) == 2
    assert len(m.pairs) == 1 and len(m.unmatched_current) == 1
    assert m.pairs[0][1].line == before[0].line          # the original pairs with itself


def test_position_suffixes_are_not_identity():
    assert normalize_procedure("anonymous_L12") == "anonymous"
    assert normalize_procedure("handler_L5C3") == "handler"
    assert normalize_procedure("<unsafe-deserialize>-0") == "<unsafe-deserialize>"
    assert normalize_procedure("F_Spring.user") == "F_Spring.user"


# ---- --changed / --files / --baseline ----------------------------------------------

def test_nothing_changed_is_a_clean_scan(repo, capsys):
    rc, doc = scan(capsys, ".", "--changed")
    assert rc == 0 and doc["files"] == [] and doc["schema_version"] == 1


def test_changed_scans_only_modified_and_untracked_files(repo, capsys):
    (repo / "app.py").write_text(SQLI + "\n# touched\n")
    (repo / "new.py").write_text(CMDI)
    rc, doc = scan(capsys, ".", "--changed")
    assert {f["filename"].rsplit("/", 1)[-1] for f in doc["files"]} == {"app.py", "new.py"}
    assert rc == 1


def test_changed_against_a_ref(repo, capsys):
    (repo / "new.py").write_text(CMDI)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "second")
    rc, doc = scan(capsys, ".", "--changed", "HEAD~1")
    assert [f["filename"].rsplit("/", 1)[-1] for f in doc["files"]] == ["new.py"]


def test_changed_in_a_repository_without_commits(tmp_path, capsys, monkeypatch):
    git(tmp_path, "init", "-q")
    (tmp_path / "new.py").write_text(CMDI)
    monkeypatch.chdir(tmp_path)
    rc, doc = scan(capsys, ".", "--changed")
    assert ("new.py", "CWE-78", "run") in new_findings(doc)


def test_changed_errors_exit_2(repo, tmp_path_factory, capsys, monkeypatch):
    assert frame_main(["scan", ".", "--changed", "no-such-ref", "--no-verify"]) == 2
    plain = tmp_path_factory.mktemp("plain")
    (plain / "a.py").write_text("x = 1\n")
    monkeypatch.chdir(plain)
    assert frame_main(["scan", ".", "--changed", "--no-verify"]) == 2
    assert frame_main(["scan", "a.py", "--changed", "--no-verify"]) == 2
    capsys.readouterr()


def test_files_limits_the_scan(repo, capsys):
    (repo / "new.py").write_text(CMDI)
    rc, doc = scan(capsys, ".", "--files", "new.py", "missing.py")
    assert [f["filename"].rsplit("/", 1)[-1] for f in doc["files"]] == ["new.py"]
    assert "missing.py" in scan.last_err


def test_baseline_reports_only_new_findings(repo, capsys):
    assert frame_main(["scan", ".", "--no-verify", "--fail-on", "none",
                       "--write-baseline", "b.json", "-f", "json"]) == 0
    capsys.readouterr()
    shift_down(repo / "app.py")                     # the known finding moves
    (repo / "app.py").write_text((repo / "app.py").read_text() + SECOND_SQLI)
    (repo / "util.py").write_text(CMDI)
    rc, doc = scan(capsys, ".", "--changed", "--baseline", "b.json")
    assert rc == 1
    assert sorted(new_findings(doc)) == [("app.py", "CWE-89", "p"), ("util.py", "CWE-78", "run")]
    assert doc["baseline"]["baselined"] == 1 and doc["baseline"]["fixed"] == []
    assert doc["summary"]["baselined"] == 1


def test_only_known_findings_pass(repo, capsys):
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "--write-baseline", "b.json"])
    capsys.readouterr()
    shift_down(repo / "app.py")
    rc, doc = scan(capsys, ".", "--baseline", "b.json", "--fail-on", "any")
    assert rc == 0 and new_findings(doc) == []


def test_baseline_lists_fixed_findings(repo, capsys):
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "--write-baseline", "b.json"])
    capsys.readouterr()
    (repo / "app.py").write_text(SQLI.replace(
        "\"SELECT * FROM u WHERE n = '%s'\" % name", "\"SELECT * FROM u WHERE n = ?\", (name,)"))
    rc, doc = scan(capsys, ".", "--changed", "--baseline", "b.json")
    assert rc == 0
    assert [(e["path"], e["cwe_id"]) for e in doc["baseline"]["fixed"]] == [("app.py", "CWE-89")]


def test_partial_scan_updates_the_baseline_without_truncating_it(repo, capsys):
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "--write-baseline", "b.json"])
    (repo / "util.py").write_text(CMDI)
    frame_main(["scan", ".", "--changed", "--no-verify", "--fail-on", "none",
                "--write-baseline", "b.json"])
    capsys.readouterr()
    entries = json.loads((repo / "b.json").read_text())["findings"]
    assert sorted((e["path"], e["cwe_id"]) for e in entries) == [
        ("app.py", "CWE-89"), ("util.py", "CWE-78")]


def test_bad_baseline_exits_2(repo, capsys):
    assert frame_main(["scan", ".", "--no-verify", "--baseline", "nope.json"]) == 2
    (repo / "bad.json").write_text("{}")
    assert frame_main(["scan", ".", "--no-verify", "--baseline", "bad.json"]) == 2
    assert "not a Frame baseline" in capsys.readouterr().err


def test_sarif_carries_fingerprints_and_baseline_state(repo, capsys):
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "--write-baseline", "b.json"])
    (repo / "util.py").write_text(CMDI)
    capsys.readouterr()
    frame_main(["scan", ".", "--no-verify", "--baseline", "b.json", "-f", "sarif"])
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert len(results) == 1
    assert set(results[0]["partialFingerprints"]) == {"frame/v1", "frame-loose/v1"}
    assert results[0]["baselineState"] == "new"


# ---- frame verify --------------------------------------------------------------------

def _scan_to_file(repo, capsys, *args):
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "-f", "json",
                "-o", "findings.json", *args])
    capsys.readouterr()
    return repo / "findings.json"


def verify(capsys, path, *args):
    rc = frame_main(["verify", str(path), "-f", "json", *args])
    doc = json.loads(capsys.readouterr().out)
    return rc, {r["path"]: r["status"] for r in doc["results"]}


def test_verify_fixed_and_still_present(repo, capsys):
    (repo / "util.py").write_text(CMDI)
    findings = _scan_to_file(repo, capsys)
    (repo / "app.py").write_text(SQLI.replace(
        "\"SELECT * FROM u WHERE n = '%s'\" % name", "\"SELECT * FROM u WHERE n = ?\", (name,)"))
    shift = (repo / "util.py").read_text().replace("import os\n", "import os\nimport sys\n")
    (repo / "util.py").write_text(shift)
    rc, status = verify(capsys, findings)
    assert status == {"app.py": "fixed", "util.py": "present"}
    assert rc == 1


def test_verify_all_fixed_exits_0(repo, capsys):
    findings = _scan_to_file(repo, capsys)
    (repo / "app.py").write_text(SQLI.replace(
        "\"SELECT * FROM u WHERE n = '%s'\" % name", "\"SELECT * FROM u WHERE n = ?\", (name,)"))
    assert verify(capsys, findings) == (0, {"app.py": "fixed"})


def test_verify_suppression_is_not_a_fix(repo, capsys):
    findings = _scan_to_file(repo, capsys)
    (repo / "app.py").write_text(SQLI.replace("% name)", "% name)  # frame: ignore"))
    assert verify(capsys, findings) == (1, {"app.py": "suppressed"})


def test_verify_renamed_bug_is_uncertain_not_fixed(repo, capsys):
    findings = _scan_to_file(repo, capsys)
    (repo / "app.py").write_text(SQLI.replace("name", "who"))
    assert verify(capsys, findings) == (1, {"app.py": "uncertain"})


def test_verify_known_finding_is_not_mistaken_for_a_moved_one(repo, capsys):
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "--write-baseline", "b.json"])
    (repo / "app.py").write_text(SQLI + SECOND_SQLI)
    findings = _scan_to_file(repo, capsys, "--baseline", "b.json")
    (repo / "app.py").write_text(SQLI + SECOND_SQLI.replace(
        '" + pid)', '?", (pid,))'))
    assert verify(capsys, findings) == (0, {"app.py": "fixed"})


def test_verify_from_another_directory(repo, capsys, tmp_path_factory, monkeypatch):
    findings = _scan_to_file(repo, capsys)
    (repo / "app.py").write_text(SQLI.replace(
        "\"SELECT * FROM u WHERE n = '%s'\" % name", "\"SELECT * FROM u WHERE n = ?\", (name,)"))
    monkeypatch.chdir(tmp_path_factory.mktemp("elsewhere"))
    assert verify(capsys, findings) == (0, {"app.py": "fixed"})


def test_verify_removed_file(repo, capsys):
    findings = _scan_to_file(repo, capsys)
    (repo / "app.py").unlink()
    assert verify(capsys, findings) == (0, {"app.py": "file_removed"})


def test_verify_without_root_never_claims_removed(repo, capsys, tmp_path_factory, monkeypatch):
    findings = _scan_to_file(repo, capsys)
    doc = json.loads(findings.read_text())
    doc.pop("root")
    findings.write_text(json.dumps(doc))
    monkeypatch.chdir(tmp_path_factory.mktemp("elsewhere"))
    assert verify(capsys, findings) == (1, {"app.py": "unverifiable"})


def test_verify_one_id_and_unknown_id(repo, capsys):
    (repo / "util.py").write_text(CMDI)
    findings = _scan_to_file(repo, capsys)
    doc = json.loads(findings.read_text())
    fp = next(v["fingerprint"] for f in doc["files"] for v in f["vulnerabilities"]
              if v["path"] == "util.py")
    assert verify(capsys, findings, "--id", fp) == (1, {"util.py": "present"})
    assert frame_main(["verify", str(findings), "--id", "0000000000000000"]) == 2
    capsys.readouterr()


def test_verify_needs_fingerprints(tmp_path, capsys):
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"vulnerabilities": [{"location": "a.py", "line": 1,
                                                    "cwe_id": "CWE-89"}]}))
    assert frame_main(["verify", str(old)]) == 2
    assert "fingerprint" in capsys.readouterr().err
