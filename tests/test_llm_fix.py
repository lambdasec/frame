"""Tests for the LLM remediation layer + `frame fix` CLI (no network -- stubbed)."""

import argparse
import json
from types import SimpleNamespace

from frame.sil.llm_triage import TriageConfig, LLMTriageClient
from frame.sil.llm_fix import (
    generate_fix, apply_fix, make_diff, verify_fix, _fix_response_format, FIX_SCHEMA,
)
import frame.sil.llm_fix as fixmod
import frame.cli as cli


def test_apply_fix_exact_whitespace_and_nomatch():
    src = "def f(x):\n    q = 'SELECT '+x\n    return q\n"
    out, ok = apply_fix(src, {"original": "q = 'SELECT '+x",
                              "replacement": "q = param_query('SELECT ?', x)"})
    assert ok and "param_query" in out and "'SELECT '+x" not in out
    # whitespace-tolerant: model echoed the span with different surrounding spacing
    out2, ok2 = apply_fix(src, {"original": "q = 'SELECT '+x   ", "replacement": "SAFE"})
    assert ok2 and "SAFE" in out2
    # no match -> not applied, source unchanged
    out3, ok3 = apply_fix(src, {"original": "not in the file", "replacement": "x"})
    assert not ok3 and out3 == src
    # empty original -> not applied
    assert apply_fix(src, {"original": "", "replacement": "x"}) == (src, False)


def test_make_diff():
    d = make_diff("a.py", "line1\nbad\n", "line1\ngood\n")
    assert "-bad" in d and "+good" in d and "a/a.py" in d


def test_fix_response_format():
    assert _fix_response_format("json_object") == {"type": "json_object"}
    js = _fix_response_format("json_schema")
    assert js["type"] == "json_schema" and js["json_schema"]["strict"] is True
    assert js["json_schema"]["schema"] is FIX_SCHEMA
    assert _fix_response_format("off") is None


def test_generate_fix_structured():
    patch = {"reasoning": "concat", "original": "q='SELECT '+x",
             "replacement": "q=cur.execute('SELECT ?',(x,))", "rationale": "parameterized"}
    c = LLMTriageClient(TriageConfig(base_url="x", model="m"),
                        call_fn=lambda m: json.dumps(patch))
    g = generate_fix({"cwe_id": "CWE-89", "line": 2, "type": "sqli"},
                     "code", TriageConfig(), c)
    assert g["replacement"].startswith("q=cur.execute") and g["rationale"] == "parameterized"


def test_verify_fix_gone_vs_still(monkeypatch):
    # patched code re-scans clean -> verified True
    monkeypatch.setattr(fixmod, "detect_in_file", lambda *a, **k: [])
    assert verify_fix("safe", "python", "x.py", {"cwe_id": "CWE-89"}, TriageConfig()) is True
    # still detects same CWE -> verified False
    monkeypatch.setattr(fixmod, "detect_in_file",
                        lambda *a, **k: [SimpleNamespace(cwe_id="CWE-89")])
    assert verify_fix("bad", "python", "x.py", {"cwe_id": "CWE-89"}, TriageConfig()) is False
    # a different CWE remains but ours is gone -> verified True
    monkeypatch.setattr(fixmod, "detect_in_file",
                        lambda *a, **k: [SimpleNamespace(cwe_id="CWE-79")])
    assert verify_fix("x", "python", "x.py", {"cwe_id": "CWE-89"}, TriageConfig()) is True
    # detection itself raises -> could not verify (None)
    def boom(*a, **k): raise RuntimeError("down")
    monkeypatch.setattr(fixmod, "detect_in_file", boom)
    assert verify_fix("x", "python", "x.py", {"cwe_id": "CWE-89"}, TriageConfig()) is None


def _fix_args(**kw):
    base = dict(source=None, guidance=None, in_place=False, diff=False,
                no_verify=False, model=None, format="text")
    base.update(kw)
    return argparse.Namespace(**base)


def _stub_fix(monkeypatch, *, verified=True):
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("FRAME_LLM_MODEL", "m")
    monkeypatch.setattr(fixmod, "generate_fix", lambda f, s, c, client=None: {
        "original": "q='SELECT '+x", "replacement": "q=safe('SELECT ?', x)",
        "rationale": "parameterized"})
    monkeypatch.setattr(fixmod, "verify_fix", lambda *a, **k: verified)


def test_cmd_fix_diff_mode_does_not_write(monkeypatch, tmp_path, capsys):
    _stub_fix(monkeypatch)
    src = tmp_path / "app.py"
    src.write_text("def h(x):\n    q='SELECT '+x\n    return q\n")
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps({"vulnerabilities": [
        {"cwe_id": "CWE-89", "type": "sqli", "line": 2, "location": str(src)}]}))
    rc = cli.cmd_fix(_fix_args(source=str(tmp_path), guidance=str(findings)))
    out = capsys.readouterr().out
    assert rc == 0
    assert "safe('SELECT ?'" in out and "verified" in out          # diff + verify shown
    assert src.read_text() == "def h(x):\n    q='SELECT '+x\n    return q\n"  # NOT modified


def test_cmd_fix_in_place_writes_and_verifies(monkeypatch, tmp_path, capsys):
    _stub_fix(monkeypatch, verified=True)
    src = tmp_path / "app.py"
    src.write_text("def h(x):\n    q='SELECT '+x\n    return q\n")
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps({"vulnerabilities": [
        {"cwe_id": "CWE-89", "type": "sqli", "line": 2, "location": str(src)}]}))
    rc = cli.cmd_fix(_fix_args(source=str(tmp_path), guidance=str(findings), in_place=True))
    assert rc == 0 and "safe('SELECT ?'" in src.read_text()         # file patched
    assert "1 verified fixed" in capsys.readouterr().out


def test_cmd_fix_requires_env(monkeypatch, tmp_path):
    monkeypatch.delenv("FRAME_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("FRAME_LLM_MODEL", raising=False)
    f = tmp_path / "f.json"; f.write_text(json.dumps({"vulnerabilities": []}))
    assert cli.cmd_fix(_fix_args(source=str(tmp_path), guidance=str(f))) == 1
