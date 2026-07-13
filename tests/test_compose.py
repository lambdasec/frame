"""End-to-end composability: a real `frame scan -f json` payload flows through
`frame exploit --guidance -` and `frame fix --guidance -`.

These lock the JSON interchange contract that makes the CLI composable -- each stage
is unit-tested elsewhere; here we check that the actual scanner output (not a
hand-built dict) is consumable by the downstream commands. The scan is symbolic
(no network); the exploit/fix agents are stubbed.
"""

import argparse
import io
import json

import frame.cli as cli
import frame.sil.llm_exploit as exploit_mod
import frame.sil.llm_fix as fix_mod
from frame.sil.llm_exploit import ExploitResult
from frame.sil.scanner import FrameScanner


def _real_scan(tmp_path):
    """Run the real symbolic scanner over a SQLi file; return (file, scan_json, result)."""
    src = (
        "def get_user():\n"
        "    user_id = input()\n"
        '    cursor.execute("SELECT * FROM users WHERE id=" + user_id)\n'
    )
    f = tmp_path / "app.py"
    f.write_text(src)
    result = FrameScanner(language="python", verify=False).scan(src, str(f))
    return str(f), result.to_json(), result


def test_real_scan_output_parses_into_findings(tmp_path):
    _, scan_json, result = _real_scan(tmp_path)
    assert result.vulnerabilities, "symbolic engine should flag the SQLi"
    findings = cli._load_findings(scan_json)
    assert findings, "real `scan -f json` output must parse into findings"
    assert any(str(f.get("cwe_id") or "").upper().startswith("CWE") for f in findings)


def test_scan_json_pipes_to_exploit_guidance(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("FRAME_LLM_MODEL", "m")
    _, scan_json, _ = _real_scan(tmp_path)

    cap = {}
    def fake(task, config, client=None, *, exec_tool, guidance=None, is_solved=None,
             max_steps=None, **kw):
        cap["guidance"] = guidance
        return ExploitResult(solved=True, steps=1, reason="ok")
    monkeypatch.setattr(exploit_mod, "exploit_agentic", fake)
    monkeypatch.setattr("sys.stdin", io.StringIO(scan_json))

    args = argparse.Namespace(target="http://t:9090", goal=None, guidance="-",
                              success_check=None, max_steps=40, exec_timeout=60,
                              model=None, format="text", trace_out=None)
    assert cli.cmd_exploit(args) == 0
    g = cap["guidance"]
    assert g and g.get("leads"), "guidance built from the piped scan output"
    assert str(g["leads"][0]["cwe"]).upper().startswith("CWE")


def test_scan_json_pipes_to_fix(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("FRAME_LLM_MODEL", "m")
    fpath, scan_json, _ = _real_scan(tmp_path)

    # stub the LLM: patch the vulnerable concat, verify reports the finding gone
    monkeypatch.setattr(fix_mod, "generate_fix", lambda f, s, c, client=None: {
        "original": '"SELECT * FROM users WHERE id=" + user_id',
        "replacement": '"SELECT * FROM users WHERE id=?", (user_id,)',
        "rationale": "parameterized"})
    monkeypatch.setattr(fix_mod, "verify_fix", lambda *a, **k: True)
    monkeypatch.setattr("sys.stdin", io.StringIO(scan_json))

    args = argparse.Namespace(source=str(tmp_path), guidance="-", in_place=True,
                              diff=False, no_verify=False, model=None, format="text")
    assert cli.cmd_fix(args) == 0
    # the real finding's file (from the scan output) was located and patched
    patched = open(fpath).read()
    assert "?\", (user_id,)" in patched and "+ user_id" not in patched
