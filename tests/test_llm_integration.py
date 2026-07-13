"""End-to-end scanner integration tests for the optional LLM layers.

These exercise the wiring in FrameScanner (detect adds findings, triage filters
them, ordering, tiering, off-by-default) with a fully stubbed transport -- no
network. The unit behavior of each piece lives in test_llm_detect.py /
test_llm_triage.py; here we verify they compose correctly inside a real scan.
"""

import json

import pytest

from frame.sil import FrameScanner
from frame.sil.llm_triage import TriageConfig, LLMTriageClient
from frame.sil.llm_detect import DETECT_SYSTEM


# A JS file that is a detection *candidate* (mentions req.query) but has no sink
# the symbolic engine recognizes -- so symbolic finds nothing and any finding in
# the result must have come from the (stubbed) LLM detection layer.
CANDIDATE_SRC = "const data = req.query.payload;\nprocessData(data);\nsomethingElse(data);\n"


def _stub_client(detect_findings, triage_is_tp=True, triage_conf=0.9):
    """One call_fn that answers BOTH the detection and triage prompts, told apart
    by the system prompt. detect -> a findings object; triage -> a verdict."""
    def call_fn(messages):
        system = messages[0]["content"] if messages else ""
        if "application-security auditor" in system:          # DETECT_SYSTEM
            return json.dumps({"findings": detect_findings})
        return json.dumps({"is_true_positive": triage_is_tp,  # triage verdict
                           "confidence": triage_conf, "reasoning": "stub"})
    assert "application-security auditor" in DETECT_SYSTEM     # guard the sentinel
    return LLMTriageClient(TriageConfig(base_url="x", model="m"), call_fn=call_fn)


def _scanner(tmp_path, **kw):
    sc = FrameScanner(language="javascript", verify=False,
                      llm_config=TriageConfig(base_url="x", model="m"), **kw)
    return sc


def test_detection_adds_a_finding(tmp_path):
    f = tmp_path / "a.js"; f.write_text(CANDIDATE_SRC)
    sc = _scanner(tmp_path, llm_detect=True)
    sc._llm_client = _stub_client(
        [{"cwe": "CWE-502", "line": 1, "type": "deserialization",
          "reasoning": "untrusted payload deserialized", "confidence": 0.8}])
    res = sc.scan_file(str(f))
    hits = [v for v in res.vulnerabilities if v.cwe_id == "CWE-502"]
    assert hits and hits[0].source_var == "llm_detect"        # tiered as LLM-detected


def test_off_by_default(tmp_path):
    """No LLM calls, no LLM findings, when the flags are not set (sound default)."""
    f = tmp_path / "a.js"; f.write_text(CANDIDATE_SRC)
    sc = _scanner(tmp_path)                                    # neither flag
    sc._llm_client = _stub_client([{"cwe": "CWE-502", "line": 1, "type": "x",
                                    "reasoning": "y", "confidence": 0.9}])
    res = sc.scan_file(str(f))
    assert not any(v.source_var == "llm_detect" for v in res.vulnerabilities)


def test_triage_filters_a_detection(tmp_path):
    """With both layers on, triage drops a confident-FP detection finding."""
    f = tmp_path / "a.js"; f.write_text(CANDIDATE_SRC)
    sc = _scanner(tmp_path, llm_detect=True, llm_triage=True)
    sc._llm_client = _stub_client(
        [{"cwe": "CWE-502", "line": 1, "type": "deser", "reasoning": "z", "confidence": 0.8}],
        triage_is_tp=False, triage_conf=0.95)                 # triage says confident FP
    res = sc.scan_file(str(f))
    assert not any(v.cwe_id == "CWE-502" for v in res.vulnerabilities)   # dropped


def test_triage_keeps_a_confirmed_detection(tmp_path):
    """Triage retains a detection it judges a true positive (recall preserved)."""
    f = tmp_path / "a.js"; f.write_text(CANDIDATE_SRC)
    sc = _scanner(tmp_path, llm_detect=True, llm_triage=True)
    sc._llm_client = _stub_client(
        [{"cwe": "CWE-502", "line": 1, "type": "deser", "reasoning": "z", "confidence": 0.8}],
        triage_is_tp=True)
    res = sc.scan_file(str(f))
    assert any(v.cwe_id == "CWE-502" for v in res.vulnerabilities)       # kept


def test_no_endpoint_no_detection(tmp_path):
    """llm_detect requested but no endpoint configured -> gracefully no-op."""
    f = tmp_path / "a.js"; f.write_text(CANDIDATE_SRC)
    sc = FrameScanner(language="javascript", verify=False, llm_detect=True,
                      llm_config=TriageConfig(base_url="", model=""))
    res = sc.scan_file(str(f))                                # must not raise
    assert not any(v.source_var == "llm_detect" for v in res.vulnerabilities)


def test_csharp_controller_is_a_candidate():
    """The C# coverage fix: an ASP.NET controller registers as a detection candidate."""
    from frame.sil.llm_detect import is_detection_candidate
    cs = ('public class MovieController : Controller {\n'
          '  public IActionResult Get([FromQuery] string id) {\n'
          '    var cmd = new SqlCommand("SELECT * FROM m WHERE id=" + id);\n'
          '  }\n}')
    assert is_detection_candidate(cs, False) is True
    # a plain C# DTO with no security-relevant surface is not a candidate
    assert is_detection_candidate("public class Movie { public string Title; }", False) is False


def test_cli_ai_flags_parse():
    """`frame scan --ai` (and the granular flags) parse and reach args."""
    from frame.cli import create_parser
    p = create_parser()
    a = p.parse_args(["scan", "app.js", "--ai"])
    assert a.ai is True and a.llm_detect is False and a.llm_triage is False
    b = p.parse_args(["scan", "app.js", "--llm-detect", "--llm-triage"])
    assert b.llm_detect is True and b.llm_triage is True and b.ai is False
    c = p.parse_args(["scan", "app.js"])
    assert c.ai is False and c.llm_detect is False and c.llm_triage is False


# ---- Any-language coverage: LLM-detect-only for languages without a frontend ----

def test_unsupported_language_without_ai_is_graceful():
    """A language with no symbolic frontend must not crash; it points to --ai."""
    from frame.sil import FrameScanner
    sc = FrameScanner(language="php", verify=False)
    res = sc.scan("<?php echo $_GET['x']; ?>", "a.php")
    assert res.vulnerabilities == [] and any("--ai" in e for e in res.errors)


def test_unsupported_language_with_ai_runs_llm_detect():
    """Under --ai, LLM-detect runs on ANY language; findings are LLM-tier (not symbolic)."""
    from frame.sil import FrameScanner
    cfg = TriageConfig(base_url="x", model="m")
    def call_fn(messages):
        return json.dumps({"findings": [{"cwe": "CWE-89", "line": 1, "type": "sql_injection",
                                         "reasoning": "user input in query", "confidence": 0.8}]})
    sc = FrameScanner(language="php", verify=False, llm_detect=True, llm_config=cfg)
    sc._llm_client = LLMTriageClient(cfg, call_fn=call_fn)
    res = sc.scan("<?php $id=$_GET['id']; mysqli_query($c, \"SELECT * FROM u WHERE id=$id\"); ?>", "a.php")
    hits = [v for v in res.vulnerabilities if v.cwe_id == "CWE-89"]
    assert hits and hits[0].source_var == "llm_detect"   # LLM-tier, never "proven"


def test_rust_has_no_frontend_but_constructs():
    from frame.sil import FrameScanner
    assert FrameScanner(language="rust", verify=False).frontend is None
    assert FrameScanner(language="python", verify=False).frontend is not None
