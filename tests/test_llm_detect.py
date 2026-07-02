"""Tests for the optional LLM detection pass (no network -- stubbed transport)."""

import json

from frame.sil.llm_triage import TriageConfig, LLMTriageClient
from frame.sil.llm_detect import detect_in_file, is_detection_candidate, _numbered


SRC = ("app.get('/x', (req, res) => {\n"
       "  const id = req.query.id;\n"
       "  db.query('SELECT * FROM u WHERE id=' + id);\n"
       "});\n")


def _client(findings):
    def call_fn(messages):
        return json.dumps({"findings": findings})
    return LLMTriageClient(TriageConfig(base_url="x", model="m"), call_fn=call_fn)


def test_detects_and_labels():
    c = _client([{"reasoning": "user id concatenated into SQL", "cwe": "CWE-89",
                  "line": 3, "type": "sql_injection", "confidence": 0.9}])
    vs = detect_in_file(SRC, "javascript", "x.js", TriageConfig(), c)
    assert len(vs) == 1
    v = vs[0]
    assert v.cwe_id == "CWE-89" and v.line == 3
    assert v.source_var == "llm_detect"           # separate tier
    assert v.confidence <= 0.85                    # capped below symbolic
    assert v.description.startswith("[LLM-detected]")


def test_empty_findings():
    assert detect_in_file(SRC, "javascript", "x.js", TriageConfig(), _client([])) == []


def test_finding_without_cwe_is_dropped():
    # No mappable CWE -> not emitted (avoids untyped noise).
    c = _client([{"reasoning": "maybe", "line": 3, "type": "unknown"}])
    assert detect_in_file(SRC, "javascript", "x.js", TriageConfig(), c) == []


def test_transport_error_yields_nothing():
    def boom(messages):
        raise OSError("down")
    c = LLMTriageClient(TriageConfig(base_url="x", model="m"), call_fn=boom)
    assert detect_in_file(SRC, "javascript", "x.js", TriageConfig(), c) == []


def test_candidate_selection():
    assert is_detection_candidate("const x = req.query.id;", False) is True
    assert is_detection_candidate("db.query(stuff)", False) is True
    assert is_detection_candidate("const total = a + b;", False) is False
    # anything the symbolic pass already flagged is a candidate
    assert is_detection_candidate("const total = a + b;", True) is True


def test_sink_grounding():
    from frame.sil.llm_detect import is_sink_grounded
    sinks = [(5, "sql"), (20, "html")]
    assert is_sink_grounded("CWE-89", 5, sinks) is True          # sql sink at line
    assert is_sink_grounded("CWE-89", 6, sinks, window=3) is True  # within window
    assert is_sink_grounded("CWE-89", 50, sinks) is False        # no sink near
    assert is_sink_grounded("CWE-79", 5, sinks) is False         # wrong kind at line
    assert is_sink_grounded("CWE-209", 5, sinks) is False        # CWE with no sink model


def test_agentic_tool_loop(tmp_path):
    from frame.sil.llm_detect import detect_agentic
    (tmp_path / "helper.js").write_text("const cp=require('child_process'); cp.exec(cmd)")
    calls = {"n": 0}
    def fake_chat(messages, tools=None):
        calls["n"] += 1
        if calls["n"] == 1:                      # first: model calls a tool
            return {"content": "", "tool_calls": [
                {"id": "t1", "function": {"name": "read_file",
                                          "arguments": '{"path": "helper.js"}'}}]}
        return {"content": json.dumps({"findings": [                 # then: reports
            {"cwe": "CWE-78", "line": 3, "type": "command_injection",
             "reasoning": "cmd flows cross-file to cp.exec", "confidence": 0.9}]})}
    cfg = TriageConfig(base_url="x", model="m", repo_root=str(tmp_path))
    c = LLMTriageClient(cfg)
    c.chat_raw = fake_chat
    vs = detect_agentic("app.get('/x',(req,res)=>helper.run(req.query.cmd))",
                        "javascript", "h.js", cfg, c)
    assert calls["n"] == 2                        # one tool round, then answer
    assert len(vs) == 1 and vs[0].cwe_id == "CWE-78"


def test_exec_tool_and_path_safety(tmp_path):
    from frame.sil.llm_detect import _exec_tool, _safe_path
    (tmp_path / "a.js").write_text("secret-content")
    assert _exec_tool("read_file", {"path": "a.js"}, str(tmp_path)) == "secret-content"
    assert "ERROR" in _exec_tool("read_file", {"path": "../../etc/passwd"}, str(tmp_path))
    assert _safe_path(str(tmp_path), "../escape") is None       # no repo escape
    assert _safe_path(str(tmp_path), "a.js") is not None


def test_numbered_truncates():
    big = "\n".join(f"line{i}" for i in range(1000))
    out = _numbered(big, 200)
    assert "truncated" in out and len(out) < 400


def test_cross_file_grounded():
    from frame.sil.llm_detect import cross_file_grounded
    assert cross_file_grounded("CWE-78", {"shell", "html"}) is True   # cmd sink in explored file
    assert cross_file_grounded("CWE-89", {"html"}) is False           # no sql sink explored
    assert cross_file_grounded("CWE-209", {"sql"}) is False           # CWE with no sink model
