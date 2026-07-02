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


def test_numbered_truncates():
    big = "\n".join(f"line{i}" for i in range(1000))
    out = _numbered(big, 200)
    assert "truncated" in out and len(out) < 400
