"""Tests for the optional LLM triage pass (no network -- stubbed transport)."""

import json
from types import SimpleNamespace

from frame.sil.llm_triage import (
    TriageConfig, LLMTriageClient, triage_vulnerabilities, _extract_json_object,
    _context_snippet,
)


def _vuln(line, cwe, vtype="xss", msg="finding"):
    return SimpleNamespace(line=line, cwe_id=cwe, message=msg,
                           type=SimpleNamespace(value=vtype),
                           severity=SimpleNamespace(value="high"))


SRC = "\n".join(f"line{i}" for i in range(1, 21))


def _client(verdict_for):
    """Build a client whose transport returns a verdict computed from the prompt."""
    def call_fn(messages):
        user = messages[-1]["content"]
        return json.dumps(verdict_for(user))
    return LLMTriageClient(TriageConfig(base_url="x", model="m"), call_fn=call_fn)


def test_confident_false_positive_is_dropped():
    client = _client(lambda _: {"is_true_positive": False, "confidence": 0.95, "reasoning": "safe"})
    kept, c = triage_vulnerabilities([_vuln(5, "CWE-79")], SRC, "js", "a.js",
                                     TriageConfig(drop_threshold=0.75), client)
    assert kept == []
    assert c.stats["dropped"] == 1


def test_true_positive_is_kept_and_annotated():
    client = _client(lambda _: {"is_true_positive": True, "confidence": 0.9, "reasoning": "real"})
    v = _vuln(5, "CWE-89")
    kept, _ = triage_vulnerabilities([v], SRC, "java", "a.java",
                                     TriageConfig(drop_threshold=0.75), client)
    assert kept == [v]
    assert v.llm_triage["is_true_positive"] is True


def test_low_confidence_false_positive_is_kept():
    # Uncertain FP (below threshold) must NOT be dropped -- triage only removes
    # confident false positives, so recall is preserved.
    client = _client(lambda _: {"is_true_positive": False, "confidence": 0.4, "reasoning": "maybe"})
    kept, _ = triage_vulnerabilities([_vuln(5, "CWE-79")], SRC, "js", "a.js",
                                     TriageConfig(drop_threshold=0.75), client)
    assert len(kept) == 1


def test_transport_error_keeps_finding():
    def boom(messages):
        raise OSError("endpoint down")
    client = LLMTriageClient(TriageConfig(base_url="x", model="m"), call_fn=boom)
    kept, c = triage_vulnerabilities([_vuln(5, "CWE-79")], SRC, "js", "a.js",
                                     TriageConfig(), client)
    assert len(kept) == 1          # fail-safe: never drop on error
    assert c.stats["errors"] == 1


def test_verdict_is_cached():
    calls = {"n": 0}
    def call_fn(messages):
        calls["n"] += 1
        return json.dumps({"is_true_positive": True, "confidence": 0.9})
    client = LLMTriageClient(TriageConfig(base_url="x", model="m"), call_fn=call_fn)
    v = _vuln(5, "CWE-79")
    triage_vulnerabilities([v], SRC, "js", "a.js", TriageConfig(), client)
    triage_vulnerabilities([_vuln(5, "CWE-79")], SRC, "js", "a.js", TriageConfig(), client)
    assert calls["n"] == 1         # second identical finding served from cache


def test_no_endpoint_configured_is_disabled():
    assert TriageConfig().enabled is False


def test_response_format_modes():
    assert LLMTriageClient(TriageConfig(json_mode="json_object"))._response_format() \
        == {"type": "json_object"}
    schema = LLMTriageClient(TriageConfig(json_mode="json_schema"))._response_format()
    assert schema["type"] == "json_schema" and schema["json_schema"]["strict"] is True
    assert LLMTriageClient(TriageConfig(json_mode="off"))._response_format() is None


def test_reasoning_first_order_still_parses():
    # Structured output emits reasoning before the verdict; parsing is key-order
    # independent, and the confident-FP still drops.
    client = _client(lambda _: {"reasoning": "url is a constant, not user input",
                                "is_true_positive": False, "confidence": 0.9})
    kept, _ = triage_vulnerabilities([_vuln(5, "CWE-601")], SRC, "js", "a.js",
                                     TriageConfig(drop_threshold=0.75), client)
    assert kept == []


def test_extract_json_and_context():
    assert _extract_json_object('noise {"a": 1} tail')["a"] == 1
    assert _extract_json_object("no json here") is None
    snip = _context_snippet(SRC.splitlines(), 3, 1)
    assert ">> 3:" in snip and "2:" in snip
