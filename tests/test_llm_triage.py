"""Tests for the optional LLM triage pass (no network -- stubbed transport)."""

import json
from types import SimpleNamespace

from frame.sil.llm_triage import (
    TriageConfig, LLMTriageClient, triage_vulnerabilities, _extract_json_object,
    _context_snippet, _verdict_response_format, triage_agentic, _should_escalate,
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


def test_transport_error_raises():
    # User asked for LLM triage and the endpoint is unreachable -> flag it (raise),
    # never silently proceed as if triage ran.
    import pytest
    from frame.sil.llm_client import LLMUnavailableError
    def boom(messages):
        raise OSError("endpoint down")
    client = LLMTriageClient(TriageConfig(base_url="x", model="m", agent_retries=0),
                             call_fn=boom)
    with pytest.raises(LLMUnavailableError):
        triage_vulnerabilities([_vuln(5, "CWE-79")], SRC, "js", "a.js",
                               TriageConfig(agent_retries=0), client)


def test_parse_blip_keeps_finding():
    # A non-transport blip (model returns un-parseable content, no exception) is
    # fail-safe: keep the finding (triage only ever drops confident false positives).
    def junk(messages):
        return "not json at all"
    client = LLMTriageClient(TriageConfig(base_url="x", model="m"), call_fn=junk)
    kept, _ = triage_vulnerabilities([_vuln(5, "CWE-79")], SRC, "js", "a.js",
                                     TriageConfig(), client)
    assert len(kept) == 1          # kept, not dropped


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
    # The triage verdict's structured-output spec now lives in the triage layer
    # (the shared client is schema-agnostic).
    assert _verdict_response_format("json_object") == {"type": "json_object"}
    schema = _verdict_response_format("json_schema")
    assert schema["type"] == "json_schema" and schema["json_schema"]["strict"] is True
    assert _verdict_response_format("off") is None


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


def test_extract_json_reason_first_with_prose_braces():
    # Reason-first output: prose with code-snippet braces BEFORE the JSON object.
    # A greedy first{...}last{ would span the prose and fail to parse -> None,
    # silently dropping every finding. The extractor must return the trailing
    # findings object (the last balanced, parseable dict).
    raw = ('Reasoning: path = base + {category}/{folder}, no sanitize.\n'
           'A stray dict {"note": "x"} appears mid-reasoning.\n'
           '{"findings": [{"cwe": "CWE-22", "line": 501, "type": "path_traversal"}]}')
    o = _extract_json_object(raw)
    assert o is not None and o["findings"][0]["cwe"] == "CWE-22"
    assert o["findings"][0]["line"] == 501
    # nested braces inside the target object are handled (balanced scan)
    assert _extract_json_object('x {"a": {"b": 1}} y')["a"]["b"] == 1


# ---- agentic triage (opt-in escalation) ----------------------------------------

def test_should_escalate_band():
    cfg = TriageConfig(drop_threshold=0.75)
    assert _should_escalate(None, cfg) is True                  # unparseable -> investigate
    assert _should_escalate({"confidence": 0.5}, cfg) is True   # ambiguous band
    assert _should_escalate({"confidence": 0.9}, cfg) is False  # confident -> act as-is
    assert _should_escalate({"confidence": 0.1}, cfg) is False  # clueless -> keep as-is


def test_triage_agentic_investigates_then_verdicts(tmp_path):
    (tmp_path / "helper.js").write_text("function sanitize(x){ return esc(x); }")
    cfg = TriageConfig(base_url="x", model="m", repo_root=str(tmp_path))
    c = LLMTriageClient(cfg)
    seq = {"i": 0}
    def chat(messages, tools=None):
        seq["i"] += 1
        if seq["i"] == 1:                          # first: investigate the repo
            return {"content": "", "tool_calls": [{"id": "1", "function": {
                "name": "grep", "arguments": '{"pattern": "sanitize"}'}}]}
        return {"content": json.dumps({"reasoning": "sanitized in caller",       # then: verdict
                "is_true_positive": False, "confidence": 0.9}), "tool_calls": []}
    c.chat_raw = chat
    v = triage_agentic("finding context", cfg, c)
    assert seq["i"] == 2 and v["is_true_positive"] is False


def test_triage_agentic_no_repo_falls_back_to_single_call():
    c = _client(lambda _: {"is_true_positive": True, "confidence": 0.8, "reasoning": "x"})
    v = triage_agentic("ctx", TriageConfig(base_url="x", model="m"), c)  # no repo_root
    assert v["is_true_positive"] is True


def test_escalation_is_opt_in_off_by_default(tmp_path):
    (tmp_path / "a.js").write_text("x")
    calls = {"chat_raw": 0}
    c = _client(lambda _: {"is_true_positive": False, "confidence": 0.5, "reasoning": "maybe"})
    orig = c.chat_raw
    def counting(messages, tools=None):
        calls["chat_raw"] += 1
        return orig(messages, tools)
    c.chat_raw = counting
    cfg = TriageConfig(base_url="x", model="m", repo_root=str(tmp_path), drop_threshold=0.75)
    # triage_agentic defaults False: uncertain FP@0.5 is kept, never escalates
    kept, _ = triage_vulnerabilities([_vuln(5, "CWE-79")], SRC, "js", "a.js", cfg, c)
    assert kept and calls["chat_raw"] == 0


def test_escalation_when_enabled_upgrades_verdict(tmp_path):
    (tmp_path / "a.js").write_text("x")
    cfg = TriageConfig(base_url="x", model="m", repo_root=str(tmp_path),
                       drop_threshold=0.75, triage_agentic=True)
    c = _client(lambda _: {"is_true_positive": False, "confidence": 0.5, "reasoning": "uncertain"})
    def chat(messages, tools=None):   # agentic path: investigate -> confident FP
        return {"content": json.dumps({"is_true_positive": False, "confidence": 0.95,
                "reasoning": "found sanitizer in caller"}), "tool_calls": []}
    c.chat_raw = chat
    kept, cc = triage_vulnerabilities([_vuln(5, "CWE-79")], SRC, "js", "a.js", cfg, c)
    assert kept == [] and cc.stats["dropped"] == 1   # uncertain single call -> confident drop
