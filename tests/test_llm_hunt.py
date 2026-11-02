"""Agentic authorization / business-logic hunting (frame/sil/llm_hunt.py), stubbed transport.

The agent's tools are Frame's sound engine facts, and every finding is tiered against them:
a claim an engine fact corroborates (the named handler reaches a resource and is not protected)
is the higher `llm_verified` tier; an intent-only claim the engine cannot back stays `llm_detect`.
The tiers are never merged. No network -- `chat_raw` is scripted."""

import json

from frame.sil.llm_client import LLMClient, LLMConfig
from frame.sil.llm_hunt import build_index, hunt_exec, hunt_authz, EngineIndex, HandlerFact
from frame.sil.types import Location


class _Proc:
    def __init__(self, span):
        self.span = span
        self.nodes = {}


class _Program:
    """Minimal translated-program stand-in: the hunting layer reads only handler_authz
    and procedures (for spans / sinks)."""
    def __init__(self, authz, procs=None):
        self.handler_authz = authz
        self.procedures = procs or {}


def _client(script):
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    seq = {"i": 0}
    def chat(messages, tools=None):
        msg = script[min(seq["i"], len(script) - 1)]
        seq["i"] += 1
        return msg
    c.chat_raw = chat
    return c


def _tool(name, **args):
    return {"content": "", "tool_calls": [{"id": "1", "function": {
        "name": name, "arguments": json.dumps(args)}}]}


def _final(findings):
    return {"content": json.dumps({"reasoning": "done", "findings": findings}), "tool_calls": []}


def _prog():
    # two handlers: `del_doc` reaches a resource and is unprotected; `me` is protected.
    return _Program(
        {"Docs.del_doc": (False, True, Location("app.py", 10)),
         "Docs.me": (True, True, Location("app.py", 20))},
        {"Docs.del_doc": _Proc((10, 14)), "Docs.me": _Proc((20, 24))})


# ---- the engine index and tools ------------------------------------------------

def test_build_index_captures_posture():
    idx = build_index(_prog(), [], repo_root="")
    by = {h.name: h for h in idx.handlers}
    assert by["Docs.del_doc"].reaches_resource and not by["Docs.del_doc"].protected
    assert by["Docs.me"].protected


def test_list_handlers_tool():
    idx = build_index(_prog(), [], repo_root="")
    out = json.loads(hunt_exec(idx)("list_handlers", {}))
    names = {h["name"]: h for h in out}
    assert names["Docs.del_doc"]["reaches_resource"] is True
    assert names["Docs.del_doc"]["protected"] is False


def test_handler_facts_tool_reports_proven_findings():
    class V:
        location, line, cwe_id = "app.py", 11, "CWE-89"
        type = "sql_injection"
    idx = build_index(_prog(), [V()], repo_root="")
    facts = json.loads(hunt_exec(idx)("handler_facts", {"name": "del_doc"}))
    assert facts["name"] == "Docs.del_doc"
    assert any(p["cwe"] == "CWE-89" for p in facts["proven_findings"])


def test_handler_facts_unknown_handler():
    idx = build_index(_prog(), [], repo_root="")
    assert "ERROR" in hunt_exec(idx)("handler_facts", {"name": "nope"})


# ---- tiering -------------------------------------------------------------------

def _cwes(vulns):
    return sorted((v.cwe_id, v.source_var) for v in vulns)


def test_engine_backed_claim_on_unprotected_handler_is_verified():
    c = _client([
        _tool("list_handlers"),
        _final([{"reasoning": "deletes any doc by id, no owner check", "handler": "Docs.del_doc",
                 "file": "app.py", "line": 11, "mechanism": "missing_authorization",
                 "cwe": "CWE-862", "confidence": 0.8, "engine_backed": True}]),
    ])
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=5)
    assert _cwes(out) == [("CWE-862", "llm_verified")]


def test_claim_on_a_protected_handler_is_not_verified():
    # Docs.me is protected, so the engine does not corroborate an authz claim -> llm_detect.
    c = _client([_final([{"reasoning": "maybe", "handler": "Docs.me", "file": "app.py", "line": 21,
                          "mechanism": "idor", "cwe": "CWE-639", "confidence": 0.7,
                          "engine_backed": True}])])
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=3)
    assert _cwes(out) == [("CWE-639", "llm_detect")]


def test_intent_only_claim_without_engine_backing_stays_detect():
    # engine_backed=False (an intent judgement the engine cannot mechanically confirm).
    c = _client([_final([{"reasoning": "price comes from the client", "handler": "Docs.del_doc",
                          "file": "app.py", "line": 12, "mechanism": "business_logic",
                          "cwe": "CWE-840", "confidence": 0.6, "engine_backed": False}])])
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=3)
    assert _cwes(out) == [("CWE-840", "llm_detect")]


def test_already_proven_handler_is_not_re_reported():
    class V:
        location, line, cwe_id = "app.py", 11, "CWE-89"
        type = "sql_injection"
    c = _client([_final([{"reasoning": "dup", "handler": "Docs.del_doc", "file": "app.py",
                          "line": 11, "mechanism": "idor", "cwe": "CWE-639", "confidence": 0.9,
                          "engine_backed": True}])])
    out = hunt_authz(_prog(), [V()], repo_root="", config=LLMConfig(), client=c, max_steps=3)
    assert out == []


def test_no_handlers_and_no_repo_means_no_call():
    # No engine facts and no repository to walk: nothing to hunt, no client needed.
    assert hunt_authz(_Program({}), [], repo_root="", config=LLMConfig(), client=None) == []


def test_cross_language_fallback_runs_without_a_frontend(tmp_path):
    # A language Frame has no frontend for (e.g. PHP): no engine index, so the hunt runs
    # over the repo with grep/read_file and every finding is llm_detect (no corroboration).
    (tmp_path / "admin.php").write_text(
        "<?php\nfunction delete_user($id){ db_delete('users', $id); }\n"
        "// route /admin/delete/:id -> delete_user, no role check\n")
    c = _client([
        _tool("grep", pattern="route"),
        _final([{"reasoning": "delete_user route has no role/authn check", "handler": "delete_user",
                 "file": "admin.php", "line": 2, "mechanism": "missing_authorization",
                 "cwe": "CWE-862", "confidence": 0.7, "engine_backed": True}]),
    ])
    out = hunt_authz(None, [], repo_root=str(tmp_path), config=LLMConfig(), client=c,
                     max_steps=5, language="php")
    # engine_backed was claimed, but there is no engine fact to corroborate -> llm_detect.
    assert _cwes(out) == [("CWE-862", "llm_detect")]
