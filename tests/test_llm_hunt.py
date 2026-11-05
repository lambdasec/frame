"""Agentic authorization / business-logic hunting (frame/sil/llm_hunt.py), stubbed transport.

The agent's tools are Frame's sound engine facts, and every finding is tiered against them:
a claim an engine fact corroborates (the named handler reaches a resource and is not protected)
is the higher `llm_verified` tier; an intent-only claim the engine cannot back stays `llm_detect`.
The tiers are never merged. No network -- `chat_raw` is scripted."""

import json

import pytest

from frame import config as frame_config
from frame.sil.llm_client import LLMClient, LLMConfig
from frame.sil.llm_hunt import build_index, hunt_exec, hunt_authz, EngineIndex, HandlerFact
from frame.sil.types import Location


class _Proc:
    def __init__(self, span):
        self.span = span            # a line range here; frontends record bytes
        self.end_line = span[1]
        self.nodes = {}


class _Program:
    """Minimal translated-program stand-in: the hunting layer reads only handler_authz
    and procedures (for spans / sinks)."""
    def __init__(self, authz, procs=None, service_functions=None,
                 authz_gates=None, resource_proc_callees=None):
        self.handler_authz = authz
        self.procedures = procs or {}
        if service_functions is not None:
            self.service_functions = service_functions
        if authz_gates is not None:
            self.authz_gates = authz_gates
        if resource_proc_callees is not None:
            self.resource_proc_callees = resource_proc_callees


def _text(content):
    """A message's text whether plain or in content blocks (the hunt intro carries a
    cache_control breakpoint, so it is sent as a block list)."""
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content if isinstance(b, dict))
    return content or ""


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


def test_build_index_surfaces_service_layer_functions():
    # A non-handler function that touches a resource is the shared layer a handler delegates to;
    # the hunt must see it (parse-server enforceRoleSecurity shape), with its principal-scope flag.
    prog = _Program(
        {"UsersRouter.handleLogInAs": (True, True, Location("src/Routers/UsersRouter.js", 30))},
        service_functions={"enforceRoleSecurity": (False, True, Location("src/SharedRest.js", 42)),
                           "scoped_helper": (True, True, Location("src/SharedRest.js", 88))})
    idx = build_index(prog, [], repo_root="")
    by = {s["name"]: s for s in idx.service_functions}
    assert by["enforceRoleSecurity"]["scoped"] is False
    assert by["enforceRoleSecurity"]["file"] == "src/SharedRest.js"
    assert by["scoped_helper"]["scoped"] is True


def test_service_layer_functions_appear_in_the_hunt_intro():
    # The unscoped service function must get an agent of its own, ranked ahead of the (protected)
    # route handler -- the whole point of the lift is to pull the audit off the route handlers into
    # the shared enforcement layer. Every unit's opening prompt is captured.
    prog = _Program(
        {"UsersRouter.handleLogInAs": (True, True, Location("src/Routers/UsersRouter.js", 30))},
        {"UsersRouter.handleLogInAs": _Proc((30, 40))},
        service_functions={"enforceRoleSecurity": (False, True, Location("src/SharedRest.js", 42))})
    intros = []
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    def chat(messages, tools=None):
        intro = _text(messages[1]["content"])
        if intro not in intros:
            intros.append(intro)
        return {"content": "done, nothing found", "tool_calls": []}
    c.chat_raw = chat
    status = {}
    hunt_authz(prog, [], "", LLMConfig(base_url="x", model="m"), client=c, status=status)
    svc = [i for i in intros if "SERVICE-LAYER FUNCTIONS" in i]
    assert svc and "enforceRoleSecurity" in svc[0] and "src/SharedRest.js" in svc[0]
    assert "scoped_to_caller=False" in svc[0]
    # Ranked first: an unscoped data access outranks a protected handler.
    assert status["units"][0]["id"] == "src/SharedRest.js::<service>"


def test_translator_records_the_delegated_db_helper_as_a_service_function():
    # end-to-end: the translator records the non-handler DB helper, not the route handler, as a
    # service function, so build_index surfaces exactly the delegated layer. The helper does not
    # bring the caller's identity into scope -> scoped=False (the enforceRoleSecurity shape).
    from frame.sil.frontends.python_frontend import PythonFrontend
    from frame.sil.translator import SILTranslator
    code = ("from django.urls import path\n"
            "from django.db import models\n"
            "class Doc(models.Model): pass\n\n"
            "def _load(pk):\n"                   # service/helper: touches a resource, not a handler
            "    return Doc.objects.get(pk=pk)\n\n"
            "def view(request, pk):\n"
            "    return str(_load(pk))\n\n"
            "urlpatterns = [path('d/<pk>/', view)]\n")
    prog = PythonFrontend().translate(code, "views.py")
    SILTranslator(prog).translate_program()
    svc = getattr(prog, "service_functions", {}) or {}
    names = {n.rsplit(".", 1)[-1].rsplit("::", 1)[-1] for n in svc}
    assert "_load" in names and "view" not in names
    load_key = next(n for n in svc if n.rsplit(".", 1)[-1].rsplit("::", 1)[-1] == "_load")
    assert svc[load_key][0] is False          # scopes_by_identity: the helper has no principal


def test_build_index_surfaces_a_gate_reached_from_a_resource_handler():
    # An authorization GATE (a non-handler that decides on its inputs and touches no resource) is
    # surfaced only when a resource-reaching procedure delegates to it -- the parse-server
    # enforceRoleSecurity shape, where RestWrite (a resource reacher) calls the gate. The
    # delegation edge may cross files, so the caller set is read from a different program.
    gate_prog = _Program({}, authz_gates={"enforceRoleSecurity": Location("src/SharedRest.js", 12)})
    caller_prog = _Program(
        {"RestWrite.handleWrite": (True, True, Location("src/RestWrite.js", 5))},
        service_functions={"RestWrite.handleWrite": (False, True, Location("src/RestWrite.js", 5))},
        resource_proc_callees={"enforceRoleSecurity", "query"})
    idx = build_index([gate_prog, caller_prog], [], repo_root="")
    by = {g["name"]: g for g in idx.authz_gates}
    assert "enforceRoleSecurity" in by
    assert by["enforceRoleSecurity"]["file"] == "src/SharedRest.js"


def test_a_gate_no_resource_handler_delegates_to_is_not_surfaced():
    # A function that merely branches on its inputs is not an enforcement point unless a resource
    # handler actually delegates to it: without that edge it is plain input validation, and the
    # hunt must not drown in it.
    gate_prog = _Program({}, authz_gates={"validateEmailFormat": Location("src/util.js", 3)},
                         resource_proc_callees=set())
    idx = build_index([gate_prog], [], repo_root="")
    assert [g["name"] for g in idx.authz_gates] == []


def test_enforcement_points_appear_in_the_hunt_intro():
    # The surfaced gate gets a unit whose prompt tells the agent to audit it for an INCOMPLETE
    # clause (the missing-authorization shape with no dataflow).
    gate_prog = _Program({}, authz_gates={"enforceRoleSecurity": Location("src/SharedRest.js", 12)})
    caller_prog = _Program(
        {"RestWrite.handleWrite": (True, True, Location("src/RestWrite.js", 5))},
        {"RestWrite.handleWrite": _Proc((5, 20))},
        resource_proc_callees={"enforceRoleSecurity"})
    intros = []
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    def chat(messages, tools=None):
        intro = _text(messages[1]["content"])
        if intro not in intros:
            intros.append(intro)
        return {"content": "done", "tool_calls": []}
    c.chat_raw = chat
    hunt_authz([gate_prog, caller_prog], [], "", LLMConfig(base_url="x", model="m"), client=c)
    gate = [i for i in intros if "ENFORCEMENT POINT" in i and "enforceRoleSecurity" in i]
    assert gate and "FORGETS to cover" in gate[0]


def test_translator_records_a_gate_and_links_it_via_a_resource_caller(tmp_path):
    # end-to-end on the parse-server shape: a gate function (branches on its params, touches no
    # resource) in one file, a resource-reaching caller that delegates to it in another, and a
    # test spec whose callback also hits a resource. The gate is surfaced; the test file's
    # functions are NOT (its callbacks are not the application's enforcement).
    (tmp_path / "SharedRest.js").write_text(
        "const masterOnly = ['_JobStatus'];\n"
        "function enforceRoleSecurity(method, className, auth) {\n"
        "  if (masterOnly.indexOf(className) >= 0 && !auth.isMaster) { throw new Error('forbidden'); }\n"
        "}\n"
        "module.exports = { enforceRoleSecurity };\n")
    (tmp_path / "RestWrite.js").write_text(
        "const { enforceRoleSecurity } = require('./SharedRest');\n"
        "const mysql = require('mysql');\n"
        "const conn = mysql.createConnection({});\n"
        "function handleWrite(method, className, auth) {\n"
        "  enforceRoleSecurity(method, className, auth);\n"
        "  return conn.query('UPDATE ' + className + ' SET x=1');\n"
        "}\n"
        "module.exports = { handleWrite };\n")
    (tmp_path / "ParseQuery.spec.js").write_text(
        "const mysql = require('mysql');\n"
        "const conn = mysql.createConnection({});\n"
        "describe('q', () => { it('reads', (done) => { conn.query('SELECT 1'); done(); }); });\n")

    from frame.sil.scanner import FrameScanner
    sc = FrameScanner(verify=False, hunt_authz=True)
    captured = {}
    sc._apply_hunt_authz = lambda dir_path, results, excluded, selected: (
        captured.update(progs=list(sc._hunt_programs)) or results)
    sc.scan_directory(str(tmp_path), None)
    progs = captured["progs"]

    idx = build_index(progs, [], str(tmp_path))
    gate_names = {g["name"].rsplit(".", 1)[-1].rsplit("::", 1)[-1] for g in idx.authz_gates}
    assert "enforceRoleSecurity" in gate_names                 # the gate is surfaced
    # the test spec's callbacks are excluded from both the gate and the service layers
    all_svc = {s["file"] for s in idx.service_functions}
    all_gate = {g["file"] for g in idx.authz_gates}
    assert not any("spec" in f for f in all_svc | all_gate)


def test_gate_surfaces_when_the_handler_reaches_the_db_through_a_service_layer(tmp_path):
    # The parse-server shape proper: the route handler calls the gate AND delegates data access to
    # a service function in ANOTHER file -- the handler itself contains no resource sink, so it
    # reaches the database only INTERPROCEDURALLY. The gate must still surface (the engine follows
    # the call graph to the resource), while the service function is recorded as a reacher, not a
    # gate.
    (tmp_path / "SharedRest.js").write_text(
        "const masterOnly = ['_JobStatus'];\n"
        "function enforceRoleSecurity(method, className, auth) {\n"
        "  if (masterOnly.indexOf(className) >= 0 && !auth.isMaster) { throw new Error('forbidden'); }\n"
        "}\n"
        "module.exports = { enforceRoleSecurity };\n")
    (tmp_path / "RestQuery.js").write_text(
        "const mysql = require('mysql');\n"
        "const conn = mysql.createConnection({});\n"
        "function runFind(className) { return conn.query('SELECT * FROM ' + className); }\n"
        "module.exports = { runFind };\n")
    (tmp_path / "rest.js").write_text(
        "const { enforceRoleSecurity } = require('./SharedRest');\n"
        "const { runFind } = require('./RestQuery');\n"
        "function find(className, auth) {\n"
        "  enforceRoleSecurity('find', className, auth);\n"
        "  return runFind(className);\n"              # data access is one hop away, in RestQuery.js
        "}\n"
        "module.exports = { find };\n")

    from frame.sil.scanner import FrameScanner
    sc = FrameScanner(verify=False, hunt_authz=True)
    captured = {}
    sc._apply_hunt_authz = lambda dir_path, results, excluded, selected: (
        captured.update(progs=list(sc._hunt_programs)) or results)
    sc.scan_directory(str(tmp_path), None)           # cross_file on by default -> project fixpoint

    idx = build_index(captured["progs"], [], str(tmp_path))
    gate_names = {g["name"].rsplit(".", 1)[-1].rsplit("::", 1)[-1] for g in idx.authz_gates}
    assert "enforceRoleSecurity" in gate_names       # surfaced via the handler's interprocedural reach
    assert "runFind" not in gate_names               # a resource reacher is a service, never a gate
    assert "find" not in gate_names                  # the handler itself reaches a resource too


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


def _report(**args):
    # A complete report: the falsification schema (invariant + violating request) is required.
    args.setdefault("invariant", "only the document's owner may delete it")
    args.setdefault("violating_request", "DELETE /docs/7 as user B, who does not own doc 7")
    return {"content": "", "tool_calls": [{"id": "1", "function": {
        "name": "report_finding", "arguments": json.dumps(args)}}]}


def test_report_without_a_violating_request_is_not_recorded():
    # ABSENTIA's falsification schema is the filter: a claim the agent cannot turn into a concrete
    # violating request is not a finding. The harness refuses it and says what is missing.
    seen = []
    c = _client([
        _report(handler="Docs.del_doc", file="app.py", line=11, mechanism="idor", cwe="CWE-639",
                violating_request=""),
        {"content": "done", "tool_calls": []},
    ])
    orig = c.chat_raw

    def chat(messages, tools=None):
        seen.append(messages[-1].get("content"))
        return orig(messages, tools)
    c.chat_raw = chat
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=4)
    assert out == []
    assert any("NOT RECORDED" in str(m) and "violating_request" in str(m) for m in seen)


def test_report_finding_survives_an_empty_final_turn():
    # The whole point of incremental capture: the agent reports a finding via the tool, then its
    # FINAL turn whiffs (empty content, as a reasoning model does when it burns its output on
    # reasoning). The reported finding must still come back -- not be lost with the final dump.
    c = _client([
        _report(handler="Docs.del_doc", file="app.py", line=11,
                mechanism="missing_authorization", cwe="CWE-862", confidence=0.8,
                engine_backed=True),
        {"content": "", "tool_calls": []},            # empty final turn
    ])
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=5)
    assert _cwes(out) == [("CWE-862", "llm_verified")]   # salvaged from the accumulator


def test_timeout_salvages_incrementally_reported_findings():
    # No second time budget: a hard interruption (e.g. a benchmark SIGALRM) raises inside the loop.
    # The findings reported via report_finding are already captured, so the hunt returns them
    # instead of losing the whole run.
    c = _client([
        _report(handler="Docs.del_doc", file="app.py", line=11,
                mechanism="missing_authorization", cwe="CWE-862", confidence=0.8,
                engine_backed=True),
    ])
    orig = c.chat_raw
    calls = {"n": 0}

    def chat(messages, tools=None):
        calls["n"] += 1
        if calls["n"] >= 2:                      # after the report lands, the "timeout" fires
            raise RuntimeError("simulated per-case timeout")
        return orig(messages, tools)
    c.chat_raw = chat
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=10)
    assert _cwes(out) == [("CWE-862", "llm_verified")]   # salvaged, not lost


def test_report_finding_is_tiered_against_the_engine_like_the_final_json():
    # A reported claim on a protected handler is still only llm_detect (engine does not back it).
    c = _client([
        _report(handler="Docs.me", file="app.py", line=21, mechanism="idor",
                cwe="CWE-639", confidence=0.7, engine_backed=True),
        {"content": "done", "tool_calls": []},
    ])
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=3)
    assert _cwes(out) == [("CWE-639", "llm_detect")]


def test_a_finding_reported_and_restated_in_final_json_counts_once():
    c = _client([
        _report(handler="Docs.del_doc", file="app.py", line=11,
                mechanism="missing_authorization", cwe="CWE-862", confidence=0.8,
                engine_backed=True),
        _final([{"handler": "Docs.del_doc", "file": "app.py", "line": 11,
                 "mechanism": "missing_authorization", "cwe": "CWE-862", "confidence": 0.8,
                 "engine_backed": True, "reasoning": "restated"}]),
    ])
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=5)
    assert len(out) == 1


def test_report_finding_duplicate_is_ignored_by_the_harness():
    from frame.sil.llm_hunt import hunt_exec as _he
    collected: list = []
    ex = _he(build_index(_prog(), [], ""), collected)
    a = dict(handler="Docs.del_doc", file="app.py", line=11, mechanism="missing_authorization")
    first = ex("report_finding", a)
    second = ex("report_finding", a)
    assert "Recorded finding #1" in first
    assert "Already recorded" in second
    assert len(collected) == 1


def test_intent_only_claim_without_engine_backing_stays_detect():
    # engine_backed=False (an intent judgement the engine cannot mechanically confirm).
    c = _client([_final([{"reasoning": "price comes from the client", "handler": "Docs.del_doc",
                          "file": "app.py", "line": 12, "mechanism": "business_logic",
                          "cwe": "CWE-840", "confidence": 0.6, "engine_backed": False}])])
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=3)
    assert _cwes(out) == [("CWE-840", "llm_detect")]


def test_already_proven_authz_handler_is_not_re_reported():
    # The engine already PROVED (solver-verified) an authorization flaw here -> no pile-on.
    class V:
        location, line, cwe_id = "app.py", 11, "CWE-639"
        type = "idor"
        evidence = "solver-verified"
    c = _client([_final([{"reasoning": "dup", "handler": "Docs.del_doc", "file": "app.py",
                          "line": 11, "mechanism": "idor", "cwe": "CWE-639", "confidence": 0.9,
                          "engine_backed": True}])])
    out = hunt_authz(_prog(), [V()], repo_root="", config=LLMConfig(), client=c, max_steps=3)
    assert out == []


def test_unverified_engine_candidate_does_not_suppress_the_agent_finding():
    # A hunt's own scan is unverified: its IDOR at this handler is a candidate, not a proof. The
    # agent confirming it is the agent's finding (this dropped weblate's real
    # UserViewSet.notifications report in favour of the unverified symbolic hit).
    class V:
        location, line, cwe_id = "app.py", 11, "CWE-639"
        type = "idor"
        evidence = "data-flow"
    c = _client([_final([{"reasoning": "any user's doc by id", "handler": "Docs.del_doc",
                          "file": "app.py", "line": 11, "mechanism": "idor", "cwe": "CWE-639",
                          "confidence": 0.9, "engine_backed": True}])])
    out = hunt_authz(_prog(), [V()], repo_root="", config=LLMConfig(), client=c, max_steps=3)
    assert _cwes(out) == [("CWE-639", "llm_verified")]


def test_engine_findings_tool_lists_authz_candidates_and_counts_the_rest():
    class Idor:
        location, line, cwe_id, type, evidence = "app.py", 11, "CWE-639", "idor", "data-flow"

    class Xss:
        location, line, cwe_id, type, evidence = "app.py", 12, "CWE-79", "xss", "solver-verified"
    idx = build_index(_prog(), [Idor(), Xss()], repo_root="")
    out = json.loads(hunt_exec(idx)("engine_findings", {}))
    assert [(f["cwe"], f["proven"]) for f in out["authorization"]] == [("CWE-639", False)]
    assert out["other_counts"] == {"CWE-79": 1}


def test_status_records_a_finished_hunt():
    c = _client([_final([])])
    status = {}
    hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=3, status=status)
    assert status["stop"] == "finished"


def test_status_records_a_transport_failure_instead_of_a_clean_empty_hunt():
    # The endpoint never answered: the hunt returns nothing, exactly like a hunt that looked and
    # found nothing -- the status is what tells them apart (11 BAC-Bench cases died this way).
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    c.chat_raw = lambda messages, tools=None: None
    status = {}
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=3,
                     status=status)
    assert out == []
    assert status["stop"] == "transport_error"


def test_unrelated_engine_finding_does_not_suppress_an_authz_hunt_finding():
    # The engine proved an XSS in this handler; that says nothing about its authorization, so the
    # hunt's IDOR in the same function must survive. (This dropped the real wger nutrition IDOR,
    # which shared a function with a symbolic XSS.)
    class V:
        location, line, cwe_id = "app.py", 11, "CWE-79"
        type = "xss"
    c = _client([_final([{"reasoning": "deletes any doc by id, no owner check",
                          "handler": "Docs.del_doc", "file": "app.py", "line": 11,
                          "mechanism": "missing_authorization", "cwe": "CWE-862",
                          "confidence": 0.8, "engine_backed": True}])])
    out = hunt_authz(_prog(), [V()], repo_root="", config=LLMConfig(), client=c, max_steps=3)
    assert _cwes(out) == [("CWE-862", "llm_verified")]


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


# ---- scanner integration -------------------------------------------------------

def test_scanner_hunt_authz_flows_into_results(tmp_path):
    """FrameScanner(hunt_authz=True) runs the hunt repo-scale and merges its tiered
    findings. The engine backs the claim (the handler reaches a resource and is not
    protected while its peer is caller-scoped) -> llm_verified."""
    import json as _json
    from frame.sil.scanner import FrameScanner
    from frame.sil.llm_triage import TriageConfig, LLMTriageClient
    (tmp_path / "app.py").write_text(
        "from flask import Flask, jsonify\n"
        "from flask_login import login_required, current_user\n"
        "from flask_sqlalchemy import SQLAlchemy\n"
        "app = Flask(__name__)\ndb = SQLAlchemy(app)\nclass Doc(db.Model): pass\n"
        "@app.route('/mine')\n@login_required\ndef mine():\n"
        "    return jsonify(Doc.query.filter_by(owner_id=current_user.id).all())\n"
        "@app.route('/all')\ndef all_docs():\n"
        "    return jsonify(Doc.query.filter_by(status='any').all())\n")
    cfg = TriageConfig(base_url="x", model="m")
    c = LLMTriageClient(cfg)
    seq = {"i": 0}
    script = [
        {"content": "", "tool_calls": [{"id": "1", "function": {
            "name": "list_handlers", "arguments": "{}"}}]},
        {"content": _json.dumps({"reasoning": "x", "findings": [
            {"reasoning": "all_docs has no auth while its peer is caller-scoped",
             "handler": "all_docs", "file": "app.py", "line": 13,
             "mechanism": "missing_authorization", "cwe": "CWE-862",
             "confidence": 0.8, "engine_backed": True}]}), "tool_calls": []},
    ]
    def chat(messages, tools=None):
        m = script[min(seq["i"], len(script) - 1)]
        seq["i"] += 1
        return m
    c.chat_raw = chat
    sc = FrameScanner(language="python", verify=False, hunt_authz=True, llm_config=cfg)
    sc._llm_client = c
    res = sc.scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    hunt = [(v.cwe_id, v.source_var) for r in res for v in r.vulnerabilities
            if v.source_var in ("llm_verified", "llm_detect")]
    assert hunt == [("CWE-862", "llm_verified")]


# ---- trajectory persistence + resume -------------------------------------------

def test_hunt_writes_a_trace_when_env_set(tmp_path, monkeypatch):
    import json as _json, os as _os
    from frame.sil.llm_trace import read_stf
    tdir = tmp_path / "traj"; tdir.mkdir()
    frame_config.override("hunt", "trajectory_dir", str(tdir))
    c = _client([
        _tool("list_handlers"),
        _final([{"reasoning": "x", "handler": "Docs.del_doc", "file": "app.py", "line": 11,
                 "mechanism": "missing_authorization", "cwe": "CWE-862", "confidence": 0.8,
                 "engine_backed": True}]),
    ])
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=5)
    assert _cwes(out) == [("CWE-862", "llm_verified")]
    header, msgs = read_stf(str(tdir / "units" / "app.py_Docs" / "hunt.jsonl"))   # one trace per unit
    assert header["harness"] == "frame"
    roles = [m["role"] for m in msgs]
    assert roles[:2] == ["system", "user"] and "tool" in roles and roles[-1] == "assistant"


def test_hunt_resumes_from_a_saved_trace(tmp_path, monkeypatch):
    # A pre-existing trace (ending at a tool result) is resumed: the agent continues and
    # the header is not duplicated.
    import json as _json
    from frame.sil.llm_trace import TraceWriter, read_stf
    tdir = tmp_path / "traj"; tdir.mkdir()
    (tdir / "units" / "app.py_Docs").mkdir(parents=True)
    p = str(tdir / "units" / "app.py_Docs" / "hunt.jsonl")      # the unit's own trace
    w = TraceWriter(p, "authz-hunt", name="prior")
    w.start()
    from frame.sil.llm_hunt import UNIT_SYSTEM
    w.append_message({"role": "system", "content": UNIT_SYSTEM})
    w.append_message({"role": "user", "content": "handlers..."})
    w.append_message({"role": "assistant", "content": "",
                      "tool_calls": [{"id": "1", "function": {"name": "list_handlers", "arguments": "{}"}}]})
    w.append_message({"role": "tool", "tool_call_id": "1", "content": "[]"})
    frame_config.override("hunt", "trajectory_dir", str(tdir))
    c = _client([_final([{"reasoning": "y", "handler": "Docs.del_doc", "file": "app.py",
                          "line": 11, "mechanism": "missing_authorization", "cwe": "CWE-862",
                          "confidence": 0.8, "engine_backed": True}])])
    out = hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=5)
    assert _cwes(out) == [("CWE-862", "llm_verified")]
    headers = [1 for ln in open(p) if _json.loads(ln).get("type") == "session"]
    assert len(headers) == 1                       # not duplicated on resume
    _, msgs = read_stf(p)
    assert msgs[1]["content"] == "handlers..."     # prior messages preserved
    assert msgs[-1]["role"] == "assistant"         # new final turn appended


def _prior_trace(tdir, *msgs):
    from frame.sil.llm_trace import TraceWriter
    (tdir / "units" / "app.py_Docs").mkdir(parents=True)
    p = str(tdir / "units" / "app.py_Docs" / "hunt.jsonl")
    w = TraceWriter(p, "authz-hunt", name="prior")
    w.start()
    for m in msgs:
        w.append_message(m)
    return p


@pytest.mark.parametrize("why", ["finished", "other_prompt"])
def test_a_finished_or_other_prompt_trace_is_kept_aside_and_the_unit_starts_fresh(tmp_path, monkeypatch, why):
    # Resuming a FINISHED conversation sends a request ending with the assistant's turn, which
    # Claude 5 rejects as a prefill: every call was an HTTP 400 and the unit never ran (wger and
    # actualbudget on BAC-Bench). An older prompt's conversation would skip the prompt change.
    from frame.sil.llm_hunt import UNIT_SYSTEM
    from frame.sil.llm_trace import read_stf
    tdir = tmp_path / "traj"; tdir.mkdir()
    system = UNIT_SYSTEM if why == "finished" else "an older unit prompt"
    last = ({"role": "assistant", "content": "done"} if why == "finished"
            else {"role": "tool", "tool_call_id": "1", "content": "[]"})
    p = _prior_trace(tdir, {"role": "system", "content": system},
                     {"role": "user", "content": "old intro"},
                     {"role": "assistant", "content": "", "tool_calls": [
                         {"id": "1", "function": {"name": "list_handlers", "arguments": "{}"}}]},
                     {"role": "tool", "tool_call_id": "1", "content": "[]"}, last)
    frame_config.override("hunt", "trajectory_dir", str(tdir))
    sent = []

    def fn(messages, tools=None):
        sent.append([m["role"] for m in messages])
        return {"content": "done", "tool_calls": []}
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    c.chat_raw = fn
    hunt_authz(_prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=5,
               scout_steps=0)
    assert sent and all(roles[-1] != "assistant" for roles in sent)    # never a prefill
    assert sent[0] == ["system", "user"]                               # a fresh start
    archived = tdir / "units" / "app.py_Docs" / "hunt.1.jsonl"
    assert archived.is_file() and read_stf(str(archived))[1][1]["content"] == "old intro"
    assert read_stf(p)[1][0]["content"] == UNIT_SYSTEM


# --- Track 2: dynamic testing (run_code), opt-in -----------------------------------------

def test_sandbox_python_captures_stdout_and_exit():
    from frame.sil.llm_agent import sandbox_python
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out = sandbox_python("print('hello', 1 + 1)", td, timeout_s=15)
        assert "exit=0" in out and "hello 2" in out


def test_sandbox_python_reports_nonzero_exit():
    from frame.sil.llm_agent import sandbox_python
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out = sandbox_python("import sys; sys.exit(3)", td, timeout_s=15)
        assert "exit=3" in out


def test_sandbox_python_times_out_and_is_killed():
    from frame.sil.llm_agent import sandbox_python
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out = sandbox_python("import time; time.sleep(30)", td, timeout_s=1)
        assert "TIMEOUT" in out


def test_hunt_tools_gates_run_code_behind_dynamic():
    from frame.sil.llm_hunt import hunt_tools
    names = lambda ts: {t["function"]["name"] for t in ts}
    assert "run_code" not in names(hunt_tools(dynamic=False))
    assert "run_code" in names(hunt_tools(dynamic=True))


def test_run_code_disabled_by_default_in_executor():
    idx = EngineIndex(handlers=[], findings=[], repo_root="/tmp", soundness_leads=[])
    ex = hunt_exec(idx, collected=[])                      # dynamic defaults to False
    assert "not enabled" in ex("run_code", {"code": "print(1)"})


def test_run_code_executes_when_dynamic_enabled():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        idx = EngineIndex(handlers=[], findings=[], repo_root=td, soundness_leads=[])
        ex = hunt_exec(idx, collected=[], dynamic=True, probe_timeout_s=15)
        out = ex("run_code", {"code": "print('probe-ran')"})
        assert "probe-ran" in out and "exit=0" in out
