"""The unit-mode hunt end to end (frame/sil/llm_hunt.py `_hunt_units`), with scripted clients.

What it must guarantee: every unit gets a fresh agent and a verdict is demanded on each member;
unverified engine candidates reach the agent; units run in parallel with one client each; an
interruption salvages what was reported and stops the rest; a dead endpoint is `transport_error`
(all units) or `partial` (some), never a clean empty hunt; verdicts are reused on another checkout
only when every file read is unchanged; the mapping pass's profile reaches every unit and what it
teaches the engine reshapes the units; the engine tools answer inside a unit."""

import json
import threading

import pytest

import frame.sil.llm_hunt as llm_hunt
from frame import config as frame_config
from frame.sil.hunt_tools import HuntContext
from frame.sil.llm_client import LLMClient, LLMConfig
from frame.sil.llm_hunt import SCOUT_SYSTEM, UNIT_SYSTEM, hunt_authz
from frame.sil.types import Location


class _Proc:
    def __init__(self, span):
        self.span = span            # a line range here; frontends record bytes
        self.end_line = span[1]
        self.nodes = {}


class _Program:
    def __init__(self, authz, procs=None):
        self.handler_authz = authz
        self.procedures = procs or {}


def _tc(tool, **args):
    return {"content": "", "tool_calls": [{"id": "1", "function": {
        "name": tool, "arguments": json.dumps(args)}}]}


def _done(text="done"):
    return {"content": text, "tool_calls": []}


def _intro(messages):
    c = messages[1]["content"]
    return "".join(b.get("text", "") for b in c) if isinstance(c, list) else c


def _is_unit(messages):
    return messages[0]["content"] == UNIT_SYSTEM


def _prog(root=""):
    p = (lambda f: f"{root}/{f}") if root else (lambda f: f)
    return _Program({"Docs.del_doc": (False, True, Location(p("app.py"), 10)),
                     "Docs.me": (True, True, Location(p("app.py"), 20))},
                    {"Docs.del_doc": _Proc((10, 15)), "Docs.me": _Proc((20, 25))})


def _client(fn):
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    c.chat_raw = fn
    return c


REPORT = {"handler": "Docs.del_doc", "file": "app.py", "line": 11, "mechanism": "idor",
          "cwe": "CWE-639", "engine_backed": True, "invariant": "only the owner deletes a doc",
          "violating_request": "DELETE /docs/7 as user B, who does not own doc 7"}


def test_unit_mode_records_the_map_the_units_and_every_verdict():
    script = [_tc("report_finding", **REPORT),
              _tc("mark_safe", handler="Docs.me", reason="scoped to current_user by the engine"),
              _done()]
    i = {"n": 0}

    def chat(messages, tools=None):
        i["n"] += 1
        return script[min(i["n"] - 1, len(script) - 1)]
    status = {}
    out = hunt_authz(_prog(), [], "", LLMConfig(), client=_client(chat), max_steps=6, status=status)
    assert [(v.cwe_id, v.source_var) for v in out] == [("CWE-639", "llm_verified")]
    assert status["stop"] == "finished" and status["map_files"] == ["app.py"]
    (u,) = status["units"]
    assert u["id"] == "app.py::Docs" and u["investigated"] and u["stop"] == "finished"
    assert u["verdicts"] == {"Docs.del_doc": "reported", "Docs.me": "safe"}


def test_an_agent_that_stops_without_verdicts_is_pushed_back_twice_then_let_go():
    seen = []

    def chat(messages, tools=None):
        seen.append(messages[-1]["content"])
        return _done("nothing here")
    status = {}
    hunt_authz(_prog(), [], "", LLMConfig(), client=_client(chat), max_steps=10, status=status)
    nudges = [m for m in seen if isinstance(m, str) and m.startswith("Not done")]
    assert len(nudges) == 2 and "Docs.del_doc" in nudges[0] and "Docs.me" in nudges[0]
    assert status["units"][0]["verdicts"] == {"Docs.del_doc": "none", "Docs.me": "none"}
    assert status["stop"] == "finished"


def test_unverified_engine_candidates_are_put_to_the_unit_agent():
    class V:
        location, line, cwe_id, type, evidence = "app.py", 11, "CWE-639", "idor", "data-flow"
    intros = []

    def chat(messages, tools=None):
        intros.append(_intro(messages))
        return _done()
    hunt_authz(_prog(), [V()], "", LLMConfig(), client=_client(chat), max_steps=3)
    assert "ENGINE CANDIDATES" in intros[0] and "CWE-639 idor at app.py:11" in intros[0]


def _many(n):
    return _Program({f"C{i}.get": (False, True, Location(f"f{i}.py", 1)) for i in range(n)},
                    {f"C{i}.get": _Proc((1, 5)) for i in range(n)})


def test_units_run_in_parallel_with_a_fresh_client_each(monkeypatch):
    made, active, peak = [], {"n": 0}, {"n": 0}
    lock = threading.Lock()

    class Stub:
        def __init__(self, config):
            self.stats = {"calls": 0, "errors": 0}
            self.last_call = {}
            made.append(self)

        def chat_raw(self, messages, tools=None):
            import time
            with lock:
                active["n"] += 1
                peak["n"] = max(peak["n"], active["n"])
            time.sleep(0.05)
            with lock:
                active["n"] -= 1
            self.stats["calls"] += 1
            name = _intro(messages).split("HANDLERS")[1].split("- ")[1].split()[0]
            return _tc("mark_safe", handler=name, reason="public catalog by design") \
                if not any(m.get("role") == "tool" for m in messages) else _done()
    monkeypatch.setattr(llm_hunt, "LLMClient", Stub)
    status = {}
    hunt_authz(_many(6), [], "", LLMConfig(), client=None, status=status, concurrency=4,
               unit_steps=4, scout_steps=0)
    assert len(made) == 6                                 # one client per unit
    assert peak["n"] > 1                                  # actually concurrent
    assert status["stop"] == "finished" and status["llm_calls"] == 12
    assert all(u["verdicts"] == {u["handlers"][0]: "safe"} for u in status["units"])


def test_an_interruption_salvages_reports_and_cancels_the_remaining_units():
    calls = {"n": 0}

    def chat(messages, tools=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return _tc("report_finding", **{**REPORT, "handler": "C0.get", "file": "f0.py", "line": 2})
        raise RuntimeError("simulated per-case timeout")
    prog = _many(3)
    prog.handler_authz["C0.get"] = (False, True, Location("f0.py", 1))
    status = {}
    out = hunt_authz(prog, [], "", LLMConfig(), client=_client(chat), max_steps=5, status=status)
    assert [v.cwe_id for v in out] == ["CWE-639"]
    assert status["stop"] == "exception" and status["error"] == "RuntimeError"
    assert [u["stop"] for u in status["units"]] == ["exception", "cancelled", "cancelled"]


def test_a_dead_endpoint_is_transport_error_and_a_flaky_one_is_partial(monkeypatch):
    dead = []

    class Stub:
        def __init__(self, config):
            self.stats = {"calls": 0, "errors": 0}
            self.last_call = {}
            self.dead = len(dead) in (0,)            # the first unit's endpoint never answers
            dead.append(self)

        def chat_raw(self, messages, tools=None):
            self.stats["calls"] += 1
            if self.dead:
                self.stats["errors"] += 1
                return None
            return _done()
    monkeypatch.setattr(llm_hunt, "LLMClient", Stub)
    status = {}
    hunt_authz(_many(3), [], "", LLMConfig(), client=None, status=status, concurrency=1,
               unit_steps=3, scout_steps=0)
    assert status["stop"] == "partial"
    assert [u["investigated"] for u in status["units"]] == [False, True, True]
    assert status["units"][0]["stop"] == "transport_error"

    status = {}
    hunt_authz(_many(2), [], "", LLMConfig(), client=_client(lambda m, t=None: None),
               max_steps=3, status=status)
    assert status["stop"] == "transport_error"


def test_verdicts_are_reused_on_an_unchanged_checkout_and_redone_after_a_change(tmp_path):
    for d in ("vuln", "fixed"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "app.py").write_text("x = 1\n" * 30)
    cache = str(tmp_path / "cache.json")
    calls = {"n": 0}

    def chat(messages, tools=None):
        calls["n"] += 1
        if not any(m.get("role") == "tool" for m in messages):
            return _tc("report_finding", **REPORT)
        if sum(1 for m in messages if m.get("role") == "tool") == 1:
            return _tc("mark_safe", handler="Docs.me", reason="scoped by current_user")
        return _done()
    run = lambda d: hunt_authz(_prog(str(tmp_path / d)), [], str(tmp_path / d), LLMConfig(),  # noqa: E731
                               client=_client(chat), max_steps=6, verdict_cache=cache,
                               scout_steps=0, status=(st := {})) and st or st
    first = {}
    out1 = hunt_authz(_prog(str(tmp_path / "vuln")), [], str(tmp_path / "vuln"), LLMConfig(),
                      client=_client(chat), max_steps=6, verdict_cache=cache, scout_steps=0,
                      status=first)
    n1 = calls["n"]
    assert n1 > 0 and len(out1) == 1 and not first["units"][0]["reused"]
    # Same content on the other checkout: reused, no model call, same finding and verdicts.
    second = {}
    out2 = hunt_authz(_prog(str(tmp_path / "fixed")), [], str(tmp_path / "fixed"), LLMConfig(),
                      client=_client(chat), max_steps=6, verdict_cache=cache, scout_steps=0,
                      status=second)
    assert calls["n"] == n1 and second["units"][0]["reused"]
    assert len(out2) == 1 and second["units"][0]["verdicts"]["Docs.me"] == "safe"
    # The fix changed a file the agent read: investigated again.
    (tmp_path / "fixed" / "app.py").write_text("x = 2\n" * 30)
    third = {}
    hunt_authz(_prog(str(tmp_path / "fixed")), [], str(tmp_path / "fixed"), LLMConfig(),
               client=_client(chat), max_steps=6, verdict_cache=cache, scout_steps=0, status=third)
    assert calls["n"] > n1 and not third["units"][0]["reused"]
    del run


def test_the_profile_reaches_every_unit(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n" * 30)
    intros = []

    def chat(messages, tools=None):
        if messages[0]["content"] == SCOUT_SYSTEM:
            if not any(m.get("role") == "tool" for m in messages):
                return _tc("finish_scout", summary="Ownership: Doc.owner_id == request.user.id")
            return _done()
        intros.append(_intro(messages))
        return _done()
    status = {}
    hunt_authz(_prog(str(tmp_path)), [], str(tmp_path), LLMConfig(), client=_client(chat),
               max_steps=3, status=status)
    assert status["profile"] == "Ownership: Doc.owner_id == request.user.id"
    assert intros and all("APPLICATION PROFILE" in i and "Doc.owner_id" in i for i in intros)


BLIND_APP = '''from flask import Flask
from myapp.auth import require_admin
from myapp.repo import Repository

app = Flask(__name__)
repo = Repository()


@app.route("/docs/<doc_id>")
def show(doc_id):
    return repo.get(doc_id)


@app.route("/admin/<doc_id>", methods=["DELETE"])
@require_admin
def wipe(doc_id):
    return repo.get(doc_id)
'''

TAUGHT = '''[pack]
name = "app-conventions"
language = "python"
description = "the app's repository and admin gate"

[[sink]]
call = ["myapp.repo.Repository.get"]
kind = "resource_select"

[[auth_gate]]
decorator = ["myapp.auth.require_admin"]
'''


@pytest.fixture
def blind_repo(tmp_path):
    (tmp_path / "myapp").mkdir()
    (tmp_path / "myapp" / "__init__.py").write_text("")
    (tmp_path / "myapp" / "auth.py").write_text("def require_admin(f):\n    return f\n")
    (tmp_path / "myapp" / "repo.py").write_text(
        "class Repository:\n    def get(self, ident):\n        return {'id': ident}\n")
    (tmp_path / "app.py").write_text(BLIND_APP)
    progs, vulns = HuntContext(None, [], str(tmp_path), "python")._rescan(["app.py"], [], verify=False)
    return tmp_path, progs, vulns


def test_what_the_mapping_pass_teaches_reshapes_the_units(blind_repo, monkeypatch):
    root, progs, vulns = blind_repo
    tdir = root.parent / "traj"
    frame_config.override("hunt", "trajectory_dir", str(tdir))
    intros = []

    def chat(messages, tools=None):
        tools_done = sum(1 for m in messages if m.get("role") == "tool")
        if messages[0]["content"] == SCOUT_SYSTEM:
            if tools_done == 0:
                return _tc("teach", pack_toml=TAUGHT, files=["app.py"])
            if tools_done == 1:
                return _tc("finish_scout", summary="Admin routes use @require_admin.")
            return _done()
        intros.append(_intro(messages))
        return _done()
    status = {}
    hunt_authz(progs, vulns, str(root), LLMConfig(), client=_client(chat), max_steps=3,
               status=status, language="python")
    assert status["taught_packs"] == 1
    unit = intros[0]
    # The engine now sees both data accesses and the admin gate.
    assert "- show " in unit and "show  (app.py:10-11)  protected=False  reaches_data=True" in unit
    assert "wipe  (app.py:16-17)  protected=True  reaches_data=True" in unit
    assert (tdir / "scout" / "taught-1.toml").read_text() == TAUGHT     # the reusable artifact


APP = '''from flask import Flask, abort
from flask_login import login_required, current_user
from models import Doc

app = Flask(__name__)


@app.route("/docs/<int:doc_id>", methods=["DELETE"])
@login_required
def delete_doc(doc_id):
    doc = Doc.query.get(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
    doc.delete()
    return "ok"


@app.route("/docs/<int:doc_id>/purge", methods=["DELETE"])
@login_required
def purge_doc(doc_id):
    doc = Doc.query.get(doc_id)
    doc.delete()
    return "ok"
'''


def test_the_engine_answers_inside_a_unit(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "models.py").write_text("class Doc:\n    pass\n")
    progs, vulns = HuntContext(None, [], str(tmp_path), "python")._rescan(["app.py"], [], verify=False)
    results = {}

    def chat(messages, tools=None):
        if not _is_unit(messages):
            return _done()
        n = sum(1 for m in messages if m.get("role") == "tool")
        if n == 0:
            return _tc("siblings", name="purge_doc")
        if n == 1:
            results["siblings"] = messages[-1]["content"]
            return _tc("check", name="purge_doc", line=22, kind="guarded_by", pattern="owner")
        if n == 2:
            results["check"] = messages[-1]["content"]
            return _tc("read_file", path="app.py", start_line=20, end_line=23)
        if n == 3:
            results.setdefault("read", messages[-1]["content"])   # not the coverage nudge after it
        return _done()
    hunt_authz(progs, vulns, str(tmp_path), LLMConfig(), client=_client(chat), max_steps=6,
               scout_steps=0, language="python")
    sib = json.loads(results["siblings"])
    assert {r["name"] for r in sib["handlers"]} == {"delete_doc", "purge_doc"}
    assert json.loads(results["check"])["verdict"] == "refuted"
    assert "21:     doc = Doc.query.get(doc_id)" in results["read"]


def test_scanner_passes_the_hunt_budget_through(tmp_path):
    from frame.sil.llm_triage import LLMTriageClient, TriageConfig
    from frame.sil.scanner import FrameScanner
    (tmp_path / "a.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n@app.route('/a')\ndef a():\n    return 'a'\n")
    (tmp_path / "b.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n@app.route('/b')\ndef b():\n    return 'b'\n")
    cfg = TriageConfig(base_url="x", model="m")
    c = LLMTriageClient(cfg)
    c.chat_raw = lambda messages, tools=None: _done()
    sc = FrameScanner(language="python", verify=False, hunt_authz=True, llm_config=cfg,
                      hunt_options={"max_units": 1, "scout_steps": 0})
    sc._llm_client = c
    sc.scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    st = sc.last_hunt_status
    assert st["stop"] == "finished" and st["deferred_units"] == 1
    assert [u["stop"] for u in st["units"]] == ["finished", "deferred"]


class _Fn:
    def __init__(self, file, line, end):
        self.loc = Location(file, line)
        self.end_line = end
        self.nodes = {}


def _coverage_repo(tmp_path):
    for f in ("f0.py", "f1.py", "perm.py"):
        (tmp_path / f).write_text("x = 1\n" * 30)
    progs = [_Program({f"C{i}.get": (False, True, Location(str(tmp_path / f"f{i}.py"), 1))},
                      {f"C{i}.get": _Fn(str(tmp_path / f"f{i}.py"), 1, 5)}) for i in range(2)]
    progs.append(_Program({}, {"can_edit": _Fn(str(tmp_path / "perm.py"), 3, 8),
                               "fmt": _Fn(str(tmp_path / "perm.py"), 20, 22)}))
    return progs


def _reading_agent(intros):
    """First-wave agents read perm.py:1-10 and mark their handler safe; a coverage unit's agent
    marks what it is shown safe."""
    import re

    def chat(messages, tools=None):
        intro = _intro(messages)
        names = re.findall(r"^- (\S+)  \(", intro, re.M)
        turn = (len(messages) - 2) // 2
        if "CODE OTHER UNITS RELIED ON" in intro:
            intros.append(intro)
            return _tc("mark_safe", handler=names[0], reason="checks the caller's role") \
                if turn == 0 else _done()
        if turn == 0:
            return _tc("read_file", path="./perm.py", start_line=1, end_line=10)
        if turn == 1:
            return _tc("mark_safe", handler=names[0], reason="delegates to perm.can_edit")
        return _done()
    return chat


def test_code_the_units_relied_on_gets_a_unit_of_its_own(tmp_path):
    intros = []
    status = {}
    hunt_authz(_coverage_repo(tmp_path), [], str(tmp_path), LLMConfig(),
               client=_client(_reading_agent(intros)), unit_steps=6, scout_steps=0, status=status)
    assert status["stop"] == "finished"
    assert status["coverage"]["read_unowned"] == [{"file": "perm.py", "readers": 2}]
    assert status["coverage"]["units"] == 1 and status["coverage"]["deferred"] == 0
    (row,) = [u for u in status["units"] if u["kind"] == "coverage"]
    assert row["handlers"] == ["can_edit"] and row["verdicts"] == {"can_edit": "safe"}
    assert "read by 2 of the units" in intros[0] and "fmt" not in intros[0]


def test_coverage_wave_is_off_at_zero_and_counts_against_the_unit_budget(tmp_path):
    status = {}
    frame_config.override("hunt", "coverage_readers", 0)
    hunt_authz(_coverage_repo(tmp_path), [], str(tmp_path), LLMConfig(),
               client=_client(_reading_agent([])), unit_steps=6, scout_steps=0, status=status)
    assert "coverage" not in status and all(u["kind"] != "coverage" for u in status["units"])
    frame_config.activate(None)
    status = {}
    hunt_authz(_coverage_repo(tmp_path), [], str(tmp_path), LLMConfig(),
               client=_client(_reading_agent([])), unit_steps=6, scout_steps=0, max_units=2,
               status=status)
    assert status["coverage"]["deferred"] == 1 and status["deferred_units"] == 1
    assert [u["stop"] for u in status["units"] if u["kind"] == "coverage"] == ["deferred"]


def test_an_unresolved_member_reaches_the_status_with_its_place():
    script = [_tc("mark_unresolved", handler="Docs.del_doc",
                  suspicion="any user deletes any doc if the proxy does not strip X-Owner",
                  checked="Docs.del_doc and the middleware in app.py",
                  needs="whether the deployment's proxy strips the X-Owner header"),
              _tc("mark_safe", handler="Docs.me", reason="scoped to current_user by the engine"),
              _done()]
    i = {"n": 0}

    def chat(messages, tools=None):
        i["n"] += 1
        return script[min(i["n"] - 1, len(script) - 1)]
    status = {}
    out = hunt_authz(_prog(), [], "", LLMConfig(), client=_client(chat), max_steps=6, status=status)
    assert out == [] and status["stop"] == "finished"
    assert status["units"][0]["verdicts"] == {"Docs.del_doc": "unresolved", "Docs.me": "safe"}
    (u,) = status["unresolved"]
    assert (u["file"], u["line"], u["handler"], u["unit"]) == ("app.py", 10, "Docs.del_doc", "app.py::Docs")
    assert "X-Owner" in u["needs"]


def test_scan_output_shows_the_hunt_and_what_it_left_unresolved():
    from frame.sil.cli import format_hunt_text, hunt_summary
    assert hunt_summary(None) is None and hunt_summary({"stop": "not_run"}) is None
    h = hunt_summary({"stop": "finished", "deferred_units": 1, "coverage": {"units": 2},
                      "units": [{"stop": "finished"}, {"stop": "reused"}, {"stop": "deferred"}],
                      "unresolved": [{"file": "app.py", "line": 10, "handler": "Docs.del_doc",
                                      "suspicion": "any user deletes any doc", "needs": "proxy config"}]})
    assert (h["units"], h["deferred_units"], h["coverage_units"]) == (2, 1, 2)
    text = format_hunt_text(h)
    assert "Authorization hunt: 2 units audited (finished)" in text
    assert "app.py:10 Docs.del_doc: any user deletes any doc" in text and "needs: proxy config" in text
