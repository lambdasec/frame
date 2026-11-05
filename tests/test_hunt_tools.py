"""The hunt's tools (frame/sil/hunt_tools.py): the agent asks the engine and teaches it.

Real translations of small Flask apps, no model: ranged reads with line numbers (the old
read_file stopped at 8,000 characters), grep that skips vendored bundles, the call graph across
files, siblings, guards / check backed by the engine's path facts, an on-demand verified scan,
teach() turning a blind engine into one that sees the app's data access and gate, verdict
recording with the falsification schema, and verdict reuse keyed on file contents."""

import json
import os

import pytest

from frame.sil.hunt_tools import (HuntContext, VerdictCache, grep, list_files, match_member,
                                  read_file, verdict_exec)


# ---- repository tools ----------------------------------------------------------------------

def test_read_file_ranges_are_numbered_and_say_how_to_continue(tmp_path):
    (tmp_path / "big.py").write_text("".join(f"x{i} = {i}\n" for i in range(1, 3001)))
    out = read_file(str(tmp_path), "big.py", 2835, 2840)
    assert out.splitlines()[0] == "big.py (3000 lines), lines 2835-2840:"
    assert "2835: x2835 = 2835" in out and "2840: x2840 = 2840" in out
    assert "start_line=2841" in out                       # how to keep reading
    head = read_file(str(tmp_path), "big.py")
    assert "1: x1 = 1" in head and "start_line=401" in head  # 400 lines max per call


def test_read_file_refuses_paths_outside_the_repo(tmp_path):
    assert read_file(str(tmp_path), "../../etc/passwd").startswith("ERROR")
    assert read_file(str(tmp_path), "missing.py").startswith("ERROR")


def test_grep_scopes_to_a_path_and_skips_vendored_and_minified_code(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.py").write_text("def get(): check_owner()\n")
    (tmp_path / "node_modules" / "lib").mkdir(parents=True)
    (tmp_path / "node_modules" / "lib" / "x.js").write_text("check_owner()\n")
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "swagger-ui.min.js").write_text("check_owner()\n")
    (tmp_path / "static" / "huge.js").write_text("check_owner()\n" + "a" * 1_100_000)
    (tmp_path / "other.py").write_text("check_owner()\n")
    out = grep(str(tmp_path), "check_owner")
    assert out.splitlines() == ["other.py:1: check_owner()", "app/views.py:1: def get(): check_owner()"]
    assert grep(str(tmp_path), "check_owner", path="app").splitlines() == [
        "app/views.py:1: def get(): check_owner()"]
    assert grep(str(tmp_path), "(").startswith("ERROR")


def test_list_files_counts_sources(tmp_path):
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "a.py").write_text("")
    (tmp_path / "api" / "b.py").write_text("")
    (tmp_path / "node_modules").mkdir()
    out = list_files(str(tmp_path))
    assert "api/  (2 source files)" in out and "node_modules" not in out


# ---- the engine as a tool, on a real translated app -----------------------------------------

APP = '''from flask import Flask, abort
from flask_login import login_required, current_user
from models import Doc
from service import load_doc

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


@app.route("/docs/<int:doc_id>/view")
def view_doc(doc_id):
    return load_doc(doc_id)
'''

SERVICE = '''from models import Doc


def load_doc(doc_id):
    return Doc.query.get(doc_id)
'''


@pytest.fixture
def app_ctx(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "service.py").write_text(SERVICE)
    (tmp_path / "models.py").write_text("class Doc:\n    pass\n")
    ctx = HuntContext(None, [], str(tmp_path), "python")
    progs, vulns = ctx._rescan(["app.py", "service.py", "models.py"], [], verify=False)
    ctx.programs, ctx.raw_findings = progs, vulns
    ctx.rebuild_index()
    return ctx


def test_handler_facts_show_posture_decorators_and_numbered_source(app_ctx):
    f = json.loads(app_ctx.handler_facts("purge_doc"))
    assert f["file"] == "app.py" and f["protected"] is True
    assert "login_required" in f["decorators"]
    assert "22:     doc = Doc.query.get(doc_id)" in f["source"]
    assert app_ctx.handler_facts("nope").startswith("ERROR")


def test_siblings_put_the_neighbours_checks_side_by_side(app_ctx):
    s = json.loads(app_ctx.siblings("purge_doc"))
    rows = {r["name"]: r for r in s["handlers"]}
    assert set(rows) >= {"delete_doc", "purge_doc", "view_doc"}
    # delete_doc's data access is guarded by the ownership check; purge_doc's is not.
    assert any("owner_id" in g for g in rows["delete_doc"].get("guards_at_data_access", []))
    assert not any("owner_id" in g for g in rows["purge_doc"].get("guards_at_data_access", []))


def test_callees_follow_a_handler_into_another_files_service_function(app_ctx):
    c = json.loads(app_ctx.callees("view_doc"))
    load = next(x for x in c["calls"] if x["call"].endswith("load_doc"))
    assert any(d.startswith("service.py:") for d in load["defined_in"])
    callers = json.loads(app_ctx.callers("load_doc"))["callers"]
    assert [(x["caller"], x["file"]) for x in callers] == [("view_doc", "app.py")]


def test_guards_and_check_answer_from_the_engines_path_facts(app_ctx):
    g = json.loads(app_ctx.guards("delete_doc", 15))
    texts = [x["text"] for x in g["guards_by_line"]["15"]]
    assert any("owner_id" in t for t in texts)
    proved = json.loads(app_ctx.check("delete_doc", 15, "guarded_by", "owner"))
    assert proved["verdict"] == "proved"
    refuted = json.loads(app_ctx.check("purge_doc", 23, "guarded_by", "owner"))
    assert refuted["verdict"] == "refuted" and refuted["witness"]
    assert json.loads(app_ctx.check("nope", 1, "guarded_by", "x"))["verdict"] == "unknown"


def test_trace_reports_engine_flows_or_says_there_are_none(app_ctx):
    t = json.loads(app_ctx.trace("purge_doc"))
    assert t["file"] == "app.py" and "flows" in t


def test_engine_scan_runs_the_verified_engine_on_demand(app_ctx):
    r = json.loads(app_ctx.engine_scan(["service.py"]))
    assert r["files"] == ["service.py"]
    assert app_ctx.engine_scan(["../outside.py"]).startswith("ERROR")


# ---- teach: a blind engine learns the app's convention ---------------------------------------

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
def blind_ctx(tmp_path):
    (tmp_path / "myapp").mkdir()
    (tmp_path / "myapp" / "__init__.py").write_text("")
    (tmp_path / "myapp" / "auth.py").write_text("def require_admin(f):\n    return f\n")
    (tmp_path / "myapp" / "repo.py").write_text(
        "class Repository:\n    def get(self, ident):\n        return {'id': ident}\n")
    (tmp_path / "app.py").write_text(BLIND_APP)
    ctx = HuntContext(None, [], str(tmp_path), "python")
    progs, vulns = ctx._rescan(["app.py"], [], verify=False)
    ctx.programs, ctx.raw_findings = progs, vulns
    ctx.rebuild_index()
    return ctx


def _posture(ctx):
    return {h.name: (h.protected, h.reaches_resource) for h in ctx.index.handlers}


def test_teach_makes_the_engine_see_the_apps_data_access_and_gate(blind_ctx):
    assert _posture(blind_ctx) == {"show": (False, False), "wipe": (False, False)}   # blind
    delta = json.loads(blind_ctx.teach(TAUGHT, ["app.py"]))
    assert delta["applied"] and delta["reaching_data_after"] == 2
    assert _posture(blind_ctx) == {"show": (False, True), "wipe": (True, True)}
    assert blind_ctx.taught_text == [TAUGHT]


def test_teach_rejects_an_invalid_pack_with_the_schema_error_and_changes_nothing(blind_ctx):
    out = blind_ctx.teach('[pack]\nname = "x"\nlanguage = "python"\nbogus = 1\n', ["app.py"])
    assert out.startswith("INVALID PACK") and "bogus" in out
    assert blind_ctx.taught == [] and _posture(blind_ctx) == {"show": (False, False), "wipe": (False, False)}


def test_teach_needs_files_to_apply_to(blind_ctx):
    assert blind_ctx.teach(TAUGHT, []).startswith("ERROR")
    assert blind_ctx.taught == []


def test_the_pack_guide_shown_to_the_agent_is_a_valid_pack(tmp_path):
    # The mapping pass shows the agent this example; an invalid example would teach it errors.
    from frame.sil.llm_hunt import PACK_GUIDE
    from frame.sil.packs import PackSet
    p = tmp_path / "guide.toml"
    p.write_text(PACK_GUIDE)
    PackSet.build([str(p)], builtin=True)                # raises PackError if invalid


# ---- verdicts -------------------------------------------------------------------------------

def _key(f):
    return (str(f.get("handler") or ""), str(f.get("file") or ""), f.get("line") or 0)


def test_report_needs_the_falsification_schema_and_sets_the_verdict():
    names = ["Docs.get", "Docs.put"]
    collected, verdicts, seen = [], {n: "none" for n in names}, set()
    ex = verdict_exec(names, collected, verdicts, seen, _key)
    out = ex("report_finding", {"handler": "get", "file": "a.py", "line": 3, "mechanism": "idor"})
    assert out.startswith("NOT RECORDED") and collected == []
    ok = {"handler": "get", "file": "a.py", "line": 3, "mechanism": "idor",
          "invariant": "only the owner reads a doc", "violating_request": "GET /docs/2 as user B"}
    assert ex("report_finding", ok).startswith("Recorded finding #1")
    assert ex("report_finding", ok).startswith("(Already recorded")
    assert verdicts == {"Docs.get": "reported", "Docs.put": "none"}
    assert ex("mark_safe", {"handler": "Docs.get", "reason": "owner filter in get_queryset"}) == "Marked Docs.get safe."
    assert verdicts["Docs.get"] == "reported"            # a report is not undone by mark_safe
    assert ex("mark_safe", {"handler": "put", "reason": "x"}).startswith("NOT RECORDED")
    assert ex("mark_safe", {"handler": "Other.x", "reason": "admin only via decorator"}).startswith("ERROR")
    assert ex("read_file", {}) is None                   # not a verdict tool


def test_match_member_needs_an_unambiguous_simple_name():
    assert match_member(["A.get", "B.put"], "get") == "A.get"
    assert match_member(["A.get", "B.get"], "get") is None
    assert match_member(["A.get", "B.get"], "B.get") == "B.get"


# ---- verdict reuse --------------------------------------------------------------------------

def test_verdicts_are_reused_only_when_every_file_read_is_unchanged(tmp_path):
    (tmp_path / "views.py").write_text("v1\n")
    (tmp_path / "perm.py").write_text("p1\n")
    path = str(tmp_path / "cache" / "case.json")
    VerdictCache(path).store("views.py::Docs", str(tmp_path), ["views.py", "perm.py"],
                             {"Docs.get": "safe"}, [])
    cache = VerdictCache(path)                           # reloaded from disk
    assert cache.lookup("views.py::Docs", str(tmp_path))["verdicts"] == {"Docs.get": "safe"}
    assert cache.lookup("other::X", str(tmp_path)) is None
    (tmp_path / "perm.py").write_text("p2\n")            # the fix touched a file the agent read
    assert cache.lookup("views.py::Docs", str(tmp_path)) is None
    os.remove(tmp_path / "perm.py")
    assert cache.lookup("views.py::Docs", str(tmp_path)) is None


def test_unresolved_is_a_verdict_that_must_say_what_would_decide_it():
    from frame.sil.hunt_tools import verdict_exec
    names = ["Docs.get", "Docs.put"]
    collected, verdicts, unresolved = [], {n: "none" for n in names}, []
    ex = verdict_exec(names, collected, verdicts, set(), lambda a: (a.get("file"), a.get("line")),
                      unresolved)
    assert ex("mark_unresolved", {"handler": "Docs.get", "suspicion": "x"}).startswith("NOT RECORDED")
    args = {"handler": "get", "suspicion": "any tenant admin creates root tenants",
            "checked": "create_tenant_allowed in routes/tenant.js",
            "needs": "whether role_id is read in the root schema at runtime"}
    assert ex("mark_unresolved", args) == "Marked Docs.get unresolved."
    assert verdicts["Docs.get"] == "unresolved" and unresolved[0]["handler"] == "Docs.get"
    ex("mark_safe", {"handler": "Docs.get", "reason": "found the root-schema check at :40"})
    assert verdicts["Docs.get"] == "safe" and unresolved == []
    assert ex("mark_unresolved", args).startswith("(Kept the earlier verdict")
    ex("mark_unresolved", {**args, "handler": "Docs.put"})
    ex("report_finding", {"handler": "Docs.put", "file": "a.py", "line": 3, "mechanism": "idor",
                          "invariant": "only the owner edits", "violating_request": "PUT /d/2 as B"})
    assert verdicts["Docs.put"] == "reported" and unresolved == []
