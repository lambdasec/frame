"""The hunt's scouts (frame/sil/llm_hunt.py `_scout_pass`, hunt_units.scout_areas / plan_units).

Unit mode audited only what the engine mapped. On the full BAC-Bench run, every miss so far had a
ground-truth file the engine never mapped (n8n, strapi, payload, parse-server, indico): their route
conventions had no pack, and the one mapping pass taught sinks and gates, never an entry point.
Scouts explore the repository area by area first, list the routes / service functions / helpers
they find, and teach the engine entry points; what the engine still does not cover gets units of
its own, so nothing is unaudited just because Frame does not know the framework."""

import json

import pytest

from frame.sil.hunt_tools import HuntContext
from frame.sil.hunt_units import Area, plan_units, scout_areas
from frame.sil.llm_client import LLMClient, LLMConfig
from frame.sil.llm_hunt import SCOUT_SYSTEM, UNIT_SYSTEM, EngineIndex, HandlerFact, hunt_authz


def _tc(tool, **args):
    return {"content": "", "tool_calls": [{"id": "1", "function": {
        "name": tool, "arguments": json.dumps(args)}}]}


def _done(text="done"):
    return {"content": text, "tool_calls": []}


def _client(fn):
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    c.chat_raw = fn
    return c


def _intro(messages):
    c = messages[1]["content"]
    return "".join(b.get("text", "") for b in c) if isinstance(c, list) else c


def _tools_done(messages):
    return sum(1 for m in messages if m.get("role") == "tool")


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


# ---- areas ---------------------------------------------------------------------------------

def test_a_small_repo_is_one_scout_and_skipped_dirs_are_not_scouted(tmp_path):
    _write(tmp_path, {"app/a.py": "", "app/b.py": "", "main.py": "", "tests/test_a.py": "",
                      "node_modules/x/index.js": "", "docs/conf.py": "", "app/readme.md": ""})
    scouts = scout_areas(str(tmp_path), "python")
    assert len(scouts) == 1 and [(a.path, a.files) for a in scouts[0]] == [("", 3)]


def test_a_monorepo_is_split_and_every_file_is_in_exactly_one_area(tmp_path):
    files = {f"packages/cli/src/c{i}.ts": "" for i in range(30)}
    files.update({f"packages/core/src/k{i}.ts": "" for i in range(25)})
    files.update({f"packages/ui/u{i}.tsx": "" for i in range(5)})
    files.update({"server.js": "", "packages/root.ts": ""})
    _write(tmp_path, files)
    scouts = scout_areas(str(tmp_path), "javascript", max_files=20, max_scouts=16)
    areas = [a for s in scouts for a in s]
    assert all(a.files <= 20 or not a.path.count("/") > 2 for a in areas)
    for rel in files:
        assert sum(1 for a in areas if a.holds(rel)) == 1, rel
    assert sum(a.files for a in areas) == len(files)
    # the files directly in a split directory are an area of their own
    assert any(a.path == "packages" and a.own_only for a in areas)


def test_areas_are_packed_into_at_most_max_scouts(tmp_path):
    _write(tmp_path, {f"svc{i}/m{j}.py": "" for i in range(10) for j in range(3)})
    scouts = scout_areas(str(tmp_path), "python", max_files=5, max_scouts=4)
    assert len(scouts) == 4
    assert sorted(a.path for s in scouts for a in s) == [f"svc{i}" for i in range(10)]


def test_a_scout_gets_neighbouring_directories(tmp_path):
    files = {f"packages/cli/src/{d}/f{j}.ts": "" for d in ("auth", "executions", "workflows") for j in range(4)}
    files.update({f"packages/nodes/n{i}/f{j}.ts": "" for i in range(12) for j in range(4)})
    _write(tmp_path, files)
    scouts = scout_areas(str(tmp_path), "javascript", max_files=4, max_scouts=5)
    cli = [i for i, s in enumerate(scouts) for a in s if a.path.startswith("packages/cli/")]
    assert len(set(cli)) == 1                       # the three controller folders, one scout
    assert sum(a.files for s in scouts for a in s) == len(files) and len(scouts) <= 5


# ---- the inventory -------------------------------------------------------------------------

def test_the_inventory_rejects_what_is_not_real_or_not_in_the_scouts_area(tmp_path):
    _write(tmp_path, {"api/flows.py": "def read_flow():\n    pass\n", "other/x.py": ""})
    ctx = HuntContext(EngineIndex(handlers=[HandlerFact("read_flow", "api/flows.py", 1, False, True)]),
                      [], str(tmp_path), "python")
    sink = []
    msg = ctx.record_inventory([
        {"kind": "route", "file": "api/flows.py", "function": "read_flow", "line": 1},
        {"kind": "route", "file": "api/flows.py", "function": "update_flow"},
        {"kind": "route", "file": "api/missing.py", "function": "x"},
        {"kind": "page", "file": "api/flows.py", "function": "y"},
        {"kind": "service", "file": "other/x.py", "function": "z"},
    ], sink, area=[Area("api", 1)])
    assert [(i["file"], i["function"]) for i in sink] == [("api/flows.py", "read_flow"),
                                                          ("api/flows.py", "update_flow")]
    assert "1 already engine handlers, 1 new" in msg and "outside your area" in msg
    assert "missing.py" in msg and "y (needs kind" in msg


def test_scouted_functions_the_engine_covers_get_no_unit_of_their_own():
    index = EngineIndex(handlers=[HandlerFact("Docs.get", "api/docs.py", 5, False, True)])
    scouted = [
        {"name": "Docs.get", "file": "api/docs.py", "line": 5, "role": "scouted_route"},
        {"name": "get", "file": "api/docs.py", "line": 5, "role": "scouted_route"},        # same
        {"name": "Notes.get", "file": "api/docs.py", "line": 30, "role": "scouted_route"},  # other class
        {"name": "delete_doc", "file": "api/docs.py", "line": 40, "role": "scouted_route"},
    ]
    units, _ = plan_units(index, "python", scouted=scouted)
    sc = [u for u in units if u.kind == "scouted"]
    assert len(sc) == 1 and sc[0].names() == ["Notes.get", "delete_doc"]
    assert "found by the scouts" in sc[0].reasons[0]
    other, _ = plan_units(index, "python", scouted=scouted[:3])
    assert [u.id for u in other if u.kind == "scouted"] != [sc[0].id]   # id follows the members


def test_a_named_file_never_resolves_to_another_files_handler():
    index = EngineIndex(handlers=[HandlerFact("show", "a/views.py", 3, False, True)])
    assert index.handler("show", "a/views.py") is not None
    assert index.handler("show", "b/views.py") is None
    assert index.handler("show") is not None


# ---- end to end: a blind app -----------------------------------------------------------------

BLIND = {
    "myapp/__init__.py": "",
    "myapp/web.py": "class BaseHandler:\n    def dispatch(self):\n        return None\n",
    "myapp/repo.py": "class Repository:\n    def get(self, ident):\n        return {'id': ident}\n",
    "app/__init__.py": "",
    "app/handlers.py": (
        "from myapp.web import BaseHandler\n"
        "from myapp.repo import Repository\n"
        "\n"
        "repo = Repository()\n"
        "\n"
        "\n"
        "class DocHandler(BaseHandler):\n"
        "    def get(self, doc_id):\n"
        "        return repo.get(doc_id)\n"),
}

ENTRYPOINT = '''[pack]
name = "app-routes"
language = "python"
description = "handlers are methods of BaseHandler subclasses"

[[entrypoint]]
extends = ["myapp.web.BaseHandler"]
method = ["get", "post"]
params = "all"
'''


@pytest.fixture
def blind(tmp_path):
    _write(tmp_path, BLIND)
    progs, vulns = HuntContext(None, [], str(tmp_path), "python")._rescan(
        ["app/handlers.py", "myapp/web.py", "myapp/repo.py"], [], verify=False)
    return tmp_path, progs, vulns


ROUTE = {"kind": "route", "file": "app/handlers.py", "function": "DocHandler.get", "line": 8,
         "note": "GET /docs/{id}"}


def test_a_route_only_a_scout_found_is_audited_and_never_engine_backed(blind):
    root, progs, vulns = blind
    units = []

    def chat(messages, tools=None):
        if messages[0]["content"] == SCOUT_SYSTEM:
            if _tools_done(messages) == 0:
                return _tc("record_inventory", items=[ROUTE])
            if _tools_done(messages) == 1:
                return _tc("finish_scout", summary="Callers authenticate with a session cookie.")
            return _done()
        assert messages[0]["content"] == UNIT_SYSTEM
        if _tools_done(messages) == 0:
            units.append(_intro(messages))
            return _tc("report_finding", handler="DocHandler.get", file="app/handlers.py", line=9,
                       mechanism="idor", cwe="CWE-639", engine_backed=True,
                       invariant="only the owner may read a doc",
                       violating_request="GET /docs/<someone else's id> as any signed-in user")
        return _done()
    status = {}
    out = hunt_authz(progs, vulns, str(root), LLMConfig(), client=_client(chat), max_steps=4,
                     status=status, language="python")
    # the engine saw no handler at all, yet the hunt ran in units (not the one-agent fallback)
    assert status["scout"]["inventory"] == {"route": 1} and status["scout"]["scouted_units"] == 1
    assert len(units) == 1 and "FOUND BY THE SCOUTS" in units[0]
    assert "DocHandler.get  (app/handlers.py:8)" in units[0] and "GET /docs/{id}" in units[0]
    assert "APPLICATION PROFILE" in units[0] and "session cookie" in units[0]
    assert status["profile"] == "Callers authenticate with a session cookie."
    assert "app/handlers.py" in status["map_files"]
    row = next(u for u in status["units"] if u["kind"] == "scouted")
    assert row["verdicts"] == {"DocHandler.get": "reported"}
    assert [(v.cwe_id, v.source_var) for v in out] == [("CWE-639", "llm_detect")]


def test_a_taught_entrypoint_turns_the_scouted_route_into_an_engine_handler(blind):
    root, progs, vulns = blind
    replies, units = [], []

    def chat(messages, tools=None):
        n = _tools_done(messages)
        if messages[0]["content"] == SCOUT_SYSTEM:
            if n:
                replies.append(messages[-1]["content"])
            if n == 0:
                return _tc("teach", pack_toml=ENTRYPOINT, files=["app/handlers.py"])
            if n == 1:
                return _tc("record_inventory", items=[ROUTE])
            if n == 2:
                return _tc("finish_scout", summary="BaseHandler subclasses are the routes.")
            return _done()
        if len(messages) == 2:              # a unit agent's first turn (nudges follow)
            units.append(_intro(messages))
        return _done()
    status = {}
    hunt_authz(progs, vulns, str(root), LLMConfig(), client=_client(chat), max_steps=4,
               status=status, language="python")
    taught = json.loads(replies[0])
    assert taught["new_handlers"] == ["app/handlers.py:DocHandler.get"] and "note" not in taught
    assert "1 already engine handlers, 0 new" in replies[1]
    assert status["taught_packs"] == 1 and status["scout"]["scouted_units"] == 0
    assert len(units) == 1 and "FOUND BY THE SCOUTS" not in units[0]
    assert "- DocHandler.get  (app/handlers.py:8-9)" in units[0]


def test_a_pack_that_adds_no_handler_says_so(blind):
    root, progs, vulns = blind
    ctx = HuntContext(EngineIndex(), progs, str(root), "python", vulns)
    out = json.loads(ctx.teach(ENTRYPOINT.replace("myapp.web.BaseHandler", "myapp.web.Nothing"),
                               ["app/handlers.py"]))
    assert out["new_handlers"] == [] and "NO new handlers" in out["note"]


def test_without_scouts_a_blind_app_falls_back_to_one_agent(blind):
    root, progs, vulns = blind
    seen = []

    def chat(messages, tools=None):
        seen.append(messages[0]["content"])
        return _done()
    status = {}
    hunt_authz(progs, vulns, str(root), LLMConfig(), client=_client(chat), max_steps=2,
               status=status, language="python", scout_steps=0)
    assert seen and SCOUT_SYSTEM not in seen and UNIT_SYSTEM not in seen
    assert "scout" not in status
