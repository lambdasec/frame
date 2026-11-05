"""Code regions for the BAC-Bench deterministic matcher (benchmarks/bacbench/regions.py, match.py).

A finding about a case's defect is often cited at the handler that reaches the recorded helper
or at the helper a recorded handler delegates to. These pin what counts as the same code (the
enclosing function's own code, its same-file direct callers, uniquely-defined direct callees)
and what does not (a nested function's body, an ambiguous callee name, a function elsewhere)."""

import textwrap

from benchmarks.bacbench.match import case_detected, finding_matches_case
from benchmarks.bacbench.regions import case_regions, functions

FLOWS = textwrap.dedent('''\
    from .db import session


    def _read_flow(flow_id, user):
        stmt = select(Flow).where(Flow.id == flow_id)
        if user.auto_login:
            stmt = stmt.where(Flow.user_id == user.id)
        return session.exec(stmt).first()


    def read_flow(flow_id, user):
        return _read_flow(flow_id, user)


    def update_flow(flow_id, user, data):
        flow = _read_flow(flow_id, user)
        flow.data = data
        return flow


    def unrelated(x):
        return x + 1
    ''')

RUNS = textwrap.dedent('''\
    from .services.prep import prepare_run


    async def create_run(thread_id, user):
        return await prepare_run(thread_id, user)
    ''')

PREP = textwrap.dedent('''\
    async def prepare_run(thread_id, user):
        thread = await get_thread(thread_id)
        thread.status = "busy"
        return thread
    ''')


def _repo(tmp_path, files):
    for rel, code in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(code)
    return str(tmp_path)


def _case(file, a, b, lang="python"):
    return {"language": lang, "expected_cwes": ["CWE-639"], "sink_files": [file],
            "sink_locations": [{"file": file, "line_start": a, "line_end": b}]}


def _f(file, line, cwe="CWE-639"):
    return {"file": file, "line": line, "cwe": cwe}


def test_a_same_file_caller_of_the_recorded_helper_is_the_same_defect(tmp_path):
    root = _repo(tmp_path, {"api/flows.py": FLOWS})
    case = _case("api/flows.py", 4, 8)                      # _read_flow
    regs = case_regions(case, {"vulnerable": root})["vulnerable"]
    rel = {r["name"]: r["relation"] for r in regs}
    assert rel == {"_read_flow": "enclosing", "read_flow": "caller", "update_flow": "caller"}
    upd = FLOWS.splitlines().index("    flow.data = data") + 1
    assert finding_matches_case(_f("api/flows.py", upd + 40), case, regions=regs) is False  # past the end
    assert finding_matches_case(_f("api/flows.py", upd), case, regions=regs)
    unrel = FLOWS.splitlines().index("def unrelated(x):") + 1
    assert not finding_matches_case(_f("api/flows.py", unrel + 1), case, window=0, regions=regs)
    assert not finding_matches_case(_f("api/flows.py", upd, "CWE-89"), case, regions=regs)   # CWE still gates


def test_a_uniquely_defined_callee_in_another_file_is_the_same_defect(tmp_path):
    root = _repo(tmp_path, {"api/runs.py": RUNS, "services/prep.py": PREP})
    case = _case("api/runs.py", 5, 5)
    regs = case_regions(case, {"vulnerable": root})["vulnerable"]
    assert {(r["file"], r["name"], r["relation"]) for r in regs} == {
        ("api/runs.py", "create_run", "enclosing"), ("services/prep.py", "prepare_run", "callee")}
    assert case_detected([_f("services/prep.py", 3)], case, regs)
    assert not case_detected([_f("services/prep.py", 3)], case)          # the window alone misses it


def test_an_ambiguous_callee_is_not_guessed(tmp_path):
    other = "def prepare_run(x):\n    return x\n"
    root = _repo(tmp_path, {"api/runs.py": RUNS, "services/prep.py": PREP, "legacy/prep.py": other})
    regs = case_regions(_case("api/runs.py", 5, 5), {"vulnerable": root})["vulnerable"]
    assert [r["relation"] for r in regs] == ["enclosing"]


def test_the_fixed_checkout_finds_the_same_functions_by_name(tmp_path):
    vuln = _repo(tmp_path / "v", {"api/flows.py": FLOWS})
    fixed_src = "\n\n\n# the fix moved everything down\n" + FLOWS.replace(
        "        if user.auto_login:\n            stmt = stmt.where(Flow.user_id == user.id)\n",
        "        stmt = stmt.where(Flow.user_id == user.id)\n")
    fixed = _repo(tmp_path / "f", {"api/flows.py": fixed_src})
    regs = case_regions(_case("api/flows.py", 4, 8), {"vulnerable": vuln, "fixed": fixed})
    f_read = next(r for r in regs["fixed"] if r["name"] == "_read_flow")
    assert f_read["start"] == fixed_src.splitlines().index("def _read_flow(flow_id, user):") + 1
    assert {r["name"] for r in regs["fixed"]} == {"_read_flow", "read_flow", "update_flow"}


JS = textwrap.dedent('''\
    module.exports = function (app) {
      app.get('/api/a', (req, res) => {
        res.json(load(req.query.id));
      });
      app.post('/api/b', (req, res) => {
        save(req.body);
      });
    };
    ''')


def test_a_nested_function_is_a_hole_in_its_parent(tmp_path):
    root = _repo(tmp_path, {"server/index.js": JS})
    names = {f.name for f in functions(str(tmp_path / "server/index.js"))}
    assert {"app.get('/api/a')", "app.post('/api/b')"} <= names
    # the recorded line is the GET handler's body: the POST handler is not the same code
    case = _case("server/index.js", 3, 3, "javascript")
    regs = case_regions(case, {"vulnerable": root})["vulnerable"]
    assert [r["name"] for r in regs if r["relation"] == "enclosing"] == ["app.get('/api/a')"]
    assert not finding_matches_case(_f("server/index.js", 6, "CWE-862"), case, window=0, regions=regs)
    # a recorded line in the registration wrapper itself does not make every route the defect
    case = _case("server/index.js", 1, 1, "javascript")
    regs = case_regions(case, {"vulnerable": root})["vulnerable"]
    assert not finding_matches_case(_f("server/index.js", 6, "CWE-862"), case, window=0, regions=regs)


def test_no_regions_keeps_the_window_rule(tmp_path):
    case = _case("api/flows.py", 4, 8)
    assert finding_matches_case(_f("api/flows.py", 40), case)
    assert not finding_matches_case(_f("api/flows.py", 60), case)
    assert case_regions(case, {"vulnerable": str(tmp_path / "missing")}) == {}


def test_a_method_call_or_test_code_is_never_a_callee(tmp_path):
    runs = ("from .prep import prepare_run\n\n\n"
            "class V:\n"
            "    def create(self, tid):\n"
            "        self.get_object()\n"
            "        return prepare_run(tid)\n")
    other = "class Unrelated:\n    def get_object(self):\n        return 1\n"
    fake = "def prepare_run(x):\n    return x\n"
    root = _repo(tmp_path, {"api/runs.py": runs, "api/prep.py": PREP, "api/other.py": other,
                            "tests/test_runs.py": fake})
    regs = case_regions(_case("api/runs.py", 6, 6), {"vulnerable": root})["vulnerable"]
    assert {(r["name"], r["relation"]) for r in regs} == {("V.create", "enclosing"), ("prepare_run", "callee")}


def test_a_pair_is_blocked_only_where_the_vulnerable_checkout_found_the_defect(tmp_path):
    import json

    from benchmarks.bacbench.score import _score_system
    vuln = _repo(tmp_path / "v", {"api/flows.py": FLOWS})
    fixed = _repo(tmp_path / "f", {"api/flows.py": FLOWS})
    case = _case("api/flows.py", 4, 8)
    case["_regions"] = case_regions(case, {"vulnerable": vuln, "fixed": fixed})
    upd = FLOWS.splitlines().index("    flow.data = data") + 1
    read = FLOWS.splitlines().index("    return _read_flow(flow_id, user)") + 1

    def score(v, f):
        d = tmp_path / "res" / str(len(list((tmp_path).glob("res*/**/*.json")))) / "frame_hunt"
        d.mkdir(parents=True)
        (d / "c.json").write_text(json.dumps({"scans": {"vulnerable": {"findings": v},
                                                        "fixed": {"findings": f}}}))
        return _score_system(d, {"c": case})["per_case"]["c"]
    far = 200                                  # outside every window: only the regions decide
    case["sink_locations"][0].update(line_start=far, line_end=far)
    found_in_update = [_f("api/flows.py", upd)]
    # the fixed checkout still reports it in update_flow: the defect is still there
    assert score(found_in_update, [_f("api/flows.py", upd)]) == "detected"
    # it reports something in another caller of the helper: a different claim, the fix holds
    assert score(found_in_update, [_f("api/flows.py", read)]) == "paired"
