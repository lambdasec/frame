"""Investigation units for the authorization hunt (frame/sil/hunt_units.py).

The engine decides what the hunt looks at: handlers grouped by class / file (siblings together),
the service layer in units of its own, unverified engine candidates attached to the unit that
contains them, and a ranking from engine facts only. v11's one-agent hunt missed 7 BAC-Bench
cases whose vulnerable handler was in the engine's own list; here every handler is in a unit and
a budget cut is reported (`deferred`), never silent."""

from frame.sil.hunt_units import class_of, plan_units, simple_name
from frame.sil.llm_hunt import EngineIndex, HandlerFact


def _h(name, file="app/views.py", line=10, end=None, protected=False, reaches=False, sinks=None,
       program=None):
    return HandlerFact(name=name, file=file, line=line, end_line=end or line + 5,
                       protected=protected, reaches_resource=reaches, sinks=sinks or [],
                       program=program)


def _ids(units):
    return [u.id for u in units]


def test_names():
    assert simple_name("pkg::Docs.get#2") == "get"
    assert class_of("AddonViewSet.destroy") == "AddonViewSet"
    assert class_of("index") == "" and class_of("anonymous_L118") == ""


def test_handlers_group_by_class_and_by_file_for_module_functions():
    idx = EngineIndex(handlers=[
        _h("AddonViewSet.list", line=10), _h("AddonViewSet.destroy", line=30),
        _h("UserViewSet.list", line=80),
        _h("index", file="app/routes.py", line=3), _h("show", file="app/routes.py", line=20)])
    units, deferred = plan_units(idx)
    assert deferred == []
    by_id = {u.id: u for u in units}
    assert sorted(by_id) == ["app/routes.py::<module>", "app/views.py::AddonViewSet",
                             "app/views.py::UserViewSet"]
    assert by_id["app/views.py::AddonViewSet"].names() == ["AddonViewSet.list", "AddonViewSet.destroy"]
    assert by_id["app/routes.py::<module>"].names() == ["index", "show"]


def test_a_big_class_is_split_into_chunks_in_line_order():
    idx = EngineIndex(handlers=[_h(f"Big.m{i}", line=10 * i + 1) for i in range(11)])
    units, _ = plan_units(idx, max_per_unit=4)
    assert sorted(_ids(units)) == ["app/views.py::Big#1", "app/views.py::Big#2", "app/views.py::Big#3"]
    first = next(u for u in units if u.id.endswith("#1"))
    assert first.names() == ["Big.m0", "Big.m1", "Big.m2", "Big.m3"]


def test_test_code_is_not_audited():
    class P:
        imports = {"pytest": "pytest"}
        procedures = {}
        language = "python"
    idx = EngineIndex(handlers=[_h("test_view", file="tests/test_views.py", program=P()),
                                _h("view", file="app/views.py")])
    units, _ = plan_units(idx, "python")
    assert _ids(units) == ["app/views.py::<module>"]


def test_unverified_candidates_go_to_the_unit_that_contains_them():
    idx = EngineIndex(
        handlers=[_h("Docs.get", line=10, end=20), _h("Docs.put", line=30, end=40),
                  _h("Other.get", file="app/other.py", line=5)],
        findings=[{"file": "app/views.py", "line": 33, "cwe": "CWE-639", "type": "idor", "proven": False},
                  {"file": "app/views.py", "line": 12, "cwe": "CWE-639", "type": "idor", "proven": True},
                  {"file": "app/views.py", "line": 14, "cwe": "CWE-79", "type": "xss", "proven": False}])
    units, _ = plan_units(idx)
    docs = next(u for u in units if u.id == "app/views.py::Docs")
    # Only the unverified authorization finding: a proven one is done, an XSS is not ours.
    assert [(c["line"], c["cwe"]) for c in docs.candidates] == [(33, "CWE-639")]
    assert units[0].id == "app/views.py::Docs"          # an open candidate ranks first


def test_ranking_uses_engine_facts_never_names():
    idx = EngineIndex(handlers=[
        _h("Safe.get", file="a.py", protected=True, reaches=True),
        _h("Open.get", file="b.py", protected=False, reaches=True),
        _h("Mixed.get", file="c.py", line=10, protected=True, reaches=True),
        _h("Mixed.delete", file="c.py", line=30, protected=False, reaches=True,
           sinks=[{"kind": "resource_modify", "line": 32}]),
        _h("Nothing.get", file="d.py")])
    units, _ = plan_units(idx)
    assert _ids(units) == ["c.py::Mixed", "b.py::Open", "a.py::Safe", "d.py::Nothing"]
    mixed = units[0]
    assert "siblings disagree about protection" in mixed.reasons
    assert "modifies stored data" in mixed.reasons


def test_service_layer_gets_its_own_units_and_an_unscoped_one_ranks_high():
    idx = EngineIndex(
        handlers=[_h("Router.handle", file="src/Router.js", protected=True, reaches=True)],
        service_functions=[{"name": "enforceRoleSecurity", "file": "src/SharedRest.js", "line": 42,
                            "scoped": False},
                           {"name": "find", "file": "src/RestQuery.js", "line": 5, "scoped": True}],
        authz_gates=[{"name": "checkAcl", "file": "src/SharedRest.js", "line": 90}],
        soundness_leads=[{"name": "grant", "file": "src/Grant.js", "line": 3, "reason": "unscoped grant"}])
    units, _ = plan_units(idx)
    by_id = {u.id: u for u in units}
    shared = by_id["src/SharedRest.js::<service>"]
    assert shared.kind == "service"
    assert [(m["name"], m["role"]) for m in shared.members] == [("enforceRoleSecurity", "service"),
                                                                ("checkAcl", "gate")]
    assert by_id["src/Grant.js::<service>"].members[0]["role"] == "soundness"
    # An unscoped data access + a gate outranks a protected route handler.
    assert units.index(shared) < units.index(by_id["src/Router.js::Router"])


def test_a_function_that_is_both_handler_and_service_is_audited_once():
    idx = EngineIndex(handlers=[_h("load", file="svc.py")],
                      service_functions=[{"name": "load", "file": "svc.py", "line": 10, "scoped": False}])
    units, _ = plan_units(idx)
    assert _ids(units) == ["svc.py::<module>"]


def test_the_budget_defers_the_rest_and_says_so():
    idx = EngineIndex(handlers=[_h(f"C{i}.get", file=f"f{i}.py", reaches=(i == 3)) for i in range(5)])
    units, deferred = plan_units(idx, max_units=2)
    assert len(units) == 2 and len(deferred) == 3
    assert units[0].id == "f3.py::C3"                    # the one reaching data is kept
    assert sorted(_ids(units) + _ids(deferred)) == sorted(f"f{i}.py::C{i}" for i in range(5))


def test_unit_ids_are_stable_across_runs():
    mk = lambda: EngineIndex(handlers=[_h("A.x", line=1), _h("A.y", line=9), _h("f", file="g.py")])  # noqa: E731
    assert _ids(plan_units(mk())[0]) == _ids(plan_units(mk())[0])


def test_coverage_units_take_what_several_units_read_and_none_owns():
    from frame.sil.hunt_units import coverage_units
    procs = {"perm.py": [{"name": "can_edit", "line": 3, "end_line": 8},
                         {"name": "fmt", "line": 20, "end_line": 22}],
             "util.py": [{"name": "slug", "line": 1, "end_line": 4}],
             "urls.py": [],
             "views.py": [{"name": "Docs.get", "line": 1, "end_line": 9}]}
    reads = {"perm.py": {"u1": [(1, 10)], "u2": [(2, 6)]},      # two readers, can_edit only
             "util.py": {"u1": [(1, 40)]},                       # one reader: incidental
             "urls.py": {"u1": [(1, 50)], "u2": [(1, 50)]},      # nothing to judge there
             "views.py": {"u1": [(1, 9)], "u2": [(1, 9)]}}       # owned by a unit already
    (u,) = coverage_units(reads, {"views.py"}, procs, min_readers=2)
    assert u.kind == "coverage" and u.files == ["perm.py"] and u.names() == ["can_edit"]
    assert u.members[0]["readers"] == 2 and u.id.startswith("perm.py::<coverage:")
    assert coverage_units(reads, {"views.py"}, procs, min_readers=3) == []


def test_coverage_members_are_the_most_read_procedures_capped_per_file():
    from frame.sil.hunt_units import MAX_PER_UNIT, coverage_units
    procs = {"svc.py": [{"name": f"f{i}", "line": 10 * i + 1, "end_line": 10 * i + 5}
                        for i in range(MAX_PER_UNIT + 3)]}
    hot = {"u1": [(1, 1000)], "u2": [(1, 15)], "u3": [(1, 15)]}   # f0, f1 read by all three
    (u,) = coverage_units({"svc.py": hot}, set(), procs)
    assert len(u.members) == MAX_PER_UNIT
    assert [m["readers"] for m in u.members[:2]] == [3, 3]
    assert [m["line"] for m in u.members] == sorted(m["line"] for m in u.members)
