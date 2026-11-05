"""BAC-Bench scoring (benchmarks/bacbench/score.py): a hunt that never reached the model is
not evidence. On the vulnerable checkout it is a hunt-error, not a miss; on the fixed checkout
its empty finding list must not turn a detection into a pair. The per-tier view keeps the hunt
agent's results apart from the engine's (a frame_hunt run carries both)."""

import json

from benchmarks.bacbench.score import _score_system

CASE = {"expected_cwes": ["CWE-639"], "sink_files": ["app/views.py"],
        "sink_locations": [{"file": "app/views.py", "line_start": 10, "line_end": 12}]}
HIT_LLM = {"file": "app/views.py", "line": 11, "cwe": "CWE-639", "tier": "llm"}
HIT_SYM = {"file": "app/views.py", "line": 11, "cwe": "CWE-639", "tier": "symbolic"}


def _rec(tmp_path, cid, vulnerable, fixed):
    d = tmp_path / "frame_hunt"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{cid}.json").write_text(json.dumps({"scans": {"vulnerable": vulnerable, "fixed": fixed}}))
    return d


def test_dead_hunt_on_the_vulnerable_checkout_is_not_a_miss(tmp_path):
    d = _rec(tmp_path, "c", {"findings": [], "hunt": {"stop": "transport_error"}},
             {"findings": [], "hunt": {"stop": "finished"}})
    s = _score_system(d, {"c": CASE})
    assert s["per_case"]["c"] == "hunt-error" and s["hunt_errors"] == 1


def test_dead_hunt_on_the_fixed_checkout_is_not_a_pair(tmp_path):
    d = _rec(tmp_path, "c", {"findings": [HIT_LLM], "hunt": {"stop": "finished"}},
             {"findings": [], "hunt": {"stop": "transport_error"}})
    assert _score_system(d, {"c": CASE})["per_case"]["c"] == "detected"


def test_a_finished_hunt_that_clears_the_fix_pairs(tmp_path):
    d = _rec(tmp_path, "c", {"findings": [HIT_LLM], "hunt": {"stop": "finished"}},
             {"findings": [], "hunt": {"stop": "budget"}})
    assert _score_system(d, {"c": CASE})["per_case"]["c"] == "paired"


def test_tiers_are_scored_apart(tmp_path):
    # The engine's candidate fires on both checkouts (it does not see the guard the fix adds);
    # the agent's finding is gone at the fix. Blended this reads "detected"; by tier the agent
    # pairs and the engine only detects.
    d = _rec(tmp_path, "c", {"findings": [HIT_LLM, HIT_SYM], "hunt": {"stop": "finished"}},
             {"findings": [HIT_SYM], "hunt": {"stop": "finished"}})
    cases = {"c": CASE}
    assert _score_system(d, cases)["per_case"]["c"] == "detected"
    assert _score_system(d, cases, "llm")["per_case"]["c"] == "paired"
    assert _score_system(d, cases, "symbolic")["per_case"]["c"] == "detected"


def test_engine_tier_ignores_a_dead_hunt(tmp_path):
    # The engine ran even if the agent did not: its own miss is a miss.
    d = _rec(tmp_path, "c", {"findings": [], "hunt": {"stop": "transport_error"}},
             {"findings": [], "hunt": {"stop": "finished"}})
    assert _score_system(d, {"c": CASE}, "symbolic")["per_case"]["c"] == "miss"


# ---- funnel: where the agent lost a case --------------------------------------------------

from benchmarks.bacbench.score import _funnel_case, funnel, score_cases  # noqa: E402


def _status(map_files, units, stop="finished"):
    return {"stop": stop, "map_files": map_files, "units": units, "profile": "", "taught_packs": 0}


def _unit(files, investigated=True, verdicts=None):
    return {"id": "u", "files": files, "handlers": list((verdicts or {}).keys()),
            "investigated": investigated, "reused": False, "stop": "finished",
            "verdicts": verdicts or {}}


def test_funnel_stages_from_the_hunt_status():
    other = _unit(["app/other.py"], verdicts={"Other.get": "reported"})
    # Never in the map.
    assert _funnel_case(_status(["app/other.py"], [other]), CASE) == {
        "in_map": False, "investigated": False, "verdict_on_gt": "none"}
    # In the map, its unit never investigated (budget ran out before it).
    f = _funnel_case(_status(["app/views.py"], [_unit(["app/views.py"], investigated=False)]), CASE)
    assert f == {"in_map": True, "investigated": False, "verdict_on_gt": "none"}
    # Investigated and judged safe, then reported: the best verdict on a GT unit wins.
    safe = _unit(["app/views.py"], verdicts={"V.get": "safe"})
    assert _funnel_case(_status(["app/views.py"], [safe]), CASE)["verdict_on_gt"] == "safe"
    rep = _unit(["app/views.py"], verdicts={"V.get": "safe", "V.put": "reported"})
    assert _funnel_case(_status(["app/views.py"], [rep]), CASE)["verdict_on_gt"] == "reported"


def test_funnel_is_unknown_for_an_older_status():
    assert _funnel_case({"stop": "finished"}, CASE) == {
        "in_map": None, "investigated": None, "verdict_on_gt": None}


def test_funnel_counts_and_report(tmp_path):
    d = tmp_path / "frame_hunt"
    d.mkdir()
    rep = _unit(["app/views.py"], verdicts={"V.get": "reported"})
    (d / "a.json").write_text(json.dumps({"scans": {
        "vulnerable": {"findings": [HIT_LLM], "hunt": _status(["app/views.py"], [rep])},
        "fixed": {"findings": [], "hunt": _status(["app/views.py"], [rep])}}}))
    (d / "b.json").write_text(json.dumps({"scans": {   # an old record: no map data
        "vulnerable": {"findings": [], "hunt": {"stop": "finished"}},
        "fixed": {"findings": [], "hunt": {"stop": "finished"}}}}))
    fn = funnel(d, {"a": CASE, "b": CASE}, {"a": "paired", "b": "miss"})
    assert (fn["cases_with_map"], fn["in_map"], fn["investigated"], fn["reported_on_gt"],
            fn["detected"], fn["paired"]) == (1, 1, 1, 1, 1, 1)
    assert fn["per_case"]["b"]["in_map"] is None
    report = score_cases({"a": CASE, "b": CASE}, tmp_path)
    assert report["systems"]["frame_hunt"]["funnel"]["paired"] == 1


# ---- run.py: the hunt's options per case --------------------------------------------------

def test_hunt_options_omit_unset_flags_and_share_the_cache_per_case(tmp_path):
    from argparse import Namespace
    from benchmarks.bacbench.run import hunt_options
    unset = Namespace(hunt_max_units=None, hunt_unit_steps=None, hunt_concurrency=None,
                      hunt_verdict_cache=False)
    assert hunt_options(unset, tmp_path, "c1") == {}
    full = Namespace(hunt_max_units=40, hunt_unit_steps=25, hunt_concurrency=6,
                     hunt_verdict_cache=True)
    opts = hunt_options(full, tmp_path, "c1")
    assert opts == {"max_units": 40, "unit_steps": 25, "concurrency": 6,
                    "verdict_cache": str(tmp_path / "frame_hunt" / "cache" / "c1.json")}
    # One file per case, the same for both of its checkouts (the call does not see the checkout).
    assert hunt_options(full, tmp_path, "c2")["verdict_cache"].endswith("c2.json")


# ---- a fixed checkout whose ground-truth unit was not finished is not a pair -----------------

def _hunt(units, stop="partial"):
    return {"stop": stop, "map_files": ["app/views.py"], "units": units}


def _u(stop, files=("app/views.py",)):
    return {"id": "u", "files": list(files), "handlers": ["V.get"], "investigated": stop != "deferred",
            "reused": stop == "reused", "stop": stop, "verdicts": {"V.get": "none"}}


def test_a_deferred_or_cut_off_ground_truth_unit_on_the_fix_blocks_the_pair(tmp_path):
    # The fix added a guard, the unit ranked lower and the budget deferred it: nothing was
    # reported there because nobody looked, not because the fix cleared it.
    for stop in ("deferred", "cancelled", "transport_error"):
        d = _rec(tmp_path, "c", {"findings": [HIT_LLM], "hunt": _hunt([_u("finished")], "finished")},
                 {"findings": [], "hunt": _hunt([_u(stop)])})
        assert _score_system(d, {"c": CASE})["per_case"]["c"] == "detected", stop


def test_a_finished_or_reused_ground_truth_unit_on_the_fix_pairs(tmp_path):
    for stop in ("finished", "budget", "reused"):
        d = _rec(tmp_path, "c", {"findings": [HIT_LLM], "hunt": _hunt([_u("finished")], "finished")},
                 {"findings": [], "hunt": _hunt([_u(stop), _u("deferred", files=("app/other.py",))])})
        # An unfinished unit elsewhere does not matter; only the ground-truth file's units do.
        assert _score_system(d, {"c": CASE})["per_case"]["c"] == "paired", stop


def test_the_engine_tier_pairs_regardless_of_the_agents_units(tmp_path):
    d = _rec(tmp_path, "c", {"findings": [HIT_SYM], "hunt": _hunt([_u("finished")], "finished")},
             {"findings": [], "hunt": _hunt([_u("deferred")])})
    assert _score_system(d, {"c": CASE}, "symbolic")["per_case"]["c"] == "paired"


# ---- run.py: outage damage is rerun, nothing else -------------------------------------------

def test_outage_damage_is_told_apart_from_a_hunt_that_ran_out_of_time():
    from benchmarks.bacbench.run import outage_damaged
    ok = {"findings": [], "hunt": _hunt([_u("finished"), _u("reused")], stop="finished")}
    assert not outage_damaged({"scans": {"vulnerable": ok, "fixed": ok}})
    lost_unit = {"findings": [], "hunt": _hunt([_u("finished"), _u("transport_error")])}
    assert outage_damaged({"scans": {"vulnerable": ok, "fixed": lost_unit}})
    assert outage_damaged({"scans": {"vulnerable": {"hunt": {"stop": "transport_error"}}}})
    assert outage_damaged({"scans": {"fixed": {"error": "LLMUnavailableError: unreachable"}}})
    # the cap fired while units sat out an outage: damage, though no unit says transport_error
    waited = {"error": "timeout", "hunt": dict(_hunt([_u("cancelled")]), outage_waits=12)}
    assert outage_damaged({"scans": {"vulnerable": waited}})
    # ran out of time on its own: rerunning would only repeat it
    slow = {"error": "timeout", "hunt": _hunt([_u("finished"), _u("cancelled")])}
    assert not outage_damaged({"scans": {"vulnerable": slow}})
    assert not outage_damaged({"scans": {"vulnerable": {"findings": []}}})   # frame_symbolic


def _run_main(monkeypatch, tmp_path, argv, results):
    """run.py's main over two prepared cases, with _run_case replaced by `results` (a list of
    records per case id, consumed in order)."""
    import sys

    import benchmarks.bacbench.run as run
    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    cases = [{"id": cid, "language": "python", "checkouts": {}} for cid in ("a", "b")]
    (ws / "prepared.json").write_text(json.dumps({"cases": cases}))
    calls = []

    def fake(args, system, c, outdir, out_root):
        calls.append(c["id"])
        return results[c["id"]].pop(0)
    monkeypatch.setattr(run, "_run_case", fake)
    monkeypatch.setattr(run, "_wait_for_endpoint", lambda limit: True)
    monkeypatch.setattr(sys, "argv", ["run.py", "--workspace", str(ws), "--systems", "frame_hunt",
                                      "--output", str(tmp_path / "out"), *argv])
    assert run.main() == 0
    return calls


DAMAGED = {"scans": {"vulnerable": {"hunt": {"stop": "transport_error"}}}}
CLEAN = {"scans": {"vulnerable": {"findings": [], "hunt": {"stop": "finished"}}}}


def test_retry_outages_reruns_only_the_damaged_cases(monkeypatch, tmp_path):
    calls = _run_main(monkeypatch, tmp_path, ["--retry-outages", "3"],
                      {"a": [CLEAN], "b": [DAMAGED, DAMAGED, CLEAN]})
    assert calls == ["a", "b", "b", "b"]          # b until it came back clean, a once
    out = json.loads((tmp_path / "out" / "frame_hunt" / "b.json").read_text())
    assert out == CLEAN


def test_retries_stop_at_the_limit_and_without_the_flag_nothing_is_rerun(monkeypatch, tmp_path):
    calls = _run_main(monkeypatch, tmp_path, ["--retry-outages", "1"],
                      {"a": [CLEAN], "b": [DAMAGED, DAMAGED, CLEAN]})
    assert calls == ["a", "b", "b"]
    calls = _run_main(monkeypatch, tmp_path / "2", [], {"a": [CLEAN], "b": [DAMAGED]})
    assert calls == ["a", "b"]


def test_resume_skips_a_clean_result_and_reruns_a_damaged_one(monkeypatch, tmp_path):
    out = tmp_path / "out" / "frame_hunt"
    out.mkdir(parents=True)
    (out / "a.json").write_text(json.dumps(CLEAN))
    (out / "b.json").write_text(json.dumps(DAMAGED))
    calls = _run_main(monkeypatch, tmp_path, ["--resume"], {"a": [], "b": [CLEAN]})
    assert calls == ["b"]


def test_a_ground_truth_unit_cut_off_on_the_vulnerable_checkout_is_a_hunt_error(tmp_path):
    # The endpoint killed the unit holding the case's code: finding nothing there is not a miss.
    fixed = {"findings": [], "hunt": _hunt([_u("finished")], stop="finished")}
    d = _rec(tmp_path, "cut", {"findings": [], "hunt": _hunt([_u("transport_error"),
                                                              _u("finished", ("other.py",))])}, fixed)
    assert _score_system(d, {"cut": CASE})["per_case"]["cut"] == "hunt-error"
    # deferred by the unit budget: the hunt chose not to look, a real miss
    d = _rec(tmp_path / "2", "skip", {"findings": [], "hunt": _hunt([_u("deferred")])}, fixed)
    assert _score_system(d, {"skip": CASE})["per_case"]["skip"] == "miss"
    # a unit lost elsewhere in the app does not excuse missing the ground truth
    d = _rec(tmp_path / "3", "else", {"findings": [], "hunt": _hunt(
        [_u("finished"), _u("transport_error", ("other.py",))])}, fixed)
    assert _score_system(d, {"else": CASE})["per_case"]["else"] == "miss"
