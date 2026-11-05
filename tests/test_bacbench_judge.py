"""BAC-Bench adjudication (benchmarks/bacbench/judge.py), stubbed transport.

The benchmark credits a finding in two stages: a deterministic location gate (an implicated file,
or an affected route in the claim) and an LLM judge that reads the claim against the advisory's
invariant and violation, blind to the tool. These pin the gate, the cap and ranking, the strict
reply parsing (a malformed reply is a judge error, never a miss), batching (one call per
checkout), the on-disk cache (re-scoring never re-bills) and the paired logic under the judge."""

import json

from benchmarks.bacbench.judge import (Judge, build_messages, candidates, location_gate,
                                       parse_verdicts)
from benchmarks.bacbench.score import _judge_system

CASE = {
    "id": "c",
    "invariant": "File access must be scoped to the requesting user.",
    "violation": "The shared-chat branch grants access without checking the caller.",
    "match_criteria": "Matches if it identifies cross-user file access via file_id.",
    "affected_routes": ["GET /api/v1/files/{id}"],
    "sink_files": ["backend/access/files.py"],
    "root_files": ["backend/access/files.py"],
    "root_symbols": ["has_access_to_file"],
    "expected_cwes": ["CWE-639"],
    "sink_locations": [{"file": "backend/access/files.py", "line_start": 68, "line_end": 72}],
}


def _f(file, line, cwe="CWE-639", tier="llm", desc="unscoped file access"):
    return {"file": file, "line": line, "cwe": cwe, "type": "idor", "tier": tier,
            "source_var": "llm_verified" if tier == "llm" else "user_input", "description": desc}


class _Client:
    """Scripted chat_raw: returns the queued replies in order, records each call."""
    def __init__(self, *replies):
        self.replies = list(replies)
        self.seen = []

    def chat_raw(self, messages, tools=None):
        self.seen.append(messages)
        r = self.replies.pop(0) if self.replies else None
        return None if r is None else {"content": r}


def _reply(*matches):
    return json.dumps({"verdicts": [{"index": i, "match": m, "rationale": "r"}
                                    for i, m in enumerate(matches)]})


def test_location_gate_keeps_implicated_files_and_route_claims():
    assert location_gate(_f("backend/access/files.py", 500), CASE)
    assert not location_gate(_f("backend/other.py", 70), CASE)
    # A finding elsewhere whose claim names the affected route passes the gate (route match).
    assert location_gate(_f("backend/routers/files.py", 10,
                            desc="GET /api/v1/files/{id} returns any user's file"), CASE)


def test_candidates_are_ranked_by_sink_distance_then_class_and_capped():
    fs = [_f("backend/access/files.py", 300, cwe="CWE-79"),     # far, not access control
          _f("backend/other.py", 70),                           # gated out
          _f("backend/access/files.py", 70),                    # inside the sink range
          _f("backend/access/files.py", 300)]                   # far, access control
    got = [i for i, _ in candidates(fs, CASE)]
    assert got == [2, 3, 0]
    assert [i for i, _ in candidates(fs, CASE, cap=1)] == [2]


def test_the_judge_is_blind_to_the_tool():
    msgs = build_messages(CASE, candidates([_f("backend/access/files.py", 70,
                                                desc="[LLM-verified] any user's file by id")], CASE))
    user = msgs[1]["content"]
    assert "LLM-verified" not in user and "llm_verified" not in user and '"tier"' not in user
    assert "any user's file by id" in user
    assert CASE["invariant"] in user and CASE["violation"] in user


def test_parse_verdicts_is_strict():
    assert parse_verdicts(_reply(True, False), 2) == {0: (True, "r"), 1: (False, "r")}
    assert parse_verdicts("<think>hmm {</think>" + _reply(True), 1) == {0: (True, "r")}
    assert parse_verdicts("I think finding 0 matches.", 1) is None
    assert parse_verdicts('{"verdicts": [{"index": 0, "match": "yes"}]}', 1) is None
    assert parse_verdicts('{"answer": 1}', 1) is None
    # An index the reply omits is not a match; an out-of-range index is ignored.
    assert parse_verdicts('{"verdicts": [{"index": 7, "match": true}]}', 2) == {0: (False, ""), 1: (False, "")}


def test_one_call_per_checkout_and_matches_map_back_to_findings():
    fs = [_f("backend/other.py", 1), _f("backend/access/files.py", 300), _f("backend/access/files.py", 70)]
    c = _Client(_reply(True, False))          # candidate 0 = finding 2 (in range), 1 = finding 1
    out = Judge(c).judge("frame_hunt", "c", "vulnerable", fs, CASE)
    assert len(c.seen) == 1
    assert out["status"] == "ok" and out["matched"] == [2]


def test_no_candidates_means_no_call():
    c = _Client()
    out = Judge(c).judge("s", "c", "vulnerable", [_f("elsewhere.py", 1)], CASE)
    assert out == {"status": "no-candidates", "matched": [], "rationale": {}} and not c.seen


def test_transport_failure_and_malformed_reply_are_judge_errors(tmp_path):
    fs = [_f("backend/access/files.py", 70)]
    assert Judge(_Client(None)).judge("s", "c", "vulnerable", fs, CASE)["status"] == "judge-error"
    assert Judge(_Client("not json")).judge("s", "c", "vulnerable", fs, CASE)["status"] == "judge-error"
    # An error is never cached: the next scoring asks again.
    cache = tmp_path / "judge_cache.json"
    Judge(_Client(None), cache).judge("s", "c", "vulnerable", fs, CASE)
    assert not cache.exists()


def test_cached_verdicts_are_reused_without_a_call(tmp_path):
    cache = tmp_path / "judge_cache.json"
    fs = [_f("backend/access/files.py", 70)]
    first = Judge(_Client(_reply(True)), cache, model="m").judge("s", "c", "vulnerable", fs, CASE)
    again = _Client()
    second = Judge(again, cache, model="m").judge("s", "c", "vulnerable", fs, CASE)
    assert first["matched"] == second["matched"] == [0] and not again.seen
    # A different judge model is a different verdict: it asks.
    other = _Client(_reply(False))
    assert Judge(other, cache, model="m2").judge("s", "c", "vulnerable", fs, CASE)["matched"] == []
    assert len(other.seen) == 1


class _StubJudge:
    """Judge stand-in for the score layer: per checkout, a fixed result."""
    def __init__(self, results):
        self.results = results

    def judge(self, system, case_id, checkout, findings, case):
        return self.results[checkout]


def _rec(tmp_path, vulnerable, fixed):
    d = tmp_path / "frame_hunt"
    d.mkdir(exist_ok=True)
    (d / "c.json").write_text(json.dumps({"scans": {"vulnerable": vulnerable, "fixed": fixed}}))
    return d


def _ok(*matched):
    return {"status": "ok", "matched": list(matched), "rationale": {}}


def test_judged_pair_needs_a_clean_fixed_commit(tmp_path):
    hits = {"findings": [_f("backend/access/files.py", 70)], "hunt": {"stop": "finished"}}
    d = _rec(tmp_path, hits, hits)
    assert _judge_system(d, {"c": CASE}, _StubJudge({"vulnerable": _ok(0), "fixed": _ok()}))["all"]["per_case"]["c"] == "paired"
    assert _judge_system(d, {"c": CASE}, _StubJudge({"vulnerable": _ok(0), "fixed": _ok(0)}))["all"]["per_case"]["c"] == "detected"


def test_judge_errors_are_not_misses_and_block_a_pair(tmp_path):
    hits = {"findings": [_f("backend/access/files.py", 70)], "hunt": {"stop": "finished"}}
    d = _rec(tmp_path, hits, hits)
    err = {"status": "judge-error", "matched": [], "rationale": {}}
    s = _judge_system(d, {"c": CASE}, _StubJudge({"vulnerable": err, "fixed": _ok()}))["all"]
    assert s["per_case"]["c"] == "judge-error" and s["judge_errors"] == 1
    s = _judge_system(d, {"c": CASE}, _StubJudge({"vulnerable": _ok(0), "fixed": err}))["all"]
    assert s["per_case"]["c"] == "detected"


def test_judged_tiers_and_dead_hunts(tmp_path):
    both = [_f("backend/access/files.py", 70, tier="llm"), _f("backend/access/files.py", 71, tier="symbolic")]
    d = _rec(tmp_path, {"findings": both, "hunt": {"stop": "finished"}},
             {"findings": [both[1]], "hunt": {"stop": "finished"}})
    # Fixed checkout: only the engine's finding persists (index 0 there) and is judged a match,
    # so the agent tier pairs while the engine tier stays detect-only; blended it is detected.
    j = _judge_system(d, {"c": CASE}, _StubJudge({"vulnerable": _ok(0, 1), "fixed": _ok(0)}),
                      (None, "llm", "symbolic"))
    assert j["llm"]["per_case"]["c"] == "paired"
    assert j["symbolic"]["per_case"]["c"] == "detected"
    assert j["all"]["per_case"]["c"] == "detected"
    dead = _rec(tmp_path, {"findings": [], "hunt": {"stop": "transport_error"}},
                {"findings": [], "hunt": {"stop": "finished"}})
    j = _judge_system(dead, {"c": CASE}, _StubJudge({"vulnerable": _ok(), "fixed": _ok()}),
                      (None, "llm", "symbolic"))
    assert j["all"]["per_case"]["c"] == "hunt-error" and j["symbolic"]["per_case"]["c"] == "miss"
