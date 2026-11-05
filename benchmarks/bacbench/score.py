#!/usr/bin/env python3
"""Score Frame's BAC-Bench runs: recall on the vulnerable commit and a paired
patched-commit differential.

  detected (vulnerable) : a finding matches the advisory (match.finding_matches_case).
  paired                : detected AND no match at the fixed commit (the fix cleared it).

Positive-only: findings elsewhere in an application are not counted as false positives
(the dataset does not label every route). Reads the case metadata from the pinned dataset
clone in the workspace, and the run records from --results.

  python benchmarks/bacbench/score.py --workspace /tmp/frame-bacbench \\
      --results benchmarks/bacbench/results/v1

`--judge` adds the benchmark's own adjudication (judge.py: location gate + LLM judge over the
advisory's invariant and violation) beside the deterministic matcher, which stays the default.
For frame_hunt runs whose hunt recorded its route map and units, a FUNNEL per case says where
the agent lost a case: not in the map, in the map but never investigated, investigated but
judged safe, or reported.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from match import _same_file, case_detected, regions_holding  # noqa: E402


def _cases(workspace: Path) -> dict:
    manifest = yaml.safe_load((HERE / "manifest.yaml").read_text())
    ds = workspace / "_dataset" / manifest["dataset"]["records"]
    out = {}
    for line in ds.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            out[r["id"]] = r
    return out


# A hunt that ended without the model doing its work. Its empty finding list is not evidence:
# on the vulnerable checkout it is not a miss, and on the fixed checkout it is not a pair.
DEAD_HUNT = {"transport_error", "exception", "no_endpoint", "not_run"}


def _hunt_dead(scan: dict) -> bool:
    return str((scan.get("hunt") or {}).get("stop", "")) in DEAD_HUNT


_DONE_UNIT = {"finished", "budget", "reused"}


def _fixed_unproven(fscan: dict, case: dict) -> bool:
    """On the fixed checkout, a unit covering a ground-truth file that the agent did not finish
    (deferred by the unit budget, cancelled, cut off by the endpoint): nothing reported there is
    not evidence the fix cleared it. A fix that adds a guard makes that unit look safer, so it can
    rank lower and be deferred -- exactly the run that would otherwise score a free pair. Records
    without unit data (older runs) are not judged by this."""
    units = (fscan.get("hunt") or {}).get("units")
    if not units:
        return False
    gt = list(case.get("sink_files") or []) + list(case.get("root_files") or [])
    return any(u.get("stop") not in _DONE_UNIT
               for u in units if any(_same_file(f, g) for f in u.get("files") or [] for g in gt))


def _gt_unit_lost(vscan: dict, case: dict) -> bool:
    """On the vulnerable checkout, a unit covering a ground-truth file that the endpoint cut
    off (`transport_error`, `exception`): the agent never judged the code the case is about, so
    finding nothing there is a hunt error, not a miss. A unit deferred by the unit budget is a
    real miss (the hunt chose not to look), so it does not count here."""
    units = (vscan.get("hunt") or {}).get("units")
    if not units:
        return False
    gt = list(case.get("sink_files") or []) + list(case.get("root_files") or [])
    return any(u.get("stop") in ("transport_error", "exception")
               for u in units if any(_same_file(f, g) for f in u.get("files") or [] for g in gt))


def _pair_regions(vuln, case: dict, regs: dict) -> list:
    """The fixed checkout's regions that can block a pair: the functions where the vulnerable
    checkout's own matching findings sit (same name, looked up on the fixed checkout). A finding
    the fixed checkout has in some OTHER region of the case (a caller, a callee) is a different
    claim: on the fixed checkouts of h1-h3, every such finding was another bug in nearby code
    (a folder check next to the fixed flow check, an assistant lookup next to the fixed thread
    check). The +-40-line window still applies to every finding."""
    held = regions_holding(vuln or [], case, regs.get("vulnerable"))
    return [r for r in regs.get("fixed") or [] if (r.get("file", ""), r.get("name")) in held]


def _tiered(findings, tier):
    if findings is None or tier is None:
        return findings
    return [f for f in findings if f.get("tier") == tier]


def _score_system(sysdir: Path, cases: dict, tier=None) -> dict:
    """One system's tally, over every finding (`tier` None) or one tier's ("llm" = the hunt
    agent, "symbolic" = the engine). A frame_hunt run carries both tiers, so the blended tally
    alone cannot say which one found a case."""
    detected = paired = 0
    per_case = {}
    for cid, case in cases.items():
        rec_path = sysdir / f"{cid}.json"
        if not rec_path.is_file():
            per_case[cid] = "not-run"
            continue
        rec = json.loads(rec_path.read_text())
        vscan = rec.get("scans", {}).get("vulnerable") or {}
        fscan = rec.get("scans", {}).get("fixed") or {}
        if vscan.get("error") == "timeout":
            per_case[cid] = "timeout"       # could not finish scanning in the cap; not a miss
            continue
        agent_counts = tier in (None, "llm")
        vuln = _tiered(vscan.get("findings"), tier)
        fixed = _tiered(fscan.get("findings"), tier)
        regs = case.get("_regions") or {}
        hit_v = vuln is not None and case_detected(vuln, case, regs.get("vulnerable")) is not None
        hit_f = fixed is not None and case_detected(fixed, case, _pair_regions(vuln, case, regs)) is not None
        if hit_v:
            detected += 1
            if fixed is not None and not hit_f and not (
                    agent_counts and (_hunt_dead(fscan) or _fixed_unproven(fscan, case))):
                paired += 1
                per_case[cid] = "paired"
            else:
                per_case[cid] = "detected"
        elif agent_counts and (_hunt_dead(vscan) or _gt_unit_lost(vscan, case)):
            per_case[cid] = "hunt-error"    # the agent never ran: not evidence of a miss
        else:
            per_case[cid] = "miss"
    return {"detected": detected, "paired": paired, "n": len(cases),
            "recall": round(detected / len(cases), 3) if cases else 0.0,
            "hunt_errors": sum(1 for v in per_case.values() if v == "hunt-error"),
            "per_case": per_case}


def _judge_system(sysdir: Path, cases: dict, judge, tiers=(None,)) -> dict:
    """The judged tally per tier label ("all" for None). Each checkout is judged once over all
    its findings; a tier's view keeps the matches whose finding is that tier's (the judge rules
    on each finding independently). Same dead-hunt rules as the deterministic tally; a judge
    failure on the vulnerable checkout is `judge-error`, never a miss, and on the fixed checkout
    it blocks the pair (the fix was not shown to clear the finding)."""
    out = {}
    tallies = {t: {"detected": 0, "paired": 0, "per_case": {}} for t in tiers}
    for cid, case in cases.items():
        rec_path = sysdir / f"{cid}.json"
        if not rec_path.is_file():
            for t in tiers:
                tallies[t]["per_case"][cid] = "not-run"
            continue
        rec = json.loads(rec_path.read_text())
        vscan = rec.get("scans", {}).get("vulnerable") or {}
        fscan = rec.get("scans", {}).get("fixed") or {}
        if vscan.get("error") == "timeout":
            for t in tiers:
                tallies[t]["per_case"][cid] = "timeout"
            continue
        vf, ff = vscan.get("findings"), fscan.get("findings")
        jv = judge.judge(sysdir.name, cid, "vulnerable", vf, case) if vf is not None else None
        jf = judge.judge(sysdir.name, cid, "fixed", ff, case) if ff is not None else None
        for t in tiers:
            tal = tallies[t]
            agent_counts = t in (None, "llm")
            if jv is not None and jv["status"] == "judge-error":
                tal["per_case"][cid] = "judge-error"
                continue
            hit_v = jv is not None and any(t is None or vf[i].get("tier") == t for i in jv["matched"])
            fixed_ok = jf is not None and jf["status"] != "judge-error"
            hit_f = fixed_ok and any(t is None or ff[i].get("tier") == t for i in jf["matched"])
            if hit_v:
                tal["detected"] += 1
                if fixed_ok and not hit_f and not (
                        agent_counts and (_hunt_dead(fscan) or _fixed_unproven(fscan, case))):
                    tal["paired"] += 1
                    tal["per_case"][cid] = "paired"
                else:
                    tal["per_case"][cid] = "detected"
            elif agent_counts and (_hunt_dead(vscan) or _gt_unit_lost(vscan, case)):
                tal["per_case"][cid] = "hunt-error"
            else:
                tal["per_case"][cid] = "miss"
    for t, tal in tallies.items():
        pc = tal["per_case"]
        out["all" if t is None else t] = {
            "detected": tal["detected"], "paired": tal["paired"], "n": len(cases),
            "judge_errors": sum(1 for v in pc.values() if v == "judge-error"),
            "hunt_errors": sum(1 for v in pc.values() if v == "hunt-error"),
            "per_case": pc}
    return out


# An unresolved verdict ranks above "safe": it puts the case in front of a person.
_VERDICT_RANK = {"reported": 3, "unresolved": 2, "safe": 1, "none": 0}


def _funnel_case(status: dict, case: dict) -> dict:
    """Where the hunt agent stood on this case's code, from the vulnerable checkout's hunt
    status. None for a stage the status does not record (an older run)."""
    gt = list(case.get("sink_files") or []) + list(case.get("root_files") or [])

    def is_gt(path) -> bool:
        return any(_same_file(path, g) for g in gt)
    map_files = status.get("map_files")
    units = status.get("units")
    f: Dict[str, Any] = {"in_map": None, "investigated": None, "verdict_on_gt": None}
    if isinstance(map_files, list):
        f["in_map"] = any(is_gt(m) for m in map_files)
    if isinstance(units, list):
        gt_units = [u for u in units if isinstance(u, dict)
                    and any(is_gt(p) for p in (u.get("files") or []))]
        f["investigated"] = any(u.get("investigated") for u in gt_units)
        best = "none"
        for u in gt_units:
            for v in (u.get("verdicts") or {}).values():
                if _VERDICT_RANK.get(v, 0) > _VERDICT_RANK[best]:
                    best = v
        f["verdict_on_gt"] = best
    return f


def funnel(sysdir: Path, cases: dict, agent_per_case: dict) -> dict:
    """Per-case funnel for a frame_hunt run plus counts. `agent_per_case` is the agent tier's
    deterministic per-case verdict (detected / paired)."""
    per_case = {}
    for cid, case in cases.items():
        rec_path = sysdir / f"{cid}.json"
        if not rec_path.is_file():
            continue
        rec = json.loads(rec_path.read_text())
        status = ((rec.get("scans", {}).get("vulnerable") or {}).get("hunt")) or {}
        f = _funnel_case(status, case)
        verdict = agent_per_case.get(cid)
        f["detected"] = verdict in ("detected", "paired")
        f["paired"] = verdict == "paired"
        per_case[cid] = f
    known = [f for f in per_case.values() if f["in_map"] is not None]
    return {"cases_with_map": len(known),
            "in_map": sum(1 for f in known if f["in_map"]),
            "investigated": sum(1 for f in per_case.values() if f["investigated"]),
            "reported_on_gt": sum(1 for f in per_case.values() if f["verdict_on_gt"] == "reported"),
            "safe_on_gt": sum(1 for f in per_case.values() if f["verdict_on_gt"] == "safe"),
            "unresolved_on_gt": sum(1 for f in per_case.values()
                                    if f["verdict_on_gt"] == "unresolved"),
            "detected": sum(1 for f in per_case.values() if f["detected"]),
            "paired": sum(1 for f in per_case.values() if f["paired"]),
            "per_case": per_case}


def score(workspace: Path, results: Path, judge=None, regions: bool = True) -> dict:
    cases = _cases(workspace)
    if regions:
        attach_regions(cases, workspace)
    return score_cases(cases, results, judge)


def attach_regions(cases: dict, workspace: Path) -> None:
    """Give each case its code regions per checkout (regions.py), from the prepared checkouts,
    cached in <workspace>/gt_regions.json (they depend only on the dataset and the checkouts)."""
    from regions import VERSION, case_regions
    prepared = workspace / "prepared.json"
    if not prepared.is_file():
        return
    checkouts = {c["id"]: c.get("checkouts") or {} for c in json.loads(prepared.read_text())["cases"]}
    cache_path = workspace / "gt_regions.json"
    try:
        cache = json.loads(cache_path.read_text())
    except (OSError, ValueError):
        cache = {}
    if cache.get("version") != VERSION:
        cache = {"version": VERSION, "cases": {}}
    changed = False
    for cid, case in cases.items():
        if cid not in cache["cases"] and cid in checkouts:
            cache["cases"][cid] = case_regions(case, checkouts[cid])
            changed = True
        case["_regions"] = cache["cases"].get(cid) or {}
    if changed:
        cache_path.write_text(json.dumps(cache))


def score_cases(cases: dict, results: Path, judge=None) -> dict:
    report = {"n_cases": len(cases), "systems": {}}
    for sysdir in sorted(p for p in results.iterdir() if p.is_dir()):
        s = _score_system(sysdir, cases)
        hunt = sysdir.name == "frame_hunt"
        if hunt:
            s["by_tier"] = {t: _score_system(sysdir, cases, t) for t in ("llm", "symbolic")}
            s["funnel"] = funnel(sysdir, cases, s["by_tier"]["llm"]["per_case"])
        if judge is not None:
            j = _judge_system(sysdir, cases, judge, (None, "llm", "symbolic") if hunt else (None,))
            s["judged"] = j.pop("all")
            if hunt:
                s["judged"]["by_tier"] = j
        report["systems"][sysdir.name] = s
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--results", default=str(HERE / "results" / "v1"))
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    ap.add_argument("--window-only", action="store_true",
                    help="match by the recorded line ranges +-40 lines only, without the code regions "
                         "(the function holding a range, its same-file callers, its unique callees)")
    ap.add_argument("--judge", action="store_true",
                    help="also score with the benchmark's adjudication (location gate + LLM judge, "
                         "judge.py); verdicts are cached in <results>/judge_cache.json")
    ap.add_argument("--judge-model", default="", help="judge model (default: FRAME_LLM_MODEL)")
    ap.add_argument("--judge-base-url", default="", help="judge endpoint (default: FRAME_LLM_BASE_URL)")
    ap.add_argument("--judge-key-env", default="FRAME_LLM_API_KEY",
                    help="NAME of the environment variable holding the judge's API key")
    args = ap.parse_args()
    results = Path(args.results)
    judge = None
    if args.judge:
        from judge import Judge, judge_config
        from frame.sil.llm_client import LLMClient
        cfg = judge_config(args.judge_model or None, args.judge_base_url or None, args.judge_key_env)
        if not cfg.enabled:
            print("score: --judge needs a judge endpoint and model (FRAME_LLM_* or --judge-*)",
                  file=sys.stderr)
            return 2
        judge = Judge(LLMClient(cfg), results / "judge_cache.json", model=cfg.model)
    report = score(Path(args.workspace).expanduser().resolve(), results, judge,
                   regions=not args.window_only)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"BAC-Bench: {report['n_cases']} cases")
        for name, s in report["systems"].items():
            err = f"  hunt-errors {s['hunt_errors']}" if s.get("hunt_errors") else ""
            print(f"  {name:16s} detected {s['detected']}/{s['n']}  "
                  f"paired {s['paired']}/{s['n']}  recall {s['recall']}{err}")
            for t, ts in (s.get("by_tier") or {}).items():
                print(f"    {t:14s} detected {ts['detected']}/{ts['n']}  paired {ts['paired']}/{ts['n']}")
            j = s.get("judged")
            if j:
                je = f"  judge-errors {j['judge_errors']}" if j.get("judge_errors") else ""
                print(f"  {'(judged)':16s} detected {j['detected']}/{j['n']}  "
                      f"paired {j['paired']}/{j['n']}{je}")
                for t, ts in (j.get("by_tier") or {}).items():
                    print(f"    {t:14s} detected {ts['detected']}/{ts['n']}  paired {ts['paired']}/{ts['n']}")
            fn = s.get("funnel")
            if fn and fn["cases_with_map"]:
                print(f"    funnel (agent, {fn['cases_with_map']} cases with a map): "
                      f"in map {fn['in_map']}  investigated {fn['investigated']}  "
                      f"reported {fn['reported_on_gt']}  judged safe {fn['safe_on_gt']}  "
                      f"unresolved {fn.get('unresolved_on_gt', 0)}  "
                      f"detected {fn['detected']}  paired {fn['paired']}")
        if judge is not None:
            print(f"  judge calls this run: {judge.calls} (model {judge.model})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
