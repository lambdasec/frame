#!/usr/bin/env python3
"""Score Frame's VLoc Bench predictions using Cisco's OWN scoring code.

We import `scoring.py` from the pinned benchmark checkout and never modify it,
so File F1, True Negative Rate and the aggregates are computed by the benchmark
authors' implementation. Output is emitted in the leaderboard's
`docs/model-performance.json` entry shape so a submission is a copy-paste.

    python benchmarks/vloc/score.py --workspace /tmp/frame-vloc --results /tmp/vloc-results
"""
import argparse
import csv
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--label", default="Frame (GLM-5.2)")
    ap.add_argument("--output", default="")
    args = ap.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    bench = ws / "vulnerability-localization-benchmark"
    src = bench / "src"
    if not src.is_dir():
        print("run prepare.py first", file=sys.stderr)
        return 1
    sys.path.insert(0, str(src))
    # Cisco's scorer, imported verbatim -- the numbers below are theirs, not ours.
    from vulnerability_localization_benchmark.scoring import (  # noqa: E402
        score_phase_a, score_phase_b, aggregate_scores, filter_ground_truth,
    )

    manifest = ws / "manifest_subset.csv"
    if not manifest.is_file():
        manifest = bench / "data" / "manifest.csv"
    gt = {r["alpha_id"]: r for r in csv.DictReader(manifest.open())}

    results = Path(args.results).expanduser().resolve()
    a_scores, b_scores, per_task = [], [], {}
    for f in sorted(results.glob("*_phase_*.json")):
        pred = json.loads(f.read_text())
        aid, phase = pred["alpha_id"], pred["phase"]
        row = gt.get(aid)
        if row is None:
            continue
        submitted = pred["submitted_files"]
        nothing = pred["submitted_nothing"]
        if phase == "a":
            truth = filter_ground_truth(json.loads(row["ground_truth_files"] or "[]"))
            s = score_phase_a(submitted, truth, nothing)
            a_scores.append(s)
            per_task.setdefault(aid, {})["a"] = {**s, "n_truth": len(truth),
                                                 "n_submitted": len(submitted)}
        else:
            s = score_phase_b(submitted, nothing)
            b_scores.append(s)
            per_task.setdefault(aid, {})["b"] = {**s, "n_submitted": len(submitted)}

    agg_a = aggregate_scores(a_scores, "a") if a_scores else {}
    agg_b = aggregate_scores(b_scores, "b") if b_scores else {}

    prec = sum(s["precision"] for s in a_scores) / len(a_scores) if a_scores else 0.0
    rec = sum(s["recall"] for s in a_scores) / len(a_scores) if a_scores else 0.0

    entry = {
        "model": args.label,
        "size": "—",
        "type": "system",
        "file_f1": agg_a.get("mean_file_f1"),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "true_negative_rate": agg_b.get("true_negative_rate"),
        "false_positive_rate": agg_b.get("false_positive_rate"),
        "submitted_nothing_rate": agg_a.get("abstain_rate"),
    }
    report = {
        "leaderboard_entry": entry,
        "phase_a": agg_a,
        "phase_b": agg_b,
        "n_tasks_scored": len(per_task),
        "methodology_note": (
            "Frame is a static scanner, not a 15-terminal-call agent: it performs an "
            "unbudgeted whole-repository scan. Scores are therefore NOT like-for-like "
            "with the reference agent results on the public leaderboard. Reported for "
            "the sampled task set only unless n_tasks_scored is 500."
        ),
        "per_task": per_task,
    }
    out = Path(args.output) if args.output else results / "scores.json"
    out.write_text(json.dumps(report, indent=2))

    print(f"[score] tasks scored: {len(per_task)}")
    if agg_a:
        print(f"[score] Phase A  File F1 {agg_a['mean_file_f1']:.4f}  "
              f"P {prec:.4f}  R {rec:.4f}  abstain {agg_a['abstain_rate']:.4f}")
    if agg_b:
        print(f"[score] Phase B  TNR {agg_b['true_negative_rate']:.4f}  "
              f"FPR {agg_b['false_positive_rate']:.4f}")
    print(f"[score] reference: GLM-5.2 bare = 0.186 F1 (Phase A only, no TNR published); "
          f"best published = GPT-5.5 xhigh 0.229 F1 / 0.279 TNR")
    print(f"[score] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
