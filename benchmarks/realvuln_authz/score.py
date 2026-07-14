#!/usr/bin/env python3
"""Score RealVuln authz runs against the frozen manifest.

Curated view: the 8 labelled IDOR/BOLA cases + 2 explicit safe controls.
  positive case  -> true positive if any finding matches (repo + file + line +-10 + acceptable CWE).
  safe control   -> false positive if a finding flags its file/line range with an authz CWE.
Reports per-case detection across runs, majority-vote aggregate, and precision/recall/F1/F2.

  python benchmarks/realvuln_authz/score.py --manifest .../manifest.yaml --results .../results/v1
"""

import argparse
import json
from pathlib import Path

import yaml

_AUTHZ_CWES = {"CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-915", "CWE-306"}


def _norm_cwe(c):
    c = str(c).upper().strip()
    return c if c.startswith("CWE-") else (f"CWE-{c}" if c.isdigit() else c)


def _same_file(a, b):
    a, b = str(a).replace("\\", "/"), str(b).replace("\\", "/")
    return a == b or a.endswith("/" + b) or b.endswith("/" + a) or Path(a).name == Path(b).name


def _matches(finding, case, window=10):
    if not _same_file(finding.get("file", ""), case["file"]):
        return False
    fl = int(finding.get("start_line", 0) or 0)
    if not (case["start_line"] - window <= fl <= case["end_line"] + window):
        return False
    fc = _norm_cwe(finding.get("cwe", ""))
    return fc in {_norm_cwe(c) for c in case["acceptable_cwes"]}


def _load_runs(results: Path, system: str, repo: str):
    d = results / system / repo
    if not d.is_dir():
        return []
    return [json.loads(p.read_text()) for p in sorted(d.glob("run-*.json"))]


def score(manifest_path: Path, results: Path):
    manifest = yaml.safe_load(manifest_path.read_text())
    cases = [(r["slug"], c) for r in manifest["repositories"] for c in r["cases"]]
    systems = sorted({p.name for p in results.iterdir() if p.is_dir()})

    report = {"version": manifest["version"], "systems": {}}
    for system in systems:
        per_case = {}       # case_id -> {"detected_runs": k, "n_runs": N, "expected": ...}
        for slug, case in cases:
            runs = _load_runs(results, system, slug)
            n = len(runs)
            det = sum(1 for run in runs
                      if any(_matches(f, case) for f in run.get("normalized_findings", [])))
            per_case[case["id"]] = {
                "repository": slug, "expected": case["expected"], "class": case["class"],
                "operation": case["operation"], "n_runs": n, "detected_runs": det,
                "majority": (det * 2 > n) if n else False,
            }

        pos = [c for c in per_case.values() if c["expected"] == "vulnerable"]
        safe = [c for c in per_case.values() if c["expected"] == "safe"]
        tp = sum(1 for c in pos if c["majority"])
        fn = len(pos) - tp
        safe_failed = sum(1 for c in safe if c["majority"])   # flagged a safe control
        safe_passed = len(safe) - safe_failed
        fp = safe_failed
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        f2 = 5 * precision * recall / (4 * precision + recall) if (4 * precision + recall) else 0.0
        stability = {k: sum(1 for c in per_case.values()
                            if c["n_runs"] and c["detected_runs"] == round(k * c["n_runs"] / 3))
                     for k in (0, 1, 2, 3)}
        report["systems"][system] = {
            "true_positives": tp, "false_negatives": fn,
            "safe_controls_passed": safe_passed, "safe_controls_failed": safe_failed,
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3), "f2": round(f2, 3),
            "per_case": per_case,
        }
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=str(Path(__file__).resolve().parent / "manifest.yaml"))
    ap.add_argument("--results", required=True)
    args = ap.parse_args()
    results = Path(args.results)
    rep = score(Path(args.manifest), results)
    (results / "scores.json").write_text(json.dumps(rep, indent=2))
    print(f"[score] wrote {results/'scores.json'}")
    for system, s in rep["systems"].items():
        print(f"  {system:22s} TP={s['true_positives']}/8  safe-passed={s['safe_controls_passed']}/2  "
              f"P={s['precision']} R={s['recall']} F1={s['f1']}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
