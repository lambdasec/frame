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
"""

import argparse
import json
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from match import case_detected  # noqa: E402


def _cases(workspace: Path) -> dict:
    manifest = yaml.safe_load((HERE / "manifest.yaml").read_text())
    ds = workspace / "_dataset" / manifest["dataset"]["records"]
    out = {}
    for line in ds.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            out[r["id"]] = r
    return out


def score(workspace: Path, results: Path) -> dict:
    cases = _cases(workspace)
    report = {"n_cases": len(cases), "systems": {}}
    for sysdir in sorted(p for p in results.iterdir() if p.is_dir()):
        detected = paired = 0
        per_case = {}
        for cid, case in cases.items():
            rec_path = sysdir / f"{cid}.json"
            if not rec_path.is_file():
                per_case[cid] = "not-run"
                continue
            rec = json.loads(rec_path.read_text())
            vuln = (rec.get("scans", {}).get("vulnerable") or {}).get("findings")
            fixed = (rec.get("scans", {}).get("fixed") or {}).get("findings")
            hit_v = vuln is not None and case_detected(vuln, case) is not None
            hit_f = fixed is not None and case_detected(fixed, case) is not None
            if hit_v:
                detected += 1
                if fixed is not None and not hit_f:
                    paired += 1
                    per_case[cid] = "paired"
                else:
                    per_case[cid] = "detected"
            else:
                per_case[cid] = "miss"
        report["systems"][sysdir.name] = {
            "detected": detected, "paired": paired, "n": len(cases),
            "recall": round(detected / len(cases), 3) if cases else 0.0,
            "per_case": per_case}
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--results", default=str(HERE / "results" / "v1"))
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = ap.parse_args()
    report = score(Path(args.workspace).expanduser().resolve(), Path(args.results))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"BAC-Bench: {report['n_cases']} cases")
        for name, s in report["systems"].items():
            print(f"  {name:16s} detected {s['detected']}/{s['n']}  "
                  f"paired {s['paired']}/{s['n']}  recall {s['recall']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
