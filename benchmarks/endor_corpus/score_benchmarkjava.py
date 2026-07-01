#!/usr/bin/env python3
"""Score Frame on OWASP BenchmarkJava using its official ground truth.

This is the one repo in the Endor corpus that ships machine-readable,
line/file-level ground truth (expectedresults-1.2.csv), so it is the only place
this harness can honestly compute precision/recall/F1.

Usage:
    # Use findings already produced by run_endor_corpus.py:
    python -m benchmarks.endor_corpus.score_benchmarkjava \
        --repo /tmp/endor-corpus/benchmarkjava \
        --findings /tmp/frame-endor-results/results/benchmarkjava/frame.json \
        --output /tmp/frame-endor-results/benchmarkjava-scorecard

    # Or scan the checkout directly (no prior run needed):
    python -m benchmarks.endor_corpus.score_benchmarkjava \
        --repo /tmp/endor-corpus/benchmarkjava \
        --output /tmp/frame-endor-results/benchmarkjava-scorecard

Reminder: OWASP BenchmarkJava is a synthetic benchmark with its OWN ground truth.
This scorecard is a real, standalone result but is NOT Endor's benchmark and is
NOT comparable to Endor's real-world corpus numbers.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from benchmarks.endor_corpus import owasp_benchmark as OB


def log(msg: str) -> None:
    print(f"[benchmarkjava-score] {msg}", flush=True)


def _git_commit(repo: Path) -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo),
                       check=False, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def _scan_repo(repo: Path) -> List[Dict[str, Any]]:
    """Scan BenchmarkJava's testcode directory with Frame; return normalized findings."""
    from frame.sil import FrameScanner

    testcode = repo / OB.TESTCODE_REL
    files = sorted(testcode.glob("*.java")) if testcode.exists() else \
        sorted(repo.glob("**/*.java"))
    log(f"scanning {len(files)} Java files with Frame (default config) ...")
    scanner = FrameScanner(language="java", verify=True)
    findings: List[Dict[str, Any]] = []
    for i, f in enumerate(files, 1):
        if i % 500 == 0:
            log(f"  {i}/{len(files)}")
        try:
            res = scanner.scan_file(str(f))
        except Exception as exc:  # noqa: BLE001
            log(f"  scanner error on {f.name}: {exc}")
            continue
        rel = str(f.relative_to(repo)) if str(f).startswith(str(repo)) else str(f)
        for v in res.vulnerabilities:
            findings.append({"path": rel, "cwe": v.cwe_id,
                             "severity": v.severity.value, "line": v.line})
    return findings


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="score_benchmarkjava",
        description="Score Frame on OWASP BenchmarkJava (real ground truth).")
    p.add_argument("--repo", required=True, type=Path,
                   help="Path to an OWASP BenchmarkJava checkout.")
    p.add_argument("--findings", type=Path, default=None,
                   help="Optional frame.json from run_endor_corpus.py. If omitted, "
                        "the repo is scanned directly.")
    p.add_argument("--output", required=True, type=Path,
                   help="Directory to write the scorecard artifacts.")
    args = p.parse_args(argv)

    if not args.repo.exists():
        log(f"ERROR: repo not found: {args.repo}")
        return 2

    try:
        expected = OB.load_expected_results(args.repo)
    except FileNotFoundError as exc:
        log(f"ERROR: {exc}")
        return 2
    log(f"loaded {len(expected)} labeled test cases "
        f"({sum(e['is_real'] for e in expected)} real, "
        f"{sum(not e['is_real'] for e in expected)} safe traps)")

    if args.findings:
        if not args.findings.exists():
            log(f"ERROR: findings file not found: {args.findings}")
            return 2
        findings = json.loads(args.findings.read_text(encoding="utf-8"))
        log(f"loaded {len(findings)} Frame findings from {args.findings}")
    else:
        findings = _scan_repo(args.repo)
        log(f"Frame produced {len(findings)} findings")

    commit = _git_commit(args.repo)
    scorecard = OB.score(findings, expected)

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "scorecard.json").write_text(
        json.dumps({"commit": commit, **scorecard}, indent=2), encoding="utf-8")
    (args.output / "scorecard.md").write_text(
        OB.render_scorecard_md(scorecard, commit), encoding="utf-8")
    # Also emit the real ground-truth file (positive labels) in harness schema.
    gt = OB.to_ground_truth_json(expected, commit)
    (args.output / "ground_truth.benchmarkjava.json").write_text(
        json.dumps(gt, indent=2), encoding="utf-8")

    ov = scorecard["overall"]
    log(f"OVERALL: TP={ov['tp']} FP={ov['fp']} TN={ov['tn']} FN={ov['fn']} "
        f"precision={ov['precision']} recall={ov['tpr_recall']} f1={ov['f1']} "
        f"youden={ov['youden_score']}")
    log(f"wrote scorecard to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
