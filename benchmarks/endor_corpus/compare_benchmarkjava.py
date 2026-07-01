#!/usr/bin/env python3
"""Compare Frame vs Semgrep on OWASP BenchmarkJava (same benchmark, same labels).

This is the *fair* comparison the README calls for: both tools scored against the
identical BenchmarkJava ground truth (expectedresults-1.2.csv) with the identical
OWASP methodology. Unlike Endor's published Semgrep numbers (which are on Endor's
real-world corpus), this puts Frame and Semgrep on exactly the same footing.

Usage:
    python -m benchmarks.endor_corpus.compare_benchmarkjava \
        --repo /path/to/benchmarkjava \
        --frame-findings  results/benchmarkjava/frame.json \
        --semgrep-json    semgrep_default.json \
        --semgrep-ruleset p/default \
        --output out/compare

Both input files must already exist (produce frame.json with run_endor_corpus.py
and semgrep JSON with `semgrep --config <ruleset> --json -o <file> <testcode>`).
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
    print(f"[compare-benchmarkjava] {msg}", flush=True)


def _git_commit(repo: Path) -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo),
                       check=False, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def _row(name: str, ov: Dict[str, Any]) -> str:
    return (f"| {name} | {ov['tp']} | {ov['fp']} | {ov['tn']} | {ov['fn']} | "
            f"{ov['precision']} | {ov['tpr_recall']} | {ov['fpr']} | {ov['f1']} | "
            f"{ov['youden_score']} |")


def render_comparison_md(frame_sc: Dict[str, Any], semgrep_sc: Dict[str, Any],
                         commit: str, semgrep_ruleset: str) -> str:
    L: List[str] = []
    L.append("# Frame vs Semgrep — OWASP BenchmarkJava (same benchmark, same labels)")
    L.append("")
    L.append(f"- Benchmark: **OWASP BenchmarkJava** v1.2, commit `{commit[:12]}`")
    L.append(f"- Ground truth: `expectedresults-1.2.csv` "
             f"({frame_sc['total_test_cases']} labeled test cases)")
    L.append(f"- Semgrep ruleset: `{semgrep_ruleset}`")
    L.append(f"- Frame: default config")
    L.append("")
    L.append("Both tools scored with the identical official OWASP Benchmark "
             "methodology (per-file, CWE-matched, TPR − FPR = Youden score).")
    L.append("")
    L.append("## Overall")
    L.append("")
    L.append("| Tool | TP | FP | TN | FN | Precision | Recall | FPR | F1 | Youden |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    L.append(_row("**Frame**", frame_sc["overall"]))
    L.append(_row(f"Semgrep (`{semgrep_ruleset}`)", semgrep_sc["overall"]))
    L.append("")
    L.append("## By category (Youden score = TPR − FPR)")
    L.append("")
    cats = sorted(set(frame_sc["by_category"]) | set(semgrep_sc["by_category"]))
    L.append("| Category | CWE | Cases | Frame F1 | Frame Youden | Semgrep F1 | Semgrep Youden |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for cat in cats:
        fm = frame_sc["by_category"].get(cat, {})
        sm = semgrep_sc["by_category"].get(cat, {})
        cwe = fm.get("cwe") or sm.get("cwe") or "-"
        cases = fm.get("total_cases") or sm.get("total_cases") or 0
        L.append(f"| {cat} | {cwe} | {cases} | {fm.get('f1', '-')} | "
                 f"{fm.get('youden_score', '-')} | {sm.get('f1', '-')} | "
                 f"{sm.get('youden_score', '-')} |")
    L.append("")
    L.append("## Honest caveats")
    L.append("")
    L.append("- **Synthetic benchmark.** OWASP BenchmarkJava is synthetic; strong scores "
             "here do not predict real-world performance. This is exactly Endor's thesis, "
             "so do **not** extrapolate these numbers to Endor's real-world corpus.")
    L.append(f"- **Ruleset choice matters.** Semgrep's score depends on the ruleset "
             f"(`{semgrep_ruleset}` here). A different ruleset (e.g. `p/java`, "
             f"`p/security-audit`) would shift its numbers. This is Semgrep OSS out of the "
             f"box, not a tuned configuration.")
    L.append("- **Category coverage differs.** Each tool only scores where it has rules for "
             "the category; missing coverage shows up as low recall, not as an error.")
    L.append("- **Not Endor's Semgrep number.** Endor's published *\"over 460 false "
             "positives\"* / *\"2x fewer TPs than Endor\"* are on Endor's real-world corpus, "
             "a different dataset; they are not comparable to this table.")
    L.append("")
    return "\n".join(L)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="compare_benchmarkjava",
        description="Compare Frame vs Semgrep on OWASP BenchmarkJava.")
    p.add_argument("--repo", required=True, type=Path)
    p.add_argument("--frame-findings", required=True, type=Path,
                   help="frame.json produced by run_endor_corpus.py")
    p.add_argument("--semgrep-json", required=True, type=Path,
                   help="Semgrep --json output over the same testcode files")
    p.add_argument("--semgrep-ruleset", default="p/default",
                   help="Label for the Semgrep ruleset used (default: p/default)")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)

    for f in (args.repo, args.frame_findings, args.semgrep_json):
        if not f.exists():
            log(f"ERROR: not found: {f}")
            return 2

    expected = OB.load_expected_results(args.repo)
    commit = _git_commit(args.repo)

    frame_findings = json.loads(args.frame_findings.read_text(encoding="utf-8"))
    semgrep_findings = OB.parse_semgrep_findings(args.semgrep_json)
    log(f"Frame findings: {len(frame_findings)} | "
        f"Semgrep CWE-tagged findings: {len(semgrep_findings)}")

    frame_sc = OB.score(frame_findings, expected)
    semgrep_sc = OB.score(semgrep_findings, expected)

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "comparison.json").write_text(json.dumps({
        "commit": commit,
        "semgrep_ruleset": args.semgrep_ruleset,
        "frame": frame_sc,
        "semgrep": semgrep_sc,
    }, indent=2), encoding="utf-8")
    (args.output / "comparison.md").write_text(
        render_comparison_md(frame_sc, semgrep_sc, commit, args.semgrep_ruleset),
        encoding="utf-8")

    fo, so = frame_sc["overall"], semgrep_sc["overall"]
    log(f"FRAME   : P={fo['precision']} R={fo['tpr_recall']} F1={fo['f1']} "
        f"Youden={fo['youden_score']} (TP={fo['tp']} FP={fo['fp']})")
    log(f"SEMGREP : P={so['precision']} R={so['tpr_recall']} F1={so['f1']} "
        f"Youden={so['youden_score']} (TP={so['tp']} FP={so['fp']})")
    log(f"wrote comparison to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
