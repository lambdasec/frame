#!/usr/bin/env python3
"""Compare Frame vs Semgrep raw findings on corpus repos WITHOUT ground truth.

Only OWASP BenchmarkJava ships ground truth, so for every other repo we cannot
compute precision/recall/F1. This tool instead reports what each tool *surfaces*
and how much they agree:

  * total findings per tool,
  * findings by CWE and by severity,
  * agreement at (file, CWE) granularity: findings both tools flag vs. findings
    unique to each tool.

Agreement is NOT correctness. A finding both tools report is not necessarily a
true positive, and a unique finding is not necessarily wrong. This mirrors the
"unique findings" framing in the Endor article, which is about tool
complementarity, not accuracy.

Usage:
    python -m benchmarks.endor_corpus.compare_findings \
        --results-dir /tmp/frame-endor-results/results \
        --output /tmp/frame-endor-results/findings-comparison
    # or a single repo:
    python -m benchmarks.endor_corpus.compare_findings \
        --frame results/juice-shop/frame.json \
        --semgrep results/juice-shop/semgrep.json \
        --repo juice-shop --output out/
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from benchmarks.endor_corpus import owasp_benchmark as OB


def log(msg: str) -> None:
    print(f"[compare-findings] {msg}", flush=True)


def _norm_cwe(cwe: Any) -> Optional[str]:
    n = OB.cwe_to_int(cwe)
    return f"CWE-{n}" if n is not None else None


def _rel_path(path: Optional[str], repo: str) -> Optional[str]:
    """Normalize a finding path to a repo-relative form.

    Frame emits repo-relative paths (``src/...``); Semgrep emits absolute paths
    (``/tmp/.../<repo>/src/...``). Strip everything up to and including the last
    ``/<repo>/`` segment so the two are comparable.
    """
    if not path:
        return None
    p = str(path).replace("\\", "/")
    # Only strip the repo prefix from absolute paths, using the FIRST occurrence:
    # the repo name can recur in the path (e.g. WebGoat's org/owasp/webgoat/
    # package), where rfind would wrongly truncate.
    if p.startswith("/"):
        marker = f"/{repo}/"
        idx = p.find(marker)
        return p[idx + len(marker):] if idx != -1 else p.lstrip("/")
    return p.lstrip("./")


def _key(f: Dict[str, Any], repo: str) -> Optional[Tuple[str, str]]:
    """Agreement key: (repo-relative path, normalized CWE). None if unusable."""
    path = _rel_path(f.get("path"), repo)
    cwe = _norm_cwe(f.get("cwe"))
    if not path or not cwe:
        return None
    return (path, cwe)


def compare_repo(repo: str, frame_findings: List[Dict[str, Any]],
                 semgrep_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    frame_keys = {k for k in (_key(f, repo) for f in frame_findings) if k}
    semgrep_keys = {k for k in (_key(f, repo) for f in semgrep_findings) if k}
    both = frame_keys & semgrep_keys

    def by(field: str, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        c: Counter = Counter()
        for f in findings:
            if field == "cwe":
                c[_norm_cwe(f.get("cwe")) or "unmapped"] += 1
            else:
                c[(f.get(field) or "unknown")] += 1
        return dict(c.most_common())

    return {
        "repo": repo,
        "frame_total": len(frame_findings),
        "semgrep_total": len(semgrep_findings),
        "frame_cwe_keyed": len(frame_keys),
        "semgrep_cwe_keyed": len(semgrep_keys),
        "agree_file_cwe": len(both),
        "frame_only_file_cwe": len(frame_keys - semgrep_keys),
        "semgrep_only_file_cwe": len(semgrep_keys - frame_keys),
        "frame_by_cwe": by("cwe", frame_findings),
        "semgrep_by_cwe": by("cwe", semgrep_findings),
        "frame_by_severity": by("severity", frame_findings),
        "semgrep_by_severity": by("severity", semgrep_findings),
    }


def _load(path: Path) -> List[Dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def render_md(comparisons: List[Dict[str, Any]], semgrep_ruleset: str) -> str:
    L: List[str] = []
    L.append("# Frame vs Semgrep — raw findings (no ground truth)")
    L.append("")
    L.append(f"- Semgrep ruleset: `{semgrep_ruleset}`")
    L.append("")
    L.append("> **No ground truth.** These repos have no validated labels, so this is a "
             "comparison of what each tool *surfaces*, not of accuracy. Agreement is measured "
             "at (file, CWE) granularity and does **not** imply either finding is correct. "
             "No precision/recall/F1 is computed here.")
    L.append("")
    L.append("## Totals and agreement")
    L.append("")
    L.append("| Repo | Frame | Semgrep | Agree (file+CWE) | Frame-only | Semgrep-only |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for c in comparisons:
        L.append(f"| {c['repo']} | {c['frame_total']} | {c['semgrep_total']} | "
                 f"{c['agree_file_cwe']} | {c['frame_only_file_cwe']} | "
                 f"{c['semgrep_only_file_cwe']} |")
    L.append("")
    L.append("_Agreement uses only CWE-tagged findings; a tool's total may exceed its "
             "CWE-keyed count when some findings carry no CWE._")
    L.append("")
    for c in comparisons:
        L.append(f"## {c['repo']}")
        L.append("")
        L.append(f"- Frame: {c['frame_total']} findings "
                 f"({c['frame_cwe_keyed']} CWE-tagged)")
        L.append(f"- Semgrep: {c['semgrep_total']} findings "
                 f"({c['semgrep_cwe_keyed']} CWE-tagged)")
        L.append("")
        L.append("Frame by CWE: " + (", ".join(f"{k}:{v}" for k, v in
                 list(c["frame_by_cwe"].items())[:12]) or "_none_"))
        L.append("")
        L.append("Semgrep by CWE: " + (", ".join(f"{k}:{v}" for k, v in
                 list(c["semgrep_by_cwe"].items())[:12]) or "_none_"))
        L.append("")
        L.append("Frame by severity: " + (", ".join(f"{k}:{v}" for k, v in
                 c["frame_by_severity"].items()) or "_none_"))
        L.append("")
        L.append("Semgrep by severity: " + (", ".join(f"{k}:{v}" for k, v in
                 c["semgrep_by_severity"].items()) or "_none_"))
        L.append("")
    L.append("## Caveats")
    L.append("")
    L.append("- Agreement ≠ correctness; disagreement ≠ error. Without labels neither can be "
             "resolved here.")
    L.append("- CWE taxonomies differ between tools; agreement is only counted where both "
             "assign a CWE that normalizes equal, so real overlap may be undercounted.")
    L.append("- Semgrep's output depends on its ruleset; the ruleset used is shown above.")
    L.append("")
    return "\n".join(L)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="compare_findings",
        description="Compare Frame vs Semgrep raw findings (no ground truth).")
    p.add_argument("--results-dir", type=Path, default=None,
                   help="A run's results/ dir; compares every repo that has both "
                        "frame.json and semgrep.json.")
    p.add_argument("--frame", type=Path, default=None, help="Single repo frame.json")
    p.add_argument("--semgrep", type=Path, default=None, help="Single repo semgrep.json")
    p.add_argument("--repo", default=None, help="Repo name for --frame/--semgrep mode")
    p.add_argument("--semgrep-ruleset", default="p/default")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)

    comparisons: List[Dict[str, Any]] = []
    if args.results_dir:
        for repo_dir in sorted(args.results_dir.iterdir()):
            fj, sj = repo_dir / "frame.json", repo_dir / "semgrep.json"
            if fj.exists() and sj.exists():
                comparisons.append(compare_repo(repo_dir.name, _load(fj), _load(sj)))
        if not comparisons:
            log("ERROR: no repo dirs with both frame.json and semgrep.json found.")
            return 2
    elif args.frame and args.semgrep:
        comparisons.append(compare_repo(args.repo or "repo",
                                        _load(args.frame), _load(args.semgrep)))
    else:
        log("ERROR: provide --results-dir OR (--frame AND --semgrep).")
        return 2

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "findings_comparison.json").write_text(
        json.dumps({"semgrep_ruleset": args.semgrep_ruleset,
                    "repos": comparisons}, indent=2), encoding="utf-8")
    (args.output / "findings_comparison.md").write_text(
        render_md(comparisons, args.semgrep_ruleset), encoding="utf-8")

    for c in comparisons:
        log(f"{c['repo']:<24} Frame={c['frame_total']:<5} Semgrep={c['semgrep_total']:<5} "
            f"agree={c['agree_file_cwe']:<4} frame_only={c['frame_only_file_cwe']:<4} "
            f"semgrep_only={c['semgrep_only_file_cwe']}")
    log(f"wrote comparison to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
