#!/usr/bin/env python3
"""Pool Frame + Semgrep judge verdicts into a reusable corpus ground-truth file.

The expensive part of this benchmark is the per-finding LLM adjudication
(Claude Sonnet 5 via `claude -p`). This tool combines the verdicts for BOTH
tools across the corpus so the result can be committed and reused -- nobody has
to re-run the judging.

It emits two artifacts under --output (default: this directory):

  ground_truth.pooled.json
      The de-duplicated set of judge-confirmed TRUE positives across Frame and
      Semgrep -- the corpus's "known real vulnerabilities". Written in the
      harness ground-truth schema, so `run_endor_corpus --ground-truth` and
      `summarize.compute_ground_truth_metrics` accept it directly.

  judged_findings.json
      Every judged finding + its verdict from both tools (a verdict cache), so a
      re-run can look up an existing verdict instead of paying to re-judge.

HONESTY / SCOPE (documented in the file and the README):
  * Labels are MODEL-adjudicated (Claude Sonnet 5), not human-verified. Each
    carries source "claude_code_judge:<model>".
  * The positive set is the UNION of what Frame and Semgrep found -- it is NOT a
    complete labeling of the corpus. It therefore supports measuring RECALL of a
    tool against these *known* vulnerabilities, but a finding absent from it is
    not necessarily a false positive (it may be a real vuln both tools missed).
  * Validate trust via the BenchmarkJava judge-vs-truth agreement (~0.89).
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from benchmarks.endor_corpus import owasp_benchmark as OB

HERE = Path(__file__).resolve().parent
LINE_CLUSTER = 3  # merge cross-tool TPs within +/- this many lines


def _rel_path(path: Optional[str], repo: str) -> str:
    """Normalize a finding path to repo-relative.

    Frame verdicts already store repo-relative paths; Semgrep verdicts store
    absolute paths. Only strip the ``/<repo>/`` prefix from *absolute* paths, and
    use the FIRST occurrence -- the repo name can recur later in the path (e.g.
    WebGoat's ``org/owasp/webgoat/`` package), and rfind would wrongly truncate.
    """
    p = (path or "").replace("\\", "/")
    if p.startswith("/"):
        marker = f"/{repo}/"
        i = p.find(marker)
        return p[i + len(marker):] if i != -1 else p.lstrip("/")
    return p.lstrip("./")


def _norm_cwe(cwe: Any) -> Optional[str]:
    n = OB.cwe_to_int(cwe)
    return f"CWE-{n}" if n is not None else None


def _load_verdicts(gt_dir: Path) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
    """Return {repo: [(tool, record), ...]} from all ground_truth.<repo>[.semgrep].json."""
    out: Dict[str, List[Tuple[str, Dict[str, Any]]]] = defaultdict(list)
    for f in sorted(glob.glob(str(gt_dir / "ground_truth.*.json"))):
        name = Path(f).name
        if name.endswith(".summary.json") or name in (
            "ground_truth.pooled.json", "ground_truth.example.json"):
            continue
        stem = name[len("ground_truth."):-len(".json")]
        if stem.endswith(".semgrep"):
            repo, tool = stem[:-len(".semgrep")], "semgrep"
        else:
            repo, tool = stem, "frame"
        try:
            recs = json.loads(Path(f).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for r in recs:
            if isinstance(r, dict) and "_comment" not in r:
                out[repo].append((tool, r))
    return out


def build(gt_dir: Path
          ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    by_repo = _load_verdicts(gt_dir)
    pooled: List[Dict[str, Any]] = []
    cache: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {"by_repo": {}, "by_cwe": Counter(), "totals": Counter()}

    for repo, entries in sorted(by_repo.items()):
        commit = next((r.get("commit") for _, r in entries if r.get("commit")), None)
        # cluster confirmed TPs by (rel_path, cwe) then by line proximity
        clusters: Dict[Tuple[str, str], List[Tuple[int, str, Dict[str, Any]]]] = defaultdict(list)
        repo_counts = Counter()
        for tool, r in entries:
            rel = _rel_path(r.get("path"), repo)
            cwe = _norm_cwe(r.get("cwe"))
            status = r.get("status")
            repo_counts[f"{tool}:{status}"] += 1
            cache.append({
                "repo": repo, "commit": commit, "tool": tool,
                "path": rel, "line": r.get("line"), "cwe": cwe,
                "status": status, "judge_confidence": r.get("judge_confidence"),
                "rule_id": r.get("rule_id"),
                "source": r.get("source", "claude_code_judge"),
            })
            if status == "true_positive" and cwe:
                clusters[(rel, cwe)].append((int(r.get("line") or 0), tool, r))

        repo_pos = 0
        for (rel, cwe), hits in clusters.items():
            hits.sort(key=lambda h: (h[0], h[1]))
            used = [False] * len(hits)
            for i, (line, _, _) in enumerate(hits):
                if used[i]:
                    continue
                group = [hits[i]]
                used[i] = True
                for j in range(i + 1, len(hits)):
                    if not used[j] and abs(hits[j][0] - line) <= LINE_CLUSTER:
                        group.append(hits[j]); used[j] = True
                tools = sorted({t for _, t, _ in group})
                rep = group[0][2]  # representative record
                pooled.append({
                    "repo": repo,
                    "commit": commit,
                    "cwe": cwe,
                    "path": rel,
                    "line": group[0][0] or None,
                    "description": (rep.get("description") or "")[:300],
                    "source": f"claude_code_judge:claude-sonnet-5 (pooled {'+'.join(tools)})",
                    "status": "true_positive",
                    "found_by": tools,
                    "provenance": "claude_judge_pooled",   # model-adjudicated, real-world
                    "granularity": "line",
                })
                repo_pos += 1
                summary["by_cwe"][cwe] += 1
        summary["by_repo"][repo] = {"confirmed_vulns": repo_pos, **dict(repo_counts)}
        summary["totals"]["confirmed_vulns"] += repo_pos

    # Note: OWASP BenchmarkJava is intentionally NOT merged here. It is Frame's
    # existing, separately-tested Java benchmark (the `owasp_java` division and
    # score_benchmarkjava.py, scored against its real expectedresults labels);
    # mixing its 1400+ synthetic cases into this real-world pool would only
    # confuse the two. This file is the real-world corpus ground truth.

    summary["by_cwe"] = dict(summary["by_cwe"].most_common())
    summary["totals"] = dict(summary["totals"])
    summary["note"] = (
        "Model-adjudicated (Claude Sonnet 5), pooled union of Frame + Semgrep "
        "true positives. NOT a complete labeling: supports recall of known "
        "vulns, not absolute precision. Validate via BenchmarkJava agreement.")
    return pooled, cache, summary


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="build_ground_truth",
        description="Pool Frame + Semgrep judge verdicts into a reusable ground-truth file.")
    p.add_argument("--gt-dir", type=Path, default=HERE,
                   help="Directory with ground_truth.<repo>[.semgrep].json (default: this dir).")
    p.add_argument("--output", type=Path, default=HERE,
                   help="Where to write ground_truth.pooled.json + judged_findings.json.")
    args = p.parse_args(argv)

    pooled, cache, summary = build(args.gt_dir)
    if not pooled:
        print("[build-gt] ERROR: no judged verdicts found in", args.gt_dir, file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "ground_truth.pooled.json").write_text(
        json.dumps(pooled, indent=2), encoding="utf-8")
    (args.output / "judged_findings.json").write_text(
        json.dumps(cache, indent=2), encoding="utf-8")
    (args.output / "ground_truth.pooled.summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")

    print(f"[build-gt] {summary['totals'].get('confirmed_vulns', 0)} confirmed vulnerabilities "
          f"(pooled Frame+Semgrep) across {len(summary['by_repo'])} repos")
    for repo, s in summary["by_repo"].items():
        print(f"    {repo:<20} {s['confirmed_vulns']} confirmed")
    print(f"[build-gt] wrote ground_truth.pooled.json ({len(pooled)}) + "
          f"judged_findings.json ({len(cache)} verdicts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
