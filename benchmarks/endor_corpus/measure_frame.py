#!/usr/bin/env python3
"""Measure Frame against the pooled real-world ground truth -- free, no re-judging.

Re-scans Frame over the 5 real-world corpus repos and scores it against:
  * ground_truth.pooled.json  -> RECALL  (of the N known vulns, how many Frame finds)
  * judged_findings.json       -> PRECISION on findings whose verdict is already
    cached (Frame findings we previously judged); genuinely NEW findings (created
    by detector improvements) are reported separately as "unjudged" -- only those
    would ever need a fresh `claude -p` verdict.

This is the fix-and-measure loop for improving Frame: change a detector, re-run
this, watch recall climb and cached-precision hold, at zero judging cost.

Usage:
    python -m benchmarks.endor_corpus.measure_frame --workspace /tmp/endor-corpus
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from benchmarks.endor_corpus import owasp_benchmark as OB
from benchmarks.endor_corpus import run_endor_corpus as R

HERE = Path(__file__).resolve().parent
REPOS = ["webgoat", "juice-shop", "shopizer", "anonymous-github", "demo-netflicks"]


def _norm_cwe(c: Any) -> Optional[str]:
    n = OB.cwe_to_int(c)
    return f"CWE-{n}" if n is not None else None


def _rel(path: str, repo: str) -> str:
    # Only strip the repo prefix from absolute paths, first occurrence (the repo
    # name can recur in the path, e.g. WebGoat's org/owasp/webgoat/ package).
    p = (path or "").replace("\\", "/")
    if p.startswith("/"):
        marker = f"/{repo}/"
        i = p.find(marker)
        return p[i + len(marker):] if i != -1 else p.lstrip("/")
    return p.lstrip("./")


def scan_repo(repo: str, repo_dir: Path, patterns: List[str]) -> List[Tuple[str, int, str]]:
    from frame.sil import FrameScanner
    exts = R.patterns_to_extensions(patterns)
    sc = FrameScanner(language="python", verify=False)
    out = []
    for fp in R.collect_files(repo_dir):
        if fp.suffix.lower() not in exts:
            continue
        try:
            res = sc.scan_file(str(fp))
        except Exception:
            continue
        rel = str(fp.resolve().relative_to(repo_dir.resolve()))
        for v in res.vulnerabilities:
            out.append((rel, v.line, v.cwe_id))
    return out


def measure(workspace: Path, gt_path: Path, cache_path: Path,
            window: int = 5) -> Dict[str, Any]:
    corpus = {c["name"]: c for c in yaml.safe_load(
        (HERE / "corpus.yaml").read_text())["repos"]}
    gt = json.loads(gt_path.read_text())
    cache = json.loads(cache_path.read_text()) if cache_path.exists() else []

    # verdict cache: (repo, rel, cwe) -> list of (line, status)
    verdicts: Dict[Tuple[str, str, str], List[Tuple[int, str]]] = defaultdict(list)
    for c in cache:
        if c.get("tool") != "frame":
            continue
        key = (c["repo"], _rel(c.get("path"), c["repo"]), _norm_cwe(c.get("cwe")))
        verdicts[key].append((int(c.get("line") or 0), c.get("status")))

    # ground-truth positives per repo: (rel, cwe) -> [lines]
    gt_by_repo: Dict[str, List[Tuple[str, str, int]]] = defaultdict(list)
    for e in gt:
        gt_by_repo[e["repo"]].append(
            (_rel(e.get("path"), e["repo"]), _norm_cwe(e.get("cwe")), int(e.get("line") or 0)))

    total_gt = sum(len(v) for v in gt_by_repo.values())
    matched_gt = 0
    prec = Counter()  # cached_tp / cached_fp / unjudged
    per_repo = {}

    for repo in REPOS:
        rd = workspace / repo
        if not rd.exists():
            per_repo[repo] = {"error": "not cloned"}
            continue
        findings = scan_repo(repo, rd, corpus[repo]["supported_patterns"])
        findings_norm = [(rel, line, _norm_cwe(cwe)) for rel, line, cwe in findings]

        # recall: which GT entries does Frame hit? Match at FILE + CWE (not exact
        # line): two tools routinely report the SAME vuln at different lines (the
        # query is built on one line, executed several lines later), so a tight
        # line window under-counts real recall.
        gt_entries = gt_by_repo.get(repo, [])
        frame_file_cwe = {(frel, fcwe) for frel, _, fcwe in findings_norm}
        hit = sum(1 for grel, gcwe, _ in gt_entries if (grel, gcwe) in frame_file_cwe)
        matched_gt += hit

        # precision via cache
        rp = Counter()
        for frel, fline, fcwe in findings_norm:
            cands = verdicts.get((repo, frel, fcwe), [])
            status = None
            for cline, cstatus in cands:
                if abs((fline or 0) - cline) <= window:
                    status = cstatus
                    if cstatus == "true_positive":
                        break
            if status == "true_positive":
                rp["cached_tp"] += 1
            elif status == "false_positive":
                rp["cached_fp"] += 1
            else:
                rp["unjudged"] += 1
        prec.update(rp)
        per_repo[repo] = {
            "findings": len(findings), "gt_vulns": len(gt_entries), "recall_hits": hit,
            **dict(rp)}

    cached_dec = prec["cached_tp"] + prec["cached_fp"]
    return {
        "recall": {
            "matched": matched_gt, "total_gt": total_gt,
            "value": round(matched_gt / total_gt, 3) if total_gt else None},
        "precision_cached": {
            "tp": prec["cached_tp"], "fp": prec["cached_fp"],
            "value": round(prec["cached_tp"] / cached_dec, 3) if cached_dec else None,
            "unjudged_new_findings": prec["unjudged"]},
        "per_repo": per_repo,
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="measure_frame",
                                description="Measure Frame vs pooled ground truth (free).")
    p.add_argument("--workspace", required=True, type=Path)
    p.add_argument("--ground-truth", type=Path, default=HERE / "ground_truth.pooled.json")
    p.add_argument("--cache", type=Path, default=HERE / "judged_findings.json")
    args = p.parse_args(argv)

    r = measure(args.workspace, args.ground_truth, args.cache)
    rc, pc = r["recall"], r["precision_cached"]
    print(f"RECALL vs pooled GT: {rc['matched']}/{rc['total_gt']} = {rc['value']}")
    print(f"PRECISION (cached verdicts only): {pc['tp']} TP / {pc['fp']} FP = {pc['value']}"
          f"   (+{pc['unjudged_new_findings']} new findings not yet judged)")
    print("per-repo:")
    for repo, s in r["per_repo"].items():
        print(f"  {repo:<18} {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
