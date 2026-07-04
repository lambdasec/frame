#!/usr/bin/env python3
"""Score Frame and Semgrep on the SusVibes vulnerable/fixed pairs.

    python benchmarks/susvibes/score.py --pairs /tmp/susvibes-pairs            # Frame symbolic
    python benchmarks/susvibes/score.py --pairs /tmp/susvibes-pairs --semgrep  # + Semgrep
    python benchmarks/susvibes/score.py --pairs /tmp/susvibes-pairs --ai       # + LLM detection

recall  = flags the task CWE on the VULNERABLE version / N
precision = TP / (TP + FP), FP = flags the task CWE on the FIXED version
(OWASP-Benchmark-style paired scoring; match at file + CWE, CWE families normalized).
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import subprocess
import sys
from pathlib import Path

_FAM = {"CWE-73": "CWE-22", "CWE-29": "CWE-22", "CWE-23": "CWE-22", "CWE-36": "CWE-22",
        "CWE-77": "CWE-78", "CWE-80": "CWE-79", "CWE-83": "CWE-79", "CWE-87": "CWE-79",
        "CWE-116": "CWE-79", "CWE-91": "CWE-89", "CWE-943": "CWE-89", "CWE-95": "CWE-94",
        "CWE-96": "CWE-94", "CWE-259": "CWE-798", "CWE-321": "CWE-798", "CWE-326": "CWE-327",
        "CWE-338": "CWE-330"}


def fam(c):
    m = re.search(r"CWE-\d+", str(c) or "")
    if not m:
        return None
    c = m.group(0)
    return _FAM.get(c, c)


def frame_cwes(d: Path) -> set:
    from frame.sil import FrameScanner
    out = set()
    for f in d.glob("*.py"):
        try:
            r = FrameScanner(language="python", verify=True, library_mode=True).scan_file(str(f))
            for v in r.vulnerabilities:
                if v.cwe_id:
                    out.add(fam(v.cwe_id))
        except Exception:
            pass
    return {c for c in out if c}


def llm_cwes(d: Path) -> set:
    from frame.sil.llm_triage import TriageConfig, LLMTriageClient
    from frame.sil.llm_detect import detect_in_file
    cfg = TriageConfig.from_env()
    client = LLMTriageClient(cfg)
    out = set()
    for f in d.glob("*.py"):
        try:
            for v in detect_in_file(f.read_text(encoding="utf-8", errors="replace"),
                                    "python", f.name, cfg, client):
                if v.cwe_id:
                    out.add(fam(v.cwe_id))
        except Exception:
            pass
    return {c for c in out if c}


def semgrep_index(pairs: Path) -> dict:
    out = pairs / "_semgrep.json"
    subprocess.run(["semgrep", "--config", "p/security-audit", "--timeout", "30",
                    "--timeout-threshold", "3", "-j", "8", "--json", "--metrics=off",
                    "-o", str(out), str(pairs)], capture_output=True, text=True, timeout=3600)
    data = json.loads(out.read_text())
    idx = {}
    for r in data.get("results", []):
        mm = re.search(r"([^/]+)/(vulnerable|secure)/", r.get("path", ""))
        if not mm:
            continue
        key = (mm.group(1), "vul" if mm.group(2) == "vulnerable" else "sec")
        for c in (r.get("extra", {}).get("metadata", {}).get("cwe") or []):
            if fam(c):
                idx.setdefault(key, set()).add(fam(c))
    return idx


def score(name, manifest, pairs, get_vul, get_sec):
    n = len(manifest)
    TP = FP = 0
    for m in manifest:
        iid = m["instance_id"]
        task = {fam(c) for c in m["cwe_ids"] if fam(c)}
        if get_vul(iid) & task:
            TP += 1
        if get_sec(iid) & task:
            FP += 1
    rec = TP / n if n else 0.0
    prec = TP / (TP + FP) if (TP + FP) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    print(f"  {name:34} recall={rec:.3f}  precision={prec:.3f}  F1={f1:.3f}  (TP={TP} FP-on-fix={FP})")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", required=True)
    ap.add_argument("--semgrep", action="store_true")
    ap.add_argument("--ai", action="store_true")
    args = ap.parse_args(argv)
    pairs = Path(args.pairs)
    manifest = json.loads((pairs / "manifest.json").read_text())
    print(f"SusVibes: {len(manifest)} real-CVE Python pairs\n")

    fr = {m["instance_id"]: (frame_cwes(pairs / m["instance_id"] / "vulnerable"),
                             frame_cwes(pairs / m["instance_id"] / "secure")) for m in manifest}
    score("Frame (symbolic core)", manifest, pairs, lambda i: fr[i][0], lambda i: fr[i][1])

    if args.semgrep:
        si = semgrep_index(pairs)
        score("Semgrep (p/security-audit)", manifest, pairs,
              lambda i: si.get((i, "vul"), set()), lambda i: si.get((i, "sec"), set()))

    if args.ai:
        ai = {m["instance_id"]: (llm_cwes(pairs / m["instance_id"] / "vulnerable"),
                                 llm_cwes(pairs / m["instance_id"] / "secure")) for m in manifest}
        score("Frame + LLM detect (reason-first)", manifest, pairs,
              lambda i: ai[i][0], lambda i: ai[i][1])


if __name__ == "__main__":
    main()
