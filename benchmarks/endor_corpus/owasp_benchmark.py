"""OWASP BenchmarkJava ground truth + official scoring for Frame.

OWASP BenchmarkJava ships a machine-readable ground-truth file,
``expectedresults-1.2.csv``, with one row per synthetic test case:

    # test name, category, real vulnerability, cwe, ...
    BenchmarkTest00001,pathtraver,true,22

Each test case is a single Java file containing exactly one sink of the given
category. ``real vulnerability`` = ``true`` means the file is genuinely
exploitable and a tool *should* flag it; ``false`` means the file is a safe
"trap" and a tool that flags it earns a false positive.

This module (a) converts that CSV into ground-truth records and (b) scores a set
of Frame findings using the official OWASP Benchmark methodology: per-category
TP / FP / TN / FN, true/false positive rates, precision, recall, F1, and the
Benchmark's Youden score (TPR - FPR).

IMPORTANT HONESTY NOTE
----------------------
This is the OWASP Benchmark: a *synthetic* benchmark with its *own* ground truth.
It is NOT Endor's benchmark. Frame's score here is a real, standalone result on a
well-known public benchmark, but it is NOT comparable to Endor's aggregate
real-world corpus numbers (whose whole thesis is that synthetic benchmarks like
this one over-state tool quality). Do not mix the two.
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

TESTCASE_RE = re.compile(r"(BenchmarkTest\d+)", re.IGNORECASE)
EXPECTED_CSV = "expectedresults-1.2.csv"
TESTCODE_REL = "src/main/java/org/owasp/benchmark/testcode"

# CWE -> BenchmarkJava category. This is the canonical map (the CWE the CSV uses
# for each category) PLUS sibling-CWE aliases that different tools emit for the
# same weakness class. Matching by category (not raw CWE number) is what the
# official OWASP Benchmark scorer does, and it keeps the comparison fair when a
# tool tags e.g. weak crypto as CWE-326 instead of CWE-327.
CWE_CATEGORY = {
    22: "pathtraver", 78: "cmdi", 79: "xss", 89: "sqli", 90: "ldapi",
    327: "crypto", 328: "hash", 330: "weakrand", 501: "trustbound",
    614: "securecookie", 643: "xpathi",
    # aliases (sibling CWEs for the same category):
    326: "crypto",   # Inadequate Encryption Strength (Semgrep uses this for crypto)
    916: "hash",     # Use of Password Hash With Insufficient Computational Effort
}

# The canonical CWE the CSV assigns to each category (for display in the report).
CATEGORY_CANONICAL_CWE = {
    "pathtraver": 22, "cmdi": 78, "xss": 79, "sqli": 89, "ldapi": 90,
    "crypto": 327, "hash": 328, "weakrand": 330, "trustbound": 501,
    "securecookie": 614, "xpathi": 643,
}


def cwe_to_category(cwe: Any) -> Optional[str]:
    """Map a CWE reference to a BenchmarkJava category (or None)."""
    n = cwe_to_int(cwe)
    return CWE_CATEGORY.get(n) if n is not None else None


def cwe_to_int(cwe: Any) -> Optional[int]:
    """Normalize CWE references to an int.

    Handles 'CWE-89', '89', 89, and Semgrep's 'CWE-89: SQL Injection'.
    Returns None if no CWE number can be found.
    """
    if cwe is None:
        return None
    s = str(cwe).strip().upper()
    m = re.search(r"CWE[-\s_]*(\d+)", s)
    if m:
        return int(m.group(1))
    return int(s) if s.isdigit() else None


def parse_semgrep_findings(semgrep_json_path: Path) -> List[Dict[str, Any]]:
    """Parse a Semgrep ``--json`` file into {path, cwe} findings.

    A single Semgrep result may carry several CWEs in
    ``extra.metadata.cwe``; each becomes its own finding so scoring can match any
    of them. Results without a CWE are dropped (they cannot be scored by CWE).
    """
    data = json.loads(Path(semgrep_json_path).read_text(encoding="utf-8"))
    out: List[Dict[str, Any]] = []
    for r in data.get("results", []):
        path = r.get("path")
        meta = (r.get("extra") or {}).get("metadata") or {}
        cwes = meta.get("cwe")
        if isinstance(cwes, str):
            cwes = [cwes]
        for c in (cwes or []):
            if cwe_to_int(c) is not None:
                out.append({"path": path, "cwe": c,
                            "rule_id": r.get("check_id"),
                            "severity": (r.get("extra") or {}).get("severity")})
    return out


def load_expected_results(repo_dir: Path) -> List[Dict[str, Any]]:
    """Parse expectedresults-1.2.csv into ground-truth records.

    Returns records: {repo, name, category, cwe, cwe_int, is_real, path}.
    """
    repo_dir = Path(repo_dir)
    csv_path = repo_dir / EXPECTED_CSV
    if not csv_path.exists():
        raise FileNotFoundError(
            f"{EXPECTED_CSV} not found in {repo_dir}. Is this an OWASP "
            f"BenchmarkJava checkout?")

    out: List[Dict[str, Any]] = []
    with csv_path.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            name, category, real, cwe = parts[0], parts[1], parts[2], parts[3]
            cwe_int = cwe_to_int(cwe)
            if cwe_int is None:
                continue
            out.append({
                "repo": "benchmarkjava",
                "name": name,
                "category": category,
                "cwe": f"CWE-{cwe_int}",
                "cwe_int": cwe_int,
                "is_real": real.lower() == "true",
                "path": f"{TESTCODE_REL}/{name}.java",
            })
    return out


def to_ground_truth_json(expected: List[Dict[str, Any]], commit: str
                         ) -> List[Dict[str, Any]]:
    """Render expected-results records in the harness ground-truth schema.

    Only the genuinely-vulnerable ('true') cases become positive labels, matching
    the ground_truth.json schema (which lists real vulnerabilities). Safe traps
    are omitted here (they are used by score(), not by the generic matcher).
    """
    return [{
        "repo": "benchmarkjava",
        "commit": commit,
        "cwe": e["cwe"],
        "path": e["path"],
        "line": None,
        "description": f"OWASP BenchmarkJava {e['category']} true positive",
        "source": "owasp_benchmark_expectedresults-1.2.csv",
        "status": "true_positive",
    } for e in expected if e["is_real"]]


def _metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, Any]:
    tpr = tp / (tp + fn) if (tp + fn) else 0.0            # recall
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tpr
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "tpr_recall": round(tpr, 4),
        "fpr": round(fpr, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "youden_score": round(tpr - fpr, 4),
    }


def score(findings: List[Dict[str, Any]],
          expected: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Score Frame findings against BenchmarkJava ground truth (OWASP method).

    A test case is 'detected' iff the tool emitted a finding whose CWE maps to the
    test's category, located in that test's file. Matching is by category (via
    cwe_to_category, which includes sibling-CWE aliases), mirroring the official
    OWASP Benchmark scorer. Cross-category findings do not count (each
    BenchmarkJava file has a single designated category).
    """
    flagged: Dict[str, set] = defaultdict(set)
    for f in findings:
        m = TESTCASE_RE.search(f.get("path") or "")
        cat = cwe_to_category(f.get("cwe"))
        if m and cat is not None:
            flagged[m.group(1).lower()].add(cat)

    by_cat: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    for e in expected:
        cat = e["category"]
        detected = cat in flagged.get(e["name"].lower(), set())
        if e["is_real"] and detected:
            by_cat[cat]["tp"] += 1
        elif e["is_real"] and not detected:
            by_cat[cat]["fn"] += 1
        elif (not e["is_real"]) and detected:
            by_cat[cat]["fp"] += 1
        else:
            by_cat[cat]["tn"] += 1

    category_metrics = {
        cat: {**_metrics(**counts),
              "cwe": (f"CWE-{CATEGORY_CANONICAL_CWE[cat]}"
                      if cat in CATEGORY_CANONICAL_CWE else None),
              "total_cases": sum(counts.values())}
        for cat, counts in sorted(by_cat.items())
    }
    tot = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for counts in by_cat.values():
        for k in tot:
            tot[k] += counts[k]

    return {
        "benchmark": "OWASP BenchmarkJava",
        "ground_truth_source": EXPECTED_CSV,
        "total_test_cases": len(expected),
        "overall": {**_metrics(**tot), "total_cases": sum(tot.values())},
        "by_category": category_metrics,
        "methodology": (
            "Official OWASP Benchmark scoring: each test file is TP/FN if it is a "
            "real vulnerability and the tool did/did not flag a matching-CWE "
            "finding in it, and FP/TN if it is a safe trap and the tool did/did "
            "not flag it. recall = TPR = TP/(TP+FN); FPR = FP/(FP+TN); "
            "F1 = 2PR/(P+R); Youden score = TPR - FPR."
        ),
    }


def render_scorecard_md(scorecard: Dict[str, Any], commit: str,
                        endor_semgrep_context: bool = True) -> str:
    ov = scorecard["overall"]
    L: List[str] = []
    L.append("# Frame — OWASP BenchmarkJava Scorecard")
    L.append("")
    L.append(f"- Benchmark: **{scorecard['benchmark']}** (commit `{commit[:12]}`)")
    L.append(f"- Ground truth: `{scorecard['ground_truth_source']}` "
             f"({scorecard['total_test_cases']} labeled test cases)")
    L.append("")
    L.append("> **This is the OWASP Benchmark, a _synthetic_ benchmark with its own "
             "ground truth.** It is a real, standalone result for Frame, but it is "
             "**NOT** Endor's benchmark and is **NOT comparable** to Endor's "
             "real-world corpus numbers. See the context note at the bottom.")
    L.append("")
    L.append("## Overall")
    L.append("")
    L.append("| TP | FP | TN | FN | Precision | Recall (TPR) | FPR | F1 | Youden |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    L.append(f"| {ov['tp']} | {ov['fp']} | {ov['tn']} | {ov['fn']} | "
             f"{ov['precision']} | {ov['tpr_recall']} | {ov['fpr']} | "
             f"{ov['f1']} | {ov['youden_score']} |")
    L.append("")
    L.append("## By category")
    L.append("")
    L.append("| Category | CWE | Cases | TP | FP | TN | FN | Precision | Recall | F1 | Youden |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for cat, m in scorecard["by_category"].items():
        L.append(f"| {cat} | {m['cwe']} | {m['total_cases']} | {m['tp']} | {m['fp']} | "
                 f"{m['tn']} | {m['fn']} | {m['precision']} | {m['tpr_recall']} | "
                 f"{m['f1']} | {m['youden_score']} |")
    L.append("")
    L.append(f"_Methodology: {scorecard['methodology']}_")
    L.append("")
    if endor_semgrep_context:
        L.append("## Endor's published Semgrep numbers (context only — different benchmark)")
        L.append("")
        L.append("These are from the Endor Labs article and describe Semgrep on **Endor's "
                 "aggregate real-world corpus**, not on OWASP BenchmarkJava. They are "
                 "**not comparable** to the scorecard above:")
        L.append("")
        L.append("- Semgrep OSS false positives: *\"over 460\"* (Endor claims *\"about 60% "
                 "fewer false positives\"*).")
        L.append("- Endor claims *\"2x more real vulnerabilities compared to Semgrep OSS\"* "
                 "(Endor 192 true positives → Semgrep ≈ 96, an arithmetic implication, not a "
                 "directly published figure).")
        L.append("- Strongest traditional tool caught 17 high-severity vs Endor's 72.")
        L.append("")
        L.append("> To compare Frame and Semgrep on the *same* footing you must run Semgrep "
                 "on this same BenchmarkJava commit (the OWASP project also publishes official "
                 "Semgrep scorecards), not reuse Endor's real-world-corpus numbers.")
        L.append("")
    return "\n".join(L)
