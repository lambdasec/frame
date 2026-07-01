"""Aggregation, SARIF parsing, and report rendering for the Endor corpus harness.

This module is intentionally free of side effects on import so it can be unit
tested. The runner (run_endor_corpus.py) collects per-repo results and calls
build_summary() + render_summary_md() to produce results/summary.json and
results/summary.md.

Nothing here fabricates numbers. Precision/recall/F1 are computed ONLY when a
real ground-truth file is supplied (compute_ground_truth_metrics). Endor's
published headline numbers live in ENDOR_PUBLISHED_NUMBERS and are rendered in a
clearly separated "context only" section -- they are never mixed into Frame's
computed results.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# --------------------------------------------------------------------------- #
# Constants and Endor context (documentation only)
# --------------------------------------------------------------------------- #

ARTICLE_URL = (
    "https://www.endorlabs.com/learn/"
    "ai-sast-benchmark-2x-more-real-vulnerabilities"
)

# Endor Labs' published headline numbers, quoted from the reference article.
# CONTEXT ONLY. These are NOT computed by this harness and must NOT be compared
# directly to Frame's numbers (see ENDOR_WARNING). Frame does not run the same
# commits, ground-truth labels, scanner configs, prompts, aggregation logic, or
# scoring denominators, so a side-by-side comparison would be misleading.
ENDOR_PUBLISHED_NUMBERS: Dict[str, Any] = {
    "source": ARTICLE_URL,
    "disclaimer": (
        "Quoted from the Endor Labs article for context only. Not reproduced or "
        "verified by this harness."
    ),
    "endor_ai_sast": {
        "true_positives": '"found 192 real vulnerabilities"',
        "unique_findings": '"63 of its findings were caught by no other tool in the test"',
        "cwe_coverage": '"detected 64 of the 106 CWE types in the benchmark"',
        "recall": '"led the test on ... recall (0.435)"',
        "f1": '"led the test on ... F1 (0.465)"',
        "high_severity": '"catching 4x more high-severity vulnerabilities as the strongest '
                         'traditional tool (72 vs 17)"',
        "critical_severity": '"leading on critical (46 vs 38)"',
    },
    "comparisons": {
        "claude_opus_4_7": '"2.6x what Claude (Opus 4.7) caught"; Claude precision "0.718" with '
                           'near-bottom recall; Claude unique findings "18"; Claude CWE types "36"',
        "codex_gpt_5_5": '"3.5x what Codex (GPT-5.5) caught"; Codex precision "0.859" with '
                         'near-bottom recall',
        "semgrep_oss": '"2x more real vulnerabilities compared to Semgrep OSS"; "about 60% fewer '
                       'false positives than Semgrep OSS"; Semgrep flagged "over 460" false positives',
        "opengrep": '"60% fewer false positives than ... OpenGrep, which flagged over 460 each"',
        "bearer": "No standalone headline number quoted in the article for Bearer.",
        "codeql": "No standalone headline number quoted in the article for CodeQL.",
    },
    "methodology_notes": (
        'Endor established ground truth by "pooling every tool\'s true positives, '
        'de-duplicating them by hand, adding issues found through manual review, and '
        'verifying each one." Testing covered "Java, Python, JavaScript, TypeScript, C# and Go."'
    ),
}

ENDOR_WARNING = (
    "Frame results from this harness should not be compared directly to Endor's "
    "headline numbers unless the same commits, ground-truth labels, scanner "
    "configurations, model prompts, run aggregation logic, and scoring "
    "denominators are reconstructed."
)

# --------------------------------------------------------------------------- #
# File classification
# --------------------------------------------------------------------------- #

# Extensions Frame can currently analyze (per frame/sil/scanner.py auto-detect).
SUPPORTED_EXT: Dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
}

# Code that Frame explicitly does NOT support yet. Reported, never scanned.
UNSUPPORTED_CODE_EXT: Dict[str, str] = {
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
}

# Non-code / config / markup buckets tracked for context.
OTHER_EXT: Dict[str, str] = {
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "css",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".xml": "xml",
    ".ini": "config",
    ".cfg": "config",
    ".toml": "config",
    ".properties": "config",
}


def classify_extension(suffix: str) -> str:
    """Return one of: 'supported', 'unsupported', 'other', 'unknown'."""
    s = suffix.lower()
    if s in SUPPORTED_EXT:
        return "supported"
    if s in UNSUPPORTED_CODE_EXT:
        return "unsupported"
    if s in OTHER_EXT:
        return "other"
    return "unknown"


# --------------------------------------------------------------------------- #
# SARIF parsing
# --------------------------------------------------------------------------- #

def _rule_to_cwe_map() -> Dict[str, str]:
    """Build a rule-id -> CWE map from Frame's own authoritative CWE_MAP.

    Frame's SARIF does not carry CWE ids, but its rule ids are
    ``frame/<vuln_type>`` and Frame internally maps each vuln type to a CWE.
    Deriving CWE from that mapping is safe (not invented). Returns {} if Frame
    is not importable so the parser degrades gracefully.
    """
    try:
        from frame.sil.scanner import FrameScanner  # lazy import
    except Exception:
        return {}
    out: Dict[str, str] = {}
    for vuln_type, cwe in getattr(FrameScanner, "CWE_MAP", {}).items():
        value = getattr(vuln_type, "value", str(vuln_type))
        if cwe:
            out[f"frame/{value}"] = cwe
    return out


def level_to_severity(level: Optional[str]) -> Optional[str]:
    """Approximate SARIF level -> severity. Lossy: 'error' covers critical+high.

    Documented as approximate. The runner's normalized frame.json uses the
    scanner's authoritative severity instead; this is only for consumers that
    have nothing but SARIF.
    """
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }.get((level or "").lower())


def parse_frame_sarif(
    sarif_path: Path,
    repo: Optional[str] = None,
    commit: Optional[str] = None,
    rule_cwe_map: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Parse a Frame SARIF file into normalized finding records.

    Extracts, per result: rule id, CWE (derived from rule id when safely
    available -- Frame SARIF has no CWE field), severity/level, message, file
    path, line number, repo, and fingerprint if present. CWE is None when it
    cannot be derived. No CWE ids are invented.
    """
    if rule_cwe_map is None:
        rule_cwe_map = _rule_to_cwe_map()

    data = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    findings: List[Dict[str, Any]] = []
    index = 0
    for run in data.get("runs", []):
        for res in run.get("results", []):
            rule_id = res.get("ruleId")
            level = res.get("level") or res.get("kind")
            message = ((res.get("message") or {}).get("text") or "").strip()

            path = None
            line = None
            locs = res.get("locations") or []
            if locs:
                phys = locs[0].get("physicalLocation") or {}
                path = (phys.get("artifactLocation") or {}).get("uri")
                line = (phys.get("region") or {}).get("startLine")

            fingerprints = res.get("fingerprints") or res.get("partialFingerprints")
            fingerprint = None
            if isinstance(fingerprints, dict) and fingerprints:
                # take a stable, single representative value
                fingerprint = next(iter(sorted(fingerprints.values())))

            findings.append({
                "repo": repo,
                "commit": commit,
                "tool": "frame",
                "rule_id": rule_id,
                "cwe": rule_cwe_map.get(rule_id) if rule_id else None,
                "level": level,
                "severity": level_to_severity(level),
                "message": message,
                "path": path,
                "line": line,
                "fingerprint": fingerprint,
                "sarif_result_index": index,
            })
            index += 1
    return findings


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

def summarize_findings(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate normalized findings by repo, CWE, and severity."""
    by_repo: Counter = Counter()
    by_cwe: Counter = Counter()
    by_severity: Counter = Counter()
    total = 0
    for f in findings:
        total += 1
        by_repo[f.get("repo") or "unknown"] += 1
        by_cwe[f.get("cwe") or "unmapped"] += 1
        by_severity[f.get("severity") or "unknown"] += 1
    return {
        "total_findings": total,
        "by_repo": dict(by_repo.most_common()),
        "by_cwe": dict(by_cwe.most_common()),
        "by_severity": dict(by_severity.most_common()),
    }


def _norm_cwe(cwe: Optional[str]) -> str:
    if not cwe:
        return ""
    c = str(cwe).strip().upper()
    if c.startswith("CWE-"):
        return c
    if c.isdigit():
        return f"CWE-{c}"
    return c


def compute_ground_truth_metrics(
    findings: List[Dict[str, Any]],
    ground_truth: List[Dict[str, Any]],
    line_window: int = 5,
) -> Dict[str, Any]:
    """Compute precision/recall/F1 against a REAL ground-truth label list.

    Matching logic (documented, deliberately conservative):
      A Frame finding matches a ground-truth item iff
        * same repo, AND
        * same CWE (normalized, e.g. "89" == "CWE-89"), AND
        * same file path (basename-insensitive suffix match), AND
        * line numbers within +/- ``line_window``.
    Each ground-truth item can be matched by at most one finding (greedy).

    This is only called when the caller supplies a real ground-truth file. It is
    never invoked with the example schema file.
    """
    gt_items = [g for g in ground_truth if isinstance(g, dict) and "repo" in g]

    def path_match(fpath: Optional[str], gpath: Optional[str]) -> bool:
        if not fpath or not gpath:
            return False
        fp, gp = fpath.replace("\\", "/"), gpath.replace("\\", "/")
        return fp.endswith(gp) or gp.endswith(fp) or Path(fp).name == Path(gp).name

    matched_gt = set()
    matched_findings = set()
    for fi, f in enumerate(findings):
        for gi, g in enumerate(gt_items):
            if gi in matched_gt:
                continue
            if (f.get("repo") == g.get("repo")
                    and _norm_cwe(f.get("cwe")) == _norm_cwe(g.get("cwe"))
                    and _norm_cwe(f.get("cwe")) != ""
                    and path_match(f.get("path"), g.get("path"))):
                fl, gl = f.get("line"), g.get("line")
                if fl is not None and gl is not None and abs(int(fl) - int(gl)) <= line_window:
                    matched_gt.add(gi)
                    matched_findings.add(fi)
                    break

    tp = len(matched_findings)
    fp = len(findings) - tp
    fn = len(gt_items) - len(matched_gt)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "ground_truth_items": len(gt_items),
        "frame_findings_considered": len(findings),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "line_window": line_window,
        "matching_logic": (
            "repo + CWE (normalized) + file-path suffix/basename match + line "
            f"within +/-{line_window}; each ground-truth item matched at most once."
        ),
    }


# --------------------------------------------------------------------------- #
# Top-level summary assembly + markdown rendering
# --------------------------------------------------------------------------- #

def build_summary(
    repo_reports: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    run_meta: Dict[str, Any],
    scanner_errors: List[Dict[str, Any]],
    ground_truth_metrics: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble the summary.json structure."""
    agg = summarize_findings(findings)
    return {
        "benchmark": "Frame on the Endor Labs AI-SAST public corpus",
        "harness_kind": (
            "Evaluation harness over Endor's public corpus list. NOT a reproduction "
            "of Endor's benchmark."
        ),
        "reference_article": ARTICLE_URL,
        "run": run_meta,
        "repositories": repo_reports,
        "frame_findings": agg,
        "scanner_errors": scanner_errors,
        "ground_truth_metrics": ground_truth_metrics,
        "endor_published_numbers_context_only": ENDOR_PUBLISHED_NUMBERS,
        "warning": ENDOR_WARNING,
    }


def _md_table(headers: List[str], rows: List[List[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def render_summary_md(summary: Dict[str, Any]) -> str:
    """Render a human-readable summary.md from build_summary() output."""
    L: List[str] = []
    run = summary.get("run", {})
    repos = summary.get("repositories", [])
    agg = summary.get("frame_findings", {})
    errors = summary.get("scanner_errors", [])

    L.append("# Frame on the Endor Labs AI-SAST Public Corpus")
    L.append("")
    L.append(f"Reference article (context only): {summary['reference_article']}")
    L.append("")
    L.append(f"- Generated: {run.get('finished_at', 'n/a')}")
    L.append(f"- Frame scanner: verify={run.get('verify')}, timeout_ms={run.get('timeout_ms')}")
    L.append(f"- Mode: {run.get('mode')}")
    if run.get("semgrep"):
        L.append(f"- Semgrep baseline: {run.get('semgrep')}")
    L.append("")

    # 3 / 4. What it is / is not
    L.append("## What this benchmark is")
    L.append("")
    L.append("This harness clones the 8 public repositories that Endor Labs named as their "
             "AI-SAST benchmark corpus, pins each to a recorded commit SHA, runs Frame on the "
             "language portions Frame supports, and reports what Frame found. It is a "
             "**reproducible way to run Frame over a public corpus** and inspect its output.")
    L.append("")
    L.append("## What this benchmark is NOT")
    L.append("")
    L.append("- It is **not** a reproduction of Endor's benchmark results.")
    L.append("- Endor published the corpus *list* but not commit SHAs, ground-truth labels, "
             "scanner configurations, model prompts, run-aggregation logic, or their verified "
             "findings database.")
    L.append("- Without a ground-truth label file, this harness reports **raw findings only** and "
             "does **not** compute precision, recall, or F1.")
    L.append("")

    # 5. Corpus repos + commits
    L.append("## Corpus repositories and commits")
    L.append("")
    rows = []
    for r in repos:
        rows.append([
            r.get("display_name", r.get("repo")),
            r.get("repo"),
            (r.get("commit") or "n/a")[:12],
            "cloned" if r.get("cloned") else ("skipped" if r.get("skipped") else "failed"),
        ])
    L.append(_md_table(["Repository", "Slug", "Commit", "Status"], rows))
    L.append("")
    for r in repos:
        L.append(f"- `{r.get('repo')}`: {r.get('url')}")
    L.append("")

    # 6 / 7. Supported vs unsupported coverage
    L.append("## Supported coverage by repo")
    L.append("")
    rows = []
    for r in repos:
        fc = r.get("file_counts", {})
        rows.append([
            r.get("repo"),
            fc.get("supported_total", 0),
            r.get("files_scanned", 0),
            ", ".join(sorted((fc.get("supported_by_language") or {}).keys())) or "-",
        ])
    L.append(_md_table(["Repo", "Supported files", "Files scanned", "Languages"], rows))
    L.append("")
    L.append("## Unsupported coverage by repo")
    L.append("")
    rows = []
    for r in repos:
        fc = r.get("file_counts", {})
        unsup = fc.get("unsupported_by_language") or {}
        rows.append([
            r.get("repo"),
            fc.get("unsupported_total", 0),
            ", ".join(f"{k}:{v}" for k, v in sorted(unsup.items())) or "-",
        ])
    L.append(_md_table(["Repo", "Unsupported code files", "Breakdown"], rows))
    L.append("")
    L.append("> Unsupported code (Go, PHP, Ruby) is counted and reported here, not silently "
             "ignored. Frame produces no findings for these files.")
    L.append("")

    # 8. Findings summary
    L.append("## Frame findings summary")
    L.append("")
    L.append(f"**Total Frame findings: {agg.get('total_findings', 0)}**")
    L.append("")
    L.append("### Findings by repo")
    L.append("")
    L.append(_md_table(["Repo", "Findings"],
                       [[k, v] for k, v in (agg.get("by_repo") or {}).items()]) or "_none_")
    L.append("")
    # 9. CWE summary
    L.append("### Findings by CWE")
    L.append("")
    L.append(_md_table(["CWE", "Findings"],
                       [[k, v] for k, v in (agg.get("by_cwe") or {}).items()]) or "_none_")
    L.append("")
    # 10. Severity summary
    L.append("### Findings by severity")
    L.append("")
    L.append(_md_table(["Severity", "Findings"],
                       [[k, v] for k, v in (agg.get("by_severity") or {}).items()]) or "_none_")
    L.append("")

    # 11. Scanner errors
    L.append("## Scanner errors")
    L.append("")
    if errors:
        L.append(_md_table(["Repo", "Path", "Error"],
                           [[e.get("repo"), e.get("path"), (e.get("error") or "")[:200]]
                            for e in errors]))
    else:
        L.append("_No scanner errors recorded._")
    L.append("")

    # Ground-truth metrics (only if real ground truth provided)
    gtm = summary.get("ground_truth_metrics")
    L.append("## Ground-truth metrics")
    L.append("")
    if gtm:
        L.append("Computed against the supplied ground-truth label file:")
        L.append("")
        L.append(_md_table(
            ["TP", "FP", "FN", "Precision", "Recall", "F1"],
            [[gtm["true_positives"], gtm["false_positives"], gtm["false_negatives"],
              gtm["precision"], gtm["recall"], gtm["f1"]]]))
        L.append("")
        L.append(f"Matching logic: {gtm['matching_logic']}")
    else:
        L.append("No ground-truth label file was supplied, so **precision, recall, and F1 are "
                 "not computed**. This harness never prints those metrics without real labels.")
    L.append("")

    # 12. How to interpret
    L.append("## How to interpret these results")
    L.append("")
    L.append("- Counts above are **raw Frame findings**, not verified true positives.")
    L.append("- A finding count is not a quality score: some findings may be false positives and "
             "some real vulnerabilities may be missed (especially in unsupported languages).")
    L.append("- Only the supported-language portions of each repo were scanned. Unsupported "
             "portions are reported separately and contribute zero findings by construction.")
    L.append("- To turn raw findings into precision/recall/F1 you must add a validated "
             "ground-truth file (see the README).")
    L.append("")

    # 13. Why not a reproduction
    L.append("## Why this is not a reproduction of Endor's recall/F1")
    L.append("")
    L.append("Endor's recall and F1 depend on: the exact commits they scanned, their manually "
             "curated and de-duplicated ground-truth set, each tool's scanner configuration and "
             "(for AI tools) prompts, their run-aggregation logic, and the scoring denominators "
             "they chose. None of these were published in enough detail to reconstruct. This "
             "harness therefore measures *Frame's output on the public corpus*, which is a "
             "different quantity.")
    L.append("")

    # 14. Endor published numbers (context only)
    L.append("## Endor published numbers for context only")
    L.append("")
    L.append("The following are quoted from the Endor Labs article **for context only**. They "
             "are NOT computed by this harness and must NOT be treated as Frame's results.")
    L.append("")
    epn = summary.get("endor_published_numbers_context_only", {})
    eas = epn.get("endor_ai_sast", {})
    L.append("**Endor AI SAST (as published):**")
    L.append("")
    for k, v in eas.items():
        L.append(f"- {k.replace('_', ' ')}: {v}")
    L.append("")
    L.append("**Endor's published comparisons:**")
    L.append("")
    for k, v in (epn.get("comparisons") or {}).items():
        L.append(f"- {k.replace('_', ' ')}: {v}")
    L.append("")
    L.append(f"**Endor methodology note:** {epn.get('methodology_notes', '')}")
    L.append("")

    # 15. Warning
    L.append("## Comparison warning")
    L.append("")
    L.append(f"> {summary.get('warning', ENDOR_WARNING)}")
    L.append("")

    # 16. Next steps
    L.append("## Next steps to make this a true benchmark")
    L.append("")
    L.append("1. Add validated ground-truth labels (see `ground_truth.example.json`).")
    L.append("2. Pin Endor-equivalent commits once/if Endor publishes them.")
    L.append("3. Manually validate a sample of Frame findings to estimate precision.")
    L.append("4. Add baselines for Semgrep (supported via `--with-semgrep`) and CodeQL.")
    L.append("5. Compare tools only on shared, supported-language denominators.")
    L.append("")

    return "\n".join(L)
