#!/usr/bin/env python3
"""Adjudicate Frame/Semgrep findings with Claude Code (headless) to build ground truth.

Only OWASP BenchmarkJava ships real ground truth. For the other corpus repos we
have none. This tool uses **Claude Code in headless mode** (`claude -p`) with the
**Sonnet 5** model as an LLM judge to triage each finding as a true or false
positive, one finding at a time, and writes the verdicts as a ground-truth file
in the harness schema. This automates the "pool findings, then verify each one"
step of Endor's methodology -- with a model judge instead of a human.

HONESTY / SCOPE -- read before trusting the numbers this produces:
  * These labels are **model-adjudicated**, NOT human-verified. They are saved
    with source "claude_code:<model>" so they are never confused with manual
    ground truth. Validate the judge against BenchmarkJava's real labels first
    (--validate) to know how much to trust it.
  * The judge only sees the *tool's* findings, so it can measure **precision**
    (of the flagged findings, how many are real) but NOT recall or F1 -- it
    cannot discover vulnerabilities the tools missed (false negatives).
  * No verdicts are invented. Every verdict comes from an actual `claude -p`
    invocation; parse failures are recorded as "error", never guessed.

Requires the `claude` CLI (Claude Code) on PATH, authenticated. No API key needed.

Usage:
    # Adjudicate a repo's Frame findings, slowly, one by one:
    python -m benchmarks.endor_corpus.judge_ground_truth \
        --repo /tmp/endor-corpus/webgoat \
        --findings /tmp/frame-endor-results/results/webgoat/frame.json \
        --output benchmarks/endor_corpus/ground_truth.webgoat.json \
        --model sonnet --delay 1.0

    # Validate the judge against BenchmarkJava's REAL ground truth first:
    python -m benchmarks.endor_corpus.judge_ground_truth \
        --repo /tmp/endor-corpus/benchmarkjava \
        --findings /tmp/frame-endor-results/results/benchmarkjava/frame.json \
        --validate --max-findings 40 --output /tmp/bj_judge_validation.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from benchmarks.endor_corpus import owasp_benchmark as OB

VERDICTS = {"true_positive", "false_positive", "uncertain"}
# Tools Claude Code must NOT use -- judging is pure reasoning over the context we
# pass inline, so we forbid file/network/shell access for determinism and speed.
DISALLOWED_TOOLS = "Bash Read Edit Write WebFetch WebSearch Task Glob Grep NotebookEdit"


def log(msg: str) -> None:
    print(f"[judge] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Prompt + context
# --------------------------------------------------------------------------- #

def extract_context(repo: Path, rel_path: str, line: Optional[int],
                    context_lines: int = 12) -> str:
    """Return a numbered code window around `line` from repo/rel_path."""
    fpath = repo / rel_path
    if not fpath.exists():
        return f"(source file not found: {rel_path})"
    try:
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"(could not read {rel_path}: {exc})"
    if not lines:
        return "(empty file)"
    if line is None or line < 1:
        lo, hi = 0, min(len(lines), context_lines * 2)
    else:
        lo = max(0, line - 1 - context_lines)
        hi = min(len(lines), line + context_lines)
    out = []
    for i in range(lo, hi):
        marker = ">>" if (line is not None and i == line - 1) else "  "
        out.append(f"{marker}{i + 1:5d}: {lines[i]}")
    return "\n".join(out)


def build_prompt(finding: Dict[str, Any], context: str) -> str:
    cwe = finding.get("cwe") or "unknown"
    rule = finding.get("rule_id") or "unknown"
    path = finding.get("path")
    line = finding.get("line")
    message = finding.get("message") or ""
    return f"""You are a precise application-security triage judge. A static analysis \
tool reported the finding below. Decide whether it is a TRUE positive (a real, \
exploitable vulnerability reachable from untrusted input, or a genuine security \
defect of the stated class) or a FALSE positive (safe code, sanitized/validated \
input, non-reachable, test/mock code, or a mis-classification).

Judge ONLY from the code shown. If the shown context is insufficient to decide, \
answer "uncertain". Do not assume unseen sanitization exists, and do not assume \
unseen exploitability exists.

Finding:
- Rule: {rule}
- CWE: {cwe}
- Location: {path}:{line}
- Tool message: {message}

Code (>> marks the reported line):
{context}

Respond with ONLY a single JSON object, no prose and no markdown fences:
{{"verdict":"true_positive"|"false_positive"|"uncertain","confidence":0.0-1.0,\
"cwe":"CWE-XX or null","reasoning":"one or two sentences"}}"""


# --------------------------------------------------------------------------- #
# Claude Code invocation + parsing
# --------------------------------------------------------------------------- #

def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Best-effort: pull the first balanced {...} JSON object out of `text`."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1:]
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def judge_finding(finding: Dict[str, Any], context: str, model: str,
                  timeout: int = 180) -> Dict[str, Any]:
    """Run `claude -p` once for one finding. Returns a verdict record.

    Never raises for a bad model reply -- records status "error" instead.
    """
    prompt = build_prompt(finding, context)
    cmd = ["claude", "-p", prompt, "--model", model,
           "--output-format", "json", "--disallowedTools", DISALLOWED_TOOLS]
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"verdict": "error", "error": f"claude -p timed out after {timeout}s"}
    if proc.returncode != 0:
        return {"verdict": "error",
                "error": f"claude -p exit {proc.returncode}: {proc.stderr.strip()[:300]}"}

    try:
        envelope = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"verdict": "error", "error": "claude -p output was not JSON",
                "raw": proc.stdout[:500]}
    if envelope.get("is_error") or envelope.get("api_error_status"):
        return {"verdict": "error",
                "error": f"claude api error: {envelope.get('api_error_status')}"}

    result_text = envelope.get("result", "")
    obj = _extract_json_object(result_text)
    if not obj or obj.get("verdict") not in VERDICTS:
        return {"verdict": "error", "error": "could not parse verdict",
                "raw": result_text[:500]}

    model_used = next(iter((envelope.get("modelUsage") or {}).keys()), model)
    return {
        "verdict": obj["verdict"],
        "confidence": obj.get("confidence"),
        "judged_cwe": obj.get("cwe"),
        "reasoning": obj.get("reasoning", ""),
        "model": model_used,
        "cost_usd": envelope.get("total_cost_usd"),
    }


# --------------------------------------------------------------------------- #
# Ground-truth assembly
# --------------------------------------------------------------------------- #

def to_ground_truth_record(finding: Dict[str, Any], verdict: Dict[str, Any],
                           commit: str) -> Dict[str, Any]:
    return {
        "repo": finding.get("repo"),
        "commit": commit,
        "cwe": finding.get("cwe"),
        "path": finding.get("path"),
        "line": finding.get("line"),
        "description": (verdict.get("reasoning") or finding.get("message") or "")[:500],
        "source": f"claude_code:{verdict.get('model', 'unknown')}",
        "status": verdict["verdict"],            # true_positive | false_positive | uncertain | error
        "judge_confidence": verdict.get("confidence"),
        "tool": finding.get("tool", "frame"),
        "rule_id": finding.get("rule_id"),
    }


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {"true_positive": 0, "false_positive": 0, "uncertain": 0, "error": 0}
    total_cost = 0.0
    for r in records:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    tp, fp = counts["true_positive"], counts["false_positive"]
    decided = tp + fp
    precision = round(tp / decided, 4) if decided else None
    return {
        "counts": counts,
        "judged_precision": precision,
        "judged_precision_note": (
            "TP / (TP + FP) over findings the judge decided (uncertain/error "
            "excluded). This is model-adjudicated precision of the tool's "
            "findings, NOT recall or F1 -- the judge cannot find missed bugs."
        ),
    }


# --------------------------------------------------------------------------- #
# Validation against BenchmarkJava real labels
# --------------------------------------------------------------------------- #

def validate_against_benchmarkjava(records: List[Dict[str, Any]],
                                   repo: Path) -> Dict[str, Any]:
    """Compare judge verdicts to BenchmarkJava's real expectedresults labels.

    For each judged finding located in a BenchmarkTestNNNNN file, the real label
    is whether that test case is a genuine vulnerability of the finding's CWE.
    Measures how often the judge agrees with ground truth -- i.e. how much to
    trust the judge on unlabeled repos.
    """
    expected = OB.load_expected_results(repo)
    # (test name, category) -> is_real
    real: Dict[str, bool] = {}
    for e in expected:
        real[e["name"].lower()] = e["is_real"] and True
    cat_of: Dict[str, str] = {e["name"].lower(): e["category"] for e in expected}

    import re
    name_re = re.compile(r"(BenchmarkTest\d+)", re.IGNORECASE)
    agree = disagree = skipped = 0
    rows = []
    for r in records:
        if r["status"] not in ("true_positive", "false_positive"):
            skipped += 1
            continue
        m = name_re.search(r.get("path") or "")
        if not m:
            skipped += 1
            continue
        name = m.group(1).lower()
        if name not in real:
            skipped += 1
            continue
        # Real label applies to the file's designated category; only compare when
        # the finding's category matches the test's category.
        fcat = OB.cwe_to_category(r.get("cwe"))
        if fcat != cat_of.get(name):
            skipped += 1
            continue
        judged_tp = r["status"] == "true_positive"
        truth_tp = real[name]
        if judged_tp == truth_tp:
            agree += 1
        else:
            disagree += 1
        rows.append({"name": name, "judged_tp": judged_tp, "truth_tp": truth_tp})
    total = agree + disagree
    return {
        "judge_vs_truth_agreement": round(agree / total, 4) if total else None,
        "agree": agree, "disagree": disagree, "skipped": skipped,
        "note": ("Agreement between the Claude judge and BenchmarkJava's real "
                 "labels on findings whose category matches the test case. Higher "
                 "= the judge is more trustworthy on unlabeled repos."),
    }


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def _git_commit(repo: Path) -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo),
                       check=False, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="judge_ground_truth",
        description="Adjudicate findings with Claude Code (headless) to build ground truth.")
    p.add_argument("--repo", required=True, type=Path)
    p.add_argument("--findings", required=True, type=Path,
                   help="Normalized findings JSON (frame.json / semgrep.json / findings.json)")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--model", default="sonnet",
                   help="Claude Code model (default: sonnet = Sonnet 5)")
    p.add_argument("--max-findings", type=int, default=None,
                   help="Cap findings judged (cost control; logged).")
    p.add_argument("--delay", type=float, default=1.0,
                   help="Seconds to wait between calls (judge slowly; default 1.0).")
    p.add_argument("--context-lines", type=int, default=12)
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--validate", action="store_true",
                   help="Also compare verdicts to BenchmarkJava real labels (repo must be BenchmarkJava).")
    args = p.parse_args(argv)

    if shutil.which("claude") is None:
        log("ERROR: the `claude` CLI (Claude Code) is not on PATH. It is required "
            "for headless judging. Install/authenticate Claude Code first.")
        return 2
    if not args.repo.exists():
        log(f"ERROR: repo not found: {args.repo}")
        return 2
    if not args.findings.exists():
        log(f"ERROR: findings not found: {args.findings}")
        return 2

    findings = json.loads(args.findings.read_text(encoding="utf-8"))
    if args.max_findings is not None and len(findings) > args.max_findings:
        log(f"COVERAGE LIMITED: judging {args.max_findings} of {len(findings)} findings")
        findings = findings[:args.max_findings]
    commit = _git_commit(args.repo)
    log(f"judging {len(findings)} findings with claude -p --model {args.model} "
        f"(one by one, {args.delay}s apart)")

    records: List[Dict[str, Any]] = []
    total_cost = 0.0
    for i, finding in enumerate(findings, 1):
        ctx = extract_context(args.repo, finding.get("path") or "",
                              finding.get("line"), args.context_lines)
        verdict = judge_finding(finding, ctx, args.model, timeout=args.timeout)
        rec = to_ground_truth_record(finding, verdict, commit)
        records.append(rec)
        if verdict.get("cost_usd"):
            total_cost += verdict["cost_usd"]
        log(f"  [{i}/{len(findings)}] {finding.get('path')}:{finding.get('line')} "
            f"{finding.get('cwe')} -> {rec['status']} "
            f"(conf={rec.get('judge_confidence')})")
        # Persist incrementally so a long slow run is never lost.
        args.output.write_text(json.dumps(records, indent=2), encoding="utf-8")
        if i < len(findings) and args.delay > 0:
            time.sleep(args.delay)

    summary = summarize(records)
    summary["total_cost_usd"] = round(total_cost, 4)
    if args.validate:
        try:
            summary["validation"] = validate_against_benchmarkjava(records, args.repo)
        except FileNotFoundError:
            summary["validation"] = {"error": "repo is not an OWASP BenchmarkJava checkout"}

    summary_path = args.output.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log(f"wrote {len(records)} adjudications -> {args.output}")
    log(f"summary: {json.dumps(summary['counts'])} "
        f"judged_precision={summary['judged_precision']} "
        f"cost=${summary['total_cost_usd']}")
    if "validation" in summary and summary["validation"].get("judge_vs_truth_agreement") is not None:
        log(f"judge-vs-truth agreement on BenchmarkJava: "
            f"{summary['validation']['judge_vs_truth_agreement']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
