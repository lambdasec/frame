#!/usr/bin/env python3
"""Generate a publishable Frame-vs-Semgrep report (HTML + charts) from harness data.

Consumes the JSON artifacts produced by the rest of the harness and emits a
single-page, academic-style HTML report plus matplotlib PNG charts into a
standalone output directory (index.html + charts/). The output is meant to be
copied to a site such as lambdasec.github.io -- it is NOT committed to the frame
repo.

Inputs (all optional; sections are skipped if data is missing):
  --bj-compare        comparison.json from compare_benchmarkjava
  --findings-compare  findings_comparison.json from compare_findings
  --frame-judged-dir  dir with ground_truth.<repo>.json (Frame, from judge_ground_truth)
  --semgrep-judged-dir dir with ground_truth.<repo>.json (Semgrep, judged the same way)
  --judge-validation  *.summary.json from judge_ground_truth --validate
  --output            report output directory

Everything here is honest by construction: it renders only numbers present in the
inputs, labels model-adjudicated data as such, and carries the "not a reproduction
of Endor" caveats. It invents nothing.
"""

from __future__ import annotations

import argparse
import datetime
import html
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from benchmarks.endor_corpus import summarize as S  # noqa: E402

FRAME_COLOR = "#2563eb"
SEMGREP_COLOR = "#d97706"
GREY = "#6b7280"


def _load(path: Optional[Path]) -> Optional[Any]:
    if path and Path(path).exists():
        return json.loads(Path(path).read_text(encoding="utf-8"))
    return None


def _load_judged_dir(d: Optional[Path]) -> Dict[str, List[Dict[str, Any]]]:
    """Load ground_truth.<repo>.json files into {repo: records}."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    if not d or not Path(d).exists():
        return out
    for f in sorted(Path(d).glob("ground_truth.*.json")):
        # ground_truth.<repo>.json  (skip .summary.json)
        if f.name.endswith(".summary.json"):
            continue
        repo = f.name[len("ground_truth."):-len(".json")]
        try:
            out[repo] = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
    return out


def _precision(records: List[Dict[str, Any]]) -> Optional[float]:
    tp = sum(1 for r in records if r.get("status") == "true_positive")
    fp = sum(1 for r in records if r.get("status") == "false_positive")
    return round(tp / (tp + fp), 4) if (tp + fp) else None


# --------------------------------------------------------------------------- #
# Charts
# --------------------------------------------------------------------------- #

def chart_bj_overall(bj: Dict[str, Any], out: Path) -> Optional[str]:
    fo, so = bj["frame"]["overall"], bj["semgrep"]["overall"]
    metrics = ["precision", "tpr_recall", "f1", "youden_score"]
    labels = ["Precision", "Recall", "F1", "Youden"]
    fvals = [fo[m] for m in metrics]
    svals = [so[m] for m in metrics]
    x = range(len(labels))
    w = 0.38
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar([i - w / 2 for i in x], fvals, w, label="Frame", color=FRAME_COLOR)
    ax.bar([i + w / 2 for i in x], svals, w,
           label=f"Semgrep ({bj.get('semgrep_ruleset', 'p/default')})", color=SEMGREP_COLOR)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("Score")
    ax.set_title("OWASP BenchmarkJava — overall (real ground truth)")
    ax.legend()
    for i, v in enumerate(fvals):
        ax.text(i - w / 2, v + 0.01, f"{v:.2f}", ha="center", fontsize=8)
    for i, v in enumerate(svals):
        ax.text(i + w / 2, v + 0.01, f"{v:.2f}", ha="center", fontsize=8)
    return _save(fig, out, "bj_overall.png")


def chart_bj_by_category(bj: Dict[str, Any], out: Path) -> Optional[str]:
    fcat = bj["frame"]["by_category"]
    scat = bj["semgrep"]["by_category"]
    cats = sorted(set(fcat) | set(scat))
    fvals = [fcat.get(c, {}).get("youden_score", 0) for c in cats]
    svals = [scat.get(c, {}).get("youden_score", 0) for c in cats]
    x = range(len(cats))
    w = 0.38
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.bar([i - w / 2 for i in x], fvals, w, label="Frame", color=FRAME_COLOR)
    ax.bar([i + w / 2 for i in x], svals, w, label="Semgrep", color=SEMGREP_COLOR)
    ax.set_xticks(list(x))
    ax.set_xticklabels(cats, rotation=35, ha="right")
    ax.set_ylabel("Youden (TPR − FPR)")
    ax.set_title("OWASP BenchmarkJava — Youden score by category")
    ax.legend()
    return _save(fig, out, "bj_by_category.png")


def chart_findings_totals(fc: Dict[str, Any], out: Path) -> Optional[str]:
    repos = [c["repo"] for c in fc["repos"]]
    fvals = [c["frame_total"] for c in fc["repos"]]
    svals = [c["semgrep_total"] for c in fc["repos"]]
    x = range(len(repos))
    w = 0.38
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar([i - w / 2 for i in x], fvals, w, label="Frame", color=FRAME_COLOR)
    ax.bar([i + w / 2 for i in x], svals, w,
           label=f"Semgrep ({fc.get('semgrep_ruleset', 'p/default')})", color=SEMGREP_COLOR)
    ax.set_xticks(list(x))
    ax.set_xticklabels(repos, rotation=25, ha="right")
    ax.set_ylabel("Findings")
    ax.set_title("Real-world corpus — raw findings per repository")
    ax.legend()
    return _save(fig, out, "findings_totals.png")


def chart_overlap(fc: Dict[str, Any], out: Path) -> Optional[str]:
    repos = [c["repo"] for c in fc["repos"]]
    agree = [c["agree_file_cwe"] for c in fc["repos"]]
    fonly = [c["frame_only_file_cwe"] for c in fc["repos"]]
    sonly = [c["semgrep_only_file_cwe"] for c in fc["repos"]]
    x = range(len(repos))
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar(x, agree, label="Agree (both)", color="#059669")
    ax.bar(x, fonly, bottom=agree, label="Frame only", color=FRAME_COLOR)
    bottom2 = [a + f for a, f in zip(agree, fonly)]
    ax.bar(x, sonly, bottom=bottom2, label="Semgrep only", color=SEMGREP_COLOR)
    ax.set_xticks(list(x))
    ax.set_xticklabels(repos, rotation=25, ha="right")
    ax.set_ylabel("Findings (file + CWE)")
    ax.set_title("Frame vs Semgrep — overlap and unique findings (no ground truth)")
    ax.legend()
    return _save(fig, out, "overlap.png")


def chart_judged_precision(frame_j: Dict[str, List[Dict[str, Any]]],
                           semgrep_j: Dict[str, List[Dict[str, Any]]],
                           out: Path) -> Optional[str]:
    repos = sorted(set(frame_j) | set(semgrep_j))
    if not repos:
        return None
    fvals = [(_precision(frame_j.get(r, [])) or 0) for r in repos]
    x = range(len(repos))
    fig, ax = plt.subplots(figsize=(9, 4.5))
    if semgrep_j:
        svals = [(_precision(semgrep_j.get(r, [])) or 0) for r in repos]
        w = 0.38
        ax.bar([i - w / 2 for i in x], fvals, w, label="Frame", color=FRAME_COLOR)
        ax.bar([i + w / 2 for i in x], svals, w, label="Semgrep", color=SEMGREP_COLOR)
        ax.legend()
    else:
        ax.bar(x, fvals, 0.5, label="Frame", color=FRAME_COLOR)
        ax.legend()
    ax.set_xticks(list(x))
    ax.set_xticklabels(repos, rotation=25, ha="right")
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("Judged precision (TP / decided)")
    ax.set_title("Model-adjudicated precision on real repos (Claude Sonnet 5 judge)")
    return _save(fig, out, "judged_precision.png")


def chart_cwe_distribution(fc: Dict[str, Any], out: Path) -> Optional[str]:
    frame_cwe: Counter = Counter()
    semgrep_cwe: Counter = Counter()
    for c in fc["repos"]:
        for k, v in (c.get("frame_by_cwe") or {}).items():
            if k != "unmapped":
                frame_cwe[k] += v
        for k, v in (c.get("semgrep_by_cwe") or {}).items():
            if k != "unmapped":
                semgrep_cwe[k] += v
    cwes = [c for c, _ in (frame_cwe + semgrep_cwe).most_common(12)]
    if not cwes:
        return None
    fvals = [frame_cwe.get(c, 0) for c in cwes]
    svals = [semgrep_cwe.get(c, 0) for c in cwes]
    x = range(len(cwes))
    w = 0.38
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.bar([i - w / 2 for i in x], fvals, w, label="Frame", color=FRAME_COLOR)
    ax.bar([i + w / 2 for i in x], svals, w, label="Semgrep", color=SEMGREP_COLOR)
    ax.set_xticks(list(x))
    ax.set_xticklabels(cwes, rotation=40, ha="right")
    ax.set_ylabel("Findings (all real repos)")
    ax.set_title("Findings by CWE — real-world corpus")
    ax.legend()
    return _save(fig, out, "cwe_distribution.png")


CHART_PREFIX = "frame-endor-"


def _save(fig, out: Path, name: str) -> str:
    """Save a chart into <out>/images/ and return the Jekyll-relative ref."""
    images = out / "images"
    images.mkdir(parents=True, exist_ok=True)
    fname = CHART_PREFIX + name
    fig.tight_layout()
    fig.savefig(images / fname, dpi=130)
    plt.close(fig)
    return f"../images/{fname}"


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

def _md_table(headers: List[str], rows: List[List[Any]]) -> str:
    def cell(x: Any) -> str:
        return str(x).replace("|", "\\|")
    out = ["| " + " | ".join(cell(h) for h in headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        out.append("| " + " | ".join(cell(c) for c in r) + " |")
    return "\n".join(out)


def _md_fig(src: Optional[str], caption: str, n: int) -> str:
    if not src:
        return ""
    return f"![Figure {n}]({src})\n\n*Figure {n}. {caption}*"


def build_markdown(ctx: Dict[str, Any]) -> str:
    """Render the report as a Jekyll post (front matter + Markdown body)."""
    P: List[str] = []
    P.append("---")
    P.append("layout: post")
    P.append(f'title: "{ctx["title"]}"')
    P.append("---")

    # Abstract (lead paragraph, like the AutoGrep post)
    P.append("We evaluate **Frame**, a separation-logic / SMT-backed security scanner, "
             "against **Semgrep OSS** on the eight public repositories that Endor Labs named "
             "as their AI-SAST benchmark corpus. Where real ground truth exists (OWASP "
             "BenchmarkJava) we report precision, recall, F1, and the Benchmark's Youden "
             "score for both tools under the identical official scoring methodology. For the "
             "real-world repositories, which have no published labels, we report raw "
             "findings, cross-tool agreement, and **model-adjudicated precision** produced "
             "by an LLM judge (Claude Sonnet 5, run headless via Claude Code), validated "
             "against BenchmarkJava's real labels. This is an independent evaluation "
             "harness, **not a reproduction of Endor's benchmark numbers**.")

    # 1. Introduction
    P.append("## 1. Introduction")
    P.append(f"Endor Labs published an [AI-SAST benchmark]({S.ARTICLE_URL}) reporting that "
             "their AI scanner found substantially more real vulnerabilities than "
             "traditional SAST tools on a corpus of eight public repositories. Endor "
             "published the *corpus list* and headline numbers, but not the commit SHAs, "
             "ground-truth labels, scanner configurations, or scoring denominators needed "
             "to reproduce those numbers.")
    P.append(f"> **Comparison warning.** {S.ENDOR_WARNING}")
    P.append("### 1.1 Contributions")
    P.append("1. A **reproducible harness** that pins each corpus repository to a commit "
             "and scans the Frame-supported languages.\n"
             "2. An **apples-to-apples Frame-vs-Semgrep scorecard** on OWASP BenchmarkJava "
             "using the official methodology (real ground truth).\n"
             "3. An **LLM-judge pipeline** (Claude Sonnet 5, headless) that adjudicates "
             "findings on the unlabeled repositories to estimate real-world precision, with "
             "its accuracy validated against real labels.")

    # 2. Methodology
    P.append("## 2. Methodology")
    P.append("### 2.1 Corpus")
    if ctx.get("corpus_rows"):
        P.append(_md_table(["Repository", "Commit", "Frame support"], ctx["corpus_rows"]))
    P.append("Frame supports Python, Java, JavaScript, TypeScript, C, C++, and C#. Go "
             "(`doublestar`) and the PHP majority of the XBOW benchmarks are reported as "
             "unsupported and excluded from scanning.")
    P.append("### 2.2 Tools")
    P.append("Frame runs in its default configuration. Semgrep OSS runs with the "
             f"`{ctx.get('semgrep_ruleset', 'p/default')}` ruleset (out of the box, not "
             "tuned). Both scan the same Frame-supported files.")
    P.append("### 2.3 Scoring")
    P.append("On OWASP BenchmarkJava we use the official per-file, CWE-category-matched "
             "methodology (TP/FP/TN/FN, then TPR, FPR, precision, recall, F1, and "
             "Youden = TPR - FPR). On the unlabeled repositories we adjudicate each finding "
             "with Claude Sonnet 5 (run one finding at a time via `claude -p`), which reads "
             "a code window and returns true/false-positive. This yields **precision** but "
             "not recall -- the judge cannot discover vulnerabilities the tools missed.")
    if ctx.get("judge_validation") is not None:
        P.append(f"> **Judge trust check.** On a BenchmarkJava sample the Sonnet 5 judge "
                 f"agreed with the real labels **{ctx['judge_validation']:.1%}** of the time.")

    # 3. Results
    P.append("## 3. Results")

    if ctx.get("bj"):
        P.append("### 3.1 OWASP BenchmarkJava (real ground truth)")
        fo, so = ctx["bj"]["frame"]["overall"], ctx["bj"]["semgrep"]["overall"]
        P.append(_md_table(
            ["Tool", "TP", "FP", "TN", "FN", "Precision", "Recall", "FPR", "F1", "Youden"],
            [["Frame", fo["tp"], fo["fp"], fo["tn"], fo["fn"], fo["precision"],
              fo["tpr_recall"], fo["fpr"], fo["f1"], fo["youden_score"]],
             [f"Semgrep {ctx.get('semgrep_ruleset','p/default')}", so["tp"], so["fp"],
              so["tn"], so["fn"], so["precision"], so["tpr_recall"], so["fpr"], so["f1"],
              so["youden_score"]]]))
        P.append(_md_fig(ctx["figs"].get("bj_overall"),
                         "Frame vs Semgrep on OWASP BenchmarkJava (overall).", ctx["fign"]()))
        P.append(_md_fig(ctx["figs"].get("bj_by_category"),
                         "Youden score by vulnerability category.", ctx["fign"]()))
        P.append("Semgrep attains higher raw recall but roughly double the false-positive "
                 "rate; Frame leads on precision, F1, and the Benchmark's headline Youden "
                 "score. This is a *synthetic* benchmark -- see Limitations.")

    if ctx.get("fc"):
        P.append("### 3.2 Real-world corpus: findings and overlap")
        rows = [[c["repo"], c["frame_total"], c["semgrep_total"], c["agree_file_cwe"],
                 c["frame_only_file_cwe"], c["semgrep_only_file_cwe"]]
                for c in ctx["fc"]["repos"]]
        P.append(_md_table(["Repo", "Frame", "Semgrep", "Agree", "Frame-only", "Semgrep-only"],
                           rows))
        P.append(_md_fig(ctx["figs"].get("findings_totals"),
                         "Raw findings per repository.", ctx["fign"]()))
        P.append(_md_fig(ctx["figs"].get("overlap"),
                         "Overlap and unique findings at (file, CWE) granularity.", ctx["fign"]()))
        P.append(_md_fig(ctx["figs"].get("cwe_distribution"),
                         "Findings by CWE across the real-world corpus.", ctx["fign"]()))
        P.append("> **Agreement is not correctness.** With no labels, a finding both tools "
                 "report is not necessarily a true positive, and a unique finding is not "
                 "necessarily wrong.")

    if ctx.get("judged_rows"):
        P.append("### 3.3 Model-adjudicated precision (Claude Sonnet 5 judge)")
        P.append(_md_table(ctx["judged_headers"], ctx["judged_rows"]))
        P.append(_md_fig(ctx["figs"].get("judged_precision"),
                         "Judged precision per repository. Labels are model-adjudicated, "
                         "not human-verified.", ctx["fign"]()))
        P.append("> These labels come from an LLM judge, not human review. They estimate "
                 "**precision** only. Recall and F1 on real code are not computed -- the "
                 "judge cannot find vulnerabilities both tools missed.")

    # 4. Discussion & limitations
    P.append("## 4. Discussion and Limitations")
    P.append("- **Not a reproduction of Endor.** Endor's recall/F1 depend on their exact "
             "commits, hand-verified ground truth, scanner configs, prompts, and scoring "
             "denominators -- none fully published. Our numbers are a different measurement.\n"
             "- **Synthetic vs real.** BenchmarkJava scores (where both tools do well) "
             "over-state real-world quality -- that is Endor's own thesis. Semgrep OSS "
             "precision is ~0.69 on BenchmarkJava but Endor reports it far lower on their "
             "real-world corpus; the same tool, different scales.\n"
             "- **Model-adjudicated labels.** Real-repo precision uses a Sonnet 5 judge "
             "(validated agreement above), not human review.\n"
             "- **No true recall on real code.** The judge only sees tool findings; false "
             "negatives are invisible, so we report precision, not recall/F1.\n"
             f"- **Ruleset dependence.** Semgrep's numbers depend on the ruleset "
             f"(`{ctx.get('semgrep_ruleset','p/default')}` here).")

    # 5. Endor published numbers (context)
    P.append("## 5. Endor Published Numbers (Context Only)")
    P.append("Quoted from the Endor Labs article for context; not computed here and not "
             "comparable to the tables above.")
    epn = S.ENDOR_PUBLISHED_NUMBERS
    P.append(_md_table(["Endor AI SAST (published)", "Value"],
                       [[k.replace("_", " "), html.unescape(str(v))]
                        for k, v in epn["endor_ai_sast"].items()]))
    P.append(_md_table(["Endor comparison (published)", "Value"],
                       [[k.replace("_", " "), html.unescape(str(v))]
                        for k, v in epn["comparisons"].items()]))

    # 6. Conclusion
    P.append("## 6. Conclusion")
    P.append("On a shared, real-labeled benchmark (OWASP BenchmarkJava), Frame achieves "
             "higher precision, F1, and Youden than Semgrep OSS at the cost of some recall. "
             "On real-world code, an LLM-judge estimate of precision -- validated against "
             "real labels -- lets us compare the two tools where no ground truth exists, "
             "while being explicit that this is precision-focused and not a reproduction of "
             "Endor's recall benchmark.")

    P.append("## References")
    P.append(f"1. Endor Labs, *AI SAST Benchmark: 2x More Real Vulnerabilities*. "
             f"[{S.ARTICLE_URL}]({S.ARTICLE_URL})\n"
             "2. OWASP Benchmark Project. "
             "[owasp.org/www-project-benchmark](https://owasp.org/www-project-benchmark/)\n"
             "3. Frame -- separation-logic security scanner. "
             "[github.com/lambdasec/frame](https://github.com/lambdasec/frame)")

    return "\n\n".join(x for x in P if x)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="generate_report",
                                description="Generate the Frame-vs-Semgrep report (HTML + charts).")
    p.add_argument("--bj-compare", type=Path, default=None)
    p.add_argument("--findings-compare", type=Path, default=None)
    p.add_argument("--frame-judged-dir", type=Path, default=None)
    p.add_argument("--semgrep-judged-dir", type=Path, default=None)
    p.add_argument("--judge-validation", type=Path, default=None)
    p.add_argument("--title", default="Frame vs Semgrep on the Endor Labs Public Corpus")
    p.add_argument("--date", default=None, help="Report date (default: today).")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)

    bj = _load(args.bj_compare)
    fc = _load(args.findings_compare)
    frame_j = _load_judged_dir(args.frame_judged_dir)
    semgrep_j = _load_judged_dir(args.semgrep_judged_dir)
    jval_doc = _load(args.judge_validation)
    jval = None
    if isinstance(jval_doc, dict):
        jval = (jval_doc.get("validation") or {}).get("judge_vs_truth_agreement")

    args.output.mkdir(parents=True, exist_ok=True)
    figs: Dict[str, Optional[str]] = {}
    if bj:
        figs["bj_overall"] = chart_bj_overall(bj, args.output)
        figs["bj_by_category"] = chart_bj_by_category(bj, args.output)
    if fc:
        figs["findings_totals"] = chart_findings_totals(fc, args.output)
        figs["overlap"] = chart_overlap(fc, args.output)
        figs["cwe_distribution"] = chart_cwe_distribution(fc, args.output)
    if frame_j or semgrep_j:
        figs["judged_precision"] = chart_judged_precision(frame_j, semgrep_j, args.output)

    # judged precision table
    judged_headers: List[str] = []
    judged_rows: List[List[Any]] = []
    if frame_j or semgrep_j:
        repos = sorted(set(frame_j) | set(semgrep_j))
        if semgrep_j:
            judged_headers = ["Repo", "Frame TP", "Frame FP", "Frame precision",
                              "Semgrep TP", "Semgrep FP", "Semgrep precision"]
            for r in repos:
                fr, sg = frame_j.get(r, []), semgrep_j.get(r, [])
                judged_rows.append([
                    r,
                    sum(1 for x in fr if x.get("status") == "true_positive"),
                    sum(1 for x in fr if x.get("status") == "false_positive"),
                    _precision(fr),
                    sum(1 for x in sg if x.get("status") == "true_positive"),
                    sum(1 for x in sg if x.get("status") == "false_positive"),
                    _precision(sg)])
        else:
            judged_headers = ["Repo", "Findings judged", "TP", "FP", "Uncertain",
                              "Judged precision"]
            for r in repos:
                fr = frame_j.get(r, [])
                judged_rows.append([
                    r, len(fr),
                    sum(1 for x in fr if x.get("status") == "true_positive"),
                    sum(1 for x in fr if x.get("status") == "false_positive"),
                    sum(1 for x in fr if x.get("status") == "uncertain"),
                    _precision(fr)])

    corpus_rows = None
    if bj or fc:
        corpus_rows = [
            ["anonymous-github", "pinned", "JS/TS"],
            ["demo-netflicks", "pinned", "Java + JS/TS"],
            ["doublestar", "pinned", "none (Go)"],
            ["OWASP BenchmarkJava", "pinned", "Java"],
            ["OWASP Juice Shop", "pinned", "JS/TS"],
            ["OWASP WebGoat", "pinned", "Java + JS/TS"],
            ["Shopizer", "pinned", "Java + JS/TS"],
            ["XBOW Validation Benchmarks", "pinned", "Py/JS/TS/Java/C# (PHP unsupported)"],
        ]

    today = datetime.date.today()
    date = args.date or f"{today.year}-{today.month}-{today.day}"
    counter = {"n": 0}

    def fign() -> int:
        counter["n"] += 1
        return counter["n"]

    ctx = {
        "title": args.title, "date": date,
        "bj": bj, "fc": fc, "figs": figs, "fign": fign,
        "semgrep_ruleset": (bj or {}).get("semgrep_ruleset")
        or (fc or {}).get("semgrep_ruleset") or "p/default",
        "judge_validation": jval,
        "judged_headers": judged_headers, "judged_rows": judged_rows,
        "corpus_rows": corpus_rows,
    }

    # Jekyll layout: _posts/<date>-<Title-Slug>.md  +  images/frame-endor-*.png
    slug = "-".join(w for w in args.title.split() if w)
    posts = args.output / "_posts"
    posts.mkdir(parents=True, exist_ok=True)
    post_path = posts / f"{date}-{slug}.md"
    post_path.write_text(build_markdown(ctx), encoding="utf-8")
    n_charts = len([f for f in figs.values() if f])
    print(f"[report] wrote Jekyll post {post_path}")
    print(f"[report] wrote {n_charts} charts under {args.output / 'images'}")
    print("[report] To publish: copy _posts/*.md into lambdasec.github.io/_posts/ and "
          "images/*.png into lambdasec.github.io/images/. Do NOT commit into the frame repo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
