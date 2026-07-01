# Endor Corpus Benchmark

An **evaluation harness** that runs Frame over the public repositories that
Endor Labs named as their AI-SAST benchmark corpus, based on their article:

**Endor Labs, *"AI SAST Benchmark: 2x More Real Vulnerabilities"***
<https://www.endorlabs.com/learn/ai-sast-benchmark-2x-more-real-vulnerabilities>

> **This is NOT a reproduction of Endor's benchmark.** Endor published the corpus
> *list* but not commit SHAs, ground-truth labels, scanner configurations, model
> prompts, run-aggregation logic, or their verified findings database. This is an
> independent harness over the same public corpus; its numbers are a different
> quantity from Endor's published recall/F1. The article is used **only** for the
> corpus list, methodological context, and Endor's published headline numbers
> (quoted below). See
> [Why exact Endor numbers cannot be reproduced](#why-exact-endor-numbers-cannot-be-reproduced).

## What this benchmark covers — and what it leaves out

Endor's corpus is 8 repositories. This benchmark scores Frame on the **5
real-world applications** in it, and deliberately excludes the other 3:

| Excluded | Why |
| --- | --- |
| **OWASP BenchmarkJava** | Already covered by Frame's **main benchmarks** (the `owasp_java` division scores the *same* repo + `expectedresults-1.2.csv`). Scored separately here via [`score_benchmarkjava.py`](score_benchmarkjava.py); its numbers are reported in the results, not merged into the real-world ground truth. |
| **doublestar** | **Go** — a language Frame does not support. |
| **XBOW Validation Benchmarks** | Majority **PHP** — a language Frame does not support (only its incidental Py/JS/TS/Java/C# files, if any, are scanned). |

So the benchmark proper is the **5 real-world apps**: `anonymous-github`,
`demo-netflicks`, `juice-shop`, `webgoat`, `shopizer`.

## Ground truth (pooled, not complete)

Real-world repos ship no vulnerability labels, so this benchmark builds a
**pooled ground truth**: it runs Frame **and** Semgrep OSS, then adjudicates every
finding with an LLM judge (Claude Sonnet 5, headless via `claude -p`), and keeps
the union of judge-confirmed true positives —
[`ground_truth.pooled.json`](ground_truth.pooled.json) (**106 confirmed
vulnerabilities** across the 5 apps). See
[Pooled ground truth](#pooled-ground-truth-reusable).

> ⚠️ **This is a lower bound, not complete ground truth.** It contains only vulns
> that Frame *or* Semgrep found and the judge confirmed. Vulnerabilities **both
> tools missed are absent**, so the true count is ≥ 106 (likely well above it —
> only 4 of the 106 were found by *both* tools). A finding *absent* from the set is
> therefore **not** necessarily a false positive. The labels are also
> **model-adjudicated**, not human-verified (validated at ~0.89 agreement against
> BenchmarkJava's real labels). Endor closed this gap by pooling *many* tools plus
> manual review; this harness uses two tools + an LLM judge.

## Corpus

| Slug | Repository | Clone URL | Frame support |
| --- | --- | --- | --- |
| `anonymous-github` | anonymous-github | https://github.com/tdurieux/anonymous_github.git | JS/TS |
| `demo-netflicks` | demo-netflicks | https://github.com/Contrast-Security-OSS/demo-netflicks.git | Java + JS/TS |
| `doublestar` | doublestar | https://github.com/bmatcuk/doublestar.git | **none (Go)** |
| `benchmarkjava` | OWASP BenchmarkJava | https://github.com/OWASP-Benchmark/BenchmarkJava.git | Java |
| `juice-shop` | OWASP Juice Shop | https://github.com/juice-shop/juice-shop.git | JS/TS |
| `webgoat` | OWASP WebGoat | https://github.com/WebGoat/WebGoat.git | Java + JS/TS |
| `shopizer` | Shopizer | https://github.com/shopizer-ecommerce/shopizer.git | Java + JS/TS |
| `xbow-validation-benchmarks` | XBOW Validation Benchmarks | https://github.com/xbow-engineering/validation-benchmarks.git | Py/JS/TS/Java/C# (PHP unsupported) |

All 8 URLs were verified reachable at the time of writing; none required
correction. The authoritative machine-readable manifest is [`corpus.yaml`](corpus.yaml).

## Ground-truth availability (surveyed)

Only one corpus repo ships machine-readable, file/line-level ground truth:

| Repo | Public ground truth? | Usable for scoring? |
| --- | --- | --- |
| **OWASP BenchmarkJava** | **Yes** — `expectedresults-1.2.csv` (2740 labeled cases: category, real/safe flag, CWE) | **Yes** — see [Scoring on OWASP BenchmarkJava](#scoring-on-owasp-benchmarkjava-real-ground-truth) |
| XBOW Validation Benchmarks | Partial — per-benchmark `benchmark.json` with coarse CWE `tags` (one class per benchmark, no line) | Weak, and mostly **PHP** (unsupported by Frame) |
| OWASP Juice Shop | Only `data/static/challenges.yml` (CTF challenge metadata, not line-level SAST labels) | No |
| WebGoat / Shopizer / demo-netflicks / anonymous-github / doublestar | None found | No |

Because of this, the harness computes precision/recall/F1 **only** on
BenchmarkJava. For the other repos it reports raw findings only.

## Supported vs unsupported languages

Frame currently supports: **Python, Java, JavaScript, TypeScript, C, C++, C#**.

Frame does **not** support **Go** or **PHP** (nor Ruby). Consequences:

- `doublestar` is Go-only → cloned and pinned for provenance, but produces no
  Frame findings; all Go files are reported as *unsupported*.
- `xbow-validation-benchmarks` is largely PHP → only its Python/JS/TS/Java/C#
  files (where present) are scanned; PHP files are counted as *unsupported*.

Unsupported portions are **explicitly reported**, never silently ignored.

## Setup

```bash
pip install -e ".[scan]"          # Frame + tree-sitter grammars
pip install pyyaml                 # manifest parsing
# optional baseline:
pip install semgrep
```

`git` must be on `PATH`. The harness clones with full history (so `--use-lock`
can check out arbitrary pinned commits), which requires network access and
several GB of disk for the full corpus.

## Commands

Clone/update the repos and record the commit SHAs actually scanned (writes
[`corpus.lock.json`](corpus.lock.json)):

```bash
python -m benchmarks.endor_corpus.run_endor_corpus \
  --workspace /tmp/endor-corpus \
  --output /tmp/frame-endor-results \
  --lock
```

Re-run reproducibly against the exact pinned commits:

```bash
python -m benchmarks.endor_corpus.run_endor_corpus \
  --workspace /tmp/endor-corpus \
  --output /tmp/frame-endor-results \
  --use-lock
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `--repos a,b,c` | Restrict to specific repo slugs (faster iteration). |
| `--max-files-per-repo N` | Cap scanned files per repo. **Reduces coverage** — the drop is logged and recorded in `coverage_note`. |
| `--no-verify` | Skip Frame's Z3 verification (much faster, more false positives). |
| `--timeout MS` | Frame per-check verification timeout (default 5000). |
| `--continue-on-error` | Do not exit non-zero when a repo fails to clone or a file crashes the scanner. |
| `--with-semgrep` | Also run Semgrep as a public baseline (see below). |
| `--semgrep-config P` | Semgrep ruleset (default `p/default`; e.g. `p/security-audit`). |
| `--ground-truth FILE` | Compute precision/recall/F1 against a **real** label file (see below). |

The full corpus is large and Frame's verified scan is slow (seconds per file).
Expect a full run to take a long time; use `--repos` / `--max-files-per-repo` /
`--no-verify` while iterating.

### Behavior contract

- `--lock` and `--use-lock` are mutually exclusive. With neither, repos are
  cloned/updated at current `HEAD` and results are **not** pinned (mode
  `unpinned`).
- `--use-lock` with no lock file **fails** with a clear error (exit 1).
- A repo that fails to clone is a **hard failure** (exit 1) unless
  `--continue-on-error`.
- A file that crashes the scanner is recorded in `scanner_errors` and is a hard
  failure (exit 1) unless `--continue-on-error`.
- `--with-semgrep` without `semgrep` installed **fails** with install
  instructions (exit 2).

## Output files

```
<output>/results/
  summary.json            # machine-readable rollup (+ Endor context, warning)
  summary.md              # human-readable report (16 sections)
  findings.json           # all normalized Frame findings, combined
  <repo>/
    frame.sarif           # Frame SARIF (SARIF 2.1.0)
    frame.json            # normalized findings for this repo
    scan_metadata.json    # commit, timings, file counts, exit code, semgrep status
    semgrep.sarif         # (only with --with-semgrep)
    semgrep.json          # (only with --with-semgrep) normalized
```

Normalized finding schema (`frame.json` / `findings.json`):

```json
{
  "repo": "benchmarkjava",
  "commit": "…",
  "tool": "frame",
  "rule_id": "frame/sql_injection",
  "cwe": "CWE-89",
  "severity": "high",
  "message": "…",
  "path": "src/main/java/…",
  "line": 123,
  "sarif_result_index": 0
}
```

`sarif_result_index` aligns each finding to the corresponding result in the
repo's combined `frame.sarif`.

### A note on Frame SARIF and CWE

Frame's SARIF (`ScanResult.to_sarif`) emits `ruleId`, `level`, `message`, file
path and line, but **not** CWE ids or fingerprints. The normalized `frame.json`
carries the authoritative CWE and severity taken directly from the scanner's
`Vulnerability` objects. The standalone SARIF parser in
[`summarize.py`](summarize.py) (`parse_frame_sarif`) *derives* CWE from the rule
id using Frame's own `CWE_MAP` (e.g. `frame/sql_injection → CWE-89`) — it never
invents CWE ids, and returns `None` when a CWE cannot be safely derived. Because
SARIF `level` collapses critical+high into `error`, the parser's SARIF-only
severity is approximate; prefer `frame.json` for severity.

## How to interpret results

- The counts are **raw Frame findings**, not verified true positives. A finding
  count is not a quality score.
- Only supported-language portions were scanned; unsupported portions contribute
  zero findings *by construction*, so absence of findings there means "not
  analyzed", not "clean".
- Precision/recall/F1 are printed **only** when you pass `--ground-truth` with a
  real label file. Never otherwise.

## Endor published numbers for context only

Quoted from the reference article. **Context only** — not computed by this
harness, and not to be treated as Frame's results.

**Endor AI SAST (as published):**

- True positives: *"found 192 real vulnerabilities"*
- Unique findings: *"63 of its findings were caught by no other tool in the test"*
- CWE coverage: *"detected 64 of the 106 CWE types in the benchmark"*
- Recall: *"led the test on … recall (0.435)"*
- F1: *"led the test on … F1 (0.465)"*
- High severity: *"catching 4x more high-severity vulnerabilities as the strongest traditional tool (72 vs 17)"*
- Critical severity: *"leading on critical (46 vs 38)"*

**Endor's published comparisons:**

- vs **Claude (Opus 4.7)**: *"2.6x what Claude (Opus 4.7) caught"*; Claude precision *"0.718"* with near-bottom recall; Claude unique findings *"18"*; Claude CWE types *"36"*.
- vs **Codex (GPT-5.5)**: *"3.5x what Codex (GPT-5.5) caught"*; Codex precision *"0.859"* with near-bottom recall.
- vs **Semgrep OSS**: *"2x more real vulnerabilities compared to Semgrep OSS"*; *"about 60% fewer false positives than Semgrep OSS"*; Semgrep flagged *"over 460"* false positives.
- vs **OpenGrep**: *"60% fewer false positives than … OpenGrep, which flagged over 460 each"*.
- vs **Bearer** / **CodeQL**: no standalone headline number is quoted in the article.

**Endor methodology note:** Endor established ground truth by *"pooling every
tool's true positives, de-duplicating them by hand, adding issues found through
manual review, and verifying each one."* Testing covered *"Java, Python,
JavaScript, TypeScript, C# and Go."*

> **Comparison warning.** Frame results from this harness should not be compared
> directly to Endor's headline numbers unless the same commits, ground-truth
> labels, scanner configurations, model prompts, run aggregation logic, and
> scoring denominators are reconstructed.

## Why exact Endor numbers cannot be reproduced

Endor's recall and F1 depend on inputs the blog post does not publish in
reproducible form:

1. **Exact commits** they scanned (SHAs were not published).
2. Their **manually curated, de-duplicated ground-truth set** (the denominator
   for recall).
3. Each tool's **scanner configuration**, and for AI tools the **prompts**.
4. Their **run-aggregation logic** (how multiple runs were combined).
5. The **scoring denominators** (e.g. all findings vs supported-language only).

Without those, any "Frame vs Endor" number would be apples-to-oranges. This
harness deliberately refuses to print such a comparison.

## How to add ground-truth labels later

1. Copy the schema example (illustrative, **fake**, never read by the runner):

   ```bash
   cp benchmarks/endor_corpus/ground_truth.example.json \
      benchmarks/endor_corpus/ground_truth.json
   ```

2. Replace it with **manually validated** entries:

   ```json
   [
     {
       "repo": "benchmarkjava",
       "commit": "…",
       "cwe": "CWE-89",
       "path": "src/main/java/…",
       "line": 123,
       "description": "SQL injection through unsanitized request parameter",
       "source": "manual_validation",
       "status": "true_positive"
     }
   ]
   ```

3. Run with `--ground-truth`:

   ```bash
   python -m benchmarks.endor_corpus.run_endor_corpus \
     --workspace /tmp/endor-corpus --output /tmp/frame-endor-results \
     --use-lock \
     --ground-truth benchmarks/endor_corpus/ground_truth.json
   ```

**Matching logic:** a Frame finding matches a ground-truth item iff same repo,
same CWE (normalized so `"89" == "CWE-89"`), file-path suffix/basename match, and
line numbers within `±5`. Each ground-truth item is matched at most once. From
the matches the harness reports TP / FP / FN / precision / recall / F1.

## Cross-tool findings comparison (no ground truth)

For the repos without ground truth, [`compare_findings.py`](compare_findings.py)
compares what Frame and Semgrep each *surface* — totals, breakdowns by CWE and
severity, and agreement at (file, CWE) granularity (both-flag vs unique-to-each).
Run the harness with `--with-semgrep`, then:

```bash
python -m benchmarks.endor_corpus.compare_findings \
  --results-dir /tmp/frame-endor-results/results \
  --output /tmp/frame-endor-results/findings-comparison
```

> **Agreement is not correctness.** With no labels, a finding both tools report is
> not necessarily a true positive, and a unique finding is not necessarily wrong.
> This mirrors Endor's "unique findings / complementarity" framing — nothing more.
> No precision/recall/F1 is produced here.

## Model-adjudicated ground truth via Claude Code (Sonnet 5)

Manually validating findings is slow. [`judge_ground_truth.py`](judge_ground_truth.py)
automates the "verify each finding" step using **Claude Code in headless mode**
(`claude -p`) with the **Sonnet 5** model as an LLM judge — one finding at a time,
reading a code window around each finding and returning `true_positive` /
`false_positive` / `uncertain`. It needs the `claude` CLI on `PATH` (no API key).

```bash
# Validate the judge against BenchmarkJava's REAL labels first (trust check):
python -m benchmarks.endor_corpus.judge_ground_truth \
  --repo /tmp/endor-corpus/benchmarkjava \
  --findings /tmp/frame-endor-results/results/benchmarkjava/frame.json \
  --validate --max-findings 40 --output /tmp/bj_judge_validation.json

# Then adjudicate an unlabeled repo, slowly, to produce a ground-truth file:
python -m benchmarks.endor_corpus.judge_ground_truth \
  --repo /tmp/endor-corpus/webgoat \
  --findings /tmp/frame-endor-results/results/webgoat/frame.json \
  --output benchmarks/endor_corpus/ground_truth.webgoat.json \
  --model sonnet --delay 1.0
```

Output is a ground-truth file in the harness schema, with each entry labeled
`source: "claude_code:claude-sonnet-5"` and `status` set to the judge's verdict,
plus a `.summary.json` with judged precision and (in `--validate` mode) the judge's
agreement with real labels. Verdicts are written incrementally, so a long slow run
is never lost.

**Trust check (measured).** On a 12-finding BenchmarkJava sample the Sonnet 5 judge
**agreed with the real `expectedresults` labels 88.9%** of the time (8/9
category-matched cases; it called one genuine weak-hash case a false positive), at
roughly **$0.14 per finding**. Treat the judge as a fast, imperfect stand-in for
manual review — validate it on BenchmarkJava before trusting it elsewhere.

**Honest limitations.**

- Labels are **model-adjudicated, not human-verified** — never conflate them with
  the manual `ground_truth.json`. They carry the `claude_code:*` source so they're
  always distinguishable.
- The judge only sees the *tool's* findings, so it yields **precision** (of the
  flagged findings, how many are real) but **not recall or F1** — it cannot find
  vulnerabilities the tools missed.
- Every verdict comes from a real `claude -p` call; parse failures are recorded as
  `error`, never guessed.

## Scoring on OWASP BenchmarkJava (real ground truth)

OWASP BenchmarkJava is the one corpus repo with usable ground truth, so it is the
only place this harness can honestly compute precision/recall/F1. Its ground truth
is `expectedresults-1.2.csv` (2740 synthetic test cases; each file is one sink of a
given category, flagged `true` = real vulnerability or `false` = safe trap).

[`score_benchmarkjava.py`](score_benchmarkjava.py) reads that CSV and scores Frame
using the **official OWASP Benchmark methodology** (per-category TP/FP/TN/FN, TPR,
FPR, precision, recall, F1, and the Benchmark's Youden score = TPR − FPR):

```bash
# reuse findings already produced by run_endor_corpus.py:
python -m benchmarks.endor_corpus.score_benchmarkjava \
  --repo /tmp/endor-corpus/benchmarkjava \
  --findings /tmp/frame-endor-results/results/benchmarkjava/frame.json \
  --output /tmp/frame-endor-results/benchmarkjava-scorecard

# or scan the checkout directly (no prior run needed):
python -m benchmarks.endor_corpus.score_benchmarkjava \
  --repo /tmp/endor-corpus/benchmarkjava \
  --output /tmp/frame-endor-results/benchmarkjava-scorecard
```

Outputs: `scorecard.json`, `scorecard.md`, and `ground_truth.benchmarkjava.json`
(the real positive labels, in the harness ground-truth schema).

**Reference result** (Frame default config, commit `56f8b33`, BenchmarkJava v1.2):

| TP | FP | TN | FN | Precision | Recall | F1 | Youden |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1149 | 270 | 1055 | 266 | 0.81 | 0.81 | 0.81 | 0.61 |

> ⚠️ **This is the OWASP Benchmark — a _synthetic_ benchmark with its own ground
> truth. It is a real, standalone Frame result, but it is NOT Endor's benchmark
> and NOT comparable to Endor's real-world corpus numbers.** Endor's central thesis
> is precisely that synthetic benchmarks like BenchmarkJava overstate tool quality
> relative to real-world code, so a strong BenchmarkJava score says nothing about
> Endor's aggregate recall/F1. Treat it as "Frame's OWASP Benchmark scorecard",
> full stop.

### Comparing to Semgrep on the *same* benchmark

Endor's published Semgrep numbers (further below) are on **Endor's real-world
corpus**, not on BenchmarkJava, so they are **not** comparable to the scorecard
above. For a fair, same-benchmark Frame-vs-Semgrep comparison, run Semgrep on the
identical BenchmarkJava commit and score it with the identical OWASP methodology
via [`compare_benchmarkjava.py`](compare_benchmarkjava.py):

```bash
# 1) Run Semgrep OSS over the same test files:
semgrep --config p/default --json --metrics=off \
  -o /tmp/semgrep_default.json \
  /tmp/endor-corpus/benchmarkjava/src/main/java/org/owasp/benchmark/testcode

# 2) Score Frame and Semgrep side by side against the same ground truth:
python -m benchmarks.endor_corpus.compare_benchmarkjava \
  --repo /tmp/endor-corpus/benchmarkjava \
  --frame-findings /tmp/frame-endor-results/results/benchmarkjava/frame.json \
  --semgrep-json /tmp/semgrep_default.json \
  --semgrep-ruleset p/default \
  --output /tmp/frame-endor-results/benchmarkjava-compare
```

This writes `comparison.md` / `comparison.json` with overall and per-category
Frame-vs-Semgrep tables. Matching is by **category** (via sibling-CWE aliases, e.g.
Semgrep tags weak crypto `CWE-326` while BenchmarkJava uses `CWE-327`), mirroring
the official OWASP scorer so neither tool is penalized for CWE-number choices.

**Reference result** (BenchmarkJava v1.2, commit `56f8b33`, 2740 cases; Frame
default config vs Semgrep OSS `p/default`):

| Tool | TP | FP | TN | FN | Precision | Recall | FPR | F1 | Youden |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Frame** | 1149 | 270 | 1055 | 266 | **0.81** | 0.81 | **0.20** | **0.81** | **0.61** |
| Semgrep `p/default` | 1292 | 585 | 740 | 123 | 0.69 | **0.91** | 0.44 | 0.78 | 0.47 |

Reading it honestly: **Semgrep has higher raw recall (0.91 vs 0.81)** but **more
than double the false-positive rate (0.44 vs 0.20)**, so Frame leads on precision,
F1, and the Benchmark's headline **Youden score (0.61 vs 0.47)** — its taint
analysis is more precise at telling each test's vulnerable variant from its safe
variant. Both tools are perfect on `crypto`/`securecookie`; Semgrep edges
`weakrand`/`pathtraver`, Frame edges `hash` and the injection categories.

**Caveats:** Semgrep's score depends on the ruleset chosen (`p/default` is Semgrep
OSS out of the box, not a tuned config); the ruleset is recorded in the output. And
this is still a *synthetic* benchmark — see the warning above; do not extrapolate to
real-world code. The OWASP Benchmark project also publishes its own official tool
scorecards (<https://owasp.org/www-project-benchmark/>).

## Optional Semgrep baseline

```bash
python -m benchmarks.endor_corpus.run_endor_corpus \
  --workspace /tmp/endor-corpus --output /tmp/frame-endor-results \
  --use-lock --with-semgrep --semgrep-config p/security-audit
```

Semgrep runs over the same supported-file portions (via `--include *.<ext>`),
writing `semgrep.sarif` and a normalized `semgrep.json` per repo. Semgrep is
**never required** for the core benchmark.

## CodeQL baseline

Not implemented. Adding CodeQL would require per-language database builds
(`codeql database create`) that are out of scope here. This is a documentation
placeholder only — the harness creates **no** fake CodeQL outputs.

## Limitations

- Finding counts are unvalidated; no precision/recall without ground truth.
- Only Frame-supported languages are analyzed; Go/PHP are out of scope.
- Verified scans are slow; large repos may need `--max-files-per-repo` (which
  reduces coverage — recorded in `coverage_note`).
- Vendored/build directories (`node_modules`, `dist`, `build`, `target`, …) are
  excluded from both counting and scanning.
- Commit SHAs in `corpus.lock.json` are the repos' current heads as cloned by
  this harness, **not** Endor's commits.
