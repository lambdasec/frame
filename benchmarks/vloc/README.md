# VLoc Bench: repository-scale vulnerability localization

An independent run of Cisco Foundation AI's [Vulnerability Localization
Benchmark](https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark)
(500 real GitHub Security Advisory vulnerabilities across 290 repositories and 6
package ecosystems), scored with the benchmark authors' own `scoring.py`.

Pinned to benchmark commit `000c19cda9ba027e1d241216768b2b6358685000`, manifest
MD5 `15671557ddad5d2a8e2652aaa92d5de5`.

## What it measures

Two phases, run over the same repository at two commits:

- **Phase A (localization)** on the vulnerable snapshot. Given the task's CWE,
  which files contain the vulnerability? Scored **File F1** against the
  ground-truth patch.
- **Phase B (fix verification)** on the patched snapshot. The correct answer is
  to report **nothing**. Scored **True Negative Rate**.

Phase B is the interesting one for Frame: it is precision on patched code, the
same discipline as the patched twins in the XBOW study and the safe controls in
RealVuln.

## Read the leaderboard carefully

Phase A and Phase B are inversely correlated in the published results, because
the models with the best TNR earn it by abstaining rather than by being precise:

| Model | File F1 | TNR | submits nothing |
|-------|--------:|----:|----------------:|
| GPT-5.5 (xhigh) | 0.229 | 0.279 | 15.8% |
| Antares-3B-GRPO | 0.223 | not evaluated | |
| GLM-5.2 | 0.186 | not evaluated | |
| Gemma-4-31B | 0.101 | 0.682 | |
| GPT-5-Nano | 0.024 | 0.868 | 86.0% |

A system that always submits nothing scores TNR 1.0 and F1 0.0. So a high TNR on
its own is not a result. The open frontier is doing well at **both**: no
published system exceeds 0.229 F1 while holding TNR meaningfully above 0.279.

`GLM-5.2` at 0.186 F1 is the reference point that matters here, because it is the
same model Frame's LLM layer runs. The delta between bare GLM-5.2 and Frame
driving GLM-5.2 is Frame's contribution, isolated.

## Methodology difference (read before quoting any number)

Frame is a static scanner, not a terminal agent. The benchmark's reference
implementation gives a model **15 terminal calls** and 20 turns to explore the
repository. Frame instead performs a whole-repository scan with its symbolic
engine plus, under `--ai`, an LLM layer that explores with `read_file`/`grep`.

That asymmetry favours Frame on Phase A recall and works against it on Phase B,
where scanning everything creates more chances to report something on patched
code. It is a real difference and these numbers are **not like-for-like** with
the published agent results. Set `FRAME_LLM_MAX_TOOL_STEPS=15` to align Frame's
LLM layer with the reference budget for a closer comparison.

The benchmark's submission rules permit "this repo's CLI, or a documented
equivalent", and maintainers request raw prediction logs before merging, so a
Frame entry is legitimate provided the difference is stated. It is stated in the
emitted `scores.json` under `methodology_note`.

## Coverage

Frame's symbolic frontends cover about half the task set; the rest reaches only
the LLM layer, so `--ai` (and an LLM endpoint) is required for a full run.

| Ecosystem | Tasks | Frame symbolic core |
|-----------|------:|---------------------|
| go | 215 | no, LLM layer only |
| maven (Java) | 104 | yes |
| npm (JS/TS) | 88 | yes |
| pip (Python) | 52 | yes |
| rust | 40 | no, LLM layer only |
| composer (PHP) | 1 | no, LLM layer only |

## Running it

```bash
# 1. Clone the pinned benchmark and fetch snapshots for a stratified sample.
python benchmarks/vloc/prepare.py --workspace /tmp/frame-vloc --sample 80

# 2. Scan. Needs FRAME_LLM_* pointing at an OpenAI-compatible endpoint.
export FRAME_LLM_MAX_TOOL_STEPS=15        # align with the reference budget
python benchmarks/vloc/run.py --workspace /tmp/frame-vloc --out /tmp/vloc-results

# 3. Score with Cisco's scorer, unmodified.
python benchmarks/vloc/score.py --workspace /tmp/frame-vloc --results /tmp/vloc-results
```

The full 500-task set is 15 GB zipped and 40 GB unzipped. `run.py` extracts each
snapshot immediately before scanning and deletes it afterwards, so peak disk stays
in the low single-digit GB regardless of task count. Sampling is proportional
across ecosystems and deterministic for a given `--seed`; it is deliberately not
weighted toward the CWE classes Frame detects best, since that would inflate the
score relative to the published full-set numbers.

## Honest caveats

- A sampled run is **not leaderboard-comparable**. Only a full 500-task run is.
- Frame is CWE-scoped: it submits only findings whose CWE matches the task
  target. `--cwe-any` reports a recall upper bound and is not a headline number.
- The CWE head of the benchmark (CWE-400 resource exhaustion, 53 tasks; CWE-20
  input validation, 45) is not a taint-analysis class. Roughly a quarter of tasks
  map cleanly onto Frame's detectors.
- Detection through the LLM layer is non-deterministic, so a single run varies.
