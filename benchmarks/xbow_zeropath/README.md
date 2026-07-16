# XBOW / ZeroPath AI-SAST Benchmark

An independent, head-to-head comparison of Frame against commercial and open-source
SAST tools on real web-vulnerability applications, using a public benchmark and
scoring harness published by a commercial AI-SAST vendor.

## What this is

[XBOW](https://github.com/xbow-engineering/validation-benchmarks) open-sourced 104
dockerized web-security challenge apps (SQLi, XSS, SSTI, IDOR, LFI, SSRF, and more).
[ZeroPath](https://zeropath.com), a commercial AI-SAST vendor, forked them into a
*static-analysis* benchmark: they removed the hints that favor AI tools, added a
patched/secure twin of each app for false-positive testing, and published
detection-rate and false-positive-rate numbers for **ZeroPath, Semgrep, Snyk, and
Bearer** on 39 of them, scored by a GPT-4o judge. Their fork ships the ground truth,
the vendors' raw SARIF, and the scoring scripts.

We run **Frame** on that exact benchmark and score it with **ZeroPath's own GPT-4o
judge**, so Frame's numbers drop in next to the published vendor numbers on equal
terms. Frame runs entirely through its CLI (`frame scan --ai`) with an open model
(GLM-5.2, `z-ai/glm-5.2`, or a local mlx-optiq model); no frontier vendor is used.

## Metrics

- **Detection rate:** fraction of the vulnerable apps where the tool flags the
  ground-truth vulnerability (judged by GPT-4o matching the finding to the known vuln).
- **False-positive rate:** fraction of the patched (secure) twins where the tool
  still flags the now-fixed vulnerability.

A good tool has high detection and low false positives. Both are computed by the
same judge (gpt-4o, seed 1337) and prompt used for the published vendor numbers.

## Run it

```bash
# 1. clone ZeroPath's fork at the pinned commit
python benchmarks/xbow_zeropath/prepare.py --workspace /tmp/frame-xbow

# 2. scan every app with Frame's CLI (writes frame_raw.sarif per benchmark)
export FRAME_LLM_BASE_URL=https://openrouter.ai/api/v1
export FRAME_LLM_API_KEY=<key>
export FRAME_LLM_MODEL=z-ai/glm-5.2
python benchmarks/xbow_zeropath/run.py --workspace /tmp/frame-xbow

# 3. score with ZeroPath's GPT-4o judge, compare to the published vendor numbers
export OPENAI_API_KEY=<key> OPENAI_BASE_URL=https://openrouter.ai/api/v1
export JUDGE_MODEL=openai/gpt-4o
python benchmarks/xbow_zeropath/score.py --workspace /tmp/frame-xbow
```

Results are written to `results.json`; see [REPORT.md](REPORT.md) for the scored table.

## Honest framing and caveats

- This is **not** a reproduction of ZeroPath's product claims; it is Frame scored on
  their public benchmark with their public judge.
- The apps are intentionally vulnerable training/CTF apps, mostly small Flask
  programs; they are not production codebases.
- 39 benchmarks (31 technical + 8 business-logic/auth) is a modest sample; the
  ground truth is public, so it is not a permanently blind test.
- The GPT-4o judge matches findings to the ground truth semantically and by file, so
  it can conflate two different vulnerabilities in the same file.
- Frame is non-deterministic through its LLM layer; a single run varies.
- Everything is pinned to fork commit `9c114481` for reproducibility.
