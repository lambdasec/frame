# Endor Labs Corpus Benchmark

An independent harness that runs Frame over the public repositories Endor Labs
named as their AI-SAST benchmark corpus, from the article
[*"AI SAST Benchmark: 2x More Real Vulnerabilities"*](https://www.endorlabs.com/learn/ai-sast-benchmark-2x-more-real-vulnerabilities).

This is not a reproduction of Endor's benchmark. Endor published the corpus list
but not the commit SHAs, ground-truth labels, tool configurations, prompts, or
run-aggregation logic. This harness scores Frame and Semgrep OSS on the same public
repositories using its own pooled, model-judged ground truth. Its numbers are a
different quantity from Endor's published recall/F1. The article is used for the
corpus list and for the published numbers quoted at the end as context.

## Scope

Endor's corpus is 8 repositories. This benchmark scores the 5 real-world
applications and excludes 3:

| Excluded | Why |
| --- | --- |
| OWASP BenchmarkJava | Synthetic, and already scored in Frame's [main benchmarks](../README.md) (`owasp_java`). |
| doublestar | Go, which Frame does not support. |
| XBOW Validation Benchmarks | Mostly PHP, which Frame does not support. |

The five apps: `anonymous-github`, `demo-netflicks`, `juice-shop`, `webgoat`,
`shopizer`. The machine-readable manifest is [`corpus.yaml`](corpus.yaml).

## Results

Frame pairs a sound symbolic core (taint + separation logic) with an optional
local-LLM layer for detection (recall) and triage (precision). Numbers are on the
pooled ground truth: 193 judge-confirmed vulnerabilities across the 5 apps.

| Scanner | Recall | Precision | F1 |
| --- | :---: | :---: | :---: |
| Frame, symbolic core only | 0.37 | 0.45 | 0.41 |
| Frame, + LLM detection | 0.71 | 0.46 | 0.56 |
| Frame, + LLM detection + triage | 0.67 | 0.51 | 0.58 |
| Semgrep OSS (`p/default`) | 0.52 | 0.40 | 0.45 |
| Endor AI SAST (published, different GT) | 0.44 | 0.50¹ | 0.47 |

¹ Derived from Endor's published recall (0.435) and F1 (0.465). Endor's numbers use
their own larger, manually-reviewed ground truth. They are quoted for context and
are not comparable to this harness.

The symbolic core alone finds 0.37 recall. The LLM detection layer recovers about
65 real, Sonnet-confirmed vulnerabilities that both Frame's symbolic engine and
Semgrep miss, across Java, JS/TS, and C#. That includes cross-file flows found
through agentic tool use, and 5 ASP.NET C# vulns in `demo-netflicks` where symbolic
C# specs and Semgrep both found nothing. Triage then lifts detection precision from
0.48 to 0.59 while keeping 90% of the true positives.

LLM findings stay separate from the proven ones. Symbolic findings are "proven."
LLM findings carry an `llm_detect` or `llm_verified` tier, the latter meaning the
claimed sink is confirmed in Frame's own sink model, cross-file included.

### Caveats

Read these before quoting the numbers.

- The pooled ground truth is enriched by Frame's own LLM detection. About 65 of the
  193 vulns were surfaced by Frame's LLM layer, which Semgrep as shipped has no way
  to find. A fair AI-SAST-vs-AI-SAST comparison would give Semgrep an LLM layer too.
  So the size of Frame's recall lead is one-sided. The vulns are real, but Semgrep's
  recall is measured against a denominator Frame helped grow.
- Agentic detection is noisier than single-file, 0.43 to 0.56 raw precision.
  Verification and triage recover it.
- Labels are model-adjudicated by Claude Sonnet 5. They are a lower bound, about
  0.89 agreement with BenchmarkJava's real labels, not exhaustive human review.
- `demo-netflicks` was a weak data point for both tools until the LLM layer covered
  its C#.

## The pooled ground truth

Real apps ship no vulnerability labels. So the harness builds a pooled ground truth.
It runs Frame (symbolic and its LLM detection layer) and Semgrep OSS, adjudicates
every finding with an LLM judge (Claude Sonnet 5, via `claude -p`), and keeps the
union of confirmed true positives in [`ground_truth.pooled.json`](ground_truth.pooled.json)
(193 vulnerabilities). It grew from an initial 106 as the LLM detection layer found
vulns neither tool's traditional engine did.

This is a lower bound, not complete ground truth. It holds only vulns that some
engine found and the judge confirmed. Vulnerabilities all engines missed are absent,
so the real count is at least 193. A finding absent from the set is not necessarily
a false positive.

## Running it

```bash
pip install -e ".[scan]"
pip install pyyaml semgrep       # semgrep is optional
```

Clone and pin the repos, then scan:

```bash
python -m benchmarks.endor_corpus.run_endor_corpus \
  --workspace /tmp/endor-corpus --output /tmp/frame-endor-results --lock
```

Score Frame against the pooled ground truth (recall by file+CWE, precision from
cached judge verdicts, at no re-judging cost):

```bash
python -m benchmarks.endor_corpus.measure_frame --workspace /tmp/endor-corpus
```

Add the LLM layer (needs an OpenAI-compatible endpoint, see below):

```bash
python -m benchmarks.endor_corpus.measure_frame --workspace /tmp/endor-corpus \
  --llm-detect --llm-triage
```

## Using the LLM layer

Frame's detection and triage talk to any OpenAI-compatible `/v1/chat/completions`
endpoint. You can point them at a frontier hosted model or a local one. A stronger
model generally does better, so a hosted frontier model is a reasonable choice if
privacy and cost are not constraints.

Our numbers here use a local model, for privacy and cost. On Apple Silicon we served
[`mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit`](https://huggingface.co/mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit)
with [mlx-optiq](https://mlx-optiq.com), which supports tool-calling and context
past 16k tokens (both needed for agentic cross-file detection):

```bash
pip install mlx-optiq
# one-time: build the mixed-precision KV-cache config for the model
optiq kv-cache mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit --target-bits 5.0 -o ./kv
# serve OpenAI-compatible, with MTP (multi-token prediction) for ~1.4x faster decode
optiq serve --model mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit \
  --kv-config ./kv/kv_config.json --port 47317 --mtp
```

Then point Frame at the endpoint:

```bash
export FRAME_LLM_BASE_URL=http://localhost:47317/v1
export FRAME_LLM_API_KEY=                                   # empty for local servers
export FRAME_LLM_MODEL=mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit
export FRAME_LLM_REPO_ROOT=/path/to/repo                    # enables agentic cross-file tools
```

For a hosted model, set `FRAME_LLM_BASE_URL` to the provider's OpenAI-compatible
base, `FRAME_LLM_API_KEY` to your key, and `FRAME_LLM_MODEL` to the model id.

| Env var | Meaning |
| --- | --- |
| `FRAME_LLM_BASE_URL` | OpenAI-compatible base URL |
| `FRAME_LLM_MODEL` | model id |
| `FRAME_LLM_API_KEY` | API key; empty for local servers |
| `FRAME_LLM_REPO_ROOT` | repo root; enables agentic `read_file`/`grep` cross-file detection |
| `FRAME_LLM_MAX_TOOL_STEPS` | tool-call rounds before a verdict (default 6) |
| `FRAME_LLM_DROP_THRESHOLD` | triage confidence needed to drop a finding (default 0.75) |

Both layers are off by default. In code they are `FrameScanner(llm_detect=True,
llm_triage=True)`.

## Files

```
ground_truth.pooled.json          # 193 pooled, judge-confirmed vulns
ground_truth.<repo>.json          # per-repo Frame verdicts
ground_truth.<repo>.semgrep.json  # per-repo Semgrep detections
judged_findings.json              # every judge verdict (the precision cache)
corpus.yaml                       # corpus manifest
```

## The LLM judge

Labels come from [`judge_ground_truth.py`](judge_ground_truth.py), which uses Claude
Code headless (`claude -p`) with Sonnet 5 to adjudicate one finding at a time. It
reads a code window around each finding and returns `true_positive`,
`false_positive`, or `uncertain`. On a BenchmarkJava sample the judge agreed with the
real labels about 89% of the time. Treat it as a fast, imperfect stand-in for manual
review. Labels carry a `claude_code:*` source so they stay distinct from any
hand-validated set. It only sees the tools' findings, so it yields precision, not
recall.

## Endor's published numbers (context only)

Quoted from the article. Not computed here, and not comparable to the results above.

- Endor AI SAST: 192 real vulnerabilities found, 63 unique to it, recall 0.435,
  F1 0.465.
- vs Semgrep OSS: "2x more real vulnerabilities" and "about 60% fewer false
  positives."
- vs Claude (Opus 4.7): precision 0.718 with near-bottom recall.
- vs Codex (GPT-5.5): precision 0.859 with near-bottom recall.

Endor built ground truth by pooling every tool's true positives, de-duplicating by
hand, adding manual-review findings, and verifying each one, across Java, Python,
JavaScript, TypeScript, C#, and Go. Frame's numbers here cannot be compared to
Endor's without the same commits, labels, configurations, prompts, and denominators,
which the article does not publish.

## BenchmarkJava

BenchmarkJava is excluded here. It is synthetic and already scored in Frame's
[main benchmarks](../README.md), which also carry a same-benchmark Frame-vs-Semgrep
comparison via [`compare_benchmarkjava.py`](compare_benchmarkjava.py).
