# SusVibes: Frame on real-CVE Python pairs

An evaluation of Frame (and Semgrep) on [SusVibes](https://github.com/LeiLiLab/susvibes),
a benchmark of real vulnerabilities in open-source Python projects drawn from actual
CVE-fixing commits. Unlike the [Endor corpus](../endor_corpus/), the ground truth here
is real and execution-verified upstream, not model-judged: each task is a known CVE
with a vulnerable version (pre-fix) and a secure version (the fix).

## What it measures

SusVibes has 186 tasks from 108 open-source projects across 77 CWE classes. For each,
we reconstruct a vulnerable/fixed pair:

- **vulnerable** = the changed file(s) at the fix commit's parent (pre-fix, has the bug).
- **secure** = the same file(s) at the fix commit (patched).

We scan both with each tool and score in the OWASP-Benchmark style:

- **recall** = flags the task's CWE on the vulnerable version, over 181.
- **precision** = TP / (TP + FP), where FP = flags the task CWE on the *fixed* version
  (the tool could not tell the patch removed the bug).

Matching is at file + CWE, with CWE families normalized. 181 of 186 tasks reconstruct
cleanly; 5 are skipped because their patch touches only non-Python files.

## Results (core symbolic vs LLM layer, local model)

| Configuration | Recall | Precision | F1 |
| --- | :---: | :---: | :---: |
| Frame (symbolic core, no LLM) | 0.011 | 0.667 | 0.022 |
| Semgrep OSS (`p/security-audit`) | 0.061 | 0.550 | 0.109 |
| Frame + LLM detect (terse prompt) | 0.077 | 0.538 | 0.135 |
| **Frame + LLM detect (reason-first)** | **0.138** | **0.556** | **0.221** |

The LLM layer runs on a local model, `mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit` via
[mlx-optiq](https://mlx-optiq.com). Frozen numbers are in [`results.json`](results.json).

## What we learned

**Symbolic SAST is near-blind on real library CVEs.** Frame's symbolic core (0.011) and
Semgrep (0.061) both score near zero. These CVEs are mostly authorization gaps,
information exposure, resource exhaustion, and sanitizer bypasses. Those are semantic
flaws, not source-to-sink patterns. Frame's taint also needs a recognized framework
source, which an isolated library function taking plain parameters does not have.

**The LLM layer is the only thing that moves recall off the floor, and reasoning first
nearly doubled it.** A "reason step by step, then emit the findings JSON" prompt reached
0.138 recall against 0.077 for a terse "JSON only" prompt, at equal precision. This is
now Frame's default detection prompt. It caught path traversal 14 times, XSS 4 times,
plus SSRF, XXE, open redirect, broken auth, and request smuggling.

**But it is "better, not solved."** Even reason-first reaches only 0.138. Real-world CVE
detection from an isolated function is genuinely hard for every approach. Two levers we
tested and rejected:

- **Thinking mode** (Qwen3 `chat_template_kwargs: {enable_thinking: true}`): about 2x
  slower, with no recall gain. The model over-reasoned and talked itself out of subtle
  findings, and even lost an XSS the lighter prompt caught.
- **Triage**: on this set it dropped real true positives (net F1 down). Its
  endor-tuned drop threshold is too aggressive for subtle library CVEs.

## Honest caveats

- **Isolated-function scanning.** We scan the changed file(s), not the whole repo. This
  handicaps cross-file taint (Frame) more than pattern matching (Semgrep), and truncates
  a few very large files. It measures "can you spot the bug in the changed function," not
  full-repo analysis.
- **Low absolute numbers for everyone.** Read the relative comparison, not the absolute
  recall.
- **Precision about 0.55 at scale.** The LLM flags a fixed version roughly as often as a
  vulnerable one on the cases where it fires. A vulnerable-versus-fixed check or better
  triage would earn precision back.

## Reproduce

```bash
git clone https://github.com/LeiLiLab/susvibes /tmp/susvibes
python benchmarks/susvibes/build_pairs.py \
  --dataset /tmp/susvibes/datasets/default/susvibes_dataset.jsonl --out /tmp/susvibes-pairs

# Frame symbolic core + Semgrep:
python benchmarks/susvibes/score.py --pairs /tmp/susvibes-pairs --semgrep

# add the LLM detection layer (needs FRAME_LLM_* env; see endor_corpus/README.md):
python benchmarks/susvibes/score.py --pairs /tmp/susvibes-pairs --ai
```
