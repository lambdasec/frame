# BAC-Bench (ABSENTIA) — broken access control

[BAC-Bench](https://github.com/avduarte333/Absentia) is a public benchmark of **30 disclosed
broken-access-control advisories** across 25 open-source web applications and nine frameworks
(18 Python, 9 TypeScript, 3 JavaScript), published with the ABSENTIA paper
([arXiv:2610.00977](https://arxiv.org/abs/2610.00977)). Each case pins an upstream repository,
a **vulnerable commit** and a **fixing commit**, the affected routes, the access-control
invariant, and the disclosed CWEs.

This harness runs Frame directly over the pinned checkouts. It is **not** a reproduction of the
ABSENTIA system, and its numbers are **not** the paper's. For orientation only, the paper reports
ABSENTIA 19/30 (17 paired with the fixed commit), an unstructured agent on the same model 3/30,
and CodeQL and Semgrep 0/30.

## Why it fits Frame

All 30 cases are in languages Frame has a frontend for, so the whole benchmark exercises the
engine-backed tier, and it measures exactly the authorization work Frame added:

- **`frame_symbolic`** — the sound findings: IDOR/BOLA (CWE-639) and missing function-level
  authorization (CWE-862) by handler consistency.
- **`frame_hunt`** — the agentic authorization / business-logic hunt (`frame scan --hunt-authz`),
  whose tools are the engine's own handler facts. Findings are `llm_verified` where an engine fact
  corroborates, else `llm_detect`. Needs an LLM endpoint (`FRAME_LLM_*`).

The two tiers are scored separately and never merged (Frame's standing rule).

## Running

```bash
python benchmarks/bacbench/prepare.py --workspace /tmp/frame-bacbench          # clone dataset + apps
python benchmarks/bacbench/run.py     --workspace /tmp/frame-bacbench --systems frame_symbolic
python benchmarks/bacbench/score.py   --workspace /tmp/frame-bacbench --results benchmarks/bacbench/results/v1
# frame_hunt additionally needs FRAME_LLM_BASE_URL / FRAME_LLM_MODEL set.
```

`prepare.py` clones each application from its public upstream at the pinned commits; no application
source is vendored into Frame. The dataset revision is pinned in `manifest.yaml`.

## Scoring

The unit is one advisory at its pinned vulnerable commit.

- **detected** — a finding matches the advisory (`match.py`).
- **paired** — detected on the vulnerable commit **and** gone on the fixed commit.

This is a **positive-only** benchmark of known issues: other findings in an application are not
counted as false positives, because the dataset does not label every route. `match.py` is a
deterministic approximation of the dataset's prose `match_criteria`: a finding matches when it is an
access-control CWE (the 639/862/863/284/285 family) in one of the case's recorded source locations
(a sink or root file, within a sink line range when one is given). It is unit-tested in
`tests/test_bacbench_match.py`.
