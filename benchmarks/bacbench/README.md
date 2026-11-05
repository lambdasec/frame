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

Frame's results (22/30 detected, 11 paired, Claude Haiku 5.5) are in [REPORT.md](REPORT.md).

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
Paths must agree (equal, or one a path suffix of the other); a shared basename alone never matches,
since every controller in a TypeScript monorepo is `index.ts`.

A finding about the recorded defect is often cited a little away from the recorded lines: at the
handler that reaches a recorded helper, or in the helper a recorded handler delegates to.
`regions.py` reads each checkout's syntax tree (tree-sitter, no model) and also credits a finding
inside one of the case's code regions: the function holding a recorded range, a function in the
same file that calls it directly, or a function it calls as a plain function call when exactly one
non-test function of that name exists in the repository. A region is a function's own code (nested
functions are holes, so a route-registration wrapper is not one region). Regions are found on the
vulnerable checkout, looked up by name on the fixed one, and cached in
`<workspace>/gt_regions.json`. On the fixed checkout a finding blocks the pair when it is in the
window or in a function where a vulnerable-side match sits. Two different bugs in one function
cannot be told apart this way, so the pair then counts as not fixed: an undercount, never an
inflation. `--window-only` scores with the recorded ranges alone, the rule before regions
(`tests/test_bacbench_regions.py`).

For `frame_hunt`, `score.py` also reports each tier on its own (`llm` is the hunt agent,
`symbolic` the engine), because the blended count cannot say which one found a case. A hunt that
never reached the model (`hunt.stop` of `transport_error`, `exception`, `no_endpoint`,
`not_run`) is `hunt-error` on the vulnerable commit, not a miss, and on the fixed commit it never
counts as a pair.

### Judged scoring (`--judge`)

The paper's own adjudication (Section 5.2) is a location gate followed by an LLM judge (Claude
Sonnet 4.6, temperature zero) that reads each finding against the advisory's invariant and the way
the code breaks it, blind to the tool and without the source. `judge.py` follows it: the gate keeps
a finding in an implicated file or whose claim names an affected route; the judge sees the record's
`invariant`, `violation`, `match_criteria`, routes, files, symbols and CWEs, and each finding's
location, CWE and claim (the tool's tier and labels withheld). The paper publishes no prompt, so the
prompt is ours. For cost, candidates are capped at 25 per checkout (nearest the sink first) and one
call judges a checkout's candidates, each independently. Verdicts are cached in
`<results>/judge_cache.json`; a judge failure is `judge-error`, never a miss.

```bash
python benchmarks/bacbench/score.py --workspace /tmp/frame-bacbench --results <dir> --judge \
    --judge-model anthropic/claude-sonnet-4.6 --judge-base-url https://openrouter.ai/api/v1 \
    --judge-key-env OPENROUTER_API_KEY
```

Without `--judge-*` flags the judge uses the hunt's `FRAME_LLM_*` endpoint.

### Funnel

When a `frame_hunt` run records its route map and investigation units, `score.py` prints where the
agent stood on each case's implicated files: in the map, investigated, the best verdict reached
(reported, judged safe, none), detected and paired. Older runs show the stage as unknown.

### Hunt options

`run.py` passes `--hunt-max-units`, `--hunt-unit-steps` and `--hunt-concurrency` to the hunt (unset
flags keep its defaults). `--hunt-verdict-cache` keeps each unit's verdict in
`<output>/frame_hunt/cache/<case>.json`, shared by a case's vulnerable and fixed scans, so a unit
whose files did not change between the commits keeps its verdict.

### Surviving network outages

A unit whose endpoint stops answering ends as `transport_error`, which the scorer reports as a
hunt error rather than a miss, but the case is still lost. Two layers keep a long run going:

- `outage_wait = <seconds>` under `[llm]` in the file `--frame-config` names makes each agent
  wait out an outage (retrying every 30 s) and continue where it was. Cancelling the hunt ends
  the wait at once.
- `--retry-outages N` reruns, after the pass, every case that still lost units to the endpoint
  (a unit ended `transport_error`, or the per-case cap fired while units waited), once the
  endpoint answers again (`--outage-probe-wait`, default 6 hours). With `--hunt-verdict-cache`
  the units that finished are reused, so only the lost ones do new work. `--resume` likewise
  reruns a result file the outage damaged instead of skipping it.
