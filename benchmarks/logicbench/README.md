# Business-logic benchmark

Real, disclosed business-logic vulnerabilities in open-source web applications, one per advisory, each pinned to a vulnerable commit and the commit that fixed it. It measures the business-logic hunt (`frame scan --hunt logic`, [docs/ai.md](../../docs/ai.md#hunting-business-logic-flaws---hunt)) the way [BAC-Bench](../bacbench/README.md) measures the authorization hunt.

| Class | What a case is |
|---|---|
| `limits` | a number the caller chooses reaches stored state without its bound (negative quantity, refund above the price) |
| `race` | read, decide, write without a lock: a balance, coupon, vote or invite used twice |
| `workflow` | a required state or step skipped, a one-time token accepted again |
| `replay` | a state change accepted twice: no nonce, idempotency key or status check |
| `bruteforce` | a password, code or PIN checked with no attempt limit |

## Keyed blind

The cases were collected and keyed before Frame was run on any of them. The ground truth comes from each advisory and its fixing commit's diff, never from Frame's output: the expected CWEs and the vulnerable-side files and line ranges. So the first run's score is blind; scores after fixes that run drove are not, and are reported as such.

## Running

The scripts are BAC-Bench's, pointed at this manifest:

```bash
python benchmarks/bacbench/prepare.py --manifest benchmarks/logicbench/manifest.yaml --workspace /tmp/frame-logicbench
python benchmarks/bacbench/run.py --workspace /tmp/frame-logicbench --systems frame_hunt \
    --hunt-classes logic --output benchmarks/logicbench/results/v1        # needs FRAME_LLM_*
python benchmarks/bacbench/score.py --manifest benchmarks/logicbench/manifest.yaml \
    --workspace /tmp/frame-logicbench --results benchmarks/logicbench/results/v1
```

`prepare.py` clones each application from its public upstream at the pinned commits; no application source is vendored into Frame.

## Scoring

As BAC-Bench: a case is **detected** when a finding is in one of its recorded locations (or code regions) with a CWE the case expects or a sibling in its class's family (`scoring.cwe_families` in the manifest: an advisory's CWE-20 and the hunt's CWE-1284 describe the same missing bound), and **paired** when that finding is gone on the fixed commit. Positive-only: other findings are not counted as false positives, because the dataset does not label every route. Score with the deterministic matcher.
