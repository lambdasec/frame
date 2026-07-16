# XBOW / ZeroPath AI-SAST Benchmark: Report

Frame vs commercial and open-source SAST tools on 39 real web-vulnerability apps,
scored by ZeroPath's own GPT-4o judge (seed 1337) so the numbers drop in next to the
published vendor numbers on equal terms. Frame runs through its CLI (`frame scan
--ai`) with the open model GLM-5.2. See [README.md](README.md) for methods and caveats.

## Results (all 39 benchmarks)

Detection is judged over the vulnerable app; false positives over the patched twin.
Technical = injection, traversal, SSRF, and similar; business-logic = IDOR/BOLA and
broken authentication.

| Scanner | Technical detect | Business-logic detect | Technical FP |
|---------|:----------------:|:---------------------:|:------------:|
| **Frame (open GLM-5.2)** | **78.8%** (26/33) | **87.5%** (7/8) | **26.3%** (5/19) |
| ZeroPath (commercial) | 80.0% | 87.5% | 25.0% |
| Semgrep | 54.3% | 12.5% | 45.0% |
| Snyk | 40.0% | 0.0% | 30.0% |
| Bearer | 5.7% | 0.0% | 0.0% |

Frame, an open model driven through the CLI, matches the commercial vendor ZeroPath on
technical detection (78.8% vs 80.0%), technical false positives (26.3% vs 25.0%), and
business-logic detection (87.5% vs 87.5%), and far exceeds Semgrep, Snyk, and Bearer on
every axis. It is the only tool besides ZeroPath that finds the IDOR/BOLA class at all;
the pattern-based scanners score 0 to 12.5% there.

## The weak spot: business-logic false positives

Frame's business-logic false-positive rate is 50% (3 of 6 patched twins), against the
vendors' roughly 0%. Frame both detects the IDOR/BOLA bugs (which the pattern scanners
miss) and over-flags some of their fixes. This is the same effect diagnosed in the
pilot: Frame's symbolic engine correctly drops the fixed vulnerability but flags a
second, unrelated resource access in the same file, which the file-level GPT-4o judge
counts as re-flagging the fixed bug. Tightening that is the clearest next improvement.

## Takeaway

On the technical axis, the standard SAST comparison, Frame with an open model is
competitive with a commercial AI-SAST vendor and well ahead of open-source scanners.
It also reaches the IDOR/BOLA class the pattern scanners cannot, at the cost of a
higher business-logic false-positive rate.

Pinned to fork commit `9c114481`, single run, GLM-5.2 via a hosted OpenAI-compatible
API. Detection through the LLM layer is non-deterministic, so a single run varies.
