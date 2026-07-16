# XBOW / ZeroPath AI-SAST Benchmark: Report

Frame vs commercial and open-source SAST tools on real web-vulnerability apps, scored
by ZeroPath's own GPT-4o judge. See [README.md](README.md) for methodology and caveats.
Frame runs through its CLI (`frame scan --ai`) with the open model GLM-5.2.

> **Status: full 39-benchmark run in progress.** The table below is a 5-benchmark
> pilot (one per vulnerability class) scored end-to-end with the GPT-4o judge. The
> full 39-benchmark detection and false-positive numbers will replace it.

## Pilot: detection and false positives (5 benchmarks, one per class)

Same corpus, same GPT-4o judge (seed 1337) that produced ZeroPath's published numbers.

| Benchmark | Class | ZeroPath | Semgrep | Snyk | Bearer | Frame |
|-----------|-------|:--------:|:-------:|:----:|:------:|:-----:|
| XBEN-001 | IDOR | detect | - | - | - | **detect** |
| XBEN-006 | SQLi | detect | detect | detect | - | **detect** |
| XBEN-009 | SSTI | detect | detect | - | detect | **detect** |
| XBEN-010 | XSS | detect | detect | detect | - | **detect** |
| XBEN-019 | LFI | - | - | - | - | **-** |
| **Detection** | | **4/5** | 3/5 | 2/5 | 1/5 | **4/5** |
| **False positives** | | 2/5 | 2/5 | 1/5 | 0/5 | **2/5** |

On this pilot Frame ties ZeroPath (the vendor whose benchmark this is) on both
detection and false positives, and leads Semgrep, Snyk, and Bearer on detection.
Notes:

- Frame is the only tool besides ZeroPath to catch the **IDOR** (XBEN-001); the
  pattern-based scanners all miss it.
- Every tool misses the **LFI** (XBEN-019), so Frame's one detection miss is shared.
- Bearer's 0 false positives come with the weakest detection (1/5); it barely fires.
- Frame's IDOR false positive (patched XBEN-001) is a coarse-judge artifact: Frame
  correctly stopped flagging the fixed vulnerability and instead flagged a different
  username lookup in the same file, which the file-level judge counted as the same bug.

The pilot is a favorable subset (5 Frame-addressable classes); the full 39-benchmark
run, with many XSS variants, is the real test and is what will be published here.
