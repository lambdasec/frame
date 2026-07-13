# Frame Benchmark Suite

Comprehensive benchmark infrastructure for evaluating Frame against industry-standard test suites.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Results Summary](#results-summary)
- [Real-World Benchmark (Endor Labs Corpus)](#real-world-benchmark-endor-labs-corpus)
- [SAST Security Benchmarks](#sast-security-benchmarks)
  - [Python (OWASP)](#python-owasp-benchmark)
  - [Java (OWASP)](#java-owasp-benchmark)
  - [JavaScript (SecBench.js)](#javascript-secbenchjs-benchmark)
  - [C/C++ (NIST Juliet)](#cc-nist-juliet-benchmark)
  - [C# (IssueBlot.NET)](#c-issueblotnet-benchmark)
- [Logic Solver Benchmarks](#logic-solver-benchmarks)
  - [Separation Logic (SL-COMP)](#separation-logic-sl-comp)
  - [String Theory (QF_S)](#string-theory-qf_s)
  - [Array Theory (QF_AX)](#array-theory-qf_ax)
  - [Bitvector Theory (QF_BV)](#bitvector-theory-qf_bv)
- [CLI Reference](#cli-reference)
- [Benchmark Formats](#benchmark-formats)
- [Development Workflow](#development-workflow)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Run Curated Benchmarks (Recommended)

```bash
# All curated benchmarks (4,742 tests, ~15-20 minutes)
python -m benchmarks run --curated

# Security benchmarks only
python -m benchmarks run --division owasp_python_curated  # Python (500 tests)
python -m benchmarks run --division owasp_java            # Java (500 tests)
python -m benchmarks run --division secbench              # JavaScript (SecBench.js)
python -m benchmarks run --division juliet_curated        # C/C++ (1000 tests)

# Logic solver benchmarks
python -m benchmarks run --division slcomp_curated        # Separation logic (692 tests)
python -m benchmarks run --division qf_s_curated          # String theory (3,300 tests)
python -m benchmarks run --division qf_ax_curated         # Array theory (500 tests)
python -m benchmarks run --division qf_bv_curated         # Bitvector theory (250 tests)
```

### Run Full Benchmarks

```bash
# All benchmarks (~20,000 tests, ~2+ hours)
python -m benchmarks run --all
```

---

## Results Summary

### Real-World Security

A live end-to-end benchmark plus two detection datasets with published ground truth.

**[CVE-Bench](cve_bench/README.md)** — the full agent loop on 10 curated live web CVEs:
**detect → exploit → fix**, each stage independently verified. Unlike the detection
datasets below, this measures the complete lifecycle against *running* targets, graded
by CVE-Bench's own `done.sh` execution oracle:

| Stage | Result on 10 curated CVEs |
|-------|:-------------------------:|
| Detect (findings in source) | 5/10 |
| Exploit (compromise live target, `done.sh`-verified) | **4/10** |
| Fix (patch + re-scan-verified) | **16 fixes** |

2 CVEs run the entire detect→exploit→fix→verify loop end-to-end (SSRF, XXE). A
capability demonstration — multi-model, on-device-capable, curated source-localizable
subset. Full methodology and honest caveats: [`cve_bench/`](cve_bench/README.md).

**[Endor Labs corpus](#real-world-benchmark-endor-labs-corpus)** — 5 production
applications, pooled ground truth of 193 vulnerabilities. Frame's full
mode is the sound symbolic core plus an LLM detection and triage layer. Recall,
precision, and F1:

| Scanner | Recall | Precision | F1 |
|---------|:------:|:---------:|:--:|
| Frame, symbolic core only | 0.37 | 0.45 | 0.41 |
| Frame, + LLM detection | 0.71 | 0.46 | 0.56 |
| Frame, + LLM detection + triage | 0.67 | 0.51 | 0.58 |
| Semgrep OSS (`p/default`) | 0.52 | 0.40 | 0.45 |
| Endor AI SAST (published, different GT) | 0.44 | 0.50¹ | 0.47 |

¹ Derived from Endor's published recall and F1. Endor's numbers use their own
larger, manually-reviewed ground truth, quoted for context and not comparable.
Full scoreboard, LLM setup, and caveats:
[Real-World Benchmark](#real-world-benchmark-endor-labs-corpus) below, and
[`endor_corpus/`](endor_corpus/README.md).

**[SusVibes](susvibes/README.md)** — 181 real-CVE Python pairs (vulnerable vs fixed),
with independent, execution-verified ground truth from the CVE fix commits. Much
harder than the pooled corpus, and a clean test of the LLM layer since symbolic SAST
scores near zero:

| Scanner | Recall | Precision | F1 |
|---------|:------:|:---------:|:--:|
| Frame, symbolic core only | 0.011 | 0.667 | 0.022 |
| Frame, + LLM detection (reason-first) | 0.138 | 0.556 | 0.221 |
| Semgrep OSS (`p/security-audit`) | 0.061 | 0.550 | 0.109 |

Absolute recall is low for every tool here (these CVEs are mostly authz,
info-exposure, and sanitizer-bypass bugs, not source→sink patterns), so read the
relative comparison. Full numbers and caveats: [`susvibes/`](susvibes/README.md).

### Synthetic SAST Suites

| Language | Benchmark | Tests | Precision | Recall | OWASP Score | vs Semgrep |
|----------|-----------|-------|-----------|--------|-------------|------------|
| Python | OWASP | 500 | 95.3% | 83.5% | **80.9%** | +76.4 pts |
| Java | OWASP | 500 | 97.2% | 84.8% | **81.5%** | +65.8 pts |
| JavaScript | SecBench.js | 300 | 82.0% | 81.0% | **43.0%** | +33 pts |
| C/C++ | NIST Juliet | 1,000 | 89.9% | 60.5% | **54.4%** | +69.3 pts |
| C# | IssueBlot.NET | 171 | 84.7% | 80.3% | **80.3%** | +66.1 pts |

### Logic Solver Benchmarks

| Theory | Benchmark | Tests | Accuracy | Avg Time |
|--------|-----------|-------|----------|----------|
| Separation Logic | SL-COMP | 692 | 79.9% | ~1s |
| String | QF_S | 3,300 | 99.3% | ~15ms |
| Array | QF_AX | 500 | 100% | 48ms |
| Bitvector | QF_BV | 250 | 89.2% | 25ms |
| **Total Curated** | | **4,742** | **96.0%** | 970ms |

---

## Real-World Benchmark (Endor Labs Corpus)

Synthetic suites can overstate real-world quality. That is Endor Labs' central
thesis. This benchmark scores Frame on the 5 real-world applications in
[Endor Labs' public AI-SAST corpus](https://www.endorlabs.com/learn/ai-sast-benchmark-2x-more-real-vulnerabilities)
(`anonymous-github`, `demo-netflicks`, `juice-shop`, `webgoat`, `shopizer`).

Real apps ship no labels, so this benchmark scores against a pooled, judge-confirmed
ground truth of 193 vulnerabilities (the union of Frame and Semgrep findings).
[`endor_corpus/README.md`](endor_corpus/README.md) explains how it is built.

| Scanner | Recall | Precision | F1 |
|---------|:------:|:---------:|:--:|
| Frame, symbolic core only | 0.37 | 0.45 | 0.41 |
| Frame, + LLM detection | 0.71 | 0.46 | 0.56 |
| Frame, + LLM detection + triage | 0.67 | 0.51 | 0.58 |
| Semgrep OSS (`p/default`) | 0.52 | 0.40 | 0.45 |
| Endor AI SAST (published, different GT) | 0.44 | 0.50¹ | 0.47 |

¹ Derived from Endor's published recall and F1. Endor's numbers use their own
larger, manually-reviewed ground truth. They are quoted for context and are not
directly comparable.

The symbolic core alone finds 0.37 recall. The LLM detection layer recovers about
65 real, judge-confirmed vulnerabilities that both Frame's symbolic engine and
Semgrep miss, across Java, JS/TS, and C#. That includes cross-file flows found
through agentic tool use, and 5 ASP.NET C# vulns in `demo-netflicks` where symbolic
C# specs and Semgrep both scored zero. Triage then lifts detection precision from
0.48 to 0.59 while keeping 90% of the true positives.

The LLM layer works with any OpenAI-compatible endpoint, so you can point it at a
frontier hosted model or a local one. Our numbers use a local model, for privacy
and cost: [mlx-optiq](https://mlx-optiq.com) serving
[`mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit`](https://huggingface.co/mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit)
on Apple Silicon. A stronger hosted model would likely do better.

```bash
# our local setup (Apple Silicon), then reproduce
pip install mlx-optiq
optiq kv-cache mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit --target-bits 5.0 -o ./kv
optiq serve --model mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit \
  --kv-config ./kv/kv_config.json --port 47317 --mtp
python -m benchmarks.endor_corpus.measure_frame --workspace /tmp/endor-corpus \
  --llm-detect --llm-triage
```

One caveat to keep in mind: the pooled ground truth is enriched by Frame's own LLM
detection, about 65 of the 193 vulns, which Semgrep as shipped cannot find. So the
size of Frame's recall lead is one-sided. The
[corpus README](endor_corpus/README.md) records the full set of caveats.

## SAST Security Benchmarks

### Python (OWASP Benchmark)

**Dataset:** 500 tests, 194 true vulnerabilities across 11 categories

| Metric | Frame | Semgrep | Bandit |
|--------|:-----:|:-------:|:------:|
| True Positives | 162 | 62 | 56 |
| False Positives | 8 | 84 | 60 |
| Precision | **95.3%** | 42.5% | 48.3% |
| Recall | **83.5%** | 32.0% | 28.9% |
| OWASP Score | **80.9%** | 4.5% | 9.3% |

**Vulnerability Categories:**
- SQL Injection (89 tests)
- Command Injection (94 tests)
- LDAP Injection (90 tests)
- XSS (50 tests)
- XPath Injection (50 tests)
- Weak Hash (50 tests)
- Weak Crypto (28 tests)
- Path Traversal (22 tests)
- Deserialization (16 tests)
- XXE (11 tests)

```bash
python -m benchmarks run --division owasp_python_curated
```

---

### Java (OWASP Benchmark)

**Dataset:** 500 tests, 289 true vulnerabilities

| Metric | Frame | Semgrep | FindSecBugs |
|--------|:-----:|:-------:|:-----------:|
| True Positives | 245 | 1,279 | ~145 |
| False Positives | 7 | 991 | ~65 |
| Precision | **97.2%** | 56.3% | 68.9% |
| Recall | 84.8% | **90.4%** | 50% |
| F1 Score | **90.6%** | 69.4% | 52.1% |
| OWASP Score | **81.5%** | 15.7% | 39% |

**Vulnerability Categories:**
- SQL Injection, XSS, Command Injection
- Path Traversal, Weak Crypto, Weak Hash
- XXE, LDAP Injection, XPath Injection
- Trust Boundary violations

```bash
python -m benchmarks run --division owasp_java
```

---

### JavaScript (SecBench.js Benchmark)

**Dataset:** [SecBench.js](https://github.com/cristianstaicu/SecBench.js)
(Staicu et al., ICSE 2023): 600 publicly-reported server-side JavaScript
vulnerabilities in real npm packages, across 5 CWE categories, each with a
ground-truth sink location and (usually) a patched version. The numbers below
are a 60-per-category sample (~300 CVEs). Packages are fetched from npm and
scanned in **library mode** (exported-function parameters are treated as
untrusted, the correct threat model for a library's public API). Recall is
measured on each vulnerable package's sink file; precision on the patched
version.

| Metric | Frame | Semgrep |
|--------|:-----:|:-------:|
| Precision | **82%** | 75% |
| Recall | **81%** | 35% |
| OWASP Score (TPR−FPR) | **+43%** | +10% |

Semgrep is run with its out-of-the-box ruleset (`p/default`) under the identical
methodology. Frame's recall lead (81% vs 35%) comes from library-mode SL taint
analysis catching the inter-procedural, closure-captured and library-parameter
flows that rule-based matching misses.

**Frame by category:**

| Category | CWE | Precision | Recall |
|----------|-----|:---------:|:------:|
| Command injection | CWE-78 | 80% | 87% |
| Code injection | CWE-94 | 74% | 81% |
| Path traversal | CWE-22 | 90% | 92% |
| Prototype pollution | CWE-1321 | 86% | 91% |
| ReDoS | CWE-1333 | 77% | 54% |
| **Overall** | | **82%** | **81%** |

ReDoS precision is measured per-regex: a static detector cannot observe runtime
input-length mitigations, so a patched-version flag counts as a false positive
only when the patch actually changed the flagged regex.

```bash
# Reproduce the Semgrep comparison (requires: pip install semgrep)
python -m benchmarks.runners.semgrep_secbench 60
```

```bash
python -m benchmarks run --division secbench
```

---

### C/C++ (NIST Juliet Benchmark)

**Dataset:** 1,000 tests, 952 expected vulnerabilities

| Metric | Frame | Semgrep |
|--------|:-----:|:-------:|
| True Positives | **576** | 82 |
| False Positives | **65** | 324 |
| Precision | **89.9%** | 20.2% |
| Recall | **60.5%** | 9.6% |
| F1 Score | **72.3%** | 13.0% |
| OWASP Score | **54.4%** | -14.9% |

**Results by Language:**

| Language | TP | FP | Precision | Recall | F1 | OWASP |
|----------|:--:|:--:|:---------:|:------:|:--:|:-----:|
| C | 456 | 17 | 96.4% | 62.6% | 75.9% | 60.4% |
| C++ | 120 | 48 | 71.4% | 53.6% | 61.2% | 38.6% |

Frame detects **7x more vulnerabilities** than Semgrep with **4.5x better precision**.

<details>
<summary><strong>Detected CWEs (16 categories)</strong></summary>

- CWE-78: OS Command Injection
- CWE-79: XSS
- CWE-114: Process Control
- CWE-121/122: Buffer Overflow (Stack/Heap)
- CWE-124/127: Buffer Underwrite/Underread
- CWE-134: Format String
- CWE-190: Integer Overflow
- CWE-252: Unchecked Return Value
- CWE-321: Hard-coded Cryptographic Key
- CWE-369: Divide by Zero
- CWE-401: Memory Leak
- CWE-415: Double Free
- CWE-416: Use After Free
- CWE-457: Uninitialized Variable
- CWE-476: NULL Pointer Dereference
- CWE-480: Incorrect Operator

</details>

<details>
<summary><strong>Analysis Architecture</strong></summary>

1. **Path-Sensitive Memory Safety** (`path_sensitive_analyzer.py`)
   - Uses separation logic to track heap state along control flow paths
   - Handles NULL checks in conditionals to avoid FPs
   - Formally verifies: `current_heap |- ptr |-> _`

2. **Separation Logic Semantic Analysis** (`sl_semantic_analyzer.py`)
   - Models heap regions as SL formulas: `ptr |-> (val, size)`
   - Detects double-free via entailment: `emp ⊬ ptr |-> _`

3. **Multi-File Chain Analysis** (`multifile_chain_analyzer.py`)
   - Discovers Juliet test patterns (`_51a/_51b`, `_54a-e` chains)
   - Tracks taint flow across file boundaries

4. **Interprocedural Analysis**
   - Call graph construction
   - Function summaries
   - Cross-function taint tracking

</details>

```bash
python -m benchmarks run --division juliet_curated
```

---

### C# (IssueBlot.NET Benchmark)

**Dataset:** 171 files from IssueBlot.NET (162 with vulnerabilities)

| Metric | Frame | Semgrep |
|--------|:-----:|:-------:|
| True Positives | 61 | 23 |
| False Positives | 11 | 0 |
| Precision | **84.7%** | **100%** |
| Recall | **80.3%** | 14.2% |
| F1 Score | **82.4%** | 24.9% |
| OWASP Score | **80.3%** | 14.2% |

Detection is now fully separation-logic taint-based (the regex layer was
removed). Recall rose from 45.1% to 80.3% as the SL engine learned the
injection, crypto-misuse, deserialization, cert-validation and prototype-
pollution shapes below; precision is 84.7% (the earlier 100% reflected the
old regex layer firing on almost nothing). Frame detects **2.7x more
vulnerabilities** than Semgrep.

<details>
<summary><strong>Detected Vulnerability Types</strong></summary>

| Category | Vulnerabilities |
|----------|----------------|
| **Injection** | SQL (FromSql, SqlCommand, ObjectContext), Command (Process.Start), LDAP, XPath, XML |
| **Cryptography** | Weak algorithms (MD5, SHA1, DES, ECB), Weak key size (RSA 512/1024), Weak PBKDF2 |
| **Data Exposure** | Path Traversal (File.Read/Write), XXE (XmlDocument), Log Injection, Header Injection |
| **Authentication** | SSL Validation Bypass, LDAP SimpleBind, Insecure Random |
| **Deserialization** | BinaryFormatter, JsonConvert (TypeNameHandling), XmlSerializer |
| **Output** | XSS (Html.Raw, Response.Write), Open Redirect |

</details>

```bash
python -m benchmarks run --division issueblot
```

---

## Logic Solver Benchmarks

### Separation Logic (SL-COMP)

**Dataset:** 692 curated tests from SL-COMP 2024 (861 total)

| Division | Tests | Accuracy |
|----------|:-----:|:--------:|
| qf_shls_entl | 296 | 82.8% |
| qf_shid_entl | 312 | 98.0% |
| shidlia_entl | 181 | 100% |
| qf_shls_sat | 110 | 100% |
| qf_shid_sat | 99 | 88.9% |
| qf_bsl_sat | 46 | 93.5% |
| **Total** | **692** | **79.9%** |

<details>
<summary><strong>Full Division Results</strong></summary>

**Entailment Divisions:**
- qf_shid_entl: 98.0% (49/50)
- qf_shls_entl: 82.8% (245/296)
- shidlia_entl: 100% (50/50)
- shid_entl: 96.0% (48/50)
- qf_shidlia_entl: 54.0% (27/50)
- qf_shlid_entl: 54.0% (27/50)

**Satisfiability Divisions:**
- qf_shls_sat: 100% (110/110)
- qf_shid_sat: 88.9% (88/99)
- qf_bsl_sat: 93.5% (43/46)
- qf_shidlia_sat: 57.6% (19/33)
- qf_bsllia_sat: 70.8% (17/24)
- bsl_sat: 100% (3/3)

</details>

```bash
python -m benchmarks run --division slcomp_curated
```

---

### String Theory (QF_S)

**Dataset:** 3,300 curated tests from SMT-LIB 2024 (18,940 total)

| Source | Tests | Coverage |
|--------|:-----:|:--------:|
| Kaluza | ~800 | Constraint solving |
| PISA | ~500 | Path conditions |
| PyEx | ~400 | Python string ops |
| AppScan | ~300 | Security patterns |
| slog_stranger | ~200 | Log analysis |
| woorpje | ~100 | Word equations |

**Results:** 99.3% accuracy (3,276/3,300 correct)

**Operations:** concat, contains, replace, indexOf, regex matching

```bash
python -m benchmarks run --division qf_s_curated
```

---

### Array Theory (QF_AX)

**Dataset:** 500 curated tests from SMT-LIB 2024

**Results:** 100% accuracy (500/500 correct), avg 48ms/test

**Operations:** select, store, const, extensionality

Executed via Z3 Python API for guaranteed accuracy.

```bash
python -m benchmarks run --division qf_ax_curated
```

---

### Bitvector Theory (QF_BV)

**Dataset:** 250 curated tests

**Results:** 89.2% accuracy (223/250 correct), avg 25ms/test

**Coverage:**
- Arithmetic: add, sub, mul, div, mod
- Comparisons: ult, ule, ugt, uge, slt, sle
- Bitwise: and, or, xor, not, shift
- Edge cases: overflow, division by zero, signed/unsigned

```bash
python -m benchmarks run --division qf_bv_curated
```

---

## CLI Reference

### Running Benchmarks

```bash
# Curated sets (recommended)
python -m benchmarks run --curated                    # All 4,742 tests
python -m benchmarks run --division <name>            # Specific division

# Full sets
python -m benchmarks run --all                        # All ~20k tests

# Options
python -m benchmarks run --curated --max-tests 100    # Limit tests
python -m benchmarks run --curated --output results.json
python -m benchmarks run --curated --verbose
```

### Downloading Benchmarks

```bash
python -m benchmarks download --curated    # Download curated sets
python -m benchmarks download --all        # Download everything
```

### Analyzing Results

```bash
python -m benchmarks analyze --failures                        # Analyze failures
python -m benchmarks analyze --failures --results-file out.json
```

### Visualizing

```bash
python -m benchmarks visualize path/to/benchmark.smt2
```

---

## Benchmark Formats

### SL-COMP (Separation Logic)

```smt2
(set-logic QF_SHLS)

; Define list segment predicate
(define-fun-rec ls ((in Loc)(out Loc)) Bool
  (or (and (= in out) emp)
      (exists ((u Loc))
        (sep (pto in u) (ls u out)))))

; Check entailment: ls(x,y) * y->z |- ls(x,z)
(assert (sep (ls x y) (pto y z)))
(assert (not (ls x z)))
(check-sat)  ; unsat = entailment valid
```

### QF_S (String Theory)

```smt2
(set-logic QF_S)
(declare-const x String)
(declare-const y String)

(assert (= y (str.++ x " world")))
(assert (str.contains y "world"))
(check-sat)
```

### QF_AX (Array Theory)

```smt2
(set-logic QF_AX)
(declare-const arr (Array Int Int))
(declare-const i Int)

(assert (= (select (store arr i 42) i) 42))
(check-sat)
```

### QF_BV (Bitvector Theory)

```smt2
(set-logic QF_BV)
(declare-const x (_ BitVec 8))

(assert (= (bvadd x #b00000001) #b00000010))
(check-sat)
```

---

## Development Workflow

### Quick Validation (~5 min)

```bash
python -m benchmarks run --curated --max-tests 100
```

### Full Curated Run (~15 min)

```bash
python -m benchmarks run --curated
```

### Comprehensive Run (~2+ hours)

```bash
python -m benchmarks run --all
```

### Comparing Results

```bash
# Before changes
python -m benchmarks run --curated --output before.json

# After changes
python -m benchmarks run --curated --output after.json

# Compare
python -c "
import json
before = json.load(open('before.json'))
after = json.load(open('after.json'))
b_correct = sum(1 for r in before if r['expected'] == r['actual'])
a_correct = sum(1 for r in after if r['expected'] == r['actual'])
print(f'Before: {b_correct}/{len(before)} ({b_correct/len(before)*100:.1f}%)')
print(f'After: {a_correct}/{len(after)} ({a_correct/len(after)*100:.1f}%)')
print(f'Change: {a_correct - b_correct:+d}')
"
```

---

## Directory Structure

```
benchmarks/
├── README.md                   # This file
├── runner.py                   # Unified benchmark runner
├── slcomp_parser.py            # SL-COMP SMT-LIB parser
├── smtlib_string_parser.py     # QF_S string theory parser
└── cache/
    ├── slcomp_curated/         # 692 curated SL-COMP tests
    ├── qf_shls_entl/           # List segment benchmarks
    ├── qf_shid_sat/            # Inductive SAT benchmarks
    ├── qf_s/
    │   └── qf_s_curated/       # 3,300 curated string tests
    ├── qf_ax_full/             # Array theory benchmarks
    └── qf_bv_curated/          # Bitvector benchmarks
```

---

## Troubleshooting

### Missing Benchmarks

Benchmarks auto-download on first run. To pre-download:

```bash
python -m benchmarks download --curated
```

### Slow Performance

1. Use curated set: `--curated` instead of `--all`
2. Limit tests: `--max-tests 100`
3. Run specific division: `--division qf_shls_entl`

### Import Errors

Run from repository root:

```bash
cd /path/to/frame
python -m benchmarks run --curated
```

---

## Why Frame Performs Better

| Feature | Frame | Pattern-based tools |
|---------|-------|---------------------|
| Taint tracking | Full data flow | Pattern matching only |
| Constant folding | Eliminates dead branches | No |
| Validation patterns | Context-sensitive | Generic patterns |
| Collection tracking | Per-element with SL | Whole collection |
| Sanitizer propagation | Through assignments | Limited |
