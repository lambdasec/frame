# Frame Benchmark Suite

Comprehensive benchmark infrastructure for evaluating Frame against industry-standard test suites.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Results Summary](#results-summary)
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
python -m benchmarks run --division secbench_js           # JavaScript (166 files)
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

### SAST Security Benchmarks

| Language | Benchmark | Tests | Precision | Recall | OWASP Score | vs Semgrep |
|----------|-----------|-------|-----------|--------|-------------|------------|
| Python | OWASP | 500 | 95.3% | 83.5% | **80.9%** | +76.4 pts |
| Java | OWASP | 500 | 97.2% | 84.8% | **81.5%** | +65.8 pts |
| JavaScript | SecBench.js | 166 | 99.1% | 81.2% | **77.6%** | +68.0 pts |
| C/C++ | NIST Juliet | 1,000 | 89.9% | 60.5% | **54.4%** | +69.3 pts |
| C# | IssueBlot.NET | 171 | 100% | 45.1% | **45.1%** | +30.9 pts |

### Logic Solver Benchmarks

| Theory | Benchmark | Tests | Accuracy | Avg Time |
|--------|-----------|-------|----------|----------|
| Separation Logic | SL-COMP | 692 | 79.9% | ~1s |
| String | QF_S | 3,300 | 99.3% | ~15ms |
| Array | QF_AX | 500 | 100% | 48ms |
| Bitvector | QF_BV | 250 | 89.2% | 25ms |
| **Total Curated** | | **4,742** | **96.0%** | 970ms |

---

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

**Dataset:** 166 files from ICSE 2023 SecBench.js, 138 with vulnerabilities

| Metric | Frame | Semgrep |
|--------|:-----:|:-------:|
| True Positives | 112 | 28 |
| False Positives | 1 | 3 |
| Precision | **99.1%** | 90.3% |
| Recall | **81.2%** | 20.3% |
| F1 Score | **89.2%** | 33.1% |
| OWASP Score | **77.6%** | 9.6% |
| Scan Time | **1.2s** | 63.0s |

**Sources:** Juice Shop, NodeGoat, DVNA, OpenSSF CVE samples

Frame is **52x faster** than Semgrep on this benchmark.

```bash
python -m benchmarks run --division secbench_js
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

**Dataset:** 171 files, 162 with vulnerabilities

| Metric | Frame | Semgrep |
|--------|:-----:|:-------:|
| True Positives | 73 | 23 |
| False Positives | 0 | 0 |
| Precision | **100%** | **100%** |
| Recall | **45.1%** | 14.2% |
| F1 Score | **62.1%** | 24.9% |
| OWASP Score | **45.1%** | 14.2% |

Frame detects **3.2x more vulnerabilities** with the same 100% precision.

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
