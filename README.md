# Frame

**A Static Analysis Tool for Memory Safety and Security**

[![Tests](https://img.shields.io/badge/tests-1330%20passed-green)](tests/) [![Python](https://img.shields.io/badge/python-3.10%2B-blue)]() [![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE) [![OWASP Score](https://img.shields.io/badge/OWASP%20Score-80.9%25-brightgreen)](benchmarks/) [![Benchmarks](https://img.shields.io/badge/benchmarks-96.0%25%20(4742)-blue)](benchmarks/)

## What is Frame?

Frame helps you find bugs before they become vulnerabilities. It uses **separation logic**—a mathematical framework for reasoning about memory—to detect issues like:

- **Memory errors**: Use-after-free, buffer overflows, null pointer dereferences
- **Security vulnerabilities**: SQL injection, XSS, command injection, path traversal
- **Data flow problems**: Tainted user input reaching sensitive operations

**How it works**: Frame analyzes your code without running it. It builds a model of how your program uses memory and data, then mathematically proves whether dangerous conditions can occur.

```bash
# Scan a file for vulnerabilities
$ frame scan app.py

# Check a memory safety property
$ frame solve "x |-> 5 * y |-> 3 |- x |-> 5"
✓ VALID
```

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Security Scanner](#security-scanner)
- [Python API](#python-api)
- [Supported Theories](#supported-theories)
- [Benchmarks](#benchmarks)
- [Architecture](#architecture)
- [Getting Help](#getting-help)
- [References](#references)

---

## Features

### Two Ways to Use Frame

| Use Case | Command | What It Does |
|----------|---------|--------------|
| **Security scanning** | `frame scan app.py` | Find vulnerabilities in your code |
| **Logic verification** | `frame solve "P \|- Q"` | Prove memory safety properties |

### Core Capabilities

- **Security Scanner**: Finds SQL injection, XSS, command injection, and 30+ vulnerability types using taint analysis
- **Separation Logic Solver**: Proves properties about heap memory, pointers, and data structures (lists, trees, etc.)
- **Multi-Theory Support**: Reasons about heap, strings, arrays, and bitvectors in one framework
- **Fast**: Sub-millisecond for simple checks, 10-50x faster than Z3/CVC5 on string constraints

### Vulnerability Detection

- SQL Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- Buffer Overflow detection
- Use-After-Free detection

### Output Formats

- Human-readable text
- JSON for programmatic access
- SARIF for CI/CD integration (GitHub, GitLab, etc.)
- CSV for batch analysis

---

## Installation

```bash
git clone https://github.com/lambdasec/frame.git
cd frame
```

**Choose your installation:**

| Installation | Command | Use When |
|--------------|---------|----------|
| **Recommended** | `pip install -e ".[scan]"` | You want to scan code for vulnerabilities |
| Basic | `pip install -e .` | You only need the logic solver |
| Full | `pip install -e ".[all]"` | You're developing or running benchmarks |

### Requirements

- **Python 3.10+**
- Z3 SMT Solver (installed automatically)
- tree-sitter (installed with `[scan]` option)

---

## Quick Start

### Security Scanning (Most Common Use)

```bash
# Scan a Python file for vulnerabilities
frame scan app.py

# Scan a directory
frame scan src/ --pattern "**/*.py"

# Get machine-readable output for CI/CD
frame scan app.py --format sarif -o results.sarif
```

### Logic Verification

```bash
# Check if an entailment is valid
# Read as: "x points to 5 AND y points to 3 (separately) IMPLIES x points to 5"
frame solve "x |-> 5 * y |-> 3 |- x |-> 5"
# Output: ✓ VALID

# The "|-> " means "points to", "*" means "separate memory regions", "|-" means "implies"
```

### Other Commands

```bash
frame parse "x |-> 5 * y |-> 3"   # Show formula structure
frame check formulas.txt          # Batch check multiple formulas
frame repl                        # Interactive mode
```

### Python API

```python
from frame import EntailmentChecker

checker = EntailmentChecker()

# Check: does "x points to 5, y points to 3" imply "x points to 5"?
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)   # True
print(result.reason)  # "Reflexivity" (trivially true)
```

---

## CLI Reference

Frame provides a unified command-line interface with multiple subcommands.

### `frame scan` - Security Scanner

Scan source code for security vulnerabilities using taint analysis.

```bash
# Basic scan
frame scan app.py

# Scan directory with pattern
frame scan src/ --pattern "**/*.py"

# Output formats
frame scan app.py --format text    # Human-readable (default)
frame scan app.py --format json    # JSON output
frame scan app.py --format sarif   # SARIF for CI/CD

# Save to file
frame scan app.py --format sarif -o results.sarif

# Fast scan (skip verification, may have false positives)
frame scan app.py --no-verify

# Filter by severity
frame scan app.py --min-severity high

# CI/CD exit codes
frame scan app.py --fail-on critical  # Exit 1 only on critical
frame scan app.py --fail-on none      # Always exit 0
```

**Options:**

| Option | Description |
|--------|-------------|
| `-l, --language` | Source language (default: python) |
| `-p, --pattern` | Glob pattern for directory scan |
| `-f, --format` | Output format: text, json, sarif |
| `-o, --output` | Output file (default: stdout) |
| `--no-verify` | Skip Frame verification |
| `--min-severity` | Minimum severity to report |
| `--fail-on` | Exit with error on this severity |
| `--timeout` | Verification timeout in ms |

### `frame solve` - Entailment Checker

Check if a separation logic entailment is valid.

```bash
# Basic check
frame solve "x |-> 5 |- x |-> 5"

# With verbose output
frame solve "x |-> 5 * y |-> 3 |- x |-> 5" --verbose

# JSON output
frame solve "ls(x, nil) |- ls(x, nil)" --format json

# Show countermodel if invalid
frame solve "x |-> 5 |- y |-> 5" --model

# Read from file
frame solve -f entailment.txt

# Custom timeout
frame solve "complex formula" --timeout 10000
```

**Output:**

```
✓ VALID
```
or
```
✗ INVALID
  Reason: Sanity check
```

### `frame check` - Batch Checker

Check multiple entailments from a file.

```bash
# Basic batch check
frame check entailments.txt

# With different output formats
frame check entailments.txt --format json
frame check entailments.txt --format csv -o results.csv

# Stop on first failure
frame check entailments.txt --stop-on-failure

# Verbose output
frame check entailments.txt -v
```

**Input file format:**

```
# Comments start with # or //
x |-> 5 |- x |-> 5
emp |- emp
ls(x, nil) |- ls(x, nil)
```

**Output:**

```
============================================================
Frame Entailment Check: entailments.txt
============================================================

Total: 3
Valid: 3 (100.0%)
Invalid: 0
Errors: 0
Time: 15.23ms
============================================================
```

### `frame parse` - Formula Parser

Parse and display formula structure.

```bash
# Tree format (default)
frame parse "x |-> 5 * y |-> 3"

# JSON format
frame parse "x |-> 5 * y |-> 3" --format json

# S-expression format
frame parse "ls(x, nil)" --format sexp

# Read from file
frame parse -f formula.txt
```

**Tree output:**

```
└── *
    ├── points-to
    │   ├── x
    │   └── 5
    └── points-to
        ├── y
        └── 3
```

### `frame repl` - Interactive Mode

Start an interactive Read-Eval-Print Loop.

```bash
frame repl
```

**Commands in REPL:**

```
frame> x |-> 5 |- x |-> 5
✓ VALID (Reflexivity)

frame> :parse x |-> 5 * y |-> 3
└── *
    ├── points-to ...

frame> :help
frame> :quit
```

---

## Security Scanner

Frame's security scanner finds vulnerabilities by tracking how untrusted data (like user input) flows through your code. If tainted data reaches a dangerous operation (like a SQL query) without sanitization, Frame reports it.

### How It Works

```
Source Code → Parse → Build Control Flow → Track Taint → Verify with Logic → Report
```

The scanner uses a **Separation Intermediate Language (SIL)** inspired by Facebook Infer, enabling:

- Language-agnostic analysis
- Precise taint tracking
- Local reasoning with the frame rule
- Zero false positives (when verification is enabled)

### OWASP Top 10 2025 Coverage

Frame detects vulnerabilities across [OWASP Top 10](https://owasp.org/Top10/) categories using static analysis and taint tracking:

| OWASP 2025 | Vulnerabilities Detected | CWEs |
|------------|-------------------------|------|
| **A01: Broken Access Control** | Path Traversal, SSRF, Open Redirect, IDOR, CORS Misconfiguration | CWE-22, CWE-918, CWE-601, CWE-639, CWE-942 |
| **A02: Security Misconfiguration** | Header Injection, Secret Exposure, Debug Enabled | CWE-113, CWE-200, CWE-215 |
| **A03: Supply Chain Failures** | *Requires SCA tools (out of scope for SAST)* | — |
| **A04: Cryptographic Failures** | Weak Crypto, Hardcoded Secrets, Insecure Random, Weak Hash | CWE-327, CWE-798, CWE-330, CWE-328 |
| **A05: Injection** | SQL, XSS, Command, LDAP, XPath, Code, Template, NoSQL, XXE, ReDoS | CWE-89, CWE-79, CWE-78, CWE-90, CWE-643, CWE-94, CWE-1336, CWE-943, CWE-611, CWE-1333 |
| **A06: Insecure Design** | Mass Assignment, Race Condition | CWE-915, CWE-362 |
| **A07: Authentication Failures** | Broken Auth, Session Fixation, Weak Password | CWE-287, CWE-384, CWE-521 |
| **A08: Integrity Failures** | Insecure Deserialization | CWE-502 |
| **A09: Logging Failures** | Log Injection, Sensitive Data Logged | CWE-117, CWE-532 |
| **A10: Error Handling** | Error Disclosure, Unhandled Exception | CWE-209, CWE-755 |

> **Note:** A03 (Supply Chain Failures) requires Software Composition Analysis (SCA) tools that analyze dependency manifests and check against vulnerability databases. Frame focuses on SAST (Static Application Security Testing) with taint analysis for detecting code-level vulnerabilities.

### Supported Frameworks

**Python:**
- **Web:** Flask, Django, FastAPI
- **Database:** SQLAlchemy, PyMongo, Redis
- **Security:** cryptography, hashlib, secrets
- **Shell:** subprocess, os.system
- **XML:** lxml, xml.etree, defusedxml
- **Templates:** Jinja2, Mako

### Example Scan

```python
# vulnerable.py
def search():
    user_id = input()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)  # SQL Injection!
```

```bash
$ frame scan vulnerable.py

============================================================
Frame Security Scan: vulnerable.py
============================================================

Vulnerabilities Found: 1
----------------------------------------

1. [CRITICAL] sql_injection
   Location: vulnerable.py:4:4
   Function: search
   Description: Tainted data from 'user_id' flows to sql sink
   CWE: CWE-89
   Source: user_id
   Data flow: query
   Confidence: 80%

============================================================
```

### CI/CD Integration

**GitHub Actions:**

```yaml
- name: Checkout
  uses: actions/checkout@v4

- name: Setup Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.10'

- name: Install Frame
  run: |
    git clone https://github.com/lambdasec/frame.git
    cd frame && pip install -e ".[scan]"

- name: Security Scan
  run: frame scan src/ --format sarif -o results.sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

---

## Python API

Use Frame programmatically in your Python code.

### Entailment Checking

```python
from frame import EntailmentChecker

checker = EntailmentChecker(timeout=5000)  # timeout in milliseconds

# Check if entailment holds
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)   # True
print(result.reason)  # "Reflexivity" or explanation

# Works with predicates too
result = checker.check_entailment("ls(x, nil) |- ls(x, nil)")
```

### Formula Parsing

```python
from frame import parse, parse_entailment

# Parse a single formula (returns AST)
formula = parse("x |-> 5 * y |-> 3")

# Parse an entailment (returns two ASTs: left and right of |-)
antecedent, consequent = parse_entailment("x |-> 5 |- x |-> 5")
```

### Security Scanning

```python
from frame.sil import FrameScanner

scanner = FrameScanner()
result = scanner.scan_file("app.py")

for vuln in result.vulnerabilities:
    print(f"{vuln.type}: {vuln.description}")
    print(f"  Location: {vuln.location}")
    print(f"  CWE: {vuln.cwe_id}")
```

### Custom Predicates

Define your own data structure predicates:

```python
from frame import PredicateRegistry, EntailmentChecker

registry = PredicateRegistry()

# Define a binary search tree predicate
registry.register_from_smt2("bst", """
(bst ?x ?lo ?hi) := ((= ?x nil) * emp) |
  (exists ?v ?l ?r. (?x |-> (?v, ?l, ?r)) * (?lo < ?v) * (?v < ?hi) *
   (bst ?l ?lo ?v) * (bst ?r ?v ?hi))
""")

checker = EntailmentChecker(predicate_registry=registry)
result = checker.check_entailment(
    "x |-> (5, l, r) * bst(l, 0, 5) * bst(r, 5, 10) |- bst(x, 0, 10)"
)
```

---

## Supported Theories

Frame can reason about different types of program data. Most users only need separation logic (for the security scanner).

### Separation Logic (Core)

Separation logic describes heap memory—how pointers connect data structures.

**Basic Operators:**

| Syntax | Name | Meaning | Example |
|--------|------|---------|---------|
| `x \|-> v` | Points-to | Location x holds value v | `x \|-> 5` means x points to 5 |
| `emp` | Empty | No heap memory used | Used as base case |
| `P * Q` | Separating conjunction | P and Q use *disjoint* memory | `x \|-> 1 * y \|-> 2` (x ≠ y) |
| `P -* Q` | Magic wand | "If given P, produces Q" | Advanced; for frame inference |
| `P \|- Q` | Entailment | "P implies Q" | What we're proving |

**Built-in Predicates:**

| Predicate | Meaning | Example |
|-----------|---------|---------|
| `ls(x, y)` | Linked list segment from x to y | `ls(head, nil)` is a complete list |
| `list(x)` | Null-terminated linked list | `list(head)` |
| `tree(x)` | Binary tree rooted at x | `tree(root)` |
| `dll(x, p, y, n)` | Doubly-linked list | Four-argument predicate |

**Example entailments:**

```bash
# "x points to y, and y is a list" implies "x is a list"
frame solve "x |-> y * list(y) |- list(x)"

# Two list segments joined together form one segment
frame solve "ls(x, y) * ls(y, z) |- ls(x, z)"
```

### String Theory (QF_S)

For reasoning about string operations (useful for injection vulnerability detection).

```python
formula = parse('x = "hello" & y = (str.++ x " world")')
```

Supported: concatenation, contains, indexOf, replace, substring, regex matching.

### Array Theory (QF_AX)

For reasoning about array access and buffer operations.

```python
from frame.core.ast import ArraySelect, ArrayStore, Var, Const

arr = ArrayStore(Var("arr"), Const(5), Const(42))  # arr[5] = 42
val = ArraySelect(arr, Const(5))                    # read arr[5]
```

### Bitvector Theory (QF_BV)

For reasoning about fixed-width integers and overflow.

```python
from frame.core.ast import BitVecExpr, BitVecVal

# 8-bit overflow: 255 + 1 = 0 (wraps around)
overflow = BitVecExpr("bvadd", [BitVecVal(255, 8), BitVecVal(1, 8)], 8)
```

---

## Benchmarks

Frame is validated against industry-standard benchmark suites.

### Security Scanner (OWASP Benchmark)

Frame's security scanner is tested against industry-standard OWASP benchmarks:

**Python Benchmark** (500 tests, 194 vulnerabilities):

| Metric | Frame | Semgrep | Bandit |
|--------|-------|---------|--------|
| **Precision** | **95.3%** | 42.5% | 48.3% |
| **Recall** | **83.5%** | 32.0% | 28.9% |
| **OWASP Score** | **80.9%** | 4.5% | 9.3% |

**Java Benchmark** (500 tests, 289 vulnerabilities):

| Metric | Frame | Semgrep | FindSecBugs |
|--------|-------|---------|-------------|
| **Precision** | **97.2%** | 56.3% | 68.9% |
| **Recall** | 84.8% | **90.4%** | 50% |
| **F1 Score** | **90.6%** | 69.4% | 52.1% |
| **OWASP Score** | **81.5%** | 15.7% | 39% |

**JavaScript/TypeScript Benchmark** (SecBench.js - 166 files, 138 with vulnerabilities):

| Metric | Frame | Semgrep |
|--------|-------|---------|
| **Precision** | **99.1%** | 90.3% |
| **Recall** | **81.2%** | 20.3% |
| **F1 Score** | **89.2%** | 33.1% |
| **OWASP Score** | **77.6%** | 9.6% |
| **Time** | **1.2s** | 63.0s |

**C/C++ Benchmark** (NIST Juliet - 471 curated files, 418 with vulnerabilities):

| Metric | Frame | Semgrep | Advantage |
|--------|-------|---------|-----------|
| **Precision** | **95.4%** | 100.0% | Semgrep +4.6% |
| **Recall** | **80.1%** | 3.8% | **Frame +76.3%** |
| **F1 Score** | **87.1%** | 7.4% | **Frame +79.7%** |
| **OWASP Score** | **50.0%** | 3.8% | **Frame +46.2%** |
| **Time** | 5.3s | ~60s | Frame 11x faster |

*Frame detects 21x more vulnerabilities than Semgrep (335 vs 16 TPs) with 95.4% precision. Coverage includes buffer overflows, integer overflows, command injection, format strings, divide-by-zero, and 40+ CWE types.*

Frame achieves **80.9% OWASP Score** on Python, **81.5% OWASP Score** on Java, **77.6% OWASP Score** on JavaScript/TypeScript, and **50.0% OWASP Score** on C/C++. Frame is **11-52x faster** than Semgrep across benchmarks.

```bash
# Run security benchmarks
python -m benchmarks run --division owasp_python_curated
python -m benchmarks run --division owasp_java
python -m benchmarks run --division secbench_js
python -m benchmarks run --division juliet  # C/C++ (NIST Juliet)
```

### Logic Solver (SMT-LIB/SL-COMP)

**Curated Results** (4,742 tests, ~5 minutes):

| Theory | Tests | Accuracy | Avg Time |
|--------|-------|----------|----------|
| Separation Logic (SL-COMP) | 692 | 79.9% | ~1s |
| String (QF_S) | 3,300 | **99.3%** | ~15ms |
| Array (QF_AX) | 500 | **100%** | 0.048s |
| Bitvector (QF_BV) | 250 | 89.2% | 0.025s |
| **Total** | **4,742** | **96.0%** | 970ms |

**Full Results** (19,801 tests, ~2+ hours):

| Theory | Tests | Accuracy | Avg Time |
|--------|-------|----------|----------|
| Separation Logic (SL-COMP) | 861 | 77.7% | 0.8s |
| String (QF_S) | 18,940 | 84.2% | ~15ms |
| Array (QF_AX) | 500 | **100%** | 0.048s |
| Bitvector (QF_BV) | 250 | 76.4% | 0.025s |
| **Total** | **19,801** | **83.9%** | 0.8s |

```bash
# Run curated benchmarks (~5 minutes)
python -m benchmarks run --curated

# Run full benchmarks (~2+ hours)
python -m benchmarks run --all
```

**Benchmark Sources:**
- **OWASP Benchmark**: Industry-standard security test suite
- **SL-COMP 2024**: Official separation logic competition
- **SMT-LIB 2024**: QF_S, QF_AX, QF_BV from Zenodo release

See [benchmarks/README.md](benchmarks/README.md) for detailed methodology.

---

## Architecture

### How Frame Works

**Security Scanner Pipeline:**
```
Source Code → Parse (tree-sitter) → Build CFG → Taint Analysis → Verify with Frame → Report
```

**Entailment Checker Pipeline:**
```
Formula String → Parse → Fold predicates → Unfold definitions → Encode to Z3 → Solve
```

The key insight: Frame converts separation logic formulas into SMT queries that Z3 can solve. This lets us leverage Z3's power while keeping the intuitive separation logic interface.

### Code Organization

```
frame/
├── core/           # Formula parsing and AST
├── encoding/       # Convert formulas to Z3 constraints
├── checking/       # Main entailment checker
├── folding/        # Predicate folding/unfolding
├── predicates/     # Built-in predicates (lists, trees, etc.)
├── lemmas/         # Proven facts for fast-path checks
├── sil/            # Security scanner
│   ├── scanner.py      # Main interface
│   ├── translator.py   # SIL to Frame
│   └── frontends/      # Language parsers
└── cli.py          # Command-line interface
```

See [CLAUDE.md](CLAUDE.md) for the full development guide.

---

## Getting Help

- **Command help**: `frame --help` or `frame <command> --help`
- **Interactive mode**: `frame repl` then type `:help`
- **Issues & bugs**: [GitHub Issues](https://github.com/lambdasec/frame/issues)
- **Development guide**: See [CLAUDE.md](CLAUDE.md)

---

## References

### Academic Papers

- Reynolds, O'Hearn (2002). [Separation Logic: A Logic for Shared Mutable Data Structures](https://doi.org/10.1109/LICS.2002.1029817) — The foundational paper
- Piskac, Wies, Zufferey (2013). [Automating Separation Logic with Trees and Data](https://dl.acm.org/doi/10.1007/978-3-319-08867-9_47) — SMT encoding approach
- O'Hearn (2020). [Incorrectness Logic](https://doi.org/10.1145/3371078) — Bug-finding logic

### Related Tools

- [Infer](https://fbinfer.com/) — Facebook's static analyzer (inspiration for Frame's SIL)
- [Sleek/HIP](https://github.com/sleek-hoare) — NUS separation logic prover
- [Cyclist](https://www.cyclist.cs.ucl.ac.uk/) — UCL cyclic proof system

---

## Citation

```bibtex
@software{frame_solver,
  title = {Frame: Separation Logic Verification Tool with Security Scanning},
  author = {Asankhaya Sharma},
  year = {2025},
  url = {https://github.com/lambdasec/frame}
}
```

## Acknowledgments

Built with:
- [Z3 SMT Solver](https://github.com/Z3Prover/z3) - Microsoft Research
- [tree-sitter](https://tree-sitter.github.io/) - Incremental parsing
- [SL-COMP](https://sl-comp.github.io/) - Separation logic benchmarks
- [SMT-LIB](https://smtlib.cs.uiowa.edu/) - SMT standard format
