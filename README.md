# Frame

**Static Analysis for Memory Safety and Security**

[![Tests](https://img.shields.io/badge/tests-1330%20passed-green)](tests/) [![Python](https://img.shields.io/badge/python-3.10%2B-blue)]() [![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

## Overview

Frame is a static analysis tool that uses **separation logic** to find security vulnerabilities and memory safety bugs. It provides:

- **Security Scanner**: Detects SQL injection, XSS, command injection, and 30+ vulnerability types across 5 languages
- **Separation Logic Solver**: Proves memory safety properties about heap, pointers, and data structures

**Key Results** (vs Semgrep on industry benchmarks):

| Language | Precision | Recall | OWASP Score | vs Semgrep |
|----------|-----------|--------|-------------|------------|
| Python | 95.3% | 83.5% | **80.9%** | +76.4 pts |
| Java | 97.2% | 84.8% | **81.5%** | +65.8 pts |
| JavaScript | 99.1% | 81.2% | **77.6%** | +68.0 pts |
| C/C++ | 89.9% | 60.5% | **54.4%** | +69.3 pts |
| C# | 100% | 45.1% | **45.1%** | +30.9 pts |

See [benchmarks/README.md](benchmarks/README.md) for detailed methodology and results.

## Installation

```bash
git clone https://github.com/lambdasec/frame.git
cd frame
pip install -e ".[scan]"  # For security scanning
```

**Requirements**: Python 3.10+, Z3 SMT Solver (installed automatically)

## Quick Start

### Security Scanning

```bash
# Scan a file
frame scan app.py

# Scan a directory
frame scan src/ --pattern "**/*.py"

# CI/CD output (SARIF format)
frame scan app.py --format sarif -o results.sarif
```

### Logic Verification

```bash
# Check separation logic entailment
frame solve "x |-> 5 * y |-> 3 |- x |-> 5"
# Output: VALID
```

## Architecture

Frame uses a multi-stage analysis pipeline:

```
Source Code
    |
    v
Language Frontend (Python/Java/JS/C/C++/C#)
    | tree-sitter parsing
    v
SIL (Separation Intermediate Language)
    | TaintSource/TaintSink annotations
    v
Symbolic Execution (Translator)
    | VulnerabilityCheck formulas
    v
Incorrectness Checker + Z3 Verification
    |
    v
Vulnerabilities / Entailment Result
```

**Components**:

- **Language Frontends**: Parse source code via tree-sitter into SIL with taint annotations
- **Translator**: Symbolic execution generates VulnerabilityCheck formulas with Frame SL assertions
- **Verification**: Incorrectness logic + Z3 for formal verification of vulnerability reachability
- **Solver**: Separation logic entailment checking for memory safety (heap, lists, trees)

**Two Analysis Paths**:

1. **Taint Analysis** (injection, XSS): Tracks data flow from sources to sinks with Z3 verification
2. **Memory Safety** (buffer overflow, UAF): SL formulas with entailment checking `heap |- ptr |-> _`

## CLI Reference

### `frame scan` - Security Scanner

```bash
frame scan app.py                           # Basic scan
frame scan src/ --pattern "**/*.py"         # Directory scan
frame scan app.py --format sarif -o out.sarif  # SARIF output for CI/CD
frame scan app.py --no-verify               # Fast mode (skip Z3 verification)
frame scan app.py --min-severity high       # Filter by severity
frame scan app.py --fail-on critical        # CI exit code control
```

**Supported Languages**: Python, Java, JavaScript/TypeScript, C/C++, C#

### `frame solve` - Entailment Checker

```bash
frame solve "x |-> 5 |- x |-> 5"            # Check entailment
frame solve "ls(x, nil) |- ls(x, nil)" -v   # Verbose output
frame solve "x |-> 5 |- y |-> 5" --model    # Show countermodel
```

### Other Commands

```bash
frame check formulas.txt    # Batch check multiple formulas
frame parse "x |-> 5"       # Show formula structure
frame repl                  # Interactive mode
```

## Security Scanner

Frame tracks how untrusted data flows through code. When tainted data reaches a dangerous operation without sanitization, Frame reports it.

### OWASP Top 10 Coverage

| OWASP 2025 | Vulnerabilities Detected |
|------------|-------------------------|
| **A01: Broken Access Control** | Path Traversal, SSRF, Open Redirect, IDOR |
| **A02: Security Misconfiguration** | Header Injection, Secret Exposure |
| **A04: Cryptographic Failures** | Weak Crypto, Hardcoded Secrets |
| **A05: Injection** | SQL, XSS, Command, LDAP, XPath, Code, XXE |
| **A07: Authentication Failures** | Broken Auth, Session Fixation |
| **A08: Integrity Failures** | Insecure Deserialization |
| **A09: Logging Failures** | Log Injection |

### Example

```python
# vulnerable.py
def search():
    user_id = input()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)  # SQL Injection
```

```bash
$ frame scan vulnerable.py

Vulnerabilities Found: 1
----------------------------------------
1. [CRITICAL] sql_injection
   Location: vulnerable.py:4:4
   CWE: CWE-89
   Source: user_id
   Confidence: 80%
```

### CI/CD Integration (GitHub Actions)

```yaml
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

## Python API

```python
from frame import EntailmentChecker
from frame.sil import FrameScanner

# Entailment checking
checker = EntailmentChecker()
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)  # True

# Security scanning
scanner = FrameScanner()
result = scanner.scan_file("app.py")
for vuln in result.vulnerabilities:
    print(f"{vuln.type}: {vuln.cwe_id}")
```

## Separation Logic

Frame supports separation logic for reasoning about heap memory:

| Syntax | Meaning |
|--------|---------|
| `x \|-> v` | Location x points to value v |
| `emp` | Empty heap |
| `P * Q` | P and Q use disjoint memory |
| `P -* Q` | Magic wand (if given P, produces Q) |
| `P \|- Q` | Entailment (P implies Q) |

**Built-in Predicates**: `ls(x,y)` (list segment), `list(x)` (linked list), `tree(x)` (binary tree), `dll(x,p,y,n)` (doubly-linked list)

**Example**:
```bash
# List segment transitivity
frame solve "ls(x, y) * ls(y, z) |- ls(x, z)"
```

## Benchmarks

Frame achieves state-of-the-art results on industry benchmarks:

| Benchmark | Tests | Precision | Recall | OWASP Score |
|-----------|-------|-----------|--------|-------------|
| OWASP Python | 500 | 95.3% | 83.5% | 80.9% |
| OWASP Java | 500 | 97.2% | 84.8% | 81.5% |
| SecBench.js | 166 | 99.1% | 81.2% | 77.6% |
| NIST Juliet (C/C++) | 1000 | 89.9% | 60.5% | 54.4% |
| IssueBlot.NET (C#) | 171 | 100% | 45.1% | 45.1% |

**Logic Solver** (SL-COMP, SMT-LIB):

| Theory | Tests | Accuracy |
|--------|-------|----------|
| Separation Logic | 692 | 79.9% |
| String (QF_S) | 3,300 | 99.3% |
| Array (QF_AX) | 500 | 100% |
| Bitvector (QF_BV) | 250 | 89.2% |

```bash
python -m benchmarks run --curated  # Run all curated benchmarks
```

See [benchmarks/README.md](benchmarks/README.md) for detailed results and methodology.

## Code Organization

```
frame/
  core/           # Formula parsing and AST
  encoding/       # Z3 SMT encoding
  checking/       # Entailment checker
  folding/        # Predicate folding/unfolding
  predicates/     # Built-in predicates (lists, trees)
  lemmas/         # Proven facts for fast-path checks
  sil/            # Security scanner
    scanner.py        # Main interface
    translator.py     # SIL to Frame
    frontends/        # Language parsers
  cli.py          # Command-line interface
```

## References

- Reynolds, O'Hearn (2002). [Separation Logic: A Logic for Shared Mutable Data Structures](https://doi.org/10.1109/LICS.2002.1029817)
- Piskac, Wies, Zufferey (2013). [Automating Separation Logic with Trees and Data](https://dl.acm.org/doi/10.1007/978-3-319-08867-9_47)
- O'Hearn (2020). [Incorrectness Logic](https://doi.org/10.1145/3371078)

**Related Tools**: [Infer](https://fbinfer.com/) (inspiration for SIL), [Sleek/HIP](https://github.com/sleek-hoare), [Cyclist](https://www.cyclist.cs.ucl.ac.uk/)

## Citation

```bibtex
@software{frame_solver,
  title = {Frame: Separation Logic Verification Tool with Security Scanning},
  author = {Asankhaya Sharma},
  year = {2025},
  url = {https://github.com/lambdasec/frame}
}
```

---

Built with [Z3](https://github.com/Z3Prover/z3), [tree-sitter](https://tree-sitter.github.io/), [SL-COMP](https://sl-comp.github.io/), [SMT-LIB](https://smtlib.cs.uiowa.edu/)
