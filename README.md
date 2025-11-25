# Frame

**Separation Logic Verification Tool with Security Scanning**

Frame is a fast, practical separation logic solver that combines heap reasoning, taint analysis, and automated vulnerability detection. It provides both a powerful Python API and a command-line interface for security scanning.

[![Tests](https://img.shields.io/badge/tests-1329%20passed-green)]() [![Python](https://img.shields.io/badge/python-3.9%2B-blue)]() [![License](https://img.shields.io/badge/license-MIT-blue)]()

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
- [References](#references)

---

## Features

### Core Capabilities

- **Separation Logic Solver**: Entailment checking with inductive predicates (lists, trees, DLLs)
- **Security Scanner**: Automated vulnerability detection with taint analysis
- **Multi-Theory Support**: Heap, strings, arrays, and bitvectors in a unified framework
- **Command-Line Interface**: `frame scan`, `frame solve`, `frame check`, `frame parse`
- **High Performance**: <1ms reflexivity checks, 10-50x faster than Z3/CVC5 on string constraints

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

### Basic Installation

```bash
git clone https://github.com/lambdasec/frame.git
cd frame
pip install -e .
```

### With Security Scanner (Recommended)

```bash
pip install -e ".[scan]"
```

### Full Development Setup

```bash
pip install -e ".[all]"
```

### Requirements

- Python 3.9+
- Z3 SMT Solver (installed automatically)
- tree-sitter (for security scanning)

---

## Quick Start

### Command Line

```bash
# Scan a Python file for vulnerabilities
frame scan app.py

# Check a separation logic entailment
frame solve "x |-> 5 * y |-> 3 |- x |-> 5"

# Parse and display a formula
frame parse "x |-> 5 * y |-> 3"

# Interactive REPL
frame repl
```

### Python API

```python
from frame import EntailmentChecker

checker = EntailmentChecker()
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)  # True
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

Frame includes a powerful security scanner that uses separation logic for precise vulnerability detection.

### Architecture

```
Source Code → Python Frontend → SIL (IR) → Taint Analysis → Frame Verification → Vulnerabilities
```

The scanner uses a **Separation Intermediate Language (SIL)** inspired by Facebook Infer, enabling:

- Language-agnostic analysis
- Precise taint tracking
- Local reasoning with the frame rule
- Zero false positives (when verification is enabled)

### Detected Vulnerabilities

| Type | CWE | Description |
|------|-----|-------------|
| SQL Injection | CWE-89 | Tainted data in SQL queries |
| XSS | CWE-79 | Tainted data in HTML output |
| Command Injection | CWE-78 | Tainted data in shell commands |
| Path Traversal | CWE-22 | Tainted data in file paths |
| SSRF | CWE-918 | Tainted data in URLs |
| Code Injection | CWE-94 | Tainted data in eval/exec |

### Supported Frameworks

**Python:**
- Flask (`request.args`, `request.form`, `request.data`)
- Django (`request.GET`, `request.POST`)
- SQLAlchemy (`cursor.execute`)
- subprocess (`os.system`, `subprocess.run`)
- File operations (`open`, `os.path.join`)

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
- name: Security Scan
  run: |
    pip install frame-sl[scan]
    frame scan src/ --format sarif -o results.sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

---

## Python API

### Entailment Checking

```python
from frame import EntailmentChecker

checker = EntailmentChecker(timeout=5000)

# Check entailment
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)   # True
print(result.reason)  # Why it's valid/invalid

# With predicates
result = checker.check_entailment("ls(x, nil) |- ls(x, nil)")
```

### Formula Parsing

```python
from frame import parse, parse_entailment

# Parse a formula
formula = parse("x |-> 5 * y |-> 3")

# Parse an entailment (returns antecedent, consequent)
ant, cons = parse_entailment("x |-> 5 |- x |-> 5")
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

```python
from frame import PredicateRegistry, EntailmentChecker

registry = PredicateRegistry()
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

### Separation Logic (Core)

| Feature | Syntax | Description |
|---------|--------|-------------|
| Points-to | `x \|-> v` | Location x points to value v |
| Empty heap | `emp` | Empty heap |
| Separating conjunction | `P * Q` | P and Q on disjoint heaps |
| Magic wand | `P -* Q` | If given P, produces Q |
| List segment | `ls(x, y)` | List from x to y |
| Linked list | `list(x)` | Null-terminated list |
| Tree | `tree(x)` | Binary tree |
| DLL | `dll(x, p, y, n)` | Doubly-linked list |

### String Theory (QF_S)

```python
formula = parse('x = "hello" & y = (str.++ x " world")')
```

Supported operations: concatenation, contains, indexof, replace, substring, regex matching.

### Array Theory (QF_AX)

```python
from frame.core.ast import ArraySelect, ArrayStore, Var, Const

arr = ArrayStore(Var("arr"), Const(5), Const(42))
val = ArraySelect(arr, Const(5))
```

### Bitvector Theory (QF_BV)

```python
from frame.core.ast import BitVecExpr, BitVecVal

# 8-bit overflow: 255 + 1 = 0
overflow = BitVecExpr("bvadd", [BitVecVal(255, 8), BitVecVal(1, 8)], 8)
```

---

## Benchmarks

Frame is validated against industry-standard benchmark suites.

### Results Summary

| Theory | Tests | Accuracy | Avg Time |
|--------|-------|----------|----------|
| Separation Logic | 861 | 77.7% | 0.8s |
| String (QF_S) | 18,940 | 84.2% | ~15ms |
| Array (QF_AX) | 500 | **100%** | 0.048s |
| Bitvector (QF_BV) | 250 | 76.4% | 0.025s |

### Running Benchmarks

```bash
# Quick validation (~15-20 min)
python -m benchmarks run --curated

# Full validation (~2+ hours)
python -m benchmarks run --all

# By theory
python -m benchmarks run --division slcomp_curated
python -m benchmarks run --division qf_s_curated
python -m benchmarks run --division qf_ax_curated
python -m benchmarks run --division qf_bv_curated
```

See [benchmarks/README.md](benchmarks/README.md) for detailed methodology.

---

## Architecture

```
frame/
├── core/           # AST, parser
├── encoding/       # Z3 SMT encoding
├── checking/       # Entailment checking
├── folding/        # Predicate folding/unfolding
├── predicates/     # Inductive predicates (lists, trees, DLLs)
├── lemmas/         # Lemma library
├── sil/            # Security scanner
│   ├── types.py        # SIL type definitions
│   ├── instructions.py # SIL instructions
│   ├── procedure.py    # CFG representation
│   ├── translator.py   # SIL to Frame translation
│   ├── scanner.py      # Main scanner interface
│   └── frontends/      # Language frontends
│       └── python_frontend.py
└── cli.py          # Command-line interface
```

**Algorithm**: Parse → Fold → Unfold → Encode → Z3 Solve

See [CLAUDE.md](CLAUDE.md) for detailed development guide.

---

## References

### Separation Logic

- Reynolds, O'Hearn (2002). [Separation Logic: A Logic for Shared Mutable Data Structures](https://doi.org/10.1109/LICS.2002.1029817)
- Piskac, Wies, Zufferey (2013). [Automating Separation Logic with Trees and Data](https://dl.acm.org/doi/10.1007/978-3-319-08867-9_47)

### Incorrectness Logic

- O'Hearn (2020). [Incorrectness Logic](https://doi.org/10.1145/3371078)

### Related Tools

- [Infer](https://fbinfer.com/) - Facebook's static analyzer (inspiration for SIL)
- [Sleek/HIP](https://github.com/sleek-hoare) - NUS separation logic prover
- [Cyclist](https://www.cyclist.cs.ucl.ac.uk/) - UCL cyclic proof system

---

## License

MIT License - see [LICENSE](LICENSE) for details.

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
