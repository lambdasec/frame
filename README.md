<p align="center">
  <h1 align="center">Frame</h1>
  <p align="center">
    <strong>Static Analysis for Memory Safety and Security</strong>
  </p>
  <p align="center">
    <a href="tests/"><img src="https://img.shields.io/badge/tests-1497%20passed-brightgreen" alt="Tests"></a>
    <a href="#"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  </p>
</p>

---

Frame is a static analysis tool powered by **separation logic** that finds security vulnerabilities and memory safety bugs with high precision. It supports **5 languages** and achieves **80%+ OWASP scores** - significantly outperforming tools like Semgrep and Bandit.

## Highlights

**OWASP Score** (True Positive Rate - False Positive Rate):

| Benchmark | Frame | Semgrep | Difference |
|-----------|:---:|:---:|:---:|
| **Python** (OWASP) | 80.9% | 4.5% | +76.4 pts |
| **Java** (OWASP) | 81.5% | 15.7% | +65.8 pts |
| **JavaScript** (SecBench.js) | 77.6% | 9.6% | +68.0 pts |
| **C/C++** (NIST Juliet) | 54.4% | -14.9% | +69.3 pts |
| **C#** (IssueBlot.NET) | 45.1% | 14.2% | +30.9 pts |

<sub>Higher is better. See [benchmarks/](benchmarks/) for detailed methodology and results.</sub>

## Installation

```bash
git clone https://github.com/lambdasec/frame.git
cd frame
pip install -e ".[scan]"
```

## Quick Start

```bash
# Scan for vulnerabilities
frame scan app.py

# Scan a directory
frame scan src/ --pattern "**/*.py"

# CI/CD integration (SARIF output)
frame scan src/ --format sarif -o results.sarif --fail-on high
```

<details>
<summary><strong>More examples</strong></summary>

```bash
# Check separation logic entailment
frame solve "x |-> 5 * y |-> 3 |- x |-> 5"

# Batch check formulas
frame check formulas.txt

# Interactive mode
frame repl
```

</details>

## Supported Languages

| Language | Frameworks & Libraries |
|----------|----------------------|
| **Python** | Flask, Django, FastAPI, SQLAlchemy, subprocess |
| **Java** | Spring, JDBC, Hibernate, JNDI |
| **JavaScript/TypeScript** | Express, Node.js, DOM APIs |
| **C/C++** | POSIX, Windows API, memory operations |
| **C#** | ASP.NET, Entity Framework, ADO.NET |

## What Frame Detects

<table>
<tr>
<td width="50%">

**Injection & XSS**
- SQL Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Command Injection (CWE-78)
- LDAP/XPath Injection
- Template Injection

</td>
<td width="50%">

**Memory Safety**
- Buffer Overflow (CWE-121/122)
- Use-After-Free (CWE-416)
- Double Free (CWE-415)
- Null Pointer Dereference
- Integer Overflow

</td>
</tr>
<tr>
<td>

**Data Exposure**
- Path Traversal (CWE-22)
- SSRF (CWE-918)
- Open Redirect (CWE-601)
- Hardcoded Secrets
- Log Injection

</td>
<td>

**Cryptography**
- Weak Algorithms (CWE-327)
- Insecure Random (CWE-330)
- Weak Hashing (CWE-328)
- Insecure Deserialization

</td>
</tr>
</table>

## How It Works

Frame uses a unique approach combining **taint analysis** with **separation logic verification**:

```
Source Code
     |
     v
[Language Frontend] ---> SIL (Separation Intermediate Language)
     |                         |
     v                         v
[Taint Tracking]        [Symbolic Execution]
     |                         |
     v                         v
[Pattern Detection] <---> [Z3 Verification]
     |
     v
Vulnerability Report
```

**Why this matters:**
- **Taint analysis** tracks untrusted data flow from sources (user input) to sinks (SQL queries)
- **Separation logic** formally verifies memory safety properties
- **Z3 verification** eliminates false positives by proving vulnerability reachability

## CI/CD Integration

```yaml
# GitHub Actions
- name: Install Frame
  run: pip install -e ".[scan]"

- name: Security Scan
  run: frame scan src/ --format sarif -o results.sarif --fail-on high

- name: Upload Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## Python API

```python
from frame import EntailmentChecker
from frame.sil import FrameScanner

# Security scanning
scanner = FrameScanner()
result = scanner.scan_file("app.py")
for vuln in result.vulnerabilities:
    print(f"{vuln.cwe_id}: {vuln.description}")

# Separation logic verification
checker = EntailmentChecker()
result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
print(result.valid)  # True
```

## Separation Logic Solver

Frame includes a separation logic solver for verifying heap properties:

| Syntax | Meaning |
|--------|---------|
| `x \|-> v` | x points to value v |
| `emp` | Empty heap |
| `P * Q` | P and Q in separate memory |
| `P -* Q` | Magic wand |
| `P \|- Q` | P entails Q |

**Built-in predicates:** `ls(x,y)` (list segment), `list(x)`, `tree(x)`, `dll(x,p,y,n)`

```bash
frame solve "ls(x, y) * ls(y, z) |- ls(x, z)"  # List transitivity
```

## Benchmarks

Frame is validated against industry-standard benchmark suites:

| Benchmark | Domain | Tests | Precision | Recall |
|-----------|--------|-------|-----------|--------|
| OWASP Python | Web Security | 500 | 95.3% | 83.5% |
| OWASP Java | Web Security | 500 | 97.2% | 84.8% |
| SecBench.js | Node.js Security | 166 | 99.1% | 81.2% |
| NIST Juliet | C/C++ Memory | 1,000 | 89.9% | 60.5% |
| IssueBlot.NET | C# Security | 171 | 100% | 45.1% |
| SL-COMP | Separation Logic | 692 | 79.9% | - |
| SMT-LIB QF_S | String Theory | 3,300 | 99.3% | - |

```bash
python -m benchmarks run --curated  # Run all benchmarks
```

See [benchmarks/README.md](benchmarks/README.md) for detailed results, methodology, and tool comparisons.

## Project Structure

```
frame/
  core/           # AST and parser
  encoding/       # Z3 SMT encoding
  checking/       # Entailment checker
  sil/            # Security scanner
    scanner.py    # Main interface
    frontends/    # Language parsers (Python, Java, JS, C, C#)
    analyzers/    # Taint & memory analysis
  cli.py          # Command-line interface
```

## References

- Reynolds & O'Hearn (2002). [Separation Logic: A Logic for Shared Mutable Data Structures](https://doi.org/10.1109/LICS.2002.1029817)
- O'Hearn (2020). [Incorrectness Logic](https://doi.org/10.1145/3371078)

**Related:** [Infer](https://fbinfer.com/), [Semgrep](https://semgrep.dev/), [CodeQL](https://codeql.github.com/)

---

<p align="center">
  <sub>Built with <a href="https://github.com/Z3Prover/z3">Z3</a> and <a href="https://tree-sitter.github.io/">tree-sitter</a></sub>
</p>
