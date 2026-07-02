<p align="center">
  <img src="assets/logo.svg" alt="Frame" width="400">
  <p align="center">
    <strong>Neuro-Symbolic AI SAST: Separation Logic + LLMs</strong>
  </p>
  <p align="center">
    <a href="tests/"><img src="https://img.shields.io/badge/tests-1593%20passed-brightgreen" alt="Tests"></a>
    <a href="#"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  </p>
</p>

---

Frame is a neuro-symbolic AI SAST. Its core is a sound static-analysis engine: taint analysis plus separation-logic verification with Z3. On top of that core sits an optional local-LLM layer that detects vulnerabilities the symbolic engine misses and triages false positives. Frame supports 5 languages and scores 80%+ on the OWASP benchmarks, well ahead of Semgrep and Bandit. With the LLM layer on, it also finds real-world vulnerabilities that a symbolic engine and a mature pattern scanner both miss. Everything runs on-device, and every LLM finding is grounded and tiered, never blurred with the sound results.

## Highlights

**OWASP Score** (True Positive Rate - False Positive Rate):

| Benchmark | Frame | Semgrep | Difference |
|-----------|:---:|:---:|:---:|
| **Python** (OWASP) | 80.9% | 4.5% | +76.4 pts |
| **Java** (OWASP) | 81.5% | 15.7% | +65.8 pts |
| **JavaScript** (SecBench.js) | 43.0% | 10.0% | +33 pts |
| **C/C++** (NIST Juliet) | 54.4% | -14.9% | +69.3 pts |
| **C#** (IssueBlot.NET) | 80.3% | 14.2% | +66.1 pts |

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

Frame combines taint analysis with separation logic verification:

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

## AI-Assisted Detection & Triage (optional)

Frame's symbolic core is sound and precise. But structural analysis can't reach everything: context-dependent flows, unknown frameworks, business logic. Frame adds an optional layer driven by an LLM.

- **Detect** (recall): find vulnerabilities the symbolic engine misses. It can explore across files, calling `read_file`/`grep` tools over your repo to trace a flow from one file into another.
- **Triage** (precision): drop confident false positives from the findings.
- **Verify**: each LLM finding is checked against Frame's own sink model. A finding grounded in a recognized sink, cross-file included, moves up to a higher-confidence tier (`llm_verified`). Symbolic results and LLM results are never conflated.

On the [Endor Labs public AI-SAST corpus](benchmarks/endor_corpus/README.md) (5 real-world apps), Frame's full mode reaches 0.71 recall at 0.51 precision. Semgrep gets 0.52 and 0.40. The LLM layer recovers around 65 real vulnerabilities across Java, JS/TS, and C# that both Frame's symbolic engine and Semgrep miss. See the [benchmark README](benchmarks/endor_corpus/README.md) for the full scoreboard and the honest caveats.

The layer works with any OpenAI-compatible endpoint, so you can point it at a frontier hosted model or a local one. Our results use a local model, for privacy and cost: [mlx-optiq](https://mlx-optiq.com) serving [`mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit`](https://huggingface.co/mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit) on Apple Silicon. A stronger hosted model would likely do better. Both layers are off by default; without them you get the sound symbolic core.

```bash
# our local setup (Apple Silicon): serve the model, then point Frame at it
pip install mlx-optiq
optiq kv-cache mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit --target-bits 5.0 -o ./kv
optiq serve --model mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit \
  --kv-config ./kv/kv_config.json --port 47317 --mtp    # --mtp: ~1.4x faster decode

export FRAME_LLM_BASE_URL=http://localhost:47317/v1
export FRAME_LLM_API_KEY=                                  # empty for local servers
export FRAME_LLM_MODEL=mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit
export FRAME_LLM_REPO_ROOT=/path/to/repo                   # enables agentic cross-file tools
```

Then turn the layer on with one flag:

```bash
frame scan src/ --ai          # symbolic + LLM detection + triage
```

Or from the Python API:

```python
from frame.sil import FrameScanner
# symbolic + LLM detection + triage (reads the FRAME_LLM_* env above)
scanner = FrameScanner(language="java", llm_detect=True, llm_triage=True)
result = scanner.scan_file("Controller.java")
```

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
| SecBench.js | Node.js Security | 300 | 82.0% | 81.0% |
| NIST Juliet | C/C++ Memory | 1,000 | 89.9% | 60.5% |
| IssueBlot.NET | C# Security | 171 | 84.7% | 80.3% |
| SL-COMP | Separation Logic | 692 | 79.9% | n/a¹ |
| SMT-LIB QF_S | String Theory | 3,300 | 99.3% | n/a¹ |

```bash
python -m benchmarks run --curated  # Run all benchmarks
```

<sub>¹ SL-COMP and QF_S are logic-solver suites: the percentage is solver accuracy, and recall does not apply.</sub>

Beyond the synthetic suites, Frame is scored on the
[Endor Labs public AI-SAST corpus](benchmarks/endor_corpus/README.md): 5
production applications. With the LLM layer, Frame reaches 0.71 recall at 0.51
precision, against Semgrep's 0.52 and 0.40. It finds around 65 real
vulnerabilities across Java, JS/TS, and C# that both a symbolic engine and
Semgrep miss. The benchmark README records how the ground truth was built and the
honest caveats.

See [benchmarks/README.md](benchmarks/README.md) for detailed results, methodology, and tool comparisons.

## Project Structure

```
frame/
  core/           # AST and parser
  encoding/       # Z3 SMT encoding
  checking/       # Entailment checker
  sil/            # Security scanner
    scanner.py    # Main interface (symbolic + optional LLM layers)
    frontends/    # Language parsers (Python, Java, JS, C, C#)
    analyzers/    # Taint & memory analysis
    llm_detect.py # Optional LLM detection (recall) + agentic cross-file tools
    llm_triage.py # Optional LLM triage (precision) + OpenAI-compatible client
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
