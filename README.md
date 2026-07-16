<p align="center">
  <img src="assets/logo.svg" alt="Frame" width="400">
  <p align="center">
    <strong>Sound static analysis and LLM reasoning, in one security agent</strong>
  </p>
  <p align="center">
    <a href="tests/"><img src="https://img.shields.io/badge/tests-1660%20passed-brightgreen" alt="Tests"></a>
    <a href="#"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  </p>
</p>

---

Frame is a neuro-symbolic security agent. A sound static-analysis core (taint analysis plus separation-logic verification with Z3) is fused with an LLM layer in one loop: the model proposes, the sound core disposes.

It runs the whole loop end to end. Detect vulnerabilities across 5 languages. Exploit them with a working proof-of-concept against a live target. Fix the code, then re-scan to confirm the bug is gone. Symbolic findings are proven, not guessed; LLM findings are tiered separately so the two are never confused. On independent real-world benchmarks Frame is competitive with commercial AI-SAST vendors, and it scores 80%+ on the synthetic OWASP suites. The LLM layer runs on any OpenAI-compatible endpoint, on-device if you want.

## Highlights

**Real-world security benchmarks.** Frame is competitive with commercial AI-SAST vendors, validated on five independent datasets with published ground truth, spanning detection, exploitation, and remediation on real applications. Every Frame number uses open models (local Qwen via mlx-optiq, or hosted GLM-5.2):

| Benchmark | What it measures | Frame | Comparison |
|-----------|------------------|------|-----------|
| [XBOW / ZeroPath](benchmarks/xbow_zeropath/REPORT.md) | AI-SAST on 39 web-vuln apps | _run in progress_ | vs ZeroPath, Semgrep, Snyk, Bearer |
| [CVE-Bench](benchmarks/cve_bench/README.md) | Full loop, 10 live web CVEs | detect **5/10**, exploit **4/10**, fix **4/10** | each stage verified on a live target |
| [Endor Labs corpus](benchmarks/endor_corpus/README.md) | 193 vulns, 5 production apps | recall **0.67**, precision **0.51** | Semgrep recall 0.52, precision 0.40 |
| [RealVuln IDOR/BOLA](benchmarks/realvuln_authz/REPORT.md) | Broken authorization, 4 real apps | **6/8** detected, precision **1.00** | 0 false positives on safe controls |
| [SusVibes](benchmarks/susvibes/README.md) | 181 real-CVE Python pairs | recall **0.14**, precision **0.56** | Semgrep recall 0.06, precision 0.55 |

<sub>Each cell names its own metric. SusVibes is hard for every tool (independent, execution-verified ground truth). See each benchmark's report for methods and caveats.</sub>

**OWASP score, synthetic suites** (True Positive Rate minus False Positive Rate):

| Benchmark | Frame | Semgrep | Difference |
|-----------|:---:|:---:|:---:|
| **Python** (OWASP) | 80.9% | 4.5% | +76.4 pts |
| **Java** (OWASP) | 81.5% | 15.7% | +65.8 pts |
| **JavaScript** (SecBench.js) | 43.0% | 10.0% | +33 pts |
| **C/C++** (NIST Juliet) | 54.4% | -14.9% | +69.3 pts |
| **C#** (IssueBlot.NET) | 80.3% | 14.2% | +66.1 pts |

<sub>Higher is better. See [benchmarks/](benchmarks/) for detailed methods and results.</sub>

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

# AI-assisted scan: LLM detection + triage (needs an LLM endpoint, see below)
frame scan src/ --ai

# CI/CD integration (SARIF output)
frame scan src/ --format sarif -o results.sarif --fail-on high
```

<details>
<summary><strong>More examples</strong></summary>

```bash
# Exploit a finding against a live, authorized target (primed by a scan)
frame exploit --target http://localhost:8080 --guidance findings.json

# Generate a fix, then re-scan to confirm the vulnerability is gone
frame fix app.py --guidance findings.json --diff

# Separation-logic solver
frame solve "x |-> 5 * y |-> 3 |- x |-> 5"   # check an entailment
frame check formulas.txt                       # batch-check a file
frame repl                                      # interactive REPL
```

</details>

## Commands

Frame is one CLI covering the whole workflow (detect, triage, exploit, fix) plus the separation-logic solver. Run `frame <command> --help` for all flags.

| Command | What it does |
|---------|--------------|
| `frame scan <path>` | Scan source for vulnerabilities (sound symbolic engine; add `--ai` for LLM detection + triage). `-f json\|sarif`, `-o <file>`, `--fail-on <sev>`. |
| `frame exploit --target <url>` | Drive an LLM agent to exploit a live, authorized target. Prime it with `--guidance <findings.json\|->` from a scan so it attacks the localized flaw. `--goal`, `--success-check`, `--max-steps`. |
| `frame fix <path>` | Generate a fix for each scan finding, then re-scan the patched code to confirm the vulnerability is gone. `--guidance <findings.json\|->`, `--in-place` or `--diff`. |
| `frame solve "<P> \|- <Q>"` | Check a single separation-logic entailment. |
| `frame check <file>` | Batch-check entailments (one per line). |
| `frame parse "<formula>"` | Parse and display a formula's AST. |
| `frame repl` | Interactive separation-logic REPL. |

The analysis stages compose over a shared findings JSON, so the shell is the pipeline:

```bash
# scan (symbolic + LLM) produces findings; the exploit agent attacks the localized bug
frame scan ./repo --ai -f json | \
  frame exploit --target http://app:8080 --guidance - --goal 'read the admin secret'
```

## Supported Languages

The symbolic engine has sound frontends for five languages:

| Language | Frameworks & Libraries |
|----------|----------------------|
| **Python** | Flask, Django, FastAPI, SQLAlchemy, subprocess |
| **Java** | Spring, JDBC, Hibernate, JNDI |
| **JavaScript/TypeScript** | Express, Node.js, DOM APIs |
| **C/C++** | POSIX, Windows API, memory operations |
| **C#** | ASP.NET, Entity Framework, ADO.NET |

The LLM layer (`--ai`) runs on any language, including ones with no symbolic frontend (PHP, Ruby, Go, and more). Those findings stay in the LLM tier, never mixed with the sound symbolic results.

## What Frame Detects

Frame recognizes 80+ vulnerability classes across the families below. The symbolic core proves the ones reachable by taint or memory reasoning; the LLM layer adds context-dependent, authorization, and business-logic flaws.

<table>
<tr>
<td width="50%">

**Injection**
- SQL / NoSQL / ORM Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Command & Code Injection (CWE-78/94)
- Template Injection (SSTI)
- LDAP / XPath / XML Injection
- Header & Log Injection

</td>
<td width="50%">

**Access Control & Auth**
- IDOR / BOLA (CWE-639)
- Authorization Bypass (CWE-285)
- Mass Assignment (CWE-915)
- Broken Authentication
- Session Fixation
- CSRF (CWE-352)

</td>
</tr>
<tr>
<td>

**Data Exposure & Crypto**
- Path Traversal (CWE-22)
- SSRF (CWE-918)
- Open Redirect (CWE-601)
- XXE (CWE-611)
- Hardcoded Secrets, Insecure Deserialization
- Weak Crypto / Hashing / Random

</td>
<td>

**Memory Safety**
- Buffer Overflow / Underflow (CWE-121/122)
- Use-After-Free (CWE-416)
- Double / Invalid Free (CWE-415)
- Null Pointer Dereference
- Integer Overflow, Format String

</td>
</tr>
</table>

## How It Works

Frame runs one investigation at rising commitment (detect, triage, exploit, fix), with a sound symbolic core grounding every stage so the LLM can't hallucinate:

```
 source code
     |
     v
  DETECT   sound core (taint + separation logic, Z3-verified, zero-FP)
           + LLM layer for recall  ->  findings, tiered: proven / llm
     |
     v
  TRIAGE   LLM drops confident false positives, grounded to Frame's sink model
     |
     v
  EXPLOIT  LLM agent drives a working PoC against a live target,
           stopping only when success is observably verified
     |
     v
  FIX      generate a patch, re-scan the patched code, prove the bug is gone
```

- **Detect:** the sound core proves reachable bugs with zero false positives; the LLM layer adds recall, tracing flows across files. Symbolic and LLM findings are never conflated.
- **Triage:** the LLM drops confident false positives, keeping a finding unless it *finds* the mitigating control.
- **Exploit:** an LLM agent develops and executes a working proof-of-concept against a live, authorized target.
- **Fix:** Frame generates a patch, re-scans, and confirms the vulnerability is gone with no regressions.

**Inside detect:** a per-language frontend lowers source into SIL (a separation intermediate language); taint tracking follows untrusted data from sources to sinks, symbolic execution explores paths, and Z3 discharges the reachability proof. A bug is reported only when it is provably reachable.

## AI-Assisted Detection & Triage

Frame's symbolic core is sound and precise. But structural analysis can't reach everything: context-dependent flows, unknown frameworks, business logic. Frame adds a layer driven by an LLM.

- **Detect** (recall): find vulnerabilities the symbolic engine misses. It can explore across files, calling `read_file`/`grep` tools over your repo to trace a flow from one file into another.
- **Triage** (precision): drop confident false positives from the findings.
- **Verify**: each LLM finding is checked against Frame's own sink model. A finding grounded in a recognized sink, cross-file included, moves up to a higher-confidence tier (`llm_verified`). Symbolic results and LLM results are never conflated.

On the [Endor Labs public AI-SAST corpus](benchmarks/endor_corpus/README.md) (5 real-world apps), Frame's full mode (detection + triage) reaches 0.67 recall at 0.51 precision, or 0.71 recall with detection alone. Semgrep gets 0.52 recall at 0.40 precision. The LLM layer recovers around 65 real vulnerabilities across Java, JS/TS, and C# that both Frame's symbolic engine and Semgrep miss. See the [benchmark README](benchmarks/endor_corpus/README.md) for the full scoreboard and the honest caveats.

The layer works with any OpenAI-compatible endpoint, local or hosted, so Frame stays open and ungated end to end. For privacy and cost you can run it fully on-device with [mlx-optiq](https://mlx-optiq.com) serving [`mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit`](https://huggingface.co/mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit) on Apple Silicon; our benchmarks use both this local setup and a hosted open-source model, GLM-5.2 (`z-ai/glm-5.2`).

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

The symbolic core runs on its own; add the LLM layer with one flag:

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

## Exploitation

Detection tells you a bug *might* be there; exploitation proves it. `frame exploit` closes that gap. It drives an LLM through a tool loop against a live target and stops only when success is observably verified, never on the model's unchecked say-so.

- **Frame-guided.** Pipe a scan's findings in with `--guidance`. Frame's symbolic taint path hands the agent the exact endpoint, parameter, and sink, so it attacks the right surface instead of probing blind. The guidance header is honest about provenance: a symbolic finding is presented as a sound, verified-reachable lead; an LLM-detected finding as a heuristic lead to verify while exploiting.
- **Verified success.** Pass `--success-check '<cmd>'` (exit 0 ⇒ solved) to use an external oracle, or let the agent self-terminate once it verifies a real state change (a returned secret, a written file, an executed command). Unverified "done" is treated as failure.
- **Runs anywhere.** Commands execute from wherever you invoke `frame`, so point it at any reachable target; use any OpenAI-compatible model (an open, ungated model is the right base for offensive tasks).

```bash
# guided end-to-end: scan localizes the bug, the agent exploits it
frame scan ./repo --ai -f json | \
  frame exploit --target http://app:8080 --guidance - \
    --goal 'read /etc/secret' --success-check 'curl -sf http://app:8080/pwned'

# unguided attempt (no scan findings)
frame exploit --target http://app:8080 --goal 'achieve RCE' --max-steps 40
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

## The Symbolic Core: Separation Logic + Z3

Frame's soundness rests on a mathematical foundation. It models heaps in separation
logic and discharges the resulting proof obligations with the Z3 SMT solver, so the
symbolic engine can prove a vulnerability is reachable (reporting it with no false
positives) or prove it cannot happen. That same engine is exposed directly for
verifying heap properties:

| Syntax | Meaning |
|--------|---------|
| `x \|-> v` | x points to value v |
| `emp` | Empty heap |
| `P * Q` | P and Q in separate memory |
| `P -* Q` | Magic wand |
| `P \|- Q` | P entails Q |

**Built-in predicates:** `ls(x,y)`, `list(x)`, `tree(x)`, `dll(x,p,y,n)`

```bash
frame solve "ls(x, y) * ls(y, z) |- ls(x, z)"  # list-segment transitivity
```

The core is validated on the standard logic suites: SL-COMP (separation logic) at
79.9% and SMT-LIB QF_S (string theory) at 99.3%. Run the full suite with
`python -m benchmarks run --curated`; [benchmarks/README.md](benchmarks/README.md) has
every division, the real-world corpora, per-tool comparisons, and methods.
