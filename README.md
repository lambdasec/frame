<p align="center">
  <img src="https://raw.githubusercontent.com/lambdasec/frame/main/assets/logo.svg" alt="Frame" width="400">
  <p align="center">
    <strong>Sound static analysis and LLM reasoning, in one security agent</strong>
  </p>
  <p align="center">
    <a href="https://github.com/lambdasec/frame/actions/workflows/tests.yml"><img src="https://github.com/lambdasec/frame/actions/workflows/tests.yml/badge.svg?branch=main" alt="Tests"></a>
    <a href="https://pypi.org/project/frame-security/"><img src="https://img.shields.io/pypi/v/frame-security" alt="PyPI version"></a>
    <a href="https://pepy.tech/projects/frame-security"><img src="https://static.pepy.tech/personalized-badge/frame-security?period=monthly&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=GREEN&left_text=downloads%2Fmonth" alt="PyPI Downloads"></a>
    <a href="https://github.com/marketplace/actions/frame-security-scan"><img src="https://img.shields.io/badge/Marketplace-Frame%20Security%20Scan-blue?logo=github" alt="GitHub Marketplace"></a>
    <a href="https://github.com/lambdasec/frame/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
  </p>
</p>

Frame finds vulnerabilities by **following attacker data through your code**, across functions, files and layers, and proves each finding with a solver instead of pattern-matching. An optional LLM layer adds recall, then exploits and fixes what was found.

<p align="center"><img src="https://raw.githubusercontent.com/lambdasec/frame/main/assets/chart-ai-sast.svg" alt="XBOW / ZeroPath AI-SAST benchmark: Frame 78.8% technical and 87.5% business-logic detection, level with ZeroPath and ahead of Semgrep, Snyk and Bearer" width="760"></p>

## Why Frame?

- **Five languages**: Python, JavaScript/TypeScript, Java, C# and C/C++.
- **Cross-file by default**: a request that enters a controller and reaches a query three files away is one finding.
- **70+ framework packs**: Flask to Spring to ASP.NET to Express, plus your own stack in one TOML file.
- **Dependencies too**: lockfiles of 11 ecosystems plus C/C++, matched against OSV offline, ranked by whether attacker data reaches the vulnerable function, with upgrades it plans, applies and verifies against your tests, licence policy, SBOM and VEX.
- **Infrastructure too**: Kubernetes manifests checked against the Pod Security Standards, decided with Z3 and matching the Kubernetes admission controller's own evaluator.
- **Built for guardrails**: scan only what changed, baseline what you accept, verify that a fix removed the bug.
- **Wherever you work**: a [GitHub Action](https://github.com/marketplace/actions/frame-security-scan), a pre-commit hook, and an [MCP server](https://github.com/lambdasec/frame-mcp) for Claude Code, Codex, Cursor and other coding agents.
- **Its own separation logic engine** on Z3: entailment, frame inference, bi-abduction and countermodels.
- **Runs on open models**, local or hosted, for detection, triage, exploitation and fixing.

## Quick start

```bash
pip install "frame-security[scan]"
frame scan src/
```

A three-file Flask app, where the request enters in `app.py` and the query runs in `services/orders.py`:

```python
# shop/app.py
@app.route("/orders")
def list_orders():
    customer = request.args.get("customer", "")
    return jsonify(orders.for_customer(customer))

# shop/services/orders.py
def for_customer(name):
    cur.execute("SELECT * FROM orders WHERE customer = '" + name.strip() + "'")
```

```console
$ frame scan benchmarks/exemplars/quickstart --root benchmarks/exemplars/quickstart
1. [CRITICAL] 🔴 sql_injection
   Location: benchmarks/exemplars/quickstart/shop/services/orders.py:8:4
   Description: Tainted data from 'customer' flows to sql sink
   CWE: CWE-89
   Data flow: shop/app.py:11 -> shop/services/orders.py::for_customer(name)
...
Scanned 4 files: 2 findings (2 critical)
```

Use a placeholder query, or wrap the value in `int()`, and the finding goes away.

For dependencies:

```bash
frame kb pull --advisories            # cache the advisories once (then everything runs offline)
frame deps --vulns                    # vulnerable dependencies, and whether your code calls the vulnerable function
frame deps --vulns --apply --relock   # upgrade, re-lock, report what is left
frame scan . --sca                    # attacker data reaching a vulnerable function, at the call site
```

For infrastructure: `frame iac .` (or `frame scan . --iac`).

## Benchmarks

<p align="center"><img src="https://raw.githubusercontent.com/lambdasec/frame/main/assets/chart-owasp.svg" alt="OWASP score by language: Frame 80.9 Python, 81.5 Java, 80.3 C#, 54.4 C/C++, 43.0 JavaScript; Semgrep 4.5, 15.7, 14.2, -14.9, 10.0" width="760"></p>

<p align="center"><img src="https://raw.githubusercontent.com/lambdasec/frame/main/assets/chart-cross-file.svg" alt="Cross-file flows: Frame finds 10/10 in four real apps with 0 false alarms on 33 safe twins; CodeQL 7/10 with 5 false alarms; Semgrep stock packs 7/10 with 21" width="760"></p>

| Benchmark | What it measures | Frame | Comparison |
|-----------|------------------|-------|------------|
| [XBOW / ZeroPath](https://github.com/lambdasec/frame/blob/main/benchmarks/xbow_zeropath/REPORT.md) | AI-SAST on 39 web-vuln apps | detect **78.8%**, FP **26.3%** | ZeroPath 80% / 25%, Semgrep 54% / 45% |
| [Endor Labs corpus](https://github.com/lambdasec/frame/blob/main/benchmarks/endor_corpus/README.md) | 193 vulns in 5 production apps | recall **0.67**, precision **0.51** | Semgrep 0.52 / 0.40 |
| [RealVuln IDOR/BOLA](https://github.com/lambdasec/frame/blob/main/benchmarks/realvuln_authz/REPORT.md) | Broken authorization, 4 real apps | **6/8** found, precision **1.00** | 0 false positives on safe controls |
| [CVE-Bench](https://github.com/lambdasec/frame/blob/main/benchmarks/cve_bench/README.md) | Detect, exploit, fix on 10 live CVEs | **5 / 4 / 4** of 10 | each stage verified on a live target |
| [SusVibes](https://github.com/lambdasec/frame/blob/main/benchmarks/susvibes/README.md) | 181 real-CVE Python pairs | recall **0.14**, precision **0.56** | Semgrep 0.06 / 0.55 |
| [Cross-file exemplars](https://github.com/lambdasec/frame/blob/main/benchmarks/exemplars/README.md) | Hand-labelled precision on 4 real apps | **98%** | CodeQL 95% |

Methods and every suite, including SL-COMP for the engine, are in [benchmarks/README.md](https://github.com/lambdasec/frame/blob/main/benchmarks/README.md).

## Documentation

| | |
|---|---|
| [Usage](https://github.com/lambdasec/frame/blob/main/docs/usage.md) | Scanning, GitHub Action, pre-commit hook and MCP server, baselines and `verify`, suppressions, configuration, every command and flag, environment variables, Python API |
| [Dependencies](https://github.com/lambdasec/frame/blob/main/docs/dependencies.md) | Supported ecosystems, advisories, reachability, upgrade plans, code mitigation, licences, SBOM, VEX, CI |
| [Coverage](https://github.com/lambdasec/frame/blob/main/docs/coverage.md) | Cross-file resolution per language, supported frameworks, writing a pack, vulnerability classes |
| [Infrastructure as code](https://github.com/lambdasec/frame/blob/main/docs/iac.md) | Kubernetes Pod Security Standards, how close they are to Kubernetes itself, writing policies, how Z3 decides them |
| [AI layer](https://github.com/lambdasec/frame/blob/main/docs/ai.md) | Detect, triage, exploit and fix with any OpenAI-compatible model, including on-device |
| [Separation logic engine](https://github.com/lambdasec/frame/blob/main/docs/engine.md) | The prover under the scanner: capabilities, syntax, CLI, Python API, SL-COMP results |
| [Roadmap](https://github.com/lambdasec/frame/blob/main/docs/roadmap.md) | Where Frame is going: SAST gaps, the knowledge base, SCA, secrets and IaC, AI app security, autonomous pentesting |
| [Examples](https://github.com/lambdasec/frame/blob/main/examples/README.md) | Runnable walkthroughs with real output: dependencies end to end, mitigations, adapting to a breaking upgrade, secrets, Kubernetes, AI apps and MCP servers |
| [Exemplars](https://github.com/lambdasec/frame/blob/main/benchmarks/exemplars/README.md) | The quickstart app, a vulnerable and safe app per framework, and the cross-file comparison |

## Contributing

```bash
pip install -e ".[dev]"
python -m pytest tests/ -n auto
ruff check frame tests benchmarks
```

`CLAUDE.md` is the engineering map of the codebase. To add a framework, write a pack under `frame/sil/packs/data/<language>/` and a vulnerable/safe app pair under `benchmarks/exemplars/frameworks/`; the fixture test checks both.

## License

[Apache 2.0](https://github.com/lambdasec/frame/blob/main/LICENSE)
