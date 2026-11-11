# Roadmap

Frame is the open-source application security platform: code (SAST), dependencies (SCA), secrets, infrastructure and containers, AI application security, all on one engine, where every finding says how strongly it is proven. An LLM, frontier or local, stays an optional add-on at every stage.

## Principles

- **One engine, reused everywhere.** The program model (SIL, the project index, canonical call ids, taint, Z3) serves every domain: SCA reachability is "is this vulnerable function called", AI-app security is taint with new source and sink kinds, and proof generation solves the same path conditions for the concrete inputs that reach a finding.
- **Knowledge is data.** What Frame knows about languages, frameworks, rules, advisories and secret formats lives in versioned, data-only files (TOML/JSON), not in the engine. No framework or benchmark name is special-cased in the core.
- **Every finding carries its evidence.** One finding model across all domains, with an evidence level (matched, llm-detected, llm-verified, data-flow, solver-verified, exploit-confirmed). Fingerprints, baselines, `verify`, SARIF, the GitHub Action, the pre-commit hook and MCP work the same for every category.
- **No benchmark-specific behaviour.** Every change is checked against the full benchmark sweep (identical results unless the change intends otherwise), and solver changes against every SL-COMP division.

## Built

- **SAST** across Python, JavaScript/TypeScript, Java, C# and C/C++: cross-file taint, 100+ finding types, 110 framework packs, C/C++ memory safety decided by the separation logic engine. ([coverage](coverage.md), [engine](engine.md))
- **SCA** for 11 ecosystems plus C/C++ and vendored copies: offline OSV matching, reachability ranking, upgrade plans Frame applies and verifies, code and configuration mitigations, licences, SBOM, VEX, container images. ([dependencies](dependencies.md))
- **Secrets** by name and by provider format, in code and across git history, with live verification. ([secrets](secrets.md))
- **Infrastructure as code**: Kubernetes, Dockerfiles, Terraform (AWS, Azure, Google Cloud) and CloudFormation, every policy decided with Z3. ([iac](iac.md))
- **Authorization hunting**: an agentic hunt for broken access control and business-logic flaws, directed by the engine, with a verdict on every handler and the code they rely on; 22 of 30 on BAC-Bench. ([AI layer](ai.md#hunting-authorization-flaws---hunt-authz))
- **AI application security**: prompt injection, model output as taint, MCP tools and tool-metadata attacks. ([LLM and MCP](llm-security.md))
- **The knowledge base as open data**: framework packs ([`lambdasec/frame-kb`](https://huggingface.co/datasets/lambdasec/frame-kb)) and the OSV advisory database rebuilt daily ([`lambdasec/frame-advisories`](https://huggingface.co/datasets/lambdasec/frame-advisories)), pinnable for air-gapped CI.
- **One configuration**: every setting in one file (`.frame.toml` or `[tool.frame]`), validated strictly, resolved as flag, then environment variable, then file, then default. The environment holds only the model endpoint, the knowledge base's switch, sources and caches (9 variables, down from 33); a retired variable is warned about with its replacement. ([usage](usage.md#configuration))
- **Proof-carrying findings**: a finding the engine proved reachable becomes a runnable test that triggers it, raised to the `exploit-confirmed` evidence level when the fault is observed. The C integer-overflow/underflow, signed-size, truncation and out-of-bounds findings compile and run under the sanitizers with the solver's own inputs (`frame scan --confirm-proofs`, no model); `--reproduce-proofs` drives a seeded agent for an input that comes from stdin/argv. `frame exploit --deps` turns reachability into a runnable reproduction across languages: both `frame scan --sca` dependency flows (Python, JavaScript/TypeScript, and the Java and C# DI-seam interface sinks) and code taint flows (SQL/command/XSS/path/SSRF and the other source-to-sink injections), each driven to the sink through the project and confirmed by a harness spy, with the fix-loop tie-in (`--check-fixed`) re-running the confirmed driver against a fixed copy so a proof of the vulnerability becomes a proof of the fix. ([AI layer](ai.md#proof-carrying-findings---confirm-proofs))
- **Distribution**: PyPI `frame-security`, the [GitHub Action](https://github.com/marketplace/actions/frame-security-scan) (`lambdasec/frame-action@v1`), a pre-commit hook, and an [MCP server](https://github.com/lambdasec/frame-mcp). On each 1.x release the `v1` tag moves to it.

The engine audit that removed every framework and benchmark heuristic from the core (so all of the above is data, not special cases) is complete; the git history has the stage-by-stage record.

## What's next

**Data**: the advisory database (daily) and vulnerable-function mappings (weekly) are rebuilt by jobs on their own. Vendored C/C++ libraries and curated configuration mitigations grow by hand, each entry added from the advisory text and upstream source.

**Phase 5: proof-carrying findings.** Built end to end (see Built): the C memory/integer families under sanitizers, the stdin/argv reproduction loop, dependency-reachability reproductions (Python, JavaScript/TypeScript, and the Java/C# DI-seam interface sinks), taint-flow reproductions (SQLi, XSS and the other source-to-sink injections, where the reaching input is a crafted string), and the fix-loop tie-in (the confirmed driver is re-run against a fixed copy and must stop reaching the sink). Everything runs against the user's own code in a sandbox; there is no live third-party target. One family is deliberately not reproducible this way and is certified by a re-scan instead: a fix that leaves attacker data reaching the sink but makes it safe (a sanitize-in-place, or a dependency upgrade that keeps the call) does not flip a reachability reproduction. Remaining widening bricks, each a new capability rather than a gap: a ByteBuddy java agent for bootstrap/concrete (non-interface) Java sinks, and Pose/Harmony for non-interface C# static sinks.

**Lowering soundness.** GitHub issue #9 (an SQL injection lost when the connection came from `flask.g`) led to an adversarial review of every frontend: about 50 everyday constructs were lowered wrongly or dropped, so findings disappeared when code was written another ordinary way. Most are fixed, and two kinds of test now guard the class: `tests/test_metamorphic*.py` rewrite each seed flow without changing its meaning and require the finding to survive (the rewrite of a constant must stay clean), and `tests/test_lowering_coverage*.py` fail when data-carrying syntax falls back to a variable named by its source text. What is left is listed there as strict xfails, each with its reason:
- Python: dict literals per key, `match` captures, a list literal's later elements, `d[k] += v`, lambda bodies, calling a `functools.partial` written inline.
- JavaScript/TypeScript: library callbacks (`forEach`, `map`, `then`), function aliases (`const run = cp.exec`), methods of same-file object literals and static methods as callees, async-error wrappers, numeric and boolean results of operators keeping string taint, ES `export` values across files, static class fields.
- Java: receiver types from `var x = <call>` and the class's own getters, field taint across a same-class call, method references, return summaries in per-file mode (a helper returning a constant still taints its result).
- C#: `out`/`ref` arguments, sinks nested in call arguments, `StreamReader` over a stream, `Process.StartInfo` chains, collection `Add`, Razor loops.

**Not planned**: more SAST languages (PHP, Go, Swift, Kotlin, Rust `unsafe`), and detecting AI-generated code (authorship does not change whether code is vulnerable; the guardrails cover the need).

## Licensing

Packs Apache-2.0, datasets CC-BY-4.0.
