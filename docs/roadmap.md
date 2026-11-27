# Roadmap

Frame is the open-source application security platform: code (SAST), dependencies (SCA), secrets, infrastructure and containers, AI application security, all on one engine, where every finding says how strongly it is proven. An LLM, frontier or local, stays an optional add-on at every stage.

## Principles

- **One engine, reused everywhere.** The program model (SIL, the project index, canonical call ids, taint, Z3) serves every domain: SCA reachability is "is this vulnerable function called", AI-app security is taint with new source and sink kinds, and proof generation solves the same path conditions for the concrete inputs that reach a finding.
- **Knowledge is data.** What Frame knows about languages, frameworks, rules, advisories and secret formats lives in versioned, data-only files (TOML/JSON), not in the engine. No framework or benchmark name is special-cased in the core.
- **Every finding carries its evidence.** One finding model across all domains, with an evidence level (matched, llm-detected, llm-verified, data-flow, solver-verified, exploit-confirmed). Fingerprints, baselines, `verify`, SARIF, the GitHub Action, the pre-commit hook and MCP work the same for every category.
- **No benchmark-specific behaviour.** Every change is checked against the full benchmark sweep (identical results unless the change intends otherwise), and solver changes against every SL-COMP division.

## Built

- **SAST** across Python, JavaScript/TypeScript, Java, C# and C/C++: cross-file taint, 100+ finding types, 121 framework packs, C/C++ memory safety decided by the separation logic engine. ([coverage](coverage.md), [engine](engine.md))
- **SCA** for 11 ecosystems plus C/C++ and vendored copies: offline OSV matching, reachability ranking, upgrade plans Frame applies and verifies, code and configuration mitigations, licences, SBOM, VEX, container images. ([dependencies](dependencies.md))
- **Secrets** by name and by provider format, in code and across git history, with live verification. ([secrets](secrets.md))
- **Infrastructure as code**: Kubernetes, Dockerfiles, Terraform (AWS, Azure, Google Cloud) and CloudFormation, every policy decided with Z3. ([iac](iac.md))
- **Authorization hunting**: an agentic hunt for broken access control and business-logic flaws, directed by the engine, with a verdict on every handler and the code they rely on; 22 of 30 on BAC-Bench. ([AI layer](ai.md#hunting-authorization-flaws---hunt-authz))
- **AI application security**: prompt injection, model output as taint, MCP tools and tool-metadata attacks. ([LLM and MCP](llm-security.md))
- **The knowledge base as open data**: framework packs ([`lambdasec/frame-kb`](https://huggingface.co/datasets/lambdasec/frame-kb)) and the OSV advisory database rebuilt daily ([`lambdasec/frame-advisories`](https://huggingface.co/datasets/lambdasec/frame-advisories)), pinnable for air-gapped CI.
- **One configuration**: every setting in one file (`.frame.toml` or `[tool.frame]`), validated strictly, resolved as flag, then environment variable, then file, then default. The environment holds only the model endpoint, the knowledge base's switch, sources and caches (9 variables, down from 33); a retired variable is warned about with its replacement. ([usage](usage.md#configuration))
- **Proof-carrying findings**: a finding the engine proved reachable becomes a runnable test that triggers it, raised to the `exploit-confirmed` evidence level when the fault is observed. C integer and out-of-bounds findings compile and run under the sanitizers with the solver's own inputs (`frame scan --confirm-proofs`, no model; `--reproduce-proofs` for input from stdin/argv). `frame exploit --deps` drives dependency flows and code taint flows to the sink through the project in Python, JavaScript/TypeScript, Java and C#, confirmed by a spy that counts only data arriving through the project's own code (an injected sink interface is proxied; any other Java/C# sink is hooked at its call site's arguments, with nothing attached at run time). `--check-fixed` re-runs the confirmed driver against a fixed copy: the fix is proved only when the driver still runs there and no longer reaches the sink. ([AI layer](ai.md#proof-carrying-findings---confirm-proofs))
- **Business-logic hunting**: `frame scan --hunt CLASSES` runs the hunt's pipeline for `limits`, `race`, `workflow`, `replay` and `bruteforce`, each corroborated by an engine check (`lower_bound` / `upper_bound` with a Z3 witness, NaN included; `guarded_by`; `atomic_write` over locks, atomic and conditional writes, claims and version fields across ORMs; `attempt_limit` over limiters and stored lockouts). A held-out benchmark of real advisories keyed before tuning is `benchmarks/logicbench`. ([AI layer](ai.md#hunting-business-logic-flaws---hunt))
- **Invariants as data**: `[[invariant]]` pack entries (a bound on a stored field, a check a write requires) are checked by the engine on every scan with no model, in Python, JavaScript/TypeScript, Java and C#; `--save-invariants` writes the rule behind each engine-backed hunt finding, so what an agent found once is enforced in CI. ([AI layer](ai.md#invariants-as-data---save-invariants))
- **The engine as a query service**: `frame query` answers the hunt's engine queries (handlers, callers, callees, data flows, the guards on a line, a claim decided over the feasible paths) for any agent, each with its evidence, resolution and limits; `--serve` keeps the project's index warm between edits, and frame-mcp exposes the queries as `engine_*` tools. ([usage](usage.md#frame-query-dir-tool))
- **Distribution**: PyPI `frame-security`, the [GitHub Action](https://github.com/marketplace/actions/frame-security-scan) (`lambdasec/frame-action@v1`), a pre-commit hook, and an [MCP server](https://github.com/lambdasec/frame-mcp). On each 1.x release the `v1` tag moves to it.

The engine audit that removed every framework and benchmark heuristic from the core (so all of the above is data, not special cases) is complete; the git history has the stage-by-stage record.

## What's next

Every planned phase is built. What continues:

- **Data**: the advisory database (daily) and vulnerable-function mappings (weekly) are rebuilt by jobs on their own. Vendored C/C++ libraries and curated configuration mitigations grow by hand, each entry added from the advisory text and upstream source.
- **Recall on held-out benchmarks**: BAC-Bench and `benchmarks/logicbench` (blind first run 3/32) measure the hunts; gaps they expose are fixed in the engine or the packs, never as benchmark-shaped rules.

New work is proposed in [Discussions](https://github.com/lambdasec/frame/discussions) and added here when it is taken up.

## Approximations kept

These are deliberate, documented limits rather than open bugs. Lowering is guarded by `tests/test_metamorphic*.py` (each seed flow rewritten without changing its meaning must keep its finding) and `tests/test_lowering_coverage*.py` (data-carrying syntax must not fall back to a variable named by its text); no frontend has strict xfails left.

- **Reproduction**: a fix that leaves attacker data reaching the sink but makes it safe (a sanitize-in-place, or a dependency upgrade that keeps the call) does not flip a reachability reproduction and is certified by a re-scan instead. A Java/C# call-site hook sees the marker in text, arrays, collections and bytes, not inside a stream, and a sink reached only through a method reference or reflection has no call to hook.
- **C#**: a project method's `out`/`ref` parameters and its return value share one summary; a ternary inside a larger expression is a value (only an assigned or returned one becomes branches); Razor brace matching does not parse markup text.
- **C/C++**: a write through a pointer that is not provably one local's address is a weak update; lambda captures are flow-insensitive over the enclosing function; a container is one value; constructors resolve only when the class has one; a call through `using` resolves only when no global function or library row of the same name is visible.

**Not planned**: more SAST languages (PHP, Go, Swift, Kotlin, Rust `unsafe`), and detecting AI-generated code (authorship does not change whether code is vulnerable; the guardrails cover the need).

## Licensing

Packs Apache-2.0, datasets CC-BY-4.0.
