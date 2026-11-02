# Roadmap

Frame is the open-source application security platform: code (SAST), dependencies (SCA), secrets, infrastructure and containers, AI application security, all on one engine, where every finding says how strongly it is proven. An LLM, frontier or local, stays an optional add-on at every stage.

## Principles

- **One engine, reused everywhere.** The program model (SIL, the project index, canonical call ids, taint, Z3) serves every domain: SCA reachability is "is this vulnerable function called", AI-app security is taint with new source and sink kinds, pentest recon reads routes from the packs' entrypoints.
- **Knowledge is data.** What Frame knows about languages, frameworks, rules, advisories and secret formats lives in versioned, data-only files (TOML/JSON), not in the engine. No framework or benchmark name is special-cased in the core.
- **Every finding carries its evidence.** One finding model across all domains, with an evidence level (matched, reachable, solver-verified, LLM-triaged, exploit-confirmed). Fingerprints, baselines, `verify`, SARIF, the GitHub Action, the pre-commit hook and MCP work the same for every category.
- **No benchmark-specific behaviour.** Every change is checked against the full benchmark sweep (identical results unless the change intends otherwise), and solver changes against every SL-COMP division.

## Built

- **SAST** across Python, JavaScript/TypeScript, Java, C# and C/C++: cross-file taint, 80+ vulnerability classes, 70+ framework packs, C/C++ memory safety decided by the separation logic engine. ([coverage](coverage.md), [engine](engine.md))
- **SCA** for 11 ecosystems plus C/C++ and vendored copies: offline OSV matching, reachability ranking, upgrade plans Frame applies and verifies, code and configuration mitigations, licences, SBOM, VEX, container images. ([dependencies](dependencies.md))
- **Secrets** by name and by provider format, in code and across git history, with live verification. ([secrets](secrets.md))
- **Infrastructure as code**: Kubernetes, Dockerfiles, Terraform (AWS, Azure, Google Cloud) and CloudFormation, every policy decided with Z3. ([iac](iac.md))
- **AI application security**: prompt injection, model output as taint, MCP tools and tool-metadata attacks. ([LLM and MCP](llm-security.md))
- **The knowledge base as open data**: framework packs ([`lambdasec/frame-kb`](https://huggingface.co/datasets/lambdasec/frame-kb)) and the OSV advisory database rebuilt daily ([`lambdasec/frame-advisories`](https://huggingface.co/datasets/lambdasec/frame-advisories)), pinnable for air-gapped CI.
- **Distribution**: PyPI `frame-security`, the [GitHub Action](https://github.com/marketplace/actions/frame-security-scan) (`lambdasec/frame-action@v1`), a pre-commit hook, and an [MCP server](https://github.com/lambdasec/frame-mcp). On each 1.x release the `v1` tag moves to it.

The engine audit that removed every framework and benchmark heuristic from the core (so all of the above is data, not special cases) is complete; the git history has the stage-by-stage record.

## What's next

**Precision and recall polish** (small, measured on the benchmark sweep):
- A quote- and prefix-context check at the sink, so a value guarded by a substring test (`"'" in x`, `"../" in x`) is cleared only where it lands inside a quoted literal or under a constant path prefix, not by the guard alone.
- Carry JavaScript kind facts through function returns and across the call sites of exported functions.
- Scan `.cshtml` / `.razor`, and apply a pack rule to a procedure defined in the same file.
- IaC network reachability for databases and load balancers.

**Data**: the advisory database (daily) and vulnerable-function mappings (weekly) are rebuilt by jobs on their own. Vendored C/C++ libraries and curated configuration mitigations grow by hand, each entry added from the advisory text and upstream source.

**Phase 5: autonomous pentesting.** Turn the inventory, the routes from entrypoint packs, and the reachable SAST and SCA findings into an attack plan for `frame exploit` against a live, authorized target, with a frontier or local model. Then black-box support (crawling and OpenAPI import, authentication and sessions for IDOR, parallel hypotheses, an independent validator for every claimed exploit, and scope and safety controls), measured on XBOW's validation benchmark and CVE-Bench, blind and primed with Frame's findings.

**Not planned**: more SAST languages (PHP, Go, Swift, Kotlin, Rust `unsafe`), and detecting AI-generated code (authorship does not change whether code is vulnerable; the guardrails cover the need).

## Licensing

Packs Apache-2.0, datasets CC-BY-4.0.
