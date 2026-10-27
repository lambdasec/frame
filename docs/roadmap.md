# Roadmap

Frame's goal is to be the open-source application security platform: code (SAST), dependencies (SCA), secrets, infrastructure and containers, AI application security and autonomous pentesting, all on one engine, where every finding says how strongly it is proven. An LLM, frontier or local, stays an optional add-on at every stage.

The phases are ordered so that each one builds on the last. Pick work from the earliest phase that is not done.

## Principles

- **One engine, reused everywhere.** The program model (SIL, the project index, canonical call ids, taint, Z3) serves every domain: SCA reachability is "is this vulnerable function called", LLM app security is taint with new source and sink kinds, pentest recon reads routes from the packs' entrypoints.
- **Knowledge is data.** What Frame knows about languages, frameworks, rules, advisories and secret formats lives in versioned, data-only files (TOML/JSON, never code), not in the engine.
- **Every finding carries its evidence.** One finding model across all domains, with an evidence level: matched, reachable, path proven feasible by the solver, LLM-triaged, exploit-confirmed. Fingerprints, baselines, `verify`, SARIF, the GitHub Action, the pre-commit hook and MCP work the same for every category.
- **No benchmark-specific behaviour.** Every change is checked against the full benchmark sweep (identical results unless the change intends otherwise), and solver changes against every SL-COMP division.

## Phase 0: close the SAST known gaps (done, October 2026)

All 37 gaps that were strict xfails in `tests/e2e/test_known_gaps_*.py` are now regular vulnerable/safe cases; a newly found gap goes there first.

Done (October 2026): extensionless shebang scripts, a warning for files that do not parse, C constant shifts (`1u << 20`), a Java redirect target reassigned to a constant on the bad branch, JS path containment (`path.resolve` + `startsWith(BASE)`), JS prototype methods.

**A. Taint stored in object state**: done. A constructor or setter storing attacker data in a field reaches a sink in another method of the object (Java, C#, Python, JS); a Python `@property` returning request data; Express middleware setting `req.x` for the handlers of the same app; a servlet Filter's request attribute read by a servlet.

**B. Call resolution**: done. Interfaces with several implementations (taint reaches each, Java and C#), C# extension methods and partial classes, Java static-factory chains, instances a module exports or builds at its top level (Python `repo = Repo()`, JS `module.exports = new Mailer()`, an object-literal DI container), CommonJS barrels (`module.exports = { ...require("./q") }`), `functools.partial`, and Django managers held as class attributes.

**C. C/C++ validation idioms**: done. `strcmp` allowlists, `strspn` charset checks, a loop rejecting the first character that fails `isalnum` (or another character-class test), `strncmp` against a fixed `scheme://host/` prefix, a lookup in a table of literals (`std::map::find`), numeric conversion inside `snprintf` (`atoi`), and a `memcpy` length checked on the path (the length, not the copied bytes, is the sink).

**D. C/C++ interprocedural and memory**: done. Attacker data passed into a helper function reaches its sinks (the interprocedural fixpoint runs for C/C++, including C++ overload sets); `sprintf` of attacker text that can exceed the destination; an attacker index into a file-scope array; a branch that frees and returns no longer makes the later free a double free; `new[]` stored in a member (also from a constructor's initializer list, now lowered) released with `delete`. The line-based `system()`/`popen()` rule, which flagged every call whether tainted or not, is gone.

**E. Weak randomness by flow**: done. `rand()`/`random()`/`drand48()` output is `weak_random` taint, reported as CWE-338 only where a value must be unpredictable (a `Set-Cookie` header, an `EVP_*Init` key or IV, an HMAC key, a PBKDF2 salt, a CSPRNG seed), also through a helper that fills a buffer; it never counts as an injection payload. Python, JS and Java still report every non-cryptographic random call (OWASP Benchmark scores weak randomness that way); moving them to the flow rule is a separate, measured change.

**Engine fixes found along the way**: an assignment that is not a literal forgets the variable's constant (`nonconst`), so code after `for (i = 0; i < N; i++)` is analysed (it was unreachable, hidden by the removed `system()` line rule); a C store taints the buffer it writes into; `n = strlen(buf)` is bounded by buf's capacity.

**Engine debts found along the way**: done. Sanitization checks resolve sink-kind aliases (`path` is `filesystem`); assigning a plain local is a strong update (its old taint goes unless the new value reads it); Python `os.path.realpath`/`normpath` are no longer sanitizers on their own (a `startswith(BASE)` check on the normalised path is); Java numeric parsing (`Integer.parseInt`, ...) sanitizes text-payload sinks; a ternary takes the branch its condition folds to over known constants, replacing a heuristic keyed on the words "always"/"never".

## Phase 1: foundations

- Done: **workspace inventory** (`frame inventory`, `frame/sil/inventory.py`): languages, frameworks (packs whose `detect` matched), manifests and lockfiles by ecosystem, IaC (Terraform, Kubernetes, Helm, CloudFormation, Compose), Dockerfiles, LLM SDKs and MCP servers.
- Done: **unified finding model** (`frame/sil/findings.py`): every finding has a `category` (taint, memory, crypto, secret, access-control, hardening; dependency, iac, container and ai reserved) and an `evidence` level (matched, llm-detected, llm-verified, data-flow, solver-verified, exploit-confirmed), in JSON and SARIF.
- **Knowledge base (KB)**:
  - Done: the client (`frame/kb`, `frame kb pull | status | build`). A revision is a directory with `manifest.json` (every file's SHA-256, size, language, kind) and data files; `pull` downloads only the project's languages, verifies each file, caches it, and can pin the revision in `.frame/kb.lock`; scans load cached packs (they replace built-in packs of the same name) and never fetch. Sources: `hf:org/dataset`, an HTTPS mirror, or a local directory for air-gapped CI.
  - Next: create the `lambdasec/frame-kb` dataset and the publishing job (build on merge, upload to HF); sign the manifest once a publishing key exists, and verify the signature in `pull`.
  - Next: move the language specs (`frame/sil/specs/*_specs.py`) into TOML language packs, with a benchmark-identical sweep, so they can ship through the KB too.
- **Config cleanup**: `.frame.toml` holds project settings only (severities, excludes, pinned knowledge). Packs describe code; rules become pack kinds (pattern, policy, secret, advisory). Only what cannot be data (C memory analysis, the solver) stays in the engine.
- **Licensing**: packs Apache-2.0, datasets CC-BY-4.0.

## Phase 2: SCA

- Dependency graph (direct and transitive) from lockfiles: Python (`requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`), JS (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`), Java (`pom.xml`, Gradle lockfiles), C# (`packages.lock.json`).
- Advisories from OSV, enriched by a Frame dataset of vulnerable functions per advisory, built by mapping each fix commit's changed functions to canonical call ids with Frame's own frontends.
- Reachability levels: installed, imported, vulnerable function called, attacker data reaches it (taint).
- Z3 remediation planning: the smallest set of upgrades that removes every vulnerable version while satisfying every package's constraints; whether an unpinned manifest admits a vulnerable version.
- SBOM (CycloneDX, SPDX) and license data from the same graph.

## Phase 3: secrets, infrastructure, containers

- Secrets: entropy and provider key formats on top of the value-shape gate, test code recognised from the program model (not file names), git history, optional live verification of a found key.
- IaC: Terraform, Kubernetes, Helm, CloudFormation, Dockerfiles (tree-sitter grammars); policies as KB packs; Z3 for reachability-style policy questions ("can the internet reach this bucket").
- Containers: image layers to OS packages to the SCA pipeline (OSV distro advisories).

## Phase 4: AI application security

- LLM taint: untrusted input (requests, retrieved documents, tool output) reaching a prompt (prompt injection, OWASP LLM01); LLM output reaching exec, SQL or HTML (OWASP LLM05).
- Packs for the OpenAI, Anthropic, LangChain, LlamaIndex and MCP SDKs.
- MCP servers: tool handlers scanned as ordinary SAST through an MCP entrypoint pack, plus tool-metadata checks (injected instructions, over-broad capabilities).
- Not planned: detecting AI-generated code. Detectors are unreliable and authorship does not change whether code is vulnerable; guardrails on agent edits (pre-commit, `--files`, MCP) cover the need.

## Phase 5: autonomous pentesting

- Grey-box: inventory, routes from entrypoint packs, SAST findings and reachable SCA vulnerabilities become the attack plan for `frame exploit`, with a frontier or local model.
- Add for black-box work: crawling and OpenAPI import, authentication and sessions (needed for IDOR), parallel hypotheses, an independent validator for every claimed exploit, scope and safety controls.
- Measure on XBOW's validation benchmark and CVE-Bench, blind and primed with Frame's findings.
- Later: attacks on LLM apps and agents (prompt injection payloads, tool abuse).

## Distribution (done)

- PyPI `frame-security`, GitHub Action on the Marketplace (`lambdasec/frame-action@v1`, which follows Frame's `v1` tag), pre-commit hook (`id: frame`), MCP server (`frame-mcp` on PyPI and the official MCP Registry).
- On each 1.x release, move the `v1` tag to it: `git tag -f v1 vX.Y.Z && git push -f origin v1`.
