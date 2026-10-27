# Roadmap

Frame's goal is to be the open-source application security platform: code (SAST), dependencies (SCA), secrets, infrastructure and containers, AI application security and autonomous pentesting, all on one engine, where every finding says how strongly it is proven. An LLM, frontier or local, stays an optional add-on at every stage.

The phases are ordered so that each one builds on the last. Pick work from the earliest phase that is not done.

## Principles

- **One engine, reused everywhere.** The program model (SIL, the project index, canonical call ids, taint, Z3) serves every domain: SCA reachability is "is this vulnerable function called", LLM app security is taint with new source and sink kinds, pentest recon reads routes from the packs' entrypoints.
- **Knowledge is data.** What Frame knows about languages, frameworks, rules, advisories and secret formats lives in versioned, data-only files (TOML/JSON, never code), not in the engine.
- **Every finding carries its evidence.** One finding model across all domains, with an evidence level: matched, reachable, path proven feasible by the solver, LLM-triaged, exploit-confirmed. Fingerprints, baselines, `verify`, SARIF, the GitHub Action, the pre-commit hook and MCP work the same for every category.
- **No benchmark-specific behaviour.** Every change is checked against the full benchmark sweep (identical results unless the change intends otherwise), and solver changes against every SL-COMP division.

## Phase 0: close the SAST known gaps (in progress)

Each gap is a strict xfail in `tests/e2e/test_known_gaps_*.py`. Fixing one turns it into a regular vulnerable/safe case. 31 remain.

Done (October 2026): extensionless shebang scripts, a warning for files that do not parse, C constant shifts (`1u << 20`), a Java redirect target reassigned to a constant on the bad branch, JS path containment (`path.resolve` + `startsWith(BASE)`), JS prototype methods.

**A. Taint stored in object state** (the largest design change)
- Java: `constructor_stores_request_data_in_field`, `builder_field_setter_carries_request_data`, `filter_sets_attribute_servlet_reads`
- C#: `constructor_stores_request_value_in_field`
- JS: `middleware_chain_sets_req_field`
- Python: `property_returns_request_data`

**B. Call resolution**
- Interfaces: `two_implementations_behind_interface` (C#), `two_implementations_behind_interface_with_qualifier` (Java)
- C#: `extension_method_runs_process`, `partial_class_second_file`
- Java: `static_factory_chained_call_in_other_file`
- JS: `cjs_spread_require_barrel`, `inversify_style_di_container`, `module_exports_singleton_instance`, `module_singleton_repo`
- Python: `functools_partial_dispatch`, `django_manager_raw` (class-attribute types across files, and `self.raw()` in a `Manager` subclass as a sink)

**C. C/C++ validation idioms** (reuse the guard machinery the other languages have)
- `strcmp_allowlist_before_system`, `strspn_charset_before_popen`, `isalnum_loop_before_system`, `map_allowlist_before_std_system`, `prefix_allowlist_before_curl`, `memcpy_length_checked_against_capacity`, `nested_atoi_in_snprintf_argument`

**D. C/C++ interprocedural and memory** (part of replacing the line-based C detectors with structural analysis)
- `helper_gets_tainted_sql`, `helper_gets_tainted_path`, `sprintf_untrusted_into_small_buffer`, `tainted_index_into_global_table`, `free_in_branch_then_free_on_other_path`, `member_array_new_scalar_delete`

**E. Needs a design first**
- `rand_for_session_token_without_crypto_include`: reporting every `rand()` floods Juliet with false positives and guessing from names is brittle. Follow the random value into what it is used for.

**Engine debts found along the way**
- `is_sanitized_for` compares sink-kind names literally (`path` vs `filesystem`); resolve aliases on both sides.
- An assignment kills taint only for a literal into a plain local; generalise to a strong update for any plain-local assignment.
- Python treats `os.path.realpath` alone as a path-traversal sanitizer; only a containment check after normalisation confines a path.
- `_exec_assign` has a heuristic keyed on the words "always" and "never" in string constants (OWASP Benchmark shaped); replace it with real constant folding of the condition.

## Phase 1: foundations

- **Workspace inventory**: one pass that finds languages, frameworks, lockfiles, IaC files, Dockerfiles, LLM SDKs and MCP servers, and decides which analyzers run and which knowledge to fetch.
- **Unified finding model** with `category` (taint, hardening, dependency, secret, iac, container, ai) and the evidence level.
- **Knowledge base (KB)**:
  - Language specs (`frame/sil/specs/*_specs.py`) move into TOML language packs, with a benchmark-identical sweep.
  - Packs, rules, policies, secret formats and advisories are published as public Hugging Face datasets under the lambdasec org.
  - Frame downloads only what the inventory needs, verifies a signed manifest, caches it, and pins revisions in `.frame/kb.lock` for reproducible CI.
  - `frame kb pull` builds an offline bundle for air-gapped CI; a mirror URL serves networks that block huggingface.co.
  - A core bundle (language specs and the most used frameworks) ships in the wheel, so `pip install frame-security` scans offline on first run.
  - New packs and rules reach users without a Frame release.
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

- PyPI `frame-security`, GitHub Action on the Marketplace (`lambdasec/frame-action@v1`, which follows Frame's `v1` tag), pre-commit hook (`id: frame`), MCP server (`frame-mcp`, in progress).
- On each 1.x release, move the `v1` tag to it: `git tag -f v1 vX.Y.Z && git push -f origin v1`.
