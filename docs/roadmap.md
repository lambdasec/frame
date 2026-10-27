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
  - Done: the `lambdasec/frame-kb` dataset, published from a private source repo on every merge (check, build, upload, tag); the first published revisions carry the 77 packs and the six spec tables. Manifest signing is deferred.
  - Done: the language specs are data (`frame/sil/specs/data/<table>.toml`, 2,888 entries across six tables), identical in order and fields to the Python tables they replace; the KB can ship them too (`frame kb build --specs`).
- **Config cleanup**: `.frame.toml` holds project settings only (severities, excludes, extra packs; the KB pin is `.frame/kb.lock`). Packs describe code; rules become pack kinds. Done: `[[setting]]` (configuration that switches a protection off) replaces the hard-coded hardening rules, with `files`/`module_names` detect keys for settings modules. Secret formats and advisories arrive as kinds with Phases 2 and 3. Only what cannot be data (C memory analysis, the solver) stays in the engine.
- **Licensing**: packs Apache-2.0, datasets CC-BY-4.0.

## Phase 2: SCA

- Done: the dependency graph (`frame deps`, `frame/sca/`) from lockfiles and manifests: Python (`requirements*.txt` with `-r` includes, `pyproject.toml`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`), JS (`package.json`, `package-lock.json` v1-v3, `yarn.lock` classic and berry, `pnpm-lock.yaml` v5-v9), Java (`pom.xml` with properties and dependency management, `gradle.lockfile`), C# (`packages.lock.json`, `*.csproj`, `packages.config`), and, for dependencies only, Go (`go.mod`), Rust (`Cargo.lock` with `Cargo.toml` for dev) and Swift (`Package.resolved`). Exact versions, edges, direct (from the manifest beside a lockfile, else unknown), dev only (the lockfile's flag, else unreachable from a production dependency), package URLs. Not read: Gradle build scripts and Maven transitive resolution (both need the build tool).
- Done: resolved graphs for Java and .NET (Maven `dependency:tree` text and JSON, Gradle `dependencies` reports, `obj/project.assets.json`, `Directory.Packages.props`), and `frame deps --resolve`, which runs Maven, Gradle and pip (dry run, wheels only) for projects without a lockfile.
- Next for the graph: `build.gradle` direct dependencies without running Gradle; Ruby, PHP, Dart and Elixir lockfiles.
- Done: C/C++ dependencies (`frame/sca/cppdeps.py`, `cpp.py`, `cmake.py`): Conan, vcpkg, submodules, CMake fetches, each resolved to its upstream repository and tag (a map generated from vcpkg ports and Conan Center recipes, `frame/sca/data/cpp-repos.json`) and matched against OSV's GIT advisories by affected tag, sharded by repository (the Linux kernel's git.kernel.org records are left to the OS work). Next: commit-range matching for a submodule pinned to an untagged commit (needs the repository history), and identifying vendored copies.
- Go reachability comes from `govulncheck -json` when a report is present (it uses the compiler's call graph); Frame imports it rather than re-deriving it.
- Done: advisory matching (`frame/sca/versions.py`, `osv.py`, `advisories.py`; `frame deps --vulns`, `frame kb pull --advisories`, `frame kb build-advisories`). Version order per registry, checked against Maven's own ComparableVersion, `packaging` and npm's semver; OSV range semantics checked against the OSV API's answers for 29 vulnerable and fixed versions across all seven ecosystems; aliases merged; CVSS v3 base scores.
- Advisories: a separate dataset, `lambdasec/frame-advisories`, published by the same machinery as `frame-kb` but rebuilt daily from OSV (packs change with Frame and are pinned per project; advisories should be current by default, with an optional pin for reproducible audits). Compact per-ecosystem files (`advisories/<ecosystem>.json`: package, affected ranges, fixed versions, ids, severity), so `pull` fetches only what a project uses; each source keeps its licence.
- Vulnerable functions per advisory, in the same dataset (`functions/<ecosystem>.json`, CC-BY-4.0, keyed by advisory id, rebuilt on its own schedule and joined at load time): Frame canonical call ids with provenance, `osv` (Go's `ecosystem_specific.imports[].symbols`), `fix-commit` (the public functions a fix commit changed, found with Frame's frontends) or `curated`. Reachability evidence carries the provenance.
- Done: reachability levels installed, imported, called (`frame/sca/reachability.py`): imports and calls from Frame's frontends (`Program.imports`, `Call.canonical`; C# `using` plus `Type.Method` only when it equals the advisory's own id), PyPI module names from the project's virtualenv, else a table. Positive evidence only. Vulnerable-function data ships as `functions/<Ecosystem>.json.gz` in the advisory dataset (`frame kb build-advisories --functions`), merged by advisory id or alias.
- Done: the tainted level (`frame scan --sca`, `frame/sca/scan.py`): vulnerable functions become sinks of a generated pack (`only_if_not_sink`), and a finding counts for an advisory only when its sink call (`Vulnerability.sink_call`) is that function at that call site. Curated function files ship in the dataset (daily).
- Done: fix-commit mining (`frame kb mine-functions`, `frame/sca/mine.py`): the public functions an advisory's GitHub fix commit changed, as canonical ids (Java/C# package.Class.method; Python from the package's import name in the repository path; JS only for exported functions), internal changes lifted to the public functions of the same file that call them; a fix outside any function (PyYAML's) is listed for curation. Next: run it weekly in the dataset's source repo, and lift through the library's whole call graph (a checkout at the parent commit) where same-file lifting finds nothing.
- Z3 remediation planning: the smallest set of upgrades that removes every vulnerable version while satisfying every package's constraints; whether an unpinned manifest admits a vulnerable version.
- Done: SBOM (`frame deps --sbom cyclonedx|spdx`, `frame/sca/sbom.py`): CycloneDX 1.6 and SPDX 2.3 from the graph, validated against the official schemas on all 25 real package-manager fixtures; licences only where a lockfile records them. Next: licence data for the other ecosystems (registry metadata, in the knowledge base) and licence policy.
- Remediation (`frame fix` for dependencies), deterministic first, the LLM only where judgement is needed, every fix verified by Frame:
  1. Upgrade. Done: the plan (`frame deps --vulns --plan`, `frame/sca/plan.py`, `ranges.py`): the minimum version clear of every advisory, and re-lock / raise-requirement / override from the declared ranges (npm ranges checked against node-semver, PEP 440 against `packaging`). Done: applying it (`--apply`, `frame/sca/apply.py`: minimal manifest edits per ecosystem, `--relock` through the package manager, then the graph re-read and re-matched; a live test re-locks through real npm in CI). Next: running the project's build and tests after applying, and upgrading the packages in between from registry metadata, where solving every package's constraints together is a job for Z3.
  2. Breaking-change adaptation when an upgrade crosses a major version (LLM, from the changelog and the API difference); verified by the build, the tests and a clean re-scan.
  3. Done: code mitigation (`frame fix DIR --deps`, `frame/sca/mitigate.py`): the LLM proposes, the taint engine decides by re-running the whole analysis on a patched copy (removed / untainted, nothing new); exact-value guards (constant allowlists, equality) cut a flow to a vulnerable function, character classes do not.
  4. Configuration mitigation from curated per-advisory data (e.g. Log4Shell's `formatMsgNoLookups`).
  5. Backported patches (upstream fix commit applied to the pinned version, `patch-package`, vendoring) when no upgrade is possible.
  6. Done: VEX (`frame deps --vex`, `frame scan --sca --vex`, `frame/sca/vex.py`): OpenVEX 0.2.0 and CycloneDX 1.6, validated in tests against the official schemas; `affected` with the plan's upgrade, `exploitable` for a verified flow, `not_affected` only from a decision recorded in `.frame/vex.toml` (and never against a verified flow) or opt-in for dev-only dependencies.

## Source languages

SAST covers Python, JavaScript/TypeScript, Java, C# and C/C++: the most used languages, each with a public benchmark, and C/C++ where the separation logic engine decides memory safety. Dependencies are read for more ecosystems than that (Go, Rust, Swift), because an inventory or SBOM that omits part of a repository is wrong. Next SAST languages, on demand: PHP (a large share of web CVEs, injection-heavy), then Go (strong existing tools: `govulncheck`, `gosec`), then Swift and Kotlin with mobile-specific checks. Rust: only `unsafe` code can hold the memory errors the engine proves, a research item.

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
