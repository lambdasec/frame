# Changelog

All notable changes to Frame are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Frame uses [semantic versioning](https://semver.org/). Each release's full notes are on the [releases page](https://github.com/lambdasec/frame/releases).

## [Unreleased]

### Added

- **An engine check for races.** `check atomic_write` (hunt agents and `frame query`) decides at a write of stored data whether two concurrent requests can both act on the same old value: proved when the write is atomic or a lock comes first, refuted when the function reads first and neither it nor a caller locks, checks a version or writes atomically, unknown otherwise. A refutation corroborates a `race` finding (`llm-verified`). What protects is pack data (`[[concurrency]]`, in the Django, TypeORM and JPA packs).

- **ORM writes in JavaScript/TypeScript, Java and C# are data facts.** TypeORM repository and entity-manager writes, Prisma model writes, Drizzle `insert` / `update` / `delete` (new `javascript/drizzle` pack, transactions included), JPA `EntityManager` and Hibernate `Session` writes, Spring Data repository writes (new `java/spring-data` pack) and EF Core `SaveChanges` / `Add` / `Update` / `Remove` mark the code as writing stored data, as Django's `save()` already did. The business-logic hunt plans its service-layer units and its `race` / `limits` / `workflow` / `replay` audits from these facts; before, a NestJS or Next.js service that wrote through an ORM was invisible to it. They are markers, never findings.
- **Calls named after the library type they come from.** A Java call on a project type is named after the library type that declares the method (`repo.save(c)` with `CouponRepository extends JpaRepository<...>` is `JpaRepository.save`), as C# already was across files; a C# call on a field of a `DbContext` subclass (`_db.SaveChanges()`) is `DbContext.SaveChanges`.
- **TypeScript types followed further.** A type alias of a library type (`type DB = MySql2Database<S> & { $client: Pool }`), in the same file or imported from another, types a value declared with it; and a project method declared to return a library type (`getRepository(...): Repository<E>`, `Promise<T>` read as T) types the calls on its result.

### Fixed

- **The hunt runs in the language the scan was asked for.** A directory scan moved `FrameScanner.language` to each file's language, so the hunt got the last file's: a Python app with a `#!/usr/bin/env node` script was hunted as JavaScript, its scouts laid out over the front end and its backend counted as one file.
- **Claude 5 models on Anthropic's OpenAI-compatible endpoint.** They reject any request carrying `temperature` (HTTP 400), so every LLM call failed and a hunt ended with no findings. The client now drops the field once the endpoint rejects it and remembers that for the endpoint and model; other endpoints still receive `[llm] temperature`.

## [1.1.8] - 2026-11-18

### Added

- **Malicious packages get malware advice.** OpenSSF's `MAL-` records and GitHub's CWE-506 advisories (a compromised release, a typosquat) are now labelled `malicious`, and the advice is no longer `no fixed version`: a package malicious in every release is to be removed, a malicious release pinned away from (the plan names the releases to avoid), and in both cases the credentials the installing machine could reach rotated. MAL-2026-20101 (agent-framework 1.26.1 and 1.26.2) is reported this way. RustSec's informational advisories are labelled too (`unmaintained`, `unsound`, `notice`), and an unmaintained crate's advice is to replace it. See `examples/malicious-packages`.
- **Python start-up hooks in installed environments.** `frame deps --rootfs` / `--image` list each `.pth` file whose lines Python executes at start-up, and `sitecustomize` / `usercustomize`, with the distribution that installed it (or none). A credential stealer that runs from a start-up hook is visible before any advisory exists.

## [1.1.7] - 2026-11-18

### Added

- **Language runtimes in images.** A JDK, Node.js, CPython, .NET or Ruby that an image installs from a tarball (`eclipse-temurin`, `node`, `python`, `ruby`, `mcr.microsoft.com/dotnet`) is in no package database, so Frame missed it. Each is now read from its own version file (a JDK's `release`, `node_version.h`, `patchlevel.h`, the shared framework's `deps.json`, `rbconfig.rb`) and matched against the runtime's own advisories: OpenJDK's vulnerability advisories (new `OpenJDK` table), the Node.js security WG's (`Node.js`), the Ruby advisory database's (`Ruby`), OSV's CPython records by release tag, and GitHub's advisories for the .NET runtime packs. `frame deps --image eclipse-temurin:17-jre --vulns` now reports CVE-2026-114938 ("Java4Shell"). A JDK on a release line OpenJDK no longer lists gets a note, an OpenJ9 JDK a warning. See `examples/container-runtimes`.
- **The last affected version in findings.** An advisory that names no fix but a last affected version (all of OpenJDK's) now says so: `no fixed version named; last affected 17.0.21.0.3`.

### Fixed

- **A CVE record's packages no longer change an advisory OSV already has.** In 1.1.6 the packages a CVE record names were merged with OSV's records of the same CVE, so where the two disagreed the wider range won (OWASP dependency-check 9.0.6 is fixed per GitHub's advisory and last affected per the CNA). They now only fill packages OSV does not file the CVE under. On today's OSV exports this adds 2,049 advisories across Maven, npm, Go, Packagist, crates.io, PyPI and NuGet, and changes no existing one.

## [1.1.6] - 2026-11-17

### Added

- **Business-logic hunting: `frame scan --hunt CLASSES`.** The hunt's pipeline (scouts, units, one agent per unit, a verdict on every member) now takes a flaw class: `authz` (the authorization hunt, unchanged), `limits` (a client number stored without its bound), `race`, `workflow`, `replay` and `bruteforce`, or `logic` for all of the business-logic classes (also `[hunt] classes`). Each class brings its own instructions and ranks units from the engine's facts, never from names. A business-logic finding is `llm-verified` only when an engine check the agent ran refuted the bound or the guard in that function, and the witness is in its description.
- **Bounds decided by the engine.** `check` has two new kinds, `lower_bound` and `upper_bound`, in the hunt and in `frame query` (`--var`, `--bound`). Z3 decides whether a number the caller chooses can be outside a bound on a feasible path to a line. Numbers are recognised from conversions (`int()`, `Number()`, `Integer.parseInt`, `int.Parse`...) and from handler parameters of a number type. A refutation names the value that gets through, including NaN past a guard written as a rejection (`if amount <= 0: abort()`). See `examples/business-logic`.

### Fixed

- **Views that extend a project base view in another file are handlers.** An entry point declared on a framework class (`extends`: Django REST framework's `APIView`, Django's `View`, ...) held only when the file's own classes reached it, so `class E(BaseAPIView)` with the project's `BaseAPIView(APIView)` in another file was not a handler, and nor was any view built on it (Plane: 141 handlers found, 767 now). The project step now resolves each class's bases across files (`ClassInfo.project_bases`) for Python, JavaScript and TypeScript.
- **Writes through a Django model or a REST framework serializer are recognised.** A project class whose base is a library class (a serializer built on `ModelSerializer` in another file) is an instance of that library class when called, so `serializer.save()` and `instance.save()` / `delete()` count as writes of stored data. The missing-authorization check (CWE-862) now compares the mutation endpoints written that way too.
- **`.tsx` files are parsed with the TSX grammar.** They were parsed with the plain TypeScript grammar, which reads JSX as type assertions and parse errors, so JSX in `.tsx` files was invisible to the analysis (JSX attribute sinks, what a component returns). The secret-format pass reads them the same way.
- **An agent reply cut off at the output limit is no longer read as its answer.** A reasoning model that spent its whole output budget thinking returned empty content, and the hunt took that as the agent finishing: a scout ended with nothing recorded and its area got no units. The loop now asks again, up to three times in a row. Streamed calls also record why generation stopped.
- **A rate-limited call waits what the endpoint asks.** A 429 or 503 with a `Retry-After` header is retried after that many seconds (or that date), up to 120 s and with up to a second of jitter, instead of on the client's own backoff: a per-minute limit counts refused requests too, so retrying inside the same minute used up the budget.
- **The agents' call log says why and when an attempt failed.** A call a retry rescued logged only its retry count, so an outage could not be told apart (DNS, refused connection, reset, timeout) or placed in time. Each call record now has its UTC start time (`at`) and a `failures` list (time, error, reason) of the attempts before it; a failed call's `detail` holds the reason.
- **The cross-file limit is per language.** A full scan over `--cross-file-limit` files (default 2000) analysed every file alone, so a Python backend beside a large TypeScript frontend lost its cross-file analysis (Plane: 616 Python files beside 3,505 JavaScript and TypeScript ones). Imports never cross from one language family to another, so only a family over the limit is now analysed file by file, with a warning naming it.
- **Business-logic units skip code no request reaches.** A file is reached when it holds an entry point (an engine handler, or a route the scouts found that is not browser code) or a reached file calls it, transitively. Before, any file another file called counted, so a client store that components call was audited as server code, and so was a store method the engine had no procedure for by name (`getRole = computedFn(...)`).
- **Packages a CVE record names are matched when OSV's record dropped them.** OSV's conversion of a CVE record can keep only the git commit range, losing the Maven, npm or PyPI packages the CNA listed: CVE-2026-90436 (Apache Axis 1.x, actively exploited through Confluence) was filed under the Axis repository alone, so no project depending on `axis:axis` was flagged. `frame kb build-advisories` now also reads CVE JSON 5 records (`cvelistV5`) and adds the registry packages their CNA names, with the versions it states as affected. Commit ranges still come only from OSV, so C/C++ matching is unchanged.
- **WAR and EAR files in an image are read.** Only `.jar` files were opened, so a web application deployed as a `.war` (Tomcat's `webapps/`) named none of its libraries. A `.war` or `.ear` is now read like a jar, through the `pom.properties` of the jars inside it.
- **unittest tests are test code wherever their TestCase comes from.** A `test_*` method that calls `self.assert...` is test code even when it inherits TestCase through a project base class in another file. `frappe.tests` is listed as a test framework.

## [1.1.5] - 2026-11-13

### Added

- **`frame query`: the engine as a query service for coding agents.** The tools Frame's authorization hunt gives its agents (`handlers`, `handler_facts`, `siblings`, `trace`, `callers`, `callees`, `guards`, `check`) now answer for any agent or script, with no model. Each answer carries the evidence it rests on, how names were resolved, its limits, the index it was computed over and the query time; call sites carry their line of code. `frame query DIR --serve` keeps the translated project in memory and rebuilds only when a source file changes; frame-mcp 0.3.0 exposes the tools as `engine_*` MCP tools over one such process per project.

### Changed

- **Faster directory scans in large checkouts.** The file walk no longer descends into excluded directories (`.venv`, `node_modules`, `.git`...) only to drop each file afterwards, and the JavaScript frontend indexes a file's identifiers once instead of re-walking the tree for every function (a bundled library was quadratic). Findings are unchanged.

## [1.1.4] - 2026-11-11

### Fixed

- **Findings lost when code was written another ordinary way** ([#9](https://github.com/lambdasec/frame/issues/9)). A Flask app that keeps its database connection on `flask.g` (the Flask docs' `get_db()` pattern) lost its SQL injection findings. An adversarial review of every frontend then found and fixed the same class of bug in Python, JavaScript/TypeScript, Java, C# and C/C++: chained and unpacking assignments, `try`/`except`/`finally` and `catch` bodies, compound assignment (`x += e` was lowered as `x = e` in Java and C#), ternaries, `switch`, `break`/`continue`/`goto`, struct and object fields, dict and list literals, comprehensions, lambdas, method references, library callbacks (`forEach`, `map`, `then`), `out`/`ref` arguments, Razor control flow, C macros and many more. Metamorphic tests now rewrite each vulnerable flow without changing its meaning and require the finding to survive, and lowering tripwires fail when data-carrying syntax is dropped.
- **Fewer false positives.** A same-file Java helper returning a constant no longer taints its result (OWASP BenchmarkJava, full suite: false positives 429 to 216, no true positive lost); constant dict keys (`', '.join(f'{k} = ?' for k in updates)`), numeric operators in JavaScript, numeric parsing in C#, and `sizeof` in C (was the constant 0) no longer produce findings.
- **Scanner robustness.** The Python frontend evaluated constant conditions with `eval`, so a scanned file containing `9**9**9` could stall the scan; it now uses a bounded evaluator.
- Package metadata: the licence is an SPDX expression (`license = "Apache-2.0"`), removing the setuptools deprecation warning.

### Added

- **Unhashed credential storage (CWE-522).** A password or generated token written to a database without a hash, MAC or KDF in between, read from the SQL the program writes.
- **Flask views' returned HTML is an XSS sink** when the response is sent as HTML.
- Replacer functions (`re.sub`, `String.replace`) and `map` callbacks carry what they return; path containment through `path.relative` / `os.path.relpath` is a guard.

### Changed

- C#: `while (true)` with no way out is reported as CWE-835, as in Java and C.

## [1.1.3] - 2026-11-06

### Added

- **Proof-carrying findings, across languages.** `frame exploit --deps` now reproduces code taint flows (SQL injection, command injection, XSS, path traversal, SSRF and the other source-to-sink injections) as well as dependency reachability, for Python, JavaScript/TypeScript, Java and C#. Java spies the sink interface with a core-JDK `java.lang.reflect.Proxy` (only a JDK needed); C# uses xUnit + Moq (the .NET SDK). Every reproduction counts only when the marker reaches the sink through the project's own code.
- **Fix-loop.** `frame exploit --deps --check-fixed DIR` re-runs a confirmed reproduction against a fixed copy of the project and verifies it no longer reaches the sink, so a proof of the vulnerability becomes a proof of the fix.
- **Reports for more platforms.** `frame scan -f markdown` (a pull-request comment or `$GITHUB_STEP_SUMMARY` report), `-f gitlab` (GitLab SAST report) and `-f sonar` (SonarQube generic issue import). SARIF results now carry code flows and proofs.
- **`frame diff OLD.json NEW.json`** reports which findings a change introduced, fixed or left unchanged, paired by fingerprint.
- **`--fail-on-evidence LEVEL`** breaks a build only on findings at or above an evidence level, for example only on what the solver proved.
- Reproduction exemplars for XSS and a JavaScript dependency, and a CI job that runs every cross-language reproduction on real toolchains.

### Fixed

- Findings JSON now includes `sink_call`, so `frame exploit --deps` can build a reproduction of a code taint finding from a scan's output. Before, taint reproductions only ran from the exemplars.

## [1.1.2] - 2026-11-06

### Fixed

- `frame scan --confirm-proofs` failed to compile every harness on GCC, because it passed the Clang-only `-fsanitize=implicit-conversion`. The sanitizer set is now probed per compiler.

## [1.1.1] - 2026-11-06

### Added

- **Proof-carrying findings.** `frame scan --confirm-proofs` (no model) runs C integer-overflow, signed-size, truncation and out-of-bounds findings with the solver's own inputs under AddressSanitizer and UndefinedBehaviorSanitizer, and raises a finding to `exploit-confirmed` on an observed fault; `--proof-tests-dir` keeps each confirmed test as a regression guard. `--reproduce-proofs` drives a seeded agent for inputs read from stdin or argv. `frame exploit --deps` turns `frame scan --sca` reachability into a pytest that drives the project to the vulnerable call.

### Fixed

- `sca-real`: a case skips instead of failing when the external package manager crashes in its own code.

## [1.1.0] - 2026-11-06

### Added

- **Broken access control hunting.** `frame scan --hunt-authz` runs an engine-directed agent for IDOR, missing authorization, privilege escalation and mass assignment: 22 of 30 on BAC-Bench (ABSENTIA 19, CodeQL and Semgrep 0).
- **Infrastructure as code.** Kubernetes (Pod Security Standards), Dockerfiles, Terraform (AWS, Azure, Google Cloud), CloudFormation and Helm, every policy decided with Z3 (`frame iac`, `frame scan --iac`).
- **Containers.** OS packages of Debian, Ubuntu, Alpine, RHEL/UBI, AlmaLinux, Rocky, Wolfi/Chainguard, openSUSE, SLES and Azure Linux, language packages in images, and modules compiled into Go and Rust binaries.
- **SCA.** Ruby, PHP, Dart and Elixir; Gradle build scripts without Gradle; Z3 upgrade planning; `--adapt` for code an upgrade breaks; licence policy; configuration mitigations; govulncheck reachability; backported npm fixes; vendored C/C++ libraries.
- **Secrets.** Provider key formats, opt-in live verification, and `frame history` across git history.
- **AI applications.** Prompt injection, model output and retrieved documents as taint, MCP tools and hidden instructions in tool metadata.

### Changed

- **One configuration.** Every setting lives in `.frame.toml` or `[tool.frame]`, resolved as flag, then environment variable, then file, then default. Environment variables drop from 33 to 9, and a retired one that is still set is warned about with its replacement.
- `frame exploit --max-steps` defaults to `llm.exploit_max_steps` (250, was 40), and `--model` now wins over `FRAME_LLM_MODEL` and the config file.

### Removed

- `FRAME_LLM_REPO_ROOT`: use `frame scan --root`.

## [1.0.0] - 2026-10-27

The first stable release: five languages (Python, JavaScript/TypeScript, Java, C# and C/C++), cross-file taint by default, 70+ framework packs, `--changed` / baselines / `frame verify` for CI and coding agents, the GitHub Action and pre-commit hook, the optional AI layer (detect, triage, exploit, fix), and the separation logic engine on Z3.

[Unreleased]: https://github.com/lambdasec/frame/compare/v1.1.8...HEAD
[1.1.8]: https://github.com/lambdasec/frame/compare/v1.1.7...v1.1.8
[1.1.7]: https://github.com/lambdasec/frame/compare/v1.1.6...v1.1.7
[1.1.6]: https://github.com/lambdasec/frame/compare/v1.1.5...v1.1.6
[1.1.5]: https://github.com/lambdasec/frame/compare/v1.1.4...v1.1.5
[1.1.4]: https://github.com/lambdasec/frame/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/lambdasec/frame/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/lambdasec/frame/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/lambdasec/frame/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/lambdasec/frame/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lambdasec/frame/releases/tag/v1.0.0
