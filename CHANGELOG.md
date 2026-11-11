# Changelog

All notable changes to Frame are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Frame uses [semantic versioning](https://semver.org/). Each release's full notes are on the [releases page](https://github.com/lambdasec/frame/releases).

## [Unreleased]

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

[Unreleased]: https://github.com/lambdasec/frame/compare/v1.1.4...HEAD
[1.1.4]: https://github.com/lambdasec/frame/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/lambdasec/frame/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/lambdasec/frame/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/lambdasec/frame/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/lambdasec/frame/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lambdasec/frame/releases/tag/v1.0.0
