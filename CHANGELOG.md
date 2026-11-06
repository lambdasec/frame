# Changelog

All notable changes to Frame are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Frame uses [semantic versioning](https://semver.org/). Each release's full notes are on the [releases page](https://github.com/lambdasec/frame/releases).

## [Unreleased]

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

[Unreleased]: https://github.com/lambdasec/frame/compare/v1.1.2...HEAD
[1.1.2]: https://github.com/lambdasec/frame/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/lambdasec/frame/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/lambdasec/frame/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lambdasec/frame/releases/tag/v1.0.0
