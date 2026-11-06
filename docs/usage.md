# Using Frame: scanning, CI, configuration and every command

## Scanning

```bash
frame scan app.py                       # one file
frame scan src/                         # every supported language under src/
frame scan src/ -l java                 # one language (or -p "app/**/*.py" for a glob)
frame scan src/ -f sarif -o out.sarif --fail-on high    # SARIF, non-zero exit on high+
frame scan src/ --ai                    # add LLM detection and triage (see ai.md)
```

Text output lists the files with findings and a summary line; `-f json` and `-f sarif` carry the same findings plus stable paths and fingerprints. Exit status: 0 clean, 1 findings at or above `--fail-on`, 2 the scan could not run.

Every finding has a `category` (`taint`, `memory`, `crypto`, `secret`, `access-control`, `hardening`, `dependency`, `ai`) and an `evidence` level saying how strongly it is proven, weakest first: `matched` (a usage or pattern), `llm-detected`, `llm-verified`, `data-flow` (a source-to-sink path), `solver-verified` (the solver proved the path reachable), `exploit-confirmed`. In SARIF both are result properties. A finding in test code has `context: "test"` (`(test code)` in the text): the file imports a test framework, declares tests the way its framework finds them (`[Fact]`, a JUnit `@Test`, an asserting pytest `test_*` function) or registers callbacks with `describe` / `it` / `test`, whatever the file is called. It is a tag, not a filter; only a credential found by its variable's name drops to `low` there.

`frame inventory [dir]` reports what a repository contains without analysing it: languages, the frameworks Frame has packs for, dependency manifests and lockfiles, infrastructure-as-code, Dockerfiles, LLM SDKs and MCP servers, and each MCP tool with what its handler can do (shell, code execution, files, network, database, deserialization) (`-f json` for every path).

`frame deps` covers dependencies: the graph from every lockfile and manifest, known vulnerabilities and whether your code reaches them, upgrade plans that it can apply and verify, licence policy, SBOM and VEX. `frame scan . --sca` adds vulnerable dependencies to the source scan, with attacker data reaching a vulnerable function reported at the call site. Both are covered step by step in [dependencies.md](dependencies.md).

Empty, binary, non-UTF-8 and minified files never abort a scan, and neither does a file that cannot be read.

## Guardrails for CI and coding agents

```bash
frame scan . --write-baseline .frame-baseline.json --fail-on none                       # accept today's state
frame scan . --changed origin/main --baseline .frame-baseline.json -f json -o new.json   # only what's new
frame verify new.json          # after a fix: fixed / present / suppressed / uncertain / unverifiable
```

`--changed` widens to the files that import what changed, since editing a helper can make an untouched caller vulnerable. Fingerprints contain no line numbers, so inserting code above a finding keeps its identity, and `verify` never mistakes silencing or moving a finding for fixing it.

## GitHub Actions

```yaml
# .github/workflows/frame.yml
name: frame
on: [push, pull_request]
permissions:
  contents: read
  security-events: write        # upload SARIF to code scanning
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: lambdasec/frame-action@v1
        with:
          path: src
          fail-on: high
```

The [action](https://github.com/marketplace/actions/frame-security-scan) installs Frame, scans, uploads the SARIF report to code scanning and fails the job on findings at or above `fail-on`. SARIF carries CWE tags and `security-severity`, so GitHub ranks the alerts.

| Input | Default | |
|---|---|---|
| `path` | `.` | Directory or file to scan |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `any` or `none` |
| `args` | | Extra `frame scan` flags |
| `sarif-file` | `frame.sarif` | Where the report is written (also an output, with `exit-code`) |
| `upload-sarif` | `true` | Set `false` when the repo has no code scanning |
| `python-version` | `3.12` | Python that runs Frame |

For pull requests, scan only what the change can affect and fail only on new findings:

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0             # --changed diffs against the base branch
      - uses: lambdasec/frame-action@v1
        with:
          args: --changed origin/${{ github.base_ref }} --baseline .frame-baseline.json
```

Any other CI runs the same thing from the command line:

```bash
pip install "frame-security[scan]"
frame scan src/ -f sarif -o frame.sarif --fail-on high
```

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/lambdasec/frame
    rev: v1.1.3
    hooks:
      - id: frame
        # args: [--baseline, .frame-baseline.json]
```

The hook scans the staged Python, JavaScript/TypeScript, Java, C# and C/C++ files, widened to the files that import them, and blocks the commit on findings at or above `high` (or `fail_on` from `.frame.toml`).

## Coding agents (MCP)

[frame-mcp](https://github.com/lambdasec/frame-mcp) gives Claude Code, Codex, Cursor, VS Code, Windsurf, Gemini CLI, Zed and any other MCP client the whole of Frame as tools, so the agent can scan what it just wrote, fix it and confirm the fix:

```bash
claude mcp add frame -- uvx frame-mcp          # Claude Code
```

```toml
# Codex: ~/.codex/config.toml
[mcp_servers.frame]
command = "uvx"
args = ["frame-mcp"]
```

```json
// Cursor: .cursor/mcp.json  (VS Code: .vscode/mcp.json, under "servers" with "type": "stdio")
{"mcpServers": {"frame": {"command": "uvx", "args": ["frame-mcp"]}}}
```

| Tool | What it does |
|---|---|
| `scan` | Scan a path, symbolic, with `ai`, or with the authorization hunt (`hunt_authz`), optionally only changed files or against a baseline |
| `write_baseline` | Accept the current findings |
| `verify` | Re-check earlier findings: fixed, present, suppressed, uncertain |
| `fix` | Patch findings and re-scan to confirm (needs a model) |
| `exploit` | Attack a live target you are authorized to test |
| `diff` | Compare two scan JSONs: introduced / fixed findings by fingerprint |
| `packs_list`, `packs_check` | List and validate framework packs |
| `solve` | Check a separation logic entailment |

A `security-review` prompt runs scan, verify and fix in one go. The model for the AI tools comes from the `FRAME_LLM_*` variables set for the server or the project's `[llm]` table ([ai.md](ai.md)). Without MCP, an agent gets the same check by running `frame scan . --files <edited files>` after each edit.

For agents that load skills, [`lambdasec/skills`](https://github.com/lambdasec/skills) has `frame-security-scan`: running a scan, reading and triaging the findings, fixing them and re-scanning to confirm, in the open SKILL.md format.

## Suppressions

Silence a reviewed finding inline, optionally by rule:

```python
cursor.execute(query)  # frame: ignore[CWE-89] query is a static string
```

A marker covers its own line or the comment-only line above it. `frame: ignore` alone silences every finding there; `frame: ignore[CWE-89, 79]` only those CWEs (or finding types such as `sql_injection`). Suppressed findings are counted (`summary.suppressed`) and kept in the JSON; `--no-suppress` reports everything.

## Configuration

Every setting lives in one file: `.frame.toml`, or the same keys under `[tool.frame]` in `pyproject.toml`. Each command uses the nearest one above its target (`--config PATH` names one, `--no-config` ignores it). When a setting can be given more than one way, the first of these wins:

```
command-line flag  >  environment variable  >  config file  >  built-in default
```

```toml
min_severity = "medium"
fail_on = "high"
disable = ["CWE-798", "weak_hash"]   # CWE ids or finding types
exclude = ["vendor", "third_party"]  # added to the default excludes
packs = ["security/acme.toml"]       # extra framework packs

[licenses]                           # frame deps --licenses (see dependencies.md)
deny = ["GPL-*", "AGPL-*"]
unknown = "report"
include_dev = false

[llm]                                # the model for --ai, fix, exploit and the hunt (ai.md)
model = "anthropic/claude-haiku-5.5"
api_key_env = "OPENROUTER_API_KEY"   # the variable holding the key; never the key itself
stream = true

[hunt]                               # frame scan --hunt-authz
concurrency = 8
trajectory_dir = ".frame/traces"
```

Unknown keys and values of the wrong type are an error naming the file, so a typo never silently disables a setting. Flags win over the file (`--min-severity`, `--fail-on`, `--disable RULE`, `--pack PATH`, `--model`, `--root`). Directory scans skip `.git`, `node_modules`, `.venv`, `__pycache__` and similar; `--no-default-excludes` scans them. [`examples/configs/`](../examples/configs/README.md) has a minimal, an AI, a dependencies and a hunt config to start from.

The settings tables:

| Key | Default | |
|---|---|---|
| `llm.base_url`, `llm.model` | | the OpenAI-compatible endpoint and model (`FRAME_LLM_BASE_URL`, `FRAME_LLM_MODEL` win) |
| `llm.api_key_env` | `FRAME_LLM_API_KEY` | the variable holding the key (set it to `""` to send none) |
| `llm.temperature` | 0.0 | sampling temperature |
| `llm.max_tokens` | 4096 | completion budget per call |
| `llm.timeout` | 60 | seconds per request (a hung connection, not a cap on the work) |
| `llm.total_timeout` | 0 (derived from the request timeout) | seconds for one HTTP call before its socket is closed |
| `llm.json_mode` | `json_schema` | `json_schema`, `json_object` or `off`, for servers without structured output |
| `llm.stream` | false | stream responses, so a slow generation does not trip a read timeout |
| `llm.stream_stall_timeout` | 60 | seconds with no new streamed token before the stream is re-issued |
| `llm.outage_wait` | 0 (off) | after the retries, keep retrying an unreachable endpoint (network errors, HTTP 408/425/429/5xx) every 30 s for up to this many seconds; for long unattended runs |
| `llm.cache_path` | | a JSON file that keeps LLM verdicts across runs |
| `llm.context_lines` | 12 | lines of code around a finding sent to the model |
| `llm.max_context_chars` | 6000 | cap on one code snippet |
| `llm.drop_threshold` | 0.75 | triage drops a finding only as a false positive at or above this confidence |
| `llm.triage_agentic` | false | let triage use tools to read more of the repository |
| `llm.max_tool_steps` | 30 | tool calls per agentic detect/triage session |
| `llm.agent_max_tokens` | 16000 | completion budget per agent turn |
| `llm.agent_context_budget_chars` | 400000 | context an agent session keeps before old tool results are elided |
| `llm.agent_retries` | 5 | retries for a failed agent turn (backoff 2, 4, 8, 16, 30 s) |
| `llm.exploit_max_steps` | 250 | `exploit` steps (`--max-steps` wins) |
| `llm.hunt_max_steps` | 200 | turns for the single-agent hunt, where Frame has no frontend for the language |
| `hunt.concurrency` | 8 | unit agents at once |
| `hunt.unit_steps` | 24 | tool turns per unit |
| `hunt.max_units` | all | units audited (the rest are reported as deferred) |
| `hunt.scout_steps` | 30 | tool turns per scout; 0 turns the scouts off |
| `hunt.max_scouts` | 16 | scouts that explore the repository before the units |
| `hunt.coverage_readers` | 2 | code read by this many units and owned by none gets a unit of its own after the first wave; 0 turns this off |
| `hunt.trajectory_dir` | | write each agent run's trace (HF Session-Trace JSONL) here; an interrupted trace is resumed |
| `kb.enabled` | true | false uses built-in packs only and no advisories (`FRAME_KB=off`) |
| `kb.source`, `kb.cache` | `hf:lambdasec/frame-kb`, `~/.cache/frame/kb` | where `kb pull` gets packs and where packs and advisories are cached |
| `sca.advisories_source` | the last advisories pull's source, else `hf:lambdasec/frame-advisories` | where advisories come from |
| `sca.registry_cache` | `~/.cache/frame/registry` | registry metadata for `--plan --registry` |
| `sca.backport_cache` | `~/.cache/frame/backport` | OSV records and fix commits for `--backport` (a recorded directory works air-gapped) |
| `engine.generated_line_threshold` | 2000 | a file with lines this long is treated as minified or generated |
| `engine.aggressive_detectors` | false | Java context-dependent detectors (CSRF disabled, field-initializer secrets); use only with LLM triage |

Every file Frame reads from a project:

| File | What it holds |
|---|---|
| `.frame.toml` / `[tool.frame]` in `pyproject.toml` | the settings above |
| `.frame/packs/*.toml` | the project's own framework packs ([coverage.md](coverage.md)) |
| `.frame/kb.lock` | the pinned knowledge-base revision (`frame kb pull --lock`) |
| `.frame/vex.toml` | recorded VEX decisions ([dependencies.md](dependencies.md#vex)) |
| `.frame-baseline.json` (any name) | accepted findings (`--baseline`, `--write-baseline`) |
| `# frame: ignore[...]` comments | inline suppressions |

## Knowledge base

Framework packs and vulnerability advisories arrive as data, between Frame releases, from two public datasets: [`lambdasec/frame-kb`](https://huggingface.co/datasets/lambdasec/frame-kb) (packs and spec tables) and [`lambdasec/frame-advisories`](https://huggingface.co/datasets/lambdasec/frame-advisories) (the OSV advisory database, rebuilt daily). `frame kb pull` downloads the packs for the languages a project uses, and `frame kb pull --advisories` the advisories for the ecosystems its dependencies use. Every file is checked against the manifest's SHA-256 and cached (`~/.cache/frame/kb`, or `FRAME_KB_CACHE`); scans read the cache and never go to the network (with no packs cached they use the ones built into Frame).

```bash
frame kb pull --lock              # this project's languages; pin the revision in .frame/kb.lock
frame kb pull --advisories        # vulnerability advisories (lambdasec/frame-advisories, rebuilt daily)
frame kb status                   # which revisions a scan here would use
FRAME_KB=off frame scan .         # built-in packs only, no advisories
```

For air-gapped CI, lay out a revision on a connected machine and pull from the directory (or an internal HTTPS mirror):

```bash
frame kb build packs/ kb-2026.10/ --revision 2026.10    # packs, on the connected side
frame kb pull --source /mnt/kb-2026.10 --lock           # in CI
frame kb pull --advisories --source /mnt/advisories     # advisories: a copy of a pulled revision directory
```

`--source` (or `FRAME_KB_SOURCE` for packs, `FRAME_ADVISORIES_SOURCE` for advisories) takes `hf:org/dataset`, an `https://` mirror, or a directory. The source of the last advisories pull is remembered, so later scans read that cache. A knowledge base holds data files only (TOML and JSON); nothing in it runs.

## Command reference

Exit status, for every command that checks something: 0 clean, 1 findings (or violations) at or above the threshold, 2 the command could not run or could not judge.

### `frame scan [target]`

| Flag | |
|---|---|
| `-f`, `--format text\|json\|sarif\|markdown\|gitlab\|sonar` | output format (markdown: a PR-comment / `$GITHUB_STEP_SUMMARY` report; gitlab: GitLab SAST report; sonar: SonarQube generic issue import) |
| `-o`, `--output FILE` | write to a file instead of stdout |
| `-l`, `--language LANG` | which files a directory scan walks (default: every supported one), and the language of files with an unknown extension |
| `-p`, `--pattern GLOB` | only files matching the glob |
| `--fail-on critical\|high\|medium\|low\|any\|none` | exit 1 at or above this severity (default: config, else high) |
| `--fail-on-evidence LEVEL` | only fail (per `--fail-on`) on findings at or above this evidence level (`matched`, `llm-detected`, `llm-verified`, `data-flow`, `solver-verified`, `exploit-confirmed`); ANDed with `--fail-on`, so `--fail-on-evidence solver-verified` breaks the build only on findings Frame proved |
| `--min-severity critical\|high\|medium\|low\|info` | report only at or above this (default: config, else low) |
| `--disable RULE` | drop a CWE id or finding type (repeatable) |
| `--config FILE` / `--no-config` | use this config file / ignore config files |
| `--no-suppress` | ignore `frame: ignore` comments |
| `--no-default-excludes` | also scan `.git`, `node_modules`, `.venv` and similar |
| `--changed [REF]` | only files that differ from REF (default HEAD), widened to the files that import them |
| `--files PATH...` | only these files (combines with `--changed`) |
| `--baseline FILE` / `--write-baseline FILE` | report only findings not in the baseline / record this run's findings |
| `--root DIR` | the root that finding paths and fingerprints are relative to |
| `--no-cross-file` | analyse each file alone |
| `--cross-file-limit N` | most files one cross-file analysis spans (default 2000) |
| `--pack PATH` / `--no-packs` | load an extra pack (repeatable) / skip the built-in packs |
| `--verify-secrets` | ask each found credential's provider whether it still works ([secrets.md](secrets.md#verifying-with-the-provider); network, off by default) |
| `--confirm-proofs` | compile and run each directly constructible C integer-overflow or out-of-bounds finding under AddressSanitizer+UndefinedBehaviorSanitizer; an observed fault raises it to the `exploit-confirmed` evidence level (runs compiled code, opt-in, offline, no model; [ai.md](ai.md#proof-carrying-findings---confirm-proofs)) |
| `--proof-tests-dir DIR` | with `--confirm-proofs`: write each confirmed finding's reproduction test (a self-contained C file) to DIR as a regression guard |
| `--reproduce-proofs` | implies `--confirm-proofs`; for a C finding whose triggering value is not a bare parameter (read from stdin/argv), drive a seeded agent to write a reproduction program and raise it to `exploit-confirmed` on an observed fault (uses the `[llm]` endpoint, runs a model, opt-in; [ai.md](ai.md#proof-carrying-findings---confirm-proofs)) |
| `--sca` | add vulnerable dependencies ([dependencies.md](dependencies.md)) |
| `--iac` | add infrastructure findings: Kubernetes manifests, Dockerfiles, Terraform, CloudFormation (directory targets; [iac.md](iac.md)) |
| `--vex openvex\|cyclonedx`, `--vex-out FILE` | with `--sca`: also write a VEX document |
| `--no-verify` | skip solver verification (faster, more false positives) |
| `--timeout MS` | solver timeout per check (default 5000) |
| `-v`, `--verbose` | more detail |
| `--ai` | LLM detection and triage ([ai.md](ai.md)) |
| `--llm-detect` / `--llm-triage` | only one of the two |
| `--model MODEL` | the model for this run (wins over `FRAME_LLM_MODEL` and `llm.model`) |
| `--repo-scale` | one LLM session for the whole repository (with `--ai` or `--llm-detect`) |
| `--hunt-authz` | agentic hunt for authorization and business-logic flaws, with a verdict on every handler (a finding, safe, or unresolved); adds a `hunt` section to the output ([ai.md](ai.md#hunting-authorization-flaws---hunt-authz)) |

### `frame verify <findings.json>`

Re-scans the files behind earlier findings: `fixed`, `file_removed`, `present`, `suppressed`, `uncertain` or `unverifiable`. Exit 0 only when every finding is fixed or its file removed.

| Flag | |
|---|---|
| `--id FINGERPRINT` | only this finding (repeatable) |
| `-f`, `--format text\|json` | output format |
| `--timeout MS` | solver timeout |

### `frame deps [dir]`

The dependency graph, vulnerabilities, upgrades, licences, SBOM and VEX; a walkthrough is in [dependencies.md](dependencies.md).

| Flag | |
|---|---|
| `-f`, `--format text\|json` | output format |
| `-o`, `--output FILE` | write to a file instead of stdout |
| `--exclude DIR` | skip a directory name or relative path (repeatable) |
| `--resolve` | run Maven, Gradle and pip to resolve projects without a lockfile (runs the build configuration) |
| `--image REF` | also read a container image's OS packages, the PyPI, npm and Maven packages installed in it, and the modules compiled into its Go and Rust binaries (a reference Docker has or can pull, or a `docker save` `.tar`; repeatable) |
| `--rootfs DIR` | the same for an unpacked root filesystem (repeatable) |
| `--vulns` | match against the cached advisories |
| `--no-reachability` | with `--vulns`: do not read the source for imports and calls |
| `--backport` | with `--vulns`: apply each npm advisory's upstream fix commit to the installed version as a `patch-package` patch (shown as a diff; `--apply` writes it and the `postinstall`); fetches the OSV record and the commits ([dependencies.md](dependencies.md#backported-fixes)) |
| `--govulncheck FILE` | with `--vulns`: a `govulncheck -json ./...` report (source mode) whose call-graph reachability replaces Frame's for the Go advisories it decided (repeatable; [dependencies.md](dependencies.md#is-it-reachable)) |
| `--fail-on critical\|high\|medium\|low\|any\|none` | with `--vulns`: exit 1 at or above this severity; exit 2 if advisories are missing or one at or above it could not be decided (an untagged submodule commit; default none) |
| `--plan` | with `--vulns`: the smallest safe upgrades and the edits, as a diff |
| `--registry` | with `--licenses` / `--sbom`: fill unknown licences from the registries (npm, PyPI, RubyGems, crates.io, NuGet, Maven Central); with `--vulns`: also list the project's declared ranges that admit vulnerable releases; with `--plan`: fetch release metadata (npm, PyPI, crates.io, NuGet) and solve the upgrades of all packages together with Z3, so upgrading a package in between replaces an override, and for Go read each fix's `go` directive from the module proxy to name fixes that need a newer Go (network; cached) |
| `--mitigate` | with `--vulns`: write each complete configuration mitigation not yet applied (a properties file, else the Dockerfile), as a diff until `--apply` |
| `--apply` | write what `--plan` and/or `--mitigate` propose, then re-read and report what is fixed and what remains |
| `--relock` | with `--apply`: regenerate lockfiles with the package manager (runs it) |
| `--verify COMMAND` | with `--apply`: run your build or tests before and after; roll back an upgrade that breaks them |
| `--adapt` | with `--verify`: when the upgrade breaks the command, let a model adapt the code that uses the upgraded packages; kept only if the command passes and a re-scan finds nothing new (needs a model, [ai.md](ai.md#setting-it-up)) |
| `--licenses` | check licences against `[licenses]` (exit 1 on a violation) |
| `--sbom cyclonedx\|spdx` | print a CycloneDX 1.6 or SPDX 2.3 SBOM |
| `--vex openvex\|cyclonedx` | print VEX statements (implies `--vulns`; exit 1 on a conflict with `.frame/vex.toml`) |
| `--product ID` | with `--sbom`/`--vex`: the product identifier (default `pkg:generic/<directory>`) |
| `--dev-not-shipped` | with `--vex`: state dev-only dependencies `not_affected` |

### `frame fix <source>`

Patches findings and re-scans to confirm each patch (needs a model, [ai.md](ai.md)).

| Flag | |
|---|---|
| `--guidance FILE` | findings JSON to fix (`-` for stdin), from `frame scan -f json` |
| `--deps` | mitigate vulnerable dependencies in code, the version unchanged ([dependencies.md](dependencies.md#fixing-in-code-when-you-cannot-upgrade)) |
| `--include-called` | with `--deps`: also call sites with no attacker data flow |
| `--diff` / `--in-place` | print a diff (the default) / write the patches |
| `--no-verify` | do not re-scan the patched code |
| `--model MODEL` | the model for this run (wins over `FRAME_LLM_MODEL` and `llm.model`) |
| `--format text\|json` | output format |

### `frame exploit --target URL`

Drives an agent against a live target you are authorized to test ([ai.md](ai.md)): `--goal`, `--guidance FILE`, `--success-check COMMAND`, `--max-steps N` (default `llm.exploit_max_steps`, 250), `--exec-timeout S` (default 120), `--model`, `--format text|json`, `--trace-out FILE`.

`frame exploit --deps` needs no live target: it turns reachability into runnable tests. Give it a `frame scan --sca -f json` findings file (`--guidance FILE`) and the project (`--root DIR`); for each reachable finding -- attacker data reaching a vulnerable dependency call or a code injection sink (SQLi, command injection, XSS, path traversal, SSRF) -- a seeded agent drives the project to that call and a harness spy confirms the marker reaches it through the project. `--out-dir DIR` writes each confirmed reproduction as a pytest. `--check-fixed DIR` re-runs the confirmed driver against a fixed copy of the project and verifies the reproduction no longer reaches the sink (the fix-loop: a proof of the vulnerability becomes a proof of the fix) ([ai.md](ai.md#proof-carrying-findings---confirm-proofs)).

### `frame iac [target]`

Infrastructure files (Kubernetes manifests, Dockerfiles, Terraform, CloudFormation) under a directory, or one file, against the policy packs ([iac.md](iac.md)). Findings at or above `--fail-on` exit 1. A violation that depends on values the files do not give is listed as undecided, never as a finding.

| Flag | |
|---|---|
| `-f`, `--format text\|json\|sarif` | output format |
| `-o`, `--output FILE` | write to a file instead of stdout |
| `--pack PATH` / `--no-packs` | load an extra policy pack (repeatable) / skip the built-in packs |
| `--min-severity critical\|high\|medium\|low\|info` | report only at or above this (default: config, else low) |
| `--fail-on critical\|high\|medium\|low\|any\|none` | exit 1 at or above this severity (default: config, else high) |
| `--render-helm` | render each Helm chart with `helm template` (default values, nothing fetched) and check the output; runs Helm |
| `--no-config` | ignore `.frame.toml` / `[tool.frame]` |

### `frame history [repo]`

Provider credentials anywhere in the git history: every line each commit added (all refs; `--range REV` for one branch or range, e.g. `origin/main..HEAD`), each credential reported once at the commit that first added it, with whether the current tree still has it. Values are never printed (the first four characters, the length, and a SHA-256 fingerprint in `-f json`). Comments count, unlike in `frame scan`: a real key in a comment is as leaked as one in a string. Exit 1 when any is found, 2 when the directory is not a git repository. `-f text|json`. `--verify` asks each credential's provider whether it still works ([secrets.md](secrets.md#verifying-with-the-provider)).

### `frame diff OLD.json NEW.json`

Pairs two `frame scan -f json` runs by fingerprint (exact, then loose by nearest line) and reports which findings a change introduced, fixed, or left unchanged, so a reviewer sees "this PR introduces 2, fixes 1" rather than diffing a baseline file by hand. Exit 1 when any finding was introduced, else 0. `-f text|json`.

### `frame inventory [dir]`

Languages, framework packs, manifests and lockfiles, IaC, containers, LLM SDKs and MCP servers, without analysing anything. Dependency files are the ones `frame deps` reads, under the same ecosystem names (OSV's: `PyPI`, `npm`, `Maven`...), each with `read: true`; a declaration `frame deps` does not read on its own (`setup.py`, `Pipfile`, `go.sum`) is listed with `read: false`. Each MCP tool is listed with its capabilities: the kinds of sink its handler and the file's functions it calls reach, whatever the arguments (`ai.mcp_tools` in JSON), so a tool that can run a shell or write files is visible before anyone reads its code: `-f text|json`, `--no-sources` (skip reading source files), `--file-limit N` (default 5000).

### `frame packs list | check`

`list` shows the packs a scan would load (`--language LANG`, `--project DIR`); `check PATH...` validates pack files.

### `frame kb`

| Subcommand | |
|---|---|
| `pull` | download into the cache: `--project DIR`, `--languages a,b`, `--all`, `--revision R`, `--source S`, `--lock` (write `.frame/kb.lock`), `--advisories` (advisories instead of packs), `--ecosystems a,b` (with `--advisories`: these instead of the project's, e.g. `Debian:12` for an image) |
| `status` | which revisions a scan of the project uses: `--project DIR`, `-f text|json` |
| `build PACKS_DIR OUT` | lay out a packs revision for a mirror: `--revision R`, `--specs DIR` (spec tables to include) |
| `build-advisories INPUTS... OUT` | for dataset maintainers: an advisories revision from OSV exports (and SUSE's patch OVAL files, `suse.linux.enterprise.15-spN-patch.xml.gz`, for SLES with `--ecosystems SUSE`): `--revision R`, `--ecosystems a,b`, `--functions DIR` (vulnerable functions), `--mitigations DIR` (curated configuration mitigations) |
| `mine-functions INPUTS...` | for dataset maintainers: vulnerable functions from advisories' fix commits: `--out DIR`, `--existing DIR` (curated entries, which win), `--ecosystems a,b`, `--limit N`, `--cache DIR`, `--recorded DIR` (commits on disk instead of GitHub), `--since TIMESTAMP` (resume after the last run's `resume_after`), `--only IDS` (only these advisories: a comma list, a file of ids, or a `needs-curation.json`); uses `GITHUB_TOKEN` when set |

### `frame solve`, `check`, `parse`, `repl`

The separation logic engine; flags in [engine.md](engine.md).

`frame <command> --help` prints the same flags.

## Environment variables

The environment holds what belongs to the machine running Frame. Each variable wins over its key in the config file.

| Variable | Key | |
|---|---|---|
| `FRAME_LLM_BASE_URL`, `FRAME_LLM_MODEL` | `llm.base_url`, `llm.model` | the model for `--ai`, `fix`, `exploit` and the hunt ([ai.md](ai.md)) |
| `FRAME_LLM_API_KEY` | (`llm.api_key_env` names another) | the endpoint's key |
| `FRAME_KB` | `kb.enabled` | `off` uses built-in packs only and no advisories |
| `FRAME_KB_SOURCE`, `FRAME_KB_CACHE` | `kb.source`, `kb.cache` | where packs come from and where the knowledge base is cached |
| `FRAME_ADVISORIES_SOURCE` | `sca.advisories_source` | where advisories come from |
| `FRAME_REGISTRY_CACHE` | `sca.registry_cache` | registry metadata for `--plan --registry` |
| `FRAME_BACKPORT_CACHE` | `sca.backport_cache` | OSV records and fix commits for `--backport` |

These variables are no longer read. A command warns about any that is still set, naming its replacement:

| Retired variable | Use instead |
|---|---|
| `FRAME_LLM_TEMPERATURE`, `FRAME_LLM_MAX_TOKENS`, `FRAME_LLM_TIMEOUT`, `FRAME_LLM_TOTAL_TIMEOUT`, `FRAME_LLM_JSON_MODE` | `llm.temperature`, `llm.max_tokens`, `llm.timeout`, `llm.total_timeout`, `llm.json_mode` |
| `FRAME_LLM_STREAM`, `FRAME_LLM_STREAM_STALL`, `FRAME_LLM_OUTAGE_WAIT`, `FRAME_LLM_CACHE` | `llm.stream`, `llm.stream_stall_timeout`, `llm.outage_wait`, `llm.cache_path` |
| `FRAME_LLM_CONTEXT_LINES`, `FRAME_LLM_MAX_CONTEXT_CHARS`, `FRAME_LLM_DROP_THRESHOLD`, `FRAME_LLM_TRIAGE_AGENTIC`, `FRAME_LLM_MAX_TOOL_STEPS` | `llm.context_lines`, `llm.max_context_chars`, `llm.drop_threshold`, `llm.triage_agentic`, `llm.max_tool_steps` |
| `FRAME_LLM_AGENT_MAX_TOKENS`, `FRAME_LLM_AGENT_CONTEXT_BUDGET_CHARS`, `FRAME_LLM_AGENT_RETRIES` | `llm.agent_max_tokens`, `llm.agent_context_budget_chars`, `llm.agent_retries` |
| `FRAME_LLM_EXPLOIT_MAX_STEPS`, `FRAME_LLM_HUNT_MAX_STEPS`, `FRAME_LLM_TRAJECTORY_DIR` | `llm.exploit_max_steps`, `llm.hunt_max_steps`, `hunt.trajectory_dir` |
| `FRAME_LLM_REPO_ROOT` | `frame scan --root` (a directory scan uses the scanned directory) |
| `FRAME_GENERATED_LINE_THRESHOLD`, `FRAME_AGGRESSIVE_DETECTORS` | `engine.generated_line_threshold`, `engine.aggressive_detectors` |

## Python API

```python
from frame.sil import FrameScanner

result = FrameScanner(language="python").scan_file("app.py")
for vuln in result.vulnerabilities:
    print(f"{vuln.cwe_id}: {vuln.description}")

results = FrameScanner(packs=["security/acme.toml"]).scan_directory("src/", pattern=None)
```
