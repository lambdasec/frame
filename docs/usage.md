# Using Frame: scans, CI, guardrails and configuration

## Scanning

```bash
frame scan app.py                       # one file
frame scan src/                         # every supported language under src/
frame scan src/ -l java                 # one language (or -p "app/**/*.py" for a glob)
frame scan src/ -f sarif -o out.sarif --fail-on high    # SARIF, non-zero exit on high+
frame scan src/ --ai                    # add LLM detection and triage (see ai.md)
```

Text output lists the files with findings and a summary line; `-f json` and `-f sarif` carry the same findings plus stable paths and fingerprints. Exit status: 0 clean, 1 findings at or above `--fail-on`, 2 the scan could not run.

Every finding has a `category` (`taint`, `memory`, `crypto`, `secret`, `access-control`, `hardening`) and an `evidence` level saying how strongly it is proven, weakest first: `matched` (a usage or pattern), `llm-detected`, `llm-verified`, `data-flow` (a source-to-sink path), `solver-verified` (the solver proved the path reachable), `exploit-confirmed`. In SARIF both are result properties.

`frame inventory [dir]` reports what a repository contains without analysing it: languages, the frameworks Frame has packs for, dependency manifests and lockfiles, infrastructure-as-code, Dockerfiles, LLM SDKs and MCP servers (`-f json` for every path).

`frame deps [dir]` reads the dependency graph: every lockfile (`poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` classic and berry, `pnpm-lock.yaml`, `gradle.lockfile`, NuGet `packages.lock.json`, Go `go.mod`, Rust `Cargo.lock`, Swift `Package.resolved`) and each manifest without one (`requirements*.txt`, `pyproject.toml`, `package.json`, `pom.xml`, `*.csproj`, `packages.config`). For each package it reports the exact version, whether it is direct (from the manifest beside the lockfile; left unknown rather than guessed when there is none), whether only development needs it, and its package URL; `-f json` adds the edges between packages. No package manager runs and nothing is fetched.

A `pom.xml` names only direct dependencies, and most Java vulnerabilities arrive transitively, so Frame reads the resolved graph the build tool reports when it finds one: `maven_dep_tree.txt` or `.json` (`mvn dependency:tree -DoutputFile=maven_dep_tree.txt`) and `gradle-dependencies.txt` (`gradle dependencies > gradle-dependencies.txt`). For .NET it reads the restore output (`obj/project.assets.json`) and fills `.csproj` versions from `Directory.Packages.props`.

`frame deps --resolve` produces those graphs itself: it runs `mvn dependency:tree` (or `./mvnw`) once per Maven build, `gradle dependencies` (or `./gradlew`) for every Gradle project, and pip's resolver (`pip install --dry-run --report`, wheels only, nothing installed) for each `requirements*.txt` and lockfile-less `pyproject.toml`. It is opt-in because it runs the project's build configuration and downloads packages; a missing or failing tool is a warning and the manifest is read as before.

`frame deps --vulns` matches every resolved version against known vulnerabilities from OSV, shipped as a dataset (`lambdasec/frame-advisories`, rebuilt daily) that `frame kb pull --advisories` caches for the ecosystems the project uses. Each finding names the advisory (merged across GHSA, PYSEC, CVE and other ids), its severity (the CVSS v3 base score, else the database's rating), the lowest fixed version, whether the package is direct or dev only, and the chain of packages that pulls it in. Matching runs offline.

Each vulnerability is also checked against the project's own code (Python, JavaScript/TypeScript, Java, C#), through the files under the manifest that declared the package: `imported` when the code imports the package, `called` when it calls a function the advisory names as vulnerable (with the file and line). The evidence is positive only: a package your code never imports can still be reached through another library (Log4Shell reached applications that log through SLF4J), so an unused package stays `installed`, never "unreachable". `--no-reachability` skips reading the source.

```bash
frame kb pull --advisories            # once, and whenever you want fresh advisories
frame deps --vulns                    # vulnerable dependencies, with the upgrade that fixes each
frame deps . --resolve --vulns --exclude tests --fail-on high    # a CI gate (exit 1 on high or critical)
```

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
    rev: v1.0.0
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
| `scan` | Scan a path, symbolic or with `ai`, optionally only changed files or against a baseline |
| `write_baseline` | Accept the current findings |
| `verify` | Re-check earlier findings: fixed, present, suppressed, uncertain |
| `fix` | Patch findings and re-scan to confirm (needs `FRAME_LLM_*`) |
| `exploit` | Attack a live target you are authorized to test |
| `packs_list`, `packs_check` | List and validate framework packs |
| `solve` | Check a separation logic entailment |

A `security-review` prompt runs scan, verify and fix in one go. The `FRAME_LLM_*` variables set for the server reach the AI tools ([ai.md](ai.md)). Without MCP, an agent gets the same check by running `frame scan . --files <edited files>` after each edit.

## Suppressions

Silence a reviewed finding inline, optionally by rule:

```python
cursor.execute(query)  # frame: ignore[CWE-89] query is a static string
```

A marker covers its own line or the comment-only line above it. `frame: ignore` alone silences every finding there; `frame: ignore[CWE-89, 79]` only those CWEs (or finding types such as `sql_injection`). Suppressed findings are counted (`summary.suppressed`) and kept in the JSON; `--no-suppress` reports everything.

## Configuration

Project defaults live in `.frame.toml` (or `[tool.frame]` in `pyproject.toml`), found by walking up from the scan target:

```toml
min_severity = "medium"
fail_on = "high"
disable = ["CWE-798", "weak_hash"]   # CWE ids or finding types
exclude = ["vendor", "third_party"]  # added to the default excludes
packs = ["security/acme.toml"]       # extra framework packs
```

Command-line flags win over the file (`--min-severity`, `--fail-on`, `--disable RULE`, `--pack PATH`, `--config PATH`, `--no-config`). Directory scans skip `.git`, `node_modules`, `.venv`, `__pycache__` and similar; `--no-default-excludes` scans them.

## Knowledge base

Framework packs also arrive as data, between Frame releases. `frame kb pull` downloads the packs for the languages a project uses, checks every file against the manifest's SHA-256, and caches them; scans read the cache and never go to the network (with nothing cached they use the packs built into Frame).

```bash
frame kb pull --lock          # this project's languages; pin the revision in .frame/kb.lock
frame kb status               # which revision a scan here would use
FRAME_KB=off frame scan .     # built-in packs only
```

For air-gapped CI, lay out a revision on a connected machine and pull from the directory (or an internal HTTPS mirror):

```bash
frame kb build packs/ kb-2026.10/ --revision 2026.10   # on the connected side
frame kb pull --source /mnt/kb-2026.10 --lock          # in CI
```

`--source` (or `FRAME_KB_SOURCE`) takes `hf:org/dataset`, an `https://` mirror, or a directory. A knowledge base holds data files only (TOML and JSON); nothing in it runs.

## Commands

| Command | What it does |
|---------|--------------|
| `frame scan <path>` | Scan for vulnerabilities. `-f text\|json\|sarif`, `-o`, `-l`, `-p`, `--fail-on`, `--min-severity`, `--ai`, `--pack`, `--no-cross-file`, `--root` |
| `frame scan --changed [REF]` / `--files` | Scan only what changed, plus the files that import it |
| `frame scan --baseline F` / `--write-baseline F` | Report only findings not in the baseline; write or update one |
| `frame verify <findings.json>` | Re-scan the files behind earlier findings and report each one's status |
| `frame packs list \| check` | List the packs a scan would load; validate pack files |
| `frame kb pull \| status \| build` | Download, pin and inspect the knowledge base; lay out a revision for a mirror. `pull --advisories` caches the vulnerability advisories; `build-advisories` lays them out from OSV exports |
| `frame deps [dir]` | The dependency graph from lockfiles, build-tool reports and manifests: versions, direct or transitive, dev only, edges. `--resolve` runs Maven, Gradle and pip; `--vulns` matches the cached advisories |
| `frame inventory [dir]` | Languages, frameworks, dependencies, IaC, containers, LLM SDKs and MCP servers in a repository |
| `frame exploit --target <url>` | Exploit a live, authorized target, primed with `--guidance` ([ai.md](ai.md)) |
| `frame fix <path>` | Fix each finding, then re-scan to confirm (`--in-place` or `--diff`) |
| `frame solve`, `check`, `parse`, `repl` | The separation logic engine ([engine.md](engine.md)) |

Run `frame <command> --help` for every flag.

## Python API

```python
from frame.sil import FrameScanner

result = FrameScanner(language="python").scan_file("app.py")
for vuln in result.vulnerabilities:
    print(f"{vuln.cwe_id}: {vuln.description}")

results = FrameScanner(packs=["security/acme.toml"]).scan_directory("src/", pattern=None)
```
