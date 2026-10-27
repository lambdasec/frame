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
    rev: main                     # or a commit SHA
    hooks:
      - id: frame
        # args: [--baseline, .frame-baseline.json]
```

The hook scans the staged Python, JavaScript/TypeScript, Java, C# and C/C++ files, widened to the files that import them, and blocks the commit on findings at or above `high` (or `fail_on` from `.frame.toml`). Coding agents get the same check by running `frame scan . --files <edited files>` after each edit.

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

## Commands

| Command | What it does |
|---------|--------------|
| `frame scan <path>` | Scan for vulnerabilities. `-f text\|json\|sarif`, `-o`, `-l`, `-p`, `--fail-on`, `--min-severity`, `--ai`, `--pack`, `--no-cross-file`, `--root` |
| `frame scan --changed [REF]` / `--files` | Scan only what changed, plus the files that import it |
| `frame scan --baseline F` / `--write-baseline F` | Report only findings not in the baseline; write or update one |
| `frame verify <findings.json>` | Re-scan the files behind earlier findings and report each one's status |
| `frame packs list \| check` | List the packs a scan would load; validate pack files |
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
