# Security policy

Frame is a security tool, and we treat vulnerabilities in it seriously. This page covers how to report one, which versions get fixes, and what Frame runs and sends on your machine, so you can judge its risk before you put it in CI.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Report it privately through GitHub: on the repository's **Security** tab choose **Report a vulnerability**, or go straight to [the private advisory form](https://github.com/lambdasec/frame/security/advisories/new). Only the maintainers can see the report.

Include what you can of:

- the Frame version (`frame --version`) and how it was installed (PyPI, the GitHub Action, the pre-commit hook, the MCP server);
- the command or API call, and the input that triggers the problem (a minimal file or repository is ideal);
- what an attacker gains, and any preconditions.

We will acknowledge the report, keep you informed while we investigate and fix it, and credit you in the advisory unless you prefer otherwise. Please give us a reasonable time to release a fix before disclosing it publicly.

## Supported versions

Fixes are released for the latest minor version. Upgrade with `pip install -U "frame-security[scan]"`.

| Version | Supported |
|---|---|
| 1.1.x | yes |
| < 1.1 | no |

## What is in scope

A vulnerability in Frame itself or in what it distributes:

- the `frame-security` package and the `frame` command;
- the GitHub Action ([`lambdasec/frame-action`](https://github.com/lambdasec/frame-action)), the pre-commit hook and the [MCP server](https://github.com/lambdasec/frame-mcp);
- the published datasets, [`lambdasec/frame-kb`](https://huggingface.co/datasets/lambdasec/frame-kb) and [`lambdasec/frame-advisories`](https://huggingface.co/datasets/lambdasec/frame-advisories).

Examples: scanning a malicious repository makes Frame execute code or write outside its output paths, a crafted lockfile or manifest crashes or hangs a scan, a dataset revision that fails its checksum is accepted anyway, or a credential is sent anywhere other than its provider's verification URL.

Not in scope: a vulnerability Frame reports (or misses) in **your** code. A false positive or a missed vulnerability is a bug in the analysis, and we want to hear about it through the [issue forms](https://github.com/lambdasec/frame/issues/new/choose).

## What Frame runs and sends

By default, `frame scan`, `frame deps`, `frame iac`, `frame inventory`, `frame verify` and `frame diff` read files and nothing else:

- **No project code is executed.** Source is parsed with tree-sitter; lockfiles, manifests and infrastructure files are read as data.
- **Nothing is fetched during a scan.** Packs and advisories come from the local cache filled by `frame kb pull`, verified against the SHA-256 checksums in the dataset manifest. The datasets hold only TOML and JSON, never code.
- **No telemetry.** Frame does not report usage anywhere.

Each of the following is opt-in, and runs code or reaches the network only when you ask for it:

| Option | What it does |
|---|---|
| `frame kb pull` | downloads pack and advisory datasets from the configured source |
| `frame deps --resolve` | runs the project's build tools (`mvn`, Gradle, `pip install --dry-run`), which execute the project's build code |
| `frame deps --relock`, `--verify COMMAND`, `--adapt` | run the package manager, and your command before and after an upgrade |
| `frame deps --registry`, `--backport` | fetch registry metadata, and fix commits from GitHub |
| `frame scan --render-helm` | runs `helm template` |
| `frame scan --verify-secrets`, `frame history --verify` | send each found credential to its own provider's verification URL, and nowhere else |
| `frame scan --confirm-proofs` | compiles and runs C harnesses built from your code under sanitizers |
| `frame scan --ai`, `--hunt-authz`, `--reproduce-proofs`, `frame fix`, `frame exploit` | send code to the model endpoint you configure (`[llm]`), which can be a local model; `--reproduce-proofs` and `frame exploit --deps` also run your code to confirm a reproduction, and `frame exploit --target` runs commands against a target you are authorized to test |

Run the opt-in options that execute code only on repositories you trust, or in a sandbox.
