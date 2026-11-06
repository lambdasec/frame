# Frame documentation

Frame finds vulnerabilities by following attacker data through your code and proving each finding with a solver. One tool covers the code, its dependencies, its secrets, its infrastructure, its containers and its AI calls, and it runs offline. New to Frame? Start with the [quick start](../README.md#quick-start), then [Usage](usage.md).

## Using Frame

| Guide | What it covers |
|---|---|
| [Usage](usage.md) | Scanning, output formats, CI (the GitHub Action, pre-commit hook, baselines, `--changed`, `verify`, `diff`), suppressions, configuration, the knowledge base, every command, flag, setting and environment variable, and the Python API |
| [Coverage](coverage.md) | Cross-file resolution per language, the frameworks supported out of the box, writing a pack for your own stack, and every vulnerability class Frame detects |
| [Dependencies](dependencies.md) | Lockfiles of every supported ecosystem, offline advisories, reachability, upgrade plans Frame applies and verifies, code and configuration mitigations, licences, SBOM, VEX, container images |
| [Secrets](secrets.md) | Credentials by name and by provider key format, git-history scanning, and live verification with each provider |
| [Infrastructure as code](iac.md) | Kubernetes, Dockerfiles, Terraform and CloudFormation, how each is read, how Z3 decides every policy, and writing policies |
| [AI application security](llm-security.md) | Prompt injection, model output as taint, MCP servers and hidden instructions in tool metadata, the OWASP LLM Top 10 |

## Going further

| Guide | What it covers |
|---|---|
| [AI layer](ai.md) | Optional model-assisted detection, triage, the authorization hunt, exploitation, fixing, and proof-carrying reproductions, with any OpenAI-compatible model, including a local one |
| [Separation logic engine](engine.md) | The prover under the scanner: entailment, frame inference, bi-abduction, countermodels, its CLI and Python API, and SL-COMP results |
| [Roadmap](roadmap.md) | What is built and what comes next |

## Elsewhere in the repository

- [Examples](../examples/README.md): runnable walkthroughs with real output.
- [Benchmarks](../benchmarks/README.md): every suite Frame is measured on, with methods and comparisons.
- [Exemplars](../benchmarks/exemplars/README.md): the quickstart app, a vulnerable and safe app per framework, and reproduction cases.
- [Changelog](../CHANGELOG.md), [Contributing](../CONTRIBUTING.md), [Security policy](../SECURITY.md).
