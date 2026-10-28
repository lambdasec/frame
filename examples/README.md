# Examples

Each folder is a small project that shows one part of Frame at work. Its README has the commands to run and what they print. Every example runs offline from data recorded beside it, except where noted below.

```bash
pip install "frame-security[scan]"
cd examples/sca-express        # pick one; its README takes it from there
```

`tests/test_examples.py` reruns each README's commands on every change and fails if the output no longer matches, so what you read is what you get.

## The examples

### [sca-express](sca-express/README.md): dependencies, start to finish

An Express app with a vulnerable lodash and an old Express. It shows the dependency graph, the 37 known vulnerabilities, and that the code calls the vulnerable `lodash.template`. The source scan then proves request data reaches it. Planned one package at a time, the fix needs overrides; solved together with Z3, it needs none. Also: licences, an SBOM and VEX.
*Runs offline.*

### [java-mitigation](java-mitigation/README.md): settings that stop a vulnerability

A Maven service using fastjson and Log4j. Frame finds the Log4j mitigation already set in the Dockerfile, and says why it is only partial. It notices fastjson's complete mitigation is missing, and `--mitigate` writes it and confirms it took effect.
*Runs offline.*

### [adapt-werkzeug](adapt-werkzeug/README.md): an upgrade that breaks your code

A Flask-style helper on Werkzeug 2. The fix is Werkzeug 3, which removed two functions the code uses. `--verify` runs the tests and rolls the upgrade back; `--adapt` lets a model rewrite the code, and the result is kept only because the tests pass and a re-scan finds nothing new.
*The plan runs offline; the rollback needs pip, and `--adapt` needs a model (`FRAME_LLM_*`).*

### [container-image](container-image/README.md): OS packages in a Docker image

The package lists of the official `debian:12.0` and `alpine:3.18.0` images. It shows their known vulnerabilities (the same ones OSV's API reports), the version that fixes each, a CI gate, and an SBOM.
*Runs offline; `--image` on a real image needs Docker.*

### [secrets](secrets/README.md): hardcoded credentials

A script writes a small app with credentials where people really leave them: passed to a client, in a request header, as a keyword argument. Frame finds each by its provider's format (GitHub, AWS, Stripe, OpenAI...), and ignores documented example keys and comments.
*Runs offline.*

### [ai-apps](ai-apps/README.md): LLM apps and MCP servers

Apps using OpenAI, Anthropic, LangChain and MCP, in Python and TypeScript, each beside a safe twin. Shows untrusted input reaching a model's system prompt (prompt injection), model output run as a shell command or code, and MCP tool arguments reaching a shell or SQL.
*Runs offline.*

## More

- One vulnerable app and its safe twin for every supported framework: [benchmarks/exemplars/frameworks](../benchmarks/exemplars/frameworks). These measure Frame (every finding is labelled) rather than walk you through a feature.
- The quickstart's three-file Flask app, where the vulnerability spans files: [benchmarks/exemplars/quickstart](../benchmarks/exemplars/quickstart).
- Every command and option: [docs/usage.md](../docs/usage.md); dependencies in depth: [docs/dependencies.md](../docs/dependencies.md).

To add an example: make the folder with its README, record its offline data with `python examples/record_offline.py examples/<name>` (after `frame kb pull --advisories`), and add a test to `tests/test_examples.py`.
