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

### [container-image](container-image/README.md): what is inside a Docker image

The package lists of the official `debian:12.0`, `alpine:3.18.0`, `rockylinux:9.4` and `ubi9/ubi:9.4` images, and an application image with pip packages, an npm tree, a jar, and Go and Rust binaries. It shows their known vulnerabilities (OS packages: the same ones OSV's API reports), why Debian's own Python packages are left to Debian's advisories, the fix for each, a CI gate, and an SBOM.
*Runs offline; `--image` on a real image needs Docker.*

### [upgrade-nuget-go](upgrade-nuget-go/README.md): .NET and Go upgrades

A .NET app whose vulnerable MSAL comes through Azure.Identity, and a Go module with old `x/crypto`. NuGet picks the lowest version a range admits, so re-locking fixes nothing; solved with `--registry`, one raised `PackageReference` does it. For Go, the plan names when a fix needs a newer Go than the module declares, and the newest fix the module's own Go can build.
*Runs offline; `--relock` needs the .NET SDK or Go.*

### [vendored-c](vendored-c/README.md): C libraries copied into a repository

A C program with zlib and cJSON copied into `third_party/`, no manifest anywhere. Frame identifies each by the version its own header declares (only when the library's sources are beside it), and a second zlib copy in `vendor/zlib-src/` with no header at all by its files' git blob ids, then matches the 19 known vulnerabilities by release tag.
*Runs offline.*

### [secrets](secrets/README.md): hardcoded credentials

A script writes a small app with credentials where people really leave them: passed to a client, in a request header, as a keyword argument. Frame finds each by its provider's format (GitHub, AWS, Stripe, OpenAI...), and ignores documented example keys and comments. A fixture password in a pytest file is tagged as test code (known from its imports, not its name) and reported as low. With `--history`, a key deleted from the code is still found in the git history.
*Runs offline.*

### [java-allocation](java-allocation/README.md): sizes a peer chose

Three Apache Kafka methods (CVE-2026-114349, CVE-2026-111551), reduced from the commits before and after their fixes: a length or count read off the wire sizes a buffer or a list with nothing bounding it, so a tiny message makes the JVM allocate gigabytes. Frame finds all three before the fixes and nothing after; the record reader's size comes from Kafka's own `ByteUtils`, which the `kafka-protocol` pack teaches.
*Runs offline.*

### [ai-apps](ai-apps/README.md): LLM apps and MCP servers

Apps using OpenAI, Anthropic, LangChain and MCP, in Python and TypeScript, each beside a safe twin. Shows untrusted input reaching a model's system prompt (prompt injection), model output run as a shell command or code, and MCP tool arguments reaching a shell or SQL.
*Runs offline.*

## More

- One vulnerable app and its safe twin for every supported framework: [benchmarks/exemplars/frameworks](../benchmarks/exemplars/frameworks). These measure Frame (every finding is labelled) rather than walk you through a feature.
- The quickstart's three-file Flask app, where the vulnerability spans files: [benchmarks/exemplars/quickstart](../benchmarks/exemplars/quickstart).
- Every command and option: [docs/usage.md](../docs/usage.md); dependencies in depth: [docs/dependencies.md](../docs/dependencies.md).

To add an example: make the folder with its README, record its offline data with `python examples/record_offline.py examples/<name>` (after `frame kb pull --advisories`), and add a test to `tests/test_examples.py`.
