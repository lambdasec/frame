# Examples

Small projects that show each feature doing its job, with the commands to run and what they print. Each runs offline from data recorded beside it, except where it says it needs a model. `tests/test_examples.py` runs every one on each change and checks that the output still matches the README, so what you read is what you get.

| Example | What it shows |
|---|---|
| [sca-express](sca-express/README.md) | An Express app's dependencies end to end: the graph, known vulnerabilities and whether the code calls the vulnerable function, the source scan finding attacker data reaching it, upgrade plans one package at a time and solved together with Z3, licences, SBOM and VEX |
| [java-mitigation](java-mitigation/README.md) | fastjson and Log4j: a partial mitigation already in the Dockerfile (with its caveat), a complete one missing, and `--mitigate` writing and confirming it |
| [adapt-werkzeug](adapt-werkzeug/README.md) | A major upgrade that breaks the tests: rolled back by `--verify`, then the code adapted by a model with `--adapt` and kept because the tests pass and a re-scan finds nothing new |
| [container-image](container-image/README.md) | The OS packages of a Debian and an Alpine image, their known vulnerabilities (as OSV's API reports them), the versions that fix them, an SBOM with apk's licences |
| [secrets](secrets/README.md) | Hardcoded credentials found by their provider format wherever they sit: client constructors, headers, keyword arguments |
| [ai-apps](ai-apps/README.md) | Prompt injection into system instructions, model output run as a shell command or code, and MCP tool handlers, in Python and TypeScript, each with a safe twin |

More, per framework, with a vulnerable app and its safe twin each: [benchmarks/exemplars/frameworks](../benchmarks/exemplars/frameworks). The quickstart's cross-file Flask app: [benchmarks/exemplars/quickstart](../benchmarks/exemplars/quickstart).

To record the offline data for a new example: `python examples/record_offline.py examples/<name>` (after `frame kb pull --advisories`).
