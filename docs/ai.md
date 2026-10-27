# The AI layer: detect, triage, exploit, fix

Structural analysis cannot reach everything: unknown frameworks, context-dependent flows, business logic. `--ai` adds an LLM layer, and the symbolic core grounds it at every stage. Symbolic and LLM findings are tiered separately (`llm_detect`, `llm_verified`) and never merged.

<p align="center">
  <img src="../assets/how-it-works.svg" alt="Frame pipeline: source code flows through DETECT, TRIAGE, EXPLOIT, and FIX" width="620">
</p>

- **Detect**: the model explores the repo with file and search tools and traces flows across files. A finding grounded in a sink Frame recognises is promoted to `llm_verified`. This also covers languages with no symbolic frontend (PHP, Ruby, Go).
- **Triage**: drops confident false positives, keeping a finding unless it finds the mitigating control.
- **Exploit**: an agent builds and runs a proof of concept against a live, authorized target, and stops only on observable success (`--success-check '<cmd>'` for an external oracle).
- **Fix**: generates a patch, re-scans, and confirms the bug is gone with no regressions.

```bash
export FRAME_LLM_BASE_URL=http://localhost:47317/v1     # any OpenAI-compatible endpoint
export FRAME_LLM_API_KEY=                                # empty for local servers
export FRAME_LLM_MODEL=mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit
export FRAME_LLM_REPO_ROOT=/path/to/repo                 # enables agentic cross-file tools

frame scan src/ --ai                                     # symbolic + LLM detection + triage
frame scan ./repo --ai -f json | \
  frame exploit --target http://app:8080 --guidance - --goal 'read /etc/secret'
frame fix app.py --guidance findings.json --diff         # patch, re-scan, confirm
```

On the [Endor Labs corpus](../benchmarks/endor_corpus/README.md) the full mode reaches 0.67 recall at 0.51 precision (Semgrep: 0.52 / 0.40); the LLM layer recovers about 65 vulnerabilities in Java, JS/TS and C# that both the symbolic engine and Semgrep miss.

## Serving a local model on Apple Silicon

```bash
pip install mlx-optiq
optiq kv-cache mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit --target-bits 5.0 -o ./kv
optiq serve --model mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit \
  --kv-config ./kv/kv_config.json --port 47317 --mtp    # --mtp: ~1.4x faster decode
```

Hosted open models (our benchmarks also use GLM-5.2) work through the same variables.
