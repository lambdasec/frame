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

## Choosing a model

Any OpenAI-compatible endpoint works, so the same commands run on a laptop or against a hosted frontier model.

### Frontier open models, hosted

Open frontier models such as GLM are strong at security work: reading unfamiliar code, tracing flows and writing working exploits. Our benchmarks run on GLM. With [mlx-optiq cloud](https://cloud.mlx-optiq.com), create an API key and point Frame at it:

```bash
export FRAME_LLM_BASE_URL=https://cloud.mlx-optiq.com/api/v1
export FRAME_LLM_API_KEY=sk-optiq-cloud-...              # from the dashboard's API keys page
export FRAME_LLM_MODEL=glm-5.3-flash                     # or glm-5.3 for the hardest repos

frame scan src/ --ai
frame fix app.py --guidance findings.json --diff
```

`curl https://cloud.mlx-optiq.com/api/v1/models` lists the available models (also `deepseek-v4.1-flash` and `minimax-m3.1-flash`), each with a context window of about 1M tokens, enough for a whole service.

### Local, on Apple Silicon

To keep code on the machine, serve a quantized model with mlx-optiq:

```bash
pip install mlx-optiq
optiq kv-cache mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit --target-bits 5.0 -o ./kv
optiq serve --model mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit \
  --kv-config ./kv/kv_config.json --port 47317 --mtp    # --mtp: ~1.4x faster decode
```

Then use the local endpoint from the example above (`http://localhost:47317/v1`, empty key).
