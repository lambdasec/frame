# Configuring Frame

Every Frame setting lives in one file: `.frame.toml` at the project root, or the same keys
under `[tool.frame]` in `pyproject.toml`. A scan uses the nearest one above its target;
`--config PATH` names one, and `--no-config` ignores it.

When a setting can be given more than one way, the first of these wins:

```
command-line flag  >  environment variable  >  config file  >  built-in default
```

The environment holds only what belongs to the machine running Frame:
- the model endpoint: `FRAME_LLM_BASE_URL`, `FRAME_LLM_MODEL`, and the variable holding the key;
- the knowledge base: `FRAME_KB=off`, and its sources and caches.

Everything else goes in the file. The full list of keys is in
[docs/usage.md](../../docs/usage.md#configuration).

## The examples

| File | For |
|------|-----|
| [`minimal.toml`](minimal.toml) | what a scan reports and when CI fails |
| [`ai.toml`](ai.toml) | the AI layer: endpoint, model, the key's variable, streaming, a verdict cache |
| [`dependencies.toml`](dependencies.toml) | a licence policy, and the knowledge base and advisories from a mirror |
| [`hunt.toml`](hunt.toml) | an unattended authorization hunt: outage waits, unit and scout budgets, traces |

Copy one to your project as `.frame.toml` and edit it.

## Trying it

`app.py` passes a request parameter into SQL. With `minimal.toml` as the project's config, the
scan reports it and fails CI (`fail_on = "high"`):

```bash
cp minimal.toml .frame.toml
frame scan app.py
```

```
1. [CRITICAL] 🔴 sql_injection
   Location: app.py:12:4
```

The exit status is 1.

A misspelt key is an error naming the file and the keys it expected, never a silently ignored
setting:

```bash
printf '[hunt]\nconcurency = 8\n' > typo.toml
frame scan app.py --config typo.toml
```

```
Error: typo.toml: [hunt] has unknown key(s) ['concurency']
```

The exit status is 2.

Variables that used to hold agent settings are no longer read. One that is still set is
reported, with the key that replaced it:

```bash
FRAME_LLM_MAX_TOKENS=900 frame scan app.py
```

```
Warning: FRAME_LLM_MAX_TOKENS is no longer read; set llm.max_tokens in .frame.toml (or [tool.frame]) instead
```
