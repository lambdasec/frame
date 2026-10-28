# AI applications: prompt injection, model output, MCP tools

Four small apps, each beside a safe twin that does the same job correctly. They live with Frame's framework exemplars, which CI scans on every change:

| App | Vulnerable | Safe twin |
|---|---|---|
| Flask app using Anthropic, OpenAI and LangChain | [python/llm-sdks/vulnerable/app.py](../../benchmarks/exemplars/frameworks/python/llm-sdks/vulnerable/app.py) | [safe/app.py](../../benchmarks/exemplars/frameworks/python/llm-sdks/safe/app.py) |
| Express app using Anthropic and OpenAI | [javascript/llm-sdks/vulnerable/app.js](../../benchmarks/exemplars/frameworks/javascript/llm-sdks/vulnerable/app.js) | [safe/app.js](../../benchmarks/exemplars/frameworks/javascript/llm-sdks/safe/app.js) |
| MCP server (Python, FastMCP) | [python/mcp-servers/vulnerable/server.py](../../benchmarks/exemplars/frameworks/python/mcp-servers/vulnerable/server.py) | [safe/server.py](../../benchmarks/exemplars/frameworks/python/mcp-servers/safe/server.py) |
| MCP server (TypeScript SDK) | [javascript/mcp-servers/vulnerable/server.ts](../../benchmarks/exemplars/frameworks/javascript/mcp-servers/vulnerable/server.ts) | [safe/server.ts](../../benchmarks/exemplars/frameworks/javascript/mcp-servers/safe/server.ts) |

```bash
cd benchmarks/exemplars/frameworks
```

`--root .` below keeps a scan from indexing all of Frame's repository for cross-file imports (a scan of a subdirectory indexes the project root, here the git top level); in your own project you would not need it.

## Untrusted data in a model's instructions, and model output run as code

```console
$ frame scan python/llm-sdks/vulnerable --root .
1. [MEDIUM] 🟡 prompt_injection
   Location: python/llm-sdks/vulnerable/app.py:18:4
   Description: Tainted data from 'persona' flows to prompt sink
2. [CRITICAL] 🔴 command_injection
   Location: python/llm-sdks/vulnerable/app.py:27:4
   Description: Tainted data from 'resp' flows to command sink
3. [MEDIUM] 🟡 prompt_injection
   Location: python/llm-sdks/vulnerable/app.py:34:24
   Description: Tainted data from 'custom' flows to prompt sink
4. [CRITICAL] 🔴 code_injection
   Location: python/llm-sdks/vulnerable/app.py:36:4
   Description: Tainted data from 'reply' flows to eval sink
Scanned 1 file: 4 findings (2 critical, 2 medium)

$ frame scan python/llm-sdks/safe --root .
Scanned 1 file: 0 findings (none)
```

- **Line 18:** a request field goes into Claude's `system=`. The system prompt decides what the model may do, so data there can rewrite it (CWE-1427, OWASP LLM01).
- **Line 27:** what GPT returned is run with `shell=True`. A prompt injection in anything the model read can choose that command (OWASP LLM05).
- **Line 34:** a request parameter becomes part of a LangChain `SystemMessage`.
- **Line 36:** the model's reply is passed to `exec`.

The safe twin sends the user's text only as the user turn (how every chat works, and not a finding), runs only commands from a fixed allowlist, and prints the reply instead of executing it. All four findings have category `ai` in JSON and SARIF.

The Node app shows the same two flows:

```console
$ frame scan javascript/llm-sdks/vulnerable --root .
1. [CRITICAL] 🔴 command_injection
   Location: javascript/llm-sdks/vulnerable/app.js:19:2
2. [MEDIUM] 🟡 prompt_injection
   Location: javascript/llm-sdks/vulnerable/app.js:12:8
Scanned 1 file: 2 findings (1 critical, 1 medium)
```

## MCP tools

A tool's arguments are written by the model, which a prompt injection can steer, so they are attacker data inside the handler:

```console
$ frame scan python/mcp-servers/vulnerable --root .
1. [CRITICAL] 🔴 command_injection
   Location: python/mcp-servers/vulnerable/server.py:12:4
2. [CRITICAL] 🔴 sql_injection
   Location: python/mcp-servers/vulnerable/server.py:17:4
Scanned 1 file: 2 findings (2 critical)

$ frame scan javascript/mcp-servers/vulnerable --root .
1. [CRITICAL] 🔴 command_injection
   Location: javascript/mcp-servers/vulnerable/server.ts:12:43
2. [CRITICAL] 🔴 command_injection
   Location: javascript/mcp-servers/vulnerable/server.ts:8:43
Scanned 1 file: 2 findings (2 critical)
```

The safe servers pass the argument as a separate argument (`["du", "-sh", "--", path]`) and use a parameterised query, and report nothing. In TypeScript, the handler's destructured parameter (`async ({ path }) => ...`) is what carries the model's input.

What is covered, and what is not yet: [docs/coverage.md](../../docs/coverage.md#what-it-detects).
