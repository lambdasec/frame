# AI applications: prompt injection, model output, MCP tools

Six small apps, each beside a safe twin that does the same job correctly. They live with Frame's framework exemplars, which CI scans on every change:

| App | Vulnerable | Safe twin |
|---|---|---|
| Flask app using Anthropic, OpenAI and LangChain | [python/llm-sdks/vulnerable/app.py](../../benchmarks/exemplars/frameworks/python/llm-sdks/vulnerable/app.py) | [safe/app.py](../../benchmarks/exemplars/frameworks/python/llm-sdks/safe/app.py) |
| Express app using Anthropic and OpenAI | [javascript/llm-sdks/vulnerable/app.js](../../benchmarks/exemplars/frameworks/javascript/llm-sdks/vulnerable/app.js) | [safe/app.js](../../benchmarks/exemplars/frameworks/javascript/llm-sdks/safe/app.js) |
| MCP server (Python, FastMCP) | [python/mcp-servers/vulnerable/server.py](../../benchmarks/exemplars/frameworks/python/mcp-servers/vulnerable/server.py) | [safe/server.py](../../benchmarks/exemplars/frameworks/python/mcp-servers/safe/server.py) |
| MCP server (TypeScript SDK) | [javascript/mcp-servers/vulnerable/server.ts](../../benchmarks/exemplars/frameworks/javascript/mcp-servers/vulnerable/server.ts) | [safe/server.ts](../../benchmarks/exemplars/frameworks/javascript/mcp-servers/safe/server.ts) |
| RAG answerer and MCP client (Python: LangChain, Anthropic, `mcp`) | [python/llm-context/vulnerable/app.py](../../benchmarks/exemplars/frameworks/python/llm-context/vulnerable/app.py) | [safe/app.py](../../benchmarks/exemplars/frameworks/python/llm-context/safe/app.py) |
| RAG answerer and MCP client (JS: LangChain.js, Anthropic, MCP SDK) | [javascript/llm-context/vulnerable/app.mjs](../../benchmarks/exemplars/frameworks/javascript/llm-context/vulnerable/app.mjs) | [safe/app.mjs](../../benchmarks/exemplars/frameworks/javascript/llm-context/safe/app.mjs) |

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
5. [MEDIUM] 🟡 prompt_injection
   Location: python/llm-sdks/vulnerable/app.py:44:46
   Description: Tainted data from 'product' flows to prompt sink
Scanned 1 file: 5 findings (2 critical, 3 medium)

$ frame scan python/llm-sdks/safe --root .
Scanned 1 file: 0 findings (none)
```

- **Line 18:** a request field goes into Claude's `system=`. The system prompt decides what the model may do, so data there can rewrite it (CWE-1427, OWASP LLM01).
- **Line 27:** what GPT returned is run with `shell=True`. A prompt injection in anything the model read can choose that command (OWASP LLM05).
- **Line 34:** a request parameter becomes part of a LangChain `SystemMessage`.
- **Line 36:** the model's reply is passed to `exec`.
- **Line 44:** a request parameter goes into a `{"role": "system", "content": ...}` message, the OpenAI chat format, built in a list before the call. Frame reads a role/content message whose role is the literal `system` or `developer` as the system prompt wherever the list is built; a `user` or `assistant` turn is not a finding, and neither is a role that is not a literal.

The safe twin sends the user's text only as the user turn (how every chat works, and not a finding), runs only commands from a fixed allowlist, and prints the reply instead of executing it. All five findings have category `ai` in JSON and SARIF.

The Node app shows the same flows, including a `{ role: "system", content: ... }` message on line 26:

```console
$ frame scan javascript/llm-sdks/vulnerable --root .
1. [MEDIUM] 🟡 prompt_injection
   Location: javascript/llm-sdks/vulnerable/app.js:26:31
2. [CRITICAL] 🔴 command_injection
   Location: javascript/llm-sdks/vulnerable/app.js:19:2
3. [MEDIUM] 🟡 prompt_injection
   Location: javascript/llm-sdks/vulnerable/app.js:12:8
Scanned 1 file: 3 findings (1 critical, 2 medium)
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

## Retrieved documents and tool results (indirect prompt injection)

An app also feeds its model text nobody in the conversation wrote: documents a vector store returns, an MCP server's tool result. Whoever wrote that text (a web page, a support ticket, a tool server) can put instructions in it:

```console
$ frame scan python/llm-context/vulnerable --root .
1. [MEDIUM] 🟡 prompt_injection
   Location: python/llm-context/vulnerable/app.py:17:4
   Description: Tainted data from '$docs' flows to prompt sink
2. [MEDIUM] 🟡 prompt_injection
   Location: python/llm-context/vulnerable/app.py:26:16
   Description: Tainted data from 'docs' flows to prompt sink
3. [CRITICAL] 🔴 command_injection
   Location: python/llm-context/vulnerable/app.py:34:4
   Description: Tainted data from 'result' flows to command sink
Scanned 1 file: 3 findings (1 critical, 2 medium)

$ frame scan javascript/llm-context/vulnerable --root .
1. [MEDIUM] 🟡 prompt_injection
   Location: javascript/llm-context/vulnerable/app.mjs:14:9
2. [MEDIUM] 🟡 prompt_injection
   Location: javascript/llm-context/vulnerable/app.mjs:25:9
3. [CRITICAL] 🔴 command_injection
   Location: javascript/llm-context/vulnerable/app.mjs:31:2
Scanned 1 file: 3 findings (1 critical, 2 medium)
```

- **Line 17:** what `store.similarity_search(...)` returned goes into Claude's `system=`, so a planted ticket can rewrite the instructions.
- **Line 26:** documents from `retriever.invoke(...)` go into a LangChain `SystemMessage`.
- **Line 34:** an MCP tool's result (`session.call_tool(...)`) is run in a shell.

The safe twins give the documents to the model in the user turn, with a system prompt saying they are data, and pass the tool's answer to `tar` as an argument list: 0 findings. Retrieved content in a user turn is how retrieval works and is not a finding. The `llm-context` packs name the sources: LangChain's vector-store search methods and retrievers (`retriever.invoke` by the conventional name), and an MCP client's `call_tool` / `read_resource` / `get_prompt` (`callTool`, `readResource`, `getPrompt` in JS). Findings from them have category `ai`.

What is covered, and what is not yet: [docs/coverage.md](../../docs/coverage.md#what-it-detects).
