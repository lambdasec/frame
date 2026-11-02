# LLM and MCP application security

Frame treats a model's output and the data an app feeds its model as taint, with source and sink kinds for the AI-specific flaws, so a prompt injection or an unsafe MCP tool is found by the same engine that finds SQL injection. These are the `ai` category and map to the [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/). This is detection in apps that *use* a model; the model Frame may use itself is the [AI layer](ai.md).

| Finding | What it is |
|---|---|
| **Prompt injection** (CWE-1427, LLM01) | Untrusted data in a model's system instructions: Anthropic `system=`, OpenAI `instructions=`, LangChain `SystemMessage`, and a role/content chat message whose role is `system` or `developer` (`{"role": "system", "content": ...}`, wherever the messages list is built; Python and JS/TS). Untrusted data in a user turn is how a chat works and is not reported. |
| **Model output reaching a sink** (LLM05) | What a model returns (OpenAI, Anthropic, LangChain, LlamaIndex) can be steered by an injection anywhere in what it read, so it is attacker data at every injection sink: a shell, `exec`, SQL, HTML. It is not treated as confidential, so logging it is not a finding. |
| **MCP tools** | A tool's arguments are model output, so a shell or SQL sink in a tool handler (`@mcp.tool()`, `server.tool(...)` / `server.registerTool(...)`) is a finding. |
| **Indirect prompt injection** (CWE-1427, LLM01) | Text the app feeds its model from outside: documents a LangChain vector store or retriever returns (Python and JS), and an MCP client's tool results, resources and prompts. In the system instructions it is prompt injection; at a shell, SQL or `exec` it is attacker data like any other. In a user turn it is how retrieval works and is not reported. |
| **MCP tool metadata** (CWE-1427) | What a server tells the model about its tools (names, descriptions, parameter descriptions; FastMCP docstrings, low-level `Tool(...)`, `server.tool` / `registerTool` / `addTool` in JS/TS). Hidden characters (Unicode tag characters, decoded in the finding; bidirectional controls; zero-width spaces and joiners) are `mcp_hidden_instructions`: the model reads what the person approving the tool cannot see. A description computed at run time is `mcp_dynamic_tool_metadata`: the server can say something other than what was approved. A literal, literals joined, or a module constant is fixed. The wording itself is not judged. |

Supported SDKs and servers: the OpenAI, Anthropic, LangChain and LlamaIndex SDKs (Python; OpenAI, Anthropic and LangChain in JS/TS), MCP servers (FastMCP, the TypeScript SDK), LangChain vector stores and retrievers, and MCP clients. They are [framework packs](coverage.md#teach-it-your-own-framework), so a new SDK is one TOML file.

`frame inventory` lists each MCP tool with its capabilities: the kinds of sink its handler and the file's functions it calls reach, whatever the arguments, so a tool that can run a shell or write files is visible before anyone reads its code.

A walkthrough with real output is in [examples/ai-apps](../examples/ai-apps/README.md).
