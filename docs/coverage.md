# Coverage: languages, frameworks and vulnerability classes

## Data flow across files

Directory scans follow taint across imports and calls by default.

| | Same file | Across files |
|---|---|---|
| **Python** | functions, methods, returns, callbacks | imports, re-exports, star imports, aliases, factories, injected objects |
| **JavaScript / TypeScript** | functions, closures, classes, callbacks | `require`/`import`, barrels, default exports, tsconfig `paths`, class instances |
| **Java** | helpers, overloads | packages, imports, single-implementation interfaces, supertypes |
| **C#** | calls by declared type, DI-style fields | namespaces, `using`, interfaces, base classes |
| **C / C++** | helper sinks, returned data, buffers filled by a helper | per file |

Resolution is deliberately narrow and never guessed. A helper that sanitises its argument clears the flow; one that only looks like validation (`return x.strip()`) does not.

Frame knows what makes data safe (parameterised queries, `shlex.quote`, `basename`, allow-lists, `isdigit()` and anchored-regex checks, numeric conversion) per branch, so `if x in ALLOWED: pass` followed by the sink is still flagged.

## Frameworks, out of the box

| Language | Frameworks and libraries |
|---|---|
| **Python** | Flask, Django, DRF, FastAPI, Starlette, Tornado, aiohttp, Sanic, Bottle, Falcon, Pyramid, CherryPy, Jinja2/Mako, SQLAlchemy, peewee, pymongo, requests/httpx |
| **JavaScript / TypeScript** | Express, Koa, Fastify, Hapi, Restify, NestJS, Next.js, Sails, Apollo, Socket.IO, AWS Lambda, Electron, React, Angular, Mongoose, Prisma, Knex, TypeORM |
| **Java** | Spring MVC/Boot/WebFlux, JAX-RS (Jersey, RESTEasy, Quarkus), Struts 2, JSF, Servlet/JSP, Vert.x, Spark, Javalin, Micronaut, Play, Hibernate/JPA, MyBatis, jOOQ |
| **C#** | ASP.NET Core MVC and Web API, Minimal APIs, Razor Pages, Blazor, SignalR, Azure Functions, WebForms, WCF/gRPC, EF Core/EF6, Dapper, NHibernate |
| **C / C++** | CGI/FastCGI, POSIX sockets, libmicrohttpd, civetweb/Mongoose, cpp-httplib, Crow, Qt, Boost.Beast, gRPC, libcurl, OpenSSL, libxml2, libarchive, SQLite/libpq/MySQL |
| **AI apps** | OpenAI, Anthropic, LangChain and LlamaIndex SDKs (Python; OpenAI, Anthropic and LangChain in JS/TS), MCP servers (FastMCP, the TypeScript SDK) |

Every pack is proven by a vulnerable app and its safe twin, scanned through the real CLI in the test suite: 80+ apps and 400+ labelled flaws in [`benchmarks/exemplars/frameworks/`](../benchmarks/exemplars/frameworks).

## Teach it your own framework

An in-house web stack needs one TOML file, not a fork:

```toml
# .frame/packs/acme.toml  (picked up automatically; or --pack PATH, or packs = [...] in .frame.toml)
[pack]
name = "acme"
language = "python"
detect = { imports = ["acme"] }          # applies only to files that use it

[[entrypoint]]                           # who receives attacker data
decorator = ["acme.web.route"]
params = "all"

[[source]]
call = ["acme.web.param"]

[[sink]]
call = ["acme.store.query_sql"]
kind = "sql"

[[sink]]                                 # only when shell=True
call = ["acme.proc.launch"]
kind = "command"
when_kwarg = { name = "shell", value = "True" }

[[sanitizer]]
call = ["acme.text.sql_clean"]
kinds = ["sql"]

[[setting]]                              # configuration that switches a protection off
kind = "debug"                           # debug | cookie_secure | cookie_httponly
at = "kwarg"                             # kwarg | assignment | attribute | subscript | property
call = ["acme.web.serve"]
keys = ["trace"]
value = true                             # acme.web.serve(trace=True) is reported
description = "Tracing server enabled"
```

`frame packs check acme.toml` validates it, naming the file and field of any unknown key or kind. A pack refines the built-in knowledge of a call instead of replacing it. `frame packs list` shows the packs a scan would load.

## What it detects

80+ vulnerability classes. The symbolic core proves the ones reachable by taint or memory reasoning; the [AI layer](ai.md) adds authorization and business-logic flaws.

| Injection | Access control | Data exposure and crypto | Memory safety |
|---|---|---|---|
| SQL / NoSQL / ORM (CWE-89, 943) | IDOR / BOLA (CWE-639) | Path traversal (CWE-22) | Buffer overflow (CWE-121/122) |
| XSS (CWE-79) | Authorization bypass (CWE-285) | SSRF (CWE-918) | Use-after-free (CWE-416) |
| Command and code (CWE-78/94) | Mass assignment (CWE-915) | Open redirect (CWE-601) | Double / invalid free (CWE-415) |
| Template (SSTI) | Broken authentication | XXE (CWE-611) | Null dereference |
| LDAP / XPath / XML | Session fixation | Secrets, unsafe deserialization | Integer overflow |
| Header and log | CSRF (CWE-352) | Weak crypto, hashing, random | Format string |

Hardcoded secrets are found two ways. A credential-named variable (`password`, `API_KEY`, `client_secret`) bound to a literal is reported unless the value is plainly not a secret (a field name, a filename, a placeholder). Separately, any string literal containing a provider's credential format is reported whatever holds it: an argument, a dict value, a header. That covers AWS, GitHub, GitLab, Slack, Google, Stripe (live keys), OpenAI, Anthropic, SendGrid, npm, PyPI, Hugging Face, DigitalOcean, Shopify and PEM private keys. The formats are data (`frame/sil/specs/data/secret-formats.toml`, each with the provider's documentation). Literals come from the syntax tree, so a token in a comment is not reported, and the providers' own published example keys are ignored.

A credential removed from the code is still in every clone's history. `frame history` reads every line the git history added, in any file, comments included, and reports each credential once at the commit that added it, saying whether the current tree still has it (rotate it either way). On a test repository it finds every credential gitleaks finds, at the same commit, file and line, and also Hugging Face and Anthropic keys gitleaks 8.21 has no rule for (`tests/test_secret_history.py`).

AI applications (category `ai`; walkthrough with real output in [examples/ai-apps](../examples/ai-apps/README.md)):

| Finding | What it is |
|---|---|
| Prompt injection (CWE-1427, OWASP LLM01) | Untrusted data in a model's system instructions: Anthropic `system=`, OpenAI `instructions=`, LangChain `SystemMessage`. Untrusted data in a user turn is how a chat works and is not reported. |
| Model output reaching a sink (OWASP LLM05) | What a model returns (OpenAI, Anthropic, LangChain, LlamaIndex) can be steered by a prompt injection anywhere in what it read, so it is attacker data at every injection sink: a shell, `exec`, SQL, HTML. It is not treated as confidential, so logging it is not a finding. |
| MCP tools | A tool's arguments are model output, so a shell or SQL sink in a tool handler (`@mcp.tool()`, `server.tool(...)` / `server.registerTool(...)`) is a finding. |

Not covered yet: OpenAI chat requests that put untrusted data in a `{"role": "system"}` message, since a dict inside a list is not yet followed by the Python frontend.

Protection-off switches (Flask `debug=True`, insecure cookie flags, Django `DEBUG`) are reported separately as `hardening`. They are `[[setting]]` entries in packs, so a pack can add its own; only an explicit off switch is reported, never a missing option.

C and C++ memory safety (use-after-free, double free, leaks, null dereference, uninitialised reads, out-of-bounds indexing) is decided structurally by the [separation logic engine](engine.md): ownership and heap state are tracked in separation logic, and the solver decides whether the bad state is reachable.
