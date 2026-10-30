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
| **Java** | Spring MVC/Boot/WebFlux, JAX-RS (Jersey, RESTEasy, Quarkus), Struts 2, JSF, Servlet/JSP, Vert.x, Spark, Javalin, Micronaut, Play, Hibernate/JPA, MyBatis, jOOQ, Kafka's wire readers |
| **C#** | ASP.NET Core MVC and Web API, Minimal APIs, Razor Pages, Blazor, SignalR, Azure Functions, WebForms, WCF/gRPC, EF Core/EF6, Dapper, NHibernate |
| **C / C++** | CGI/FastCGI, POSIX sockets, libmicrohttpd, civetweb/Mongoose, cpp-httplib, Crow, Qt, Boost.Beast, gRPC, libcurl, OpenSSL, libxml2, libarchive, SQLite/libpq/MySQL |
| **AI apps** | OpenAI, Anthropic, LangChain and LlamaIndex SDKs (Python; OpenAI, Anthropic and LangChain in JS/TS), MCP servers (FastMCP, the TypeScript SDK), LangChain vector stores and retrievers, MCP clients |

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

An `[[entrypoint]]` selects handlers by what the framework itself uses to find them, and every selector given must hold: `decorator` (decorators, annotations, attributes), `class_decorator`, `extends` (base classes, transitively), `class_name` (a naming convention, globbed: ASP.NET's `*Controller`), `method`, `registered_via` (the call a function is passed to), `modifiers` (all of them, as written: `public`), and the exclusions `exclude_method`, `exclude_modifiers`, `exclude_decorator` (`[NonAction]`). The built-in ASP.NET packs state the controller conventions this way, so a public, non-static method of a `*Controller` class is an action and its constructor is not:

```toml
[[entrypoint]]
class_name = ["*Controller"]
method = ["*"]
exclude_method = ["ctor"]
modifiers = ["public"]
exclude_modifiers = ["static"]
exclude_decorator = ["NonAction"]
params = "all"
```

`first_param` selects functions by their first parameter's name (after `self`/`cls`): Django calls a view with the `HttpRequest` first and routes by name in `urls.py`, so the built-in `django` pack takes `first_param = ["request"]`. `params_from` keeps only the parameters from a position on: Graphene calls `resolve_<field>(parent, info, **arguments)`, so its pack takes `params_from = 2`. `param_positions` narrows an entry point to parameters by position (0-based), whatever they are called or however they are destructured: a GraphQL resolver is called as `(parent, args, context, info)`, so the built-in `graphql` pack takes `param_positions = [1]`.

JavaScript packs have two more kinds. `[[registration]]` names the functions an application hands to a framework inside an object, for an entry point's `registered_via` to select:

```toml
[[registration]]                         # Query: { user(parent, args) {...} }, or const resolvers = { User: {...} }
keys = ["Query", "Mutation", "Subscription"]
containers = ["*resolvers"]              # case-insensitive globs on the enclosing object's name
registered_as = "graphql.resolver"
```

`[[fluent]]` names methods that return the object they configure, so a call at the end of a chain is matched as if made on the object itself. With `roots`, a call of a root starts such a chain and calls on it are named `<name>.<method>`. A pack holding `[[fluent]]` entries has no `detect` (the object is often a parameter of a file that imports nothing):

```toml
[[fluent]]                               # res.status(200).send(x) is res.send(x)
methods = ["status", "type", "set"]
content_type = ["type"]                  # res.type("json").send(x) is not an HTML response
content_type_header = ["set"]            # nor is res.set("Content-Type", "image/png").send(x)

[[fluent]]                               # $("#x").find("li").html(v) is $.html(v)
roots = ["$", "jQuery"]
name = "$"
methods = ["find", "filter"]
```

Python packs have `[[deferred_call]]`: a method that runs the function it is called on with the same arguments, so `tasks.convert.delay(path)` is `tasks.convert(path)` for taint (the built-in `celery` pack). It has no `detect`, since the caller imports only the task module. A Python pack's `[pack]` table can say `dict_queries = true` (the built-in `pymongo` pack): in the files it applies to, a dict literal is a query document whose values reach the call it is passed to.

Java packs have five more kinds, each read where the frontend meets the code it describes:

```toml
[[annotated_query]]                      # MyBatis: @Select("... ${col}") splices col into the SQL
annotations = ["Select", "org.apache.ibatis.annotations.*"]
substitution = '\$\{\s*(?P<name>[A-Za-z_]\w*)'
param_name_annotation = "Param"
kind = "sql"

[[required_flag]]                        # a Cookie added without setSecure(true)
types = ["Cookie", "jakarta.servlet.http.Cookie"]
escape = ["addCookie"]
setter = "setSecure"
value = "true"
kind = "insecure_cookie"

[[disabled_protection]]                  # http.csrf().disable(), csrf(c -> c.disable())
configurer = ["csrf"]
disable = ["disable"]
kind = "csrf_disabled"

[[handler_return]]                       # return "redirect:" + url;
prefix = "redirect:"
kind = "redirect"

[[injected_field]]                       # fields a container fills in are not request-bound state
annotations = ["Autowired", "Inject"]
```

A `[[handler_return]]` can instead name the handler's class (`class_decorator`), `return_type` and `exclude_decorator`: a String returned by a Spring `@Controller` handler without `@ResponseBody` is a view name.

C# packs state ASP.NET's cookie off-switches as `[[setting]]` entries with `at = "member"` (a property assignment or object-initializer member on a `receiver` type, switched off by `value` or one of the enum `values`, such as `CookieSecurePolicy.None`), and a `[[same_origin_check]]` names a method that is true exactly for a path on this site (`Url.IsLocalUrl(x)`), so a redirect on its true branch is safe.

A sink rule with `json_for_literals = true` is a response that serialises an object or array literal as JSON (`reply.send({ q })`), so such a value is not an HTML sink.

For C and C++, a pack also says what the project's own functions do with memory and control, so the memory analysis follows an in-house allocator, release function, logging helper or `die()` the way it follows `malloc`, `free`, `strlen` and `exit`:

```toml
[pack]
name = "pool"
language = "c"
detect = { imports = ["pool.h"] }

[[function]]
name = "pool_alloc"
allocates = "heap"                       # heap | stack | mapped | new | new_array (allocates_via = N: through argument N)

[[function]]
name = "pool_release"
frees = "heap"                           # the kind it releases

[[function]]
name = "log_message"
dereferences = [0]                       # argument positions it reads through; -1 for every one

[[function]]
name = "fatal"
noreturn = true
```

A walkthrough: [examples/c-memory-pack](../examples/c-memory-pack/README.md).

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
| | | | Allocation sized by a peer (CWE-770) |

Weak randomness is reported by where the value goes, not by the call: the output of a non-cryptographic generator (`java.util.Random`, Python's `random`, JS `Math.random`, C's `rand()`) is CWE-338 when it becomes a cookie's value, a cryptographic key, IV, nonce or salt (`frame/sil/specs/data/unpredictable.toml`), and nothing when it picks a delay, a sample or a test value. It is also CWE-338 when it is written to something whose name says it must be unpredictable: a variable, field or buffer named as a token, secret, password, nonce, salt, IV, OTP, CSRF token or session id (`reset_token = str(random.randint(...))`, `token[i] = charset[rand() % 62]`), or the result of a function so named (`generate_token()` returning it, or C's `new_session_token(char *out)` writing it into `out`). The words are data (`unpredictable.toml` `[destinations]`); `token_length` and `salt_size` name something about the value, not the value. A digest is as predictable as its input, so `rand()` bytes hashed with SHA-256 are still predictable. A `SecureRandom` declared as `Random` is not weak, and a random number is never attacker data at an injection sink. C# still reports each `System.Random` call (CWE-330).

Hardcoded secrets are found two ways. A credential-named variable (`password`, `API_KEY`, `client_secret`) bound to a literal is reported unless the value is plainly not a secret (a field name, a filename, a placeholder). Separately, any string literal containing a provider's credential format is reported whatever holds it: an argument, a dict value, a header. That covers AWS, GitHub, GitLab, Slack, Google, Stripe (live keys), OpenAI, Anthropic, SendGrid, npm, PyPI, Hugging Face, DigitalOcean, Shopify and PEM private keys. The formats are data (`frame/sil/specs/data/secret-formats.toml`, each with the provider's documentation). Literals come from the syntax tree, so a token in a comment is not reported, and the providers' own published example keys are ignored.

With `--verify-secrets` (and `frame history --verify`), each found credential is checked with its provider: GitHub, Slack, Stripe, OpenAI, Anthropic, SendGrid, Hugging Face, DigitalOcean and npm, through a read-only request to the provider's own API. A live one becomes critical, a rejected one low ([verifying secrets](usage.md#verifying-secrets)).

Test code is told apart by its program, not its file name: a test framework's import (pytest, unittest, JUnit, TestNG, Mockito, jest, vitest, mocha, gtest, Catch2...), C# test attributes, a JUnit or TestNG `@Test`, a module-level pytest `test_*` function that asserts, or callbacks passed to `describe` / `it` / `test`. Every finding there is tagged `context: "test"` and kept. A credential found only by its variable's name drops to low (a test's password is a fixture); one in a provider's format keeps its severity, since it may be real (`frame/sil/test_code.py`, `tests/test_test_code.py`).

A credential removed from the code is still in every clone's history. `frame history` reads every line the git history added, in any file, comments included, and reports each credential once at the commit that added it, saying whether the current tree still has it (rotate it either way). On a test repository it finds every credential gitleaks finds, at the same commit, file and line, and also Hugging Face and Anthropic keys gitleaks 8.21 has no rule for (`tests/test_secret_history.py`).

An allocation sized by attacker data with nothing on the path bounding it is CWE-770 (Python, JS/TS, Java): in Java an array dimension, `ByteBuffer.allocate`, or a capacity constructor (`new ArrayList<>(n)`, `new HashMap<>(n)`, `new StringBuilder(n)`, only when the argument is an integer; with a collection or a String they copy). Besides request data, a number read off a binary stream or buffer is a source of its own (`wire_size`: `DataInputStream`/`DataInput`/`ObjectInputStream`/`RandomAccessFile` `readInt`, `readLong`, `readShort`, ..., `ByteBuffer.getInt`, ...; Kafka's `ByteUtils` through the `kafka-protocol` pack). It is a number, not text, so it is reported only as an allocation size, never at an injection sink. Any branch condition mentioning the size on the path counts as a bound, and so does `Math.min`. Walkthrough on three Apache Kafka bugs (CVE-2026-114349, CVE-2026-111551), before and after their fixes: [examples/java-allocation](../examples/java-allocation/README.md).

Integer overflow in C and C++ (CWE-190) is decided by the solver, not by a pattern: attacker data in an operand of `*`, `+` or a constant `<<`, whose declared integer type is known (`int`, `unsigned`, `short`, `int64_t`...), is reported only when, with what the path has established, the result can exceed the maximum of the type C computes it in. `if (d < 1000)` before `d * 2` clears it; `if (d < 2000000000)` does not. A `char` squared is computed as an `int` and cannot overflow it. A type whose width depends on the platform (`long`, `size_t`) is not guessed, so its arithmetic is not checked. The same question covers the other integer defects: a result that can go below the type's minimum (CWE-191), a value assigned to a narrower type that can lie outside it (CWE-197), and a signed value that can be negative where the callee takes a size, such as `memcpy`'s length (CWE-195, or CWE-194 when it is sign-extended from `short` or `char`). Which arguments are sizes is data: `size_args` in the C and C++ spec tables. Attacker data choosing a system setting (Windows `SetComputerName`, `SetEnvironmentVariable`, `RegSetValueEx`...) is CWE-15, and choosing a library to load (`dlopen`, `LoadLibrary`, `LoadLibraryEx`) is CWE-114. A Windows CryptoAPI call that selects a weak algorithm by its constant (`CryptCreateHash(prov, CALG_MD5, ...)`, `CryptDeriveKey(prov, CALG_RC4, ...)`) is CWE-328 or CWE-327, from the same weak-algorithm lists as Java's `MessageDigest` and Python's `hashlib.new`. A literal given as a cryptographic key (`AES_set_encrypt_key`, `EVP_EncryptInit_ex`, `HMAC`, `DES_set_key`), directly or through a local that holds one, is CWE-321. A file checked (`stat`, `access`) and then opened or changed (`open`, `fopen`, `unlink`...) through the same path variable, with nothing in between giving it another value, is CWE-367. A `case` that runs into the next one without a `break`, `return` or fall-through mark (`[[fallthrough]]`, a `/* fall through */` comment) is CWE-484, and a fixed numeric address given to a pointer is CWE-587, both read from the syntax tree. An access through a pointer is checked against the array or heap block it points into: the pointer is followed through its single definition (`p = buf + 3`, `p = heap - 8`), only when every step has the same element type, and an access is reported when the facts on the path prove it outside (`*(p - 5)`, `p[-4]`, `memcpy(p, src, n)` with p before the start: CWE-124/127; past a fixed array's end: CWE-787/125). An index from attacker data is reported when it can be negative on some path given its declared type (`if (i < 10) buf[i] = x;`, CWE-124/127; an `unsigned` or `size_t` index never is) or reach the end. Copying a constant number of bytes from a buffer that holds fewer (`memcpy(dst, src, 2048)` with `char src[100]`) is CWE-126. `execl` of a shell with `-c` runs the next argument as a command line, so attacker data there is CWE-78, as it is in `CreateProcess`, `WinExec` and `ShellExecute`. Reading through the result of a function that returns NULL as an ordinary outcome (`getenv` of an unset variable, `fopen` of a missing file, `strchr` with no match, `readdir` at the end) on a path that did not rule NULL out is CWE-690 (`strlen(getenv("HOME"))`); a check before the read clears it, and an unchecked allocation (NULL only when memory runs out) is not reported. A C or C++ string macro is a binding like an assignment, so `#define PASSWORD "..."` is a hard-coded password.

AI applications (category `ai`; walkthrough with real output in [examples/ai-apps](../examples/ai-apps/README.md)):

| Finding | What it is |
|---|---|
| Prompt injection (CWE-1427, OWASP LLM01) | Untrusted data in a model's system instructions: Anthropic `system=`, OpenAI `instructions=`, LangChain `SystemMessage`, and a role/content chat message whose role is `system` or `developer` (`{"role": "system", "content": ...}`, the OpenAI chat format, wherever the messages list is built; Python and JS/TS). Untrusted data in a user turn is how a chat works and is not reported. |
| Model output reaching a sink (OWASP LLM05) | What a model returns (OpenAI, Anthropic, LangChain, LlamaIndex) can be steered by a prompt injection anywhere in what it read, so it is attacker data at every injection sink: a shell, `exec`, SQL, HTML. It is not treated as confidential, so logging it is not a finding. |
| MCP tools | A tool's arguments are model output, so a shell or SQL sink in a tool handler (`@mcp.tool()`, `server.tool(...)` / `server.registerTool(...)`) is a finding. |
| Indirect prompt injection (CWE-1427, OWASP LLM01) | Text the app feeds its model from outside: documents a LangChain vector store or retriever returns (Python and JS), and an MCP client's tool results, resources and prompts. In the system instructions it is prompt injection; at a shell, SQL or `exec` it is attacker data like any other. In a user turn it is how retrieval works and is not reported. |
| MCP tool metadata (CWE-1427) | What a server tells the model about its tools (names, descriptions, parameter descriptions; FastMCP docstrings, low-level `Tool(...)`, `server.tool` / `registerTool` / `addTool` in JS/TS). Hidden characters (Unicode tag characters, decoded in the finding; bidirectional controls; zero-width spaces and joiners) are `mcp_hidden_instructions`: the model reads what the person approving the tool cannot see. A description computed at run time (the environment, a file, a call) is `mcp_dynamic_tool_metadata`: the server can say something other than what was approved. A literal, literals joined, or a module constant is fixed. The wording itself is not judged. `frame inventory` lists each tool's capabilities (shell, code execution, files, network, database). |

Not covered yet: OpenAI chat requests that put untrusted data in a `{"role": "system"}` message, since a dict inside a list is not yet followed by the Python frontend.

Protection-off switches (Flask `debug=True`, insecure cookie flags, Django `DEBUG`) are reported separately as `hardening`. They are `[[setting]]` entries in packs, so a pack can add its own; only an explicit off switch is reported, never a missing option.

C and C++ memory safety (use-after-free, double free, leaks, null dereference, uninitialised reads, out-of-bounds indexing) is decided structurally by the [separation logic engine](engine.md): ownership and heap state are tracked in separation logic, and the solver decides whether the bad state is reachable.
