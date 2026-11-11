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
| **JavaScript / TypeScript** | Express, Koa, Fastify, Hapi, Restify, NestJS, Next.js, Sails, Apollo, Socket.IO, AWS Lambda, Electron, React, Angular, MongoDB driver, Mongoose, Prisma, Sequelize, Knex, TypeORM, MikroORM, mysql/mysql2, pg, pg-promise, sqlite3, better-sqlite3, mssql, oracledb |
| **Java** | Spring MVC/Boot/WebFlux, JAX-RS (Jersey, RESTEasy, Quarkus), Struts 2, JSF, Servlet/JSP, Vert.x, Spark, Javalin, Micronaut, Play, Hibernate/JPA, MyBatis, jOOQ, Kafka's wire readers |
| **C#** | ASP.NET Core MVC and Web API, Minimal APIs, Razor Pages, Blazor, SignalR, Azure Functions, WebForms, WCF/gRPC, EF Core/EF6, Dapper, NHibernate |
| **C / C++** | CGI/FastCGI, POSIX sockets, libmicrohttpd, civetweb/Mongoose, cpp-httplib, Crow, Qt, Boost.Beast, gRPC, libcurl, OpenSSL, libxml2, libarchive, SQLite/libpq/MySQL |
| **AI apps** | OpenAI, Anthropic, LangChain and LlamaIndex SDKs (Python; OpenAI, Anthropic and LangChain in JS/TS), MCP servers (FastMCP, the TypeScript SDK), LangChain vector stores and retrievers, MCP clients |

Every pack is proven by a vulnerable app and its safe twin, scanned through the real CLI in the test suite: 80+ apps and 400+ labelled flaws in [`benchmarks/exemplars/frameworks/`](../benchmarks/exemplars/frameworks).

Razor pages (`.cshtml`, `.razor`) are scanned through the C# engine: the page is transpiled to the C# that Razor compiles it to (code blocks, `@functions` / `@code`, `@expr`, `@Html.Raw`, `@model` / `@inject`), so request data written raw (`@Html.Raw(Request.Query["q"])`) is XSS while an encoded `@expr` is not, and a sink inside a `@{ ... }` block is found like any other C#.

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

`param_positions` narrows an entry point to parameters by position (0-based), whatever they are called or however they are destructured: a GraphQL resolver is called as `(parent, args, context, info)`, so the built-in `graphql` pack takes `param_positions = [1]`. `params_from` keeps only the parameters from a position on. In Python, positions count the arguments the framework passes: a method's bound receiver (the first parameter of a function defined in a class, whatever it is named, unless it is a `@staticmethod`) is not one, so Django's `get(self, request, slug)` has the request at 0. `unbound = true` says the framework calls methods unbound: Graphene's resolvers are implicitly static and get `(parent, info, **arguments)`, so its pack takes `params_from = 2` with `unbound = true`. `receiver = true` selects the receiver itself (`self`), for frameworks that keep the request on the handler instance. `first_param` selects functions by their first parameter's name.

An escaper is recognised by what it does, not by its name: a chain of `replace` calls that replaces every `&`, `<`, `>`, `"` and `'` with a character reference (or removes them) sanitizes for HTML output, in JavaScript (a `g` regex or `replaceAll`) and Python (`str.replace`). Dropping the `g`, leaving one character out, or replacing with markup leaves the value attacker data.

A database call is a sink because of the value it is made on, never because of a variable's name: `pool.query(sql)` is SQL injection when `pool` is a pg or mysql pool (built in the file, exported by another module, handed to a constructor, or declared `pool: Pool` in TypeScript), and `users.find(filter)` NoSQL injection when `users` is a MongoDB collection or a Mongoose model. A call on a value Frame cannot trace is not reported as a database sink.

In JavaScript and Python, `registered_via` names the call by what its receiver is, not by the variable's name: `app.get(path, handler)` after `const app = express()` is `express.get`, `express.Router()` gives `express.Router.get`, `app.route("/x").get` is `express.route.get` (a value bound once to a library call takes that call's id, `frame/sil/value_origins.py`). In a project the same holds for a routes module that callers hand the application (`require("./routes")(app)`: every resolved caller passes the same kind of value), and for a handler defined in another file (`router.get("/", users.show)`, `app.get("/", handler.show)` with `handler = new Handler()`), resolved through the project index. Python registrations are calls passing a function of the file or of an imported module (`app.router.add_get("/x", handler)` is `aiohttp.web.Application.router.add_get`, `path("x/", views.show)` in a `urls.py` is `django.urls.path`) and decorator calls (`@routes.get("/x")` after `routes = web.RouteTableDef()` is `aiohttp.web.RouteTableDef.get`). A `[[wrapper]]` names calls that return the handler wrapped and called with the same arguments, so `path("x/", login_required(views.show))` registers `views.show` (the built-in `django` pack lists Django's view decorators; in JavaScript the `express-async-handler` pack makes `app.get("/x", asyncHandler(async (req, res) => ...))` register the wrapped function, and a wrapper the file defines itself is recognised by its shape: `const catchAsync = fn => (req, res, next) => fn(req, res, next).catch(next)`). A Django function view is a view because the URLconf routes to it: scanned without its `urls.py`, a `views.py` has no views.

A request object is a value, not a name. `[[request_type]]` lists what a framework's request holds that the client chose: `fields` (property paths: `query`, `request.body`), `methods` (method paths whose result is client data: `get`, `cookies.get`), `kinds` for fields of another source kind (`file` for uploads). An entry point with `request_type` makes the selected parameter a request object: reading a listed field or calling a listed method is attacker data, anything else on it (`session`, `user`, `app`) is server state, and the object itself reaching a sink is no finding. It travels through copies, destructuring, helpers (a helper's return summary records which paths it reads) and closures. `fields = ["*"]` makes every property client data except `server_state` (Django's `HttpRequest`: all but `user`, `session`, `site`, `resolver_match` and what application code sets). `objects` names a path holding another request object (a Django class-based view's `self.request`, an `HttpRequest`), `headers` the header maps (a credential header looked up there by name, `Authorization` or `Cookie`, is the caller's own credential: an object it selects is no IDOR), `sessions` the server-side session (storing client data in `request.session` is CWE-501), `identities` the server-state names holding the authenticated caller (Django's `request.user`), and `origin` the value origin calls on the object are named after (`pyramid.request.Request.route_url`). A method called on a request's client data (`request.query.get("k")`) returns that data, whatever library row its name would otherwise match. The built-in `express` pack:

```toml
[[request_type]]
id = "request"
fields = ["params", "query", "body", "cookies", "headers", "rawHeaders", "url", "originalUrl", "path", "hostname",
          "host", "subdomains", "file", "files"]
methods = ["get", "header", "param"]

[[entrypoint]]
id = "handler"
registered_via = ["express.get", "express.post", "express.use", "express.Router.get", "express.Router.post"]
param_positions = [0]
params = "all"
exclude_arity = [4]                      # (err, req, res, next) is error-handling middleware
request_type = "request"
```

Python has module-level request proxies: `proxies` names the objects that are, inside a request, that request (`flask.request` and `quart.request`, `bottle.request`, `cherrypy.request`), in every function of a file that imports them unless the function binds the name itself:

```toml
[[request_type]]                         # python/flask
id = "Request"
fields = ["args", "form", "values", "files", "cookies", "headers", "data", "json", "authorization",
          "query_string", "view_args", "stream", "input_stream", "user_agent", "referrer", "access_route"]
methods = ["get_data", "get_json"]
kinds = { files = "file", cookies = "principal", authorization = "principal" }
headers = ["headers"]
proxies = ["flask.request", "quart.request"]
```

The authenticated caller is a value too (taint kind `identity`): an `[[identity]]` entry's `proxies` (Flask-Login's `current_user`, in the built-in `flask-auth` pack), a source with `kind = "identity"` (`get_jwt_identity()`), a request type's `identities`, the claims a verified token decodes to when the token is the caller's credential (the spec field `identity_arg`, on `jwt.decode`), and the record a selection scoped by the caller returns (`User.query.get(claims["user_id"])` is the caller's own user). It is never attacker data at a sink. It decides IDOR (CWE-639): a resource selection whose argument or query carries it (`filter_by(owner_id=current_user.id, id=x)`) selects the caller's own object, and a comparison of a fetched object's field with it (`if order.owner_id != current_user.id: abort(403)`) is an ownership check. What the variables are called plays no part: a local named `current_user` holding a request value is a request value.

Missing function-level authorization (CWE-862) is read from the application's own convention, not from a notion of which endpoints are meant to be public. Among a program's entry-point handlers that perform a resource or database operation, when a clear majority are protected (an authorization gate, or the authenticated caller used to scope the access) and a minority are not, the unprotected handlers are the ones that skipped the check their peers apply. A gate is pack data: a `[[auth_gate]]` entry lists the decorators or annotations that authenticate a handler (`login_required`, `jwt_required` in the built-in `flask-auth` pack; Django's `login_required`, `permission_required`, `staff_member_required`), and a project teaches Frame its own with a pack of its own. An app with no authorization convention stays silent, and a handler already reported as an IDOR is left to that finding, not reported twice.

Python route decorators register a handler on the framework's object, known by value: `@app.route` after `app = Flask(__name__)` (or `from app import app`, or a function handed the app by its caller) is `flask.Flask.route`, so a `@cache.get(...)` decorator on some other object is no route. A Flask view's parameters are the route rule's variables (`route_syntax = "werkzeug"` reads `<converter:name>` from the matched decorator's rule; `*args`/`**kwargs` take any): a parameter the rule does not name comes from a decorator or a default. A function a decorator of the project wraps (`@token_required`) receives what the decorator's wrapper passes it (`return f(user, *args, **kwargs)`), in the file and across a project, and a Python closure sees the values of its enclosing functions.

A Django project's middleware is what `settings.MIDDLEWARE` lists by dotted path (`[[setting_registration]]`): a listed class's `__call__` and `process_*` hooks, or the function a listed factory returns, receive the request; so do ModelAdmin hooks, at their documented positions, and `@admin.action` functions.

A connexion app's handlers are the functions its OpenAPI documents' `operationId`s name (a dotted path, or the `x-openapi-router-controller` module's function): the project's YAML and JSON OpenAPI and Swagger 2.0 documents are read, and the `connexion` pack's `[[operation_dispatch]]` resolves each id like the app's file imports it.

Python handlers get the request by routing (Django's URLconf, aiohttp's router and route tables, Starlette's `Route`, Pyramid's `add_view`), by decorator (`@api_view`, Sanic routes, `@view_config`), by base class (Django and DRF views, Tornado's `RequestHandler`, Starlette endpoints, aiohttp's `web.View`), by type (a parameter declared `fastapi.Request` or `aiohttp.web.Request`, wherever it is) or by method name (Falcon's `on_get(req, resp)`). A class the framework constructs with the request (a Pyramid view class) keeps it: a field its `__init__` sets from the request holds it in the class's other methods.

`arity` / `exclude_arity` select functions by their parameter count. `module_path` (globs on the file's path) with `exports` (what the module exports the function as: `default`, a name, `*`) selects by a documented file-system convention: Next.js treats the default export of a file under `pages/api/` as a route handler, Sails the actions a module in `api/controllers/` exports. `directives` and `body_directives` select by a directive prologue: a `'use server'` module's exports, or a function whose body starts with `'use server'`, are server actions. A destructuring parameter (`({ body, query }, res) => ...`) is one positional parameter (`$argN`) whose names are bound from it at entry. `detect.dependencies` holds when the nearest `package.json` declares one of the packages (Sails provides a global, so a Sails app is known by its manifest).

An entry point with `origin` names what its parameters are rather than tainting them: the built-in `express` pack gives a handler's second parameter the origin `express.Response`, so `res.send(x)` is the call `express.Response.send` and the pack's sinks name it by that id (`node-http`, `koa`, `fastify`, `hapi`, `restify`, `nextjs` and `sails` do the same for their responses). A helper handed the response (`function after(r, url) { r.redirect(url) }`) gets the origin when every call of it passes one, in the file and across a project. A sink rule with `property = true` names a property whose assignment is the sink (`ctx.body = x` on a `koa.Context`); `renders_view = true` marks a `(view, data)` render call, whose data counts only where the template prints it raw. A call written inside another expression (`foo(res.send(x))`, `return ok ? res.send(x) : null`) is checked by the same names, and a `&&`, `||` or ternary written as a statement is the branch it is.

`[[callback_param]]` says a framework calls the functions registered through `registered_via` with a value of origin `origin` at `position`, optionally only for `event` (the registration's first literal argument), so calls on that parameter are named after it: Socket.IO's `io.on("connection", socket => ...)` hands in a `socket.io.Socket`, `fastify.register(plugin)` a Fastify instance:

```toml
[[callback_param]]
registered_via = ["socket.io.Server.on", "socket.io.on"]
event = ["connection", "connect"]
position = 0
origin = "socket.io.Socket"
```

JavaScript packs have two more kinds. `[[registration]]` names the functions an application hands to a framework inside a value it passes to one of the framework's calls, for an entry point's `registered_via` to select. The value is followed through names bound to it, arrays, spreads and other modules' exports, never found by an object key or a variable's name:

```toml
[[registration]]                         # new ApolloServer({ typeDefs, resolvers }): Query.books, User.posts
call = ["@apollo/server.ApolloServer", "@graphql-tools/schema.makeExecutableSchema"]
option = "resolvers"                     # that key of the options object at `arg` (default 0)
depth = 2                                # object levels from the value to the functions
leaf_keys = ["resolve", "subscribe"]     # or a field's config object one level further
registered_as = "graphql.resolver"

[[registration]]                         # startStandaloneServer(server, { context: async ({ req }) => ({...}) })
call = ["@apollo/server/standalone.startStandaloneServer"]
arg = 1
option = "context"                       # depth 0: the value is the function itself
registered_as = "graphql.context.http"
server_arg = 0                           # the server it serves
context_of = "graphql.resolver"          # its result is that server's resolvers' third argument
context_param = 2
```

What a context function returns reaches each resolver field by field: `ctx.db` holds the pool the context put there (so `ctx.db.query(q)` is that driver's sink) and `ctx.tenant` the header it read, while a field holding a constant is no attacker data. Another server's context reaches none of these resolvers.

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

A C# `[[service_registration]]` names a method that registers a dependency-injection service (`services.AddScoped<IRepo, Repo>()`): the service is the `type_arg`-th type argument, the type of a `typeof(T)` at `typeof_arg`, or one of the fixed `registers` types. An entry point with `exclude_services = true` does not taint a handler parameter of a registered type, wherever in the project the registration is written, because the container supplies it; `exclude_param_annotation` drops parameters such as `[FromServices]`. A type is never a service because of its name (`IOrderService` registered nowhere is bound from the request). Minimal API handlers are registered by value: `app.MapGet` on `WebApplication.CreateBuilder(args).Build()`, a route group, or a declared `IEndpointRouteBuilder`. A `Program.cs` without using directives still resolves through the project: the SDK's implicit usings when the `.csproj` enables them, its `<Using>` items, those of the `Directory.Build.props` above it, and every `global using` in the project's files. A lambda passed to a library method gets the parameter types the method's delegate gives (`options.AddPolicy("p", policy => policy.AllowAnyOrigin())`: `policy` is a `CorsPolicyBuilder`).

A Python `[[returned_response]]` says a framework sends what a view returns as the response: the `entrypoints` it applies to, the sink `kind`, the `content_types` that make it one, and the `default_content_type` of a `str` body written with no Content-Type (`default_needs_markup`: only a body whose literal text has a tag). Flask's: `return page, 200, {"Content-Type": "text/html"}` and `return f"<p>{name}</p>"` are HTML responses; `return jsonify(...)`, a dict, or a body sent as `application/octet-stream` are not.

A `[[function]]` in a pack of any language can say `noreturn = true` (`flask.abort` ends the request); the memory facts (`allocates`, `frees`, `dereferences`, and `writes_headers` for a C call that writes an HTTP header from its literal argument) are C and C++ only. A JavaScript `[[middleware]]` names the method that registers middleware on an app or router (`app.use(mw)`: the request fields mw sets reach every handler of `app`), and a Java `[[request_attribute]]` says that what a filter stores on the request (`setAttribute`) is what a servlet's `getAttribute` reads.

C and C++ packs name option-dispatch functions with `[[option_call]]` (`name`, `option_arg`, optional `value_arg`): `curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L)` then has the canonical id `curl_easy_setopt:CURLOPT_SSL_VERIFYPEER:off`, which a rule can match. A C++ `[[content_type_call]]` (`method`, `arg`) names a response writer whose content type sits beside the body: `res.set_content(body, "text/html")` becomes `res.set_content:html`.

Python and JavaScript packs say how a server library registers a tool a model may call with `[[tool_registration]]`, so the tool metadata checks (hidden characters, descriptions computed at run time) and `frame inventory` read the text the model is shown and find the handler. Python takes a `decorator` (globs over the callee; `docstring` and `signature` add the handler's docstring and parameters) or a constructor `call` (with `when_kwargs`), plus `name_kwarg` and `text_kwargs`. JavaScript takes a `method` with the tool's name at `name_arg` or in `name_field` of the object at `config_arg`, a string-shaped description at `description_arg`, `text_fields`, and the handler at `handler_arg` (-1 is the last) or `handler_field`. `entrypoint` names the pack's entry point whose procedures are the tools:

```toml
[[tool_registration]]                     # server.registerTool(name, {title, description}, handler)
id = "register-tool"
entrypoint = "tool"
method = ["registerTool"]
name_arg = 0
config_arg = 1
text_fields = ["title", "description"]
handler_arg = -1
```

A sink rule with `json_for_literals = true` is a response that serialises an object or array literal as JSON (`reply.send({ q })`), so such a value is not an HTML sink.

In the spec tables (`frame/sil/specs/data/<table>.toml`), a usage sink (`sink_args = []`, where the call itself is the finding) can say what makes the call weak. With `algorithm_name_arg`, the argument names the algorithm as a string and the call is reported only for a weak one from `specs/data/weak-algorithms.toml` (`hashlib.new("md5")`, `Cipher.getInstance("DES/CBC/PKCS5Padding")`); a name the analysis cannot read is not reported. `safe_kwargs = { usedforsecurity = "False" }` drops the call when that keyword is that literal. `scanf_format_arg` reports a scanf-family call only when its format has an unbounded `%s` or `%[`.

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

100+ finding types. The symbolic core proves the ones reachable by taint or memory reasoning; the [AI layer](ai.md) adds authorization and business-logic flaws ([the hunt](ai.md#hunting-authorization-flaws---hunt-authz)).

| Injection | Access control | Data exposure and crypto | Memory safety |
|---|---|---|---|
| SQL / NoSQL / ORM (CWE-89, 943) | IDOR / BOLA (CWE-639) | Path traversal (CWE-22) | Buffer overflow (CWE-121/122) |
| XSS (CWE-79) | Authorization bypass (CWE-285), missing authorization (CWE-862) | SSRF (CWE-918) | Use-after-free (CWE-416) |
| Command and code (CWE-78/94) | Mass assignment (CWE-915) | Open redirect (CWE-601) | Double / invalid free (CWE-415) |
| Template (SSTI) | Broken authentication | XXE (CWE-611) | Null dereference |
| LDAP / XPath / XML | Session fixation | Secrets, unsafe deserialization | Integer overflow |
| Header and log | CSRF (CWE-352) | Weak crypto, hashing, random | Format string |
| | | | Allocation sized by a peer (CWE-770) |

Weak randomness is reported by where the value goes, not by the call: the output of a non-cryptographic generator (`java.util.Random`, Python's `random`, JS `Math.random`, C's `rand()`) is CWE-338 when it becomes a cookie's value, a cryptographic key, IV, nonce or salt (`frame/sil/specs/data/unpredictable.toml`), and nothing when it picks a delay, a sample or a test value. It is also CWE-338 when it is written to something whose name says it must be unpredictable: a variable, field or buffer named as a token, secret, password, nonce, salt, IV, OTP, CSRF token or session id (`reset_token = str(random.randint(...))`, `token[i] = charset[rand() % 62]`), or the result of a function so named (`generate_token()` returning it, or C's `new_session_token(char *out)` writing it into `out`). The words are data (`unpredictable.toml` `[destinations]`); `token_length` and `salt_size` name something about the value, not the value. A digest is as predictable as its input, so `rand()` bytes hashed with SHA-256 are still predictable. A `SecureRandom` declared as `Random` is not weak, and a random number is never attacker data at an injection sink. C# still reports each `System.Random` call (CWE-330).

A credential written to a database as it is (CWE-522) is found from the SQL statement the program writes: an `INSERT` or `UPDATE` whose column is named as a credential (`password`, `session_token`, `api_key`; not `password_hash` or `token_type`), and the element of the parameters list that column takes (`?`, `%s`, `$1`, `:name`), whatever helper the statement goes through. It is reported when that value is a password or token from the request, or a secret the program just generated (`secrets.token_urlsafe`, `uuid.uuid4`, `crypto.randomBytes`, `crypto.randomUUID`), and no hash function replaced it on the way (`hashlib`, `hmac`, passlib, bcrypt, argon2, `generate_password_hash`, Node's `createHash`/`createHmac`, `pbkdf2Sync`, `scryptSync`: the `credential-storage` packs). A generated secret is not attacker data, so it matters at no other sink.

Hardcoded secrets are found two ways: a credential-named variable bound to a literal, and any string literal holding one of 15 providers' key formats. Frame also scans the whole git history and can verify a found credential against its provider. Full details, including the formats and the live check, are in [secrets](secrets.md).

An allocation sized by attacker data with nothing on the path bounding it is CWE-770 (Python, JS/TS, Java): in Java an array dimension, `ByteBuffer.allocate`, or a capacity constructor (`new ArrayList<>(n)`, `new HashMap<>(n)`, `new StringBuilder(n)`, only when the argument is an integer; with a collection or a String they copy). Besides request data, a number read off a binary stream or buffer is a source of its own (`wire_size`: `DataInputStream`/`DataInput`/`ObjectInputStream`/`RandomAccessFile` `readInt`, `readLong`, `readShort`, ..., `ByteBuffer.getInt`, ...; Kafka's `ByteUtils` through the `kafka-protocol` pack). It is a number, not text, so it is reported only as an allocation size, never at an injection sink. Any branch condition mentioning the size on the path counts as a bound, and so does `Math.min`. Walkthrough on three Apache Kafka bugs (CVE-2026-114349, CVE-2026-111551), before and after their fixes: [examples/java-allocation](../examples/java-allocation/README.md).

Integer overflow in C and C++ (CWE-190) is decided by the solver, not by a pattern: attacker data in an operand of `*`, `+` or a constant `<<`, whose declared integer type is known (`int`, `unsigned`, `short`, `int64_t`...), is reported only when, with what the path has established, the result can exceed the maximum of the type C computes it in. `if (d < 1000)` before `d * 2` clears it; `if (d < 2000000000)` does not. A `char` squared is computed as an `int` and cannot overflow it. A type whose width depends on the platform (`long`, `size_t`) is not guessed, so its arithmetic is not checked. The same question covers the other integer defects: a result that can go below the type's minimum (CWE-191), a value assigned to a narrower type that can lie outside it (CWE-197), and a signed value that can be negative where the callee takes a size, such as `memcpy`'s length (CWE-195, or CWE-194 when it is sign-extended from `short` or `char`). Which arguments are sizes is data: `size_args` in the C and C++ spec tables. Attacker data choosing a system setting (Windows `SetComputerName`, `SetEnvironmentVariable`, `RegSetValueEx`...) is CWE-15, and choosing a library to load (`dlopen`, `LoadLibrary`, `LoadLibraryEx`) is CWE-114. A Windows CryptoAPI call that selects a weak algorithm by its constant (`CryptCreateHash(prov, CALG_MD5, ...)`, `CryptDeriveKey(prov, CALG_RC4, ...)`) is CWE-328 or CWE-327, from the same weak-algorithm lists as Java's `MessageDigest` and Python's `hashlib.new`. A literal given as a cryptographic key (`AES_set_encrypt_key`, `EVP_EncryptInit_ex`, `HMAC`, `DES_set_key`), directly or through a local that holds one, is CWE-321. A file checked (`stat`, `access`) and then opened or changed (`open`, `fopen`, `unlink`...) through the same path variable, with nothing in between giving it another value, is CWE-367. A `case` that runs into the next one without a `break`, `return` or fall-through mark (`[[fallthrough]]`, a `/* fall through */` comment) is CWE-484, and a fixed numeric address given to a pointer is CWE-587, both read from the syntax tree. An access through a pointer is checked against the array or heap block it points into: the pointer is followed through its single definition (`p = buf + 3`, `p = heap - 8`), only when every step has the same element type, and an access is reported when the facts on the path prove it outside (`*(p - 5)`, `p[-4]`, `memcpy(p, src, n)` with p before the start: CWE-124/127; past a fixed array's end: CWE-787/125). An index from attacker data is reported when it can be negative on some path given its declared type (`if (i < 10) buf[i] = x;`, CWE-124/127; an `unsigned` or `size_t` index never is) or reach the end. Copying a constant number of bytes from a buffer that holds fewer (`memcpy(dst, src, 2048)` with `char src[100]`) is CWE-126. `execl` of a shell with `-c` runs the next argument as a command line, so attacker data there is CWE-78, as it is in `CreateProcess`, `WinExec` and `ShellExecute`. Reading through the result of a function that returns NULL as an ordinary outcome (`getenv` of an unset variable, `fopen` of a missing file, `strchr` with no match, `readdir` at the end) on a path that did not rule NULL out is CWE-690 (`strlen(getenv("HOME"))`); a check before the read clears it, and an unchecked allocation (NULL only when memory runs out) is not reported. A C or C++ string macro is a binding like an assignment, so `#define PASSWORD "..."` is a hard-coded password.

AI applications (category `ai`): prompt injection, model output reaching a sink, unsafe MCP tools, indirect prompt injection, and hidden instructions in MCP tool metadata, mapped to the OWASP LLM Top 10. Full details are in [LLM and MCP application security](llm-security.md).

Protection-off switches (Flask `debug=True`, insecure cookie flags, Django `DEBUG`) are reported separately as `hardening`. They are `[[setting]]` entries in packs, so a pack can add its own; only an explicit off switch is reported, never a missing option.

C and C++ memory safety (use-after-free, double free, leaks, null dereference, uninitialised reads, out-of-bounds indexing) is decided structurally by the [separation logic engine](engine.md): ownership and heap state are tracked in separation logic, and the solver decides whether the bad state is reachable.
