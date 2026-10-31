# Exemplars: where Frame's cross-file analysis finds what other scanners don't

This folder is a living comparison. Each exemplar is a vulnerability whose **source and sink sit in
different files** (a handler reads request data, a helper module runs the query), the shape that
file-at-a-time scanners miss and that real code is full of. We run Frame and other scanners on the
same code, score them against an answer key we confirmed by reading both ends, and write down what
each tool does and why.

**Current headline** (Python, JavaScript, TypeScript; every number below comes from `run_comparison.py` and `triage.json`):

- **Controlled cross-file cases** (9, each with a safe twin): Frame found **9/9 with 0 false alarms**; CodeQL 7/9 with 1;
  Semgrep/OpenGrep taint rules 1/9; OpenGrep's experimental interfile build 3/9. Stock rule packs "found" 6/9 but flagged all
  6 safe twins too, because they match the sink pattern and not the flow.
- **Blind hold-out** (14 cases keyed before Frame was run on them): Frame **14/14, 0 false alarms**; CodeQL 10/14 with 1; Semgrep stock
  packs 9/14 with 8 false alarms; taint rules 1/14. The first Frame run scored 7/14; the fixes that followed are listed under "Blind hold-out".
- **Java** (10 cases keyed before the Java feature existed; Frame's first run found 1/10): Frame **10/10 with 0 false alarms**; CodeQL 10/10 with 3; Semgrep/OpenGrep taint rules 1/10 (stock packs 8/10, but 7 safe twins flagged).
- **Four deliberately vulnerable apps** at pinned commits: Frame found **10/10** of the cross-file vulnerabilities in the answer key;
  CodeQL 7/10 (it misses dvpwa's static async DAO and NodeGoat's DAOs); Semgrep and OpenGrep intrafile taint rules 0/10, OpenGrep's interfile build 3/10.
- **Precision, labelled by hand** (every Frame and CodeQL report on those apps): Frame 52 real, 1 false, 4 debatable of 57
  (98%); CodeQL 38 real, 2 false, 3 debatable, 14 hardening-only of 57 (95%).
- **The app authors' own answer key** (vulnerable-node ships `sast/ground-truth.yaml`): Frame 10/12 seeds and 0 of 2 clean seeds flagged; CodeQL 8/12 and 1 of 2.
- Not run: Semgrep Pro, Snyk Code, SonarQube, Checkmarx and other commercial tools (they need an account or server;
  see "Not covered"). Nothing here supports a claim about them.

Start with [`quickstart/`](quickstart/README.md) (three files, two cross-file flaws), then [`frameworks/`](frameworks/README.md) (a vulnerable app and a safe twin per framework). The sections below compare Frame with other scanners.

## What is compared

| tool | version | how it was run |
|---|---|---|
| Frame | this repo | `frame scan DIR` (cross-file analysis on by default) |
| Semgrep OSS | 1.182.1 | custom taint rules in `rules/`; and stock packs `p/default p/python p/javascript p/typescript p/security-audit p/owasp-top-ten` |
| OpenGrep | 1.32.0 | same rules, `--taint-intrafile` |
| OpenGrep interfile build | `--version` prints 1.30.0 | same taint rules, `--taint-interfile` (experimental) |
| Bandit | 1.9.4 | default, Python only |
| CodeQL CLI | 2.27.3 | `security-extended` suite, database built per target without a build step |

**Custom taint rules.** `rules/` holds taint-mode rules written the way a Semgrep user would: request
accessors as sources, the dangerous calls as sinks, `shlex.quote` as a sanitizer. They are checked against
`controls/` (source and sink in one function), where they all fire (`run_comparison.py --controls`), so a
miss on a cross-file case is the engine's reach, not a broken rule.

The nine controlled cases illustrate shapes Frame resolves; the blind hold-out below is the independent check.

**Scoring.** A tool scores a hit when it reports a finding in the sink's file within one line of the sink
(`tolerance` per entry in the key). Frame must also name the right CWE; other tools' rule ids are not CWEs,
so for them location is the only evidence. On the safe twin the same report is a false alarm. For real apps,
"+N" counts every other report in the scanned tree. Those were **not triaged**: these apps are full of real
bugs that are not in the key, so +N is volume, not a false-positive rate.

## Controlled cases

✅ found · ❌ missed · ⚠️ also reported on the safe twin (false alarm)

| case | Frame | Semgrep (taint rules) | Semgrep (stock packs) | OpenGrep (taint rules) | OpenGrep (stock packs) | OpenGrep interfile (taint rules) | Bandit | CodeQL |
|---|---|---|---|---|---|---|---|---|
| `py_helper_module` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ ⚠️ | ✅ ⚠️ | ✅ |
| `py_three_hops` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ ⚠️ | ✅ ⚠️ | ✅ |
| `py_source_in_helper` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| `py_sanitizer_in_helper` | ✅ | ✅ ⚠️ | ✅ ⚠️ | ✅ ⚠️ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ✅ ⚠️ |
| `py_class_dao` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ✅ | ✅ ⚠️ | ✅ |
| `py_injected_service` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ✅ | ✅ ⚠️ | ✅ |
| `js_helper_module` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ❌ | ✅ |
| `js_constructor_dao` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `ts_class_service` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ✅ | ❌ | ❌ |
| **found · false alarms** | **9/9** · 0 | **1/9** · 1 | **6/9** · 6 | **1/9** · 1 | **6/9** · 6 | **3/9** · 2 | **5/9** · 5 | **7/9** · 1 |

Each case is in `cases/<id>/vulnerable` and `cases/<id>/safe`; the key is `cases.json`.

## Blind hold-out

Fourteen more cases (`holdout/`), written and keyed **before Frame was run on them**; the commit that adds them
(`29cceed`) predates every result here. They deliberately use shapes the resolver did not handle yet. Frame's first run scored
**7/14** with one false alarm (`holdout/first_run_frame.json`); the misses became the work list: `from m import *`, factory
functions, tsconfig `paths`, NestJS `@Query()` parameters, default-exported class statics, a dict returned by a helper,
`createCipheriv`-style spec keys, and a `shell-escape` sanitizer. The table is the run after those fixes, so it is a
regression check on the fixes; the 7/14 is the blind score.

Amended 2026-11: three cases were incomplete programs whose database handle nothing defined (`ts_nest_three_layers`
declared `db: any`, `js_factory_instance` never assigned `this.db`, and `js_router_service_object` required a `../db`
module the case did not contain). Frame found them only because the variable was called `db`; since database sinks are
calls on a known value (a pool, a `DataSource`), each twin now defines its handle as a real app does (a `mysql.createPool`
module, the repository creating its pool, Nest's injected `DataSource`). The cases' shapes are unchanged, and the keyed
lines moved with the added lines (`holdout.json`).

✅ found · ❌ missed · ⚠️ also reported on the safe twin

| case | Frame | Semgrep (taint rules) | Semgrep (stock packs) | OpenGrep (taint rules) | OpenGrep (stock packs) | OpenGrep interfile (taint rules) | Bandit | CodeQL |
|---|---|---|---|---|---|---|---|---|
| `py_aliased_module_call` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ✅ |
| `py_parameterized_helper` | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ |
| `py_helper_returns_dict` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ✅ |
| `py_decorated_helper` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ ⚠️ | ✅ |
| `py_star_import` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ ⚠️ | ✅ |
| `py_factory_instance` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ✅ |
| `py_fastapi_depends` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ |
| `js_router_service_object` | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| `js_default_class_static` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ✅ | ❌ | ✅ |
| `ts_nest_three_layers` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `ts_path_alias_import` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ❌ | ✅ |
| `js_factory_instance` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `js_anonymous_module_function` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ❌ | ✅ |
| `js_sanitizer_module` | ✅ | ✅ ⚠️ | ✅ ⚠️ | ✅ ⚠️ | ✅ ⚠️ | ✅ ⚠️ | ❌ | ✅ ⚠️ |
| **found · false alarms** | **14/14** · 0 | **1/14** · 1 | **9/14** · 8 | **1/14** · 1 | **9/14** · 8 | **3/14** · 1 | **7/14** · 6 | **10/14** · 1 |

## Java

Ten Java cross-file cases (`java/`), keyed **before the Java feature existed**: a servlet or Spring controller passes request data to a
method of another class and the sink is there. Frame's first run found **1/10** (`java/first_run_frame.json`, before any Java cross-file code); the table is the run after the
feature, so it is a regression check on what it added, like the hold-out. The shapes are a DAO imported from another package, a static
utility, a Spring controller -> service -> repository chain with constructor injection and `@RequestParam`, an interface with one implementation,
a sink in an inherited method, a helper that returns the request value, an HTML escaper in another class (real escaping or an identity function),
`import com.app.dao.*;` with an `@Autowired` field, overloads where only the `String` one is injectable, and three hops through three packages.
Semgrep/OpenGrep use `rules/taint_java.yml` (checked against `controls/Java*.java`); the stock run adds `p/java`.

✅ found · ❌ missed · ⚠️ also reported on the safe twin

| case | Frame | Semgrep (taint rules) | Semgrep (stock packs) | OpenGrep (taint rules) | OpenGrep (stock packs) | OpenGrep interfile (taint rules) | CodeQL |
|---|---|---|---|---|---|---|---|
| `java_dao_servlet` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ |
| `java_static_util` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ ⚠️ |
| `java_spring_three_layers` | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| `java_interface_impl` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ |
| `java_inherited_sink` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| `java_source_in_helper` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ |
| `java_sanitizer_in_helper` | ✅ | ✅ ⚠️ | ✅ ⚠️ | ✅ ⚠️ | ✅ ⚠️ | ✅ ⚠️ | ✅ |
| `java_wildcard_import` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ |
| `java_overloads` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ |
| `java_three_hops` | ✅ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ | ❌ | ✅ ⚠️ |
| **found · false alarms** | **10/10** · 0 | **1/10** · 1 | **8/10** · 7 | **1/10** · 1 | **8/10** · 7 | **1/10** · 1 | **10/10** · 3 |

CodeQL's whole-program taint handles all ten; it also reports three safe twins (`java_static_util`, `java_overloads`, `java_three_hops`),
which Frame does not. On Java this is a recall tie and a false-alarm gap, not a recall win.

## Real applications

Cloned at the pinned commits in `real_repos.json` at run time (never vendored). Cells are
`found/expected (+other reports)`.

| app | Frame | Semgrep (taint rules) | Semgrep (stock packs) | OpenGrep (taint rules) | OpenGrep (stock packs) | OpenGrep interfile (taint rules) | Bandit | CodeQL |
|---|---|---|---|---|---|---|---|---|
| `vulpy` | 3/3 (+1) | 0/3 (+0) | 3/3 (+24) | 0/3 (+0) | 3/3 (+24) | 0/3 (+0) | 3/3 (+19) | 3/3 (+6) |
| `dvpwa` | 1/1 (+1) | 0/1 (+0) | 1/1 (+8) | 0/1 (+0) | 1/1 (+4) | 0/1 (+0) | 0/1 (+2) | 0/1 (+1) |
| `vulnerable-node` | 4/4 (+30) | 0/4 (+2) | 3/4 (+44) | 0/4 (+2) | 3/4 (+44) | 3/4 (+12) | 0/4 (+0) | 4/4 (+40) |
| `NodeGoat` | 2/2 (+10) | 0/2 (+0) | 0/2 (+16) | 0/2 (+0) | 0/2 (+16) | 0/2 (+0) | 0/2 (+0) | 0/2 (+1) |
| **found** | **10/10** | **0/10** | **7/10** | **0/10** | **7/10** | **3/10** | **3/10** | **7/10** |

The expected sinks, each confirmed by reading source and sink:

- **vulpy** `bad/libuser.py` lines 12, 25, 53: SQL built with `format`/`%` in helpers that `mod_user.py` feeds from `request.form`.
- **dvpwa** `sqli/dao/student.py:45`: `Student.create`, a static async method, formats `name` into an INSERT; the value is aiohttp `await request.post()` in `views.py`.
- **vulnerable-node** `model/db.js` lines 14, 26, 101 (SQL injection, including an `ORDER BY` column) and `model/merge.js` (prototype pollution via a recursive merge fed `req.body` from `routes/account.js`).
- **NodeGoat** `app/data/user-dao.js` lines 91, 104: `findOne({userName})` with the value straight from `req.body` (NoSQL operator injection).
- Not scored either way: `benefits-dao.js:24` (request value inside `$set`; debatable) and `good/libuser.py:61` in vulpy.

## Precision, and the apps' own answer key

Every report Frame and CodeQL make on the four apps, labelled by reading the code (`triage.json` holds each label and the reason):
**real** is a genuine vulnerability, **false** is not a vulnerability as reported, **debatable** is a judgement call (a request value inside
`$set`, a token in a mock server), **advisory** is a hardening query CodeQL reports and we do not key (missing rate limiting, CSRF).

| app | Frame reports | real | false | debatable | CodeQL reports | real | false | debatable | advisory |
|---|---|---|---|---|---|---|---|---|---|
| `vulpy` | 6 | 6 | 0 | 0 | 9 | 5 | 1 | 3 | 0 |
| `dvpwa` | 2 | 2 | 0 | 0 | 1 | 1 | 0 | 0 | 0 |
| `vulnerable-node` | 36 | 33 | 1 | 2 | 46 | 31 | 1 | 0 | 14 |
| `NodeGoat` | 13 | 11 | 0 | 2 | 1 | 1 | 0 | 0 | 0 |
| **all four** | 57 | 52 | 1 | 4 | 57 | 38 | 2 | 3 | 14 |

Frame's precision on the labelled reports is 98%; CodeQL's is 95% (advisory queries excluded; Frame's count includes its three hardening findings: two `debug=True` and one `secure: false`). Both are lists of what each tool
reported, not recall: neither is exhaustive. The other tools' extra reports in the real-app table above are not labelled.

vulnerable-node also ships its own answer key (`sast/ground-truth.yaml`: twelve seed files, plus two "clean" seeds that must produce nothing),
written by the app's authors:

| | seeds found (of 12) | missed | clean seeds flagged (of 2) |
|---|---|---|---|
| Frame | 10/12 | sqli-concat, nosql-operator | 0 |
| CodeQL | 8/12 | sqli-concat, nosql-operator, path-traversal, hardcoded-secret | 1 |

Frame's two misses are library-style seeds that take untrusted input as a plain function parameter; its default treats only request reads as sources.
We read this key after the first runs and fixed what it exposed (an `md5` hash call, a redirect guard, a file name), so this row is not blind either.

## Framework coverage

Frame ships *packs* -- small TOML files that teach it a framework's entry points, sources, sinks and
sanitizers (`frame/sil/packs/data`) -- and every pack is proven the same way: a realistic application with the
flaw, and the same application done correctly, scanned through the real `frame` CLI.

86 applications, 406 labelled vulnerable lines, each with a safe twin that must stay silent
(`benchmarks/exemplars/frameworks/<language>/<framework>/{vulnerable,safe}`):

| Language | Apps | Labelled flaws | Frameworks and libraries |
|---|---|---|---|
| Python | 18 | 90 | aiohttp, bottle, cherrypy, deserialize-xml, django-views, drf, falcon, fastapi, flask-extras, http-clients, jinja-mako, nosql-pymongo, orm-raw-sql, process-exec, pyramid, sanic, starlette, tornado |
| JavaScript / TypeScript | 21 | 85 | angular, apollo, dom-vanilla, electron, express, fastify, hapi, http-clients, koa, lambda, mongoose, nestjs, nextjs, prisma, react, restify, sails, serialization, socketio, template-engines, xml-jwt-redis |
| Java | 17 | 105 | deserialization, hibernate-jpa, http-clients, javalin, jaxrs, jdk-core, jooq, jsf, micronaut, mybatis, play, servlet-jsp, sparkjava, spring-mvc, struts2, template-engines, vertx-web |
| C# | 13 | 68 | aspnetcore-config, aspnetcore-minimal, aspnetcore-mvc, aspnetcore-razor-pages, azure-functions, blazor, data-access, dotnet-system-apis, dotnet-xml-deserialization, nhibernate-ef6, signalr-hub, wcf-grpc, webforms |
| C | 11 | 36 | cgi, cli-getopt, db-clients, fastcgi, libarchive, libcurl, libmicrohttpd, libxml2, mongoose, openssl, posix-sockets |
| C++ | 6 | 22 | boost-beast, cpp-httplib, crow, grpc, qt, sql-clients |

`tests/e2e/test_framework_packs.py` runs all of them: every marked line must be reported with its CWE, nothing
unmarked of those CWEs may appear in the vulnerable app, the safe twin must be clean, the packs the fixture names
must have applied, and a scan with `--no-packs` must miss something -- a pack has to earn its place. Teams add
their own the same way (`.frame/packs/`, `--pack`, `frame packs check`).

## Use cases

Each entry: the situation, why a file-at-a-time scanner cannot see it, how Frame handles it. Add new
ones at the bottom of this section.

### 1. Request data passed to a helper module
`views.py` reads `request.args`, calls `db.find_user(name)`; `db.py` formats `name` into SQL. The sink has no
source in its file and the handler has no sink in its. Frame resolves the import, learns that `find_user`
passes its parameter to a SQL sink, and reports at `db.py:6` with the call site in `data_flow`. The safe twin
passes a constant and is silent. (`py_helper_module`, `js_helper_module`; also vulpy and vulnerable-node.)
CodeQL also finds these; Semgrep/OpenGrep taint rules do not, and their stock rules report the sink in both versions.

### 2. Three files deep
handler → `service.check()` → `shell.ping()` → `os.system`. Frame iterates call summaries to a fixpoint, so
depth costs nothing extra and the order files are read in does not matter. (`py_three_hops`.)
CodeQL finds it. The OpenGrep interfile build did not, and flagged the safe twin.

### 3. The source is hidden in a helper
`params.requested_path()` returns `request.args.get(...)`; the view only calls `open(requested_path())`.
Nothing in `views.py` looks like input. Frame summarises what a helper returns, including a source, and applies it
at the call site. (`py_source_in_helper`.) Only Frame and CodeQL found this one.

### 4. Is the helper a sanitizer, or an identity function?
`sanitize()` lives in another module. In the safe twin it calls `shlex.quote`; in the vulnerable one it returns its
argument. The two `views.py` files are identical, so a scanner that cannot see into `clean.py` must guess. Every
tool that reported the vulnerable version also reported the safe one (CodeQL included); the OpenGrep interfile
build reported neither. Frame found the vulnerable version and stayed silent on the safe one because it records which
sink kinds each helper sanitises on *every* path. (`py_sanitizer_in_helper`.)

### 5. Methods on objects, injected dependencies, constructor functions
The DAO pattern: a class in `repo.py`, an instance in `views.py`, or one injected through an annotated
constructor parameter (`self.repo = repo`), or a `function UserDAO(db) { this.byId = ... }` constructor function (NodeGoat's
style) or a TypeScript parameter property. Frame resolves the receiver's class from `new C()`, annotations and
assignments, follows base classes, and refuses to guess when the evidence conflicts (a receiver assigned two different
classes, or built by a factory, stays unresolved). (`py_class_dao`, `py_injected_service`, `js_constructor_dao`,
`ts_class_service`; dvpwa's static async `Student.create`; NodeGoat's DAOs.)
CodeQL missed `js_constructor_dao`, `ts_class_service` and NodeGoat; the OpenGrep interfile build found the class-based cases.

### 6. A one-file edit makes a different file vulnerable
`use_cases/helper_edit_regression.py` commits a repo whose `sanitize()` quotes, then edits only `clean.py` so it
does not. `views.py` is untouched but is now a command injection. `frame scan --changed --baseline ...`
widens the scan to the files that import what changed, and reports `views.py:9` (CWE-78) as new (exit 1).
With the taint rules, Semgrep and OpenGrep report `views.py:9` in the committed (safe) state *and* in the edited
state, so the diff contains nothing new: the regression is invisible, and the safe state already carried a false alarm.
This is the guardrail case for AI coding agents, where the agent edits a helper and never opens its callers.

### 7. Hiding where a function comes from
Real code rarely calls `module.function()` plainly. The hold-out has `from helpers import *`, a factory (`repo = make_repo()`),
a `@/services/shell` alias from tsconfig `paths`, an `export default class` with a static method, a decorated helper
(`functools.lru_cache`), a FastAPI `Depends(get_repo)`, a Nest controller -> service -> repository chain whose source is a
`@Query('name')` parameter, and `module.exports = function (file) {...}`. Frame resolves each from evidence in the code (an
import's `__all__`, what every `return` of a function builds, `compilerOptions.paths`, the decorator on the parameter) and leaves a
receiver unresolved when the evidence conflicts. All fourteen hold-out cases are found with no false alarm; CodeQL finds ten and
misses the FastAPI dependency, the router/service object, the Nest chain and the JS factory; Semgrep and OpenGrep intrafile taint rules find one, OpenGrep's interfile build three.

### 8. A query object built from request data
`const filter = { origin: req.body.tags }; col.find(filter)`: a NoSQL operator-injection shape (`{"tags": {"$ne": null}}`) that hides the request read
inside an object literal. Frame taints the object (and `filter.origin = req.body.tags` stores), keeps `{ n: parseInt(req.body.n) }`
clean, and reports vulnerable-node's `shop.js:41` and `:58`, both documented. CodeQL finds the same two.

### 9. Validated is not the same as tainted
The same data can be safe after a check. Frame recognises a same-origin redirect guard (`startsWith('/') && !startsWith('//')`, either
shape), a constant `/path` prefix, membership in a constant allowlist (`Object.values(DOCS).includes(file)`), `jwt.verify` (a verified token is the intended use),
and a template that escapes the key being rendered. On vulnerable-node it stays silent on the app authors' clean seed and on the allowlisted
`/labs/docs/:file`; CodeQL is silent on the allowlisted route too but reports the clean seed's redirect.

### 10. Packages, interfaces and Spring layers (Java)
Java cross-file means resolving a call the way the compiler would: the receiver's declared type, looked up through the file's explicit
imports, its package and its `import pkg.*` lines; a method found on the class, else on the nearest project superclass, else -- for an
interface or an abstract type -- on its one implementation in the project. Frame resolves exactly that and stops where the code does not decide:
two implementations of an interface, or an overload the argument types cannot choose, stay unresolved instead of being guessed. It also analyses
`new ProcessBuilder(cmd).start()` as two calls (the creation is a sink), which a plain method-name lookup never saw. On WebGoat (498 Java files) a
project scan takes about 37 seconds and adds three reports to the single-file scan.

## Not covered

Cross-file taint is documented as a **Semgrep Pro Engine** feature ([docs](https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-data-flow))
and Snyk Code has announced interfile data-flow analysis (for example [Ruby](https://updates.snyk.io/snyk-code-ruby-interfile-ga/)).
Both need an account, so we did not run them, and SonarQube, Checkmarx, Veracode, Fortify and the AI-native scanners are likewise untested.
If you can run one, `run_comparison.py` takes a new adapter in about ten lines (see `bandit()`); send us the numbers.

## Reproduce

```bash
pip install -e ".[dev]"
python benchmarks/exemplars/run_comparison.py                      # Frame only, controlled cases
python benchmarks/exemplars/run_comparison.py --controls --semgrep semgrep --opengrep opengrep   # rules fire on controls
python benchmarks/exemplars/run_comparison.py \
    --semgrep semgrep --opengrep opengrep --opengrep-interfile ./opengrep-interfile --bandit bandit \
    --codeql ~/codeql/codeql \
    --stock-config p/default --stock-config p/python --stock-config p/javascript \
    --stock-config p/typescript --stock-config p/security-audit --stock-config p/owasp-top-ten
python benchmarks/exemplars/run_comparison.py --holdout ...                  # the blind hold-out
python benchmarks/exemplars/run_comparison.py --java ...                     # the Java cases
python benchmarks/exemplars/run_comparison.py --real --repos-dir /tmp/repos ...   # the four apps
python benchmarks/exemplars/use_cases/helper_edit_regression.py --semgrep semgrep --opengrep opengrep
```

A full run of one table takes about 15 to 30 minutes (registry rule packs are fetched per scan; each CodeQL database takes about 45 s).
CodeQL is not bundled: its licence limits use to OSI-licensed code and demonstrations, so install your own.
Stock registry packs change over time, so expect small drift in the stock columns.

## Adding a use case

1. Add `cases/<id>/vulnerable` and `cases/<id>/safe`: the same structure, one real flow, and a twin with no flow.
2. Add the sink (file, line, CWE, hops, shape) to `cases.json`. For a real app, add it to `real_repos.json` with a pinned commit and read both ends before listing a sink; put debatable ones under `ignore`.
3. Make sure the custom rules can express it (add a control in `controls/` if a rule is new), so a miss is the engine's.
4. Run the harness, put the numbers in the tables above, and write the use-case entry, including who else got it.
5. Date it below.

## Log

- 2026-10: first release: 9 controlled cases, 4 real apps, 1 diff scenario; Frame 9/9 and 10/10, CodeQL 7/9 and 7/10.
- 2026-10 (second pass): blind hold-out added (Frame 7/14 first run, 14/14 after the fixes it drove; CodeQL 10/14); labelled triage of every Frame and CodeQL report on the four apps;
  the vulnerable-node authors' seed key; resolution for factories, star imports, tsconfig aliases, Nest decorators, default-class statics; NoSQL query objects, redirect and allowlist guards.
- 2026-11: the cases' handlers are registered as an application does (`js_constructor_dao`, `ts_class_service` gain the
  `app.js` / `app.ts` that wires them; JS/TS request data comes only from registered handlers), three hold-out cases define
  the database handle they use (above), and the runner gives a cloned app the project root `frame scan DIR` takes (the
  git top level: NodeGoat's `server.js` hands `app` and the MongoDB `db` to `app/routes`).
- 2026-10 (third pass): hardening findings (debug mode, explicit insecure cookie flags); Java cross-file support (Frame 1/10 -> 10/10 on cases keyed first; CodeQL 10/10 with 3 false alarms); OWASP BenchmarkJava +18 correct CWE-330.
