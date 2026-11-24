# The AI layer: detect, triage, hunt, exploit, fix

Structural analysis cannot reach everything: frameworks it does not know, flows that depend on context, and flaws that turn on intent, such as who should be allowed to read which record. The AI layer adds a model at those points, and the symbolic engine grounds it at every stage. It is optional: every command works without it.

<p align="center">
  <img src="../assets/how-it-works.svg" alt="Frame pipeline: source code flows through DETECT, TRIAGE, EXPLOIT, and FIX" width="620">
</p>

| Stage | Command | What the model does | What keeps it honest |
|---|---|---|---|
| Detect | `frame scan --ai` | explores the repository with file and search tools and traces flows across files; also covers languages with no symbolic frontend (PHP, Ruby, Go) | a finding grounded in a sink Frame recognises is `llm-verified`, otherwise `llm-detected`; never merged with the engine's findings |
| Triage | `frame scan --ai` | drops confident false positives | a finding is kept unless the model names the control that mitigates it |
| Hunt | `frame scan --hunt-authz` | audits authorization and business logic, unit by unit ([below](#hunting-authorization-flaws---hunt-authz)) | a finding needs the invariant and a concrete violating request; the engine's facts decide its tier |
| Exploit | `frame exploit` | builds and runs a proof of concept against a live target you are authorized to test | it stops only on observable success (`--success-check '<cmd>'` for an external oracle) |
| Fix | `frame fix` | writes a patch | the patch is kept only if a re-scan shows the bug gone and nothing new |

## Setting it up

Any OpenAI-compatible endpoint works: a local server, a hosted open model, or a frontier API. The endpoint and model come from the environment or from the `[llm]` table of `.frame.toml`; the variables win over the file.

```bash
export FRAME_LLM_BASE_URL=http://localhost:47317/v1     # any OpenAI-compatible endpoint
export FRAME_LLM_API_KEY=                                # empty for local servers
export FRAME_LLM_MODEL=mlx-community/Qwen3.6-35B-A3B-OptiQ-4bit

frame scan src/ --ai                                     # symbolic + LLM detection + triage
frame scan src/ --hunt-authz                             # the authorization hunt
frame scan ./repo --ai -f json | \
  frame exploit --target http://app:8080 --guidance - --goal 'read /etc/secret'
frame fix app.py --guidance findings.json --diff         # patch, re-scan, confirm
```

```toml
# .frame.toml
[llm]
base_url = "https://openrouter.ai/api/v1"
model = "anthropic/claude-haiku-5.5"
api_key_env = "OPENROUTER_API_KEY"   # the variable that holds the key; never the key itself
stream = true
```

Frame speaks both wire formats. An OpenAI-compatible endpoint (OpenRouter, OptiQ, vLLM, llama.cpp, MLX) takes chat completions; Anthropic's own endpoint takes the Messages API, chosen automatically for `base_url = "https://api.anthropic.com/v1"` (`[llm] api` forces either). On the Messages API the agents' prompts are cached: each turn reads the conversation so far from cache, so a hunt unit pays full price only for what is new (in our runs, 84 to 87% of input tokens came from cache with Claude Haiku 5.5). Anthropic's OpenAI-compatible layer caches nothing, so point Frame at the native endpoint rather than at `/v1/chat/completions`. A long agent conversation is compacted by the API itself there (threshold compaction): Frame sends the history unedited, so the thinking blocks of earlier turns stay valid and the cached prefix stays intact. On OpenAI-compatible endpoints, which also cache by prefix (OptiQ, vLLM, llama.cpp, MLX), Frame compacts rarely and in large steps for the same reason.

```toml
[llm]
base_url = "https://api.anthropic.com/v1"
model = "claude-haiku-5-5"
api_key_env = "ANTHROPIC_API_KEY"
```

Everything else about the model (timeouts, streaming, retries, agent budgets, waiting out an outage) is a key of `[llm]`, listed in [usage.md](usage.md#configuration); [`examples/configs/ai.toml`](../examples/configs/ai.toml) is a starting point. `--model` overrides the model for one run. A directory scan gives the agents' file tools the scanned directory as their root (`--root` names another).

With a hosted endpoint, code snippets leave the machine; a server on your own machine keeps them local ([below](#local-on-apple-silicon)).

On the [Endor Labs corpus](../benchmarks/endor_corpus/README.md), detection plus triage reaches 0.67 recall at 0.51 precision (Semgrep: 0.52 / 0.40); the model recovers about 65 vulnerabilities in Java, JS/TS and C# that both the engine and Semgrep miss.

## Hunting authorization flaws (`--hunt-authz`)

Broken access control turns on intent: who should be allowed to do what to which object. A dataflow engine cannot decide that alone, and a single agent left to roam a repository spends its budget where its curiosity takes it (3 of 30 BAC-Bench advisories in ABSENTIA's measurement). `frame scan DIR --hunt-authz` hunts for IDOR, missing authorization, privilege escalation, mass assignment and client-controlled server values with the engine directing the work and answering the agents' questions.

On [BAC-Bench](../benchmarks/bacbench/REPORT.md), 30 real advisories in 25 open-source apps, the hunt with Claude Haiku 5.5 finds 22 of 30, against 19 for ABSENTIA and 0 for CodeQL and Semgrep. It pairs fewer with the fix (11 against 17): on the fixing commit its agents often report a different flaw in the same function.

### How it works

1. **Scouts map the application.** The repository is split into areas (a monorepo's packages, a large app's directories), and one scout per area lists every route a remote caller reaches, every service function that reads or changes stored data, and every authorization helper. When the engine does not see routes a scout found, the scout writes a [framework pack](coverage.md#teach-it-your-own-framework) for the convention; the pack schema accepts or rejects it, and the engine rescans with it. Taught packs are saved with the trace (`scout/taught-N.toml`), ready to keep in `.frame/packs/`. The scouts' summaries become the authorization profile every later agent reads.
2. **The engine plans units.** Handlers are grouped into small units (a class's handlers, or a file's functions, so a check one sibling lacks stands out). The service functions and authorization helpers the handlers delegate to get units of their own, and so does anything the scouts found that the engine still does not cover. A handler a framework base class serves without the class writing it (a Django REST Framework `ModelViewSet`'s `list` or `update`) is a member too, described by its pack's `[[provided_action]]`. Units are ranked by engine facts only: an unverified authorization candidate, data access without a gate, siblings that disagree about protection.
3. **One agent per unit, with the engine as a tool.** Each unit gets a fresh agent (8 at a time by default). Besides reading and searching code it can ask the engine: `guards` lists the checks that hold on every feasible path to a data access, `check` proves or refutes one (a refutation comes with a path that avoids it), `siblings` puts the neighbouring handlers' checks side by side, `callees` and `callers` follow the call graph into the service layer, `trace` shows which request values reach which data access, and `engine_scan` runs the solver-verified engine on another file.
4. **A verdict on every member.** The agent is sent back if it stops with a member undecided. There are three verdicts:
   - `report_finding`: requires the invariant the code should guarantee and a concrete request that violates it (who sends what, to which endpoint, with what they already have). A claim that cannot be turned into such a request is not recorded.
   - `mark_safe`: requires the check that enforces the invariant, or why the endpoint is public by design.
   - `mark_unresolved`: for an answer that depends on something the repository does not hold (a configuration value, the roles a deployment assigns, a library's behaviour). It must state the suspected flaw, where the agent looked, and the fact that would decide it. It is not a finding; it is listed for a person to settle, rather than hidden behind a confident "safe".
5. **Coverage before finishing.** Agents follow a handler into the code it relies on. A file that two or more units read to reach their verdicts, and that no unit owns, is a layer those verdicts depend on that nobody was asked to judge, so it gets a unit of its own after the first wave. In BAC-Bench, two of the misses were exactly this: four units each read parse-server's `enforceRoleSecurity` and strapi's document-service repository, and none audited them.

A finding the engine's facts corroborate (the handler reaches data and is not protected) is `llm-verified`; one that rests on intent alone, or on code only a scout found, is `llm-detected`. Only a solver-verified engine finding suppresses an agent's finding at the same place. Where Frame has no frontend for the language, one agent hunts the repository with search and file tools instead, and every finding is `llm-detected`.

### Running it

```bash
frame scan . --hunt-authz -f json -o findings.json
```

The output has a `hunt` section beside the findings (JSON key `hunt`): how the hunt ended (`stop`: `finished`, `partial`, `transport_error`, `exception`), the units audited and deferred, the coverage units, and every `unresolved` member with its file, line, suspicion and the fact that would decide it. A hunt that did not finish is warned about on stderr, so an endpoint that went down is never read as a clean result.

The budgets are the `[hunt]` table ([usage.md](usage.md#configuration), [`examples/configs/hunt.toml`](../examples/configs/hunt.toml)):

| Key | Default | |
|---|---|---|
| `concurrency` | 8 | unit agents at once |
| `unit_steps` | 24 | tool turns per unit |
| `max_units` | all | units audited; the rest are listed as deferred, never dropped silently |
| `scout_steps`, `max_scouts` | 30, 16 | turns per scout and scouts per repository; `scout_steps = 0` turns scouting off |
| `coverage_readers` | 2 | how many units must have read unowned code for it to get a unit; 0 turns the coverage wave off |
| `trajectory_dir` | | keep every agent's trace (HF Session-Trace JSONL); an interrupted run resumes from it |

For long unattended runs, set `[llm] outage_wait` so a network drop is waited out instead of ending the hunt. The Python API takes the same budgets as `FrameScanner(hunt_authz=True, hunt_options={...})`, plus `verdict_cache`: a JSON file that reuses a unit's verdicts on another checkout when every file its agent read is unchanged.

A hunt is as expensive as the application is large: one agent per unit, every unit audited by default. On BAC-Bench the 60 checkouts took about 15.5 hours of scan time on an 8-core machine, much of it the engine's pre-scan of the largest Django apps. `max_units` bounds it.

## Hunting business-logic flaws (`--hunt`)

The same pipeline hunts other flaws of intent, one class at a time. `frame scan . --hunt limits,race` (or `[hunt] classes`) picks them:

| Class | What it hunts | The engine's part |
|---|---|---|
| `authz` | the authorization hunt above (`--hunt-authz`) | handler facts, guards, identity scoping |
| `limits` | a number the caller chooses reaching stored state or money without its bound: a negative quantity, a refund above the price, a discount over 100%, NaN past a guard; and a value the server should take from its own records (a price, a total, a plan id that must belong to the item bought: CWE-472) | `check` decides `lower_bound` / `upper_bound` with Z3 and names the value that gets through |
| `race` | read, decide and write without a lock or an atomic statement: a balance spent twice, a coupon redeemed twice | data reads and writes per handler; `check atomic_write` |
| `workflow` | a required state or step skipped, a one-time token (reset link, invite, coupon) accepted again | `check guarded_by` the state check, `siblings` |
| `replay` | a state change accepted twice: no nonce, idempotency key or status check | `check guarded_by` the check |
| `bruteforce` | a password, one-time code or PIN checked with no attempt limit | the handlers that compare a guess with a stored secret ([`credential-checks.toml`](../frame/sil/specs/data/credential-checks.toml)); `check attempt_limit` |

`logic` is every business-logic class, `all` adds authorization. Each class brings its own instructions and its own way of ranking units from the engine's facts, never from names: `limits` ranks a unit by the client numbers its handlers convert or take as typed parameters, `bruteforce` by a credential check. A unit is audited once per class its facts make it matter for, by a fresh agent with that class's instructions, and the classes share a `max_units` budget in turn. Verdicts, unresolved members, coverage and the `hunt` output section work as for authorization (the `hunt` section lists the `classes`).

Business rules are enforced where the server acts, so a class audits a unit only when one of its members is an entry point or reaches stored data (itself, or through a function it calls). That applies to units the scouts found and to coverage units as well. Browser code (a page, a hook or a client store, which stores nothing; a module marked `"use client"`), a view that only returns markup and writes nothing, code no request reaches, and test code are not audited. A request reaches a file that holds an entry point (one the engine knows, or a route the scouts found that is not browser code), and every file such a file calls, transitively; a migration, a seed script, or a store or hook that only components call is outside it. A unit gets the base score without engine facts only when the engine has no program for any of its members, and not when the engine parsed their files and those files are browser code or unreached (a store method written as a wrapped class field, `getRole = computedFn(...)`, has no procedure of its own name, but its file still says where it runs). A finding needs a caller who gains something. A value that only an administrator, or the owner of the record, can set is not a flaw when it harms only that person. One flaw reported both at a handler and at the service function it calls becomes one finding, kept where the value is stored. For missing limits, a unit needs a number the caller chooses or a write: a create, update or delete the engine recognises (Django's `Model.save()`, a REST framework serializer's `save()`, ORM create and update calls) or a SQL, NoSQL or ORM query, which may write. An endpoint the engine knows only selects records is not audited for limits. An entry point that hands client data to a call is audited even when the engine sees no number and no data access (one that only formats what it was sent, such as a page title, is not), because a price or plan id is often text and is checked against a store the engine may not model. A declared number type counts as a client number in every language, Python annotations (`amount: float`) included. A limit the server sets for the caller (a rate limit, quota or plan tier stored as a field the caller can write) is a bound too, and a caller raising their own is a gain; an endpoint that merely lacks a rate limit, throttle or captcha, or a missing authentication check, is not a missing limit. Scouts never record browser code (pages, hooks, client stores, calls to the app's own API) as routes or data access, and finish early on an area that is all browser code.

A business-logic finding is `llm-verified` only when an engine check the agent ran in that function refuted the bound or the guard: the engine found a feasible path on which the caller's value is outside the bound (or the state check is skipped). The witness is in the finding's description (`engine: order.quantity = 0 reaches line 11 on a feasible path`). Everything else is `llm-detected`. For `race` it is `check atomic_write` at the write. It is refuted when the function reads stored data first and neither it nor any caller locks the row, checks a version or writes in a way the database re-checks. It is also refuted when the write is computed from the stored value (an increment) but the code decided on that field's old value first: `if (link.nbAccess >= link.limitAccess) throw` and then an atomic `nbAccess + 1` lets two requests both pass the check. Writes are read three ways: plain; atomic, computed from the stored value (Django's `F()`, TypeORM's and Sequelize's `increment`, MongoDB's `$inc` and array operators, Prisma's `{ decrement: 1 }`, SQLAlchemy's `values(n=T.n - 1)`, Drizzle's `set({ n: sql`${t.n} + 1` })`, EF Core's `SetProperty(x => x.N, x => x.N - 1)`, `SET n = n - 1`); and conditional, re-checking the value they change: a `where` (Prisma, Sequelize, Drizzle, SQLAlchemy, EF Core's `ExecuteUpdate`), a Django `filter()` or a MongoDB filter on the field the update changes, SQL whose WHERE tests a column it sets, `INSERT ... ON CONFLICT DO NOTHING`, or a version field on the entity it saves (JPA and Spring Data `@Version`, EF Core `[ConcurrencyCheck]` / `[Timestamp]` or the same token configured with `IsRowVersion()` / `IsConcurrencyToken()`, a Mongoose schema with `optimisticConcurrency: true`). A property assigned on an entity the function loaded is a write where it is assigned when a save of the tracked changes follows (EF Core's `SaveChanges()`, SQLAlchemy's `commit()` / `flush()`). Locks count before the first read: Django's `select_for_update`, SQLAlchemy's `with_for_update()`, TypeORM's `setLock`, JPA's `EntityManager.lock`, Sequelize's `findOne({ lock })`, knex's `forUpdate()`, `SELECT ... FOR UPDATE` (Prisma's `$queryRaw` included), `LOCK TABLE`, advisory locks. A lock taken after a read also proves the write when that read only chose which rows to lock and the code reads them again under the lock. So does a claim before the reads: a write only one request can make (an insert that does nothing on a conflict, an upsert of a fixed key that sets values only on insert) whose result the code checks before going on. Reads, writes and locks made through the application's own functions (a repository, a service helper, a lambda handed to `flatMap`) count where those are called, up to five calls deep. All of it is pack data (`[[concurrency]]` entries with call ids, `keys`, `filter` / `update` selectors, `self_reference`, `statement`, `tracked`), and a transaction alone is never a protection. For `bruteforce` it is `check attempt_limit` at the function that compares the guess: `proved` when a limiter covers it (a rate-limit decorator or annotation on it or its class, limiter middleware in its own route registration, a call in it or a function it calls that spends an attempt, or every caller so covered), `refuted` when it compares a guess with a stored secret and nothing in it, its class, its route, its callers or the application's configuration limits attempts, and it writes no stored data. A limiter installed for the whole application (`app.use(limiter)`, a module's global guard, Flask-Limiter's defaults, django-axes in `MIDDLEWARE`), a class attribute such as REST framework's `throttle_classes`, some callers covered and others not, a write of stored data or of a cache or Redis on the path (an attempt counter the application keeps itself; a session counter does not count, since the caller drops the cookie), a check made inside a function handed to the project's own code (`loginThrottle.VerifyAsync(() => VerifyPassword(pw))`, which decides when it runs), or a check known only from a library base class (Django's `LoginView` calls back into the project's form) make it `unknown`. What limits attempts is pack data (`[[rate_limit]]`, kinds `decorator`, `middleware`, `call`, `global`, `exempt`, `attribute` and `state`; the `rate-limits` packs cover django-ratelimit, Flask-Limiter, slowapi, REST framework throttles, django-axes, express-rate-limit, express-slow-down, express-brute, koa-ratelimit, @fastify/rate-limit, rate-limiter-flexible, @nestjs/throttler, Resilience4j, Bucket4j, Guava and ASP.NET Core rate limiting). A limiter outside the code, such as a proxy or an API gateway, is not visible, so `refuted` is a claim about the application.

A value the client sends without conversion is a number to the engine only when the code uses it as one: it computes with it (`-`, `*`, `/`, `%`) or compares it with `<`, `<=`, `>` or `>=`. An id that is only tested for presence or equality is text, so a bound on it is `unknown`.

The bound check is also a plain engine query, with no model: `frame query . check --name add_item --line 11 --kind lower_bound --var order.quantity --bound 1` ([usage.md](usage.md#frame-query-dir-tool)).

### Invariants as data (`--save-invariants`)

What an agent learns once can be checked on every later scan with no model. `frame scan . --hunt limits --save-invariants .frame/packs/invariants.toml` writes the rule behind each engine-backed finding as an `[[invariant]]` pack entry. An entry is written only when the refuted check names a write the engine can find again: the field the checked value is stored in, or the write a guard was missing from. Before it is saved, it is checked again and must be refuted on the same code. Entries already in the file are kept. From then on every scan that loads the pack checks the rule without a model, and the scan fails in CI like any other finding:

```toml
[[invariant]]
id = "add-item-quantity-missing-limit"
kind = "bound"              # a bound on a stored field: min and/or max
model = "Order"             # optional: only that class's field
field = "quantity"
min = 1
function = ["add_item"]     # where the agent established it; drop it to hold everywhere
cwe = "CWE-1284"
description = "an order holds at least one item"

[[invariant]]
id = "ship-after-payment"
kind = "guarded"            # a state a write requires
field = "status"
value = "shipped"           # optional: only writes of this literal
guarded_by = "paid"         # a condition every path to the write passes (as `check guarded_by`)
```

A field is written by an assignment (`order.quantity = q`), a keyword or named argument (`Order.objects.create(quantity=q)`), a setter (`order.setQuantity(q)`, `set_quantity`), or a JavaScript object literal that holds only that key (`Order.create({ quantity: q })`). With several keys the lowering keeps no value per key. `model` holds when the object is of that class by evidence: a declared type, the class of `self` / `this`, the call that produced it, or the call's own name. A `guarded` entry can name `call` globs (`*.refund`) instead of a field.

The verdicts are the hunt's own checks. A client-chosen value outside the bound, or a feasible path to the write that skips the guard, is a `business_logic_flaw` with the entry's CWE (default CWE-1284 for a bound, CWE-841 for a guard), at `solver-verified`. A write the engine cannot decide, such as a value computed or read from storage, is a warning. A full scan in which an entry meets no write warns that it checks nothing (a renamed function or field) and lists it under `invariants.stale` in the JSON. Invariants are checked for Python, JavaScript/TypeScript, Java and C#. [examples/business-logic](../examples/business-logic) has a pack and its output.

## Proof-carrying findings (`--confirm-proofs`)

When the symbolic engine proves a finding reachable it also computes the concrete inputs that reach it. `frame scan --confirm-proofs` turns those inputs into a test, runs it, and raises the finding to the `exploit-confirmed` evidence level only when the fault is actually observed. A finding with a reproduced test is a true positive by construction. This step runs compiled code, so it is opt-in; it uses no model and no network, and never contacts a live target.

Today it covers the C integer-overflow and out-of-bounds findings (CWE-190/191/194/195/197 and CWE-125/787/124/127), whose trigger is an attacker integer leaving a range. Each such finding carries a `proof` in the JSON: the solver's `witness` (the concrete values), the `inputs` restricted to the function's parameters, whether it is directly `constructible` (every triggering value is a scalar parameter, so the function can be called with them), and the triggering condition.

```bash
frame scan src/ -l c --confirm-proofs --proof-tests-dir tests/frame-proofs
```

For each directly constructible finding, Frame compiles the file with a `main` that calls the function with the witness inputs, under AddressSanitizer and UndefinedBehaviorSanitizer, and runs it. An observed fault (a sanitizer report or a non-zero exit) confirms the finding and records the run on its `proof`; anything else (a function that does not compile on its own, a guard that makes it safe, no compiler) leaves the finding exactly as it was. With `--proof-tests-dir`, each confirmed finding's reproduction test is written there as a self-contained C file: a regression guard that must stop faulting once the bug is fixed.

A finding whose triggering value is not a function parameter (for example an integer read from stdin) still records its witness, but is not directly constructible: calling the function alone will not reach it. `--reproduce-proofs` (which implies `--confirm-proofs`) handles those with a small seeded agent. The agent is given the source and the solver's witness and asked to write a complete reproduction program that drives the real input path so the fault fires; the harness compiles and runs it under the same sanitizers, and the loop stops only on an observed fault, never the model's claim. A reproduced finding is raised to `exploit-confirmed` and, with `--proof-tests-dir`, its program is written there. This uses the `[llm]` endpoint and runs a model, so it is opt-in; it still runs only against your own code in a local sandbox, with no live target.

### Dependency reachability as a runnable test (`frame exploit --deps`)

When `frame scan --sca` finds attacker data reaching a vulnerable library function in your own code (`reachability: tainted`), `frame exploit --deps` turns that into a test you can run. Give it the findings JSON and the project:

```bash
frame scan ./app --sca -f json -o findings.json
frame exploit --deps --guidance findings.json --root ./app --out-dir tests/frame-proofs
```

For each reachable finding a seeded agent explores the project, finds the entry point that leads to the vulnerable call, and writes a driver that passes a marker through it. A harness installs a spy on the vulnerable function and confirms the marker arrives there through the project's own code: calling the library function directly does not count (the flagged call site must be on the runtime stack), so the agent cannot fake the result. Each confirmed finding is written as a self-contained pytest that imports your entry point, spies on the vulnerable function, and asserts attacker data reaches it. The same command reproduces code injection flows (SQL injection, command injection, XSS, path traversal, SSRF and the other taint findings in the JSON, which records each finding's `sink_call`): the sink -- a module function like `os.system`, a class method like a DB cursor's `execute`, or an HTML-marking call like `Markup` -- is spied the same way, so the test proves attacker data reaches the injection point through your code. Reproduction runs for Python and JavaScript/TypeScript projects (the JS sink, e.g. `child_process.exec` or an installed package's function such as `js-yaml`'s `load`, is spied in Node), and for Java and C# projects via a generated test that spies the sink INTERFACE (the dependency-injection seam): Java uses a core-JDK `java.lang.reflect.Proxy` (just a JDK, no Maven), C# uses xUnit + Moq (the .NET SDK). Both drive the project to the sink and confirm the marker arrived through the project's own code. A non-interface or JDK-bootstrap sink is left for the agent-based runner. Worked reproductions across languages are in [`benchmarks/exemplars/reproductions/`](../benchmarks/exemplars/reproductions/README.md). Drop it into your test suite: it passes while the reachable flow exists and fails once a fix removes it. To check a fix directly, add `--check-fixed DIR` with a fixed copy of the project: after a reproduction is confirmed, Frame re-runs the same driver against `DIR` and reports the fix as verified only when the reproduction no longer reaches the sink, so the proof of the vulnerability becomes a proof of the fix:

```bash
frame exploit --deps --guidance findings.json --root ./app --check-fixed ./app-fixed
```

The test proves reachability, so it flips for a fix that removes the flow (validation that rejects the attacker's value, a switch to a safe API, a dropped call). A fix that keeps the data reaching the sink but makes it safe (escaping in place, or a dependency upgrade that keeps the same call) does not flip it; confirm those with a re-scan or `frame verify`. This runs a model (the `[llm]` endpoint) against your own code in a local sandbox; there is no live target.

## Choosing a model

### Hosted

Open frontier models such as GLM are strong at security work: reading unfamiliar code, tracing flows and writing working exploits. The XBOW / ZeroPath results ran on GLM-5.2, CVE-Bench's exploits too (DeepSeek detected and fixed there), and BAC-Bench on Claude Haiku 5.5. With [mlx-optiq cloud](https://cloud.mlx-optiq.com), create an API key and point Frame at it:

```bash
export FRAME_LLM_BASE_URL=https://cloud.mlx-optiq.com/api/v1
export FRAME_LLM_API_KEY=sk-optiq-cloud-...              # from the dashboard's API keys page
export FRAME_LLM_MODEL=glm-5.3-flash                     # or glm-5.3 for the hardest repos

frame scan src/ --ai
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

Then use the local endpoint from [Setting it up](#setting-it-up) (`http://localhost:47317/v1`, empty key).

## Fixing vulnerable dependencies in code

When an upgrade is not possible yet (`frame deps --apply` does upgrades), `frame fix --deps` changes how the code uses the vulnerable function and leaves the version alone:

```bash
frame kb pull --advisories
frame fix src/ --deps --diff          # each call site attacker data reaches (frame scan --sca)
frame fix src/ --deps --in-place      # write only the verified patches
```

Every patch is verified by re-running the whole analysis on a patched copy of the project: it is kept only if attacker data no longer reaches the vulnerable function (or the call is gone) and the file has no new finding. A character-class check in front of the call is not enough (a long digit string is still a ReDoS input); a constant allowlist or the library's safe equivalent (`yaml.safe_load`) is. `--include-called` also takes call sites without a flow, verified only when the call is gone. More in [dependencies.md](dependencies.md#fixing-in-code-when-you-cannot-upgrade).
