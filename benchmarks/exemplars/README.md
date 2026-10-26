# Exemplars: where Frame's cross-file analysis finds what other scanners don't

This folder is a living comparison. Each exemplar is a vulnerability whose **source and sink sit in
different files** (a handler reads request data, a helper module runs the query), the shape that
file-at-a-time scanners miss and that real code is full of. We run Frame and other scanners on the
same code, score them against an answer key we confirmed by reading both ends, and write down what
each tool does and why.

**Current headline** (Python, JavaScript, TypeScript; details and caveats below):

- On 9 controlled cross-file cases, each with a vulnerable tree and a structurally identical safe twin,
  Frame found **9/9 real flows with 0 false alarms**. CodeQL (the strongest comparator, with whole-program
  taint) found 7/9 with 1 false alarm. Semgrep and OpenGrep with taint rules found 1/9 (intrafile) or
  3/9 (OpenGrep's experimental interfile build). Their stock rule packs "found" 6/9 but flagged all
  6 safe twins too: those rules match the sink pattern, not the flow.
- On 4 deliberately vulnerable open-source apps at pinned commits, Frame found **10/10** of the
  cross-file vulnerabilities in the answer key. CodeQL found 7/10, tying Frame on vulpy and
  vulnerable-node and missing dvpwa and NodeGoat. The Semgrep/OpenGrep taint rules found 0/10
  (3/10 for OpenGrep interfile, on one app); stock packs found 7/10 by sink pattern, with 7 to 44 other reports per app.
- Not run: Semgrep Pro, Snyk Code, SonarQube, Checkmarx and other commercial tools (they need an account or server;
  see "Not covered"). Nothing here supports a claim about them.

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

The cases are written to exercise the shapes Frame resolves; they illustrate those shapes rather than form a blind benchmark.

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

## Real applications

Cloned at the pinned commits in `real_repos.json` at run time (never vendored). Cells are
`found/expected (+other reports)`.

| app | Frame | Semgrep (taint rules) | Semgrep (stock packs) | OpenGrep (taint rules) | OpenGrep (stock packs) | OpenGrep interfile (taint rules) | Bandit | CodeQL |
|---|---|---|---|---|---|---|---|---|
| `vulpy` | 3/3 (+1) | 0/3 (+0) | 3/3 (+24) | 0/3 (+0) | 3/3 (+24) | 0/3 (+0) | 3/3 (+19) | 3/3 (+6) |
| `dvpwa` | 1/1 (+1) | 0/1 (+0) | 1/1 (+7) | 0/1 (+0) | 1/1 (+4) | 0/1 (+0) | 0/1 (+2) | 0/1 (+1) |
| `vulnerable-node` | 4/4 (+40) | 0/4 (+2) | 3/4 (+44) | 0/4 (+2) | 3/4 (+44) | 3/4 (+12) | 0/4 (+0) | 4/4 (+40) |
| `NodeGoat` | 2/2 (+8) | 0/2 (+0) | 0/2 (+16) | 0/2 (+0) | 0/2 (+16) | 0/2 (+0) | 0/2 (+0) | 0/2 (+1) |

The expected sinks, each confirmed by reading source and sink:

- **vulpy** `bad/libuser.py` lines 12, 25, 53: SQL built with `format`/`%` in helpers that `mod_user.py` feeds from `request.form`.
- **dvpwa** `sqli/dao/student.py:45`: `Student.create`, a static async method, formats `name` into an INSERT; the value is aiohttp `await request.post()` in `views.py`.
- **vulnerable-node** `model/db.js` lines 14, 26, 101 (SQL injection, including an `ORDER BY` column) and `model/merge.js` (prototype pollution via a recursive merge fed `req.body` from `routes/account.js`).
- **NodeGoat** `app/data/user-dao.js` lines 91, 104: `findOne({userName})` with the value straight from `req.body` (NoSQL operator injection).
- Not scored either way: `benefits-dao.js:24` (request value inside `$set`; debatable) and `good/libuser.py:61` in vulpy.

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
python benchmarks/exemplars/run_comparison.py --real --repos-dir /tmp/repos ...   # the four apps
python benchmarks/exemplars/use_cases/helper_edit_regression.py --semgrep semgrep --opengrep opengrep
```

A full run takes about 15 minutes (registry rule packs are fetched per scan; each CodeQL database takes about 45 s).
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
