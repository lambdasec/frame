# Contributing to Frame

Thank you for helping. Frame is an open application security platform (code, dependencies, secrets, infrastructure, containers and AI applications) built on one engine, and most of what it knows is data that anyone can extend: a framework pack, a source or sink row, an advisory mitigation, a policy. This guide covers how to set up, what a good change looks like, and how it gets merged.

Questions about using Frame go in [Discussions](https://github.com/lambdasec/frame/discussions). To report a vulnerability in Frame itself, do not open an issue: follow [SECURITY.md](SECURITY.md).

## Ways to contribute

- **Report a false positive or a missed vulnerability.** These are the most valuable reports a scanner gets. Use the issue forms, and include the smallest code that shows it.
- **Teach Frame a framework or library** with a pack (a TOML file, no engine code).
- **Add a source, sink or sanitizer** to a language's spec table.
- **Fix a bug or improve a frontend, analyzer or the engine.**
- **Improve the docs**, or add a runnable example.

If you plan a large change (a new analysis, a new language or ecosystem, a new command), open an issue first so we can agree on the approach before you write it.

## Setting up

Frame needs Python 3.10 or later.

```bash
git clone https://github.com/lambdasec/frame && cd frame
pip install -e ".[dev]"            # the scanner grammars plus pytest, xdist, ruff, mypy, benchmark deps
python -m pytest tests/ -n auto    # the full suite, in parallel
ruff check frame tests benchmarks  # enforced in CI
mypy frame                         # informational for now, not enforced
```

Some tests need external toolchains and skip when they are absent: a C compiler for proof-carrying C findings, Node for JavaScript reproductions, a JDK and the .NET SDK for the Java and C# reproductions, and the real package managers for `tests/sca_real/` (run with `FRAME_SCA_REAL=1`). CI installs all of them, so a skip on your machine still runs in CI.

[`CLAUDE.md`](CLAUDE.md) (also `AGENTS.md`) is the detailed engineering map: how each part of the pipeline works, the conventions that keep it sound, and the bugs that taught us each one. Read the section for the area you are changing.

## Where things live

| Path | What it is |
|---|---|
| `frame/sil/frontends/` | tree-sitter frontends that lower Python, JavaScript/TypeScript, Java, C# and C/C++ to SIL |
| `frame/sil/specs/data/` | per-language source, sink and sanitizer tables, type models and other library facts (TOML) |
| `frame/sil/packs/data/` | built-in framework packs and IaC policy packs (TOML) |
| `frame/sil/translator.py`, `frame/sil/analyzers/` | taint, path-sensitive and memory-safety analysis |
| `frame/sil/scanner.py`, `frame/sil/cli.py` | the scan pipeline and `frame scan` |
| `frame/sca/` | dependencies: lockfiles, advisories, reachability, upgrade plans, SBOM, VEX, containers |
| `frame/iac/` | Kubernetes, Dockerfile, Terraform and CloudFormation readers and the policy engine |
| `frame/kb/` | the knowledge base (packs and advisories as versioned datasets) |
| `frame/core/`, `encoding/`, `checking/`, ... | the separation logic engine on Z3 |
| `benchmarks/` | benchmark harnesses, scoring and the exemplars |
| `examples/` | runnable walkthroughs, each checked by `tests/test_examples.py` |

## Principles every change follows

These are what keep Frame's findings trustworthy. Reviews check them.

- **Knowledge is data.** A framework's handlers, sources and sinks belong in a pack; a library's API facts belong in a spec table under `frame/sil/specs/data/`. The engine holds no framework or benchmark names (`tests/test_engine_without_framework_rules.py` checks this).
- **No benchmark-specific behaviour.** A change that improves a score must be a real improvement for real code. Never special-case a benchmark's files, names or harness in the scanner; harness facts go in `benchmarks/packs/`.
- **Facts, not guesses.** Decide from the syntax tree, a type, a value's origin or a solver question, never from a variable's name or a regular expression over source text. When Frame cannot tell, it leaves a call unresolved or a policy undecided rather than guessing.
- **Every finding carries its evidence.** Set the evidence level where the finding is made, and never claim more than was shown (a reproduction confirms only on an observed fault or a spy hit, never on a model's word).
- **Report everything; let scoring collapse.** The scanner reports every distinct finding. One-label-per-file benchmarks collapse in their scoring code, not in the scanner.

## Common contributions

### Teach Frame a framework (a pack)

1. Write a pack in `frame/sil/packs/data/<language>/<name>.toml`: what detects the framework (`[pack].detect`), its entry points, and any sources, sinks, sanitizers or propagators. The format is described in [Teach it your own framework](docs/coverage.md#teach-it-your-own-framework); `frame packs check` validates a pack.
2. Add a fixture in `benchmarks/exemplars/frameworks/<language>/<framework>/`: a `framework.toml`, a `vulnerable/` app with `frame-expect: CWE-n` markers on the lines that must be reported, and a `safe/` twin that must come out clean.
3. Run `python -m pytest tests/e2e/test_framework_packs.py -k <framework>`. It scans both apps through the real CLI, requires every marker and no unlabelled finding, and checks that the pack is needed (`--no-packs` must miss at least one marker).

### Add a source, sink or sanitizer

Add a `[[spec]]` row to `frame/sil/specs/data/<language>.toml` with only the fields that differ from their defaults. A sink kind must be a known kind or alias (`tests/test_sink_kind_resolution.py`), and a new finding type needs its entry in `frame/sil/specs/data/kinds.toml`. Add a test that pairs the new positive with the nearest safe idiom as a negative.

### Fix a false positive or a missed vulnerability

Start with a failing test: the reported code as a positive or negative case, in the test file for that area (for example `tests/test_python_recall.py`, `tests/test_js_recall.py`). Then fix the cause, not the symptom: a missing type, origin or guard fact, rather than a rule that matches this one snippet.

### Add a command, flag or setting

A `frame scan` flag goes in both argument parsers, `frame/cli.py` and `frame/sil/cli.py` (`tests/test_cli_frame_entrypoint_excludes.py` exists because this was missed once). A tunable is a key of `config.SCHEMA` in `frame/config.py`, never a new `FRAME_*` environment variable. Every flag, setting and variable must be documented in [docs/usage.md](docs/usage.md); `tests/test_docs.py` fails otherwise.

### Add a reproduction exemplar

A small project in `benchmarks/exemplars/reproductions/<name>/` with a `case.json` (the sink, the call site and a confirmed driver). An optional `fixed/` subdirectory holds a repaired copy, and the fix-loop test then requires the reproduction to stop triggering against it. See [the exemplars README](benchmarks/exemplars/reproductions/README.md).

### Change a dependency parser

Ground truth comes from the package manager itself, never from Frame. Add or refresh a case under `tests/sca_real/` (`python tests/sca_real/refresh.py`), and compare with the tool's own listing.

## Validating a change

- `python -m pytest tests/ -n auto` and `ruff check frame tests benchmarks` must pass.
- A change to detection must leave the benchmark sweep identical unless the change intends otherwise; say in the pull request which results moved and why. `python -m benchmarks run --curated` runs the solver suites; [benchmarks/README.md](benchmarks/README.md) lists every SAST, SCA and authorization suite and how to run it.
- A Java spec or frontend change should be checked on OWASP BenchmarkJava (`benchmarks/endor_corpus/score_benchmarkjava.py`): the per-file CWE set should not change unless intended.
- A solver change should be checked against every SL-COMP division.

## Documentation

User-facing changes update the docs in the same pull request: [README.md](README.md), the guides in [docs/](docs/README.md), and a runnable example in `examples/<name>/` for a new feature. Show real output from a real run, not an invented one. `tests/test_docs.py` checks that relative links and anchors resolve, and `tests/test_examples.py` re-runs each example README's commands. Write plainly, with commas, colons or parentheses rather than em dashes.

## Pull requests

- Keep a pull request to one change, with a title that says what it does.
- Describe what changed, why, and how you validated it, including any benchmark movement.
- Add tests for new behaviour and regressions.
- CI must be green: lint, the test matrix (Python 3.10 and 3.13), the cross-language reproduction job, the self-scan, and the package-manager job when SCA code changes.

A maintainer reviews every pull request. We may ask for changes to keep a contribution in line with the principles above; that is about keeping findings trustworthy, not about the contributor.

## License

Frame is licensed under [Apache 2.0](LICENSE). By submitting a contribution you agree that it is licensed under the same terms (section 5 of the license). Framework packs are Apache 2.0 and the published datasets are CC-BY-4.0.
