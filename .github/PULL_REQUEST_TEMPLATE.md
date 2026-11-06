## What this changes

<!-- One change per pull request. What does it do, and why? Link the issue if there is one. -->

## How it was validated

<!-- Tests added or updated, and the commands you ran. -->

- [ ] `python -m pytest tests/ -n auto` passes
- [ ] `ruff check frame tests benchmarks` passes
- [ ] New behaviour and regressions have tests (a positive paired with the nearest safe idiom, for detection changes)

## Detection changes

<!-- Delete this section if the change does not affect what Frame reports. -->

- [ ] Benchmark results are unchanged, or the movement is listed below with the reason
- [ ] No framework or benchmark knowledge was added to the engine (it belongs in a pack, a spec table, or `benchmarks/packs/`)

## Documentation

- [ ] User-facing changes are documented (README, `docs/`, an example with real output); new flags, settings and variables are in `docs/usage.md`
