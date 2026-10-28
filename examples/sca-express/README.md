# Dependencies end to end: an Express app

A small Express app (express 4.17.1, lodash 4.17.20, mocha 10.2.0 for tests), its `package-lock.json` written by npm 10, and one route that compiles a template the caller chooses. Every command below runs offline from this directory's recorded data, and every output shown is what it prints (`tests/test_examples.py` runs them and checks).

```bash
cd examples/sca-express
frame kb pull --advisories --source offline-advisories    # or plain `frame kb pull --advisories` for today's data
export FRAME_REGISTRY_CACHE=$PWD/offline-registry          # recorded npm metadata, for --registry
```

The advisories in `offline-advisories/` are the subset of the [advisories dataset](https://huggingface.co/datasets/lambdasec/frame-advisories) for this lockfile's packages (OSV data, CC-BY 4.0), recorded with `python examples/record_offline.py examples/sca-express`.

## 1. The graph

```console
$ frame deps
  package-lock.json  (npm lockfile): 127 packages, 3 direct
npm: 127 distinct packages (3 direct, 76 dev only)
```

## 2. Known vulnerabilities, and whether the code reaches them

```console
$ frame deps --vulns
37 known vulnerabilities:
  HIGH     body-parser@1.19.0 (transitive) GHSA-qwcr-r2fm-qrc7: body-parser vulnerable to denial of service when url encoding is enabled; fixed in 1.20.3  [package-lock.json]
           via express@4.17.1 -> body-parser@1.19.0
  ...
  HIGH     lodash@4.17.20 (direct, called) GHSA-35jh-r3h4-6jhm: Command Injection in lodash; fixed in 4.17.21  [package-lock.json]
           calls lodash.template at app.js:8
           calls lodash.template at app.js:14
```

`called`: the code calls `lodash.template`, the function the advisory names.

## 3. Is attacker data what reaches it?

```console
$ frame scan . --sca
1. [HIGH] 🟠 template_injection
   Location: app.js:8:8
Scanned 1 file: 1 finding (1 high)
  tainted: GHSA-35jh-r3h4-6jhm reached by attacker data at app.js:8 (solver-verified)
```

Line 8 compiles `req.query.tpl`, so the advisory is `tainted` there. Line 14 compiles a fixed template that only escapes (`<%- %>`), so it is called but carries no attacker data, and there is no finding.

## 4. Upgrade plans

Planned one package at a time, the packages express and mocha pin can only be overridden:

```console
$ frame deps --vulns --plan
  express 4.17.1 -> 4.20.0: raise the project's requirement  [package-lock.json; fixes 2]
  qs 6.7.0 -> 6.16.1: override: an `overrides` entry (npm), `resolutions` (yarn) or `pnpm.overrides`  [package-lock.json; fixes 5]
  ...
```

With the registry's metadata, Z3 solves every package's ranges together, and upgrading the packages in between replaces every override:

```console
$ frame deps --vulns --plan --registry
Upgrade plan (14 packages):
  express 4.17.1 -> 4.22.3: raise the project's requirement  [package-lock.json; fixes 2]
  lodash 4.17.20 -> 4.18.1: raise the project's requirement  [package-lock.json; fixes 5]
  nanoid@3.3.3: leaves the tree (no upgraded package depends on it)  [package-lock.json; fixes 4]
  qs 6.7.0 -> 6.16.1: re-lock to it (admitted by the solved upgrades)  [package-lock.json; fixes 5]
  mocha 10.2.0 -> 12.0.0 [major]: raise the project's requirement  [package-lock.json; lets diff, js-yaml, minimatch upgrade]
  ...

Edits (dry run; --apply writes them):
--- a/package.json
+++ b/package.json
@@ -3,10 +3,10 @@
   "dependencies": {
-    "express": "4.17.1",
-    "lodash": "~4.17.20"
+    "express": "4.22.3",
+    "lodash": "~4.18.1"
   },
   "devDependencies": {
-    "mocha": "10.2.0"
+    "mocha": "12.0.0"
```

Express stays on 4.x, because 4.22.3 admits every fix. `--apply --relock` writes the edits and re-locks with npm. On this project that leaves 37 fixed and 0 remaining, checked by `tests/test_sca_solve.py` against real npm.

## 5. Licences

```console
$ frame deps --licenses
Licences: 51 packages, 51 acceptable, 0 violation(s), 0 unknown
```

The policy is in `.frame.toml` (`deny = ["GPL-*", "AGPL-*"]`). Dev-only packages are not checked unless `include_dev = true`.

## 6. SBOM and VEX

```bash
frame deps --sbom cyclonedx -o sbom.json     # CycloneDX 1.6, components with package URLs and licences
frame deps --vex openvex -o vex.json         # 37 statements, each `affected` with the planned upgrade
```

See [docs/dependencies.md](../../docs/dependencies.md) for every option.
