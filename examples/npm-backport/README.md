# Backporting a fix when you cannot upgrade

A small CLI that depends on `minimist@1.2.5`, installed (`node_modules/` is a real `npm install`). minimist 1.2.5 has a critical prototype pollution (GHSA-xvch-5gv4-984h, CVE-2021-44906), fixed in 1.2.6. When the upgrade is not an option (a pinned transitive version, a release you cannot take yet), `--backport` applies the advisory's own upstream fix commit to the version you have, as a [patch-package](https://github.com/ds300/patch-package) patch.

`--backport` fetches the advisory's OSV record and the fix commits from GitHub. This example ships them in `offline-cache/` (recorded from the OSV API and GitHub), so with `FRAME_BACKPORT_CACHE` set nothing is fetched:

```bash
cd examples/npm-backport
frame kb pull --advisories --source offline-advisories --project .
export FRAME_BACKPORT_CACHE=offline-cache
```

## The patch

```console
$ frame deps --vulns --backport
1 known vulnerability:
  CRITICAL minimist@1.2.5 (direct, imported) GHSA-xvch-5gv4-984h: Prototype Pollution in minimist; fixed in 1.2.6  [package-lock.json]

Backported fixes (dry run; --apply writes them):
  minimist@1.2.5: minimistjs/minimist@c2b981977fa8 applies (GHSA-xvch-5gv4-984h); not applied: minimistjs/minimist@34e20b846111: does not apply to 1.2.5 (error: patch failed: index.js:7); minimistjs/minimist@bc8ecee43875: changes no source file the package ships; minimistjs/minimist@ef9153fc52b6: does not apply to 1.2.5 (error: patch failed: index.js:6)
--- a/patches/minimist+1.2.5.patch
+++ b/patches/minimist+1.2.5.patch
@@ -0,0 +1,30 @@
+diff --git a/node_modules/minimist/index.js b/node_modules/minimist/index.js
...
+-            if (key === '__proto__') return;
++            if (isConstructorOrProto(o, key)) return;
...
--- a/package.json
+++ b/package.json
@@ -3,6 +3,7 @@
   "version": "1.0.0",
   "private": true,
   "scripts": {
+    "postinstall": "patch-package",
     "start": "node cli.js"
   },
...
manual: install patch-package once: npm install --save-dev patch-package
A patch that applies fits this version; it is not proof that it fixes it. Run the project's tests, and prefer the upgrade when one exists.
```

The advisory links four commits. One release line's fix does not apply to another's code: `34e20b8` and `ef9153f` are the fixes for minimist 0.x, and their hunks fail against 1.2.5's `index.js`. `bc8ecee` only adds a test. `c2b9819` is the 1.x fix and applies cleanly, so it is the patch: a commit's files are mapped to the package as published, files it does not ship and tests are left out, and each commit is kept only if it applies, in order, with `git apply --check`.

`--apply` writes `patches/minimist+1.2.5.patch` (patch-package's name and layout) and adds `"postinstall": "patch-package"`, so every `npm install` re-applies it. A different `postinstall` already there is left for you to combine.

## Does it fix it?

That the patch applies is evidence it fits 1.2.5, not that it fixes the vulnerability. Here it does, with the real tools (`tests/test_sca_backport.py` runs this in CI): the advisory's own proof of concept pollutes `Function.prototype` before, and not after `npm install` has run patch-package:

```console
$ node -e "var p=require('minimist'); p(['--_.concat.constructor.prototype.y','123']); function f(){}; console.log('polluted:', f.y)"
polluted: 123
$ frame deps --vulns --backport --apply && npm install --save-dev patch-package && npm install
...
Applying patches...
minimist@1.2.5 ✔
$ node -e "var p=require('minimist'); p(['--_.concat.constructor.prototype.y','123']); function f(){}; console.log('polluted:', f.y)"
polluted: undefined
```

The upgrade remains the better fix when you can take it (`frame deps --vulns --plan`). See [docs/dependencies.md](../../docs/dependencies.md#backported-fixes).
