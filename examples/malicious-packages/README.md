# Malicious packages, unmaintained crates and Python start-up hooks

Some advisories are not about a flaw with a fixed version. A malicious release already ran its
code when it was installed, so upgrading is not enough. An unmaintained crate will never get a
fix. Frame reads which kind an advisory is from the record's own fields: OpenSSF's `MAL-` ids,
GitHub's CWE-506 family (embedded malicious code), and RustSec's `informational` notices. It
gives advice to match.

`project/` pins agent-framework 1.26.1, one of the two releases published with a credential
stealer (MAL-2026-20101), and the unmaintained `adler` crate. `app-image/` is a container's
site-packages with the same release installed, with a harmless stand-in for its start-up hook.
`offline-advisories/` holds the real OSV records of
[tests/fixtures/sca/malicious](../../tests/fixtures/sca/malicious/README.md).

```bash
cd examples/malicious-packages
frame kb pull --advisories --source offline-advisories --ecosystems PyPI,crates.io
```

## Malicious releases

```console
$ frame deps project --vulns
...
2 known vulnerabilities:
  CRITICAL agent-framework@1.26.1 (direct, malicious) MAL-2026-20101: Malicious code in agent-framework (PyPI); malicious release: pin a release the advisory does not list and rotate every credential the machine or CI runner that installed it could reach  [requirements.txt]
  UNKNOWN  adler@1.0.2 (direct, unmaintained) RUSTSEC-2025-0056: adler crate is unmaintained, use adler2 instead; unmaintained, no fix will come: replace it (see the advisory)  [Cargo.lock]
```

The plan names the releases to avoid:

```console
$ frame deps project --vulns --plan
...
Upgrade plan (2 packages):
  adler@1.0.2: unmaintained, no fix will come; replace it with a maintained package (RUSTSEC-2025-0056: see the advisory)  [Cargo.lock]
  agent-framework@1.26.1: malicious release: pin a release other than 1.26.1, 1.26.2, then rotate every credential the machine or CI runner that installed it could reach (its code ran at install or start-up) (MAL-2026-20101)  [requirements.txt]
```

A package that is malicious in every release (a typosquat published only to steal, such as npm's
`m-backdoor`) is reported as `malicious package, every release: remove it`, and its plan says
the same. A malicious advisory that does name a fixed release gets the upgrade, plus the note
to rotate credentials.

## Start-up hooks

Python runs some files at every interpreter start, whether or not anything imports their
package: each `.pth` line in site-packages that starts with `import` (CPython's
`site.addpackage`), and `sitecustomize` / `usercustomize`. A credential stealer installed this
way runs even if the application never imports it. Frame lists every such file it finds in an
installed environment, with the distribution whose `RECORD` lists it:

```console
$ frame deps project --rootfs app-image --vulns
...
  app-image:/usr/local/lib/python3.12/site-packages  (PyPI image): 2 packages, direct unknown
    startup hook: agent_framework_init.pth runs 1 line at every Python start, imported or not (installed by agent-framework 1.26.1)
    startup hook: distutils-precedence.pth runs 1 line at every Python start, imported or not (installed by setuptools 80.9.0)
    startup hook: zz_unclaimed.pth runs 1 line at every Python start, imported or not (no installed package lists it)
...
  CRITICAL agent-framework@1.26.1 (dependency, malicious) MAL-2026-20101: Malicious code in agent-framework (PyPI); malicious release: pin a release the advisory does not list and rotate every credential the machine or CI runner that installed it could reach  [app-image:/usr/local/lib/python3.12/site-packages]
```

Many hooks are legitimate: setuptools, coverage, editable installs and virtualenv each write
one. The list is what runs, not a verdict. A hook installed by a package nobody chose, or one no
installed package lists, deserves a look before any advisory exists. A `.pth` file that only adds
directories runs nothing and is not listed. Point `--rootfs` at a virtualenv (`--rootfs .venv`)
to check a local environment, and use `--image` for a container image.
