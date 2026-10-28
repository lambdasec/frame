# Vendored C libraries

A small C program that copied two libraries into its tree instead of declaring them anywhere: zlib 1.2.11 in `third_party/zlib/` and cJSON 1.7.14 in `third_party/cjson/`, plus zlib's sources alone in `vendor/zlib-src/` (their header kept apart, in `include/`). There is no `conan.lock`, `vcpkg.json` or submodule to read. The files are the libraries' own, from their release archives (for brevity, only the header and the sources Frame looks for); `include/zlib.h` is a lone copy of zlib's header, as a project building against the system zlib keeps. The advisories in `offline-advisories/` are OSV's records for these two repositories (CC-BY 4.0).

```bash
cd examples/vendored-c
frame kb pull --advisories --source offline-advisories --project .
```

## What is vendored

```console
$ frame deps .
  third_party/cjson/cJSON.h  (GIT vendored): 1 packages, 1 direct
  third_party/zlib/zlib.h  (GIT vendored): 1 packages, 1 direct
  vendor/zlib-src  (GIT vendored): 1 packages, 1 direct
GIT: 2 distinct packages (2 direct, 0 dev only)
```

Each library is known by the version its own header declares: zlib's `#define ZLIB_VERSION "1.2.11"`, cJSON's `CJSON_VERSION_MAJOR` / `MINOR` / `PATCH`, read from the header's syntax tree. A library is reported only when its own sources are beside the header (`inflate.c` or `deflate.c` for zlib, `cJSON.c` for cJSON), so `include/zlib.h`, a header with no zlib sources, is not a vendored zlib. A header inside a git submodule is left to the submodule's commit.

`vendor/zlib-src/` has no version header at all, only `inflate.c` and `deflate.c`. A source file copied unchanged has the git blob id (`git hash-object`) that zlib's own repository gives it at every release that shipped it, so the copy is known by its files: the releases that shipped every one of them, here exactly 1.2.11. The ids come from the libraries' repositories at their release tags (`frame/sca/data/vendored-fingerprints.json.gz`, 13 of the 14 libraries; SQLite's amalgamation is generated, not in its repository). An edited file matches nothing, and files of different releases in one directory are said, not matched. When the files fit several releases (`inflate.c` alone is the same in 1.2.9, 1.2.10 and 1.2.11), an advisory is reported only if it affects all of them, and one affecting some is listed as not decided:

```console
$ mkdir -p /tmp/lone/z && cp vendor/zlib-src/inflate.c /tmp/lone/z/ && frame deps /tmp/lone --vulns
warning: github.com/madler/zlib 1.2.9 or 1.2.10 or 1.2.11 (z): 1 advisory(ies) not decided, they affect some of the 3 releases these files are in: CVE-2026-76844
5 known vulnerabilities:
  ...
NOT DECIDED: 1 advisory(ies) (see the warnings above)
```

## Their vulnerabilities

```console
$ frame deps . --vulns
19 known vulnerabilities:
  CRITICAL github.com/davegamble/cjson@1.7.14 (direct) CVE-2025-57052: cJSON 1.5.0 through 1.7.18 allows out-of-bounds access via the decode_array_inde; fixed upstream after this tag (see the advisory)  [third_party/cjson/cJSON.h]
  CRITICAL github.com/madler/zlib@1.2.11 (direct) CVE-2022-37434: zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in infl; fixed upstream after this tag (see the advisory)  [third_party/zlib/zlib.h]
  ...
```

The version becomes the release tag the repository uses (`v1.2.11`, `v1.7.14`; curl's `curl-8_6_0`, expat's `R_2_6_2`, sqlite's `version-3.45.0`), and is matched against the tags OSV lists as affected, as Conan and vcpkg dependencies are. OSV's records name the commit that fixed each one, not a release, so the plan says so:

```console
$ frame deps . --vulns --plan
Upgrade plan (3 packages):
  github.com/madler/zlib@1.2.11: fixed upstream by commit (OSV names no release); update to a release after the fix (CVE-2018-25032, CVE-2022-37434, CVE-2023-45853, CVE-2026-22184, CVE-2026-3381, CVE-2026-76844)  [third_party/zlib/zlib.h]
  github.com/madler/zlib@1.2.11: fixed upstream by commit (OSV names no release); update to a release after the fix (CVE-2018-25032, CVE-2022-37434, CVE-2023-45853, CVE-2026-22184, CVE-2026-3381, CVE-2026-76844)  [vendor/zlib-src]
  ...
```

A copy whose header carries a development version (`8.6.1-DEV`, as curl's git tree does between releases) is reported with a warning and not matched, since no release tag names it.

Fourteen libraries are known: zlib, libpng, expat, cJSON, curl, Lua, Mbed TLS, libxml2, PCRE2, SQLite, FreeType, libarchive, c-ares and uriparser (`frame/sca/data/vendored.json`). Each was checked against real releases, and its tag form against the tags OSV lists for the repository. See [docs/dependencies.md](../../docs/dependencies.md#c-and-c-dependencies).
