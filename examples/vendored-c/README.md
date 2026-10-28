# Vendored C libraries

A small C program that copied two libraries into its tree instead of declaring them anywhere: zlib 1.2.11 in `third_party/zlib/` and cJSON 1.7.14 in `third_party/cjson/`. There is no `conan.lock`, `vcpkg.json` or submodule to read. The files are the libraries' own, from their release archives (for brevity, only the header and the sources Frame looks for); `include/zlib.h` is a lone copy of zlib's header, as a project building against the system zlib keeps. The advisories in `offline-advisories/` are OSV's records for these two repositories (CC-BY 4.0).

```bash
cd examples/vendored-c
frame kb pull --advisories --source offline-advisories --project .
```

## What is vendored

```console
$ frame deps .
  third_party/cjson/cJSON.h  (GIT vendored): 1 packages, 1 direct
  third_party/zlib/zlib.h  (GIT vendored): 1 packages, 1 direct
GIT: 2 distinct packages (2 direct, 0 dev only)
```

Each library is known by the version its own header declares: zlib's `#define ZLIB_VERSION "1.2.11"`, cJSON's `CJSON_VERSION_MAJOR` / `MINOR` / `PATCH`, read from the header's syntax tree. A library is reported only when its own sources are beside the header (`inflate.c` or `deflate.c` for zlib, `cJSON.c` for cJSON), so `include/zlib.h`, a header with no zlib sources, is not a vendored zlib. A header inside a git submodule is left to the submodule's commit.

## Their vulnerabilities

```console
$ frame deps . --vulns
13 known vulnerabilities:
  CRITICAL github.com/davegamble/cjson@1.7.14 (direct) CVE-2025-57052: cJSON 1.5.0 through 1.7.18 allows out-of-bounds access via the decode_array_inde; fixed upstream after this tag (see the advisory)  [third_party/cjson/cJSON.h]
  CRITICAL github.com/madler/zlib@1.2.11 (direct) CVE-2022-37434: zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in infl; fixed upstream after this tag (see the advisory)  [third_party/zlib/zlib.h]
  ...
```

The version becomes the release tag the repository uses (`v1.2.11`, `v1.7.14`; curl's `curl-8_6_0`, expat's `R_2_6_2`, sqlite's `version-3.45.0`), and is matched against the tags OSV lists as affected, as Conan and vcpkg dependencies are. OSV's records name the commit that fixed each one, not a release, so the plan says so:

```console
$ frame deps . --vulns --plan
Upgrade plan (2 packages):
  github.com/madler/zlib@1.2.11: fixed upstream by commit (OSV names no release); update to a release after the fix (CVE-2018-25032, CVE-2022-37434, CVE-2023-45853, CVE-2026-22184, CVE-2026-3381, CVE-2026-76844)
  ...
```

A copy whose header carries a development version (`8.6.1-DEV`, as curl's git tree does between releases) is reported with a warning and not matched, since no release tag names it.

Fourteen libraries are known: zlib, libpng, expat, cJSON, curl, Lua, Mbed TLS, libxml2, PCRE2, SQLite, FreeType, libarchive, c-ares and uriparser (`frame/sca/data/vendored.json`). Each was checked against real releases, and its tag form against the tags OSV lists for the repository. See [docs/dependencies.md](../../docs/dependencies.md#c-and-c-dependencies).
