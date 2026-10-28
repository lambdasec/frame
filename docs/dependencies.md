# Dependencies: vulnerabilities, upgrades, licences, SBOM and VEX

`frame deps` reads a project's dependencies from its lockfiles and manifests, matches them against known vulnerabilities, checks whether your code reaches the vulnerable part, plans and applies the upgrade that fixes each one, and checks licences. It never guesses: a version, a licence or a fix appears only when a file, a tool or an advisory says so.

Nothing runs and nothing is fetched unless you ask: `frame kb pull --advisories` downloads the advisories once, and every other command works offline from that cache. The options that run a tool (`--resolve`, `--relock`, `--verify`) say so.

Every step below is also a runnable walkthrough with real output: [examples/sca-express](../examples/sca-express/README.md), [examples/java-mitigation](../examples/java-mitigation/README.md) and [examples/adapt-werkzeug](../examples/adapt-werkzeug/README.md).

## Quick start

```bash
pip install "frame-security[scan]"
frame kb pull --advisories           # cache the advisories for the ecosystems this project uses
frame deps                           # the dependency graph
frame deps --vulns                   # known vulnerabilities, with the version that fixes each
frame deps --vulns --plan            # the smallest safe upgrades, as a diff
frame deps --vulns --apply --relock  # write them, re-lock, report what is left
frame scan . --sca                   # vulnerable functions that attacker data reaches in your code
```

On a small Express app with lodash 4.17.20:

```console
$ frame deps --vulns
Dependencies under /work/shop
  package-lock.json  (npm lockfile): 127 packages, 3 direct
npm: 127 distinct packages (3 direct, 76 dev only)
37 known vulnerabilities:
  HIGH     body-parser@1.19.0 (transitive) GHSA-qwcr-r2fm-qrc7: body-parser vulnerable to denial of service when url encoding is enabled; fixed in 1.20.3  [package-lock.json]
           via express@4.17.1 -> body-parser@1.19.0
  HIGH     lodash@4.17.20 (direct, called) GHSA-35jh-r3h4-6jhm: Command Injection in lodash; fixed in 4.17.21  [package-lock.json]
           calls lodash.template at app.js:5
...
```

Each finding names the advisory (GHSA, PYSEC, CVE and other ids for the same issue are merged), its severity, the lowest fixed version, whether the package is direct or dev only, the chain that pulls it in, and how far your code reaches it.

## Supported ecosystems

| Ecosystem | Read | Upgrades written by `--apply` |
|---|---|---|
| Python | `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`; without a lockfile `requirements*.txt` (with `-r` includes) and `pyproject.toml` | requirements files, `pyproject.toml` (PEP 621, Poetry), uv constraints |
| JavaScript / TypeScript | `package-lock.json` (v1 to v3), `npm-shrinkwrap.json`, `yarn.lock` (classic and berry), `pnpm-lock.yaml` (v5 to v9); `package.json` | `package.json`, `overrides`, `resolutions`, `pnpm.overrides` |
| Java / Kotlin | `pom.xml`, `gradle.lockfile`, `build.gradle` / `build.gradle.kts` with `gradle/libs.versions.toml`; resolved graphs from `maven_dep_tree.txt` / `.json` and `gradle-dependencies.txt` | `pom.xml` (the property for `${...}`), `dependencyManagement`, Gradle coordinates and the version catalog |
| .NET | `packages.lock.json`, `obj/project.assets.json`, `*.csproj` (with `Directory.Packages.props`), `packages.config` | `.csproj`, `Directory.Packages.props` |
| Go | `go.mod` | `go.mod` |
| Rust | `Cargo.lock` (with `Cargo.toml` for dev dependencies) | re-lock only |
| Swift | `Package.resolved` | manual |
| Ruby | `Gemfile.lock` (with `Gemfile` groups) | manual |
| PHP | `composer.lock`, `composer.json` | manual |
| Dart | `pubspec.lock`, `pubspec.yaml` | manual |
| Elixir | `mix.lock`, `mix.exs` | manual |
| Container images (Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux, RHEL / UBI 8 and 9) | the OS packages of an image (`--image`) or root filesystem (`--rootfs`): `/etc/os-release`, dpkg's database (and distroless `status.d/`), apk's database, rpm's database (sqlite or Berkeley DB); and the PyPI, npm and Maven packages installed in it (`*.dist-info`, `node_modules/*/package.json`, jars' `pom.properties`), and the modules compiled into Go and Rust binaries | manual (upgrade in the image) |
| C / C++ | `conan.lock`, `conanfile.txt`, `conanfile.py`, `vcpkg.json`, vcpkg's installed status, git submodules, CMake `FetchContent` / `ExternalProject` / CPM, and vendored copies of fourteen common libraries (by the version their header declares) | manual |

Every reader is tested against the package manager's own answer (`npm ls`, `pnpm list`, `poetry export`, `mvn dependency:list`, Gradle, `dotnet list package`, `cargo metadata`, `bundle`, `composer show`, `dart pub deps`, `mix` and others) on real projects, in CI.

A lockfile wins over the manifest beside it. A manifest names only the declared versions, so for Java, where most vulnerabilities arrive transitively, give Frame the resolved graph:

```bash
mvn dependency:tree -DoutputFile=maven_dep_tree.txt      # Maven
gradle dependencies > gradle-dependencies.txt            # Gradle
frame deps --resolve                                     # or let Frame run Maven, Gradle and pip for you
```

`--resolve` runs `mvn dependency:tree` (or `./mvnw`) once per Maven build, `gradle dependencies` (or `./gradlew`) per Gradle project, and pip's resolver (`pip install --dry-run --report`, wheels only, nothing installed) for each `requirements*.txt` and lockfile-less `pyproject.toml`. It runs the project's build configuration and downloads packages, so it is opt-in; a tool that is missing or fails is a warning, and the manifest is read as before.

`direct` is left unknown, rather than guessed, when nothing beside the lockfile says. Dev-only comes from the lockfile's own flags, else from what production dependencies cannot reach. `-f json` adds the edges between packages and each package URL.

## Container images

```bash
frame kb pull --advisories --ecosystems Debian:12              # the release's advisories (frame deps names the one it needs;
                                                               # Rocky Linux:9, AlmaLinux:8 ...)
frame deps --image myapp:latest --vulns --plan                 # an image Docker can `docker save`, or a saved .tar
frame deps --rootfs ./rootfs --vulns --fail-on critical        # an unpacked root filesystem
```

Frame reads an image's OS packages: `/etc/os-release` for the distribution and release (`Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.18`, `Rocky Linux:9`, `AlmaLinux:8`), and the package database (dpkg's `status`, or `status.d/` in distroless images, apk's `installed`, or rpm's database: `rpmdb.sqlite` on EL 9, the Berkeley DB `Packages` on EL 8). From an image, only those files are read, applying the layers in order with deletions (whiteouts) honoured. Packages are counted by source package (Debian's `openssl`, not `libssl3`), since that is what the distribution's advisories name. Versions are compared as dpkg and apk compare them, checked against `dpkg --compare-versions` and `apk version -t`.

- **Matching:** on the official `debian:12.0` and `alpine:3.18.0` images, the package lists equal `dpkg-query`'s and `apk list --installed`'s, and the advisories found are those OSV's own API gives (202 and 22).
- **AlmaLinux and Rocky Linux:** the rpm database is read without rpm (sqlite through Python's `sqlite3`; Berkeley DB's hash pages as go-rpmdb, used by Trivy and Syft, reads them), and equals `rpm -qa` on the official `rockylinux:9.4`, `rockylinux:8.9`, `almalinux:9.4` and `almalinux:8.9` images. Versions are `epoch:version-release` in rpm's order (a port of `rpmvercmp`, 0 disagreements with rpm's `labelCompare` on 6,861 pairs). The two distributions name packages differently in their advisories, and Frame follows each: Rocky Linux's records name the source package (RLSA-2024:6783 names `openssl`), so packages are grouped by source rpm; AlmaLinux's name each binary package (`openssl-libs`). Matching equals OSV's API for every package of both fixtures. RHEL 8 and 9 (and UBI images) are read the same way. Red Hat's advisories are split by product stream (`Red Hat:enterprise_linux:9::baseos`, `::appstream`, `::crb`...), which the rpm database does not record; across OSV's whole Red Hat export, every advisory gives a RHEL 8 or 9 package the same range in every stream it is listed in, so a release's streams are one table (`Red Hat:enterprise_linux:9`) and no stream is guessed. On a UBI 9.4 fixture made by rpm, matching equals the union of OSV's answers over every RHEL 9 stream. RHEL 7 is not read (its streams disagree, through its `ael7b` builds), nor are the extended-support products (EUS, AUS, E4S, TUS), RHEL 10 (named per minor release), SUSE (NDB), Fedora or Amazon Linux.
- **Fixing:** the plan names the version that fixes each package. There is no manifest to edit, so `--apply` lists them: upgrade them in the Dockerfile, or rebuild on a newer base image.
- **Language packages:** Python packages (`site-packages/*.dist-info/METADATA`, `*.egg-info`), npm packages (each `node_modules/<name>/package.json` whose name is its directory's), and Maven artifacts (each jar's `META-INF/maven/**/pom.properties`, including jars inside a Spring Boot or WAR archive) are read too, one group per place (`/usr/local/lib/python3.12/site-packages`, `/app/node_modules`, the jar). A jar with no `pom.properties` is counted in a warning, never named from its file name. On a real image they equal `importlib.metadata`, `npm ls --all` and the jars' own coordinates.
- **Packages the distribution ships:** a Python or Node package whose files an OS package owns (dpkg's `info/*.list`, apk's `F:` lines), such as Debian's `python3-urllib3`, is left to the distribution's advisories. Debian and Alpine patch what they ship without changing the upstream version, so PyPI's or npm's advisories would report fixes already made. The warning counts them.
- **Go and Rust binaries:** an executable's Go build info (Go 1.18 and later: the modules `go version -m` prints, replacements applied, and the standard library as `stdlib` at the Go version, the name OSV's advisories use), and the `.dep-v0` section `cargo auditable` embeds in a Rust binary (its crates.io crates, as `rust-audit-info` prints them). The plan says what to rebuild with: `rebuild the binary with Go 1.26.10 or later`, or the module or crate upgraded. A Rust binary built without `cargo auditable`, and a Go binary older than 1.18 (counted in a warning), carry no list Frame reads. Advisories on the Go standard library are many (89 for Go 1.21.0) because every binary contains it. To say which matter, Frame reads the binary's function table (`pclntab`, kept even by `-s -w`, since stack traces need it): Go's linker drops functions nothing calls, so an advisory whose vulnerable function (on the binary's `GOOS`/`GOARCH`) is in the table is `called` (`contains net/url.Parse (linked into the binary)`), and the rest stay `installed`. It is positive evidence only: an inlined function has no entry of its own, so nothing is marked not affected. On real binaries the called set equals `govulncheck -mode binary` on the unstripped build (54 of 89 on a small `net/http` server); on a stripped binary govulncheck itself falls back to every function of each package present (85).
- **Not covered:** distributions other than Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux and RHEL 8 / 9 are reported as such, never guessed (their language packages are still read). With the project that built the image, `frame deps .` also says direct or transitive and can apply upgrades.

A walkthrough with real output: [examples/container-image](../examples/container-image/README.md).

## Advisories

Advisories come from [OSV](https://osv.dev), published daily as the `lambdasec/frame-advisories` dataset with the vulnerable functions mined from fix commits. Pull them once, then whenever you want them fresh:

```bash
frame kb pull --advisories                  # the ecosystems this project uses
frame kb pull --advisories --all            # every ecosystem
frame kb status                             # which revisions a scan here uses
```

Every file is checked against the manifest's SHA-256 before it is cached (`~/.cache/frame/kb`, or `FRAME_KB_CACHE`). Matching, plans, reachability and scans never go to the network. With no advisories cached, `frame deps --vulns` warns and names the command to run.

### C and C++ dependencies

C and C++ dependencies are matched against OSV's records for their upstream git repositories, by the release tag a version is. Only the repositories a project uses are downloaded. A version that cannot be mapped to a tag with certainty is listed but not matched.

A git submodule pinned to an untagged commit is matched by commit: OSV's records give `introduced` and `fixed` commits, and the submodule's own checkout has the history that decides them, so nothing is fetched. The rule is the OSV schema's: the commit is affected when an `introduced` commit is its ancestor and no `fixed` commit lies between the two (a fix on another branch does not count; `last_affected` and `limit` bound it from above), asked of `git merge-base --is-ancestor`. When the checkout lacks an advisory's commits (a shallow clone), or an advisory gives tags but no commit ranges, it is reported as undecided, never as unaffected: a warning names it, the result ends with `NOT DECIDED: N advisory(ies)` instead of "no known vulnerabilities", the JSON has `undecided`, and `--fail-on` exits 2 (cannot be judged) when any undecided advisory is at or above its threshold. On real zlib and libexpat histories, the answers equal OSV's own commit query on every commit OSV's index answers for (the commits of the default branch). OSV's index leaves commits that reached the default branch only through a merged side branch unanswered, even when they predate the fix (33 of 34 such libexpat commits); Frame decides them by the same rule. A CMake `GIT_TAG` that is a bare commit has no checkout to ask, and stays unmatched.

A project with zlib as a submodule pinned six commits after v1.2.12 (`v1.2.12-6-g441a2ac`, no tag), with advisories 2026.10.28-61e59fe:

```console
$ frame deps . --vulns
6 known vulnerabilities:
  CRITICAL github.com/madler/zlib@441a2ac6028a (direct) CVE-2022-37434: zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in infl; fixed upstream after this commit (see the advisory)  [.gitmodules]
  ...
```

The six are what OSV's own commit query answers for `441a2ac`. With advisory data older than commit ranges, the same project ends `NOT DECIDED: 12 advisory(ies)` rather than reporting it clean.

A library copied into the tree (vendored) has no manifest, but its own header says its version: zlib's `#define ZLIB_VERSION "1.2.11"`, expat's `XML_MAJOR_VERSION` / `MINOR` / `MICRO`. Frame knows fourteen such libraries (`frame/sca/data/vendored.json`: zlib, libpng, expat, cJSON, curl, Lua, Mbed TLS, libxml2, PCRE2, SQLite, FreeType, libarchive, c-ares, uriparser), each with the header and macros that state its version (read from the header's syntax tree), the library's own source files that must sit beside the header (a lone `zlib.h` copied in to build against the system zlib is not vendored zlib), and its repository's release-tag forms (`v{V}`, `curl-{V_}`, `VER-{V-}`, `version-{V}`). The version is matched by tag like any other C/C++ dependency. Every entry was checked against real releases of the library and its tag forms against the tags OSV lists for the repository (`tests/test_sca_vendored.py`; live, each release is downloaded again and its tag confirmed with `git ls-remote`). A development version (`8.6.1-DEV`, which curl's git tree carries between releases) is reported and not matched; a header inside a git submodule is left to the submodule's commit. libxml2 2.12 and later ship `xmlversion.h` only after `configure`, so an unconfigured copy is not identified. Walkthrough: [examples/vendored-c](../examples/vendored-c/README.md).

For air-gapped CI, pull on a connected machine into a directory and pull from it inside:

```bash
frame kb pull --advisories --all --source hf:lambdasec/frame-advisories   # connected side, then copy the cache
FRAME_ADVISORIES_SOURCE=/mnt/frame-advisories frame kb pull --advisories  # or an https:// mirror
```

### Declared ranges (`--vulns --registry`)

A library's users resolve its declared ranges, not its lockfile, so a range that admits a vulnerable release passes it on even when the lockfile is safe. With `--registry`, `frame deps --vulns` also checks the project's own ranges against every released version:

```console
$ frame deps --vulns --registry
Declared ranges that admit vulnerable versions (2): consumers who resolve these ranges can install them
  express 4.17.1: admits 1 vulnerable of 1 (4.17.1 .. 4.17.1; GHSA-qw6h-vgh9-j6wx, GHSA-rv95-896h-c2vc); every version it admits is vulnerable: widen it  [package-lock.json]
  lodash ~4.17.20: admits 3 vulnerable of 3 (4.17.20 .. 4.17.23; GHSA-29mw-wpgm-hmr9, GHSA-35jh-r3h4-6jhm, GHSA-f23m-r3pf-42rh...); every version it admits is vulnerable: widen it  [package-lock.json]
```

Where some admitted versions are safe, it names the lowest floor that leaves no vulnerable one (`raise the floor to 1.2.0`). JSON: `exposed_ranges`.

## Is it reachable?

For Python, JavaScript/TypeScript, Java and C#, each vulnerability is checked against the code under the manifest that declared the package:

| Level | Meaning |
|---|---|
| `installed` | in the graph |
| `imported` | your code imports the package |
| `called` | your code calls a function the advisory names as vulnerable (file and line given) |
| `tainted` | attacker data reaches that call (`frame scan --sca`) |

Without a known vulnerable function, the fallback is the module: Python, npm and NuGet packages are `imported` when your code imports them. A Maven artifact's coordinates do not say which Java packages it holds, so for Java the fallback comes from the fix commit instead: the advisory dataset records the classes a fix changed (read from each file's own package declaration), and the advisory is `imported` when your code imports from that package. The output names the class either way (`the fix changed org.springframework.util.MimeTypeUtils (imported in src/App.java)`). The package is the class's own: jackson-databind's fixes change `com.fasterxml.jackson.databind.jsontype.impl`, which applications rarely import directly, and widening it to `com.fasterxml.jackson` would also match jackson-core, so it is not widened.

The evidence is positive only. A package your code never imports can still be reached through another library (Log4Shell reached applications that logged through SLF4J), so an unused package stays `installed`, never "unreachable". `--no-reachability` skips reading the source.

`frame scan DIR --sca` puts dependencies into the source scan: every function an advisory names becomes a taint sink, so attacker data reaching it is a finding at the call site (`vulnerable_dependency`, CWE-1395, category `dependency`, at the advisory's severity). A call that is already a sink keeps its own finding and raises the advisory to `tainted`:

```console
$ frame scan . --sca
1. [HIGH] 🟠 template_injection
   Location: app.js:5:8
   Description: Tainted data from 'req.query' flows to template sink
   CWE: CWE-1336
Scanned 1 file: 1 finding (1 high)
  tainted: GHSA-35jh-r3h4-6jhm reached by attacker data at app.js:5 (solver-verified)
  tainted: GHSA-r5fr-rjxr-66jc reached by attacker data at app.js:5 (solver-verified)
```

The JSON gains a `dependencies` object with every matched advisory and its reachability, and SARIF one result per advisory at its manifest. `--fail-on` counts them.

## Fixing: upgrade plans

```bash
frame deps --vulns --plan                     # what to change, as a diff (writes nothing)
frame deps --vulns --apply                    # write the edits
frame deps --vulns --apply --relock           # and regenerate the lockfile with the package manager
frame deps --vulns --apply --relock --verify "npm ci && npm test"
```

For each vulnerable package the plan picks the lowest version, at or above the current one, that no known advisory affects. It flags a jump to a new major version and says what the change takes:

- **re-lock:** every declared range already admits the fix;
- **raise the project's requirement:** your manifest pins it;
- **override:** a package in between pins a range that excludes it, so an npm `overrides`, yarn `resolutions`, `pnpm.overrides`, a pip / uv constraint or Maven `dependencyManagement` entry is added.

```console
$ frame deps --vulns --plan
Upgrade plan (13 packages):
  express 4.17.1 -> 4.20.0: raise the project's requirement  [package-lock.json; fixes 2]
      (project) requires 4.17.1
  lodash 4.17.20 -> 4.18.0: raise the project's requirement  [package-lock.json; fixes 5]
      (project) requires ~4.17.20
  qs 6.7.0 -> 6.16.1: override: an `overrides` entry (npm), `resolutions` (yarn) or `pnpm.overrides`  [package-lock.json; fixes 5]
      body-parser@1.19.0 requires 6.7.0
      express@4.17.1 requires 6.7.0
...
```

### Solving the upgrades together (`--registry`)

An override is a workaround: the package in between still asks for the old version. Usually a newer release of that package admits the fix, and upgrading it is the real repair. `--registry` (npm, PyPI, crates.io and NuGet) fetches every version's dependency ranges from the registry and solves the upgrades of all the packages involved together with Z3:
- every chosen version's ranges admit the chosen versions of its dependencies;
- no vulnerable version remains, where any version can avoid it;
- major jumps are minimised first, then raised requirements, then the number of packages changed, then the distance from the current versions.

A newer version that no longer depends on a vulnerable package takes it out of the tree. On the same Express app, the plan needs no override at all:

```console
$ frame deps --vulns --plan --registry
Upgrade plan (14 packages):
  body-parser 1.19.0 -> 1.20.9: re-lock to it (admitted by the solved upgrades)  [package-lock.json; fixes 3]
  express 4.17.1 -> 4.22.3: raise the project's requirement  [package-lock.json; fixes 2]
  nanoid@3.3.3: leaves the tree (no upgraded package depends on it)  [package-lock.json; fixes 4]
  qs 6.7.0 -> 6.16.1: re-lock to it (admitted by the solved upgrades)  [package-lock.json; fixes 5]
  mocha 10.2.0 -> 12.0.0 [major]: raise the project's requirement  [package-lock.json; lets diff, js-yaml, minimatch upgrade]
...
$ frame deps --vulns --plan --registry --apply --relock
After applying: 37 fixed, 0 remaining
```

Express stays on 4.x, because 4.22.3 admits every fix. Mocha does jump a major version: no 10.x or 11.x release admits fixed versions of its vulnerable dependencies. Metadata is cached (`FRAME_REGISTRY_CACHE`, default beside the knowledge-base cache), so a re-plan is offline. A vulnerable package no upgrade can fix keeps its override. The other dependencies of an upgraded package are resolved by re-locking; the plan lists the ones that must move (`re-locking also moves click 8.0.1 (>=8.1.3)`).

For Rust, the ranges come from crates.io's index. `url` 2.4.1 requires `idna ^0.4`, and the fix for RUSTSEC-2024-0421 is idna 1.0.0. The solver upgrades url to 2.5.1, which requires `idna ^1.0.0`, and re-locks both with `cargo update --precise`. Optional dependencies count as built, since whether a feature enables one is not known.

For .NET, NuGet resolves a transitive package to the **lowest** version every requirer admits, not the newest, so re-locking never moves one: without `--registry` a vulnerable transitive package gets a direct `PackageReference` (an override), and a direct one has its reference raised. The solver models the rule (a transitive package is the lowest version all its present parents admit), so it raises the parent whose new range starts at a fixed version. Azure.Identity 1.10.3 asks for MSAL `[4.56.0, )` and gets the vulnerable 4.56.0; 1.11.4 asks for `[4.61.3, )`, so raising Azure.Identity alone fixes MSAL. Ranges come from nuget.org's registration index; when a package's framework groups differ, the strictest range counts. `--relock` runs `dotnet restore --force-evaluate`. Walkthrough: [examples/upgrade-nuget-go](../examples/upgrade-nuget-go/README.md).

Go needs no solver: `go.mod` lists every module and Go takes the highest version any `go.mod` requires, so every plan raises the line in your `go.mod`. With `--registry`, Frame reads each target's `go.mod` from the module proxy, and when the fix needs a newer Go than your `go` directive, says so and names the newest fix your Go builds and what it fixes (`needs Go 1.26.0 (go.mod says go 1.21); the newest fix that Go builds is 0.31.0 (go 1.20), fixing 6 of 26`).

An advisory with no fixed version (an unmaintained package) affects every version, so it is listed as staying open and never blocks the upgrades that fix the package's other advisories.

For Python, `uv.lock` records no ranges between packages, so they come from PyPI's metadata (each version's `requires_dist`; requirements behind an `extra` are not installed by default and are skipped). A range Frame cannot learn is never treated as open: the dependency stays where it is unless its parent is upgraded to a version whose ranges are known.

`--apply` changes only the version text (or adds the override), so formatting and comments are kept. An edit that cannot be made safely, such as an upper bound that excludes the fix, or a Gradle `version.ref` that other libraries share, is listed as manual instead. After writing, Frame re-reads the graph and reports what is fixed and what remains.

| Option | Runs | What it does |
|---|---|---|
| `--relock` | the package manager (`npm`, `pnpm`, `yarn`, `poetry`, `uv`, `cargo`, `dotnet`, `go`) | regenerates the lockfile so the new versions are resolved |
| `--verify COMMAND` | your command | runs it before and after; if it passed before and fails after, every edited manifest and lockfile is restored. If it already failed before, the edits are kept and the result says the command proves nothing |

### When an upgrade breaks your code (`--adapt`)

A fix in a new major version often changes the API your code uses. With `--adapt`, an upgrade that turns your `--verify` command from passing to failing goes to a model before it is rolled back:
1. The model gets the upgrades, the failing output, the files that import the upgraded packages, and the release notes between the two versions, and proposes minimal edits to your source. The notes are the project's own changelog sections at the target version's tag (feature releases first), else its GitHub release bodies, found through the repository the registry names. For Werkzeug 2.2.3 to 3.1.9 they include 2.3.0's "Deprecate the `werkzeug.urls` module" and 3.0.0's "Remove previously deprecated code".
2. Frame applies them and runs your command again, for up to three rounds, each seeing the latest output. It never touches a manifest or lockfile, since that would undo the upgrade.
3. The result is kept only if your command passes **and** a Frame scan of every edited file finds nothing it did not find before. Otherwise every edit is restored and the upgrade is rolled back.

It needs a model (`FRAME_LLM_*`, see [ai.md](ai.md)).

```console
$ frame deps --vulns --plan --apply --verify ".venv/bin/pip install -q -r requirements.txt && .venv/bin/python -m pytest -q" --adapt
  werkzeug 2.2.3 -> 3.1.9 [major]: raise the project's requirement  [requirements.txt; fixes 8]
Adapted: the code was changed for the new versions in 1 round(s) (Werkzeug 3 removed url_parse/url_quote; use urllib.parse equivalents ...); the command passes and a re-scan of the edited files finds nothing new:
--- a/app.py
+++ b/app.py
-from werkzeug.urls import url_parse, url_quote
+from urllib.parse import quote, urlsplit
...
```

Without `--adapt`, the same upgrade is rolled back (`ImportError: cannot import name 'url_parse'`).

## Fixing in code, when you cannot upgrade

```bash
frame fix src/ --deps --diff        # each call site attacker data reaches (frame scan --sca)
frame fix src/ --deps --in-place    # write only the verified patches
```

For each call site where attacker data reaches a vulnerable function, an LLM proposes a change to how your code uses it, with the dependency's version unchanged (validating the input, or calling a safe alternative). The taint engine then re-runs the whole analysis on a patched copy of the project. A patch is kept only if the flow is gone and nothing new appears. `--include-called` also covers call sites with no attacker data flow. This needs a model (`FRAME_LLM_*`, see [ai.md](ai.md)).

## Configuration mitigations

Some vulnerabilities can be switched off by a setting while you wait for an upgrade. Frame ships these per advisory, curated from the advisory's own text and the library's source or documentation, and `frame deps --vulns` shows whether your project already applies one:

```console
$ frame deps --vulns
  CRITICAL com.alibaba:fastjson@1.2.80 (direct) GHSA-crf3-v9rr-v7hj: fastjson has a remote code execution (RCE) vulnerability; no fixed version  [pom.xml]
  HIGH     com.alibaba:fastjson@1.2.80 (direct) GHSA-pv7h-hx5h-mgfj: Unsafe deserialization in com.alibaba:fastjson; fixed in 1.2.83  [pom.xml]
           mitigation (complete): enable fastjson safeMode, which disables autoType completely: APPLIED at Dockerfile:2 (JAVA_TOOL_OPTIONS)
```

A mitigation belongs to an advisory, not a package: nothing says safeMode stops the newer GHSA-crf3-v9rr-v7hj, so none is shown for it.

A mitigation is `complete` only when the advisory or the library says it stops that vulnerability; otherwise it is `partial` and comes with the caveat. Log4Shell's `log4j2.formatMsgNoLookups=true`, for instance, does not stop CVE-2021-45046, and Apache withdrew that advice. Each one applies only to the versions where the setting exists.

Frame looks for the setting where a running application gets it, and never in build configuration:

| Kind | Where |
|---|---|
| JVM system property | `-Dkey=value` in a Dockerfile `CMD` / `ENTRYPOINT`, a `java` command line in a shell script or systemd `ExecStart`, the JVM option variables (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `JAVA_OPTS`) wherever they are set, or `System.setProperty("key", "value")` in Java source |
| Environment variable | Dockerfile `ENV`, Compose `environment`, Kubernetes container `env`, systemd `Environment=`, `.env`, `export` in shell scripts |
| Properties file | a file with the name the library reads (`fastjson.properties`, `log4j2.component.properties`) |
| Call | the call the library documents, from the Java syntax tree (`ParserConfig.getGlobalInstance().setSafeMode(true)`) |

`.mvn/jvm.config`, `gradle.properties` and `RUN mvn -D...` configure the build's JVM, not the application's, so they do not count.

`--mitigate` writes a complete mitigation that is not applied yet, shown as a diff until `--apply`. It prefers a properties file the library reads from the classpath (`src/main/resources/fastjson.properties`), since that travels inside the artifact whatever runs it. Otherwise it extends the JVM options in the Dockerfile's last stage, keeping any earlier value (`ENV JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS} -D..."`). After writing, Frame re-reads the project and confirms the mitigation is seen. A partial mitigation is never written for you, and one with nowhere to go is listed with the exact setting. `--apply` writes only what you asked for: `--mitigate --apply` changes no versions, and `--plan --mitigate --apply` does both.

```console
$ frame deps --vulns --mitigate --apply
Configuration mitigations:
--- a/src/main/resources/fastjson.properties
+++ b/src/main/resources/fastjson.properties
@@ -0,0 +1 @@
+fastjson.parser.safeMode=true

Applied and confirmed by re-reading the project: com.alibaba:fastjson@1.2.80 GHSA-pv7h-hx5h-mgfj
```

A mitigation found is evidence, with its location, not a verdict: a Dockerfile does not prove that is how the service runs. In VEX the statement stays `affected` with the evidence in its notes. If it is how the application runs, record the decision in `.frame/vex.toml` with the justification `inline_mitigations_already_exist`.

## Licences

```bash
frame deps --licenses               # check against the policy; exit 1 on a violation
frame deps --licenses -f json       # every package with its licence, where it came from, and the verdict
```

The policy lives in `.frame.toml` (or `[tool.frame.licenses]` in `pyproject.toml`):

```toml
[licenses]
deny = ["GPL-*", "AGPL-*"]        # SPDX ids or globs
# allow = ["MIT", "Apache-2.0", "BSD-*", "ISC"]   # accept only these
unknown = "report"                # "fail" to fail on packages with no licence evidence
include_dev = false               # dev-only dependencies are skipped by default
```

An SPDX expression is judged as written. `MIT OR GPL-3.0-only` passes when MIT is acceptable, since you may choose it, while `MIT AND GPL-3.0-only` needs both. `X WITH exception` matches a deny entry for `X`, or one for the exact `X WITH exception`. A licence that is not an SPDX id is reported as unknown, unless a deny entry names it.

Licences come from:
- the lockfile: npm, Composer;
- the installed metadata of the same version: `node_modules`, including pnpm's store, and a project `.venv`'s `License-Expression` or SPDX `License` field.

Ruby, Dart, Elixir, Go and Rust lockfiles record no licences. `--registry` fills what is still unknown from each version's own registry record: npm, PyPI (`license_expression`, or an SPDX `License`), RubyGems, crates.io, NuGet (`licenseExpression`) and Maven. A POM names its licences in free text, inherited from a parent POM when it has none (as Maven does), so each must map to exactly one SPDX id through SPDX's own licence list: its URL is one of that licence's reference URLs, or its name is the SPDX name. Logback's LGPL URL is shared by `LGPL-2.1-only` and `LGPL-2.1-or-later`, so it stays unknown rather than picking one. Hex only publishes the latest release's licence and pub.dev and Go none, so those stay unknown rather than guessed. On devise's real `Gemfile.lock`, all 87 gems go from unknown to known. The answers are checked live against what the package managers install: each `.gem`'s own metadata, `cargo metadata`, each `.nupkg`'s nuspec, and Maven's effective POM.

```bash
frame deps --licenses --registry           # goes to the registries once; cached
frame deps --sbom cyclonedx --registry     # the SBOM carries the same licences
```

## SBOM

```bash
frame deps --sbom cyclonedx -o sbom.json     # CycloneDX 1.6
frame deps --sbom spdx -o sbom.spdx.json     # SPDX 2.3
frame deps --sbom cyclonedx --product pkg:github/acme/shop
```

Components carry package URLs, dev-only ones are `scope: optional` (SPDX: `DEV_DEPENDENCY_OF`), and the dependency graph is included. Licences are the ones above; with none, CycloneDX omits the field and SPDX says `NOASSERTION`. `--product` names the root (default `pkg:generic/<directory>`). Both formats are validated against the official schemas.

## VEX

```bash
frame deps --vex openvex -o vex.json                         # OpenVEX 0.2.0
frame deps --vex cyclonedx -o vex.cdx.json                   # CycloneDX 1.6 vulnerabilities
frame scan . --sca --vex cyclonedx --vex-out vex.cdx.json    # with the source scan's evidence
```

Statements follow Frame's evidence:
- **`affected`:** a vulnerable version is present. The upgrade from the plan is the action.
- **`exploitable`:** attacker data reaches a vulnerable function, with the flow. This needs `scan --sca`.
- **`not_affected`:** Frame never states this on its own, because reachability cannot prove a package unreachable. Record decisions in `.frame/vex.toml` and they are included.

If a verified flow contradicts a recorded `not_affected`, the statement stays `affected`, the conflict is reported, and the command exits 1. `--dev-not-shipped` states dev-only dependencies `not_affected` (`component_not_present`).

```toml
# .frame/vex.toml
[[statement]]
vulnerability = "CVE-2021-23337"            # any id or alias
package = "lodash"                          # optional
status = "not_affected"
justification = "vulnerable_code_cannot_be_controlled_by_adversary"
impact_statement = "Templates come from a fixed map."
author = "appsec@example.com"
```

## In CI

```yaml
# .github/workflows/deps.yml
name: dependencies
on: [push, pull_request]
jobs:
  deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install "frame-security[scan]"
      - run: frame kb pull --advisories
      - run: frame deps --vulns --fail-on high --exclude tests      # exit 1 on high or critical
      - run: frame deps --licenses                                   # exit 1 on a licence violation
      - run: frame deps --sbom cyclonedx -o sbom.json
      - uses: actions/upload-artifact@v4
        with: {name: sbom, path: sbom.json}
```

To put dependency findings into code scanning next to the source findings, add `--sca` to the scan: `frame scan . --sca -f sarif -o frame.sarif` (with the [GitHub Action](usage.md#github-actions), `args: --sca`, after a `frame kb pull --advisories` step).

Exit status for `frame deps`: 0 clean, 1 a vulnerability at or above `--fail-on`, a licence violation, or a VEX conflict, and 2 when the command could not run.

## Limits

- Transitive use through another library is invisible to reachability, so `installed` never means unreachable.
- Without a lockfile, a resolved graph or `--resolve`, a manifest gives declared versions only (Gradle may resolve a higher one), and no transitive dependencies.
- Vulnerable functions are known for some advisories only (OSV's Go and RustSec symbols, curated entries, and functions mined from fix commits, growing weekly). Without them, a vulnerability stops at `imported`.
- `--apply` writes Python, npm, Maven, Gradle, .NET and Go manifests; other ecosystems are listed as manual or re-locked only.
