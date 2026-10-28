# Dependencies: vulnerabilities, upgrades, licences, SBOM and VEX

`frame deps` reads a project's dependencies from its lockfiles and manifests, matches them against known vulnerabilities, checks whether your code reaches the vulnerable part, plans and applies the upgrade that fixes each one, and checks licences. It never guesses: a version, a licence or a fix appears only when a file, a tool or an advisory says so.

Nothing runs and nothing is fetched unless you ask: `frame kb pull --advisories` downloads the advisories once, and every other command works offline from that cache. The options that run a tool (`--resolve`, `--relock`, `--verify`) say so.

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
| C / C++ | `conan.lock`, `conanfile.txt`, `conanfile.py`, `vcpkg.json`, vcpkg's installed status, git submodules, CMake `FetchContent` / `ExternalProject` / CPM | manual |

Every reader is tested against the package manager's own answer (`npm ls`, `pnpm list`, `poetry export`, `mvn dependency:list`, Gradle, `dotnet list package`, `cargo metadata`, `bundle`, `composer show`, `dart pub deps`, `mix` and others) on real projects, in CI.

A lockfile wins over the manifest beside it. A manifest names only the declared versions, so for Java, where most vulnerabilities arrive transitively, give Frame the resolved graph:

```bash
mvn dependency:tree -DoutputFile=maven_dep_tree.txt      # Maven
gradle dependencies > gradle-dependencies.txt            # Gradle
frame deps --resolve                                     # or let Frame run Maven, Gradle and pip for you
```

`--resolve` runs `mvn dependency:tree` (or `./mvnw`) once per Maven build, `gradle dependencies` (or `./gradlew`) per Gradle project, and pip's resolver (`pip install --dry-run --report`, wheels only, nothing installed) for each `requirements*.txt` and lockfile-less `pyproject.toml`. It runs the project's build configuration and downloads packages, so it is opt-in; a tool that is missing or fails is a warning, and the manifest is read as before.

`direct` is left unknown, rather than guessed, when nothing beside the lockfile says. Dev-only comes from the lockfile's own flags, else from what production dependencies cannot reach. `-f json` adds the edges between packages and each package URL.

## Advisories

Advisories come from [OSV](https://osv.dev), published daily as the `lambdasec/frame-advisories` dataset with the vulnerable functions mined from fix commits. Pull them once, then whenever you want them fresh:

```bash
frame kb pull --advisories                  # the ecosystems this project uses
frame kb pull --advisories --all            # every ecosystem
frame kb status                             # which revisions a scan here uses
```

Every file is checked against the manifest's SHA-256 before it is cached (`~/.cache/frame/kb`, or `FRAME_KB_CACHE`). Matching, plans, reachability and scans never go to the network. With no advisories cached, `frame deps --vulns` warns and names the command to run.

C and C++ dependencies are matched against OSV's records for their upstream git repositories, by the release tag a version is. Only the repositories a project uses are downloaded. A bare commit, or a version that cannot be mapped to a tag with certainty, is listed but not matched.

For air-gapped CI, pull on a connected machine into a directory and pull from it inside:

```bash
frame kb pull --advisories --all --source hf:lambdasec/frame-advisories   # connected side, then copy the cache
FRAME_ADVISORIES_SOURCE=/mnt/frame-advisories frame kb pull --advisories  # or an https:// mirror
```

## Is it reachable?

For Python, JavaScript/TypeScript, Java and C#, each vulnerability is checked against the code under the manifest that declared the package:

| Level | Meaning |
|---|---|
| `installed` | in the graph |
| `imported` | your code imports the package |
| `called` | your code calls a function the advisory names as vulnerable (file and line given) |
| `tainted` | attacker data reaches that call (`frame scan --sca`) |

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

An override is a workaround: the package in between still asks for the old version. Usually a newer release of that package admits the fix, and upgrading it is the real repair. `--registry` (npm and PyPI) fetches every version's dependency ranges from the registry and solves the upgrades of all the packages involved together with Z3:
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

For Python, `uv.lock` records no ranges between packages, so they come from PyPI's metadata (each version's `requires_dist`; requirements behind an `extra` are not installed by default and are skipped). A range Frame cannot learn is never treated as open: the dependency stays where it is unless its parent is upgraded to a version whose ranges are known.

`--apply` changes only the version text (or adds the override), so formatting and comments are kept. An edit that cannot be made safely, such as an upper bound that excludes the fix, or a Gradle `version.ref` that other libraries share, is listed as manual instead. After writing, Frame re-reads the graph and reports what is fixed and what remains.

| Option | Runs | What it does |
|---|---|---|
| `--relock` | the package manager (`npm`, `pnpm`, `yarn`, `poetry`, `uv`, `cargo`, `go`) | regenerates the lockfile so the new versions are resolved |
| `--verify COMMAND` | your command | runs it before and after; if it passed before and fails after, every edited manifest and lockfile is restored. If it already failed before, the edits are kept and the result says the command proves nothing |

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

Ruby, Dart, Elixir, Go and Rust lockfiles record no licences, so their packages are unknown unless installed metadata is present.

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
