# Container images: the language runtimes themselves

A JDK, Node.js, Python, .NET or Ruby that an image installs from a tarball (the official
`eclipse-temurin`, `node`, `python`, `ruby` and `mcr.microsoft.com/dotnet` images all do) is in no
package database, so neither the OS packages nor the language packages show it. Frame reads each
runtime from the version file it ships with. This example holds the JDK `release` files of three
real images (`eclipse-temurin:17-jre`, `eclipse-temurin:8-jre`, `ibm-semeru-runtimes:open-17-jre`,
by digest in [tests/fixtures/sca/runtimes](../../tests/fixtures/sca/runtimes/README.md)), and
`offline-advisories/` the OpenJDK advisories Frame builds from OpenJDK's own pages, so it runs
offline. With Docker, `frame deps --image eclipse-temurin:17-jre --vulns` reads the same file
straight from the image.

```bash
cd examples/container-runtimes
frame kb pull --advisories --source offline-advisories --ecosystems OpenJDK
```

## The runtimes

```console
$ frame deps --rootfs temurin-17-jre --rootfs temurin-8-jre --rootfs semeru-17-jre
  temurin-17-jre:/opt/java/openjdk  (OpenJDK image): 1 packages, direct unknown
  temurin-8-jre:/opt/java/openjdk  (OpenJDK image): 1 packages, direct unknown
OpenJDK: 2 distinct packages (0 direct, 0 dev only)
warning: semeru-17-jre: no /etc/os-release, so the distribution is unknown
warning: semeru-17-jre:/opt/java/openjdk/release: JDK 17.0.21.0.3: its JVM is Openj9 (IBM Corporation), not HotSpot; OpenJDK's advisories describe HotSpot builds, so it is not matched (see the vendor's bulletins)
```

Each JDK is its `release` file's `JAVA_VERSION` (`17.0.21`; JDK 8 writes `1.8.0_512`, which is
`8u512`). IBM Semeru's JVM is OpenJ9, and OpenJDK's advisories describe HotSpot builds (many of
them are HotSpot flaws), so it is reported rather than matched against them.

## Their vulnerabilities

```console
$ frame deps --rootfs temurin-17-jre --vulns
10 known vulnerabilities:
  CRITICAL openjdk@17.0.21 (runtime) CVE-2026-114820: OpenJDK security-libs/java.security vulnerability; no fixed version named; last affected 17.0.21.0.2  [temurin-17-jre:/opt/java/openjdk]
  CRITICAL openjdk@17.0.21 (runtime) CVE-2026-91403: OpenJDK security-libs/java.security vulnerability; no fixed version named; last affected 17.0.21  [temurin-17-jre:/opt/java/openjdk]
  HIGH     openjdk@17.0.21 (runtime) CVE-2026-114938: OpenJDK hotspot/compiler vulnerability; no fixed version named; last affected 17.0.21.0.3  [temurin-17-jre:/opt/java/openjdk]
  ...

$ frame deps --rootfs temurin-8-jre --vulns
5 known vulnerabilities:
  HIGH     openjdk@1.8.0_512 (runtime) CVE-2026-114939: OpenJDK security-libs/org.ietf.jgss vulnerability; no fixed version named; last affected 8u512  [temurin-8-jre:/opt/java/openjdk]
  ...
```

CVE-2026-114938 ("Java4Shell", an out-of-bounds write in HotSpot's AVX-512 Base64 decoder) is
OpenJDK's advisory of 2026-11-17: it marks the 17, 21, 25 and 27 lines, each up to the version the
advisory names as its last affected one (`17.0.21.0.3 and earlier`). The 8 line is not marked, so
JDK 8 does not have it. The severity is the CVSS 3.1 vector of OpenJDK's risk matrix (8.1).
OpenJDK's advisories name the last affected version of each line, not the release that fixes
it, so Frame names none:

```console
$ frame deps --rootfs temurin-17-jre --vulns --plan
...
Upgrade plan (1 package):
  openjdk@17.0.21: OpenJDK names the last affected version, not the fix; upgrade the JDK to a later release of its line (CVE-2026-114820, CVE-2026-114938, ...)  [temurin-17-jre:/opt/java/openjdk]
```

A JDK on a release line OpenJDK's latest advisory no longer lists (JDK 26 once 27 shipped) gets
a note instead of a clean result: the line gets no OpenJDK fixes, and what was found since is
not known to Frame.

The other runtimes work the same way, from their own files: Node.js (`include/node/node_version.h`,
the Node.js security WG's advisories), CPython (`include/python3.X/patchlevel.h`, matched by its
release tag against OSV's records for `github.com/python/cpython`), .NET (the shared framework's
`deps.json`, which names the NuGet runtime pack GitHub's advisories are filed under) and Ruby
(`rbconfig.rb`, the Ruby advisory database). See [docs/dependencies.md](../../docs/dependencies.md#container-images).
