# Container images: OS packages, language packages and their advisories

`debian-12.0/` and `alpine-3.18.0/` are the package databases of the official `debian:12.0` and `alpine:3.18.0` images (their `/etc/os-release`, `/var/lib/dpkg/status` and `/lib/apk/db/installed`), recorded so this runs offline. With Docker, `frame deps --image debian:12.0` reads the same files straight from the image. `app-image/` holds the same files of an application image built by [`app-image.Dockerfile`](app-image.Dockerfile): Python packages installed with pip, an npm tree, a jar, and Debian's own `python3-urllib3`. The advisories in `offline-advisories/` are those for all these packages, from OSV's data (CC-BY 4.0).

```bash
cd examples/container-image
frame kb pull --advisories --source offline-advisories --ecosystems Debian:12,Alpine:v3.18,PyPI,npm,Maven
```

## The packages

```console
$ frame deps --rootfs alpine-3.18.0 --rootfs debian-12.0
  alpine-3.18.0:/lib/apk/db/installed  (Alpine:v3.18 installed): 10 packages, direct unknown
  debian-12.0:/var/lib/dpkg/status  (Debian:12 installed): 63 packages, direct unknown
Alpine:v3.18: 10 distinct packages (0 direct, 0 dev only)
Debian:12: 63 distinct packages (0 direct, 0 dev only)
```

The release comes from `/etc/os-release` (`Debian:12`, `Alpine:v3.18`, `Ubuntu:22.04:LTS`), because a distribution fixes each release separately. Packages are counted by **source** package (Debian's `openssl`, not its binaries `libssl3` and `openssl`), since that is what the distribution's advisories name. The lists are exactly what `dpkg-query` and `apk list --installed` report inside the images.

## Their vulnerabilities

```console
$ frame deps --rootfs alpine-3.18.0 --vulns
22 known vulnerabilities:
  CRITICAL busybox@1.36.0-r9 (os package) ALPINE-CVE-2022-48174: There is a stack overflow vulnerability in ash.c:6030 in busybox before 1.35. In; fixed in 1.36.1-r1  [alpine-3.18.0:/lib/apk/db/installed]
  CRITICAL openssl@3.1.0-r4 (os package) ALPINE-CVE-2024-5535: Issue summary: Calling the OpenSSL API function SSL_select_next_proto with an em; fixed in 3.1.6-r0  [alpine-3.18.0:/lib/apk/db/installed]
  HIGH     musl@1.2.4-r0 (os package) ALPINE-CVE-2025-26519: musl libc 0.9.13 through 1.2.5 before 1.2.6 has an out-of-bounds write vulnerabi; fixed in 1.2.4-r3  [alpine-3.18.0:/lib/apk/db/installed]
  ...

$ frame deps --rootfs debian-12.0 --vulns
202 known vulnerabilities:
  ...
```

Both counts are what OSV's own API answers for every one of these packages at these versions (`tests/test_sca_container.py`). Versions are compared as the package managers compare them (dpkg's `~` and epochs, apk's `-r` revisions and `_rc` suffixes), checked against `dpkg --compare-versions` and `apk version -t`.

## What to upgrade

```console
$ frame deps --rootfs alpine-3.18.0 --vulns --plan
Upgrade plan (3 packages):
  busybox 1.36.0-r9 -> 1.36.1-r7: upgrade it in the image (apt-get / apk upgrade, or a newer base image)  [alpine-3.18.0:/lib/apk/db/installed; fixes 5]
  musl 1.2.4-r0 -> 1.2.4-r3: upgrade it in the image (apt-get / apk upgrade, or a newer base image)  [alpine-3.18.0:/lib/apk/db/installed; fixes 1]
  openssl 3.1.0-r4 -> 3.1.8-r0: upgrade it in the image (apt-get / apk upgrade, or a newer base image)  [alpine-3.18.0:/lib/apk/db/installed; fixes 16]
```

There is no manifest to edit, so `--apply` lists these for a person: upgrade them in the Dockerfile (`apk upgrade`, `apt-get upgrade`) or rebuild on a newer base image.

## Language packages in an image

An application image also holds what pip, npm or a build copied into it. Frame reads those from what the package managers leave: Python's `*.dist-info/METADATA`, each `node_modules/<name>/package.json`, and each jar's `META-INF/maven/**/pom.properties` (also inside a Spring Boot or WAR archive).

```console
$ frame deps --rootfs app-image --vulns
  app-image:/var/lib/dpkg/status  (Debian:12 installed): 79 packages, direct unknown
  app-image:/app/lib/commons-text-1.9.jar  (Maven image): 1 packages, direct unknown
  app-image:/usr/local/lib/python3.12/site-packages  (PyPI image): 7 packages, direct unknown
  app-image:/app/node_modules  (npm image): 51 packages, direct unknown
warning: app-image: 2 language package(s) installed by the OS package manager are covered by the distribution's advisories
181 known vulnerabilities:
  CRITICAL org.apache.commons:commons-text@1.9 (dependency) GHSA-599f-7c49-w659: Arbitrary code execution in Apache Commons Text; fixed in 1.10.0  [app-image:/app/lib/commons-text-1.9.jar]
  CRITICAL PyYAML@5.3.1 (dependency) GHSA-8q59-q68h-6hv4: Improper Input Validation in PyYAML; fixed in 5.4  [app-image:/usr/local/lib/python3.12/site-packages]
  ...
```

- The lists equal what the image's own tools report: `importlib.metadata` for pip's packages, `npm ls --all` for the npm tree, and the jar's own `pom.properties` (Text4Shell's commons-text 1.9).
- The image also has Debian's `python3-urllib3` 1.26.12 and `python3-six`. dpkg owns their files, and Debian patches the packages it ships without changing the upstream version, so matching them against PyPI's advisories would report fixes Debian already made. They are left to Debian's advisories, and the warning counts them. pip's own urllib3 1.26.4 in `/usr/local` is matched against PyPI.
- A jar without `pom.properties` is counted in a warning, never named from its file name.

```console
$ frame deps --rootfs app-image --vulns --plan
Upgrade plan (44 packages):
  org.apache.commons:commons-text 1.9 -> 1.10.0: replace the jar the image copies (or rebuild the application with the fixed version)  [app-image:/app/lib/commons-text-1.9.jar; fixes 1]
  lodash 4.17.20 -> 4.18.0: upgrade it in the project whose node_modules the image copies, and rebuild  [app-image:/app/node_modules; fixes 5]
  PyYAML 5.3.1 -> 5.4: upgrade it in the image's pip install step (or its requirements file)  [app-image:/usr/local/lib/python3.12/site-packages; fixes 1]
  ...
```

When you have the project that built the image, scanning it (`frame deps .`) gives more: direct versus transitive, and upgrades applied to its manifests. Reading the image tells you what actually shipped.

## In CI, an SBOM, licences

```bash
frame deps --image myapp:latest --vulns --fail-on critical         # exit 1 on a critical OS package
frame deps --rootfs alpine-3.18.0 --sbom cyclonedx -o sbom.json    # pkg:apk/alpine/openssl@3.1.0-r4?distro=3.18 ...
```

Alpine records each package's licence, so the SBOM and `frame deps --licenses` have them without fetching anything. Distributions other than Debian, Ubuntu and Alpine are reported as not covered, never guessed.

See [docs/dependencies.md](../../docs/dependencies.md#container-images).
