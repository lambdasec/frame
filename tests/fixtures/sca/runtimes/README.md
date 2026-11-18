# Language runtime fixtures

Real files, recorded 2026-11-18, for `tests/test_sca_runtimes.py`.

## `images/`

The version files of official images (linux/amd64), read from the registry by digest, keeping
only the files `frame.sca.runtimes` reads (and `os-release`):

| Directory | Image | Digest |
|---|---|---|
| `eclipse-temurin_17-jre` | `eclipse-temurin:17-jre` | `sha256:fb2cec8da84e3f086b59e29bf432d372e396fe0c247adcfb89303a28c2e313c0` |
| `eclipse-temurin_8-jre` | `eclipse-temurin:8-jre` | `sha256:1ddd5cc9ac1dac409c938e97db3e39553e89355632cd93ef3bd2604c42a2adc2` |
| `amazoncorretto_21-al2023-headless` | `amazoncorretto:21-al2023-headless` | `sha256:991deb593574c5952eb7e5793dbe88a0173cc6848a9f15927cbdafd4716db15e` |
| `ibm-semeru-runtimes_open-17-jre` | `ibm-semeru-runtimes:open-17-jre` | `sha256:4e359e559587bf5b75c8e4c2baa5b1c4cdc2681cbd7edac158ff7314d8a3da58` |
| `node_22-slim` | `node:22-slim` | `sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee` |
| `node_22-alpine` | `node:22-alpine` | `sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a` |
| `python_3.12-slim` | `python:3.12-slim` | `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b` |
| `ruby_3.3-slim` | `ruby:3.3-slim` | `sha256:db3ad6dd68a886d51a187fb9bf486052f2976cdbe3b750169c25092aba1297fa` |
| `aspnet8` | `mcr.microsoft.com/dotnet/aspnet:8.0` | `sha256:dccacae9e0e103b5d3ba5fbe442dd8d3316b990cd8f2ec9be0a0ec9db0c0e520` |

## Advisory sources

* `runtimes/openjdk/*.html`: OpenJDK Vulnerability Group advisories
  (`https://openjdk.org/groups/vulnerability/advisories/<date>`): 2026-11-17 (CVE-2026-114938,
  "Java4Shell"), 2026-10-20 (line 26 no longer listed), 2025-04-15, 2021-10-19 (line 17 marked
  with no last affected version named), 2019-04-16 (an unpadded date in the heading).
* `node-vulns.json.gz`: `nodejs/security-wg` `vuln/core/index.json` (MIT).
  `node-releases.json.gz`: `https://nodejs.org/dist/index.json`, version and date only.
* `ruby.tar.gz`: `rubysec/ruby-advisory-db` `rubies/ruby/*.yml` (as `advisories/`) and
  `ruby/www.ruby-lang.org` `_data/releases.yml`.
* `dotnet-osv.json.gz`: OSV's records for every advisory OSV's API answers for
  `Microsoft.NETCore.App.Runtime.linux-x64` and `Microsoft.AspNetCore.App.Runtime.linux-x64` at
  8.0.10 and 8.0.34; `dotnet-osv-expected.json` the API's answers.
* `cpython-osv.json.gz`: eight of OSV's GIT records for `github.com/python/cpython` (six OSV's API
  answers for tag `v3.12.4`, two it does not); `cpython-osv-expected.json` the API's answers for
  `v3.12.4` and `v3.12.16`, restricted to those eight.

## Ground truth

* `node_semver_expected.json.gz`: for each security WG advisory, the releases npm's `semver`
  7.6.3 says are affected (`satisfies(vulnerable) && !satisfies(patched)`, the rule
  `is-my-node-vulnerable` applies), made by `node node_semver_expected.js VULNS RELEASES`.
* `ruby_gem_expected.json`: for each Ruby advisory, the releases RubyGems' `Gem::Requirement`
  (Ruby 2.6.10) says satisfy none of `patched_versions` / `unaffected_versions`, made by
  `ruby ruby_gem_expected.rb DIR` (DIR holding `releases.yml` and `advisories/`).
* `jdk_order.tsv`: `Runtime.Version.compareToIgnoreOptional` (OpenJDK 11.0.28) on every pair of
  `JdkOrder.java`'s versions, except pairs with a build number (`17.0.21+9`): Java orders a
  version without a build first, and Frame ignores builds on purpose (OpenJDK's advisories and a
  release file's `JAVA_VERSION` carry none).
