# Configuration mitigations: fastjson and Log4j

A Maven service with two dependencies that have well-known vulnerabilities (and, in `gateway/`, a Spring Cloud Gateway service, below): fastjson 1.2.80 (its `JSON.parseObject` is how orders are read, `src/main/java/shop/Orders.java`) and log4j-core 2.14.1. The `Dockerfile` already sets one mitigation. Every output below is what the command prints, offline from `offline-advisories/` (`tests/test_examples.py` checks).

```bash
cd examples/java-mitigation
frame kb pull --advisories --source offline-advisories
```

## What is mitigated already, and how much it is worth

```console
$ frame deps --vulns
12 known vulnerabilities:
  CRITICAL org.apache.logging.log4j:log4j-core@2.14.1 (direct) GHSA-jfh8-c2jp-5v3q: Remote code injection in Log4j; fixed in 2.15.0  [pom.xml]
           mitigation (partial): disable message lookups (log4j2.formatMsgNoLookups=true): APPLIED at Dockerfile:7 (Dockerfile ENV)
             caveat: does NOT mitigate CVE-2021-45046 (GHSA-7rjr-3q55-vv33), and Apache withdrew this advice: upgrade, or remove the JndiLookup class from the classpath
  HIGH     com.alibaba:fastjson@1.2.80 (direct) GHSA-pv7h-hx5h-mgfj: Unsafe deserialization in com.alibaba:fastjson; fixed in 1.2.83  [pom.xml]
           mitigation (complete): enable fastjson safeMode, which disables autoType completely: not found; set one of -Dfastjson.parser.safeMode=true; fastjson.parser.safeMode=true in fastjson.properties; ...
  ...
```

Two things to read here:

- **Log4Shell:** the Dockerfile's `ENV LOG4J_FORMAT_MSG_NO_LOOKUPS=true` is found, at the line that sets it. It is reported as **partial**, with the advisory's own caveat: it does not stop CVE-2021-45046, which is listed above it, still open. Only the upgrade fixes Log4j.
- **fastjson:** safeMode would stop GHSA-pv7h-hx5h-mgfj completely (the advisory names it as the workaround, and fastjson's wiki documents it from 1.2.68), but nothing sets it.

The curated entries cite their evidence: `frame/sca/data/mitigations/Maven.json`.

## Writing the missing one

```console
$ frame deps --vulns --mitigate
Configuration mitigations (dry run; --apply writes them):
--- a/gateway/src/main/resources/application.properties
+++ b/gateway/src/main/resources/application.properties
@@ -0,0 +1 @@
+management.cloudfoundry.enabled=false

--- a/src/main/resources/fastjson.properties
+++ b/src/main/resources/fastjson.properties
@@ -0,0 +1 @@
+fastjson.parser.safeMode=true

$ frame deps --vulns --mitigate --apply
Applied and confirmed by re-reading the project: com.alibaba:fastjson@1.2.80 GHSA-crf3-v9rr-v7hj, com.alibaba:fastjson@1.2.80 GHSA-pv7h-hx5h-mgfj, org.springframework.boot:spring-boot-actuator-autoconfigure@2.6.3 GHSA-g5h3-w546-pj7f
```

It is written to a properties file fastjson reads from the classpath, so it travels inside the jar whatever runs it. Without a `src/main/resources`, it would go into the Dockerfile's last stage as `ENV JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS} -Dfastjson.parser.safeMode=true"`. A partial mitigation is never written for you.

Nothing here changes a version. `--plan` shows the upgrades. fastjson's newer GHSA-crf3-v9rr-v7hj (CVE-2026-16723) has no fixed version in OSV's record, but fastjson's own advisory for it lists safeMode as a complete mitigation, so the same one line covers both advisories (it is written once).

A mitigation found is evidence, not a verdict: a VEX document from `frame deps --vex openvex` keeps the advisory `affected`, with the mitigation in its notes, until you record `inline_mitigations_already_exist` in `.frame/vex.toml`.

## Spring Boot properties

`gateway/` is a Spring Cloud Gateway 3.1.0 service on Spring Boot 2.6.3. Spring's advisories name a property as the workaround for both of its critical advisories, and its `application.yml` already sets one of them:

```console
$ frame deps gateway --vulns
2 known vulnerabilities:
  CRITICAL org.springframework.boot:spring-boot-actuator-autoconfigure@2.6.3 (direct) GHSA-g5h3-w546-pj7f: Spring Boot Security Bypass with Wildcard Pattern Matching on Cloud Foundry; fixed in 2.6.15  [pom.xml]
           mitigation (complete): disable the Cloud Foundry actuator endpoints (management.cloudfoundry.enabled=false): not found; set one of management.cloudfoundry.enabled=false (application.properties / .yml, -D, --argument, or MANAGEMENT_CLOUDFOUNDRY_ENABLED=false)
  CRITICAL org.springframework.cloud:spring-cloud-gateway@3.1.0 (direct) GHSA-3gx9-37ww-9qw6: Spring Cloud Gateway vulnerable to Code Injection when Gateway Actuator endpoint; fixed in 3.1.1  [pom.xml]
           mitigation (complete): disable the Gateway actuator endpoint (management.endpoint.gateway.enabled=false), through which the SpEL injection is reached: APPLIED at src/main/resources/application.yml:12 (application.yml)
```

A Spring Boot property is found wherever Spring Boot reads it, under its relaxed names: `application.properties` or `application.yml` (any profile; YAML keys are flattened, `cloud-foundry` is `cloudfoundry`), a `-D` system property, a `--key=value` argument on the `java` command line, or the environment variable Spring Boot binds (`MANAGEMENT_CLOUDFOUNDRY_ENABLED`). The missing one goes into the application's own configuration:

```console
$ frame deps gateway --vulns --mitigate
Configuration mitigations (dry run; --apply writes them):
--- a/src/main/resources/application.properties
+++ b/src/main/resources/application.properties
@@ -0,0 +1 @@
+management.cloudfoundry.enabled=false
```

Each entry quotes the workaround from Spring's advisory (spring.io/security/cve-2022-22947, cve-2023-20873) and the source showing the property exists in every version it is offered for (`@ConditionalOnProperty(prefix = "management.cloudfoundry", name = "enabled")` from Spring Boot 2.0.0; the gateway endpoint's `id = "gateway"`).

See [docs/dependencies.md](../../docs/dependencies.md#configuration-mitigations).
