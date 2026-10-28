# Configuration mitigations: fastjson and Log4j

A Maven service with two dependencies that have well-known vulnerabilities: fastjson 1.2.80 (its `JSON.parseObject` is how orders are read, `src/main/java/shop/Orders.java`) and log4j-core 2.14.1. The `Dockerfile` already sets one mitigation. Every output below is what the command prints, offline from `offline-advisories/` (`tests/test_examples.py` checks).

```bash
cd examples/java-mitigation
frame kb pull --advisories --source offline-advisories
```

## What is mitigated already, and how much it is worth

```console
$ frame deps --vulns
10 known vulnerabilities:
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
--- a/src/main/resources/fastjson.properties
+++ b/src/main/resources/fastjson.properties
@@ -0,0 +1 @@
+fastjson.parser.safeMode=true

$ frame deps --vulns --mitigate --apply
Applied and confirmed by re-reading the project: com.alibaba:fastjson@1.2.80 GHSA-pv7h-hx5h-mgfj
```

It is written to a properties file fastjson reads from the classpath, so it travels inside the jar whatever runs it. Without a `src/main/resources`, it would go into the Dockerfile's last stage as `ENV JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS} -Dfastjson.parser.safeMode=true"`. A partial mitigation is never written for you.

Nothing here changes a version. `--plan` shows the upgrades, and fastjson's newer GHSA-crf3-v9rr-v7hj has no fixed version and no curated mitigation, so it stays open either way.

A mitigation found is evidence, not a verdict: a VEX document from `frame deps --vex openvex` keeps the advisory `affected`, with the mitigation in its notes, until you record `inline_mitigations_already_exist` in `.frame/vex.toml`.

See [docs/dependencies.md](../../docs/dependencies.md#configuration-mitigations).
