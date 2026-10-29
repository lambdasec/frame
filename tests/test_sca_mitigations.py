"""Configuration mitigations: curated per advisory (data/mitigations), and found where a running
application gets them (Dockerfile, Compose, Kubernetes, systemd, shell, .env, properties files,
Java source). Build-time JVM settings never count."""

import json
from pathlib import Path

import pytest

from frame.sca.mitigations import (MitigationError, annotate, builtin, check, format_lines, project_settings)

FASTJSON = "GHSA-pv7h-hx5h-mgfj"
LOG4SHELL = "GHSA-jfh8-c2jp-5v3q"


def finding(adv, package, version, aliases=()):
    return {"id": adv, "aliases": list(aliases), "ecosystem": "Maven", "package": package, "version": version}


def write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


def settings(root, **kw):
    return {(s.kind, s.key, s.value, s.via) for s in project_settings(root, **kw)}


def test_builtin_data_is_valid_and_cites_evidence():
    data = builtin("Maven")
    assert data[FASTJSON][0]["complete"] is True
    log4j = data[LOG4SHELL][0]
    assert log4j["complete"] is False and "45046" in log4j["caveat"]


def test_validation_is_strict():
    good = {"package": "g:a", "versions": "[1,)", "complete": True, "summary": "s", "references": ["r"],
            "ways": [{"kind": "env", "key": "K", "value": "1"}]}
    check({"X": [good]}, "t")
    for bad in ({**good, "complete": False},                       # partial without a caveat
                {**good, "references": []},                        # no evidence
                {**good, "ways": [{"kind": "registry", "key": "k"}]},
                {**good, "extra": 1}):
        with pytest.raises(MitigationError):
            check({"X": [bad]}, "t")


def test_dockerfile_runtime_settings_and_not_build_ones(tmp_path):
    write(tmp_path, {"Dockerfile": (
        "FROM eclipse-temurin:17\n"
        "RUN mvn -Dfastjson.parser.safeMode=true package\n"             # build time: not the app
        "ENV JAVA_TOOL_OPTIONS=\"-Xmx512m -Dlog4j2.formatMsgNoLookups=true\" \\\n"
        "    LOG4J_FORMAT_MSG_NO_LOOKUPS=true\n"
        "ENV APP_MODE production\n"
        "CMD [\"java\", \"-Dfastjson.parser.safeMode=true\", \"-jar\", \"app.jar\"]\n"),
        ".mvn/jvm.config": "-Dfastjson.parser.safeMode=true\n",           # Maven's own JVM
        "gradle.properties": "org.gradle.jvmargs=-Dfastjson.parser.safeMode=true\n"})
    got = settings(tmp_path)
    assert ("jvm-property", "log4j2.formatMsgNoLookups", "true", "JAVA_TOOL_OPTIONS") in got
    assert ("env", "LOG4J_FORMAT_MSG_NO_LOOKUPS", "true", "Dockerfile ENV") in got
    assert ("env", "APP_MODE", "production", "Dockerfile ENV") in got
    assert ("jvm-property", "fastjson.parser.safeMode", "true", "Dockerfile CMD") in got
    assert sum(1 for s in got if s[1] == "fastjson.parser.safeMode") == 1   # RUN, jvm.config, gradle: none


def test_compose_kubernetes_systemd_shell_and_env_files(tmp_path):
    write(tmp_path, {
        "docker-compose.yml": ("services:\n  api:\n    image: shop\n    environment:\n"
                               "      - LOG4J_FORMAT_MSG_NO_LOOKUPS=true\n"
                               "    command: [\"java\", \"-Dfastjson.parser.safeMode=true\", \"-jar\", \"a.jar\"]\n"),
        "k8s/deploy.yaml": ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: shop}\nspec:\n  template:\n"
                            "    spec:\n      containers:\n        - name: shop\n          env:\n"
                            "            - name: JAVA_OPTS\n              value: \"-Dlog4j2.formatMsgNoLookups=true\"\n"
                            "---\napiVersion: v1\nkind: Service\nmetadata: {name: shop}\n"),
        "deploy/shop.service": ("[Service]\nEnvironment=\"JDK_JAVA_OPTIONS=-Dfastjson.parser.safeMode=true\"\n"
                                "ExecStart=/usr/bin/java -Dlog4j2.formatMsgNoLookups=true -jar /opt/shop.jar\n"),
        "bin/start.sh": ("#!/bin/sh\nexport JAVA_OPTS=\"-Dfastjson.parser.safeMode=true\"\n"
                         "echo -Dlog4j2.formatMsgNoLookups=true\n"                  # not a java command
                         "exec java -Dlog4j2.formatMsgNoLookups=true -jar shop.jar\n"),
        ".env": "LOG4J_FORMAT_MSG_NO_LOOKUPS='true'\n# COMMENTED=1\n",
        "config/not-k8s.yaml": "containers:\n  - env: [{name: X, value: y}]\n",     # no kind/apiVersion
    })
    got = {(s.kind, s.key, s.value, s.via, s.location.split(":")[0]) for s in project_settings(tmp_path)}
    assert ("env", "LOG4J_FORMAT_MSG_NO_LOOKUPS", "true", "Compose", "docker-compose.yml") in got
    assert ("jvm-property", "fastjson.parser.safeMode", "true", "Compose command", "docker-compose.yml") in got
    assert ("jvm-property", "log4j2.formatMsgNoLookups", "true", "JAVA_OPTS", "k8s/deploy.yaml") in got
    assert ("jvm-property", "fastjson.parser.safeMode", "true", "JDK_JAVA_OPTIONS", "deploy/shop.service") in got
    assert ("jvm-property", "log4j2.formatMsgNoLookups", "true", "systemd ExecStart", "deploy/shop.service") in got
    assert ("jvm-property", "fastjson.parser.safeMode", "true", "JAVA_OPTS", "bin/start.sh") in got
    assert ("jvm-property", "log4j2.formatMsgNoLookups", "true", "java command line", "bin/start.sh") in got
    assert sum(1 for s in got if s[4] == "bin/start.sh" and s[1] == "log4j2.formatMsgNoLookups") == 1   # not echo
    assert ("env", "LOG4J_FORMAT_MSG_NO_LOOKUPS", "true", ".env", ".env") in got
    assert not any(s[4] == "config/not-k8s.yaml" for s in got)
    assert ("env", "COMMENTED", "1", ".env", ".env") not in got


def test_java_source_and_properties_files(tmp_path):
    write(tmp_path, {
        "src/main/java/shop/Boot.java": (
            "package shop;\nimport com.alibaba.fastjson.parser.ParserConfig;\n"
            "public class Boot {\n  static {\n    ParserConfig.getGlobalInstance().setSafeMode(true);\n"
            "    System.setProperty(\"log4j2.formatMsgNoLookups\", \"true\");\n"
            "    System.setProperty(\"other\", someValue());\n  }\n}\n"),
        "src/main/resources/fastjson.properties": "# safe\nfastjson.parser.safeMode = true\n",
        "src/main/resources/application.properties": "fastjson.parser.safeMode=true\n",   # not the file fastjson reads
    })
    got = settings(tmp_path, properties_files={"fastjson.properties"},
                   calls={("ParserConfig.getGlobalInstance()", "setSafeMode")})
    assert ("java-call", "ParserConfig.getGlobalInstance().setSafeMode", "true", "call") in got
    assert ("jvm-property", "log4j2.formatMsgNoLookups", "true", "System.setProperty") in got
    assert ("properties-file", "fastjson.properties:fastjson.parser.safeMode", "true", "fastjson.properties") in got
    assert not any(s[1] == "other" for s in got)                                   # not a literal
    assert not any("application.properties" in s[1] for s in got)


def test_annotate_by_advisory_version_and_value(tmp_path):
    write(tmp_path, {"Dockerfile": "FROM x\nCMD [\"java\", \"-Dfastjson.parser.safeMode=true\", \"-jar\", \"a.jar\"]\n",
                     ".env": "LOG4J_FORMAT_MSG_NO_LOOKUPS=false\n"})
    fs = [finding(FASTJSON, "com.alibaba:fastjson", "1.2.80"),
          finding(FASTJSON, "com.alibaba:fastjson", "1.2.60"),                      # safeMode does not exist yet
          finding("CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "2.14.1", aliases=[LOG4SHELL]),
          finding("GHSA-other", "com.alibaba:fastjson", "1.2.80")]
    annotate(fs, tmp_path, None)
    fast = fs[0]["mitigations"][0]
    assert fast["complete"] and fast["applied"] and fast["applied"][0]["location"] == "Dockerfile:2"
    assert "mitigations" not in fs[1] and "mitigations" not in fs[3]
    log4j = fs[2]["mitigations"][0]
    assert not log4j["complete"] and log4j["applied"] == []                         # set to false
    text = "\n".join(format_lines(fs[2]))
    assert "partial" in text and "not found" in text and "45046" in text


def test_dataset_entries_win_for_the_same_advisory(tmp_path):
    import gzip
    from frame.sca.mitigations import load, mitigations_path
    entry = {"package": "com.alibaba:fastjson", "versions": "[1.2.68,)", "complete": False, "caveat": "c",
             "summary": "from the dataset", "references": ["r"], "ways": [{"kind": "env", "key": "K", "value": "1"}]}
    (tmp_path / "mitigations").mkdir()
    (tmp_path / mitigations_path("Maven")).write_bytes(gzip.compress(json.dumps(
        {"mitigations": {FASTJSON: [entry]}}).encode()))
    data = load("Maven", tmp_path)
    assert data[FASTJSON][0]["summary"] == "from the dataset" and LOG4SHELL in data


def test_shipped_in_the_advisories_dataset_and_pulled_with_the_ecosystem(tmp_path, monkeypatch):
    from frame.kb.store import KBError, pull
    from frame.sca.advisories import build_advisories
    osv = tmp_path / "osv"
    osv.mkdir()
    (osv / "r.json").write_text(json.dumps({"id": FASTJSON, "modified": "2024-01-01T00:00:00Z", "affected": [
        {"package": {"ecosystem": "Maven", "name": "com.alibaba:fastjson"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.83"}]}]}]}))
    mits = tmp_path / "mits"
    mits.mkdir()
    (mits / "Maven.json").write_text(json.dumps({FASTJSON: builtin("Maven")[FASTJSON]}))
    build_advisories([osv], tmp_path / "mirror", "r1", ["Maven"], mitigations_dir=mits)
    manifest = json.loads((tmp_path / "mirror" / "manifest.json").read_text())
    assert manifest["files"]["mitigations/Maven.json.gz"]["kind"] == "mitigations"
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    got = pull(["maven"], source=str(tmp_path / "mirror"))
    assert "mitigations/Maven.json.gz" in got.files
    (mits / "Maven.json").write_text(json.dumps({FASTJSON: [{"package": "x"}]}))     # invalid: refused
    with pytest.raises(KBError):
        build_advisories([osv], tmp_path / "mirror2", "r1", ["Maven"], mitigations_dir=mits)


def test_frame_deps_shows_a_mitigation_end_to_end(tmp_path, monkeypatch):
    """fastjson 1.2.80 in a pom, safeMode in the Dockerfile: the advisory is reported with the
    mitigation applied, and the VEX statement stays affected with the evidence as a note."""
    import subprocess
    import sys
    from frame.sca.advisories import build_advisories
    osv = tmp_path / "osv"
    osv.mkdir()
    (osv / "r.json").write_text(json.dumps({"id": FASTJSON, "summary": "Unsafe deserialization in fastjson",
        "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2022-25845"], "affected": [
            {"package": {"ecosystem": "Maven", "name": "com.alibaba:fastjson"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.83"}]}]}]}))
    build_advisories([osv], tmp_path / "mirror", "r1", ["Maven"])
    proj = write(tmp_path / "proj", {
        "pom.xml": ("<project><modelVersion>4.0.0</modelVersion><groupId>a</groupId><artifactId>b</artifactId>"
                    "<version>1</version><dependencies><dependency><groupId>com.alibaba</groupId>"
                    "<artifactId>fastjson</artifactId><version>1.2.80</version></dependency></dependencies></project>"),
        "Dockerfile": "FROM x\nENV JAVA_TOOL_OPTIONS=-Dfastjson.parser.safeMode=true\n"})
    env = {"FRAME_KB_CACHE": str(tmp_path / "cache"), "FRAME_ADVISORIES_SOURCE": str(tmp_path / "mirror"),
           "PATH": __import__("os").environ["PATH"]}
    run = lambda *a: subprocess.run([sys.executable, "-m", "frame.cli", *a], capture_output=True, text=True, env=env)
    assert run("kb", "pull", "--advisories", "--project", str(proj)).returncode == 0
    text = run("deps", str(proj), "--vulns").stdout
    assert "mitigation (complete)" in text and "APPLIED at Dockerfile:2 (JAVA_TOOL_OPTIONS)" in text
    vex = json.loads(run("deps", str(proj), "--vex", "openvex").stdout)
    (st,) = vex["statements"]
    assert st["status"] == "affected"                     # evidence, not a decision Frame makes
    assert "complete mitigation is set" in st["status_notes"] and "Dockerfile:2" in st["status_notes"]
    assert "inline_mitigations_already_exist" in st["status_notes"]


# --- writing a mitigation (frame deps --vulns --mitigate) ---------------------------------

def _annotated(root, *fs):
    annotate(list(fs), root, None)
    return list(fs)


def test_propose_prefers_the_artifact_then_the_dockerfile_and_never_a_partial_one(tmp_path):
    from frame.sca.mitigations import propose, project_settings
    root = write(tmp_path, {"pom.xml": "<project/>",
                            "Dockerfile": ("FROM maven:3 AS build\nRUN mvn package\nFROM eclipse-temurin:17\n"
                                           "ENV JAVA_TOOL_OPTIONS=-Xmx1g\nCMD [\"java\", \"-jar\", \"/a.jar\"]\n")})
    fast = finding(FASTJSON, "com.alibaba:fastjson", "1.2.80")
    fast["path"] = "pom.xml"
    log4j = finding("CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "2.14.1", aliases=[LOG4SHELL])
    log4j["path"] = "pom.xml"
    edits, manual = propose(_annotated(root, fast, log4j), root)
    (docker,) = edits                                                  # no resources dir: the Dockerfile
    lines = docker.after.splitlines()
    added = 'ENV JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS} -Dfastjson.parser.safeMode=true"'
    assert lines.index(added) == len(lines) - 2 and lines.index(added) > lines.index("FROM eclipse-temurin:17")
    assert len(manual) == 1 and "partial" in manual[0] and "45046" in manual[0]
    (root / "Dockerfile").write_text(docker.after)
    got = {(s.key, s.value, s.via) for s in project_settings(root)}
    assert ("fastjson.parser.safeMode", "true", "JAVA_TOOL_OPTIONS") in got        # Frame's reader sees it
    assert ("JAVA_TOOL_OPTIONS", "-Xmx1g", "Dockerfile ENV") in {(s.key, s.value, s.via) for s in project_settings(root)
                                                                  if s.kind == "env"}
    (root / "src" / "main" / "resources").mkdir(parents=True)
    (root / "Dockerfile").write_text("FROM x\n")
    fast2 = finding(FASTJSON, "com.alibaba:fastjson", "1.2.80")
    fast2["path"] = "pom.xml"
    (props,) = propose(_annotated(root, fast2), root)[0]
    assert props.path == "src/main/resources/fastjson.properties" and props.after == "fastjson.parser.safeMode=true\n"


def test_nowhere_to_write_it_is_manual(tmp_path):
    from frame.sca.mitigations import propose
    root = write(tmp_path, {"pom.xml": "<project/>"})
    f = finding(FASTJSON, "com.alibaba:fastjson", "1.2.80")
    f["path"] = "pom.xml"
    edits, manual = propose(_annotated(root, f), root)
    assert not edits and "-Dfastjson.parser.safeMode=true" in manual[0]


def test_cli_mitigate_apply_confirms_and_touches_nothing_else(tmp_path):
    import subprocess
    import sys
    from frame.sca.advisories import build_advisories
    osv = tmp_path / "osv"
    osv.mkdir()
    (osv / "r.json").write_text(json.dumps({"id": FASTJSON, "summary": "Unsafe deserialization in fastjson",
        "modified": "2024-01-01T00:00:00Z", "affected": [
            {"package": {"ecosystem": "Maven", "name": "com.alibaba:fastjson"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.83"}]}]}]}))
    build_advisories([osv], tmp_path / "mirror", "r1", ["Maven"])
    pom = ("<project><modelVersion>4.0.0</modelVersion><groupId>a</groupId><artifactId>b</artifactId>"
           "<version>1</version><dependencies><dependency><groupId>com.alibaba</groupId>"
           "<artifactId>fastjson</artifactId><version>1.2.80</version></dependency></dependencies></project>")
    proj = write(tmp_path / "proj", {"pom.xml": pom, "src/main/resources/application.properties": "a=b\n"})
    env = {"FRAME_KB_CACHE": str(tmp_path / "cache"), "FRAME_ADVISORIES_SOURCE": str(tmp_path / "mirror"),
           "PATH": __import__("os").environ["PATH"]}
    run = lambda *a: subprocess.run([sys.executable, "-m", "frame.cli", *a], capture_output=True, text=True, env=env)
    assert run("kb", "pull", "--advisories", "--project", str(proj)).returncode == 0
    out = run("deps", str(proj), "--vulns", "--mitigate", "--apply").stdout
    assert "confirmed by re-reading the project: com.alibaba:fastjson@1.2.80 GHSA-pv7h-hx5h-mgfj" in out
    assert (proj / "src/main/resources/fastjson.properties").read_text() == "fastjson.parser.safeMode=true\n"
    assert (proj / "pom.xml").read_text() == pom                        # --mitigate --apply writes no upgrade
    again = run("deps", str(proj), "--vulns", "--mitigate").stdout
    assert "nothing to apply" in again and "APPLIED" in again           # idempotent


# -- Spring Boot properties (spring-property): from the Spring advisories' own workarounds ---------

CLOUDFOUNDRY = "GHSA-g5h3-w546-pj7f"          # CVE-2023-20873
ACTUATOR = "org.springframework.boot:spring-boot-actuator-autoconfigure"


def test_spring_advisory_workarounds_are_curated_with_their_evidence():
    data = builtin("Maven")
    for adv, key in [(CLOUDFOUNDRY, "management.cloudfoundry.enabled"),
                     ("GHSA-3gx9-37ww-9qw6", "management.endpoint.gateway.enabled"),
                     ("GHSA-jjfh-589g-3hjx", "management.metrics.enable.http.server.requests"),
                     ("GHSA-v94h-hvhg-mf9h", "management.metrics.enable.http.server.requests")]:
        [e] = data[adv]
        assert e["ways"] == [{"kind": "spring-property", "key": key, "value": "false"}]
        assert any(r.startswith("https://spring.io/security/cve-") for r in e["references"])
    assert data["GHSA-v94h-hvhg-mf9h"][0]["complete"] is False      # Spring Framework without Boot


@pytest.mark.parametrize("files,via", [
    ({"src/main/resources/application.properties": "server.port=8080\nmanagement.cloudfoundry.enabled=false\n"},
     "application.properties"),
    ({"src/main/resources/application.yml": "management:\n  cloudfoundry:\n    enabled: false\n"}, "application.yml"),
    ({"config/application-prod.yaml": "management:\n  cloud-foundry:\n    enabled: false\n"}, "application-prod.yaml"),
    ({"Dockerfile": "FROM eclipse-temurin:17\nENV MANAGEMENT_CLOUDFOUNDRY_ENABLED=false\n"}, "Dockerfile ENV"),
    ({"Dockerfile": "FROM eclipse-temurin:17\nCMD [\"java\", \"-Dmanagement.cloudfoundry.enabled=false\", \"-jar\", \"a.jar\"]\n"},
     "Dockerfile CMD"),
    ({"Dockerfile": "FROM eclipse-temurin:17\nCMD [\"java\", \"-jar\", \"a.jar\", \"--management.cloudfoundry.enabled=false\"]\n"},
     "Dockerfile CMD argument"),
])
def test_a_spring_property_is_found_wherever_spring_boot_reads_it(tmp_path, files, via):
    """Spring's relaxed binding: application.properties / .yml (any profile), an environment variable
    (dots as `_`), a system property, a command-line argument; `cloud-foundry` is `cloudfoundry`."""
    write(tmp_path, files)
    fs = [finding(CLOUDFOUNDRY, ACTUATOR, "2.7.10")]
    annotate(fs, tmp_path, None)
    [m] = fs[0]["mitigations"]
    assert m["complete"] and [a["via"] for a in m["applied"]] == [via]
    assert "MANAGEMENT_CLOUDFOUNDRY_ENABLED=false" in m["ways"][0]


@pytest.mark.parametrize("files", [
    {"src/main/resources/application.properties": "management.cloudfoundry.enabled=true\n"},     # the default
    {"src/main/resources/application.yml": "management:\n  cloudfoundry:\n    skip-ssl-validation: false\n"},
    {"src/main/resources/fastjson.properties": "management.cloudfoundry.enabled=false\n"},      # not Spring's file
])
def test_a_different_value_or_file_is_not_the_mitigation(tmp_path, files):
    write(tmp_path, files)
    fs = [finding(CLOUDFOUNDRY, ACTUATOR, "2.7.10")]
    annotate(fs, tmp_path, None)
    assert fs[0]["mitigations"][0]["applied"] == []


def test_propose_writes_a_spring_property_into_the_application_s_own_configuration(tmp_path):
    from frame.sca.mitigations import propose
    write(tmp_path, {"pom.xml": "<project/>\n", "src/main/resources/application.properties": "server.port=8080\n"})
    fs = [{**finding(CLOUDFOUNDRY, ACTUATOR, "2.7.10"), "path": "pom.xml"}]
    annotate(fs, tmp_path, None)
    changes, manual = propose(fs, tmp_path)
    assert not manual and [(c.path, c.after) for c in changes] == [
        ("src/main/resources/application.properties", "server.port=8080\nmanagement.cloudfoundry.enabled=false\n")]


def test_two_advisories_one_setting_is_written_once(tmp_path):
    """fastjson's GHSA-pv7h-hx5h-mgfj and GHSA-crf3-v9rr-v7hj share safeMode: one line."""
    from frame.sca.mitigations import propose
    write(tmp_path, {"pom.xml": "<project/>\n", "src/main/resources/.keep": ""})
    fs = [{**finding(FASTJSON, "com.alibaba:fastjson", "1.2.80"), "path": "pom.xml"},
          {**finding("GHSA-crf3-v9rr-v7hj", "com.alibaba:fastjson", "1.2.80"), "path": "pom.xml"}]
    annotate(fs, tmp_path, None)
    assert all(f["mitigations"][0]["complete"] for f in fs)
    changes, manual = propose(fs, tmp_path)
    assert not manual and [(c.path, c.after) for c in changes] == [
        ("src/main/resources/fastjson.properties", "fastjson.parser.safeMode=true\n")]
