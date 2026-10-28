"""The examples in examples/ run as their READMEs say: each command, on a copy of the example,
offline from its recorded data, prints the lines the README shows. A change that alters what a
user would see breaks this test instead of silently outdating the docs."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def frame(cwd: Path, env: dict, *args: str) -> str:
    proc = subprocess.run([sys.executable, "-m", "frame.cli", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=600)
    return proc.stdout + proc.stderr


@pytest.fixture
def express(tmp_path):
    work = tmp_path / "sca-express"
    shutil.copytree(EXAMPLES / "sca-express", work)
    env = {**os.environ, "FRAME_KB_CACHE": str(tmp_path / "kb"),
           "FRAME_REGISTRY_CACHE": str(work / "offline-registry"), "PYTHONPATH": str(ROOT)}
    env.pop("FRAME_ADVISORIES_SOURCE", None)
    out = frame(work, env, "kb", "pull", "--advisories", "--source", "offline-advisories")
    assert "1 files" in out, out
    return work, env


def test_sca_express_walkthrough(express):
    work, env = express
    readme = (work / "README.md").read_text()
    shown = [
        (("deps",), ["127 packages, 3 direct", "npm: 127 distinct packages (3 direct, 76 dev only)"]),
        (("deps", "--vulns"), ["37 known vulnerabilities:",
                               "lodash@4.17.20 (direct, called) GHSA-35jh-r3h4-6jhm: Command Injection in lodash",
                               "calls lodash.template at app.js:8", "calls lodash.template at app.js:14"]),
        (("scan", ".", "--sca"), ["template_injection", "app.js:8:8", "Scanned 1 file: 1 finding (1 high)",
                                  "tainted: GHSA-35jh-r3h4-6jhm reached by attacker data at app.js:8 (solver-verified)"]),
        (("deps", "--vulns", "--plan"), ["express 4.17.1 -> 4.20.0: raise the project's requirement",
                                         "qs 6.7.0 -> 6.16.1: override"]),
        (("deps", "--vulns", "--plan", "--registry"), [
            "Upgrade plan (14 packages):", "express 4.17.1 -> 4.22.3: raise the project's requirement",
            "nanoid@3.3.3: leaves the tree", "qs 6.7.0 -> 6.16.1: re-lock to it (admitted by the solved upgrades)",
            "mocha 10.2.0 -> 12.0.0 [major]", '+    "express": "4.22.3",', '+    "lodash": "~4.18.1"']),
        (("deps", "--licenses"), ["Licences: 51 packages, 51 acceptable, 0 violation(s), 0 unknown"]),
    ]
    for args, lines in shown:
        out = frame(work, env, *args)
        for line in lines:
            assert line in out, (args, line, out[-2000:])
            assert line in readme, f"README does not show {line!r}"
    assert "override" not in frame(work, env, "deps", "--vulns", "--plan", "--registry").split("Edits")[0]
    import json
    vex = json.loads(frame(work, env, "deps", "--vex", "openvex"))
    assert len(vex["statements"]) == 37 and all(s["status"] == "affected" for s in vex["statements"])
    sbom = json.loads(frame(work, env, "deps", "--sbom", "cyclonedx"))
    assert sbom["specVersion"] == "1.6" and len(sbom["components"]) == 127


def _example(tmp_path, name):
    work = tmp_path / name
    shutil.copytree(EXAMPLES / name, work)
    env = {**os.environ, "FRAME_KB_CACHE": str(tmp_path / "kb"), "PYTHONPATH": str(ROOT)}
    env.pop("FRAME_ADVISORIES_SOURCE", None)
    assert "1 files" in frame(work, env, "kb", "pull", "--advisories", "--source", "offline-advisories")
    return work, env


def test_java_mitigation_walkthrough(tmp_path):
    work, env = _example(tmp_path, "java-mitigation")
    readme = (work / "README.md").read_text()
    out = frame(work, env, "deps", "--vulns")
    for line in ["10 known vulnerabilities:",
                 "mitigation (partial): disable message lookups (log4j2.formatMsgNoLookups=true): APPLIED at Dockerfile:7 (Dockerfile ENV)",
                 "caveat: does NOT mitigate CVE-2021-45046 (GHSA-7rjr-3q55-vv33)",
                 "mitigation (complete): enable fastjson safeMode, which disables autoType completely: not found"]:
        assert line in out and line in readme, line
    dry = frame(work, env, "deps", "--vulns", "--mitigate")
    assert "+fastjson.parser.safeMode=true" in dry and not (work / "src/main/resources/fastjson.properties").exists()
    applied = frame(work, env, "deps", "--vulns", "--mitigate", "--apply")
    line = "Applied and confirmed by re-reading the project: com.alibaba:fastjson@1.2.80 GHSA-pv7h-hx5h-mgfj"
    assert line in applied and line in readme
    assert (work / "pom.xml").read_text() == (EXAMPLES / "java-mitigation" / "pom.xml").read_text()   # no upgrade


def test_adapt_werkzeug_plan(tmp_path):
    """The plan runs offline; the rollback and the adaptation need pip and a model, and are
    exercised live in tests/test_sca_adapt.py."""
    work, env = _example(tmp_path, "adapt-werkzeug")
    readme = (work / "README.md").read_text()
    out = frame(work, env, "deps", "--vulns", "--plan")
    for line in ["8 known vulnerabilities:",
                 "werkzeug 2.2.3 -> 3.1.9 [major]: raise the project's requirement  [requirements.txt; fixes 8]",
                 "-werkzeug==2.2.3", "+werkzeug==3.1.9"]:
        assert line in out and line in readme, line


def test_secrets_walkthrough(tmp_path):
    work = tmp_path / "secrets"
    shutil.copytree(EXAMPLES / "secrets", work, ignore=shutil.ignore_patterns("demo"))
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    subprocess.run([sys.executable, "make_demo.py"], cwd=work, check=True, capture_output=True)
    out = frame(work, env, "scan", "demo")
    readme = (work / "README.md").read_text()
    for line in ["demo/billing.js:3:22", "Hardcoded Stripe live secret or restricted key (Stripe format: stripe-live-key)",
                 "demo/deploy.py:6:12", "Hardcoded GitHub token", "demo/deploy.py:11:44",
                 "Hardcoded OpenAI API key (OpenAI format: openai-api-key)", "demo/deploy.py:14:42",
                 "Hardcoded AWS access key ID (AWS format: aws-access-key-id)", "Scanned 2 files: 4 findings (4 critical)"]:
        assert line in out and line in readme, line
    demo = (work / "demo" / "deploy.py").read_text().splitlines()
    assert "IOSFODNN7EXAMPLE" in demo[16] and demo[18].startswith("# A rotated token")   # the README's lines 17, 19
    shutil.rmtree(work / "demo")
    subprocess.run([sys.executable, "make_demo.py", "--history"], cwd=work, check=True, capture_output=True)
    out = frame(work, env, "history", "demo")
    for line in ["4 credential(s) in the history",
                 "Stripe Stripe live secret or restricted key: sk_l... (32 characters) added in e325fd7f4e58 billing.js:3 "
                 "(not in the current tree, still in the history)",
                 "AWS AWS access key ID: AKIA... (20 characters) added in e325fd7f4e58 deploy.py:14 (still in the current tree)"]:
        assert line in out and line in readme, (line, out)


def test_the_repository_holds_no_token_shaped_string():
    """The secrets example assembles its tokens at run time; nothing committed may hold one."""
    from frame.sil.secret_formats import find
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    hits = []
    for f in tracked:
        p = ROOT / f
        if p.suffix in (".py", ".js", ".ts", ".java", ".cs", ".c", ".cpp", ".toml", ".json", ".md", ".yml") and p.is_file():
            for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if find(line):
                    hits.append(f"{f}:{i}")
    assert not hits, hits


def test_ai_apps_walkthrough():
    readme = (EXAMPLES / "ai-apps" / "README.md").read_text()
    frameworks = ROOT / "benchmarks" / "exemplars" / "frameworks"
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    for app, summary in [("python/llm-sdks/vulnerable", "Scanned 1 file: 5 findings (2 critical, 3 medium)"),
                         ("javascript/llm-sdks/vulnerable", "Scanned 1 file: 3 findings (1 critical, 2 medium)"),
                         ("python/mcp-servers/vulnerable", "Scanned 1 file: 2 findings (2 critical)"),
                         ("javascript/mcp-servers/vulnerable", "Scanned 1 file: 2 findings (2 critical)")]:
        out = frame(frameworks, env, "scan", app, "--root", ".")
        assert summary in out and summary in readme, (app, out[-600:])
        for line in [ln.strip() for ln in out.splitlines() if ln.strip().startswith(("Location:", "Description:"))]:
            assert line.replace(str(frameworks) + "/", "") in readme or "Description" in line, line
        safe = frame(frameworks, env, "scan", app.replace("vulnerable", "safe"), "--root", ".")
        assert "0 findings" in safe, (app, safe[-400:])


def test_container_image_walkthrough(tmp_path):
    work = tmp_path / "container-image"
    shutil.copytree(EXAMPLES / "container-image", work)
    env = {**os.environ, "FRAME_KB_CACHE": str(tmp_path / "kb"), "PYTHONPATH": str(ROOT)}
    env.pop("FRAME_ADVISORIES_SOURCE", None)
    assert "8 files" in frame(work, env, "kb", "pull", "--advisories", "--source", "offline-advisories",
                              "--ecosystems", "Debian:12,Alpine:v3.18,PyPI,npm,Maven,Go,crates.io,Rocky Linux:9")
    readme = (work / "README.md").read_text()
    shown = [
        (("deps", "--rootfs", "alpine-3.18.0", "--rootfs", "debian-12.0"),
         ["alpine-3.18.0:/lib/apk/db/installed  (Alpine:v3.18 installed): 10 packages, direct unknown",
          "debian-12.0:/var/lib/dpkg/status  (Debian:12 installed): 63 packages, direct unknown"]),
        (("deps", "--rootfs", "alpine-3.18.0", "--vulns"),
         ["22 known vulnerabilities:", "CRITICAL busybox@1.36.0-r9 (os package) ALPINE-CVE-2022-48174",
          "HIGH     musl@1.2.4-r0 (os package) ALPINE-CVE-2025-26519"]),
        (("deps", "--rootfs", "debian-12.0", "--vulns"), ["202 known vulnerabilities:"]),
        (("deps", "--rootfs", "rocky-9.4", "--vulns"),
         ["rocky-9.4:/var/lib/rpm/rpmdb.sqlite  (Rocky Linux:9 installed): 8 packages, direct unknown",
          "43 known vulnerabilities:",
          "CRITICAL openssl@1:3.0.7-27.el9 (os package) RLSA-2026:1473: Important: openssl security update; "
          "fixed in 1:3.5.1-7.el9_7  [rocky-9.4:/var/lib/rpm/rpmdb.sqlite]"]),
        (("deps", "--rootfs", "app-image", "--vulns"),
         ["app-image:/usr/local/lib/python3.12/site-packages  (PyPI image): 7 packages, direct unknown",
          "app-image:/app/node_modules  (npm image): 51 packages, direct unknown",
          "warning: app-image: 2 language package(s) installed by the OS package manager are covered by the "
          "distribution's advisories", "273 known vulnerabilities:",
          "app-image:/usr/local/bin/svc-go  (Go image): 2 packages, direct unknown",
          "app-image:/usr/local/bin/svc-rust  (crates.io image): 1 packages, direct unknown",
          "UNKNOWN  stdlib@1.21.0 (dependency, called) GO-2025-4010: Insufficient validation of bracketed IPv6 "
          "hostnames in net/url; fixed in 1.24.8  [app-image:/usr/local/bin/svc-go]",
          "contains net/url.Parse (linked into the binary)",
          "CRITICAL org.apache.commons:commons-text@1.9 (dependency) GHSA-599f-7c49-w659"]),
        (("deps", "--rootfs", "app-image", "--vulns", "--plan"),
         ["org.apache.commons:commons-text 1.9 -> 1.10.0: replace the jar the image copies",
          "PyYAML 5.3.1 -> 5.4: upgrade it in the image's pip install step (or its requirements file)",
          "stdlib 1.21.0 -> 1.26.10: rebuild the binary with Go 1.26.10 or later (the standard library is compiled in)",
          "smallvec 1.6.0 -> 1.6.1: rebuild the binary with the crate upgraded (cargo update -p, then cargo auditable build)"]),
        (("deps", "--rootfs", "alpine-3.18.0", "--vulns", "--plan"),
         ["openssl 3.1.0-r4 -> 3.1.8-r0: upgrade it in the image (apt-get / apk / dnf upgrade, or a newer base image)"]),
    ]
    for args, lines in shown:
        out = frame(work, env, *args)
        for line in lines:
            assert line in out and line in readme, (args, line, out[-1500:])
    called = [line for line in frame(work, env, "deps", "--rootfs", "app-image", "--vulns").splitlines()
              if "svc-go]" in line and ", called)" in line]
    assert len(called) == 4 and not any("GO-2025-3750" in line for line in called), called   # = govulncheck's set
    gate = subprocess.run([sys.executable, "-m", "frame.cli", "deps", "--rootfs", "debian-12.0", "--vulns",
                           "--fail-on", "critical"], cwd=work, env=env, capture_output=True, text=True)
    assert gate.returncode == 1
    import json
    sbom = json.loads(frame(work, env, "deps", "--rootfs", "alpine-3.18.0", "--sbom", "cyclonedx"))
    assert any(c["purl"] == "pkg:apk/alpine/openssl@3.1.0-r4?distro=3.18" for c in sbom["components"])


def test_upgrade_nuget_go_walkthrough(tmp_path):
    work = tmp_path / "upgrade-nuget-go"
    shutil.copytree(EXAMPLES / "upgrade-nuget-go", work)
    env = {**os.environ, "FRAME_KB_CACHE": str(tmp_path / "kb"),
           "FRAME_REGISTRY_CACHE": str(work / "offline-registry"), "PYTHONPATH": str(ROOT)}
    env.pop("FRAME_ADVISORIES_SOURCE", None)
    assert "2 files" in frame(work, env, "kb", "pull", "--advisories", "--source", "offline-advisories")
    readme = (work / "README.md").read_text()
    shown = [
        (("deps", "dotnet", "--vulns", "--plan"),
         ["4 known vulnerabilities:",
          "Azure.Identity 1.10.3 -> 1.11.4: raise the project's requirement  [packages.lock.json; fixes 2]",
          "Microsoft.Identity.Client 4.56.0 -> 4.60.4: override: a direct PackageReference at that version"]),
        (("deps", "dotnet", "--vulns", "--plan", "--registry"),
         ["Upgrade plan (3 packages):",
          "Microsoft.Identity.Client 4.56.0 -> 4.61.3: re-lock to it (admitted by the solved upgrades)",
          '+    <PackageReference Include="Azure.Identity" Version="1.11.4" />']),
        (("deps", "go", "--vulns", "--plan", "--registry"),
         ["github.com/gin-gonic/gin 1.7.0 -> 1.9.1: raise the project's requirement  [go.mod; fixes 3]",
          "fixes 26; 1 with no fix stay open: GO-2026-5932]",
          "needs Go 1.26.0 (go.mod says go 1.21); the newest fix that Go builds is 0.31.0 (go 1.20), fixing 6 of 26"]),
    ]
    for args, lines in shown:
        out = frame(work, env, *args)
        for line in lines:
            assert line in out and line in readme, (args, line, out[-1500:])
    solved = frame(work, env, "deps", "dotnet", "--vulns", "--plan", "--registry").split("Edits")[0]
    assert "override" not in solved


def test_vendored_c_walkthrough(tmp_path):
    work = tmp_path / "vendored-c"
    shutil.copytree(EXAMPLES / "vendored-c", work)
    env = {**os.environ, "FRAME_KB_CACHE": str(tmp_path / "kb"), "PYTHONPATH": str(ROOT)}
    env.pop("FRAME_ADVISORIES_SOURCE", None)
    assert "1 C/C++ repository shard(s)" in frame(work, env, "kb", "pull", "--advisories", "--source",
                                                   "offline-advisories", "--project", ".")
    readme = (work / "README.md").read_text()
    shown = [
        (("deps", "."), ["third_party/cjson/cJSON.h  (GIT vendored): 1 packages, 1 direct",
                         "third_party/zlib/zlib.h  (GIT vendored): 1 packages, 1 direct"]),
        (("deps", ".", "--vulns"), ["13 known vulnerabilities:",
                                    "CRITICAL github.com/madler/zlib@1.2.11 (direct) CVE-2022-37434"]),
        (("deps", ".", "--vulns", "--plan"),
         ["github.com/madler/zlib@1.2.11: fixed upstream by commit (OSV names no release); update to a release after "
          "the fix (CVE-2018-25032, CVE-2022-37434, CVE-2023-45853, CVE-2026-22184, CVE-2026-3381, CVE-2026-76844)"]),
    ]
    for args, lines in shown:
        out = frame(work, env, *args)
        for line in lines:
            assert line in out and line in readme, (args, line, out[-1500:])
    assert "include/zlib.h" not in frame(work, env, "deps", ".")            # a lone header is not vendored zlib
