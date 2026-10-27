"""Advisories: version ordering checked against each registry's own implementation, OSV
matching checked against the OSV API's answers, and the dataset from build to frame deps --vulns.

Fixtures are real: tests/fixtures/sca/osv/records.json.gz holds 306 OSV records fetched from
api.osv.dev, and expected.json the ids the API returned for 29 (package, version) queries,
vulnerable and fixed versions in every ecosystem Frame reads.
"""

import gzip
import json
import subprocess
import sys
from functools import cmp_to_key
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.advisories import AdvisoryDB, build_advisories, match
from frame.sca.model import normalize_name
from frame.sca.osv import compact, cvss3_base_score, fixed_versions, in_range, is_affected
from frame.sca.versions import compare, sort_key

OSV = Path(__file__).parent / "fixtures" / "sca" / "osv"
RECORDS = json.loads(gzip.decompress((OSV / "records.json.gz").read_bytes()))
EXPECTED = json.loads((OSV / "expected.json").read_text())["queries"]

# Sorted by Frame and confirmed by Maven 3.10's own ComparableVersion (every neighbour "<" or
# "=="), including the documented ComparableVersionTest sequences.
MAVEN_ORDER = "1.0-alpha-1 1-alpha2snapshot 1-alpha2 1-alpha-123 1.0-beta 1-beta-2 1-beta123 1-m2 1-m11 1-rc 1-cr2 1-rc123 1-SNAPSHOT 1.0-SNAPSHOT 1 1.0.0.Final 1.0 1-sp 1-sp2 1-sp123 1-abc 1-def 1-pom-1 1-1-snapshot 1-1 1.0-1 1-2 1-123 1.0.1 1.2.3.RELEASE 1.2.17 1.33 2.0-beta9 2.0.0-M1 2.0-rc1 2.0.0.RC2 2.0 2.0.0 2.0.a 2-1 2.0.2 2.0.123 2.1.0 2.1-a 2.1b 2.1-c 2.1-1 2.1.0.1 2.2 2.13.4 2.13.4.1 2.13.4.2 2.15.0-rc1 2.15.0 2.16.0 2.17.0 2.17.1 2.123 3.0.0-M5 3.0.0-RC1 3.0.0 4.1.92.Final 4.1.100.Final 5.3.9 5.3.20 9.4.9.v20180320 9.4.51.v20230217 11.a2 11.a11 11.b2 11.b11 11.m2 11.m11 11 11.a 11b 11c 11m 31.1-android 31.1-jre 32.0.0-jre".split()
MAVEN_EQUAL = [("1-SNAPSHOT", "1.0-SNAPSHOT"), ("1", "1.0.0.Final"), ("1.0.0.Final", "1.0"), ("1-1", "1.0-1"),
               ("2.0", "2.0.0"), ("1-ga", "1"), ("1-cr", "1-rc")]


def _sorted(eco, versions):
    return sorted(versions, key=cmp_to_key(lambda a, b: compare(eco, a, b)))


def test_maven_order_matches_maven():
    resorted = _sorted("Maven", MAVEN_ORDER[::-1])
    assert all(compare("Maven", a, b) == 0 for a, b in zip(resorted, MAVEN_ORDER))   # same order up to ties
    assert all(compare("Maven", a, b) <= 0 for a, b in zip(MAVEN_ORDER, MAVEN_ORDER[1:]))
    for a, b in MAVEN_EQUAL:
        assert compare("Maven", a, b) == 0, (a, b)
    for a, b in zip(MAVEN_ORDER, MAVEN_ORDER[1:]):
        if (a, b) not in MAVEN_EQUAL:
            assert compare("Maven", a, b) < 0, (a, b)


PEP440 = ("1.0.dev0 1.0.dev1 1.0a1 1.0a2.dev1 1.0a2 1.0b1 1.0rc1 1.0c2 1.0 1.0+abc.5 1.0+abc.10 "
          "1.0.post1.dev1 1.0.post1 1.0.post2 1.1 2.0.0rc1 2.0 3.2.9 3.2.10 1!0.1").split()


def test_pep440_order_matches_packaging():
    assert all(compare("PyPI", a, b) < 0 for a, b in zip(PEP440, PEP440[1:]))
    assert compare("PyPI", "1.0", "1.0.0") == 0 and compare("PyPI", "1.0-1", "1.0.post1") == 0
    packaging = pytest.importorskip("pip._vendor.packaging.version")
    shuffled = PEP440[::-1] + ["1.0a", "1.0.alpha1", "1.0-rc-1", "1.0preview2", "1.0r3", "0.9"]
    mine = _sorted("PyPI", shuffled)
    assert all(packaging.Version(a) <= packaging.Version(b) for a, b in zip(mine, mine[1:]))


SEMVER = ("0.0.1 1.0.0-alpha 1.0.0-alpha.1 1.0.0-alpha.beta 1.0.0-beta 1.0.0-beta.2 1.0.0-beta.11 "
          "1.0.0-rc.1 1.0.0 1.0.1 1.9.9 1.10.0 4.17.4 4.17.20 4.17.21").split()


def test_semver_order_and_registry_variants():
    assert all(compare("npm", a, b) < 0 for a, b in zip(SEMVER, SEMVER[1:]))
    assert compare("NuGet", "1.0.0.0", "1.0") == 0 and compare("NuGet", "4.0.0.1", "4.0.0") > 0
    assert compare("NuGet", "1.0.0-Beta", "1.0.0-beta") == 0
    assert compare("Go", "0.0.0-20220314234659-1baeb1ce4c0b", "0.1.0") < 0
    assert compare("Go", "v1.2.3+incompatible", "1.2.3") == 0
    assert sort_key("npm", "not-a-version") is None and sort_key("Maven", "1 0") is None


@pytest.mark.skipif(not __import__("shutil").which("node"), reason="needs node (npm's semver)")
def test_semver_order_matches_npm_semver():
    root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
    semver = Path(root) / "npm" / "node_modules" / "semver"
    if not semver.is_dir():
        pytest.skip("npm's semver not found")
    script = ("const s=require(process.argv[1]);const v=JSON.parse(process.argv[2]);"
              "console.log(JSON.stringify(v.slice(1).every((x,i)=>s.compare(v[i],x)<0)))")
    out = subprocess.run(["node", "-e", script, str(semver), json.dumps(SEMVER)], capture_output=True, text=True)
    assert out.stdout.strip() == "true"


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),     # Log4Shell
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_base_score(vector, score):
    assert cvss3_base_score(vector) == score


def test_matching_agrees_with_the_osv_api():
    """Every vulnerability the API reports for a version is found, and every one found has an id
    the API reported (records about one vulnerability under several ids are merged)."""
    ids = {r["id"] for r in RECORDS}
    tables = {}
    for q in EXPECTED:
        eco = q["ecosystem"]
        table = tables.setdefault(eco, compact(RECORDS, eco))
        want = set(q["ids"])
        groups = [({a["id"], *a["aliases"]} & ids) for a in table["packages"].get(normalize_name(eco, q["name"]), [])
                  if is_affected(eco, q["version"], a)]
        found = set().union(*groups) if groups else set()
        assert want <= found, (q["name"], q["version"], sorted(want - found))
        assert all(g & want for g in groups), (q["name"], q["version"])


def test_ranges_follow_the_osv_event_semantics():
    rng = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5"}, {"introduced": "2.0"},
                                           {"last_affected": "2.3"}]}
    hits = [v for v in ["0.1", "1.4.9", "1.5", "1.9", "2.0", "2.3", "2.3.1"] if in_range("PyPI", v, rng)]
    assert hits == ["0.1", "1.4.9", "2.0", "2.3"]
    assert not in_range("PyPI", "1.0", {"type": "GIT", "events": [{"introduced": "abc"}]})


def test_aliases_merge_and_log4shell_shape():
    table = compact(RECORDS, "Maven")
    advs = table["packages"]["org.apache.logging.log4j:log4j-core"]
    log4shell = [a for a in advs if "CVE-2021-44228" in [a["id"], *a["aliases"]]]
    assert len(log4shell) == 1 and log4shell[0]["severity"] == "critical"
    assert fixed_versions("Maven", "2.14.1", log4shell[0])[0] == "2.15.0"
    assert not is_affected("Maven", "2.17.1", log4shell[0])
    django = compact(RECORDS, "PyPI")["packages"]["django"]
    assert len({a["id"] for a in django}) == len(django)
    assert not any(a["id"].startswith("PYSEC-") and any(x.startswith("GHSA-") for x in a["aliases"]) for a in django)


def test_go_advisories_carry_their_affected_functions():
    advs = compact(RECORDS, "Go")["packages"]["golang.org/x/net"]
    fns = {f["id"] for a in advs for f in a["functions"]}
    assert any(f.startswith("golang.org/x/net/") for f in fns)
    assert all(f["source"] == "osv" for a in advs for f in a["functions"])


MAVEN_TREE = """com.acme:app:jar:1.0
+- org.springframework.boot:spring-boot-starter-log4j2:jar:2.6.1:compile
|  \\- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
\\- com.fasterxml.jackson.core:jackson-databind:jar:2.13.4.2:compile
"""


def test_build_pull_and_match_end_to_end(tmp_path, monkeypatch):
    from frame.kb.store import pull
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "2026.10.27")
    manifest = json.loads((mirror / "manifest.json").read_text())
    assert {m["name"] for m in manifest["files"].values() if m["language"] != "git"} >= {
        "PyPI", "npm", "Maven", "NuGet", "Go", "crates.io", "SwiftURL"}
    assert all(p.startswith("advisories/GIT/") for p, m in manifest["files"].items() if m["language"] == "git")
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    got = pull(["maven", "pypi"], source=str(mirror))
    assert sorted(got.files) == ["advisories/Maven.json.gz", "advisories/PyPI.json.gz"]

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "maven_dep_tree.txt").write_text(MAVEN_TREE)
    (proj / "requirements.txt").write_text("pyyaml==5.4\n")
    report = read_dependencies(proj)
    db = AdvisoryDB.cached(["Maven", "PyPI", "npm"])
    assert db.missing == ["npm"]
    found = match(report.files, db)
    log4 = [f for f in found if "CVE-2021-44228" in [f["id"], *f["aliases"]]]
    assert len(log4) == 1
    assert log4[0]["via"] == ["org.springframework.boot:spring-boot-starter-log4j2@2.6.1",
                              "org.apache.logging.log4j:log4j-core@2.14.1"]
    assert log4[0]["direct"] is False and log4[0]["fixed"][0] == "2.15.0" and log4[0]["severity"] == "critical"
    assert not [f for f in found if f["package"] == "pyyaml"]                 # 5.4 is fixed (API: no vulns)
    assert all(f["category"] == "dependency" for f in found)


def test_frame_deps_vulns_cli(tmp_path):
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", ["npm"])
    env = {"FRAME_KB_CACHE": str(tmp_path / "cache"), "FRAME_ADVISORIES_SOURCE": str(mirror),
           "PATH": __import__("os").environ["PATH"]}
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    run = lambda *a: subprocess.run([sys.executable, "-m", "frame.cli", *a], capture_output=True, text=True,
                                    env=env, cwd=str(Path(__file__).parents[1]))
    assert run("kb", "pull", "--advisories", "--project", str(proj)).returncode == 0
    out = json.loads(run("deps", str(proj), "--vulns", "-f", "json").stdout)
    ids = {x for v in out["vulnerabilities"] for x in [v["id"], *v["aliases"]]}
    want = next(q["ids"] for q in EXPECTED if q["name"] == "lodash" and q["version"] == "4.17.20")
    assert set(want) <= ids
    text = run("deps", str(proj), "--vulns").stdout
    assert "lodash@4.17.20" in text and "known vulnerabilit" in text


def test_a_tampered_advisory_table_is_refused(tmp_path):
    from frame.kb.store import KBError, pull
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", ["npm"])
    (mirror / "advisories" / "npm.json.gz").write_bytes(gzip.compress(b'{"schema":1,"packages":{}}'))
    with pytest.raises(KBError, match="sha256"):
        pull(None, source=str(mirror))


def test_malicious_package_records_are_critical():
    rec = {"id": "MAL-2025-1", "summary": "Malicious code in evil-pkg (npm)",
           "affected": [{"package": {"ecosystem": "npm", "name": "evil-pkg"},
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
    adv = compact([rec], "npm")["packages"]["evil-pkg"][0]
    assert adv["severity"] == "critical" and is_affected("npm", "1.0.0", adv)


def test_frame_deps_exclude_and_fail_on(tmp_path):
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", ["npm"])
    env = {"FRAME_KB_CACHE": str(tmp_path / "cache"), "FRAME_ADVISORIES_SOURCE": str(mirror),
           "PATH": __import__("os").environ["PATH"]}
    proj = tmp_path / "proj"
    (proj / "tests" / "fixtures").mkdir(parents=True)
    (proj / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}))
    (proj / "tests" / "fixtures" / "package.json").write_text(json.dumps({"dependencies": {"minimist": "1.2.5"}}))
    run = lambda *a: subprocess.run([sys.executable, "-m", "frame.cli", *a], capture_output=True, text=True,
                                    env=env, cwd=str(Path(__file__).parents[1]))
    assert run("kb", "pull", "--advisories", "--all", "--source", str(mirror)).returncode == 0
    everything = json.loads(run("deps", str(proj), "--vulns", "-f", "json").stdout)
    assert {v["package"] for v in everything["vulnerabilities"]} >= {"minimist"}
    trimmed = run("deps", str(proj), "--vulns", "-f", "json", "--exclude", "tests/fixtures")
    assert "minimist" not in {v["package"] for v in json.loads(trimmed.stdout)["vulnerabilities"]}
    assert run("deps", str(proj), "--vulns", "--fail-on", "any").returncode == 1
    assert run("deps", str(proj), "--vulns").returncode == 0                     # report only by default


def test_nothing_cached_is_never_reported_clean(tmp_path):
    """With no advisories cached, the packages were not checked: the report says so, and a
    --fail-on gate cannot pass on no data (exit 2)."""
    env = {"FRAME_KB_CACHE": str(tmp_path / "cache"), "PATH": __import__("os").environ["PATH"]}
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    run = lambda *a: subprocess.run([sys.executable, "-m", "frame.cli", *a], capture_output=True, text=True,
                                    env=env, cwd=str(Path(__file__).parents[1]))
    text = run("deps", str(proj), "--vulns")
    assert text.returncode == 0 and "NOT CHECKED" in text.stdout and "No known vulnerabilities" not in text.stdout
    assert json.loads(run("deps", str(proj), "--vulns", "-f", "json").stdout)["not_checked"] == ["npm"]
    gate = run("deps", str(proj), "--vulns", "--fail-on", "high")
    assert gate.returncode == 2 and "cannot be judged" in gate.stderr


def test_a_pull_from_a_mirror_is_what_later_reads_use(tmp_path):
    """Air-gapped: `kb pull --advisories --source DIR`, then plain `frame deps --vulns`."""
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", ["npm"])
    env = {"FRAME_KB_CACHE": str(tmp_path / "cache"), "PATH": __import__("os").environ["PATH"]}
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    run = lambda *a: subprocess.run([sys.executable, "-m", "frame.cli", *a], capture_output=True, text=True,
                                    env=env, cwd=str(Path(__file__).parents[1]))
    assert run("kb", "pull", "--advisories", "--project", str(proj), "--source", str(mirror)).returncode == 0
    out = run("deps", str(proj), "--vulns", "--fail-on", "critical", "-f", "json")
    data = json.loads(out.stdout)
    assert data["not_checked"] == [] and any(v["package"] == "lodash" for v in data["vulnerabilities"])
