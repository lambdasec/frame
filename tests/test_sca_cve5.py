"""CVE records (CVE JSON 5) in the advisory build: the registry packages a CNA names are matched
even when OSV's conversion kept only a commit range.

Fixtures are real (tests/fixtures/sca/cve5): CVE-2026-90436 (Apache Axis 1.x, remote class
instantiation through a SOAP fault) as the CVE Program publishes it (cvelistV5) and as OSV's API
returns it (GIT ranges only, no Maven package), plus GHSA-55w9-c3g2-4rrh, an older Axis advisory
OSV does file under Maven.
"""

import io
import json
import zipfile
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.advisories import AdvisoryDB, build_advisories, match
from frame.sca.cve5 import parse_purl, to_osv

F = Path(__file__).parent / "fixtures" / "sca" / "cve5"
CVE = json.loads((F / "CVE-2026-90436.cve.json").read_text())
OSV = json.loads((F / "CVE-2026-90436.osv.json").read_text())
GHSA = json.loads((F / "GHSA-55w9-c3g2-4rrh.osv.json").read_text())
AXIS = "CVE-2026-90436"

POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>soap-client</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>{group}</groupId><artifactId>axis</artifactId><version>{version}</version></dependency>
  </dependencies>
</project>
"""


def _db(tmp_path, monkeypatch, *inputs, ecosystems=("Maven", "GIT")):
    raw = tmp_path / "raw"
    raw.mkdir(exist_ok=True)
    for i, doc in enumerate(inputs):
        (raw / f"{i}.json").write_text(json.dumps(doc))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", list(ecosystems))
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    from frame.kb.store import pull
    pull(["maven"], source=str(mirror))                         # as `frame kb pull --advisories` does
    return mirror, AdvisoryDB.cached(["Maven"])


def _ids(found, package):
    return {i for f in found if f["package"] == package for i in [f["id"], *f["aliases"]]}


def _project(tmp_path, name, files):
    proj = tmp_path / name
    proj.mkdir()
    for rel, text in files.items():
        (proj / rel).write_text(text)
    return read_dependencies(proj).files


def test_the_cna_s_maven_packages_are_read_from_the_cve_record():
    rec = to_osv(CVE)
    assert rec["id"] == AXIS
    assert {(a["package"]["ecosystem"], a["package"]["name"]) for a in rec["affected"]} == {
        ("Maven", "axis:axis"), ("Maven", "org.apache.axis:axis")}
    for a in rec["affected"]:
        assert a["ranges"] == [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.4"}]}]
    # the CNA's commit range is OSV's to carry; it is not turned into a package
    assert all(a["package"]["ecosystem"] != "GIT" for a in rec["affected"])
    assert rec["severity"] == [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]


def test_osv_s_own_record_has_no_maven_package():
    """Why the CVE record is needed: OSV's record of the same id names only the git repository."""
    assert {r["type"] for a in OSV["affected"] for r in a["ranges"]} == {"GIT"}
    assert not [a for a in OSV["affected"] if a.get("package")]


@pytest.mark.parametrize("group", ["axis", "org.apache.axis"])
def test_a_pom_depending_on_axis_1_4_is_flagged(tmp_path, monkeypatch, group):
    _, db = _db(tmp_path, monkeypatch, OSV, CVE, GHSA)
    found = match(_project(tmp_path, "proj", {"pom.xml": POM.format(group=group, version="1.4")}), db)
    hit = [f for f in found if f["id"] == AXIS or AXIS in f["aliases"]]
    assert len(hit) == 1 and hit[0]["package"] == f"{group}:axis" and hit[0]["version"] == "1.4"
    assert hit[0]["severity"] == "critical" and hit[0]["fixed"] == []
    # the GHSA OSV already filed under Maven is still reported beside it, as its own advisory
    assert "GHSA-55w9-c3g2-4rrh" in _ids(found, f"{group}:axis")


def test_a_gradle_build_depending_on_axis_is_flagged(tmp_path, monkeypatch):
    _, db = _db(tmp_path, monkeypatch, OSV, CVE)
    files = _project(tmp_path, "proj", {"build.gradle": "plugins { id 'java' }\n"
                                        "dependencies {\n    implementation 'axis:axis:1.4'\n}\n"})
    assert AXIS in _ids(match(files, db), "axis:axis")


def test_an_older_axis_release_is_affected_too(tmp_path, monkeypatch):
    _, db = _db(tmp_path, monkeypatch, OSV, CVE)
    files = _project(tmp_path, "proj", {"pom.xml": POM.format(group="axis", version="1.2.1")})
    assert AXIS in _ids(match(files, db), "axis:axis")


def _jar(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


AXIS_JAR = _jar({"META-INF/maven/axis/axis/pom.properties": "groupId=axis\nartifactId=axis\nversion=1.4\n",
                 "org/apache/axis/message/SOAPFaultBuilder.class": b""})


@pytest.mark.parametrize("layout", ["war", "exploded", "fat-jar"])
def test_an_image_shipping_the_axis_jar_is_flagged(tmp_path, monkeypatch, layout):
    """A WAR in Tomcat's webapps, an exploded web application (Confluence's layout) and a Spring
    Boot jar: each names Axis only through the jar's own pom.properties."""
    from frame.sca.container import read_rootfs
    _, db = _db(tmp_path, monkeypatch, OSV, CVE)
    root = tmp_path / "rootfs"
    if layout == "war":
        target, data = "usr/local/tomcat/webapps/app.war", _jar({"WEB-INF/lib/axis-1.4.jar": AXIS_JAR})
    elif layout == "exploded":
        target, data = "opt/atlassian/confluence/confluence/WEB-INF/lib/axis-1.4.jar", AXIS_JAR
    else:
        target, data = "srv/app.jar", _jar({"BOOT-INF/lib/axis-1.4.jar": AXIS_JAR})
    (root / target).parent.mkdir(parents=True)
    (root / target).write_bytes(data)
    files, _ = read_rootfs(root)
    hit = [f for f in match(files, db) if f["id"] == AXIS or AXIS in f["aliases"]]
    assert len(hit) == 1 and hit[0]["package"] == "axis:axis" and hit[0]["path"].endswith(target)


def test_a_project_without_axis_is_not_flagged(tmp_path, monkeypatch):
    _, db = _db(tmp_path, monkeypatch, OSV, CVE)
    axis2 = POM.format(group="org.apache.axis2", version="1.8.2").replace("<artifactId>axis</artifactId>",
                                                                           "<artifactId>axis2-kernel</artifactId>")
    found = match(_project(tmp_path, "proj", {"pom.xml": axis2}), db)
    assert not [f for f in found if f["id"] == AXIS or AXIS in f["aliases"]]


def test_adding_cve_records_changes_no_git_shard(tmp_path, monkeypatch):
    """C/C++ matching reads the GIT shards, which come from OSV's records alone."""
    from frame.sca.advisories import git_shard
    alone = tmp_path / "alone"
    with_cve = tmp_path / "with"
    for d, docs in ((alone, [OSV]), (with_cve, [OSV, CVE])):
        (d / "raw").mkdir(parents=True)
        for i, doc in enumerate(docs):
            (d / "raw" / f"{i}.json").write_text(json.dumps(doc))
        build_advisories([d / "raw"], d / "out", "r1", ["GIT", "Maven"])
    shards = sorted(p.relative_to(alone / "out") for p in (alone / "out" / "advisories" / "GIT").glob("*.json.gz"))
    assert shards == [Path(git_shard("github.com/apache/axis-axis1-java"))]
    for rel in shards:
        assert (alone / "out" / rel).read_bytes() == (with_cve / "out" / rel).read_bytes()
    assert not (alone / "out" / "advisories" / "Maven.json.gz").exists()
    assert (with_cve / "out" / "advisories" / "Maven.json.gz").exists()


def _cve(affected, state="PUBLISHED"):
    return {"dataType": "CVE_RECORD", "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2099-0001", "state": state},
            "containers": {"cna": {"affected": affected}}}


def test_only_what_the_cna_states_is_converted():
    pkg = {"packageURL": "pkg:maven/com.acme/lib"}
    conv = lambda versions, **kw: to_osv(_cve([{**pkg, **kw, "versions": versions}]))
    ranges = lambda rec: rec["affected"][0]["ranges"] if rec else None
    assert ranges(conv([{"status": "affected", "version": "1.0", "lessThan": "1.5", "versionType": "maven"}])) == [
        {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.5"}]}]
    assert conv([{"status": "affected", "version": "2.0"}])["affected"][0]["versions"] == ["2.0"]
    # not affected, status changes, a commit or a vendor's own scheme, prose: nothing
    assert conv([{"status": "unaffected", "version": "1.5", "lessThan": "*"}]) is None
    assert conv([{"status": "affected", "version": "1.0", "lessThan": "*",
                  "changes": [{"at": "1.5", "status": "unaffected"}]}]) is None
    assert conv([{"status": "affected", "version": "abc123", "lessThan": "def456", "versionType": "git"}]) is None
    assert conv([{"status": "affected", "version": "1.0", "lessThan": "1.5", "versionType": "custom"}]) is None
    assert conv([{"status": "affected", "version": "1.4 and earlier"}]) is None
    # defaultStatus says every version only when no version is listed
    assert ranges(conv([], defaultStatus="affected")) == [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
    assert conv([], defaultStatus="unaffected") is None
    # a record that is not published, or names no registry package, gives nothing
    assert to_osv(_cve([{**pkg, "versions": [{"status": "affected", "version": "1.0"}]}], state="REJECTED")) is None
    assert to_osv(_cve([{"vendor": "Acme", "product": "lib", "versions": [{"status": "affected", "version": "1.0"}]}])) is None
    assert to_osv(_cve([{"collectionURL": "https://example.com/repo", "packageName": "lib",
                         "versions": [{"status": "affected", "version": "1.0"}]}])) is None


def test_package_urls_and_registry_collections():
    assert parse_purl("pkg:maven/org.apache.axis/axis@1.4?type=jar") == ("Maven", "org.apache.axis:axis")
    assert parse_purl("pkg:npm/%40babel/core") == ("npm", "@babel/core")
    assert parse_purl("pkg:pypi/django") == ("PyPI", "django")
    assert parse_purl("pkg:golang/github.com/gin-gonic/gin") == ("Go", "github.com/gin-gonic/gin")
    assert parse_purl("pkg:composer/symfony/http-kernel") == ("Packagist", "symfony/http-kernel")
    assert parse_purl("pkg:maven/axis") is None                      # no group
    assert parse_purl("pkg:github/apache/axis") is None              # not a registry Frame reads
    rec = to_osv(_cve([{"collectionURL": "https://registry.npmjs.org/", "packageName": "lodash",
                        "versions": [{"status": "affected", "version": "0", "lessThan": "4.17.21",
                                      "versionType": "semver"}]}]))
    assert rec["affected"][0]["package"] == {"ecosystem": "npm", "name": "lodash"}


def test_an_osv_record_of_the_same_cve_wins_for_its_package():
    """The CVE record only fills a package OSV does not file the CVE under: where a GHSA aliasing
    the CVE names the package, its reviewed ranges are kept and the CNA's dropped (the two disagree
    on real advisories: a version GHSA calls fixed is the CNA's `lessThanOrEqual`)."""
    from frame.sca.osv import compact, is_affected
    from frame.sca.cve5 import to_osv
    ghsa = {"id": "GHSA-test-only-axis", "aliases": [AXIS], "modified": "2026-11-15T00:00:00Z",
            "affected": [{"package": {"ecosystem": "Maven", "name": "axis:axis"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.2"}, {"fixed": "1.4"}]}]}]}
    tbl = compact([to_osv(CVE), ghsa], "Maven")["packages"]
    [adv] = tbl["axis:axis"]
    assert adv["id"] == "GHSA-test-only-axis" and AXIS in adv["aliases"]
    assert adv["ranges"] == ghsa["affected"][0]["ranges"]
    assert not is_affected("Maven", "1.4", adv) and is_affected("Maven", "1.3", adv)
    assert "fallback" not in adv
    # the package GHSA does not name keeps the CNA's statement
    [other] = tbl["org.apache.axis:axis"]
    assert other["id"] == AXIS and is_affected("Maven", "1.4", other) and "fallback" not in other
