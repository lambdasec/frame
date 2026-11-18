"""Language runtimes installed in an image (frame/sca/runtimes.py) and the advisories of those OSV
does not cover (frame/sca/runtime_advisories.py).

Everything is real (tests/fixtures/sca/runtimes, README there): the version files of official
images, OpenJDK's advisory pages, the Node.js security WG's and the Ruby advisory database's
data, OSV's records for .NET runtime packs and CPython. Ground truth comes from the real
implementations: npm's `semver`, RubyGems' `Gem::Requirement`, Java's `Runtime.Version`, OSV's API.
"""

import gzip
import io
import json
import re
import shutil
import tarfile
from pathlib import Path

import pytest

from frame.sca.advisories import AdvisoryDB, build_advisories, match
from frame.sca.container import read_files, read_rootfs
from frame.sca.model import GIT, NODEJS, NUGET, OPENJDK, RUBY, DependencyFile, Package
from frame.sca.osv import is_affected
from frame.sca.plan import format_plan, plan
from frame.sca.runtime_advisories import node_records, openjdk_records, ruby_records
from frame.sca.runtimes import CPYTHON_REPO
from frame.sca.versions import compare

F = Path(__file__).parent / "fixtures" / "sca" / "runtimes"
IMAGES = F / "images"
JAVA4SHELL = "CVE-2026-114938"


def _gz_json(name):
    return json.loads(gzip.decompress((F / name).read_bytes()))


def _packages(image):
    files, warnings = read_rootfs(IMAGES / image)
    return [(f.path.split(":", 1)[1], p.ecosystem, p.name, p.version, p.tags)
            for f in files for p in f.packages.values()], warnings


@pytest.fixture(scope="module")
def runtimes_dir(tmp_path_factory):
    """The layout the advisory build reads, from the fixtures."""
    d = tmp_path_factory.mktemp("runtimes")
    shutil.copytree(F / "runtimes" / "openjdk", d / "openjdk")
    (d / "nodejs").mkdir()
    (d / "nodejs" / "vulns.json").write_bytes(gzip.decompress((F / "node-vulns.json.gz").read_bytes()))
    (d / "nodejs" / "releases.json").write_bytes(gzip.decompress((F / "node-releases.json.gz").read_bytes()))
    (d / "ruby").mkdir()
    with tarfile.open(F / "ruby.tar.gz") as t:
        t.extractall(d / "ruby", filter="data") if hasattr(tarfile, "data_filter") else t.extractall(d / "ruby")
    return d


@pytest.fixture(scope="module")
def db(runtimes_dir, tmp_path_factory):
    """A revision built from the runtimes directory plus OSV's .NET and CPython records."""
    tmp = tmp_path_factory.mktemp("db")
    osv = tmp / "osv"
    osv.mkdir()
    for name in ("dotnet-osv.json.gz", "cpython-osv.json.gz"):
        (osv / name.replace(".gz", "")).write_bytes(gzip.decompress((F / name).read_bytes()))
    mirror = tmp / "mirror"
    build_advisories([runtimes_dir, osv], mirror, "r1", [OPENJDK, NODEJS, RUBY, NUGET, GIT])
    mp = pytest.MonkeyPatch()
    mp.setenv("FRAME_KB_CACHE", str(tmp / "cache"))
    mp.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    from frame.kb.store import pull
    from frame.sca.advisories import git_shard
    pull(["openjdk", "node.js", "ruby", "nuget"], source=str(mirror), also=[git_shard(CPYTHON_REPO)])
    yield AdvisoryDB.cached([OPENJDK, NODEJS, RUBY, NUGET, GIT], [CPYTHON_REPO])
    mp.undo()


# ---------------------------------------------------------------------------------------------
# reading the runtimes

@pytest.mark.parametrize("image, expected", [
    ("eclipse-temurin_17-jre", ("/opt/java/openjdk", OPENJDK, "openjdk", "17.0.21", [])),
    ("eclipse-temurin_8-jre", ("/opt/java/openjdk", OPENJDK, "openjdk", "1.8.0_512", [])),
    ("amazoncorretto_21-al2023-headless",
     ("/usr/lib/jvm/java-21-amazon-corretto.x86_64", OPENJDK, "openjdk", "21.0.13", [])),
    ("node_22-slim", ("/usr/local", NODEJS, "node", "22.23.5", [])),
    ("node_22-alpine", ("/usr/local", NODEJS, "node", "22.23.5", [])),
    ("python_3.12-slim", ("/usr/local", GIT, CPYTHON_REPO, "3.12.16", ["v3.12.16"])),
    ("ruby_3.3-slim", ("/usr/local", RUBY, "ruby", "3.3.13", [])),
])
def test_each_runtime_is_read_from_its_own_version_file(image, expected):
    found, _ = _packages(image)
    assert found == [expected]


def test_dotnet_shared_frameworks_are_the_runtime_packs_their_deps_json_names():
    found, _ = _packages("aspnet8")
    assert found == [
        ("/usr/share/dotnet/shared/Microsoft.AspNetCore.App/8.0.34", NUGET,
         "Microsoft.AspNetCore.App.Runtime.linux-x64", "8.0.34", []),
        ("/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.34", NUGET,
         "Microsoft.NETCore.App.Runtime.linux-x64", "8.0.34", []),
    ]


def test_a_self_contained_apps_runtime_pack_is_read_from_its_deps_json():
    deps = json.dumps({"runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/linux-x64"},
                       "libraries": {"api/1.0.0": {"type": "project"},
                                     "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/8.0.10": {"type": "runtimepack"},
                                     "Newtonsoft.Json/13.0.3": {"type": "package"}}})
    files, _ = read_files({"app/api.deps.json": deps}, "img")
    assert [(p.name, p.version) for f in files for p in f.packages.values()] == \
        [("Microsoft.NETCore.App.Runtime.linux-x64", "8.0.10")]


def test_an_openj9_jdk_is_reported_not_matched():
    found, warnings = _packages("ibm-semeru-runtimes_open-17-jre")
    assert found == []
    assert any("JDK 17.0.21.0.3" in w and "Openj9" in w and "not HotSpot" in w for w in warnings)


def _with_owner(path, release):
    """An image whose dpkg records that it installed `path`."""
    return {"etc/os-release": release, "var/lib/dpkg/status": "",
            "var/lib/dpkg/info/openjdk-17-jre-headless:amd64.list": f"/{path}\n",
            path: (IMAGES / "eclipse-temurin_17-jre/opt/java/openjdk/release").read_text()}


def test_a_runtime_the_distribution_installed_is_left_to_its_advisories():
    files, warnings = read_files(_with_owner("usr/lib/jvm/java-17-openjdk-amd64/release",
                                             'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian 12"\n'), "img")
    assert not [p for f in files for p in f.packages.values() if p.ecosystem == OPENJDK]
    assert any("runtime(s) installed by the OS package manager" in w for w in warnings)


def test_on_a_distribution_frame_has_no_advisories_for_the_runtime_is_matched_itself():
    # Amazon Linux's Corretto is an rpm, and Frame has no Amazon Linux advisories
    files, _ = read_files(_with_owner("usr/lib/jvm/java-17-amazon-corretto/release",
                                      'ID="amzn"\nVERSION_ID="2023"\nPRETTY_NAME="Amazon Linux 2023"\n'), "img")
    assert [(p.ecosystem, p.version) for f in files for p in f.packages.values()] == [(OPENJDK, "17.0.21")]


# ---------------------------------------------------------------------------------------------
# OpenJDK's advisories

def test_jdk_versions_order_as_runtime_version_does():
    for line in (F / "jdk_order.tsv").read_text().splitlines():
        a, b, want = line.split("\t")
        assert compare(OPENJDK, a, b) == int(want), (a, b)


def test_jdk_8_is_written_two_ways_and_builds_are_not_ordered():
    assert compare(OPENJDK, "1.8.0_512", "8u512") == 0          # a release file / an advisory
    assert compare(OPENJDK, "8u511", "1.8.0_512") < 0
    assert compare(OPENJDK, "17.0.21+9", "17.0.21") == 0        # neither source carries a build


def test_java4shell_is_read_from_openjdks_advisory():
    recs, warnings = openjdk_records((F / "runtimes/openjdk/2026-11-17.html").read_text())
    rec = next(r for r in recs if r["id"] == JAVA4SHELL)
    assert rec["affected"][0]["ranges"] == [
        {"type": "ECOSYSTEM", "events": [{"introduced": "17"}, {"last_affected": "17.0.21.0.3"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "21"}, {"last_affected": "21.0.13.0.3"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "25"}, {"last_affected": "25.0.5.0.3"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "27"}, {"last_affected": "27.0.1.0.3"}]}]
    # the matrix's NHNNUHHH, 8.1
    assert rec["severity"] == [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    assert rec["published"] == "2026-11-17" and warnings == []
    assert len(recs) == 10                                     # the OpenJDK matrix only, not OpenJFX's


def test_a_marked_line_with_no_named_version_is_left_out():
    recs, warnings = openjdk_records((F / "runtimes/openjdk/2021-10-19.html").read_text())
    rec = next(r for r in recs if r["id"] == "CVE-2021-35567")
    assert {e["events"][0]["introduced"] for e in rec["affected"][0]["ranges"]} == {"8", "11", "13", "15"}
    assert any("CVE-2021-35567: line 17 is marked but no last affected version is named" in w for w in warnings)


def test_2019_pages_with_unpadded_dates_are_read():
    recs, _ = openjdk_records((F / "runtimes/openjdk/2019-04-16.html").read_text())
    assert recs and {r["published"] for r in recs} == {"2019-04-16"}


def test_a_page_that_is_not_an_advisory_gives_nothing():
    assert openjdk_records("<html><h1>Something else</h1></html>")[0] == []


# ---------------------------------------------------------------------------------------------
# Node.js and Ruby: ranges over the release list, against the real implementations

def _affected_releases(recs, versions, eco, key):
    out = {}
    for r in recs:
        adv = {"ranges": r["affected"][0]["ranges"], "versions": []}
        out[key(r)] = {v for v in versions if is_affected(eco, v, adv)}
    return out


def test_node_advisories_affect_exactly_the_releases_npm_semver_says():
    vulns, releases = _gz_json("node-vulns.json.gz"), _gz_json("node-releases.json.gz")
    recs, warnings = node_records(vulns, releases)
    assert warnings == []
    versions = [r["version"].lstrip("v") for r in releases]
    own = _affected_releases(recs, versions, NODEJS,
                             lambda r: next((a for a in [r["id"], *r["aliases"]] if a.startswith("NSWG-CORE-")),
                                            r["id"]).replace("NSWG-CORE-", ""))
    truth = _gz_json("node_semver_expected.json.gz")
    assert len(truth) == 204
    assert {k: set(v) for k, v in truth.items() if v} == {k: v for k, v in own.items() if v}


def test_ruby_advisories_affect_exactly_the_releases_gem_requirement_says(runtimes_dir):
    import yaml
    rels = [str(r["version"]) for r in yaml.safe_load((runtimes_dir / "ruby/releases.yml").read_text())]
    advs = [yaml.safe_load(f.read_text()) for f in sorted((runtimes_dir / "ruby/advisories").glob("*.yml"))]
    recs, warnings = ruby_records(advs, rels)
    assert warnings == []
    finals = [v for v in rels if re.fullmatch(r"\d+\.\d+\.\d+", v)]   # an image's rbconfig.rb names no preview
    own = _affected_releases(recs, finals, RUBY, lambda r: r["id"])
    truth = json.loads((F / "ruby_gem_expected.json").read_text())
    assert len(truth) == 92
    assert {k: set(v) for k, v in truth.items() if v} == {k: v for k, v in own.items() if v}


# ---------------------------------------------------------------------------------------------
# matching the images

def _found(image, db):
    files, _ = read_rootfs(IMAGES / image)
    return match(files, db), files


def test_java4shell_is_found_in_temurin_17_and_corretto_21(db):
    for image, version in (("eclipse-temurin_17-jre", "17.0.21"), ("amazoncorretto_21-al2023-headless", "21.0.13")):
        found, _ = _found(image, db)
        hit = [f for f in found if f["id"] == JAVA4SHELL]
        assert [(f["package"], f["version"], f["severity"], f["fixed"]) for f in hit] == \
            [("openjdk", version, "high", [])], image


def test_java4shell_is_not_found_in_jdk_8(db):
    found, _ = _found("eclipse-temurin_8-jre", db)
    assert found and JAVA4SHELL not in {f["id"] for f in found}  # line 8 is not marked


def test_a_jdk_on_a_line_openjdk_no_longer_lists_gets_a_note(db):
    db.notes.clear()
    df = DependencyFile("img:/opt/jdk-26", OPENJDK, "image")
    df.add(Package(OPENJDK, "openjdk", "26.0.2"))
    match([df], db)
    assert any("release line 26 is not in OpenJDK's latest advisory (2026-11-17" in n for n in db.notes)
    db.notes.clear()
    found, _ = _found("eclipse-temurin_17-jre", db)
    assert db.notes == []


def test_the_upgrade_plan_says_openjdk_names_no_fix(db):
    found, files = _found("eclipse-temurin_17-jre", db)
    text = format_plan(plan(found, files, db))
    assert "OpenJDK names the last affected version, not the fix" in text


def test_current_node_and_ruby_images_are_clean_and_older_releases_are_not(db):
    for image in ("node_22-slim", "ruby_3.3-slim"):
        assert _found(image, db)[0] == []
    for eco, name, version, cve in ((NODEJS, "node", "22.23.3", "CVE-2026-111497"),
                                    (RUBY, "ruby", "4.0.4", "CVE-2026-46727")):
        df = DependencyFile("img:/usr/local", eco, "image")
        df.add(Package(eco, name, version))
        assert cve in {f["id"] for f in match([df], db)}


@pytest.mark.parametrize("name", ["Microsoft.NETCore.App.Runtime.linux-x64", "Microsoft.AspNetCore.App.Runtime.linux-x64"])
@pytest.mark.parametrize("version", ["8.0.10", "8.0.34"])
def test_dotnet_runtime_packs_match_osvs_answer(db, name, version):
    df = DependencyFile("img:/usr/share/dotnet", NUGET, "image")
    df.add(Package(NUGET, name, version))
    found = {i for f in match([df], db) for i in [f["id"], *f["aliases"]]}
    expected = set(json.loads((F / "dotnet-osv-expected.json").read_text())[f"{name}@{version}"])
    assert expected <= found and {f["id"] for f in match([df], db)} <= found
    assert len({f["id"] for f in match([df], db)}) == len(expected)


def test_cpython_is_matched_by_its_release_tag_as_osv_answers(db):
    expected = json.loads((F / "cpython-osv-expected.json").read_text())
    for tag, ids in expected.items():
        df = DependencyFile("img:/usr/local", GIT, "image")
        df.add(Package(GIT, CPYTHON_REPO, tag[1:], repo=CPYTHON_REPO, tags=[tag]))
        found = {i for f in match([df], db) for i in [f["id"], *f["aliases"]]}
        assert found & {r["id"] for r in _gz_json("cpython-osv.json.gz")} == set(ids), tag


def test_the_build_reads_a_runtimes_directory_beside_osv_exports(runtimes_dir, tmp_path):
    out = build_advisories([runtimes_dir], tmp_path / "out", "r1", [OPENJDK, NODEJS, RUBY]).parent
    tables = {p.name for p in (out / "advisories").glob("*.json.gz")}
    assert tables == {"OpenJDK.json.gz", "Node.js.json.gz", "Ruby.json.gz"}
    jdk = json.loads(gzip.decompress((out / "advisories/OpenJDK.json.gz").read_bytes()))
    assert JAVA4SHELL in {a["id"] for a in jdk["packages"]["openjdk"]}
