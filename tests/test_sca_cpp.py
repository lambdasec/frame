"""C and C++ dependencies: Conan, vcpkg, git submodules and CMake fetches, each resolved to its
upstream repository and release tag, and matched against real OSV GIT advisories (commit ranges
with the affected tags listed) pulled one repository shard at a time."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.advisories import AdvisoryDB, build_advisories, git_shard, match, repos_of
from frame.sca.cmake import commands
from frame.sca.cpp import normalize_repo, repo_and_tags, tag_from_url, tag_pattern

ROOT = Path(__file__).resolve().parents[1]
GIT_RECORDS = ROOT / "tests" / "fixtures" / "sca" / "osv" / "git_records.json"


def test_cmake_commands_are_read_like_cmake():
    cmds = commands('''# a comment with FetchContent_Declare(fake)
#[[ a block
comment ]]
FetchContent_Declare(zlib
  GIT_REPOSITORY "https://github.com/madler/zlib.git"  # trailing comment
  GIT_TAG        v1.2.11)
set(x [[bracket (arg)]] "q\\"uoted")
CPMAddPackage("gh:nlohmann/json@3.10.0")
''')
    assert [(c.name, c.line) for c in cmds] == [("fetchcontent_declare", 4), ("set", 7), ("cpmaddpackage", 8)]
    assert cmds[0].keyword("GIT_TAG") == "v1.2.11"
    assert cmds[1].args == ["x", "bracket (arg)", 'q"uoted']


@pytest.mark.parametrize("url,repo", [
    ("https://github.com/Madler/zlib.git", "github.com/madler/zlib"),
    ("git@github.com:madler/zlib.git", "github.com/madler/zlib"),
    ("https://github.com/curl/curl/releases/download/curl-8_3_0/curl-8.3.0.tar.gz", "github.com/curl/curl"),
    ("https://codeload.github.com/madler/zlib/tar.gz/refs/tags/v1.3", "github.com/madler/zlib"),
    ("https://zlib.net/zlib-1.3.tar.gz", None),
])
def test_repositories_are_normalised(url, repo):
    assert normalize_repo(url) == repo


@pytest.mark.parametrize("url,tag", [
    ("https://github.com/madler/zlib/archive/refs/tags/v1.2.13.tar.gz", "v1.2.13"),
    ("https://github.com/curl/curl/releases/download/curl-8_3_0/curl-8.3.0.tar.gz", "curl-8_3_0"),
    ("https://github.com/x/y/archive/0123456789abcdef0123456789abcdef01234567.tar.gz", None),   # a commit
    ("https://gitlab.com/libtiff/libtiff/-/archive/v4.5.0/libtiff-v4.5.0.tar.gz", "v4.5.0"),
])
def test_tags_from_archive_urls(url, tag):
    assert tag_from_url(url) == tag


def test_tag_patterns_need_agreement():
    assert tag_pattern({"2.4.8": "R_2_4_8", "2.5.0": "R_2_5_0"}) == "R_{V_}"
    assert tag_pattern({"1.1.1w": "OpenSSL_1_1_1w", "3.0.1": "openssl-3.0.1"}) is None
    assert tag_pattern({"1.0": "v1.0"}) is None                                   # one pair is not a pattern
    # the shipped map: zlib's pattern is corroborated by vcpkg's REF v${VERSION}
    assert repo_and_tags("conan", "zlib", "1.2.11") == ("github.com/madler/zlib", ["v1.2.11"])
    assert repo_and_tags("vcpkg", "zlib", "1.2.12") == ("github.com/madler/zlib", ["v1.2.12"])
    assert repo_and_tags("conan", "no-such-recipe", "1.0") == (None, [])


def project(tmp_path, files):
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    return {(p.ecosystem, p.name, p.version): (p.repo, tuple(p.tags), p.direct, p.dev)
            for f in read_dependencies(tmp_path).files for p in f.packages.values()}


def test_conan_manifests_and_lockfiles(tmp_path):
    got = project(tmp_path / "txt", {"conanfile.txt": "[requires]\nzlib/1.2.11\nexpat/2.4.8@user/stable\n"
                                                      "[tool_requires]\ncmake/3.27.0\n"})
    assert got[("ConanCenter", "zlib", "1.2.11")] == ("github.com/madler/zlib", ("v1.2.11",), True, False)
    assert got[("ConanCenter", "expat", "2.4.8")][1] == ("R_2_4_8",)
    assert got[("ConanCenter", "cmake", "3.27.0")][3] is True                        # a tool: dev
    py = project(tmp_path / "py", {"conanfile.py": "from conan import ConanFile\nclass App(ConanFile):\n"
                                                   "    requires = ('zlib/1.2.11', 'expat/[>=2.4 <3]')\n"
                                                   "    def requirements(self):\n        self.requires('fmt/10.1.1')\n"})
    assert {k[1] for k in py} == {"zlib", "expat", "fmt"} and py[("ConanCenter", "expat", None)][0]
    v2 = project(tmp_path / "lock2", {"conan.lock": json.dumps({"version": "0.5", "requires": [
        "zlib/1.2.12#87a7211557b6690ef5bf7fc599dd8349%1706000000.0"], "build_requires": ["cmake/3.27.0#abc"]}),
        "conanfile.txt": "[requires]\nzlib/1.2.12\n"})
    assert set(v2) == {("ConanCenter", "zlib", "1.2.12"), ("ConanCenter", "cmake", "3.27.0")}  # the lock wins
    v1 = project(tmp_path / "lock1", {"conan.lock": json.dumps({"graph_lock": {"nodes": {
        "0": {"ref": "app/1.0", "requires": ["1"]}, "1": {"ref": "zlib/1.2.11#rev", "requires": []}}}})})
    assert v1[("ConanCenter", "zlib", "1.2.11")][2] is True


def test_vcpkg_manifest_and_installed_status(tmp_path):
    got = project(tmp_path / "m", {"vcpkg.json": json.dumps({
        "dependencies": ["zlib", {"name": "fmt", "version>=": "10.0.0"}],
        "overrides": [{"name": "zlib", "version": "1.2.12"}], "builtin-baseline": "a" * 40})})
    assert got[("vcpkg", "zlib", "1.2.12")] == ("github.com/madler/zlib", ("v1.2.12",), True, False)
    assert ("vcpkg", "fmt", None) in got                                             # a range: unmatched
    status = ("Package: zlib\nVersion: 1.2.11\nArchitecture: x64-linux\nStatus: install ok installed\n\n"
              "Package: zlib\nFeature: core\nArchitecture: x64-linux\nStatus: install ok installed\n\n"
              "Package: fmt\nVersion: 10.1.1\nStatus: purge ok not-installed\n")
    got = project(tmp_path / "s", {"vcpkg.json": json.dumps({"dependencies": ["zlib"]}),
                                   "vcpkg_installed/vcpkg/status": status})
    assert set(got) == {("vcpkg", "zlib", "1.2.11")}                                 # status wins; purged skipped


def test_cmake_fetches(tmp_path):
    got = project(tmp_path, {"CMakeLists.txt": '''
include(FetchContent)
FetchContent_Declare(zlib GIT_REPOSITORY https://github.com/madler/zlib.git GIT_TAG v1.2.11)
FetchContent_Declare(curl URL https://github.com/curl/curl/releases/download/curl-8_3_0/curl-8.3.0.tar.gz)
FetchContent_Declare(pinned GIT_REPOSITORY https://github.com/fmtlib/fmt GIT_TAG 0c9fce2ffefecfdce794e1859584e25877b7b592)
FetchContent_Declare(varied GIT_REPOSITORY https://github.com/gabime/spdlog GIT_TAG ${SPDLOG_TAG})
CPMAddPackage("gh:nlohmann/json@3.10.0")
CPMAddPackage(NAME expat GITHUB_REPOSITORY libexpat/libexpat GIT_TAG R_2_4_8)
'''})
    tags = {k[1]: v[1] for k, v in got.items()}
    assert tags == {"github.com/madler/zlib": ("v1.2.11",), "github.com/curl/curl": ("curl-8_3_0",),
                    "github.com/fmtlib/fmt": (), "github.com/gabime/spdlog": (),
                    "github.com/nlohmann/json": ("v3.10.0",), "github.com/libexpat/libexpat": ("R_2_4_8",)}


@pytest.mark.skipif(not shutil.which("git"), reason="needs git")
def test_submodules_resolve_their_pinned_tag(tmp_path):
    git = lambda cwd, *a: subprocess.run(["git", "-c", "user.email=t@x", "-c", "user.name=t",
                                          "-c", "protocol.file.allow=always", *a], cwd=cwd, check=True,
                                         capture_output=True)
    lib = tmp_path / "zlib-src"
    lib.mkdir()
    git(lib, "init", "-q")
    (lib / "zlib.h").write_text("/* zlib */\n")
    git(lib, "add", ".")
    git(lib, "commit", "-qm", "release")
    git(lib, "tag", "v1.2.11")
    app = tmp_path / "app"
    app.mkdir()
    git(app, "init", "-q")
    git(app, "submodule", "add", "-q", str(lib), "third_party/zlib")
    (app / ".gitmodules").write_text('[submodule "third_party/zlib"]\n\tpath = third_party/zlib\n'
                                     '\turl = https://github.com/madler/zlib.git\n')
    git(app, "commit", "-qam", "add zlib")
    got = {k[1]: (k[2], v[1]) for k, v in project(app, {}).items()}
    assert got == {"github.com/madler/zlib": ("v1.2.11", ("v1.2.11",))}


@pytest.fixture
def git_db(tmp_path, monkeypatch):
    from frame.kb.store import pull
    mirror = tmp_path / "mirror"
    build_advisories([GIT_RECORDS], mirror, "r1")
    shards = [p for p, m in json.loads((mirror / "manifest.json").read_text())["files"].items() if m["language"] == "git"]
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    return mirror, shards, pull


def test_cpp_dependencies_match_osv_git_advisories_pulling_only_their_shards(tmp_path, git_db):
    mirror, shards, pull = git_db
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "conanfile.txt").write_text("[requires]\nexpat/2.4.8\n")
    (proj / "CMakeLists.txt").write_text(
        "FetchContent_Declare(zlib GIT_REPOSITORY https://github.com/madler/zlib.git GIT_TAG v1.2.11)\n"
        "FetchContent_Declare(curl URL https://github.com/curl/curl/releases/download/curl-8_3_0/curl-8.3.0.tar.gz)\n"
        "FetchContent_Declare(newzlib GIT_REPOSITORY https://github.com/madler/zlib.git GIT_TAG v1.3)\n")
    files = read_dependencies(proj).files
    needed = sorted({git_shard(r) for r in repos_of(files)})
    got = pull([], source=str(mirror), also=needed)
    assert sorted(got.files) == needed and len(needed) < len(shards)                # only what the project needs
    db = AdvisoryDB.cached([], repos_of(files))
    found = {(f["package"], f["tag"], f["id"]) for f in match(files, db)}
    assert found == {("github.com/madler/zlib", "v1.2.11", "CVE-2022-37434"),
                     ("expat", "R_2_4_8", "CVE-2022-40674"),
                     ("github.com/curl/curl", "curl-8_3_0", "CVE-2023-38545")}         # v1.3 is fixed


def test_cpp_sbom_validates(tmp_path):
    pytest.importorskip("jsonschema")
    from tests.test_sca_sbom import validate_cyclonedx, validate_spdx
    from frame.sca.sbom import to_cyclonedx, to_spdx
    (tmp_path / "conanfile.txt").write_text("[requires]\nzlib/1.2.11\n")
    (tmp_path / "CMakeLists.txt").write_text("CPMAddPackage(\"gh:nlohmann/json@3.10.0\")\n")
    report = read_dependencies(tmp_path)
    cdx = to_cyclonedx(report, "pkg:generic/app", timestamp="2026-10-28T12:00:00Z")
    validate_cyclonedx(cdx)
    assert {c["purl"] for c in cdx["components"]} == {"pkg:conan/zlib@1.2.11", "pkg:github/nlohmann/json@v3.10.0"}
    validate_spdx(to_spdx(report, "pkg:generic/app", timestamp="2026-10-28T12:00:00Z"))
