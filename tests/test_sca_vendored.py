"""Vendored C/C++ libraries (`frame/sca/vendored.py`, `data/vendored.json`): identified by the
version their own header declares, next to their own sources, and matched by release tag.

Ground truth: each library's real version header from a real release (tests/fixtures/sca/vendored,
recorded from the release archives), and the tags OSV's own GIT records list for its repository,
so every curated tag form is shown to name real tags. Live (FRAME_SCA_REAL=1), every library is
re-checked against two freshly downloaded releases.
"""

import gzip
import json
import os
import re
from pathlib import Path

import pytest

from frame.sca.vendored import find_vendored, libraries, tags_for

F = Path(__file__).parent / "fixtures" / "sca" / "vendored"
HEADERS = json.loads(gzip.decompress((F / "headers.json.gz").read_bytes()))
OSV_TAGS = json.loads(gzip.decompress((F / "osv_tags.json.gz").read_bytes()))
LIBS = {lib.name: lib for lib in libraries()}


def _lay_out(root: Path, name: str, with_companions: bool = True) -> Path:
    h = HEADERS[name]
    (root / h["header"]).parent.mkdir(parents=True, exist_ok=True)
    (root / h["header"]).write_text(h["text"])
    for c in h["companions"] if with_companions else []:
        (root / c).parent.mkdir(parents=True, exist_ok=True)
        (root / c).write_text("/* the library's own source */\n")
    return root / h["header"]


def test_every_curated_library_has_a_recorded_release():
    assert set(HEADERS) == set(LIBS) and len(LIBS) >= 14
    for lib in LIBS.values():
        assert lib.reference.startswith("https://") and lib.companions


@pytest.mark.parametrize("name", sorted(HEADERS))
def test_a_real_release_header_gives_its_version_and_tag(tmp_path, name):
    _lay_out(tmp_path, name)
    files, warnings = find_vendored(tmp_path)
    assert not warnings
    [pkg] = [p for f in files for p in f.packages.values()]
    assert pkg.version == HEADERS[name]["version"] and HEADERS[name]["tag"] in pkg.tags
    assert pkg.repo == LIBS[name].repo and files[0].kind == "vendored"


@pytest.mark.parametrize("name", sorted(LIBS))
def test_every_tag_form_names_tags_osv_lists(name):
    """A form that named no real tag would make a vendored copy silently match nothing."""
    lib = LIBS[name]
    listed = set(OSV_TAGS[lib.repo])
    for form in lib.tags:
        rx = re.compile("^" + re.escape(form).replace(re.escape("{V_}"), r"\d+(_\d+)+")
                        .replace(re.escape("{V-}"), r"\d+(-\d+)+").replace(re.escape("{V}"), r"\d+(\.\d+)+") + "$")
        assert sum(1 for t in listed if rx.match(t)) >= 3, (name, form)


def test_a_lone_header_is_not_a_vendored_library(tmp_path):
    """A copy of zlib.h alone (to build against the system zlib) has none of zlib's sources."""
    _lay_out(tmp_path, "zlib", with_companions=False)
    assert find_vendored(tmp_path) == ([], [])


def test_a_development_snapshot_is_said_and_not_matched(tmp_path):
    header = _lay_out(tmp_path, "curl")
    header.write_text(header.read_text().replace('"8.6.0"', '"8.6.1-DEV"', 1))
    files, warnings = find_vendored(tmp_path)
    [pkg] = [p for f in files for p in f.packages.values()]
    assert pkg.version == "8.6.1-DEV" and pkg.tags == []
    assert "development snapshot" in warnings[0]


def test_a_submodule_checkout_is_not_reported_again(tmp_path):
    _lay_out(tmp_path / "third_party", "zlib")
    sub = next((tmp_path / "third_party").iterdir())
    (sub / ".git").write_text("gitdir: ../../.git/modules/zlib\n")      # how a submodule checkout looks
    from frame.sca.vendored import identify
    assert identify([p for p in tmp_path.rglob("zlib.h")], tmp_path) == ([], [])


def test_a_vendored_zlib_is_matched_like_any_tagged_dependency(tmp_path):
    """zlib 1.1.0 copied into third_party/: read_dependencies finds it, and the advisories are
    exactly the OSV records that list v1.1.0 among their affected tags."""
    from frame.sca import read_dependencies
    from frame.sca.advisories import AdvisoryDB, match
    from frame.sca.osv import git_entries, table
    _lay_out(tmp_path / "third_party", "zlib")
    records = json.loads(gzip.decompress((F / "zlib_osv_records.json.gz").read_bytes()))
    by: dict = {}
    for rec in records:
        for repo, e in git_entries(rec):
            by.setdefault(repo, []).append(e)
    db = AdvisoryDB(tables={"GIT": table("GIT", by)["packages"]})
    files = read_dependencies(tmp_path).files
    assert [(f.kind, f.path) for f in files] == [("vendored", "third_party/zlib-1.1.0/zlib.h")]
    found = {f["id"] for f in match(files, db)}
    expected = {r["id"] for r in records if any("v1.1.0" in (a.get("versions") or []) for a in r["affected"])}
    assert found == expected and expected


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1", reason="live: set FRAME_SCA_REAL=1 (downloads release sources)")
@pytest.mark.parametrize("name", sorted(HEADERS))
def test_live_the_recorded_release_still_reads_the_same(tmp_path, name):
    """Re-download the recorded release and check the detector reads the same version from it."""
    import io
    import tarfile
    import urllib.request
    import zipfile
    lib, h = LIBS[name], HEADERS[name]
    special = {"sqlite": "https://www.sqlite.org/2022/sqlite-amalgamation-3390400.zip",
               "libxml2": "https://download.gnome.org/sources/libxml2/2.9/libxml2-2.9.14.tar.xz",
               "curl": "https://curl.se/download/curl-8.6.0.tar.gz"}
    url = special.get(name) or f"https://codeload.github.com/{lib.repo.split('/', 1)[1]}/tar.gz/refs/tags/{h['tag']}"
    data = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "frame"}), timeout=300).read()
    want = {h["header"], *h["companions"]}
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                if n in want:
                    (tmp_path / n).parent.mkdir(parents=True, exist_ok=True)
                    (tmp_path / n).write_bytes(z.read(n))
    else:
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            for m in t.getmembers():
                if m.name in want and m.isfile():
                    (tmp_path / m.name).parent.mkdir(parents=True, exist_ok=True)
                    (tmp_path / m.name).write_bytes(t.extractfile(m).read())
    assert (tmp_path / h["header"]).read_text(errors="replace") == h["text"]
    files, _ = find_vendored(tmp_path)
    [pkg] = [p for f in files for p in f.packages.values()]
    assert pkg.version == h["version"] and h["tag"] in tags_for(lib, pkg.version)
    # the tag is the repository's own (OSV lists only the tags an advisory affects)
    import subprocess
    refs = subprocess.run(["git", "ls-remote", "--tags", f"https://{lib.repo}", f"refs/tags/{h['tag']}"],
                          capture_output=True, text=True, timeout=300).stdout
    assert f"refs/tags/{h['tag']}" in refs
    # without its header, the same sources are known by their blob ids (sqlite's amalgamation is
    # generated, so its repository has no sqlite3.c to fingerprint)
    if name != "sqlite":
        (tmp_path / h["header"]).unlink()
        from frame.sca.vendored import identify_by_fingerprint
        files, _ = identify_by_fingerprint(list(tmp_path.rglob("*.c")), tmp_path)
        [pkg] = [p for f in files for p in f.packages.values()]
        assert pkg.version == h["version"] or any(h["tag"] in a for a in pkg.alternatives)


def test_without_the_scan_extra_vendored_copies_are_said_not_read(tmp_path, monkeypatch):
    """`frame deps` runs on a plain install (no tree-sitter): a candidate header is reported as
    not read, and nothing fails."""
    import frame.sca.vendored as V
    _lay_out(tmp_path, "zlib")

    def missing():
        raise ImportError("No module named 'tree_sitter'")
    monkeypatch.setattr(V, "_c_parser", missing)
    files, warnings = V.find_vendored(tmp_path)
    assert files == [] and "pip install" in warnings[0] and "1 possible vendored" in warnings[0]


# ---------------------------------------------------------------------------------------------
# copies without their version header: file fingerprints (git blob ids at each release)

EXAMPLE = Path(__file__).parent.parent / "examples" / "vendored-c" / "third_party"


def _copy(dst: Path, *files: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for f in files:
        (dst / f.name).write_bytes(f.read_bytes())


def test_the_fingerprint_data_is_well_formed():
    from frame.sca.vendored import _indices, _runs, fingerprints
    data = fingerprints()
    assert set(data) == set(LIBS) - {"sqlite"}           # sqlite's sources are generated
    for name, lib in data.items():
        assert lib["releases"] == sorted(lib["releases"], key=lambda v: [int(x) for x in v.split(".")])
        assert len(set(lib["releases"])) == len(lib["releases"])
        n = len(lib["releases"])
        for blobs in lib["files"].values():
            for blob, runs in blobs.items():
                assert re.fullmatch(r"[0-9a-f]{16}", blob) and max(_indices(runs)) < n
    assert "6.0" not in data["libxml2"]["releases"]       # LIBXML2_6_0 is 2.6.0 (exclude_tags)
    assert _runs([0, 1, 2, 5, 7, 8]) == "0-2,5,7-8" and _indices("0-2,5,7-8") == {0, 1, 2, 5, 7, 8}


def test_a_copy_without_its_header_is_known_by_its_files(tmp_path):
    """zlib 1.2.11's inflate.c and deflate.c (from the release archive) with zlib.h renamed away,
    and cJSON 1.7.14's cJSON.c alone: each is exactly its release."""
    _copy(tmp_path / "src" / "z", EXAMPLE / "zlib" / "inflate.c", EXAMPLE / "zlib" / "deflate.c")
    (tmp_path / "src" / "z" / "z.h").write_bytes((EXAMPLE / "zlib" / "zlib.h").read_bytes())
    _copy(tmp_path / "lib" / "cj", EXAMPLE / "cjson" / "cJSON.c")
    from frame.sca import read_dependencies
    report = read_dependencies(tmp_path)
    got = {(f.path, f.kind, p.name, p.version, tuple(p.tags)) for f in report.files for p in f.packages.values()}
    assert got == {("lib/cj", "vendored", "github.com/davegamble/cjson", "1.7.14", ("v1.7.14",)),
                   ("src/z", "vendored", "github.com/madler/zlib", "1.2.11", ("v1.2.11",))}


def test_windows_line_endings_are_the_same_file(tmp_path):
    from frame.sca.vendored import identify_by_fingerprint
    for f in ("inflate.c", "deflate.c"):
        (tmp_path / f).write_bytes((EXAMPLE / "zlib" / f).read_bytes().replace(b"\n", b"\r\n"))
    files, _ = identify_by_fingerprint(list(tmp_path.glob("*.c")), tmp_path)
    assert [p.version for f in files for p in f.packages.values()] == ["1.2.11"]


def test_an_edited_file_is_not_upstream_s(tmp_path):
    from frame.sca.vendored import identify_by_fingerprint
    (tmp_path / "inflate.c").write_bytes((EXAMPLE / "zlib" / "inflate.c").read_bytes() + b"/* local patch */\n")
    assert identify_by_fingerprint([tmp_path / "inflate.c"], tmp_path) == ([], [])


def test_a_header_identified_copy_is_not_reported_twice(tmp_path):
    from frame.sca import read_dependencies
    _copy(tmp_path / "zlib", *(EXAMPLE / "zlib" / f for f in ("zlib.h", "inflate.c", "deflate.c")))
    assert [(f.path, f.kind) for f in read_dependencies(tmp_path).files] == [("zlib/zlib.h", "vendored")]


def test_one_file_shared_by_several_releases_decides_only_what_they_agree_on(tmp_path):
    """inflate.c alone is the same in zlib 1.2.9, 1.2.10 and 1.2.11: an advisory affecting all
    three is reported, one affecting some is not decided (never reported as not affecting)."""
    from frame.sca.advisories import AdvisoryDB, match
    from frame.sca.osv import git_entries, table
    from frame.sca.vendored import identify_by_fingerprint
    _copy(tmp_path / "z", EXAMPLE / "zlib" / "inflate.c")
    files, _ = identify_by_fingerprint([tmp_path / "z" / "inflate.c"], tmp_path)
    [pkg] = [p for f in files for p in f.packages.values()]
    assert pkg.version == "1.2.9 or 1.2.10 or 1.2.11" and not pkg.tags
    assert pkg.alternatives == [["v1.2.9"], ["v1.2.10"], ["v1.2.11"]]
    records = json.loads(gzip.decompress((F / "zlib_osv_records.json.gz").read_bytes()))
    by: dict = {}
    for rec in records:
        for repo, e in git_entries(rec):
            by.setdefault(repo, []).append(e)
    db = AdvisoryDB(tables={"GIT": table("GIT", by)["packages"]})
    found = {f["id"] for f in match(files, db)}
    listed = {r["id"]: {t for a in r["affected"] for t in a.get("versions") or []} for r in records}
    assert found == {i for i, v in listed.items() if {"v1.2.9", "v1.2.10", "v1.2.11"} <= v}
    some = {i for i, v in listed.items() if v & {"v1.2.9", "v1.2.10", "v1.2.11"}} - found
    assert len(db.undecided) == len(some) and (not some or "not decided" in db.notes[0])


def test_files_of_different_releases_are_said_not_matched(tmp_path, monkeypatch):
    import frame.sca.vendored as V
    (tmp_path / "inflate.c").write_bytes(b"a")
    (tmp_path / "deflate.c").write_bytes(b"b")
    fake = {"zlib": {"releases": ["1.0", "1.1"],
                     "files": {"inflate.c": {V.blob_id(b"a")[:16]: "0"}, "deflate.c": {V.blob_id(b"b")[:16]: "1"}}}}
    monkeypatch.setattr(V, "fingerprints", lambda: fake)
    files, warnings = V.identify_by_fingerprint([tmp_path / "inflate.c", tmp_path / "deflate.c"], tmp_path)
    assert files == [] and "different releases" in warnings[0]
