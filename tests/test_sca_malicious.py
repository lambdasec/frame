"""Malicious packages, RustSec's informational notices and Python start-up hooks.

What an advisory is about (`osv.advisory_kind`) comes from the record's own fields: OpenSSF's
`MAL-` ids, GitHub's CWE-506 family, RustSec's `informational`. The advice follows from it: a
malicious release is pinned away from and its credentials rotated, a malicious package (every
release) removed, an unmaintained crate replaced. Start-up hooks are the files CPython runs at
every interpreter start (`.pth` import lines, sitecustomize), checked against `site` itself.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca.advisories import AdvisoryDB, build_advisories, finding_kind, match
from frame.sca.container import pth_executes, read_rootfs
from frame.sca.discover import format_vulns
from frame.sca.model import NPM, PYPI, DependencyFile, Package
from frame.sca.osv import _merged_kind, compact
from frame.sca.plan import format_plan, plan

CRATES = "crates.io"
F = Path(__file__).parent / "fixtures" / "sca" / "malicious"


def _records():
    return [json.loads(p.read_text()) for p in sorted(F.glob("*.json"))]


def _kinds(eco):
    return {a["id"]: a.get("kind") for advs in compact(_records(), eco)["packages"].values() for a in advs}


def test_the_kind_comes_from_the_records_own_fields():
    assert _kinds(PYPI) == {"MAL-2026-20101": "malicious", "PYSEC-2026-151": None}
    assert _kinds(NPM) == {"GHSA-54pg-9963-v8vg": "malicious", "GHSA-vv52-3mrp-455m": "malicious",
                           "MAL-2026-3204": "malicious"}
    assert _kinds(CRATES) == {"RUSTSEC-2025-0056": "unmaintained"}


def test_merged_records_are_malicious_if_any_says_so_and_a_notice_only_if_all_do():
    assert _merged_kind([{"kind": "malicious"}, {}]) == "malicious"
    assert _merged_kind([{}, {"kind": "malicious"}]) == "malicious"
    assert _merged_kind([{"kind": "unmaintained"}, {}]) is None          # a flaw filed beside it is a flaw
    assert _merged_kind([{"kind": "unsound"}, {"kind": "unsound"}]) == "unsound"


def test_a_table_built_before_the_field_still_names_openssfs_id():
    assert finding_kind({"id": "GHSA-x", "aliases": ["MAL-2026-1"]}) == "malicious"
    assert finding_kind({"id": "GHSA-x", "aliases": ["CVE-2026-1"]}) is None


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("db")
    mirror = tmp / "mirror"
    build_advisories([F], mirror, "r1", [PYPI, NPM, CRATES])
    mp = pytest.MonkeyPatch()
    mp.setenv("FRAME_KB_CACHE", str(tmp / "cache"))
    mp.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    from frame.kb.store import pull
    pull(["pypi", "npm", "crates.io"], source=str(mirror))
    yield AdvisoryDB.cached([PYPI, NPM, CRATES])
    mp.undo()


def _file(eco, name, version):
    df = DependencyFile("requirements.txt", eco, "manifest")
    df.add(Package(eco, name, version, direct=True))
    return df


def test_a_malicious_release_is_pinned_away_from_and_its_credentials_rotated(db):
    files = [_file(PYPI, "agent-framework", "1.26.1")]
    found = match(files, db)
    assert [(f["id"], f["kind"], f["every_version"], f["severity"]) for f in found] == [
        ("MAL-2026-20101", "malicious", False, "critical")]
    text = format_vulns(found)
    assert "(direct, malicious)" in text
    assert "malicious release: pin a release the advisory does not list and rotate every credential" in text
    assert "no fixed version" not in text
    out = format_plan(plan(found, files, db))
    assert "malicious release: pin a release other than 1.26.1, 1.26.2, then rotate every credential" in out
    assert match([_file(PYPI, "agent-framework", "1.26.0")], db) == []


def test_a_package_malicious_in_every_release_is_removed(db):
    files = [_file(NPM, "m-backdoor", "0.0.1")]
    found = match(files, db)
    assert [(f["id"], f["every_version"]) for f in found] == [("GHSA-vv52-3mrp-455m", True)]
    assert "malicious package, every release: remove it" in format_vulns(found)
    assert "every release is malicious: remove it" in format_plan(plan(found, files, db))


def test_an_unmaintained_crate_is_replaced(db):
    files = [_file(CRATES, "adler", "1.0.2")]
    found = match(files, db)
    assert [(f["id"], f["kind"]) for f in found] == [("RUSTSEC-2025-0056", "unmaintained")]
    assert "unmaintained, no fix will come: replace it" in format_vulns(found)
    assert "unmaintained, no fix will come; replace it with a maintained package" in format_plan(plan(found, files, db))


def test_an_ordinary_flaw_keeps_its_advice(db):
    found = match([_file(PYPI, "wasmtime", "43.0.0")], db)
    assert found and all("kind" not in f for f in found)
    assert "last affected 43.0.0" in format_vulns(found)


# ---------------------------------------------------------------------------------------------
# start-up hooks

PTH_LINES = ["import os; open(os.environ['M'] + '/a', 'w')",      # executed
             "import\tos; open(os.environ['M'] + '/b', 'w')",     # import + tab: executed
             " import os; open(os.environ['M'] + '/c', 'w')",     # leading space: a path
             "#import os; open(os.environ['M'] + '/d', 'w')",     # a comment
             "importos",                                          # a path
             "/opt/extra"]


def test_the_lines_a_pth_file_executes_are_the_ones_cpythons_site_runs(tmp_path):
    site, marks = tmp_path / "site", tmp_path / "marks"
    site.mkdir()
    marks.mkdir()
    (site / "x.pth").write_text("\n".join(PTH_LINES) + "\n")
    subprocess.run([sys.executable, "-I", "-c", f"import site; site.addsitedir({str(site)!r})"],
                   check=True, env={"M": str(marks)})
    ran = {p.name for p in marks.iterdir()}
    assert ran == {"a", "b"}
    assert pth_executes((site / "x.pth").read_text()) == PTH_LINES[:2]


def test_startup_hooks_are_listed_with_the_package_that_installed_them(tmp_path):
    sp = tmp_path / "usr/lib/python3.12/site-packages"
    dist = sp / "agent_framework-1.26.1.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: agent-framework\nVersion: 1.26.1\n")
    (dist / "RECORD").write_text("agent_framework_init.pth,sha256=x,30\n"
                                 "agent_framework-1.26.1.dist-info/METADATA,,\n")
    (sp / "agent_framework_init.pth").write_text("import agent_framework_init\n")
    (sp / "orphan.pth").write_text("import os; os.getcwd()\n")
    (sp / "paths.pth").write_text("/opt/extra\n# only paths\n")
    (sp / "sitecustomize.py").write_text("print('start')\n")
    files, _ = read_rootfs(tmp_path)
    hooks = [h for f in files for h in f.startup_hooks]
    assert hooks == [
        {"file": "agent_framework_init.pth", "kind": "pth", "executes": 1, "owner": "agent-framework 1.26.1"},
        {"file": "orphan.pth", "kind": "pth", "executes": 1, "owner": None},
        {"file": "sitecustomize.py", "kind": "sitecustomize", "owner": None}]
    assert [f.to_dict()["startup_hooks"] for f in files if f.startup_hooks] == [hooks]
