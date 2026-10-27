"""Vulnerable functions mined from real fix commits (recorded under tests/fixtures/sca/commits:
the commit's patches and each changed file at the parent, from GitHub). Each expected id is
what the advisory itself documents; a fix that only changes module-level code yields nothing
and asks for curation."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca.mine import RecordedSource, changed_old_lines, commit_links, functions, mine

ROOT = Path(__file__).resolve().parents[1]
COMMITS = ROOT / "tests" / "fixtures" / "sca" / "commits"
RECORDS = json.loads((COMMITS / "records.json").read_text())


@pytest.fixture(scope="module")
def mined():
    tables, report = mine(RECORDS, ["npm", "PyPI", "Maven"], RecordedSource(COMMITS))
    return tables, {m.advisory: m for m in report}


def ids(m):
    return [e["id"] for e in m.entries]


def test_lodash_template_fix_is_lodash_template(mined):
    _, by = mined
    assert ids(by["GHSA-35jh-r3h4-6jhm"]) == ["lodash.template"]          # CVE-2021-23337
    e = by["GHSA-35jh-r3h4-6jhm"].entries[0]
    assert e["source"] == "fix-commit" and e["commit"].endswith("3469357cff396a26c363f8c1b5a91dde28ba4b1c")


def test_lodash_redos_fix_names_the_documented_functions(mined):
    _, by = mined
    assert ids(by["GHSA-29mw-wpgm-hmr9"]) == ["lodash.toNumber", "lodash.trim", "lodash.trimEnd"]  # CVE-2020-28500
    assert any("not" in s or "no recorded" in s for s in by["GHSA-29mw-wpgm-hmr9"].skipped)       # 2nd commit absent


def test_guava_fix_names_files_create_temp_dir_and_lifts_through_private_helpers(mined):
    _, by = mined
    m = by["GHSA-5mg8-w23w-74h3"]
    assert "com.google.common.io.Files.createTempDir" in ids(m)                                   # CVE-2020-8908
    lifted = {e["id"]: e.get("lifted_from") for e in m.entries}
    assert lifted["com.google.common.io.FileBackedOutputStream.write"] == "FileBackedOutputStream.update"
    assert not any("Test" in i for i in ids(m))                                                   # tests skipped


def test_a_fix_outside_any_function_asks_for_curation(mined):
    _, by = mined
    m = by["GHSA-8q59-q68h-6hv4"]                       # PyYAML moves constructor registrations
    assert m.entries == [] and m.needs_curation
    assert set(m.outside_functions) == {"lib/yaml/constructor.py", "lib3/yaml/constructor.py"}


def test_curated_entries_win_when_merged():
    existing = {"npm": {"GHSA-35jh-r3h4-6jhm": [{"id": "lodash.template", "source": "curated"}]}}
    tables, _ = mine(RECORDS, ["npm"], RecordedSource(COMMITS), existing=existing)
    assert tables["npm"]["GHSA-35jh-r3h4-6jhm"] == [{"id": "lodash.template", "source": "curated"}]
    assert {e["id"] for e in tables["npm"]["GHSA-29mw-wpgm-hmr9"]} == {"lodash.toNumber", "lodash.trim", "lodash.trimEnd"}


def test_patch_lines_and_commit_links():
    patch = "@@ -10,4 +10,5 @@ def f():\n a\n-b\n+B\n+C\n c\n d\n"
    assert changed_old_lines(patch) == {11, 12}            # b removed at 11; B and C inserted before 12
    rec = {"references": [{"url": "https://github.com/o/r/commit/abcdef1234567"},
                          {"url": "https://github.com/o/r/pull/9/commits/1234567abcdef"},
                          {"url": "https://example.com/advisory"}]}
    assert commit_links(rec) == [("o", "r", "abcdef1234567"), ("o", "r", "1234567abcdef")]


def test_public_and_private_are_read_from_the_source():
    java = ("package a.b;\npublic class C {\n  public void open() {}\n  private void helper() {}\n"
            "  protected C() {}\n  static class Hidden { public void x() {} }\n}\n")
    got = {f.name: f.public for f in functions(java, "java")}
    assert got == {"C.open": True, "C.helper": False, "C.<init>": True, "C.Hidden.x": False}
    py = "class Loader:\n    def load(self): pass\n    def _scan(self): pass\ndef _private(): pass\n"
    assert {f.name: f.public for f in functions(py, "python")} == {"Loader.load": True, "Loader._scan": False,
                                                                  "_private": False}


def test_frame_kb_mine_functions_cli(tmp_path):
    (tmp_path / "records.json").write_text(json.dumps(RECORDS))
    out = subprocess.run([sys.executable, "-m", "frame.cli", "kb", "mine-functions", str(tmp_path / "records.json"),
                          "--out", str(tmp_path / "out"), "--recorded", str(COMMITS)],
                         capture_output=True, text=True, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr
    assert "1 need curation" in out.stdout
    npm = json.loads((tmp_path / "out" / "npm.json").read_text())
    assert [e["id"] for e in npm["GHSA-35jh-r3h4-6jhm"]] == ["lodash.template"]
    curate = json.loads((tmp_path / "out" / "needs-curation.json").read_text())
    assert [c["advisory"] for c in curate] == ["GHSA-8q59-q68h-6hv4"]


class _Fake:
    """A one-commit source: qs's prototype-pollution fix shape (merge in lib/utils.js)."""
    def commit(self, owner, repo, sha):
        return {"sha": sha, "parents": ["p0"], "files": [
            {"filename": "lib/utils.js", "status": "modified", "patch": "@@ -2,3 +2,3 @@\n function merge(a, b) {\n-  return a;\n+  return b;\n }\n"}]}

    def file(self, owner, repo, ref, path):
        return {"package.json": '{"name": "qs", "main": "lib/index.js"}',
                "lib/utils.js": "function merge(a, b) {\n  return a;\n}\nexports.merge = merge;\n"}.get(path)


def test_an_export_outside_the_package_entry_is_not_the_packages_api():
    rec = {"id": "GHSA-qs", "references": [{"url": "https://github.com/ljharb/qs/commit/abcdef1"}],
           "affected": [{"package": {"ecosystem": "npm", "name": "qs"}}]}
    _, [m] = mine([rec], ["npm"], _Fake())
    assert m.entries == [] and m.needs_curation
    assert m.internal_only == ["lib/utils.js:merge (not the package entry)"]


class _Throttled:
    """A source whose quota runs out after the first commit."""
    def __init__(self):
        self.calls = 0

    def commit(self, owner, repo, sha):
        from frame.sca.mine import RateLimited
        self.calls += 1
        if self.calls > 1:
            raise RateLimited("GitHub API rate limit")
        return {"sha": sha, "parents": ["p"], "files": []}

    def file(self, *a):
        return None


def test_a_rate_limited_run_stops_and_resumes_exactly_where_it_left_off():
    from frame.sca.mine import Progress
    recs = [{"id": f"GHSA-{i}", "modified": f"2026-01-0{i}T00:00:00Z",
             "references": [{"url": f"https://github.com/o/r/commit/{i:07d}"}],
             "affected": [{"package": {"ecosystem": "PyPI", "name": "x"}}]} for i in (3, 1, 2)]
    prog = Progress()
    _, report = mine(recs, ["PyPI"], _Throttled(), since="2026-01-00", progress=prog)
    assert [m.advisory for m in report] == ["GHSA-1"]                       # oldest first; stopped at the 2nd
    assert prog.rate_limited and prog.processed == 1 and prog.resume_after == "2026-01-01T00:00:00Z"
    _, report = mine(recs, ["PyPI"], RecordedSource(COMMITS), since=prog.resume_after, progress=Progress())
    assert [m.advisory for m in report] == ["GHSA-2", "GHSA-3"]             # the next run picks up there
