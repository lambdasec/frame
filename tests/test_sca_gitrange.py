"""C/C++ dependencies pinned to an untagged commit (a git submodule): OSV's GIT commit ranges,
decided on the checkout's own history (`frame.sca.gitrange`).

The rule is the OSV schema's: a commit is affected when an `introduced` commit is its ancestor
and no `fixed` commit lies between that `introduced` and it; `last_affected` and `limit` bound it
from above. Offline, a small repository built with real git covers the branch cases. Live
(FRAME_SCA_REAL=1), real zlib and libexpat histories are compared with OSV's own commit query: on
every commit OSV's index answers for, the sets are equal. OSV's index leaves commits that only
reached the default branch through a merged side branch unanswered (33 of 34 such libexpat
commits), even when they predate the fix; Frame decides them by the same rule.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from frame.sca.gitrange import commit_affected, git_ancestry

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_AUTHOR_DATE": "2020-01-01T00:00:00", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00"}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()


@pytest.fixture
def history(tmp_path):
    """main: A - B - C ------- M - E      (M merges the fix branch: F)
                     \\- F (fix) -/
       D: a commit on main after C but before M (concurrent with the fix)."""
    repo = tmp_path / "lib"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    c = {}
    for name in ("A", "B", "C"):
        _git(repo, "commit", "-q", "--allow-empty", "-m", name)
        c[name] = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "fix")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "F")
    c["F"] = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "D")
    c["D"] = _git(repo, "rev-parse", "HEAD")
    _git(repo, "merge", "-q", "--no-ff", "fix", "-m", "M")
    c["M"] = _git(repo, "rev-parse", "HEAD")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "E")
    c["E"] = _git(repo, "rev-parse", "HEAD")
    return repo, c


def test_introduced_and_fixed_on_the_commit_graph(history):
    repo, c = history
    anc = git_ancestry(repo)
    rng = [[{"introduced": c["B"]}, {"fixed": c["F"]}]]
    assert [commit_affected(c[n], rng, anc) for n in "ABCDFME"] == [False, True, True, True, False, False, False]
    # D was written after the fix branched off and before it was merged: still vulnerable code
    assert commit_affected(c["D"], [[{"introduced": "0"}, {"fixed": c["F"]}]], anc) is True


def test_last_affected_and_limit(history):
    repo, c = history
    anc = git_ancestry(repo)
    assert [commit_affected(c[n], [[{"introduced": "0"}, {"last_affected": c["C"]}]], anc) for n in "ACDE"] == \
        [True, True, False, False]
    assert [commit_affected(c[n], [[{"introduced": c["A"]}, {"limit": c["D"]}]], anc) for n in "ACDE"] == \
        [True, True, False, False]


def test_a_commit_the_checkout_lacks_is_undecided(history):
    repo, c = history
    missing = "f" * 40
    anc = git_ancestry(repo)
    assert commit_affected(c["C"], [[{"introduced": missing}, {"fixed": c["F"]}]], anc) is None
    assert commit_affected(c["C"], [[{"introduced": "0"}, {"fixed": missing}]], anc) is None
    # another range of the same advisory that does decide wins
    assert commit_affected(c["C"], [[{"introduced": missing}], [{"introduced": c["A"]}, {"fixed": c["F"]}]], anc) is True


def test_an_untagged_submodule_is_matched_by_commit(history, tmp_path):
    """A project with the library as a submodule pinned to C (no tag): the advisory whose range
    holds C is found through the checkout's history, the one fixed before C is not, and one whose
    commits the checkout lacks is reported as undecided."""
    from frame.sca import read_dependencies
    from frame.sca.advisories import AdvisoryDB, match
    lib, c = history
    app = tmp_path / "app"
    app.mkdir()
    _git(app, "init", "-q", "-b", "main")
    subprocess.run(["git", "-C", str(app), "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                    "https://github.com/acme/lib", "third_party/lib"], capture_output=True)
    shutil.rmtree(app / "third_party" / "lib", ignore_errors=True)
    subprocess.run(["git", "clone", "-q", str(lib), str(app / "third_party" / "lib")], check=True)
    _git(app / "third_party" / "lib", "checkout", "-q", c["C"])
    (app / ".gitmodules").write_text('[submodule "lib"]\n\tpath = third_party/lib\n\turl = https://github.com/acme/lib\n')
    _git(app, "add", ".gitmodules", "third_party/lib")
    _git(app, "commit", "-q", "-m", "app")
    pkg = next(p for f in read_dependencies(app).files for p in f.packages.values())
    assert pkg.commit == c["C"] and not pkg.tags and pkg.checkout
    entry = {"summary": "", "severity": "high", "score": None, "cvss": None, "aliases": [], "versions": [], "functions": []}
    db = AdvisoryDB(tables={"GIT": {"github.com/acme/lib": [
        {**entry, "id": "OPEN", "commits": [[{"introduced": "0"}, {"fixed": c["F"]}]]},
        {**entry, "id": "DONE", "commits": [[{"introduced": "0"}, {"fixed": c["B"]}]]},
        {**entry, "id": "ELSEWHERE", "commits": [[{"introduced": "e" * 40}, {"fixed": "d" * 40}]]},
        {**entry, "id": "TAGS-ONLY", "versions": ["v1.0"]}]}})
    found = match(read_dependencies(app).files, db)
    assert [(f["id"], f["commit"]) for f in found] == [("OPEN", c["C"])]
    assert any("not in the checkout" in n and "ELSEWHERE" in n for n in db.notes)
    # an advisory with tags but no commit ranges cannot decide an untagged commit: said, not "clean"
    assert any("no commit ranges" in n and "TAGS-ONLY" in n for n in db.notes)
    assert db.undecided == ["high", "high"]
    from frame.sca.discover import format_vulns
    assert "No known vulnerabilities" not in format_vulns([], (), len(db.undecided))
    assert "NOT DECIDED: 2 advisory(ies)" in format_vulns([], (), len(db.undecided))


def _osv_commit_query(commit: str) -> set:
    import urllib.request
    body, ids = {"commit": commit}, set()
    while True:
        r = json.load(urllib.request.urlopen(urllib.request.Request("https://api.osv.dev/v1/query", json.dumps(body).encode()), timeout=60))
        ids |= {v["id"] for v in r.get("vulns", [])}
        if not r.get("next_page_token"):
            return ids
        body["page_token"] = r["next_page_token"]


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1", reason="live: set FRAME_SCA_REAL=1 (clones zlib, libexpat; OSV API)")
@pytest.mark.parametrize("url,repo", [("https://github.com/madler/zlib.git", "github.com/madler/zlib"),
                                      ("https://github.com/libexpat/libexpat.git", "github.com/libexpat/libexpat")])
def test_live_commits_on_the_default_branch_agree_with_osv(tmp_path, url, repo):
    """On the default branch's first-parent commits (the ones OSV's commit index answers for),
    Frame's answer from OSV's own records equals OSV's commit query."""
    import random
    import urllib.request
    from frame.sca.osv import git_entries, table
    checkout = tmp_path / "repo"
    subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url, str(checkout)], check=True, timeout=1800)
    fp = subprocess.run(["git", "-C", str(checkout), "rev-list", "--first-parent", "HEAD"], capture_output=True, text=True).stdout.split()
    random.seed(11)
    sample = random.sample(fp, min(25, len(fp)))
    truth = {c: _osv_commit_query(c) for c in sample}
    ids = set().union(*truth.values())
    records = [json.load(urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{i}", timeout=60)) for i in sorted(ids)]
    by: dict = {}
    for rec in records:
        for rp, e in git_entries(rec):
            by.setdefault(rp, []).append(e)
    advs = table("GIT", {repo: by.get(repo, [])})["packages"][repo]
    anc = git_ancestry(checkout)
    mine = {i for a in advs for i in [a["id"], *a.get("aliases", [])]}
    for c in sample:
        ours = {i for a in advs if commit_affected(c, a.get("commits", []), anc) for i in [a["id"], *a.get("aliases", [])]}
        assert ours & ids == truth[c] & mine, (c, sorted(truth[c] - ours), sorted(ours - truth[c]))
