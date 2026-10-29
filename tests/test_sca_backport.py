"""Backported fixes for npm (`frame deps --vulns --backport`, frame/sca/backport.py): the advisory's
own fix commits applied to the installed version as a patch-package patch.

Recorded: GHSA-xvch-5gv4-984h (minimist prototype pollution) from OSV, and its four linked
commits from GitHub (tests/fixtures/sca/backport, in GitHubSource's cache layout, so nothing is
fetched); examples/npm-backport is a real `npm install` of minimist 1.2.5. Live (FRAME_SCA_REAL=1,
needs npm): real patch-package applies the patch on `npm install`, and the advisory's own proof of
concept no longer pollutes.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from frame.sca.backport import _postinstall, installed, patch_file, propose
from frame.sca.mine import GitHubSource

ROOT = Path(__file__).parent.parent
F = ROOT / "tests" / "fixtures" / "sca" / "backport"
EXAMPLE = ROOT / "examples" / "npm-backport"
ADV = "GHSA-xvch-5gv4-984h"
FINDING = {"id": ADV, "aliases": ["CVE-2021-44906"], "ecosystem": "npm", "package": "minimist", "version": "1.2.5",
           "path": "package-lock.json"}


def record(advisory):
    return json.loads((F / "cache" / "osv" / f"{advisory}.json").read_text())


def source():
    return GitHubSource(F / "cache")


@pytest.fixture
def project(tmp_path):
    work = tmp_path / "p"
    shutil.copytree(EXAMPLE, work)
    return work


def test_only_the_commit_for_this_release_line_applies(project):
    changes, manual, [bp] = propose([dict(FINDING)], project, source(), record)
    assert bp.commits == ["minimistjs/minimist@c2b981977fa8"]          # the 1.x fix
    skipped = dict(s.split(": ", 1) for s in bp.skipped)
    assert skipped["minimistjs/minimist@bc8ecee43875"] == "changes no source file the package ships"   # a test
    assert skipped["minimistjs/minimist@34e20b846111"].startswith("does not apply to 1.2.5")           # 0.x line
    assert skipped["minimistjs/minimist@ef9153fc52b6"].startswith("does not apply to 1.2.5")
    assert manual == ["install patch-package once: npm install --save-dev patch-package"]
    patch, pkg = changes
    assert patch.path == "patches/minimist+1.2.5.patch" and patch.before == ""
    assert patch.after.startswith("diff --git a/node_modules/minimist/index.js b/node_modules/minimist/index.js")
    assert "+        if (isConstructorOrProto(o, key)) return;" in patch.after
    assert pkg.path == "package.json" and '"postinstall": "patch-package",' in pkg.after


def test_the_patch_applies_to_the_installed_files_with_git(project, tmp_path):
    """The patch-package file applies to node_modules as patch-package applies it (`git apply`)."""
    changes, _, _ = propose([dict(FINDING)], project, source(), record)
    (tmp_path / "x.patch").write_text(changes[0].after)
    r = subprocess.run(["git", "apply", "--check", str(tmp_path / "x.patch")], cwd=project, capture_output=True,
                       text=True)
    assert r.returncode == 0, r.stderr


def test_not_installed_or_no_commit_is_said(tmp_path, project):
    shutil.rmtree(project / "node_modules")
    changes, manual, done = propose([dict(FINDING)], project, source(), record)
    assert not changes and not done and "not installed in node_modules" in manual[0]
    rec = {**record(ADV), "references": []}
    changes, manual, done = propose([dict(FINDING)], tmp_path, source(), lambda a: rec)
    assert "not installed" in manual[0] or "no fix commit" in manual[0]


@pytest.mark.parametrize("before,after", [
    ('{\n  "scripts": {\n    "start": "node a.js"\n  }\n}\n',
     '{\n  "scripts": {\n    "postinstall": "patch-package",\n    "start": "node a.js"\n  }\n}\n'),
    ('{\n  "name": "x"\n}\n', '{\n  "scripts": {\n    "postinstall": "patch-package"\n  },\n  "name": "x"\n}\n'),
    ('{"scripts": {}}', '{"scripts": {"postinstall": "patch-package"}}'),
    ('{"scripts": {"postinstall": "patch-package && husky"}}', '{"scripts": {"postinstall": "patch-package && husky"}}'),
    ('{"scripts": {"postinstall": "husky"}}', None),                    # a person combines them
])
def test_postinstall_is_added_as_one_line(before, after):
    assert _postinstall(before) == after


def test_names():
    assert patch_file("@babel/core", "7.0.0") == "patches/@babel+core+7.0.0.patch"
    assert installed(EXAMPLE, "package-lock.json", "minimist", "1.2.5") is not None
    assert installed(EXAMPLE, "package-lock.json", "minimist", "1.2.6") is None


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1", reason="live: set FRAME_SCA_REAL=1 (needs npm)")
def test_live_patch_package_applies_it_and_the_poc_stops(project):
    if shutil.which("npm") is None:
        pytest.fail("npm is not installed")
    poc = ("var p=require('minimist'); p(['--_.concat.constructor.prototype.y','123']); "
           "function f(){}; process.stdout.write(String(f.y))")
    before = subprocess.run(["node", "-e", poc], cwd=project, capture_output=True, text=True).stdout
    assert before == "123"                                              # 1.2.5 is vulnerable
    for c in propose([dict(FINDING)], project, source(), record)[0]:
        (project / c.path).parent.mkdir(parents=True, exist_ok=True)
        (project / c.path).write_text(c.after)
    subprocess.run(["npm", "install", "--no-audit", "--no-fund", "--save-dev", "patch-package"], cwd=project,
                   check=True, capture_output=True, timeout=600)
    out = subprocess.run(["npm", "install", "--no-audit", "--no-fund"], cwd=project, capture_output=True,
                         text=True, timeout=600)
    assert "minimist@1.2.5" in out.stdout + out.stderr
    after = subprocess.run(["node", "-e", poc], cwd=project, capture_output=True, text=True).stdout
    assert after == "undefined"
