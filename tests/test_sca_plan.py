"""Version ranges (checked against node-semver and packaging) and upgrade plans: the smallest
version that leaves every known advisory, and what the change takes."""

import gzip
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.advisories import AdvisoryDB, build_advisories, match
from frame.sca.model import normalize_name
from frame.sca.osv import compact, is_affected
from frame.sca.plan import plan, target_version
from frame.sca.ranges import satisfies
from frame.sca.versions import compare, sort_key

OSV = Path(__file__).parent / "fixtures" / "sca" / "osv"
RECORDS = json.loads(gzip.decompress((OSV / "records.json.gz").read_bytes()))
EXPECTED = json.loads((OSV / "expected.json").read_text())["queries"]

NPM_VERSIONS = ["0.0.1", "0.1.0", "0.1.5", "0.2.0", "1.0.0", "1.0.0-beta.1", "1.2.2", "1.2.3", "1.2.3-alpha",
                "1.2.4", "1.3.0", "1.9.9", "2.0.0", "2.0.0-rc.1", "2.1.0", "3.0.0", "4.17.20", "4.17.21"]
NPM_RANGES = ["^1.2.3", "~1.2.3", "~1.2", "~1", "^0.1.2", "^0.0.1", "^0.1", "^1", "1.x", "1.2.x", "*", "",
              "1.2.3 - 2.0.0", "1.2 - 1.9", ">=1.2.3 <2.0.0", ">1.2", ">1", "<=1.2", "<2", "<1.2.3", "1.2.3",
              "^1.2.3 || ^3", "~1.2.3 || >=4.17.21", "^4.17.20", ">=1.0.0-beta.0 <1.0.0", "^2.0.0-rc.0",
              ">1.2.3-alpha <1.3.0", "1.2", "~>1.2"]


@pytest.mark.skipif(not shutil.which("node"), reason="needs node (npm's semver)")
def test_npm_ranges_match_node_semver():
    root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
    semver = Path(root) / "npm" / "node_modules" / "semver"
    if not semver.is_dir():
        pytest.skip("npm's semver not found")
    js = ("const s=require(process.argv[1]);const V=JSON.parse(process.argv[2]),R=JSON.parse(process.argv[3]);"
          "const o={};for(const v of V)for(const r of R)o[v+'|'+r]=s.satisfies(v,r);console.log(JSON.stringify(o))")
    ref = json.loads(subprocess.run(["node", "-e", js, str(semver), json.dumps(NPM_VERSIONS), json.dumps(NPM_RANGES)],
                                    capture_output=True, text=True).stdout)
    mine = {f"{v}|{r}": satisfies("npm", v, r) for v in NPM_VERSIONS for r in NPM_RANGES}
    assert {k: (mine[k], ref[k]) for k in mine if mine[k] != ref[k]} == {}


def test_npm_ranges_spot_checks():
    assert satisfies("npm", "4.17.21", "^4.17.20") and not satisfies("npm", "5.0.0", "^4.17.20")
    assert satisfies("npm", "0.1.9", "^0.1.2") and not satisfies("npm", "0.2.0", "^0.1.2")
    assert not satisfies("npm", "2.0.0-rc.1", "^1.2.3")                   # prereleases need an opt-in
    assert satisfies("npm", "1.2.3", "git+https://x/y.git") is None        # not a range: unknown


PEP440_VERSIONS = ["0.9", "1.0", "1.0a1", "1.0.post1", "1.0.dev1", "1.1", "1.4", "1.4.5", "1.5", "2.0", "2.0rc1",
                   "2.0.1", "3.0", "1.2.3", "1.2.10", "1!0.5", "1.1.post3", "2.0rc2"]
PEP440_SPECS = [">=1.0,<2", "~=1.4", "~=1.4.2", "==1.2.*", "!=1.4", ">1.0", "<2.0", "<=1.4", "==1.0", "~=2.0",
                ">=1.0,!=1.4,<2.0", "==2.*", ">1.0.post1", "<2.0rc2", ">=2.0rc1", "", ">1.1", "!=2.*"]


def _is_pre(v):
    return any(t in v for t in ("a", "b", "rc", "dev"))


def test_pep440_specifiers_match_packaging_on_releases():
    """Final and post releases: `packaging` is stable there across versions. (Its default
    pre-release handling changed between releases of the library, so pre-releases are pinned
    to the PEP 440 text below instead.)"""
    specifiers = pytest.importorskip("pip._vendor.packaging.specifiers")
    version = pytest.importorskip("pip._vendor.packaging.version")
    bad = [(v, s) for v in PEP440_VERSIONS if not _is_pre(v) for s in PEP440_SPECS
           if satisfies("PyPI", v, s) != specifiers.SpecifierSet(s).contains(version.Version(v))]
    assert bad == []


@pytest.mark.parametrize("version,spec,want", [
    ("1.0a1", "!=1.4", False),          # pre-releases are excluded unless the specifier names one
    ("1.0a1", "", False),
    ("1.0a1", ">=1.0a1", True),          # ... and admitted when it does
    ("2.0rc1", "<2.0rc2", True),
    ("2.0rc1", "<2.0", False),           # `<V` excludes pre-releases of V itself
    ("1.0.dev1", ">=1.0.dev0", True),
    ("1.0.post1", ">1.0", False),        # `>V` excludes post-releases of V
    ("1.1.post3", ">1.0", True),
])
def test_pep440_prerelease_and_postrelease_rules(version, spec, want):
    assert satisfies("PyPI", version, spec) is want


def test_poetry_caret_and_tilde():
    assert satisfies("PyPI", "1.9.0", "^1.2.3") and not satisfies("PyPI", "2.0", "^1.2.3")
    assert satisfies("PyPI", "0.2.9", "^0.2.3") and not satisfies("PyPI", "0.3.0", "^0.2.3")
    assert satisfies("PyPI", "1.2.9", "~1.2") and not satisfies("PyPI", "1.3", "~1.2")


@pytest.mark.parametrize("eco,version,spec,want", [
    ("NuGet", "13.0.1", "[13.0.1, )", True), ("NuGet", "12.0.3", "[13.0.1, )", False),
    ("NuGet", "1.5.0", "1.0", True), ("NuGet", "0.9", "1.0", False),
    ("NuGet", "2.0", "[1.0,2.0)", False), ("NuGet", "1.0", "(1.0,2.0]", False), ("NuGet", "1.2", "[1.2]", True),
    ("Maven", "2.17.1", "[2.15.0,)", True), ("Maven", "2.14.1", "[2.15.0,)", False),
    ("Maven", "1.5", "(,1.0],[1.2,)", True), ("Maven", "1.1", "(,1.0],[1.2,)", False),
    ("Maven", "9.9", "1.0", True),                      # a soft requirement: the build may choose another
    ("crates.io", "1.33.1", "1.33", True), ("crates.io", "2.0.0", "1.33", False),   # Cargo: caret by default
])
def test_interval_and_cargo_requirements(eco, version, spec, want):
    assert satisfies(eco, version, spec) is want


def test_targets_are_minimal_and_leave_every_advisory():
    """Over every vulnerable fixture query: the target no advisory affects, and no smaller
    fixed version would do."""
    tables = {}
    for q in EXPECTED:
        if not q["ids"]:
            continue
        eco = q["ecosystem"]
        advs = tables.setdefault(eco, compact(RECORDS, eco))["packages"].get(normalize_name(eco, q["name"]), [])
        t = target_version(eco, q["version"], advs)
        if t is None:
            continue
        assert compare(eco, t, q["version"]) >= 0
        assert not any(is_affected(eco, t, a) for a in advs), (q["name"], t)
        smaller = {str(e["fixed"]) for a in advs for r in a["ranges"] for e in r["events"]
                   if "fixed" in e and sort_key(eco, str(e["fixed"])) is not None
                   and compare(eco, str(e["fixed"]), q["version"]) >= 0 and compare(eco, str(e["fixed"]), t) < 0}
        assert all(any(is_affected(eco, v, a) for a in advs) for v in smaller), (q["name"], t)


@pytest.fixture
def db(tmp_path, monkeypatch):
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1")
    from frame.kb.store import pull
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    pull(None, source=str(mirror))
    return AdvisoryDB.cached(["npm", "Maven", "PyPI"])


LOCK = {"name": "app", "lockfileVersion": 3, "packages": {
    "": {"dependencies": {"lodash": "~4.17.20", "mkdirp": "^0.5.5", "old-tool": "1.0.0"}},
    "node_modules/lodash": {"version": "4.17.20"},
    "node_modules/mkdirp": {"version": "0.5.5", "dependencies": {"minimist": "^1.2.5"}},
    "node_modules/minimist": {"version": "1.2.5"},
    "node_modules/old-tool": {"version": "1.0.0", "dependencies": {"minimist": "1.2.5"}},
    "node_modules/old-tool/node_modules/minimist": {"version": "1.2.5"},
}}


def test_plan_actions_follow_the_recorded_requirements(tmp_path, db):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package-lock.json").write_text(json.dumps(LOCK))
    report = read_dependencies(proj)
    plans = {p["package"]: p for p in plan(match(report.files, db), report.files, db)}
    lodash = plans["lodash"]
    assert lodash["target"] and not any(is_affected("npm", lodash["target"], a) for a in db.advisories("npm", "lodash"))
    assert lodash["action"] == "raise-requirement"            # ~4.17.20 excludes the fix
    assert lodash["requirers"] == [{"by": "(project)", "spec": "~4.17.20", "admits_target": False}]
    minimist = plans["minimist"]
    assert minimist["target"] == "1.2.6" and minimist["direct"] is False
    # one copy is under mkdirp (^1.2.5 admits 1.2.6), the other under old-tool's exact pin
    assert minimist["action"] == "override" and "overrides" in minimist["how"]
    assert {(r["by"], r["admits_target"]) for r in minimist["requirers"]} == {
        ("mkdirp@0.5.5", True), ("old-tool@1.0.0", False)}


def test_maven_plans_edit_the_pom(tmp_path, db):
    """Maven has no lockfile: a direct version is raised in the pom (re-running Maven would
    resolve the same version), even though the tree records no ranges."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "maven_dep_tree.txt").write_text(
        "com.acme:app:jar:1.0\n\\- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile\n")
    report = read_dependencies(proj)
    p = plan(match(report.files, db), report.files, db)[0]
    assert p["package"] == "org.apache.logging.log4j:log4j-core" and p["action"] == "raise-requirement"
    assert p["known_requirements"] is False and p["target"]
    assert not any(is_affected("Maven", p["target"], a)
                   for a in db.advisories("Maven", "org.apache.logging.log4j:log4j-core"))


def test_frame_deps_plan_cli(tmp_path, db):
    import os
    import sys
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package-lock.json").write_text(json.dumps(LOCK))
    out = subprocess.run([sys.executable, "-m", "frame.cli", "deps", str(proj), "--vulns", "--plan"],
                         capture_output=True, text=True, env=dict(os.environ), cwd=str(Path(__file__).parents[1]))
    assert "Upgrade plan" in out.stdout and "minimist 1.2.5 -> 1.2.6" in out.stdout
    assert "old-tool@1.0.0 requires 1.2.5" in out.stdout
