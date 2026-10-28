"""Cross-package upgrade planning with Z3 (`frame deps --plan --registry`).

The real case (tests/fixtures/sca/solve/express-app) is an npm 10 lockfile, npm's own registry
metadata and the dataset's advisories. The solver's answer is re-checked here by plain code
(every chosen range admits every chosen child, no chosen version is affected), and, live,
by applying it and re-locking with real npm (0 vulnerabilities left, no overrides)."""

import gzip
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca import read_dependencies
from frame.sca.advisories import AdvisoryDB, match
from frame.sca.model import NPM, DependencyFile, Package
from frame.sca.osv import is_affected
from frame.sca.plan import plan
from frame.sca.ranges import satisfies
from frame.sca.registry import RecordedRegistry
from frame.sca.solve import solve_file

APP = Path(__file__).parent / "fixtures" / "sca" / "solve" / "express-app"


def app_db():
    return AdvisoryDB(tables={NPM: json.loads(gzip.decompress((APP / "advisories.json.gz").read_bytes()))})


def test_the_real_app_needs_no_override_and_stays_on_express_4(tmp_path):
    for n in ("package.json", "package-lock.json"):
        shutil.copy(APP / n, tmp_path / n)
    files = read_dependencies(tmp_path).files
    db = app_db()
    findings = match(files, db)
    alone = plan(findings, files, db)
    assert sum(p["action"] == "override" for p in alone) >= 5          # what planning one package at a time gives
    reg = RecordedRegistry(APP / "registry")
    solved = plan(findings, files, db, reg)
    assert not any(p["action"] in ("override", "no-fix") for p in solved)
    chosen = {p["package"]: p["target"] for p in solved}
    assert chosen["express"].startswith("4.")                           # no major jump where a minor will do
    # re-check the solution without the solver
    df = files[0]
    installed = {p.name: p.version for p in df.packages.values()}
    final = {**installed, **{n: v for n, v in chosen.items()}}
    for name, version in final.items():
        if version is None:
            continue
        assert not any(is_affected(NPM, version, a) for a in db.advisories(NPM, name)), (name, version)
    for p in solved:
        if p["action"] == "removed":
            dependents = [q for q, v in final.items() if v and v != installed.get(q)
                          and p["package"] in (reg.versions(q) or {}).get(v, {}).get("deps", {})]
            assert not dependents, (p["package"], dependents)
    for parent, version in chosen.items():
        meta = reg.versions(parent)
        if version is None or meta is None:
            continue
        for child, rng in meta[version]["deps"].items():
            if child in chosen and chosen[child] is not None:
                assert satisfies(NPM, chosen[child], rng), (parent, version, child, rng, chosen[child])


def _df(packages, edges, requires, direct):
    df = DependencyFile("package-lock.json", NPM, "lockfile")
    keys = {}
    for name, version in packages:
        keys[name] = df.add(Package(NPM, name, version, direct=name in direct)).key
    for parent, children in edges.items():
        for c in children:
            df.edge(keys[parent], keys[c])
    for parent, reqs in requires.items():
        for child, spec in reqs.items():
            df.require(keys[parent] if parent else "", child, spec)
    return df, keys


class Reg:
    def __init__(self, data):
        self.data = data

    def versions(self, name):
        return {v: {"deps": d, "deprecated": False} for v, d in self.data.get(name, {}).items()} or None


class DB:
    def __init__(self, advisories):
        self.a = advisories

    def advisories(self, eco, name):
        return self.a.get(name, [])


def adv(fixed):
    return {"id": "X", "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}


def test_an_upgrade_that_drops_the_dependency_removes_it():
    df, keys = _df([("app", "1.0.0"), ("bad", "1.0.0")], {"app": ["bad"]}, {"": {"app": "^1.0.0"}, "app": {"bad": "1.0.0"}},
                   {"app"})
    reg = Reg({"app": {"1.0.0": {"bad": "1.0.0"}, "1.1.0": {}}, "bad": {"1.0.0": {}}})
    sol = solve_file(df, {keys["bad"]}, DB({"bad": [adv("9.0.0")]}), reg)
    changes = {c.package: c.target for c in sol.changes}
    assert changes == {"app": "1.1.0", "bad": None} and sol.fixed == {keys["bad"]}


def test_a_minor_beats_a_major_and_a_raise_is_flagged():
    df, keys = _df([("app", "1.0.0"), ("lib", "1.0.0")], {"app": ["lib"]},
                   {"": {"app": "~1.0.0"}, "app": {"lib": "1.0.0"}}, {"app"})
    reg = Reg({"app": {"1.0.0": {"lib": "1.0.0"}, "1.2.0": {"lib": "^1.1.0"}, "2.0.0": {"lib": "^1.1.0"}},
               "lib": {"1.0.0": {}, "1.1.0": {}}})
    sol = solve_file(df, {keys["lib"]}, DB({"lib": [adv("1.1.0")]}), reg)
    app = next(c for c in sol.changes if c.package == "app")
    assert app.target == "1.2.0" and app.raise_requirement                  # ~1.0.0 excludes 1.2.0


def test_what_no_upgrade_can_fix_is_left_unresolved():
    df, keys = _df([("app", "1.0.0"), ("lib", "1.0.0")], {"app": ["lib"]},
                   {"": {"app": "^1.0.0"}, "app": {"lib": "1.0.0"}}, {"app"})
    reg = Reg({"app": {"1.0.0": {"lib": "1.0.0"}, "1.1.0": {"lib": "1.0.0"}}, "lib": {"1.0.0": {}, "2.0.0": {}}})
    sol = solve_file(df, {keys["lib"]}, DB({"lib": [adv("2.0.0")]}), reg)
    assert sol.unresolved == {keys["lib"]} and not sol.fixed


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("npm"),
                    reason="live: set FRAME_SCA_REAL=1 (npm and the npm registry)")
def test_live_npm_relock_of_the_solved_plan_leaves_nothing(tmp_path):
    for n in ("package.json", "package-lock.json"):
        shutil.copy(APP / n, tmp_path / n)
    files = read_dependencies(tmp_path).files
    db = app_db()
    from frame.sca.apply import apply_plan
    from frame.sca.registry import NpmRegistry
    plans = plan(match(files, db), files, db, NpmRegistry())
    out = apply_plan(plans, tmp_path, write=True, relock_=True)
    assert not out.warnings, out.warnings
    assert "overrides" not in json.loads((tmp_path / "package.json").read_text())
    assert match(read_dependencies(tmp_path).files, db) == []
