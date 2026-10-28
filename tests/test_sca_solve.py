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

    def deps(self, name, version):
        d = self.data.get(name, {}).get(version)
        return d if isinstance(d, dict) else None              # a non-dict: the registry does not say


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


def test_an_unknown_range_is_never_an_open_one():
    """The lockfile records no range for the current parent (uv.lock) and the registry gives
    none for it: the child is held at its current version, so only a parent upgrade can fix it.
    A parent version whose dependencies are unknown is never chosen."""
    df, keys = _df([("app", "1.0.0"), ("lib", "1.0.0")], {"app": ["lib"]}, {"": {"app": ">=1"}}, {"app"})
    reg = Reg({"app": {"1.0.0": "unknown", "1.1.0": "unknown", "1.2.0": {"lib": ">=1.1"}},
               "lib": {"1.0.0": {}, "1.1.0": {}}})
    sol = solve_file(df, {keys["lib"]}, DB({"lib": [adv("1.1.0")]}), reg)
    assert {c.package: c.target for c in sol.changes} == {"app": "1.2.0", "lib": "1.1.0"}


def test_pep_508_requirements():
    from frame.sca.registry import parse_requires_dist
    got = parse_requires_dist(["Werkzeug (>=2.0)", "Jinja2>=3.0", "asgiref (>=3.2) ; extra == 'async'",
                               "importlib-metadata>=3.6.0; python_version < '3.10'", "idna",
                               "typing_extensions>=4; python_version<'3.8'"])
    assert got == {"werkzeug": ">=2.0", "jinja2": ">=3.0", "importlib-metadata": ">=3.6.0", "idna": ">=0",
                   "typing-extensions": ">=4"}


FLASK = Path(__file__).parent / "fixtures" / "sca" / "solve" / "flask-app"


def flask_db():
    return AdvisoryDB(tables={"PyPI": json.loads(gzip.decompress((FLASK / "advisories.json.gz").read_bytes()))})


def test_the_real_flask_app_from_uv_lock(tmp_path, monkeypatch):
    """uv.lock records no per-package ranges: the solver reads them from PyPI's metadata. The
    project's own ranges come from the root's requires-dist (requests==2.25.1, flask<3)."""
    from frame.sca.registry import Registries
    monkeypatch.setenv("FRAME_REGISTRY_CACHE", str(FLASK / "registry"))
    for n in ("pyproject.toml", "uv.lock"):
        shutil.copy(FLASK / n, tmp_path / n)
    files = read_dependencies(tmp_path).files
    assert files[0].requires[""] == {"flask": ">=1.1.2,<3", "requests": "==2.25.1"}
    db = flask_db()
    reg = Registries(offline=True)
    solved = {p["package"]: p for p in plan(match(files, db), files, db, reg)}
    assert solved["requests"]["action"] == "raise-requirement"            # pinned by the project
    assert solved["flask"]["action"] == "raise-requirement" and solved["flask"]["major"]
    assert not any(p["action"] in ("override", "no-fix") for p in solved.values())
    pypi = reg.for_ecosystem("PyPI")
    chosen = {n: p["target"] for n, p in solved.items()}
    final = {pk.name: chosen.get(pk.name, pk.version) for pk in files[0].packages.values()}
    brought = {b["package"] for p in solved.values() for b in p.get("brings", [])}
    for name, version in final.items():                                    # re-checked without the solver
        assert not any(is_affected("PyPI", version, a) for a in db.advisories("PyPI", name)), (name, version)
        for child, rng in (pypi.deps(name, version) or {}).items():
            if child in final and not satisfies("PyPI", final[child], rng):
                assert child not in chosen and child in brought, (name, version, child, rng, final[child])
    assert "click" in brought                                              # flask 3 needs click>=8.1.3


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("uv"),
                    reason="live: set FRAME_SCA_REAL=1 (uv and PyPI)")
def test_live_uv_relock_of_the_solved_plan(tmp_path):
    """The flask<3 bound is the project's: Frame leaves that raise to a person (manual), so
    after re-locking only Flask's own advisories remain."""
    from frame.sca.apply import apply_plan
    from frame.sca.registry import Registries
    for n in ("pyproject.toml", "uv.lock"):
        shutil.copy(FLASK / n, tmp_path / n)
    files = read_dependencies(tmp_path).files
    db = flask_db()
    plans = plan(match(files, db), files, db, Registries())
    out = apply_plan(plans, tmp_path, write=True, relock_=True)
    assert not out.warnings, out.warnings
    assert any(m.startswith("flask") for m in out.manual)
    assert {f["package"] for f in match(read_dependencies(tmp_path).files, db)} <= {"flask"}


def test_a_declared_range_that_admits_vulnerable_releases():
    from frame.sca.solve import format_exposure, range_exposure
    df = DependencyFile("package.json", NPM, "manifest")
    df.require("", "lib", "^1.0.0")
    df.require("", "safe", "^2.0.0")
    df.require("", "pinned", "1.0.0")
    reg = Reg({"lib": {"1.0.0": {}, "1.1.0": {}, "1.2.0": {}, "2.0.0": {}},
               "safe": {"2.0.0": {}, "2.1.0": {}}, "pinned": {"1.0.0": {}, "1.1.0": {}}})
    rows = {r["package"]: r for r in range_exposure([df], DB({"lib": [adv("1.2.0")], "safe": [adv("2.0.0")],
                                                               "pinned": [adv("1.1.0")]}), reg)}
    assert set(rows) == {"lib", "pinned"}                                  # ^2.0.0 admits nothing vulnerable
    assert (rows["lib"]["vulnerable"], rows["lib"]["admits"], rows["lib"]["floor"]) == (2, 3, "1.2.0")
    assert rows["pinned"]["floor"] is None
    text = format_exposure(list(rows.values()))
    assert "raise the floor to 1.2.0" in text and "every version it admits is vulnerable" in text


CARGO_URL = Path(__file__).parent / "fixtures" / "sca" / "solve" / "cargo-url"


def test_the_real_cargo_app_upgrades_url_for_idna(tmp_path, monkeypatch):
    """url 2.4.1 requires idna ^0.4; the fix is idna 1.0.0, which url 2.5.1 requires (the index
    says so: 2.5.2 went back to ^0.5). Per package this was a re-lock that could not work."""
    from frame.sca.registry import CratesRegistry, Registries, crates_index_path
    assert [crates_index_path(n) for n in ("a", "ab", "url", "idna", "serde_json")] == \
        ["1/a", "2/ab", "3/u/url", "id/na/idna", "se/rd/serde_json"]
    monkeypatch.setenv("FRAME_REGISTRY_CACHE", str(CARGO_URL / "registry"))
    for n in ("Cargo.toml", "Cargo.lock"):
        shutil.copy(CARGO_URL / n, tmp_path / n)
    files = read_dependencies(tmp_path).files
    db = AdvisoryDB(tables={"crates.io": json.loads(gzip.decompress((CARGO_URL / "advisories.json.gz").read_bytes()))})
    solved = {p["package"]: p for p in plan(match(files, db), files, db, Registries(offline=True))}
    assert (solved["url"]["target"], solved["idna"]["target"]) == ("2.5.1", "1.0.0")
    assert solved["url"]["action"] == "update-lockfile" and solved["url"]["enables"] == ["idna"]
    idx = CratesRegistry(offline=True)
    assert satisfies("crates.io", "1.0.0", idx.deps("url", "2.5.1")["idna"])     # re-checked without the solver
    assert not any(is_affected("crates.io", "1.0.0", a) for a in db.advisories("crates.io", "idna"))


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1" or not shutil.which("cargo"),
                    reason="live: set FRAME_SCA_REAL=1 (cargo and crates.io)")
def test_live_cargo_relock_of_the_solved_plan(tmp_path):
    """cargo update -p X --precise V, retried in dependency order (idna can move only after url)."""
    from frame.sca.apply import apply_plan
    from frame.sca.registry import Registries
    for n in ("Cargo.toml", "Cargo.lock"):
        shutil.copy(CARGO_URL / n, tmp_path / n)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text("fn main() {}\n")
    files = read_dependencies(tmp_path).files
    db = AdvisoryDB(tables={"crates.io": json.loads(gzip.decompress((CARGO_URL / "advisories.json.gz").read_bytes()))})
    out = apply_plan(plan(match(files, db), files, db, Registries()), tmp_path, write=True, relock_=True)
    assert not out.warnings, out.warnings
    assert match(read_dependencies(tmp_path).files, db) == []


def test_what_relocking_moves_counts_every_installed_copy(tmp_path):
    """express 4.22.3 needs debug 2.6.9, which the lockfile already has beside mocha's 4.3.4:
    nothing to move. minimatch 10 needs brace-expansion ^5, which no installed copy satisfies:
    listed once, with both installed versions."""
    for n in ("package.json", "package-lock.json"):
        shutil.copy(APP / n, tmp_path / n)
    files = read_dependencies(tmp_path).files
    db = app_db()
    solved = {p["package"]: p for p in plan(match(files, db), files, db, RecordedRegistry(APP / "registry"))}
    express = {b["package"] for b in solved["express"].get("brings", [])}
    assert "debug" not in express and "depd" in express          # depd: only 1.1.2 is locked
    braces = [b for b in solved["minimatch"]["brings"] if b["package"] == "brace-expansion"]
    assert len(braces) == 1 and "," in braces[0]["current"]
