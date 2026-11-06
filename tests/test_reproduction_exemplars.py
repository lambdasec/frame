"""Proof-carrying reproduction exemplars: real reachability reproductions across languages.

Each case under `benchmarks/exemplars/reproductions/<name>/` is a small project that
reaches a known vulnerability shape (SCA deserialization, command injection, SQL
injection) through its own code, with a `case.json` giving the finding and a driver
Frame confirmed. These are both rigorous cross-language tests and the outreach demos
("a real, runnable reproduction of a known vuln").

The test is deterministic -- it runs each case's confirmed driver through the spy
runner (no model), so it validates the engine in CI. The agent finds that driver in
practice (validated separately against a live model).
"""

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from frame.sil.proof_deps import (
    DepsReproSpec, run_deps_repro, run_deps_repro_js, run_deps_repro_java,
)

_JS = {"javascript", "js", "typescript", "ts"}
_JAVA = {"java"}


def _skip_if_unavailable(meta: dict, language: str):
    if language in _JS and shutil.which("node") is None:
        pytest.skip("node not available for a JS exemplar")
    if language in _JAVA:
        # Opt-in only: Mockito mocking a JDK bootstrap class (java.lang.Runtime) is
        # JDK-vendor/version fragile (fails on some CI JDKs with "Could not modify
        # all classes"), so this never runs in the default suite. Set FRAME_REPRO_JAVA=1
        # on a host with a compatible JDK + Maven to exercise it.
        import os
        if not os.environ.get("FRAME_REPRO_JAVA"):
            pytest.skip("set FRAME_REPRO_JAVA=1 (needs a compatible JDK + Maven) for Java exemplars")
        if shutil.which("mvn") is None or shutil.which("javac") is None:
            pytest.skip("JDK + Maven not available for a Java exemplar")
    for mod in meta.get("requires", []):
        if importlib.util.find_spec(mod) is None:
            pytest.skip(f"real library {mod!r} not installed for this exemplar")


def _run_case(language: str, driver: str, spec, case):
    if language in _JS:
        return run_deps_repro_js(driver, spec, str(case))
    if language in _JAVA:
        return run_deps_repro_java(driver, spec, str(case))
    return run_deps_repro(driver, spec, str(case))


CASES_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "exemplars" / "reproductions"
CASES = sorted(p for p in CASES_DIR.glob("*") if (p / "case.json").is_file()) \
    if CASES_DIR.is_dir() else []


def _spec(meta: dict) -> DepsReproSpec:
    return DepsReproSpec(
        advisory=meta.get("advisory", meta.get("cwe", "")),
        package=meta.get("package", ""), version=meta.get("version", ""),
        vuln_function=meta["vuln_function"], call_text=meta["vuln_function"],
        call_site=meta["call_site"], source_var=meta.get("source_var", ""))


@pytest.mark.skipif(not CASES, reason="no reproduction exemplars found")
@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_exemplar_reproduces(case):
    meta = json.loads((case / "case.json").read_text())
    language = meta["language"].lower()
    _skip_if_unavailable(meta, language)
    run = _run_case(language, meta["driver"], _spec(meta), case)
    assert run.reproduced, f"{case.name}: {run.detail} ({run.result})"


@pytest.mark.skipif(not CASES, reason="no reproduction exemplars found")
@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_exemplar_rejects_a_driver_that_does_not_drive_the_sink(case):
    # Soundness guard: a driver that never drives the project to the sink must NOT
    # count as a reproduction (the spy is never reached with the marker).
    meta = json.loads((case / "case.json").read_text())
    language = meta["language"].lower()
    _skip_if_unavailable(meta, language)
    noop = ";" if language in (_JS | _JAVA) else "pass"
    run = _run_case(language, noop, _spec(meta), case)
    assert not run.reproduced
