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
import subprocess
from pathlib import Path

import pytest


def _tool_works(*cmd) -> bool:
    """True only when the tool runs (not a macOS JDK stub with no runtime behind it)."""
    exe = shutil.which(cmd[0])
    if exe is None:
        return False
    try:
        return subprocess.run([exe, *cmd[1:]], capture_output=True,
                              timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False

from frame.sil.proof_deps import (
    DepsReproSpec, fix_proof, run_deps_repro, run_deps_repro_js, run_deps_repro_java,
    run_deps_repro_csharp,
)

_JS = {"javascript", "js", "typescript", "ts"}
_JAVA = {"java"}
_CSHARP = {"csharp", "c#", "cs"}


def _skip_if_unavailable(meta: dict, language: str):
    if language in _JS and shutil.which("node") is None:
        pytest.skip("node not available for a JS exemplar")
    if language in _JAVA and not (_tool_works("javac", "-version") and _tool_works("java", "-version")):
        pytest.skip("a working JDK (javac/java) is not available for a Java exemplar")
    if language in _CSHARP and not _tool_works("dotnet", "--version"):
        pytest.skip(".NET SDK not available for a C# exemplar")
    for mod in meta.get("requires", []):
        if importlib.util.find_spec(mod) is None:
            pytest.skip(f"real library {mod!r} not installed for this exemplar")


def _run_case(language: str, driver: str, spec, case):
    if language in _JS:
        return run_deps_repro_js(driver, spec, str(case))
    if language in _JAVA:
        return run_deps_repro_java(driver, spec, str(case))
    if language in _CSHARP:
        return run_deps_repro_csharp(driver, spec, str(case))
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


# Fix-loop tie-in: a case with a `fixed/` subdir carries a repaired copy of its own
# sources. The SAME confirmed driver must reproduce against the vulnerable code and
# must NO LONGER reproduce against the fixed code -- the proof of the vulnerability has
# become a proof of the fix (the flow to the sink is gone). Only fixes that remove the
# flow flip a reachability reproduction; a sanitize-in-place or an upgrade that keeps
# the call is certified by a re-scan, not by this test.
FIX_CASES = [c for c in CASES if (c / "fixed").is_dir()]


@pytest.mark.skipif(not FIX_CASES, reason="no reproduction exemplars carry a fixed/ variant")
@pytest.mark.parametrize("case", FIX_CASES, ids=[c.name for c in FIX_CASES])
def test_fix_stops_the_reproduction(case):
    meta = json.loads((case / "case.json").read_text())
    language = meta["language"].lower()
    _skip_if_unavailable(meta, language)
    proof = fix_proof(meta["driver"], _spec(meta), str(case), str(case / "fixed"),
                      language=language)
    assert proof.before.reproduced, \
        f"{case.name}: the driver did not reproduce against the vulnerable code ({proof.before.detail})"
    assert not proof.after.reproduced, \
        f"{case.name}: the fix did not stop the reproduction ({proof.after.detail})"
    assert proof.proved, f"{case.name}: {proof.detail}"


@pytest.mark.skipif(not CASES, reason="no reproduction exemplars found")
@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_exemplar_rejects_a_driver_that_does_not_drive_the_sink(case):
    # Soundness guard: a driver that never drives the project to the sink must NOT
    # count as a reproduction (the spy is never reached with the marker).
    meta = json.loads((case / "case.json").read_text())
    language = meta["language"].lower()
    _skip_if_unavailable(meta, language)
    noop = ";" if language in (_JS | _JAVA | _CSHARP) else "pass"
    run = _run_case(language, noop, _spec(meta), case)
    assert not run.reproduced
