"""Proof-carrying findings for dependencies (Phase 5c, foundation brick).

`frame scan --sca` can already show that a project's own code reaches a vulnerable
library function with attacker data (`reachability.level == "tainted"`). This turns
that reachability into an executable artifact: a test that drives the project's code
to the vulnerable call and checks, with a spy on the library function, that attacker
data actually arrives there. A reachability claim you can run.

This module is the deterministic foundation: it pulls the reproduction spec out of a
tainted dependency finding and emits a pytest that installs the spy and asserts the
flow. Driving the entry point with a concrete reaching input is the next brick -- for
a simple parameter it is direct, otherwise a seeded agent fills it (mirroring
`frame.sil.proof_reproduce` for C), and the spy is the oracle. Pure and offline: it
shapes data the scan already produced and writes text; it runs nothing.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class DepsReproSpec:
    """What a tainted dependency finding gives us to build a reproduction from."""
    advisory: str                       # advisory id (e.g. GHSA-.../CVE-...)
    package: str
    version: str
    vuln_function: str                  # the library function's canonical id
    call_text: str                      # how it is written at the call site
    call_site: str                      # "path:line" where attacker data reaches it
    source_var: str                     # the tainted variable at the sink
    fixed: Optional[str] = None
    summary: str = ""
    flows: List[Dict] = field(default_factory=list)

    @property
    def module_path(self) -> str:
        """The source file holding the reachable call (no line number)."""
        return self.call_site.rpartition(":")[0]


def deps_repro_spec(finding: Dict) -> Optional[DepsReproSpec]:
    """Extract a reproduction spec from a `frame scan --sca` finding, or None when the
    finding is not a reached-by-attacker-data (`tainted`) dependency finding -- only a
    tainted flow has a concrete site to drive to."""
    reach = finding.get("reachability") or {}
    if reach.get("level") != "tainted":
        return None
    flows = reach.get("flows") or []
    calls = reach.get("calls") or []
    if not flows:
        return None
    primary = flows[0]
    # the call at the flow's site, for the function id and call text
    site = primary.get("location", "")
    call = next((c for c in calls if c.get("location") == site), calls[0] if calls else {})
    fixed = finding.get("fixed") or []
    return DepsReproSpec(
        advisory=finding.get("id", ""),
        package=finding.get("package", ""),
        version=finding.get("version", ""),
        vuln_function=call.get("function", ""),
        call_text=call.get("call", "") or call.get("function", ""),
        call_site=site,
        source_var=primary.get("source", ""),
        fixed=(fixed[0] if fixed else None),
        summary=finding.get("summary", ""),
        flows=flows,
    )


def _spy_target(spec: DepsReproSpec) -> str:
    """The dotted path to patch so the test observes the vulnerable call. Best effort
    from the canonical id; the generated test has a clear marker to adjust it."""
    fn = spec.vuln_function or spec.call_text
    return fn.replace("/", ".").strip(".")


def python_deps_test(spec: DepsReproSpec) -> str:
    """Emit a pytest that spies on the vulnerable library function and asserts the
    project's code reaches it with attacker data. The place to drive the entry point
    with a reaching input is marked: a parameter is filled directly, anything else is
    where the reproduction agent (next brick) writes the call."""
    target = _spy_target(spec)
    fix = f"  Fixed in {spec.fixed}." if spec.fixed else ""
    lines = [
        '"""Frame proof-carrying dependency test (reachability reproduction).',
        "",
        f"Advisory {spec.advisory} in {spec.package}=={spec.version}.{fix}",
        f"Frame found attacker data reaching {spec.vuln_function!r}",
        f"at {spec.call_site} (tainted variable {spec.source_var!r}).",
        "This test drives the code to that call and checks the data arrives there.",
        '"""',
        "import pytest",
        "",
        "",
        "def test_attacker_data_reaches_the_vulnerable_function(monkeypatch):",
        f"    # Spy on the vulnerable library function: {spec.vuln_function}",
        "    seen = {}",
        "",
        "    def _spy(*args, **kwargs):",
        "        seen['args'] = args",
        "        seen['kwargs'] = kwargs",
        "        return None",
        "",
        f"    # Adjust this dotted path if the import differs: {target}",
        f"    monkeypatch.setattr({target.rpartition('.')[0]!r} + '.' +",
        f"                        {target.rpartition('.')[2]!r}, _spy, raising=False)",
        "",
        "    MARKER = 'PROOF_MARKER_7F3A'",
        "    # TODO(reaching input): call the project entry point reached at",
        f"    #   {spec.call_site}",
        "    # with input that carries MARKER so it flows to the vulnerable call.",
        "    # For a handler taking the input as a parameter, call it directly:",
        "    #     from your.module import handler; handler(MARKER)",
        "    pytest.skip('fill in the entry-point call that drives MARKER to the sink')",
        "",
        "    assert seen, 'the vulnerable function was not reached'",
        "    assert any(MARKER in str(a) for a in seen.get('args', ())), \\",
        "        'attacker data did not reach the vulnerable function'",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------------------
# Phase 5c brick 2: run a reproduction driver with a harness-controlled spy oracle.
#
# The agent writes only a DRIVER: code that imports the project's entry point and calls it so
# the global MARKER flows toward the vulnerable library function. The harness owns everything
# that decides success -- it installs the spy on the vulnerable function and judges -- so the
# agent cannot forge a result (the lesson from the C forged-abort bug). A reproduction counts
# only when the spy saw the marker in its arguments AND the vulnerable function was called from
# the flagged call-site file (checked via the runtime stack), which defeats the obvious cheat of
# calling the vulnerable function directly from the driver.


_RUNNER = r'''
import importlib, json, sys, traceback
sys.path.insert(0, {root!r})
MARKER = {marker!r}
_CALLSITE = {callsite!r}
_DOTTED = {dotted!r}
RESULT = {{"seen": False, "marker_in_args": False, "via_callsite": False, "error": ""}}

def _resolve_parent(dotted):
    # longest importable module prefix, then walk attributes to the parent of the leaf
    parts = dotted.split(".")
    mod = None
    i = len(parts)
    while i > 0:
        try:
            mod = importlib.import_module(".".join(parts[:i])); break
        except Exception:
            i -= 1
    if mod is None:
        raise ImportError("no importable module in %r" % dotted)
    obj = mod
    for p in parts[i:-1]:
        obj = getattr(obj, p)
    return obj, parts[-1]

try:
    _parent, _leaf = _resolve_parent(_DOTTED)
    def _spy(*a, **k):
        RESULT["seen"] = True
        vals = [str(x) for x in a] + [str(v) for v in k.values()]
        RESULT["marker_in_args"] = any(MARKER in s for s in vals)
        frames = traceback.extract_stack()[:-1]
        RESULT["via_callsite"] = any(str(f.filename).endswith(_CALLSITE) for f in frames)
        return None
    setattr(_parent, _leaf, _spy)
except Exception as e:
    RESULT["error"] = "patch failed: %s: %s" % (type(e).__name__, e)

if not RESULT["error"]:
    try:
{driver}
    except Exception as e:
        RESULT["error"] = "driver error: %s: %s" % (type(e).__name__, e)

with open({result!r}, "w") as _f:
    json.dump(RESULT, _f)
'''


@dataclass
class DepsRun:
    """Outcome of running a reproduction driver under the spy."""
    reproduced: bool
    detail: str = ""
    result: Dict = field(default_factory=dict)


def run_deps_repro(driver_src: str, spec: "DepsReproSpec", project_root: str, *,
                   marker: str = "PROOF_MARKER_7F3A", python: Optional[str] = None,
                   timeout: int = 30) -> DepsRun:
    """Run the agent's driver with a harness spy on the vulnerable function.

    ``reproduced`` is True only when the spy observed the marker in the vulnerable
    function's arguments AND that function was called from the flagged call-site
    file -- i.e. attacker-marked data reached the vulnerable function through the
    project's own code, not a direct call from the driver. Never raises.
    """
    dotted = (spec.vuln_function or spec.call_text).replace("/", ".").strip(".")
    if not dotted:
        return DepsRun(False, "could not resolve the vulnerable function")
    callsite_file = spec.module_path.replace("/", "/").split(":")[0]
    indented = "\n".join("        " + ln for ln in driver_src.splitlines()) or "        pass"
    interp = python or sys.executable
    with tempfile.TemporaryDirectory() as d:
        result_path = str(Path(d) / "result.json")
        runner = _RUNNER.format(root=str(project_root), marker=marker,
                                callsite=callsite_file, dotted=dotted,
                                driver=indented, result=result_path)
        runner_path = Path(d) / "_frame_deps_runner.py"
        runner_path.write_text(runner)
        try:
            subprocess.run([interp, str(runner_path)], capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return DepsRun(False, f"run error: {exc}")
        try:
            res = json.loads(Path(result_path).read_text())
        except (OSError, ValueError):
            return DepsRun(False, "driver produced no result")
    ok = bool(res.get("seen") and res.get("marker_in_args") and res.get("via_callsite")
              and not res.get("error"))
    detail = ("marker reached the vulnerable function via the project" if ok
              else res.get("error") or "the marker did not reach the vulnerable function via the project")
    return DepsRun(ok, detail, res)


def python_deps_test_with_driver(spec: "DepsReproSpec", driver: str,
                                 marker: str = "PROOF_MARKER_7F3A") -> str:
    """A complete, runnable pytest built from a CONFIRMED driver.

    Installs a spy on the vulnerable function, runs the driver (which drives the
    project entry with MARKER), and asserts the marker reached the vulnerable
    function through the project. This asserts the vulnerability's reachability is
    present; after a fix that removes the flow the assertion fails, flagging that the
    reproduction no longer holds."""
    dotted = (spec.vuln_function or spec.call_text).replace("/", ".").strip(".")
    callsite = spec.module_path.split(":")[0]
    driver_lines = "\n".join("    " + ln for ln in driver.splitlines()) or "    pass"
    fix = f"  Fixed in {spec.fixed}." if spec.fixed else ""
    pkg = f" in {spec.package}=={spec.version}" if spec.package else ""
    return (
        '"""Frame proof-carrying reachability test (reproduction).\n\n'
        f"{spec.advisory}{pkg}.{fix}\n"
        f"Attacker data reaches {spec.vuln_function} at {spec.call_site}.\n"
        'Generated by Frame; the driver was confirmed by a spy on the sink.\n"""\n'
        "import traceback\n\n\n"
        "def test_attacker_data_reaches_the_sink(monkeypatch):\n"
        f"    MARKER = {marker!r}\n"
        "    seen = {}\n\n"
        "    def _spy(*args, **kwargs):\n"
        "        vals = [str(a) for a in args] + [str(v) for v in kwargs.values()]\n"
        "        seen['marker'] = any(MARKER in v for v in vals)\n"
        f"        seen['via_callsite'] = any(str(f.filename).endswith({callsite!r})\n"
        "                                   for f in traceback.extract_stack()[:-1])\n"
        "        return None\n\n"
        f"    # monkeypatch resolves a dotted target, including a class method:\n"
        f"    monkeypatch.setattr({dotted!r}, _spy, raising=False)\n\n"
        "    # driver confirmed by Frame to drive MARKER to the sink:\n"
        f"{driver_lines}\n\n"
        "    assert seen.get('marker'), 'attacker data did not reach the sink'\n"
        "    assert seen.get('via_callsite'), 'the sink was not reached via the project'\n"
    )


def taint_repro_spec(finding: Dict) -> Optional["DepsReproSpec"]:
    """A reproduction spec for a CODE taint finding (SQL injection, command injection,
    XSS, ...): the 'vulnerable function' is the injection sink the attacker data
    reaches. Reuses the dependency reproduction machinery -- same spy, same oracle.
    Returns None when the finding names no resolvable sink call."""
    sink = finding.get("sink_call") or ""
    if not sink or "/" not in sink and "." not in sink:
        return None   # a bare textual sink (e.g. "execute") cannot be import-resolved
    loc = finding.get("location", "")
    line = finding.get("line")
    call_site = f"{loc}:{line}" if loc and line else loc
    return DepsReproSpec(
        advisory=finding.get("cwe_id") or finding.get("type", ""),
        package="", version="",
        vuln_function=sink, call_text=sink,
        call_site=call_site, source_var=finding.get("source_var", ""),
        summary=finding.get("description", ""),
        flows=[{"location": call_site, "type": finding.get("type", ""),
                "source": finding.get("source_var", "")}],
    )
