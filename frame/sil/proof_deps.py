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
import re
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
    _orig = getattr(_parent, _leaf, None)
    def _spy(*a, **k):
        # Pass-through: record only the marker-carrying call, and delegate every
        # other call to the original -- so a sink the harness itself uses (open for
        # the result file, the import machinery) keeps working.
        vals = [str(x) for x in a] + [str(v) for v in k.values()]
        if any(MARKER in s for s in vals):
            RESULT["seen"] = True
            RESULT["marker_in_args"] = True
            frames = traceback.extract_stack()[:-1]
            RESULT["via_callsite"] = any(str(f.filename).endswith(_CALLSITE) for f in frames)
            return None
        return _orig(*a, **k) if callable(_orig) else None
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


# ---------------------------------------------------------------------------------------------
# JavaScript/TypeScript reproduction runner (Node). Same soundness model as the Python runner:
# the harness patches the sink before the project requires it, runs the agent's driver, and
# confirms the marker reached the sink from the flagged call-site file. Module-function and
# module-level sinks (child_process.exec, a package export) are covered; a prototype method is
# a refinement. Needs `node` on PATH (or passed in).

_JS_RUNNER = r'''
const fs = require('fs');
const path = require('path');
const { createRequire } = require('module');
const projectRequire = createRequire(path.join(@@ROOT@@, 'noop.js'));
const MARKER = @@MARKER@@;
const CALLSITE = @@CALLSITE@@;
const DOTTED = @@DOTTED@@;
const RESULT = { seen: false, marker_in_args: false, via_callsite: false, error: "" };

function resolveParent(dotted) {
  const parts = dotted.split('.');
  let mod = null, i = parts.length;
  for (; i > 0; i--) {
    try { mod = projectRequire(parts.slice(0, i).join('.')); break; } catch (e) { mod = null; }
  }
  if (mod === null) { try { mod = projectRequire(parts[0]); i = 1; } catch (e) { throw new Error('no requirable module in ' + dotted); } }
  let obj = mod;
  for (let k = i; k < parts.length - 1; k++) obj = obj[parts[k]];
  return [obj, parts[parts.length - 1]];
}

try {
  const [parent, leaf] = resolveParent(DOTTED);
  const orig = parent[leaf];
  parent[leaf] = function (...args) {
    // Pass-through: record only the marker-carrying call; delegate everything else
    // to the original, so a sink node itself uses (fs for require) keeps working.
    const hit = args.some(a => { try { return String(a).includes(MARKER); } catch (e) { return false; } });
    if (hit) {
      RESULT.seen = true;
      RESULT.marker_in_args = true;
      const stack = (new Error().stack || '').split('\n');
      RESULT.via_callsite = stack.some(l => l.includes(CALLSITE));
      return undefined;
    }
    return typeof orig === 'function' ? orig.apply(this, args) : undefined;
  };
} catch (e) { RESULT.error = 'patch failed: ' + e.message; }

if (!RESULT.error) {
  try {
    (function (require) {
@@DRIVER@@
    })(projectRequire);
  } catch (e) { RESULT.error = 'driver error: ' + e.message; }
}
fs.writeFileSync(@@RESULT@@, JSON.stringify(RESULT));
'''


def run_deps_repro_js(driver_src: str, spec: "DepsReproSpec", project_root: str, *,
                      marker: str = "PROOF_MARKER_7F3A", node: Optional[str] = None,
                      timeout: int = 30) -> DepsRun:
    """Node counterpart of `run_deps_repro`. The driver gets a `require` resolving from the
    project root; it drives the project so MARKER reaches the sink, and the harness spy
    confirms the marker arrived from the flagged call-site file. Never raises."""
    import json as _json
    import shutil as _shutil
    dotted = (spec.vuln_function or spec.call_text).replace("/", ".").strip(".")
    if not dotted:
        return DepsRun(False, "could not resolve the sink")
    node_bin = node or _shutil.which("node")
    if not node_bin:
        return DepsRun(False, "node is not available")
    callsite_file = spec.module_path.split(":")[0]
    indented = "\n".join("      " + ln for ln in driver_src.splitlines()) or "      ;"
    with tempfile.TemporaryDirectory() as d:
        result_path = str(Path(d) / "result.json")
        runner = (_JS_RUNNER
                  .replace("@@ROOT@@", _json.dumps(str(project_root)))
                  .replace("@@MARKER@@", _json.dumps(marker))
                  .replace("@@CALLSITE@@", _json.dumps(callsite_file))
                  .replace("@@DOTTED@@", _json.dumps(dotted))
                  .replace("@@RESULT@@", _json.dumps(result_path))
                  .replace("@@DRIVER@@", indented))
        runner_path = Path(d) / "_frame_repro_runner.js"
        runner_path.write_text(runner)
        try:
            subprocess.run([node_bin, str(runner_path)], capture_output=True, text=True,
                           errors="replace", timeout=timeout, cwd=d)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return DepsRun(False, f"run error: {exc}")
        try:
            res = _json.loads(Path(result_path).read_text())
        except (OSError, ValueError):
            return DepsRun(False, "driver produced no result")
    ok = bool(res.get("seen") and res.get("marker_in_args") and res.get("via_callsite")
              and not res.get("error"))
    detail = ("marker reached the sink via the project" if ok
              else res.get("error") or "the marker did not reach the sink via the project")
    return DepsRun(ok, detail, res)


# ---------------------------------------------------------------------------------------------
# Java reproduction runner (scoped). Java is compiled with static dispatch, so there is no
# runtime monkeypatch; the spy is Mockito. This covers the mockable sink families -- today the
# command-injection family (Runtime.getRuntime().exec) -- via a generated JUnit+Mockito test
# with the same stack-based via-project oracle as the other runners. Arbitrary-reachability
# sinks need a ByteBuddy java agent (a later brick). Needs a JDK + Maven; validated on a host
# that has them, so its exemplar test is gated on the toolchain.

# sink canonical id -> (mocked class, how to stub it so a call records). Keyed by a substring
# of the sink so java.lang.Runtime.exec and Runtime.exec both match.
_JAVA_SINK_TEMPLATES = {
    "Runtime.exec": {
        "mocked": "Runtime",
        "stub": ("        Runtime _rt = mock(Runtime.class);\n"
                 "        try (MockedStatic<Runtime> _st = mockStatic(Runtime.class)) {\n"
                 "            _st.when(Runtime::getRuntime).thenReturn(_rt);\n"
                 "            when(_rt.exec(anyString())).thenAnswer(_i -> record(_i.getArgument(0)));\n"
                 "            __DRIVER__\n"
                 "        }\n"),
    },
}


def _java_sink_template(spec: "DepsReproSpec") -> Optional[dict]:
    fn = (spec.vuln_function or spec.call_text or "").replace("/", ".")
    for key, tmpl in _JAVA_SINK_TEMPLATES.items():
        if fn.endswith(key) or key in fn:
            return tmpl
    return None


def java_repro_test(spec: "DepsReproSpec", driver: str,
                    marker: str = "PROOF_MARKER_7F3A") -> Optional[str]:
    """Generate a JUnit 5 + Mockito test that mocks the sink, runs the driver, and asserts
    the marker reached the sink through the project (a project class, not the test, on the
    stack). Pure/offline -- the compile+run is `run_deps_repro_java`. None for an unsupported
    Java sink family."""
    tmpl = _java_sink_template(spec)
    if tmpl is None:
        return None
    callsite_class = spec.module_path.split("/")[-1].rsplit(".", 1)[0]  # ShellService.java -> ShellService
    body = tmpl["stub"].replace("__DRIVER__", "\n            ".join(driver.splitlines()) or "            ;")
    return (
        "import static org.junit.jupiter.api.Assertions.*;\n"
        "import static org.mockito.Mockito.*;\n"
        "import org.junit.jupiter.api.Test;\n"
        "import org.mockito.MockedStatic;\n"
        "import java.util.Arrays;\n\n"
        "public class ReproTest {\n"
        f"    static final String MARKER = \"{marker}\";\n"
        f"    static final String CALLSITE = \"{callsite_class}\";\n"
        "    static final boolean[] seen = {false, false};\n"
        "    static Object record(Object arg) {\n"
        "        String a = String.valueOf(arg);\n"
        "        if (a.contains(MARKER)) {\n"
        "            seen[0] = true;\n"
        "            seen[1] = Arrays.stream(Thread.currentThread().getStackTrace())\n"
        "                .anyMatch(f -> f.getClassName().contains(CALLSITE)\n"
        "                            && !f.getClassName().equals(\"ReproTest\"));\n"
        "        }\n"
        "        return null;\n"
        "    }\n"
        "    @Test public void reproduces() throws Exception {\n"
        f"{body}"
        "        assertTrue(seen[0] && seen[1],\n"
        "            \"the marker must reach the sink through the project\");\n"
        "    }\n"
        "}\n"
    )


def run_deps_repro_java(driver_src: str, spec: "DepsReproSpec", project_root: str, *,
                        marker: str = "PROOF_MARKER_7F3A", mvn: Optional[str] = None,
                        jdk: Optional[str] = None, timeout: int = 300) -> DepsRun:
    """Compile the project's Java sources plus a generated Mockito test and run it, so the
    marker is driven through the project to the sink. Needs Maven (`mvn`) and a JDK (`jdk` =
    JAVA_HOME). Never raises; returns a skipped/unsupported DepsRun when the toolchain or the
    sink family is missing."""
    import os
    import shutil as _shutil
    test_src = java_repro_test(spec, driver_src, marker)
    if test_src is None:
        return DepsRun(False, "no Mockito template for this Java sink family yet")
    mvn_bin = mvn or _shutil.which("mvn")
    if not mvn_bin:
        return DepsRun(False, "maven is not available")
    java_home = jdk or os.environ.get("JAVA_HOME")
    src = Path(project_root)
    with tempfile.TemporaryDirectory() as d:
        proj = Path(d)
        main = proj / "src" / "main" / "java"
        test = proj / "src" / "test" / "java"
        main.mkdir(parents=True)
        test.mkdir(parents=True)
        for jf in src.rglob("*.java"):
            text = jf.read_text(errors="replace")
            m = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.M)
            pkgdir = main.joinpath(*m.group(1).split(".")) if m else main
            pkgdir.mkdir(parents=True, exist_ok=True)
            (pkgdir / jf.name).write_text(text)
        (test / "ReproTest.java").write_text(test_src)
        (proj / "pom.xml").write_text(_JAVA_POM)
        env = dict(os.environ)
        if java_home:
            env["JAVA_HOME"] = java_home
        try:
            r = subprocess.run([mvn_bin, "-q", "-B", "test"], cwd=str(proj),
                               capture_output=True, text=True, errors="replace",
                               timeout=timeout, env=env)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return DepsRun(False, f"run error: {exc}")
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0:
            return DepsRun(True, "marker reached the sink via the project",
                           {"stdout": out[-1500:]})
        if "BUILD FAILURE" in out and "ReproTest" not in out and "COMPILATION" in out:
            return DepsRun(False, "the project did not compile standalone", {"stdout": out[-1500:]})
        return DepsRun(False, "the marker did not reach the sink via the project",
                       {"stdout": out[-1500:]})


_JAVA_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>frame.repro</groupId><artifactId>repro</artifactId><version>1.0</version>
  <properties><maven.compiler.release>17</maven.compiler.release></properties>
  <dependencies>
    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>5.10.2</version><scope>test</scope></dependency>
    <dependency><groupId>org.mockito</groupId><artifactId>mockito-core</artifactId><version>5.11.0</version><scope>test</scope></dependency>
  </dependencies>
  <build><plugins>
    <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-surefire-plugin</artifactId><version>3.2.5</version></plugin>
  </plugins></build>
</project>
"""
