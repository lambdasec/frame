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

from frame.sil.proof_hooks import (
    CSHARP_SPY, JAVA_NOT_REACHED, JAVA_SPY, csharp_hook_test, hook_call_site, java_hook_main, sink_of,
)


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
    """Outcome of running a reproduction driver under the spy. ``ran`` says the driver
    actually ran against the project with the spy in place (it compiled, it imported, it
    called the entry point); a fix is proved only by a run that ran and did not reach the
    sink, never by one that could not run at all."""
    reproduced: bool
    detail: str = ""
    result: Dict = field(default_factory=dict)
    ran: bool = False


# A driver that fails with one of these never reached the project's logic: the code it
# names is missing or no longer has that shape (Python exception types; JS error names
# and Node's module-resolution message).
_DID_NOT_RUN = ("ImportError", "ModuleNotFoundError", "SyntaxError", "NameError",
                "AttributeError", "TypeError", "ReferenceError", "Cannot find module")


def _driver_ran(error: str) -> bool:
    """True when a Python/JS runner's recorded error leaves the driver's run meaningful."""
    if not error:
        return True
    if not error.startswith("driver error:"):
        return False                                # the spy could not be installed
    return not any(token in error for token in _DID_NOT_RUN)


# Languages, kept here so the dispatcher and callers agree on one spelling.
_JS_LANGS = {"javascript", "js", "typescript", "ts"}
_JAVA_LANGS = {"java"}
_CSHARP_LANGS = {"csharp", "c#", "cs"}


def run_reproduction(driver_src: str, spec: "DepsReproSpec", project_root: str, *,
                     language: str = "python", **kw) -> "DepsRun":
    """Dispatch a reproduction driver to the runner for ``language`` (python, a JS/TS
    value, java, or a C# value). One entry point so the fix-loop and callers do not
    repeat the language switch. Never raises; returns the runner's ``DepsRun``."""
    lang = (language or "python").lower()
    if lang in _JS_LANGS:
        return run_deps_repro_js(driver_src, spec, project_root, **kw)
    if lang in _JAVA_LANGS:
        return run_deps_repro_java(driver_src, spec, project_root, **kw)
    if lang in _CSHARP_LANGS:
        return run_deps_repro_csharp(driver_src, spec, project_root, **kw)
    return run_deps_repro(driver_src, spec, project_root, **kw)


@dataclass
class FixProof:
    """The reproduction run before and after a fix. ``proved`` is True only when the
    SAME driver reproduced against the vulnerable code and NO LONGER reproduces against
    the fixed code -- the flow to the sink is gone, so the proof of the vulnerability
    has become a proof of the fix. A fix that leaves attacker data reaching the sink
    (a sanitize-in-place or a dependency upgrade that keeps the call) does not flip the
    reachability reproduction; that is certified by a re-scan, not by this test."""
    proved: bool
    before: "DepsRun"
    after: "DepsRun"
    detail: str = ""


def fix_proof(driver_src: str, spec: "DepsReproSpec", vulnerable_root: str,
              fixed_root: str, *, language: str = "python", **kw) -> "FixProof":
    """Run a confirmed reproduction driver against the vulnerable project and against a
    fixed copy, and report whether the reproduction FLIPPED off. This is the fix-loop
    tie-in: the generated reproduction is a regression guard, and a fix that removes the
    flow to the sink makes it stop triggering. Never raises."""
    before = run_reproduction(driver_src, spec, vulnerable_root, language=language, **kw)
    after = run_reproduction(driver_src, spec, fixed_root, language=language, **kw)
    if not before.reproduced:
        detail = f"no proof to begin with: the driver did not reproduce against the vulnerable code ({before.detail})"
    elif after.reproduced:
        detail = "the fix did NOT remove the flow: attacker data still reaches the sink via the project"
    elif not after.ran:
        detail = f"no proof of the fix: the driver could not run against the fixed code ({after.detail})"
    else:
        detail = "fix verified: the reproduction no longer reaches the sink via the project"
    return FixProof(proved=bool(before.reproduced and after.ran and not after.reproduced),
                    before=before, after=after, detail=detail)


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
    return DepsRun(ok, detail, res, ran=_driver_ran(res.get("error") or ""))


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
  } catch (e) { RESULT.error = 'driver error: ' + ((e && e.name) ? e.name + ': ' : '') + (e && e.message); }
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
    return DepsRun(ok, detail, res, ran=_driver_ran(res.get("error") or ""))


# ---------------------------------------------------------------------------------------------
# Java reproduction runner (scoped). Java is compiled with static dispatch, so there is no
# runtime monkeypatch. The portable spy is a java.lang.reflect.Proxy over the sink's INTERFACE
# (the DI-seam shape: the project takes the sink as an injected interface and the driver passes
# the proxy in its place) -- pure core-JDK reflection, no Mockito, no bytecode instrumentation
# and no Maven, so it works on ANY JDK with just `javac`/`java`. (Mockito's inline mock maker,
# which mockStatic/mockConstruction need, attaches a java agent at runtime; CI JDKs disallow
# that -- "Could not modify all classes" -- so an instrumentation-based runner is not portable.)
# A directly-called static sink (Runtime.exec, Files.*) or a concrete-class sink reached via
# `new`/a final method is not an interface and is refused here; those need a ByteBuddy java
# agent (a later brick). The same stack-based via-project oracle as the other runners. Needs a JDK.

def _java_sink_parts(spec: "DepsReproSpec") -> Optional[tuple]:
    """(fully-qualified interface, method) for a Java DI-seam sink, or None.

    The spy is a reflective Proxy, which implements an INTERFACE (conventionally an
    `I`-prefixed type, like the C# runner). A java.lang.* / javax.* bootstrap sink or a
    non-interface concrete sink is not proxyable this way and is refused -- those need the
    ByteBuddy agent brick."""
    fn = (spec.vuln_function or spec.call_text or "").replace("/", ".").strip(".")
    if "." not in fn:
        return None
    iface, _, method = fn.rpartition(".")
    simple = iface.rsplit(".", 1)[-1]
    if not iface or not method or iface.startswith("java.") or iface.startswith("javax."):
        return None
    if simple[:1] != "I":                      # DI-seam interface convention (mirrors C#)
        return None
    return iface, method


def java_repro_main(spec: "DepsReproSpec", driver: str,
                    marker: str = "PROOF_MARKER_7F3A") -> Optional[str]:
    """Generate a self-contained `Main.java` whose main() installs a reflective Proxy spy on
    the sink interface, runs the driver (which injects `spy`), and exits 0 only when the marker
    reached the sink through the project (the call-site class on the stack). Pure/offline --
    the compile+run is `run_deps_repro_java`. None for a non-interface / bootstrap sink."""
    parts = _java_sink_parts(spec)
    if parts is None:
        return None
    iface, method = parts
    callsite_class = spec.module_path.split("/")[-1].rsplit(".", 1)[0]  # Api.java -> Api
    body = "\n            ".join(driver.splitlines()) or ";"
    return (
        "import java.lang.reflect.*;\n"
        "import java.util.Arrays;\n\n"
        "public class Main {\n"
        f"    static final String MARKER = \"{marker}\";\n"
        f"    static final String CALLSITE = \"{callsite_class}\";\n"
        "    static boolean seenMarker = false, seenVia = false;\n"
        "    static void record(Object arg) {\n"
        "        if (arg != null && String.valueOf(arg).contains(MARKER)) {\n"
        "            seenMarker = true;\n"
        "            seenVia = Arrays.stream(Thread.currentThread().getStackTrace())\n"
        "                .anyMatch(f -> f.getClassName().contains(CALLSITE)\n"
        "                            && !f.getClassName().startsWith(\"Main\"));\n"
        "        }\n"
        "    }\n"
        "    static Object defaultReturn(Class<?> t) {\n"
        "        if (t == boolean.class) return false;\n"
        "        if (t == char.class) return '\\0';\n"
        "        if (t == byte.class) return (byte) 0;\n"
        "        if (t == short.class) return (short) 0;\n"
        "        if (t == int.class) return 0;\n"
        "        if (t == long.class) return 0L;\n"
        "        if (t == float.class) return 0f;\n"
        "        if (t == double.class) return 0d;\n"
        "        return null;\n"
        "    }\n"
        "    @SuppressWarnings(\"unchecked\")\n"
        "    public static void main(String[] args) {\n"
        f"        {iface} spy = ({iface}) Proxy.newProxyInstance(\n"
        f"            {iface}.class.getClassLoader(), new Class<?>[]{{{iface}.class}},\n"
        "            (proxy, method, margs) -> {\n"
        f"                if (method.getName().equals(\"{method}\") && margs != null)\n"
        "                    for (Object a : margs) record(a);\n"
        "                return defaultReturn(method.getReturnType());\n"
        "            });\n"
        f"        try {{ {body} }} catch (Throwable _t) {{ /* the sink is spied; faults are irrelevant */ }}\n"
        f"        System.exit(seenMarker && seenVia ? 0 : {JAVA_NOT_REACHED});\n"
        "    }\n"
        "}\n"
    )


def _callsite_class(spec: "DepsReproSpec") -> str:
    """The class the call site's file declares, by the file's name (Api.java -> Api)."""
    return Path(spec.module_path).name.rsplit(".", 1)[0]


def _hooked_call_site(spec: "DepsReproSpec", project_root: str, language: str):
    """The call-site file with the sink call's arguments hooked (`proof_hooks`), or a
    DepsRun saying why the sink cannot be spied this way."""
    sink = sink_of(spec.vuln_function or spec.call_text)
    if sink is None:
        return DepsRun(False, f"no spy for this sink: {spec.vuln_function or spec.call_text!r} "
                              "names no type and method")
    path = Path(project_root) / spec.module_path
    if not spec.module_path or not path.is_file():
        return DepsRun(False, f"the call-site file {spec.module_path!r} is not in the project")
    try:
        line = int(spec.call_site.rpartition(":")[2])
    except ValueError:
        line = 0
    hooked = hook_call_site(path.read_text(errors="replace"), language, line, sink)
    if hooked is None:
        what = f"new {sink.type_name}" if not sink.method else sink.method
        return DepsRun(False, f"the call-site file has no call to {what}: the flow to the sink is gone",
                       {"hook": {"calls": 0}}, ran=True)
    return hooked


def _hook_note(hook) -> Dict:
    return {"calls": hook.calls, "on_line": hook.on_line}


def run_deps_repro_java(driver_src: str, spec: "DepsReproSpec", project_root: str, *,
                        marker: str = "PROOF_MARKER_7F3A", mvn: Optional[str] = None,
                        jdk: Optional[str] = None, timeout: int = 180) -> DepsRun:
    """Compile the project's Java sources plus a generated `Main.java` with `javac` and run it
    with `java`, so the marker is driven through the project to the sink interface's proxy spy.
    Needs only a JDK (`jdk` = JAVA_HOME, else PATH `javac`/`java`); no Maven, no Mockito. The
    `mvn` argument is accepted for call-compatibility and ignored. Never raises; returns a
    skipped/unsupported DepsRun when the toolchain or the sink family is missing."""
    import os
    import shutil as _shutil
    main_src = java_repro_main(spec, driver_src, marker)
    hook = None
    if main_src is None:
        hook = _hooked_call_site(spec, project_root, "java")
        if isinstance(hook, DepsRun):
            return hook
        main_src = java_hook_main(driver_src, _callsite_class(spec), marker)
    java_home = jdk or os.environ.get("JAVA_HOME")

    def _bin(name: str) -> Optional[str]:
        if java_home:
            cand = Path(java_home) / "bin" / name
            if cand.exists():
                return str(cand)
        return _shutil.which(name)

    javac, java = _bin("javac"), _bin("java")
    if not javac or not java:
        return DepsRun(False, "a JDK (javac/java) is not available")
    src = Path(project_root)
    with tempfile.TemporaryDirectory() as d:
        proj = Path(d)
        for jf in src.rglob("*.java"):
            dest = proj / jf.relative_to(src)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(jf.read_text(errors="replace"))
        (proj / "Main.java").write_text(main_src)
        if hook is not None:
            (proj / spec.module_path).write_text(hook.source)
            (proj / "frameproof").mkdir(exist_ok=True)
            (proj / "frameproof" / "Spy.java").write_text(JAVA_SPY)
        out = proj / "out"
        out.mkdir()
        sources = [str(p) for p in proj.rglob("*.java")]
        try:
            c = subprocess.run([javac, "-d", str(out), *sources], cwd=str(proj),
                               capture_output=True, text=True, errors="replace", timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return DepsRun(False, f"compile error: {exc}")
        if c.returncode != 0:
            err = c.stderr or ""
            if "Unable to locate a Java Runtime" in err or "No Java runtime" in err:
                return DepsRun(False, "a JDK (javac/java) is not available", {"stderr": err[-1500:]})
            return DepsRun(False, "the project did not compile standalone", {"stderr": err[-1500:]})
        try:
            r = subprocess.run([java, "-cp", str(out), "Main"], cwd=str(proj),
                               capture_output=True, text=True, errors="replace", timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return DepsRun(False, f"run error: {exc}")
        out_txt = ((r.stdout or "") + (r.stderr or ""))[-1500:]
        result = {"stdout": out_txt}
        if hook is not None:
            result["hook"] = _hook_note(hook)
        if r.returncode == 0:
            return DepsRun(True, "marker reached the sink via the project", result, ran=True)
        if r.returncode == JAVA_NOT_REACHED:
            return DepsRun(False, "the marker did not reach the sink via the project", result, ran=True)
        return DepsRun(False, f"the driver did not run (exit {r.returncode})", result)


# ---------------------------------------------------------------------------------------------
# C# reproduction runner (scoped). Like Java, C# is compiled with static dispatch; the portable
# spy is Moq over the sink's INTERFACE (the DI-seam shape: the project takes the sink as an
# injected interface). Moq mocks an interface with a dynamic proxy -- no bootstrap/IL rewriting,
# so it is portable across .NET runtimes. A directly-called static sink (Process.Start) or a
# sealed class would need a Pose/Harmony shim (a later brick). Needs the .NET SDK.

def _csharp_sink_parts(spec: "DepsReproSpec") -> Optional[tuple]:
    """(interface, method) for a C# DI-seam sink, or None. Scoped to an interface sink
    (conventionally an `I`-prefixed type) that the project has injected."""
    fn = (spec.vuln_function or spec.call_text or "").replace("/", ".").strip(".")
    if "." not in fn:
        return None
    iface, _, method = fn.rpartition(".")      # keep the namespace on the interface
    simple = iface.rsplit(".", 1)[-1]
    if not iface or not method or simple[:1] != "I":
        return None
    return iface, method


def csharp_repro_test(spec: "DepsReproSpec", driver: str,
                      marker: str = "PROOF_MARKER_7F3A") -> Optional[str]:
    """Generate an xUnit + Moq test that mocks the sink interface, runs the driver (which
    injects `mock.Object` into the project entry), and asserts the marker reached the sink
    through the project (the call-site class on the stack). None for a non-interface sink."""
    parts = _csharp_sink_parts(spec)
    if parts is None:
        return None
    iface, method = parts
    callsite = spec.module_path.split("/")[-1].rsplit(".", 1)[0]   # Api.cs -> Api
    body = "\n            ".join(driver.splitlines()) or ";"
    return (
        "using System;\nusing System.Linq;\nusing System.Diagnostics;\n"
        "using Xunit;\nusing Moq;\n\n"
        "public class ReproTest {\n"
        f"    const string MARKER = \"{marker}\";\n"
        f"    const string CALLSITE = \"{callsite}\";\n"
        "    static bool marker, via;\n"
        "    static void Record(object a) {\n"
        "        if (a != null && a.ToString().Contains(MARKER)) {\n"
        "            marker = true;\n"
        "            via = new StackTrace().GetFrames()\n"
        "                .Any(f => (f.GetMethod()?.DeclaringType?.Name ?? \"\") == CALLSITE);\n"
        "        }\n"
        "    }\n"
        "    [Fact] public void Reproduces() {\n"
        "        marker = false; via = false;\n"
        f"        var mock = new Mock<{iface}>();\n"
        f"        mock.Setup(x => x.{method}(It.IsAny<string>())).Callback<string>(Record);\n"
        f"        {body}\n"
        "        Assert.True(marker && via, \"the marker must reach the sink through the project\");\n"
        "    }\n"
        "}\n"
    )


_CSHARP_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework><Nullable>disable</Nullable>
    <IsPackable>false</IsPackable></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.9.0" />
    <PackageReference Include="xunit" Version="2.7.0" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.5.7" />
    <PackageReference Include="Moq" Version="4.20.70" />
  </ItemGroup>
</Project>
"""


def run_deps_repro_csharp(driver_src: str, spec: "DepsReproSpec", project_root: str, *,
                          marker: str = "PROOF_MARKER_7F3A", dotnet: Optional[str] = None,
                          timeout: int = 420) -> DepsRun:
    """Compile the project's C# sources plus a generated xUnit+Moq test and run `dotnet test`,
    driving the marker through the project to the mocked sink interface. Needs the .NET SDK.
    Never raises; returns an unsupported/skipped DepsRun when the sink or toolchain is missing."""
    import os
    import shutil as _shutil
    test_src = csharp_repro_test(spec, driver_src, marker)
    hook = None
    if test_src is None:
        hook = _hooked_call_site(spec, project_root, "csharp")
        if isinstance(hook, DepsRun):
            return hook
        test_src = csharp_hook_test(driver_src, _callsite_class(spec), marker)
    dn = dotnet or _shutil.which("dotnet")
    if not dn:
        return DepsRun(False, "the .NET SDK is not available")
    src = Path(project_root)
    with tempfile.TemporaryDirectory() as d:
        proj = Path(d)
        for cs in src.rglob("*.cs"):
            (proj / cs.name).write_text(cs.read_text(errors="replace"))
        (proj / "ReproTest.cs").write_text(test_src)
        if hook is not None:
            (proj / Path(spec.module_path).name).write_text(hook.source)
            (proj / "FrameProofSpy.cs").write_text(CSHARP_SPY)
        (proj / "repro.csproj").write_text(_CSHARP_CSPROJ)
        env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1",
                   DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1", DOTNET_NOLOGO="1")
        try:
            r = subprocess.run([dn, "test", "-v", "q", "--nologo"], cwd=str(proj),
                               capture_output=True, text=True, errors="replace",
                               timeout=timeout, env=env)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return DepsRun(False, f"run error: {exc}")
        out = (r.stdout or "") + (r.stderr or "")
        result = {"stdout": out[-1500:]}
        if hook is not None:
            result["hook"] = _hook_note(hook)
        if r.returncode == 0:
            return DepsRun(True, "marker reached the sink via the project", result, ran=True)
        if re.search(r"error (CS|MSB|NU)\d+", out):
            return DepsRun(False, "the project did not compile standalone", result)
        if re.search(r"Failed!\s*-\s*Failed:\s*1\b", out):      # the test ran, its assertion failed
            return DepsRun(False, "the marker did not reach the sink via the project", result, ran=True)
        return DepsRun(False, "the test did not run", result)
