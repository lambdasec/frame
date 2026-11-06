"""Proof-carrying dependency findings (Phase 5c brick 2): drive the project to the sink.

Given a tainted SCA finding (`frame.sil.proof_deps.DepsReproSpec`) and the project,
a seeded agent writes a DRIVER -- code that imports the project's entry point and
calls it so a marker string flows to the vulnerable library function. The harness
(`proof_deps.run_deps_repro`) owns the spy and the judgment, so the agent cannot
forge success: a reproduction counts only when the marker reaches the vulnerable
function through the flagged project code.

Defensive QA, not offence: the artifact is a reachability test a developer keeps.
Oracle-terminating on a real spy hit, never the model's claim. Local sandbox, no
network target. Adds no configuration -- the endpoint comes from the [llm] settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from frame.sil.llm_agent import run_agent
from frame.sil.proof_deps import (
    DepsReproSpec, run_deps_repro, run_deps_repro_js, run_deps_repro_java,
)

_PY_LANGS = {"python", "py"}
_JS_LANGS = {"javascript", "js", "typescript", "ts"}
_JAVA_LANGS = {"java"}


def _lang_note(language: str) -> str:
    if language in _JS_LANGS:
        return ("Write the driver in JavaScript. `require` is already provided and resolves from "
                "the project root, so `const { handler } = require('./routes'); handler(MARKER);`. "
                "MARKER is already defined.")
    if language in _JAVA_LANGS:
        return ("Write the driver as Java statements that call the entry point, e.g. "
                "`new app.Api().ping(MARKER);`. MARKER is a String already in scope.")
    return ("Write the driver in Python. MARKER is already defined, e.g. "
            "`from routes import handler; handler(MARKER)`.")


REPRODUCE_SYSTEM = (
    "You are writing a REACHABILITY TEST for your own project: static analysis found that "
    "attacker-controlled data reaches a vulnerable function (a dependency call or an injection "
    "sink), and you want a runnable test that proves it, so the risk is concrete and a fix can be "
    "verified. Ordinary QA.\n\n"
    "You are given the vulnerable function, the file and line where your project calls it, and "
    "the tainted variable. Explore the project with `read_file` and `grep` to find the entry "
    "point (the handler/function a caller invokes) that leads to that call. Then write a DRIVER "
    "that calls that entry point so the already-defined variable MARKER flows to the vulnerable "
    "call, and submit it with `try_driver`.\n\n"
    "The harness installs a spy on the vulnerable function and tells you whether MARKER actually "
    "reached it THROUGH your project's code. Calling the vulnerable function directly does not "
    "count -- the data must flow through the project. Iterate on the harness feedback until it "
    "reports the marker reached the function via the project."
)

_TOOLS = [
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a project file by path relative to the project root.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}},
                       "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "grep",
        "description": "Regex-search the project's Python files; returns up to 40 'path:line: text'.",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}},
                       "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "try_driver",
        "description": ("Run your driver with a spy on the vulnerable function. MARKER is already "
                        "defined. Returns whether MARKER reached the vulnerable function via the "
                        "project. Reachability through the project is success."),
        "parameters": {"type": "object", "properties": {"driver": {"type": "string"}},
                       "required": ["driver"]}}},
]

_STALL = ("Do not stop. Find the entry point with read_file/grep, then call try_driver with a "
          "driver that imports it and passes MARKER through to the vulnerable call.")


@dataclass
class DepsReproduceResult:
    reproduced: bool
    driver: str = ""
    detail: str = ""
    steps: int = 0
    transcript: List[Dict[str, Any]] = field(default_factory=list)


def _seed(spec: DepsReproSpec, language: str) -> str:
    pkg = f" in {spec.package}=={spec.version}" if spec.package else ""
    return (f"Finding {spec.advisory}{pkg}.\n"
            f"Vulnerable function: {spec.vuln_function} (called as {spec.call_text!r})\n"
            f"Your project reaches it at: {spec.call_site}\n"
            f"Tainted variable at that call: {spec.source_var!r}\n\n"
            f"{_lang_note(language)}\n"
            "Find the entry point that leads to that call and write a driver that passes MARKER "
            "through it to the vulnerable function. Submit with try_driver.")


def _read_tool(root: Path):
    def _read(path: str) -> str:
        try:
            p = (root / path).resolve()
            if not str(p).startswith(str(root.resolve())) or not p.is_file():
                return f"error: {path} is not a readable project file"
            return p.read_text(errors="replace")[:8000]
        except OSError as exc:
            return f"error: {exc}"
    return _read


_GREP_GLOBS = {"python": ("*.py",), "javascript": ("*.js", "*.ts", "*.jsx", "*.tsx"),
               "java": ("*.java",)}


def _grep_tool(root: Path, language: str = "python"):
    import re
    globs = (_GREP_GLOBS["javascript"] if language in _JS_LANGS
             else _GREP_GLOBS["java"] if language in _JAVA_LANGS
             else _GREP_GLOBS["python"])

    def _grep(pattern: str) -> str:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return f"error: bad pattern: {exc}"
        hits: List[str] = []
        paths = sorted(p for g in globs for p in root.rglob(g))
        for p in paths:
            try:
                for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{p.relative_to(root)}:{i}: {line.strip()[:200]}")
                        if len(hits) >= 40:
                            return "\n".join(hits)
            except OSError:
                continue
        return "\n".join(hits) or "(no matches)"
    return _grep


def reproduce_deps_finding(spec: DepsReproSpec, project_root: str, config: Any,
                           client: Any = None, *,
                           language: str = "python",
                           max_steps: int = 8,
                           python: Optional[str] = None,
                           node: Optional[str] = None,
                           mvn: Optional[str] = None,
                           jdk: Optional[str] = None,
                           timeout: int = 30) -> DepsReproduceResult:
    """Drive a seeded agent to write a driver that reaches the vulnerable function.

    ``language`` picks the runner and the driver dialect (``python``, a JS/TS value, or
    ``java``). ``reproduced`` is True only when the harness spy confirms the marker
    reached the vulnerable function through the project's code -- never the model's claim.
    """
    try:
        from frame.sil.llm_client import LLMClient
    except ImportError:
        return DepsReproduceResult(False, detail="LLM client unavailable")
    if client is None:
        client = LLMClient(config)
    language = (language or "python").lower()
    is_js = language in _JS_LANGS
    is_java = language in _JAVA_LANGS
    root = Path(project_root)
    state: Dict[str, Any] = {"driver": "", "detail": ""}
    read_fn, grep_fn = _read_tool(root), _grep_tool(root, language)

    def _run(driver: str):
        if is_js:
            return run_deps_repro_js(driver, spec, str(root), node=node, timeout=timeout)
        if is_java:
            return run_deps_repro_java(driver, spec, str(root), mvn=mvn, jdk=jdk,
                                       timeout=max(timeout, 300))
        return run_deps_repro(driver, spec, str(root), python=python, timeout=timeout)

    def _exec(name: str, args: Dict[str, Any]) -> str:
        if name == "read_file":
            return read_fn(args.get("path", ""))
        if name == "grep":
            return grep_fn(args.get("pattern", ""))
        if name == "try_driver":
            driver = args.get("driver", "")
            if not driver.strip():
                return "error: empty driver"
            run = _run(driver)
            if run.reproduced:
                state["driver"] = driver
                state["detail"] = run.detail
                return "SUCCESS: " + run.detail
            return "not yet: " + run.detail + " (the marker must reach the function via the project)"
        return f"error: unknown tool {name!r}"

    def _done():
        return True if state["driver"] else None

    messages = [
        {"role": "system", "content": REPRODUCE_SYSTEM},
        {"role": "user", "content": _seed(spec, language)},
    ]
    res = run_agent(messages, client, tools=_TOOLS, exec_tool=_exec,
                    max_steps=max_steps, check_done=_done, stall_nudge=_STALL,
                    dedupe_tools={"read_file", "grep"})
    return DepsReproduceResult(
        reproduced=bool(state["driver"]),
        driver=state["driver"],
        detail=state["detail"] or "not reproduced",
        steps=res.steps,
        transcript=res.transcript,
    )
