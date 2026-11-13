"""The engine as a query service (`frame query`): the facts the authorization hunt's agents
ask for (handlers, callers/callees, data flows, the guards on a line, a claim the solver
decides), answered over a project the engine has translated once.

`QueryIndex` scans a directory symbolically (no model), keeps every file's translated
program, and answers each tool through `hunt_tools.HuntContext`, the same code the hunt's
agents call, so an agent outside Frame sees exactly what the hunt sees. Every answer comes in
one envelope: the tool's result, the evidence it rests on, how names were resolved, what the
answer cannot see, the index it was computed over, and how long the query took.

The index is rebuilt when a file it covers changes, appears or disappears (size and mtime per
file), so a long-lived process (`frame query --serve`, held by frame-mcp) answers from memory
until the code changes. Nothing here changes a finding.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# What each tool says about itself: the evidence its facts rest on, how a name becomes a
# function, and what it cannot see. Stated once, here, so every answer carries them.
TOOLS: Dict[str, Dict[str, Any]] = {
    "handlers": {
        "args": [],
        "evidence": "entry points from framework packs and registrations (no model)",
        "resolution": "a handler is what an applied pack's entry point or a registration marks",
        "limits": ["routes served by a convention no pack describes are missing (teach a pack)",
                   "`protected` means an authorization gate or the caller's identity was seen, "
                   "not that the check is correct"],
    },
    "handler_facts": {
        "args": ["name", "file?"],
        "evidence": "engine facts for one entry point or function: gate, resource reach, sinks, "
                    "the engine's own findings in its range",
        "resolution": "exact name, else simple name; `file` picks among same-named functions",
        "limits": ["a function that is not an entry point has no protection facts"],
    },
    "siblings": {
        "args": ["name", "file?"],
        "evidence": "the handlers of the same class / file, each with its gate and the guards "
                    "that hold at its data accesses (path facts)",
        "resolution": "grouped by file and enclosing class",
        "limits": ["handlers of the same resource in other files are not siblings here"],
    },
    "trace": {
        "args": ["name", "file?"],
        "evidence": "the engine's data-flow findings inside the function, each with its own "
                    "evidence level (solver-verified, data-flow, matched)",
        "resolution": "findings whose line falls in the function's range",
        "limits": ["only flows the scan reported; a flow into a sink kind Frame does not model "
                   "is not traced",
                   "a flow is listed where its sink is: for a handler that hands the data to a "
                   "helper, trace the helper (callees names it; its data_flow names the call)"],
    },
    "callers": {
        "args": ["name"],
        "evidence": "call instructions of the translated programs",
        "resolution": "matched by simple name across the project (not by type)",
        "limits": ["a call through a value, a callback or reflection is not seen",
                   "same-named functions in different classes are not told apart"],
    },
    "callees": {
        "args": ["name", "file?"],
        "evidence": "call instructions of the translated program",
        "resolution": "each callee's definitions found by simple name; several = ambiguous",
        "limits": ["library calls have no definition in the project"],
    },
    "guards": {
        "args": ["name", "line?", "file?"],
        "evidence": "conditions that hold on every feasible path to the line (branch guards, "
                    "gate decorators, identity scoping), recorded by the engine's path walk",
        "resolution": "without `line`: the function's data-access lines",
        "limits": ["a condition is reported as written; whether it is the right check is for "
                   "the reader to decide"],
    },
    "check": {
        "args": ["name", "line", "kind", "pattern?", "file?"],
        "evidence": "decided over the engine's feasible paths: `proved` holds on every path, "
                    "`refuted` comes with a witness path, `unknown` when the engine has no facts",
        "resolution": "kind guarded_by (pattern: regex or substring of a condition or gate) or "
                      "scoped_by_identity",
        "limits": ["matching is by condition text; read the polarity in the reason"],
    },
}


def _stamp(path: str) -> Optional[Tuple[int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _line_text(root: str, file: str, line: int) -> str:
    if not file or not line:
        return ""
    try:
        with open(os.path.join(root, file), encoding="utf-8", errors="replace") as fh:
            for i, text in enumerate(fh, 1):
                if i == line:
                    return text.strip()[:240]
    except OSError:
        pass
    return ""


class QueryIndex:
    """A project translated once, answering engine queries until its files change."""

    def __init__(self, root: str, language: Optional[str] = None,
                 packs: Optional[List[str]] = None, verify: bool = True,
                 project_root: Optional[str] = None):
        self.root = str(Path(root).resolve())
        self.project_root = project_root     # `--root`: the root imports resolve under
        self.language = language
        self.packs = list(packs or [])
        self.verify = verify
        self.ctx = None
        self.stamps: Dict[str, Optional[Tuple[int, int]]] = {}
        self.build_ms = 0.0
        self.builds = 0
        self.complete = True
        self.files = 0

    # -- building -------------------------------------------------------------------------
    def _watch(self) -> Dict[str, Optional[Tuple[int, int]]]:
        """Size and mtime of every source file the build reads (the project root's, which a
        subdirectory scan reads as context) and the mtime of every directory walked, so an
        added or removed file shows as a changed directory without walking the tree again."""
        from frame.sil.fingerprints import project_root
        from frame.sil.scanner import (DEFAULT_EXCLUDED_SCAN_DIRS, EXTENSION_LANGUAGES,
                                       FrameScanner)
        base = Path(project_root(Path(self.root), self.project_root)).resolve()
        exts = {e.lower() for e in EXTENSION_LANGUAGES}
        out: Dict[str, Optional[Tuple[int, int]]] = {}
        for dirpath, dirnames, filenames in os.walk(base):
            here = Path(dirpath)
            dirnames[:] = [d for d in dirnames if not FrameScanner._is_excluded_dir_member(
                here / d / "_", base, DEFAULT_EXCLUDED_SCAN_DIRS)]
            out[dirpath + os.sep] = _stamp(dirpath)
            for f in filenames:
                if os.path.splitext(f)[1].lower() in exts:
                    full = os.path.join(dirpath, f)
                    out[full] = _stamp(full)
        return out

    def build(self) -> None:
        from frame.sil.hunt_tools import HuntContext
        from frame.sil.llm_hunt import build_index
        from frame.sil.scanner import FrameScanner, language_extensions
        t0 = time.perf_counter()
        stamps = self._watch()          # before scanning: an edit during the build is seen next time
        sc = FrameScanner(language=self.language, verify=self.verify, packs=self.packs or None)
        sc.collect_programs = True
        results = sc.scan_directory(self.root, None, extensions=language_extensions(self.language),
                                    project_root=self.project_root)
        programs = list(sc._hunt_programs)
        findings = [v for r in results for v in r.vulnerabilities]
        index = build_index(programs, findings, self.root)
        self.ctx = HuntContext(index, programs, self.root, self.language or "", findings)
        self.stamps = stamps
        self.files = len(results)
        scope = getattr(sc, "last_project_scope", None)
        self.complete = bool(scope.get("complete", True)) if isinstance(scope, dict) else True
        self.build_ms = (time.perf_counter() - t0) * 1000.0
        self.builds += 1

    def stale(self) -> bool:
        if self.ctx is None:
            return True
        return any(_stamp(p.rstrip(os.sep) or os.sep) != s for p, s in self.stamps.items())

    # -- answering ------------------------------------------------------------------------
    def query(self, tool: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        args = dict(args or {})
        if tool not in TOOLS:
            return {"tool": tool, "error": f"unknown tool {tool!r}", "tools": sorted(TOOLS)}
        t0 = time.perf_counter()
        rebuilt = False
        if self.stale():
            self.build()
            rebuilt = True
        t1 = time.perf_counter()
        try:
            result = self._run(tool, args)
        except (TypeError, ValueError) as exc:
            result = {"error": f"bad arguments: {exc}", "expects": TOOLS[tool]["args"]}
        meta = TOOLS[tool]
        return {
            "tool": tool,
            "args": args,
            "result": result,
            "evidence": meta["evidence"],
            "resolution": meta["resolution"],
            "limits": meta["limits"],
            "index": {"root": self.root, "files": self.files,
                      "programs": len(self.ctx.programs) if self.ctx else 0,
                      "handlers": len(self.ctx.index.handlers) if self.ctx else 0,
                      "complete": self.complete, "build_ms": round(self.build_ms, 1),
                      "rebuilt": rebuilt},
            "query_ms": round((time.perf_counter() - t1) * 1000.0, 2),
            "total_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }

    def _run(self, tool: str, a: Dict[str, Any]) -> Any:
        ctx = self.ctx
        name = str(a.get("name") or "")
        file = a.get("file") or None
        if tool == "handlers":
            return [{"name": h.name, "file": h.file, "line": h.line, "end_line": h.end_line,
                     "protected": h.protected, "reaches_resource": h.reaches_resource,
                     "sink_kinds": sorted({str(s.get("kind")) for s in (h.sinks or [])}),
                     "engine_findings": len(h.proven or [])}
                    for h in sorted(ctx.index.handlers, key=lambda h: (h.file, h.line))]
        if not name:
            raise ValueError("`name` is required")
        if tool == "handler_facts":
            out = _parse(ctx.handler_facts(name, file))
        elif tool == "siblings":
            out = _parse(ctx.siblings(name, file))
        elif tool == "trace":
            out = _parse(ctx.trace(name, file))
        elif tool == "callers":
            out = _parse(ctx.callers(name))
            for c in (out.get("callers", []) if isinstance(out, dict) else []):
                c["code"] = _line_text(self.root, c.get("file", ""), int(c.get("line") or 0))
        elif tool == "callees":
            out = _parse(ctx.callees(name, file))
            if isinstance(out, dict):
                for c in out.get("calls", []):
                    c["code"] = _line_text(self.root, out.get("file", ""), int(c.get("line") or 0))
        elif tool == "guards":
            line = a.get("line")
            out = _parse(ctx.guards(name, int(line) if line else None, file))
            if isinstance(out, dict) and "guards_by_line" in out:
                out["code"] = {ln: _line_text(self.root, out.get("file", ""), int(ln))
                               for ln in out["guards_by_line"]}
        else:   # check
            if not a.get("line") or not a.get("kind"):
                raise ValueError("`line` and `kind` are required")
            out = _parse(ctx.check(name, int(a["line"]), str(a["kind"]), str(a.get("pattern") or ""),
                                   file))
        return out


def _parse(text: str) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return {"error": text} if str(text).startswith("ERROR") else {"note": text}


def serve(index: QueryIndex, inp, out) -> int:
    """One JSON request per line ({"tool": ..., "args": {...}}), one JSON answer per line.
    `{"tool": "tools"}` lists the tools; end of input stops the server."""
    for raw in inp:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise ValueError("a request is a JSON object")
        except ValueError as exc:
            answer: Dict[str, Any] = {"error": f"bad request: {exc}"}
        else:
            if req.get("tool") == "tools":
                answer = {"tools": {k: {"args": v["args"], "evidence": v["evidence"]}
                                    for k, v in TOOLS.items()}}
            else:
                try:
                    answer = index.query(str(req.get("tool") or ""), req.get("args") or {})
                except Exception as exc:   # one bad query must not end the server
                    answer = {"tool": req.get("tool"), "error": f"{type(exc).__name__}: {exc}"}
            if "id" in req:
                answer["id"] = req["id"]
        out.write(json.dumps(answer) + "\n")
        out.flush()
    return 0
