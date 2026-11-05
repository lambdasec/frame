"""The authorization hunt's tools: the agent ASKS the engine and TEACHES it.

The v11 hunt handed one agent a one-time dump of engine facts (up to 2,247 handlers) and let it
grep. Its facts were frozen at scan time, blind spots included (`reaches_resource` false for nearly
every handler of a SQLModel or Express app), and nothing the agent learned flowed back. Here the
engine is a tool the agent queries on demand:

  ask    handler_facts / siblings / trace / callers / callees / guards / check / engine_scan:
         targeted questions with engine answers (a guard on every feasible path, a refuting
         path, the resolved call chain) instead of a dump;
  teach  the agent writes a Frame pack (entry points, resource sinks, identity, auth gates) for
         a convention the engine does not know; the strict pack schema accepts or rejects it,
         the engine rescans with it and reports what changed, and from then on the convention
         applies to every route deterministically.

The repository tools read line ranges with line numbers (the old read_file returned only the
first 8,000 characters, so a handler at line 2,835 was unreadable) and grep skips vendored
bundles. Verdict tools carry ABSENTIA's falsification schema: a finding must name the violated
invariant and a concrete request that violates it, and a handler judged safe must say why.

Engine calls are serialized (`ENGINE_LOCK`): unit agents run in threads and Z3 / the translators
are not thread-safe. Model calls are what run in parallel.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from frame.sil.hunt_units import AUTHZ_CWES, class_of, proc_end_line, simple_name
from frame.sil.llm_agent import _GREP_EXTS, _safe_path

ENGINE_LOCK = threading.RLock()

# Directories that are never the application's own code, and files too big to be hand-written
# source (a minified swagger-ui bundle flooded v11's greps on open-webui).
_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
                        ".mypy_cache", ".pytest_cache", ".next", ".nuxt"})
_SKIP_SUFFIXES = (".min.js", ".bundle.js", "-bundle.js", ".map")
_MAX_GREP_FILE = 1_000_000
_GREP_FILE_EXTS = _GREP_EXTS + (".vue", ".svelte", ".yaml", ".yml")


# ---- Tool schemas -------------------------------------------------------------------------

def _fn(name: str, description: str, props: Dict[str, Any], required: Optional[List[str]] = None):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": props, "required": required or []}}}


_NAME = {"type": "string", "description": "handler / function name (as listed)"}
_FILE = {"type": "string", "description": "repo-relative file, to disambiguate a name"}

READ_FILE = _fn("read_file", "Read a repository file with line numbers. Give start_line/end_line "
                "for a range (up to 400 lines per call); a long file without a range returns its "
                "first lines and says how to continue.",
                {"path": {"type": "string"}, "start_line": {"type": "integer"},
                 "end_line": {"type": "integer"}}, ["path"])
GREP = _fn("grep", "Regex-search the repository (case-insensitive); returns up to 60 "
           "'path:line: text' matches. `path` limits it to a directory or file. Vendored and "
           "minified files are skipped.",
           {"pattern": {"type": "string"}, "path": {"type": "string"}}, ["pattern"])
LIST_FILES = _fn("list_files", "List a repository directory: its subdirectories (with source-file "
                 "counts) and files.", {"path": {"type": "string"}})
HANDLER_FACTS = _fn("handler_facts", "Engine facts for a handler or function: posture (protected, "
                    "reaches_resource), sinks, decorators, parameters, the engine's findings in it "
                    "(proven or candidate), and its numbered source.", {"name": _NAME, "file": _FILE},
                    ["name"])
SIBLINGS = _fn("siblings", "The handlers next to this one (same class, or same file): each one's "
               "decorators, protection, data access and the engine's guards at its data access. "
               "A check the siblings have and this one lacks is the classic missing-authorization "
               "bug.", {"name": _NAME, "file": _FILE}, ["name"])
TRACE = _fn("trace", "Engine data flows in a handler: which request values reach which sinks, "
            "through which calls (cross-file where resolved).", {"name": _NAME, "file": _FILE},
            ["name"])
CALLERS = _fn("callers", "Functions that call `name` (by name across the project; may list "
              "several definitions).", {"name": _NAME}, ["name"])
CALLEES = _fn("callees", "The calls a function makes, in order, with where each callee is "
              "defined in the project. Follow a handler into its service layer and permission "
              "helpers with this.", {"name": _NAME, "file": _FILE}, ["name"])
GUARDS = _fn("guards", "The conditions the engine proves hold on EVERY feasible path to a line "
             "in a function (branch checks, ownership checks, identity-scoped queries, auth "
             "decorators). Without `line`, it reports them at the function's data accesses.",
             {"name": _NAME, "line": {"type": "integer"}, "file": _FILE}, ["name"])
CHECK = _fn("check", "Ask the engine to prove or refute a claim at a line: kind='guarded_by' "
            "with a `pattern` (a check every path must pass, e.g. 'owner' or 'has_perm') or "
            "kind='scoped_by_identity' (the data access is filtered by the caller). Returns "
            "proved / refuted (with a path that avoids it) / unknown.",
            {"name": _NAME, "line": {"type": "integer"},
             "kind": {"type": "string", "enum": ["guarded_by", "scoped_by_identity"]},
             "pattern": {"type": "string"}, "file": _FILE}, ["name", "line", "kind"])
ENGINE_SCAN = _fn("engine_scan", "Run Frame's engine (solver-verified) on up to 5 files now -- "
                  "e.g. a service module the handler list does not cover -- and get its findings "
                  "and handler facts for them.",
                  {"paths": {"type": "array", "items": {"type": "string"}}}, ["paths"])
TEACH = _fn("teach", "Teach the engine a convention it does not know, as a Frame pack (TOML): "
            "entry points, resource sinks, the caller's identity, authorization gates. The pack "
            "is validated strictly; if valid, the engine rescans `files` with it and returns what "
            "changed (handlers found, data access seen, protection). Invalid packs are rejected "
            "with the error.",
            {"pack_toml": {"type": "string"},
             "files": {"type": "array", "items": {"type": "string"},
                       "description": "repo-relative files to rescan with the pack (up to 60)"}},
            ["pack_toml", "files"])
RECORD_INVENTORY = _fn(
    "record_inventory",
    "Record what you found in your area, in batches: every ROUTE (a function a remote caller "
    "reaches: an HTTP route, RPC / GraphQL resolver, websocket or webhook handler), every SERVICE "
    "function that reads or changes stored data, every authorization HELPER (a permission check, "
    "an ownership filter). Each item gets audited by its own agent, so list the real ones, in "
    "your area. The reply says which the engine already covers.",
    {"items": {"type": "array", "items": {"type": "object", "properties": {
        "kind": {"type": "string", "enum": ["route", "service", "helper"]},
        "file": {"type": "string", "description": "repo-relative file"},
        "function": {"type": "string", "description": "the function or method (Cls.method)"},
        "line": {"type": "integer", "description": "line where it is defined"},
        "note": {"type": "string", "description": "e.g. 'DELETE /api/flows/{id}' or what it reads"}},
        "required": ["kind", "file", "function"]}}},
    ["items"])
FINISH_SCOUT = _fn("finish_scout", "End your scouting with a summary of your area for the "
                   "auditors (at most ~10 lines): how callers are authenticated here, the access "
                   "model, the helpers that enforce it (names and files).",
                   {"summary": {"type": "string"}}, ["summary"])
REPORT_FINDING = _fn(
    "report_finding",
    "Record ONE confirmed authorization / business-logic flaw. Required: the invariant the code "
    "should guarantee, and a concrete violating request (method, path or entry point, parameters, "
    "who sends it and what they must already have) grounded in the code you read. A claim you "
    "cannot turn into such a request is not a finding.",
    {"handler": {"type": "string"}, "file": {"type": "string"}, "line": {"type": "integer"},
     "mechanism": {"type": "string", "enum": ["missing_authorization", "idor",
                                              "privilege_escalation", "mass_assignment",
                                              "business_logic"]},
     "cwe": {"type": "string"},
     "invariant": {"type": "string", "description": "what should hold (who may do what to which object)"},
     "violating_request": {"type": "string", "description": "the request that breaks it"},
     "enforcement_checked": {"type": "string", "description": "where you looked for the check"},
     "confidence": {"type": "number"},
     "engine_backed": {"type": "boolean",
                       "description": "true only if an engine fact supports it (it reaches data "
                                      "and is not protected, or check() refuted the guard)"},
     "reasoning": {"type": "string"}},
    ["handler", "file", "line", "mechanism", "invariant", "violating_request"])
MARK_SAFE = _fn("mark_safe", "Record that a handler in this unit is NOT vulnerable, and why: the "
                "check that enforces its invariant (or why it is public by design).",
                {"handler": {"type": "string"}, "reason": {"type": "string"},
                 "enforcing_file": {"type": "string"}, "enforcing_line": {"type": "integer"}},
                ["handler", "reason"])

MARK_UNRESOLVED = _fn(
    "mark_unresolved",
    "Record that a member cannot be decided from the repository: the flaw you suspect, where you "
    "looked for its enforcement, and the one fact that would decide it (a configuration value, a "
    "deployment's roles, behaviour of a library the repository does not contain). A person reads "
    "these. Use it only after looking for the check; a member you could settle by reading more "
    "code is not unresolved.",
    {"handler": {"type": "string"},
     "suspicion": {"type": "string", "description": "the flaw it would be, and the request"},
     "checked": {"type": "string", "description": "where you looked for the enforcement"},
     "needs": {"type": "string", "description": "the fact that would decide it, and where it lives"}},
    ["handler", "suspicion", "checked", "needs"])

REPO_TOOLS = [READ_FILE, GREP, LIST_FILES]
ASK_TOOLS = [HANDLER_FACTS, SIBLINGS, TRACE, CALLERS, CALLEES, GUARDS, CHECK, ENGINE_SCAN]
UNIT_TOOLS = REPO_TOOLS + ASK_TOOLS + [REPORT_FINDING, MARK_SAFE, MARK_UNRESOLVED]
SCOUT_TOOLS = REPO_TOOLS + [HANDLER_FACTS, TEACH, RECORD_INVENTORY, FINISH_SCOUT]
READ_ONLY = {"read_file", "grep", "list_files", "handler_facts", "siblings", "trace", "callers",
             "callees", "guards", "check", "engine_scan", "list_handlers", "engine_findings"}


# ---- Repository tools ---------------------------------------------------------------------

def read_file(repo_root: str, path: str, start: Optional[int] = None, end: Optional[int] = None,
              max_lines: int = 400, max_chars: int = 16000) -> str:
    p = _safe_path(repo_root, path or "")
    if not p or not os.path.isfile(p):
        return f"ERROR: file not found: {path}"
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        return f"ERROR: {e}"
    n = len(lines)
    a = max(1, int(start or 1))
    b = min(n, int(end) if end else a + max_lines - 1, a + max_lines - 1)
    out: List[str] = []
    size = 0
    last = a - 1
    for i in range(a, b + 1):
        row = f"{i}: {lines[i - 1]}"
        if size + len(row) > max_chars:
            break
        out.append(row)
        size += len(row) + 1
        last = i
    head = f"{path} ({n} lines), lines {a}-{last}:"
    tail = (f"\n[... {n - last} more lines: read_file(path, start_line={last + 1}) to continue]"
            if last < n else "")
    return head + "\n" + "\n".join(out) + tail


def _skip_file(fn: str, fp: str) -> bool:
    low = fn.lower()
    if not low.endswith(_GREP_FILE_EXTS) or low.endswith(_SKIP_SUFFIXES):
        return True
    try:
        return os.path.getsize(fp) > _MAX_GREP_FILE
    except OSError:
        return True


def grep(repo_root: str, pattern: str, path: str = "", limit: int = 60) -> str:
    try:
        pat = re.compile(str(pattern or ""), re.I)
    except re.error as e:
        return f"ERROR: bad regex: {e}"
    root = os.path.realpath(repo_root)
    base = _safe_path(repo_root, path) if path else root
    if not base or not os.path.exists(base):
        return f"ERROR: no such path: {path}"
    files: List[str] = []
    if os.path.isfile(base):
        files = [base]
    else:
        for dp, dns, fns in os.walk(base):
            dns[:] = sorted(d for d in dns if d not in _SKIP_DIRS)
            files.extend(os.path.join(dp, fn) for fn in sorted(fns) if not _skip_file(fn, os.path.join(dp, fn)))
    out: List[str] = []
    for fp in files:
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                for i, ln in enumerate(fh, 1):
                    if pat.search(ln):
                        out.append(f"{os.path.relpath(fp, root)}:{i}: {ln.strip()[:200]}")
                        if len(out) >= limit:
                            return "\n".join(out) + f"\n[stopped at {limit} matches; narrow it with path=]"
        except OSError:
            continue
    return "\n".join(out) or "no matches"


def list_files(repo_root: str, path: str = "", limit: int = 200) -> str:
    base = _safe_path(repo_root, path) if path else os.path.realpath(repo_root)
    if not base or not os.path.isdir(base):
        return f"ERROR: not a directory: {path}"
    rows: List[str] = []
    try:
        entries = sorted(os.listdir(base))
    except OSError as e:
        return f"ERROR: {e}"
    for e in entries:
        fp = os.path.join(base, e)
        if os.path.isdir(fp):
            if e in _SKIP_DIRS:
                continue
            count = 0
            for _, dns, fns in os.walk(fp):
                dns[:] = [d for d in dns if d not in _SKIP_DIRS]
                count += sum(1 for f in fns if f.lower().endswith(_GREP_EXTS))
            rows.append(f"{e}/  ({count} source files)")
        else:
            rows.append(e)
        if len(rows) >= limit:
            rows.append("[... truncated]")
            break
    return "\n".join(rows) or "(empty)"


# ---- The engine, as the agent sees it -----------------------------------------------------

def _rel(path: str, root: str) -> str:
    try:
        if root and path and os.path.isabs(path):
            return os.path.relpath(path, root)
    except ValueError:
        pass
    return path or ""


def _program_file(program, root: str) -> str:
    files = getattr(program, "source_files", None) or []
    if files:
        return _rel(files[0], root)
    for proc in (getattr(program, "procedures", {}) or {}).values():
        loc = getattr(proc, "loc", None)
        if loc is not None and getattr(loc, "file", ""):
            return _rel(loc.file, root)
    return ""


class HuntContext:
    """What the hunt's tools work over: the engine index, the translated programs, the raw
    symbolic findings, and the packs taught during this run. Shared read-only by the unit
    agents (teaching happens before they start)."""

    def __init__(self, index, programs, repo_root: str, language: str = "",
                 symbolic_findings: Optional[list] = None):
        self.index = index
        self.programs = [p for p in (programs or []) if p is not None]
        self.repo_root = repo_root or ""
        self.language = language or ""
        self.raw_findings = list(symbolic_findings or [])
        self.taught: List[str] = []
        self.taught_text: List[str] = []
        self._workdir: Optional[str] = None
        self._graph: Optional[Tuple[Dict[str, List[Dict[str, Any]]], Dict[Tuple[str, str], List[Tuple[str, int]]]]] = None

    # -- lookup ---------------------------------------------------------------------------
    def handler(self, name: str, file: Optional[str] = None):
        name = str(name or "").strip()
        hs = [h for h in self.index.handlers if h.name == name] or \
             [h for h in self.index.handlers if simple_name(h.name) == simple_name(name)]
        if file:
            hs = [h for h in hs if h.file == file or h.file.endswith("/" + file)] or hs
        return hs[0] if hs else None

    def locate(self, name: str, file: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """A handler or any project function: {program, proc, name, file, line, end_line}."""
        h = self.handler(name, file)
        if h is not None and getattr(h, "program", None) is not None:
            return {"program": h.program, "proc": h.name, "name": h.name, "file": h.file,
                    "line": h.line, "end_line": h.end_line or h.line, "handler": h}
        want = simple_name(name)
        found = []
        for prog in self.programs:
            pf = _program_file(prog, self.repo_root)
            if file and pf and not (pf == file or pf.endswith("/" + file)):
                continue
            for pname, proc in (getattr(prog, "procedures", {}) or {}).items():
                if pname == name or simple_name(pname) == want:
                    loc = getattr(proc, "loc", None)
                    line = getattr(loc, "line", 0) if loc else 0
                    found.append({"program": prog, "proc": pname, "name": pname, "file": pf,
                                  "line": line, "end_line": proc_end_line(proc, line),
                                  "handler": h})
        exact = [f for f in found if f["name"] == name]
        pick = (exact or found)
        return pick[0] if pick else None

    def graph(self):
        if self._graph is None:
            defs: Dict[str, List[Dict[str, Any]]] = {}
            calls: Dict[Tuple[str, str], List[Tuple[str, int]]] = {}
            for prog in self.programs:
                pf = _program_file(prog, self.repo_root)
                for pname, proc in (getattr(prog, "procedures", {}) or {}).items():
                    loc = getattr(proc, "loc", None)
                    defs.setdefault(simple_name(pname), []).append(
                        {"name": pname, "file": pf, "line": getattr(loc, "line", 0) if loc else 0})
                    out: List[Tuple[str, int]] = []
                    for node in (getattr(proc, "nodes", {}) or {}).values():
                        for ins in getattr(node, "instrs", []) or []:
                            if type(ins).__name__ != "Call":
                                continue
                            try:
                                callee = ins.get_func_name()
                            except Exception:
                                continue
                            if not callee or callee.startswith(("$", "<")):
                                continue
                            out.append((callee, getattr(getattr(ins, "loc", None), "line", 0) or 0))
                    calls[(pf, pname)] = sorted(set(out), key=lambda c: (c[1], c[0]))
            self._graph = (defs, calls)
        return self._graph

    def rebuild_index(self) -> None:
        from frame.sil.llm_hunt import build_index
        self.index = build_index(self.programs, self.raw_findings, self.repo_root)
        self._graph = None

    # -- tools ----------------------------------------------------------------------------
    def handler_facts(self, name: str, file: Optional[str] = None) -> str:
        loc = self.locate(name, file)
        if loc is None:
            return f"ERROR: no handler or function named {name!r} (try grep)"
        h = loc["handler"]
        proc = (getattr(loc["program"], "procedures", {}) or {}).get(loc["proc"])
        facts: Dict[str, Any] = {"name": loc["name"], "file": loc["file"], "line": loc["line"],
                                 "end_line": loc["end_line"]}
        if h is not None:
            facts.update(protected=h.protected, reaches_resource=h.reaches_resource, sinks=h.sinks,
                         engine_findings=h.proven)
        else:
            facts["note"] = "not an entry point the engine knows (a helper / service function)"
        if proc is not None:
            facts["decorators"] = [a.name for a in (getattr(proc, "annotations", None) or [])]
            facts["params"] = [str(p[0]) for p in (getattr(proc, "params", None) or [])]
        facts["source"] = read_file(self.repo_root, loc["file"], loc["line"],
                                    max(loc["end_line"], loc["line"]), max_lines=150, max_chars=7000) \
            if self.repo_root else ""
        return json.dumps(facts)

    def _guards_text(self, program, proc: str, line: int) -> List[str]:
        try:
            from frame.sil.authz_guards import guards_at
        except ImportError:
            return []
        with ENGINE_LOCK:
            try:
                gs = guards_at(program, proc, line) or []
            except Exception:
                return []
        return [f"{g.get('kind')}@{g.get('line')}: {g.get('text')}" for g in gs][:6]

    def _data_lines(self, h) -> List[int]:
        """The lines where a handler reads or changes stored data: the engine's resource
        operations (authz_guards.sink_lines) when available, else its data sinks. All of them --
        the check that matters usually guards the write after the lookup, not the lookup."""
        lines: List[int] = []
        program = getattr(h, "program", None)
        if program is not None:
            try:
                from frame.sil.authz_guards import sink_lines
                with ENGINE_LOCK:
                    lines = [int(x) for x in (sink_lines(program, h.name) or [])]
            except Exception:
                lines = []
        lines += [int(s.get("line") or 0) for s in (h.sinks or [])
                  if str(s.get("kind")) in ("resource_select", "resource_modify", "sql", "nosql", "orm")]
        lo, hi = h.line, max(h.end_line or h.line, h.line)
        # Plus the handler's last call: the effect (`doc.delete()` on an object the specs cannot
        # type) usually comes last, after the check that guards it.
        proc = (getattr(program, "procedures", {}) or {}).get(h.name) if program is not None else None
        calls = [getattr(getattr(i, "loc", None), "line", 0) or 0
                 for n in (getattr(proc, "nodes", {}) or {}).values()
                 for i in (getattr(n, "instrs", []) or []) if type(i).__name__ == "Call"]
        calls = [c for c in calls if lo <= c <= hi]
        if calls:
            lines.append(max(calls))
        return sorted(set(ln for ln in lines if ln and lo <= ln <= hi))

    def siblings(self, name: str, file: Optional[str] = None) -> str:
        h = self.handler(name, file)
        if h is None:
            return f"ERROR: no handler named {name!r}"
        cls = class_of(h.name)
        group = [x for x in self.index.handlers if x.file == h.file and class_of(x.name) == cls]
        rows = []
        for x in sorted(group, key=lambda x: x.line)[:24]:
            proc = (getattr(getattr(x, "program", None), "procedures", {}) or {}).get(x.name)
            data = self._data_lines(x)
            row = {"name": x.name, "line": x.line, "protected": x.protected,
                   "reaches_resource": x.reaches_resource,
                   "decorators": [a.name for a in (getattr(proc, "annotations", None) or [])],
                   "sink_kinds": sorted({str(s.get("kind")) for s in (x.sinks or [])})}
            if data and getattr(x, "program", None) is not None:
                guards: List[str] = []
                for ln in data[-4:]:                 # the last data accesses: where writes are
                    for g in self._guards_text(x.program, x.name, ln):
                        if g not in guards:
                            guards.append(g)
                row["data_access_lines"] = data[-4:]
                row["guards_at_data_access"] = guards[:8]
            rows.append(row)
        return json.dumps({"group": f"{h.file} :: {cls or '<module>'}", "handlers": rows})

    def trace(self, name: str, file: Optional[str] = None) -> str:
        loc = self.locate(name, file)
        if loc is None:
            return f"ERROR: no handler or function named {name!r}"
        flows = []
        for v in self.raw_findings:
            vf = _rel(getattr(v, "location", "") or "", self.repo_root)
            vl = int(getattr(v, "line", 0) or 0)
            if vf == loc["file"] and loc["line"] <= vl <= max(loc["end_line"], loc["line"]):
                flows.append({"cwe": getattr(v, "cwe_id", None), "line": vl,
                              "type": getattr(getattr(v, "type", None), "value", str(getattr(v, "type", ""))),
                              "source": getattr(v, "source_var", ""),
                              "data_flow": list(getattr(v, "data_flow", []) or [])[:10],
                              "evidence": getattr(v, "evidence", "")})
        h = loc["handler"]
        return json.dumps({"name": loc["name"], "file": loc["file"],
                           "sinks": (h.sinks if h is not None else []), "flows": flows[:20],
                           "note": ("" if flows else "no engine data flow recorded here; read the "
                                    "code and use callees() to follow the data")})

    def callees(self, name: str, file: Optional[str] = None) -> str:
        loc = self.locate(name, file)
        if loc is None:
            return f"ERROR: no function named {name!r}"
        defs, calls = self.graph()
        out = []
        for callee, line in calls.get((loc["file"], loc["proc"]), []):
            where = [d for d in defs.get(simple_name(callee), [])][:3]
            out.append({"call": callee, "line": line,
                        "defined_in": [f"{d['file']}:{d['line']} ({d['name']})" for d in where]})
        return json.dumps({"function": loc["name"], "file": loc["file"], "calls": out[:60],
                           "note": "callees resolved by name; several definitions = ambiguous"})

    def callers(self, name: str) -> str:
        want = simple_name(name)
        _, calls = self.graph()
        out = []
        for (pf, pname), cs in sorted(calls.items()):
            for callee, line in cs:
                if simple_name(callee) == want:
                    out.append({"caller": pname, "file": pf, "line": line, "call": callee})
        return json.dumps({"function": name, "callers": out[:40],
                           "note": "matched by name across the project"})

    def guards(self, name: str, line: Optional[int] = None, file: Optional[str] = None) -> str:
        loc = self.locate(name, file)
        if loc is None:
            return f"ERROR: no handler or function named {name!r}"
        try:
            from frame.sil.authz_guards import guards_at
        except ImportError:
            return "guards are not available in this build"
        lines: List[int] = [int(line)] if line else []
        if not lines and loc["handler"] is not None:
            lines = self._data_lines(loc["handler"])[:5]
        if not lines:
            try:
                from frame.sil.authz_guards import sink_lines
                with ENGINE_LOCK:
                    lines = list(sink_lines(loc["program"], loc["proc"]) or [])[:5]
            except Exception:
                lines = []
        if not lines:
            return json.dumps({"function": loc["name"], "note": "no data access lines known; pass line="})
        out = {}
        with ENGINE_LOCK:
            for ln in lines:
                try:
                    out[str(ln)] = guards_at(loc["program"], loc["proc"], ln) or []
                except Exception:
                    out[str(ln)] = []
        return json.dumps({"function": loc["name"], "file": loc["file"], "guards_by_line": out})

    def check(self, name: str, line: int, kind: str, pattern: str = "",
              file: Optional[str] = None) -> str:
        loc = self.locate(name, file)
        if loc is None:
            return json.dumps({"verdict": "unknown", "reason": f"no handler or function named {name!r}",
                               "witness": []})
        try:
            from frame.sil.authz_guards import check_claim
        except ImportError:
            return json.dumps({"verdict": "unknown", "reason": "check is not available in this build"})
        claim: Dict[str, Any] = {"kind": kind}
        if pattern:
            claim["pattern"] = pattern
        with ENGINE_LOCK:
            try:
                r = check_claim(loc["program"], loc["proc"], int(line or 0), claim)
            except Exception as e:
                r = {"verdict": "unknown", "reason": f"engine error: {type(e).__name__}"}
        return json.dumps(r)

    def _rescan(self, files: List[str], packs: List[str], verify: bool):
        from frame.sil.scanner import FrameScanner
        sc = FrameScanner(language=self.language or None, verify=verify,
                          packs=packs or None, hunt_authz=True)
        sc._collecting_hunt_programs = True
        vulns: List[Any] = []
        for f in files:
            try:
                res = sc.scan_file(os.path.join(self.repo_root, f))
            except Exception:
                continue
            vulns.extend(res.vulnerabilities)
        return list(sc._hunt_programs), vulns

    def _files(self, paths: List[str], cap: int) -> List[str]:
        out = []
        for p in paths or []:
            sp = _safe_path(self.repo_root, str(p))
            if sp and os.path.isfile(sp):
                out.append(_rel(sp, os.path.realpath(self.repo_root)))
            if len(out) >= cap:
                break
        return out

    def engine_scan(self, paths: List[str]) -> str:
        files = self._files(paths, 5)
        if not files:
            return "ERROR: none of those paths is a file in the repository"
        with ENGINE_LOCK:
            try:
                progs, vulns = self._rescan(files, self.taught, verify=True)
            except Exception as e:
                return f"ERROR: engine scan failed: {type(e).__name__}"
        from frame.sil.llm_hunt import build_index
        idx = build_index(progs, vulns, self.repo_root)
        findings = [f for f in idx.findings if str(f.get("cwe") or "").upper() in AUTHZ_CWES]
        other: Dict[str, int] = {}
        for f in idx.findings:
            if str(f.get("cwe") or "").upper() not in AUTHZ_CWES:
                k = str(f.get("cwe") or f.get("type") or "?")
                other[k] = other.get(k, 0) + 1
        return json.dumps({"files": files, "authorization_findings": findings, "other_counts": other,
                           "handlers": [{"name": h.name, "file": h.file, "line": h.line,
                                         "protected": h.protected,
                                         "reaches_resource": h.reaches_resource} for h in idx.handlers][:60]})

    def teach(self, pack_toml: str, files: List[str]) -> str:
        """Validate the pack strictly, rescan `files` with it (plus earlier taught packs), and
        keep it only if it loads. The rescanned files' programs replace the old ones, so every
        later fact -- the units, their ranking, siblings, guards -- reflects the convention."""
        with ENGINE_LOCK:                  # scouts teach concurrently; programs/index are shared
            return self._teach(pack_toml, files)

    def _teach(self, pack_toml: str, files: List[str]) -> str:
        from frame.sil.packs import PackSet
        if self._workdir is None:
            self._workdir = tempfile.mkdtemp(prefix="frame-hunt-packs-")
        path = os.path.join(self._workdir, f"taught-{len(self.taught) + 1}.toml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(pack_toml or "")
        try:
            PackSet.build(list(self.taught) + [path], builtin=True)
        except Exception as e:
            os.remove(path)
            return f"INVALID PACK (not applied): {e}"
        targets = self._files(files, 60)
        if not targets:
            os.remove(path)
            return "ERROR: give the repo-relative files the pack should apply to (files=[...])"
        before = {(h.file, h.name): (h.protected, h.reaches_resource)
                  for h in self.index.handlers if h.file in targets}
        with ENGINE_LOCK:
            try:
                progs, vulns = self._rescan(targets, self.taught + [path], verify=False)
            except Exception as e:
                os.remove(path)
                return f"ERROR: rescan with the pack failed: {type(e).__name__}"
        target_set = set(targets)
        self.programs = [p for p in self.programs
                         if _program_file(p, self.repo_root) not in target_set] + progs
        self.raw_findings = [v for v in self.raw_findings
                             if _rel(getattr(v, "location", "") or "", self.repo_root) not in target_set] + vulns
        self.taught.append(path)
        self.taught_text.append(pack_toml)
        self.rebuild_index()
        after = {(h.file, h.name): (h.protected, h.reaches_resource)
                 for h in self.index.handlers if h.file in targets}
        added = sorted(f"{f}:{n}" for (f, n) in set(after) - set(before))
        changed = sorted(f"{f}:{n} protected {before[k][0]}->{after[k][0]}, reaches_resource "
                         f"{before[k][1]}->{after[k][1]}"
                         for k in set(after) & set(before) if before[k] != after[k]
                         for f, n in [k])
        out = {"applied": True, "files_rescanned": len(targets),
               "handlers_before": len(before), "handlers_after": len(after),
               "reaching_data_after": sum(1 for v in after.values() if v[1]),
               "new_handlers": added[:40], "changed": changed[:40]}
        if not added:
            # Silent before: a pack that validates but matches nothing looked like a success, and
            # every pack the v12 mapping pass taught (sinks, gates) added no handler at all.
            out["note"] = ("NO new handlers in these files. Only an [[entrypoint]] makes a function a "
                           "handler; if their routes are still missing, the entrypoint did not match "
                           "(check `extends` / `decorator` / `registered_via` against how the code "
                           "imports and names them) -- fix it and teach again.")
        return json.dumps(out)

    # -- scouts ---------------------------------------------------------------------------
    def record_inventory(self, items: Any, sink: List[Dict[str, Any]], area=None) -> str:
        """Validate a scout's items into `sink`: a known kind, an existing repo file (in the
        scout's `area` when given), a function name. Says which the engine already covers."""
        if not isinstance(items, list):
            return "ERROR: items must be a list of {kind, file, function, line, note}"
        added, covered, rejected = 0, 0, []
        for it in items[:200]:
            if not isinstance(it, dict):
                continue
            kind = str(it.get("kind") or "").strip().lower()
            fn = str(it.get("function") or "").strip()
            files = self._files([str(it.get("file") or "")], 1)
            if kind not in ("route", "service", "helper") or not fn or not files:
                rejected.append(f"{it.get('file')}:{fn or '?'} (needs kind route|service|helper, an "
                                "existing repo file and a function)")
                continue
            if area is not None and not any(a.holds(files[0]) for a in area):
                rejected.append(f"{files[0]}:{fn} (outside your area)")
                continue
            entry = {"kind": kind, "file": files[0], "function": fn,
                     "line": _int(it.get("line")) or 0, "note": str(it.get("note") or "")[:200]}
            sink.append(entry)
            added += 1
            if self.handler(fn, files[0]) is not None and self.handler(fn, files[0]).file == files[0]:
                covered += 1
        msg = f"Recorded {added} item(s); {covered} already engine handlers, {added - covered} new to the hunt."
        if rejected:
            msg += " Rejected: " + "; ".join(rejected[:8])
        return msg


# ---- Verdict reuse across checkouts / commits ----------------------------------------------

def _hash_files(repo_root: str, files: List[str]) -> str:
    h = hashlib.sha256()
    for f in sorted(set(files)):
        h.update(f.encode("utf-8", "replace") + b"\0")
        p = _safe_path(repo_root, f)
        try:
            with open(p, "rb") as fh:            # type: ignore[arg-type]
                h.update(hashlib.sha256(fh.read()).digest())
        except (OSError, TypeError):
            h.update(b"<missing>")
    return h.hexdigest()


class VerdictCache:
    """A unit's verdicts and findings, reusable on another checkout of the same repository when
    every file the unit's agent read is byte-identical there (ABSENTIA's re-analysis after a
    commit). Keyed by the unit's id; the content hash, not the commit, decides reuse, so a fix
    that touched any file the agent read is always re-investigated."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        try:
            with open(path, encoding="utf-8") as fh:
                self.data: Dict[str, Any] = json.load(fh)
        except (OSError, ValueError):
            self.data = {}

    def lookup(self, unit_id: str, repo_root: str) -> Optional[Dict[str, Any]]:
        e = self.data.get(unit_id)
        if not e:
            return None
        return e if _hash_files(repo_root, e.get("read", [])) == e.get("hash") else None

    def store(self, unit_id: str, repo_root: str, read: List[str], verdicts: Dict[str, str],
              findings: List[Dict[str, Any]],
              ranges: Optional[Dict[str, List[Tuple[int, int]]]] = None,
              unresolved: Optional[List[Dict[str, Any]]] = None) -> None:
        read = sorted(set(read))
        entry = {"hash": _hash_files(repo_root, read), "read": read, "verdicts": verdicts,
                 "findings": findings, "ranges": {f: [list(r) for r in rs]
                                                  for f, rs in (ranges or {}).items()},
                 "unresolved": list(unresolved or [])}
        with self._lock:
            self.data[unit_id] = entry
            tmp = self.path + ".tmp"
            try:
                os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(self.data, fh, indent=1)
                os.replace(tmp, self.path)
            except OSError:
                pass


# ---- Executors -----------------------------------------------------------------------------

def _int(v: Any) -> Optional[int]:
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def repo_rel(repo_root: str, path: str) -> str:
    """A path an agent wrote (`./src/x.js`, an absolute path under the root) as repo-relative."""
    p = str(path or "").replace("\\", "/")
    if repo_root and os.path.isabs(p):
        try:
            p = os.path.relpath(p, repo_root).replace(os.sep, "/")
        except ValueError:
            return p
    while p.startswith("./"):
        p = p[2:]
    return p


def repo_exec(ctx: HuntContext, name: str, args: Dict[str, Any],
              read_log: Optional[set] = None,
              ranges: Optional[Dict[str, List[Tuple[int, int]]]] = None) -> Optional[str]:
    """The repository and ask tools (shared by the mapping pass and the units); None when
    `name` is not one of them. `read_log` collects the files read, `ranges` the line ranges
    read per file (what the hunt's coverage wave is planned from)."""
    if name == "read_file":
        start, end = _int(args.get("start_line")), _int(args.get("end_line"))
        out = read_file(ctx.repo_root, str(args.get("path", "")), start, end)
        rel = repo_rel(ctx.repo_root, str(args.get("path") or ""))
        if rel and not out.startswith("ERROR"):
            if read_log is not None:
                read_log.add(rel)
            if ranges is not None:
                a = max(1, start or 1)
                ranges.setdefault(rel, []).append((a, max(a, min(end or a + 399, a + 399))))
        return out
    if name == "grep":
        return grep(ctx.repo_root, str(args.get("pattern", "")), str(args.get("path") or ""))
    if name == "list_files":
        return list_files(ctx.repo_root, str(args.get("path") or ""))
    file = str(args.get("file") or "") or None
    if name == "handler_facts":
        return ctx.handler_facts(str(args.get("name", "")), file)
    if name == "siblings":
        return ctx.siblings(str(args.get("name", "")), file)
    if name == "trace":
        return ctx.trace(str(args.get("name", "")), file)
    if name == "callers":
        return ctx.callers(str(args.get("name", "")))
    if name == "callees":
        return ctx.callees(str(args.get("name", "")), file)
    if name == "guards":
        return ctx.guards(str(args.get("name", "")), _int(args.get("line")), file)
    if name == "check":
        return ctx.check(str(args.get("name", "")), _int(args.get("line")) or 0,
                         str(args.get("kind", "")), str(args.get("pattern") or ""), file)
    if name == "engine_scan":
        paths = args.get("paths") or []
        return ctx.engine_scan(paths if isinstance(paths, list) else [str(paths)])
    if name == "list_handlers":
        return json.dumps([{"name": h.name, "file": h.file, "line": h.line, "protected": h.protected,
                            "reaches_resource": h.reaches_resource} for h in ctx.index.handlers][:300])
    if name == "engine_findings":
        authz = [f for f in ctx.index.findings if str(f.get("cwe") or "").upper() in AUTHZ_CWES]
        return json.dumps({"authorization": authz[:100]})
    return None


def match_member(names: List[str], handler: str) -> Optional[str]:
    """The unit member a reported handler name refers to (exact, else a unique simple-name match)."""
    handler = str(handler or "").strip()
    if handler in names:
        return handler
    hits = [n for n in names if simple_name(n) == simple_name(handler)]
    return hits[0] if len(hits) == 1 else None


def verdict_exec(names: List[str], collected: List[Dict[str, Any]], verdicts: Dict[str, str],
                 seen_keys: set, key_fn: Callable[[Dict[str, Any]], tuple],
                 unresolved: Optional[List[Dict[str, Any]]] = None
                 ) -> Callable[[str, Dict[str, Any]], Optional[str]]:
    """report_finding / mark_safe / mark_unresolved for one unit. A finding without an invariant
    and a concrete violating request is not recorded (the agent is told what is missing and can
    resubmit); neither is an unresolved verdict that does not say what would decide it. A finding
    outranks the other verdicts, and "safe" a later "unresolved" (the agent found the check)."""
    def _exec(name: str, args: Dict[str, Any]) -> Optional[str]:
        if name == "report_finding":
            missing = [k for k in ("invariant", "violating_request")
                       if len(str(args.get(k) or "").strip()) < 8]
            if missing:
                return ("NOT RECORDED: a finding needs " + " and ".join(missing) +
                        " -- the property that should hold and a concrete request (who sends what, "
                        "to which endpoint, with what they already have) that breaks it. If you "
                        "cannot state one, it is not a finding; mark_safe or keep investigating.")
            key = key_fn(args)
            if key in seen_keys:
                return (f"(Already recorded a finding at {args.get('file')}:{args.get('line')}; "
                        "ignored.)")
            seen_keys.add(key)
            collected.append(dict(args))
            m = match_member(names, str(args.get("handler") or ""))
            if m:
                verdicts[m] = "reported"
                if unresolved is not None:
                    unresolved[:] = [u for u in unresolved if u["handler"] != m]
            return (f"Recorded finding #{len(collected)} ({args.get('mechanism')} at "
                    f"{args.get('file')}:{args.get('line')}).")
        if name == "mark_safe":
            if len(str(args.get("reason") or "").strip()) < 8:
                return "NOT RECORDED: say what enforces the invariant (or why it is public by design)."
            m = match_member(names, str(args.get("handler") or ""))
            if m is None:
                return f"ERROR: {args.get('handler')!r} is not a handler of this unit: {', '.join(names)}"
            if verdicts.get(m) != "reported":
                verdicts[m] = "safe"
                if unresolved is not None:
                    unresolved[:] = [u for u in unresolved if u["handler"] != m]
            return f"Marked {m} safe."
        if name == "mark_unresolved":
            missing = [k for k in ("suspicion", "checked", "needs")
                       if len(str(args.get(k) or "").strip()) < 8]
            if missing:
                return ("NOT RECORDED: an unresolved verdict needs " + ", ".join(missing) +
                        " -- the flaw you suspect, where you looked for its enforcement, and the "
                        "fact that would decide it.")
            m = match_member(names, str(args.get("handler") or ""))
            if m is None:
                return f"ERROR: {args.get('handler')!r} is not a handler of this unit: {', '.join(names)}"
            if verdicts.get(m) in ("reported", "safe"):
                return f"(Kept the earlier verdict on {m}: {verdicts[m]}.)"
            verdicts[m] = "unresolved"
            if unresolved is not None:
                unresolved[:] = [u for u in unresolved if u["handler"] != m]
                unresolved.append({"handler": m, **{k: str(args.get(k) or "").strip()
                                                     for k in ("suspicion", "checked", "needs")}})
            return f"Marked {m} unresolved."
        return None
    return _exec
