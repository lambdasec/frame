"""Agentic hunting for authorization and business-logic flaws (neuro-symbolic).

Symbolic analysis decides mechanism (does attacker data reach this operation? is the
selection scoped to the caller?); it cannot decide INTENT (should the client control
this price? should this role reach this resource?). This layer closes that gap: an
LLM drives an open-ended investigation whose TOOLS are Frame's sound engine facts, so
its hypotheses are grounded in analysis rather than guessed from source text.

What makes it different from `llm_detect` (free grep/read over files):
  * The agent queries the ENGINE -- `list_handlers` (each entry point with its
    authorization posture), `handler_facts` (the sinks it reaches, the findings Frame
    already proved, its source), `engine_findings` -- facts the symbolic core computed.
  * Every finding is tiered against those facts. A claim the engine corroborates
    (the named handler reaches a resource operation and is not protected) is the
    higher `llm_verified` tier; an intent-only assertion the engine cannot back stays
    `llm_detect`. The tiers are never merged (Frame's standing rule).

Cache discipline (long runs stay affordable): the loop is `run_agent`, which is
append-only -- the system prompt and tool definitions are a fixed prefix for the whole
run and every turn appends at the tail, so a prefix-caching endpoint keeps its hits
high across the many tool-calling turns. Only the rare compaction step rewrites the
body, by design.

Gated behind the scanner; a transport/parse failure yields no findings (fail-safe).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from frame.sil.llm_client import LLMClient, LLMConfig, _extract_json_object
from frame.sil.llm_agent import run_agent, INVESTIGATION_TOOLS, _repo_exec, sandbox_python
from frame.sil.llm_detect import _repo_inventory
from frame.sil.llm_trace import TraceWriter, read_stf
from frame.sil.hunt_units import AUTHZ_CWES, proc_end_line


# ---- Engine facts the agent can query ------------------------------------------

@dataclass
class HandlerFact:
    """One entry-point handler as the engine sees it."""
    name: str
    file: str                         # repo-relative where possible
    line: int
    protected: bool                   # an auth gate, or the caller's identity used to scope
    reaches_resource: bool            # performs a resource / DB operation
    end_line: int = 0
    sinks: List[Dict[str, Any]] = field(default_factory=list)       # [{kind, line}]
    proven: List[Dict[str, Any]] = field(default_factory=list)      # Frame's own findings in range
    # The translated program it lives in: the hunt's engine tools (guards, check, callees) ask it.
    program: Any = field(default=None, repr=False, compare=False)
    # A handler the class does not write: a framework base class serves it (`[[provided_action]]`,
    # e.g. a DRF ReadOnlyModelViewSet's `list`). `provided_by` names the base, `decided_by` the class
    # attributes the framework's code reads. The engine has no facts about its body.
    provided_by: str = ""
    decided_by: List[str] = field(default_factory=list)


@dataclass
class EngineIndex:
    """The sound facts the hunting agent reasons over: the handlers and what Frame
    already proved. Built from a translated program; carries no model state."""
    handlers: List[HandlerFact] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)    # [{file, line, cwe, type}]
    # Authorization-decision functions the engine found with an under-constrained grant path
    # (translator._authorization_soundness_checks): leads to investigate for intent -- the real
    # authorization logic often lives in such a helper, not the route handler.
    soundness_leads: List[Dict[str, Any]] = field(default_factory=list)
    # Service / helper functions: non-handler procedures that touch a resource (the layer a
    # handler delegates data access to, where the real authorization enforcement often lives:
    # parse-server's enforceRoleSecurity, open-webui's has_access_to_file). The handler-centric
    # suspect list never surfaces these; the hunt audits them too. [{name, file, line, scoped}].
    service_functions: List[Dict[str, Any]] = field(default_factory=list)
    # Authorization GATES reached from a resource handler: non-handler functions that decide on
    # their own inputs and touch no resource, which a resource-reaching caller delegates the
    # access check to (parse-server's enforceRoleSecurity). The highest-value bug here is an
    # INCOMPLETE gate -- a class, operation or role it forgets to cover -- which has no dataflow,
    # so only an intent-aware audit (the hunt) can find it. [{name, file, line}].
    authz_gates: List[Dict[str, Any]] = field(default_factory=list)
    repo_root: str = ""

    def handler(self, name: str, file: Optional[str] = None) -> Optional[HandlerFact]:
        """The handler `name` refers to; with `file`, the one in that file first (`index` or
        `get` exists in many files, and a finding must stay in the file it names)."""
        name = (name or "").strip()
        hits = [h for h in self.handlers
                if h.name == name or h.name.rsplit("::", 1)[-1].rsplit(".", 1)[-1] == name]
        if file:
            f = str(file).replace("\\", "/").lstrip("./")
            in_file = [h for h in hits if h.file == f or h.file.endswith("/" + f) or f.endswith("/" + h.file)]
            # Never another file's handler of the same name: a finding on a function only a scout
            # found would otherwise be "corroborated" by an unrelated handler elsewhere.
            return in_file[0] if in_file else None
        return hits[0] if hits else None


def _provided_handlers(progs, repo_root: str, known: set) -> List[HandlerFact]:
    """Handlers a class gets from a framework base without writing them (`[[provided_action]]` of
    the packs applied to its file). The class's bases are followed through the project's own
    classes, across files by name when exactly one file defines it (never guessed); an action the
    class or a project base writes is a real procedure, not a provided one. Each becomes a member
    of the class's unit placed at the class, so the agent must judge it like a written handler."""
    from fnmatch import fnmatchcase
    defs: Dict[str, List[Tuple[Any, Any]]] = {}
    for program in progs:
        for cname, info in (getattr(program, "class_info", None) or {}).items():
            defs.setdefault(cname, []).append((program, info))

    def lookup(program, base: str):
        simple = base.rsplit(".", 1)[-1].rsplit("::", 1)[-1]
        info = (getattr(program, "class_info", None) or {}).get(simple)
        if info is not None:
            return program, simple, info
        hits = defs.get(simple) or []
        return (hits[0][0], simple, hits[0][1]) if len(hits) == 1 else None

    def written(program, cname: str) -> set:
        return {n.split("#", 1)[0].rsplit(".", 1)[-1]
                for n, pr in (getattr(program, "procedures", {}) or {}).items()
                if getattr(pr, "class_name", None) == cname}

    out: List[HandlerFact] = []
    for program in progs:
        entries = [e for pk in (getattr(program, "active_packs", None) or ())
                   for e in (getattr(pk, "provided_actions", None) or ())]
        if not entries:
            continue
        path = _rel(_program_file(program), repo_root)
        for cname, info in sorted((getattr(program, "class_info", None) or {}).items()):
            bases: List[str] = []
            own = set(written(program, cname))
            seen, todo = {cname}, [(program, info)]
            while todo:
                prog, ci = todo.pop()
                for b in [*ci.bases, *ci.canonical_bases]:
                    bases.append(b)
                    hit = lookup(prog, b)
                    if hit is not None and hit[1] not in seen:
                        seen.add(hit[1])
                        own |= written(hit[0], hit[1])
                        todo.append((hit[0], hit[2]))
            for e in entries:
                base = next((b for b in bases for g in e.extends if fnmatchcase(b, g)), None)
                if base is None:
                    continue
                for action in e.actions:
                    name = f"{cname}.{action}"
                    if action in own or (path, name) in known:
                        continue
                    known.add((path, name))
                    line = int(getattr(info, "line", 0) or 0)
                    out.append(HandlerFact(
                        name=name, file=path, line=line,
                        end_line=int(getattr(info, "end_line", 0) or 0) or line,
                        protected=False, reaches_resource=True, program=program,
                        provided_by=base, decided_by=list(e.decided_by)))
    return out


def _program_file(program) -> str:
    for proc in (getattr(program, "procedures", {}) or {}).values():
        f = getattr(getattr(proc, "loc", None), "file", "")
        if f:
            return f
    files = getattr(program, "source_files", None) or []
    return files[0] if files else ""


def _rel(path: str, root: str) -> str:
    try:
        if root and path:
            return os.path.relpath(path, root)
    except ValueError:
        pass
    return path or ""


def build_index(programs, symbolic_findings: Optional[list], repo_root: str) -> EngineIndex:
    """Collect the engine facts for the hunting agent from one or more translated
    programs (a project has one program per file).

    `symbolic_findings` is the scan's own Vulnerability list (what Frame proved), used
    to tell the agent what is already covered and to corroborate its claims.
    """
    if programs is None:
        progs: list = []
    elif isinstance(programs, (list, tuple, set)):
        progs = [p for p in programs if p is not None]
    else:
        progs = [programs]
    idx = EngineIndex(repo_root=repo_root or "")

    findings = []
    for v in (symbolic_findings or []):
        # `proven` only for a solver-verified flow. A hunt's own scan runs unverified, so its
        # authorization findings are CANDIDATES (an IDOR the dataflow pass flagged without
        # seeing the guard a fix adds): leads for the agent to confirm or refute, never a reason
        # to drop what the agent reports.
        findings.append({"file": _rel(getattr(v, "location", "") or "", repo_root),
                         "line": getattr(v, "line", 0), "cwe": getattr(v, "cwe_id", None),
                         "type": getattr(getattr(v, "type", None), "value", str(getattr(v, "type", ""))),
                         "proven": getattr(v, "evidence", "") == "solver-verified"})
    idx.findings = findings

    for program in progs:
        for lead in (getattr(program, "authz_soundness", None) or []):
            idx.soundness_leads.append({
                "name": lead.get("name", ""),
                "file": _rel(lead.get("file", "") or "", repo_root),
                "line": lead.get("line", 0), "reason": lead.get("reason", "")})
        for sname, (scoped, _reaches, sloc) in (getattr(program, "service_functions", None) or {}).items():
            idx.service_functions.append({
                "name": sname, "file": _rel(getattr(sloc, "file", "") or "", repo_root),
                "line": getattr(sloc, "line", 0) or 0, "scoped": bool(scoped)})
        authz = getattr(program, "handler_authz", None) or {}
        # Sinks in this program, attributed to a handler by line range.
        sinks_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for proc in getattr(program, "procedures", {}).values():
            for node in getattr(proc, "nodes", {}).values():
                for instr in getattr(node, "instrs", []):
                    if type(instr).__name__ == "TaintSink":
                        loc = getattr(instr, "loc", None)
                        kind = getattr(getattr(instr, "kind", None), "value", None)
                        if loc is not None and kind:
                            sinks_by_file.setdefault(loc.file, []).append({"kind": kind, "line": loc.line})
        procs = getattr(program, "procedures", {})
        for name, (protected, reaches, loc) in authz.items():
            proc = procs.get(name)
            start = loc.line if loc is not None else 0
            end = proc_end_line(proc, start)
            f = loc.file if loc is not None else ""
            rel = _rel(f, repo_root)
            in_range = [s for s in sinks_by_file.get(f, []) if start <= s["line"] <= (end or start)]
            proven = [x for x in findings if x["file"] == rel and start <= (x["line"] or 0) <= (end or start)]
            idx.handlers.append(HandlerFact(
                name=name, file=rel, line=start, end_line=end or start,
                protected=bool(protected), reaches_resource=bool(reaches),
                sinks=in_range, proven=proven, program=program))

    idx.handlers += _provided_handlers(progs, repo_root, {(h.file, h.name) for h in idx.handlers})

    # Authorization gates reached from a resource handler. `resource_proc_callees` (per program)
    # names every function a resource-reaching procedure delegates to; a gate is surfaced only
    # when its own simple name appears there -- i.e. it sits on a handler -> resource path -- which
    # is what separates authorization enforcement from plain input validation. The delegation edge
    # may cross files (the gate in one module, its caller in another), so the caller sets are
    # unioned across all programs before filtering.
    reached: set = set()
    for program in progs:
        reached.update(getattr(program, "resource_proc_callees", None) or set())
    seen_gate: set = set()
    for program in progs:
        for gname, gloc in (getattr(program, "authz_gates", None) or {}).items():
            simple = gname.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
            if simple in reached and gname not in seen_gate:
                seen_gate.add(gname)
                idx.authz_gates.append({
                    "name": gname, "file": _rel(getattr(gloc, "file", "") or "", repo_root),
                    "line": getattr(gloc, "line", 0) or 0})
    return idx


# ---- Tools: engine facts + repo investigation ----------------------------------

ENGINE_TOOLS = [
    {"type": "function", "function": {
        "name": "list_handlers",
        "description": "List the application's entry-point handlers with their engine-computed "
                       "authorization posture: protected (an auth gate or the caller's identity "
                       "used to scope access) and reaches_resource (performs a resource/DB "
                       "operation). Start here.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "handler_facts",
        "description": "Engine facts for one handler by name: its authorization posture, the sinks "
                       "it reaches (kind + line), the vulnerabilities Frame has already proved in "
                       "it, and its source code.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}},
                       "required": ["name"]}}},
    {"type": "function", "function": {
        "name": "engine_findings",
        "description": "The authorization findings of Frame's symbolic engine (file, line, cwe, "
                       "type, proven), plus a count of its other findings by CWE. proven=true is "
                       "solver-verified: do not re-report it. proven=false is an unverified "
                       "candidate: confirm or refute it.",
        "parameters": {"type": "object", "properties": {}}}},
]

# Incremental capture: the agent reports each finding the MOMENT it is confident, instead of
# holding them all for one final JSON dump. A long run's final synthesis turn is fragile (a
# reasoning model can burn its whole output budget on reasoning and emit empty content -- a 200-
# step, 1600s investigation then yielding zero findings), and nothing forces the agent to commit,
# so it thrashes. With this tool the harness accumulates findings as they are found: a whiffed
# final turn loses nothing, and reporting IS the progress.
REPORT_TOOL = {"type": "function", "function": {
    "name": "report_finding",
    "description": "Record ONE confirmed authorization/business-logic finding now. Call this the "
                   "moment you are confident, then keep auditing other handlers -- do not wait to "
                   "report everything at the end. Reporting the same handler+line twice is "
                   "ignored. When you have audited the handlers and reported every real finding, "
                   "stop (reply with a one-line summary and NO tool call).",
    "parameters": {"type": "object", "properties": {
        "handler": {"type": "string", "description": "handler name from list_handlers, if any"},
        "file": {"type": "string"}, "line": {"type": "integer"},
        "mechanism": {"type": "string", "enum": ["missing_authorization", "idor",
                      "privilege_escalation", "mass_assignment", "business_logic"]},
        "cwe": {"type": "string"}, "confidence": {"type": "number"},
        "engine_backed": {"type": "boolean",
                          "description": "true only if a list_handlers/handler_facts fact supports "
                                         "it (reaches a resource and is not protected)"},
        "reasoning": {"type": "string", "description": "why this is a real violation"}},
        "required": ["file", "line", "mechanism"]}}}

HUNT_TOOLS = ENGINE_TOOLS + [REPORT_TOOL] + INVESTIGATION_TOOLS

# Dynamic testing (opt-in): the agent writes a short Python probe that drives the target app's own
# test client as two users to CONFIRM a candidate authorization flaw by exercise -- the user's
# direction that the LLM should "try running code to test, not just read". Off by default, so a
# plain scan or benchmark never runs model-authored code; enabled via hunt_authz(dynamic=True).
RUN_CODE_TOOL = {"type": "function", "function": {
    "name": "run_code",
    "description": "Run a short Python script in the repository to TEST a hypothesis (the repo is "
                   "importable). Use it to confirm a candidate IDOR/authorization flaw by exercise: "
                   "drive the app's own test client (Flask app.test_client(), Django "
                   "django.test.Client, FastAPI TestClient) as two different users and check "
                   "whether one reaches the other's resource. Returns combined stdout+stderr "
                   "(exit code, truncated). A hard timeout kills it. Print what you observe.",
    "parameters": {"type": "object", "properties": {
        "code": {"type": "string", "description": "the Python script to run"},
        "reason": {"type": "string", "description": "what this probe is testing"}},
        "required": ["code"]}}}


def hunt_tools(dynamic: bool = False) -> list:
    """The hunt's tool set; with `dynamic`, adds run_code (sandboxed probe execution)."""
    return HUNT_TOOLS + ([RUN_CODE_TOOL] if dynamic else [])


def _handler_source(h: HandlerFact, repo_root: str) -> str:
    path = os.path.join(repo_root, h.file) if repo_root else h.file
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    lo = max(0, h.line - 1)
    hi = min(len(lines), (h.end_line or h.line) + 1)
    return "".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))[:6000]


def _finding_key(f: Dict[str, Any]) -> tuple:
    """Identity of a finding for dedupe: handler+file+line (mechanism ignored so the same
    spot reported under two mechanisms counts once)."""
    return (str(f.get("handler") or "").strip(),
            str(f.get("file") or "").strip(), f.get("line") or 0)


def hunt_exec(index: EngineIndex,
              collected: Optional[list] = None,
              dynamic: bool = False,
              interpreter: Optional[str] = None,
              probe_timeout_s: int = 60) -> Callable[[str, Dict[str, Any]], str]:
    """Executor for the hunting tools: engine-fact tools over `index`, the shared
    read_file / grep over the repository, and report_finding which appends to `collected`
    (incremental capture -- the accumulated list is the run's result, final JSON or not).
    With `dynamic`, also serves run_code (a sandboxed Python probe against the repo, run with
    `interpreter` -- the app's own virtualenv when given -- under a `probe_timeout_s` wall clock)."""
    seen_keys: set = set()

    def _exec(name: str, args: Dict[str, Any]) -> str:
        if name == "report_finding":
            if collected is None:
                return "ERROR: reporting unavailable"
            key = _finding_key(args)
            if key in seen_keys:
                return (f"(Already recorded a finding at {args.get('file')}:{args.get('line')}; "
                        "ignored. Audit a different handler, or stop when done.)")
            seen_keys.add(key)
            collected.append(dict(args))
            return (f"Recorded finding #{len(collected)} ({args.get('mechanism')} at "
                    f"{args.get('file')}:{args.get('line')}). Continue auditing other handlers; "
                    "stop with a one-line summary and no tool call when every real one is in.")
        if name == "list_handlers":
            return json.dumps([{"name": h.name, "file": h.file, "line": h.line,
                                "protected": h.protected, "reaches_resource": h.reaches_resource}
                               for h in index.handlers]) or "[]"
        if name == "handler_facts":
            h = index.handler(str(args.get("name", "")))
            if h is None:
                return "ERROR: no such handler (use list_handlers)"
            return json.dumps({"name": h.name, "file": h.file, "line": h.line,
                               "protected": h.protected, "reaches_resource": h.reaches_resource,
                               "sinks": h.sinks, "proven_findings": h.proven,
                               "source": _handler_source(h, index.repo_root)})
        if name == "engine_findings":
            # Only the authorization class in full: the rest (XSS, test fixtures' secrets) is
            # noise to an authorization hunt and filled the context on big apps (n8n: 589).
            authz = [f for f in index.findings if str(f.get("cwe") or "").upper() in _AUTHZ_CWES]
            other: Dict[str, int] = {}
            for f in index.findings:
                if str(f.get("cwe") or "").upper() not in _AUTHZ_CWES:
                    k = str(f.get("cwe") or f.get("type") or "?")
                    other[k] = other.get(k, 0) + 1
            return json.dumps({"authorization": authz, "other_counts": other})
        if name in ("read_file", "grep"):
            return _repo_exec(name, args, index.repo_root)
        if name == "run_code":
            if not dynamic:
                return "ERROR: run_code is not enabled"
            return sandbox_python(str(args.get("code") or ""), index.repo_root,
                                  timeout_s=probe_timeout_s, interpreter=interpreter)
        return "ERROR: unknown tool"
    return _exec


HUNT_SYSTEM = (
    "You are a precise application-security auditor hunting for AUTHORIZATION and "
    "BUSINESS-LOGIC flaws -- the bugs a dataflow scanner cannot decide because they turn "
    "on INTENT: broken object-level / function-level authorization (IDOR/BOLA, missing "
    "authorization), privilege escalation, mass assignment of privileged fields, and "
    "client control of values that must be server-authoritative (price, quantity, "
    "discount, role, account id, workflow state).\n\n"
    "Frame's symbolic engine has already analyzed this code. Use its facts as your "
    "ground truth, do not guess from source text:\n"
    "  - list_handlers(): the entry points and, for each, whether it is protected (an "
    "authorization gate, or the caller's identity used to scope access) and whether it "
    "reaches a resource/DB operation.\n"
    "  - handler_facts(name): the sinks a handler reaches, the vulnerabilities Frame "
    "ALREADY proved in it, and its source.\n"
    "  - engine_findings(): the engine's authorization findings. proven=true is solver-verified: "
    "never re-report it. proven=false is an unverified candidate (the dataflow pass saw "
    "request data reach a resource but not the guard): read it and report it only if you "
    "confirm the access is really unguarded.\n"
    "  - read_file / grep: read related code to judge intent.\n\n"
    "If list_handlers() is empty, Frame has no symbolic model for this language: "
    "enumerate the entry points yourself with grep/read_file (route decorators, "
    "controllers, request handlers) and reason about them from the source. Such findings "
    "cannot be engine-backed, so set engine_backed=false.\n\n"
    "Work systematically: enumerate handlers, focus on those that reach a resource and "
    "are NOT protected, read their code, and decide whether a real authorization or "
    "business-logic violation exists. A handler that is public by design (login, signup, "
    "health, a public catalog) is NOT a finding. When unsure, do not report.\n\n"
    "Report each finding the MOMENT you are confident by calling report_finding(handler, "
    "file, line, mechanism, cwe, confidence, engine_backed, reasoning) -- then move on to "
    "the next handler. Do NOT save them for one JSON dump at the end; report as you go so no "
    "work is lost. Set engine_backed true only when a handler_facts/list_handlers fact "
    "supports the mechanism (it reaches a resource and is not protected). A wrong finding is "
    "worse than no finding. When you have audited the handlers and reported every real one, "
    "stop: reply with a one-line summary and NO tool call. (You may also restate them as a "
    "final JSON object {\"findings\": [...]}, but report_finding is what counts.)"
)

# How the hunting mechanisms map to a CWE when the model does not give a usable one.
_MECH_CWE = {"missing_authorization": "CWE-862", "idor": "CWE-639",
             "privilege_escalation": "CWE-269", "mass_assignment": "CWE-915",
             "business_logic": "CWE-840"}
_AUTHZ_MECHANISMS = {"missing_authorization", "idor", "privilege_escalation"}


def _corroborated(f: Dict[str, Any], index: EngineIndex) -> bool:
    """An engine fact supports the claimed mechanism: the named handler reaches a
    resource operation and is not protected (so the access really is un-gated /
    un-scoped). The model's own `engine_backed` flag is necessary but not trusted on
    its own -- we check the fact."""
    h = index.handler(str(f.get("handler", "")), f.get("file"))
    if h is None or h.provided_by:      # the engine has no facts about framework-provided code
        return False
    if not (h.reaches_resource and not h.protected):
        return False
    return bool(f.get("engine_backed"))


def _to_vuln(f: Dict[str, Any], index: EngineIndex, verified: bool):
    from frame.sil.scanner import Vulnerability, Severity
    from frame.sil.translator import VulnType
    mech = str(f.get("mechanism", "")).strip().lower()
    cwe = str(f.get("cwe") or "").strip() or _MECH_CWE.get(mech, "")
    if not cwe.upper().startswith("CWE-"):
        cwe = _MECH_CWE.get(mech, "")
    if not cwe:
        return None
    vt = next((c for c in VulnType if c.value == mech), None) or \
        getattr(VulnType, "MISSING_AUTHORIZATION", getattr(VulnType, "TAINT_FLOW", list(VulnType)[0]))
    try:
        line = int(f.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    try:
        conf = float(f.get("confidence", 0.6))
    except (TypeError, ValueError):
        conf = 0.6
    h = index.handler(str(f.get("handler", "")), f.get("file"))
    rel = str(f.get("file") or "") or (h.file if h is not None else "")
    path = os.path.join(index.repo_root, rel) if index.repo_root and not os.path.isabs(rel) else rel
    tier = "llm_verified" if verified else "llm_detect"
    return Vulnerability(
        type=vt, severity=Severity.HIGH if verified else Severity.MEDIUM,
        location=path, line=(h.line if (h is not None and not line) else line), column=0,
        description=("[LLM-verified] " if verified else "[LLM-detected] ") + str(f.get("reasoning", ""))[:200],
        procedure="<llm-hunt>", source_var=tier,
        confidence=min(conf, 0.9 if verified else 0.7),
        cwe_id=cwe.upper(), evidence=("llm-verified" if verified else "llm-detected"))


# Vulnerability classes the hunt is about (authorization / business logic). The dedup against
# the symbolic engine must be scoped to THESE: an XSS or log-injection the engine already proved
# in a handler says nothing about whether its authorization is broken, so it must not suppress an
# IDOR the hunt found in the same function (this dropped the real wger nutritional_values IDOR,
# which shared a function with a symbolic XSS).
_AUTHZ_CWES = AUTHZ_CWES


def _engine_already_proved_authz(h) -> bool:
    # Only a solver-verified proof suppresses: an unverified candidate the agent confirms is
    # the agent's finding (this dropped the real weblate UserViewSet.notifications report).
    return any(str(p.get("cwe", "")).upper() in _AUTHZ_CWES and p.get("proven")
               for p in (getattr(h, "proven", None) or []))


def _findings_to_vulns(findings: list, index: EngineIndex) -> list:
    out = []
    emitted: set = set()
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        key = _finding_key(f)
        if key in emitted:                       # a collected finding the final JSON repeats
            continue
        # Do not re-report an authorization flaw the engine already PROVED at this handler --
        # but only an authorization-class proof suppresses it (see _AUTHZ_CWES), never an
        # unrelated finding (XSS, log injection) that happens to sit in the same function.
        h = index.handler(str(f.get("handler", "")), f.get("file"))
        if h is not None and _engine_already_proved_authz(h):
            continue
        v = _to_vuln(f, index, _corroborated(f, index))
        if v is not None:
            emitted.add(key)
            out.append(v)
    return out


def hunt_authz(programs, symbolic_findings: Optional[list], repo_root: str,
               config: LLMConfig, client: Optional[LLMClient] = None,
               max_steps: Optional[int] = None, language: str = "",
               dynamic: bool = False, interpreter: Optional[str] = None,
               status: Optional[Dict[str, Any]] = None,
               max_units: Optional[int] = None, unit_steps: Optional[int] = None,
               concurrency: Optional[int] = None, verdict_cache: Optional[str] = None,
               scout_steps: Optional[int] = None, max_scouts: Optional[int] = None) -> list:
    """Run the agentic authorization / business-logic hunt. `programs` is the project's
    translated programs (one per file), a single program, or None.

    Where Frame has a frontend for the language it runs in UNITS (frame/sil/hunt_units.py). First
    SCOUTS explore: the repository is split into areas (a monorepo's packages, a large app's
    directories; `max_scouts` agents of `scout_steps` each, in parallel), and each scout lists the
    routes, data-touching service functions and authorization helpers of its area, and teaches the
    engine an entry point for any route convention it does not see (a pack, validated and applied
    at once). Then the units: the engine's handlers and service layer, plus every scouted function
    the engine still does not cover, grouped into small units, ranked, and audited by a fresh agent
    each -- in parallel, `concurrency` at a time, `unit_steps` each, the `max_units` best first --
    with the engine as a tool (frame/sil/hunt_tools.py) and a verdict required on every member.
    Then a coverage wave: code at least `[hunt] coverage_readers` units read and no unit owns (a
    helper or service the verdicts relied on) gets a unit of its own. A
    corroborated claim is tiered `llm_verified`, an intent-only one `llm_detect` (always for code
    only a scout found). Where there is no frontend for the language, one agent hunts the
    repository with grep/read_file instead, and every finding is `llm_detect`.

    `verdict_cache` (a JSON path shared by two checkouts of one repository) reuses a unit's
    verdicts when every file its agent read is unchanged. With `dynamic`, the agents also get
    run_code to confirm a candidate flaw by exercising the app (off by default: a scan never runs
    model-authored code unless asked). `max_steps`, when given, is the per-agent step budget.

    `status`, when given, is filled with how the hunt ended (`stop`: finished / partial / budget
    / transport_error / exception / no_targets, LLM call and error counts, and in unit mode the
    route map's files, every unit with its verdicts, and the profile), so a hunt that died on a
    dropped connection is distinguishable from one that looked and found nothing.
    """
    if status is None:
        status = {}
    status["stop"] = "no_targets"
    index = build_index(programs, symbolic_findings, repo_root)
    has_programs = bool(programs) if isinstance(programs, (list, tuple)) else programs is not None
    scouting = (scout_steps if scout_steps is not None else _hunt_setting("scout_steps")) > 0
    if index.handlers or index.service_functions or index.authz_gates or index.soundness_leads or \
            (has_programs and scouting and bool(repo_root) and os.path.isdir(repo_root)):
        # A blind engine (no handler at all) still has a frontend: the scouts find the routes.
        return _hunt_units(index, programs, symbolic_findings, repo_root, config, client,
                           language=language, dynamic=dynamic, interpreter=interpreter,
                           status=status, max_units=max_units,
                           unit_steps=unit_steps if unit_steps is not None else max_steps,
                           concurrency=concurrency, verdict_cache=verdict_cache,
                           scout_steps=scout_steps, max_scouts=max_scouts)
    return _hunt_single(index, repo_root, config, client, max_steps, language, dynamic,
                        interpreter, status)


def _hunt_single(index: EngineIndex, repo_root: str, config: LLMConfig,
                 client: Optional[LLMClient], max_steps: Optional[int], language: str,
                 dynamic: bool, interpreter: Optional[str], status: Dict[str, Any]) -> list:
    """One agent over the whole repository: the fallback where the engine has no handler facts
    (a language without a frontend), so there is nothing to divide into units."""
    if client is None:
        client = LLMClient(config)
    if index.handlers:
        intro = "Handlers (from the engine):\n" + json.dumps(
            [{"name": h.name, "file": h.file, "line": h.line, "protected": h.protected,
              "reaches_resource": h.reaches_resource} for h in index.handlers])
    elif repo_root and os.path.isdir(repo_root):
        inv = _repo_inventory(os.path.realpath(repo_root), language)
        if not inv.strip():
            return []
        intro = ("No engine handler facts for this language -- enumerate entry points "
                 "yourself with grep/read_file. Source files:\n" + inv)
    else:
        return []
    # Engine-found authorization-decision functions with an under-constrained grant: the real
    # authorization logic often lives in such a helper, not the route handler, so these are the
    # highest-value starting points -- read each and decide whether the unscoped grant is a real
    # bypass or a legitimate public path.
    leads = ""
    if index.soundness_leads:
        leads = ("\n\nENGINE AUTHORIZATION-SOUNDNESS LEADS (investigate these FIRST -- each grants "
                 "access on a path that does not bind the resource to the caller; confirm whether "
                 "that is a real cross-user bypass or an intended public path):\n" + json.dumps(
                     [{"name": x["name"], "file": x["file"], "line": x["line"]}
                      for x in index.soundness_leads]))
    # Service / helper layer: the functions a handler delegates data access to, where the real
    # authorization enforcement often lives (NOT the route handler). A handler can look protected
    # (a master-key / session gate) while the shared function it calls enforces access unsoundly --
    # the route-handler-centric suspect list misses this entirely. Lead with the ones that touch a
    # resource but never bring the caller's identity into scope: a shared data operation with no
    # principal binding is the prime broken-access-control shape.
    svc = ""
    if index.service_functions:
        unscoped = [s for s in index.service_functions if not s["scoped"]]
        ranked = (unscoped + [s for s in index.service_functions if s["scoped"]])[:20]
        svc = ("\n\nSERVICE-LAYER FUNCTIONS (not route handlers, but they touch a resource -- the "
               "shared layer handlers delegate to, where access enforcement often lives). Audit "
               "whether each binds the resource to the authenticated caller; the ones marked "
               "scoped=false perform a data operation with NO caller identity in scope and are the "
               "highest-value targets -- follow the handlers' calls into them:\n" + json.dumps(ranked))
    # Enforcement points: functions a resource handler delegates the access CHECK to (they decide
    # on their inputs and touch no resource). The flaw that lives here is an INCOMPLETE gate -- a
    # class, operation, object type or role it forgets to cover -- which has no dataflow, so the
    # symbolic engine cannot see it; only an intent-aware read can. This is exactly the shape a
    # route-handler-centric hunt (and a dataflow scanner) miss.
    gates = ""
    if index.authz_gates:
        gates = ("\n\nENFORCEMENT POINTS (the resource handlers delegate the access CHECK to these "
                 "-- each decides on its own inputs and touches no resource, e.g. a "
                 "require-permission / assert-can-access / enforce-* helper). The highest-value "
                 "bug here is INCOMPLETE enforcement: a class, collection, operation, object type "
                 "or role the gate FORGETS to cover, letting an attacker reach a resource through "
                 "the uncovered case. Read each one and ask what it does NOT guard that its peers "
                 "do:\n" + json.dumps(index.authz_gates[:20]))
    dyn = ("\n\nYou can also run_code: when you suspect an IDOR or broken access control but the "
           "code is ambiguous, CONFIRM it by exercise -- write a short probe that drives the app's "
           "own test client as two users and checks whether one reaches the other's resource. A "
           "finding you confirmed by running code is far stronger than one argued from source."
           ) if dynamic else ""
    # The system prompt + this engine-facts intro are the STABLE prefix of a long tool loop
    # (re-sent unchanged every turn). A `cache_control` breakpoint on the last stable block
    # lets a provider that honours it read the whole prefix from cache after the first turn
    # (OpenRouter -> Claude: ~90% cheaper, measured); a provider that doesn't (OptiQ/DeepSeek)
    # accepts the block form and ignores the hint. The growing tool-call tail stays uncached,
    # and `_compact_messages` keeps this prefix whole, so the cache key is stable across turns.
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": HUNT_SYSTEM},
        {"role": "user", "content": [{"type": "text", "text": (
            intro + leads + gates + svc + "\n\nHunt for authorization and business-logic flaws. Use the "
            "engine facts (if any), handler_facts and read_file to judge intent, and call "
            "report_finding for each real finding as you confirm it." + dyn),
            "cache_control": {"type": "ephemeral"}}]},
    ]
    collected: List[Dict[str, Any]] = []
    # Durable trace + resume (opt-in via `[hunt] trajectory_dir`). A saved trace lets an
    # interrupted hunt continue from its last step instead of restarting.
    trace, messages = _setup_trace(repo_root, messages)
    steps = max_steps if max_steps is not None else max(1, getattr(config, "hunt_max_steps", 200))

    def _finalize(content: str) -> list:
        # The accumulated findings are the source of truth; a final JSON (if the model still
        # emits one) only supplements with anything it reported there but never via the tool.
        final = (_extract_json_object(content) or {}).get("findings") or []
        return _findings_to_vulns(collected + list(final), index)

    # Finish-gate: on big apps the agent reports its findings early (observed: all by step 21)
    # then spins to the step budget re-grepping without finding anything new. Once it has gone
    # QUIET -- no new finding for `quiet` steps -- gently let it wrap up. CRITICAL: only after it
    # has reported at least one finding. An agent that has found nothing yet must keep looking,
    # never be told it is done (a v4 gate that fired at step 33 with zero reports made the agent
    # quit with 0 findings -- a recall regression). Thrashing is cheap (prompt cache ~95%), so the
    # gate only trims the tail after findings are in; it never risks cutting the search short, and
    # the step budget stays the ceiling. Cooldown so it fires at most every `quiet` steps.
    quiet = max(10, min(40, steps // 6))
    _gate = {"n_at": 0, "last_report": 0, "last_fire": 0}
    suspects = [h.name for h in index.handlers if h.reaches_resource and not h.protected][:20]

    def _step_hook(step: int) -> Optional[str]:
        if len(collected) != _gate["n_at"]:           # a new finding landed -> reset the quiet clock
            _gate["n_at"] = len(collected)
            _gate["last_report"] = step
        if not collected:                             # found nothing yet -> keep hunting, never stop
            return None
        if step - _gate["last_report"] < quiet or step - _gate["last_fire"] < quiet:
            return None
        _gate["last_fire"] = step
        tail = (" The unprotected handlers that reach a resource are the only ones that can be an "
                "authorization flaw; make sure you have checked each: "
                + ", ".join(suspects) + ".") if suspects else ""
        return (f"You have reported {len(collected)} finding(s) and found nothing new in the last "
                f"{quiet} steps. If any relevant handler is still UNCHECKED, audit it now. "
                f"Otherwise you are done: reply with a one-line summary and no tool call -- do not "
                f"keep re-grepping code you have already read." + tail)

    try:
        res = run_agent(
            messages, client, tools=hunt_tools(dynamic),
            exec_tool=hunt_exec(index, collected, dynamic=dynamic, interpreter=interpreter),
            max_steps=steps, finalize=_finalize, step_hook=_step_hook,
            final_nudge=("This is your LAST turn. Do NOT say you will report -- report NOW. For "
                         "every finding you have not yet reported, call report_finding this turn "
                         "(one call per finding). If you have already reported them all, reply "
                         "'done'. Any finding you only describe in prose is lost."),
            compact_at_chars=getattr(config, "agent_context_budget_chars", 80000),
            trace=trace,
            # Every investigation tool is read-only and idempotent, so an identical repeat is pure
            # waste (observed: read_file on one file 8x). Refuse repeats. report_finding is NOT here:
            # it is side-effecting and dedupes itself by (handler, file, line).
            dedupe_tools={"list_handlers", "handler_facts", "engine_findings", "read_file", "grep"})
    except Exception as exc:
        # Interrupted (an external hard timeout, a transport failure): the findings reported via
        # report_finding are already in `collected`, so salvage them instead of losing the whole
        # run. This is why the agent reports incrementally -- a cut-off run still returns what it
        # found, with no second time budget to coordinate.
        stats = getattr(client, "stats", None) or {}
        status.update(stop="exception", error=type(exc).__name__, reported=len(collected),
                      llm_calls=stats.get("calls", 0), llm_errors=stats.get("errors", 0))
        return _findings_to_vulns(collected, index)
    stats = getattr(client, "stats", None) or {}
    status.update(stop=res.stop or ("finished" if res.done else "budget"), steps=res.steps,
                  reported=len(collected), llm_calls=stats.get("calls", 0),
                  llm_errors=stats.get("errors", 0))
    return res.result or []


# ---- Unit mode: the engine assigns the work, one fresh agent per unit ------------------------

UNIT_SYSTEM = (
    "You are auditing ONE unit of an application -- a few related handlers, or the service "
    "functions and authorization helpers they delegate to -- for AUTHORIZATION and "
    "BUSINESS-LOGIC flaws: broken object-level authorization (IDOR/BOLA), missing "
    "function-level authorization, privilege escalation, mass assignment of privileged fields, "
    "and client control of values that must be server-authoritative (price, role, owner, "
    "workflow state). The unit's members are listed in the first message, with their source. "
    "You must leave a verdict on EVERY member.\n\n"
    "For each member:\n"
    "  1. Invariant: who should be allowed to do what to which object (the owner only, members "
    "of the project, admins, any signed-in user, anyone).\n"
    "  2. Enforcement: find the code that enforces it -- decorators, permission classes, "
    "middleware, the query's filter, a check in the service layer or a helper. Ask the engine "
    "instead of guessing: guards(name) lists the checks that hold on EVERY feasible path to its "
    "data access; check(name, line, kind, pattern) proves or refutes one; callees(name) follows "
    "it into the service layer; siblings(name) shows what the neighbouring handlers check -- a "
    "check they have and it lacks is the classic bug; trace(name) shows which request values "
    "reach which data access.\n"
    "  3. Falsify: try to build a request that violates the invariant -- who sends it, to which "
    "endpoint, with which ids, and what they must already have.\n"
    "  4. Verdict: report_finding (with the invariant and that request) if you can build one; "
    "otherwise mark_safe, naming what enforces it (or why it is public by design: login, "
    "signup, health, a public catalog). If, after looking for the check, the answer depends on "
    "something the repository does not hold (a configuration value, the roles a deployment "
    "assigns, a library's behaviour), use mark_unresolved: the suspected flaw, where you looked, "
    "and the fact that would decide it. A person reads those; a confident 'safe' you could not "
    "back with a check hides the case from them.\n\n"
    "A member marked NOT WRITTEN IN THE CLASS is a request the framework serves for the class "
    "from a base class: it runs the framework's own code over the class attributes and hooks "
    "listed with it, so judge what a caller can reach through it from those (and from what the "
    "class overrides), exactly like a written handler.\n\n"
    "ENGINE CANDIDATES in the unit are unverified: the dataflow pass saw request data reach a "
    "data access but did not see the guard. Confirm each (report_finding) or refute it "
    "(mark_safe naming the guard). A claim you cannot turn into a concrete violating request is "
    "not a finding. When the code deliberately treats roles differently -- a branch that limits "
    "what a lower-privileged caller may change (e.g. non-admins may only edit some fields) -- that "
    "branch IS the policy: report only a request that gets past what it allows, not the fact that "
    "lower-privileged callers can do something. Read code with read_file and line ranges; grep "
    "with a path to stay focused. "
    "When every member has a verdict, reply with a one-line summary and no tool call."
)

UNIT_FINAL = ("This is your LAST turn. Record a verdict for every member that has none: "
              "report_finding (invariant + violating request), mark_safe (what enforces it) or "
              "mark_unresolved (what would decide it). "
              "Then reply 'done'. Anything you only describe in prose is lost.")

SCOUT_SYSTEM = (
    "You are a SCOUT mapping one area of an application before a security audit of its "
    "authorization. Auditors will audit exactly what gets mapped, so what you miss is never "
    "audited. Other scouts cover the rest of the repository; stay inside your area.\n\n"
    "  1. Find every ROUTE in your area: each function a remote caller reaches (HTTP routes, "
    "controller methods, RPC / GraphQL resolvers, websocket and webhook handlers), however this "
    "app registers them (decorators, base classes, router calls, a file-system convention, a "
    "routes table). Also the SERVICE functions that read or change stored data, and the "
    "authorization HELPERS (permission checks, ownership filters, access policies).\n"
    "  2. Record them with record_inventory (in batches). The engine's handlers in your area are "
    "listed in the first message; record those too only if you have something to add.\n"
    "  3. If routes you found are missing from the engine's list, the engine does not know how this "
    "app registers routes: TEACH it with teach(pack_toml, files) -- an [[entrypoint]] first (only "
    "an entry point makes a function a handler); sinks, gates and identity are secondary. The "
    "reply lists the new handlers: if there are none, your entrypoint did not match -- fix it and "
    "teach again (at most 3 packs).\n"
    "  4. End with finish_scout(summary): how callers are authenticated here, the access model, "
    "the helpers that enforce it, with names and files (at most ~10 lines).\n"
    "Use list_files and grep with a path to move fast; read code only to confirm."
)

# What a pack looks like, for teach(). Kept valid: tests/test_hunt_tools.py loads it.
PACK_GUIDE = '''[pack]
name = "app-conventions"
language = "python"                 # or "javascript" (TypeScript too)
description = "what this pack teaches"
detect = { imports = ["myapp"] }    # optional: only files importing one of these

# ROUTES FIRST: only an entry point makes a function a handler (and so a unit that is audited).
# Use the shape the app uses; names are as the code imports them (`*` globs a name):
# methods of classes extending a base class ...
[[entrypoint]]
extends = ["myapp.web.BaseHandler"]
method = ["get", "post", "_process*"]
params = "all"

# ... functions carrying a route decorator ...
[[entrypoint]]
decorator = ["myapp.routing.route"]
params = "all"

# ... or functions passed to a registration call (`router.get("/x", handler)`).
[[entrypoint]]
registered_via = ["myapp.routing.Router.get", "myapp.routing.Router.post"]
params = "all"

# A data access the engine does not know (an ORM wrapper / repository): reads are
# "resource_select", writes "resource_modify". `call` is the canonical call id
# (module.Class.method, as imported); `*` matches within a segment, `**` across.
[[sink]]
call = ["myapp.db.Repository.get", "myapp.db.Repository.find_*"]
kind = "resource_select"

[[sink]]
call = ["myapp.db.Repository.save", "myapp.db.Repository.delete"]
kind = "resource_modify"

# A decorator that authenticates / authorizes the handler it wraps.
[[auth_gate]]
decorator = ["myapp.auth.require_admin", "myapp.auth.login_required"]

# The authenticated caller, as the app exposes it (a module-level proxy).
[[identity]]
proxies = ["myapp.auth.current_user"]
'''


@dataclass
class _UnitRun:
    unit: Any
    collected: List[Dict[str, Any]] = field(default_factory=list)
    verdicts: Dict[str, str] = field(default_factory=dict)
    read: set = field(default_factory=set)
    ranges: Dict[str, List[Tuple[int, int]]] = field(default_factory=dict)   # file -> lines read
    unresolved: List[Dict[str, Any]] = field(default_factory=list)          # mark_unresolved entries
    stop: str = "not_run"
    steps: int = 0
    investigated: bool = False
    reused: bool = False
    error: str = ""


class _Stoppable:
    """A client whose calls stop at once when the hunt is interrupted (a timeout fires in the
    main thread while unit agents run in workers), and that counts the replies it got -- a unit
    whose agent got none never investigated anything."""

    def __init__(self, inner, stop):
        self._inner = inner
        self._stop = stop
        self.replies = 0

    def chat_raw(self, messages, tools=None):
        if self._stop.is_set():
            return None
        msg = self._inner.chat_raw(messages, tools)
        if msg is not None:
            self.replies += 1
        return msg

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _slug(text: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)[:120] or "unit"


def _unit_tools(dynamic: bool) -> list:
    from frame.sil.hunt_tools import UNIT_TOOLS
    return UNIT_TOOLS + ([RUN_CODE_TOOL] if dynamic else [])


def _unit_source(ctx, unit) -> str:
    """The unit's code, numbered, so the agent starts reading instead of searching. A class's
    attributes above its first method (permission_classes, queryset) are included."""
    from frame.sil.hunt_tools import read_file
    from frame.sil.hunt_units import class_of
    if not ctx.repo_root or not unit.files:
        return ""
    if unit.kind == "handlers":
        hs = unit.members
        lo = min(h.line for h in hs)
        hi = max(max(h.end_line or h.line, h.line) for h in hs)
        pre = 25 if class_of(hs[0].name) else 3
        a = max(1, lo - pre)
        if hi + 2 - a <= 320:
            ranges = [(a, hi + 2)]
        else:
            ranges = ([(a, lo)] if pre > 3 else []) + [
                (max(1, h.line - 2), min(max(h.end_line or h.line, h.line) + 2, h.line + 80)) for h in hs]
    else:
        ranges = [(max(1, int(m.get("line") or 1) - 2),
                   min(max(int(m.get("end_line") or 0), int(m.get("line") or 1) + 45),
                       int(m.get("line") or 1) + 120) + 2) for m in unit.members]
    parts: List[str] = []
    budget = 14000
    for a, b in ranges:
        txt = read_file(ctx.repo_root, unit.files[0], a, b, max_lines=400, max_chars=budget)
        if txt.startswith("ERROR"):
            break
        parts.append(txt)
        budget -= len(txt)
        if budget <= 600:
            break
    return "\n\n".join(parts)


_ROLE_TEXT = {
    "gate": "ENFORCEMENT POINT: handlers delegate the access CHECK here; look for a class, "
            "operation, object type or role it FORGETS to cover",
    "service": "SERVICE-LAYER FUNCTION: touches data; does it bind the object to the caller?",
    "soundness": "AUTHORIZATION-SOUNDNESS LEAD: grants access on a path that does not bind the "
                 "resource to the caller",
    "scouted_route": "ROUTE a remote caller reaches",
    "scouted_service": "SERVICE FUNCTION that reads or changes stored data: does it bind the object "
                       "to the caller?",
    "scouted_helper": "AUTHORIZATION HELPER: look for a case, role or object type it forgets",
}


def _unit_intro(ctx, unit, profile: str) -> str:
    rows: List[str] = []
    if profile:
        rows += ["APPLICATION PROFILE (from the scouts):", profile.strip()[:2500], ""]
    rows.append(f"UNIT: {unit.title}")
    if unit.reasons:
        rows.append("Selected because: " + "; ".join(unit.reasons))
    if unit.kind == "handlers":
        rows.append("\nHANDLERS (a verdict is required for EACH):")
        for h in unit.members:
            proc = (getattr(h.program, "procedures", {}) or {}).get(h.name) if h.program is not None else None
            decos = [a.name for a in (getattr(proc, "annotations", None) or [])]
            sinks = ", ".join(f"{s.get('kind')}@{s.get('line')}" for s in (h.sinks or [])[:8])
            if h.provided_by:
                cls = (getattr(h.program, "class_info", None) or {}).get(h.name.rsplit(".", 1)[0])
                set_here = [a for a in h.decided_by if a in (getattr(cls, "fields", None) or [])]
                rows.append(f"- {h.name}  ({h.file}:{h.line}, the class)  NOT WRITTEN IN THE CLASS: "
                            f"inherited from {h.provided_by}, served by the framework's own code. "
                            f"What it may touch is decided by: {', '.join(h.decided_by)}"
                            + (f" (set in the class: {', '.join(set_here)}; the others are the base's"
                               f" defaults or methods above)" if set_here else
                               " (none set in the class itself)"))
                continue
            rows.append(f"- {h.name}  ({h.file}:{h.line}-{h.end_line or h.line})  "
                        f"protected={h.protected}  reaches_data={h.reaches_resource}"
                        + (f"  decorators={decos}" if decos else "")
                        + (f"  sinks=[{sinks}]" if sinks else ""))
    elif unit.kind == "scouted":
        rows.append("\nFOUND BY THE SCOUTS -- no engine facts (no pack describes this code yet), so read "
                    "it; a verdict is required for EACH:")
        for m in unit.members:
            rows.append(f"- {m['name']}  ({m['file']}:{m['line'] or '?'})  "
                        f"[{_ROLE_TEXT.get(m.get('role'), m.get('role'))}]"
                        + (f"  ({m['reason']})" if m.get("reason") else ""))
    elif unit.kind == "coverage":
        rows.append("\nCODE OTHER UNITS RELIED ON -- their agents read it to decide their own verdicts, "
                    "but no unit audited it. Judge it on its own: what it allows, and which class, "
                    "operation, role or object it forgets to cover or fails to bind to the caller. "
                    "A verdict is required for EACH:")
        for m in unit.members:
            rows.append(f"- {m['name']}  ({m['file']}:{m['line']}-{m.get('end_line') or m['line']})  "
                        f"({m.get('reason', '')})")
    else:
        rows.append("\nSERVICE-LAYER FUNCTIONS AND ENFORCEMENT POINTS (a verdict is required for EACH):")
        for m in unit.members:
            extra = ""
            if m.get("role") == "service":
                extra = "  scoped_to_caller=" + str(bool(m.get("scoped")))
            if m.get("reason"):
                extra += f"  ({m['reason']})"
            rows.append(f"- {m['name']}  ({m['file']}:{m['line']})  [{_ROLE_TEXT.get(m.get('role'), m.get('role'))}]"
                        + extra)
    if unit.candidates:
        rows.append("\nENGINE CANDIDATES (unverified; confirm with report_finding or refute with "
                    "mark_safe naming the guard):")
        for c in unit.candidates[:12]:
            rows.append(f"- {c.get('cwe')} {c.get('type')} at {c.get('file')}:{c.get('line')}")
    for lead in unit.leads[:6]:
        rows.append(f"\nLEAD: {lead.get('name')} ({lead.get('file')}:{lead.get('line')}) "
                    f"{lead.get('reason', '')}".rstrip())
    src = _unit_source(ctx, unit)
    if src:
        rows += ["\nSOURCE:", src]
    rows.append("\nAudit every member, using the engine tools to settle what reading alone cannot.")
    return "\n".join(rows)


def _run_unit(ctx, run: "_UnitRun", client, steps: int, profile: str, dynamic: bool,
              interpreter: Optional[str], stop) -> None:
    """One unit's agent, start to verdicts. Fills `run` in place, so what it reported survives
    an interruption."""
    from frame.sil.hunt_tools import READ_ONLY, match_member, repo_exec, verdict_exec
    unit = run.unit
    names = unit.names()
    run.verdicts = {n: "none" for n in names}
    run.read = set(unit.files)
    seen: set = set()
    vexec = verdict_exec(names, run.collected, run.verdicts, seen, _finding_key, run.unresolved)

    def harvest(content: str) -> None:
        # Findings stated only in a final JSON object still count (a fallback, not the protocol).
        for f in ((_extract_json_object(content or "") or {}).get("findings") or []):
            if not isinstance(f, dict) or _finding_key(f) in seen:
                continue
            seen.add(_finding_key(f))
            run.collected.append(dict(f))
            m = match_member(names, str(f.get("handler") or ""))
            if m:
                run.verdicts[m] = "reported"

    def _exec(name: str, args: Dict[str, Any]) -> str:
        try:
            out = vexec(name, args)
            if out is not None:
                return out
            if name == "run_code":
                if not dynamic:
                    return "ERROR: run_code is not enabled"
                return sandbox_python(str(args.get("code") or ""), ctx.repo_root, timeout_s=60,
                                      interpreter=interpreter)
            out = repo_exec(ctx, name, args, run.read, run.ranges)
            return out if out is not None else "ERROR: unknown tool"
        except Exception as e:                       # a tool bug must not end the unit
            return f"ERROR: tool failed: {type(e).__name__}"

    nudges = {"n": 0}

    def on_final(content: str) -> Optional[str]:
        harvest(content)
        missing = [n for n in names if run.verdicts.get(n) == "none"]
        if missing and nudges["n"] < 2 and not stop.is_set():
            nudges["n"] += 1
            return ("Not done: these members of the unit have no verdict yet: " + ", ".join(missing)
                    + ". For each, call report_finding (with the invariant and a violating "
                    "request), mark_safe (with what enforces it) or mark_unresolved (with the fact "
                    "that would decide it).")
        return None

    def finalize(content: str) -> list:
        harvest(content)
        return run.collected

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": UNIT_SYSTEM},
        {"role": "user", "content": [{"type": "text", "text": _unit_intro(ctx, unit, profile),
                                      "cache_control": {"type": "ephemeral"}}]},
    ]
    trace, messages = _setup_trace(ctx.repo_root, messages, sub="units/" + _slug(unit.id))
    res = run_agent(messages, client, tools=_unit_tools(dynamic), exec_tool=_exec,
                    max_steps=steps, finalize=finalize, on_final=on_final, final_nudge=UNIT_FINAL,
                    compact_at_chars=getattr(ctx, "compact_at", None), trace=trace,
                    dedupe_tools=READ_ONLY)
    run.stop = res.stop or ("finished" if res.done else "budget")
    run.steps = res.steps


def _scout_intro(ctx, area) -> str:
    """One scout's first message: its area, the engine's coverage there, the pack format."""
    from collections import Counter
    hs = [h for h in ctx.index.handlers if any(a.holds(h.file) for a in area)]
    files = sum(a.files for a in area)
    packs = sorted({getattr(p, "name", str(p)) for prog in ctx.programs
                    for p in (getattr(prog, "active_packs", None) or [])})
    by_file = Counter(h.file for h in hs).most_common(25)
    rows = [f"Language: {ctx.language or 'unknown'}",
            f"Framework packs the engine applied: {', '.join(packs) or 'none'}",
            "YOUR AREA: " + ", ".join(a.label() for a in area) + f"  ({files} source files)",
            f"Engine handlers in your area: {len(hs)} "
            f"(reaching data {sum(1 for h in hs if h.reaches_resource)}, "
            f"protected {sum(1 for h in hs if h.protected)})"]
    if by_file:
        rows.append("By file: " + ", ".join(f"{f} ({c})" for f, c in by_file))
    if len(hs) < max(1, files // 20):
        rows.append(f"BLIND SPOT: the engine sees only {len(hs)} handler(s) in {files} files. If this "
                    "area has routes, the engine does not know how they are registered: record them "
                    "and teach an [[entrypoint]].")
    rows.append("\nPack format for teach():\n" + PACK_GUIDE)
    rows.append("Scout your area, record what you find, teach the engine its route convention if it "
                "is blind, then finish_scout.")
    return "\n".join(rows)


def _run_scout(ctx, area, client, steps: int, holder: Dict[str, Any]) -> str:
    """One scout, start to summary. Fills `holder` (items, summary, teaches) in place, so what it
    recorded survives an interruption."""
    from frame.sil.hunt_tools import READ_ONLY, SCOUT_TOOLS, repo_exec

    def _exec(name: str, args: Dict[str, Any]) -> str:
        try:
            if name == "record_inventory":
                return ctx.record_inventory(args.get("items"), holder["items"], area)
            if name == "finish_scout":
                holder["summary"] = str(args.get("summary") or "")[:2000]
                return "Recorded. Reply 'done' with no tool call."
            if name == "teach":
                if holder["teaches"] >= 3:
                    return "Teaching budget used (3 packs). Record what you found and finish_scout."
                holder["teaches"] += 1
                files = args.get("files") or []
                return ctx.teach(str(args.get("pack_toml") or ""),
                                 files if isinstance(files, list) else [str(files)])
            out = repo_exec(ctx, name, args)
            return out if out is not None else "ERROR: unknown tool"
        except Exception as e:
            return f"ERROR: tool failed: {type(e).__name__}"

    def finalize(content: str) -> str:
        return holder["summary"] or (content or "").strip()[:2000]

    messages: List[Dict[str, Any]] = [{"role": "system", "content": SCOUT_SYSTEM},
                                      {"role": "user", "content": _scout_intro(ctx, area)}]
    label = "+".join(a.path or "root" for a in area)
    trace, messages = _setup_trace(ctx.repo_root, messages, sub=f"scout/{_slug(label)}")
    res = run_agent(messages, client, tools=SCOUT_TOOLS, exec_tool=_exec, max_steps=steps,
                    finalize=finalize, trace=trace, dedupe_tools=READ_ONLY,
                    final_nudge="This is your LAST turn: record_inventory anything not yet recorded, "
                                "then finish_scout with your summary.")
    holder["summary"] = holder["summary"] or (res.result or "")
    return res.stop or ""


def _def_line(repo_root: str, file: str, name: str) -> int:
    """Where a scouted function a frontend did not record is defined, read from the file: its
    `def` / `function` / method / `name = (...) =>` line. Placement only (it decides which
    lines the unit's agent is shown), never a fact about the code."""
    import re
    simple = re.escape(name.split("::")[-1].split("#")[0].rsplit(".", 1)[-1])
    if not simple:
        return 0
    pat = re.compile(rf"^\s*(?:export\s+)?(?:async\s+)?(?:def|function\*?|class)\s+{simple}\b|"
                     rf"^\s*(?:public|private|protected|static|async|\s)*{simple}\s*\(|"
                     rf"\b{simple}\s*[:=]\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_]\w*\s*=>)")
    try:
        with open(os.path.join(repo_root, file), encoding="utf-8", errors="replace") as fh:
            for i, ln in enumerate(fh, 1):
                if pat.search(ln):
                    return i
    except OSError:
        pass
    return 0


def _scouted_members(ctx, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Scout items as unit members, placed where the code is: the frontend's procedure when it
    recorded one (its real extent), else the scout's line or the definition read from the file."""
    from frame.sil.hunt_units import proc_end_line
    roles = {"route": "scouted_route", "service": "scouted_service", "helper": "scouted_helper"}
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for it in items:
        key = (it["file"], it["function"])
        if key in seen:
            continue
        seen.add(key)
        loc = ctx.locate(it["function"], it["file"])
        if loc is not None and loc.get("file") == it["file"]:
            line, end = int(loc["line"] or 0), int(loc["end_line"] or 0)
        else:
            line = int(it.get("line") or 0) or _def_line(ctx.repo_root, it["file"], it["function"])
            end = 0
        out.append({"name": it["function"], "file": it["file"], "line": line,
                    "end_line": end or (line + 40 if line else 0),
                    "role": roles.get(it["kind"], "scouted_route"), "reason": it.get("note", "")})
    return out


def _scout_pass(ctx, new_client, steps: int, max_scouts: int, concurrency: int, stop,
                status: Dict[str, Any]) -> tuple:
    """The scouts: (profile, unit members for what they found). Areas from the repository
    layout (hunt_units.scout_areas), one agent each, in parallel; teaching applies to the shared
    engine at once, so the units planned after see the conventions the scouts taught."""
    from collections import Counter
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from frame.sil.hunt_units import scout_areas
    areas = scout_areas(ctx.repo_root, ctx.language, max_scouts=max_scouts)
    holders = [{"items": [], "summary": "", "teaches": 0, "stop": "not_run", "area": a} for a in areas]

    def run(h: Dict[str, Any]) -> None:
        if stop.is_set():
            h["stop"] = "cancelled"
            return
        try:
            h["stop"] = _run_scout(ctx, h["area"], new_client(), steps, h)
        except Exception as exc:
            h["stop"] = f"exception:{type(exc).__name__}"

    if len(holders) <= 1 or concurrency <= 1:
        for h in holders:
            run(h)
    else:
        pool = ThreadPoolExecutor(max_workers=min(concurrency, len(holders)))
        try:
            for fut in as_completed([pool.submit(run, h) for h in holders]):
                fut.result()
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
    items = [it for h in holders for it in h["items"]]
    members = _scouted_members(ctx, items)
    parts = [(", ".join(a.path or "." for a in h["area"]), h["summary"].strip())
             for h in holders if h["summary"].strip()]
    profile = parts[0][1] if len(parts) == 1 else "\n".join(f"[{lbl}] {txt}" for lbl, txt in parts)
    status["scout"] = {
        "scouts": len(holders),
        "areas": [{"path": a.path, "files": a.files, "own_only": a.own_only}
                  for h in holders for a in h["area"]],
        "stops": dict(Counter(h["stop"] for h in holders)),
        "inventory": dict(Counter(it["kind"] for it in items)),
        "teaches": sum(h["teaches"] for h in holders)}
    return profile[:4000], members


def _hunt_setting(key: str):
    """A `[hunt]` setting for an option the caller left unset (config file, else default)."""
    from frame import config
    return config.setting("hunt", key)


def _client_stats(clients: list) -> Dict[str, int]:
    seen: set = set()
    calls = errors = waits = 0
    for c in clients:
        inner = getattr(c, "_inner", c)
        if id(inner) in seen:
            continue
        seen.add(id(inner))
        st = getattr(inner, "stats", None) or {}
        calls += int(st.get("calls", 0) or 0)
        errors += int(st.get("errors", 0) or 0)
        waits += int(st.get("outage_waits", 0) or 0)
    # outage_waits: retries spent waiting for an unreachable endpoint (LLMConfig.outage_wait). A
    # hunt that did not finish after any is outage damage, even when the cap cancelled it.
    return {"llm_calls": calls, "llm_errors": errors, "outage_waits": waits}


def _member_place(unit, name: str) -> Dict[str, Any]:
    """Where a unit member is: {file, line}."""
    for m in unit.members:
        mname = m.name if hasattr(m, "name") else str(m.get("name", ""))
        if mname == name:
            return {"file": m.file if hasattr(m, "file") else m.get("file", ""),
                    "line": int((m.line if hasattr(m, "line") else m.get("line")) or 0)}
    return {"file": unit.files[0] if unit.files else "", "line": 0}


def _procs_by_file(ctx) -> Dict[str, List[Dict[str, Any]]]:
    """Every named procedure of the application's programs (not test code), by repo-relative file:
    what a coverage unit's members are chosen from."""
    from types import SimpleNamespace
    from frame.sil.hunt_tools import _program_file
    from frame.sil.hunt_units import _is_test_code
    out: Dict[str, List[Dict[str, Any]]] = {}
    for prog in ctx.programs:
        if _is_test_code(SimpleNamespace(program=prog), ctx.language):
            continue
        path = _program_file(prog, ctx.repo_root)
        for pname, proc in (getattr(prog, "procedures", {}) or {}).items():
            loc = getattr(proc, "loc", None)
            line = int(getattr(loc, "line", 0) or 0) if loc else 0
            if not path or not line or pname.startswith(("<", "$")):
                continue
            out.setdefault(path, []).append({"name": pname, "line": line,
                                             "end_line": proc_end_line(proc, line)})
    return out


def _coverage_wave(ctx, runs: List["_UnitRun"], planned: list, min_readers: int,
                   budget: Optional[int], used: int, status: Dict[str, Any]) -> tuple:
    """The coverage wave after the first: (units to run, units the max_units budget defers).
    Planned from what the first wave's agents actually read (hunt_units.coverage_units), and
    recorded in `status["coverage"]` with every file read that no unit owns, so what the hunt
    relied on but never judged is visible even when it gets no unit."""
    from frame.sil.hunt_units import _score, coverage_units
    owned = {f for u in planned for f in u.files}
    reads: Dict[str, Dict[str, List[Tuple[int, int]]]] = {}
    for r in runs:
        for f, rs in r.ranges.items():
            if f not in owned:
                reads.setdefault(f, {}).setdefault(r.unit.id, []).extend(rs)
    wave = coverage_units(reads, owned, _procs_by_file(ctx), min_readers)
    for u in wave:
        _score(u)
    wave.sort(key=lambda u: (-u.score, u.id))
    held: list = []
    if budget is not None and budget > 0:
        room = max(0, budget - used)
        wave, held = wave[:room], wave[room:]
    status["coverage"] = {
        "min_readers": min_readers,
        "read_unowned": sorted(({"file": f, "readers": len(by)} for f, by in reads.items()),
                               key=lambda x: (-x["readers"], x["file"]))[:200],
        "units": len(wave) + len(held), "deferred": len(held)}
    return wave, held


def _hunt_units(index: EngineIndex, programs, symbolic_findings, repo_root: str, config,
                client, *, language: str, dynamic: bool, interpreter: Optional[str],
                status: Dict[str, Any], max_units: Optional[int], unit_steps: Optional[int],
                concurrency: Optional[int], verdict_cache: Optional[str],
                scout_steps: Optional[int], max_scouts: Optional[int]) -> list:
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from frame.sil.hunt_tools import HuntContext, VerdictCache
    from frame.sil.hunt_units import plan_units

    progs = programs if isinstance(programs, (list, tuple)) else ([programs] if programs is not None else [])
    ctx = HuntContext(index, progs, repo_root, language, symbolic_findings)
    ctx.compact_at = getattr(config, "agent_context_budget_chars", None)
    stop = threading.Event()
    shared = client is not None          # an injected client (tests, the scanner's) runs units in turn
    steps = unit_steps or _hunt_setting("unit_steps")
    clients: List[Any] = []

    def new_client():
        inner = client if shared else LLMClient(config)
        if not shared:
            inner.abort = stop          # an outage wait ends when the hunt is interrupted
        c = _Stoppable(inner, stop)
        clients.append(c)
        return c

    conc = 1 if shared else max(1, concurrency or _hunt_setting("concurrency"))
    profile, scouted = "", []
    ssteps = _hunt_setting("scout_steps") if scout_steps is None else scout_steps
    if repo_root and os.path.isdir(repo_root) and ssteps > 0:
        try:
            profile, scouted = _scout_pass(ctx, new_client, ssteps,
                                           max_scouts or _hunt_setting("max_scouts"), conc, stop, status)
        except Exception as exc:            # interrupted before any unit ran
            status.update(stop="exception", error=type(exc).__name__, **_client_stats(clients))
            return []
    status["profile"] = (profile or "")[:3000]
    status["taught_packs"] = len(ctx.taught)
    _save_taught(ctx)

    budget = max_units if max_units is not None else _hunt_setting("max_units")
    units, deferred = plan_units(ctx.index, language, budget, scouted=scouted)
    if "scout" in status:
        status["scout"]["scouted_units"] = sum(1 for u in units + deferred if u.kind == "scouted")
        status["scout"]["scouted_members"] = sum(len(u.members) for u in units + deferred
                                                 if u.kind == "scouted")
    # The route map: files with an engine handler, plus files only a scout found routes in.
    status["map_files"] = sorted({h.file for h in ctx.index.handlers} |
                                 {f for u in units + deferred if u.kind == "scouted" for f in u.files})
    runs = [_UnitRun(u) for u in units]
    cache = VerdictCache(verdict_cache) if verdict_cache else None

    def run_one(run: _UnitRun) -> None:
        if stop.is_set():
            run.stop = "cancelled"
            return
        hit = cache.lookup(run.unit.id, ctx.repo_root) if cache is not None else None
        if hit:
            run.collected.extend(hit.get("findings") or [])
            run.verdicts = dict(hit.get("verdicts") or {})
            run.read = set(hit.get("read") or [])
            run.ranges = {f: [tuple(r) for r in rs] for f, rs in (hit.get("ranges") or {}).items()}
            run.unresolved = list(hit.get("unresolved") or [])
            run.reused = run.investigated = True
            run.stop = "reused"
            return
        c = new_client()
        try:
            _run_unit(ctx, run, c, steps, profile, dynamic, interpreter, stop)
        except Exception as exc:            # an interruption or a client fault: stop the hunt,
            run.stop, run.error = "exception", type(exc).__name__   # keep what was reported
            stop.set()
        finally:
            run.investigated = c.replies > 0
        if cache is not None and run.investigated and run.stop in ("finished", "budget"):
            cache.store(run.unit.id, ctx.repo_root, sorted(run.read), run.verdicts, run.collected,
                        run.ranges, run.unresolved)

    def run_wave(wave: List[_UnitRun]) -> Optional[BaseException]:
        try:
            if conc == 1:
                for r in wave:
                    run_one(r)
            else:
                pool = ThreadPoolExecutor(max_workers=conc)
                try:
                    for fut in as_completed([pool.submit(run_one, r) for r in wave]):
                        fut.result()
                finally:
                    pool.shutdown(wait=False, cancel_futures=True)
        except BaseException as exc:        # a timeout lands in the main thread: salvage
            stop.set()
            return exc
        return None

    interrupted = run_wave(runs)
    # Coverage is a condition of finishing, not a by-product: the code the first wave's agents
    # relied on and nobody owned gets units of its own before the hunt calls itself done.
    readers = _hunt_setting("coverage_readers")
    if interrupted is None and not stop.is_set() and readers > 0:
        wave, held = _coverage_wave(ctx, runs, units + deferred, readers, budget, len(units), status)
        deferred += held
        more = [_UnitRun(u) for u in wave]
        runs += more
        interrupted = run_wave(more)
    for r in runs:
        if r.stop == "not_run":
            r.stop = "cancelled"

    findings = [f for r in runs for f in r.collected]
    vulns = _findings_to_vulns(findings, ctx.index)
    rows = [{"id": r.unit.id, "kind": r.unit.kind, "files": r.unit.files, "handlers": r.unit.names(),
             "investigated": r.investigated, "reused": r.reused, "stop": r.stop, "steps": r.steps,
             "verdicts": r.verdicts, "findings": len(r.collected), "score": r.unit.score,
             "reasons": r.unit.reasons} for r in runs]
    unresolved = [{"unit": r.unit.id, **_member_place(r.unit, u["handler"]), **u}
                  for r in runs for u in r.unresolved]
    rows += [{"id": u.id, "kind": u.kind, "files": u.files, "handlers": u.names(),
              "investigated": False, "reused": False, "stop": "deferred", "steps": 0,
              "verdicts": {n: "none" for n in u.names()}, "findings": 0, "score": u.score,
              "reasons": u.reasons} for u in deferred]
    status.update(units=rows, deferred_units=len(deferred), reported=len(findings),
                  unresolved=unresolved,
                  steps=sum(r.steps for r in runs), **_client_stats(clients))
    if interrupted is not None or any(r.stop == "exception" for r in runs):
        err = interrupted if interrupted is not None else None
        status.update(stop="exception",
                      error=type(err).__name__ if err is not None else
                      next(r.error for r in runs if r.stop == "exception"))
    elif not runs:
        status["stop"] = "no_targets"
    elif not any(r.investigated for r in runs):
        status["stop"] = "transport_error"
    elif any(r.stop in ("transport_error", "cancelled") for r in runs):
        status["stop"] = "partial"
    else:
        status["stop"] = "finished"
    if interrupted is not None and not isinstance(interrupted, Exception):
        raise interrupted                   # KeyboardInterrupt / SystemExit are not ours to eat
    return vulns


def _trajectory_dir() -> str:
    """Where agent traces go (`[hunt] trajectory_dir`); empty when they are not kept."""
    from frame import config
    return config.setting("hunt", "trajectory_dir") or ""


def _save_taught(ctx) -> None:
    """Keep the packs the scouts taught next to the trace: they are the run's reusable
    output (drop one in .frame/packs and the next scan knows the convention without a model)."""
    tdir = _trajectory_dir()
    if not tdir or not ctx.taught_text:
        return
    os.makedirs(os.path.join(tdir, "scout"), exist_ok=True)
    for i, text in enumerate(ctx.taught_text, 1):
        try:
            with open(os.path.join(tdir, "scout", f"taught-{i}.toml"), "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError:
            pass


def _setup_trace(repo_root: str, messages: List[Dict[str, Any]], sub: str = ""):
    """When a trajectory directory is set (`[hunt] trajectory_dir`), return (TraceWriter, starting messages): a
    fresh trace keeps `messages`; an existing one is resumed when it is an INTERRUPTED run of
    the same prompt (its messages replace the fresh ones, dropping a trailing assistant
    tool-call with no result so the sequence stays valid). Otherwise (None, messages). `sub`
    puts the trace in a subdirectory (one per unit agent, `units/<unit>`, and `profile` for the
    mapping pass).

    A trace that ended in a final answer, or was made with another system prompt, is not
    resumed: it is kept beside the new one as `hunt.<n>.jsonl` and the agent starts fresh.
    Resuming a finished conversation sends a request that ends with the assistant's turn,
    which Claude 5 models reject as a prefill (HTTP 400 on every call, so the unit never ran);
    resuming another prompt's conversation would silently skip the prompt change."""
    tdir = _trajectory_dir()
    if not tdir:
        return None, messages
    if sub:
        tdir = os.path.join(tdir, sub)
        os.makedirs(tdir, exist_ok=True)
    path = os.path.join(tdir, "hunt.jsonl")
    prior: List[Dict[str, Any]] = []
    if os.path.isfile(path) and os.path.getsize(path) > 0:
        try:
            _, prior = read_stf(path)
        except (OSError, ValueError):
            prior = []
        while prior and prior[-1].get("role") == "assistant" and prior[-1].get("tool_calls"):
            prior.pop()                 # interrupted mid-tool -> re-derive from the last clean turn
        if not _resumable(prior, messages):
            _archive_trace(path)
            prior = []
    writer = TraceWriter(path, session_id="authz-hunt", name="Frame authorization hunt")
    if writer.resumed and prior:
        messages = prior
    return writer, messages


def _resumable(prior: List[Dict[str, Any]], fresh: List[Dict[str, Any]]) -> bool:
    """An interrupted run of the same prompt: same system message, and it did not end with the
    assistant's final answer (an assistant turn without tool calls)."""
    if len(prior) < 2:
        return False
    if fresh and fresh[0].get("role") == "system" and prior[0].get("content") != fresh[0].get("content"):
        return False
    return prior[-1].get("role") != "assistant"


def _archive_trace(path: str) -> None:
    """Move a trace (and its call log) aside as hunt.<n>.jsonl, the first free n."""
    base = path[:-len(".jsonl")]
    n = 1
    while os.path.exists(f"{base}.{n}.jsonl"):
        n += 1
    for suffix in ("", ".calls.jsonl"):
        src = path + suffix
        if os.path.exists(src):
            try:
                os.replace(src, f"{base}.{n}.jsonl{suffix}")
            except OSError:
                pass
