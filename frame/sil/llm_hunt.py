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
from typing import Any, Callable, Dict, List, Optional

from frame.sil.llm_client import LLMClient, LLMConfig, _extract_json_object
from frame.sil.llm_agent import run_agent, INVESTIGATION_TOOLS, _repo_exec
from frame.sil.llm_detect import _repo_inventory


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


@dataclass
class EngineIndex:
    """The sound facts the hunting agent reasons over: the handlers and what Frame
    already proved. Built from a translated program; carries no model state."""
    handlers: List[HandlerFact] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)    # [{file, line, cwe, type}]
    repo_root: str = ""

    def handler(self, name: str) -> Optional[HandlerFact]:
        name = (name or "").strip()
        for h in self.handlers:
            if h.name == name or h.name.rsplit("::", 1)[-1].rsplit(".", 1)[-1] == name:
                return h
        return None


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
        findings.append({"file": _rel(getattr(v, "location", "") or "", repo_root),
                         "line": getattr(v, "line", 0), "cwe": getattr(v, "cwe_id", None),
                         "type": getattr(getattr(v, "type", None), "value", str(getattr(v, "type", "")))})
    idx.findings = findings

    for program in progs:
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
            span = getattr(proc, "span", None) if proc is not None else None
            start = loc.line if loc is not None else 0
            end = span[1] if (span and len(span) == 2) else start
            f = loc.file if loc is not None else ""
            rel = _rel(f, repo_root)
            in_range = [s for s in sinks_by_file.get(f, []) if start <= s["line"] <= (end or start)]
            proven = [x for x in findings if x["file"] == rel and start <= (x["line"] or 0) <= (end or start)]
            idx.handlers.append(HandlerFact(
                name=name, file=rel, line=start, end_line=end or start,
                protected=bool(protected), reaches_resource=bool(reaches),
                sinks=in_range, proven=proven))
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
        "description": "Every vulnerability Frame's symbolic engine has already proved (file, line, "
                       "cwe, type). Do not re-report these; build on them.",
        "parameters": {"type": "object", "properties": {}}}},
]

HUNT_TOOLS = ENGINE_TOOLS + INVESTIGATION_TOOLS


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


def hunt_exec(index: EngineIndex) -> Callable[[str, Dict[str, Any]], str]:
    """Executor for the hunting tools: engine-fact tools over `index`, plus the shared
    read_file / grep over the repository."""
    def _exec(name: str, args: Dict[str, Any]) -> str:
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
            return json.dumps(index.findings) or "[]"
        if name in ("read_file", "grep"):
            return _repo_exec(name, args, index.repo_root)
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
    "  - engine_findings(): everything Frame already proved -- never re-report these.\n"
    "  - read_file / grep: read related code to judge intent.\n\n"
    "If list_handlers() is empty, Frame has no symbolic model for this language: "
    "enumerate the entry points yourself with grep/read_file (route decorators, "
    "controllers, request handlers) and reason about them from the source. Such findings "
    "cannot be engine-backed, so set engine_backed=false.\n\n"
    "Work systematically: enumerate handlers, focus on those that reach a resource and "
    "are NOT protected, read their code, and decide whether a real authorization or "
    "business-logic violation exists. A handler that is public by design (login, signup, "
    "health, a public catalog) is NOT a finding. When unsure, do not report.\n\n"
    "When finished, reply with ONLY a JSON object: {\"reasoning\": str, \"findings\": "
    "[{\"reasoning\": str, \"handler\": str, \"file\": str, \"line\": int, \"mechanism\": "
    "\"missing_authorization\"|\"idor\"|\"privilege_escalation\"|\"mass_assignment\"|"
    "\"business_logic\", \"cwe\": str, \"confidence\": 0.0-1.0, \"engine_backed\": bool}]}. "
    "Set engine_backed true only when a handler_facts/list_handlers fact supports the "
    "mechanism (it reaches a resource and is not protected). A wrong finding is worse "
    "than no finding."
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
    h = index.handler(str(f.get("handler", "")))
    if h is None:
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
    h = index.handler(str(f.get("handler", "")))
    rel = (h.file if h is not None else str(f.get("file") or ""))
    path = os.path.join(index.repo_root, rel) if index.repo_root and not os.path.isabs(rel) else rel
    tier = "llm_verified" if verified else "llm_detect"
    return Vulnerability(
        type=vt, severity=Severity.HIGH if verified else Severity.MEDIUM,
        location=path, line=(h.line if (h is not None and not line) else line), column=0,
        description=("[LLM-verified] " if verified else "[LLM-detected] ") + str(f.get("reasoning", ""))[:200],
        procedure="<llm-hunt>", source_var=tier,
        confidence=min(conf, 0.9 if verified else 0.7),
        cwe_id=cwe.upper(), evidence=("llm-verified" if verified else "llm-detected"))


def _findings_to_vulns(findings: list, index: EngineIndex) -> list:
    out = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        # Do not re-report what the engine already proved at the same spot.
        h = index.handler(str(f.get("handler", "")))
        if h is not None and h.proven:
            continue
        v = _to_vuln(f, index, _corroborated(f, index))
        if v is not None:
            out.append(v)
    return out


def hunt_authz(programs, symbolic_findings: Optional[list], repo_root: str,
               config: LLMConfig, client: Optional[LLMClient] = None,
               max_steps: Optional[int] = None, language: str = "") -> list:
    """Run one agentic authorization / business-logic hunt. `programs` is the project's
    translated programs (one per file), a single program, or None.

    Engine-backed where a frontend exists: the agent queries the handler facts and a
    corroborated claim is tiered `llm_verified`. Where there is no frontend for the
    language (`program` is None or has no handlers), it falls back to a grep/read_file
    hunt over the repository -- every finding is then `llm_detect` (no engine to
    corroborate). Returns [] only when there is nothing to work with at all.
    """
    index = build_index(programs, symbolic_findings, repo_root)
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
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": HUNT_SYSTEM},
        {"role": "user", "content": (
            intro + "\n\nHunt for authorization and business-logic flaws. Use the engine "
            "facts (if any), handler_facts and read_file to judge intent, then report real "
            "findings as the JSON object.")},
    ]
    steps = max_steps if max_steps is not None else max(1, getattr(config, "max_tool_steps", 30))
    res = run_agent(
        messages, client, tools=HUNT_TOOLS, exec_tool=hunt_exec(index),
        max_steps=steps,
        finalize=lambda content: _findings_to_vulns(
            (_extract_json_object(content) or {}).get("findings") or [], index),
        final_nudge="Report the findings now as the JSON object.",
        compact_at_chars=getattr(config, "agent_context_budget_chars", 80000))
    return res.result or []
