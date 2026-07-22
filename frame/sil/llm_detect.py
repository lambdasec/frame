"""Optional LLM-based vulnerability *detection* (neuro-symbolic recall layer).

Frame's symbolic engine is the sound spine; this pass uses a local LLM to DETECT
vulnerabilities the symbolic detectors miss -- context-dependent flows, unknown
frameworks, business logic -- adding recall where structural analysis can't reach.

Design (keeps Frame's guarantees):
  * LLM findings are a SEPARATE, clearly-labeled tier: each carries
    source_var="llm_detect" and a reduced confidence, so "proven" (symbolic) and
    "LLM-detected" findings are never conflated.
  * Detection is scoped to security-relevant files (a candidate heuristic), so a
    scan doesn't call the model on every file.
  * The model returns STRUCTURED findings (a JSON object) -- no free-form parsing.
  * Any transport/parse error yields no findings (fail-safe: never fabricate).

Uses the same OpenAI-compatible transport as llm_triage (local MLX/OptiQ etc.).
Gated behind FrameScanner(llm_detect=True) / `--llm-detect`.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from frame.sil.llm_client import (
    LLMClient as LLMTriageClient, LLMConfig as TriageConfig, _extract_json_object)
from frame.sil.llm_agent import (
    run_agent, INVESTIGATION_TOOLS as _TOOLS, investigation_exec,
    _safe_path, _repo_exec as _exec_tool)

# Reason-first prompt: the model reasons in prose about the flow, THEN emits the
# findings object. On real-CVE evaluation (SusVibes) this ~1.8x'd detection recall
# over a terse "JSON only" prompt at equal precision, so it is the default. It
# requires a free-text call (no forced json_object) and a larger token budget --
# see LLMClient.detect_complete / LLMConfig.max_tokens.
DETECT_SYSTEM = (
    "You are a precise application-security auditor. Analyze the given source file for "
    "REAL, exploitable vulnerabilities. First reason step by step about attacker-controlled "
    "inputs and the dangerous operations they can reach: injection (SQL / command / code), "
    "path traversal, SSRF, XSS, unsafe deserialization, open redirect, XXE, and broken "
    "authentication or authorization. Ignore style issues, defense-in-depth suggestions, and "
    "speculative items. THEN, after the reasoning, output ONLY a JSON object on its own line: "
    '{"findings": [{"reasoning": "<1 sentence>", "cwe": "CWE-89", "line": <int>, '
    '"type": "<short_snake_case>", "confidence": 0.0-1.0}]}. '
    "Use an empty findings array if there are no real vulnerabilities."
)

# Files worth sending to the model: security-relevant code. Skips the vast
# majority of files (models, DTOs, config) to keep a scan tractable.
_CANDIDATE_RE = re.compile(
    r"\b(req\.|request\.|@RequestParam|@PathVariable|@RequestBody|getParameter|"
    r"getHeader|getCookies|res\.send|sendFile|sendRedirect|redirect|execute|"
    r"executeQuery|createStatement|prepareStatement|Runtime\.|ProcessBuilder|"
    r"readFile|writeFile|ObjectInputStream|Cipher|MessageDigest|eval\(|exec\(|"
    r"\.query\(|\.find\(|\.findOne\(|new URL\(|fetch\(|axios|render|template|"
    # Python: web routes + file/path/process/deserialize sinks (path traversal,
    # command injection, SSRF, unsafe deserialization surface the JS/Java lists miss).
    # Match the call form (router.get(...)) not the @ decorator: a leading '@' is a
    # non-word char, so the wrapping \b...\b can never anchor to it.
    r"router\.(get|post|put|delete|patch|websocket|api_route)|add_api_route|"
    r"add_url_rule|\.route\(|os\.system|os\.popen|subprocess|Popen|send_file|"
    r"send_from_directory|FileResponse|StreamingResponse|shutil\.|open\(|Path\(|"
    r"\.iterdir\(|os\.path|pickle\.load|yaml\.load|marshal\.loads|os\.remove|"
    r"os\.rename|os\.mkdir|render_template_string|__import__|urlopen|"
    # C# / ASP.NET: request binding, DB, process, file, view, redirect, deserialize
    r"FromQuery|FromBody|FromRoute|FromForm|HttpContext|IActionResult|ActionResult|"
    r"SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar|DbCommand|"
    r"Process\.Start|File\.Read|File\.Write|Html\.Raw|Response\.Redirect|"
    r"Deserialize|HttpClient|WebClient|Request\.Query|Request\.Form)\b",
    re.I)


# Which symbolic sink kinds ground each CWE. If Frame's SIL has a sink of the
# matching kind at the LLM's claimed line, the finding is grounded in a real
# dangerous operation Frame recognizes (it just couldn't connect the flow).
_CWE_SINK_KINDS = {
    "CWE-89": {"sql", "orm"}, "CWE-943": {"nosql"}, "CWE-79": {"html", "xss"},
    "CWE-78": {"shell", "command"}, "CWE-22": {"path", "filesystem"},
    "CWE-73": {"path", "filesystem"}, "CWE-918": {"ssrf"},
    "CWE-94": {"eval"}, "CWE-95": {"eval"}, "CWE-91": {"xml_injection"},
    "CWE-502": {"deserialize", "deserialize_unsafe"}, "CWE-611": {"xml"},
    "CWE-90": {"ldap"}, "CWE-643": {"xpath"}, "CWE-601": {"redirect"},
    "CWE-113": {"header"}, "CWE-117": {"log"}, "CWE-1336": {"template"},
}


def collect_sinks(program) -> list:
    """[(line, sink_kind_value)] for every TaintSink in a translated program."""
    sinks = []
    for proc in program.procedures.values():
        for node in proc.nodes.values():
            for instr in getattr(node, "instrs", []):
                if type(instr).__name__ == "TaintSink":
                    loc = getattr(instr, "loc", None)
                    kind = getattr(getattr(instr, "kind", None), "value", None)
                    if loc is not None and kind is not None:
                        sinks.append((loc.line, kind))
    return sinks


def is_sink_grounded(cwe_id: Optional[str], line: Optional[int],
                     sinks: list, window: int = 3) -> bool:
    """True if Frame's SIL has a matching-kind sink near the claimed line."""
    kinds = _CWE_SINK_KINDS.get(cwe_id)
    if not kinds:
        return False
    return any(abs((line or 0) - sl) <= window and sk in kinds for sl, sk in sinks)


def cross_file_grounded(cwe_id: Optional[str], explored_sink_kinds) -> bool:
    """True if a sink of the CWE's kind exists in any file the agent explored --
    grounds a cross-file finding whose sink lives in a different file."""
    kinds = _CWE_SINK_KINDS.get(cwe_id)
    return bool(kinds and (kinds & set(explored_sink_kinds)))


def is_detection_candidate(source_code: str, has_symbolic_findings: bool) -> bool:
    """Only analyze security-relevant files (or ones the symbolic pass flagged)."""
    if has_symbolic_findings:
        return True
    return bool(_CANDIDATE_RE.search(source_code or ""))


def _numbered(source_code: str, max_chars: int) -> str:
    lines = source_code.splitlines()
    out, total = [], 0
    for i, ln in enumerate(lines, 1):
        piece = f"{i}: {ln}\n"
        if total + len(piece) > max_chars:
            out.append(f"... (truncated at line {i})")
            break
        out.append(piece)
        total += len(piece)
    return "".join(out)


def _cwe_to_int(cwe: Any) -> Optional[int]:
    """Normalize a CWE reference to its int ('CWE-89', '89', 89, 'CWE-89: SQLi').

    Inlined so core detection has NO dependency on the benchmarks package -- that
    import failing (e.g. when Frame is installed without the benchmark data) used
    to crash finding conversion and silently drop every LLM finding.
    """
    if cwe is None:
        return None
    s = str(cwe).strip().upper()
    m = re.search(r"CWE[-\s_]*(\d+)", s)
    if m:
        return int(m.group(1))
    return int(s) if s.isdigit() else None


def _to_vulnerability(f: Dict[str, Any], filename: str) -> Optional[Any]:
    """Convert a model finding dict to a labeled Vulnerability (or None)."""
    from frame.sil.scanner import Vulnerability, Severity
    from frame.sil.translator import VulnType
    cwe = f.get("cwe")
    n = _cwe_to_int(cwe)
    cwe_id = f"CWE-{n}" if n is not None else (cwe if isinstance(cwe, str) else None)
    line = f.get("line")
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = 0
    # Best-effort VulnType from the model's type string; fall back generically.
    vt = None
    tval = str(f.get("type", "")).strip().lower()
    for cand in VulnType:
        if cand.value == tval:
            vt = cand
            break
    if vt is None:
        vt = getattr(VulnType, "TAINT_FLOW", list(VulnType)[0])
    conf = f.get("confidence", 0.6)
    try:
        conf = float(conf)
    except (TypeError, ValueError):
        conf = 0.6
    # LLM-detected tier: cap confidence below symbolic (proven) findings.
    conf = min(conf, 0.85)
    return Vulnerability(
        type=vt, severity=Severity.MEDIUM, location=filename, line=line, column=0,
        description="[LLM-detected] " + str(f.get("reasoning", ""))[:200],
        procedure="<llm-detect>", source_var="llm_detect",
        confidence=conf, cwe_id=cwe_id)


# Detection reads whole files up to this many chars (~12k tokens). Handler files
# routinely exceed the triage snippet cap (max_context_chars*4); truncating them
# silently drops trailing endpoints -- a real recall bug (e.g. a path-traversal
# handler in the last 20% of a 600-line file goes unseen). Only pathological files
# past this floor still truncate with a marker.
_DETECT_MIN_CHARS = 48000


def _detect_max_chars(config: TriageConfig) -> int:
    return max(getattr(config, "max_context_chars", 6000) * 4, _DETECT_MIN_CHARS)


# Strict structured-output schema for detection. A leading `reasoning` field keeps
# the reason-first chain-of-thought (which drives recall) INSIDE the schema, so we
# get the reasoning benefit AND schema-guaranteed findings -- no prose parsing.
DETECT_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "reasoning": {"type": "string"},
                    "cwe": {"type": "string"},
                    "line": {"type": "integer"},
                    "type": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["reasoning", "cwe", "line", "type", "confidence"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["reasoning", "findings"],
    "additionalProperties": False,
}


def _detect_response_format(json_mode: str) -> Optional[Dict[str, Any]]:
    """Structured-output spec for detection, mirroring triage's json_mode knob."""
    if json_mode == "json_object":
        return {"type": "json_object"}
    if json_mode == "json_schema":
        return {"type": "json_schema", "json_schema": {
            "name": "vulnerability_findings", "schema": DETECT_SCHEMA, "strict": True}}
    return None  # "off" -> prompt-only JSON, parsed best-effort


def detect_in_file(source_code: str, language: str, filename: str,
                   config: TriageConfig,
                   client: Optional[LLMTriageClient] = None) -> List[Any]:
    """Run one structured LLM detection call over a file; return labeled findings.

    Standardized on forced JSON + strict schema (config.json_mode): frontier API
    models return schema-valid data, so findings never depend on parsing prose.
    """
    if client is None:
        client = LLMTriageClient(config)
    max_chars = _detect_max_chars(config)
    prompt = (f"Language: {language}\nFile: {filename}\n\nSource (numbered lines):\n"
              f"{_numbered(source_code, max_chars)}\n\n"
              "Reason step by step, then report the real vulnerabilities as the JSON object.")
    rf = _detect_response_format(getattr(config, "json_mode", "json_object"))
    # No fallback-to-empty: a transport failure propagates (LLMUnavailableError)
    # so the scan surfaces "LLM unreachable", never a misleading "no vulnerabilities".
    raw = client.complete(
        [{"role": "system", "content": DETECT_SYSTEM},
         {"role": "user", "content": prompt}],
        response_format=rf, force_json=(rf is not None),
        max_tokens=config.max_tokens)
    return _findings_to_vulns((_extract_json_object(raw) or {}).get("findings") or [], filename)


def _findings_to_vulns(findings: list, filename: str) -> List[Any]:
    out = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        v = _to_vulnerability(f, filename)
        if v is not None and v.cwe_id:
            out.append(v)
    return out


# ---- Agentic (tool-using) detection: cross-file exploration --------------------
# The investigation tools (read_file / grep), their executor, and the tool loop
# live in llm_agent and are imported above; `_TOOLS` / `_exec_tool` / `_safe_path`
# are re-exported here for backward compatibility.


def detect_agentic(source_code: str, language: str, filename: str,
                   config: TriageConfig,
                   client: Optional[LLMTriageClient] = None) -> List[Any]:
    """Tool-using detection: the model may read_file/grep across the repo to trace
    cross-file flows before reporting. Falls back to single-file if no repo_root."""
    if client is None:
        client = LLMTriageClient(config)
    repo_root = getattr(config, "repo_root", "")
    explored: set = set()
    client._explored = explored   # files the agent reads -> cross-file verification
    if not repo_root:
        return detect_in_file(source_code, language, filename, config, client)
    max_chars = _detect_max_chars(config)
    system = DETECT_SYSTEM + (
        " You MAY call read_file(path) and grep(pattern) to inspect related files "
        "(helpers, callers, config, sources/sinks in other files) before deciding. "
        "Work systematically: enumerate the request handlers/endpoints and, for each "
        "attacker-controlled input, trace whether it can reach a dangerous sink "
        "(injection, path traversal, SSRF, unsafe deserialization, broken authz), "
        "following the flow across files. When finished, reply with ONLY the JSON object.")
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": f"Language: {language}\nFile: {filename}\n\n"
         f"Source (numbered lines):\n{_numbered(source_code, max_chars)}\n\n"
         "Investigate (use tools if helpful for cross-file flows) and report real "
         "vulnerabilities as the JSON object."}]
    res = run_agent(
        messages, client, tools=_TOOLS,
        exec_tool=investigation_exec(repo_root, explored),
        max_steps=max(1, getattr(config, "max_tool_steps", 30)),
        finalize=lambda content: _findings_to_vulns(
            (_extract_json_object(content) or {}).get("findings") or [], filename),
        final_nudge="Report the findings now as the JSON object.",
        compact_at_chars=getattr(config, "agent_context_budget_chars", 80000))
    return res.result or []


# ---- Repository-scale detection ------------------------------------------------
# Per-file agentic detection opens one model session per candidate file, which does
# not scale to real projects: a 500-file repository means 500 sessions, each paying
# to rediscover the same context. Repository-scale detection instead runs ONE
# session over the whole tree and lets the model navigate with grep/read_file, the
# way a human reviewer works. Findings therefore have to name their own file, which
# per-file detection never needed, hence the extended schema below.

DETECT_REPO_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "reasoning": {"type": "string"},
                    "file": {"type": "string"},
                    "cwe": {"type": "string"},
                    "line": {"type": "integer"},
                    "type": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["reasoning", "file", "cwe", "line", "type", "confidence"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["reasoning", "findings"],
    "additionalProperties": False,
}

DETECT_REPO_SYSTEM = (
    "You are a precise application-security auditor reviewing an entire code "
    "repository. Find REAL, exploitable vulnerabilities: injection (SQL / command / "
    "code), path traversal, SSRF, XSS, unsafe deserialization, open redirect, XXE, "
    "and broken authentication or authorization. Ignore style issues, "
    "defense-in-depth suggestions, and speculative items.\n\n"
    "Use read_file(path) and grep(pattern) to navigate. Work systematically: locate "
    "the entry points (request handlers, routes, CLI commands, message consumers), "
    "then for each attacker-controlled input trace whether it reaches a dangerous "
    "sink, following the flow across files. Confirm by reading the code; do not "
    "guess from file names.\n\n"
    "When finished, reply with ONLY a JSON object: {\"reasoning\": str, \"findings\": "
    "[{\"reasoning\": str, \"file\": str, \"cwe\": str, \"line\": int, \"type\": str, "
    "\"confidence\": float}]}. `file` must be a repository-relative path you actually "
    "read. Report an empty findings list if the code is clean; a wrong finding is "
    "worse than no finding."
)


def _repo_inventory(repo_root: str, language: str, limit: int = 400) -> str:
    """A bounded listing of the repository's source files, as a starting map.

    The agent could discover this itself, but spending tool calls to re-list a tree
    we can hand over for free wastes its step budget on navigation instead of
    analysis.
    """
    import os
    exts = _LANGUAGE_EXTENSIONS.get((language or "").lower())
    skip_dirs = {".git", "node_modules", "vendor", "dist", "build", "target",
                 "__pycache__", ".venv", "venv", "site-packages", ".tox"}
    found: List[str] = []
    root = os.path.realpath(repo_root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for name in filenames:
            if exts and not name.lower().endswith(exts):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            found.append(rel)
            if len(found) >= limit:
                found.append(f"... (listing truncated at {limit} files)")
                return "\n".join(found)
    return "\n".join(sorted(found))


_LANGUAGE_EXTENSIONS = {
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "java": (".java",),
    "c": (".c", ".h"),
    "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".h"),
    "csharp": (".cs",),
    "go": (".go",),
    "rust": (".rs",),
    "php": (".php",),
    "ruby": (".rb",),
}


def _repo_findings_to_vulns(findings: list, repo_root: str) -> List[Any]:
    """Convert repo-scale findings, each of which names its own file.

    A path outside the repository is dropped rather than clamped: it means the model
    named something it did not read, and a finding we cannot locate is not reportable.
    """
    import os
    out = []
    root = os.path.realpath(repo_root)
    for f in findings:
        if not isinstance(f, dict):
            continue
        rel = str(f.get("file") or "").strip()
        if not rel:
            continue
        abs_path = os.path.realpath(os.path.join(root, rel))
        if abs_path != root and not abs_path.startswith(root + os.sep):
            continue
        if not os.path.isfile(abs_path):
            continue
        v = _to_vulnerability(f, abs_path)
        if v is not None and v.cwe_id:
            out.append(v)
    return out


def detect_repo(repo_root: str, language: str, config: TriageConfig,
                client: Optional[LLMTriageClient] = None,
                max_steps: Optional[int] = None) -> List[Any]:
    """Detect vulnerabilities across a whole repository in a single agentic session.

    Returns the findings, each already resolved to an absolute path inside
    `repo_root`. Returns an empty list when `repo_root` is not a usable directory,
    so callers can treat this as best-effort.
    """
    import os
    if not repo_root or not os.path.isdir(repo_root):
        return []
    if client is None:
        client = LLMTriageClient(config)
    explored: set = set()
    client._explored = explored
    root = os.path.realpath(repo_root)
    inventory = _repo_inventory(root, language)
    if not inventory.strip():
        return []
    steps = max_steps if max_steps is not None else max(
        1, getattr(config, "max_tool_steps", 30))
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": DETECT_REPO_SYSTEM},
        {"role": "user", "content": (
            f"Language: {language}\nRepository root: {root}\n\n"
            f"Source files:\n{inventory}\n\n"
            "Investigate the repository with the tools and report real "
            "vulnerabilities as the JSON object.")},
    ]
    res = run_agent(
        messages, client, tools=_TOOLS,
        exec_tool=investigation_exec(root, explored),
        max_steps=steps,
        finalize=lambda content: _repo_findings_to_vulns(
            (_extract_json_object(content) or {}).get("findings") or [], root),
        final_nudge="Report the findings now as the JSON object.",
        compact_at_chars=getattr(config, "agent_context_budget_chars", 80000))
    return res.result or []
