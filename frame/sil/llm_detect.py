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

import json
import os
import re
from typing import Any, Dict, List, Optional

from frame.sil.llm_triage import LLMTriageClient, TriageConfig, _extract_json_object

DETECT_SYSTEM = (
    "You are a precise application-security scanner. Analyze the given source file "
    "and report ONLY genuine, exploitable vulnerabilities -- an actual flow from "
    "attacker-controlled input to a dangerous sink, or a clearly dangerous pattern. "
    "Do NOT report style issues, defense-in-depth suggestions, or speculative items. "
    "Respond with ONLY a JSON object: "
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
    r"\.query\(|\.find\(|\.findOne\(|new URL\(|fetch\(|axios|render|template)\b",
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


def _to_vulnerability(f: Dict[str, Any], filename: str) -> Optional[Any]:
    """Convert a model finding dict to a labeled Vulnerability (or None)."""
    from frame.sil.scanner import Vulnerability, Severity
    from frame.sil.translator import VulnType
    from benchmarks.endor_corpus import owasp_benchmark as _OB  # cwe normalization
    cwe = f.get("cwe")
    n = None
    try:
        n = _OB.cwe_to_int(cwe)
    except Exception:
        n = None
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


def detect_in_file(source_code: str, language: str, filename: str,
                   config: TriageConfig,
                   client: Optional[LLMTriageClient] = None) -> List[Any]:
    """Run one structured LLM detection call over a file; return labeled findings."""
    if client is None:
        client = LLMTriageClient(config)
    max_chars = getattr(config, "max_context_chars", 6000) * 4  # detection uses more context
    prompt = (f"Language: {language}\nFile: {filename}\n\nSource (numbered lines):\n"
              f"{_numbered(source_code, max_chars)}\n\n"
              "Report the real vulnerabilities as the specified JSON object.")
    try:
        raw = client._call_fn([
            {"role": "system", "content": DETECT_SYSTEM},
            {"role": "user", "content": prompt},
        ])
    except Exception:
        return []
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

_TOOLS = [
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a source file in the repository by repo-relative path.",
        "parameters": {"type": "object",
                       "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "grep",
        "description": "Regex-search the repository; returns up to 40 'path:line: text' matches.",
        "parameters": {"type": "object",
                       "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}}},
]

_GREP_EXTS = (".java", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".py", ".cs", ".c", ".cpp", ".go")


def _safe_path(repo_root: str, path: str) -> Optional[str]:
    """Resolve a repo-relative path, refusing anything that escapes the repo."""
    root = os.path.realpath(repo_root)
    p = os.path.realpath(os.path.join(root, str(path).lstrip("/")))
    return p if (p == root or p.startswith(root + os.sep)) else None


def _exec_tool(name: str, args: Dict[str, Any], repo_root: str, max_chars: int = 8000) -> str:
    try:
        if name == "read_file":
            p = _safe_path(repo_root, args.get("path", ""))
            if not p or not os.path.isfile(p):
                return "ERROR: file not found"
            with open(p, encoding="utf-8", errors="replace") as fh:
                return fh.read()[:max_chars]
        if name == "grep":
            pat = re.compile(str(args.get("pattern", "")), re.I)
            root = os.path.realpath(repo_root)
            out: List[str] = []
            for dp, _, fns in os.walk(root):
                for fn in fns:
                    if not fn.lower().endswith(_GREP_EXTS):
                        continue
                    fp = os.path.join(dp, fn)
                    try:
                        with open(fp, encoding="utf-8", errors="replace") as fh:
                            for i, ln in enumerate(fh, 1):
                                if pat.search(ln):
                                    out.append(f"{os.path.relpath(fp, root)}:{i}: {ln.strip()[:160]}")
                                    if len(out) >= 40:
                                        return "\n".join(out)
                    except OSError:
                        continue
            return "\n".join(out) or "no matches"
    except (re.error, ValueError, OSError) as e:
        return f"ERROR: {e}"
    return "ERROR: unknown tool"


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
    max_chars = getattr(config, "max_context_chars", 6000) * 4
    system = DETECT_SYSTEM + (
        " You MAY call read_file(path) and grep(pattern) to inspect related files "
        "(helpers, callers, config, sources/sinks in other files) before deciding. "
        "When finished, reply with ONLY the JSON object.")
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": f"Language: {language}\nFile: {filename}\n\n"
         f"Source (numbered lines):\n{_numbered(source_code, max_chars)}\n\n"
         "Investigate (use tools if helpful for cross-file flows) and report real "
         "vulnerabilities as the JSON object."}]
    for _ in range(max(1, getattr(config, "max_tool_steps", 6))):
        msg = client.chat_raw(messages, _TOOLS)
        if msg is None:
            return []
        tcs = msg.get("tool_calls")
        if tcs:
            messages.append({"role": "assistant", "content": msg.get("content") or "",
                             "tool_calls": tcs})
            for tc in tcs:
                fn = tc.get("function", {})
                try:
                    a = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    a = {}
                if fn.get("name") == "read_file" and a.get("path"):
                    explored.add(str(a.get("path")))
                res = _exec_tool(fn.get("name", ""), a, repo_root)
                messages.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                                 "content": res[:8000]})
            continue
        return _findings_to_vulns(
            (_extract_json_object(msg.get("content") or "") or {}).get("findings") or [], filename)
    # Step budget exhausted -> force a final verdict without tools.
    messages.append({"role": "user", "content": "Report the findings now as the JSON object."})
    msg = client.chat_raw(messages)
    return _findings_to_vulns(
        (_extract_json_object((msg or {}).get("content") or "") or {}).get("findings") or [], filename)
