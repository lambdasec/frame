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
    obj = _extract_json_object(raw) or {}
    findings = obj.get("findings") or []
    out = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        v = _to_vulnerability(f, filename)
        if v is not None and v.cwe_id:
            out.append(v)
    return out
