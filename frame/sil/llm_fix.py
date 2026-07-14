"""Optional LLM-based *remediation* -- the closing step of the neuro-symbolic loop.

Detection finds a vulnerability; exploitation proves it is real; fix REMEDIATES it.
The differentiator is verification: after patching, Frame re-runs detection on the
patched code and confirms the vulnerability is gone. A code-generation model patches
and hopes; Frame patches and *proves*.

Standardized like the other layers: shared llm_client transport, strict json_schema
structured output (config.json_mode), and fail-loud on an unreachable endpoint
(LLMUnavailableError propagates -- a remediation the LLM could not produce must
surface an error, never a silent no-op).
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from frame.sil.llm_client import LLMClient, LLMConfig, _extract_json_object
from frame.sil.llm_detect import detect_in_file, _numbered, _detect_max_chars

FIX_SYSTEM = (
    "You are a senior application-security engineer. Given a confirmed vulnerability "
    "and the source file, produce a MINIMAL, correct patch that eliminates the "
    "vulnerability while preserving existing behavior. Prefer the idiomatic secure "
    "construct (parameterized queries, path canonicalization + allow-listing, output "
    "encoding, safe deserialization, authz checks). Do not add unrelated changes. "
    "First reason briefly, THEN output ONLY a JSON object giving the exact code span "
    "to replace and its secure replacement. The `original` MUST be copied verbatim "
    "from the source (no line-number prefixes) so it can be located exactly.")

# Strict structured-output schema. Leading `reasoning` keeps chain-of-thought inside
# the schema (recall/quality) while the output stays machine-parseable.
FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string"},
        "original": {"type": "string"},
        "replacement": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["reasoning", "original", "replacement", "rationale"],
    "additionalProperties": False,
}


def _fix_response_format(json_mode: str) -> Optional[Dict[str, Any]]:
    if json_mode == "json_object":
        return {"type": "json_object"}
    if json_mode == "json_schema":
        return {"type": "json_schema", "json_schema": {
            "name": "security_fix", "schema": FIX_SCHEMA, "strict": True}}
    return None


@dataclass
class FixResult:
    file: str
    cwe: str
    line: int
    applied: bool
    verified: Optional[bool]           # None = not checked / could not verify
    rationale: str = ""
    original: str = ""
    replacement: str = ""
    note: str = ""


def generate_fix(finding: Dict[str, Any], source_code: str, config: LLMConfig,
                 client: Optional[LLMClient] = None) -> Dict[str, Any]:
    """Ask the model for a minimal secure patch for one finding. Returns the patch
    dict {original, replacement, rationale, ...} (empty on unparseable output). A
    transport failure propagates (LLMUnavailableError) -- never silently no-op."""
    if client is None:
        client = LLMClient(config)
    cwe = finding.get("cwe_id") or finding.get("cwe") or ""
    line = finding.get("line") or 0
    typ = finding.get("type") or ""
    desc = finding.get("description") or finding.get("reasoning") or ""
    prompt = (f"Vulnerability: {cwe} ({typ}) at line {line}. {desc}\n\n"
              f"Source (numbered lines):\n{_numbered(source_code, _detect_max_chars(config))}\n\n"
              "Reason briefly, then output the JSON object with `original` (verbatim "
              "code span, no line-number prefixes) and its secure `replacement`.")
    rf = _fix_response_format(getattr(config, "json_mode", "json_object"))
    raw = client.complete(
        [{"role": "system", "content": FIX_SYSTEM},
         {"role": "user", "content": prompt}],
        response_format=rf, force_json=(rf is not None), max_tokens=config.max_tokens)
    return _extract_json_object(raw) or {}


def apply_fix(source_code: str, patch: Dict[str, Any]) -> "tuple[str, bool]":
    """Replace the patch's `original` span with `replacement`. Returns
    (patched_source, applied). Exact match first; then a whitespace-tolerant match so
    minor re-indentation in the model's echo doesn't block a valid fix."""
    orig = (patch or {}).get("original") or ""
    repl = (patch or {}).get("replacement") or ""
    if not orig:
        return source_code, False
    if orig in source_code:
        return source_code.replace(orig, repl, 1), True
    # whitespace-tolerant: match the stripped block line-for-line
    src_lines = source_code.splitlines()
    o_lines = [l.strip() for l in orig.splitlines() if l.strip()]
    if not o_lines:
        return source_code, False
    for i in range(len(src_lines) - len(o_lines) + 1):
        window = [src_lines[i + j].strip() for j in range(len(o_lines))]
        if window == o_lines:
            patched = src_lines[:i] + repl.splitlines() + src_lines[i + len(o_lines):]
            return "\n".join(patched) + ("\n" if source_code.endswith("\n") else ""), True
    return source_code, False


def make_diff(filename: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{filename}", tofile=f"b/{filename}"))


def verify_fixes(patched_source: str, language: str, filename: str,
                 findings: List[Dict[str, Any]], config: LLMConfig,
                 client: Optional[LLMClient] = None) -> List[Optional[bool]]:
    """Verify all of a file's findings with a SINGLE re-scan: the caller applies every
    patch first, then this detects once and checks which CWEs remain. Returns a list
    aligned to `findings` -- True = the finding's CWE is gone, False = it still detects,
    None = the re-scan could not run. Empty `findings` returns [] without scanning.

    Batching matters: per-finding re-scanning is O(findings) detection passes, which
    timed out on a file with 13 findings; this is one pass regardless of count.
    """
    if not findings:
        return []
    try:
        vulns = detect_in_file(patched_source, language, filename, config, client)
    except Exception:
        return [None] * len(findings)
    present = {str(getattr(v, "cwe_id", "") or "").upper() for v in vulns}
    return [str(f.get("cwe_id") or f.get("cwe") or "").upper() not in present
            for f in findings]


def verify_fix(patched_source: str, language: str, filename: str,
               finding: Dict[str, Any], config: LLMConfig,
               client: Optional[LLMClient] = None) -> Optional[bool]:
    """Re-run detection on the patched code; True if the finding's CWE is gone,
    False if it still detects, None if verification itself could not run.
    (Single-finding convenience over `verify_fixes`.)"""
    return verify_fixes(patched_source, language, filename, [finding], config, client)[0]
