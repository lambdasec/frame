"""Optional LLM triage pass for Frame findings (neuro-symbolic precision layer).

Frame's symbolic/separation-logic engine produces the findings; this pass asks an
LLM to adjudicate each one *in context* and drops the ones it is confident are
false positives. The design keeps Frame sound and precise:

  * The LLM never invents findings -- it only judges what the engine already found,
    so it can raise precision but cannot fabricate vulnerabilities.
  * A finding is dropped ONLY when the model says false-positive AND its confidence
    clears a threshold. Uncertainty keeps the finding. So triage can only *remove*
    false positives; it never silently discards a finding the model is unsure about.
  * Any transport/parse error keeps the finding (fail-safe -- never lose recall to
    an outage).
  * Verdicts are cached by (file, line, cwe, code-hash) so repeated scans are cheap
    and stable.

Transport is the shared `LLMClient` (frame.sil.llm_client) -- any OpenAI-compatible
/chat/completions endpoint (local MLX/OptiQ/vLLM/Ollama or a hosted API), so
proprietary code can be triaged fully on-device.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger("frame.llm")

from frame.sil.llm_client import (
    LLMClient, LLMConfig, LLMUnavailableError, _extract_json_object)
from frame.sil.llm_agent import run_agent, INVESTIGATION_TOOLS, investigation_exec

# Backward-compatible aliases: the shared transport used to live in this module.
# Callers (scanner, detect/exploit layers, benchmarks, tests) still import these
# names from here; they now resolve to the neutral transport in llm_client.
TriageConfig = LLMConfig
LLMTriageClient = LLMClient

__all__ = ["TriageConfig", "LLMTriageClient", "LLMConfig", "LLMClient",
           "_extract_json_object", "triage_vulnerabilities", "triage_agentic",
           "SYSTEM_PROMPT", "VERDICT_SCHEMA"]

SYSTEM_PROMPT = (
    "You are a precise application-security reviewer adjudicating static-analysis "
    "findings. You are given ONE finding and the surrounding code. Decide whether it "
    "is a genuine, exploitable vulnerability (true positive) or a false positive. "
    "Judge only this finding; do not look for other issues. Prefer keeping a finding "
    "when uncertain. Respond with ONLY a JSON object, filling \"reasoning\" FIRST so "
    "you analyze before you decide: "
    '{"reasoning": "<1-2 sentences>", "is_true_positive": true|false, "confidence": 0.0-1.0}.'
)

# JSON schema for servers that support strict structured output. Reasoning is first
# so the model reasons before committing to a verdict, within a bounded response.
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string"},
        "is_true_positive": {"type": "boolean"},
        "confidence": {"type": "number"},
    },
    "required": ["reasoning", "is_true_positive", "confidence"],
    "additionalProperties": False,
}


# Agentic triage: the same verdict, but the model may investigate the repo first.
# The evidence-based-drop clause is the safeguard against dropping true positives:
# a finding is only ruled a false positive if the model *finds* the mitigating control.
TRIAGE_AGENTIC_SYSTEM = (
    SYSTEM_PROMPT + " You MAY call read_file(path) and grep(pattern) to investigate "
    "whether attacker-controlled input actually REACHES this sink without a sanitizer "
    "or authorization guard: inspect the caller(s), the route/auth, and any validation "
    "elsewhere in the repo. Only conclude false-positive if you FIND the specific "
    "mitigating control; if you cannot find one, keep the finding. When finished, reply "
    "with ONLY the JSON verdict object."
)


def _verdict_response_format(json_mode: str) -> Optional[Dict[str, Any]]:
    """Structured-output spec for the triage verdict, per the config's json_mode."""
    if json_mode == "json_object":
        return {"type": "json_object"}
    if json_mode == "json_schema":
        return {"type": "json_schema", "json_schema": {
            "name": "triage_verdict", "schema": VERDICT_SCHEMA, "strict": True}}
    return None  # "off" -> prompt-only JSON, no response_format


def _triage_one(client: LLMClient, config: LLMConfig,
                prompt_ctx: str) -> Optional[Dict[str, Any]]:
    """One verdict for one finding. Returns the parsed dict, or None on any failure
    (fail-safe -- the caller then keeps the finding)."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_ctx},
    ]
    rf = _verdict_response_format(getattr(config, "json_mode", "json_object"))
    try:
        raw = client.complete(messages, response_format=rf, force_json=(rf is not None))
    except LLMUnavailableError:
        # The user asked for LLM triage and the endpoint is unreachable -> flag it,
        # never silently proceed as if triage ran.
        raise
    except Exception as exc:  # noqa: BLE001 -- a non-transport (parse/logic) blip is
        # fail-safe: keep the finding (triage only drops confident FPs, never hides a
        # vuln). Logged so a skipped verdict is visible, not silent.
        _log.warning("triage verdict errored (%s) -- keeping finding as-is", exc)
        return None
    verdict = _extract_json_object(raw)
    if verdict is None:
        _log.warning("triage verdict unparseable from model response -- keeping finding")
    return verdict


def triage_agentic(prompt_ctx: str, config: LLMConfig,
                   client: Optional[LLMClient] = None) -> Optional[Dict[str, Any]]:
    """Investigate a finding across the repo before deciding (the escalated path).
    The model may read_file/grep to check reachability and sanitization, then returns
    the verdict. Falls back to a single call when no repo_root is configured."""
    if client is None:
        client = LLMClient(config)
    repo_root = getattr(config, "repo_root", "")
    if not repo_root:
        return _triage_one(client, config, prompt_ctx)
    messages = [
        {"role": "system", "content": TRIAGE_AGENTIC_SYSTEM},
        {"role": "user", "content": prompt_ctx},
    ]
    res = run_agent(
        messages, client, tools=INVESTIGATION_TOOLS,
        exec_tool=investigation_exec(repo_root),
        max_steps=max(1, getattr(config, "max_tool_steps", 30)),
        finalize=lambda content: _extract_json_object(content),
        final_nudge="Give your final verdict now as the JSON object.",
        compact_at_chars=getattr(config, "agent_context_budget_chars", 80000))
    return res.result


def _should_escalate(verdict: Optional[Dict[str, Any]], config: LLMConfig) -> bool:
    """Escalate to agentic investigation only when a single call is *uncertain* --
    an unparseable verdict, or a confidence in the ambiguous band below the drop
    threshold (but not so low the model is clueless). Bounds the extra cost."""
    if verdict is None:
        return True
    try:
        conf = float(verdict.get("confidence", 0.0))
    except (TypeError, ValueError):
        return True
    return 0.35 <= conf < getattr(config, "drop_threshold", 0.75)


def _finding_fields(v: Any) -> Dict[str, Any]:
    return {
        "cwe": getattr(v, "cwe_id", "") or "",
        "type": getattr(getattr(v, "type", None), "value", str(getattr(v, "type", ""))),
        "line": getattr(v, "line", None),
        "description": getattr(v, "message", "") or getattr(v, "description", "") or "",
        "severity": getattr(getattr(v, "severity", None), "value", ""),
    }


def _context_snippet(source_lines: List[str], line: Optional[int], n: int) -> str:
    if not line or line < 1:
        return ""
    # `line` is 1-indexed; show n lines on each side.
    lo, hi = max(0, line - 1 - n), min(len(source_lines), line + n)
    out = []
    for i in range(lo, hi):
        marker = ">>" if (i + 1) == line else "  "
        out.append(f"{marker} {i + 1}: {source_lines[i]}")
    return "\n".join(out)


def _build_prompt(f: Dict[str, Any], snippet: str, language: str, filename: str) -> str:
    return (
        f"Language: {language}\nFile: {filename}\n"
        f"Finding: {f['type']} ({f['cwe']}), severity {f['severity']}\n"
        f"Detector note: {f['description']}\n"
        f"Reported at line {f['line']}.\n\nCode:\n{snippet}\n\n"
        "Is this a true positive (a real, exploitable vulnerability) or a false positive?"
    )


def _cache_key(filename: str, f: Dict[str, Any], snippet: str) -> str:
    h = hashlib.sha1(snippet.encode("utf-8")).hexdigest()[:12]
    return f"{filename}:{f['line']}:{f['cwe']}:{h}"


def triage_vulnerabilities(vulns: List[Any], source_code: str, language: str,
                           filename: str, config: LLMConfig,
                           client: Optional[LLMClient] = None
                           ) -> Tuple[List[Any], LLMClient]:
    """Filter `vulns` by LLM adjudication. Drops only confident false positives;
    keeps everything else (including on any error). Returns (kept, client)."""
    if client is None:
        client = LLMClient(config)
    if not vulns:
        return vulns, client
    source_lines = source_code.splitlines()
    kept: List[Any] = []
    for v in vulns:
        f = _finding_fields(v)
        snippet = _context_snippet(source_lines, f["line"], config.context_lines)
        if len(snippet) > config.max_context_chars:
            # Keep the finding line centered; drop outer context so the prompt always
            # fits a small window even on minified/very-long lines.
            half = config.max_context_chars // 2
            mid = snippet.find(">>")
            mid = mid if mid != -1 else len(snippet) // 2
            snippet = snippet[max(0, mid - half): mid + half]
        key = _cache_key(filename, f, snippet)
        rec = client.cache.get(key)
        if rec is None:
            prompt = _build_prompt(f, snippet, language, filename)
            verdict = _triage_one(client, config, prompt)
            # Opt-in: escalate an uncertain single-call verdict to an investigation
            # loop that checks reachability/sanitization across the repo.
            if (getattr(config, "triage_agentic", False)
                    and getattr(config, "repo_root", "")
                    and _should_escalate(verdict, config)):
                investigated = triage_agentic(prompt, config, client)
                if investigated is not None:
                    verdict = investigated
            rec = {"path": filename, "line": f["line"], "cwe": f["cwe"],
                   "verdict": verdict or {}}
            client.cache[key] = rec
            client._save()   # persist incrementally so a long run is never lost
        verdict = rec.get("verdict") or None
        # Drop ONLY a confident false positive; keep on uncertainty or error.
        is_fp = verdict is not None and verdict.get("is_true_positive") is False
        conf = float(verdict.get("confidence", 0.0)) if verdict else 0.0
        if is_fp and conf >= config.drop_threshold:
            client.stats["dropped"] += 1
            continue
        if verdict:
            try:
                setattr(v, "llm_triage", verdict)
            except (AttributeError, TypeError):
                pass
        client.stats["kept"] += 1
        kept.append(v)
    return kept, client
