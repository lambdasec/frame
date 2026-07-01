"""Optional LLM triage pass for Frame findings (neuro-symbolic).

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

Transport is any OpenAI-compatible /chat/completions endpoint -- a local model
served via MLX / optillm / vLLM / Ollama, or a hosted API -- so proprietary code
can be triaged fully on-device. Configure via env or a TriageConfig.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

SYSTEM_PROMPT = (
    "You are a precise application-security reviewer adjudicating static-analysis "
    "findings. You are given ONE finding and the surrounding code. Decide whether it "
    "is a genuine, exploitable vulnerability (true positive) or not (false positive). "
    "Judge only this finding; do not look for other issues. Prefer keeping a finding "
    "when uncertain. Respond with ONLY a JSON object: "
    '{"is_true_positive": true|false, "confidence": 0.0-1.0, "reasoning": "<one sentence>"}.'
)


@dataclass
class TriageConfig:
    base_url: str = ""              # OpenAI-compatible base, e.g. http://localhost:8080/v1
    api_key: str = ""               # bearer token (any string for most local servers)
    model: str = ""                 # served model name
    temperature: float = 0.0        # deterministic
    max_tokens: int = 512
    timeout: int = 60               # seconds per call
    context_lines: int = 12         # code lines of context around the finding
    drop_threshold: float = 0.75    # drop only false-positives at/above this confidence
    enabled: bool = False

    @classmethod
    def from_env(cls) -> "TriageConfig":
        base = os.environ.get("FRAME_LLM_BASE_URL", "").rstrip("/")
        return cls(
            base_url=base,
            api_key=os.environ.get("FRAME_LLM_API_KEY", "sk-local"),
            model=os.environ.get("FRAME_LLM_MODEL", ""),
            temperature=float(os.environ.get("FRAME_LLM_TEMPERATURE", "0.0")),
            drop_threshold=float(os.environ.get("FRAME_LLM_DROP_THRESHOLD", "0.75")),
            timeout=int(os.environ.get("FRAME_LLM_TIMEOUT", "60")),
            enabled=bool(base and os.environ.get("FRAME_LLM_MODEL")),
        )


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Best-effort extraction of the first JSON object from model output."""
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


class LLMTriageClient:
    """Calls an OpenAI-compatible chat endpoint. `call_fn` overrides the HTTP
    transport (used in tests and to swap in a local SDK)."""

    def __init__(self, config: TriageConfig,
                 call_fn: Optional[Callable[[List[Dict[str, str]]], str]] = None):
        self.config = config
        self._call_fn = call_fn or self._http_call
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.stats: Dict[str, int] = {"calls": 0, "errors": 0, "dropped": 0, "kept": 0}

    def _http_call(self, messages: List[Dict[str, str]]) -> str:
        url = f"{self.config.base_url}/chat/completions"
        payload = json.dumps({
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        })
        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body["choices"][0]["message"]["content"]

    def triage(self, prompt_ctx: str) -> Optional[Dict[str, Any]]:
        """Return the parsed verdict dict, or None on any failure (fail-safe)."""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt_ctx},
        ]
        try:
            self.stats["calls"] += 1
            return _extract_json_object(self._call_fn(messages))
        except (urllib.error.URLError, KeyError, ValueError, TimeoutError, OSError):
            self.stats["errors"] += 1
            return None


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
                           filename: str, config: TriageConfig,
                           client: Optional[LLMTriageClient] = None
                           ) -> Tuple[List[Any], LLMTriageClient]:
    """Filter `vulns` by LLM adjudication. Drops only confident false positives;
    keeps everything else (including on any error). Returns (kept, client)."""
    if client is None:
        client = LLMTriageClient(config)
    if not vulns:
        return vulns, client
    source_lines = source_code.splitlines()
    kept: List[Any] = []
    for v in vulns:
        f = _finding_fields(v)
        snippet = _context_snippet(source_lines, f["line"], config.context_lines)
        key = _cache_key(filename, f, snippet)
        verdict = client.cache.get(key)
        if verdict is None:
            verdict = client.triage(_build_prompt(f, snippet, language, filename))
            client.cache[key] = verdict or {}
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
