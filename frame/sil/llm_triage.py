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
    "is a genuine, exploitable vulnerability (true positive) or a false positive. "
    "Judge only this finding; do not look for other issues. Prefer keeping a finding "
    "when uncertain. Respond with ONLY a JSON object, filling \"reasoning\" FIRST so "
    "you analyze before you decide: "
    '{"reasoning": "<1-2 sentences>", "is_true_positive": true|false, "confidence": 0.0-1.0}.'
)

# JSON schema for servers that support strict structured output (OpenAI
# json_schema / many local servers). Reasoning is first so the model reasons
# before committing to a verdict, within a bounded structured response.
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


@dataclass
class TriageConfig:
    base_url: str = ""              # OpenAI-compatible base, e.g. http://localhost:8080/v1
    api_key: str = ""               # bearer token (any string for most local servers)
    model: str = ""                 # served model name
    temperature: float = 0.0        # deterministic
    # With structured output the verdict is a short JSON object (reasoning +
    # boolean + number). 256 leaves room for a 1-2 sentence reasoning field while
    # keeping prompt+generation (~490 + 256) under a 1k window -- so a larger
    # model with a small context can be used. Raise it (and the window) only for
    # longer free-form reasoning.
    max_tokens: int = 256
    # Structured output. "json_object" is widely supported by OpenAI-compatible
    # servers (incl. local MLX/optillm/vLLM/llama.cpp); "json_schema" enforces the
    # exact schema where supported; "off" falls back to prompt-only JSON.
    json_mode: str = "json_object"  # "json_object" | "json_schema" | "off"
    cache_path: str = ""            # persist verdicts here (JSON); reused across runs
    repo_root: str = ""             # repo root for agentic detection tools (read_file/grep)
    max_tool_steps: int = 6         # tool-call rounds before forcing a verdict
    timeout: int = 60               # seconds per call
    context_lines: int = 12         # code lines of context around the finding
    max_context_chars: int = 6000   # hard cap on code snippet (~1.5k tok) -> safe for a 2k window
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
            max_tokens=int(os.environ.get("FRAME_LLM_MAX_TOKENS", "256")),
            cache_path=os.environ.get("FRAME_LLM_CACHE", ""),
            repo_root=os.environ.get("FRAME_LLM_REPO_ROOT", ""),
            max_tool_steps=int(os.environ.get("FRAME_LLM_MAX_TOOL_STEPS", "6")),
            context_lines=int(os.environ.get("FRAME_LLM_CONTEXT_LINES", "12")),
            # For a strict 1k window set this ~2000 (worst-case snippet ~500 tok);
            # 6000 (~1.5k tok) suits a 2k window.
            max_context_chars=int(os.environ.get("FRAME_LLM_MAX_CONTEXT_CHARS", "6000")),
            json_mode=os.environ.get("FRAME_LLM_JSON_MODE", "json_object"),
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
        # cache maps key -> {path, line, cwe, verdict}; persisted to cache_path.
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.stats: Dict[str, int] = {"calls": 0, "errors": 0, "dropped": 0, "kept": 0}
        if getattr(config, "cache_path", ""):
            try:
                with open(config.cache_path, encoding="utf-8") as fh:
                    self.cache = json.load(fh)
            except (OSError, json.JSONDecodeError):
                self.cache = {}

    def _save(self) -> None:
        if getattr(self.config, "cache_path", ""):
            try:
                with open(self.config.cache_path, "w", encoding="utf-8") as fh:
                    json.dump(self.cache, fh, indent=2)
            except OSError:
                pass

    def _response_format(self) -> Optional[Dict[str, Any]]:
        mode = getattr(self.config, "json_mode", "json_object")
        if mode == "json_object":
            return {"type": "json_object"}
        if mode == "json_schema":
            return {"type": "json_schema", "json_schema": {
                "name": "triage_verdict", "schema": VERDICT_SCHEMA, "strict": True}}
        return None

    def _http_call(self, messages: List[Dict[str, str]]) -> str:
        url = f"{self.config.base_url}/chat/completions"
        body: Dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        rf = self._response_format()
        if rf is not None:
            body["response_format"] = rf   # structured output where supported
        payload = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        # Some local servers (e.g. OptiQ) reject *any* Authorization header; only
        # send one when a key is actually configured. Set FRAME_LLM_API_KEY="" to omit.
        if self.config.api_key and self.config.api_key.lower() not in ("none", "anything"):
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        req = urllib.request.Request(url, data=payload, headers=headers)
        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body["choices"][0]["message"]["content"]

    def chat_raw(self, messages: List[Dict[str, Any]],
                 tools: Optional[list] = None) -> Optional[Dict[str, Any]]:
        """Return the full assistant message (content + any tool_calls), or None
        on failure. Used by the agentic detection loop (tool-calling)."""
        url = f"{self.config.base_url}/chat/completions"
        body: Dict[str, Any] = {
            "model": self.config.model, "messages": messages,
            "temperature": self.config.temperature, "max_tokens": self.config.max_tokens,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key and self.config.api_key.lower() not in ("none", "anything"):
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        try:
            self.stats["calls"] += 1
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                         headers=headers)
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                out = json.loads(resp.read().decode("utf-8"))
            return out["choices"][0]["message"]
        except (urllib.error.URLError, KeyError, ValueError, TimeoutError, OSError):
            self.stats["errors"] += 1
            return None

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
        if len(snippet) > config.max_context_chars:
            # Keep the finding line centered; drop outer context so the prompt
            # always fits a small (2k) window even on minified/very-long lines.
            half = config.max_context_chars // 2
            mid = snippet.find(">>")
            mid = mid if mid != -1 else len(snippet) // 2
            snippet = snippet[max(0, mid - half): mid + half]
        key = _cache_key(filename, f, snippet)
        rec = client.cache.get(key)
        if rec is None:
            verdict = client.triage(_build_prompt(f, snippet, language, filename))
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
