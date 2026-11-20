"""Shared LLM transport for Frame's neuro-symbolic layers.

This is the model-swappable substrate used by all three LLM layers -- detection
(`llm_detect`), triage (`llm_triage`), and exploitation (`llm_exploit`). It owns
*only* the transport: talking to any OpenAI-compatible /chat/completions endpoint
(local MLX / OptiQ / vLLM / Ollama, or a hosted API), structured-output plumbing,
verdict caching, and JSON extraction. It carries no layer-specific prompts or
schemas -- each layer supplies those.

Configure with `[llm]` in the config file and `FRAME_LLM_*` (see `frame.config`), or an
explicit `LLMConfig`. `llm_triage` re-exports `LLMClient`/`LLMConfig` under their historical
names (`LLMTriageClient`/`TriageConfig`) for backward compatibility.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, List, Optional

_log = logging.getLogger("frame.llm")


class LLMUnavailableError(RuntimeError):
    """The LLM endpoint could not be reached (DNS/network/transport failure) after
    retries. Raised instead of silently returning empty results -- a scan that
    could not run the LLM layer must surface an error, never a misleading
    "no vulnerabilities found"."""


class _DroppedStream(Exception):
    """A streamed response was cut off (an in-stream error object, or an inter-token
    stall past the timeout). Half a tool call is worse than none, so the caller discards
    the partial output and re-issues the same request."""


@dataclass
class LLMConfig:
    base_url: str = ""              # OpenAI-compatible base, e.g. http://localhost:8080/v1
    api_key: str = ""               # bearer token (any string for most local servers)
    model: str = ""                 # served model name
    temperature: float = 0.0        # deterministic
    # Single-call budget for BOTH triage verdicts and reason-first detection. Sized
    # for the larger of the two -- detection emits step-by-step reasoning AND a
    # multi-finding JSON; triage's short verdict just gets harmless headroom. Too
    # small and a reasoning model truncates before the JSON completes: triage then
    # keeps everything (fail-safe) and detection loses findings. The model stops at
    # the JSON, so this is only a ceiling; lower it for tiny-context models.
    max_tokens: int = 4096
    # Agentic tool loops (detect/triage/exploit) need far more room than a triage
    # verdict: a reasoning model spends output tokens thinking *before* it emits a
    # tool call, so a small budget truncates it mid-thought and no tool call appears.
    agent_max_tokens: int = 16000
    # When the running transcript (sum of message content) exceeds this, run_agent elides
    # OLD tool-result content to short placeholders (keeping the stable task prefix and recent
    # turns), so long persistent sessions stay inside the context window. Set HIGH: a large
    # stable task prompt (e.g. a big handler inventory) is cached and cheap, so compact only
    # when the growing tail is genuinely large, not on the fixed prefix. ~100k tokens.
    agent_context_budget_chars: int = 400000
    # Retries for the agentic transport on transient network errors (flaky links).
    agent_retries: int = 5
    # After those retries, keep retrying an unreachable endpoint (network errors, HTTP 408/429/5xx)
    # every 30 seconds for up to this many seconds, measured from the first failure, instead of
    # giving up. 0 = off. For long unattended runs on a link that can drop for hours: a hunt unit
    # waits out the outage and continues where it was, rather than ending as transport_error.
    outage_wait: int = 0
    # Structured output. "json_object" is widely supported (incl. local
    # MLX/optillm/vLLM/llama.cpp); "json_schema" enforces an exact schema where
    # supported; "off" falls back to prompt-only JSON.
    json_mode: str = "json_schema"  # "json_schema" (strict) | "json_object" | "off"
    cache_path: str = ""            # persist verdicts here (JSON); reused across runs
    repo_root: str = ""             # repo root for agentic tools (read_file/grep)
    max_tool_steps: int = 30        # investigation rounds for agentic detect/triage (room to enumerate handlers/sinks across files)
    timeout: int = 60               # socket timeout: max gap between bytes / connect
    # Hard wall-clock deadline for a single HTTP call. urllib's `timeout` only bounds
    # per-socket-operation gaps, so a reasoning model that trickles bytes can block
    # far past it; this watchdog force-closes the socket at the deadline. 0 -> derive
    # a generous default from `timeout` (see effective_total_timeout).
    total_timeout: int = 0
    context_lines: int = 12         # code lines of context around a finding
    max_context_chars: int = 6000   # hard cap on a code snippet (~1.5k tok)
    drop_threshold: float = 0.75    # triage drops only false-positives at/above this confidence
    exploit_max_steps: int = 250    # exploitation: tool-loop turns against a live target (compaction keeps long runs in-context)
    # Authorization hunt: a deep investigation, like exploitation -- a real agentic run takes
    # hundreds of turns (OptiQ coding runs 200+), so 30 (the detect/triage budget) truncates it
    # mid-investigation before it concludes with findings. Dedupe + prompt caching keep it cheap.
    hunt_max_steps: int = 200
    triage_agentic: bool = False    # triage: escalate uncertain verdicts to an investigation loop
    # Streaming (recommended for cloud): read the response as it is generated, so a slow
    # generation does not trip a whole-response read timeout, and time-to-first-token is
    # visible. `stream_stall_timeout` aborts a stream with no new token for that many seconds
    # (an inter-token stall) and the call is re-issued. Opt-in so non-streaming stays default.
    stream: bool = False
    stream_stall_timeout: int = 60
    # Wire format: "openai" (chat/completions), "anthropic" (Messages API: prompt caching and
    # thinking blocks kept across tool turns; Anthropic's OpenAI-compatible layer caches
    # nothing), or "auto": anthropic when the endpoint is api.anthropic.com.
    api: str = "auto"
    enabled: bool = False

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """The model endpoint and agent settings, resolved by `frame.config`: environment
        (`FRAME_LLM_BASE_URL`, `FRAME_LLM_MODEL`, the key's variable) over the active config
        file's `[llm]` table over the defaults."""
        from frame import config
        config.warn_retired()
        s = config.section("llm")
        base = s["base_url"].rstrip("/")
        fields = {k: v for k, v in s.items() if k not in ("base_url", "api_key_env")}
        return cls(base_url=base, api_key=os.environ.get(s["api_key_env"], "sk-local"),
                   enabled=bool(base and s["model"]), **fields)


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Extract the model's JSON object from reason-first output.

    A greedy ``\\{.*\\}`` is wrong here: reasoning prose emitted before the JSON
    routinely contains braces (code snippets like ``{category}``), so first-brace
    to last-brace spans prose and fails to parse -- silently dropping every
    finding. Instead scan for balanced top-level ``{...}`` objects and return the
    LAST one that parses as a dict (the findings object is emitted last).
    """
    if not text:
        return None
    candidates: List[str] = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start >= 0:
                candidates.append(text[start:i + 1])
    for cand in reversed(candidates):
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


class LLMClient:
    """Calls an OpenAI-compatible chat endpoint. `call_fn` overrides the HTTP
    transport (used in tests and to swap in a local SDK). Layer-agnostic: prompts
    and response schemas are passed in by the caller."""

    def __init__(self, config: LLMConfig,
                 call_fn: Optional[Callable[[List[Dict[str, str]]], str]] = None):
        self.config = config
        self._call_fn = call_fn or self._http_call
        self._custom_call_fn = call_fn   # set only in tests / SDK swaps
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.stats: Dict[str, int] = {"calls": 0, "errors": 0, "dropped": 0, "kept": 0,
                                      "prompt_tokens": 0, "cached_tokens": 0, "completion_tokens": 0}
        # Timing + token usage of the most recent chat_raw call, for the agent timing log
        # (latency, prompt/cached/completion/reasoning tokens, cost, status, retries).
        self.last_call: Dict[str, Any] = {}
        # A stable session id sent as `x-session-id` for the whole run. OptiQ Cloud forwards
        # it upstream, which keeps the prompt-prefix cache warm across the many turns of a
        # tool loop (measured 70-80% of the prompt cached). One id per client = per run.
        self.session_id: str = uuid.uuid4().hex
        # Set (a threading.Event) by a caller that may cancel this client's calls: an outage
        # wait ends as soon as it is set, so a cancelled hunt never sits out the whole window.
        self.abort: Optional[Any] = None
        # Set once the endpoint has rejected `temperature` (Claude 5 models on Anthropic's
        # OpenAI-compatible endpoint answer 400 "temperature is deprecated for this model"):
        # later requests leave the field out instead of failing every call. Remembered per
        # (endpoint, model) for the process: a hunt makes one client per unit.
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

    def _http_call(self, messages: List[Dict[str, str]],
                   max_tokens: Optional[int] = None, force_json: bool = True,
                   response_format: Optional[Dict[str, Any]] = None) -> str:
        # Explicit response_format wins; otherwise a forced call defaults to a plain
        # JSON object (widely supported). A non-forced call sends nothing.
        rf = response_format if response_format is not None else (
            {"type": "json_object"} if force_json else None)
        # Degrade gracefully if the endpoint rejects the format (HTTP 400):
        # strict json_schema -> json_object -> none. Frontier models take the strict
        # schema; weaker/local ones fall back without breaking the call.
        attempts: List[Optional[Dict[str, Any]]] = [rf]
        if isinstance(rf, dict) and rf.get("type") == "json_schema":
            attempts.append({"type": "json_object"})
        if rf is not None:
            attempts.append(None)
        last_err: Optional[Exception] = None
        for fmt in attempts:
            try:
                return self._post_chat(messages, max_tokens, fmt)
            except urllib.error.HTTPError as exc:
                if exc.code == 400:          # unsupported response_format -> degrade
                    last_err = exc
                    continue
                raise
        raise last_err if last_err is not None else RuntimeError("no response_format attempt ran")

    def _effective_total_timeout(self) -> float:
        """Wall-clock deadline for one HTTP call. Defaults generously off the socket
        timeout so a legitimately slow reasoning generation still completes, while a
        genuinely hung connection is bounded."""
        tt = getattr(self.config, "total_timeout", 0) or 0
        if tt > 0:
            return float(tt)
        return float(max(self.config.timeout * 6, 600))

    def _urlopen_read(self, req: "urllib.request.Request") -> bytes:
        """urlopen + read with a hard wall-clock deadline enforced by the CALLER.

        The request runs in a daemon worker; the caller waits at most `deadline`
        seconds. urllib's own `timeout` only bounds per-operation gaps (connect,
        byte-to-byte), so a response that trickles bytes -- or a server that blocks
        inside urlopen before replying -- can otherwise hang far past it. When the
        deadline hits we close the socket (if we hold it, to unblock a stuck read)
        and raise, so the caller proceeds even if the abandoned worker lingers until
        its socket timeout.
        """
        deadline = self._effective_total_timeout()
        box: Dict[str, Any] = {}
        done = threading.Event()

        def _worker():
            try:
                resp = urllib.request.urlopen(req, timeout=self.config.timeout)
                box["resp"] = resp
                box["raw"] = resp.read()
            except Exception as exc:      # surfaced to the caller below
                box["error"] = exc
            finally:
                done.set()

        threading.Thread(target=_worker, daemon=True).start()
        if not done.wait(deadline):
            r = box.get("resp")
            if r is not None:
                try:
                    r.close()
                except Exception:
                    pass
            raise TimeoutError(
                f"LLM request exceeded {deadline:.0f}s wall-clock deadline")
        if "error" in box:
            raise box["error"]
        return box["raw"]

    def _anthropic(self) -> bool:
        from frame.sil.llm_anthropic import is_anthropic
        return is_anthropic(self.config.base_url, getattr(self.config, "api", "auto"))

    def _post_messages(self, messages, tools, max_tokens: int,
                       response_format: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """One native Messages API call, returned as an OpenAI-shaped completion."""
        from frame.sil import llm_anthropic as la
        body = la.to_request(messages, tools, self.config.model, max_tokens, response_format)
        req = urllib.request.Request(f"{self.config.base_url}/messages",
                                     data=json.dumps(body).encode("utf-8"),
                                     headers=la.headers(self.config.api_key or ""))
        return la.from_response(json.loads(self._urlopen_read(req).decode("utf-8")))

    def _post_chat(self, messages: List[Dict[str, str]], max_tokens: Optional[int],
                   response_format: Optional[Dict[str, Any]]) -> str:
        if self._anthropic():
            out = self._post_messages(messages, None, max_tokens or self.config.max_tokens,
                                      response_format)
            return out["choices"][0]["message"]["content"]
        url = f"{self.config.base_url}/chat/completions"
        body: Dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": max_tokens or self.config.max_tokens,
        }
        self._set_temperature(body)
        if response_format is not None:
            body["response_format"] = response_format
        headers = {"Content-Type": "application/json", "x-session-id": self.session_id}
        # Some local servers (e.g. OptiQ) reject *any* Authorization header; only
        # send one when a key is actually configured. Set the key's variable to "" to omit.
        if self.config.api_key and self.config.api_key.lower() not in ("none", "anything"):
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        while True:
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                         headers=headers)
            try:
                data = json.loads(self._urlopen_read(req).decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if self._temperature_rejected(exc, body):
                    continue
                raise
            return data["choices"][0]["message"]["content"]

    _NO_TEMPERATURE: set = set()

    @property
    def _omit_temperature(self) -> bool:
        return (self.config.base_url, self.config.model) in LLMClient._NO_TEMPERATURE

    def _set_temperature(self, body: Dict[str, Any]) -> None:
        if not self._omit_temperature:
            body["temperature"] = self.config.temperature

    def _temperature_rejected(self, exc: "urllib.error.HTTPError", body: Dict[str, Any],
                              detail: Optional[str] = None) -> bool:
        """True (and `temperature` dropped from `body` and every later request) when the
        endpoint answered 400 because of the `temperature` field."""
        if exc.code != 400 or "temperature" not in body:
            return False
        if detail is None:
            detail = self._error_detail(exc)
        if "temperature" not in detail:
            return False
        if not self._omit_temperature:
            _log.warning("LLM endpoint rejects `temperature`; sending requests without it")
        LLMClient._NO_TEMPERATURE.add((self.config.base_url, self.config.model))
        body.pop("temperature", None)
        return True

    def complete(self, messages: List[Dict[str, str]], *,
                 max_tokens: Optional[int] = None, force_json: bool = True,
                 response_format: Optional[Dict[str, Any]] = None) -> str:
        """Single completion returning the message content. Routes through an injected
        call_fn (tests/SDK) when present, else the HTTP transport.

        Retries transient network/DNS failures (like the agentic path) so a blip
        does not surface as an empty result -- for detection that would silently
        read as "no vulnerabilities" and drop real findings. Re-raises on final
        failure so callers can tell a failed call apart from a clean scan.
        """
        self.stats["calls"] += 1
        if self._custom_call_fn is not None:
            def _do():
                return self._custom_call_fn(messages)
        else:
            def _do():
                return self._http_call(messages, max_tokens=max_tokens,
                                       force_json=force_json,
                                       response_format=response_format)
        attempts = max(1, getattr(self.config, "agent_retries", 2) + 1)
        last_err: Optional[Exception] = None
        first_fail: Optional[float] = None
        i = 0
        while True:
            try:
                return _do()
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_err = exc
                self.stats["errors"] += 1
                first_fail = first_fail or time.time()
                asked = self._retry_after(exc)      # a rate limit says when to come back
                if i + 1 < attempts:        # transient blip -> back off and retry
                    _log.warning("LLM call to %s failed (attempt %d/%d): %s -- retrying",
                                 self.config.base_url, i + 1, attempts, exc)
                    time.sleep(asked if asked is not None else 1.5 * (i + 1))
                    i += 1
                    continue
                wait = self._outage_delay(exc, first_fail)
                if wait is None or not self._pause(asked if asked is not None else wait):
                    break
                i += 1
        _log.error("LLM endpoint %s unreachable after %d attempts: %s",
                   self.config.base_url, i + 1, last_err)
        raise LLMUnavailableError(
            f"LLM endpoint {self.config.base_url!r} unreachable after {i + 1} "
            f"attempts: {last_err}") from last_err

    def detect_complete(self, messages: List[Dict[str, str]]) -> str:
        """Detection call (reason-first): no forced JSON so the model can reason in
        prose before emitting the findings object, with a larger token budget."""
        return self.complete(messages, max_tokens=self.config.max_tokens,
                             force_json=False)

    def chat_raw(self, messages: List[Dict[str, Any]],
                 tools: Optional[list] = None) -> Optional[Dict[str, Any]]:
        """Return the full assistant message (content + any tool_calls), or None on
        failure. Used by the agentic loops (detection / exploitation tool-calling)."""
        url = f"{self.config.base_url}/chat/completions"
        body: Dict[str, Any] = {
            "model": self.config.model, "messages": messages,
            "max_tokens": getattr(self.config, "agent_max_tokens", 16000),
        }
        self._set_temperature(body)
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        headers = {"Content-Type": "application/json", "x-session-id": self.session_id}
        if self.config.api_key and self.config.api_key.lower() not in ("none", "anything"):
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        data = json.dumps(body).encode("utf-8")
        attempts = max(1, getattr(self.config, "agent_retries", 2) + 1)
        native = self._anthropic()          # Messages API (prompt caching); never streamed here
        streaming = bool(getattr(self.config, "stream", False)) and not native
        first_fail: Optional[float] = None
        # Every failed attempt of this call: when, which error and why. The call record keeps
        # them even when a retry succeeds, so an outage can be told apart (DNS, refused, reset,
        # timeout) and placed in time; before, a rescued call logged only `retries`.
        failures: List[Dict[str, Any]] = []
        i = -1
        while True:
            i += 1
            t0 = time.time()
            try:
                self.stats["calls"] += 1
                if native:
                    out = self._post_messages(messages, tools, body["max_tokens"])
                elif streaming:
                    msg = self._chat_stream(url, body, headers)
                    self._finish_record(t0, i, failures)
                    return msg
                else:
                    req = urllib.request.Request(url, data=data, headers=headers)
                    out = json.loads(self._urlopen_read(req).decode("utf-8"))
                self.last_call = self._usage_record(out, time.time() - t0, i)
                self._finish_record(t0, i, failures)
                self.stats["prompt_tokens"] += self.last_call.get("prompt_tokens") or 0
                self.stats["cached_tokens"] += self.last_call.get("cached_tokens") or 0
                self.stats["completion_tokens"] += self.last_call.get("completion_tokens") or 0
                return out["choices"][0]["message"]
            except urllib.error.HTTPError as exc:
                self.stats["errors"] += 1
                detail = self._error_detail(exc)
                if not native and self._temperature_rejected(exc, body, detail):
                    data = json.dumps(body).encode("utf-8")
                    i -= 1                    # not a failed attempt: the same call, resent
                    continue
                self._note_failure(failures, t0, f"HTTP {exc.code}", detail)
                self.last_call = {"status": "error", "error": f"HTTP {exc.code}",
                                  "latency_s": round(time.time() - t0, 2), "retries": i,
                                  "detail": detail}
                self._finish_record(t0, i, failures)
                if exc.code in (400, 401):        # malformed request / bad auth: retrying cannot help
                    return None
                first_fail = first_fail or t0
                asked = self._retry_after(exc)      # a rate limit says when to come back
                if i + 1 < attempts:
                    time.sleep(asked if asked is not None else self._agent_backoff(i))
                    continue
                wait = self._outage_delay(exc, first_fail)
                if wait is not None and self._pause(asked if asked is not None else wait):
                    continue
                return None
            except (_DroppedStream, urllib.error.URLError, KeyError, ValueError,
                    TimeoutError, OSError) as exc:
                self.stats["errors"] += 1
                reason = self._failure_reason(exc)
                self._note_failure(failures, t0, type(exc).__name__, reason)
                self.last_call = {"status": "error", "error": type(exc).__name__,
                                  "latency_s": round(time.time() - t0, 2), "retries": i,
                                  "detail": reason}
                self._finish_record(t0, i, failures)
                first_fail = first_fail or t0
                if i + 1 < attempts:      # transient blip / dropped stream -> back off and retry
                    time.sleep(self._agent_backoff(i))
                    continue
                wait = self._outage_delay(exc, first_fail)
                if wait is not None and self._pause(wait):
                    continue
                return None

    _RETRY_AFTER_CAP = 120.0   # seconds; a longer wait goes through the outage window instead

    @classmethod
    def _retry_after(cls, exc: BaseException) -> Optional[float]:
        """The wait a 429 or 503 asks for in its `Retry-After` header (seconds, or an HTTP date),
        plus up to a second of jitter so agents refused together do not all come back at the
        same instant (a per-minute limit resets for everyone at once); None when the error is
        not one of those or carries no usable header. Retrying sooner wastes the budget: a
        refused request counts against the limit too."""
        if not isinstance(exc, urllib.error.HTTPError) or exc.code not in (429, 503):
            return None
        raw = (exc.headers.get("Retry-After") if exc.headers is not None else None) or ""
        raw = str(raw).strip()
        if not raw:
            return None
        try:
            secs = float(raw)
        except ValueError:
            try:
                when = parsedate_to_datetime(raw)
            except (TypeError, ValueError):
                return None
            if when is None:
                return None
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            secs = (when - datetime.now(timezone.utc)).total_seconds()
        if secs != secs or secs < 0:
            secs = 0.0
        return min(secs, cls._RETRY_AFTER_CAP) + random.uniform(0.0, 1.0)

    _MAX_FAILURES = 20   # failed attempts kept per call record (an hour-long outage is ~120)

    @staticmethod
    def _failure_reason(exc: BaseException) -> str:
        """Why a connection-level attempt failed, as the error says it: a URLError's `reason`
        ("[Errno -3] Temporary failure in name resolution", "[Errno 111] Connection refused",
        "timed out"...), else the exception's own message, with its class when it has none."""
        reason = getattr(exc, "reason", None) if isinstance(exc, urllib.error.URLError) else None
        text = str(reason if reason is not None else exc) or type(exc).__name__
        return text[:300]

    @staticmethod
    def _timestamp(t: float) -> str:
        return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="milliseconds")[:-6] + "Z"

    def _note_failure(self, failures: List[Dict[str, Any]], t0: float, error: str,
                      reason: str) -> None:
        """Record one failed attempt (UTC start time, error, reason) and log it."""
        if len(failures) < self._MAX_FAILURES:
            failures.append({"at": self._timestamp(t0), "error": error, "reason": reason,
                             "latency_s": round(time.time() - t0, 2)})
        _log.info("LLM attempt to %s failed after %.1fs: %s (%s)", self.config.base_url,
                  time.time() - t0, error, reason)

    def _finish_record(self, t0: float, retries: int, failures: List[Dict[str, Any]]) -> None:
        """Stamp the call record with the final attempt's UTC start time, its retry count, and
        the failed attempts before it (if any)."""
        rec = self.last_call
        rec["at"] = self._timestamp(t0)
        rec["retries"] = retries
        if failures:       # the first _MAX_FAILURES; `retries` still counts them all
            rec["failures"] = list(failures)

    @staticmethod
    def _error_detail(exc: "urllib.error.HTTPError") -> str:
        """The start of an HTTP error's body (the endpoint's reason), for the call log: a 400
        logged as only "HTTP 400" left a rejected request indistinguishable from any other."""
        try:
            return (exc.read() or b"")[:500].decode("utf-8", "replace")
        except Exception:
            return ""

    _OUTAGE_HTTP = frozenset({408, 425, 429, 500, 502, 503, 504})

    def _outage_delay(self, exc: BaseException, first_fail: float) -> Optional[float]:
        """Seconds to wait before one more try once the normal retries are spent, or None to
        give up: only for failures that say the endpoint is unreachable or overloaded (network
        errors, a dropped stream, HTTP 408/429/5xx; never a reply the model got wrong), only
        while `outage_wait` has not elapsed since the first failure, and never once aborted."""
        window = getattr(self.config, "outage_wait", 0) or 0
        if window <= 0 or (self.abort is not None and self.abort.is_set()):
            return None
        if isinstance(exc, urllib.error.HTTPError):
            if exc.code not in self._OUTAGE_HTTP and exc.code < 500:
                return None
        elif not isinstance(exc, (_DroppedStream, urllib.error.URLError, TimeoutError, OSError)):
            return None
        left = window - (time.time() - first_fail)
        if left <= 0:
            return None
        if self.stats.get("outage_waits", 0) % 10 == 0:
            _log.warning("LLM endpoint %s unreachable (%s); waiting up to %ds more for it",
                         self.config.base_url, type(exc).__name__, int(left))
        self.stats["outage_waits"] = self.stats.get("outage_waits", 0) + 1
        return float(min(30.0, left))

    def _pause(self, seconds: float) -> bool:
        """Sleep, waking early if the caller aborts. True = go on and retry."""
        if self.abort is not None:
            return not self.abort.wait(seconds)
        time.sleep(seconds)
        return True

    @staticmethod
    def _agent_backoff(attempt: int) -> float:
        """Exponential backoff between agent-turn retries: 2, 4, 8, 16, 30, 30... seconds. An
        agent turn is one step of a long run (a hunt is 200 of them), so riding out a minute of
        endpoint trouble is cheap; giving up after a few seconds silently ended whole hunts
        (11 of 30 BAC-Bench cases in one run lost their agent to a short outage)."""
        return float(min(30, 2 ** (attempt + 1)))

    def cache_hit_rate(self) -> Optional[float]:
        """Cached prompt tokens / total prompt tokens over the run (None if nothing seen).
        A low number across a long tool loop means the prompt prefix is not stable."""
        p = self.stats.get("prompt_tokens", 0)
        return round(self.stats.get("cached_tokens", 0) / p, 3) if p else None

    @staticmethod
    def _usage_record(resp: Dict[str, Any], latency_s: float, retries: int) -> Dict[str, Any]:
        """Per-call usage/timing from a response. `prompt_tokens` ALREADY includes cached
        tokens (OptiQ/DeepSeek), so cache-hit rate is cached/prompt -- never add them."""
        u = resp.get("usage") or {}
        pd = u.get("prompt_tokens_details") or {}
        cd = u.get("completion_tokens_details") or {}
        rec: Dict[str, Any] = {"status": "ok", "latency_s": round(latency_s, 2), "retries": retries,
                               "prompt_tokens": u.get("prompt_tokens"),
                               "cached_tokens": pd.get("cached_tokens"),
                               **({"cache_write_tokens": pd["cache_write_tokens"]}
                                  if pd.get("cache_write_tokens") else {}),
                               "completion_tokens": u.get("completion_tokens"),
                               "reasoning_tokens": cd.get("reasoning_tokens")}
        # Why generation stopped. A safety refusal ("content_filter" / "refusal") otherwise reads
        # as an agent that answered briefly and stopped, and a truncation ("length") as one that
        # forgot to call its tool -- both silently empty a hunt unit.
        finish = ((resp.get("choices") or [{}])[0] or {}).get("finish_reason")
        if finish:
            rec["finish_reason"] = finish
        if "cost" in u:
            rec["cost"] = u.get("cost")
        # OpenRouter reports top-level `cost` as 0 under BYOK (bring-your-own-key: the spend
        # lands on the upstream provider account, not OpenRouter credits); the real inference
        # cost is then in cost_details.upstream_inference_cost. Prefer a non-zero top-level
        # cost, else fall back to the upstream figure, so spend is captured either way. Leaves
        # providers that report a plain top-level `cost` (OptiQ) unchanged.
        if not rec.get("cost"):
            up = (u.get("cost_details") or {}).get("upstream_inference_cost")
            if up:
                rec["cost"] = up
        return rec

    @staticmethod
    def _assemble_stream(events: List[Dict[str, Any]]) -> "tuple":
        """Assemble streamed SSE chunks into one OpenAI-shaped message + usage. Content and
        each tool call's `arguments` arrive as deltas and are concatenated by index. An
        in-stream `{"error": ...}` object means a dropped stream. Pure, so it is unit-tested
        without a network."""
        content: List[str] = []
        tools: Dict[int, Dict[str, Any]] = {}
        usage: Dict[str, Any] = {}
        for obj in events:
            if not isinstance(obj, dict):
                continue
            if obj.get("error"):
                raise _DroppedStream(str(obj["error"])[:200])
            if obj.get("usage"):
                usage = obj["usage"]
            for ch in obj.get("choices") or []:
                delta = ch.get("delta") or {}
                if delta.get("content"):
                    content.append(delta["content"])
                for tc in delta.get("tool_calls") or []:
                    idx = tc.get("index", 0)
                    slot = tools.setdefault(idx, {"id": "", "type": "function",
                                                  "function": {"name": "", "arguments": ""}})
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["function"]["name"] += fn["name"]
                    if fn.get("arguments"):
                        slot["function"]["arguments"] += fn["arguments"]
        msg: Dict[str, Any] = {"content": "".join(content)}
        if tools:
            msg["tool_calls"] = [tools[k] for k in sorted(tools)]
        return msg, usage

    def _chat_stream(self, url: str, body: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """One streamed chat call. Reads SSE lines with an inter-token stall timeout, records
        time-to-first-token, and returns the assembled message. Raises _DroppedStream on a
        stall or an in-stream error, HTTPError on an HTTP error."""
        body = dict(body, stream=True, stream_options={"include_usage": True})
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers)
        stall = max(5, int(getattr(self.config, "stream_stall_timeout", 60)))
        t0 = time.time()
        first_token_s: Optional[float] = None
        events: List[Dict[str, Any]] = []
        resp = urllib.request.urlopen(req, timeout=stall)   # each readline is bounded by `stall`
        try:
            while True:
                line = resp.readline()                      # raises socket.timeout on a stall
                if not line:
                    break
                s = line.decode("utf-8", "replace").strip()
                if not s or s.startswith(":") or not s.startswith("data:"):
                    continue
                payload = s[5:].strip()
                if payload == "[DONE]":
                    break
                try:
                    obj = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                if first_token_s is None and (obj.get("choices") or []):
                    first_token_s = time.time() - t0
                events.append(obj)
        except (TimeoutError, OSError) as exc:              # socket.timeout is an OSError
            raise _DroppedStream(f"stall: {type(exc).__name__}") from exc
        finally:
            try:
                resp.close()
            except Exception:
                pass
        msg, usage = self._assemble_stream(events)
        # the last chunk that names one says why generation stopped (a truncation must not read
        # as an agent that answered)
        finish = next((c.get("finish_reason") for obj in reversed(events) if isinstance(obj, dict)
                       for c in (obj.get("choices") or [])[:1]
                       if isinstance(c, dict) and c.get("finish_reason")), None)
        self.last_call = self._usage_record(
            {"usage": usage, **({"choices": [{"finish_reason": finish}]} if finish else {})},
            time.time() - t0, 0)
        if first_token_s is not None:
            self.last_call["first_token_s"] = round(first_token_s, 2)
        self.stats["prompt_tokens"] += self.last_call.get("prompt_tokens") or 0
        self.stats["cached_tokens"] += self.last_call.get("cached_tokens") or 0
        self.stats["completion_tokens"] += self.last_call.get("completion_tokens") or 0
        return msg
