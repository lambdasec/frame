"""HuggingFace Session Trace (STS-Format) for Frame's agent loops.

The Hub's trace viewer reads a JSONL file: a `session` header line, then one `message`
line per turn. Spec: https://huggingface.co/docs/hub/session-traces-format. Frame's
internal messages are OpenAI-shaped, so this converts on the way out and back on the way
in. Each line is appended and FLUSHED as soon as the message exists -- a hard kill or a
timeout keeps the trace up to that point (unlike saving only at the end of a run) -- so a
stalled run is diagnosable from its trace, and an interrupted run can resume from it.

A sidecar `<trace>.calls.jsonl` records one line per model call (latency, time to first
token, prompt / cached / completion / reasoning tokens, cost, status, retries): the timing
log that tells "slow to start" from "slow to write" and shows the prompt-cache hit rate.

Paths and usernames are redacted before a line is written, so a trace is safe to share.
"""

from __future__ import annotations

import getpass
import json
import os
from typing import Any, Dict, List, Optional, Tuple

HARNESS = "frame"


# ---- redaction -----------------------------------------------------------------

def _default_redactor() -> "callable":
    """Replace the current user's home directory and name with placeholders, so a trace
    that leaves the machine carries no local identity (OptiQ's `local_identity_redactor`)."""
    home = os.path.expanduser("~")
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    def redact(text: str) -> str:
        if not text:
            return text
        if home and home != "/":
            text = text.replace(home, "~")
        if user and len(user) >= 3:
            text = text.replace("/" + user + "/", "/<user>/")
        return text
    return redact


# ---- OpenAI <-> STS message conversion -----------------------------------------

def message_to_stf(msg: Dict[str, Any]) -> Dict[str, Any]:
    """An internal OpenAI-shaped message -> an STS `message` object (camelCase)."""
    out: Dict[str, Any] = {"role": msg.get("role", ""), "content": msg.get("content") or ""}
    tcs = msg.get("tool_calls")
    if tcs:
        out["toolCalls"] = [
            {"id": tc.get("id", ""),
             "function": {"name": (tc.get("function") or {}).get("name", ""),
                          # STS requires `arguments` as a JSON STRING, as the API returns it.
                          "arguments": (tc.get("function") or {}).get("arguments") or "{}"}}
            for tc in tcs]
    if msg.get("tool_call_id"):
        out["toolCallId"] = msg["tool_call_id"]
    if msg.get("reasoning_content"):
        out["reasoningContent"] = msg["reasoning_content"]
    if msg.get("model"):
        out["model"] = msg["model"]
    return out


def stf_to_message(m: Dict[str, Any]) -> Dict[str, Any]:
    """An STS `message` object -> an internal OpenAI-shaped message (for resume)."""
    out: Dict[str, Any] = {"role": m.get("role", ""), "content": m.get("content") or ""}
    tcs = m.get("toolCalls")
    if tcs:
        out["tool_calls"] = [
            {"id": tc.get("id", ""), "type": "function",
             "function": {"name": (tc.get("function") or {}).get("name", ""),
                          "arguments": (tc.get("function") or {}).get("arguments") or "{}"}}
            for tc in tcs]
    if m.get("toolCallId"):
        out["tool_call_id"] = m["toolCallId"]
    if m.get("reasoningContent"):      # kept across resume so the thinking is not lost
        out["reasoning_content"] = m["reasoningContent"]
    return out


def read_stf(path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Read a trace back as (session header, OpenAI-shaped messages). Used to resume a run."""
    header: Dict[str, Any] = {}
    messages: List[Dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue                 # a truncated last line from a hard kill: skip it
            if obj.get("type") == "session":
                header = obj
            elif obj.get("type") == "message" and isinstance(obj.get("message"), dict):
                messages.append(stf_to_message(obj["message"]))
    return header, messages


# ---- incremental writer --------------------------------------------------------

class TraceWriter:
    """Appends STS-Format JSONL, flushing every line. If the file already has content it
    is a RESUME: the header and the messages already there are left untouched and only new
    messages are appended (so a resumed run continues one coherent trace)."""

    def __init__(self, path: str, session_id: str, name: str = "",
                 redactor: Optional["callable"] = None):
        self.path = path
        self.session_id = session_id
        self.name = name
        self._redact = redactor if redactor is not None else _default_redactor()
        self.resumed = os.path.isfile(path) and os.path.getsize(path) > 0
        self.calls_path = path + ".calls.jsonl"

    def start(self) -> None:
        """Write the session header, unless resuming an existing trace."""
        if self.resumed:
            return
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._write(self.path, {"type": "session", "harness": HARNESS,
                                "id": self.session_id, "name": self.name})

    def _redact_message(self, m: Dict[str, Any]) -> Dict[str, Any]:
        m = dict(m)
        if isinstance(m.get("content"), str):
            m["content"] = self._redact(m["content"])
        return m

    def append_message(self, msg: Dict[str, Any]) -> None:
        self._write(self.path, {"type": "message",
                                "message": message_to_stf(self._redact_message(msg))})

    def append_call(self, call: Dict[str, Any]) -> None:
        """One per-call timing/usage record to the sidecar (not part of the STS stream)."""
        if call:
            self._write(self.calls_path, call)

    @staticmethod
    def _write(path: str, obj: Dict[str, Any]) -> None:
        # Append + flush + fsync: the line is on disk before the next model call, so a
        # crash loses at most the call in flight.
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            pass            # a tracing failure must never break the run


# ---- offline deterministic replay ----------------------------------------------

class ReplayClient:
    """Feeds the assistant turns of a saved trace back into `run_agent`, in order, with no
    model call -- so a recorded run replays deterministically. The tools re-run (against the
    same model decisions), which makes this a regression test for the harness and tools, and
    a way to debug a run offline. `chat_raw` returns None once the saved turns are exhausted."""

    def __init__(self, trace_path: str):
        _, msgs = read_stf(trace_path)
        self._assistants = [m for m in msgs if m.get("role") == "assistant"]
        self._i = 0
        self.config = None
        self.last_call: Dict[str, Any] = {"status": "replay"}
        self.stats: Dict[str, Any] = {"calls": 0}

    def chat_raw(self, messages, tools=None):
        if self._i >= len(self._assistants):
            return None
        m = self._assistants[self._i]
        self._i += 1
        self.stats["calls"] += 1
        out = {"content": m.get("content") or ""}
        if m.get("tool_calls"):
            out["tool_calls"] = m["tool_calls"]
        return out

    def complete(self, messages, **kw):
        m = self.chat_raw(messages)
        return (m or {}).get("content") or ""
