"""Common agentic substrate for Frame's LLM layers.

All three LLM layers are the same investigation at increasing commitment --
detect ("where is it?"), triage ("is it real?"), exploit ("can I trigger it?") --
so they share one tool loop. This module owns that loop plus the tools two of the
three share (repo investigation: `read_file` / `grep`). Each layer supplies only
its system prompt and how it *terminates*:

  * self-terminating (detect / triage): when the model stops calling tools, its
    content IS the answer -- pass a `finalize(content) -> result` hook.
  * oracle-terminating (exploit): an external, observable check decides success --
    pass a `check_done() -> result | None` hook.

The persistence nudge (when an oracle-driven agent stalls) and the force-final
prompt (when a self-terminating agent exhausts its budget) are generic, keyed off
which hook is set -- so the whole thing is exactly two hooks, not four.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

DEFAULT_STALL = ("Do not stop or summarize. Take the next concrete step now by "
                 "calling a tool with a real command/query.")
DEFAULT_FINAL = "Provide your final answer now as the JSON object."


@dataclass
class AgentResult:
    result: Any                 # whatever finalize/check_done produced
    done: bool                  # terminated on a real result vs budget/transport failure
    steps: int
    transcript: List[Dict[str, Any]] = field(default_factory=list)


# ---- Shared repo-investigation tools (detect + triage) -------------------------

INVESTIGATION_TOOLS = [
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


def _repo_exec(name: str, args: Dict[str, Any], repo_root: str, max_chars: int = 8000) -> str:
    """Execute a repo-investigation tool (read_file / grep) locally."""
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


def investigation_exec(repo_root: str,
                       explored: Optional[set] = None) -> Callable[[str, Dict[str, Any]], str]:
    """Executor for the investigation tools; records read files into `explored`
    (used later for cross-file sink grounding)."""
    def _exec(name: str, args: Dict[str, Any]) -> str:
        if name == "read_file" and explored is not None and args.get("path"):
            explored.add(str(args.get("path")))
        return _repo_exec(name, args, repo_root)
    return _exec


# ---- The loop ------------------------------------------------------------------

def run_agent(messages: List[Dict[str, Any]], client, *,
              tools: list, exec_tool: Callable[[str, Dict[str, Any]], str],
              max_steps: int,
              finalize: Optional[Callable[[str], Any]] = None,
              check_done: Optional[Callable[[], Any]] = None,
              max_tool_output: int = 8000,
              stall_nudge: str = DEFAULT_STALL,
              final_nudge: str = DEFAULT_FINAL) -> AgentResult:
    """Drive `client` through a tool loop over `messages`.

    Exactly one of `finalize` (self-terminating: parse the model's no-tool-call
    output) or `check_done` (oracle-terminating: external success check, non-None
    to stop) should be supplied. Returns an AgentResult.
    """
    step = 0
    for step in range(1, max_steps + 1):
        # Oracle-driven agents: did the previous action achieve the objective?
        if check_done is not None:
            r = check_done()
            if r is not None:
                return AgentResult(r, True, step - 1, messages)

        msg = client.chat_raw(messages, tools)
        if msg is None:
            # Transport hiccup. Self-terminating agents stop with an empty result;
            # oracle-driven agents keep trying.
            if finalize is not None:
                return AgentResult(finalize(""), False, step, messages)
            messages.append({"role": "user", "content": "(no response) Continue: call a tool now."})
            continue

        tool_calls = msg.get("tool_calls") or []
        messages.append({"role": "assistant", "content": msg.get("content") or "",
                         **({"tool_calls": tool_calls} if tool_calls else {})})

        if tool_calls:
            for tc in tool_calls:
                fn = tc.get("function", {}) or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except (json.JSONDecodeError, TypeError):
                    args = {}
                out = exec_tool(fn.get("name", ""), args)
                messages.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                                 "content": (out or "")[:max_tool_output]})
            continue

        # No tool call.
        if finalize is not None:
            return AgentResult(finalize(msg.get("content") or ""), True, step, messages)
        # Oracle-driven agent narrated without acting -> push a concrete step
        # (the oracle is re-checked at the top of the next iteration).
        messages.append({"role": "user", "content": stall_nudge})

    # Budget exhausted.
    if finalize is not None:
        messages.append({"role": "user", "content": final_nudge})
        msg = client.chat_raw(messages)
        return AgentResult(finalize((msg or {}).get("content") or ""), True, step, messages)
    r = check_done() if check_done is not None else None
    return AgentResult(r, r is not None, step, messages)
