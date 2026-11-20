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
    # Why the loop ended: "finished" (a final answer), "oracle" (check_done fired), "budget"
    # (step cap), "transport_error" (the endpoint gave no reply after the client's retries).
    stop: str = ""


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

# Every language Frame's LLM detection can run over (a superset of the symbolic
# frontends: the agent must be able to grep PHP / Ruby / Rust etc. where there is no
# frontend but the LLM tier still applies). Keep in step with llm_detect._LANGUAGE_EXTENSIONS.
_GREP_EXTS = (".java", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".cs",
              ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".go", ".php", ".rb", ".rs",
              ".kt", ".kts")


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


def sandbox_python(code: str, cwd: str, timeout_s: int = 60, max_chars: int = 8000,
                   interpreter: Optional[str] = None) -> str:
    """Run a short agent-written Python probe in a subprocess and return its output.

    This is the hunt's DYNAMIC testing primitive: the agent writes a script that drives the
    target application's own test client (Flask `test_client`, Django `Client`, FastAPI
    `TestClient`) as two different users and observes whether one can reach the other's
    resource -- confirming a candidate IDOR by exercise, not by reading code. It is gated OFF
    by default (see `hunt_authz(dynamic=...)`), so it never runs during an ordinary scan or a
    benchmark unless dynamic testing is explicitly enabled.

    Sandboxing: a fresh process group (so a timeout kills the whole tree, including any server
    the probe spawned), a hard wall-clock timeout, cwd pinned to the repo, combined stdout+stderr
    captured and truncated. `interpreter` lets the caller point at the app's own virtualenv so the
    probe can import the application; it defaults to the current interpreter."""
    import signal
    import subprocess
    import sys
    import tempfile

    interp = interpreter or sys.executable
    # The probe is meant to IMPORT the target application, so the repo must be importable: put it
    # first on PYTHONPATH (Python would otherwise only add the script's own tempdir to sys.path).
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([os.path.realpath(cwd), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    with tempfile.TemporaryDirectory() as td:
        script = os.path.join(td, "frame_probe.py")
        try:
            with open(script, "w", encoding="utf-8") as fh:
                fh.write(code or "")
            proc = subprocess.Popen(  # noqa: S603 - research sandbox, no shell, fixed argv
                [interp, script], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, start_new_session=True, env=env)
        except OSError as e:
            return f"ERROR: could not start probe: {e}"
        try:
            out, _ = proc.communicate(timeout=timeout_s)
            return f"exit={proc.returncode}\n{(out or '')[:max_chars]}"
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            out, _ = proc.communicate()
            return f"TIMEOUT after {timeout_s}s (killed)\n{(out or '')[:max_chars]}"


def investigation_exec(repo_root: str,
                       explored: Optional[set] = None) -> Callable[[str, Dict[str, Any]], str]:
    """Executor for the investigation tools; records read files into `explored`
    (used later for cross-file sink grounding)."""
    def _exec(name: str, args: Dict[str, Any]) -> str:
        if name == "read_file" and explored is not None and args.get("path"):
            explored.add(str(args.get("path")))
        return _repo_exec(name, args, repo_root)
    return _exec


# ---- Context compaction (keeps long sessions inside the window) ----------------

_ELIDED = "[earlier tool result elided to save context]"
_FOLD_MARK = "[Progress so far, earlier steps folded to save context; calls made:]"


def _context_chars(messages: List[Dict[str, Any]]) -> int:
    return sum(len(str(m.get("content") or "")) for m in messages)


def _compact_messages(messages: List[Dict[str, Any]], client=None,
                      keep_recent: int = 6, target_chars: Optional[int] = None) -> List[Dict[str, Any]]:
    """Shrink a long transcript by replacing OLD tool-result content with a short placeholder,
    keeping the stable prefix (system + task, messages[0:2]) and the last `keep_recent` turns in
    full. No model call -- unlike a summary this is cheap, deterministic, and preserves the
    cached prefix (the big, stable task prompt keeps hitting the provider cache), as OptiQ does.
    Tool results (file contents, grep dumps) are the bulk of a long run; the assistant turns
    (reasoning + tool calls) are small and kept, so the record of WHAT was done stays intact and
    every tool_call_id still pairs with its result. `client` is unused (kept for signature).

    With `target_chars`, only the OLDEST tool results are elided, until the transcript fits
    `target_chars`: a compaction is a rewrite that costs the endpoint's prefix cache from the
    first edited message on, so it should be rare and large (OptiQ Code's measured lesson). Eliding
    everything outside the recent tail on every turn past the budget edited the history at a new
    place each turn, so every turn re-read its prompt uncached."""
    prefix = 2 if len(messages) >= 2 and messages[1].get("role") in ("user", "system") else 1
    if len(messages) <= keep_recent + prefix:
        return messages
    head = messages[:prefix]
    middle = messages[prefix:len(messages) - keep_recent]
    tail = messages[len(messages) - keep_recent:]
    size = _context_chars(messages)

    def shrink(part: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        nonlocal size
        out: List[Dict[str, Any]] = []
        for m in part:
            content = str(m.get("content") or "")
            if m.get("role") == "tool" and len(content) > len(_ELIDED) + 80 and (
                    target_chars is None or size > target_chars):
                gist = content[:60].replace("\n", " ")
                short = f"{_ELIDED} (was: {gist}...)"
                size -= len(content) - len(short)
                out.append({**m, "content": short})
            else:
                out.append(m)
        return out

    middle = shrink(middle)
    if target_chars is not None and size > target_chars and middle:
        # Placeholders and assistant turns cannot be elided, so over a long run they alone pass the
        # target and every turn compacts again. Fold the oldest whole turns (a call with its
        # results, so tool-call ids still pair) into a progress note on the task message, built
        # from the calls themselves (no model call), as OptiQ Code does.
        folded: List[str] = []
        while middle and size > target_chars:
            group = [middle.pop(0)]
            ids = {tc.get("id") for tc in (group[0].get("tool_calls") or [])}
            while middle and middle[0].get("role") == "tool" and middle[0].get("tool_call_id") in ids:
                group.append(middle.pop(0))
            size -= sum(len(str(m.get("content") or "")) for m in group)
            for tc in group[0].get("tool_calls") or []:
                fn = tc.get("function") or {}
                folded.append(f"{fn.get('name')}({str(fn.get('arguments') or '')[:60]})")
        if folded and isinstance(head[-1].get("content"), str):
            task = head[-1]["content"].split(_FOLD_MARK, 1)
            earlier = task[1].strip() if len(task) > 1 else ""
            calls = ((earlier + "; ") if earlier else "") + "; ".join(folded)
            note = f"{_FOLD_MARK} {calls[-2000:]}"
            head = head[:-1] + [{**head[-1], "content": task[0].rstrip() + "\n\n" + note}]
            size += len(note) + 2 - (len(_FOLD_MARK) + 1 + len(earlier) if earlier else 0)
    if target_chars is not None and size > target_chars and len(tail) > 2:
        # the recent tail is protected by count, but a few big results can hold it above the
        # target, and a compaction that cannot reach it recurs on the next turn: cap it by size,
        # keeping the last two messages word for word
        tail = shrink(tail[:-2]) + tail[-2:]
    return head + middle + tail


# ---- The loop ------------------------------------------------------------------

MAX_TRUNCATED = 3
TRUNCATED_NUDGE = ("(Your last reply was cut off at the output limit before you called a tool or "
                   "answered. Do not deliberate at length: make the next tool call now, or give "
                   "your final answer briefly.)")


def _native_blocks(msg: Dict[str, Any]) -> Dict[str, Any]:
    """The provider's own content blocks for this assistant turn (the Anthropic Messages API's,
    thinking included), kept on the message so the next request sends them back unchanged:
    a tool loop on a thinking model must return them as they came."""
    native = msg.get("anthropic_content")
    return {"anthropic_content": native} if native else {}


def run_agent(messages: List[Dict[str, Any]], client, *,
              tools: list, exec_tool: Callable[[str, Dict[str, Any]], str],
              max_steps: int,
              finalize: Optional[Callable[[str], Any]] = None,
              check_done: Optional[Callable[[], Any]] = None,
              max_tool_output: int = 8000,
              stall_nudge: str = DEFAULT_STALL,
              final_nudge: str = DEFAULT_FINAL,
              compact_at_chars: Optional[int] = None,
              keep_recent: int = 6,
              trace: Optional[Any] = None,
              dedupe_tools: Optional[set] = None,
              step_hook: Optional[Callable[[int], Optional[str]]] = None,
              on_final: Optional[Callable[[str], Optional[str]]] = None) -> AgentResult:
    """Drive `client` through a tool loop over `messages`.

    Exactly one of `finalize` (self-terminating: parse the model's no-tool-call
    output) or `check_done` (oracle-terminating: external success check, non-None
    to stop) should be supplied. When `compact_at_chars` is set, the transcript is
    summarized down once it exceeds that many characters, so long runs stay inside
    the context window. When `trace` (a llm_trace.TraceWriter) is given, every message
    is appended and flushed to disk as it appears and every call's timing/usage is
    logged, so a stall is diagnosable and an interrupted run can resume. Returns an
    AgentResult. `dedupe_tools` is a set of (idempotent) tool names whose exact-argument
    repeat is refused in the harness -- the agent gets "you already ran this" instead of a
    re-execution, which stops the enumerate-the-same-thing loops that prose alone never
    prevents. Pass it only for read-only tools (never for commands with side effects).

    `step_hook(step) -> Optional[str]` is called at the top of each step with the step number;
    if it returns a string, that string is appended as a user nudge before the model is called.
    It is how a caller injects convergence pressure (a finish-gate: "you have not found a new
    finding in a while -- stop if you are done") without the loop knowing what progress means.
    The hook owns its own cadence (fire once, cool down); it must stay cheap and side-effect free.

    `on_final(content) -> Optional[str]` (self-terminating agents only) is called when the model
    answers without a tool call. A returned string is appended as a user nudge and the loop goes
    on instead of finishing: a coverage gate ("these handlers have no verdict yet"). The caller
    bounds how often it fires; returning None accepts the answer.
    """
    seen_calls: Dict[str, int] = {}

    def _t_msg():
        if trace is not None:
            trace.append_message(messages[-1])

    def _exec_tool_calls(tool_calls: List[Dict[str, Any]]) -> None:
        # Run each tool call, append its result to the transcript, and enforce idempotent-repeat
        # refusal. Shared by the main loop and the force-final turn so report_finding (and every
        # other tool) behaves identically whether the agent calls it mid-run or on its last turn.
        for tc in tool_calls:
            fn = tc.get("function", {}) or {}
            name = fn.get("name", "")
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args)
            except (json.JSONDecodeError, TypeError):
                args = {}
            key = f"{name}({raw_args})"
            if dedupe_tools and name in dedupe_tools and key in seen_calls:
                # Idempotent tool, identical arguments: refuse to re-run (the result is
                # already in the transcript). Harness-enforced; prose does not stop this.
                n = seen_calls[key]
                seen_calls[key] = n + 1
                out = (f"(You already called {name} with these exact arguments {n} time(s); "
                       f"its result is earlier in this conversation. Do not repeat it -- use "
                       f"what you have, or investigate something new.)")
            else:
                out = exec_tool(name, args)
                if dedupe_tools and name in dedupe_tools:
                    seen_calls[key] = seen_calls.get(key, 0) + 1
            messages.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                             "content": (out or "")[:max_tool_output]})
            _t_msg()

    if trace is not None:
        trace.start()
        if not getattr(trace, "resumed", False):   # a resumed trace already holds these
            for _m in messages:
                trace.append_message(_m)
    step = 0
    truncated = 0                   # consecutive replies cut off at the output limit
    for step in range(1, max_steps + 1):
        # Oracle-driven agents: did the previous action achieve the objective?
        if check_done is not None:
            r = check_done()
            if r is not None:
                return AgentResult(r, True, step - 1, messages, stop="oracle")

        # Convergence pressure: let the caller nudge the agent to wrap up (a finish-gate).
        if step_hook is not None:
            nudge = step_hook(step)
            if nudge:
                messages.append({"role": "user", "content": nudge})
                _t_msg()

        # An endpoint that compacts on its own (the Messages API) gets the history unedited:
        # rewriting old turns would invalidate their thinking blocks and the cached prefix.
        # Elsewhere a compaction is rare and large: shrink to half the budget, and keep the
        # result only when it frees a tenth of the budget (a smaller saving costs more cache
        # than it saves); between compactions the history only grows.
        size = _context_chars(messages)
        if compact_at_chars and getattr(client, "server_compacts", False) is not True \
                and size > compact_at_chars:
            smaller = _compact_messages(messages, client, keep_recent, target_chars=compact_at_chars // 2)
            if size - _context_chars(smaller) >= compact_at_chars // 10:
                messages = smaller

        msg = client.chat_raw(messages, tools)
        if msg is None:
            # Transport failure (after the client's own retries). Log the failed call so it is
            # visible in the trace -- an unlogged failure read as a hunt that found nothing.
            # Self-terminating agents stop with what they have; oracle-driven ones keep trying.
            if trace is not None:
                trace.append_call(getattr(client, "last_call", {}))
            if finalize is not None:
                return AgentResult(finalize(""), False, step, messages, stop="transport_error")
            messages.append({"role": "user", "content": "(no response) Continue: call a tool now."})
            _t_msg()
            continue

        tool_calls = msg.get("tool_calls") or []
        messages.append({"role": "assistant", "content": msg.get("content") or "",
                         **({"tool_calls": tool_calls} if tool_calls else {}),
                         **_native_blocks(msg)})
        _t_msg()
        if trace is not None:
            trace.append_call(getattr(client, "last_call", {}))

        if tool_calls:
            truncated = 0
            _exec_tool_calls(tool_calls)
            continue

        # No tool call. A reply cut off at the output limit is not an answer: a reasoning model
        # that spends its whole budget thinking returns empty content, which read as "done"
        # and ended a scout with nothing recorded (frappe LMS: 16,000 reasoning tokens, no
        # inventory, no units). Ask again, a few times in a row at most.
        if (getattr(client, "last_call", None) or {}).get("finish_reason") == "length" \
                and truncated < MAX_TRUNCATED:
            truncated += 1
            messages.append({"role": "user", "content": TRUNCATED_NUDGE})
            _t_msg()
            continue
        if finalize is not None:
            nudge = on_final(msg.get("content") or "") if on_final is not None else None
            if nudge:
                messages.append({"role": "user", "content": nudge})
                _t_msg()
                continue
            return AgentResult(finalize(msg.get("content") or ""), True, step, messages, stop="finished")
        # Oracle-driven agent narrated without acting -> push a concrete step
        # (the oracle is re-checked at the top of the next iteration).
        messages.append({"role": "user", "content": stall_nudge})
        _t_msg()

    # Step budget exhausted: force the final answer and keep it in the transcript, so a run that
    # hit the step cap still returns -- and shows -- what it found. The final turn is TOOL-ENABLED
    # and retried a few times, because an agent that reports through a tool (report_finding) cannot
    # report on a tool-less turn: observed a reasoning model answer the force-final with "Let me
    # report it." (a preamble, no JSON, no tool call) and lose a confirmed finding. With tools on,
    # it makes the call it was about to make; with a strict nudge, it emits the JSON. Each tool turn
    # is executed (so report_finding lands wherever the caller collects it) and then we ask once
    # more; a no-tool-call content turn is the final answer that finalize parses.
    if finalize is not None:
        messages.append({"role": "user", "content": final_nudge})
        _t_msg()
        content = ""
        for _ in range(3):
            msg = client.chat_raw(messages, tools)
            if trace is not None:
                trace.append_call(getattr(client, "last_call", {}))
            tc = (msg or {}).get("tool_calls") or []
            content = (msg or {}).get("content") or ""
            messages.append({"role": "assistant", "content": content,
                             **({"tool_calls": tc} if tc else {}), **_native_blocks(msg or {})})
            _t_msg()
            if not tc:
                break                       # a content-only turn is the final answer
            _exec_tool_calls(tc)            # e.g. report_finding -> the caller's collected list
        return AgentResult(finalize(content), True, step, messages, stop="budget")
    r = check_done() if check_done is not None else None
    return AgentResult(r, r is not None, step, messages, stop="oracle" if r is not None else "budget")
