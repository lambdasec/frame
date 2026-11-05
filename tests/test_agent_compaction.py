"""TDD contracts for longer self-verifying agent sessions.

These are written before the implementation (red now, green after Workstream A):
  - `run_agent` compacts old turns into a PROGRESS-NOTES message when context
    exceeds a budget, so long runs don't blow the window.
  - Raised default budgets (exploit 250 / detect 30) + a context-budget field.
  - EXPLOIT_SYSTEM frames the finding as a lead to verify/pivot on, not ground truth.
"""

import json

from frame.sil.llm_agent import run_agent
from frame.sil.llm_client import LLMConfig


class _StubClient:
    """chat_raw always calls the `run` tool (the loop keeps going). complete counts calls --
    placeholder compaction must NOT call it (no model round-trip)."""

    def __init__(self, config=None):
        self.config = config or LLMConfig(base_url="x", model="m")
        self.completes = 0

    def chat_raw(self, messages, tools=None):
        return {"content": "", "tool_calls": [{"id": "1", "function": {
            "name": "run", "arguments": json.dumps({"cmd": "probe"})}}]}

    def complete(self, messages, **kw):
        self.completes += 1
        return "unexpected model call"


# --- A1: placeholder compaction helper ------------------------------------------

def test_compact_messages_elides_old_tool_output_no_model_call():
    from frame.sil.llm_agent import _compact_messages, _ELIDED
    c = _StubClient()
    sys_msg = {"role": "system", "content": "SYSTEM PROMPT"}
    task = {"role": "user", "content": "THE TASK"}
    # alternating assistant tool-call + big tool result, then recent turns
    middle = []
    for i in range(1, 11):
        middle.append({"role": "assistant", "content": "", "tool_calls": [
            {"id": str(i), "function": {"name": "read_file", "arguments": "{}"}}]})
        middle.append({"role": "tool", "tool_call_id": str(i), "content": "X" * 5000})
    msgs = [sys_msg, task] + middle + [{"role": "user", "content": f"recent {i}"} for i in range(6)]
    out = _compact_messages(msgs, c, keep_recent=6)
    assert c.completes == 0                                    # NO model call (cheap)
    assert out[0] is sys_msg and out[1] is task                # stable cached prefix preserved
    assert out[-6:] == msgs[-6:]                               # last K turns kept verbatim
    assert len(out) == len(msgs)                               # structure kept (ids still pair)
    # old big tool results are now placeholders; assistant turns (what was done) are kept
    tool_contents = [m["content"] for m in out if m.get("role") == "tool"]
    assert all(_ELIDED in c for c in tool_contents)
    assert any(m.get("tool_calls") for m in out)               # the tool-call record survives
    # it actually shrank the transcript
    from frame.sil.llm_agent import _context_chars
    assert _context_chars(out) < _context_chars(msgs) / 2


def test_compact_messages_noop_when_short():
    from frame.sil.llm_agent import _compact_messages
    c = _StubClient()
    msgs = [{"role": "system", "content": "S"}, {"role": "user", "content": "a"}]
    assert _compact_messages(msgs, c, keep_recent=6) == msgs   # nothing to compact
    assert c.completes == 0                                    # no summarization call


# --- A1: compaction inside the loop bounds context ------------------------------

def test_run_agent_bounds_context_with_compaction():
    # Each step appends a big tool result; with a small budget the transcript's CHAR size
    # must stay bounded (old tool outputs elided to placeholders), the system prompt must
    # survive, and no model summarization call is made.
    from frame.sil.llm_agent import _context_chars, _ELIDED
    c = _StubClient()
    big = "X" * 2000
    r = run_agent([{"role": "system", "content": "S"}, {"role": "user", "content": "TASK"}], c,
                  tools=[], exec_tool=lambda n, a: big,
                  max_steps=40, check_done=lambda: None,
                  compact_at_chars=6000, keep_recent=6)
    assert _context_chars(r.transcript) < 6000 + 2000 * 8      # bounded, not ~40*2000
    assert any(_ELIDED in str(m.get("content", "")) for m in r.transcript)  # old results elided
    assert r.transcript[0]["content"] == "S"                   # system survived compaction
    assert c.completes == 0                                    # placeholder compaction: no model call


# --- A2: raised budgets ---------------------------------------------------------

def test_raised_budget_defaults():
    cfg = LLMConfig()
    assert cfg.exploit_max_steps == 250
    assert cfg.max_tool_steps == 30
    assert cfg.agent_context_budget_chars == 400000


def test_from_env_budget_defaults():
    cfg = LLMConfig.from_env()
    assert cfg.exploit_max_steps == 250
    assert cfg.max_tool_steps == 30
    assert cfg.agent_context_budget_chars == 400000


# --- A3: self-correcting exploit prompt -----------------------------------------

def test_exploit_prompt_treats_finding_as_lead():
    from frame.sil.llm_exploit import EXPLOIT_SYSTEM
    p = EXPLOIT_SYSTEM.lower()
    assert "lead" in p          # treat the FRAME ANALYSIS finding as a lead, not truth
    assert "pivot" in p         # pivot to other surfaces if the target contradicts it


# --- tool-call dedupe (harness-enforced, idempotent tools) ----------------------

def test_dedupe_refuses_exact_duplicate_tool_calls():
    import json as _json
    from frame.sil.llm_agent import run_agent
    from frame.sil.llm_client import LLMConfig, LLMClient
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    # the model calls read_file on the same path 3x, then finishes.
    call = {"content": "", "tool_calls": [{"id": "1", "function": {
        "name": "read_file", "arguments": _json.dumps({"path": "a.py"})}}]}
    script = [call, call, call, {"content": "done", "tool_calls": []}]
    seq = {"i": 0}
    def chat(messages, tools=None):
        m = script[min(seq["i"], len(script) - 1)]; seq["i"] += 1
        return m
    c.chat_raw = chat
    ran = {"n": 0}
    def exec_tool(name, args):
        ran["n"] += 1
        return "file contents"
    res = run_agent([{"role": "system", "content": "s"}, {"role": "user", "content": "go"}],
                    c, tools=[], exec_tool=exec_tool, max_steps=10,
                    finalize=lambda s: s, dedupe_tools={"read_file"})
    assert res.result == "done"
    assert ran["n"] == 1                 # executed once; the 2nd and 3rd were refused
    # the refused calls still returned a tool message (so the loop stayed valid)
    tool_msgs = [m for m in res.transcript if m.get("role") == "tool"]
    assert len(tool_msgs) == 3
    assert "already called read_file" in tool_msgs[1]["content"]


def test_step_hook_nudge_is_injected_before_the_model_call():
    # The finish-gate mechanism: a step_hook returning a string appends it as a user nudge that
    # the model sees on that step. Here the hook fires on step 2 and the agent then concludes.
    import json as _json
    from frame.sil.llm_agent import run_agent
    from frame.sil.llm_client import LLMConfig, LLMClient
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    seen = {"nudge_seen": False}

    def chat(messages, tools=None):
        if any(m.get("role") == "user" and "WRAP UP" in str(m.get("content")) for m in messages):
            seen["nudge_seen"] = True
            return {"content": "done", "tool_calls": []}
        return {"content": "", "tool_calls": [{"id": "1", "function": {
            "name": "read_file", "arguments": _json.dumps({"path": "a.py"})}}]}
    c.chat_raw = chat
    res = run_agent([{"role": "system", "content": "s"}, {"role": "user", "content": "go"}],
                    c, tools=[{"x": 1}], exec_tool=lambda n, a: "data", max_steps=10,
                    finalize=lambda s: s, step_hook=lambda step: "WRAP UP" if step >= 2 else None)
    assert seen["nudge_seen"]
    assert res.result == "done"
    # the nudge is a real user turn in the transcript
    assert any(m.get("role") == "user" and "WRAP UP" in str(m.get("content")) for m in res.transcript)


def test_forced_final_turn_is_tool_enabled_so_a_last_turn_report_is_captured():
    # Regression (BAC-Bench parse-server v6): the agent exhausted its step budget having reported
    # nothing yet, and on the (previously tool-LESS) forced-final turn answered "Let me report it."
    # -- a prose preamble, no JSON, no tool call -- so a confirmed finding was silently dropped.
    # The forced-final turn must be TOOL-ENABLED so the agent can make the report_finding call it
    # was about to make; the harness executes it and the finding lands in the collected list.
    import json as _json
    from frame.sil.llm_agent import run_agent
    from frame.sil.llm_client import LLMConfig, LLMClient
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    collected = []
    phase = {"n": 0}

    def exec_tool(name, args):
        if name == "report_finding":
            collected.append(dict(args))
            return "recorded"
        return "data"

    def chat(messages, tools=None):
        phase["n"] += 1
        on_final = any(m.get("role") == "user" and "LAST turn" in str(m.get("content"))
                       for m in messages)
        if on_final:
            # The model reports on its last turn -- only possible because tools are enabled now --
            # then, asked again, concludes (a content-only turn ends the forced-final loop).
            if not collected:
                return {"content": "", "tool_calls": [{"id": "r", "function": {
                    "name": "report_finding", "arguments": _json.dumps({"handler": "H",
                                                                        "file": "a.py", "line": 5})}}]}
            return {"content": "done", "tool_calls": []}
        # Before the budget runs out, it keeps investigating (never reports, never concludes).
        return {"content": "", "tool_calls": [{"id": "1", "function": {
            "name": "read_file", "arguments": _json.dumps({"path": "a.py"})}}]}
    c.chat_raw = chat
    run_agent([{"role": "system", "content": "s"}, {"role": "user", "content": "go"}],
              c, tools=[{"x": 1}], exec_tool=exec_tool, max_steps=3,
              finalize=lambda s: list(collected),
              final_nudge="This is your LAST turn. Report now with report_finding.")
    assert collected == [{"handler": "H", "file": "a.py", "line": 5}], collected


def test_hunt_finish_gate_does_not_fire_before_any_finding():
    # Regression (v4): the finish-gate must NOT nudge-to-stop while the agent has found nothing --
    # that made the agent quit at ~step 33 with zero findings. The gate only trims the tail AFTER
    # at least one report. Here the model never reports; the gate must stay silent and let it run.
    import json as _json
    from frame.sil.llm_hunt import hunt_authz
    from frame.sil.llm_client import LLMConfig, LLMClient
    from frame.sil.types import Location

    class _Prog:
        handler_authz = {"H.a": (False, True, Location("app.py", 10))}
        procedures = {}
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    steps = {"n": 0}

    def chat(messages, tools=None):
        steps["n"] += 1
        # never reports, never concludes on its own -> would run to max_steps unless the gate fires.
        if tools is None:
            return {"content": "", "tool_calls": []}
        return {"content": "", "tool_calls": [{"id": "1", "function": {
            "name": "grep", "arguments": _json.dumps({"pattern": "x"})}}]}
    c.chat_raw = chat
    hunt_authz(_Prog(), [], repo_root="", config=LLMConfig(), client=c, max_steps=12)
    # it ran the full budget (12) then the (tool-enabled, retried) forced-final; the gate never cut
    # it short early -- the point is it reached the budget, not the exact forced-final turn count.
    assert steps["n"] >= 12


def test_dedupe_off_by_default_reexecutes():
    import json as _json
    from frame.sil.llm_agent import run_agent
    from frame.sil.llm_client import LLMConfig, LLMClient
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    call = {"content": "", "tool_calls": [{"id": "1", "function": {
        "name": "run", "arguments": _json.dumps({"cmd": "x"})}}]}
    script = [call, call, {"content": "done", "tool_calls": []}]
    seq = {"i": 0}
    def chat(messages, tools=None):
        m = script[min(seq["i"], len(script) - 1)]; seq["i"] += 1
        return m
    c.chat_raw = chat
    ran = {"n": 0}
    res = run_agent([{"role": "system", "content": "s"}, {"role": "user", "content": "go"}],
                    c, tools=[], exec_tool=lambda n, a: ran.__setitem__("n", ran["n"] + 1) or "ok",
                    max_steps=10, finalize=lambda s: s)   # no dedupe_tools
    assert ran["n"] == 2                 # both ran (side-effecting commands must not be deduped)
