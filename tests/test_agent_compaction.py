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
    """chat_raw always calls the `run` tool (the loop keeps going); complete returns
    a canned progress summary and counts its calls."""

    def __init__(self, config=None):
        self.config = config or LLMConfig(base_url="x", model="m")
        self.completes = 0

    def chat_raw(self, messages, tools=None):
        return {"content": "", "tool_calls": [{"id": "1", "function": {
            "name": "run", "arguments": json.dumps({"cmd": "probe"})}}]}

    def complete(self, messages, **kw):
        self.completes += 1
        return "SUMMARY OF PROGRESS: tried probe, no crash yet; dead-end X ruled out."


# --- A1: compaction helper ------------------------------------------------------

def test_compact_messages_keeps_system_recent_and_notes():
    from frame.sil.llm_agent import _compact_messages
    c = _StubClient()
    sys_msg = {"role": "system", "content": "SYSTEM PROMPT"}
    msgs = [sys_msg] + [{"role": "user", "content": f"turn {i}"} for i in range(1, 21)]
    out = _compact_messages(msgs, c, keep_recent=6)
    assert out[0] is sys_msg                                   # system preserved verbatim
    assert out[1]["role"] == "user"
    assert "[PROGRESS NOTES]" in out[1]["content"]             # a notes message inserted
    assert "SUMMARY OF PROGRESS" in out[1]["content"]          # produced via client.complete
    assert c.completes == 1
    assert out[-6:] == msgs[-6:]                               # last K turns kept verbatim
    assert len(out) == 8                                       # system + notes + 6


def test_compact_messages_noop_when_short():
    from frame.sil.llm_agent import _compact_messages
    c = _StubClient()
    msgs = [{"role": "system", "content": "S"}, {"role": "user", "content": "a"}]
    assert _compact_messages(msgs, c, keep_recent=6) == msgs   # nothing to compact
    assert c.completes == 0                                    # no summarization call


# --- A1: compaction inside the loop bounds context ------------------------------

def test_run_agent_bounds_context_with_compaction():
    # Each step appends ~2 messages; over 50 steps that's ~100 without compaction.
    # With a small budget the transcript must stay bounded and the system prompt
    # must survive every compaction.
    c = _StubClient()
    big = "X" * 500
    r = run_agent([{"role": "system", "content": "S"}], c,
                  tools=[], exec_tool=lambda n, a: big,
                  max_steps=50, check_done=lambda: None,
                  compact_at_chars=3000, keep_recent=6)
    assert len(r.transcript) < 30                              # bounded, not ~100
    assert any("[PROGRESS NOTES]" in str(m.get("content", "")) for m in r.transcript)
    assert r.transcript[0]["content"] == "S"                  # system survived compaction
    assert c.completes >= 1                                    # compaction actually fired


# --- A2: raised budgets ---------------------------------------------------------

def test_raised_budget_defaults():
    cfg = LLMConfig()
    assert cfg.exploit_max_steps == 250
    assert cfg.max_tool_steps == 30
    assert cfg.agent_context_budget_chars == 80000


def test_from_env_budget_defaults(monkeypatch):
    for v in ("FRAME_LLM_EXPLOIT_MAX_STEPS", "FRAME_LLM_MAX_TOOL_STEPS",
              "FRAME_LLM_AGENT_CONTEXT_BUDGET_CHARS"):
        monkeypatch.delenv(v, raising=False)
    cfg = LLMConfig.from_env()
    assert cfg.exploit_max_steps == 250
    assert cfg.max_tool_steps == 30
    assert cfg.agent_context_budget_chars == 80000


# --- A3: self-correcting exploit prompt -----------------------------------------

def test_exploit_prompt_treats_finding_as_lead():
    from frame.sil.llm_exploit import EXPLOIT_SYSTEM
    p = EXPLOIT_SYSTEM.lower()
    assert "lead" in p          # treat the FRAME ANALYSIS finding as a lead, not truth
    assert "pivot" in p         # pivot to other surfaces if the target contradicts it
