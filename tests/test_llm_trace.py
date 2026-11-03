"""HF Session-Trace (STS-Format) persistence for Frame's agent loops (frame/sil/llm_trace.py).

Every message is appended and flushed as it appears (durable to a crash), in the Hub's
STS-Format; the trace reads back for resume; per-call timing/usage is logged to a sidecar;
local paths are redacted. No network."""

import json
import os

from frame.sil.llm_trace import (
    message_to_stf, stf_to_message, read_stf, TraceWriter, _default_redactor)
from frame.sil.llm_client import LLMClient, LLMConfig
from frame.sil.llm_agent import run_agent


def test_message_conversion_round_trip():
    msg = {"role": "assistant", "content": "hi",
           "tool_calls": [{"id": "t1", "type": "function",
                           "function": {"name": "grep", "arguments": '{"pattern":"x"}'}}],
           "reasoning_content": "thinking"}
    stf = message_to_stf(msg)
    assert stf["toolCalls"][0]["id"] == "t1"
    assert stf["toolCalls"][0]["function"]["arguments"] == '{"pattern":"x"}'  # JSON string
    assert stf["reasoningContent"] == "thinking"
    back = stf_to_message(stf)
    assert back["tool_calls"][0]["function"]["name"] == "grep"
    assert back["reasoning_content"] == "thinking"


def test_tool_result_shape():
    stf = message_to_stf({"role": "tool", "tool_call_id": "t1", "content": "result"})
    assert stf["role"] == "tool" and stf["toolCallId"] == "t1" and stf["content"] == "result"


def test_writer_header_and_append_then_read_back(tmp_path):
    p = str(tmp_path / "trace.jsonl")
    w = TraceWriter(p, session_id="s1", name="demo")
    assert not w.resumed
    w.start()
    w.append_message({"role": "system", "content": "sys"})
    w.append_message({"role": "user", "content": "do it"})
    w.append_message({"role": "assistant", "content": "",
                      "tool_calls": [{"id": "t1", "function": {"name": "f", "arguments": "{}"}}]})
    w.append_message({"role": "tool", "tool_call_id": "t1", "content": "out"})
    # First line is the session header; the rest are messages.
    lines = [json.loads(ln) for ln in open(p)]
    assert lines[0] == {"type": "session", "harness": "frame", "id": "s1", "name": "demo"}
    assert all(ln["type"] == "message" for ln in lines[1:])
    header, msgs = read_stf(p)
    assert header["id"] == "s1"
    assert [m["role"] for m in msgs] == ["system", "user", "assistant", "tool"]
    assert msgs[2]["tool_calls"][0]["id"] == "t1"
    assert msgs[3]["tool_call_id"] == "t1"


def test_resume_does_not_rewrite_header(tmp_path):
    p = str(tmp_path / "t.jsonl")
    w1 = TraceWriter(p, "s1"); w1.start(); w1.append_message({"role": "user", "content": "a"})
    w2 = TraceWriter(p, "s1")
    assert w2.resumed
    w2.start()                       # must NOT add a second header
    w2.append_message({"role": "assistant", "content": "b"})
    headers = [json.loads(ln) for ln in open(p) if json.loads(ln).get("type") == "session"]
    assert len(headers) == 1
    _, msgs = read_stf(p)
    assert [m["content"] for m in msgs] == ["a", "b"]


def test_truncated_last_line_is_skipped(tmp_path):
    # A hard kill can leave a half-written final line; read_stf must tolerate it.
    p = str(tmp_path / "t.jsonl")
    w = TraceWriter(p, "s1"); w.start(); w.append_message({"role": "user", "content": "ok"})
    with open(p, "a") as fh:
        fh.write('{"type":"message","message":{"role":"assist')   # truncated, no newline
    _, msgs = read_stf(p)
    assert [m["content"] for m in msgs] == ["ok"]


def test_redaction_scrubs_home(tmp_path):
    redact = _default_redactor()
    home = os.path.expanduser("~")
    assert redact(f"error at {home}/secret/app.py") == "error at ~/secret/app.py"


def test_usage_record_parses_tokens():
    resp = {"usage": {"prompt_tokens": 1000, "completion_tokens": 50,
                      "prompt_tokens_details": {"cached_tokens": 800},
                      "completion_tokens_details": {"reasoning_tokens": 20}, "cost": 0.01}}
    rec = LLMClient._usage_record(resp, 1.5, 0)
    assert rec["prompt_tokens"] == 1000 and rec["cached_tokens"] == 800
    assert rec["completion_tokens"] == 50 and rec["reasoning_tokens"] == 20
    assert rec["cost"] == 0.01 and rec["status"] == "ok"


def test_run_agent_writes_a_durable_trace(tmp_path):
    c = LLMClient(LLMConfig(base_url="x", model="m"))
    seq = {"i": 0}
    script = [
        {"content": "", "tool_calls": [{"id": "1", "function": {"name": "look", "arguments": "{}"}}]},
        {"content": "done", "tool_calls": []},
    ]
    def chat(messages, tools=None):
        c.last_call = {"status": "ok", "latency_s": 0.5, "prompt_tokens": 10, "cached_tokens": 5}
        m = script[min(seq["i"], len(script) - 1)]; seq["i"] += 1
        return m
    c.chat_raw = chat
    p = str(tmp_path / "run.jsonl")
    w = TraceWriter(p, "run1", name="t")
    res = run_agent([{"role": "system", "content": "s"}, {"role": "user", "content": "go"}],
                    c, tools=[], exec_tool=lambda n, a: "looked",
                    max_steps=5, finalize=lambda s: s, trace=w)
    assert res.result == "done"
    _, msgs = read_stf(p)
    roles = [m["role"] for m in msgs]
    # system, user (initial), assistant(tool_call), tool(result), assistant(final)
    assert roles == ["system", "user", "assistant", "tool", "assistant"]
    # per-call timing sidecar was written
    calls = [json.loads(ln) for ln in open(p + ".calls.jsonl")]
    assert calls and calls[0]["cached_tokens"] == 5
