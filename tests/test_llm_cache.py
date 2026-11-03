"""Prompt-cache levers for the agent loops (frame/sil/llm_client.py).

A stable `x-session-id` header is sent on every call of a run (OptiQ forwards it upstream to
keep the prompt-prefix cache warm), and per-call `usage` is accumulated into a cache-hit rate.
No network -- the HTTP read is stubbed."""

import json

from frame.sil.llm_client import LLMClient, LLMConfig


def _resp(prompt=10, cached=7):
    return json.dumps({
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": prompt, "completion_tokens": 3,
                  "prompt_tokens_details": {"cached_tokens": cached}},
    }).encode("utf-8")


def test_x_session_id_is_sent_and_stable_across_calls():
    c = LLMClient(LLMConfig(base_url="http://x", model="m", api_key=""))
    seen = []

    def fake(req):
        seen.append(req.get_header("X-session-id"))
        return _resp()
    c._urlopen_read = fake
    c.chat_raw([{"role": "user", "content": "a"}])
    c.chat_raw([{"role": "user", "content": "b"}])
    assert seen[0] and seen[0] == seen[1] == c.session_id      # present and stable per run


def test_cache_hit_rate_accumulates_usage():
    c = LLMClient(LLMConfig(base_url="http://x", model="m", api_key=""))
    c._urlopen_read = lambda req: _resp(prompt=10, cached=7)
    assert c.cache_hit_rate() is None                          # nothing seen yet
    c.chat_raw([{"role": "user", "content": "a"}])
    c.chat_raw([{"role": "user", "content": "b"}])
    assert c.stats["prompt_tokens"] == 20 and c.stats["cached_tokens"] == 14
    assert c.cache_hit_rate() == 0.7


def test_two_clients_have_distinct_session_ids():
    a = LLMClient(LLMConfig(base_url="x", model="m"))
    b = LLMClient(LLMConfig(base_url="x", model="m"))
    assert a.session_id != b.session_id                        # a different run is a different id


# ---- streaming assembly + retry policy -----------------------------------------

import pytest  # noqa: E402
import urllib.error  # noqa: E402
from frame.sil.llm_client import _DroppedStream  # noqa: E402


def test_assemble_stream_joins_content_and_usage():
    events = [
        {"choices": [{"delta": {"content": "Hel"}}]},
        {"choices": [{"delta": {"content": "lo"}}]},
        {"usage": {"prompt_tokens": 5, "completion_tokens": 2}},
    ]
    msg, usage = LLMClient._assemble_stream(events)
    assert msg["content"] == "Hello" and "tool_calls" not in msg
    assert usage["prompt_tokens"] == 5


def test_assemble_stream_concatenates_tool_call_argument_deltas():
    events = [
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "t1", "function": {"name": "grep", "arguments": '{"p":'}}]}}]},
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": '"x"}'}}]}}]},
    ]
    msg, _ = LLMClient._assemble_stream(events)
    tc = msg["tool_calls"][0]
    assert tc["id"] == "t1" and tc["function"]["name"] == "grep"
    assert tc["function"]["arguments"] == '{"p":"x"}'      # reassembled across deltas


def test_assemble_stream_in_stream_error_is_a_dropped_stream():
    with pytest.raises(_DroppedStream):
        LLMClient._assemble_stream([{"error": {"message": "upstream exploded"}}])


def test_chat_raw_does_not_retry_on_400():
    c = LLMClient(LLMConfig(base_url="http://x", model="m", api_key=""))
    def boom(req):
        raise urllib.error.HTTPError("http://x", 400, "Bad Request", {}, None)
    c._urlopen_read = boom
    assert c.chat_raw([{"role": "user", "content": "a"}]) is None
    assert c.stats["calls"] == 1                            # no retry on a 400
    assert c.last_call["error"] == "HTTP 400"


def test_chat_raw_retries_on_transient_then_fails():
    c = LLMClient(LLMConfig(base_url="http://x", model="m", api_key="", agent_retries=1))
    def flaky(req):
        raise urllib.error.URLError("conn reset")
    c._urlopen_read = flaky
    assert c.chat_raw([{"role": "user", "content": "a"}]) is None
    assert c.stats["calls"] == 2                            # initial + 1 retry
