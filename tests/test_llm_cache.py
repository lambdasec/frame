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


def test_usage_record_keeps_the_finish_reason():
    # A refusal or a truncation must be visible in the per-call log, not read as a quiet answer.
    rec = LLMClient._usage_record({"choices": [{"finish_reason": "content_filter", "message": {}}],
                                   "usage": {"prompt_tokens": 5}}, 1.0, 0)
    assert rec["finish_reason"] == "content_filter"
    assert "finish_reason" not in LLMClient._usage_record({"usage": {}}, 1.0, 0)


# ---- riding out an outage (LLMConfig.outage_wait) --------------------------------------------

class _Clock:
    """A fake `time` module: sleeping advances the clock, so a six-hour wait takes no time."""

    def __init__(self):
        self.now = 1000.0
        self.slept = 0.0

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += s
        self.slept += s


def _down_for(n, exc=None):
    """An endpoint that fails its first n calls, then answers."""
    seen = []

    def read(req):
        seen.append(1)
        if len(seen) <= n:
            raise exc or urllib.error.URLError("Network is unreachable")
        return _resp()
    return read, seen


def test_an_outage_is_waited_out_and_the_call_then_succeeds(monkeypatch):
    import frame.sil.llm_client as lc
    clock = _Clock()
    monkeypatch.setattr(lc, "time", clock)
    c = LLMClient(LLMConfig(base_url="http://x", model="m", api_key="", agent_retries=2,
                            outage_wait=3600))
    c._urlopen_read, seen = _down_for(40)          # far past the 3 normal attempts
    msg = c.chat_raw([{"role": "user", "content": "a"}])
    assert msg == {"content": "ok"} and len(seen) == 41
    assert c.stats["outage_waits"] == 38 and clock.slept < 3600


def test_an_outage_longer_than_the_window_gives_up(monkeypatch):
    import frame.sil.llm_client as lc
    clock = _Clock()
    monkeypatch.setattr(lc, "time", clock)
    c = LLMClient(LLMConfig(base_url="http://x", model="m", api_key="", agent_retries=1,
                            outage_wait=300))
    c._urlopen_read, seen = _down_for(10 ** 6)
    assert c.chat_raw([{"role": "user", "content": "a"}]) is None
    assert 300 <= clock.slept <= 340              # waited the window, then stopped


def test_the_window_is_off_by_default_and_never_covers_a_bad_request(monkeypatch):
    import frame.sil.llm_client as lc
    monkeypatch.setattr(lc, "time", _Clock())
    off = LLMClient(LLMConfig(base_url="http://x", model="m", api_key="", agent_retries=1))
    off._urlopen_read, seen = _down_for(10)
    assert off.chat_raw([{"role": "user", "content": "a"}]) is None and len(seen) == 2

    for code in (403, 404, 422):                   # the request is wrong: waiting cannot fix it
        c = LLMClient(LLMConfig(base_url="http://x", model="m", api_key="", agent_retries=0,
                                outage_wait=3600))
        c._urlopen_read, seen = _down_for(
            10, urllib.error.HTTPError("http://x", code, "no", {}, None))
        assert c.chat_raw([{"role": "user", "content": "a"}]) is None and len(seen) == 1

    busy = LLMClient(LLMConfig(base_url="http://x", model="m", api_key="", agent_retries=0,
                               outage_wait=3600))
    busy._urlopen_read, seen = _down_for(5, urllib.error.HTTPError("http://x", 503, "busy", {}, None))
    assert busy.chat_raw([{"role": "user", "content": "a"}]) == {"content": "ok"}


def test_an_abort_ends_the_wait_at_once():
    import threading
    c = LLMClient(LLMConfig(base_url="http://x", model="m", api_key="", agent_retries=0,
                            outage_wait=3600))
    c.abort = threading.Event()
    c._urlopen_read, seen = _down_for(10 ** 6)
    threading.Timer(0.2, c.abort.set).start()
    assert c.chat_raw([{"role": "user", "content": "a"}]) is None   # returns well inside 30 s
    assert len(seen) == 1


def test_a_single_completion_waits_out_an_outage_too(monkeypatch):
    import frame.sil.llm_client as lc
    monkeypatch.setattr(lc, "time", _Clock())
    calls = []

    def flaky(messages):
        calls.append(1)
        if len(calls) <= 20:
            raise urllib.error.URLError("Host is down")
        return "fine"
    c = LLMClient(LLMConfig(base_url="http://x", model="m", agent_retries=1, outage_wait=3600),
                  call_fn=flaky)
    assert c.complete([{"role": "user", "content": "a"}]) == "fine"
