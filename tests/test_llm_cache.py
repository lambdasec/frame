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
