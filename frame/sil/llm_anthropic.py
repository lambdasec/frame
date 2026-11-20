"""The native Anthropic Messages API (`POST /v1/messages`) behind Frame's OpenAI-shaped client.

Frame's agent loops speak the OpenAI chat format (system / user / assistant with `tool_calls` /
`tool` messages). Anthropic's OpenAI-compatible endpoint takes that format but supports no prompt
caching, so every turn of a tool loop was billed in full. This module translates both ways, so the
same loop runs on the Messages API:

  - system messages become the top-level `system` (with a cache breakpoint: it never changes);
  - an assistant turn is sent back with the content blocks the API returned for it (thinking
    blocks included, which a tool loop must return unchanged), kept on the message as
    `anthropic_content`; one built here from text and `tool_calls` otherwise;
  - consecutive `tool` messages become ONE user message of `tool_result` blocks;
  - tools become `{name, description, input_schema}`;
  - the request carries top-level `cache_control`, so the cache breakpoint moves to the end of
    the conversation each turn and the growing prefix is read from cache.

The reply comes back as an OpenAI-shaped response (`choices[0].message`, `usage` with
`prompt_tokens` and `prompt_tokens_details.cached_tokens`, `finish_reason`), so the client's
usage records, cache-hit rate and stop handling work unchanged. Pure functions: no I/O.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

API_VERSION = "2026-10-21"
CACHE = {"type": "ephemeral"}
# OpenAI finish reasons for Anthropic stop reasons (what the agent loop reads).
FINISH = {"end_turn": "stop", "stop_sequence": "stop", "tool_use": "tool_calls",
          "max_tokens": "length", "refusal": "content_filter", "pause_turn": "stop"}


def is_anthropic(base_url: str, api: str = "auto") -> bool:
    if api == "anthropic":
        return True
    if api == "openai":
        return False
    return (urlparse(base_url or "").hostname or "") == "api.anthropic.com"


def headers(api_key: str) -> Dict[str, str]:
    """`x-api-key` for an API key; an OAuth access token (`sk-ant-oat...`) goes on
    `Authorization: Bearer` with the OAuth beta header."""
    h = {"Content-Type": "application/json", "anthropic-version": API_VERSION}
    if api_key.startswith("sk-ant-oat"):
        h["Authorization"] = f"Bearer {api_key}"
        h["anthropic-beta"] = "oauth-2025-04-20"
    elif api_key:
        h["x-api-key"] = api_key
    return h


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
    return "" if content is None else str(content)


def _user_blocks(content: Any) -> List[Dict[str, Any]]:
    if isinstance(content, list):
        return [{"type": "text", "text": p.get("text", "")} for p in content
                if isinstance(p, dict) and p.get("type") == "text" and p.get("text")]
    text = _text(content)
    return [{"type": "text", "text": text}] if text else []


def _assistant_blocks(msg: Dict[str, Any]) -> List[Dict[str, Any]]:
    native = msg.get("anthropic_content")
    if isinstance(native, list) and native:
        return native                       # exactly what the API returned (thinking included)
    blocks: List[Dict[str, Any]] = []
    text = _text(msg.get("content"))
    if text:
        blocks.append({"type": "text", "text": text})
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except ValueError:
            args = {"_raw": fn.get("arguments")}
        blocks.append({"type": "tool_use", "id": tc.get("id") or "", "name": fn.get("name") or "",
                       "input": args if isinstance(args, dict) else {"value": args}})
    return blocks


def output_format(response_format: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """OpenAI's strict `response_format` json_schema as the Messages API's structured output
    (`output_config.format`). `json_object` has no counterpart: the reply is parsed as text."""
    if not isinstance(response_format, dict) or response_format.get("type") != "json_schema":
        return None
    schema = (response_format.get("json_schema") or {}).get("schema")
    return {"type": "json_schema", "schema": schema} if isinstance(schema, dict) else None


def to_request(messages: List[Dict[str, Any]], tools: Optional[list], model: str,
               max_tokens: int, response_format: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """An OpenAI-shaped conversation as a Messages API request body."""
    system: List[str] = []
    turns: List[Dict[str, Any]] = []

    def add(role: str, blocks: List[Dict[str, Any]]) -> None:
        if not blocks:
            return
        if turns and turns[-1]["role"] == role:
            turns[-1]["content"] = turns[-1]["content"] + blocks     # one turn per role run
        else:
            turns.append({"role": role, "content": list(blocks)})

    for m in messages:
        role = m.get("role")
        if role in ("system", "developer"):
            if turns:
                # an instruction added mid-run stays where it is (moving it into `system`
                # would change the cached prefix): a user text turn
                add("user", [{"type": "text", "text": _text(m.get("content"))}])
            else:
                system.append(_text(m.get("content")))
        elif role == "assistant":
            add("assistant", _assistant_blocks(m))
        elif role == "tool":
            add("user", [{"type": "tool_result", "tool_use_id": m.get("tool_call_id") or "",
                          "content": _text(m.get("content")) or "(empty)"}])
        else:
            add("user", _user_blocks(m.get("content")))
    if turns and turns[0]["role"] != "user":
        turns.insert(0, {"role": "user", "content": [{"type": "text", "text": "(start)"}]})
    body: Dict[str, Any] = {"model": model, "max_tokens": int(max_tokens), "messages": turns,
                            "cache_control": dict(CACHE)}
    if system:
        body["system"] = [{"type": "text", "text": "\n".join(system), "cache_control": dict(CACHE)}]
    fmt = output_format(response_format)
    if fmt is not None:
        body["output_config"] = {"format": fmt}
    if tools:
        body["tools"] = [{"name": (t.get("function") or t).get("name"),
                          "description": (t.get("function") or t).get("description") or "",
                          "input_schema": (t.get("function") or t).get("parameters")
                          or {"type": "object", "properties": {}}} for t in tools]
    return body


def from_response(resp: Dict[str, Any]) -> Dict[str, Any]:
    """A Messages API response as an OpenAI chat completion: the assistant message (text,
    `tool_calls`, and the native blocks as `anthropic_content`), finish reason and usage.
    `prompt_tokens` counts every input token, cached ones included (`cached_tokens`), as the
    client's usage records expect."""
    content = resp.get("content") or []
    text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
    calls = [{"id": b.get("id"), "type": "function",
              "function": {"name": b.get("name"), "arguments": json.dumps(b.get("input") or {})}}
             for b in content if b.get("type") == "tool_use"]
    msg: Dict[str, Any] = {"role": "assistant", "content": text, "anthropic_content": content}
    if calls:
        msg["tool_calls"] = calls
    u = resp.get("usage") or {}
    read = int(u.get("cache_read_input_tokens") or 0)
    write = int(u.get("cache_creation_input_tokens") or 0)
    plain = int(u.get("input_tokens") or 0)
    usage = {"prompt_tokens": plain + read + write, "completion_tokens": int(u.get("output_tokens") or 0),
             "prompt_tokens_details": {"cached_tokens": read, "cache_write_tokens": write}}
    return {"choices": [{"message": msg, "finish_reason": FINISH.get(resp.get("stop_reason") or "",
                                                                      resp.get("stop_reason"))}],
            "usage": usage, "stop_reason": resp.get("stop_reason")}

