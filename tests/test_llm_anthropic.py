"""The native Anthropic Messages API transport (frame/sil/llm_anthropic.py) behind LLMClient.

Anthropic's OpenAI-compatible endpoint caches nothing, so every turn of a hunt's tool loop was
billed in full. The native path keeps Frame's OpenAI-shaped loops unchanged: the request is
translated (system hoisted with a cache breakpoint, tool results as one user turn, the API's own
blocks sent back for each assistant turn, thinking included) and the reply translated back
(usage with cached tokens, finish reasons). Offline, against a stub Messages API server."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from frame.sil import llm_anthropic as la
from frame.sil.llm_agent import run_agent
from frame.sil.llm_client import LLMClient, LLMConfig

TOOLS = [{"type": "function", "function": {
    "name": "read_file", "description": "Read a file",
    "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}}]


def test_endpoint_selection():
    assert la.is_anthropic("https://api.anthropic.com/v1")
    assert not la.is_anthropic("https://openrouter.ai/api/v1")
    assert not la.is_anthropic("http://localhost:8080/v1")
    assert la.is_anthropic("http://localhost:9/v1", "anthropic")
    assert not la.is_anthropic("https://api.anthropic.com/v1", "openai")


def test_headers_by_credential_kind():
    h = la.headers("sk-ant-api03-x")
    assert h["x-api-key"] == "sk-ant-api03-x" and h["anthropic-version"] == la.API_VERSION
    assert "Authorization" not in h
    o = la.headers("sk-ant-oat01-x")
    assert o["Authorization"] == "Bearer sk-ant-oat01-x" and "x-api-key" not in o
    assert o["anthropic-beta"] == "oauth-2025-04-20"


def test_request_translation():
    native = [{"type": "thinking", "thinking": "", "signature": "sig"},
              {"type": "tool_use", "id": "t1", "name": "read_file", "input": {"path": "a.py"}}]
    body = la.to_request([
        {"role": "system", "content": "You audit code."},
        {"role": "user", "content": "Audit a.py"},
        {"role": "assistant", "content": "", "anthropic_content": native,
         "tool_calls": [{"id": "t1", "type": "function",
                         "function": {"name": "read_file", "arguments": '{"path": "a.py"}'}}]},
        {"role": "tool", "tool_call_id": "t1", "content": "def f(): pass"},
        {"role": "user", "content": "Continue."},
        {"role": "assistant", "content": "checking",
         "tool_calls": [{"id": "t2", "type": "function",
                         "function": {"name": "read_file", "arguments": '{"path": "b.py"}'}},
                        {"id": "t3", "type": "function",
                         "function": {"name": "read_file", "arguments": '{"path": "c.py"}'}}]},
        {"role": "tool", "tool_call_id": "t2", "content": "x = 1"},
        {"role": "tool", "tool_call_id": "t3", "content": ""},
        {"role": "system", "content": "Finish now."},
    ], TOOLS, "claude-haiku-5-5", 1000)
    assert body["cache_control"] == {"type": "ephemeral"}
    assert body["system"] == [{"type": "text", "text": "You audit code.", "cache_control": {"type": "ephemeral"}}]
    assert body["tools"] == [{"name": "read_file", "description": "Read a file",
                              "input_schema": TOOLS[0]["function"]["parameters"]}]
    assert "temperature" not in body
    roles = [t["role"] for t in body["messages"]]
    assert roles == ["user", "assistant", "user", "assistant", "user"]
    assert body["messages"][1]["content"] == native            # sent back exactly as returned
    # the tool result and the nudge after it are one user turn, tool_result first
    assert body["messages"][2]["content"][0] == {"type": "tool_result", "tool_use_id": "t1",
                                                 "content": "def f(): pass"}
    assert body["messages"][2]["content"][1] == {"type": "text", "text": "Continue."}
    built = body["messages"][3]["content"]
    assert built[0] == {"type": "text", "text": "checking"}
    assert [b["id"] for b in built[1:]] == ["t2", "t3"] and built[1]["input"] == {"path": "b.py"}
    last = body["messages"][4]["content"]                      # both results in ONE user turn
    assert [b.get("tool_use_id") for b in last[:2]] == ["t2", "t3"]
    assert last[1]["content"] == "(empty)"
    assert last[2] == {"type": "text", "text": "Finish now."}  # a mid-run instruction stays in place


def test_response_translation():
    out = la.from_response({
        "content": [{"type": "thinking", "thinking": "", "signature": "s"},
                    {"type": "text", "text": "Reading."},
                    {"type": "tool_use", "id": "t9", "name": "read_file", "input": {"path": "x"}}],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 40, "cache_read_input_tokens": 900,
                  "cache_creation_input_tokens": 60, "output_tokens": 25}})
    choice = out["choices"][0]
    assert choice["finish_reason"] == "tool_calls"
    msg = choice["message"]
    assert msg["content"] == "Reading."
    assert msg["tool_calls"][0]["function"] == {"name": "read_file", "arguments": '{"path": "x"}'}
    assert len(msg["anthropic_content"]) == 3
    assert out["usage"]["prompt_tokens"] == 1000
    assert out["usage"]["prompt_tokens_details"] == {"cached_tokens": 900, "cache_write_tokens": 60}
    assert la.from_response({"content": [], "stop_reason": "max_tokens"})["choices"][0]["finish_reason"] == "length"


class _Stub:
    """A Messages API: the first agent turn calls a tool (with a thinking block), the second
    ends. Every request body and its headers are recorded."""

    def __init__(self):
        self.requests = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                stub.requests.append({"path": self.path, "body": body,
                                      "headers": {k.lower(): v for k, v in self.headers.items()}})
                turn = sum(1 for m in body["messages"] if m["role"] == "assistant")
                if body.get("tools") and turn == 0:
                    out = {"content": [{"type": "thinking", "thinking": "", "signature": "SIG-1"},
                                       {"type": "tool_use", "id": "toolu_1", "name": "read_file",
                                        "input": {"path": "a.py"}}],
                           "stop_reason": "tool_use",
                           "usage": {"input_tokens": 700, "cache_creation_input_tokens": 0,
                                     "cache_read_input_tokens": 0, "output_tokens": 30}}
                else:
                    out = {"content": [{"type": "text", "text": '{"done": true}'}], "stop_reason": "end_turn",
                           "usage": {"input_tokens": 50, "cache_creation_input_tokens": 0,
                                     "cache_read_input_tokens": 700, "output_tokens": 10}}
                raw = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def config(self, **kw):
        return LLMConfig(base_url=f"http://127.0.0.1:{self.server.server_port}/v1", api_key="sk-ant-api03-test",
                         model="claude-haiku-5-5", api="anthropic", timeout=10, total_timeout=10,
                         agent_retries=0, **kw)


@pytest.fixture
def stub():
    s = _Stub()
    yield s
    s.server.shutdown()


def test_agent_loop_sends_thinking_back_and_reads_the_cache(stub):
    client = LLMClient(stub.config())
    seen = []
    result = run_agent([{"role": "system", "content": "You audit code."},
                        {"role": "user", "content": "Audit a.py"}], client,
                       tools=TOOLS, exec_tool=lambda n, a: seen.append((n, a)) or "def f(): pass",
                       max_steps=5, finalize=lambda text: text)
    assert seen == [("read_file", {"path": "a.py"})]
    assert result.result == '{"done": true}' and result.done
    first, second = stub.requests[0], stub.requests[1]
    assert first["path"] == "/v1/messages"
    assert first["headers"]["x-api-key"] == "sk-ant-api03-test"
    assert first["headers"]["anthropic-version"] == la.API_VERSION
    assert "temperature" not in first["body"]
    # the second request repeats the first turn's blocks unchanged, then the tool result
    assistant = [m for m in second["body"]["messages"] if m["role"] == "assistant"][0]
    assert assistant["content"][0] == {"type": "thinking", "thinking": "", "signature": "SIG-1"}
    assert second["body"]["messages"][-1]["content"][0]["type"] == "tool_result"
    # the prefix the second request shares with the first is byte-identical (cacheable)
    assert second["body"]["messages"][:1] == first["body"]["messages"][:1]
    assert second["body"]["system"] == first["body"]["system"]
    assert client.last_call["cached_tokens"] == 700 and client.last_call["prompt_tokens"] == 750
    assert client.stats["cached_tokens"] == 700


def test_single_completion_on_the_native_path(stub):
    client = LLMClient(stub.config())
    assert client.complete([{"role": "user", "content": "Is this safe? Answer JSON."}]) == '{"done": true}'
    assert stub.requests[0]["path"] == "/v1/messages" and "tools" not in stub.requests[0]["body"]


def test_openai_compatible_endpoints_are_unchanged():
    assert not LLMClient(LLMConfig(base_url="https://openrouter.ai/api/v1", model="m"))._anthropic()
    assert LLMClient(LLMConfig(base_url="https://api.anthropic.com/v1", model="m"))._anthropic()
    assert not LLMClient(LLMConfig(base_url="https://api.anthropic.com/v1", model="m", api="openai"))._anthropic()


def test_strict_json_schema_becomes_structured_output():
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
              "additionalProperties": False}
    body = la.to_request([{"role": "user", "content": "x"}], None, "m", 10,
                         {"type": "json_schema", "json_schema": {"name": "r", "strict": True, "schema": schema}})
    assert body["output_config"] == {"format": {"type": "json_schema", "schema": schema}}
    assert "output_config" not in la.to_request([{"role": "user", "content": "x"}], None, "m", 10,
                                                {"type": "json_object"})
