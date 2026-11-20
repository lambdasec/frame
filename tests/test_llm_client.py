

import socket as _socket
import threading as _threading
import time as _time

import pytest as _pytest

from frame.sil.llm_client import LLMClient, LLMConfig


def _hung_server():
    """A TCP server that accepts a connection and never replies (worst case:
    blocks the client inside urlopen before any HTTP response)."""
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    held = []
    _threading.Thread(target=lambda: held.append(srv.accept()), daemon=True).start()
    return srv.getsockname()[1], srv, held


def test_wall_clock_deadline_unblocks_caller():
    """A hung endpoint must not block past the wall-clock deadline, even when the
    client is stuck inside urlopen (no response object to close)."""
    port, srv, _held = _hung_server()
    try:
        cfg = LLMConfig(base_url=f"http://127.0.0.1:{port}/v1", api_key="x",
                        model="m", timeout=60, total_timeout=2)
        client = LLMClient(cfg)
        t0 = _time.time()
        with _pytest.raises(TimeoutError):
            client._post_chat([{"role": "user", "content": "hi"}], 10, None)
        elapsed = _time.time() - t0
        assert elapsed < 10, f"caller blocked {elapsed:.1f}s past a 2s deadline"
    finally:
        srv.close()


def test_effective_total_timeout_defaults_generously():
    """total_timeout=0 derives a generous deadline from the socket timeout so a
    legitimately slow reasoning generation is not cut off."""
    assert LLMClient(LLMConfig(timeout=60, total_timeout=0))._effective_total_timeout() == 600.0
    assert LLMClient(LLMConfig(timeout=60, total_timeout=45))._effective_total_timeout() == 45.0


def _rejecting_server():
    """An OpenAI-compatible endpoint that answers 400 to any request with `temperature`,
    as Anthropic's does for Claude 5 models; records each request body."""
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer

    bodies = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            bodies.append(body)
            if "temperature" in body:
                out, code = {"error": {"message": "`temperature` is deprecated for this model."}}, 400
            else:
                out, code = {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}, 200
            raw = json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    _threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, bodies


@_pytest.mark.parametrize("call", ["post_chat", "chat_raw"])
def test_rejected_temperature_is_dropped_and_remembered(call):
    srv, bodies = _rejecting_server()
    try:
        cfg = LLMConfig(base_url=f"http://127.0.0.1:{srv.server_port}/v1", api_key="x",
                        model="m", timeout=10, total_timeout=10, agent_retries=0)
        client = LLMClient(cfg)
        msgs = [{"role": "user", "content": "hi"}]
        LLMClient._NO_TEMPERATURE.clear()
        for n in range(2):
            if n:
                client = LLMClient(cfg)       # a new client (one per hunt unit) remembers it
            if call == "post_chat":
                assert client._post_chat(msgs, 10, None) == "ok"
            else:
                assert client.chat_raw(msgs)["content"] == "ok"
        # one rejected request, then every request without the field
        assert ["temperature" in b for b in bodies] == [True, False, False]
    finally:
        LLMClient._NO_TEMPERATURE.clear()
        srv.shutdown()
