"""Verifying found credentials with their providers (`--verify-secrets`, `frame history --verify`;
frame/sil/secret_verify.py, the `verify` entries of specs/data/secret-formats.toml).

Offline, the provider is played by a function (`send=`) or by a real HTTP server on localhost
that records what it was sent: the token goes in the documented header and nowhere else, and
nothing is sent unless asked. Live (FRAME_SECRETS_LIVE=1), a well-formed but fake token of every
format with a check is sent to the real provider, which must call it invalid; with
FRAME_VERIFY_GITHUB_TOKEN set to a real token, GitHub must call it valid.

Every token here is assembled at run time: never commit a contiguous token-shaped string.
"""

import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.secret_formats import SecretFormatError, formats, load
from frame.sil.secret_verify import INVALID, UNVERIFIED, VALID, Verifier, judge

A = "Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
FAKE = {                                 # well formed, never real
    "github-token": "gh" + "p_" + A[:36],
    "github-fine-grained-pat": "github" + "_pat_" + (A + A)[:82],
    "slack-token": "xox" + "b-12345678901-" + A[:24],
    "stripe-live-key": "sk" + "_live_" + A[:24],
    "openai-api-key": "sk-" + "proj-" + A[:48],
    "anthropic-api-key": "sk-" + "ant-api03-" + (A + A)[:93] + "AA",
    "sendgrid-api-key": "SG." + A[:22] + "." + A[:43],
    "huggingface-token": "hf" + "_" + "".join(c for c in A + A if c.isalpha())[:34],
    "digitalocean-token": "dop" + "_v1_" + "a1b2c3d4" * 8,
    "npm-token": "npm" + "_" + A[:36],
}
BY_ID = {f.id: f for f in formats()}
CHECKED = sorted(f.id for f in formats() if f.verify)


def test_every_check_is_a_fixed_https_endpoint_of_its_provider():
    assert CHECKED == sorted(FAKE)
    for f in formats():
        if f.verify:
            v = f.verify
            assert v.url.startswith("https://") and "{" not in v.url and v.reference.startswith("https://")
            assert any("{token}" in text for _, text in v.headers)
            assert FAKE[f.id] and f.regex.search(FAKE[f.id]), f.id      # the fakes have the real shape


@pytest.mark.parametrize("bad,why", [
    ('url = "https://{token}.example.com/"', "fixed https URL"),
    ('url = "http://api.example.com/"', "fixed https URL"),
    ('url = "https://api.example.com/"\nbody = "{token}"', "unknown keys"),
])
def test_a_check_that_could_send_the_token_elsewhere_does_not_load(tmp_path, bad, why):
    p = tmp_path / "f.toml"
    p.write_text('[[format]]\nid = "x"\nprovider = "X"\npattern = "x_[a-z]{8}"\ndescription = "d"\n'
                 'reference = "https://example.com"\n[format.verify]\nmethod = "GET"\n' + bad + '\n'
                 'headers = { Authorization = "Bearer {token}" }\nvalid = [200]\ninvalid = [401]\n'
                 'reference = "https://example.com/doc"\n')
    with pytest.raises(SecretFormatError, match=why):
        load(p)


@pytest.mark.parametrize("fid,status,body,state", [
    ("github-token", 200, b"{}", VALID),
    ("github-token", 401, b'{"message": "Bad credentials"}', INVALID),
    ("github-token", 403, b"{}", UNVERIFIED),            # rate limited, or a key that may not read /user
    ("github-token", None, b"", UNVERIFIED),             # network error
    ("slack-token", 200, b'{"ok": true, "team": "T"}', VALID),
    ("slack-token", 200, b'{"ok": false, "error": "invalid_auth"}', INVALID),
    ("slack-token", 200, b'{"ok": false, "error": "ratelimited"}', UNVERIFIED),
    ("slack-token", 200, b"not json", UNVERIFIED),
])
def test_what_the_answer_means(fid, status, body, state):
    assert judge(BY_ID[fid].verify, status, body) == state


class _Provider(BaseHTTPRequestHandler):
    seen: list = []
    answer = 401

    def _reply(self):
        self.seen.append((self.command, self.path, dict(self.headers)))
        self.send_response(self.answer)
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = do_POST = _reply

    def log_message(self, *a):
        pass


@pytest.fixture
def provider():
    """A real HTTP server standing in for the provider; requests to the format's URL go to it."""
    server = HTTPServer(("127.0.0.1", 0), _Provider)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _Provider.seen = []
    from frame.sil import secret_verify

    def send(method, url, headers):
        from urllib.parse import urlsplit
        local = f"http://127.0.0.1:{server.server_port}{urlsplit(url).path}"
        return secret_verify.http_send(method, local, {**headers, "X-Original-Host": urlsplit(url).hostname})
    yield server, send
    server.shutdown()


def test_the_token_goes_in_the_documented_header_to_the_provider_only(provider):
    server, send = provider
    _Provider.answer = 200
    state, host = Verifier(send).check(BY_ID["github-token"], FAKE["github-token"])
    [(method, path, headers)] = _Provider.seen
    assert (state, host, method, path) == (VALID, "api.github.com", "GET", "/user")
    assert headers["Authorization"] == "Bearer " + FAKE["github-token"] and headers["X-Original-Host"] == "api.github.com"


def test_each_credential_is_asked_once(provider):
    server, send = provider
    _Provider.answer = 401
    v = Verifier(send)
    for _ in range(3):
        assert v.check(BY_ID["openai-api-key"], FAKE["openai-api-key"]) == (INVALID, "api.openai.com")
    assert len(_Provider.seen) == 1


def _code(token):
    return f'from github import Github\ngh = Github("{token}")\n'


@pytest.mark.parametrize("answer,severity,validity", [(200, "critical", VALID), (401, "low", INVALID),
                                                      (500, "critical", UNVERIFIED)])
def test_a_scan_reports_what_the_provider_said(provider, answer, severity, validity):
    server, send = provider
    _Provider.answer = answer
    scanner = FrameScanner(language="python", verify_secrets=True)
    scanner.secret_verifier = Verifier(send)
    [v] = scanner.scan(_code(FAKE["github-token"]), "deploy.py").vulnerabilities
    assert (v.severity.value, v.validity) == (severity, validity)
    assert v.to_dict()["validity"] == validity and FAKE["github-token"] not in str(v.to_dict())


def test_nothing_is_sent_without_the_flag(monkeypatch):
    from frame.sil import secret_verify

    def refuse(*a):
        raise AssertionError("sent without --verify-secrets")
    monkeypatch.setattr(secret_verify, "http_send", refuse)
    [v] = FrameScanner(language="python").scan(_code(FAKE["github-token"]), "deploy.py").vulnerabilities
    assert v.validity == "" and "validity" not in v.to_dict()


def test_history_reports_what_the_provider_said(tmp_path, provider):
    server, send = provider
    _Provider.answer = 401
    from frame.sil.secret_history import format_text, scan_history
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "deploy.py").write_text(_code(FAKE["github-token"]))
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "x"], check=True, env=env)
    [leak] = scan_history(tmp_path, verifier=Verifier(send))
    assert leak.validity == INVALID and "rejected by api.github.com" in format_text([leak])


LIVE = os.environ.get("FRAME_SECRETS_LIVE") == "1"


@pytest.mark.skipif(not LIVE, reason="live: set FRAME_SECRETS_LIVE=1 (sends fake tokens to each provider)")
@pytest.mark.parametrize("fid", sorted(FAKE))
def test_live_every_provider_rejects_a_fake_token(fid):
    """The endpoint, method and header are right: the real provider answers, and says invalid."""
    assert Verifier().check(BY_ID[fid], FAKE[fid])[0] == INVALID


@pytest.mark.skipif(not os.environ.get("FRAME_VERIFY_GITHUB_TOKEN"),
                    reason="live: set FRAME_VERIFY_GITHUB_TOKEN to a real token (e.g. $(gh auth token))")
def test_live_a_real_github_token_is_valid(tmp_path):
    token = os.environ["FRAME_VERIFY_GITHUB_TOKEN"]
    f = tmp_path / "deploy.py"
    f.write_text(_code(token))
    [v] = FrameScanner(language="python", verify_secrets=True).scan(f.read_text(), "deploy.py").vulnerabilities
    assert (v.validity, v.severity.value) == (VALID, "critical")
    assert token not in str(v.to_dict()) and token not in Path(f).name
