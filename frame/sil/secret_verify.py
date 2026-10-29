"""Does a found credential still work? Asked of its provider, only when the user opts in
(`frame scan --verify-secrets`, `frame history --verify`).

Each format's `verify` entry (`specs/data/secret-formats.toml`) is a read-only request to the
provider's own API, at a fixed https URL, with the token in a header: GitHub's `/user`, Slack's
`auth.test`, OpenAI's model list. Nothing else is ever sent and no other host is contacted. The
answer is:

    valid        the provider accepted it: someone can use it now (rotate it first)
    invalid      the provider rejected it (revoked, expired, or never real)
    unverified   the format has no check, or the answer was neither (a timeout, a rate limit,
                 a 403 from a key the provider knows but that may not read that endpoint)

The value is never printed or stored; the provider sees it, as it would for any use of it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Callable, Dict, Optional, Tuple

from frame.sil.secret_formats import SecretFormat, Verify

# (method, url, headers) -> (status, body); None status for a network error
Send = Callable[[str, str, Dict[str, str]], Tuple[Optional[int], bytes]]

VALID, INVALID, UNVERIFIED = "valid", "invalid", "unverified"
TIMEOUT = 10


def http_send(method: str, url: str, headers: Dict[str, str]) -> Tuple[Optional[int], bytes]:
    req = urllib.request.Request(url, method=method, headers=headers, data=b"" if method == "POST" else None)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:      # noqa: S310 (fixed https URL)
            return r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536)
    except (urllib.error.URLError, OSError, ValueError):
        return None, b""


def _json_matches(want, body: bytes) -> bool:
    if not want:
        return True
    try:
        data = json.loads(body)
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    for key, value in want:
        options = value if isinstance(value, list) else [value]
        if data.get(key) not in options:
            return False
    return True


def judge(v: Verify, status: Optional[int], body: bytes) -> str:
    if status is None:
        return UNVERIFIED
    if status in v.invalid or (v.invalid_json and _json_matches(v.invalid_json, body)):
        return INVALID
    if status in v.valid and _json_matches(v.valid_json, body):
        return VALID
    return UNVERIFIED


class Verifier:
    """Checks each distinct credential once per run."""

    def __init__(self, send: Send = http_send):
        self.send = send
        self._seen: Dict[Tuple[str, str], Tuple[str, str]] = {}

    def check(self, fmt: SecretFormat, value: str) -> Tuple[str, str]:
        """(state, the host asked) for a credential of this format."""
        v = fmt.verify
        if v is None:
            return UNVERIFIED, ""
        key = (fmt.id, value)
        if key not in self._seen:
            headers = {name: text.replace("{token}", value) for name, text in v.headers}
            status, body = self.send(v.method, v.url, headers)
            self._seen[key] = (judge(v, status, body), v.host)
        return self._seen[key]


def describe(state: str, host: str) -> str:
    return {VALID: f"verified valid at {host}: it works now, rotate it",
            INVALID: f"rejected by {host} (revoked or expired)",
            UNVERIFIED: f"not verified ({host} gave no clear answer)" if host else "not verified (no check for this format)"}[state]


__all__ = ["Verifier", "judge", "http_send", "describe", "VALID", "INVALID", "UNVERIFIED"]
