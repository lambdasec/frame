"""Write demo/ with credentials in the shapes people commit by mistake. The tokens are assembled
here at run time, so this repository never contains one (GitHub push protection, and Frame,
would rightly object). None is a real credential.

    python make_demo.py && frame scan demo/
    python make_demo.py --history && frame history demo/

With `--history`, demo/ is also a git repository: the files are committed, then the Stripe key is
"fixed" by reading it from the environment, as people do, and committed again.
"""

import os
import subprocess
import sys
from pathlib import Path

ALNUM = "Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
GITHUB = "gh" + "p_" + ALNUM[:36]
STRIPE = "sk" + "_live_" + ALNUM[:24]
AWS = "AK" + "IA" + "Z7K3M9Q2W8E4R6T1"
OPENAI = "sk-" + "proj-" + ALNUM[:48]

FILES = {
    "deploy.py": f'''import boto3
import requests
from github import Github

# A personal access token passed straight to the client: no variable name says "token".
gh = Github("{GITHUB}")


def notify(message):
    requests.post("https://api.example.com/notify", json={{"text": message}},
                  headers={{"Authorization": "Bearer {OPENAI}"}})


s3 = boto3.client("s3", aws_access_key_id="{AWS}")

# An example from AWS's documentation is not a credential:
DOCS_EXAMPLE = "AKIA" "IOSFODNN7EXAMPLE"

# A rotated token mentioned in a comment is not a literal: {GITHUB}
''',
    # A test file (not named test_*: it is test code because it imports pytest and asserts).
    "checks.py": '''import pytest

from deploy import notify


def test_notify_posts(monkeypatch):
    sent = []
    monkeypatch.setattr("requests.post", lambda url, **kw: sent.append(url))
    admin_password = "correct-horse-battery"
    notify(f"login with {admin_password}")
    assert sent == ["https://api.example.com/notify"]
''',
    "billing.js": f'''const Stripe = require("stripe");

const stripe = Stripe("{STRIPE}");

module.exports = {{ stripe }};
''',
}

FIXED_BILLING = '''const Stripe = require("stripe");

const stripe = Stripe(process.env.STRIPE_KEY);

module.exports = { stripe };
'''


def _git(out: Path, *args: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_NAME": "demo", "GIT_AUTHOR_EMAIL": "demo@example.com",
           "GIT_COMMITTER_NAME": "demo", "GIT_COMMITTER_EMAIL": "demo@example.com",
           "GIT_AUTHOR_DATE": "2026-01-05T10:00:00+00:00", "GIT_COMMITTER_DATE": "2026-01-05T10:00:00+00:00"}
    subprocess.run(["git", "-C", str(out), *args], check=True, capture_output=True, env=env)


if __name__ == "__main__":
    out = Path(__file__).parent / "demo"
    out.mkdir(exist_ok=True)
    for name, text in FILES.items():
        (out / name).write_text(text)
    print(f"wrote {', '.join(sorted(FILES))} to {out}")
    if "--history" in sys.argv:
        _git(out, "init", "-q", "-b", "main")
        _git(out, "add", "-A")
        _git(out, "commit", "-q", "-m", "billing and deploy scripts")
        (out / "billing.js").write_text(FIXED_BILLING)
        _git(out, "commit", "-q", "-am", "read the Stripe key from the environment")
        print("committed, then moved the Stripe key to an environment variable")
