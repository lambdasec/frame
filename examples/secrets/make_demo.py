"""Write demo/ with credentials in the shapes people commit by mistake. The tokens are assembled
here at run time, so this repository never contains one (GitHub push protection, and Frame,
would rightly object). None is a real credential.

    python make_demo.py && frame scan demo/
"""

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
    "billing.js": f'''const Stripe = require("stripe");

const stripe = Stripe("{STRIPE}");

module.exports = {{ stripe }};
''',
}

if __name__ == "__main__":
    out = Path(__file__).parent / "demo"
    out.mkdir(exist_ok=True)
    for name, text in FILES.items():
        (out / name).write_text(text)
    print(f"wrote {', '.join(sorted(FILES))} to {out}")
