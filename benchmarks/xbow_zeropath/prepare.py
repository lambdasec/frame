#!/usr/bin/env python3
"""Prepare the XBOW/ZeroPath AI-SAST benchmark: clone ZeroPath's public fork of
XBOW's validation benchmarks at a pinned commit.

The fork ships, per benchmark: the (hint-removed) vulnerable app, a patched/secure
twin for false-positive testing, ground-truth vulnerabilities in rules/, the raw
SARIF of the vendor scanners (zeropath, semgrep, snyk_code, bearer), and the GPT-4o
scoring scripts. We add Frame's SARIF and score it with the same judge.

    python benchmarks/xbow_zeropath/prepare.py --workspace /tmp/frame-xbow
"""
import argparse
import subprocess
import sys
from pathlib import Path

REPO = "https://github.com/ZeroPathAI/validation-benchmarks.git"
PINNED_SHA = "9c114481b130b8755d6a56ff5a9c26c7567ded4e"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True, help="dir to clone the fork into")
    args = ap.parse_args()
    ws = Path(args.workspace).expanduser().resolve()
    dest = ws / "validation-benchmarks"
    ws.mkdir(parents=True, exist_ok=True)

    if not (dest / ".git").is_dir():
        r = subprocess.run(["git", "clone", "--quiet", REPO, str(dest)])
        if r.returncode != 0:
            print("[prepare] clone failed", file=sys.stderr)
            return 1
    subprocess.run(["git", "fetch", "--quiet", "origin", PINNED_SHA], cwd=dest)
    subprocess.run(["git", "checkout", "--quiet", "--force", PINNED_SHA], cwd=dest)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=dest,
                          capture_output=True, text=True).stdout.strip()
    if head != PINNED_SHA:
        print(f"[prepare] HEAD {head} != pinned {PINNED_SHA}", file=sys.stderr)
        return 1
    print(f"[prepare] validation-benchmarks pinned at {head[:10]} -> {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
