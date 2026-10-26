#!/usr/bin/env python3
"""A one-file edit that makes a *different*, untouched file vulnerable.

A coding agent (or a person) changes only `clean.py`: `sanitize()` stops quoting.
`views.py` is not in the diff, but its `os.system('ls ' + sanitize(...))` just became a
command injection. This script builds that repo in a temp dir, commits the safe version,
makes the edit, and asks each tool what is new relative to the committed state.

    python use_cases/helper_edit_regression.py [--semgrep PATH] [--opengrep PATH]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RULES = HERE.parent / "rules"

CLEAN_SAFE = "import shlex\n\n\ndef sanitize(name):\n    return shlex.quote(name)\n"
CLEAN_EDITED = "def sanitize(name):\n    return name.strip()\n"
VIEWS = ("from flask import Flask, request\nimport os\nfrom clean import sanitize\n"
         "app = Flask(__name__)\n\n\n@app.route('/ls')\ndef ls():\n"
         "    os.system('ls ' + sanitize(request.args.get('d', '')))\n    return 'ok'\n")


def sh(cmd, cwd, **kw):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, **kw)


def parse(stdout: str) -> dict:
    return json.loads(stdout[stdout.index("{"):])      # a status line may precede the JSON


def semgrep_rows(binary: str, repo: Path, extra: list[str]) -> list[tuple[str, int]]:
    flags = ["--metrics=off"] if "semgrep" in Path(binary).name else []
    p = sh([binary, "-q", "--json", *flags, "--config", str(RULES / "taint_python.yml")] + extra + ["."], repo)
    return sorted((r["path"], r["start"]["line"]) for r in json.loads(p.stdout)["results"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep")
    ap.add_argument("--opengrep")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "clean.py").write_text(CLEAN_SAFE)
        (repo / "views.py").write_text(VIEWS)
        for c in (["git", "init", "-q"], ["git", "add", "."],
                  ["git", "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-qm", "safe"]):
            sh(c, repo)
        frame = [sys.executable, "-m", "frame.sil.cli", "scan", str(repo)]
        before = sh(frame + ["--write-baseline", str(repo / "base.json"), "--fail-on", "none", "--format", "json"], ROOT)
        print(f"committed state: Frame reports {sum(len(f['vulnerabilities']) for f in parse(before.stdout)['files'])} findings")
        (repo / "clean.py").write_text(CLEAN_EDITED)      # the only edit
        print("edit: clean.py only (views.py untouched)\n")

        p = sh(frame + ["--changed", "--baseline", str(repo / "base.json"), "--format", "json"], ROOT)
        data = parse(p.stdout)
        new = [(Path(f["filename"]).name, v["line"], v["cwe_id"]) for f in data["files"] for v in f["vulnerabilities"]]
        print(f"Frame --changed --baseline : exit {p.returncode}, new findings {new}")

        for label, binary, extra in (("Semgrep (taint rules)", a.semgrep, []),
                                     ("OpenGrep (taint rules, intrafile)", a.opengrep, ["--taint-intrafile"])):
            if not binary:
                continue
            now = semgrep_rows(binary, repo, extra)
            sh(["git", "stash", "-q"], repo)
            then = semgrep_rows(binary, repo, extra)
            sh(["git", "stash", "pop", "-q"], repo)
            print(f"{label:34}: committed state {then}, edited state {now} -> new: {sorted(set(now) - set(then))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
