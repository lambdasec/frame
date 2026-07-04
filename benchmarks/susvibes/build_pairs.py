#!/usr/bin/env python3
"""Reconstruct vulnerable/fixed code pairs from the SusVibes dataset.

Each SusVibes task is a real CVE fix commit. We take the changed Python file(s) at
the fix commit (secure) from raw GitHub, then reverse-apply the security patch to get
the pre-fix (vulnerable) version. No Docker or full clones needed.

    python benchmarks/susvibes/build_pairs.py \
        --dataset /tmp/susvibes/datasets/default/susvibes_dataset.jsonl \
        --out /tmp/susvibes-pairs
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


def raw(proj: str, sha: str, path: str) -> str:
    u = f"https://raw.githubusercontent.com/{proj}/{sha}/{path}"
    return urllib.request.urlopen(u, timeout=30).read().decode("utf-8", "replace")


def changed_files(patch: str) -> list:
    return re.findall(r"^\+\+\+ b/(.+)$", patch, re.M)


def build_one(r: dict, out: Path):
    iid, proj, base = r["instance_id"], r["project"], r["base_commit"]
    files = [f for f in changed_files(r["security_patch"]) if f.endswith(".py")]
    if not files:
        return None, "no .py files changed"
    repo = out / iid / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=repo)
    subprocess.run(["git", "config", "user.email", "x@x"], cwd=repo)
    subprocess.run(["git", "config", "user.name", "x"], cwd=repo)
    for f in files:
        p = repo / f
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            p.write_text(raw(proj, base, f), encoding="utf-8")
        except urllib.error.HTTPError as e:
            return None, f"fetch {f}: {e}"
    subprocess.run(["git", "add", "-A"], cwd=repo)
    subprocess.run(["git", "commit", "-q", "-m", "secure"], cwd=repo)
    sec = out / iid / "secure"
    sec.mkdir(exist_ok=True)
    for f in files:
        (sec / Path(f).name).write_text((repo / f).read_text(encoding="utf-8"), encoding="utf-8")
    patchfile = out / iid / "sec.patch"
    patchfile.write_text(r["security_patch"])
    ap = subprocess.run(["git", "apply", "-R", "--recount", str(patchfile)], cwd=repo,
                        capture_output=True, text=True)
    if ap.returncode != 0:
        return None, f"git apply -R failed: {ap.stderr.strip()[:120]}"
    vul = out / iid / "vulnerable"
    vul.mkdir(exist_ok=True)
    for f in files:
        (vul / Path(f).name).write_text((repo / f).read_text(encoding="utf-8"), encoding="utf-8")
    subprocess.run(["rm", "-rf", str(repo)])  # reconstruction scratch, not needed
    (out / iid / "sec.patch").unlink(missing_ok=True)
    return {"instance_id": iid, "cwe_ids": r["cwe_ids"], "cve": r.get("cve_id"),
            "files": [Path(f).name for f in files]}, "ok"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True, help="susvibes_dataset.jsonl")
    ap.add_argument("--out", required=True, help="output dir for pairs")
    ap.add_argument("--limit", type=int, default=0, help="cap number of tasks (0 = all)")
    args = ap.parse_args(argv)
    rows = [json.loads(l) for l in open(args.dataset)]
    if args.limit:
        rows = rows[:args.limit]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest, ok, fail = [], 0, 0
    for r in rows:
        m, status = build_one(r, out)
        if m:
            manifest.append(m); ok += 1
        else:
            fail += 1
            print(f"  SKIP {r['instance_id'][:40]:40} {status}", file=sys.stderr)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"built {ok} pairs, {fail} skipped -> {out}/manifest.json")


if __name__ == "__main__":
    main()
