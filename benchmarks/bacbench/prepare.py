#!/usr/bin/env python3
"""Prepare BAC-Bench: pin the dataset, then clone each application at its vulnerable and
fixing commits. No application source is vendored into Frame; everything is fetched from
the public upstreams the dataset names and pinned by its commit SHAs.

    python benchmarks/bacbench/prepare.py --workspace /tmp/frame-bacbench

Reads the dataset from a clone of the Absentia repository pinned in manifest.yaml. Writes
`<workspace>/prepared.json`: the resolved case list (id, language, two checkout paths).
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.yaml"


def _run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def _clone_pinned(url: str, sha: str, dest: Path, local: Path = None) -> str:
    """Clone `url` and hard-checkout `sha`; return the resolved HEAD. Raises on mismatch.
    With `local` (a clone of the same repository already made), clone from it instead of the
    network, then point origin back at `url` for any commit it lacks."""
    gh = url if "://" in url else f"https://github.com/{url}.git"
    if not (dest / ".git").is_dir():
        dest.parent.mkdir(parents=True, exist_ok=True)
        if local is not None and (local / ".git").is_dir():
            r = _run(["git", "clone", "--quiet", str(local), str(dest)])
            if r.returncode == 0:
                _run(["git", "remote", "set-url", "origin", gh], cwd=dest)
        else:
            r = _run(["git", "clone", "--quiet", gh, str(dest)])
        if r.returncode != 0:
            raise RuntimeError(f"clone {url} failed: {r.stderr.strip()}")
    if _run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=dest).returncode == 0:
        r = _run(["git", "checkout", "--quiet", "--force", sha], cwd=dest)
        head = _run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
        if r.returncode == 0 and head == sha:
            return head
    _run(["git", "fetch", "--quiet", "origin", sha], cwd=dest)
    r = _run(["git", "checkout", "--quiet", "--force", sha], cwd=dest)
    if r.returncode != 0:
        _run(["git", "fetch", "--quiet", "--all", "--tags"], cwd=dest)
        r = _run(["git", "checkout", "--quiet", "--force", sha], cwd=dest)
        if r.returncode != 0:
            raise RuntimeError(f"checkout {url}@{sha} failed: {r.stderr.strip()}")
    head = _run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
    if head != sha:
        raise RuntimeError(f"{url}: HEAD {head} != pinned {sha}")
    return head


def load_cases(workspace: Path, manifest: dict, manifest_path: Path = MANIFEST) -> list:
    """Clone the pinned dataset repo and read its records (or, for a dataset kept beside its
    manifest, `dataset.local`, read that file)."""
    ds = manifest["dataset"]
    if ds.get("local"):
        records = manifest_path.parent / ds["local"]
        return [json.loads(line) for line in records.read_text().splitlines() if line.strip()]
    ds_dir = workspace / "_dataset"
    _clone_pinned(ds["repository"], ds["commit"], ds_dir)
    records = ds_dir / ds["records"]
    return [json.loads(line) for line in records.read_text().splitlines() if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True, help="dir to clone the dataset and apps into")
    ap.add_argument("--only", default="", help="comma-separated case ids to prepare")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--manifest", default=str(MANIFEST),
                    help="the benchmark's manifest (default: BAC-Bench's)")
    args = ap.parse_args()

    manifest_path = Path(args.manifest).resolve()
    manifest = yaml.safe_load(manifest_path.read_text())
    ws = Path(args.workspace).expanduser().resolve()
    ws.mkdir(parents=True, exist_ok=True)
    cases = load_cases(ws, manifest, manifest_path)
    if args.only:
        want = set(args.only.split(","))
        cases = [c for c in cases if c["id"] in want]

    if args.dry_run:
        ds = manifest["dataset"]
        print(f"dataset {ds.get('local') or ds['repository'] + '@' + ds['commit'][:10]}  {len(cases)} cases")
        for c in cases:
            print(f"  {c['id']:40s} {c['language']:10s} {c['framework']:20s} "
                  f"{c['repo']}@{c['vulnerable_commit'][:10]}")
        return 0

    prepared, ok = [], True
    for c in cases:
        apps = ws / "apps" / c["id"]
        entry = {"id": c["id"], "language": c["language"], "framework": c["framework"],
                 "repo": c["repo"], "checkouts": {}}
        for which, sha in (("vulnerable", c["vulnerable_commit"]), ("fixed", c["fixed_commit"])):
            dest = apps / which
            try:
                _clone_pinned(c["repo"], sha, dest,
                              local=apps / "vulnerable" if which == "fixed" else None)
                entry["checkouts"][which] = str(dest)
                print(f"[prepare] {c['id']} {which} {sha[:10]} OK")
            except RuntimeError as e:
                ok = False
                print(f"[prepare] {c['id']} {which} FAILED: {e}", file=sys.stderr)
        prepared.append(entry)

    (ws / "prepared.json").write_text(json.dumps(
        {"dataset": manifest["dataset"], "cases": prepared}, indent=2))
    print(f"[prepare] wrote {ws / 'prepared.json'} ({len(prepared)} cases)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
