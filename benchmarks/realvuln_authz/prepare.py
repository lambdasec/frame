#!/usr/bin/env python3
"""Prepare the RealVuln authz benchmark: clone the 4 pinned public apps at their
exact commits and verify SHAs. No app source is vendored into Frame; everything is
fetched fresh from public upstreams and pinned by the frozen manifest.

    python benchmarks/realvuln_authz/prepare.py --workspace /tmp/frame-realvuln-authz
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


def _clone_pinned(url: str, sha: str, dest: Path) -> str:
    """Clone `url` and hard-checkout `sha`. Returns the resolved HEAD sha. Raises on
    mismatch."""
    gh = f"https://github.com/{url}.git" if "://" not in url else url
    if not (dest / ".git").is_dir():
        dest.parent.mkdir(parents=True, exist_ok=True)
        r = _run(["git", "clone", "--quiet", gh, str(dest)])
        if r.returncode != 0:
            raise RuntimeError(f"clone {url} failed: {r.stderr.strip()}")
    # fetch the exact object then hard-reset (works for shallow upstreams too)
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True, help="dir to clone the apps into")
    args = ap.parse_args()

    manifest = yaml.safe_load(MANIFEST.read_text())
    ws = Path(args.workspace).expanduser().resolve()
    ws.mkdir(parents=True, exist_ok=True)

    prep = {"benchmark": manifest["benchmark"], "version": manifest["version"],
            "realvuln_commit": manifest["realvuln_benchmark"]["commit"], "repositories": []}

    ok = True
    for repo in manifest["repositories"]:
        slug, url, sha = repo["slug"], repo["upstream_repository"], repo["commit"]
        dest = ws / slug
        print(f"[prepare] {slug}  <- {url}@{sha[:10]} ...", flush=True)
        try:
            head = _clone_pinned(url, sha, dest)
            print(f"[prepare]   OK  HEAD={head[:10]}")
            prep["repositories"].append({
                "slug": slug, "upstream_repository": url, "commit": head,
                "framework": repo["framework"], "role": repo["role"],
                "path": str(dest), "n_cases": len(repo["cases"])})
        except Exception as e:
            ok = False
            print(f"[prepare]   FAIL: {e}", file=sys.stderr)
            prep["repositories"].append({"slug": slug, "error": str(e)})

    (ws / "prepare_manifest.json").write_text(json.dumps(prep, indent=2))
    print(f"[prepare] wrote {ws/'prepare_manifest.json'}")
    if not ok:
        print("[prepare] one or more repositories failed to pin", file=sys.stderr)
        return 1
    print("[prepare] all repositories pinned and SHA-verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
