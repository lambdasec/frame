#!/usr/bin/env python3
"""Prepare the VLoc Bench study: clone Cisco's benchmark at a pinned commit and
fetch the repository snapshots for the task set we score.

The benchmark itself (manifest, downloader, scorer) is used verbatim. We never
edit their scoring code, so the numbers we report are produced by Cisco's own
`scoring.py`.

    python benchmarks/vloc/prepare.py --workspace /tmp/frame-vloc --sample 80

Snapshots are large (15 GB zipped, 40 GB unzipped for all 500 tasks), so by
default only the sampled task set is downloaded. `run.py` extracts each snapshot
just before scanning it and deletes it afterwards, which keeps peak disk in the
low single-digit GB.
"""
import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

REPO = "https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark.git"
PINNED = "000c19cda9ba027e1d241216768b2b6358685000"
MANIFEST_MD5 = "15671557ddad5d2a8e2652aaa92d5de5"

# Ecosystem -> (frame --language, file globs). Go, Rust and Composer have no
# symbolic frontend in Frame and run through the LLM layer under --ai.
ECOSYSTEMS = {
    "npm":      ("javascript", ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"]),
    "pip":      ("python",     ["**/*.py"]),
    "maven":    ("java",       ["**/*.java"]),
    "go":       ("go",         ["**/*.go"]),
    "rust":     ("rust",       ["**/*.rs"]),
    "composer": ("php",        ["**/*.php"]),
}


def _run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def clone_pinned(dest: Path) -> str:
    if not (dest / ".git").is_dir():
        dest.parent.mkdir(parents=True, exist_ok=True)
        r = _run(["git", "clone", "--quiet", REPO, str(dest)])
        if r.returncode != 0:
            raise RuntimeError(f"clone failed: {r.stderr.strip()}")
    _run(["git", "fetch", "--quiet", "origin", PINNED], cwd=dest)
    r = _run(["git", "checkout", "--quiet", "--force", PINNED], cwd=dest)
    if r.returncode != 0:
        raise RuntimeError(f"checkout {PINNED} failed: {r.stderr.strip()}")
    head = _run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
    if head != PINNED:
        raise RuntimeError(f"HEAD {head} != pinned {PINNED}")
    return head


def stratified_sample(rows: list, n: int, seed: int) -> list:
    """Proportional sample across ecosystems, deterministic for a given seed.

    Proportional (not Frame-favourable) on purpose: weighting toward the CWE
    classes Frame detects best would inflate the score relative to the published
    full-set numbers and make the comparison dishonest.
    """
    import random
    if n <= 0 or n >= len(rows):
        return rows
    by_eco = {}
    for r in rows:
        by_eco.setdefault(r["ecosystem"], []).append(r)
    picked = []
    for eco, group in sorted(by_eco.items()):
        k = max(1, round(n * len(group) / len(rows)))
        rnd = random.Random(f"{seed}:{eco}")
        picked.extend(rnd.sample(group, min(k, len(group))))
    return sorted(picked, key=lambda r: r["alpha_id"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--sample", type=int, default=0,
                    help="stratified task count (0 = all 500)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--skip-download", action="store_true",
                    help="clone and select tasks but do not fetch snapshots")
    args = ap.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    bench = ws / "vulnerability-localization-benchmark"
    print(f"[prepare] cloning benchmark at {PINNED[:10]} ...")
    clone_pinned(bench)

    manifest = bench / "data" / "manifest.csv"
    import hashlib
    got = hashlib.md5(manifest.read_bytes()).hexdigest()
    if got != MANIFEST_MD5:
        raise RuntimeError(f"manifest md5 {got} != pinned {MANIFEST_MD5}")
    print(f"[prepare]   OK manifest md5 {got}")

    rows = list(csv.DictReader(manifest.open()))
    rows = [r for r in rows if not r["notes"].strip()]  # drop the deleted repo
    tasks = stratified_sample(rows, args.sample, args.seed)

    sel = ws / "tasks.json"
    sel.write_text(json.dumps({
        "pinned_commit": PINNED,
        "manifest_md5": MANIFEST_MD5,
        "seed": args.seed,
        "sampled": args.sample or len(rows),
        "n_tasks": len(tasks),
        "alpha_ids": [t["alpha_id"] for t in tasks],
    }, indent=2))
    print(f"[prepare] selected {len(tasks)} tasks -> {sel}")
    eco = {}
    for t in tasks:
        eco[t["ecosystem"]] = eco.get(t["ecosystem"], 0) + 1
    print(f"[prepare]   by ecosystem: {dict(sorted(eco.items()))}")

    if args.skip_download:
        print("[prepare] --skip-download set; run.py will fetch each snapshot on demand")
        return 0

    # The upstream downloader selects by manifest, so hand it a subset manifest
    # with the same columns rather than patching their script.
    subset = ws / "manifest_subset.csv"
    with subset.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(tasks)
    print(f"[prepare] wrote subset manifest -> {subset}")

    dl = bench / "data" / "downloader_and_verifier.py"
    print(f"[prepare] downloading {len(tasks)} snapshot pairs (this is the big step) ...")
    r = subprocess.run([sys.executable, str(dl),
                        "--manifest", str(subset),
                        "--output-dir", str(bench / "data" / "ghsa-vulns"),
                        "--resume"], cwd=bench)
    if r.returncode != 0:
        print("[prepare] downloader returned non-zero; check output above", file=sys.stderr)
        return 1
    print("[prepare] snapshots verified against manifest content MD5s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
