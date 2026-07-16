#!/usr/bin/env python3
"""Run Frame over the XBOW/ZeroPath benchmark, driving the `frame` CLI directly
(no Python API) so it exercises exactly what a user runs. For each scored benchmark
it writes `frame_raw.sarif` next to the other scanners' SARIF, for both the
vulnerable app (detection) and its patched twin (false positives).

Needs an LLM endpoint via FRAME_LLM_* (we use GLM-5.2, z-ai/glm-5.2, over an
OpenAI-compatible API; a local mlx-optiq model works too).

    python benchmarks/xbow_zeropath/run.py --workspace /tmp/frame-xbow
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def scored_benchmarks(root: Path) -> list:
    """The benchmarks ZeroPath scored (present in the published detection results)."""
    f = root / "results" / "scanner_performance_summary_detection_rates.json"
    d = json.loads(f.read_text())["results"]
    ids = set()
    for tool in d.values():
        ids |= set(tool.get("benchmark_results", {}).keys())
    return sorted(ids)  # e.g. XBEN-001


def frame_scan(bench_dir: Path) -> int:
    """Run `frame scan --ai` in bench_dir, writing frame_raw.sarif. Returns finding count."""
    subprocess.run(
        [sys.executable, "-m", "frame.sil.cli", "scan", ".", "-p", "**/*.py",
         "--ai", "--no-verify", "--format", "sarif", "-o", "frame_raw.sarif"],
        cwd=bench_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=900,
    )
    sarif = bench_dir / "frame_raw.sarif"
    if not sarif.is_file():
        return -1
    return len(json.loads(sarif.read_text())["runs"][0]["results"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--only", default="", help="comma-separated XBEN ids to limit to (pilot)")
    args = ap.parse_args()
    root = Path(args.workspace).expanduser().resolve() / "validation-benchmarks"
    if not root.is_dir():
        print("run prepare.py first", file=sys.stderr)
        return 1
    if not os.environ.get("FRAME_LLM_BASE_URL"):
        print("set FRAME_LLM_* (e.g. GLM-5.2 endpoint) first", file=sys.stderr)
        return 1

    ids = scored_benchmarks(root)
    if args.only:
        want = set(args.only.split(","))
        ids = [b for b in ids if b in want or b.replace("XBEN-", "") in want]

    for bid in ids:
        vdir = root / "benchmarks" / f"{bid}-24"
        if vdir.is_dir():
            n = frame_scan(vdir)
            print(f"[det] {bid}: {n} findings", flush=True)
        pdir = root / "benchmarks_patched" / f"{bid}-24"
        if pdir.is_dir():
            m = frame_scan(pdir)
            print(f"[fp]  {bid}: {m} findings", flush=True)
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
