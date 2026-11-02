#!/usr/bin/env python3
"""Run Frame over the prepared BAC-Bench checkouts and record its findings.

Two tiers, both real FrameScanner invocations:
  frame_symbolic - FrameScanner(verify=True): the sound authz findings.
  frame_hunt     - FrameScanner(hunt_authz=True): the agentic authorization hunt
                   (engine-backed where a frontend exists; needs FRAME_LLM_*).

For each case it scans the vulnerable AND the fixed checkout, so score.py can credit a
paired result only when the finding is gone at the fix.

    python benchmarks/bacbench/run.py --workspace /tmp/frame-bacbench \\
        --systems frame_symbolic --output benchmarks/bacbench/results/v1
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYSTEMS = ("frame_symbolic", "frame_hunt")
_LANG = {"python": "python", "javascript": "javascript", "typescript": "javascript"}


def _frame_commit() -> str:
    import subprocess
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


def _normalized(result, root: Path) -> list:
    out = []
    for v in result.vulnerabilities:
        try:
            rel = str(Path(result.filename).resolve().relative_to(root))
        except ValueError:
            rel = result.filename
        out.append({"file": rel, "line": v.line, "cwe": v.cwe_id or "",
                    "type": getattr(v.type, "value", str(v.type)),
                    "tier": ("llm" if v.source_var in ("llm_detect", "llm_verified") else "symbolic"),
                    "source_var": v.source_var})
    return out


def _scan(checkout: Path, language: str, system: str) -> list:
    from frame.sil import FrameScanner
    lang = _LANG.get(language, "python")
    hunt = system == "frame_hunt"
    sc = FrameScanner(language=lang, verify=not hunt, hunt_authz=hunt, timeout=8000)
    findings = []
    for res in sc.scan_directory(str(checkout), None, project_root=str(checkout)):
        findings.extend(_normalized(res, checkout.resolve()))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--systems", default="frame_symbolic")
    ap.add_argument("--only", default="")
    ap.add_argument("--output", default=str(HERE / "results" / "v1"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    prepared = json.loads((ws / "prepared.json").read_text())
    cases = prepared["cases"]
    if args.only:
        want = set(args.only.split(","))
        cases = [c for c in cases if c["id"] in want]
    systems = [s for s in args.systems.split(",") if s]

    if args.dry_run:
        print(f"frame {_frame_commit()[:10]}  {len(cases)} cases x {systems}")
        for c in cases:
            print(f"  {c['id']:40s} {c['language']}")
        return 0

    out_root = Path(args.output)
    for system in systems:
        for c in cases:
            outdir = out_root / system
            outdir.mkdir(parents=True, exist_ok=True)
            rec = {"system": system, "id": c["id"], "language": c["language"],
                   "frame_commit": _frame_commit(),
                   "model": os.environ.get("FRAME_LLM_MODEL") if system == "frame_hunt" else None,
                   "start_time": time.strftime("%Y-%m-%dT%H:%M:%S"), "scans": {}}
            for which, path in c.get("checkouts", {}).items():
                p = Path(path)
                if not p.is_dir():
                    rec["scans"][which] = {"error": "missing checkout"}
                    continue
                t0 = time.time()
                try:
                    findings = _scan(p, c["language"], system)
                    rec["scans"][which] = {"findings": findings,
                                           "wall_clock_seconds": round(time.time() - t0, 2)}
                except Exception as e:                       # recorded, never a silent 0
                    rec["scans"][which] = {"error": f"{type(e).__name__}: {e}"}
                print(f"[run] {system} / {c['id']} / {which}: "
                      f"{len(rec['scans'][which].get('findings', []))} findings", flush=True)
            (outdir / f"{c['id']}.json").write_text(json.dumps(rec, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
