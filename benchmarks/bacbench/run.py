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
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYSTEMS = ("frame_symbolic", "frame_hunt")
_LANG = {"python": "python", "javascript": "javascript", "typescript": "javascript"}


class _Timeout(Exception):
    """A per-checkout wall-clock cap fired. Recorded as a timeout, never a clean 'no
    findings' -- so a case Frame could not finish scanning in time is not a false miss
    silently. Large monorepos (hundreds-to-thousands of files) are bounded this way; the
    cap is fair (it scans the whole language subtree, no ground-truth scoping)."""


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


def _hunt_grep(checkout: Path, language: str, cap: int = 0) -> list:
    """Run the authorization hunt WITHOUT a full engine pre-scan: the agent greps/reads the
    repository itself (the cross-language fallback). Fast on large monorepos -- where scanning
    hundreds of files to build engine facts eats the time budget before the agent runs -- at
    the cost of the engine-backed tier (every finding is llm_detect). Produces the full
    trajectory for analysis."""
    from frame.sil.llm_hunt import hunt_authz
    from frame.sil.llm_triage import TriageConfig
    lang = _LANG.get(language, "python")
    use_alarm = cap > 0 and hasattr(signal, "SIGALRM")
    if use_alarm:
        signal.signal(signal.SIGALRM, lambda s, f: (_ for _ in ()).throw(_Timeout()))
        signal.alarm(cap)
    try:
        vulns = hunt_authz([], [], str(checkout), TriageConfig.from_env(), None, language=lang)
    finally:
        if use_alarm:
            signal.alarm(0)
    root = checkout.resolve()
    out = []
    for v in vulns:
        try:
            rel = str(Path(v.location).resolve().relative_to(root))
        except ValueError:
            rel = v.location
        out.append({"file": rel, "line": v.line, "cwe": v.cwe_id or "",
                    "type": getattr(v.type, "value", str(v.type)),
                    "tier": "llm", "source_var": v.source_var})
    return out


def _scan(checkout: Path, language: str, system: str, cap: int = 0,
          cross_file: bool = True) -> list:
    from frame.sil import FrameScanner
    lang = _LANG.get(language, "python")
    hunt = system == "frame_hunt"
    sc = FrameScanner(language=lang, verify=not hunt, hunt_authz=hunt, timeout=8000)
    findings = []
    use_alarm = cap > 0 and hasattr(signal, "SIGALRM")
    if use_alarm:
        def _fire(signum, frame):
            raise _Timeout()
        signal.signal(signal.SIGALRM, _fire)
        signal.alarm(cap)
    try:
        for res in sc.scan_directory(str(checkout), None, project_root=str(checkout),
                                     cross_file=cross_file):
            findings.extend(_normalized(res, checkout.resolve()))
    finally:
        if use_alarm:
            signal.alarm(0)
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--systems", default="frame_symbolic")
    ap.add_argument("--only", default="")
    ap.add_argument("--output", default=str(HERE / "results" / "v1"))
    ap.add_argument("--per-case-timeout", type=int, default=0,
                    help="wall-clock seconds per checkout scan (0 = no cap); a cap is recorded "
                         "as a timeout, never a clean miss")
    ap.add_argument("--save-trajectories", action="store_true",
                    help="save each hunt's HF Session-Trace + per-call timing under <output>/"
                         "<system>/traj/<case>/<checkout>/ (frame_hunt only)")
    ap.add_argument("--resume", action="store_true",
                    help="skip cases whose result file already exists (resume an interrupted run)")
    ap.add_argument("--hunt-grep-mode", action="store_true",
                    help="frame_hunt: skip the engine pre-scan; the agent greps/reads the repo "
                         "itself (fast on large monorepos; findings are llm_detect, no engine tier)")
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
            outfile = outdir / f"{c['id']}.json"
            if args.resume and outfile.is_file():
                print(f"[run] {system} / {c['id']}: resume -> skip (result exists)", flush=True)
                continue
            rec = {"system": system, "id": c["id"], "language": c["language"],
                   "frame_commit": _frame_commit(),
                   "model": os.environ.get("FRAME_LLM_MODEL") if system == "frame_hunt" else None,
                   "start_time": time.strftime("%Y-%m-%dT%H:%M:%S"), "scans": {}}
            for which, path in c.get("checkouts", {}).items():
                p = Path(path)
                if not p.is_dir():
                    rec["scans"][which] = {"error": "missing checkout"}
                    continue
                if args.save_trajectories and system == "frame_hunt":
                    tdir = outdir / "traj" / c["id"] / which
                    tdir.mkdir(parents=True, exist_ok=True)
                    os.environ["FRAME_LLM_TRAJECTORY_DIR"] = str(tdir)
                else:
                    os.environ.pop("FRAME_LLM_TRAJECTORY_DIR", None)
                t0 = time.time()
                try:
                    if system == "frame_hunt" and args.hunt_grep_mode:
                        findings = _hunt_grep(p, c["language"], args.per_case_timeout)
                    else:
                        # The hunt reasons over handler facts, not a full cross-file taint build;
                        # scanning the whole monorepo cross-file eats the time budget before the
                        # agent loop runs on large apps, so the hunt pre-scan skips cross-file.
                        findings = _scan(p, c["language"], system, args.per_case_timeout,
                                         cross_file=(system != "frame_hunt"))
                    rec["scans"][which] = {"findings": findings,
                                           "wall_clock_seconds": round(time.time() - t0, 2)}
                except _Timeout:
                    rec["scans"][which] = {"error": "timeout",
                                           "wall_clock_seconds": round(time.time() - t0, 2)}
                except Exception as e:                       # recorded, never a silent 0
                    rec["scans"][which] = {"error": f"{type(e).__name__}: {e}"}
                print(f"[run] {system} / {c['id']} / {which}: "
                      f"{len(rec['scans'][which].get('findings', []))} findings", flush=True)
            outfile.write_text(json.dumps(rec, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
