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
from typing import Optional
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
                    "source_var": v.source_var, **_claim(v)})
    return out


def _claim(v) -> dict:
    """The finding's own words (description, procedure), kept so judge.py can adjudicate the
    claim the way BAC-Bench does instead of only its location."""
    return {"description": str(getattr(v, "description", "") or "")[:400],
            "procedure": str(getattr(v, "procedure", "") or "")}


def hunt_options(args, out_root: Path, case_id: str) -> dict:
    """The hunt's keyword options for one case (FrameScanner(hunt_options=...) / hunt_authz).
    A flag left unset is omitted so the scanner's default applies. The verdict cache is one
    file per case, shared by its vulnerable and fixed scans (vulnerable first), so a unit whose
    files did not change between the commits keeps its verdict."""
    opts: dict = {}
    if getattr(args, "hunt_max_units", None) is not None:
        opts["max_units"] = args.hunt_max_units
    if getattr(args, "hunt_unit_steps", None) is not None:
        opts["unit_steps"] = args.hunt_unit_steps
    if getattr(args, "hunt_concurrency", None) is not None:
        opts["concurrency"] = args.hunt_concurrency
    if getattr(args, "hunt_verdict_cache", False):
        opts["verdict_cache"] = str(Path(out_root) / "frame_hunt" / "cache" / f"{case_id}.json")
    return opts


def _hunt_grep(checkout: Path, language: str, cap: int = 0,
               dynamic: bool = False, interpreter: Optional[str] = None,
               status: Optional[dict] = None, options: Optional[dict] = None) -> list:
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
        vulns = hunt_authz([], [], str(checkout), TriageConfig.from_env(), None, language=lang,
                           dynamic=dynamic, interpreter=interpreter, status=status,
                           **(options or {}))
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
                    "tier": "llm", "source_var": v.source_var, **_claim(v)})
    return out


def _scan(checkout: Path, language: str, system: str, cap: int = 0,
          cross_file: bool = True, dynamic: bool = False, interpreter: Optional[str] = None,
          status: Optional[dict] = None, options: Optional[dict] = None) -> list:
    """Scan one checkout. For frame_hunt, `status` receives how the hunt ended (the scanner's
    `last_hunt_status`), so a hunt that never reached the model is recorded as such, and
    `options` are the hunt's keyword options (see hunt_options)."""
    from frame.sil import FrameScanner
    lang = _LANG.get(language, "python")
    hunt = system == "frame_hunt"
    extra = {"hunt_options": dict(options or {})} if hunt else {}
    sc = FrameScanner(language=lang, verify=not hunt, hunt_authz=hunt, timeout=8000,
                      hunt_dynamic=(hunt and dynamic),
                      hunt_interpreter=interpreter if (hunt and dynamic) else None, **extra)
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
        if status is not None and hunt:
            status.update(getattr(sc, "last_hunt_status", None) or {"stop": "not_run"})
    return findings


def _run_case(args, system: str, c: dict, outdir: Path, out_root: Path) -> dict:
    """Scan one case's checkouts with one system and return its result record."""
    rec = {"system": system, "id": c["id"], "language": c["language"],
           "frame_commit": _frame_commit(),
           "model": os.environ.get("FRAME_LLM_MODEL") if system == "frame_hunt" else None,
           "start_time": time.strftime("%Y-%m-%dT%H:%M:%S"), "scans": {}}
    for which, path in c.get("checkouts", {}).items():
        p = Path(path)
        if not p.is_dir():
            rec["scans"][which] = {"error": "missing checkout"}
            continue
        from frame import config as frame_config
        if args.save_trajectories and system == "frame_hunt":
            tdir = outdir / "traj" / c["id"] / which
            tdir.mkdir(parents=True, exist_ok=True)
            frame_config.override("hunt", "trajectory_dir", str(tdir))
        else:
            frame_config.override("hunt", "trajectory_dir", "")
        t0 = time.time()
        hunt_status: dict = {}
        opts = hunt_options(args, out_root, c["id"])
        try:
            interp = args.hunt_interpreter or None
            if system == "frame_hunt" and args.hunt_grep_mode:
                findings = _hunt_grep(p, c["language"], args.per_case_timeout,
                                      dynamic=args.hunt_dynamic, interpreter=interp,
                                      status=hunt_status, options=opts)
            else:
                # The hunt reasons over handler facts. Per-file by default (scanning a
                # whole monorepo cross-file can eat the time budget before the agent loop
                # runs on large apps); `--hunt-cross-file` builds the facts cross-file so a
                # gate/service layer in another file becomes a lead, with the scanner's own
                # cross-file limit still protecting against the largest repos.
                hunt_cross = system == "frame_hunt" and args.hunt_cross_file
                findings = _scan(p, c["language"], system, args.per_case_timeout,
                                 cross_file=(system != "frame_hunt") or hunt_cross,
                                 dynamic=args.hunt_dynamic, interpreter=interp,
                                 status=hunt_status, options=opts)
            rec["scans"][which] = {"findings": findings,
                                   "wall_clock_seconds": round(time.time() - t0, 2)}
            if system == "frame_hunt":
                rec["scans"][which]["hunt"] = hunt_status
        except _Timeout:
            rec["scans"][which] = {"error": "timeout",
                                   "wall_clock_seconds": round(time.time() - t0, 2)}
            if system == "frame_hunt":
                rec["scans"][which]["hunt"] = hunt_status
        except Exception as e:                       # recorded, never a silent 0
            rec["scans"][which] = {"error": f"{type(e).__name__}: {e}"}
        print(f"[run] {system} / {c['id']} / {which}: "
              f"{len(rec['scans'][which].get('findings', []))} findings", flush=True)
    return rec


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def outage_damaged(rec: dict) -> bool:
    """True when an unreachable LLM endpoint cost this result work: a hunt that never got a reply,
    a unit that ended `transport_error`, or a scan that failed because the endpoint was down. A
    hunt that ran out of time or steps is not damage (rerunning would repeat it), so this is what
    --resume and --retry-outages redo. The verdict cache makes a rerun redo only the lost units."""
    for scan in (rec.get("scans") or {}).values():
        if not isinstance(scan, dict):
            continue
        if str(scan.get("error", "")).startswith("LLMUnavailableError"):
            return True
        hunt = scan.get("hunt") or {}
        if hunt.get("stop") == "transport_error" or hunt.get("error") == "LLMUnavailableError":
            return True
        if hunt.get("outage_waits") and hunt.get("stop") != "finished":
            return True                      # the cap fired while units waited out an outage
        if any(u.get("stop") == "transport_error" for u in hunt.get("units") or []):
            return True
    return False


def _wait_for_endpoint(limit: int, every: int = 60) -> bool:
    """Block until FRAME_LLM_BASE_URL answers anything at all (any HTTP status counts: the
    network is back), checking every `every` seconds for up to `limit` seconds."""
    import urllib.error
    import urllib.request
    base = os.environ.get("FRAME_LLM_BASE_URL", "").rstrip("/")
    if not base:
        return True
    deadline = time.time() + max(0, limit)
    while True:
        try:
            urllib.request.urlopen(f"{base}/models", timeout=20).close()
            return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError, ValueError):
            pass
        if time.time() >= deadline:
            return False
        time.sleep(min(every, max(1, deadline - time.time())))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--systems", default="frame_symbolic")
    ap.add_argument("--only", default="")
    ap.add_argument("--output", default=str(HERE / "results" / "v1"))
    ap.add_argument("--per-case-timeout", type=int, default=0,
                    help="wall-clock cap (seconds) per checkout scan; 0 (the default) = no cap. The "
                         "hunt is bounded by its step budgets, not by time: a cap that fires during a "
                         "large app's engine pre-scan leaves its agents no time at all (v11's pretix "
                         "spent its whole hour pre-scanning and never hunted). On a cap the hunt "
                         "salvages the findings it reported incrementally")
    ap.add_argument("--save-trajectories", action="store_true",
                    help="save each hunt's HF Session-Trace + per-call timing under <output>/"
                         "<system>/traj/<case>/<checkout>/ (frame_hunt only)")
    ap.add_argument("--resume", action="store_true",
                    help="skip cases whose result file already exists (resume an interrupted run); "
                         "a result an LLM outage damaged is rerun")
    ap.add_argument("--retry-outages", type=int, default=0,
                    help="frame_hunt: after the pass, rerun cases that lost units to an unreachable "
                         "endpoint, up to N more times, each once the endpoint answers again (with "
                         "--hunt-verdict-cache only the lost units do new work)")
    ap.add_argument("--outage-probe-wait", type=int, default=6 * 3600,
                    help="--retry-outages: longest wait (seconds) for the endpoint to come back "
                         "before a retry pass")
    ap.add_argument("--hunt-dynamic", action="store_true",
                    help="frame_hunt: give the agent run_code to CONFIRM a candidate flaw by "
                         "exercising the app (sandboxed Python probe). Off by default.")
    ap.add_argument("--hunt-interpreter", default="",
                    help="frame_hunt --hunt-dynamic: path to the app's virtualenv python so the "
                         "probe can import the application (default: this interpreter).")
    ap.add_argument("--hunt-grep-mode", action="store_true",
                    help="frame_hunt: skip the engine pre-scan; the agent greps/reads the repo "
                         "itself (fast on large monorepos; findings are llm_detect, no engine tier)")
    ap.add_argument("--hunt-cross-file", action="store_true",
                    help="frame_hunt: build the engine pre-scan CROSS-FILE, so the handler "
                         "facts the agent reasons over span files (an authorization gate in one "
                         "module reached from a data handler in another becomes a lead). Slower "
                         "pre-scan; the scanner still falls back to per-file above its "
                         "cross-file limit. Off by default, so the hunt numbers are unchanged.")
    ap.add_argument("--hunt-max-units", type=int, default=None,
                    help="frame_hunt: most investigation units (route groups) to give an agent "
                         "(default: the scanner's)")
    ap.add_argument("--hunt-unit-steps", type=int, default=None,
                    help="frame_hunt: step budget of each unit's agent (default: the scanner's)")
    ap.add_argument("--hunt-concurrency", type=int, default=None,
                    help="frame_hunt: unit agents run at once (default: the scanner's)")
    ap.add_argument("--hunt-verdict-cache", action="store_true",
                    help="frame_hunt: keep each unit's verdict in <output>/frame_hunt/cache/<case>.json "
                         "and reuse it on the fixed commit when the unit's files are unchanged")
    ap.add_argument("--frame-config", default=None, metavar="PATH",
                    help="a .frame.toml whose [llm] / [hunt] settings the hunt uses (e.g. "
                         "llm.outage_wait for a long unattended run); FRAME_LLM_* still name the endpoint")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.frame_config:
        from frame import config as frame_config
        from frame.sil.suppressions import load_config_file
        loaded = load_config_file(Path(args.frame_config))
        frame_config.activate(loaded.settings if loaded else None)

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
    pending = [(system, c) for system in systems for c in cases]
    for attempt in range(max(0, args.retry_outages) + 1):
        if attempt:
            print(f"[run] outage retry {attempt}/{args.retry_outages}: {len(pending)} case(s) "
                  "lost units to an unreachable endpoint", flush=True)
            if not _wait_for_endpoint(args.outage_probe_wait):
                print("[run] endpoint still unreachable; giving up on the retries", flush=True)
                break
        redo = []
        for system, c in pending:
            outdir = out_root / system
            outdir.mkdir(parents=True, exist_ok=True)
            outfile = outdir / f"{c['id']}.json"
            if args.resume and attempt == 0 and outfile.is_file():
                if not outage_damaged(_read_json(outfile)):
                    print(f"[run] {system} / {c['id']}: resume -> skip (result exists)", flush=True)
                    continue
                print(f"[run] {system} / {c['id']}: resume -> rerun (outage damage)", flush=True)
            rec = _run_case(args, system, c, outdir, out_root)
            outfile.write_text(json.dumps(rec, indent=2))
            if outage_damaged(rec):
                redo.append((system, c))
        pending = redo
        if not pending:
            break
    for system, c in pending:
        print(f"[run] {system} / {c['id']}: still has units lost to an outage", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
