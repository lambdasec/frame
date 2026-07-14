#!/usr/bin/env python3
"""Run the RealVuln authz study by driving Frame directly (no bespoke analysis).

Two systems, both real `frame` invocations via the FrameScanner API:
  frame_authz_symbolic  - FrameScanner(verify=True): sound taint-based IDOR candidates
  frame_glm52_authz     - FrameScanner(llm_detect=True, llm_triage=True): symbolic
                          candidates + GLM adjudication (the LLM decides ownership).

Usage:
  python benchmarks/realvuln_authz/run.py --workspace /tmp/frame-realvuln-authz \\
    --systems frame_authz_symbolic,frame_glm52_authz --runs 3 \\
    --output benchmarks/realvuln_authz/results/v1
  python benchmarks/realvuln_authz/run.py --workspace ... --dry-run
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.yaml"
PROMPTS = HERE / "prompts"

SYSTEMS = ("frame_authz_symbolic", "frame_glm52_authz")
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "tests",
              "test", "migrations", "site-packages", "dist", "build", ".tox"}


def _frame_commit() -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


def _prompt_hashes() -> dict:
    out = {}
    for p in sorted(PROMPTS.glob("*.md")):
        out[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _py_files(root: Path):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _SKIP_DIRS]
        for fn in fns:
            if fn.endswith(".py"):
                yield Path(dp) / fn


def _idor_findings(result, root: Path, fpath: Path):
    """Extract authz/IDOR findings (CWE-639 / VulnType.idor) as normalized dicts."""
    out = []
    for v in result.vulnerabilities:
        cwe = (v.cwe_id or "")
        if v.type.value != "idor" and cwe != "CWE-639":
            continue
        out.append({
            "repository": root.name,
            "file": str(fpath.relative_to(root)),
            "start_line": v.line, "end_line": v.line,
            "cwe": cwe or "CWE-639",
            "handler": v.procedure, "object_identifier": v.source_var,
            "resource_operation": v.sink_type, "confidence": v.confidence,
            "provenance": ("llm_verified" if v.source_var in ("llm_detect", "llm_verified")
                           else "symbolic"),
            "description": v.description,
        })
    return out


def _scan_repo(repo_path: Path, system: str):
    """Scan every app .py file; return (findings, stats)."""
    from frame.sil import FrameScanner
    llm = system == "frame_glm52_authz"
    findings, files, errors = [], 0, []
    t0 = time.time()
    for fpath in _py_files(repo_path):
        files += 1
        try:
            sc = FrameScanner(language="python", verify=not llm,
                              llm_detect=llm, llm_triage=llm, timeout=8000)
            res = sc.scan_file(str(fpath))
            findings.extend(_idor_findings(res, repo_path, fpath))
        except Exception as e:  # LLMUnavailableError etc. recorded, not swallowed as 0
            errors.append(f"{fpath.name}: {type(e).__name__}: {e}")
    return findings, {"files_scanned": files, "wall_clock_seconds": round(time.time() - t0, 2),
                      "transport_errors": errors}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--systems", default=",".join(SYSTEMS))
    ap.add_argument("--repos", default="")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--output", default=str(HERE / "results" / "v1"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    manifest = yaml.safe_load(MANIFEST.read_text())
    ws = Path(args.workspace).expanduser().resolve()
    systems = [s for s in args.systems.split(",") if s]
    repos = manifest["repositories"]
    if args.repos:
        want = set(args.repos.split(","))
        repos = [r for r in repos if r["slug"] in want]
    # symbolic is deterministic -> 1 run; LLM systems -> args.runs
    def n_runs(system):
        return 1 if system == "frame_authz_symbolic" else args.runs

    if args.dry_run:
        print("=== DRY RUN ===")
        print(f"workspace: {ws}")
        print(f"frame commit: {_frame_commit()}")
        for r in repos:
            print(f"  repo {r['slug']:42s} {r['upstream_repository']}@{r['commit'][:10]} "
                  f"({r['framework']}, {r['role']}, {len(r['cases'])} cases)")
        for s in systems:
            model = os.environ.get("FRAME_LLM_MODEL", "(unset)") if s != "frame_authz_symbolic" else "-"
            print(f"  system {s:22s} runs={n_runs(s)} model={model}")
        print(f"prompt sha256: {json.dumps(_prompt_hashes(), indent=2)}")
        print(f"output: {args.output}")
        print("planned model calls: LLM systems make 1 detect + 1 triage call per "
              "candidate file (bounded by is_detection_candidate); symbolic makes none.")
        return 0

    frame_commit = _frame_commit()
    prompt_sha = _prompt_hashes()
    out_root = Path(args.output)
    for system in systems:
        for repo in repos:
            rp = ws / repo["slug"]
            if not rp.is_dir():
                print(f"[run] MISSING {rp} (run prepare.py first)", file=sys.stderr)
                continue
            for i in range(1, n_runs(system) + 1):
                outdir = out_root / system / repo["slug"]
                outdir.mkdir(parents=True, exist_ok=True)
                outfile = outdir / f"run-{i}.json"
                if outfile.exists() and not args.force:
                    print(f"[run] skip existing {outfile} (use --force)")
                    continue
                print(f"[run] {system} / {repo['slug']} / run-{i} ...", flush=True)
                findings, stats = _scan_repo(rp, system)
                rec = {
                    "system": system, "repository": repo["slug"], "run_index": i,
                    "frame_commit": frame_commit,
                    "realvuln_commit": manifest["realvuln_benchmark"]["commit"],
                    "application_commit": repo["commit"],
                    "model": os.environ.get("FRAME_LLM_MODEL") if system != "frame_authz_symbolic" else None,
                    "endpoint_base_url": os.environ.get("FRAME_LLM_BASE_URL") if system != "frame_authz_symbolic" else None,
                    "temperature": float(os.environ.get("FRAME_LLM_TEMPERATURE", "0")) if system != "frame_authz_symbolic" else None,
                    "prompt_sha256": prompt_sha,
                    "start_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "wall_clock_seconds": stats["wall_clock_seconds"],
                    "files_scanned": stats["files_scanned"],
                    "transport_errors": stats["transport_errors"],
                    "normalized_findings": findings,
                }
                outfile.write_text(json.dumps(rec, indent=2))
                print(f"[run]   {len(findings)} authz findings -> {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
