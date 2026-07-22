#!/usr/bin/env python3
"""Run Frame over VLoc Bench, driving the `frame` CLI directly (no Python API)
so it exercises exactly what a user runs.

Per task and phase: extract the snapshot, scan it with `frame scan --ai`, keep
the findings whose CWE matches the task's target CWE, and emit a ranked file
list in the shape Cisco's scorer consumes. The snapshot is deleted immediately
after the scan, so peak disk stays small even across the full 500-task set.

    python benchmarks/vloc/run.py --workspace /tmp/frame-vloc --out /tmp/vloc-results

Needs an LLM endpoint via FRAME_LLM_* (we use GLM-5.2, z-ai/glm-5.2, over an
OpenAI-compatible API) because Go, Rust and PHP have no symbolic frontend.

METHODOLOGY NOTE: Frame is a scanner, not a 15-terminal-call agent. It performs
an unbudgeted static scan of the whole snapshot. That is a real asymmetry versus
the leaderboard's reference agent and it is disclosed in README.md and in the
emitted results. Do not present these numbers as a like-for-like agent result.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.vloc.prepare import ECOSYSTEMS  # noqa: E402

# Extensions Cisco's scorer counts as code; predictions outside this set are
# dropped by their filter anyway, so we never submit them.
CODE_EXTS = {'.go', '.java', '.py', '.js', '.ts', '.jsx', '.tsx', '.rs', '.rb',
             '.php', '.c', '.cpp', '.h', '.hpp', '.cs', '.scala', '.kt', '.swift'}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def extract(zip_path: Path, dest: Path) -> bool:
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(dest)
        return True
    except Exception as e:
        print(f"    extract failed: {e}", file=sys.stderr)
        return False


def frame_scan(repo: Path, language: str, patterns: list, use_ai: bool,
               timeout: int, repo_scale: bool = False) -> tuple:
    """Run `frame scan` once per glob. Returns (findings, errors)."""
    findings, errors = [], []
    for pat in patterns:
        out = repo.parent / "frame_out.json"
        cmd = [sys.executable, "-m", "frame.sil.cli", "scan", str(repo),
               "-l", language, "-p", pat, "-f", "json", "-o", str(out)]
        if use_ai:
            cmd.append("--ai")
        if repo_scale:
            # One LLM session for the whole repository instead of one per file.
            # Per-file costs ~40 sessions on a typical project here, which is the
            # difference between minutes and days across 500 tasks.
            cmd.append("--repo-scale")
        try:
            r = subprocess.run(cmd, cwd=repo, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            errors.append(f"timeout on {pat}")
            print(f"    TIMEOUT on {pat}", file=sys.stderr)
            continue
        if not out.is_file():
            # Surface the failure rather than silently scoring it as "no findings" --
            # a missing tree-sitter pack looks identical to a clean repo otherwise.
            msg = (r.stderr or "").strip().splitlines()
            msg = msg[0] if msg else f"no output for {pat}"
            errors.append(msg)
            print(f"    SCAN FAILED ({pat}): {msg}", file=sys.stderr)
            continue
        try:
            data = json.loads(out.read_text())
        except Exception:
            continue
        finally:
            out.unlink(missing_ok=True)
        # `frame scan -f json` over a directory emits {"files": [{... "vulnerabilities": []}],
        # "summary": {...}}; a single-file scan emits the file object directly.
        if isinstance(data, dict) and "files" in data:
            for fr in data["files"]:
                findings.extend(fr.get("vulnerabilities") or [])
        elif isinstance(data, dict):
            findings.extend(data.get("vulnerabilities") or [])
        elif isinstance(data, list):
            for fr in data:
                findings.extend((fr or {}).get("vulnerabilities") or [])
    return findings, errors


def to_prediction(findings: list, repo: Path, target_cwes: set, cwe_any: bool,
                  top_k: int) -> list:
    """Ranked, repo-relative file list for the findings matching the task CWE."""
    scored = {}
    for f in findings:
        cwe = (f.get("cwe_id") or "").strip().upper()
        if not cwe_any and cwe not in target_cwes:
            continue
        raw = f.get("file") or f.get("file_path") or f.get("location") or ""
        if not raw:
            continue
        p = Path(raw)
        try:
            rel = str(p.relative_to(repo)) if p.is_absolute() else str(p)
        except ValueError:
            rel = p.name
        rel = rel.lstrip("./")
        if os.path.splitext(rel)[1].lower() not in CODE_EXTS:
            continue
        rank = SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 5)
        if rel not in scored or rank < scored[rel]:
            scored[rel] = rank
    ordered = sorted(scored, key=lambda r: (scored[r], r))
    return ordered[:top_k] if top_k > 0 else ordered


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--phases", default="ab", help="a, b, or ab")
    ap.add_argument("--only", default="", help="comma-separated alpha_ids")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--top-k", type=int, default=0,
                    help="cap submitted files (0 = no cap); ground truth median is 3")
    ap.add_argument("--cwe-any", action="store_true",
                    help="ignore CWE matching (recall upper bound, not a headline number)")
    ap.add_argument("--no-ai", action="store_true", help="symbolic core only")
    ap.add_argument("--repo-scale", action="store_true",
                    help="one LLM session per repository instead of one per file")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    bench = ws / "vulnerability-localization-benchmark"
    zips = bench / "data" / "ghsa-vulns"
    if not zips.is_dir():
        print("run prepare.py first", file=sys.stderr)
        return 1
    if not args.no_ai and not os.environ.get("FRAME_LLM_BASE_URL"):
        print("set FRAME_LLM_* (GLM-5.2 endpoint) or pass --no-ai", file=sys.stderr)
        return 1

    import csv
    manifest = ws / "manifest_subset.csv"
    if not manifest.is_file():
        manifest = bench / "data" / "manifest.csv"
    rows = list(csv.DictReader(manifest.open()))
    if args.only:
        want = {s.strip() for s in args.only.split(",")}
        rows = [r for r in rows if r["alpha_id"] in want]
    if args.limit:
        rows = rows[:args.limit]

    outdir = Path(args.out).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    work = ws / "_work"
    work.mkdir(parents=True, exist_ok=True)

    for i, row in enumerate(rows, 1):
        aid, eco = row["alpha_id"], row["ecosystem"]
        language, patterns = ECOSYSTEMS.get(eco, ("python", ["**/*.py"]))
        target = {c.strip().upper() for c in json.loads(row["cwes"] or "[]")}
        for phase in args.phases:
            dest = outdir / f"{aid}_phase_{phase}.json"
            if dest.is_file() and not args.force:
                continue
            zip_path = zips / aid / ("pre_push.zip" if phase == "a" else "post_push.zip")
            if not zip_path.is_file():
                print(f"[{i}/{len(rows)}] {aid} phase {phase}: MISSING snapshot", file=sys.stderr)
                continue
            repo = work / f"{aid}_{phase}"
            if not extract(zip_path, repo):
                continue
            try:
                findings, errors = frame_scan(repo, language, patterns,
                                              use_ai=not args.no_ai, timeout=args.timeout,
                                              repo_scale=args.repo_scale)
                files = to_prediction(findings, repo, target, args.cwe_any, args.top_k)
            finally:
                shutil.rmtree(repo, ignore_errors=True)   # keep peak disk small

            dest.write_text(json.dumps({
                "alpha_id": aid, "phase": phase, "ecosystem": eco,
                "language": language, "target_cwes": sorted(target),
                "submitted_files": files,
                "submitted_nothing": len(files) == 0,
                "n_raw_findings": len(findings),
                "scan_errors": errors,
            }, indent=2))
            print(f"[{i}/{len(rows)}] {aid} phase {phase} ({eco}): "
                  f"{len(findings)} findings -> {len(files)} files", flush=True)

    shutil.rmtree(work, ignore_errors=True)
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
