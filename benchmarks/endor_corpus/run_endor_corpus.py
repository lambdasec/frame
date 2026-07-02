#!/usr/bin/env python3
"""Run Frame over the Endor Labs AI-SAST public corpus.

This is an *evaluation harness*, NOT a reproduction of Endor's benchmark. See
README.md and summarize.py:ENDOR_WARNING.

Usage:
    # Clone/update repos and record the commit SHAs we scanned (writes lock file):
    python -m benchmarks.endor_corpus.run_endor_corpus \
        --workspace /tmp/endor-corpus \
        --output /tmp/frame-endor-results \
        --lock

    # Re-run against the exact pinned commits from corpus.lock.json:
    python -m benchmarks.endor_corpus.run_endor_corpus \
        --workspace /tmp/endor-corpus \
        --output /tmp/frame-endor-results \
        --use-lock

Everything runs against real cloned repositories and real Frame scanner output.
There are no mock modes, fake labels, or simulated findings.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from benchmarks.endor_corpus import summarize as S

HERE = Path(__file__).resolve().parent
CORPUS_YAML = HERE / "corpus.yaml"
LOCK_FILE = HERE / "corpus.lock.json"

# Directories never worth scanning (vendored deps, build output, VCS).
EXCLUDE_DIRS = {
    ".git", "node_modules", "dist", "build", "target", "out", "bin", "obj",
    "vendor", ".venv", "venv", "env", "__pycache__", ".gradle", ".mvn",
    "coverage", ".next", ".nuxt", ".cache", "site-packages", "test-results",
    # third-party / vendored JS that is not the app's own code
    "external", "third_party", "third-party", "bower_components", "jspm_packages",
}

# Generated / minified / bundled assets: not human-authored source, and a major
# source of false positives for pattern-based checks. Excluded from scanning.
GENERATED_RE = re.compile(r"(\.min\.(js|css|mjs)|\.bundle\.js|-min\.js|\.map)$", re.I)

# Test code and *fixed*-example fixtures are not production attack surface, so
# "vulnerabilities" there (hardcoded creds in fixtures, weak crypto in test setup,
# the corrected version of a challenge) are false positives -- every SAST tool
# excludes them. NB: only the `_correct` fixtures are excluded, NOT the plain
# vulnerable challenge snippets (e.g. juice-shop data/static/codefixes/*_1.ts),
# which are real vulnerabilities in the ground truth.
TEST_PATH_RE = re.compile(
    r"(^|/)(test|tests|__tests__)/"
    r"|/src/test/"
    r"|(Test|Tests|IntegrationTest)\.java$"
    r"|\.(test|spec)\.[jt]sx?$|\.unit\.test\.[jt]sx?$"
    r"|_correct\.[jt]s$",
    re.I)


def is_generated(path: str) -> bool:
    """True for minified/bundled/generated assets (by filename)."""
    return bool(GENERATED_RE.search(str(path)))


def is_test_file(rel_path: str) -> bool:
    """True for test code / fixed-example fixtures (not production attack surface)."""
    return bool(TEST_PATH_RE.search(str(rel_path).replace("\\", "/")))


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #

def log(msg: str) -> None:
    print(f"[endor-corpus] {msg}", flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(cmd: List[str], cwd: Optional[Path] = None, timeout: Optional[int] = None
        ) -> subprocess.CompletedProcess:
    """Run a subprocess, capturing output, never raising on non-zero exit."""
    return subprocess.run(
        cmd, cwd=str(cwd) if cwd else None, check=False,
        capture_output=True, text=True, timeout=timeout,
    )


def load_corpus() -> List[Dict[str, Any]]:
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required. Install with: pip install pyyaml")
    data = yaml.safe_load(CORPUS_YAML.read_text(encoding="utf-8"))
    repos = data.get("repos", [])
    if not repos:
        sys.exit(f"No repos found in {CORPUS_YAML}")
    return repos


def patterns_to_extensions(patterns: List[str]) -> set:
    """Translate glob patterns like '**/*.js' into a set of extensions {'.js'}."""
    exts = set()
    for p in patterns or []:
        suffix = Path(p).suffix
        if suffix:
            exts.add(suffix.lower())
    return exts


# --------------------------------------------------------------------------- #
# Git
# --------------------------------------------------------------------------- #

def clone_or_update(url: str, dest: Path, checkout: Optional[str]
                    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """Clone (full history) or update a repo, optionally checking out a ref.

    Returns (ok, message, commit_sha, branch).
    """
    if (dest / ".git").exists():
        log(f"  updating existing clone: {dest}")
        r = run(["git", "fetch", "--all", "--tags", "--force"], cwd=dest)
        if r.returncode != 0:
            return False, f"git fetch failed: {r.stderr.strip()}", None, None
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        log(f"  cloning {url} -> {dest}")
        r = run(["git", "clone", url, str(dest)])
        if r.returncode != 0:
            return False, f"git clone failed: {r.stderr.strip()}", None, None

    if checkout:
        log(f"  checking out pinned ref {checkout[:12]}")
        r = run(["git", "checkout", "--force", checkout], cwd=dest)
        if r.returncode != 0:
            # Maybe the commit is not present locally; try fetching it directly.
            run(["git", "fetch", "origin", checkout], cwd=dest)
            r = run(["git", "checkout", "--force", checkout], cwd=dest)
            if r.returncode != 0:
                return False, f"git checkout {checkout} failed: {r.stderr.strip()}", None, None

    sha = run(["git", "rev-parse", "HEAD"], cwd=dest)
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=dest)
    commit = sha.stdout.strip() if sha.returncode == 0 else None
    br = branch.stdout.strip() if branch.returncode == 0 else None
    if not commit:
        return False, "could not resolve HEAD commit", None, None
    return True, "ok", commit, br


# --------------------------------------------------------------------------- #
# File collection and counting
# --------------------------------------------------------------------------- #

def collect_files(repo_dir: Path) -> List[Path]:
    """Walk repo_dir, pruning vendored/build dirs, returning all files."""
    files: List[Path] = []
    for root, dirs, filenames in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for fn in filenames:
            p = Path(root) / fn
            rel = p.relative_to(repo_dir).as_posix()
            if is_generated(fn) or is_test_file(rel):
                continue
            files.append(p)
    return files


def count_files(all_files: List[Path]) -> Dict[str, Any]:
    """Classify every file by extension into supported/unsupported/other."""
    by_ext: Dict[str, int] = {}
    supported_by_lang: Dict[str, int] = {}
    unsupported_by_lang: Dict[str, int] = {}
    other = 0
    unknown = 0
    for f in all_files:
        ext = f.suffix.lower()
        by_ext[ext] = by_ext.get(ext, 0) + 1
        klass = S.classify_extension(ext)
        if klass == "supported":
            lang = S.SUPPORTED_EXT[ext]
            supported_by_lang[lang] = supported_by_lang.get(lang, 0) + 1
        elif klass == "unsupported":
            lang = S.UNSUPPORTED_CODE_EXT[ext]
            unsupported_by_lang[lang] = unsupported_by_lang.get(lang, 0) + 1
        elif klass == "other":
            other += 1
        else:
            unknown += 1
    return {
        "by_extension": dict(sorted(by_ext.items(), key=lambda kv: -kv[1])),
        "supported_by_language": supported_by_lang,
        "unsupported_by_language": unsupported_by_lang,
        "supported_total": sum(supported_by_lang.values()),
        "unsupported_total": sum(unsupported_by_lang.values()),
        "other_total": other,
        "unknown_total": unknown,
        "files_total": len(all_files),
    }


# --------------------------------------------------------------------------- #
# Frame scanning
# --------------------------------------------------------------------------- #

def scan_repo(
    repo: Dict[str, Any],
    repo_dir: Path,
    commit: str,
    all_files: List[Path],
    verify: bool,
    timeout_ms: int,
    max_files: Optional[int],
) -> Tuple[List[Any], List[Dict[str, Any]], List[Dict[str, Any]], int, Optional[str]]:
    """Run Frame over the supported files of a repo.

    Returns (scan_results, normalized_findings, scanner_errors, files_scanned,
    dropped_note).
    """
    from frame.sil import FrameScanner

    allowed_exts = patterns_to_extensions(repo.get("supported_patterns", []))
    selected = sorted(
        (f for f in all_files if f.suffix.lower() in allowed_exts),
        key=lambda p: (p.suffix.lower(), str(p)),
    )

    dropped_note = None
    if max_files is not None and len(selected) > max_files:
        dropped_note = (f"COVERAGE LIMITED: scanned {max_files} of {len(selected)} "
                        f"supported files due to --max-files-per-repo")
        log(f"  {dropped_note}")
        selected = selected[:max_files]

    scan_results: List[Any] = []
    scanner_errors: List[Dict[str, Any]] = []

    scanner = FrameScanner(language="python", verify=verify, timeout=timeout_ms)
    total = len(selected)
    for i, fpath in enumerate(selected, 1):
        if i % 50 == 0 or i == total:
            log(f"  scanned {i}/{total} files")
        try:
            result = scanner.scan_file(str(fpath))
        except Exception as exc:  # a real scanner crash on this file
            scanner_errors.append({
                "repo": repo["name"],
                "path": _rel(fpath, repo_dir),
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue
        scan_results.append(result)

    # Build normalized findings in the SAME order the combined SARIF uses, so
    # sarif_result_index aligns with the combined SARIF results array.
    normalized: List[Dict[str, Any]] = []
    idx = 0
    for result in scan_results:
        rel = _rel(Path(result.filename), repo_dir)
        for vuln in result.vulnerabilities:
            normalized.append({
                "repo": repo["name"],
                "commit": commit,
                "tool": "frame",
                "rule_id": f"frame/{vuln.type.value}",
                "cwe": vuln.cwe_id,
                "severity": vuln.severity.value,
                "message": vuln.description,
                "path": rel,
                "line": vuln.line,
                "sarif_result_index": idx,
            })
            idx += 1

    return scan_results, normalized, scanner_errors, len(scan_results), dropped_note


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def write_repo_sarif(scan_results: List[Any], out_path: Path) -> None:
    from frame.sil.cli import format_sarif_result
    if scan_results:
        out_path.write_text(format_sarif_result(scan_results), encoding="utf-8")
    else:
        # Valid empty SARIF run so downstream tooling still parses it.
        empty = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                       "master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Frame Security Scanner",
                                          "version": "0.1.0", "rules": []}},
                      "results": []}],
        }
        out_path.write_text(json.dumps(empty, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Semgrep baseline (optional)
# --------------------------------------------------------------------------- #

def run_semgrep(repo_dir: Path, allowed_exts: set, config: str,
                out_dir: Path, repo_name: str, commit: str) -> Optional[Dict[str, Any]]:
    """Run Semgrep over the supported file portions. Returns a status dict."""
    sarif_path = out_dir / "semgrep.sarif"
    json_path = out_dir / "semgrep.json"
    includes: List[str] = []
    for ext in sorted(allowed_exts):
        includes += ["--include", f"*{ext}"]
    excludes: List[str] = []
    for d in ("node_modules", "dist", "build", "target"):
        excludes += ["--exclude", d]

    cmd = (["semgrep", "--config", config, "--sarif", "--output", str(sarif_path),
            "--quiet", "--metrics=off", "--error"] + includes + excludes + [str(repo_dir)])
    # --error makes semgrep exit non-zero on findings; we treat that as success.
    log(f"  running semgrep ({config}) ...")
    r = run(cmd, timeout=3600)
    status: Dict[str, Any] = {"config": config, "returncode": r.returncode}
    if not sarif_path.exists():
        status["error"] = f"semgrep produced no SARIF: {r.stderr.strip()[:400]}"
        return status

    # Normalize semgrep SARIF into the same finding shape as frame.json.
    findings = _parse_semgrep_sarif(sarif_path, repo_name, commit, repo_dir)
    json_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    status["findings"] = len(findings)
    return status


def _parse_semgrep_sarif(sarif_path: Path, repo: str, commit: str,
                         repo_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    out: List[Dict[str, Any]] = []
    idx = 0
    for runobj in data.get("runs", []):
        # Build ruleId -> CWE from taxa / rule tags if present.
        rule_cwe: Dict[str, str] = {}
        driver = (runobj.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules", []):
            tags = ((rule.get("properties") or {}).get("tags") or [])
            for t in tags:
                if isinstance(t, str) and t.upper().startswith("CWE-"):
                    rule_cwe[rule.get("id")] = t.upper().split(":")[0].strip()
                    break
        for res in runobj.get("results", []):
            rid = res.get("ruleId")
            locs = res.get("locations") or []
            path = line = None
            if locs:
                phys = locs[0].get("physicalLocation") or {}
                path = (phys.get("artifactLocation") or {}).get("uri")
                line = (phys.get("region") or {}).get("startLine")
            if path and repo_dir is not None:
                path = _rel(Path(path), repo_dir)
            out.append({
                "repo": repo, "commit": commit, "tool": "semgrep",
                "rule_id": rid, "cwe": rule_cwe.get(rid),
                "severity": S.level_to_severity(res.get("level")),
                "message": ((res.get("message") or {}).get("text") or "").strip(),
                "path": path, "line": line, "sarif_result_index": idx,
            })
            idx += 1
    return out


# --------------------------------------------------------------------------- #
# Lock file
# --------------------------------------------------------------------------- #

def write_lock(entries: List[Dict[str, Any]]) -> None:
    # Merge into any existing lock so a `--repos` subset run does not clobber
    # entries for repos it did not touch this time.
    existing: Dict[str, Any] = {}
    if LOCK_FILE.exists():
        try:
            existing = (json.loads(LOCK_FILE.read_text(encoding="utf-8")) or {}).get("repos", {})
        except (json.JSONDecodeError, OSError):
            existing = {}
    repos = dict(existing)
    for e in entries:
        if e.get("commit"):
            repos[e["name"]] = {"url": e["url"], "commit": e["commit"],
                                "branch": e.get("branch")}
    lock = {
        "generated_at": now_iso(),
        "note": ("Commit SHAs of the corpus repos as cloned/checked out by this "
                 "harness. These are NOT Endor's commits (Endor did not publish them)."),
        "repos": repos,
    }
    LOCK_FILE.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    log(f"wrote lock file: {LOCK_FILE}")


def load_lock() -> Dict[str, Any]:
    if not LOCK_FILE.exists():
        sys.exit(f"--use-lock requested but no lock file exists at {LOCK_FILE}. "
                 f"Run once with --lock first.")
    return json.loads(LOCK_FILE.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_endor_corpus",
        description="Run Frame over the Endor Labs AI-SAST public corpus "
                    "(evaluation harness, not a reproduction of Endor's benchmark).",
    )
    p.add_argument("--workspace", required=True, type=Path,
                   help="Directory to clone/update the corpus repos into.")
    p.add_argument("--output", required=True, type=Path,
                   help="Directory for results (per-repo SARIF/JSON + summary).")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--lock", action="store_true",
                      help="Clone/update repos and record current commit SHAs to corpus.lock.json.")
    mode.add_argument("--use-lock", action="store_true",
                      help="Checkout the exact SHAs recorded in corpus.lock.json.")
    p.add_argument("--repos", default=None,
                   help="Comma-separated repo slugs to restrict the run (default: all).")
    p.add_argument("--max-files-per-repo", type=int, default=None,
                   help="Cap supported files scanned per repo (reduces coverage; logged).")
    p.add_argument("--no-verify", action="store_true",
                   help="Disable Frame's Z3 verification (faster, more false positives).")
    p.add_argument("--timeout", type=int, default=5000,
                   help="Frame per-check verification timeout in ms (default: 5000).")
    p.add_argument("--continue-on-error", action="store_true",
                   help="Do not exit non-zero when a repo fails to clone or a file crashes.")
    p.add_argument("--with-semgrep", action="store_true",
                   help="Also run Semgrep as a public baseline (must be installed).")
    p.add_argument("--semgrep-config", default="p/default",
                   help="Semgrep ruleset for the baseline (default: p/default).")
    p.add_argument("--ground-truth", type=Path, default=None,
                   help="Path to a REAL ground-truth labels JSON to compute precision/recall/F1.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    # Fail fast if semgrep requested but unavailable.
    if args.with_semgrep and shutil.which("semgrep") is None:
        log("ERROR: --with-semgrep requested but 'semgrep' is not installed.")
        log("Install it with:  pip install semgrep   (or: brew install semgrep)")
        return 2

    corpus = load_corpus()
    if args.repos:
        wanted = {s.strip() for s in args.repos.split(",") if s.strip()}
        corpus = [r for r in corpus if r["name"] in wanted]
        if not corpus:
            log(f"ERROR: no corpus repos matched --repos={args.repos}")
            return 2

    lock_data = load_lock() if args.use_lock else None

    args.workspace.mkdir(parents=True, exist_ok=True)
    results_dir = args.output / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    run_meta = {
        "started_at": now_iso(),
        "mode": "use-lock" if args.use_lock else ("lock" if args.lock else "unpinned"),
        "verify": not args.no_verify,
        "timeout_ms": args.timeout,
        "workspace": str(args.workspace),
        "output": str(args.output),
    }

    repo_reports: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []
    all_scanner_errors: List[Dict[str, Any]] = []
    lock_entries: List[Dict[str, Any]] = []
    hard_failure = False

    for repo in corpus:
        name = repo["name"]
        url = repo["url"]
        log(f"=== {name} ({repo.get('display_name', name)}) ===")

        # Determine the ref to check out.
        checkout = repo.get("checkout")
        if args.use_lock:
            locked = (lock_data.get("repos") or {}).get(name)
            if not locked:
                msg = f"repo '{name}' missing from lock file"
                log(f"  ERROR: {msg}")
                repo_reports.append(_failed_report(repo, msg))
                hard_failure = True
                if args.continue_on_error:
                    continue
                break
            checkout = locked["commit"]

        repo_dir = args.workspace / name
        started = time.time()
        ok, msg, commit, branch = clone_or_update(url, repo_dir, checkout)
        if not ok:
            log(f"  ERROR: {msg}")
            repo_reports.append(_failed_report(repo, msg))
            hard_failure = True
            if args.continue_on_error:
                continue
            break

        lock_entries.append({"name": name, "url": url, "commit": commit, "branch": branch})

        # Count files (whole repo minus vendored dirs).
        all_files = collect_files(repo_dir)
        file_counts = count_files(all_files)
        log(f"  files: {file_counts['files_total']} total, "
            f"{file_counts['supported_total']} supported, "
            f"{file_counts['unsupported_total']} unsupported "
            f"({file_counts['unsupported_by_language']})")

        repo_out = results_dir / name
        repo_out.mkdir(parents=True, exist_ok=True)

        # Scan supported portions with Frame.
        scan_results, normalized, scanner_errors, files_scanned, dropped = scan_repo(
            repo, repo_dir, commit, all_files,
            verify=not args.no_verify, timeout_ms=args.timeout,
            max_files=args.max_files_per_repo,
        )
        all_findings.extend(normalized)
        all_scanner_errors.extend(scanner_errors)
        if scanner_errors and not args.continue_on_error:
            hard_failure = True

        # Write per-repo artifacts.
        write_repo_sarif(scan_results, repo_out / "frame.sarif")
        (repo_out / "frame.json").write_text(json.dumps(normalized, indent=2), encoding="utf-8")

        finished = time.time()
        semgrep_status = None
        if args.with_semgrep:
            allowed = patterns_to_extensions(repo.get("supported_patterns", []))
            if allowed:
                semgrep_status = run_semgrep(repo_dir, allowed, args.semgrep_config,
                                             repo_out, name, commit)
            else:
                semgrep_status = {"skipped": "no supported patterns for this repo"}

        metadata = {
            "repo": name,
            "display_name": repo.get("display_name", name),
            "url": url,
            "commit": commit,
            "branch": branch,
            "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
            "finished_at": datetime.fromtimestamp(finished, timezone.utc).isoformat(),
            "duration_seconds": round(finished - started, 2),
            "supported_patterns": repo.get("supported_patterns", []),
            "unsupported_languages": sorted(file_counts["unsupported_by_language"].keys()),
            "files_scanned": files_scanned,
            "file_counts": file_counts,
            "findings": len(normalized),
            "scanner_exit_code": 1 if scanner_errors else 0,
            "scanner_errors": scanner_errors,
            "coverage_note": dropped,
            "semgrep": semgrep_status,
        }
        (repo_out / "scan_metadata.json").write_text(json.dumps(metadata, indent=2),
                                                     encoding="utf-8")

        repo_reports.append({
            "repo": name,
            "display_name": repo.get("display_name", name),
            "url": url,
            "commit": commit,
            "branch": branch,
            "cloned": True,
            "skipped": False,
            "files_scanned": files_scanned,
            "file_counts": file_counts,
            "findings": len(normalized),
            "coverage_note": dropped,
            "semgrep": semgrep_status,
            "notes": repo.get("notes", "").strip(),
        })
        log(f"  done: {len(normalized)} findings, {files_scanned} files scanned, "
            f"{round(finished - started, 1)}s")

    # Record the lock file (only in --lock mode, only from real checkouts).
    if args.lock and lock_entries:
        write_lock(lock_entries)

    run_meta["finished_at"] = now_iso()
    if args.with_semgrep:
        run_meta["semgrep"] = args.semgrep_config

    # Ground-truth metrics ONLY when a real file is supplied.
    gt_metrics = None
    if args.ground_truth:
        if not args.ground_truth.exists():
            log(f"ERROR: --ground-truth file not found: {args.ground_truth}")
            return 2
        gt = json.loads(args.ground_truth.read_text(encoding="utf-8"))
        gt = [g for g in gt if isinstance(g, dict) and "_comment" not in g]
        gt_metrics = S.compute_ground_truth_metrics(all_findings, gt)
        log(f"ground-truth metrics: precision={gt_metrics['precision']} "
            f"recall={gt_metrics['recall']} f1={gt_metrics['f1']}")

    # Write combined findings + summary.
    (results_dir / "findings.json").write_text(json.dumps(all_findings, indent=2), encoding="utf-8")
    summary = S.build_summary(repo_reports, all_findings, run_meta,
                              all_scanner_errors, gt_metrics)
    (results_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (results_dir / "summary.md").write_text(S.render_summary_md(summary), encoding="utf-8")
    log(f"wrote summary: {results_dir / 'summary.md'}")
    log(f"TOTAL findings: {len(all_findings)} across {len(repo_reports)} repos")

    if hard_failure and not args.continue_on_error:
        log("Exiting non-zero: one or more repos failed to clone or crashed the scanner "
            "(pass --continue-on-error to override).")
        return 1
    return 0


def _failed_report(repo: Dict[str, Any], msg: str) -> Dict[str, Any]:
    return {
        "repo": repo["name"],
        "display_name": repo.get("display_name", repo["name"]),
        "url": repo["url"],
        "commit": None,
        "cloned": False,
        "skipped": False,
        "error": msg,
        "file_counts": {},
        "files_scanned": 0,
        "findings": 0,
    }


if __name__ == "__main__":
    sys.exit(main())
