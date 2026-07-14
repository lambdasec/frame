#!/usr/bin/env python3
"""
Frame CLI - Separation Logic Verification Tool.

A unified command-line interface for Frame's capabilities:
- scan: Scan source code for security vulnerabilities
- solve: Solve separation logic entailments
- check: Check specific entailment queries
- parse: Parse and display formula AST

Usage:
    frame scan app.py                    # Scan for vulnerabilities
    frame solve "x |-> 5 |- x |-> 5"     # Check entailment
    frame check entailments.txt          # Check batch of entailments
    frame parse "x |-> 5 * y |-> 3"      # Parse and display formula
"""

import argparse
import os
import sys
import json
import time
from pathlib import Path
from typing import List, Optional

# Import version from main package (single source of truth)
from frame import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser"""
    parser = argparse.ArgumentParser(
        prog="frame",
        description="Frame - Separation Logic Verification Tool",
        epilog="Use 'frame <command> --help' for more information on a specific command.",
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # === SCAN command ===
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan source code for security vulnerabilities",
        description="Scan source files for vulnerabilities using taint analysis and verification."
    )
    scan_parser.add_argument(
        "target",
        help="File or directory to scan"
    )
    scan_parser.add_argument(
        "-l", "--language",
        default="python",
        choices=["python"],
        help="Source language (default: python)"
    )
    scan_parser.add_argument(
        "-p", "--pattern",
        default="**/*.py",
        help="Glob pattern for directory scan (default: **/*.py)"
    )
    scan_parser.add_argument(
        "-f", "--format",
        default="text",
        choices=["text", "json", "sarif"],
        help="Output format (default: text)"
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)"
    )
    scan_parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip Frame verification (faster, may have false positives)"
    )
    scan_parser.add_argument(
        "--min-severity",
        default="low",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report (default: low)"
    )
    scan_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=5000,
        help="Verification timeout in ms (default: 5000)"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "any", "none"],
        default="high",
        help="Exit with error if vulnerabilities of this severity found (default: high)"
    )
    scan_parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable the AI layer (LLM detection + triage). Needs FRAME_LLM_BASE_URL "
             "and FRAME_LLM_MODEL, e.g. a local mlx-optiq or any OpenAI-compatible endpoint"
    )
    scan_parser.add_argument(
        "--llm-detect",
        action="store_true",
        help="Enable LLM detection only (adds findings the symbolic engine misses)"
    )
    scan_parser.add_argument(
        "--llm-triage",
        action="store_true",
        help="Enable LLM triage only (drops confident false positives)"
    )
    scan_parser.add_argument(
        "--model",
        help="Override FRAME_LLM_MODEL for this scan (same as setting the env var)"
    )

    # === EXPLOIT command ===
    exploit_parser = subparsers.add_parser(
        "exploit",
        help="Drive an LLM agent to exploit a live target (authorized use only)",
        description="Run the neuro-symbolic exploitation agent against a live, in-scope "
                    "target. Optionally prime it with a Frame findings JSON (from "
                    "`frame scan --ai -f json`) so it attacks the localized flaw."
    )
    exploit_parser.add_argument(
        "--target", required=True,
        help="Target under test, e.g. http://app:8080 (must be authorized/in-scope)"
    )
    exploit_parser.add_argument(
        "--goal",
        help="Objective / success condition in words (default: read a secret, run a "
             "command, or modify server state)"
    )
    exploit_parser.add_argument(
        "--guidance",
        help="Frame findings JSON to prime the agent (file path, or '-' for stdin). "
             "Pipe from `frame scan --ai -f json`."
    )
    exploit_parser.add_argument(
        "--success-check",
        help="Shell command re-run after each step; exit 0 means solved (success "
             "oracle). Omit to let the agent self-terminate when it verifies success."
    )
    exploit_parser.add_argument(
        "--max-steps", type=int, default=40,
        help="Maximum agent steps (default: 40)"
    )
    exploit_parser.add_argument(
        "--exec-timeout", type=int, default=120,
        help="Per-command execution timeout in seconds (default: 120)"
    )
    exploit_parser.add_argument(
        "--model",
        help="Override FRAME_LLM_MODEL for this run"
    )
    exploit_parser.add_argument(
        "--format", default="text", choices=["text", "json"],
        help="Output format (default: text)"
    )
    exploit_parser.add_argument(
        "--trace-out",
        help="Write the full agent trace (system prompt, guidance, every tool call "
             "and result) as JSON to this file -- useful for comparing model behavior."
    )

    # === FIX command ===
    fix_parser = subparsers.add_parser(
        "fix",
        help="Generate (and verify) security fixes for scan findings",
        description="Remediate vulnerabilities found by `frame scan`. Generates a "
                    "minimal patch per finding, then VERIFIES it by re-scanning the "
                    "patched code -- Frame confirms the vulnerability is gone."
    )
    fix_parser.add_argument(
        "source", help="Source file or directory the findings refer to"
    )
    fix_parser.add_argument(
        "--guidance", required=True,
        help="Frame findings JSON to fix (file path, or '-' for stdin). Pipe from "
             "`frame scan --ai -f json`."
    )
    fix_parser.add_argument(
        "--in-place", action="store_true",
        help="Write the patches to the files (default: print a unified diff instead)"
    )
    fix_parser.add_argument(
        "--diff", action="store_true",
        help="Print a unified diff of the patches (the default when --in-place is off)"
    )
    fix_parser.add_argument(
        "--no-verify", action="store_true",
        help="Skip re-scanning the patched code to confirm the fix (verify is on by default)"
    )
    fix_parser.add_argument(
        "--model", help="Override FRAME_LLM_MODEL for this run"
    )
    fix_parser.add_argument(
        "--format", default="text", choices=["text", "json"],
        help="Output format (default: text)"
    )

    # === SOLVE command ===
    solve_parser = subparsers.add_parser(
        "solve",
        help="Check separation logic entailments",
        description="Check if a separation logic entailment P |- Q is valid."
    )
    solve_parser.add_argument(
        "entailment",
        nargs="?",
        help="Entailment to check (e.g., 'x |-> 5 |- x |-> 5')"
    )
    solve_parser.add_argument(
        "-f", "--file",
        help="Read entailment from file"
    )
    solve_parser.add_argument(
        "--timeout",
        type=int,
        default=5000,
        help="Solver timeout in ms (default: 5000)"
    )
    solve_parser.add_argument(
        "--unfold-depth",
        type=int,
        default=3,
        help="Maximum predicate unfolding depth (default: 3)"
    )
    solve_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed solving steps"
    )
    solve_parser.add_argument(
        "--format",
        default="text",
        choices=["text", "json"],
        help="Output format (default: text)"
    )
    solve_parser.add_argument(
        "--model",
        action="store_true",
        help="Show countermodel if invalid"
    )

    # === CHECK command ===
    check_parser = subparsers.add_parser(
        "check",
        help="Check batch of entailments from file",
        description="Check multiple entailments from a file (one per line)."
    )
    check_parser.add_argument(
        "file",
        help="File containing entailments (one per line)"
    )
    check_parser.add_argument(
        "--timeout",
        type=int,
        default=5000,
        help="Solver timeout in ms per entailment (default: 5000)"
    )
    check_parser.add_argument(
        "--unfold-depth",
        type=int,
        default=3,
        help="Maximum predicate unfolding depth (default: 3)"
    )
    check_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output for each entailment"
    )
    check_parser.add_argument(
        "--format",
        default="text",
        choices=["text", "json", "csv"],
        help="Output format (default: text)"
    )
    check_parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)"
    )
    check_parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="Stop checking after first invalid entailment"
    )

    # === PARSE command ===
    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse and display formula structure",
        description="Parse a separation logic formula and display its AST."
    )
    parse_parser.add_argument(
        "formula",
        nargs="?",
        help="Formula to parse"
    )
    parse_parser.add_argument(
        "-f", "--file",
        help="Read formula from file"
    )
    parse_parser.add_argument(
        "--format",
        default="tree",
        choices=["tree", "json", "sexp"],
        help="Output format (default: tree)"
    )

    # === REPL command ===
    repl_parser = subparsers.add_parser(
        "repl",
        help="Interactive separation logic REPL",
        description="Start an interactive Read-Eval-Print Loop for separation logic."
    )
    repl_parser.add_argument(
        "--timeout",
        type=int,
        default=5000,
        help="Solver timeout in ms (default: 5000)"
    )

    return parser


# ============================================================================
# SCAN Command
# ============================================================================

def _apply_model_override(args) -> None:
    """`--model` is sugar for FRAME_LLM_MODEL: setting it here means every layer
    (scan/detect/triage/exploit) reading the env picks it up. Flag beats env."""
    if getattr(args, "model", None):
        os.environ["FRAME_LLM_MODEL"] = args.model


def cmd_scan(args) -> int:
    """Execute scan command"""
    _apply_model_override(args)
    # Delegate to the SIL scanner CLI
    from frame.sil.cli import cmd_scan as sil_scan
    return sil_scan(args)


# ============================================================================
# EXPLOIT Command
# ============================================================================

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _load_findings(raw: str) -> List[dict]:
    """Flatten a `frame scan -f json` payload (single file, multi-file, or a bare
    list) into a flat list of finding dicts."""
    data = json.loads(raw)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "vulnerabilities" in data:
            return data["vulnerabilities"] or []
        if "files" in data:
            out: List[dict] = []
            for f in data["files"]:
                out.extend(f.get("vulnerabilities", []) or [])
            return out
    return []


def _top_finding(findings: List[dict]) -> Optional[dict]:
    """Pick the finding most worth exploiting: highest severity, then confidence."""
    if not findings:
        return None

    def _key(f: dict):
        sev = _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0)
        try:
            conf = float(f.get("confidence", 0) or 0)
        except (TypeError, ValueError):
            conf = 0.0
        return (sev, conf)

    return max(findings, key=_key)


def _finding_rank(f: dict):
    sev = _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0)
    try:
        conf = float(f.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        conf = 0.0
    return (sev, conf)


def _select_findings(findings: List[dict], n: int = 6) -> List[dict]:
    """Deduped top-N findings to pass as exploit leads.

    The top-1 is frequently NOT the exploitable bug: findings bunch at the same
    severity/confidence, so ranking barely discriminates and a deserialization
    finding can outrank the actual path traversal. Passing several deduped leads
    (one per distinct cwe+type+file) lets the agent attack the right surface.
    """
    ranked = sorted(findings, key=_finding_rank, reverse=True)
    seen: set = set()
    out: List[dict] = []
    for f in ranked:
        loc = str(f.get("location") or "").rsplit("/", 1)[-1]
        key = (f.get("cwe_id") or f.get("cwe"), f.get("type"), loc)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= n:
            break
    return out


def cmd_exploit(args) -> int:
    """Execute exploit command - run the LLM exploitation agent against a target."""
    import subprocess
    from frame.sil.llm_client import LLMConfig
    from frame.sil.llm_exploit import (
        exploit_agentic, local_exec_tool, guidance_from_finding,
    )

    # LLM config from env (FRAME_LLM_*). --model overrides FRAME_LLM_MODEL, the
    # same single knob every layer reads (flag beats env, uniformly).
    _apply_model_override(args)
    config = LLMConfig.from_env()
    if not config.base_url or not config.model:
        print("Error: set FRAME_LLM_BASE_URL and FRAME_LLM_MODEL (an OpenAI-compatible "
              "endpoint) to use the exploit agent.", file=sys.stderr)
        return 1
    config.exploit_max_steps = args.max_steps

    # Optional guidance: findings JSON (file or '-' stdin) -> top finding -> guidance.
    guidance = None
    if args.guidance:
        try:
            raw = sys.stdin.read() if args.guidance == "-" else Path(args.guidance).read_text()
            findings = _load_findings(raw)
        except Exception as e:
            print(f"Error reading guidance findings: {e}", file=sys.stderr)
            return 1
        selected = _select_findings(findings)
        if selected:
            leads = [guidance_from_finding(f) for f in selected]
            guidance = {
                "leads": leads,
                "provenance": "symbolic" if any(l.get("provenance") == "symbolic"
                                                for l in leads) else "llm",
            }
        else:
            print("Warning: guidance provided but no findings parsed; running unguided.",
                  file=sys.stderr)

    goal = args.goal or ("Compromise the target: read a protected secret, execute a "
                         "command, or modify server state -- and prove it with observed "
                         "output.")
    task_prompt = f"Target: {args.target}\n\nObjective: {goal}"

    # Success oracle: optional shell command, exit 0 == solved.
    is_solved = None
    if args.success_check:
        def is_solved() -> bool:
            try:
                return subprocess.run(args.success_check, shell=True,
                                      timeout=60).returncode == 0
            except Exception:
                return False

    exec_tool = local_exec_tool(timeout=args.exec_timeout)
    result = exploit_agentic(task_prompt, config, exec_tool=exec_tool,
                             guidance=guidance, is_solved=is_solved,
                             max_steps=args.max_steps)

    out = {
        "target": args.target,
        "solved": result.solved,
        "steps": result.steps,
        "reason": result.reason,
        "guided": guidance is not None,
        "provenance": guidance.get("provenance") if guidance else None,
    }
    if getattr(args, "trace_out", None):
        try:
            with open(args.trace_out, "w") as fh:
                json.dump({"model": config.model, "summary": out,
                           "transcript": result.transcript}, fh, indent=2, default=str)
        except Exception as e:
            print(f"Warning: could not write trace to {args.trace_out}: {e}",
                  file=sys.stderr)
    if args.format == "json":
        print(json.dumps(out, indent=2))
    else:
        status = "✓ EXPLOITED" if result.solved else "✗ NOT EXPLOITED"
        print(f"{status}  (steps={result.steps}, reason={result.reason}, "
              f"guided={out['guided']}"
              + (f", lead={out['provenance']}" if guidance else "") + ")")
    return 0 if result.solved else 1


# ============================================================================
# FIX Command
# ============================================================================

_LANG_BY_EXT = {".py": "python", ".js": "javascript", ".jsx": "javascript",
                ".ts": "typescript", ".tsx": "typescript", ".java": "java",
                ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cs": "csharp",
                ".php": "php", ".rb": "ruby", ".go": "go"}


def _lang_for(path: str) -> str:
    return _LANG_BY_EXT.get(os.path.splitext(path)[1].lower(), "python")


def _resolve_finding_file(loc: Optional[str], source: str) -> Optional[str]:
    """Locate a finding's file relative to the user-supplied source path."""
    if loc and os.path.isfile(loc):
        return loc
    if os.path.isfile(source):
        return source
    if loc and os.path.isdir(source):
        cand = os.path.join(source, os.path.basename(loc))
        if os.path.isfile(cand):
            return cand
    return None


def cmd_fix(args) -> int:
    """Execute fix command - generate and verify security patches for findings."""
    from collections import OrderedDict
    from frame.sil.llm_client import LLMConfig
    from frame.sil.llm_fix import generate_fix, apply_fix, make_diff, verify_fixes, FixResult

    _apply_model_override(args)
    config = LLMConfig.from_env()
    if not config.base_url or not config.model:
        print("Error: set FRAME_LLM_BASE_URL and FRAME_LLM_MODEL (an OpenAI-compatible "
              "endpoint) to use fix.", file=sys.stderr)
        return 1
    try:
        raw = sys.stdin.read() if args.guidance == "-" else Path(args.guidance).read_text()
        findings = _load_findings(raw)
    except Exception as e:
        print(f"Error reading findings: {e}", file=sys.stderr)
        return 1
    if not findings:
        print("No findings to fix.", file=sys.stderr)
        return 1

    by_file: "OrderedDict[str, list]" = OrderedDict()
    for f in findings:
        fp = _resolve_finding_file(f.get("location"), args.source)
        if fp is not None:
            by_file.setdefault(fp, []).append(f)
    if not by_file:
        print("Could not locate any finding's file under the given source path.",
              file=sys.stderr)
        return 1

    results: List[FixResult] = []
    for fp, flist in by_file.items():
        try:
            original = Path(fp).read_text()
        except Exception as e:
            print(f"Warning: cannot read {fp}: {e}", file=sys.stderr)
            continue
        patched = original
        lang = _lang_for(fp)
        file_results: List[FixResult] = []
        for f in flist:
            patch = generate_fix(f, patched, config)
            new, applied = apply_fix(patched, patch)
            if applied:
                patched = new
            file_results.append(FixResult(
                file=fp, cwe=str(f.get("cwe_id") or f.get("cwe") or ""),
                line=f.get("line") or 0, applied=applied, verified=None,
                rationale=(patch or {}).get("rationale", ""),
                original=(patch or {}).get("original", ""),
                replacement=(patch or {}).get("replacement", "")))
        # One re-scan verifies every applied finding for this file (not one per finding
        # -- per-finding re-scanning timed out on a file with 13 findings).
        if not args.no_verify and patched != original:
            applied_findings = [flist[i] for i, r in enumerate(file_results) if r.applied]
            verdicts = iter(verify_fixes(patched, lang, os.path.basename(fp),
                                         applied_findings, config))
            for r in file_results:
                if r.applied:
                    r.verified = next(verdicts, None)
        results.extend(file_results)
        if patched != original:
            if args.in_place:
                Path(fp).write_text(patched)
            elif args.format != "json":
                print(make_diff(fp, original, patched))

    applied_n = sum(1 for r in results if r.applied)
    verified_n = sum(1 for r in results if r.verified is True)
    if args.format == "json":
        print(json.dumps([{"file": r.file, "cwe": r.cwe, "line": r.line,
                           "applied": r.applied, "verified": r.verified,
                           "rationale": r.rationale} for r in results], indent=2))
    else:
        for r in results:
            v = ("verified✓" if r.verified is True else
                 "STILL DETECTED" if r.verified is False else "verify-skipped")
            print(f"  {r.cwe} {os.path.basename(r.file)}:{r.line} -> "
                  + (f"patched ({v})" if r.applied else "could not apply"))
        mode = "written in place" if args.in_place else "shown as diff"
        print(f"\n{applied_n}/{len(results)} findings patched ({mode}); "
              f"{verified_n} verified fixed by re-scan.")
    return 0 if applied_n > 0 else 1


# ============================================================================
# SOLVE Command
# ============================================================================

def cmd_solve(args) -> int:
    """Execute solve command - check a single entailment"""
    from frame import EntailmentChecker

    # Get entailment string
    if args.entailment:
        entailment = args.entailment
    elif args.file:
        try:
            entailment = Path(args.file).read_text().strip()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    else:
        print("Error: Provide an entailment string or use -f to read from file", file=sys.stderr)
        return 1

    # Create checker
    checker = EntailmentChecker(timeout=args.timeout)

    if args.verbose:
        print(f"Checking: {entailment}")
        print("-" * 60)

    # Check entailment
    start_time = time.time()
    try:
        result = checker.check_entailment(entailment)
    except Exception as e:
        if args.format == "json":
            print(json.dumps({
                "entailment": entailment,
                "error": str(e),
                "valid": None
            }, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1

    elapsed_ms = (time.time() - start_time) * 1000

    # Output result
    if args.format == "json":
        output = {
            "entailment": entailment,
            "valid": result.valid,
            "reason": result.reason,
            "time_ms": round(elapsed_ms, 2)
        }
        if args.model and not result.valid and result.model:
            output["countermodel"] = str(result.model)
        print(json.dumps(output, indent=2))
    else:
        if result.valid:
            print(f"✓ VALID")
            if args.verbose:
                print(f"  Reason: {result.reason}")
        else:
            print(f"✗ INVALID")
            if result.reason:
                print(f"  Reason: {result.reason}")
            if args.model and result.model:
                print(f"  Countermodel: {result.model}")

        if args.verbose:
            print(f"  Time: {elapsed_ms:.2f}ms")

    return 0 if result.valid else 1


# ============================================================================
# CHECK Command
# ============================================================================

def cmd_check(args) -> int:
    """Execute check command - check batch of entailments"""
    from frame import EntailmentChecker

    # Read entailments from file
    try:
        lines = Path(args.file).read_text().strip().split('\n')
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    # Filter out comments and empty lines
    entailments = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('//'):
            entailments.append(line)

    if not entailments:
        print("No entailments found in file", file=sys.stderr)
        return 1

    # Create checker
    checker = EntailmentChecker(timeout=args.timeout)

    # Check each entailment
    results = []
    total_time = 0
    valid_count = 0
    invalid_count = 0
    error_count = 0

    for i, entailment in enumerate(entailments, 1):
        if args.verbose:
            print(f"[{i}/{len(entailments)}] Checking: {entailment}")

        start_time = time.time()
        try:
            result = checker.check_entailment(entailment)
            elapsed_ms = (time.time() - start_time) * 1000
            total_time += elapsed_ms

            if result.valid:
                valid_count += 1
                status = "valid"
            else:
                invalid_count += 1
                status = "invalid"

            results.append({
                "entailment": entailment,
                "valid": result.valid,
                "reason": result.reason,
                "time_ms": round(elapsed_ms, 2)
            })

            if args.verbose:
                symbol = "✓" if result.valid else "✗"
                print(f"  {symbol} {status.upper()} ({elapsed_ms:.2f}ms)")

            if not result.valid and args.stop_on_failure:
                break

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            total_time += elapsed_ms
            error_count += 1

            results.append({
                "entailment": entailment,
                "valid": None,
                "error": str(e),
                "time_ms": round(elapsed_ms, 2)
            })

            if args.verbose:
                print(f"  ⚠ ERROR: {e}")

    # Output results
    output_data = {
        "file": args.file,
        "total": len(entailments),
        "checked": len(results),
        "valid": valid_count,
        "invalid": invalid_count,
        "errors": error_count,
        "total_time_ms": round(total_time, 2),
        "results": results
    }

    if args.format == "json":
        output_str = json.dumps(output_data, indent=2)
    elif args.format == "csv":
        lines = ["entailment,valid,time_ms,reason"]
        for r in results:
            valid_str = str(r.get("valid", "error")).lower()
            reason = r.get("reason") or r.get("error") or ""
            reason = reason.replace(",", ";") if reason else ""
            lines.append(f"\"{r['entailment']}\",{valid_str},{r['time_ms']},\"{reason}\"")
        output_str = "\n".join(lines)
    else:
        # Text format
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append(f"Frame Entailment Check: {args.file}")
        lines.append(f"{'='*60}")
        lines.append(f"\nTotal: {len(entailments)}")
        lines.append(f"Valid: {valid_count} ({100*valid_count/len(results):.1f}%)" if results else "Valid: 0")
        lines.append(f"Invalid: {invalid_count}")
        lines.append(f"Errors: {error_count}")
        lines.append(f"Time: {total_time:.2f}ms")

        if invalid_count > 0:
            lines.append(f"\nInvalid entailments:")
            for r in results:
                if r.get("valid") is False:
                    lines.append(f"  ✗ {r['entailment']}")

        if error_count > 0:
            lines.append(f"\nErrors:")
            for r in results:
                if r.get("error"):
                    lines.append(f"  ⚠ {r['entailment']}: {r['error']}")

        lines.append(f"\n{'='*60}\n")
        output_str = "\n".join(lines)

    # Write output
    if args.output:
        Path(args.output).write_text(output_str)
        print(f"Results written to {args.output}")
    else:
        print(output_str)

    return 0 if invalid_count == 0 and error_count == 0 else 1


# ============================================================================
# PARSE Command
# ============================================================================

def cmd_parse(args) -> int:
    """Execute parse command - parse and display formula"""
    from frame import parse

    # Get formula string
    if args.formula:
        formula_str = args.formula
    elif args.file:
        try:
            formula_str = Path(args.file).read_text().strip()
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    else:
        print("Error: Provide a formula string or use -f to read from file", file=sys.stderr)
        return 1

    # Parse formula
    try:
        formula = parse(formula_str)
    except Exception as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return 1

    # Output in requested format
    if args.format == "json":
        print(json.dumps(formula_to_dict(formula), indent=2))
    elif args.format == "sexp":
        print(formula_to_sexp(formula))
    else:
        # Tree format
        print(formula_to_tree(formula))

    return 0


def formula_to_dict(formula) -> dict:
    """Convert formula to dictionary representation"""
    from frame.core.ast import (
        Emp, PointsTo, SepConj, Wand, And, Or, Not, Eq, Neq,
        Lt, Le, Gt, Ge, True_, False_, Exists, Forall, Var, Const,
        PredicateCall
    )

    if isinstance(formula, Emp):
        return {"type": "emp"}
    elif isinstance(formula, PointsTo):
        return {
            "type": "points_to",
            "location": formula_to_dict(formula.location),
            "values": [formula_to_dict(v) for v in formula.values]
        }
    elif isinstance(formula, SepConj):
        return {
            "type": "sep_conj",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, Wand):
        return {
            "type": "wand",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, And):
        return {
            "type": "and",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, Or):
        return {
            "type": "or",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, Not):
        return {
            "type": "not",
            "operand": formula_to_dict(formula.formula)
        }
    elif isinstance(formula, Eq):
        return {
            "type": "eq",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, Neq):
        return {
            "type": "neq",
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, (Lt, Le, Gt, Ge)):
        return {
            "type": formula.__class__.__name__.lower(),
            "left": formula_to_dict(formula.left),
            "right": formula_to_dict(formula.right)
        }
    elif isinstance(formula, True_):
        return {"type": "true"}
    elif isinstance(formula, False_):
        return {"type": "false"}
    elif isinstance(formula, Exists):
        return {
            "type": "exists",
            "var": str(formula.var),
            "body": formula_to_dict(formula.body)
        }
    elif isinstance(formula, Forall):
        return {
            "type": "forall",
            "var": str(formula.var),
            "body": formula_to_dict(formula.body)
        }
    elif isinstance(formula, Var):
        return {"type": "var", "name": formula.name}
    elif isinstance(formula, Const):
        return {"type": "const", "value": formula.value}
    elif isinstance(formula, PredicateCall):
        return {
            "type": "predicate",
            "name": formula.name,
            "args": [formula_to_dict(a) for a in formula.args]
        }
    else:
        return {"type": "unknown", "repr": str(formula)}


def formula_to_sexp(formula, indent=0) -> str:
    """Convert formula to S-expression format"""
    from frame.core.ast import (
        Emp, PointsTo, SepConj, Wand, And, Or, Not, Eq, Neq,
        Lt, Le, Gt, Ge, True_, False_, Exists, Forall, Var, Const,
        PredicateCall
    )

    if isinstance(formula, Emp):
        return "emp"
    elif isinstance(formula, PointsTo):
        vals = " ".join(formula_to_sexp(v) for v in formula.values)
        return f"(pto {formula_to_sexp(formula.location)} {vals})"
    elif isinstance(formula, SepConj):
        return f"(sep {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Wand):
        return f"(wand {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, And):
        return f"(and {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Or):
        return f"(or {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Not):
        return f"(not {formula_to_sexp(formula.formula)})"
    elif isinstance(formula, Eq):
        return f"(= {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Neq):
        return f"(!= {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Lt):
        return f"(< {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Le):
        return f"(<= {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Gt):
        return f"(> {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, Ge):
        return f"(>= {formula_to_sexp(formula.left)} {formula_to_sexp(formula.right)})"
    elif isinstance(formula, True_):
        return "true"
    elif isinstance(formula, False_):
        return "false"
    elif isinstance(formula, Exists):
        return f"(exists ({formula.var}) {formula_to_sexp(formula.body)})"
    elif isinstance(formula, Forall):
        return f"(forall ({formula.var}) {formula_to_sexp(formula.body)})"
    elif isinstance(formula, Var):
        return formula.name
    elif isinstance(formula, Const):
        return str(formula.value)
    elif isinstance(formula, PredicateCall):
        args = " ".join(formula_to_sexp(a) for a in formula.args)
        return f"({formula.name} {args})"
    else:
        return str(formula)


def formula_to_tree(formula, prefix="", is_last=True) -> str:
    """Convert formula to tree visualization"""
    from frame.core.ast import (
        Emp, PointsTo, SepConj, Wand, And, Or, Not, Eq, Neq,
        Lt, Le, Gt, Ge, True_, False_, Exists, Forall, Var, Const,
        PredicateCall
    )

    connector = "└── " if is_last else "├── "
    child_prefix = prefix + ("    " if is_last else "│   ")

    lines = []

    if isinstance(formula, Emp):
        lines.append(f"{prefix}{connector}emp")
    elif isinstance(formula, PointsTo):
        lines.append(f"{prefix}{connector}points-to")
        lines.append(formula_to_tree(formula.location, child_prefix, False))
        for i, v in enumerate(formula.values):
            is_last_val = (i == len(formula.values) - 1)
            lines.append(formula_to_tree(v, child_prefix, is_last_val))
    elif isinstance(formula, SepConj):
        lines.append(f"{prefix}{connector}*")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, Wand):
        lines.append(f"{prefix}{connector}-*")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, And):
        lines.append(f"{prefix}{connector}∧")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, Or):
        lines.append(f"{prefix}{connector}∨")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, Not):
        lines.append(f"{prefix}{connector}¬")
        lines.append(formula_to_tree(formula.formula, child_prefix, True))
    elif isinstance(formula, (Eq, Neq, Lt, Le, Gt, Ge)):
        op_map = {Eq: "=", Neq: "≠", Lt: "<", Le: "≤", Gt: ">", Ge: "≥"}
        op = op_map.get(type(formula), "?")
        lines.append(f"{prefix}{connector}{op}")
        lines.append(formula_to_tree(formula.left, child_prefix, False))
        lines.append(formula_to_tree(formula.right, child_prefix, True))
    elif isinstance(formula, True_):
        lines.append(f"{prefix}{connector}true")
    elif isinstance(formula, False_):
        lines.append(f"{prefix}{connector}false")
    elif isinstance(formula, Exists):
        lines.append(f"{prefix}{connector}∃{formula.var}")
        lines.append(formula_to_tree(formula.body, child_prefix, True))
    elif isinstance(formula, Forall):
        lines.append(f"{prefix}{connector}∀{formula.var}")
        lines.append(formula_to_tree(formula.body, child_prefix, True))
    elif isinstance(formula, Var):
        lines.append(f"{prefix}{connector}{formula.name}")
    elif isinstance(formula, Const):
        lines.append(f"{prefix}{connector}{formula.value}")
    elif isinstance(formula, PredicateCall):
        args = ", ".join(str(a) for a in formula.args)
        lines.append(f"{prefix}{connector}{formula.name}({args})")
    else:
        lines.append(f"{prefix}{connector}{formula}")

    return "\n".join(lines)


# ============================================================================
# REPL Command
# ============================================================================

def cmd_repl(args) -> int:
    """Execute REPL command - interactive mode"""
    from frame import EntailmentChecker, parse

    checker = EntailmentChecker(timeout=args.timeout)

    print("Frame Interactive REPL")
    print("=" * 40)
    print("Commands:")
    print("  <entailment>     Check entailment (e.g., 'x |-> 5 |- x |-> 5')")
    print("  :parse <formula> Parse and display formula")
    print("  :help            Show this help")
    print("  :quit            Exit REPL")
    print("=" * 40)
    print()

    while True:
        try:
            line = input("frame> ").strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue

        if not line:
            continue

        if line in (":quit", ":exit", ":q"):
            break
        elif line == ":help":
            print("Commands:")
            print("  <entailment>     Check entailment (e.g., 'x |-> 5 |- x |-> 5')")
            print("  :parse <formula> Parse and display formula")
            print("  :help            Show this help")
            print("  :quit            Exit REPL")
        elif line.startswith(":parse "):
            formula_str = line[7:].strip()
            try:
                formula = parse(formula_str)
                print(formula_to_tree(formula, "", True))
            except Exception as e:
                print(f"Parse error: {e}")
        elif "|-" in line:
            # Entailment check
            try:
                result = checker.check_entailment(line)
                if result.valid:
                    print(f"✓ VALID ({result.reason})")
                else:
                    print(f"✗ INVALID ({result.reason})")
            except Exception as e:
                print(f"Error: {e}")
        else:
            # Try to parse as formula
            try:
                formula = parse(line)
                print(f"Parsed: {formula}")
            except Exception as e:
                print(f"Error: {e}")

    print("Goodbye!")
    return 0


# ============================================================================
# Main Entry Point
# ============================================================================

def main(argv: List[str] = None) -> int:
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands = {
        "scan": cmd_scan,
        "exploit": cmd_exploit,
        "fix": cmd_fix,
        "solve": cmd_solve,
        "check": cmd_check,
        "parse": cmd_parse,
        "repl": cmd_repl,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
