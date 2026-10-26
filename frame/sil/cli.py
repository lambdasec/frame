#!/usr/bin/env python3
"""
Frame Security Scanner CLI.

Command-line interface for scanning source code for vulnerabilities.

Usage:
    # Scan a single file
    python -m frame.sil.cli scan app.py

    # Scan with SARIF output (for GitHub Actions)
    python -m frame.sil.cli scan app.py --format sarif -o results.sarif

    # Scan a directory
    python -m frame.sil.cli scan src/ --pattern "**/*.py"

    # Scan without verification (faster, may have FPs)
    python -m frame.sil.cli scan app.py --no-verify

    # Record today's findings, then report only new ones in what changed
    python -m frame.sil.cli scan . --write-baseline .frame-baseline.json --fail-on none
    python -m frame.sil.cli scan . --changed --baseline .frame-baseline.json

Exit status: 0 no finding at or above --fail-on (only new findings count when
--baseline is given), 1 such a finding, 2 the scan could not run (bad target,
configuration, baseline, git ref, or an unreachable LLM endpoint).
"""

import argparse
import sys
import json
from pathlib import Path
from typing import List

from frame.sil.scanner import FrameScanner, ScanResult, Severity
from frame.sil.llm_client import LLMUnavailableError



LANGUAGE_HELP = (
    "Source language. Each file is analysed in the language its extension names; "
    "this picks which files a directory scan walks (default: every supported "
    "source file) and the language of files with an unknown extension. Symbolic "
    "frontends: python, javascript, typescript, java, c, cpp, csharp. Any other "
    "language (e.g. php, ruby, go) runs LLM-detect only under --ai.")
PATTERN_HELP = ("Glob pattern for directory scan (default: every file of --language, "
                "or every supported source file)")


def add_target_arg(scan_parser) -> None:
    scan_parser.add_argument(
        "target", nargs="?", default=".",
        help="File or directory to scan (default: the current directory)")


def add_incremental_args(scan_parser) -> None:
    """Narrowing a scan to what changed and comparing it with a baseline, shared
    by this parser and `frame/cli.py`'s."""
    scan_parser.add_argument(
        "--changed", nargs="?", const="HEAD", default=None, metavar="REF",
        help="Scan only files that differ from REF (default HEAD: staged and "
             "unstaged changes) plus untracked files; needs a git repository and "
             "a directory target. Nothing changed is a clean scan.")
    scan_parser.add_argument(
        "--files", nargs="+", default=None, metavar="PATH",
        help="Scan only these files (within the target directory), e.g. the ones "
             "an agent just edited. Combines with --changed.")
    scan_parser.add_argument(
        "--baseline", metavar="FILE",
        help="Report only findings not recorded in this baseline; known ones are "
             "counted as `baselined` and do not affect the exit status. Baseline "
             "findings no longer present in the scanned files are listed as fixed.")
    scan_parser.add_argument(
        "--write-baseline", metavar="FILE",
        help="Record this run's findings as the baseline (written after --baseline "
             "is applied, so both together update it). Entries for files this run "
             "did not scan are kept. Does not change the exit status; add "
             "--fail-on none to accept the current state.")


def add_language_and_pattern_args(scan_parser) -> None:
    """`-l` / `-p` for `scan`, shared by this parser and `frame/cli.py`'s so the
    two cannot drift. Both default to None; `cmd_scan` resolves them."""
    scan_parser.add_argument("-l", "--language", default=None, help=LANGUAGE_HELP)
    scan_parser.add_argument("-p", "--pattern", default=None, help=PATTERN_HELP)

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog="frame-scan",
        description="Frame Security Scanner - Verification-grade vulnerability detection",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan files for vulnerabilities")
    add_target_arg(scan_parser)
    add_language_and_pattern_args(scan_parser)
    add_incremental_args(scan_parser)
    scan_parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Directory scans skip agent/tool state and dependency "
             "directories by default (.git, .claude/worktrees, "
             ".cursor/worktrees, .worktrees, .idea, .vscode, node_modules, "
             ".venv, venv [only if it looks like a virtualenv], .tox, "
             "__pycache__, .mypy_cache, .pytest_cache). Pass this to scan "
             "them too."
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
        default=None,
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report (default: config file, else low)"
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
        default=None,
        help="Exit with error if vulnerabilities of this severity found "
             "(default: config file, else high)"
    )
    scan_parser.add_argument(
        "--config",
        help="Path to a .frame.toml / pyproject.toml with a [tool.frame] table. "
             "Default: the nearest one above the scan target. Flags override it."
    )
    scan_parser.add_argument(
        "--no-config",
        action="store_true",
        help="Ignore any .frame.toml / [tool.frame] configuration"
    )
    scan_parser.add_argument(
        "--disable",
        action="append",
        default=[],
        metavar="RULE",
        help="Drop findings for a CWE id or finding type (e.g. CWE-798, weak_hash). "
             "Repeatable; adds to the config file's `disable` list."
    )
    scan_parser.add_argument(
        "--no-suppress",
        action="store_true",
        help="Ignore inline `frame: ignore` comments and report everything"
    )
    scan_parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable the LLM layer (detection + triage). Needs an LLM endpoint "
             "configured via FRAME_LLM_* env vars."
    )
    scan_parser.add_argument(
        "--llm-detect",
        action="store_true",
        help="Enable LLM detection only (find vulnerabilities the symbolic engine misses)."
    )
    scan_parser.add_argument(
        "--llm-triage",
        action="store_true",
        help="Enable LLM triage only (filter false positives from symbolic findings)."
    )
    scan_parser.add_argument(
        "--repo-scale",
        action="store_true",
        help="Analyze the whole repository in one LLM session instead of one per "
             "file. Far faster and cheaper on real projects, and lets the model "
             "follow flows across files. Requires --ai or --llm-detect."
    )

    return parser


def severity_value(severity: Severity) -> int:
    """Get numeric value for severity comparison"""
    values = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    return values.get(severity, 0)


def parse_severity(name: str) -> Severity:
    """Parse severity from string"""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(name.lower(), Severity.LOW)


def format_text_result(result: ScanResult, min_severity: Severity) -> str:
    """Format scan result as human-readable text"""
    lines = []

    # Header
    lines.append(f"\n{'='*60}")
    lines.append(f"Frame Security Scan: {result.filename}")
    lines.append(f"{'='*60}")

    # Stats
    lines.append(f"\nLines scanned: {result.lines_scanned}")
    lines.append(f"Procedures analyzed: {result.procedures_analyzed}")
    lines.append(f"Scan time: {result.scan_time_ms:.2f}ms")
    if result.suppressed:
        lines.append(f"Suppressed findings: {len(result.suppressed)} "
                     f"(inline `frame: ignore` or disabled rules)")
    if result.baselined:
        lines.append(f"Known findings (baseline): {len(result.baselined)}")

    # Errors
    if result.errors:
        lines.append(f"\nErrors:")
        for error in result.errors:
            lines.append(f"  ❌ {error}")

    # Vulnerabilities
    vulns = [v for v in result.vulnerabilities
             if severity_value(v.severity) >= severity_value(min_severity)]

    if vulns:
        lines.append(f"\nVulnerabilities Found: {len(vulns)}")
        lines.append("-" * 40)

        for i, vuln in enumerate(vulns, 1):
            severity_icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
                Severity.INFO: "⚪",
            }.get(vuln.severity, "⚫")

            lines.append(f"\n{i}. [{vuln.severity.value.upper()}] {severity_icon} {vuln.type.value}")
            lines.append(f"   Location: {vuln.location}:{vuln.line}:{vuln.column}")
            lines.append(f"   Function: {vuln.procedure}")
            lines.append(f"   Description: {vuln.description}")

            if vuln.cwe_id:
                lines.append(f"   CWE: {vuln.cwe_id}")

            if vuln.fingerprint:
                lines.append(f"   ID: {vuln.fingerprint}")

            if vuln.source_var:
                lines.append(f"   Source: {vuln.source_var}")

            if vuln.data_flow:
                flow = " → ".join(vuln.data_flow[:5])
                if len(vuln.data_flow) > 5:
                    flow += " → ..."
                lines.append(f"   Data flow: {flow}")

            if vuln.witness:
                lines.append(f"   Exploit witness: {vuln.witness}")

            lines.append(f"   Confidence: {vuln.confidence:.0%}")

    else:
        lines.append(f"\n✅ No vulnerabilities found!")

    lines.append(f"\n{'='*60}\n")

    return "\n".join(lines)


# Version of the `frame scan -f json` document. Bump it when a field changes
# meaning or is removed; adding a field does not need a bump.
JSON_SCHEMA_VERSION = 1


def format_json_result(results: List[ScanResult], directory: bool = False,
                       extra: dict = None) -> str:
    """Format results as JSON: one file's object for a file target, the
    `{"files": [...], "summary": ...}` shape for a directory target -- even when
    it holds a single file, so the schema depends on what was scanned, never on
    how many files matched. `extra` keys (e.g. `baseline`) go at the top level."""
    if len(results) == 1 and not directory:
        doc = results[0].to_dict()
    else:
        doc = {
            "files": [r.to_dict() for r in results],
            "summary": {
                "files_scanned": len(results),
                "total_vulnerabilities": sum(len(r.vulnerabilities) for r in results),
                "critical": sum(r.critical_count for r in results),
                "high": sum(r.high_count for r in results),
                "suppressed": sum(len(r.suppressed) for r in results),
                "baselined": sum(len(r.baselined) for r in results),
            }
        }
    doc = {"schema_version": JSON_SCHEMA_VERSION, **doc, **(extra or {})}
    return json.dumps(doc, indent=2)


def format_sarif_result(results: List[ScanResult]) -> str:
    """Format results as SARIF"""
    if not results:
        return json.dumps(ScanResult(filename="").to_sarif(), indent=2)
    if len(results) == 1:
        return json.dumps(results[0].to_sarif(), indent=2)
    else:
        # Combine multiple files into one SARIF run
        all_results = []
        rules = {}

        for result in results:
            sarif = result.to_sarif()
            if sarif["runs"]:
                run = sarif["runs"][0]
                all_results.extend(run.get("results", []))
                for rule in run["tool"]["driver"].get("rules", []):
                    rules[rule["id"]] = rule

        combined = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Frame Security Scanner",
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": all_results,
            }]
        }
        return json.dumps(combined, indent=2)


def should_fail(results: List[ScanResult], fail_on: str) -> bool:
    """Determine if scan should fail based on findings"""
    if fail_on == "none":
        return False

    if fail_on == "any":
        return any(r.vulnerabilities for r in results)

    threshold = parse_severity(fail_on)
    threshold_value = severity_value(threshold)

    for result in results:
        for vuln in result.vulnerabilities:
            if severity_value(vuln.severity) >= threshold_value:
                return True

    return False


def main(argv: List[str] = None) -> int:
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)

    return 0


def cmd_scan(args) -> int:
    """Execute scan command"""
    target = Path(args.target)

    if not target.exists():
        print(f"Error: Target not found: {args.target}", file=sys.stderr)
        return 2

    changed_ref = getattr(args, "changed", None)
    only_paths = getattr(args, "files", None)
    narrowed = changed_ref is not None or only_paths is not None
    if narrowed and not target.is_dir():
        print("Error: --changed/--files need a directory target (the scope to scan "
              "within), e.g. `frame scan . --changed`", file=sys.stderr)
        return 2

    from frame.sil.fingerprints import (
        BaselineError, apply_baseline, assign_fingerprints,
        load_baseline, project_root, write_baseline)
    root = project_root(target)
    baseline_entries = None
    if getattr(args, "baseline", None):
        try:
            baseline_entries = load_baseline(args.baseline)
        except BaselineError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2

    selection = None
    if narrowed:
        selection = []
        if changed_ref is not None:
            from frame.sil.changes import GitError, changed_files
            try:
                selection.extend(changed_files(target.resolve(), changed_ref))
            except GitError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 2
        for f in only_paths or []:
            if Path(f).is_file():
                selection.append(Path(f))
            else:
                print(f"Warning: --files: not a file, skipped: {f}", file=sys.stderr)

    # Project configuration: flags > config file > built-in defaults.
    from frame.sil.suppressions import ConfigError, ScanConfig, find_config, load_config_file
    config = ScanConfig()
    if not getattr(args, "no_config", False):
        try:
            if getattr(args, "config", None):
                config = load_config_file(Path(args.config)) or ScanConfig()
            else:
                config = find_config(target) or ScanConfig()
        except (ConfigError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
    if args.min_severity is None:
        args.min_severity = config.min_severity or "low"
    if args.fail_on is None:
        args.fail_on = config.fail_on or "high"
    disabled_rules = list(config.disable) + list(getattr(args, "disable", []) or [])

    # Create scanner
    try:
        # AI layer: --ai turns on both; --llm-detect / --llm-triage are granular.
        ai = getattr(args, "ai", False)
        scanner = FrameScanner(
            language=args.language or "python",
            verify=not args.no_verify,
            timeout=args.timeout,
            verbose=args.verbose,
            llm_detect=ai or getattr(args, "llm_detect", False),
            llm_triage=ai or getattr(args, "llm_triage", False),
            llm_repo_scale=getattr(args, "repo_scale", False),
            respect_suppressions=not getattr(args, "no_suppress", False),
            disabled_rules=disabled_rules,
        )
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Install tree-sitter: pip install tree-sitter tree-sitter-python", file=sys.stderr)
        return 2

    # Perform scan. An unreachable LLM endpoint (with --ai) surfaces as a hard
    # error, never a misleading "no vulnerabilities found".
    results = []
    try:
        if target.is_file():
            result = scanner.scan_file(str(target))
            results.append(result)
        else:
            if getattr(args, "no_default_excludes", False):
                exclude_dirs = []
            elif config.exclude:
                from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS
                exclude_dirs = list(DEFAULT_EXCLUDED_SCAN_DIRS) + config.exclude
            else:
                exclude_dirs = None
            from frame.sil.scanner import language_extensions
            results = scanner.scan_directory(
                str(target), args.pattern, exclude_dirs=exclude_dirs,
                extensions=language_extensions(args.language), only_files=selection)
    except LLMUnavailableError as e:
        print(f"Error: LLM layer unavailable -- scan aborted (findings NOT reliable): {e}",
              file=sys.stderr)
        return 2

    if not results and not narrowed:
        print("No files found to scan.", file=sys.stderr)
        return 2

    # Stable identities for every finding, then the baseline comparison.
    assign_fingerprints(results, root)
    extra = {"root": str(root)}
    if baseline_entries is not None:
        fixed = apply_baseline(results, baseline_entries, root)
        for r in results:
            r.baseline_applied = True
        extra["baseline"] = {
            "file": str(args.baseline),
            "new": sum(len(r.vulnerabilities) for r in results),
            "baselined": sum(len(r.baselined) for r in results),
            "fixed": fixed,
        }
    if getattr(args, "write_baseline", None):
        try:
            written = write_baseline(args.write_baseline, results, root)
        except OSError as e:
            print(f"Error: cannot write baseline: {e}", file=sys.stderr)
            return 2
        print(f"Baseline written: {args.write_baseline} ({written} findings)", file=sys.stderr)

    # Format output
    min_severity = parse_severity(args.min_severity)

    if args.format == "text":
        chunks = [format_text_result(result, min_severity) for result in results]
        if not results:
            chunks.append("No source files in the selection to scan.\n")
        if "baseline" in extra:
            b = extra["baseline"]
            chunks.append(f"Baseline {b['file']}: {b['new']} new, {b['baselined']} known, "
                          f"{len(b['fixed'])} fixed since it was written\n")
        for output in chunks:
            if args.output:
                with open(args.output, 'a') as f:
                    f.write(output)
            else:
                print(output)

    elif args.format == "json":
        output = format_json_result(results, directory=target.is_dir(), extra=extra)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)

    elif args.format == "sarif":
        output = format_sarif_result(results)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)

    # Determine exit code
    if should_fail(results, args.fail_on):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
