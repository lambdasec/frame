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
from collections import Counter
from pathlib import Path
from typing import List

from frame.sil.scanner import FrameScanner, ScanResult, Severity
from frame.sil.llm_client import LLMUnavailableError
from frame.sil.packs import PackError



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
        "--no-cross-file", action="store_true",
        help="Analyse each file alone. By default a directory scan follows taint "
             "across the imports of Python and JS/TS files: request data passed to a "
             "helper in another file reaches that file's sinks, and a helper that "
             "returns request data taints its callers. With --changed the scan widens "
             "to the files that import the changed ones and everything those import, "
             "so each is analysed as a full scan would.")
    scan_parser.add_argument(
        "--cross-file-limit", type=int, default=None, metavar="N",
        help="Most Python/JS/TS files one cross-file analysis spans (default 2000). "
             "A full scan over the limit analyses files alone, with a warning; "
             "--changed keeps the files nearest the change.")
    scan_parser.add_argument(
        "--root", metavar="DIR",
        help="Project root that finding paths and fingerprints are relative to "
             "(default: the git top level, else the directory of the Frame "
             "config, else the scanned directory)")
    scan_parser.add_argument(
        "--write-baseline", metavar="FILE",
        help="Record this run's findings as the baseline (written after --baseline "
             "is applied, so both together update it). Entries for files this run "
             "did not scan are kept. Does not change the exit status; add "
             "--fail-on none to accept the current state.")


def add_pack_args(scan_parser) -> None:
    """Framework-pack flags for `scan`, shared by this parser and `frame/cli.py`'s."""
    scan_parser.add_argument(
        "--pack", action="append", default=None, metavar="PATH",
        help="Load an extra framework pack (a .toml file, or a directory of them) on top "
             "of the built-in ones and the project's .frame/packs. Repeatable. "
             "`frame packs check PATH` validates a pack.")
    scan_parser.add_argument(
        "--no-packs", action="store_true",
        help="Do not load the built-in framework packs (project and --pack packs still load).")
    scan_parser.add_argument(
        "--verify-secrets", action="store_true",
        help="Ask each provider-format credential's provider whether it still works (a read-only request to "
             "the provider's own API, e.g. GitHub's /user; off by default, see docs/usage.md#verifying-secrets)")
    scan_parser.add_argument(
        "--vex", choices=["openvex", "cyclonedx"],
        help="With --sca: also write a VEX document for the dependency findings to --vex-out (attacker data "
             "reaching a vulnerable function is stated exploitable)")
    scan_parser.add_argument("--vex-out", metavar="FILE", help="Where --vex writes the VEX document")
    scan_parser.add_argument(
        "--sca", action="store_true",
        help="Also report vulnerable dependencies (directory targets): match the lockfiles against the "
             "cached advisories (`frame kb pull --advisories`), and make each vulnerable function a taint "
             "sink, so attacker data reaching it is a finding at the call site.")
    scan_parser.add_argument(
        "--iac", action="store_true",
        help="Also check infrastructure files (directory targets): Kubernetes manifests, "
             "Dockerfiles and Terraform against the policy packs, as `frame iac` does.")


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
    add_pack_args(scan_parser)
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
            lines.append(f"   Location: {vuln.location}:{vuln.line}:{vuln.column}"
                         + ("  (test code)" if getattr(vuln, "context", "") == "test" else ""))
            lines.append(f"   Function: {vuln.procedure}")
            lines.append(f"   Description: {vuln.description}")
            if getattr(vuln, "validity", ""):
                lines.append(f"   Verified: {vuln.validity_detail}")

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


def _at_least(results: List[ScanResult], min_severity: Severity) -> List[ScanResult]:
    """Copies of `results` holding only the findings at or above `min_severity` (the exit
    status is decided on the unfiltered results, as for text output)."""
    import dataclasses
    return [dataclasses.replace(r, vulnerabilities=[v for v in r.vulnerabilities
                                                    if severity_value(v.severity) >= severity_value(min_severity)])
            for r in results]


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
        BaselineError, apply_baseline, assign_fingerprints, baseline_root_mismatch,
        load_baseline, project_root, write_baseline)
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
    root = project_root(target, getattr(args, "root", None), config.source)
    if baseline_entries and baseline_root_mismatch(baseline_entries, root):
        print(f"Warning: no file the baseline names exists under the project root {root}; "
              f"it was likely written against another root (pass --root), so every "
              f"finding will look new.", file=sys.stderr)
    if args.min_severity is None:
        args.min_severity = config.min_severity or "low"
    if args.fail_on is None:
        args.fail_on = config.fail_on or "high"
    disabled_rules = list(config.disable) + list(getattr(args, "disable", []) or [])

    # Create scanner
    try:
        # AI layer: --ai turns on both; --llm-detect / --llm-triage are granular.
        ai = getattr(args, "ai", False)
        pack_paths = [str(Path(config.source).parent / p) if config.source and not Path(p).is_absolute() else p
                      for p in config.packs] + list(getattr(args, "pack", None) or [])
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
            packs=pack_paths,
            use_builtin_packs=not getattr(args, "no_packs", False),
            verify_secrets=getattr(args, "verify_secrets", False),
        )
    except PackError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Install tree-sitter: pip install tree-sitter tree-sitter-python", file=sys.stderr)
        return 2

    sca_run = None
    if getattr(args, "sca", False):
        if target.is_dir():
            from frame.sca.scan import prepare, sink_packs
            from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS
            sca_excluded = set(DEFAULT_EXCLUDED_SCAN_DIRS) | set(config.exclude or [])
            sca_run = prepare(target, sca_excluded)
            scanner.add_packs(sink_packs(sca_run))
        else:
            print("Warning: --sca needs a directory target; dependencies were not checked", file=sys.stderr)

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
            from frame.sil.scanner import DEFAULT_CROSS_FILE_LIMIT, language_extensions
            results = scanner.scan_directory(
                str(target), args.pattern, exclude_dirs=exclude_dirs,
                extensions=language_extensions(args.language), only_files=selection,
                cross_file=not getattr(args, "no_cross_file", False),
                cross_file_limit=getattr(args, "cross_file_limit", None) or DEFAULT_CROSS_FILE_LIMIT,
                project_root=root)
    except LLMUnavailableError as e:
        print(f"Error: LLM layer unavailable -- scan aborted (findings NOT reliable): {e}",
              file=sys.stderr)
        return 2

    iac_run = None
    if getattr(args, "iac", False):
        if target.is_dir():
            from frame.iac.scan import scan as iac_scan
            from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS
            iac_run = iac_scan(target, packs=scanner.pack_set,
                               exclude_dirs=set(DEFAULT_EXCLUDED_SCAN_DIRS) | set(config.exclude or []))
        else:
            print("Warning: --iac needs a directory target (use `frame iac FILE` for one file)", file=sys.stderr)

    if not results and not narrowed and iac_run is None:
        print("No files found to scan.", file=sys.stderr)
        return 2

    if sca_run is not None:
        from frame.sca.scan import link
        link(sca_run, results, target)
        if getattr(args, "vex", None):
            if not getattr(args, "vex_out", None):
                print("Error: --vex needs --vex-out FILE", file=sys.stderr)
                return 2
            from frame.sca.vex import VexError, build_statements, load_decisions, product_id, to_cyclonedx, to_openvex
            from frame.sca.advisories import AdvisoryDB
            from frame.sca.plan import plan as sca_plan
            from frame.sca import read_dependencies
            try:
                decisions = load_decisions(target)
            except VexError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 2
            files = read_dependencies(target).files
            db = AdvisoryDB.cached(sorted({f["ecosystem"] for f in sca_run.findings}))
            stmts, vex_warnings = build_statements(sca_run.findings, sca_plan(sca_run.findings, files, db), decisions)
            sca_run.warnings.extend(vex_warnings)
            doc = to_openvex(stmts, product_id(target)) if args.vex == "openvex" else to_cyclonedx(stmts, product_id(target))
            Path(args.vex_out).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    # Stable identities for every finding, then the baseline comparison.
    assign_fingerprints(results, root)
    extra = {"root": str(root)}
    if sca_run is not None:
        extra["dependencies"] = {"advisories": sca_run.revision, "findings": sca_run.findings,
                                 "warnings": sca_run.warnings}
    if iac_run is not None:
        from frame.iac.scan import at_least as iac_at_least
        extra["infrastructure"] = iac_at_least(iac_run, args.min_severity).to_dict()
    if scanner.pack_set:
        extra["packs"] = scanner.pack_set.names()
    scope = getattr(scanner, "last_project_scope", None)
    if scope:
        extra["scope"] = dict(scope)
        if scope.get("truncated"):
            print(f"Warning: the cross-file scope was cut at {scope['limit']} files "
                  f"(--cross-file-limit); a file analysed without its imports can report "
                  f"findings a full scan would not", file=sys.stderr)
        if scope.get("complete") is False:
            print("Warning: the cross-file analysis ran out of its budget before the "
                  "summaries settled; some flows between files may be missing", file=sys.stderr)
        if scope.get("cross_file") is False and scope.get("reason"):
            print(f"Warning: {scope['reason']}", file=sys.stderr)
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
        shown = results
        if target.is_dir() and not getattr(args, "verbose", False):
            # a directory scan lists the files with something to say; the summary line counts the rest
            shown = [r for r in results
                     if r.errors or r.warnings
                     or any(severity_value(v.severity) >= severity_value(min_severity)
                            for v in r.vulnerabilities)]
        chunks = [format_text_result(result, min_severity) for result in shown]
        if target.is_dir() and results:
            total = sum(1 for r in results for v in r.vulnerabilities
                        if severity_value(v.severity) >= severity_value(min_severity))
            by_sev = Counter(v.severity.value for r in results for v in r.vulnerabilities
                             if severity_value(v.severity) >= severity_value(min_severity))
            detail = ", ".join(f"{n} {s}" for s, n in sorted(
                by_sev.items(), key=lambda kv: -severity_value(parse_severity(kv[0])))) or "none"
            files = f"{len(results)} file{'s' if len(results) != 1 else ''}"
            chunks.append(f"\nScanned {files}: {total} finding{'s' if total != 1 else ''} ({detail})\n")
        if not results:
            chunks.append("No source files in the selection to scan.\n")
        sc = extra.get("scope")
        if sc and sc.get("cross_file"):
            chunks.append(f"Cross-file analysis: {sc['files']} files"
                          + (f" (from {sc['selected']} selected)" if narrowed else "") + "\n")
        if "baseline" in extra:
            b = extra["baseline"]
            chunks.append(f"Baseline {b['file']}: {b['new']} new, {b['baselined']} known, "
                          f"{len(b['fixed'])} fixed since it was written\n")
        if sca_run is not None:
            from frame.sca.scan import format_text as sca_text
            chunks.append(sca_text(sca_run))
        if iac_run is not None:
            from frame.iac.scan import at_least as iac_at_least, format_text as iac_text
            chunks.append(iac_text(iac_at_least(iac_run, args.min_severity)))
        for output in chunks:
            if args.output:
                with open(args.output, 'a') as f:
                    f.write(output)
            else:
                print(output)

    elif args.format == "json":
        results = _at_least(results, min_severity)
        output = format_json_result(results, directory=target.is_dir(), extra=extra)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)

    elif args.format == "sarif":
        output = format_sarif_result(_at_least(results, min_severity))
        if sca_run is not None and sca_run.findings:
            from frame.sca.scan import sarif_results
            doc = json.loads(output)
            doc["runs"][0].setdefault("results", []).extend(sarif_results(sca_run))
            output = json.dumps(doc, indent=2)
        if iac_run is not None and iac_run.findings:
            from frame.iac.scan import at_least as iac_at_least, sarif_results as iac_results, sarif_rules
            doc = json.loads(output)
            shown = iac_at_least(iac_run, args.min_severity)
            doc["runs"][0].setdefault("results", []).extend(iac_results(shown))
            doc["runs"][0]["tool"]["driver"].setdefault("rules", []).extend(sarif_rules(shown))
            output = json.dumps(doc, indent=2)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
        else:
            print(output)

    # Determine exit code
    if should_fail(results, args.fail_on):
        return 1
    if sca_run is not None and sca_run.findings and args.fail_on != "none":
        from frame.sca.scan import worst_severity          # 4 critical .. 1 low, as severity_value - 1
        if args.fail_on == "any" or worst_severity(sca_run) >= severity_value(parse_severity(args.fail_on)) - 1:
            return 1
    if iac_run is not None:
        from frame.iac.scan import fails
        if fails(iac_run, args.fail_on):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
