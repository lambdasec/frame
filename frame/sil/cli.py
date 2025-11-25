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
"""

import argparse
import sys
import json
from pathlib import Path
from typing import List

from frame.sil.scanner import FrameScanner, ScanResult, Severity


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog="frame-scan",
        description="Frame Security Scanner - Verification-grade vulnerability detection",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan files for vulnerabilities")
    scan_parser.add_argument(
        "target",
        help="File or directory to scan"
    )
    scan_parser.add_argument(
        "-l", "--language",
        default="python",
        choices=["python"],  # Add more as implemented
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


def format_json_result(results: List[ScanResult]) -> str:
    """Format results as JSON"""
    if len(results) == 1:
        return results[0].to_json()
    else:
        combined = {
            "files": [r.to_dict() for r in results],
            "summary": {
                "files_scanned": len(results),
                "total_vulnerabilities": sum(len(r.vulnerabilities) for r in results),
                "critical": sum(r.critical_count for r in results),
                "high": sum(r.high_count for r in results),
            }
        }
        return json.dumps(combined, indent=2)


def format_sarif_result(results: List[ScanResult]) -> str:
    """Format results as SARIF"""
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
        return 1

    # Create scanner
    try:
        scanner = FrameScanner(
            language=args.language,
            verify=not args.no_verify,
            timeout=args.timeout,
            verbose=args.verbose
        )
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Install tree-sitter: pip install tree-sitter tree-sitter-python", file=sys.stderr)
        return 1

    # Perform scan
    results = []

    if target.is_file():
        result = scanner.scan_file(str(target))
        results.append(result)
    else:
        results = scanner.scan_directory(str(target), args.pattern)

    if not results:
        print("No files found to scan.", file=sys.stderr)
        return 1

    # Format output
    min_severity = parse_severity(args.min_severity)

    if args.format == "text":
        for result in results:
            output = format_text_result(result, min_severity)
            if args.output:
                with open(args.output, 'a') as f:
                    f.write(output)
            else:
                print(output)

    elif args.format == "json":
        output = format_json_result(results)
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
