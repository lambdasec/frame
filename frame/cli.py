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

def cmd_scan(args) -> int:
    """Execute scan command"""
    # Delegate to the SIL scanner CLI
    from frame.sil.cli import cmd_scan as sil_scan
    return sil_scan(args)


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
