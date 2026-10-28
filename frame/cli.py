#!/usr/bin/env python3
"""
Frame CLI: a security agent (SAST, SCA, AI layer) on a separation logic engine.

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
        description="Frame: find, prove, exploit and fix vulnerabilities in code and dependencies",
        epilog="Use 'frame <command> --help' for more information on a specific command.",
    )

    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    from frame.sil.packs.cli import add_packs_command
    add_packs_command(subparsers)
    from frame.kb.cli import add_kb_command
    add_kb_command(subparsers)

    # === INVENTORY command ===
    inv_parser = subparsers.add_parser(
        "inventory",
        help="List what a repository contains (languages, frameworks, dependencies, IaC, AI)",
        description="Report the source languages, the frameworks Frame has packs for, dependency "
                    "manifests and lockfiles, infrastructure-as-code, container definitions, LLM "
                    "SDKs and MCP servers under a directory. Nothing is analysed."
    )
    inv_parser.add_argument("target", nargs="?", default=".", help="Directory (default: .)")
    inv_parser.add_argument("-f", "--format", default="text", choices=["text", "json"],
                            help="Output format (default: text)")
    inv_parser.add_argument("--no-sources", action="store_true",
                            help="Skip reading source files (no framework or AI detection)")
    inv_parser.add_argument("--file-limit", type=int, default=5000,
                            help="Most source files read for frameworks and AI imports (default: 5000)")

    # === HISTORY command ===
    hist_parser = subparsers.add_parser(
        "history",
        help="Find provider credentials anywhere in a repository's git history",
        description="Read every line the git history added (all refs by default) and report each provider "
                    "credential once, at the commit that added it, with whether the current tree still has it. "
                    "Values are never printed. Exit 1 when any is found."
    )
    hist_parser.add_argument("target", nargs="?", default=".", help="Repository (default: .)")
    hist_parser.add_argument("--range", dest="rev_range", default=None,
                             help="A revision or range to read instead of every ref (e.g. main, origin/main..HEAD)")
    hist_parser.add_argument("-f", "--format", default="text", choices=["text", "json"],
                             help="Output format (default: text)")

    # === DEPS command ===
    deps_parser = subparsers.add_parser(
        "deps",
        help="Read the dependency graph from manifests and lockfiles",
        description="Read every lockfile (and each manifest without one) under a directory: packages, "
                    "exact versions, direct or transitive, dev only, and the edges between them. "
                    "No package manager runs and nothing is fetched."
    )
    deps_parser.add_argument("target", nargs="?", default=".", help="Directory (default: .)")
    deps_parser.add_argument("-f", "--format", default="text", choices=["text", "json"],
                             help="Output format (default: text)")
    deps_parser.add_argument("-o", "--output", help="Write to this file instead of stdout")
    deps_parser.add_argument("--exclude", action="append", default=[], metavar="DIR",
                             help="Skip this directory name or relative path (repeatable; added to the defaults)")
    deps_parser.add_argument("--fail-on", default="none",
                             choices=["critical", "high", "medium", "low", "any", "none"],
                             help="With --vulns: exit 1 when a vulnerability at or above this severity is found "
                                  "(default: none)")
    deps_parser.add_argument("--vulns", action="store_true",
                             help="Match the packages against the cached advisories (frame kb pull --advisories)")
    deps_parser.add_argument("--plan", action="store_true",
                             help="With --vulns: the smallest upgrade that leaves every known advisory for each "
                                  "vulnerable package, and what it takes (re-lock, raise a requirement, override)")
    deps_parser.add_argument("--image", action="append", default=[], metavar="REF",
                             help="Also read the OS packages of a container image (a reference `docker save` "
                                  "can export, or a `docker save` .tar); repeatable")
    deps_parser.add_argument("--rootfs", action="append", default=[], metavar="DIR",
                             help="Also read the OS packages of an unpacked root filesystem; repeatable")
    deps_parser.add_argument("--licenses", action="store_true",
                             help="Check licences against the [licenses] policy in .frame.toml (exit 1 on a violation)")
    deps_parser.add_argument("--vex", choices=["openvex", "cyclonedx"],
                             help="Print a VEX document (OpenVEX 0.2.0, or CycloneDX 1.6 with vulnerability analysis) "
                                  "instead of the report; implies --vulns. Decisions in .frame/vex.toml are included")
    deps_parser.add_argument("--sbom", choices=["cyclonedx", "spdx"],
                             help="Print a software bill of materials (CycloneDX 1.6 or SPDX 2.3 JSON) instead of "
                                  "the report")
    deps_parser.add_argument("--product", help="With --vex/--sbom: the product identifier "
                                               "(default: pkg:generic/<directory>)")
    deps_parser.add_argument("--dev-not-shipped", action="store_true",
                             help="With --vex: state dev-only dependencies not_affected (component_not_present)")
    deps_parser.add_argument("--apply", action="store_true",
                             help="With --plan: write the manifest edits (without it, --plan shows them as a diff), "
                                  "then re-read the graph and report what is fixed and what remains")
    deps_parser.add_argument("--mitigate", action="store_true",
                             help="With --vulns: write each complete configuration mitigation not yet applied (a "
                                  "properties file the library reads, else the Dockerfile), shown as a diff; with "
                                  "--apply written, then confirmed by re-reading the project")
    deps_parser.add_argument("--registry", action="store_true",
                             help="With --licenses / --sbom: fill unknown licences from the registries (npm, PyPI, "
                                  "RubyGems, crates.io, NuGet, Maven Central); with --vulns: also list the project's declared ranges "
                                  "that admit a vulnerable release; with --plan: fetch release metadata from the registry (npm, PyPI, crates.io) and solve the upgrades of "
                                  "every package together with Z3, so upgrading a package in between replaces an "
                                  "override (goes to the network; cached)")
    deps_parser.add_argument("--verify", metavar="COMMAND",
                             help="With --apply: the project's own build / test command, run before and after; "
                                  "an upgrade that breaks a passing command is rolled back (runs the command)")
    deps_parser.add_argument("--adapt", action="store_true",
                             help="With --verify: when the upgrade breaks the command, let a model (FRAME_LLM_*) adapt "
                                  "the code that uses the upgraded packages; kept only if the command passes and a "
                                  "re-scan of the edited files finds nothing new, else everything is rolled back")
    deps_parser.add_argument("--relock", action="store_true",
                             help="With --apply: re-lock through the package manager (npm, pnpm, yarn, poetry, uv, dotnet, "
                                  "cargo, go); runs the package manager")
    deps_parser.add_argument("--no-reachability", action="store_true",
                             help="With --vulns: skip reading the project's source for imports and calls of "
                                  "the vulnerable packages and functions")
    deps_parser.add_argument("--resolve", action="store_true",
                             help="Run Maven, Gradle and pip to resolve projects without a lockfile "
                                  "(runs the project's build configuration; downloads packages)")

    # === SCAN command ===
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan source code for security vulnerabilities",
        description="Scan source files for vulnerabilities using taint analysis and verification."
    )
    from frame.sil.cli import (
        add_incremental_args, add_language_and_pattern_args, add_pack_args, add_target_arg,
    )
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
    scan_parser.add_argument(
        "--repo-scale",
        action="store_true",
        help="Analyze the whole repository in one LLM session instead of one per "
             "file. Far faster and cheaper on real projects, and lets the model "
             "follow flows across files. Requires --ai or --llm-detect."
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
        "--guidance",
        help="Frame findings JSON to fix (file path, or '-' for stdin). Pipe from "
             "`frame scan --ai -f json`. Not used with --deps."
    )
    fix_parser.add_argument(
        "--deps", action="store_true",
        help="Mitigate vulnerable dependencies in code (SOURCE is the project directory): for each call "
             "site that reaches a vulnerable function (frame scan --sca), patch how the code uses it, the "
             "version unchanged, and keep only patches the taint engine verifies"
    )
    fix_parser.add_argument(
        "--include-called", action="store_true",
        help="With --deps: also call sites with no attacker data flow (verified only when the call is gone)"
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

    # === VERIFY command ===
    verify_parser = subparsers.add_parser(
        "verify",
        help="Re-scan and report whether earlier scan findings are fixed",
        description="Re-scan the files behind findings from `frame scan -f json` and "
                    "report each as fixed, file_removed, present, suppressed, "
                    "uncertain or unverifiable. Exit status: 0 every finding is fixed "
                    "or its file removed, 1 otherwise, 2 the findings cannot be "
                    "verified as given."
    )
    verify_parser.add_argument(
        "findings", help="Findings JSON from `frame scan -f json` (file path, or '-' for stdin)"
    )
    verify_parser.add_argument(
        "--id", action="append", default=[], metavar="FINGERPRINT",
        help="Verify only this finding (repeatable; default: every finding in the JSON)"
    )
    verify_parser.add_argument(
        "-f", "--format", default="text", choices=["text", "json"],
        help="Output format (default: text)"
    )
    verify_parser.add_argument(
        "--timeout", type=int, default=5000,
        help="Verification timeout in ms (default: 5000)"
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


def cmd_history(args) -> int:
    import json
    from frame.sil.secret_history import HistoryError, format_text, scan_history
    try:
        leaks = scan_history(Path(args.target), args.rev_range)
    except HistoryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps({"credentials": [x.to_dict() for x in leaks]}, indent=2))
    else:
        print(format_text(leaks))
    return 1 if leaks else 0


def cmd_inventory(args) -> int:
    """Execute inventory command."""
    from frame.sil.inventory import build_inventory, format_text, to_json
    target = Path(args.target)
    if not target.is_dir():
        print(f"Error: not a directory: {args.target}", file=sys.stderr)
        return 2
    inv = build_inventory(target, read_sources=not args.no_sources, file_limit=args.file_limit)
    print(to_json(inv) if args.format == "json" else format_text(inv))
    return 0


def cmd_deps(args) -> int:
    """Execute deps command."""
    from frame.sca import format_text, read_dependencies
    target = Path(args.target)
    if not target.is_dir():
        print(f"Error: not a directory: {args.target}", file=sys.stderr)
        return 2
    from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS
    excluded = set(DEFAULT_EXCLUDED_SCAN_DIRS)
    for e in args.exclude:
        parts = tuple(p for p in Path(e).parts if p not in (".", ""))
        excluded.add(parts[0] if len(parts) == 1 else parts)
    report = read_dependencies(target, exclude_dirs=excluded, resolve=args.resolve)
    if args.image or args.rootfs:
        from frame.sca.container import ContainerError, read_image, read_rootfs
        for ref in args.image:
            try:
                got, warns = read_image(ref)
            except ContainerError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 2
            report.files.extend(got)
            report.warnings.extend(warns)
        for d in args.rootfs:
            got, warns = read_rootfs(Path(d))
            report.files.extend(got)
            report.warnings.extend(warns)
    if args.licenses or args.sbom:
        from frame.sca.licenses import enrich
        enrich(report.files, target)
        if args.registry:
            from frame.sca.licreg import RegistryLicences, enrich_from_registry
            report.warnings.extend(enrich_from_registry(report.files, RegistryLicences()))
    if args.licenses:
        from frame.sca.licenses import Policy, check, failing, format_text as lic_text
        from frame.sil.suppressions import ConfigError, find_config
        try:
            cfg = find_config(target)
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
        table = (cfg.licenses if cfg else None) or {}
        policy = Policy(deny=table.get("deny", []), allow=table.get("allow", []),
                        unknown=table.get("unknown", "report"), include_dev=table.get("include_dev", False),
                        source=cfg.source if cfg and cfg.licenses else "")
        lic = check(report.files, policy)
        if args.format == "json":
            text = json.dumps({"policy": {"deny": policy.deny, "allow": policy.allow, "unknown": policy.unknown,
                                          "include_dev": policy.include_dev, "source": policy.source},
                               "licenses": [f.to_dict() for f in lic], "warnings": report.warnings}, indent=2)
        else:
            text = lic_text(lic, policy) + "".join(f"\nwarning: {w}" for w in report.warnings)
        if args.output:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return 1 if failing(lic, policy) else 0
    if args.sbom:
        from frame.sca.sbom import to_cyclonedx as sbom_cdx, to_spdx
        from frame.sca.vex import product_id
        for w in report.warnings:
            print(f"warning: {w}", file=sys.stderr)
        prod = product_id(target, args.product)
        doc = sbom_cdx(report, prod) if args.sbom == "cyclonedx" else to_spdx(report, prod)
        text = json.dumps(doc, indent=2)
        if args.output:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return 0
    findings = None
    mitigation = None
    not_checked: list = []
    undecided = 0
    undecided_severities: list = []
    if args.vex:
        args.vulns = True
    if args.vulns:
        from frame.sca.advisories import AdvisoryDB, ecosystems_of, match, pull_hint, repos_of
        db = AdvisoryDB.cached(ecosystems_of(report.files), repos_of(report.files))
        findings = match(report.files, db)
        if findings and not args.no_reachability:
            from frame.sca.reachability import Usage, annotate
            annotate(findings, Usage(target.resolve(), excluded), target.resolve(),
                     {df.path: (df.binary_functions, df.binary_platform) for df in report.files if df.binary_functions})
        exposure = None
        if args.registry and not args.vex:
            from frame.sca.registry import Registries, RegistryError
            from frame.sca.solve import range_exposure
            try:
                exposure = range_exposure(report.files, db, Registries())
            except RegistryError as e:
                report.warnings.append(f"registry: {e}; declared ranges not checked")
        if findings:
            from frame.sca.advisories import cached_revision_dir
            from frame.sca.mitigations import annotate as annotate_mitigations
            annotate_mitigations(findings, target.resolve(), cached_revision_dir(), excluded)
        not_checked = list(db.missing)
        report.warnings.extend(db.notes)
        undecided = len(db.undecided)
        undecided_severities = list(db.undecided)
        if db.missing:
            report.warnings.append(f"no advisories cached for {', '.join(db.missing)}: "
                                   f"run `{pull_hint(db.missing)}`")
        mitigation = None
        if findings and args.mitigate:
            from frame.sca.mitigations import propose
            m_edits, m_manual = propose(findings, target.resolve())
            mitigation = {"edits": m_edits, "manual": m_manual, "confirmed": None}
            if args.apply and m_edits:
                for c in m_edits:
                    dest = target.resolve() / c.path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(c.after, encoding="utf-8")
                from frame.sca.advisories import AdvisoryDB, cached_revision_dir, ecosystems_of, match
                from frame.sca.mitigations import annotate as annotate_mitigations
                files_now = read_dependencies(target, exclude_dirs=excluded).files
                again = match(files_now, AdvisoryDB.cached(ecosystems_of(files_now)))
                annotate_mitigations(again, target.resolve(), cached_revision_dir(), excluded)
                reasons = " ".join(c.reason for c in m_edits)
                mitigation["confirmed"] = sorted({f"{f['package']}@{f['version']} {f['id']}" for f in again
                                                  for m in f.get("mitigations", []) if m["applied"]
                                                  and f["id"] in reasons})
        plans = None
        outcome = None
        verified = None
        if args.vex:
            from frame.sca.plan import plan
            from frame.sca.vex import (VexError, build_statements, load_decisions, product_id, to_cyclonedx,
                                       to_openvex)
            try:
                decisions = load_decisions(target)
            except VexError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 2
            stmts, vex_warnings = build_statements(findings, plan(findings, report.files, db), decisions,
                                                   args.dev_not_shipped)
            for w in report.warnings + vex_warnings:
                print(f"warning: {w}", file=sys.stderr)
            prod = product_id(target, args.product)
            doc = to_openvex(stmts, prod) if args.vex == "openvex" else to_cyclonedx(stmts, prod)
            text = json.dumps(doc, indent=2)
            if args.output:
                Path(args.output).write_text(text + "\n", encoding="utf-8")
            else:
                print(text)
            return 1 if any(s.conflict for s in stmts) else 0
        if args.plan or (args.apply and not args.mitigate):      # --apply writes what was asked for
            from frame.sca.apply import apply_plan
            from frame.sca.plan import plan
            registry = None
            if args.registry:
                from frame.sca.registry import Registries
                registry = Registries()
            try:
                plans = plan(findings, report.files, db, registry)
            except Exception as e:                        # the registry could not be reached
                from frame.sca.registry import RegistryError
                if not isinstance(e, RegistryError):
                    raise
                report.warnings.append(f"registry: {e}; planned each package alone")
                plans = plan(findings, report.files, db)
            adapt_fn = None
            if args.adapt:
                from frame.sil.llm_client import LLMConfig
                if not args.verify:
                    print("Error: --adapt needs --verify COMMAND (the project's own check decides)", file=sys.stderr)
                    return 2
                config = LLMConfig.from_env()
                if not (config.base_url and config.model):
                    print("Error: --adapt needs a model: set FRAME_LLM_BASE_URL and FRAME_LLM_MODEL", file=sys.stderr)
                    return 2
                from frame.sca.adapt import adapt
                upgrades = [p for p in plans if p.get("target")]
                from frame.sca.notes import release_notes
                adapt_fn = lambda output: adapt(target, upgrades, args.verify, output, config, excluded,  # noqa: E731
                                                notes=lambda u: release_notes(u["ecosystem"], u["package"],
                                                                              u["current"], u["target"]))
            outcome = apply_plan(plans, target, write=args.apply, relock_=args.relock, verify=args.verify,
                                 adapt_fn=adapt_fn)
            if args.apply:
                after = match(read_dependencies(target, exclude_dirs=excluded).files, db)
                key = lambda f: (f["path"], f["package"], f["id"])
                left = {key(f) for f in after}
                verified = {"fixed": sorted({f"{f['package']}@{f['version']} {f['id']}" for f in findings
                                             if key(f) not in left}),
                            "remaining": sorted({f"{f['package']}@{f['version']} {f['id']}" for f in after})}
                findings = after
    if args.format == "json":
        data = report.to_dict()
        if mitigation is not None:
            data["mitigation"] = {"edits": [{"path": c.path, "reason": c.reason, "diff": c.diff()}
                                            for c in mitigation["edits"]],
                                  "manual": mitigation["manual"], "confirmed": mitigation["confirmed"]}
        if findings is not None:
            data["vulnerabilities"] = findings
            data["not_checked"] = not_checked
            data["undecided"] = undecided
            if exposure is not None:
                data["exposed_ranges"] = exposure
            if plans is not None:
                data["plan"] = plans
                data["edits"] = [{"path": c.path, "reason": c.reason, "diff": c.diff()} for c in outcome.changes]
                data["manual"] = outcome.manual
                if verified is not None:
                    data["applied"] = {**verified, "relocked": outcome.relocked, "warnings": outcome.warnings,
                                   **({"verify": outcome.verify} if outcome.verify else {})}
                if outcome.adaptation is not None:
                    ad = outcome.adaptation
                    data["applied"]["adaptation"] = {"status": ad.status, "rounds": ad.rounds, "rationale": ad.rationale,
                                                     "introduced": ad.introduced,
                                                     "edits": [{"path": c.path, "diff": c.diff()} for c in ad.changes]}
        out = json.dumps(data, indent=2)
    else:
        out = format_text(report)
        if findings is not None:
            from frame.sca.discover import format_vulns
            out += "\n" + format_vulns(findings, not_checked, undecided)
            if exposure:
                from frame.sca.solve import format_exposure
                out += format_exposure(exposure)
            if mitigation is not None:
                out += "\n\nConfiguration mitigations" + ("" if args.apply else " (dry run; --apply writes them)") + ":"
                for c in mitigation["edits"]:
                    out += "\n" + c.diff()
                for m in mitigation["manual"]:
                    out += f"\nmanual: {m}"
                if mitigation["confirmed"] is not None:
                    out += f"\nApplied and confirmed by re-reading the project: {', '.join(mitigation['confirmed']) or 'none'}"
                if not mitigation["edits"] and not mitigation["manual"]:
                    out += "\n  nothing to apply"
            if plans is not None:
                from frame.sca.plan import format_plan
                out += format_plan(plans)
                if outcome.changes:
                    out += ("\n\nEdits written:\n" if args.apply else "\n\nEdits (dry run; --apply writes them):\n")
                    out += "\n".join(c.diff() for c in outcome.changes)
                for m in outcome.manual:
                    out += f"\nmanual: {m}"
                if verified is not None:
                    from frame.sca.lockfiles import LOCKFILES
                    locked = any(Path(p["path"]).name in LOCKFILES for p in plans if p["target"])
                    out += (f"\n\nAfter applying: {len(verified['fixed'])} fixed, {len(verified['remaining'])} "
                            "remaining" + (" (a lockfile changes only with --relock)" if locked and not args.relock
                                           else ""))
                    for w in outcome.warnings:
                        out += f"\nwarning: {w}"
                    ad = outcome.adaptation
                    if ad is not None and ad.status == "adapted":
                        out += (f"\nAdapted: the code was changed for the new versions in {ad.rounds} round(s) "
                                f"({ad.rationale}); the command passes and a re-scan of the edited files finds "
                                "nothing new:")
                        for c in ad.changes:
                            out += "\n" + c.diff()
                    elif ad is not None:
                        out += {"no-usage": "\nAdapt: no code imports the upgraded packages; nothing to adapt.",
                                "failed": f"\nAdapt: the model's edits did not make the command pass in {ad.rounds} "
                                          "round(s); they were restored.",
                                "introduces-findings": "\nAdapt: the edits made the command pass but added "
                                                       f"findings ({', '.join(ad.introduced)}); they were restored."
                                }.get(ad.status, "")
                    if outcome.verify:
                        out += {"adapted": "",
                                "passed": "\nVerify: the command passes after the upgrade.",
                                "rolled-back": "\nVerify: the command passed before and fails after the upgrade; "
                                               "every edit was rolled back:\n" + outcome.verify_output,
                                "failing-before": "\nVerify: the command already failed before the upgrade, so "
                                                  "it proves nothing; the edits were kept."}[outcome.verify]
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    if findings is not None and not_checked and args.fail_on != "none":
        from frame.sca.advisories import pull_hint
        print(f"Error: --fail-on cannot be judged: no advisories cached for {', '.join(not_checked)} "
              f"(run `{pull_hint(not_checked)}`)", file=sys.stderr)
        return 2
    if findings is not None and undecided_severities and args.fail_on not in (None, "none"):
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        at_or_above = [s for s in undecided_severities
                       if args.fail_on == "any" or s is None or rank.get(s, 0) >= rank.get(args.fail_on, 0)]
        if at_or_above:
            print(f"Error: --fail-on cannot be judged: {len(at_or_above)} advisory(ies) at or above "
                  f"{args.fail_on} were not decided (see the warnings)", file=sys.stderr)
            return 2
    if findings and args.fail_on != "none":
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if args.fail_on == "any" or any(rank.get(f["severity"] or "", 0) >= rank[args.fail_on] for f in findings):
            return 1
    return 0


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


def cmd_verify(args) -> int:
    """Execute verify command - re-scan and report whether findings are fixed."""
    from collections import Counter
    from frame.sil.verify import RESOLVED, VerifyError, verify_findings

    try:
        raw = sys.stdin.read() if args.findings == "-" else Path(args.findings).read_text()
        doc = json.loads(raw)
        findings = _load_findings(raw)
        files = doc.get("files", [doc]) if isinstance(doc, dict) else []
        context = [v for f in files for key in ("baselined", "suppressed")
                   for v in (f.get(key) or [])]
        root = doc.get("root") if isinstance(doc, dict) else None
        scope = (doc.get("scope") or {}) if isinstance(doc, dict) else {}
    except Exception as e:
        print(f"Error reading findings: {e}", file=sys.stderr)
        return 2
    if not findings and not args.id:
        print("No findings to verify.", file=sys.stderr)
        return 2
    try:
        verdicts = verify_findings(findings, args.id, timeout_ms=args.timeout,
                                   context=context, root=root,
                                   cross_file=bool(scope.get("cross_file")),
                                   cross_file_limit=scope.get("limit"))
    except VerifyError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    counts = Counter(v.status for v in verdicts)
    if args.format == "json":
        print(json.dumps({"schema_version": 1,
                          "results": [v.to_dict() for v in verdicts],
                          "summary": dict(counts)}, indent=2))
    else:
        for v in verdicts:
            moved = (f" (now line {v.current_line})"
                     if v.current_line and v.current_line != v.line else "")
            print(f"{v.status:<13} {v.cwe_id or '-':<8} {v.path}:{v.line}{moved}  "
                  f"[{v.fingerprint}] {v.detail}".rstrip())
        print(f"\n{len(verdicts)} finding(s): "
              + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())))
    return 0 if all(v.status in RESOLVED for v in verdicts) else 1


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
    if getattr(args, "deps", False):
        return _fix_deps(args, config)
    if not args.guidance:
        print("Error: --guidance is required (or --deps to mitigate vulnerable dependencies)", file=sys.stderr)
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


def _fix_deps(args, config) -> int:
    """`frame fix DIR --deps`: verified code mitigations for vulnerable dependencies."""
    from frame.sca.mitigate import mitigate
    from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS
    target = Path(args.source)
    if not target.is_dir():
        print("Error: --deps needs the project directory", file=sys.stderr)
        return 1
    results = mitigate(target, DEFAULT_EXCLUDED_SCAN_DIRS, config, write=args.in_place,
                       include_called=args.include_called)
    if args.format == "json":
        print(json.dumps([{"file": r.site.file, "line": r.site.line, "function": r.site.function,
                           "level": r.site.level, "advisories": [a["id"] for a in r.site.advisories],
                           "applied": r.applied, "verdict": r.verdict, "verified": r.verified,
                           "introduced": r.introduced, "rationale": r.rationale, "diff": r.diff}
                          for r in results], indent=2))
    else:
        if not results:
            print("No call site reaches a vulnerable function (frame kb pull --advisories; frame scan --sca).")
        for r in results:
            if r.diff and (r.verified or not args.in_place):
                print(r.diff)
            print(f"  {r.site.file}:{r.site.line} {r.site.function} ({r.site.level}) -> {r.verdict}"
                  + (f": introduces {', '.join(r.introduced)}" if r.introduced else "")
                  + (f"  [{r.rationale}]" if r.rationale else ""))
        ok = sum(1 for r in results if r.verified)
        mode = "written" if args.in_place else "shown as diffs; --in-place writes the verified ones"
        print(f"\n{ok}/{len(results)} mitigations verified by the taint engine ({mode}).")
    return 0 if results and all(r.verified for r in results) else (0 if not results else 1)


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
        "inventory": cmd_inventory,
        "history": cmd_history,
        "deps": cmd_deps,
        "exploit": cmd_exploit,
        "fix": cmd_fix,
        "verify": cmd_verify,
        "solve": cmd_solve,
        "check": cmd_check,
        "parse": cmd_parse,
        "repl": cmd_repl,
        "packs": lambda a: __import__("frame.sil.packs.cli", fromlist=["cmd_packs"]).cmd_packs(a),
        "kb": lambda a: __import__("frame.kb.cli", fromlist=["cmd_kb"]).cmd_kb(a),
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
