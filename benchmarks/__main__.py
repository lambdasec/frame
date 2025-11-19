#!/usr/bin/env python3
"""
Frame Benchmark Suite - Main Entry Point

This module provides the command-line interface for running benchmarks.
"""

import sys
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.orchestrator import BenchmarkOrchestrator
from benchmarks.commands import cmd_run, cmd_download, cmd_analyze, cmd_visualize


def main():
    """Main entry point for benchmark CLI"""
    parser = argparse.ArgumentParser(
        description="Frame Benchmark Suite - Unified CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download benchmarks
  python -m benchmarks download --all
  python -m benchmarks download --curated
  python -m benchmarks download --division qf_ax_full

  # Run benchmarks
  python -m benchmarks run --curated
  python -m benchmarks run --division qf_ax_curated
  python -m benchmarks run --all

  # Analyze results
  python -m benchmarks analyze --failures

  # Visualize heap structure
  python -m benchmarks visualize <file.smt2>
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Run command
    run_parser = subparsers.add_parser('run', help='Run benchmarks')
    run_group = run_parser.add_mutually_exclusive_group(required=True)
    run_group.add_argument('--all', action='store_true',
                          help='Run ALL benchmarks (full SL-COMP + QF_S suites, ~20k total)')
    run_group.add_argument('--curated', action='store_true',
                          help='Run curated sample sets (~5000 total: 3300 QF_S + 700 SL-COMP + 500 QF_AX + 500 QF_BV)')
    run_group.add_argument('--division', type=str,
                          help='Run specific division (e.g., qf_shls_entl, qf_s_curated)')
    run_parser.add_argument('--max-tests', type=int, help='Maximum tests per division')
    run_parser.add_argument('--output', type=str, default='benchmark_results.json',
                           help='Output file')
    run_parser.add_argument('--cache-dir', type=str, default='./benchmarks/cache',
                           help='Cache directory')
    run_parser.add_argument('--verbose', action='store_true', help='Verbose output')

    # Download command
    download_parser = subparsers.add_parser('download', help='Download benchmarks')
    download_group = download_parser.add_mutually_exclusive_group()
    download_group.add_argument('--all', action='store_true',
                               help='Download all uncached benchmarks')
    download_group.add_argument('--curated', action='store_true',
                               help='Create curated sample sets (~5000 total)')
    download_group.add_argument('--division', type=str,
                               help='Specific division to download')
    download_parser.add_argument('--max-files', type=int, help='Max files to download')
    download_parser.add_argument('--cache-dir', type=str, default='./benchmarks/cache',
                                help='Cache directory')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze results')
    analyze_parser.add_argument('--failures', action='store_true',
                               help='Show detailed failure analysis')
    analyze_parser.add_argument('--cache-dir', type=str, default='./benchmarks/cache',
                               help='Cache directory')

    # Visualize command
    visualize_parser = subparsers.add_parser('visualize', help='Visualize heap structure')
    visualize_parser.add_argument('file', type=str, help='SMT2 file to visualize')
    visualize_parser.add_argument('--cache-dir', type=str, default='./benchmarks/cache',
                                 help='Cache directory')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Execute command
    if args.command == 'run':
        orchestrator = BenchmarkOrchestrator(cache_dir=args.cache_dir, verbose=args.verbose)
        cmd_run(args, orchestrator)

    elif args.command == 'download':
        orchestrator = BenchmarkOrchestrator(cache_dir=args.cache_dir)
        cmd_download(args, orchestrator)

    elif args.command == 'analyze':
        cmd_analyze(args)

    elif args.command == 'visualize':
        cmd_visualize(args)


if __name__ == '__main__':
    main()
