"""Benchmark result analysis and reporting"""

import os
import json
from typing import Dict, List
from collections import defaultdict
from dataclasses import asdict

from benchmarks.core.result import BenchmarkResult


def analyze_results(results: List[BenchmarkResult]) -> Dict:
    """
    Analyze benchmark results and generate statistics

    Args:
        results: List of benchmark results

    Returns:
        Dictionary with overall stats, by_suite stats, by_division stats, and failures
    """
    if not results:
        return {}

    stats = {
        'total': len(results),
        'correct': sum(1 for r in results if r.correct),
        'incorrect': sum(1 for r in results if not r.correct and not r.error),
        'errors': sum(1 for r in results if r.error),
        'avg_time_ms': sum(r.time_ms for r in results) / len(results),
        'by_suite': defaultdict(lambda: {'total': 0, 'correct': 0, 'errors': 0}),
        'by_division': defaultdict(lambda: {'total': 0, 'correct': 0, 'errors': 0}),
        'failures': []
    }

    for result in results:
        # By suite
        stats['by_suite'][result.suite]['total'] += 1
        if result.correct:
            stats['by_suite'][result.suite]['correct'] += 1
        if result.error:
            stats['by_suite'][result.suite]['errors'] += 1

        # By division
        stats['by_division'][result.division]['total'] += 1
        if result.correct:
            stats['by_division'][result.division]['correct'] += 1
        if result.error:
            stats['by_division'][result.division]['errors'] += 1

        # Track failures
        if not result.correct:
            stats['failures'].append({
                'file': result.filename,
                'division': result.division,
                'expected': result.expected,
                'actual': result.actual,
                'error': result.error
            })

    return stats


def print_summary(results: List[BenchmarkResult]):
    """
    Print summary of benchmark results

    Args:
        results: List of benchmark results
    """
    stats = analyze_results(results)

    if not stats:
        print("No results to display")
        return

    print("\n" + "=" * 80)
    print("BENCHMARK SUMMARY")
    print("=" * 80)

    print(f"\nOverall:")
    print(f"  Total:     {stats['total']}")
    print(f"  Correct:   {stats['correct']} ({stats['correct']/stats['total']*100:.1f}%)")
    print(f"  Incorrect: {stats['incorrect']}")
    print(f"  Errors:    {stats['errors']}")
    print(f"  Avg Time:  {stats['avg_time_ms']:.1f}ms")

    print(f"\nBy Suite:")
    for suite, suite_stats in stats['by_suite'].items():
        total = suite_stats['total']
        correct = suite_stats['correct']
        errors = suite_stats['errors']
        print(f"  {suite}:")
        print(f"    Total: {total}, Correct: {correct} ({correct/total*100:.1f}%), Errors: {errors}")

    print(f"\nBy Division:")
    for division, div_stats in sorted(stats['by_division'].items()):
        total = div_stats['total']
        correct = div_stats['correct']
        errors = div_stats['errors']
        print(f"  {division}:")
        print(f"    Total: {total}, Correct: {correct} ({correct/total*100:.1f}%), Errors: {errors}")

    if stats['failures']:
        print(f"\nFailures ({len(stats['failures'])}):")
        for failure in stats['failures'][:10]:  # Show first 10
            print(f"  - {failure['division']}/{failure['file']}: "
                  f"expected={failure['expected']}, got={failure['actual']}")
        if len(stats['failures']) > 10:
            print(f"  ... and {len(stats['failures']) - 10} more")


def save_results(results: List[BenchmarkResult], cache_dir: str, output_file: str = "benchmark_results.json"):
    """
    Save benchmark results to JSON file

    Args:
        results: List of benchmark results
        cache_dir: Cache directory path (unused, kept for backward compatibility)
        output_file: Output filename (relative to current directory or absolute path)
    """
    # Use output_file directly - don't join with cache_dir
    # This allows users to specify where they want results saved
    output_path = output_file

    # Create parent directory if needed
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"\nResults saved to: {output_path}")
