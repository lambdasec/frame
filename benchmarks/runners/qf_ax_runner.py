"""QF_AX benchmark runner"""

import os
import time
from typing import List, Optional

from benchmarks.core import BenchmarkResult, run_smt2_with_z3, parse_smt2_expected


def run_qf_ax_benchmark(cache_dir: str, source: str, filename: str,
                        full_path: Optional[str] = None) -> BenchmarkResult:
    """Run a single QF_AX benchmark via Z3 directly"""
    if full_path:
        filepath = full_path
    else:
        filepath = os.path.join(cache_dir, 'qf_ax', source, filename)

    if not os.path.exists(filepath):
        return BenchmarkResult(
            filename=filename,
            suite='qf_ax',
            division=source,
            expected='unknown',
            actual='error',
            time_ms=0.0,
            error='File not found'
        )

    # Parse expected result
    expected = parse_smt2_expected(filepath) or 'unknown'

    # Run via Z3 directly (QF_AX is pure SMT-LIB 2.6 format)
    start_time = time.time()
    actual, error = run_smt2_with_z3(filepath, timeout=10)
    time_ms = (time.time() - start_time) * 1000

    return BenchmarkResult(
        filename=filename,
        suite='qf_ax',
        division=source,
        expected=expected,
        actual=actual,
        time_ms=time_ms,
        error=error
    )


def run_qf_ax_division(cache_dir: str, source: str,
                       max_tests: Optional[int] = None) -> List[BenchmarkResult]:
    """Run all QF_AX benchmarks in a source"""
    from benchmarks.downloaders import download_qf_ax_samples

    source_dir = os.path.join(cache_dir, 'qf_ax', source)

    if not os.path.exists(source_dir):
        print(f"{source} benchmarks not found.")
        if source == 'samples':
            print("Creating samples...")
            download_qf_ax_samples(cache_dir, max_files=max_tests or 10)
        elif source == 'qf_ax_curated':
            print("Creating curated set...")
            from benchmarks.curators import create_qf_ax_curated_set
            create_qf_ax_curated_set(cache_dir)
        else:
            print(f"ERROR: QF_AX source {source} not found")
            return []

    if not os.path.exists(source_dir):
        print(f"ERROR: Could not find or create {source}")
        return []

    files = sorted([f for f in os.listdir(source_dir) if f.endswith('.smt2')])
    if max_tests:
        files = files[:max_tests]

    print(f"\nRunning QF_AX/{source}: {len(files)} benchmarks")
    print("=" * 80)

    results = []
    for i, filename in enumerate(files, 1):
        result = run_qf_ax_benchmark(cache_dir, source, filename)
        results.append(result)
        status = "✓" if result.correct else "✗"
        print(f"[{i}/{len(files)}] {status} {filename[:50]:<50} {result.time_ms:>6.1f}ms")

    return results
