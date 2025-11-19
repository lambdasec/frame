"""QF_S benchmark runner"""

import os
import time
from pathlib import Path
from typing import List, Optional

from benchmarks.core import BenchmarkResult, run_smt2_with_z3, parse_smt2_expected


def run_qf_s_benchmark(cache_dir: str, source: str, filename: str,
                       full_path: Optional[str] = None) -> BenchmarkResult:
    """Run a single QF_S benchmark via Z3 directly

    Args:
        cache_dir: Cache directory base path
        source: Source name (kaluza, pisa, etc. or qf_s_full)
        filename: Display filename
        full_path: Optional full path to file (used for qf_s_full)
    """
    if full_path:
        filepath = full_path
    else:
        filepath = os.path.join(cache_dir, 'qf_s', source, filename)

    if not os.path.exists(filepath):
        return BenchmarkResult(
            filename=filename,
            suite='qf_s',
            division=source,
            expected='unknown',
            actual='error',
            time_ms=0.0,
            error='File not found'
        )

    # Parse expected result
    expected = parse_smt2_expected(filepath) or 'unknown'

    # Run via Z3 directly (QF_S is pure SMT-LIB 2.6 format)
    start_time = time.time()
    actual, error = run_smt2_with_z3(filepath, timeout=10)
    time_ms = (time.time() - start_time) * 1000

    return BenchmarkResult(
        filename=filename,
        suite='qf_s',
        division=source,
        expected=expected,
        actual=actual,
        time_ms=time_ms,
        error=error
    )


def run_qf_s_division(cache_dir: str, source: str,
                      max_tests: Optional[int] = None) -> List[BenchmarkResult]:
    """Run all QF_S benchmarks in a source"""
    from benchmarks.downloaders import download_qf_s_kaluza, download_full_kaluza

    # Special handling for qf_s_full (recursive search in different directory)
    if source == 'qf_s_full':
        qf_s_full_dir = os.path.join(cache_dir, 'qf_s_full')

        if not os.path.exists(qf_s_full_dir):
            print(f"\n{source} benchmarks not found. Downloading...")
            count = download_full_kaluza(cache_dir)
            if count == 0:
                print(f"ERROR: Failed to download {source}")
                return []

        # Recursively find all .smt2 files
        file_paths = sorted(list(Path(qf_s_full_dir).rglob('*.smt2')))
        if max_tests:
            file_paths = file_paths[:max_tests]

        print(f"\nRunning QF_S/{source}: {len(file_paths)} benchmarks")
        print("=" * 80)

        results = []
        total = len(file_paths)

        for i, file_path in enumerate(file_paths, 1):
            # Get relative path for display
            rel_path = file_path.relative_to(qf_s_full_dir)
            display_name = str(rel_path)

            result = run_qf_s_benchmark(cache_dir, source, display_name, full_path=str(file_path))
            results.append(result)

            status = "✓" if result.correct else "✗"

            # Progress indicator with percentage for large sets
            if total > 100:
                progress_pct = (i / total) * 100
                print(f"[{i}/{total} {progress_pct:5.1f}%] {status} {display_name[:50]:<50} {result.time_ms:>6.1f}ms")
            else:
                print(f"[{i}/{total}] {status} {display_name[:50]:<50} {result.time_ms:>6.1f}ms")

        return results

    # Normal handling for samples (flat directory structure)
    source_dir = os.path.join(cache_dir, 'qf_s', source)

    if not os.path.exists(source_dir):
        if source == 'kaluza':
            print(f"Kaluza benchmarks not found. Downloading samples...")
            download_qf_s_kaluza(cache_dir, max_files=max_tests or 10)
        else:
            print(f"ERROR: QF_S source {source} not found")
            return []

    if not os.path.exists(source_dir):
        print(f"ERROR: Could not find or download {source}")
        return []

    files = sorted([f for f in os.listdir(source_dir) if f.endswith('.smt2')])
    if max_tests:
        files = files[:max_tests]

    print(f"\nRunning QF_S/{source}: {len(files)} benchmarks")
    print("=" * 80)

    results = []
    for i, filename in enumerate(files, 1):
        result = run_qf_s_benchmark(cache_dir, source, filename)
        results.append(result)
        status = "✓" if result.correct else "✗"
        print(f"[{i}/{len(files)}] {status} {filename[:50]:<50} {result.time_ms:>6.1f}ms")

    return results
