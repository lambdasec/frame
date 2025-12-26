"""OWASP BenchmarkPython runner"""

import os
import sys
import time
from pathlib import Path
from typing import List, Optional

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from benchmarks.core import (
    SASTBenchmarkResult,
    ExpectedVulnerability,
    DetectedVulnerability,
    VulnerabilityCategory,
)
from benchmarks.core.sast_runner import run_frame_scanner, cwe_to_category
from benchmarks.downloaders.owasp_python import (
    download_owasp_python,
    load_owasp_python_expected_results,
    get_owasp_python_test_files,
)


def run_owasp_python_benchmark(
    cache_dir: str,
    filepath: str,
    expected_info: dict,
    timeout_ms: int = 30000
) -> SASTBenchmarkResult:
    """
    Run a single OWASP Python benchmark test case.

    Args:
        cache_dir: Cache directory
        filepath: Path to the test file
        expected_info: Expected vulnerability info from CSV
        timeout_ms: Scanner timeout

    Returns:
        SASTBenchmarkResult with metrics
    """
    filename = os.path.basename(filepath)
    start_time = time.time()

    # Build expected vulnerabilities from ground truth
    expected_vulns = []
    if expected_info.get('vulnerable', False):
        cwe = expected_info.get('cwe', '')
        if cwe:
            expected_vulns.append(ExpectedVulnerability(
                cwe_id=f"CWE-{cwe}" if not cwe.startswith('CWE') else cwe,
                category=cwe_to_category(cwe),
                description=expected_info.get('category', ''),
            ))

    # Run scanner (verify=False for benchmarking to measure detection capability)
    detected, error = run_frame_scanner(filepath, language='python', timeout_ms=timeout_ms, verify=False)

    elapsed_ms = (time.time() - start_time) * 1000

    result = SASTBenchmarkResult(
        filename=filename,
        suite='owasp_python',
        division='owasp_python',
        language='python',
        expected_vulns=expected_vulns,
        detected_vulns=detected,
        time_ms=elapsed_ms,
        error=error,
    )

    # Compute TP/FP/FN
    result.compute_metrics(match_by_cwe=True)

    return result


def run_owasp_python_division(
    cache_dir: str,
    division: str = 'owasp_python',
    max_tests: Optional[int] = None
) -> List[SASTBenchmarkResult]:
    """
    Run OWASP Python benchmark division.

    Args:
        cache_dir: Cache directory
        division: Division name ('owasp_python' or 'owasp_python_curated')
        max_tests: Maximum number of tests to run

    Returns:
        List of SASTBenchmarkResult
    """
    # Ensure benchmarks are downloaded
    if 'curated' in division:
        test_dir = os.path.join(cache_dir, 'owasp_python', 'owasp_python_curated')
        if not os.path.exists(test_dir):
            from benchmarks.downloaders.owasp_python import create_owasp_python_curated_set
            create_owasp_python_curated_set(cache_dir)
    else:
        download_owasp_python(cache_dir)
        test_dir = os.path.join(cache_dir, 'owasp_python', 'src')

    # Load expected results
    expected = load_owasp_python_expected_results(cache_dir)

    # Get test files
    if 'curated' in division:
        test_files = sorted([
            os.path.join(test_dir, f)
            for f in os.listdir(test_dir)
            if f.endswith('.py') and f.startswith('BenchmarkTest')
        ])
    else:
        test_files = get_owasp_python_test_files(cache_dir)

    if max_tests:
        test_files = test_files[:max_tests]

    if not test_files:
        print(f"No test files found for {division}")
        return []

    print(f"\nRunning {division}: {len(test_files)} benchmarks")
    print("=" * 80)

    results = []
    total = len(test_files)

    for i, filepath in enumerate(test_files, 1):
        test_name = os.path.basename(filepath).replace('.py', '')
        expected_info = expected.get(test_name, {})

        result = run_owasp_python_benchmark(
            cache_dir, filepath, expected_info
        )
        results.append(result)

        # Progress indicator
        status = "✓" if result.correct else "✗"
        if total > 100:
            progress_pct = (i / total) * 100
            print(f"[{i}/{total} {progress_pct:5.1f}%] {status} {result.filename[:40]:<40} "
                  f"TP:{result.true_positives} FP:{result.false_positives} FN:{result.false_negatives} "
                  f"{result.time_ms:>6.1f}ms")
        else:
            print(f"[{i}/{total}] {status} {result.filename[:40]:<40} "
                  f"TP:{result.true_positives} FP:{result.false_positives} FN:{result.false_negatives} "
                  f"{result.time_ms:>6.1f}ms")

    return results
