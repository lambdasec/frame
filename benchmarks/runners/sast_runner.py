"""Unified SAST benchmark runner for all security benchmarks"""

import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Dict

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from benchmarks.core import (
    SASTBenchmarkResult,
    ExpectedVulnerability,
    DetectedVulnerability,
    VulnerabilityCategory,
    analyze_sast_results,
    print_sast_summary,
)
from benchmarks.core.sast_runner import run_frame_scanner, cwe_to_category


def run_sast_benchmark(
    filepath: str,
    expected_vulns: List[ExpectedVulnerability],
    suite: str,
    division: str,
    language: str,
    timeout_ms: int = 30000,
) -> SASTBenchmarkResult:
    """
    Run a single SAST benchmark test case.

    Args:
        filepath: Path to the source file to scan
        expected_vulns: List of expected vulnerabilities (ground truth)
        suite: Benchmark suite name
        division: Specific division/category
        language: Programming language
        timeout_ms: Scanner timeout

    Returns:
        SASTBenchmarkResult with metrics computed
    """
    filename = os.path.basename(filepath)
    start_time = time.time()

    detected, error = run_frame_scanner(filepath, language, timeout_ms)

    elapsed_ms = (time.time() - start_time) * 1000

    result = SASTBenchmarkResult(
        filename=filename,
        suite=suite,
        division=division,
        language=language,
        expected_vulns=expected_vulns,
        detected_vulns=detected,
        time_ms=elapsed_ms,
        error=error,
    )

    result.compute_metrics(match_by_cwe=True)

    return result


def run_owasp_python_division(
    cache_dir: str,
    division: str = 'owasp_python',
    max_tests: Optional[int] = None
) -> List[SASTBenchmarkResult]:
    """Run OWASP Python benchmark division"""
    from benchmarks.downloaders.owasp_python import (
        download_owasp_python,
        create_owasp_python_curated_set,
        load_owasp_python_expected_results,
        get_owasp_python_test_files,
    )

    # Ensure benchmarks are downloaded
    if 'curated' in division:
        test_dir = os.path.join(cache_dir, 'owasp_python', 'owasp_python_curated')
        if not os.path.exists(test_dir):
            create_owasp_python_curated_set(cache_dir)
        test_files = sorted([
            os.path.join(test_dir, f)
            for f in os.listdir(test_dir)
            if f.endswith('.py') and f.startswith('BenchmarkTest')
        ])
    else:
        download_owasp_python(cache_dir)
        test_files = get_owasp_python_test_files(cache_dir)

    expected = load_owasp_python_expected_results(cache_dir)

    return _run_owasp_tests(test_files, expected, 'owasp_python', division, 'python', max_tests)


def run_owasp_java_division(
    cache_dir: str,
    division: str = 'owasp_java',
    max_tests: Optional[int] = None
) -> List[SASTBenchmarkResult]:
    """Run OWASP Java benchmark division"""
    from benchmarks.downloaders.owasp_java import (
        download_owasp_java,
        create_owasp_java_curated_set,
        load_owasp_java_expected_results,
        get_owasp_java_test_files,
    )

    if 'curated' in division:
        test_dir = os.path.join(cache_dir, 'owasp_java', 'owasp_java_curated')
        if not os.path.exists(test_dir):
            create_owasp_java_curated_set(cache_dir)
        test_files = sorted([
            os.path.join(test_dir, f)
            for f in os.listdir(test_dir)
            if f.endswith('.java') and f.startswith('BenchmarkTest')
        ])
    else:
        download_owasp_java(cache_dir)
        test_files = get_owasp_java_test_files(cache_dir)

    expected = load_owasp_java_expected_results(cache_dir)

    return _run_owasp_tests(test_files, expected, 'owasp_java', division, 'java', max_tests)


def _run_owasp_tests(
    test_files: List[str],
    expected: Dict,
    suite: str,
    division: str,
    language: str,
    max_tests: Optional[int]
) -> List[SASTBenchmarkResult]:
    """Helper to run OWASP-style tests"""
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
        ext = '.java' if language == 'java' else '.py'
        test_name = os.path.basename(filepath).replace(ext, '')
        expected_info = expected.get(test_name, {})

        # Build expected vulnerabilities
        expected_vulns = []
        if expected_info.get('vulnerable', False):
            cwe = expected_info.get('cwe', '')
            if cwe:
                expected_vulns.append(ExpectedVulnerability(
                    cwe_id=f"CWE-{cwe}" if not cwe.startswith('CWE') else cwe,
                    category=cwe_to_category(cwe),
                ))

        result = run_sast_benchmark(filepath, expected_vulns, suite, division, language)
        results.append(result)

        _print_progress(i, total, result)

    return results


def run_juliet_division(
    cache_dir: str,
    division: str = 'juliet',
    max_tests: Optional[int] = None
) -> List[SASTBenchmarkResult]:
    """Run Juliet C/C++ benchmark division"""
    from benchmarks.downloaders.juliet import (
        download_juliet,
        create_juliet_curated_set,
        get_juliet_test_files,
        parse_juliet_testcase,
    )

    if 'curated' in division:
        test_dir = os.path.join(cache_dir, 'juliet', 'juliet_curated')
        if not os.path.exists(test_dir):
            create_juliet_curated_set(cache_dir)
        test_files = sorted([
            os.path.join(test_dir, f)
            for f in os.listdir(test_dir)
            if f.endswith(('.c', '.cpp'))
        ])
    else:
        download_juliet(cache_dir)
        test_files = get_juliet_test_files(cache_dir)

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
        cwe_id, is_vuln, lang = parse_juliet_testcase(filepath)

        expected_vulns = []
        if is_vuln:
            expected_vulns.append(ExpectedVulnerability(
                cwe_id=cwe_id,
                category=cwe_to_category(cwe_id.replace('CWE-', '')),
            ))

        result = run_sast_benchmark(filepath, expected_vulns, 'juliet', division, lang)
        results.append(result)

        _print_progress(i, total, result)

    return results


def run_issueblot_division(
    cache_dir: str,
    division: str = 'issueblot',
    max_tests: Optional[int] = None
) -> List[SASTBenchmarkResult]:
    """Run IssueBlot.NET C# benchmark division"""
    from benchmarks.downloaders.issueblot import (
        download_issueblot,
        create_issueblot_curated_set,
        get_issueblot_test_files,
        parse_issueblot_testcase,
    )

    if 'curated' in division:
        test_dir = os.path.join(cache_dir, 'issueblot', 'issueblot_curated')
        if not os.path.exists(test_dir):
            create_issueblot_curated_set(cache_dir)
        test_files = sorted([
            os.path.join(test_dir, f)
            for f in os.listdir(test_dir)
            if f.endswith('.cs')
        ])
    else:
        download_issueblot(cache_dir)
        test_files = get_issueblot_test_files(cache_dir)

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
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        cwe_id, is_vuln, cwes = parse_issueblot_testcase(filepath, content)

        expected_vulns = []
        if is_vuln:
            for cwe in cwes:
                expected_vulns.append(ExpectedVulnerability(
                    cwe_id=cwe,
                    category=cwe_to_category(cwe.replace('CWE-', '')),
                ))

        result = run_sast_benchmark(filepath, expected_vulns, 'issueblot', division, 'csharp')
        results.append(result)

        _print_progress(i, total, result)

    return results


def run_secbench_js_division(
    cache_dir: str,
    division: str = 'secbench_js',
    max_tests: Optional[int] = None
) -> List[SASTBenchmarkResult]:
    """Run SecBench.js JavaScript benchmark division"""
    from benchmarks.downloaders.secbench_js import (
        download_secbench_js,
        create_secbench_curated_set,
        get_secbench_test_files,
        load_secbench_manifest,
    )

    if 'curated' in division:
        test_dir = os.path.join(cache_dir, 'secbench_js', 'secbench_js_curated')
        if not os.path.exists(test_dir):
            create_secbench_curated_set(cache_dir)
        test_files = sorted([
            os.path.join(test_dir, f)
            for f in os.listdir(test_dir)
            if f.endswith(('.js', '.ts'))
        ])
    else:
        download_secbench_js(cache_dir)
        test_files = get_secbench_test_files(cache_dir)

    manifest = load_secbench_manifest(cache_dir)
    src_dir = os.path.join(cache_dir, 'secbench_js', 'src')

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
        # Get expected vulnerabilities from manifest
        rel_path = os.path.relpath(filepath, src_dir) if src_dir in filepath else os.path.basename(filepath)
        file_info = manifest.get('files', {}).get(rel_path, {})

        # For curated files (e.g., 0039_juice_shop_unionSqlInjectionChallenge_1.ts),
        # we need to search for the original filename in manifest keys
        if not file_info and 'curated' in division:
            basename = os.path.basename(filepath)
            # Skip the numeric prefix (NNNN_) and try progressively shorter suffixes
            # This handles source names with underscores (e.g., juice_shop)
            # Format: NNNN_source_originalfilename.ext
            for idx in range(5, len(basename)):  # Start after "NNNN_"
                if basename[idx] == '_':
                    possible_suffix = basename[idx + 1:]
                    for manifest_key in manifest.get('files', {}):
                        if manifest_key.endswith(possible_suffix):
                            file_info = manifest['files'][manifest_key]
                            break
                    if file_info:
                        break

        expected_vulns = []
        for vuln in file_info.get('vulnerabilities', []):
            cwe = vuln.get('cwe', 'unknown')
            expected_vulns.append(ExpectedVulnerability(
                cwe_id=cwe,
                category=cwe_to_category(cwe.replace('CWE-', '')),
                line_number=vuln.get('line'),
            ))

        lang = 'typescript' if filepath.endswith('.ts') else 'javascript'
        result = run_sast_benchmark(filepath, expected_vulns, 'secbench_js', division, lang)
        results.append(result)

        _print_progress(i, total, result)

    return results


def _print_progress(i: int, total: int, result: SASTBenchmarkResult):
    """Print progress indicator"""
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
