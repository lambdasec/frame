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


def run_secbench_real_division(
    cache_dir: str,
    division: str = 'secbench',
    categories: Optional[List[str]] = None,
    max_per_cat: Optional[int] = None,
) -> Dict:
    """Run the real SecBench.js benchmark (Staicu et al., ICSE 2023).

    Scans each vulnerable package's ground-truth sink file in library mode
    (exported-function params are untrusted) and checks for the category's CWE
    (recall); scans the patched version's same file for precision. Returns a
    dict of per-category and overall TP/FP/FN/precision/recall.
    """
    from benchmarks.downloaders.secbench_real import (
        get_secbench_real_entries, CATEGORY_CWE,
    )
    from frame.sil import FrameScanner

    entries = get_secbench_real_entries(
        cache_dir, categories=categories, max_per_cat=max_per_cat)

    # vuln_type substrings that count as a match for each category. SecBench's
    # "code-injection" set is Arbitrary Code Execution, which includes exec-based
    # RCE -- Frame reports those as command_injection, an equally correct label.
    CAT_MATCH = {
        'command-injection': ('command_injection',),
        'code-injection': ('code_injection', 'command_injection'),
        'path-traversal': ('path_traversal',),
        'prototype-pollution': ('prototype_pollution',),
        'redos': ('regex_dos',),
    }

    def scan(path: str):
        if not path:
            return None
        lang = 'typescript' if path.endswith('.ts') else 'javascript'
        try:
            sc = FrameScanner(language=lang, verify=False, library_mode=True)
            res = sc.scan_file(path)
            return {v.type.value for v in res.vulnerabilities}
        except Exception:
            return set()

    cats = {c: {'tp': 0, 'fp': 0, 'fn': 0, 'neg': 0, 'skip': 0} for c in CATEGORY_CWE}
    print(f"\nRunning {division}: {len(entries)} real vulnerabilities")
    print("=" * 80)
    for i, e in enumerate(entries, 1):
        cat = e['category']
        want = CAT_MATCH[cat]
        if not e['vuln_file']:
            cats[cat]['skip'] += 1
            continue
        found = scan(e['vuln_file'])
        hit = any(w in t for t in found for w in want)
        if hit:
            cats[cat]['tp'] += 1
        else:
            cats[cat]['fn'] += 1
        # Precision: the patched version must NOT flag the same category.
        if e['fixed_file']:
            cats[cat]['neg'] += 1
            pf = scan(e['fixed_file'])
            patched_flags = any(w in t for t in pf for w in want)
            if patched_flags and cat == 'redos':
                # A static ReDoS detector cannot see runtime length-cap fixes, so
                # only count an FP when the patch actually changed the flagged
                # regex (the patched file flags a pattern absent from the vuln
                # file). An unchanged catastrophic regex is not a spurious flag.
                from frame.sil.frontends.javascript_frontend import JavaScriptFrontend
                fe = JavaScriptFrontend()
                vuln_pats = fe.redos_patterns(
                    open(e['vuln_file'], encoding='utf-8', errors='ignore').read()
                ) if e['vuln_file'] else set()
                patched_pats = fe.redos_patterns(
                    open(e['fixed_file'], encoding='utf-8', errors='ignore').read())
                patched_flags = bool(patched_pats - vuln_pats)
            if patched_flags:
                cats[cat]['fp'] += 1
        if i % 25 == 0:
            print(f"  [{i}/{len(entries)}] processed")

    overall = {'tp': 0, 'fp': 0, 'fn': 0, 'neg': 0, 'skip': 0}
    print("\nSecBench.js results by category:")
    for c, d in cats.items():
        for k in overall:
            overall[k] += d[k]
        tp, fp, fn = d['tp'], d['fp'], d['fn']
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / d['neg'] if d['neg'] else 0.0
        d['precision'], d['recall'], d['score'] = p, r, r - fpr
        print(f"  {c:22} TP={tp:3} FP={fp:3} FN={fn:3} skip={d['skip']:3} "
              f"P={p:.0%} R={r:.0%} TPR-FPR={r - fpr:+.0%}")
    tp, fp, fn = overall['tp'], overall['fp'], overall['fn']
    overall['precision'] = tp / (tp + fp) if (tp + fp) else 0.0
    overall['recall'] = tp / (tp + fn) if (tp + fn) else 0.0
    o_fpr = fp / overall['neg'] if overall['neg'] else 0.0
    overall['score'] = overall['recall'] - o_fpr
    print(f"  {'OVERALL':22} TP={tp:3} FP={fp:3} FN={fn:3} skip={overall['skip']:3} "
          f"P={overall['precision']:.0%} R={overall['recall']:.0%} "
          f"TPR-FPR={overall['score']:+.0%}")
    return {'by_category': cats, 'overall': overall}


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
