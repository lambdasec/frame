"""Benchmark Orchestrator - Main coordination class"""

import os
import json
from typing import List, Optional, Union

# Core utilities
from benchmarks.core import (
    BenchmarkResult,
    analyze_results,
    print_summary,
    save_results,
    # SAST
    SASTBenchmarkResult,
    analyze_sast_results,
    print_sast_summary,
)

# Downloaders
from benchmarks.downloaders import (
    download_qf_ax_samples, download_qf_ax_full,
    download_qf_bv_samples, download_qf_bv_full,
    download_qf_s_kaluza, download_qf_s_kaluza_full,
    download_qf_s_pisa, download_qf_s_woorpje,
    download_full_kaluza, download_full_pisa,
    download_full_appscan, download_full_pyex,
    download_slcomp_file, download_slcomp_division,
    # SAST downloaders
    download_owasp_python, create_owasp_python_curated_set,
    download_owasp_java, create_owasp_java_curated_set,
    download_juliet, create_juliet_curated_set,
    download_issueblot, create_issueblot_curated_set,
    download_secbench_js, create_secbench_curated_set,
)

# Runners
from benchmarks.runners import (
    run_qf_ax_benchmark, run_qf_ax_division,
    run_qf_bv_benchmark, run_qf_bv_division,
    run_qf_s_benchmark, run_qf_s_division,
    run_slcomp_benchmark, run_slcomp_division,
    # SAST runners
    run_owasp_python_division,
    run_owasp_java_division,
    run_juliet_division,
    run_issueblot_division,
    run_secbench_js_division,
)

# Curators
from benchmarks.curators import (
    create_qf_s_curated_set,
    create_slcomp_curated_set,
    create_qf_ax_curated_set,
    create_qf_bv_curated_set,
)


class BenchmarkOrchestrator:
    """
    Orchestrates all benchmark operations

    This is a thin facade that delegates to specialized modules.
    Each operation is handled by focused, testable functions.

    Supports two types of benchmarks:
    - SMT benchmarks: SL-COMP, QF_S, QF_AX, QF_BV (entailment checking)
    - SAST benchmarks: OWASP Python/Java, Juliet, IssueBlot, SecBench.js (security scanning)
    """

    def __init__(self, cache_dir: str = "./benchmarks/cache", verbose: bool = False):
        self.cache_dir = cache_dir
        self.verbose = verbose
        os.makedirs(cache_dir, exist_ok=True)
        self.results: List[BenchmarkResult] = []
        self.sast_results: List[SASTBenchmarkResult] = []

    # ========== Downloaders ==========

    def download_qf_ax_samples(self, max_files: Optional[int] = None) -> int:
        """Download QF_AX sample benchmarks"""
        return download_qf_ax_samples(self.cache_dir, max_files)

    def download_qf_ax_full(self) -> int:
        """Download full QF_AX benchmark set"""
        return download_qf_ax_full(self.cache_dir)

    def download_qf_bv_samples(self, max_files: Optional[int] = None) -> int:
        """Download QF_BV sample benchmarks"""
        return download_qf_bv_samples(self.cache_dir, max_files)

    def download_qf_bv_full(self) -> int:
        """Download full QF_BV benchmark set"""
        return download_qf_bv_full(self.cache_dir)

    def download_qf_s_kaluza(self, max_files: Optional[int] = None) -> int:
        """Download QF_S Kaluza benchmarks"""
        return download_qf_s_kaluza(self.cache_dir, max_files)

    def download_qf_s_kaluza_full(self, max_files: Optional[int] = None) -> int:
        """Download full QF_S Kaluza benchmarks"""
        return download_qf_s_kaluza_full(self.cache_dir, max_files)

    def download_qf_s_pisa(self, max_files: Optional[int] = None) -> int:
        """Download QF_S PISA benchmarks"""
        return download_qf_s_pisa(self.cache_dir, max_files)

    def download_qf_s_woorpje(self, max_files: Optional[int] = None) -> int:
        """Download QF_S Woorpje benchmarks"""
        return download_qf_s_woorpje(self.cache_dir, max_files)

    def download_full_kaluza(self) -> int:
        """Download full Kaluza benchmark set"""
        return download_full_kaluza(self.cache_dir)

    def download_full_pisa(self) -> int:
        """Download full PISA benchmark set"""
        return download_full_pisa(self.cache_dir)

    def download_full_appscan(self) -> int:
        """Download full AppScan benchmark set"""
        return download_full_appscan(self.cache_dir)

    def download_full_pyex(self) -> int:
        """Download full PyEx benchmark set"""
        return download_full_pyex(self.cache_dir)

    def download_slcomp_file(self, division: str, filename: str) -> bool:
        """Download a single SL-COMP file"""
        return download_slcomp_file(self.cache_dir, division, filename)

    def download_slcomp_division(self, division: str, max_files: Optional[int] = None) -> int:
        """Download SL-COMP division"""
        return download_slcomp_division(self.cache_dir, division, max_files)

    # ========== Runners ==========

    def run_qf_ax_benchmark(self, source: str, filename: str, full_path: Optional[str] = None) -> BenchmarkResult:
        """Run a single QF_AX benchmark"""
        result = run_qf_ax_benchmark(self.cache_dir, source, filename, full_path)
        self.results.append(result)
        return result

    def run_qf_ax_division(self, source: str, max_tests: Optional[int] = None) -> List[BenchmarkResult]:
        """Run QF_AX division"""
        results = run_qf_ax_division(self.cache_dir, source, max_tests)
        self.results.extend(results)
        return results

    def run_qf_bv_benchmark(self, source: str, filename: str, full_path: Optional[str] = None) -> BenchmarkResult:
        """Run a single QF_BV benchmark"""
        result = run_qf_bv_benchmark(self.cache_dir, source, filename, full_path)
        self.results.append(result)
        return result

    def run_qf_bv_division(self, source: str, max_tests: Optional[int] = None) -> List[BenchmarkResult]:
        """Run QF_BV division"""
        results = run_qf_bv_division(self.cache_dir, source, max_tests)
        self.results.extend(results)
        return results

    def run_qf_s_benchmark(self, source: str, filename: str, full_path: Optional[str] = None) -> BenchmarkResult:
        """Run a single QF_S benchmark"""
        result = run_qf_s_benchmark(self.cache_dir, source, filename, full_path)
        self.results.append(result)
        return result

    def run_qf_s_division(self, source: str, max_tests: Optional[int] = None) -> List[BenchmarkResult]:
        """Run QF_S division"""
        results = run_qf_s_division(self.cache_dir, source, max_tests)
        self.results.extend(results)
        return results

    def run_slcomp_benchmark(self, division: str, filename: str) -> BenchmarkResult:
        """Run a single SL-COMP benchmark"""
        result = run_slcomp_benchmark(self.cache_dir, division, filename, self.verbose)
        self.results.append(result)
        return result

    def run_slcomp_division(self, division: str, max_tests: Optional[int] = None) -> List[BenchmarkResult]:
        """Run SL-COMP division"""
        results = run_slcomp_division(self.cache_dir, division, self.verbose, max_tests)
        self.results.extend(results)
        return results

    # ========== Curators ==========

    def create_qf_s_curated_set(self, sample_size: int = 3300, seed: int = 42) -> int:
        """Create QF_S curated benchmark set"""
        return create_qf_s_curated_set(self.cache_dir, sample_size, seed)

    def create_slcomp_curated_set(self, sample_size: int = 700, seed: int = 42) -> int:
        """Create SL-COMP curated benchmark set"""
        return create_slcomp_curated_set(self.cache_dir, sample_size, seed)

    def create_qf_ax_curated_set(self, sample_size: int = 500, seed: int = 42) -> int:
        """Create QF_AX curated benchmark set"""
        return create_qf_ax_curated_set(self.cache_dir, sample_size, seed)

    def create_qf_bv_curated_set(self, sample_size: int = 250, seed: int = 42) -> int:
        """Create QF_BV curated benchmark set"""
        return create_qf_bv_curated_set(self.cache_dir, sample_size, seed)

    # ========== SAST Downloaders ==========

    def download_owasp_python(self, max_files: Optional[int] = None) -> int:
        """Download OWASP BenchmarkPython"""
        return download_owasp_python(self.cache_dir, max_files)

    def download_owasp_java(self, max_files: Optional[int] = None) -> int:
        """Download OWASP BenchmarkJava"""
        return download_owasp_java(self.cache_dir, max_files)

    def download_juliet(self, max_files: Optional[int] = None) -> int:
        """Download NIST Juliet Test Suite for C/C++"""
        return download_juliet(self.cache_dir, max_files)

    def download_issueblot(self, max_files: Optional[int] = None) -> int:
        """Download IssueBlot.NET for C#"""
        return download_issueblot(self.cache_dir, max_files)

    def download_secbench_js(self, max_files: Optional[int] = None) -> int:
        """Download SecBench.js for JavaScript/TypeScript"""
        return download_secbench_js(self.cache_dir, max_files)

    # ========== SAST Runners ==========

    def run_owasp_python_division(self, division: str = 'owasp_python',
                                   max_tests: Optional[int] = None) -> List[SASTBenchmarkResult]:
        """Run OWASP Python benchmark division"""
        results = run_owasp_python_division(self.cache_dir, division, max_tests)
        self.sast_results.extend(results)
        return results

    def run_owasp_java_division(self, division: str = 'owasp_java',
                                 max_tests: Optional[int] = None) -> List[SASTBenchmarkResult]:
        """Run OWASP Java benchmark division"""
        results = run_owasp_java_division(self.cache_dir, division, max_tests)
        self.sast_results.extend(results)
        return results

    def run_juliet_division(self, division: str = 'juliet',
                            max_tests: Optional[int] = None) -> List[SASTBenchmarkResult]:
        """Run Juliet C/C++ benchmark division"""
        results = run_juliet_division(self.cache_dir, division, max_tests)
        self.sast_results.extend(results)
        return results

    def run_issueblot_division(self, division: str = 'issueblot',
                                max_tests: Optional[int] = None) -> List[SASTBenchmarkResult]:
        """Run IssueBlot.NET C# benchmark division"""
        results = run_issueblot_division(self.cache_dir, division, max_tests)
        self.sast_results.extend(results)
        return results

    def run_secbench_js_division(self, division: str = 'secbench_js',
                                  max_tests: Optional[int] = None) -> List[SASTBenchmarkResult]:
        """Run SecBench.js JavaScript benchmark division"""
        results = run_secbench_js_division(self.cache_dir, division, max_tests)
        self.sast_results.extend(results)
        return results

    # ========== SAST Curators ==========

    def create_owasp_python_curated_set(self, sample_size: int = 500, seed: int = 42) -> int:
        """Create OWASP Python curated benchmark set"""
        return create_owasp_python_curated_set(self.cache_dir, sample_size, seed)

    def create_owasp_java_curated_set(self, sample_size: int = 500, seed: int = 42) -> int:
        """Create OWASP Java curated benchmark set"""
        return create_owasp_java_curated_set(self.cache_dir, sample_size, seed)

    def create_juliet_curated_set(self, sample_size: int = 1000, seed: int = 42) -> int:
        """Create Juliet C/C++ curated benchmark set"""
        return create_juliet_curated_set(self.cache_dir, sample_size, seed)

    def create_issueblot_curated_set(self, sample_size: int = 200, seed: int = 42) -> int:
        """Create IssueBlot.NET C# curated benchmark set"""
        return create_issueblot_curated_set(self.cache_dir, sample_size, seed)

    def create_secbench_js_curated_set(self, sample_size: int = 200, seed: int = 42) -> int:
        """Create SecBench.js JavaScript curated benchmark set"""
        return create_secbench_curated_set(self.cache_dir, sample_size, seed)

    # ========== Analysis ==========

    def analyze_results(self):
        """Analyze accumulated SMT results"""
        return analyze_results(self.results)

    def analyze_sast_results(self):
        """Analyze accumulated SAST results"""
        return analyze_sast_results(self.sast_results)

    def print_summary(self):
        """Print summary of accumulated results"""
        if self.results:
            print_summary(self.results)
        if self.sast_results:
            print_sast_summary(self.sast_results)

    def save_results(self, output_file: str = "benchmark_results.json"):
        """Save accumulated results to JSON"""
        # Save SMT results
        if self.results:
            save_results(self.results, self.cache_dir, output_file)

        # Save SAST results
        if self.sast_results:
            sast_output = output_file.replace('.json', '_sast.json')
            sast_path = os.path.join(self.cache_dir, sast_output)
            analysis = analyze_sast_results(self.sast_results)
            with open(sast_path, 'w') as f:
                json.dump({
                    'summary': analysis,
                    'results': [r.to_dict() for r in self.sast_results]
                }, f, indent=2)
            print(f"SAST results saved to: {sast_path}")


# Backward compatibility alias
UnifiedBenchmarkRunner = BenchmarkOrchestrator
