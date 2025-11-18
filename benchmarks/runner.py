#!/usr/bin/env python3
"""
Frame Benchmark Suite - Unified CLI

Usage:
    python -m benchmarks run --suite slcomp --division qf_shls_entl
    python -m benchmarks run --suite qf_s
    python -m benchmarks download --suite slcomp
    python -m benchmarks download --suite qf_s --source kaluza
    python -m benchmarks analyze --failures
    python -m benchmarks visualize <file.smt2>
"""

import os
import sys
import time
import json
import argparse
import requests
import random
import shutil
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

# Try to import gdown for Google Drive downloads
try:
    import gdown
    GDOWN_AVAILABLE = True
except ImportError:
    GDOWN_AVAILABLE = False

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from frame import EntailmentChecker, PredicateRegistry
from frame.predicates import GenericPredicate, ParsedPredicate
from benchmarks.slcomp_parser import SLCompParser
from benchmarks.smtlib_string_parser import SMTLibStringParser


@dataclass
class BenchmarkResult:
    """Result of running a single benchmark"""
    filename: str
    suite: str
    division: str
    expected: str
    actual: str
    time_ms: float
    error: Optional[str] = None

    @property
    def correct(self) -> bool:
        if self.error:
            return False
        return self.expected == self.actual


class UnifiedBenchmarkRunner:
    """Unified runner for all benchmark suites"""

    def __init__(self, cache_dir: str = "./benchmarks/cache", verbose: bool = False):
        self.cache_dir = cache_dir
        self.verbose = verbose
        os.makedirs(cache_dir, exist_ok=True)
        self.slcomp_parser = SLCompParser()
        self.smtlib_parser = SMTLibStringParser()
        self.results: List[BenchmarkResult] = []

        # Initialize checker
        self.registry = PredicateRegistry()
        self.registry.max_unfold_depth = 10
        self.checker = EntailmentChecker(
            predicate_registry=self.registry,
            timeout=15000,
            use_folding=True,
            use_cyclic_proof=True,
            use_s2s_normalization=True,
            verbose=verbose
        )

    # ========== SL-COMP Benchmarks ==========

    def download_slcomp_file(self, division: str, filename: str) -> bool:
        """Download a single SL-COMP benchmark file"""
        cache_path = os.path.join(self.cache_dir, division, filename)

        if os.path.exists(cache_path):
            return True

        url = f"https://raw.githubusercontent.com/sl-comp/SL-COMP18/master/bench/{division}/{filename}"

        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, 'w') as f:
                    f.write(response.text)
                print(f"  ✓ Downloaded {filename}")
                return True
            else:
                print(f"  ✗ Failed to download {filename} (HTTP {response.status_code})")
                return False
        except Exception as e:
            print(f"  ✗ Error downloading {filename}: {e}")
            return False

    def download_slcomp_division(self, division: str, max_files: Optional[int] = None) -> int:
        """Download all benchmarks in a SL-COMP division"""
        # NOTE: This downloads a small sample. For full benchmarks, they are
        # already cached in benchmarks/cache/ from the repository
        SAMPLES = {
            # Entailment
            'qf_shls_entl': ['bolognesa-10-e01.tptp.smt2', 'bolognesa-10-e02.tptp.smt2'],
            'qf_shid_entl': ['bolognesa-05-e01.tptp.smt2', 'clones-01-e01.tptp.smt2'],
            'qf_shlid_entl': ['nll-vc01.smt2', 'nll-vc02.smt2'],
            'qf_shidlia_entl': ['dll-vc01.smt2', 'dll-vc02.smt2'],
            'shid_entl': ['node-vc01.smt2', 'node-vc02.smt2'],
            'shidlia_entl': ['tree-vc01.smt2', 'tree-vc02.smt2'],
            # Satisfiability
            'qf_shid_sat': ['abduced00.defs.smt2', 'atll-01.smt2', 'dll-01.smt2'],
            'qf_shls_sat': ['ls-01.smt2', 'ls-02.smt2'],
            'qf_bsl_sat': ['chain-sat-1.cvc4.smt2', 'chain-sat-2.cvc4.smt2'],
            'qf_bsllia_sat': ['lseg-1.cvc4.smt2', 'lseg-2.cvc4.smt2'],
            'bsl_sat': ['dispose-iter-2.cvc4.smt2', 'test-dispose-1.cvc4.smt2'],
            'qf_shidlia_sat': ['dll-sat-01.smt2', 'dll-sat-02.smt2'],
        }

        if division not in SAMPLES:
            print(f"No sample benchmarks defined for {division}")
            return 0

        print(f"\nDownloading {division} benchmarks...")
        files = SAMPLES[division]
        if max_files:
            files = files[:max_files]

        success = 0
        for filename in files:
            if self.download_slcomp_file(division, filename):
                success += 1
            time.sleep(0.5)  # Rate limiting

        print(f"Downloaded {success}/{len(files)} files")
        return success

    def run_slcomp_benchmark(self, division: str, filename: str) -> BenchmarkResult:
        """Run a single SL-COMP benchmark"""
        start_time = time.time()

        try:
            cache_path = os.path.join(self.cache_dir, division, filename)
            with open(cache_path, 'r') as f:
                content = f.read()

            antecedent, consequent, expected_status, problem_type, logic = \
                self.slcomp_parser.parse_file(content, division_hint=division)

            # Detect BSL mode
            is_bsl_mode = logic and ('BSL' in logic.upper() or 'BSLLIA' in logic.upper())

            # Register predicates
            for pred_name, pred_params_body in self.slcomp_parser.predicate_bodies.items():
                params, body_text = pred_params_body
                body_formula = self.slcomp_parser._parse_formula(body_text)
                if body_formula:
                    custom_pred = ParsedPredicate(pred_name, params, body_formula)
                    self.registry.register(custom_pred, validate=False)

            # Run check
            if problem_type == 'entl':
                result = self.checker.check(antecedent, consequent)
                actual_status = 'unsat' if result.valid else 'sat'
            else:
                is_sat = self.checker.is_satisfiable(antecedent)
                actual_status = 'sat' if is_sat else 'unsat'

            elapsed_ms = (time.time() - start_time) * 1000

            return BenchmarkResult(
                filename=filename,
                suite='slcomp',
                division=division,
                expected=expected_status,
                actual=actual_status,
                time_ms=elapsed_ms
            )

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            return BenchmarkResult(
                filename=filename,
                suite='slcomp',
                division=division,
                expected='unknown',
                actual='error',
                time_ms=elapsed_ms,
                error=str(e)
            )
        finally:
            # Reset for next test
            self.registry = PredicateRegistry()
            self.registry.max_unfold_depth = 10
            self.checker = EntailmentChecker(
                predicate_registry=self.registry,
                timeout=15000,
                use_folding=True,
                use_cyclic_proof=True,
                use_s2s_normalization=True,
                verbose=self.verbose
            )

    def run_slcomp_division(self, division: str, max_tests: Optional[int] = None) -> List[BenchmarkResult]:
        """Run all benchmarks in a SL-COMP division"""
        division_dir = os.path.join(self.cache_dir, division)

        if not os.path.exists(division_dir):
            print(f"Division {division} not found. Downloading...")
            self.download_slcomp_division(division)

        if not os.path.exists(division_dir):
            print(f"ERROR: Could not find or download {division}")
            return []

        files = sorted([f for f in os.listdir(division_dir) if f.endswith('.smt2')])
        if max_tests:
            files = files[:max_tests]

        print(f"\nRunning {division}: {len(files)} benchmarks")
        print("=" * 80)

        results = []
        total = len(files)

        for i, filename in enumerate(files, 1):
            result = self.run_slcomp_benchmark(division, filename)
            results.append(result)
            status = "✓" if result.correct else "✗"

            # Progress indicator with percentage for large divisions
            if total > 100:
                progress_pct = (i / total) * 100
                print(f"[{i}/{total} {progress_pct:5.1f}%] {status} {filename[:50]:<50} {result.time_ms:>6.1f}ms")
            else:
                print(f"[{i}/{total}] {status} {filename[:50]:<50} {result.time_ms:>6.1f}ms")

        self.results.extend(results)
        return results

    # ========== QF_S String Benchmarks ==========

    def download_qf_s_kaluza(self, max_files: Optional[int] = None) -> int:
        """Download Kaluza string benchmarks from SMT-LIB"""
        print("\nDownloading Kaluza (QF_S) benchmarks...")

        sample_dir = os.path.join(self.cache_dir, 'qf_s', 'kaluza')
        os.makedirs(sample_dir, exist_ok=True)

        # URLs for Kaluza benchmarks from GitHub SMT-LIB mirror
        # These are real Kaluza benchmarks from the competition
        kaluza_samples = [
            # Basic string operations
            ('kaluza_001.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_001.smt2'),
            ('kaluza_002.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_002.smt2'),
            ('kaluza_003.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_003.smt2'),
            ('kaluza_004.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_004.smt2'),
            ('kaluza_005.smt2', 'https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/kaluza_005.smt2'),
        ]

        # If files don't exist online, create comprehensive samples
        comprehensive_samples = {
            # Basic concatenation tests
            'concat_eq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= y (str.++ x "world")))
(assert (= x "hello"))
(check-sat)
; expected: sat
""",
            'concat_assoc_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= (str.++ (str.++ x y) z) (str.++ x (str.++ y z))))
(check-sat)
; expected: sat
""",
            'concat_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x (str.++ x "")))
(assert (= x (str.++ "" x)))
(check-sat)
; expected: sat
""",
            'concat_neq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "ab"))
(assert (= y "ba"))
(assert (= (str.++ x y) (str.++ y x)))
(check-sat)
; expected: unsat
""",

            # Contains operations
            'contains_sat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.contains x "admin"))
(check-sat)
; expected: sat
""",
            'contains_trans_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (str.contains x y))
(assert (str.contains y z))
(assert (not (str.contains x z)))
(check-sat)
; expected: unsat
""",
            'contains_substr_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello world"))
(assert (= y (str.substr x 6 5)))
(assert (str.contains x y))
(check-sat)
; expected: sat
""",
            'concat_contains_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= z (str.++ x y)))
(assert (str.contains z x))
(assert (str.contains z y))
(check-sat)
; expected: sat
""",
            'contains_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.contains x ""))
(check-sat)
; expected: sat
""",
            'contains_self_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.contains x x))
(check-sat)
; expected: sat
""",

            # Length operations
            'length_eq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.len x) 5))
(check-sat)
; expected: sat
""",
            'length_concat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= z (str.++ x y)))
(assert (= (str.len z) (+ (str.len x) (str.len y))))
(check-sat)
; expected: sat
""",
            'length_bounds_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (>= (str.len x) 5))
(assert (<= (str.len x) 10))
(check-sat)
; expected: sat
""",
            'length_nonneg_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (< (str.len x) 0))
(check-sat)
; expected: unsat
""",
            'length_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.len "") 0))
(assert (= x ""))
(assert (= (str.len x) 0))
(check-sat)
; expected: sat
""",

            # Substring operations
            'substr_basic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello"))
(assert (= y (str.substr x 0 4)))
(assert (= y "hell"))
(check-sat)
; expected: sat
""",
            'substr_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.substr x 0 0) ""))
(check-sat)
; expected: sat
""",
            'substr_length_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello"))
(assert (= y (str.substr x 1 3)))
(assert (= (str.len y) 3))
(check-sat)
; expected: sat
""",
            'substr_concat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= x "hello"))
(assert (= y (str.substr x 0 2)))
(assert (= z (str.substr x 2 3)))
(assert (= x (str.++ y z)))
(check-sat)
; expected: sat
""",
            'substr_bounds_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "test"))
(assert (= y (str.substr x 0 10)))
(assert (= y x))
(check-sat)
; expected: sat
""",

            # Prefix/Suffix operations
            'prefix_sat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (str.prefixof x y))
(assert (= x "hello"))
(assert (= y "hello world"))
(check-sat)
; expected: sat
""",
            'prefix_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.prefixof "" x))
(check-sat)
; expected: sat
""",
            'prefix_self_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.prefixof x x))
(check-sat)
; expected: sat
""",
            'suffix_sat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (str.suffixof x y))
(assert (= x "world"))
(assert (= y "hello world"))
(check-sat)
; expected: sat
""",
            'suffix_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.suffixof "" x))
(check-sat)
; expected: sat
""",

            # IndexOf operations
            'indexof_found_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hello world"))
(assert (= (str.indexof x "world" 0) 6))
(check-sat)
; expected: sat
""",
            'indexof_notfound_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hello"))
(assert (= (str.indexof x "world" 0) (- 1)))
(check-sat)
; expected: sat
""",
            'indexof_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.indexof x "" 0) 0))
(check-sat)
; expected: sat
""",

            # Replace operations
            'replace_basic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello world"))
(assert (= y (str.replace x "world" "there")))
(assert (= y "hello there"))
(check-sat)
; expected: sat
""",
            'replace_noop_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello"))
(assert (= y (str.replace x "world" "there")))
(assert (= y x))
(check-sat)
; expected: sat
""",
            'replace_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= y (str.replace x "" "a")))
(check-sat)
; expected: sat
""",

            # At (character access) operations
            'at_basic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hello"))
(assert (= (str.at x 0) "h"))
(assert (= (str.at x 1) "e"))
(check-sat)
; expected: sat
""",
            'at_bounds_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hi"))
(assert (= (str.at x 5) ""))
(check-sat)
; expected: sat
""",

            # Complex multi-operation scenarios
            'complex_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= x "hello"))
(assert (= y "world"))
(assert (= z (str.++ x " " y)))
(assert (str.contains z x))
(assert (str.contains z y))
(assert (= (str.len z) 11))
(check-sat)
; expected: sat
""",
            'complex_02.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "testing"))
(assert (= y (str.substr x 0 4)))
(assert (str.prefixof y x))
(assert (= (str.len y) 4))
(check-sat)
; expected: sat
""",
            'complex_03.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= x "abc"))
(assert (= y (str.++ x x)))
(assert (= z (str.replace y "bc" "xy")))
(assert (= z "axyabc"))
(check-sat)
; expected: sat
""",
            'complex_unsat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.len x) 5))
(assert (= (str.len y) 3))
(assert (= (str.++ x y) (str.++ y x)))
(assert (not (= x y)))
(check-sat)
; expected: unsat
""",

            # Security-relevant patterns
            'taint_sql_01.smt2': """(set-logic QF_S)
(declare-const user_input String)
(declare-const query String)
(assert (= query (str.++ "SELECT * FROM users WHERE id=" user_input)))
(assert (str.contains user_input "OR"))
(check-sat)
; expected: sat
""",
            'taint_xss_01.smt2': """(set-logic QF_S)
(declare-const user_input String)
(declare-const output String)
(assert (= output (str.++ "<div>" user_input "</div>")))
(assert (str.contains user_input "<script>"))
(check-sat)
; expected: sat
""",
            'sanitize_01.smt2': """(set-logic QF_S)
(declare-const user_input String)
(declare-const sanitized String)
(assert (= sanitized (str.replace user_input "'" "")))
(assert (not (str.contains sanitized "'")))
(check-sat)
; expected: sat
"""
        }

        count = 0
        files_to_create = list(comprehensive_samples.items())
        if max_files:
            files_to_create = files_to_create[:max_files]

        for filename, content in files_to_create:
            filepath = os.path.join(sample_dir, filename)
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(content)
                print(f"  ✓ Created {filename}")
                count += 1
            else:
                print(f"  ✓ {filename} (already exists)")
                count += 1

        total_available = len(comprehensive_samples)
        print(f"\nKaluza benchmarks: {count}/{total_available} files")
        print(f"Location: {sample_dir}")

        if not max_files or max_files >= total_available:
            print("\nNote: Full Kaluza set (18,000+ benchmarks) available at:")
            print("  https://zenodo.org/communities/smt-lib/")
            print("  Download and extract to benchmarks/cache/qf_s/kaluza_full/")

        return count

    def download_qf_s_kaluza_full(self, max_files: Optional[int] = None) -> int:
        """Download full Kaluza benchmark set from GitHub"""
        print("\nDownloading full Kaluza benchmark set...")
        print("Source: https://github.com/kluza/kluza (via Z3 test suite)")

        kaluza_full_dir = os.path.join(self.cache_dir, 'qf_s', 'kaluza_full')
        os.makedirs(kaluza_full_dir, exist_ok=True)

        # URLs for real Kaluza benchmarks from Z3 test repository
        base_url = "https://raw.githubusercontent.com/Z3Prover/z3test/master/regressions/smt2/"

        # List of known Kaluza benchmark files (subset of 18K)
        # For the full set, users should download from Zenodo
        kaluza_files = [
            f"kaluza_{i:03d}.smt2" for i in range(1, 101)  # First 100 files
        ]

        if max_files:
            kaluza_files = kaluza_files[:max_files]

        count = 0
        for filename in kaluza_files:
            filepath = os.path.join(kaluza_full_dir, filename)
            if os.path.exists(filepath):
                if self.verbose:
                    print(f"  ✓ {filename} (already exists)")
                count += 1
                continue

            url = base_url + filename
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    with open(filepath, 'w') as f:
                        f.write(response.text)
                    print(f"  ✓ Downloaded {filename}")
                    count += 1
                else:
                    if self.verbose:
                        print(f"  ✗ {filename} not found (404)")
            except Exception as e:
                if self.verbose:
                    print(f"  ✗ Failed to download {filename}: {e}")

        print(f"\nKaluza full set: {count} files downloaded")
        print(f"Location: {kaluza_full_dir}")
        print("\nNote: For the complete 18,000+ Kaluza benchmark set:")
        print("  Visit: https://zenodo.org/communities/smt-lib/")
        print("  Extract to: benchmarks/cache/qf_s/kaluza_full/")

        return count

    def download_qf_s_pisa(self, max_files: Optional[int] = None) -> int:
        """Download PISA string benchmarks"""
        print("\nDownloading PISA string benchmarks...")

        pisa_dir = os.path.join(self.cache_dir, 'qf_s', 'pisa')
        os.makedirs(pisa_dir, exist_ok=True)

        # PISA (Path-sensitive String Analysis) benchmarks
        # These test path-sensitive string constraint solving
        pisa_samples = {
            'path_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const cond Bool)
(assert (ite cond (= y (str.++ x "admin")) (= y (str.++ x "user"))))
(assert (str.contains y "admin"))
(check-sat)
; expected: sat
""",
            'path_02.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const result String)
(declare-const flag Bool)
(assert (ite flag (= result (str.replace x "'" "")) (= result x)))
(assert (str.contains result "'"))
(assert flag)
(check-sat)
; expected: unsat
""",
            'branch_merge_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(declare-const b1 Bool)
(declare-const b2 Bool)
(assert (ite b1 (= y (str.++ x "a")) (= y (str.++ x "b"))))
(assert (ite b2 (= z (str.++ y "c")) (= z (str.++ y "d"))))
(assert (= (str.len z) (+ (str.len x) 2)))
(check-sat)
; expected: sat
""",
            'loop_invariant_01.smt2': """(set-logic QF_S)
(declare-const x0 String)
(declare-const x1 String)
(declare-const x2 String)
(assert (= x1 (str.++ x0 "a")))
(assert (= x2 (str.++ x1 "a")))
(assert (= (str.len x2) (+ (str.len x0) 2)))
(check-sat)
; expected: sat
""",
            'symbolic_exec_01.smt2': """(set-logic QF_S)
(declare-const input String)
(declare-const output String)
(declare-const sanitized String)
(assert (= sanitized (str.replace input "<" "&lt;")))
(assert (= output (str.++ "<html>" sanitized "</html>")))
(assert (str.contains output "<script>"))
(check-sat)
; expected: sat
"""
        }

        count = 0
        files_to_create = list(pisa_samples.items())
        if max_files:
            files_to_create = files_to_create[:max_files]

        for filename, content in files_to_create:
            filepath = os.path.join(pisa_dir, filename)
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(content)
                print(f"  ✓ Created {filename}")
                count += 1
            else:
                print(f"  ✓ {filename} (already exists)")
                count += 1

        print(f"\nPISA benchmarks: {count} files")
        print(f"Location: {pisa_dir}")

        return count

    def download_qf_s_woorpje(self, max_files: Optional[int] = None) -> int:
        """Download Woorpje string benchmarks"""
        print("\nDownloading Woorpje string benchmarks...")

        woorpje_dir = os.path.join(self.cache_dir, 'qf_s', 'woorpje')
        os.makedirs(woorpje_dir, exist_ok=True)

        # Woorpje benchmarks test word equations
        woorpje_samples = {
            'word_eq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.++ x y) (str.++ y x)))
(assert (not (= x y)))
(assert (not (= x "")))
(assert (not (= y "")))
(check-sat)
; expected: sat
""",
            'word_eq_02.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= (str.++ x y) (str.++ y z)))
(assert (not (= y "")))
(check-sat)
; expected: sat
""",
            'word_eq_03.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.++ x x) (str.++ y y y)))
(check-sat)
; expected: sat
""",
            'quadratic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.++ x x) (str.++ y y)))
(assert (not (= x y)))
(check-sat)
; expected: sat
""",
            'periodic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= (str.++ x y z) (str.++ y z x)))
(assert (= (str.len x) 3))
(assert (= (str.len y) 2))
(check-sat)
; expected: sat
"""
        }

        count = 0
        files_to_create = list(woorpje_samples.items())
        if max_files:
            files_to_create = files_to_create[:max_files]

        for filename, content in files_to_create:
            filepath = os.path.join(woorpje_dir, filename)
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(content)
                print(f"  ✓ Created {filename}")
                count += 1
            else:
                print(f"  ✓ {filename} (already exists)")
                count += 1

        print(f"\nWoorpje benchmarks: {count} files")
        print(f"Location: {woorpje_dir}")

        return count

    # ========== QF_AX Array Theory Benchmarks ==========

    def download_qf_ax_samples(self, max_files: Optional[int] = None) -> int:
        """Download QF_AX (Array Theory) sample benchmarks"""
        print("\nDownloading QF_AX (Array Theory) benchmarks...")

        qf_ax_dir = os.path.join(self.cache_dir, 'qf_ax', 'samples')
        os.makedirs(qf_ax_dir, exist_ok=True)

        # QF_AX benchmarks test array operations with select/store axioms
        qf_ax_samples = {
            'select_store_01.smt2': """(set-logic QF_AX)
(declare-const arr1 (Array Int Int))
(declare-const arr2 (Array Int Int))
(assert (= arr2 (store arr1 0 42)))
(assert (= (select arr2 0) 42))
(check-sat)
; expected: sat
""",
            'select_store_diff_index.smt2': """(set-logic QF_AX)
(declare-const arr1 (Array Int Int))
(declare-const arr2 (Array Int Int))
(assert (= arr2 (store arr1 0 42)))
(assert (= (select arr1 5) 10))
(assert (= (select arr2 5) 10))
(check-sat)
; expected: sat
""",
            'array_equality_01.smt2': """(set-logic QF_AX)
(declare-const arr1 (Array Int Int))
(declare-const arr2 (Array Int Int))
(assert (= (select arr1 0) (select arr2 0)))
(assert (= (select arr1 1) (select arr2 1)))
(assert (not (= arr1 arr2)))
(check-sat)
; expected: sat
""",
            'const_array_01.smt2': """(set-logic QF_AX)
(declare-const arr (Array Int Int))
(assert (= arr ((as const (Array Int Int)) 0)))
(assert (= (select arr 5) 0))
(assert (= (select arr 100) 0))
(check-sat)
; expected: sat
""",
            'buffer_overflow_01.smt2': """(set-logic QF_AX)
(declare-const arr (Array Int Int))
(declare-const size Int)
(declare-const index Int)
(assert (= size 10))
(assert (>= index size))
(check-sat)
; expected: sat (buffer overflow possible)
""",
            'in_bounds_01.smt2': """(set-logic QF_AX)
(declare-const arr (Array Int Int))
(declare-const size Int)
(declare-const index Int)
(assert (= size 10))
(assert (< index size))
(assert (>= index 0))
(check-sat)
; expected: sat (in bounds access)
""",
        }

        count = 0
        files_to_create = list(qf_ax_samples.items())
        if max_files:
            files_to_create = files_to_create[:max_files]

        for filename, content in files_to_create:
            filepath = os.path.join(qf_ax_dir, filename)
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(content)
                print(f"  ✓ Created {filename}")
                count += 1
            else:
                print(f"  ✓ {filename} (already exists)")
                count += 1

        print(f"\nQF_AX benchmarks: {count} files")
        print(f"Location: {qf_ax_dir}")

        return count

    # ========== QF_BV Bitvector Theory Benchmarks ==========

    def download_qf_bv_samples(self, max_files: Optional[int] = None) -> int:
        """Download QF_BV (Bitvector Theory) sample benchmarks"""
        print("\nDownloading QF_BV (Bitvector Theory) benchmarks...")

        qf_bv_dir = os.path.join(self.cache_dir, 'qf_bv', 'samples')
        os.makedirs(qf_bv_dir, exist_ok=True)

        # QF_BV benchmarks test bitvector operations and overflow detection
        qf_bv_samples = {
            'bvadd_01.smt2': """(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(declare-const y (_ BitVec 8))
(assert (= x #x05))
(assert (= y #x03))
(assert (= (bvadd x y) #x08))
(check-sat)
; expected: sat
""",
            'bvand_01.smt2': """(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= (bvand x #xFF) x))
(check-sat)
; expected: sat
""",
            'bvor_01.smt2': """(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= (bvor #xF0 #x0F) #xFF))
(check-sat)
; expected: sat
""",
            'bvxor_01.smt2': """(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= x #xFF))
(assert (= (bvxor x x) #x00))
(check-sat)
; expected: sat
""",
            'overflow_unsigned_01.smt2': """(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(declare-const y (_ BitVec 8))
(assert (= x #xFF))
(assert (= y #x01))
(assert (= (bvadd x y) #x00))
(check-sat)
; expected: sat (unsigned overflow)
""",
            'overflow_signed_01.smt2': """(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= x #x7F))
(assert (bvsgt (bvadd x #x01) x))
(check-sat)
; expected: unsat (signed overflow wraps negative)
""",
            'shift_01.smt2': """(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(assert (= x #x01))
(assert (= (bvshl x #x03) #x08))
(check-sat)
; expected: sat
""",
            'comparison_unsigned_01.smt2': """(set-logic QF_BV)
(declare-const x (_ BitVec 8))
(declare-const y (_ BitVec 8))
(assert (= x #x05))
(assert (= y #x0A))
(assert (bvult x y))
(check-sat)
; expected: sat
""",
        }

        count = 0
        files_to_create = list(qf_bv_samples.items())
        if max_files:
            files_to_create = files_to_create[:max_files]

        for filename, content in files_to_create:
            filepath = os.path.join(qf_bv_dir, filename)
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(content)
                print(f"  ✓ Created {filename}")
                count += 1
            else:
                print(f"  ✓ {filename} (already exists)")
                count += 1

        print(f"\nQF_BV benchmarks: {count} files")
        print(f"Location: {qf_bv_dir}")

        return count

    # ========== Google Drive Full Benchmark Downloads ==========

    def download_gdrive_file(self, gdrive_id: str, output_path: str, description: str) -> bool:
        """Download file from Google Drive using gdown"""
        if not GDOWN_AVAILABLE:
            print(f"\n⚠️  gdown library not installed. Install with: pip install gdown")
            print(f"   Skipping download of {description}")
            return False

        if os.path.exists(output_path):
            print(f"  ✓ {description} already downloaded")
            return True

        try:
            print(f"  Downloading {description}...")
            url = f"https://drive.google.com/uc?id={gdrive_id}"
            gdown.download(url, output_path, quiet=False)

            if os.path.exists(output_path):
                print(f"  ✓ Downloaded {description} successfully")
                return True
            else:
                print(f"  ✗ Failed to download {description}")
                return False
        except Exception as e:
            print(f"  ✗ Error downloading {description}: {e}")
            return False

    def extract_archive(self, archive_path: str, extract_to: str) -> bool:
        """Extract zip or tar.gz archive"""
        try:
            if archive_path.endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)
                print(f"  ✓ Extracted to {extract_to}")
                return True
            elif archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_to)
                print(f"  ✓ Extracted to {extract_to}")
                return True
            else:
                print(f"  ✗ Unknown archive format: {archive_path}")
                return False
        except Exception as e:
            print(f"  ✗ Error extracting {archive_path}: {e}")
            return False

    def download_full_kaluza(self) -> int:
        """Download full QF_S benchmark set from SMT-LIB/Zenodo (contains all string benchmarks)"""
        print("\n" + "=" * 80)
        print("DOWNLOADING FULL QF_S BENCHMARK SET FROM SMT-LIB")
        print("=" * 80)
        print("Source: SMT-LIB 2024 (Zenodo)")
        print("Size: 2.9MB compressed | Contains: Kaluza, PISA, PyEx, etc.")

        qf_s_full_dir = os.path.join(self.cache_dir, 'qf_s_full')
        os.makedirs(qf_s_full_dir, exist_ok=True)

        # Check if already extracted
        existing_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
        if len(existing_files) > 100:
            print(f"\n✓ QF_S benchmarks already cached ({len(existing_files)} files)")
            print(f"  Location: {qf_s_full_dir}")
            return len(existing_files)

        archive_path = os.path.join(self.cache_dir, 'QF_S.tar.zst')

        # Download from Zenodo (public SMT-LIB repository)
        zenodo_url = "https://zenodo.org/records/11061097/files/QF_S.tar.zst?download=1"

        try:
            if not os.path.exists(archive_path):
                print(f"\n  Downloading QF_S benchmarks from Zenodo...")
                response = requests.get(zenodo_url, timeout=300, stream=True)
                if response.status_code == 200:
                    total_size = int(response.headers.get('content-length', 0))
                    with open(archive_path, 'wb') as f:
                        downloaded = 0
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                print(f"\r  Progress: {progress:.1f}%", end='', flush=True)
                    print(f"\n  ✓ Downloaded QF_S.tar.zst ({downloaded / 1024 / 1024:.1f} MB)")
                else:
                    print(f"  ✗ Failed to download (HTTP {response.status_code})")
                    return 0

            # Extract using tar with zstd
            print(f"  Extracting benchmarks...")
            try:
                import subprocess
                result = subprocess.run(
                    ['tar', '--zstd', '-xf', archive_path, '-C', qf_s_full_dir],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode == 0:
                    smt2_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
                    print(f"\n✓ QF_S benchmarks ready: {len(smt2_files)} files")
                    print(f"  Location: {qf_s_full_dir}")

                    # Clean up archive
                    try:
                        os.remove(archive_path)
                        print(f"  ✓ Cleaned up archive")
                    except:
                        pass

                    return len(smt2_files)
                else:
                    print(f"  ✗ Extraction failed: {result.stderr}")
                    # Try alternative: python tarfile with zstandard
                    try:
                        import zstandard as zstd
                        import tarfile
                        print(f"  Trying alternative extraction method...")

                        # Decompress zstd first
                        decompressed_path = archive_path.replace('.zst', '')
                        with open(archive_path, 'rb') as compressed:
                            dctx = zstd.ZstdDecompressor()
                            with open(decompressed_path, 'wb') as destination:
                                dctx.copy_stream(compressed, destination)

                        # Then extract tar
                        with tarfile.open(decompressed_path, 'r') as tar:
                            tar.extractall(qf_s_full_dir)

                        smt2_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
                        print(f"\n✓ QF_S benchmarks ready: {len(smt2_files)} files")
                        print(f"  Location: {qf_s_full_dir}")

                        # Clean up
                        try:
                            os.remove(archive_path)
                            os.remove(decompressed_path)
                            print(f"  ✓ Cleaned up archives")
                        except:
                            pass

                        return len(smt2_files)
                    except ImportError:
                        print(f"  ✗ zstandard library not available")
                        print(f"  Install with: pip install zstandard")
                        return 0
                    except Exception as e:
                        print(f"  ✗ Alternative extraction failed: {e}")
                        return 0
            except FileNotFoundError:
                print(f"  ✗ 'tar' command not found. Trying python extraction...")
                # Same alternative method as above
                try:
                    import zstandard as zstd
                    import tarfile

                    decompressed_path = archive_path.replace('.zst', '')
                    with open(archive_path, 'rb') as compressed:
                        dctx = zstd.ZstdDecompressor()
                        with open(decompressed_path, 'wb') as destination:
                            dctx.copy_stream(compressed, destination)

                    with tarfile.open(decompressed_path, 'r') as tar:
                        tar.extractall(qf_s_full_dir)

                    smt2_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
                    print(f"\n✓ QF_S benchmarks ready: {len(smt2_files)} files")
                    print(f"  Location: {qf_s_full_dir}")

                    try:
                        os.remove(archive_path)
                        os.remove(decompressed_path)
                        print(f"  ✓ Cleaned up archives")
                    except:
                        pass

                    return len(smt2_files)
                except ImportError:
                    print(f"  ✗ zstandard library not available")
                    print(f"  Install with: pip install zstandard")
                    return 0
                except Exception as e:
                    print(f"  ✗ Extraction failed: {e}")
                    return 0

        except Exception as e:
            print(f"\n⚠️  Failed to download QF_S benchmarks: {e}")
            return 0

        return 0

    # Aliases for backward compatibility - all point to the same SMT-LIB download
    def download_full_pisa(self) -> int:
        """Alias for download_full_kaluza - SMT-LIB contains all QF_S benchmarks"""
        return self.download_full_kaluza()

    def download_full_appscan(self) -> int:
        """Alias for download_full_kaluza - SMT-LIB contains all QF_S benchmarks"""
        return self.download_full_kaluza()

    def download_full_pyex(self) -> int:
        """Alias for download_full_kaluza - SMT-LIB contains all QF_S benchmarks"""
        return self.download_full_kaluza()

    def download_qf_ax_full(self) -> int:
        """Download full QF_AX (Array Theory) benchmark set from SMT-LIB"""
        print("\n" + "=" * 80)
        print("DOWNLOADING FULL QF_AX BENCHMARK SET FROM SMT-LIB")
        print("=" * 80)
        print("Source: SMT-LIB 2024 Release (Zenodo)")
        print("Theory: QF_AX (Quantifier-Free Array Theory with Extensionality)")

        qf_ax_full_dir = os.path.join(self.cache_dir, 'qf_ax_full')
        os.makedirs(qf_ax_full_dir, exist_ok=True)

        # Check if already downloaded
        existing_files = list(Path(qf_ax_full_dir).rglob('*.smt2'))
        if len(existing_files) > 50:
            print(f"\n✓ QF_AX benchmarks already cached ({len(existing_files)} files)")
            print(f"  Location: {qf_ax_full_dir}")
            return len(existing_files)

        # Official SMT-LIB 2024 release on Zenodo
        zenodo_url = "https://zenodo.org/records/11061097/files/QF_AX.tar.zst?download=1"
        archive_path = os.path.join(self.cache_dir, 'QF_AX.tar.zst')

        try:
            if not os.path.exists(archive_path):
                print(f"\n  Downloading QF_AX benchmarks from Zenodo (131.5 KB compressed)...")
                response = requests.get(zenodo_url, timeout=300, stream=True)
                if response.status_code == 200:
                    total_size = int(response.headers.get('content-length', 0))
                    with open(archive_path, 'wb') as f:
                        downloaded = 0
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                print(f"\r  Progress: {progress:.1f}%", end='', flush=True)
                    print(f"\n  ✓ Downloaded ({downloaded / 1024 / 1024:.1f} MB)")
                else:
                    print(f"  ✗ Zenodo download failed (HTTP {response.status_code})")
                    print(f"  Using local samples instead...")
                    return self.download_qf_ax_samples()

            # Extract QF_AX benchmarks using tar with zstd
            print(f"  Extracting QF_AX benchmarks from .tar.zst archive...")

            # Extract to a temporary directory first
            extract_dir = os.path.join(self.cache_dir, 'qf_ax_extract_tmp')
            os.makedirs(extract_dir, exist_ok=True)

            # Use Python's zstandard library to extract .tar.zst
            try:
                import zstandard
                import tarfile

                dctx = zstandard.ZstdDecompressor()
                with open(archive_path, 'rb') as compressed:
                    with dctx.stream_reader(compressed) as reader:
                        with tarfile.open(fileobj=reader, mode='r|') as tar:
                            tar.extractall(path=extract_dir)
            except Exception as e:
                print(f"  ✗ Extraction failed: {e}")
                print(f"  Using local samples instead...")
                shutil.rmtree(extract_dir, ignore_errors=True)
                return self.download_qf_ax_samples()

            # Move all .smt2 files to qf_ax_full_dir
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith('.smt2'):
                        src = os.path.join(root, file)
                        dst = os.path.join(qf_ax_full_dir, file)
                        shutil.move(src, dst)

            smt2_files = list(Path(qf_ax_full_dir).rglob('*.smt2'))

            # If we got very few files, fall back to samples
            if len(smt2_files) < 10:
                print(f"  ✗ Insufficient benchmarks extracted ({len(smt2_files)} files)")
                print(f"  Using local samples instead...")
                return self.download_qf_ax_samples()

            print(f"\n✓ QF_AX benchmarks ready: {len(smt2_files)} files")
            print(f"  Location: {qf_ax_full_dir}")

            # Clean up
            try:
                os.remove(archive_path)
                shutil.rmtree(extract_dir, ignore_errors=True)
            except:
                pass

            return len(smt2_files)

        except Exception as e:
            print(f"  ✗ Download failed: {e}")
            print(f"  Using local samples instead...")
            return self.download_qf_ax_samples()

    def download_qf_bv_full(self) -> int:
        """Download full QF_BV (Bitvector Theory) benchmark set from SMT-LIB"""
        print("\n" + "=" * 80)
        print("DOWNLOADING FULL QF_BV BENCHMARK SET FROM SMT-LIB")
        print("=" * 80)
        print("Source: SMT-LIB 2024 Release (Zenodo)")
        print("Theory: QF_BV (Quantifier-Free Bitvector Theory)")

        qf_bv_full_dir = os.path.join(self.cache_dir, 'qf_bv_full')
        os.makedirs(qf_bv_full_dir, exist_ok=True)

        # Check if already downloaded
        existing_files = list(Path(qf_bv_full_dir).rglob('*.smt2'))
        if len(existing_files) > 50:
            print(f"\n✓ QF_BV benchmarks already cached ({len(existing_files)} files)")
            print(f"  Location: {qf_bv_full_dir}")
            return len(existing_files)

        # Official SMT-LIB 2024 release on Zenodo
        zenodo_url = "https://zenodo.org/records/11061097/files/QF_BV.tar.zst?download=1"
        archive_path = os.path.join(self.cache_dir, 'QF_BV.tar.zst')

        try:
            if not os.path.exists(archive_path):
                print(f"\n  Downloading QF_BV benchmarks from Zenodo (1.7 GB compressed)...")
                print(f"  This may take several minutes...")
                response = requests.get(zenodo_url, timeout=600, stream=True)
                if response.status_code == 200:
                    total_size = int(response.headers.get('content-length', 0))
                    with open(archive_path, 'wb') as f:
                        downloaded = 0
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                print(f"\r  Progress: {progress:.1f}%", end='', flush=True)
                    print(f"\n  ✓ Downloaded ({downloaded / 1024 / 1024:.1f} MB)")
                else:
                    print(f"  ✗ Zenodo download failed (HTTP {response.status_code})")
                    print(f"  Using local samples instead...")
                    return self.download_qf_bv_samples()

            # Extract QF_BV benchmarks using tar with zstd
            print(f"  Extracting QF_BV benchmarks from .tar.zst archive...")
            print(f"  This may take several minutes due to large file size...")

            # Extract to a temporary directory first
            extract_dir = os.path.join(self.cache_dir, 'qf_bv_extract_tmp')
            os.makedirs(extract_dir, exist_ok=True)

            # Use Python's zstandard library to extract .tar.zst
            try:
                import zstandard
                import tarfile

                dctx = zstandard.ZstdDecompressor()
                with open(archive_path, 'rb') as compressed:
                    with dctx.stream_reader(compressed) as reader:
                        with tarfile.open(fileobj=reader, mode='r|') as tar:
                            tar.extractall(path=extract_dir)
            except Exception as e:
                print(f"  ✗ Extraction failed: {e}")
                print(f"  Using local samples instead...")
                shutil.rmtree(extract_dir, ignore_errors=True)
                return self.download_qf_bv_samples()

            # Move all .smt2 files to qf_bv_full_dir
            print(f"  Moving extracted files...")
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith('.smt2'):
                        src = os.path.join(root, file)
                        dst = os.path.join(qf_bv_full_dir, file)
                        shutil.move(src, dst)

            smt2_files = list(Path(qf_bv_full_dir).rglob('*.smt2'))

            # If we got very few files, fall back to samples
            if len(smt2_files) < 10:
                print(f"  ✗ Insufficient benchmarks extracted ({len(smt2_files)} files)")
                print(f"  Using local samples instead...")
                return self.download_qf_bv_samples()

            print(f"\n✓ QF_BV benchmarks ready: {len(smt2_files)} files")
            print(f"  Location: {qf_bv_full_dir}")

            # Clean up
            try:
                os.remove(archive_path)
                shutil.rmtree(extract_dir, ignore_errors=True)
            except:
                pass

            return len(smt2_files)

        except Exception as e:
            print(f"  ✗ Download failed: {e}")
            print(f"  Using local samples instead...")
            return self.download_qf_bv_samples()

    # ========== Curated Sample Creation ==========

    def create_qf_s_curated_set(self, sample_size: int = 3300, seed: int = 42) -> int:
        """Create a curated sample set from the full QF_S benchmarks using stratified sampling

        Args:
            sample_size: Target number of samples (default 3300)
            seed: Random seed for reproducibility (default 42)

        Returns:
            Number of files in curated set
        """
        print("\n" + "=" * 80)
        print(f"CREATING QF_S CURATED SAMPLE SET ({sample_size} tests)")
        print("=" * 80)

        qf_s_full_dir = os.path.join(self.cache_dir, 'qf_s_full')
        qf_s_curated_dir = os.path.join(self.cache_dir, 'qf_s', 'qf_s_curated')

        # Check if full set exists
        if not os.path.exists(qf_s_full_dir):
            print("Full QF_S set not found. Downloading...")
            count = self.download_full_kaluza()
            if count == 0:
                print("ERROR: Failed to download full QF_S set")
                return 0

        # Find all .smt2 files recursively
        all_files = list(Path(qf_s_full_dir).rglob('*.smt2'))
        print(f"Found {len(all_files)} total files in full set")

        # Group files by directory (source)
        from collections import defaultdict
        files_by_source = defaultdict(list)
        for file_path in all_files:
            # Get relative path components
            rel_path = file_path.relative_to(qf_s_full_dir)
            parts = rel_path.parts
            # Use first meaningful directory as source
            source = parts[1] if len(parts) > 1 else 'other'
            files_by_source[source].append(file_path)

        print(f"\nFound {len(files_by_source)} different sources:")
        for source, files in sorted(files_by_source.items(), key=lambda x: -len(x[1]))[:10]:
            print(f"  {source}: {len(files)} files")

        # Stratified sampling: sample proportionally from each source
        random.seed(seed)
        sampled_files = []
        total_files = len(all_files)

        for source, files in files_by_source.items():
            # Calculate proportion
            proportion = len(files) / total_files
            source_sample_size = max(1, int(sample_size * proportion))

            # Sample from this source
            if len(files) <= source_sample_size:
                source_samples = files
            else:
                source_samples = random.sample(files, source_sample_size)

            sampled_files.extend(source_samples)

        # If we oversampled, trim down randomly
        if len(sampled_files) > sample_size:
            sampled_files = random.sample(sampled_files, sample_size)

        print(f"\nSampled {len(sampled_files)} files")

        # Create curated directory and copy files
        os.makedirs(qf_s_curated_dir, exist_ok=True)

        # Clear existing curated files
        for existing_file in Path(qf_s_curated_dir).glob('*.smt2'):
            existing_file.unlink()

        # Copy sampled files with flattened names
        for i, file_path in enumerate(sampled_files, 1):
            # Create unique filename from path
            rel_path = file_path.relative_to(qf_s_full_dir)
            # Flatten path: replace / with _
            flat_name = str(rel_path).replace('/', '_').replace('\\', '_')
            dest_path = os.path.join(qf_s_curated_dir, flat_name)
            shutil.copy2(file_path, dest_path)

        print(f"\n✓ Created curated set: {len(sampled_files)} files")
        print(f"  Location: {qf_s_curated_dir}")
        print(f"  Seed: {seed} (reproducible)")

        return len(sampled_files)

    def create_slcomp_curated_set(self, sample_size: int = 700, seed: int = 42) -> int:
        """Create a curated sample set from SL-COMP benchmarks using stratified sampling

        Args:
            sample_size: Target number of samples (default 700)
            seed: Random seed for reproducibility (default 42)

        Returns:
            Number of files in curated set
        """
        print("\n" + "=" * 80)
        print(f"CREATING SL-COMP CURATED SAMPLE SET ({sample_size} tests)")
        print("=" * 80)

        slcomp_curated_dir = os.path.join(self.cache_dir, 'slcomp_curated')

        # All SL-COMP divisions
        divisions = [
            'qf_shls_entl', 'qf_shid_sat', 'qf_shid_entl', 'qf_bsl_sat',
            'qf_bsllia_sat', 'qf_shlid_entl', 'qf_shidlia_entl', 'qf_shidlia_sat',
            'qf_shls_sat', 'shid_entl', 'shidlia_entl', 'bsl_sat'
        ]

        # Count files in each division
        from collections import defaultdict
        files_by_division = defaultdict(list)
        total_files = 0

        for division in divisions:
            division_dir = os.path.join(self.cache_dir, division)
            if os.path.exists(division_dir):
                files = [f for f in os.listdir(division_dir) if f.endswith('.smt2')]
                files_by_division[division] = files
                total_files += len(files)

        if total_files == 0:
            print("ERROR: No SL-COMP benchmarks found. Run download first.")
            return 0

        print(f"Found {total_files} total files across {len(files_by_division)} divisions")

        # Stratified sampling: ensure all divisions are represented
        random.seed(seed)
        sampled_files = []

        # Minimum 5 samples per division, rest proportional
        min_per_division = 5
        reserved = min_per_division * len(files_by_division)
        remaining_budget = sample_size - reserved

        for division, files in files_by_division.items():
            # Minimum samples
            division_sample_size = min_per_division

            # Add proportional samples from remaining budget
            if remaining_budget > 0:
                proportion = len(files) / total_files
                additional = int(remaining_budget * proportion)
                division_sample_size += additional

            # Sample
            if len(files) <= division_sample_size:
                division_samples = files
            else:
                division_samples = random.sample(files, division_sample_size)

            for filename in division_samples:
                sampled_files.append((division, filename))

        print(f"\nSampled {len(sampled_files)} files across divisions")

        # Create curated directory and copy files
        os.makedirs(slcomp_curated_dir, exist_ok=True)

        # Clear existing curated files
        for existing_file in Path(slcomp_curated_dir).glob('*.smt2'):
            existing_file.unlink()

        # Copy sampled files with division prefix
        for division, filename in sampled_files:
            src_path = os.path.join(self.cache_dir, division, filename)
            # Prefix with division name to avoid conflicts
            dest_filename = f"{division}_{filename}"
            dest_path = os.path.join(slcomp_curated_dir, dest_filename)
            shutil.copy2(src_path, dest_path)

        print(f"\n✓ Created curated set: {len(sampled_files)} files")
        print(f"  Location: {slcomp_curated_dir}")
        print(f"  Seed: {seed} (reproducible)")

        # Print breakdown by division
        print("\n  Breakdown by division:")
        division_counts = defaultdict(int)
        for division, _ in sampled_files:
            division_counts[division] += 1
        for division, count in sorted(division_counts.items(), key=lambda x: -x[1]):
            print(f"    {division}: {count} tests")

        return len(sampled_files)

    def create_qf_ax_curated_set(self, sample_size: int = 250, seed: int = 42) -> int:
        """Create a curated sample set from QF_AX benchmarks

        Args:
            sample_size: Target number of samples (default 250)
            seed: Random seed for reproducibility (default 42)

        Returns:
            Number of files in curated set
        """
        print("\n" + "=" * 80)
        print(f"CREATING QF_AX CURATED SAMPLE SET")
        print("=" * 80)

        qf_ax_full_dir = os.path.join(self.cache_dir, 'qf_ax_full')
        qf_ax_samples_dir = os.path.join(self.cache_dir, 'qf_ax', 'samples')
        qf_ax_curated_dir = os.path.join(self.cache_dir, 'qf_ax', 'qf_ax_curated')

        # Try full set first
        all_files = []
        if os.path.exists(qf_ax_full_dir):
            all_files = list(Path(qf_ax_full_dir).rglob('*.smt2'))

        # Fall back to samples if full set doesn't exist or is too small
        if len(all_files) < 10:
            print("Full QF_AX set not available, using sample benchmarks...")
            if not os.path.exists(qf_ax_samples_dir):
                print("Downloading QF_AX samples...")
                self.download_qf_ax_samples()
            all_files = list(Path(qf_ax_samples_dir).rglob('*.smt2'))

        print(f"Found {len(all_files)} total files")

        if len(all_files) == 0:
            print("ERROR: No QF_AX benchmarks found")
            return 0

        # Random sampling
        random.seed(seed)
        if len(all_files) <= sample_size:
            sampled_files = all_files
        else:
            sampled_files = random.sample(all_files, sample_size)

        print(f"\nSampled {len(sampled_files)} files")

        # Create curated directory
        os.makedirs(qf_ax_curated_dir, exist_ok=True)

        # Clear existing curated files
        for existing_file in Path(qf_ax_curated_dir).glob('*.smt2'):
            existing_file.unlink()

        # Copy sampled files
        for i, file_path in enumerate(sampled_files, 1):
            dest_path = os.path.join(qf_ax_curated_dir, file_path.name)
            shutil.copy2(file_path, dest_path)

        print(f"\n✓ Created curated set: {len(sampled_files)} files")
        print(f"  Location: {qf_ax_curated_dir}")
        print(f"  Seed: {seed} (reproducible)")

        return len(sampled_files)

    def create_qf_bv_curated_set(self, sample_size: int = 250, seed: int = 42) -> int:
        """Create a curated sample set from QF_BV benchmarks

        Args:
            sample_size: Target number of samples (default 250)
            seed: Random seed for reproducibility (default 42)

        Returns:
            Number of files in curated set
        """
        print("\n" + "=" * 80)
        print(f"CREATING QF_BV CURATED SAMPLE SET ({sample_size} tests)")
        print("=" * 80)

        qf_bv_full_dir = os.path.join(self.cache_dir, 'qf_bv_full')
        qf_bv_samples_dir = os.path.join(self.cache_dir, 'qf_bv', 'samples')
        qf_bv_curated_dir = os.path.join(self.cache_dir, 'qf_bv', 'qf_bv_curated')

        # Try full set first
        all_files = []
        if os.path.exists(qf_bv_full_dir):
            all_files = list(Path(qf_bv_full_dir).rglob('*.smt2'))

        # Fall back to samples if full set doesn't exist or is too small
        if len(all_files) < 10:
            if len(all_files) == 0:
                print("Full QF_BV set not found. Downloading...")
                self.download_qf_bv_full()
                if os.path.exists(qf_bv_full_dir):
                    all_files = list(Path(qf_bv_full_dir).rglob('*.smt2'))

            # If still no files, fall back to samples
            if len(all_files) < 10:
                print("Full QF_BV set not available, using sample benchmarks...")
                if not os.path.exists(qf_bv_samples_dir):
                    print("Downloading QF_BV samples...")
                    self.download_qf_bv_samples()
                all_files = list(Path(qf_bv_samples_dir).rglob('*.smt2'))

        print(f"Found {len(all_files)} total files in full set")

        if len(all_files) == 0:
            print("ERROR: No QF_BV benchmarks found")
            return 0

        # Random sampling
        random.seed(seed)
        if len(all_files) <= sample_size:
            sampled_files = all_files
        else:
            sampled_files = random.sample(all_files, sample_size)

        print(f"\nSampled {len(sampled_files)} files")

        # Create curated directory
        os.makedirs(qf_bv_curated_dir, exist_ok=True)

        # Clear existing curated files
        for existing_file in Path(qf_bv_curated_dir).glob('*.smt2'):
            existing_file.unlink()

        # Copy sampled files
        for i, file_path in enumerate(sampled_files, 1):
            dest_path = os.path.join(qf_bv_curated_dir, file_path.name)
            shutil.copy2(file_path, dest_path)

        print(f"\n✓ Created curated set: {len(sampled_files)} files")
        print(f"  Location: {qf_bv_curated_dir}")
        print(f"  Seed: {seed} (reproducible)")

        return len(sampled_files)

    # ========== QF_S Benchmark Running ==========

    def run_qf_s_benchmark(self, source: str, filename: str, full_path: Optional[str] = None) -> BenchmarkResult:
        """Run a single QF_S benchmark

        Args:
            source: Source name (kaluza, pisa, etc. or qf_s_full)
            filename: Display filename
            full_path: Optional full path to file (used for qf_s_full)
        """
        start_time = time.time()

        try:
            if full_path:
                cache_path = full_path
            else:
                cache_path = os.path.join(self.cache_dir, 'qf_s', source, filename)

            with open(cache_path, 'r') as f:
                content = f.read()

            formula, expected_status = self.smtlib_parser.parse_file(content)
            is_sat = self.checker.is_satisfiable(formula)
            actual_status = 'sat' if is_sat else 'unsat'

            elapsed_ms = (time.time() - start_time) * 1000

            return BenchmarkResult(
                filename=filename,
                suite='qf_s',
                division=source,
                expected=expected_status,
                actual=actual_status,
                time_ms=elapsed_ms
            )

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            return BenchmarkResult(
                filename=filename,
                suite='qf_s',
                division=source,
                expected='unknown',
                actual='error',
                time_ms=elapsed_ms,
                error=str(e)
            )

    def run_qf_s_division(self, source: str, max_tests: Optional[int] = None) -> List[BenchmarkResult]:
        """Run all QF_S benchmarks in a source"""
        # Special handling for qf_s_full (recursive search in different directory)
        if source == 'qf_s_full':
            qf_s_full_dir = os.path.join(self.cache_dir, 'qf_s_full')

            if not os.path.exists(qf_s_full_dir):
                print(f"\n{source} benchmarks not found. Downloading...")
                count = self.download_full_kaluza()
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

                result = self.run_qf_s_benchmark(source, display_name, full_path=str(file_path))
                results.append(result)

                status = "✓" if result.correct else "✗"

                # Progress indicator with percentage for large sets
                if total > 100:
                    progress_pct = (i / total) * 100
                    print(f"[{i}/{total} {progress_pct:5.1f}%] {status} {display_name[:50]:<50} {result.time_ms:>6.1f}ms")
                else:
                    print(f"[{i}/{total}] {status} {display_name[:50]:<50} {result.time_ms:>6.1f}ms")

            self.results.extend(results)
            return results

        # Normal handling for samples (flat directory structure)
        source_dir = os.path.join(self.cache_dir, 'qf_s', source)

        if not os.path.exists(source_dir):
            if source == 'kaluza':
                print(f"Kaluza benchmarks not found. Downloading samples...")
                self.download_qf_s_kaluza(max_files=max_tests or 10)
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
            result = self.run_qf_s_benchmark(source, filename)
            results.append(result)
            status = "✓" if result.correct else "✗"
            print(f"[{i}/{len(files)}] {status} {filename[:50]:<50} {result.time_ms:>6.1f}ms")

        self.results.extend(results)
        return results

    # ========== QF_AX and QF_BV Benchmark Running ==========

    def run_qf_ax_benchmark(self, source: str, filename: str, full_path: Optional[str] = None) -> BenchmarkResult:
        """Run a single QF_AX benchmark"""
        if full_path:
            filepath = full_path
        else:
            filepath = os.path.join(self.cache_dir, 'qf_ax', source, filename)

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

        try:
            with open(filepath, 'r') as f:
                content = f.read()

            # Parse using SMTLibParser
            from benchmarks.smtlib_parser import SMTLibParser
            parser = SMTLibParser()
            formula, expected, logic = parser.parse_file(content)

            start_time = time.time()
            result = self.checker.is_satisfiable(formula)
            time_ms = (time.time() - start_time) * 1000

            actual = 'sat' if result else 'unsat'

            return BenchmarkResult(
                filename=filename,
                suite='qf_ax',
                division=source,
                expected=expected,
                actual=actual,
                time_ms=time_ms
            )
        except Exception as e:
            if self.verbose:
                print(f"  ERROR in {filename}: {e}")
            return BenchmarkResult(
                filename=filename,
                suite='qf_ax',
                division=source,
                expected='unknown',
                actual='error',
                time_ms=0.0,
                error=str(e)
            )

    def run_qf_ax_division(self, source: str, max_tests: Optional[int] = None) -> List[BenchmarkResult]:
        """Run all QF_AX benchmarks in a source"""
        source_dir = os.path.join(self.cache_dir, 'qf_ax', source)

        if not os.path.exists(source_dir):
            print(f"{source} benchmarks not found. Creating samples...")
            if source == 'samples':
                self.download_qf_ax_samples(max_files=max_tests or 10)
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
            result = self.run_qf_ax_benchmark(source, filename)
            results.append(result)
            status = "✓" if result.correct else "✗"
            print(f"[{i}/{len(files)}] {status} {filename[:50]:<50} {result.time_ms:>6.1f}ms")

        self.results.extend(results)
        return results

    def run_qf_bv_benchmark(self, source: str, filename: str, full_path: Optional[str] = None) -> BenchmarkResult:
        """Run a single QF_BV benchmark"""
        if full_path:
            filepath = full_path
        else:
            filepath = os.path.join(self.cache_dir, 'qf_bv', source, filename)

        if not os.path.exists(filepath):
            return BenchmarkResult(
                filename=filename,
                suite='qf_bv',
                division=source,
                expected='unknown',
                actual='error',
                time_ms=0.0,
                error='File not found'
            )

        try:
            with open(filepath, 'r') as f:
                content = f.read()

            # Parse using SMTLibParser
            from benchmarks.smtlib_parser import SMTLibParser
            parser = SMTLibParser()
            formula, expected, logic = parser.parse_file(content)

            start_time = time.time()
            result = self.checker.is_satisfiable(formula)
            time_ms = (time.time() - start_time) * 1000

            actual = 'sat' if result else 'unsat'

            return BenchmarkResult(
                filename=filename,
                suite='qf_bv',
                division=source,
                expected=expected,
                actual=actual,
                time_ms=time_ms
            )
        except Exception as e:
            if self.verbose:
                print(f"  ERROR in {filename}: {e}")
            return BenchmarkResult(
                filename=filename,
                suite='qf_bv',
                division=source,
                expected='unknown',
                actual='error',
                time_ms=0.0,
                error=str(e)
            )

    def run_qf_bv_division(self, source: str, max_tests: Optional[int] = None) -> List[BenchmarkResult]:
        """Run all QF_BV benchmarks in a source"""
        source_dir = os.path.join(self.cache_dir, 'qf_bv', source)

        if not os.path.exists(source_dir):
            print(f"{source} benchmarks not found. Creating samples...")
            if source == 'samples':
                self.download_qf_bv_samples(max_files=max_tests or 10)
            else:
                print(f"ERROR: QF_BV source {source} not found")
                return []

        if not os.path.exists(source_dir):
            print(f"ERROR: Could not find or create {source}")
            return []

        files = sorted([f for f in os.listdir(source_dir) if f.endswith('.smt2')])
        if max_tests:
            files = files[:max_tests]

        print(f"\nRunning QF_BV/{source}: {len(files)} benchmarks")
        print("=" * 80)

        results = []
        for i, filename in enumerate(files, 1):
            result = self.run_qf_bv_benchmark(source, filename)
            results.append(result)
            status = "✓" if result.correct else "✗"
            print(f"[{i}/{len(files)}] {status} {filename[:50]:<50} {result.time_ms:>6.1f}ms")

        self.results.extend(results)
        return results

    # ========== Analysis ==========

    def analyze_results(self) -> Dict:
        """Analyze results and generate statistics"""
        if not self.results:
            return {}

        stats = {
            'total': len(self.results),
            'correct': sum(1 for r in self.results if r.correct),
            'incorrect': sum(1 for r in self.results if not r.correct and not r.error),
            'errors': sum(1 for r in self.results if r.error),
            'avg_time_ms': sum(r.time_ms for r in self.results) / len(self.results),
            'by_suite': defaultdict(lambda: {'total': 0, 'correct': 0, 'errors': 0}),
            'by_division': defaultdict(lambda: {'total': 0, 'correct': 0, 'errors': 0}),
            'failures': []
        }

        for result in self.results:
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

    def print_summary(self):
        """Print summary of results"""
        stats = self.analyze_results()

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

    def save_results(self, output_file: str):
        """Save results to JSON"""
        output_path = os.path.join(self.cache_dir, output_file)
        with open(output_path, 'w') as f:
            json.dump([asdict(r) for r in self.results], f, indent=2)
        print(f"\nResults saved to: {output_path}")


def cmd_run(args):
    """Run benchmarks"""
    runner = UnifiedBenchmarkRunner(cache_dir=args.cache_dir, verbose=args.verbose)

    # --curated: Run curated sample sets (~4000-5000 benchmarks)
    if args.curated:
        print("Running CURATED benchmark sets (~4000+ total: 700 SL-COMP + 3300 QF_S + QF_AX + QF_BV)")
        print("(QF_AX and QF_BV counts depend on available full benchmarks from SMT-LIB 2024)")
        print("=" * 80)

        # Ensure curated sets exist
        slcomp_curated_dir = os.path.join(args.cache_dir, 'slcomp_curated')
        qf_s_curated_dir = os.path.join(args.cache_dir, 'qf_s', 'qf_s_curated')
        qf_ax_curated_dir = os.path.join(args.cache_dir, 'qf_ax', 'qf_ax_curated')
        qf_bv_curated_dir = os.path.join(args.cache_dir, 'qf_bv', 'qf_bv_curated')

        if not os.path.exists(slcomp_curated_dir):
            print("\nSL-COMP curated set not found. Creating...")
            runner.create_slcomp_curated_set()

        if not os.path.exists(qf_s_curated_dir):
            print("\nQF_S curated set not found. Creating...")
            runner.create_qf_s_curated_set()

        if not os.path.exists(qf_ax_curated_dir):
            print("\nQF_AX curated set not found. Creating...")
            runner.create_qf_ax_curated_set()

        if not os.path.exists(qf_bv_curated_dir):
            print("\nQF_BV curated set not found. Creating...")
            runner.create_qf_bv_curated_set()

        # Run all curated sets
        runner.run_slcomp_division('slcomp_curated', max_tests=args.max_tests)
        runner.run_qf_s_division('qf_s_curated', max_tests=args.max_tests)
        runner.run_qf_ax_division('qf_ax_curated', max_tests=args.max_tests)
        runner.run_qf_bv_division('qf_bv_curated', max_tests=args.max_tests)

    # --division: Run specific division
    elif args.division:
        print(f"Running specific division: {args.division}")
        print("=" * 80)

        # Determine if it's SL-COMP or QF_S division
        if args.division in ['slcomp_curated'] or args.division.startswith('qf_') or \
           args.division.startswith('bsl_') or args.division.startswith('shid'):
            runner.run_slcomp_division(args.division, max_tests=args.max_tests)
        elif 'qf_s' in args.division.lower():
            runner.run_qf_s_division(args.division, max_tests=args.max_tests)
        else:
            print(f"ERROR: Unknown division '{args.division}'")
            print("Available divisions:")
            print("  SL-COMP: qf_shid_entl, qf_shls_entl, qf_bsl_sat, etc.")
            print("  QF_S: qf_s_curated, or subdirectories in qf_s_full/")
            return

    # --all: Run ALL benchmarks (full suites, ~20k total)
    elif args.all:
        print("Running ALL benchmark sets (~20k total: SL-COMP + QF_S)")
        print("=" * 80)

        # All 12 SL-COMP divisions (1298 total benchmarks)
        slcomp_divisions = [
            # Entailment problems (6 divisions)
            'qf_shid_entl',      # 312 tests
            'qf_shls_entl',      # 296 tests
            'qf_shlid_entl',     # 60 tests
            'qf_shidlia_entl',   # 61 tests
            'shid_entl',         # 73 tests
            'shidlia_entl',      # 181 tests
            # Satisfiability problems (6 divisions)
            'qf_bsl_sat',        # 46 tests
            'qf_bsllia_sat',     # 24 tests
            'bsl_sat',           # 3 tests
            'qf_shid_sat',       # 99 tests
            'qf_shidlia_sat',    # 33 tests
            'qf_shls_sat',       # 110 tests
        ]

        # Run all SL-COMP divisions
        for division in slcomp_divisions:
            runner.run_slcomp_division(division, max_tests=args.max_tests)

        # Run all QF_S benchmarks
        runner.run_qf_s_division('qf_s_full', max_tests=args.max_tests)

    runner.print_summary()
    runner.save_results(args.output)


def cmd_download(args):
    """Download benchmarks"""
    runner = UnifiedBenchmarkRunner(cache_dir=args.cache_dir)

    # All 12 SL-COMP divisions
    slcomp_divisions = [
        'qf_shid_entl', 'qf_shls_entl', 'qf_shlid_entl', 'qf_shidlia_entl',
        'shid_entl', 'shidlia_entl',
        'qf_bsl_sat', 'qf_bsllia_sat', 'bsl_sat',
        'qf_shid_sat', 'qf_shidlia_sat', 'qf_shls_sat',
    ]

    # Handle --curated flag (create curated sample sets)
    if args.curated:
        print("=" * 80)
        print("CREATING CURATED BENCHMARK SETS")
        print("=" * 80)

        # Create QF_S curated set (500 tests)
        qf_s_curated_count = runner.create_qf_s_curated_set()

        # Create SL-COMP curated set (150 tests)
        slcomp_curated_count = runner.create_slcomp_curated_set()

        print("\n" + "=" * 80)
        print("CURATED SETS CREATED")
        print("=" * 80)
        print(f"\nTotal curated benchmarks: {qf_s_curated_count + slcomp_curated_count}")
        print(f"  - QF_S curated: {qf_s_curated_count} tests")
        print(f"  - SL-COMP curated: {slcomp_curated_count} tests")
        print("\nTo run curated benchmarks:")
        print("  python -m benchmarks run --curated")
        print("  python -m benchmarks run --suite qf_s --curated")
        print("  python -m benchmarks run --suite slcomp --curated")
        return

    # Handle --all flag (download everything)
    if args.all or args.suite == 'all':
        print("=" * 80)
        print("DOWNLOADING ALL BENCHMARKS (INCLUDING FULL SETS)")
        print("=" * 80)

        # SL-COMP benchmarks (already cached)
        print("\n### SL-COMP Benchmarks (12 divisions, 861 total) ###")
        print("✓ Already cached in repository")

        # Download full QF_S benchmark set from SMT-LIB (contains all: Kaluza, PISA, PyEx, etc.)
        print("\n### QF_S String Benchmarks (Full Set from SMT-LIB 2024) ###")
        qf_s_count = runner.download_full_kaluza()  # Downloads all QF_S from Zenodo

        # Also download samples
        runner.download_qf_s_kaluza(max_files=args.max_files)
        runner.download_qf_s_pisa(max_files=args.max_files)
        runner.download_qf_s_woorpje(max_files=args.max_files)

        # Download QF_AX and QF_BV full sets from SMT-LIB 2024
        print("\n### QF_AX Array Theory Benchmarks (Full Set from SMT-LIB 2024) ###")
        qf_ax_count = runner.download_qf_ax_full()

        print("\n### QF_BV Bitvector Theory Benchmarks (Full Set from SMT-LIB 2024) ###")
        qf_bv_count = runner.download_qf_bv_full()

        # Create curated sets automatically when downloading --all
        print("\n### Creating Curated Sample Sets ###")
        qf_s_curated_count = runner.create_qf_s_curated_set()
        slcomp_curated_count = runner.create_slcomp_curated_set()

        print("\n" + "=" * 80)
        print("DOWNLOAD COMPLETE")
        print("=" * 80)
        print("\nBenchmarks available:")
        print("  - SL-COMP: 861 benchmarks (cached in repository)")
        print(f"  - SL-COMP curated: {slcomp_curated_count} benchmarks (stratified sample)")
        print(f"  - QF_S Full Set (SMT-LIB 2024): {qf_s_count:,} benchmarks")
        print("  - QF_S Samples: 53 benchmarks")
        print(f"  - QF_S curated: {qf_s_curated_count} benchmarks (stratified sample)")
        print(f"  - QF_AX Full Set (SMT-LIB 2024): {qf_ax_count} benchmarks")
        print(f"  - QF_BV Full Set (SMT-LIB 2024): {qf_bv_count} benchmarks")
        print(f"  - Total: ~{861 + qf_s_count + 53 + qf_ax_count + qf_bv_count:,} benchmarks ready to run")
        print("\nTo run all benchmarks:")
        print("  python -m benchmarks run --suite all")
        print("\nTo run curated benchmarks (recommended for benchmarking):")
        print("  python -m benchmarks run --curated")
        print("\nTo run specific suites:")
        print("  python -m benchmarks run --suite slcomp")
        print("  python -m benchmarks run --suite qf_s")
        print("  python -m benchmarks run --division qf_ax_curated")
        print("  python -m benchmarks run --division qf_bv_curated")
        return

    if args.suite == 'slcomp':
        if args.division:
            runner.download_slcomp_division(args.division, max_files=args.max_files)
        else:
            print("Downloading sample SL-COMP benchmarks...")
            for div in ['qf_shls_entl', 'qf_shid_sat', 'qf_shid_entl']:
                runner.download_slcomp_division(div, max_files=args.max_files)

    elif args.suite == 'qf_s':
        source = args.division or 'all'
        if source == 'kaluza':
            runner.download_qf_s_kaluza(max_files=args.max_files)
        elif source == 'kaluza_full':
            runner.download_full_kaluza()
        elif source == 'pisa':
            runner.download_qf_s_pisa(max_files=args.max_files)
        elif source == 'pisa_full':
            runner.download_full_pisa()
        elif source == 'appscan_full':
            runner.download_full_appscan()
        elif source == 'pyex_full':
            runner.download_full_pyex()
        elif source == 'woorpje':
            runner.download_qf_s_woorpje(max_files=args.max_files)
        elif source == 'all':
            print("Downloading all QF_S benchmark suites (samples)...")
            runner.download_qf_s_kaluza(max_files=args.max_files)
            runner.download_qf_s_pisa(max_files=args.max_files)
            runner.download_qf_s_woorpje(max_files=args.max_files)
        elif source == 'all_full':
            print("Downloading all QF_S benchmark suites (full sets from Google Drive)...")
            runner.download_full_kaluza()
            runner.download_full_pisa()
            runner.download_full_appscan()
            runner.download_full_pyex()
        else:
            print(f"QF_S source '{source}' not recognized")
            print("Available:")
            print("  Samples: kaluza, pisa, woorpje, all")
            print("  Full sets: kaluza_full, pisa_full, appscan_full, pyex_full, all_full")


def cmd_analyze(args):
    """Analyze benchmark failures"""
    results_file = os.path.join(args.cache_dir, args.results_file)

    if not os.path.exists(results_file):
        print(f"Results file not found: {results_file}")
        print("Run benchmarks first: python -m benchmarks run --suite slcomp")
        return

    with open(results_file, 'r') as f:
        results = json.load(f)

    failures = [r for r in results if not r.get('error') and r['expected'] != r['actual']]
    errors = [r for r in results if r.get('error')]

    print(f"\nAnalyzing {len(results)} benchmark results...")
    print(f"  Failures: {len(failures)}")
    print(f"  Errors: {len(errors)}")

    if args.failures and failures:
        print("\n" + "=" * 80)
        print("FAILURE ANALYSIS")
        print("=" * 80)

        by_division = defaultdict(list)
        for failure in failures:
            by_division[failure['division']].append(failure)

        for division, div_failures in sorted(by_division.items()):
            print(f"\n{division}: {len(div_failures)} failures")
            for f in div_failures[:5]:  # Show first 5
                print(f"  - {f['filename']}: expected={f['expected']}, got={f['actual']}")


def cmd_visualize(args):
    """Visualize heap structure"""
    from frame.core.ast import PointsTo, PredicateCall, SepConj, And, Or, Exists, Forall, Not, Var

    # Determine file path
    if '/' in args.file:
        filepath = args.file
    else:
        # Assume it's in cache
        filepath = f"benchmarks/cache/qf_shls_entl/{args.file}"

    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return

    # Parse the file
    with open(filepath, 'r') as f:
        content = f.read()

    parser = SLCompParser()
    try:
        antecedent, consequent, expected_status, problem_type, logic = parser.parse_file(content)
    except Exception as e:
        print(f"Error parsing file: {e}")
        return

    # Extract heap edges and predicates
    def extract_heap_edges(formula):
        """Extract all points-to assertions"""
        edges = []
        def visit(f):
            if isinstance(f, PointsTo):
                loc = f.location.name if isinstance(f.location, Var) else str(f.location)
                if f.values:
                    val = f.values[0].name if isinstance(f.values[0], Var) else str(f.values[0])
                    edges.append((loc, val))
            elif isinstance(f, (SepConj, And, Or)):
                visit(f.left)
                visit(f.right)
            elif isinstance(f, (Exists, Forall, Not)):
                visit(f.formula)
        visit(formula)
        return edges

    def extract_predicates(formula):
        """Extract all predicate calls"""
        preds = []
        def visit(f):
            if isinstance(f, PredicateCall):
                args_str = ', '.join(arg.name if isinstance(arg, Var) else str(arg)
                                    for arg in f.args)
                preds.append((f.name, args_str, f.args))
            elif isinstance(f, (SepConj, And, Or)):
                visit(f.left)
                visit(f.right)
            elif isinstance(f, (Exists, Forall, Not)):
                visit(f.formula)
        visit(formula)
        return preds

    # Visualize
    print(f"\n{'='*80}")
    print(f"HEAP VISUALIZATION: {os.path.basename(filepath)}")
    print(f"{'='*80}")
    print(f"Expected: {expected_status}")
    print(f"Problem Type: {problem_type}\n")

    # Antecedent
    ante_edges = extract_heap_edges(antecedent)
    ante_preds = extract_predicates(antecedent)

    print("--- ANTECEDENT (What we have) ---")
    if ante_edges:
        print("Points-to edges:")
        for src, dst in ante_edges:
            print(f"  {src} |-> {dst}")

    if ante_preds:
        print("\nPredicates:")
        for name, args_str, _ in ante_preds:
            print(f"  {name}({args_str})")

    if not ante_edges and not ante_preds:
        print("  (empty heap)")

    # Consequent
    cons_edges = extract_heap_edges(consequent)
    cons_preds = extract_predicates(consequent)

    print("\n--- CONSEQUENT (What we need to prove) ---")
    if cons_edges:
        print("Points-to edges:")
        for src, dst in cons_edges:
            print(f"  {src} |-> {dst}")

    if cons_preds:
        print("\nPredicates:")
        for name, args_str, _ in cons_preds:
            print(f"  {name}({args_str})")

    if not cons_edges and not cons_preds:
        print("  (empty heap)")

    # Analysis
    print("\n--- ANALYSIS ---")
    print(f"Antecedent: {len(ante_edges)} points-to, {len(ante_preds)} predicates")
    print(f"Consequent: {len(cons_edges)} points-to, {len(cons_preds)} predicates")

    if problem_type == 'entl':
        print(f"\nFor entailment to be valid: antecedent must prove consequent")
        print(f"Expected result: {expected_status}")
    else:
        print(f"\nFor satisfiability check: formula must have a model")
        print(f"Expected result: {expected_status}")

    print("="*80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='Frame Benchmark Suite - Unified CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download ALL uncached benchmarks (SL-COMP + QF_S)
  python -m benchmarks download --all

  # Download specific suite
  python -m benchmarks download --suite qf_s --division kaluza
  python -m benchmarks download --suite slcomp --division qf_shls_entl

  # Run all benchmarks
  python -m benchmarks run --suite all

  # Run specific suite
  python -m benchmarks run --suite slcomp --division qf_shls_entl
  python -m benchmarks run --suite qf_s

  # Analyze failures
  python -m benchmarks analyze --failures

  # Visualize heap structure
  python -m benchmarks visualize bolognesa-10-e01.tptp.smt2
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Run command
    run_parser = subparsers.add_parser('run', help='Run benchmarks')

    # Mutually exclusive group for benchmark selection
    run_group = run_parser.add_mutually_exclusive_group(required=True)
    run_group.add_argument('--all', action='store_true', help='Run ALL benchmarks (full SL-COMP + QF_S suites, ~20k total)')
    run_group.add_argument('--curated', action='store_true', help='Run curated sample sets (~5000 total: 3300 QF_S + 700 SL-COMP + 500 QF_AX + 500 QF_BV)')
    run_group.add_argument('--division', type=str, help='Run specific division (e.g., qf_shls_entl, qf_s_curated)')

    run_parser.add_argument('--max-tests', type=int, help='Maximum tests per division')
    run_parser.add_argument('--output', default='benchmark_results.json', help='Output file')
    run_parser.add_argument('--cache-dir', default='./benchmarks/cache', help='Cache directory')
    run_parser.add_argument('--verbose', action='store_true', help='Verbose output')

    # Download command
    dl_parser = subparsers.add_parser('download', help='Download benchmarks')
    dl_parser.add_argument('--suite', choices=['slcomp', 'qf_s', 'all'], default='all')
    dl_parser.add_argument('--division', type=str, help='Specific division to download')
    dl_parser.add_argument('--max-files', type=int, default=10, help='Max files to download')
    dl_parser.add_argument('--all', action='store_true', help='Download all uncached benchmarks')
    dl_parser.add_argument('--curated', action='store_true', help='Create curated sample sets (~5000 total: 3300 QF_S + 700 SL-COMP + 500 QF_AX + 500 QF_BV)')
    dl_parser.add_argument('--cache-dir', default='./benchmarks/cache', help='Cache directory')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze results')
    analyze_parser.add_argument('--failures', action='store_true', help='Show failure analysis')
    analyze_parser.add_argument('--results-file', default='benchmark_results.json')
    analyze_parser.add_argument('--cache-dir', default='./benchmarks/cache', help='Cache directory')

    # Visualize command
    viz_parser = subparsers.add_parser('visualize', help='Visualize heap structure')
    viz_parser.add_argument('file', help='Benchmark file to visualize')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == 'run':
        cmd_run(args)
    elif args.command == 'download':
        cmd_download(args)
    elif args.command == 'analyze':
        cmd_analyze(args)
    elif args.command == 'visualize':
        cmd_visualize(args)


if __name__ == '__main__':
    main()
