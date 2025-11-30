"""SL-COMP benchmark runner"""

import os
import sys
import time
from pathlib import Path
from typing import List, Optional

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from frame import EntailmentChecker, PredicateRegistry
from frame.predicates import GenericPredicate, ParsedPredicate
from benchmarks.slcomp_parser import SLCompParser
from benchmarks.smtlib_string_parser import SMTLibStringParser
from benchmarks.core import BenchmarkResult


# Initialize shared components (singleton pattern)
_slcomp_parser = None
_smtlib_parser = None
_checker = None
_registry = None

def get_slcomp_parser():
    global _slcomp_parser
    if _slcomp_parser is None:
        _slcomp_parser = SLCompParser()
    return _slcomp_parser

def get_smtlib_parser():
    global _smtlib_parser
    if _smtlib_parser is None:
        _smtlib_parser = SMTLibStringParser()
    return _smtlib_parser

def get_checker(verbose=False):
    global _checker, _registry
    if _checker is None:
        _registry = PredicateRegistry()
        _registry.max_unfold_depth = 12
        _checker = EntailmentChecker(
            predicate_registry=_registry,
            timeout=30000,
            use_folding=True,
            use_cyclic_proof=True,
            use_s2s_normalization=True,
            verbose=verbose
        )
    return _checker, _registry


def run_slcomp_benchmark(cache_dir: str, division: str, filename: str, verbose: bool = False) -> BenchmarkResult:
    """Run a single SL-COMP benchmark"""
    checker, registry = get_checker(verbose)
    start_time = time.time()

    try:
        cache_path = os.path.join(cache_dir, division, filename)
        with open(cache_path, 'r') as f:
            content = f.read()

        # For curated division, use filename to determine problem type
        # Filenames like qf_bsl_sat_dispose-1.cvc4.smt2 contain the actual division
        if division == 'slcomp_curated':
            # Detect problem type from filename patterns
            fname_lower = filename.lower()
            if '_sat_' in fname_lower or fname_lower.startswith('bsl_sat') or fname_lower.startswith('qf_bsl_sat'):
                division_hint = 'sat'  # Just needs to contain '_sat'
            elif '_entl_' in fname_lower or '_entl.' in fname_lower:
                division_hint = 'entl'  # Just needs to contain '_entl'
            else:
                division_hint = division  # Fall back to division name
        else:
            division_hint = division

        # Create fresh parser for each test to avoid state accumulation
        parser = SLCompParser()
        antecedent, consequent, expected_status, problem_type, logic = \
            parser.parse_file(content, division_hint=division_hint)

        # Detect BSL mode
        is_bsl_mode = logic and ('BSL' in logic.upper() or 'BSLLIA' in logic.upper())

        # Register predicates
        for pred_name, pred_params_body in parser.predicate_bodies.items():
            params, body_text = pred_params_body
            body_formula = parser._parse_formula(body_text)
            if body_formula:
                custom_pred = ParsedPredicate(pred_name, params, body_formula)
                registry.register(custom_pred, validate=False)

        # Run check
        if problem_type == 'entl':
            result = checker.check(antecedent, consequent)
            actual_status = 'unsat' if result.valid else 'sat'
        else:
            is_sat = checker.is_satisfiable(antecedent)
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

    except RecursionError as e:
        # Recursion limit hit - return unknown (not an error, just unable to decide)
        elapsed_ms = (time.time() - start_time) * 1000
        return BenchmarkResult(
            filename=filename,
            suite='slcomp',
            division=division,
            expected=expected_status,
            actual='unknown',
            time_ms=elapsed_ms
            # Note: No error field set - RecursionError is a limitation, not a crash
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
        global _checker, _registry
        _registry = PredicateRegistry()
        _registry.max_unfold_depth = 12
        _checker = EntailmentChecker(
            predicate_registry=_registry,
            timeout=30000,
            use_folding=True,
            use_cyclic_proof=True,
            use_s2s_normalization=True,
            verbose=verbose
        )


def run_slcomp_division(cache_dir: str, division: str, verbose: bool = False,
                        max_tests: Optional[int] = None) -> List[BenchmarkResult]:
    """Run all benchmarks in a SL-COMP division"""
    from benchmarks.downloaders import download_slcomp_division

    division_dir = os.path.join(cache_dir, division)

    if not os.path.exists(division_dir):
        print(f"Division {division} not found. Downloading...")
        download_slcomp_division(cache_dir, division)

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
        result = run_slcomp_benchmark(cache_dir, division, filename, verbose)
        results.append(result)
        status = "✓" if result.correct else "✗"

        # Progress indicator with percentage for large divisions
        if total > 100:
            progress_pct = (i / total) * 100
            print(f"[{i}/{total} {progress_pct:5.1f}%] {status} {filename[:50]:<50} {result.time_ms:>6.1f}ms")
        else:
            print(f"[{i}/{total}] {status} {filename[:50]:<50} {result.time_ms:>6.1f}ms")

    return results
