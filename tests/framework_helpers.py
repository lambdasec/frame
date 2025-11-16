"""
Test Framework Helpers for Separation Logic Entailment Checker

Internal helper classes for the test framework. This file is named to NOT match
pytest's test collection pattern (test_*.py or *_test.py) to avoid collection warnings.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from frame import *
from frame.core.parser import parse
from typing import Optional, List, Tuple
import time


class SuiteResult:
    """Result of a single test (internal helper, not a test class)"""
    __test__ = False  # Tell pytest not to collect this class

    def __init__(self, name: str, passed: bool, expected: bool, actual: bool,
                 time_ms: float, error: Optional[str] = None):
        self.name = name
        self.passed = passed
        self.expected = expected
        self.actual = actual
        self.time_ms = time_ms
        self.error = error

    def __str__(self) -> str:
        status = "✓ PASS" if self.passed else "✗ FAIL"
        time_str = f"({self.time_ms:.1f}ms)"

        if self.passed:
            return f"{status} {time_str}: {self.name}"
        else:
            msg = f"{status} {time_str}: {self.name}\n"
            msg += f"  Expected: {self.expected}, Got: {self.actual}"
            if self.error:
                msg += f"\n  Error: {self.error}"
            return msg


class SuiteRunner:
    """Collection of tests with reporting (internal helper, not a test class)"""
    __test__ = False  # Tell pytest not to collect this class

    def __init__(self, name: str, verbose: bool = False):
        self.name = name
        self.verbose = verbose
        self.tests: List[SuiteResult] = []
        self.checker = EntailmentChecker(
            predicate_registry=PredicateRegistry(),
            verbose=False,
            timeout=10000
        )

    def test_entailment(self, name: str, antecedent: Formula, consequent: Formula,
                       should_be_valid: bool = True) -> SuiteResult:
        """Test a single entailment"""
        start = time.time()
        error = None
        actual = False

        try:
            result = self.checker.check(antecedent, consequent)
            actual = result.valid
        except Exception as e:
            error = str(e)
            actual = False

        time_ms = (time.time() - start) * 1000
        passed = (actual == should_be_valid)

        test_result = SuiteResult(name, passed, should_be_valid, actual, time_ms, error)
        self.tests.append(test_result)

        if self.verbose or not passed:
            print(test_result)

        return test_result

    def test_entailment_str(self, name: str, antecedent_str: str, consequent_str: str,
                           should_be_valid: bool = True) -> SuiteResult:
        """Test entailment using string formulas"""
        try:
            antecedent = parse(antecedent_str)
            consequent = parse(consequent_str)
            return self.test_entailment(name, antecedent, consequent, should_be_valid)
        except Exception as e:
            test_result = SuiteResult(name, False, should_be_valid, False, 0.0, str(e))
            self.tests.append(test_result)
            if self.verbose or not test_result.passed:
                print(test_result)
            return test_result

    def test_satisfiability(self, name: str, formula: Formula,
                           should_be_sat: bool = True) -> SuiteResult:
        """Test satisfiability of a formula"""
        start = time.time()
        error = None
        actual = False

        try:
            actual = self.checker.is_satisfiable(formula)
        except Exception as e:
            error = str(e)
            actual = False

        time_ms = (time.time() - start) * 1000
        passed = (actual == should_be_sat)

        test_result = SuiteResult(name, passed, should_be_sat, actual, time_ms, error)
        self.tests.append(test_result)

        if self.verbose or not passed:
            print(test_result)

        return test_result

    def report(self) -> Tuple[int, int]:
        """Generate test report"""
        passed = sum(1 for t in self.tests if t.passed)
        failed = sum(1 for t in self.tests if not t.passed)
        total = len(self.tests)

        print("\n" + "=" * 70)
        print(f"Test Suite: {self.name}")
        print("=" * 70)

        if failed > 0:
            print("\nFailed Tests:")
            for test in self.tests:
                if not test.passed:
                    print(f"  {test}")

        # Statistics
        total_time = sum(t.time_ms for t in self.tests)
        avg_time = total_time / total if total > 0 else 0
        max_time = max((t.time_ms for t in self.tests), default=0)

        print(f"\nResults: {passed}/{total} passed, {failed}/{total} failed")
        print(f"Time: {total_time:.1f}ms total, {avg_time:.1f}ms avg, {max_time:.1f}ms max")

        if failed == 0:
            print("✓ All tests passed!")
        else:
            print(f"✗ {failed} test(s) failed")

        print("=" * 70)

        return passed, failed


# Backward compatibility aliases
_TestResult = SuiteResult
_TestSuite = SuiteRunner
TestResult = SuiteResult
TestSuite = SuiteRunner
