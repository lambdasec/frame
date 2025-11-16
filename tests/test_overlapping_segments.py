"""
Regression tests for overlapping list segment bug.

Tests the domain overapproximation issue discovered in SAT benchmarks
where formulas like ls(x,y) * ls(x,z) incorrectly return UNSAT.
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from frame import EntailmentChecker, PredicateRegistry
from frame.core.ast import *
from frame.predicates import ListSegment


class TestOverlappingListSegments(unittest.TestCase):
    """Test overlapping list segments from same source variable"""

    def setUp(self):
        self.registry = PredicateRegistry()
        self.registry.register(ListSegment())
        self.checker = EntailmentChecker(self.registry, timeout=10000)

    def test_two_segments_from_same_source_all_equal(self):
        """Test: ls(x,y) * ls(x,z) should be SAT when x=y=z (both empty)"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        # ls(x,y) * ls(x,z) & x=y & y=z
        ls1 = PredicateCall('ls', [x, y])
        ls2 = PredicateCall('ls', [x, z])
        sep = SepConj(ls1, ls2)

        eq1 = Eq(x, y)
        eq2 = Eq(y, z)

        formula = And(And(sep, eq1), eq2)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "ls(x,y) * ls(x,z) & x=y=z should be SAT (both empty)")

    def test_two_segments_from_same_source_one_empty(self):
        """Test: ls(x,y) * ls(x,z) should be SAT when x=y (first empty)"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        # ls(x,y) * ls(x,z) & x=y & x!=z
        ls1 = PredicateCall('ls', [x, y])
        ls2 = PredicateCall('ls', [x, z])
        sep = SepConj(ls1, ls2)

        eq = Eq(x, y)
        neq = Neq(x, z)

        formula = And(And(sep, eq), neq)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "ls(x,y) * ls(x,z) & x=y & x!=z should be SAT (first empty)")

    def test_two_segments_from_same_source_other_empty(self):
        """Test: ls(x,y) * ls(x,z) should be SAT when x=z (second empty)"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        # ls(x,y) * ls(x,z) & x=z & x!=y
        ls1 = PredicateCall('ls', [x, y])
        ls2 = PredicateCall('ls', [x, z])
        sep = SepConj(ls1, ls2)

        eq = Eq(x, z)
        neq = Neq(x, y)

        formula = And(And(sep, eq), neq)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "ls(x,y) * ls(x,z) & x=z & x!=y should be SAT (second empty)")

    def test_two_segments_from_same_source_both_nonempty(self):
        """Test: ls(x,y) * ls(x,z) should be UNSAT when x!=y and x!=z (both non-empty from x)"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        # ls(x,y) * ls(x,z) & x!=y & x!=z
        ls1 = PredicateCall('ls', [x, y])
        ls2 = PredicateCall('ls', [x, z])
        sep = SepConj(ls1, ls2)

        neq1 = Neq(x, y)
        neq2 = Neq(x, z)

        formula = And(And(sep, neq1), neq2)

        result = self.checker.is_satisfiable(formula)
        self.assertFalse(result, "ls(x,y) * ls(x,z) & x!=y & x!=z should be UNSAT (both allocate from x)")

    def test_two_segments_from_same_source_no_constraints(self):
        """Test: ls(x,y) * ls(x,z) should be SAT without extra constraints"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        # ls(x,y) * ls(x,z) - should be SAT (can pick case where both are empty)
        ls1 = PredicateCall('ls', [x, y])
        ls2 = PredicateCall('ls', [x, z])
        formula = SepConj(ls1, ls2)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "ls(x,y) * ls(x,z) should be SAT (satisfiable when x=y=z)")

    def test_three_segments_from_same_source(self):
        """Test: ls(x,a) * ls(x,b) * ls(x,c) should be SAT when all equal"""
        x = Var('x')
        a = Var('a')
        b = Var('b')
        c = Var('c')

        # ls(x,a) * ls(x,b) * ls(x,c) & x=a=b=c
        ls1 = PredicateCall('ls', [x, a])
        ls2 = PredicateCall('ls', [x, b])
        ls3 = PredicateCall('ls', [x, c])

        sep1 = SepConj(ls1, ls2)
        sep2 = SepConj(sep1, ls3)

        eq1 = Eq(x, a)
        eq2 = Eq(a, b)
        eq3 = Eq(b, c)

        formula = And(And(And(sep2, eq1), eq2), eq3)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "ls(x,a) * ls(x,b) * ls(x,c) & x=a=b=c should be SAT (all empty)")

    def test_chain_pattern_from_benchmarks(self):
        """Test pattern from spaguetti benchmarks: ls(x2,x4) * ls(x3,x9) * ls(x3,x1)"""
        x2 = Var('x2')
        x3 = Var('x3')
        x4 = Var('x4')
        x9 = Var('x9')
        x1 = Var('x1')

        # ls(x2,x4) * ls(x3,x9) * ls(x3,x1)
        # This should be SAT when x3=x9=x1 (second and third are empty)
        ls1 = PredicateCall('ls', [x2, x4])
        ls2 = PredicateCall('ls', [x3, x9])
        ls3 = PredicateCall('ls', [x3, x1])

        sep1 = SepConj(ls1, ls2)
        sep2 = SepConj(sep1, ls3)

        # Add constraint to make x3 segments empty
        eq1 = Eq(x3, x9)
        eq2 = Eq(x3, x1)

        formula = And(And(sep2, eq1), eq2)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "Benchmark pattern should be SAT when overlapping segments are empty")

    def test_multiple_overlaps_mixed(self):
        """Test: ls(x,y) * ls(x,z) * ls(a,b) * ls(a,c) - two pairs of overlaps"""
        x = Var('x')
        y = Var('y')
        z = Var('z')
        a = Var('a')
        b = Var('b')
        c = Var('c')

        # ls(x,y) * ls(x,z) * ls(a,b) * ls(a,c)
        # Should be SAT when x=y=z and a=b=c (all empty)
        ls1 = PredicateCall('ls', [x, y])
        ls2 = PredicateCall('ls', [x, z])
        ls3 = PredicateCall('ls', [a, b])
        ls4 = PredicateCall('ls', [a, c])

        sep1 = SepConj(ls1, ls2)
        sep2 = SepConj(sep1, ls3)
        sep3 = SepConj(sep2, ls4)

        eq1 = Eq(x, y)
        eq2 = Eq(y, z)
        eq3 = Eq(a, b)
        eq4 = Eq(b, c)

        constraints = And(And(And(And(sep3, eq1), eq2), eq3), eq4)

        result = self.checker.is_satisfiable(constraints)
        self.assertTrue(result, "Multiple overlapping pairs should be SAT when all are empty")


class TestNonOverlappingSegments(unittest.TestCase):
    """Control tests: non-overlapping segments that should always work"""

    def setUp(self):
        self.registry = PredicateRegistry()
        self.registry.register(ListSegment())
        self.checker = EntailmentChecker(self.registry, timeout=10000)

    def test_chain_segments(self):
        """Test: ls(x,y) * ls(y,z) should be SAT (chain, no overlap)"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        ls1 = PredicateCall('ls', [x, y])
        ls2 = PredicateCall('ls', [y, z])
        formula = SepConj(ls1, ls2)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "ls(x,y) * ls(y,z) should be SAT (chain)")

    def test_independent_segments(self):
        """Test: ls(x,y) * ls(a,b) should be SAT (independent)"""
        x = Var('x')
        y = Var('y')
        a = Var('a')
        b = Var('b')

        ls1 = PredicateCall('ls', [x, y])
        ls2 = PredicateCall('ls', [a, b])
        formula = SepConj(ls1, ls2)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "ls(x,y) * ls(a,b) should be SAT (independent)")


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestOverlappingListSegments))
    suite.addTests(loader.loadTestsFromTestCase(TestNonOverlappingSegments))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
