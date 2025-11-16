"""
Regression tests for SAT checking improvements.

These tests prevent regressions in:
1. NOT(PointsTo) encoding for qf_bsllia_sat
2. Or expression handling with spatial formulas
3. And vs SepConj semantics
4. Arithmetic expression support
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from frame import EntailmentChecker, PredicateRegistry
from frame.core.ast import *


class TestNegatedPointsTo(unittest.TestCase):
    """Test NOT(x |-> y) encoding"""

    def setUp(self):
        self.registry = PredicateRegistry()
        self.checker = EntailmentChecker(self.registry)

    def test_simple_negated_pointsto(self):
        """Test: x |-> y & NOT(x |-> z) should be SAT when y != z"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        # x |-> y & NOT(x |-> z) & y != z
        pto1 = PointsTo(x, [y])
        pto2 = PointsTo(x, [z])
        not_pto = Not(pto2)
        neq = Neq(y, z)

        formula = And(And(pto1, not_pto), neq)

        # Should be SAT - x can point to y which is different from z
        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "x |-> y & NOT(x |-> z) & y != z should be SAT")

    def test_negated_pointsto_contradiction(self):
        """Test: x |-> y & NOT(x |-> y) should be UNSAT"""
        x = Var('x')
        y = Var('y')

        pto = PointsTo(x, [y])
        not_pto = Not(pto)

        formula = And(pto, not_pto)

        # Should be UNSAT - contradiction
        result = self.checker.is_satisfiable(formula)
        self.assertFalse(result, "x |-> y & NOT(x |-> y) should be UNSAT")


class TestOrWithSpatial(unittest.TestCase):
    """Test Or expressions with spatial formulas"""

    def setUp(self):
        self.registry = PredicateRegistry()
        self.checker = EntailmentChecker(self.registry)

    def test_or_two_pointsto(self):
        """Test: (x |-> y) | (a |-> b) should be SAT"""
        x = Var('x')
        y = Var('y')
        a = Var('a')
        b = Var('b')

        pto1 = PointsTo(x, [y])
        pto2 = PointsTo(a, [b])

        formula = Or(pto1, pto2)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "(x |-> y) | (a |-> b) should be SAT")

    def test_or_with_spatial_sepconj(self):
        """Test: (x |-> y * a |-> b) | (c |-> d) should be SAT"""
        x = Var('x')
        y = Var('y')
        a = Var('a')
        b = Var('b')
        c = Var('c')
        d = Var('d')

        pto1 = PointsTo(x, [y])
        pto2 = PointsTo(a, [b])
        left = SepConj(pto1, pto2)

        pto3 = PointsTo(c, [d])

        formula = Or(left, pto3)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "(x |-> y * a |-> b) | (c |-> d) should be SAT")


class TestAndVsSepConj(unittest.TestCase):
    """Test And vs SepConj semantics"""

    def setUp(self):
        self.registry = PredicateRegistry()
        self.checker = EntailmentChecker(self.registry)

    def test_and_with_pure_and_spatial(self):
        """Test: (x = y) & (a |-> b) should be SAT (And with mixed)"""
        x = Var('x')
        y = Var('y')
        a = Var('a')
        b = Var('b')

        eq = Eq(x, y)
        pto = PointsTo(a, [b])

        # And of pure and spatial - should work
        formula = And(eq, pto)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "(x = y) & (a |-> b) should be SAT")

    def test_sepconj_requires_disjoint(self):
        """Test: (x |-> y) * (x |-> z) should be UNSAT (SepConj requires disjoint)"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        pto1 = PointsTo(x, [y])
        pto2 = PointsTo(x, [z])

        # SepConj requires disjoint domains
        formula = SepConj(pto1, pto2)

        result = self.checker.is_satisfiable(formula)
        self.assertFalse(result, "(x |-> y) * (x |-> z) should be UNSAT with SepConj")

    def test_sepconj_disjoint_sat(self):
        """Test: (x |-> y) * (a |-> b) should be SAT when x != a"""
        x = Var('x')
        y = Var('y')
        a = Var('a')
        b = Var('b')

        pto1 = PointsTo(x, [y])
        pto2 = PointsTo(a, [b])
        neq = Neq(x, a)

        formula = And(SepConj(pto1, pto2), neq)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "(x |-> y) * (a |-> b) & x != a should be SAT")


class TestArithmeticSupport(unittest.TestCase):
    """Test arithmetic expression support"""

    def setUp(self):
        self.registry = PredicateRegistry()
        self.checker = EntailmentChecker(self.registry)

    def test_arithmetic_in_pure(self):
        """Test: x = y + 1 & y = 5 & x = 6 should be SAT"""
        x = Var('x')
        y = Var('y')

        # x = y + 1
        plus = ArithExpr('+', y, Const(1))
        eq1 = Eq(x, plus)

        # y = 5
        eq2 = Eq(y, Const(5))

        # x = 6
        eq3 = Eq(x, Const(6))

        formula = And(And(eq1, eq2), eq3)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "x = y + 1 & y = 5 & x = 6 should be SAT")

    def test_arithmetic_contradiction(self):
        """Test: x = y + 1 & x = y should be UNSAT"""
        x = Var('x')
        y = Var('y')

        plus = ArithExpr('+', y, Const(1))
        eq1 = Eq(x, plus)
        eq2 = Eq(x, y)

        formula = And(eq1, eq2)

        result = self.checker.is_satisfiable(formula)
        self.assertFalse(result, "x = y + 1 & x = y should be UNSAT")


class TestComplexSATScenarios(unittest.TestCase):
    """Test complex SAT scenarios from benchmarks"""

    def setUp(self):
        self.registry = PredicateRegistry()
        self.checker = EntailmentChecker(self.registry)

    def test_chain_sat_pattern(self):
        """Test pattern from chain-sat benchmarks: NOT(pto) in And context"""
        u = Var('u')
        v = Var('v')
        y = Var('y')
        t = Var('t')

        # Simplified pattern: u |-> v & NOT(v |-> t) & t != y
        pto1 = PointsTo(u, [v])
        pto2 = PointsTo(v, [t])
        not_pto = Not(pto2)
        neq = Neq(t, y)

        formula = And(And(pto1, not_pto), neq)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "Chain-sat pattern should be SAT")

    def test_or_with_mixed_formula(self):
        """Test: (x = y & emp) | (a |-> b) should be SAT"""
        x = Var('x')
        y = Var('y')
        a = Var('a')
        b = Var('b')

        # Left: x = y & emp
        eq = Eq(x, y)
        emp = Emp()
        left = And(eq, emp)

        # Right: a |-> b
        right = PointsTo(a, [b])

        formula = Or(left, right)

        result = self.checker.is_satisfiable(formula)
        self.assertTrue(result, "(x = y & emp) | (a |-> b) should be SAT")


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestNegatedPointsTo))
    suite.addTests(loader.loadTestsFromTestCase(TestOrWithSpatial))
    suite.addTests(loader.loadTestsFromTestCase(TestAndVsSepConj))
    suite.addTests(loader.loadTestsFromTestCase(TestArithmeticSupport))
    suite.addTests(loader.loadTestsFromTestCase(TestComplexSATScenarios))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
