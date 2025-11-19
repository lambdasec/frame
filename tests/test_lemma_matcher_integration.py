"""
Tests for Lemma Matcher (frame/lemmas/_matcher.py)

Tests pattern matching for lemma application with meta-variables.
"""

import pytest
from frame.lemmas._matcher import LemmaMatcher
from frame.core.ast import (
    Var, Const, Emp, PointsTo, SepConj, And, Or, Eq, Neq,
    PredicateCall, Exists, Forall, ArithExpr, True_, False_,
    Lt, Le, Gt, Ge, Wand, Not
)


class TestExprEqual:
    """Test _expr_equal method"""

    def setup_method(self):
        """Set up test matcher"""
        self.matcher = LemmaMatcher()

    def test_var_equal(self):
        """Test variable equality"""
        assert self.matcher._expr_equal(Var('x'), Var('x')) is True
        assert self.matcher._expr_equal(Var('x'), Var('y')) is False

    def test_const_equal(self):
        """Test constant equality"""
        assert self.matcher._expr_equal(Const(5), Const(5)) is True
        assert self.matcher._expr_equal(Const(5), Const(10)) is False

    def test_different_types(self):
        """Test different types are not equal"""
        assert self.matcher._expr_equal(Var('x'), Const(5)) is False

    def test_arith_expr_equal(self):
        """Test arithmetic expression equality"""
        arith1 = ArithExpr('+', Var('x'), Const(5))
        arith2 = ArithExpr('+', Var('x'), Const(5))
        arith3 = ArithExpr('+', Var('y'), Const(5))

        assert self.matcher._expr_equal(arith1, arith2) is True
        assert self.matcher._expr_equal(arith1, arith3) is False

    def test_arith_expr_different_op(self):
        """Test arithmetic with different operator"""
        arith1 = ArithExpr('+', Var('x'), Const(5))
        arith2 = ArithExpr('-', Var('x'), Const(5))

        assert self.matcher._expr_equal(arith1, arith2) is False


class TestIsSpatialPattern:
    """Test _is_spatial_pattern method"""

    def setup_method(self):
        """Set up test matcher"""
        self.matcher = LemmaMatcher()

    def test_sepconj_is_spatial(self):
        """Test SepConj is spatial"""
        assert self.matcher._is_spatial_pattern(SepConj(Emp(), Emp())) is True

    def test_points_to_is_spatial(self):
        """Test PointsTo is spatial"""
        assert self.matcher._is_spatial_pattern(PointsTo(Var('x'), [Var('y')])) is True

    def test_predicate_call_is_spatial(self):
        """Test PredicateCall is spatial"""
        assert self.matcher._is_spatial_pattern(PredicateCall('list', [Var('x')])) is True

    def test_emp_is_spatial(self):
        """Test Emp is spatial"""
        assert self.matcher._is_spatial_pattern(Emp()) is True

    def test_wand_is_spatial(self):
        """Test Wand is spatial"""
        assert self.matcher._is_spatial_pattern(Wand(Emp(), Emp())) is True

    def test_and_not_spatial(self):
        """Test And is not spatial"""
        assert self.matcher._is_spatial_pattern(And(Emp(), Emp())) is False

    def test_eq_not_spatial(self):
        """Test Eq is not spatial"""
        assert self.matcher._is_spatial_pattern(Eq(Var('x'), Var('y'))) is False


class TestFormulasEqual:
    """Test formulas_equal method"""

    def setup_method(self):
        """Set up test matcher"""
        self.matcher = LemmaMatcher()

    def test_emp_equal(self):
        """Test emp equals emp"""
        assert self.matcher.formulas_equal(Emp(), Emp()) is True

    def test_true_false_equal(self):
        """Test True/False equality"""
        assert self.matcher.formulas_equal(True_(), True_()) is True
        assert self.matcher.formulas_equal(False_(), False_()) is True
        assert self.matcher.formulas_equal(True_(), False_()) is False

    def test_var_equal(self):
        """Test variable equality"""
        assert self.matcher.formulas_equal(Var('x'), Var('x')) is True
        assert self.matcher.formulas_equal(Var('x'), Var('y')) is False

    def test_const_equal(self):
        """Test constant equality"""
        assert self.matcher.formulas_equal(Const(5), Const(5)) is True
        assert self.matcher.formulas_equal(Const(5), Const(10)) is False

    def test_equality_formula_equal(self):
        """Test equality formulas"""
        eq1 = Eq(Var('x'), Const(5))
        eq2 = Eq(Var('x'), Const(5))
        eq3 = Eq(Var('y'), Const(5))

        assert self.matcher.formulas_equal(eq1, eq2) is True
        assert self.matcher.formulas_equal(eq1, eq3) is False

    def test_comparisons_equal(self):
        """Test comparison formulas"""
        lt1 = Lt(Var('x'), Const(5))
        lt2 = Lt(Var('x'), Const(5))

        assert self.matcher.formulas_equal(lt1, lt2) is True

    def test_points_to_equal(self):
        """Test points-to equality"""
        pto1 = PointsTo(Var('x'), [Var('y'), Const(5)])
        pto2 = PointsTo(Var('x'), [Var('y'), Const(5)])
        pto3 = PointsTo(Var('x'), [Var('z'), Const(5)])

        assert self.matcher.formulas_equal(pto1, pto2) is True
        assert self.matcher.formulas_equal(pto1, pto3) is False

    def test_predicate_call_equal(self):
        """Test predicate call equality"""
        pred1 = PredicateCall('list', [Var('x'), Var('y')])
        pred2 = PredicateCall('list', [Var('x'), Var('y')])
        pred3 = PredicateCall('tree', [Var('x'), Var('y')])

        assert self.matcher.formulas_equal(pred1, pred2) is True
        assert self.matcher.formulas_equal(pred1, pred3) is False

    def test_sepconj_commutative(self):
        """Test SepConj commutativity in equality check"""
        sep1 = SepConj(
            PointsTo(Var('x'), [Var('y')]),
            PointsTo(Var('a'), [Var('b')])
        )
        sep2 = SepConj(
            PointsTo(Var('x'), [Var('y')]),
            PointsTo(Var('a'), [Var('b')])
        )
        sep3 = SepConj(
            PointsTo(Var('a'), [Var('b')]),
            PointsTo(Var('x'), [Var('y')])
        )

        assert self.matcher.formulas_equal(sep1, sep2) is True
        # Should be equal due to commutativity
        assert self.matcher.formulas_equal(sep1, sep3) is True

    def test_and_commutative(self):
        """Test And commutativity"""
        and1 = And(Eq(Var('x'), Const(5)), Emp())
        and2 = And(Emp(), Eq(Var('x'), Const(5)))

        assert self.matcher.formulas_equal(and1, and2) is True

    def test_not_equal(self):
        """Test Not equality"""
        not1 = Not(Eq(Var('x'), Const(5)))
        not2 = Not(Eq(Var('x'), Const(5)))
        not3 = Not(Eq(Var('y'), Const(5)))

        assert self.matcher.formulas_equal(not1, not2) is True
        assert self.matcher.formulas_equal(not1, not3) is False

    def test_quantifiers_equal(self):
        """Test quantifier equality"""
        exists1 = Exists('x', Eq(Var('x'), Const(5)))
        exists2 = Exists('x', Eq(Var('x'), Const(5)))
        exists3 = Exists('y', Eq(Var('y'), Const(5)))

        assert self.matcher.formulas_equal(exists1, exists2) is True
        # Different quantified var names
        assert self.matcher.formulas_equal(exists1, exists3) is False

    def test_type_mismatch(self):
        """Test different types are not equal"""
        assert self.matcher.formulas_equal(Emp(), True_()) is False
        assert self.matcher.formulas_equal(And(Emp(), Emp()), Or(Emp(), Emp())) is False


class TestIntegration:
    """Integration tests"""

    def test_complex_pattern_matching(self):
        """Test complex pattern with multiple meta-variables"""
        matcher = LemmaMatcher()

        pattern = SepConj(
            PointsTo(Var('X'), [Var('Y')]),
            PredicateCall('list', [Var('Y'), Var('Z')])
        )

        formula = SepConj(
            PointsTo(Var('a'), [Var('b')]),
            PredicateCall('list', [Var('b'), Var('nil')])
        )

        result = matcher.match_formula(pattern, formula)

        assert result is not None
        assert result['X'].name == 'a'
        assert result['Y'].name == 'b'
        assert result['Z'].name == 'nil'

    def test_nested_pattern_matching(self):
        """Test nested pattern matching"""
        matcher = LemmaMatcher()

        pattern = And(
            SepConj(PointsTo(Var('X'), [Var('Y')]), Emp()),
            Eq(Var('X'), Var('Y'))
        )

        formula = And(
            SepConj(PointsTo(Var('a'), [Var('b')]), Emp()),
            Eq(Var('a'), Var('b'))
        )

        result = matcher.match_formula(pattern, formula)

        assert result is not None

    def test_formula_equality_complex(self):
        """Test formula equality on complex formulas"""
        matcher = LemmaMatcher()

        f1 = SepConj(
            And(PointsTo(Var('x'), [Var('y')]), Eq(Var('x'), Const(5))),
            PredicateCall('list', [Var('y')])
        )

        f2 = SepConj(
            And(PointsTo(Var('x'), [Var('y')]), Eq(Var('x'), Const(5))),
            PredicateCall('list', [Var('y')])
        )

        assert matcher.formulas_equal(f1, f2) is True
