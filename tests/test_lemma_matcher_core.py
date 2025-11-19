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


class TestMatchFormula:
    """Test match_formula method"""

    def setup_method(self):
        """Set up test matcher"""
        self.matcher = LemmaMatcher()

    def test_match_emp(self):
        """Test matching emp"""
        result = self.matcher.match_formula(Emp(), Emp())
        assert result is not None
        assert result == {}

    def test_match_true_false(self):
        """Test matching True/False"""
        assert self.matcher.match_formula(True_(), True_()) is not None
        assert self.matcher.match_formula(False_(), False_()) is not None
        assert self.matcher.match_formula(True_(), False_()) is None

    def test_match_meta_variable(self):
        """Test matching meta-variable (capitalized)"""
        pattern = Var('X')
        formula = Var('a')

        result = self.matcher.match_formula(pattern, formula)

        assert result is not None
        assert 'X' in result
        assert result['X'].name == 'a'

    def test_match_meta_variable_consistency(self):
        """Test meta-variable must bind consistently"""
        pattern = Eq(Var('X'), Var('X'))
        formula = Eq(Var('a'), Var('a'))

        result = self.matcher.match_formula(pattern, formula)
        assert result is not None

        # Should fail if variables don't match
        formula_bad = Eq(Var('a'), Var('b'))
        result = self.matcher.match_formula(pattern, formula_bad)
        assert result is None

    def test_match_regular_var(self):
        """Test matching regular variable (not meta)"""
        pattern = Var('x')
        formula = Var('x')

        result = self.matcher.match_formula(pattern, formula)
        assert result is not None

        # Should fail if names don't match
        result = self.matcher.match_formula(pattern, Var('y'))
        assert result is None

    def test_match_const(self):
        """Test matching constants"""
        pattern = Const(5)
        formula = Const(5)

        result = self.matcher.match_formula(pattern, formula)
        assert result is not None

        # Should fail if values don't match
        result = self.matcher.match_formula(pattern, Const(10))
        assert result is None

    def test_match_equality(self):
        """Test matching equality"""
        pattern = Eq(Var('X'), Var('Y'))
        formula = Eq(Var('a'), Var('b'))

        result = self.matcher.match_formula(pattern, formula)

        assert result is not None
        assert result['X'].name == 'a'
        assert result['Y'].name == 'b'

    def test_match_points_to(self):
        """Test matching points-to"""
        pattern = PointsTo(Var('X'), [Var('Y')])
        formula = PointsTo(Var('a'), [Var('b')])

        result = self.matcher.match_formula(pattern, formula)

        assert result is not None
        assert result['X'].name == 'a'
        assert result['Y'].name == 'b'

    def test_match_points_to_arity_mismatch(self):
        """Test points-to with wrong arity fails"""
        pattern = PointsTo(Var('X'), [Var('Y')])
        formula = PointsTo(Var('a'), [Var('b'), Var('c')])

        result = self.matcher.match_formula(pattern, formula)
        assert result is None

    def test_match_predicate_call(self):
        """Test matching predicate call"""
        pattern = PredicateCall('list', [Var('X'), Var('Y')])
        formula = PredicateCall('list', [Var('a'), Var('b')])

        result = self.matcher.match_formula(pattern, formula)

        assert result is not None
        assert result['X'].name == 'a'
        assert result['Y'].name == 'b'

    def test_match_predicate_wrong_name(self):
        """Test predicate with wrong name fails"""
        pattern = PredicateCall('list', [Var('X')])
        formula = PredicateCall('tree', [Var('a')])

        result = self.matcher.match_formula(pattern, formula)
        assert result is None

    def test_match_predicate_arity_mismatch(self):
        """Test predicate with wrong arity fails"""
        pattern = PredicateCall('list', [Var('X')])
        formula = PredicateCall('list', [Var('a'), Var('b')])

        result = self.matcher.match_formula(pattern, formula)
        assert result is None

    def test_match_sepconj_commutative(self):
        """Test SepConj matches in both orders (commutativity)"""
        pattern = SepConj(
            PointsTo(Var('X'), [Var('Y')]),
            PointsTo(Var('Y'), [Var('Z')])
        )

        # Match in same order
        formula1 = SepConj(
            PointsTo(Var('a'), [Var('b')]),
            PointsTo(Var('b'), [Var('c')])
        )
        result1 = self.matcher.match_formula(pattern, formula1)
        assert result1 is not None

        # Match in reversed order (commutativity)
        formula2 = SepConj(
            PointsTo(Var('b'), [Var('c')]),
            PointsTo(Var('a'), [Var('b')])
        )
        result2 = self.matcher.match_formula(pattern, formula2)
        assert result2 is not None

    def test_match_and_commutative(self):
        """Test And matches in both orders"""
        pattern = And(Eq(Var('X'), Const(5)), Emp())

        # Same order
        formula1 = And(Eq(Var('a'), Const(5)), Emp())
        assert self.matcher.match_formula(pattern, formula1) is not None

        # Reversed order
        formula2 = And(Emp(), Eq(Var('a'), Const(5)))
        assert self.matcher.match_formula(pattern, formula2) is not None

    def test_match_wand_not_commutative(self):
        """Test Wand is NOT commutative"""
        pattern = Wand(Emp(), PointsTo(Var('X'), [Var('Y')]))

        # Same order matches
        formula1 = Wand(Emp(), PointsTo(Var('a'), [Var('b')]))
        assert self.matcher.match_formula(pattern, formula1) is not None

        # Reversed order should NOT match (wand not commutative)
        formula2 = Wand(PointsTo(Var('a'), [Var('b')]), Emp())
        assert self.matcher.match_formula(pattern, formula2) is None

    def test_match_not(self):
        """Test matching Not"""
        pattern = Not(Eq(Var('X'), Const(5)))
        formula = Not(Eq(Var('a'), Const(5)))

        result = self.matcher.match_formula(pattern, formula)
        assert result is not None

    def test_match_quantifiers(self):
        """Test matching quantifiers"""
        pattern = Exists('x', Eq(Var('X'), Var('x')))
        formula = Exists('x', Eq(Var('a'), Var('x')))

        result = self.matcher.match_formula(pattern, formula)
        assert result is not None

        # Should fail if quantified var names don't match
        formula_bad = Exists('y', Eq(Var('a'), Var('y')))
        assert self.matcher.match_formula(pattern, formula_bad) is None

    def test_match_spatial_pattern_against_and(self):
        """Test spatial pattern matches against And formula"""
        # Spatial pattern can match left or right side of And
        pattern = PointsTo(Var('X'), [Var('Y')])
        formula = And(
            PointsTo(Var('a'), [Var('b')]),
            Eq(Var('a'), Var('c'))
        )

        result = self.matcher.match_formula(pattern, formula)
        # Should match the spatial part (left side)
        assert result is not None

    def test_match_type_mismatch(self):
        """Test matching with type mismatch fails"""
        pattern = Emp()
        formula = True_()

        result = self.matcher.match_formula(pattern, formula)
        assert result is None


class TestMatchExpr:
    """Test match_expr method"""

    def setup_method(self):
        """Set up test matcher"""
        self.matcher = LemmaMatcher()

    def test_match_meta_var(self):
        """Test matching meta-variable"""
        pattern = Var('X')
        expr = Var('a')

        result = self.matcher.match_expr(pattern, expr)

        assert result is not None
        assert 'X' in result
        assert result['X'].name == 'a'

    def test_match_meta_var_to_const(self):
        """Test meta-variable can match constant"""
        pattern = Var('X')
        expr = Const(5)

        result = self.matcher.match_expr(pattern, expr)

        assert result is not None
        assert result['X'].value == 5

    def test_match_regular_var(self):
        """Test matching regular variable"""
        pattern = Var('x')
        expr = Var('x')

        result = self.matcher.match_expr(pattern, expr)
        assert result is not None

        # Should fail if names don't match
        assert self.matcher.match_expr(pattern, Var('y')) is None

    def test_match_const(self):
        """Test matching constant"""
        pattern = Const(5)
        expr = Const(5)

        result = self.matcher.match_expr(pattern, expr)
        assert result is not None

        # Should fail if values don't match
        assert self.matcher.match_expr(pattern, Const(10)) is None

    def test_match_arith_expr(self):
        """Test matching arithmetic expression"""
        pattern = ArithExpr('+', Var('X'), Const(5))
        expr = ArithExpr('+', Var('a'), Const(5))

        result = self.matcher.match_expr(pattern, expr)

        assert result is not None
        assert result['X'].name == 'a'

    def test_match_arith_expr_wrong_op(self):
        """Test arithmetic with wrong operator fails"""
        pattern = ArithExpr('+', Var('X'), Const(5))
        expr = ArithExpr('-', Var('a'), Const(5))

        result = self.matcher.match_expr(pattern, expr)
        assert result is None

    def test_match_type_mismatch(self):
        """Test type mismatch fails"""
        pattern = Var('X')
        expr = ArithExpr('+', Var('a'), Const(5))

        # Meta-variable can match any expression
        result = self.matcher.match_expr(pattern, expr)
        assert result is not None

        # But regular var cannot match ArithExpr
        pattern_regular = Var('x')
        assert self.matcher.match_expr(pattern_regular, expr) is None


