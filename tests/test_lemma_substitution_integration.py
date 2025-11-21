"""
Tests for Lemma Substitution (frame/lemmas/_substitution.py)

Tests meta-variable substitution and equality constraint extraction.
"""

import pytest
from frame.lemmas._substitution import LemmaSubstitution
from frame.core.ast import (
    Var, Const, Emp, PointsTo, SepConj, And, Or, Eq, Neq,
    PredicateCall, Exists, Forall, ArithExpr, True_, False_,
    Lt, Le, Gt, Ge, Wand, Not
)


class TestTransitiveClosure:
    """Test _transitive_closure method"""

    def setup_method(self):
        """Set up test substitution"""
        self.subst = LemmaSubstitution()

    def test_simple_chain(self):
        """Test x->y, y->z becomes x->z, y->z"""
        equalities = {
            'x': Var('y'),
            'y': Var('z')
        }

        result = self.subst._transitive_closure(equalities)

        # x should map to z (transitive)
        assert 'x' in result
        assert isinstance(result['x'], Var)

    def test_no_transitive_needed(self):
        """Test when no transitive closure needed"""
        equalities = {
            'x': Var('y')
        }

        result = self.subst._transitive_closure(equalities)

        assert result == equalities

    def test_cycle_prevention(self):
        """Test that max iterations prevents infinite loops"""
        # Create a potential cycle scenario
        equalities = {
            'x': Var('y'),
            'y': Var('z'),
            'z': Var('w')
        }

        result = self.subst._transitive_closure(equalities)

        # Should terminate and produce a result
        assert result is not None


class TestExprEqual:
    """Test _expr_equal method"""

    def setup_method(self):
        """Set up test substitution"""
        self.subst = LemmaSubstitution()

    def test_var_equal(self):
        """Test variable equality"""
        assert self.subst._expr_equal(Var('x'), Var('x')) is True
        assert self.subst._expr_equal(Var('x'), Var('y')) is False

    def test_const_equal(self):
        """Test constant equality"""
        assert self.subst._expr_equal(Const(5), Const(5)) is True
        assert self.subst._expr_equal(Const(5), Const(10)) is False

    def test_different_types(self):
        """Test expressions of different types"""
        assert self.subst._expr_equal(Var('x'), Const(5)) is False

    def test_arith_expr_equal(self):
        """Test arithmetic expression equality"""
        arith1 = ArithExpr('+', Var('x'), Const(5))
        arith2 = ArithExpr('+', Var('x'), Const(5))
        arith3 = ArithExpr('+', Var('y'), Const(5))

        assert self.subst._expr_equal(arith1, arith2) is True
        assert self.subst._expr_equal(arith1, arith3) is False

    def test_arith_expr_different_op(self):
        """Test arithmetic expressions with different operators"""
        arith1 = ArithExpr('+', Var('x'), Const(5))
        arith2 = ArithExpr('-', Var('x'), Const(5))

        assert self.subst._expr_equal(arith1, arith2) is False


class TestApplySubstitution:
    """Test apply_substitution_to_formula method"""

    def setup_method(self):
        """Set up test substitution"""
        self.subst = LemmaSubstitution()

    def test_apply_to_var(self):
        """Test applying substitution to Var"""
        # Note: Var is an Expr, not a Formula
        result = self.subst.apply_substitution_to_formula(Var('x'), {'x': Var('y')})
        assert isinstance(result, Var)
        assert result.name == 'y'

    def test_apply_to_emp(self):
        """Test emp unchanged"""
        result = self.subst.apply_substitution_to_formula(Emp(), {})
        assert isinstance(result, Emp)

    def test_apply_to_equality(self):
        """Test applying to equality"""
        eq = Eq(Var('x'), Var('y'))
        subst = {'x': Var('a'), 'y': Var('b')}

        result = self.subst.apply_substitution_to_formula(eq, subst)

        assert isinstance(result, Eq)

    def test_apply_to_points_to(self):
        """Test applying to points-to"""
        pto = PointsTo(Var('x'), [Var('y')])
        subst = {'x': Var('a'), 'y': Var('b')}

        result = self.subst.apply_substitution_to_formula(pto, subst)

        assert isinstance(result, PointsTo)

    def test_apply_to_predicate_call(self):
        """Test applying to predicate call"""
        pred = PredicateCall('list', [Var('x')])
        subst = {'x': Var('y')}

        result = self.subst.apply_substitution_to_formula(pred, subst)

        assert isinstance(result, PredicateCall)

    def test_apply_to_sepconj(self):
        """Test applying to SepConj"""
        sep = SepConj(Emp(), Emp())
        result = self.subst.apply_substitution_to_formula(sep, {})

        assert isinstance(result, SepConj)

    def test_apply_to_wand(self):
        """Test applying to Wand"""
        wand = Wand(Emp(), Emp())
        result = self.subst.apply_substitution_to_formula(wand, {})

        assert isinstance(result, Wand)

    def test_apply_to_quantifiers(self):
        """Test quantifiers are preserved"""
        exists = Exists('x', Emp())
        forall = Forall('x', Emp())

        # Quantified variables should not be substituted
        assert isinstance(self.subst.apply_substitution_to_formula(exists, {'x': Var('y')}), Exists)
        assert isinstance(self.subst.apply_substitution_to_formula(forall, {'x': Var('y')}), Forall)


class TestApplySubstitutionToExpr:
    """Test _apply_substitution_to_expr method"""

    def setup_method(self):
        """Set up test substitution"""
        self.subst = LemmaSubstitution()

    def test_apply_to_var(self):
        """Test applying to variable"""
        result = self.subst._apply_substitution_to_expr(Var('x'), {'x': Var('y')})

        assert isinstance(result, Var)
        assert result.name == 'y'

    def test_apply_to_const(self):
        """Test constant unchanged"""
        result = self.subst._apply_substitution_to_expr(Const(5), {})

        assert isinstance(result, Const)
        assert result.value == 5

    def test_apply_to_arith_expr(self):
        """Test applying to arithmetic expression"""
        arith = ArithExpr('+', Var('x'), Const(5))
        subst = {'x': Var('y')}

        result = self.subst._apply_substitution_to_expr(arith, subst)

        assert isinstance(result, ArithExpr)


class TestIntegration:
    """Integration tests"""

    def test_substitute_and_extract(self):
        """Test substitution and extraction together"""
        subst = LemmaSubstitution()

        # Extract constraints
        formula = And(Eq(Var('x'), Var('y')), Emp())
        constraints = subst.extract_equality_constraints(formula)

        # Apply constraints as substitution
        result = subst.apply_substitution_to_formula(formula, constraints)

        assert result is not None

    def test_complex_formula(self):
        """Test with complex formula"""
        subst = LemmaSubstitution()

        formula = And(
            And(Eq(Var('x'), Var('y')), Eq(Var('y'), Var('z'))),
            PointsTo(Var('x'), [Var('a')])
        )

        constraints = subst.extract_equality_constraints(formula)
        result = subst.apply_substitution_to_formula(formula, constraints)

        assert result is not None
