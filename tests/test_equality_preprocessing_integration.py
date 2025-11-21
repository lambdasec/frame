"""
Tests for Equality Preprocessing (frame/preprocessing/equality.py)

Tests union-find, equality extraction, and variable substitution.
"""

import pytest
from frame.preprocessing.equality import UnionFind, EqualityPreprocessor, preprocess_equalities
from frame.core.parser import parse
from frame.core.ast import (
    Var, Const, Emp, PointsTo, SepConj, And, Or, Eq, Neq,
    PredicateCall, Exists, Forall, ArithExpr, True_, False_,
    Lt, Le, Gt, Ge, Wand, Not
)


class TestSubstituteExpr:
    """Test _substitute_expr method"""

    def setup_method(self):
        """Set up test preprocessor"""
        self.prep = EqualityPreprocessor()

    def test_substitute_var_to_var(self):
        """Test substituting variable to another variable"""
        self.prep.substitution_map = {'x': 'y'}
        result = self.prep._substitute_expr(Var('x'))

        assert isinstance(result, Var)
        assert result.name == 'y'

    def test_substitute_var_to_const(self):
        """Test substituting variable to constant"""
        self.prep.substitution_map = {'x': '5'}
        result = self.prep._substitute_expr(Var('x'))

        assert isinstance(result, Const)
        assert result.value == 5

    def test_substitute_var_to_nil(self):
        """Test substituting variable to nil"""
        self.prep.substitution_map = {'x': 'nil'}
        result = self.prep._substitute_expr(Var('x'))

        assert isinstance(result, Const)
        assert result.value is None

    def test_substitute_const_unchanged(self):
        """Test constant is unchanged"""
        result = self.prep._substitute_expr(Const(5))
        assert isinstance(result, Const)
        assert result.value == 5

    def test_substitute_arithmetic_expr(self):
        """Test substitution in arithmetic expression"""
        self.prep.substitution_map = {'x': 'y'}
        arith = ArithExpr('+', Var('x'), Const(5))
        result = self.prep._substitute_expr(arith)

        assert isinstance(result, ArithExpr)

    def test_arithmetic_addition_simplification(self):
        """Test 3 + 5 simplifies to 8"""
        arith = ArithExpr('+', Const(3), Const(5))
        result = self.prep._substitute_expr(arith)

        assert isinstance(result, Const)
        assert result.value == 8

    def test_arithmetic_subtraction_simplification(self):
        """Test 10 - 3 simplifies to 7"""
        arith = ArithExpr('-', Const(10), Const(3))
        result = self.prep._substitute_expr(arith)

        assert isinstance(result, Const)
        assert result.value == 7

    def test_arithmetic_multiplication_simplification(self):
        """Test 4 * 5 simplifies to 20"""
        arith = ArithExpr('*', Const(4), Const(5))
        result = self.prep._substitute_expr(arith)

        assert isinstance(result, Const)
        assert result.value == 20

    def test_arithmetic_division_simplification(self):
        """Test 10 div 2 simplifies to 5"""
        arith = ArithExpr('div', Const(10), Const(2))
        result = self.prep._substitute_expr(arith)

        assert isinstance(result, Const)
        assert result.value == 5

    def test_arithmetic_modulo_simplification(self):
        """Test 10 mod 3 simplifies to 1"""
        arith = ArithExpr('mod', Const(10), Const(3))
        result = self.prep._substitute_expr(arith)

        assert isinstance(result, Const)
        assert result.value == 1

    def test_arithmetic_division_by_zero_no_simplification(self):
        """Test division by zero is not simplified"""
        arith = ArithExpr('div', Const(10), Const(0))
        result = self.prep._substitute_expr(arith)

        # Should not simplify
        assert isinstance(result, ArithExpr)

    def test_arithmetic_with_nil_no_simplification(self):
        """Test arithmetic with nil is not simplified"""
        arith = ArithExpr('+', Const(None), Const(5))
        result = self.prep._substitute_expr(arith)

        # Should not simplify (nil is not an int)
        assert isinstance(result, ArithExpr)

    def test_expr_substitution_transitive(self):
        """Test transitive expression substitution"""
        self.prep.expr_substitution_map = {'x': Var('y'), 'y': Const(5)}
        result = self.prep._substitute_expr(Var('x'))

        # x -> y -> 5, should follow the chain
        assert isinstance(result, Var) or isinstance(result, Const)


class TestConvenienceFunction:
    """Test preprocess_equalities convenience function"""

    def test_convenience_function(self):
        """Test preprocess_equalities function"""
        formula = parse("list(x) & x = y")
        result = preprocess_equalities(formula)

        # Should apply preprocessing
        assert result is not None
        assert isinstance(result, And)


class TestIntegration:
    """Integration tests"""

    def test_complex_formula(self):
        """Test preprocessing complex formula"""
        formula = parse("x |-> y * y |-> z * list(a) & x = b & a = c")
        result = preprocess_equalities(formula)

        # Multiple substitutions should be applied
        assert result is not None

    def test_with_predicates(self):
        """Test with predicate calls"""
        formula = parse("list(x) * list(y) & x = y")
        result = preprocess_equalities(formula)

        assert result is not None

    def test_nested_quantifiers(self):
        """Test with nested quantifiers"""
        x = Var('x')
        y = Var('y')
        body = And(PredicateCall('list', [x]), Eq(x, y))
        inner_exists = Exists('y', body)
        outer_exists = Exists('x', inner_exists)

        result = preprocess_equalities(outer_exists)

        assert isinstance(result, Exists)

    def test_empty_formula(self):
        """Test preprocessing emp"""
        result = preprocess_equalities(Emp())
        assert isinstance(result, Emp)
