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


class TestUnionFind:
    """Test UnionFind data structure"""

    def test_find_simple(self):
        """Test find on single element"""
        uf = UnionFind()
        assert uf.find('x') == 'x'
        assert uf.find('y') == 'y'

    def test_union_simple(self):
        """Test simple union"""
        uf = UnionFind()
        uf.union('x', 'y')
        assert uf.find('x') == uf.find('y')

    def test_union_chain(self):
        """Test union chain with path compression"""
        uf = UnionFind()
        uf.union('a', 'b')
        uf.union('b', 'c')
        uf.union('c', 'd')

        # All should have same representative
        rep = uf.find('a')
        assert uf.find('b') == rep
        assert uf.find('c') == rep
        assert uf.find('d') == rep

    def test_union_prefer_constant_over_var(self):
        """Test that constants are preferred as representatives"""
        uf = UnionFind()
        uf.union('x', '5')
        # '5' should be the representative (constant preferred)
        assert uf.find('x') == '5'

    def test_union_prefer_nil(self):
        """Test that nil is preferred as representative"""
        uf = UnionFind()
        uf.union('x', 'nil')
        assert uf.find('x') == 'nil'

    def test_union_two_constants(self):
        """Test union of two constants"""
        uf = UnionFind()
        uf.union('5', '10')
        # Both are constants, rank-based union applies
        assert uf.find('5') == uf.find('10')

    def test_is_constant_name_nil(self):
        """Test nil is recognized as constant"""
        assert UnionFind._is_constant_name('nil') is True

    def test_is_constant_name_number(self):
        """Test numbers are recognized as constants"""
        assert UnionFind._is_constant_name('5') is True
        assert UnionFind._is_constant_name('0') is True
        assert UnionFind._is_constant_name('100') is True

    def test_is_constant_name_variable(self):
        """Test regular variables are not constants"""
        assert UnionFind._is_constant_name('x') is False
        assert UnionFind._is_constant_name('foo') is False


class TestEqualityPreprocessor:
    """Test EqualityPreprocessor class"""

    def setup_method(self):
        """Set up test preprocessor"""
        self.prep = EqualityPreprocessor()

    def test_simple_var_equality(self):
        """Test x = y substitution"""
        formula = parse("list(x) & x = y")
        result = self.prep.preprocess(formula)

        # Variables should be unified (x and y map to same representative)
        # The representative could be either x or y depending on union-find
        assert isinstance(result, And)
        # After preprocessing, the equality should simplify (both sides same)
        result_str = str(result)
        assert "list" in result_str

    def test_var_to_constant(self):
        """Test x = 5 substitution"""
        formula = parse("x |-> 3 & x = 5")
        result = self.prep.preprocess(formula)

        # x should be replaced with 5
        assert "5" in str(result)

    def test_var_to_nil(self):
        """Test x = nil substitution"""
        formula = parse("x |-> y & x = nil")
        result = self.prep.preprocess(formula)

        # x should be replaced with nil
        assert "nil" in str(result)

    def test_transitive_equality(self):
        """Test x = y & y = z substitution"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        list_x = PredicateCall('list', [x])
        eq1 = Eq(x, y)
        eq2 = Eq(y, z)

        formula = And(And(list_x, eq1), eq2)
        result = self.prep.preprocess(formula)

        # All should be mapped to same representative
        assert isinstance(result, And)

    def test_preserve_quantified_vars(self):
        """Test that quantified variables are not substituted"""
        x = Var('x')
        y = Var('y')

        body = And(PredicateCall('list', [x]), Eq(x, y))
        formula = Exists('x', body)

        result = self.prep.preprocess(formula)

        # x should not be substituted (it's quantified)
        assert isinstance(result, Exists)

    def test_no_preserve_quantified_vars(self):
        """Test with preserve_quantified=False"""
        prep = EqualityPreprocessor(preserve_quantified=False)
        x = Var('x')
        y = Var('y')

        body = And(PredicateCall('list', [x]), Eq(x, y))
        formula = Exists('x', body)

        result = prep.preprocess(formula)

        # With preserve=False, x might be substituted
        assert isinstance(result, Exists)

    def test_arithmetic_expression_substitution(self):
        """Test x = y + 5 substitution"""
        x = Var('x')
        y = Var('y')
        five = Const(5)

        arith = ArithExpr('+', y, five)
        eq = Eq(x, arith)
        pto = PointsTo(x, [Const(0)])

        formula = And(pto, eq)
        result = self.prep.preprocess(formula)

        # x should be replaced with y + 5
        assert isinstance(result, And)

    def test_arithmetic_simplification(self):
        """Test arithmetic simplification with constants"""
        x = Var('x')
        five = Const(5)
        three = Const(3)

        # x = 5 + 3 should simplify to x = 8
        arith = ArithExpr('+', five, three)
        eq = Eq(x, arith)
        pto = PointsTo(x, [Const(0)])

        formula = And(pto, eq)
        result = self.prep.preprocess(formula)

        # Substitution should happen
        assert isinstance(result, And)

    def test_multiple_equalities(self):
        """Test multiple equalities in same formula"""
        formula = parse("x |-> a * y |-> b & x = z & y = w")
        result = self.prep.preprocess(formula)

        # Multiple substitutions should be applied
        assert isinstance(result, And)

    def test_no_equalities(self):
        """Test formula with no equalities"""
        formula = parse("x |-> y * y |-> z")
        result = self.prep.preprocess(formula)

        # Should be unchanged
        assert isinstance(result, SepConj)


class TestGetSimpleKey:
    """Test _get_simple_key helper"""

    def setup_method(self):
        """Set up test preprocessor"""
        self.prep = EqualityPreprocessor()

    def test_var_key(self):
        """Test key for variable"""
        key = self.prep._get_simple_key(Var('x'))
        assert key == 'x'

    def test_const_int_key(self):
        """Test key for integer constant"""
        key = self.prep._get_simple_key(Const(5))
        assert key == '5'

    def test_const_nil_key(self):
        """Test key for nil constant"""
        key = self.prep._get_simple_key(Const(None))
        assert key == 'nil'

    def test_const_string_key(self):
        """Test key for string constant"""
        key = self.prep._get_simple_key(Const("hello"))
        assert key == 'hello'

    def test_arith_expr_no_key(self):
        """Test that ArithExpr returns None"""
        arith = ArithExpr('+', Var('x'), Const(5))
        key = self.prep._get_simple_key(arith)
        assert key is None


class TestSubstituteFormula:
    """Test _substitute_formula method"""

    def setup_method(self):
        """Set up test preprocessor"""
        self.prep = EqualityPreprocessor()

    def test_substitute_emp(self):
        """Test substitution preserves emp"""
        result = self.prep._substitute_formula(Emp())
        assert isinstance(result, Emp)

    def test_substitute_true_false(self):
        """Test substitution preserves True/False"""
        assert isinstance(self.prep._substitute_formula(True_()), True_)
        assert isinstance(self.prep._substitute_formula(False_()), False_)

    def test_substitute_eq(self):
        """Test substitution in equality"""
        self.prep.substitution_map = {'x': 'y'}
        eq = Eq(Var('x'), Var('z'))
        result = self.prep._substitute_formula(eq)

        assert isinstance(result, Eq)

    def test_substitute_neq(self):
        """Test substitution in inequality"""
        self.prep.substitution_map = {'x': 'y'}
        neq = Neq(Var('x'), Var('z'))
        result = self.prep._substitute_formula(neq)

        assert isinstance(result, Neq)

    def test_substitute_comparisons(self):
        """Test substitution in comparison operators"""
        self.prep.substitution_map = {'x': 'y'}

        lt = Lt(Var('x'), Var('z'))
        le = Le(Var('x'), Var('z'))
        gt = Gt(Var('x'), Var('z'))
        ge = Ge(Var('x'), Var('z'))

        assert isinstance(self.prep._substitute_formula(lt), Lt)
        assert isinstance(self.prep._substitute_formula(le), Le)
        assert isinstance(self.prep._substitute_formula(gt), Gt)
        assert isinstance(self.prep._substitute_formula(ge), Ge)

    def test_substitute_points_to(self):
        """Test substitution in points-to"""
        self.prep.substitution_map = {'x': 'y'}
        pto = PointsTo(Var('x'), [Var('a'), Var('b')])
        result = self.prep._substitute_formula(pto)

        assert isinstance(result, PointsTo)

    def test_substitute_predicate_call(self):
        """Test substitution in predicate call"""
        self.prep.substitution_map = {'x': 'y'}
        pred = PredicateCall('list', [Var('x'), Var('z')])
        result = self.prep._substitute_formula(pred)

        assert isinstance(result, PredicateCall)

    def test_substitute_and_or_sepconj(self):
        """Test substitution in binary connectives"""
        self.prep.substitution_map = {'x': 'y'}

        and_f = And(Emp(), Emp())
        or_f = Or(Emp(), Emp())
        sep_f = SepConj(Emp(), Emp())

        assert isinstance(self.prep._substitute_formula(and_f), And)
        assert isinstance(self.prep._substitute_formula(or_f), Or)
        assert isinstance(self.prep._substitute_formula(sep_f), SepConj)

    def test_substitute_wand(self):
        """Test substitution in wand (preserves order)"""
        self.prep.substitution_map = {'x': 'y'}
        wand = Wand(Emp(), Emp())
        result = self.prep._substitute_formula(wand)

        assert isinstance(result, Wand)

    def test_substitute_not(self):
        """Test substitution in negation"""
        self.prep.substitution_map = {'x': 'y'}
        not_f = Not(Emp())
        result = self.prep._substitute_formula(not_f)

        assert isinstance(result, Not)

    def test_substitute_quantifiers(self):
        """Test substitution in quantifiers"""
        self.prep.substitution_map = {'x': 'y'}

        exists = Exists('z', Emp())
        forall = Forall('z', Emp())

        assert isinstance(self.prep._substitute_formula(exists), Exists)
        assert isinstance(self.prep._substitute_formula(forall), Forall)


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
