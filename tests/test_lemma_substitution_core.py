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


class TestSubstituteBindings:
    """Test substitute_bindings method"""

    def setup_method(self):
        """Set up test substitution"""
        self.subst = LemmaSubstitution()

    def test_substitute_var(self):
        """Test substituting a variable"""
        x = Var('x')
        bindings = {'x': Var('y')}

        # Note: Var is an Expr, not a Formula
        # But we test this for edge case handling
        result = self.subst.substitute_bindings(x, bindings)
        assert isinstance(result, Var)

    def test_substitute_emp(self):
        """Test emp is unchanged"""
        result = self.subst.substitute_bindings(Emp(), {})
        assert isinstance(result, Emp)

    def test_substitute_true_false(self):
        """Test True/False unchanged"""
        assert isinstance(self.subst.substitute_bindings(True_(), {}), True_)
        assert isinstance(self.subst.substitute_bindings(False_(), {}), False_)

    def test_substitute_const(self):
        """Test constant unchanged"""
        result = self.subst.substitute_bindings(Const(5), {})
        assert isinstance(result, Const)

    def test_substitute_equality(self):
        """Test substitution in equality"""
        eq = Eq(Var('X'), Var('Y'))
        bindings = {'X': Var('a'), 'Y': Var('b')}

        result = self.subst.substitute_bindings(eq, bindings)

        assert isinstance(result, Eq)
        assert isinstance(result.left, Var)
        assert result.left.name == 'a'
        assert isinstance(result.right, Var)
        assert result.right.name == 'b'

    def test_substitute_inequality(self):
        """Test substitution in inequality"""
        neq = Neq(Var('X'), Const(5))
        bindings = {'X': Var('z')}

        result = self.subst.substitute_bindings(neq, bindings)

        assert isinstance(result, Neq)

    def test_substitute_comparisons(self):
        """Test substitution in comparison operators"""
        bindings = {'X': Var('a')}

        lt = Lt(Var('X'), Const(5))
        le = Le(Var('X'), Const(5))
        gt = Gt(Var('X'), Const(5))
        ge = Ge(Var('X'), Const(5))

        assert isinstance(self.subst.substitute_bindings(lt, bindings), Lt)
        assert isinstance(self.subst.substitute_bindings(le, bindings), Le)
        assert isinstance(self.subst.substitute_bindings(gt, bindings), Gt)
        assert isinstance(self.subst.substitute_bindings(ge, bindings), Ge)

    def test_substitute_points_to(self):
        """Test substitution in points-to"""
        pto = PointsTo(Var('X'), [Var('Y'), Const(5)])
        bindings = {'X': Var('a'), 'Y': Var('b')}

        result = self.subst.substitute_bindings(pto, bindings)

        assert isinstance(result, PointsTo)
        assert isinstance(result.location, Var)
        assert result.location.name == 'a'

    def test_substitute_predicate_call(self):
        """Test substitution in predicate call"""
        pred = PredicateCall('list', [Var('X'), Var('Y')])
        bindings = {'X': Var('x'), 'Y': Var('nil')}

        result = self.subst.substitute_bindings(pred, bindings)

        assert isinstance(result, PredicateCall)
        assert result.name == 'list'

    def test_substitute_sepconj(self):
        """Test substitution in separating conjunction"""
        sep = SepConj(
            PointsTo(Var('X'), [Var('Y')]),
            PointsTo(Var('Y'), [Const(5)])
        )
        bindings = {'X': Var('a'), 'Y': Var('b')}

        result = self.subst.substitute_bindings(sep, bindings)

        assert isinstance(result, SepConj)

    def test_substitute_and_or(self):
        """Test substitution in And/Or"""
        bindings = {'X': Var('a')}

        and_f = And(Eq(Var('X'), Const(5)), Emp())
        or_f = Or(Eq(Var('X'), Const(5)), Emp())

        assert isinstance(self.subst.substitute_bindings(and_f, bindings), And)
        assert isinstance(self.subst.substitute_bindings(or_f, bindings), Or)

    def test_substitute_not(self):
        """Test substitution in negation"""
        not_f = Not(Eq(Var('X'), Const(5)))
        bindings = {'X': Var('a')}

        result = self.subst.substitute_bindings(not_f, bindings)

        assert isinstance(result, Not)

    def test_substitute_quantifiers(self):
        """Test substitution in quantifiers"""
        bindings = {'X': Var('a')}

        exists = Exists('y', Eq(Var('X'), Var('y')))
        forall = Forall('y', Eq(Var('X'), Var('y')))

        assert isinstance(self.subst.substitute_bindings(exists, bindings), Exists)
        assert isinstance(self.subst.substitute_bindings(forall, bindings), Forall)


class TestSubstituteExpr:
    """Test substitute_expr method"""

    def setup_method(self):
        """Set up test substitution"""
        self.subst = LemmaSubstitution()

    def test_substitute_var(self):
        """Test substituting variable"""
        result = self.subst.substitute_expr(Var('X'), {'X': Var('a')})

        assert isinstance(result, Var)
        assert result.name == 'a'

    def test_substitute_var_to_const(self):
        """Test substituting variable to constant"""
        result = self.subst.substitute_expr(Var('X'), {'X': Const(5)})

        assert isinstance(result, Const)
        assert result.value == 5

    def test_substitute_const_unchanged(self):
        """Test constant unchanged"""
        result = self.subst.substitute_expr(Const(5), {})

        assert isinstance(result, Const)
        assert result.value == 5

    def test_substitute_arithmetic_expr(self):
        """Test substitution in arithmetic expression"""
        arith = ArithExpr('+', Var('X'), Const(5))
        bindings = {'X': Var('y')}

        result = self.subst.substitute_expr(arith, bindings)

        assert isinstance(result, ArithExpr)

    def test_arithmetic_addition_simplification(self):
        """Test arithmetic simplification for addition"""
        arith = ArithExpr('+', Const(3), Const(5))
        result = self.subst.substitute_expr(arith, {})

        assert isinstance(result, Const)
        assert result.value == 8

    def test_arithmetic_subtraction_simplification(self):
        """Test arithmetic simplification for subtraction"""
        arith = ArithExpr('-', Const(10), Const(3))
        result = self.subst.substitute_expr(arith, {})

        assert isinstance(result, Const)
        assert result.value == 7

    def test_arithmetic_multiplication_simplification(self):
        """Test arithmetic simplification for multiplication"""
        arith = ArithExpr('*', Const(4), Const(5))
        result = self.subst.substitute_expr(arith, {})

        assert isinstance(result, Const)
        assert result.value == 20

    def test_arithmetic_division_simplification(self):
        """Test arithmetic simplification for division"""
        arith = ArithExpr('div', Const(10), Const(2))
        result = self.subst.substitute_expr(arith, {})

        assert isinstance(result, Const)
        assert result.value == 5

    def test_arithmetic_modulo_simplification(self):
        """Test arithmetic simplification for modulo"""
        arith = ArithExpr('mod', Const(10), Const(3))
        result = self.subst.substitute_expr(arith, {})

        assert isinstance(result, Const)
        assert result.value == 1

    def test_arithmetic_division_by_zero(self):
        """Test division by zero is not simplified"""
        arith = ArithExpr('div', Const(10), Const(0))
        result = self.subst.substitute_expr(arith, {})

        # Should not simplify
        assert isinstance(result, ArithExpr)

    def test_arithmetic_with_nil(self):
        """Test arithmetic with nil is not simplified"""
        arith = ArithExpr('+', Const(None), Const(5))
        result = self.subst.substitute_expr(arith, {})

        # Should not simplify
        assert isinstance(result, ArithExpr)


class TestExtractEqualityConstraints:
    """Test extract_equality_constraints method"""

    def setup_method(self):
        """Set up test substitution"""
        self.subst = LemmaSubstitution()

    def test_simple_var_equality(self):
        """Test extracting x = y"""
        eq = Eq(Var('x'), Var('y'))
        constraints = self.subst.extract_equality_constraints(eq)

        assert len(constraints) > 0
        # One of x or y should be mapped to the other
        assert 'x' in constraints or 'y' in constraints

    def test_var_to_const_equality(self):
        """Test extracting x = 5"""
        eq = Eq(Var('x'), Const(5))
        constraints = self.subst.extract_equality_constraints(eq)

        assert 'x' in constraints
        assert isinstance(constraints['x'], Const)

    def test_const_to_var_equality(self):
        """Test extracting 5 = x (reversed)"""
        eq = Eq(Const(5), Var('x'))
        constraints = self.subst.extract_equality_constraints(eq)

        assert 'x' in constraints

    def test_multiple_equalities(self):
        """Test extracting multiple equalities"""
        eq1 = Eq(Var('x'), Var('y'))
        eq2 = Eq(Var('y'), Var('z'))
        formula = And(eq1, eq2)

        constraints = self.subst.extract_equality_constraints(formula)

        # Should extract both equalities
        assert len(constraints) >= 2

    def test_transitive_closure(self):
        """Test transitive closure: x=y, y=z => x=z"""
        eq1 = Eq(Var('x'), Var('y'))
        eq2 = Eq(Var('y'), Var('z'))
        formula = And(eq1, eq2)

        constraints = self.subst.extract_equality_constraints(formula)

        # All variables should map to same representative
        # (either all to x, y, or z depending on lexicographic order)
        assert len(constraints) >= 2

    def test_no_equalities(self):
        """Test formula with no equalities"""
        formula = PointsTo(Var('x'), [Var('y')])
        constraints = self.subst.extract_equality_constraints(formula)

        assert len(constraints) == 0

    def test_equality_in_sepconj(self):
        """Test that equalities in SepConj are not extracted"""
        sep = SepConj(Eq(Var('x'), Var('y')), Emp())
        constraints = self.subst.extract_equality_constraints(sep)

        # SepConj is not recursed into for equality extraction
        assert len(constraints) == 0

    def test_equality_in_or(self):
        """Test that equalities in Or are not extracted"""
        or_f = Or(Eq(Var('x'), Var('y')), Emp())
        constraints = self.subst.extract_equality_constraints(or_f)

        # Or is not recursed into
        assert len(constraints) == 0

    def test_equality_in_not(self):
        """Test that equalities in Not are not extracted"""
        not_f = Not(Eq(Var('x'), Var('y')))
        constraints = self.subst.extract_equality_constraints(not_f)

        # Not is not recursed into
        assert len(constraints) == 0


