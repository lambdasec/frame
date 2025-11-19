"""
Tests for Footprint Analysis (frame/analysis/footprint.py)

Tests footprint computation and safe dropping analysis for affine weakening.
"""

import pytest
from frame.analysis.footprint import FootprintAnalyzer
from frame.core.parser import parse
from frame.core.ast import (
    Var, Const, Emp, PointsTo, SepConj, And, Or, Not,
    PredicateCall, Exists, Forall, Wand, True_, False_
)


class TestIsConstant:
    """Test _is_constant helper function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_const_is_constant(self):
        """Test that Const is identified as constant"""
        assert self.analyzer._is_constant(Const(5)) is True
        assert self.analyzer._is_constant(Const(0)) is True

    def test_nil_is_constant(self):
        """Test that nil is identified as constant"""
        assert self.analyzer._is_constant(Var('nil')) is True
        assert self.analyzer._is_constant(Var('null')) is True

    def test_numeric_var_is_constant(self):
        """Test that numeric variable names are constants"""
        assert self.analyzer._is_constant(Var('5')) is True
        assert self.analyzer._is_constant(Var('0')) is True
        assert self.analyzer._is_constant(Var('100')) is True

    def test_regular_var_not_constant(self):
        """Test that regular variables are not constants"""
        assert self.analyzer._is_constant(Var('x')) is False
        assert self.analyzer._is_constant(Var('next')) is False
        assert self.analyzer._is_constant(Var('ptr')) is False


class TestFootprint:
    """Test footprint function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_emp_footprint(self):
        """Test footprint of emp"""
        formula = parse("emp")
        fp = self.analyzer.footprint(formula)
        assert fp == set()

    def test_simple_pto_footprint(self):
        """Test footprint of x |-> y"""
        formula = parse("x |-> y")
        fp = self.analyzer.footprint(formula)
        assert 'x' in fp  # location
        assert 'y' in fp  # value (potential pointer)

    def test_pto_with_constant(self):
        """Test footprint of x |-> 5 (constant value)"""
        formula = parse("x |-> 5")
        fp = self.analyzer.footprint(formula)
        assert 'x' in fp  # location
        assert '5' not in fp  # constant not in footprint

    def test_pto_with_nil(self):
        """Test footprint of x |-> nil"""
        formula = parse("x |-> nil")
        fp = self.analyzer.footprint(formula)
        assert 'x' in fp  # location
        assert 'nil' not in fp  # nil is constant

    def test_multi_field_pto(self):
        """Test footprint of x |-> (y, z)"""
        formula = parse("x |-> (y, z)")
        fp = self.analyzer.footprint(formula)
        assert 'x' in fp  # location
        assert 'y' in fp  # value
        assert 'z' in fp  # value

    def test_sepconj_footprint(self):
        """Test footprint of P * Q"""
        formula = parse("x |-> y * y |-> z")
        fp = self.analyzer.footprint(formula)
        assert 'x' in fp
        assert 'y' in fp
        assert 'z' in fp

    def test_and_footprint(self):
        """Test footprint of P & Q"""
        x = Var('x')
        y = Var('y')
        z = Var('z')
        p = PointsTo(x, [y])
        q = PointsTo(y, [z])
        formula = And(p, q)

        fp = self.analyzer.footprint(formula)
        assert 'x' in fp
        assert 'y' in fp
        assert 'z' in fp

    def test_or_footprint(self):
        """Test footprint of P | Q (union)"""
        x = Var('x')
        y = Var('y')
        a = Var('a')
        b = Var('b')
        p = PointsTo(x, [y])
        q = PointsTo(a, [b])
        formula = Or(p, q)

        fp = self.analyzer.footprint(formula)
        # Union of both branches
        assert 'x' in fp or 'a' in fp

    def test_not_footprint(self):
        """Test footprint of ¬P (empty for pure)"""
        formula = Not(True_())
        fp = self.analyzer.footprint(formula)
        assert fp == set()

    def test_exists_footprint(self):
        """Test footprint of ∃x. P"""
        x = Var('x')
        y = Var('y')
        body = PointsTo(x, [y])
        formula = Exists(['z'], body)

        fp = self.analyzer.footprint(formula)
        assert 'x' in fp
        assert 'y' in fp

    def test_forall_footprint(self):
        """Test footprint of ∀x. P"""
        x = Var('x')
        y = Var('y')
        body = PointsTo(x, [y])
        formula = Forall(['z'], body)

        fp = self.analyzer.footprint(formula)
        assert 'x' in fp
        assert 'y' in fp

    def test_wand_footprint(self):
        """Test footprint of P -* Q"""
        x = Var('x')
        y = Var('y')
        z = Var('z')
        p = PointsTo(x, [y])
        q = PointsTo(y, [z])
        formula = Wand(p, q)

        fp = self.analyzer.footprint(formula)
        # Union of both sides
        assert 'x' in fp or 'y' in fp

    def test_predicate_call_footprint(self):
        """Test footprint of predicate call"""
        x = Var('x')
        pred = PredicateCall('list', [x])

        fp = self.analyzer.footprint(pred)
        assert 'x' in fp  # root
        assert 'x_next' in fp  # symbolic next value

    def test_predicate_unfold_depth_zero(self):
        """Test predicate with unfold_depth=0"""
        analyzer = FootprintAnalyzer(unfold_depth=0)
        x = Var('x')
        pred = PredicateCall('list', [x])

        fp = analyzer.footprint(pred)
        assert 'x' in fp  # root always included


class TestGetRootVars:
    """Test _get_root_vars helper function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_pto_root(self):
        """Test extracting root from points-to"""
        formula = parse("x |-> y")
        roots = self.analyzer._get_root_vars(formula)
        assert 'x' in roots

    def test_predicate_root(self):
        """Test extracting root from predicate"""
        x = Var('x')
        pred = PredicateCall('list', [x])
        roots = self.analyzer._get_root_vars(pred)
        assert 'x' in roots

    def test_sepconj_roots(self):
        """Test extracting roots from SepConj"""
        formula = parse("x |-> y * a |-> b")
        roots = self.analyzer._get_root_vars(formula)
        assert 'x' in roots
        assert 'a' in roots


class TestContainsPredicates:
    """Test _contains_predicates helper function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_no_predicates(self):
        """Test formula without predicates"""
        formula = parse("x |-> y * y |-> z")
        result = self.analyzer._contains_predicates(formula)
        assert result is False

    def test_with_predicate(self):
        """Test formula with predicate"""
        formula = parse("x |-> y * list(z)")
        result = self.analyzer._contains_predicates(formula)
        assert result is True

    def test_nested_predicate(self):
        """Test nested predicate in And"""
        x = Var('x')
        y = Var('y')
        pred = PredicateCall('list', [x])
        pto = PointsTo(x, [y])
        formula = And(pto, pred)

        result = self.analyzer._contains_predicates(formula)
        assert result is True


class TestGetSymbolicValues:
    """Test _get_symbolic_values helper function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_pto_symbolic_value(self):
        """Test extracting symbolic value from x |-> y"""
        formula = parse("x |-> y")
        values = self.analyzer._get_symbolic_values(formula)
        assert 'y' in values

    def test_pto_constant_value(self):
        """Test that constants are not symbolic"""
        formula = parse("x |-> 5")
        values = self.analyzer._get_symbolic_values(formula)
        assert '5' not in values

    def test_pto_nil_value(self):
        """Test that nil is not symbolic"""
        formula = parse("x |-> nil")
        values = self.analyzer._get_symbolic_values(formula)
        assert 'nil' not in values

    def test_multi_field_values(self):
        """Test multi-field symbolic values"""
        formula = parse("x |-> (y, z)")
        values = self.analyzer._get_symbolic_values(formula)
        assert 'y' in values
        assert 'z' in values


class TestFlattenSepConj:
    """Test _flatten_sepconj helper function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_single_formula(self):
        """Test flattening single formula"""
        formula = parse("x |-> y")
        flat = self.analyzer._flatten_sepconj(formula)
        assert len(flat) == 1
        assert flat[0][1] == 0  # position 0

    def test_two_formulas(self):
        """Test flattening A * B"""
        formula = parse("x |-> y * a |-> b")
        flat = self.analyzer._flatten_sepconj(formula)
        assert len(flat) == 2
        assert flat[0][1] == 0  # first position
        assert flat[1][1] == 1  # second position

    def test_three_formulas(self):
        """Test flattening (A * B) * C"""
        formula = parse("x |-> y * a |-> b * p |-> q")
        flat = self.analyzer._flatten_sepconj(formula)
        assert len(flat) == 3
        assert flat[0][1] == 0
        assert flat[1][1] == 1
        assert flat[2][1] == 2

    def test_custom_start_pos(self):
        """Test flattening with custom start position"""
        formula = parse("x |-> y * a |-> b")
        flat = self.analyzer._flatten_sepconj(formula, start_pos=5)
        assert flat[0][1] == 5
        assert flat[1][1] == 6


