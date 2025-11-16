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


class TestCanDropSafely:
    """Test can_drop_safely function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_disjoint_pto_cells(self):
        """Test dropping disjoint cells"""
        remainder = parse("x |-> y")
        other = parse("a |-> b")

        result = self.analyzer.can_drop_safely(remainder, other)
        assert result is True

    def test_overlapping_locations(self):
        """Test cannot drop overlapping locations"""
        remainder = parse("x |-> y")
        other = parse("x |-> z")

        result = self.analyzer.can_drop_safely(remainder, other)
        assert result is False

    def test_value_matches_root(self):
        """Test when value matches other's root"""
        remainder = parse("x |-> z")
        other = parse("list(z)")

        result = self.analyzer.can_drop_safely(remainder, other)
        # Should be False (value z matches root z)
        assert result is False

    def test_disjoint_with_predicate(self):
        """Test dropping cell disjoint from predicate"""
        remainder = parse("a |-> b")
        other = parse("list(x)")

        result = self.analyzer.can_drop_safely(remainder, other)
        assert result is True


class TestCanDropSafelyOrderAware:
    """Test can_drop_safely_order_aware function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_remainder_after_kept(self):
        """Test dropping remainder after kept predicate"""
        remainder = parse("y |-> z")
        other = parse("list(x)")

        # remainder_pos=1 > other_pos=0 (after)
        result = self.analyzer.can_drop_safely_order_aware(
            remainder, 1, other, 0
        )
        assert result is True

    def test_remainder_before_kept(self):
        """Test cannot drop remainder before kept predicate"""
        remainder = parse("x |-> y")
        other = parse("list(z)")

        # remainder_pos=0 < other_pos=1 (before)
        result = self.analyzer.can_drop_safely_order_aware(
            remainder, 0, other, 1
        )
        # Should be False if remainder has symbolic values
        assert result is False

    def test_overlapping_roots(self):
        """Test overlapping roots"""
        x = Var('x')
        y = Var('y')
        remainder = PointsTo(x, [y])
        other = PredicateCall('list', [x])

        result = self.analyzer.can_drop_safely_order_aware(
            remainder, 0, other, 1
        )
        assert result is False

    def test_same_root_list_segments(self):
        """Test special case: ls(x,y) * ls(x,z)"""
        x = Var('x')
        y = Var('y')
        z = Var('z')
        remainder = PredicateCall('ls', [x, y])
        other = PredicateCall('ls', [x, z])

        # Special case: same root ls predicates
        result = self.analyzer.can_drop_safely_order_aware(
            remainder, 0, other, 1
        )
        assert result is True  # Let Z3 handle constraints

    def test_no_symbolic_values(self):
        """Test dropping cell with no symbolic values"""
        remainder = parse("x |-> nil")
        other = parse("list(a)")

        result = self.analyzer.can_drop_safely_order_aware(
            remainder, 0, other, 1
        )
        assert result is True


class TestEntailsEmpFootprintAware:
    """Test entails_emp_footprint_aware function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_emp_entails_emp(self):
        """Test emp |- emp"""
        antecedent = parse("emp")
        consequent = parse("emp")

        result = self.analyzer.entails_emp_footprint_aware(antecedent, consequent)
        assert result is True

    def test_pto_not_entails_emp(self):
        """Test x |-> y ⊬ emp"""
        antecedent = parse("x |-> y")
        consequent = parse("emp")

        result = self.analyzer.entails_emp_footprint_aware(antecedent, consequent)
        assert result is False

    def test_disjoint_footprints(self):
        """Test dropping when footprints disjoint"""
        antecedent = parse("x |-> y")
        consequent = parse("a |-> b")

        result = self.analyzer.entails_emp_footprint_aware(antecedent, consequent)
        assert result is True

    def test_overlapping_footprints(self):
        """Test cannot drop when footprints overlap"""
        antecedent = parse("x |-> y")
        consequent = parse("x |-> z")

        result = self.analyzer.entails_emp_footprint_aware(antecedent, consequent)
        assert result is False

    def test_no_footprint(self):
        """Test formula with no footprint"""
        antecedent = True_()
        consequent = parse("emp")

        result = self.analyzer.entails_emp_footprint_aware(antecedent, consequent)
        assert result is True


class TestFootprintIntegration:
    """Integration tests for footprint analysis"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_complex_formula_footprint(self):
        """Test footprint of complex formula"""
        formula = parse("x |-> y * y |-> z * a |-> b")
        fp = self.analyzer.footprint(formula)

        assert 'x' in fp
        assert 'y' in fp
        assert 'z' in fp
        assert 'a' in fp
        assert 'b' in fp

    def test_mixed_predicates_and_pto(self):
        """Test footprint with mixed predicates and pto"""
        formula = parse("x |-> y * list(z)")
        fp = self.analyzer.footprint(formula)

        assert 'x' in fp  # pto location
        assert 'y' in fp  # pto value
        assert 'z' in fp  # predicate root
        assert 'z_next' in fp  # predicate symbolic

    def test_safe_dropping_chain(self):
        """Test safe dropping in chain"""
        remainder = parse("a |-> b")
        other = parse("x |-> y * y |-> z")

        result = self.analyzer.can_drop_safely(remainder, other)
        assert result is True

    def test_unsafe_dropping_dependent(self):
        """Test unsafe dropping when dependent"""
        remainder = parse("x |-> y")
        other = parse("list(y)")

        result = self.analyzer.can_drop_safely(remainder, other)
        assert result is False


class TestEdgeCases:
    """Test edge cases in footprint analysis"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = FootprintAnalyzer()

    def test_custom_unfold_depth(self):
        """Test with custom unfold depth"""
        analyzer = FootprintAnalyzer(unfold_depth=2)
        x = Var('x')
        pred = PredicateCall('list', [x])

        fp = analyzer.footprint(pred)
        assert 'x' in fp

    def test_unfold_depth_zero(self):
        """Test with unfold_depth=0"""
        analyzer = FootprintAnalyzer(unfold_depth=0)
        x = Var('x')
        pred = PredicateCall('list', [x])

        fp = analyzer.footprint(pred)
        assert 'x' in fp
        # Should not have _next with depth 0
        assert 'x_next' not in fp

    def test_multiple_field_constant_mix(self):
        """Test multi-field with constant/variable mix"""
        formula = parse("x |-> (y, 5, z, nil)")
        fp = self.analyzer.footprint(formula)

        assert 'x' in fp
        assert 'y' in fp
        assert 'z' in fp
        assert '5' not in fp
        assert 'nil' not in fp

    def test_nested_sepconj(self):
        """Test deeply nested SepConj"""
        formula = parse("a |-> b * (c |-> d * (e |-> f * g |-> h))")
        fp = self.analyzer.footprint(formula)

        assert 'a' in fp
        assert 'c' in fp
        assert 'e' in fp
        assert 'g' in fp

    def test_predicate_registry_not_set(self):
        """Test when predicate registry not set"""
        analyzer = FootprintAnalyzer()
        assert analyzer._predicate_registry is None

        # Should still work without registry
        formula = parse("x |-> y")
        fp = analyzer.footprint(formula)
        assert 'x' in fp
