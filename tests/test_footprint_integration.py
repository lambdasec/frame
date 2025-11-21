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
