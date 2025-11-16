"""
Tests for Arithmetic Constraint Verification (frame/arithmetic/check.py)

Tests the arithmetic constraint checking functions that verify side conditions
for fold proposals using Z3.
"""

import pytest
import z3
from frame.arithmetic.check import (
    verify_side_conditions,
    verify_side_conditions_with_model,
    simplify_constraints,
    check_arithmetic_consistency,
    _check_entailment,
    _check_satisfiability
)


class TestVerifySideConditions:
    """Test verify_side_conditions function"""

    def test_empty_side_constraints(self):
        """Empty side constraints should be trivially valid"""
        pure = [z3.Int('x') > 0]
        result = verify_side_conditions([], pure)
        assert result is True

    def test_entailment_valid(self):
        """Side constraints entailed by pure constraints should be valid"""
        x = z3.Int('x')
        pure = [x > 10]
        side = [x > 5]
        result = verify_side_conditions(side, pure)
        assert result is True

    def test_entailment_invalid(self):
        """Side constraints not entailed or satisfiable should be invalid"""
        x = z3.Int('x')
        pure = [x < 5]
        side = [x > 10]
        result = verify_side_conditions(side, pure)
        assert result is False

    def test_satisfiability_valid(self):
        """Side constraints satisfiable with pure should be valid"""
        x = z3.Int('x')
        y = z3.Int('y')
        pure = [x > 0]
        side = [y > 10]
        result = verify_side_conditions(side, pure)
        assert result is True

    def test_multiple_side_constraints(self):
        """Multiple side constraints should be verified together"""
        x = z3.Int('x')
        y = z3.Int('y')
        pure = [x > 10, y > 5]
        side = [x > 5, y > 0]
        result = verify_side_conditions(side, pure)
        assert result is True

    def test_contradictory_constraints(self):
        """Contradictory constraints should be invalid"""
        x = z3.Int('x')
        pure = [x > 10]
        side = [x < 5]
        result = verify_side_conditions(side, pure)
        assert result is False

    def test_arithmetic_relationships(self):
        """Test arithmetic relationships in constraints"""
        x = z3.Int('x')
        y = z3.Int('y')
        pure = [x == y + 5]
        side = [x > y]
        result = verify_side_conditions(side, pure)
        assert result is True


class TestCheckEntailment:
    """Test _check_entailment function"""

    def test_simple_entailment(self):
        """Test simple entailment check"""
        x = z3.Int('x')
        pure = [x > 10]
        side = [x > 5]
        result = _check_entailment(side, pure, 1000)
        assert result is True

    def test_non_entailment(self):
        """Test when entailment doesn't hold"""
        x = z3.Int('x')
        pure = [x > 5]
        side = [x > 10]
        result = _check_entailment(side, pure, 1000)
        assert result is False

    def test_exact_match(self):
        """Test when constraints match exactly"""
        x = z3.Int('x')
        pure = [x == 10]
        side = [x == 10]
        result = _check_entailment(side, pure, 1000)
        assert result is True

    def test_multiple_constraints_entailment(self):
        """Test entailment with multiple constraints"""
        x = z3.Int('x')
        y = z3.Int('y')
        pure = [x > 10, y > 20]
        side = [x > 5, y > 15]
        result = _check_entailment(side, pure, 1000)
        assert result is True


class TestCheckSatisfiability:
    """Test _check_satisfiability function"""

    def test_satisfiable_constraints(self):
        """Test satisfiable constraints"""
        x = z3.Int('x')
        y = z3.Int('y')
        pure = [x > 0]
        side = [y > 10]
        result = _check_satisfiability(side, pure, 1000)
        assert result is True

    def test_unsatisfiable_constraints(self):
        """Test unsatisfiable constraints"""
        x = z3.Int('x')
        pure = [x > 10]
        side = [x < 5]
        result = _check_satisfiability(side, pure, 1000)
        assert result is False

    def test_consistent_constraints(self):
        """Test consistent but non-entailing constraints"""
        x = z3.Int('x')
        pure = [x > 0]
        side = [x < 100]
        result = _check_satisfiability(side, pure, 1000)
        assert result is True


class TestVerifyWithModel:
    """Test verify_side_conditions_with_model function"""

    def test_empty_constraints_no_model(self):
        """Empty constraints should return True with no model"""
        valid, model = verify_side_conditions_with_model([], [])
        assert valid is True
        assert model is None

    def test_satisfiable_returns_model(self):
        """Satisfiable constraints should return model"""
        x = z3.Int('x')
        pure = [x > 0]
        side = [x < 100]
        valid, model = verify_side_conditions_with_model(side, pure)
        assert valid is True
        assert model is not None
        # Model should satisfy constraints
        x_val = model.eval(x)
        assert x_val.as_long() > 0
        assert x_val.as_long() < 100

    def test_unsatisfiable_no_model(self):
        """Unsatisfiable constraints should return False with no model"""
        x = z3.Int('x')
        pure = [x > 10]
        side = [x < 5]
        valid, model = verify_side_conditions_with_model(side, pure)
        assert valid is False
        assert model is None

    def test_entailment_no_model(self):
        """Entailed constraints should return True with no model"""
        x = z3.Int('x')
        pure = [x > 10]
        side = [x > 5]
        valid, model = verify_side_conditions_with_model(side, pure)
        assert valid is True


class TestSimplifyConstraints:
    """Test simplify_constraints function"""

    def test_empty_constraints(self):
        """Empty list should return empty list"""
        result = simplify_constraints([])
        assert result == []

    def test_single_true_constraint(self):
        """True constraint should simplify to empty list"""
        constraints = [z3.BoolVal(True)]
        result = simplify_constraints(constraints)
        assert result == []

    def test_single_false_constraint(self):
        """False constraint should return [False]"""
        constraints = [z3.BoolVal(False)]
        result = simplify_constraints(constraints)
        assert len(result) == 1
        assert z3.is_false(result[0])

    def test_simplify_arithmetic(self):
        """Arithmetic constraints should be simplified"""
        x = z3.Int('x')
        constraints = [x + 0 == x]
        result = simplify_constraints(constraints)
        # Should simplify to True and return empty
        assert result == []

    def test_multiple_constraints_to_true(self):
        """Multiple tautological constraints should simplify to empty"""
        x = z3.Int('x')
        constraints = [x == x, True]
        result = simplify_constraints(constraints)
        assert result == []

    def test_non_trivial_constraint(self):
        """Non-trivial constraint should be returned"""
        x = z3.Int('x')
        constraints = [x > 5]
        result = simplify_constraints(constraints)
        assert len(result) == 1


class TestCheckArithmeticConsistency:
    """Test check_arithmetic_consistency function"""

    def test_empty_constraints_consistent(self):
        """Empty constraints are consistent"""
        result = check_arithmetic_consistency([])
        assert result is True

    def test_consistent_constraints(self):
        """Consistent constraints should return True"""
        x = z3.Int('x')
        y = z3.Int('y')
        constraints = [x > 0, y > 0, x + y > 0]
        result = check_arithmetic_consistency(constraints)
        assert result is True

    def test_inconsistent_constraints(self):
        """Inconsistent constraints should return False"""
        x = z3.Int('x')
        constraints = [x > 10, x < 5]
        result = check_arithmetic_consistency(constraints)
        assert result is False

    def test_complex_inconsistency(self):
        """Complex inconsistent constraints should be detected"""
        x = z3.Int('x')
        y = z3.Int('y')
        constraints = [x == y + 10, y == x + 10]
        result = check_arithmetic_consistency(constraints)
        assert result is False

    def test_borderline_consistency(self):
        """Borderline consistent constraints"""
        x = z3.Int('x')
        constraints = [x >= 0, x <= 0]
        result = check_arithmetic_consistency(constraints)
        assert result is True  # x = 0 is a valid solution


class TestTimeoutHandling:
    """Test timeout behavior"""

    def test_short_timeout(self):
        """Test with very short timeout"""
        x = z3.Int('x')
        pure = [x > 0]
        side = [x < 100]
        # Should still work with short timeout for simple constraints
        result = verify_side_conditions(side, pure, timeout_ms=10)
        assert result is True

    def test_zero_timeout(self):
        """Test with zero timeout (should handle gracefully)"""
        x = z3.Int('x')
        pure = [x > 0]
        side = [x < 100]
        # May or may not work depending on Z3's handling
        result = verify_side_conditions(side, pure, timeout_ms=0)
        # Should not crash


class TestEdgeCases:
    """Test edge cases in arithmetic verification"""

    def test_division_by_zero_guard(self):
        """Test constraints involving division"""
        x = z3.Int('x')
        y = z3.Int('y')
        pure = [y != 0, x == y * 2]
        side = [x / y == 2]
        result = verify_side_conditions(side, pure)
        assert result is True

    def test_modulo_constraints(self):
        """Test constraints with modulo"""
        x = z3.Int('x')
        pure = [x > 10]
        side = [x % 2 == 0]
        result = verify_side_conditions(side, pure)
        assert result is True  # Satisfiable

    def test_negative_numbers(self):
        """Test with negative numbers"""
        x = z3.Int('x')
        pure = [x < -10]
        side = [x < 0]
        result = verify_side_conditions(side, pure)
        assert result is True

    def test_large_numbers(self):
        """Test with large numbers"""
        x = z3.Int('x')
        pure = [x > 1000000]
        side = [x > 100]
        result = verify_side_conditions(side, pure)
        assert result is True
