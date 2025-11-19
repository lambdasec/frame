"""
Bitvector Advanced Regression Tests - Part 2

Tests for chained bitvector operations, security vulnerability scenarios,
and bitvector width variations.
"""

import pytest
from frame import EntailmentChecker
from frame.core.ast import (
    Var, Const, ArraySelect, ArrayStore, ArrayConst,
    BitVecVal, BitVecExpr,
    Eq, And, Or, Not,
    TaintedArray, BufferOverflowCheck, ArrayBounds,
    IntegerOverflow, Neq, Lt, Gt, Le, Ge
)


class TestChainedBitvectorOperations:
    """Test chained bitvector operations"""

    def test_chained_arithmetic(self):
        """Test chaining multiple arithmetic operations"""
        checker = EntailmentChecker()

        # (10 + 5) * 2 = 30
        a = BitVecVal(10, 8)
        b = BitVecVal(5, 8)
        sum_ab = BitVecExpr("bvadd", [a, b], 8)

        c = BitVecVal(2, 8)
        result = BitVecExpr("bvmul", [sum_ab, c], 8)

        formula = Eq(result, BitVecVal(30, 8))

        result_sat = checker.is_satisfiable(formula)
        assert result_sat, "(10 + 5) * 2 should equal 30"

    def test_chained_bitwise(self):
        """Test chaining bitwise operations"""
        checker = EntailmentChecker()

        # (0xFF & 0x0F) | 0xF0 = 0xFF
        a = BitVecVal(0xFF, 8)
        b = BitVecVal(0x0F, 8)
        and_result = BitVecExpr("bvand", [a, b], 8)

        c = BitVecVal(0xF0, 8)
        final = BitVecExpr("bvor", [and_result, c], 8)

        formula = Eq(final, BitVecVal(0xFF, 8))

        result = checker.is_satisfiable(formula)
        assert result, "(0xFF & 0x0F) | 0xF0 should equal 0xFF"

    def test_shift_then_mask(self):
        """Test shift followed by mask (common pattern)"""
        checker = EntailmentChecker()

        # (0x42 << 2) & 0xFF = 0x08 (lower bits)
        val = BitVecVal(0x42, 8)
        shift_amt = BitVecVal(2, 8)
        shifted = BitVecExpr("bvshl", [val, shift_amt], 8)

        mask = BitVecVal(0xFF, 8)
        masked = BitVecExpr("bvand", [shifted, mask], 8)

        # 0x42 = 01000010, shifted left 2 = 00001000 = 0x08 (with wraparound)
        # Actually: 0x42 << 2 = 0x108, truncated to 8 bits = 0x08
        formula = Eq(masked, BitVecVal(0x08, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Shift then mask should work"

    def test_comparison_in_conditional(self):
        """Test using comparison result in further operations"""
        checker = EntailmentChecker()

        # Check if 5 < 10, result is 1-bit bitvector
        left = BitVecVal(5, 8)
        right = BitVecVal(10, 8)
        cmp_result = BitVecExpr("bvult", [left, right], 1)

        # Compare result with 1 (true)
        formula = Eq(cmp_result, BitVecVal(1, 1))

        result = checker.is_satisfiable(formula)
        assert result, "Comparison result should be usable"


class TestSecurityScenarios:
    """Test realistic security vulnerability scenarios"""

    def test_integer_overflow_to_small_allocation(self):
        """Test integer overflow leading to small buffer allocation"""
        checker = EntailmentChecker()

        # User requests: size = 200, count = 2
        # Calculation: total = size * count = 400 (overflows 8-bit)
        # Result: total = 144 (400 % 256)
        size = Const(200)
        count = Const(2)

        overflow_formula = IntegerOverflow("mul", [size, count], width=8, signed=False)

        result = checker.is_satisfiable(overflow_formula)
        assert result, "200 * 2 should overflow 8-bit unsigned"

    def test_off_by_one_buffer_access(self):
        """Test classic off-by-one vulnerability"""
        checker = EntailmentChecker()

        arr = Var("arr")
        size = Const(10)

        # Accessing index 10 when size is 10 is off-by-one error
        # Valid indices: 0-9
        bad_access = BufferOverflowCheck(arr, Const(10), size)

        result = checker.is_satisfiable(bad_access)
        assert not result, "Off-by-one access should be detected"

    def test_negative_index_via_underflow(self):
        """Test negative index created via unsigned underflow"""
        checker = EntailmentChecker()

        # 0 - 1 = 255 (for unsigned 8-bit)
        zero = BitVecVal(0, 8)
        one = BitVecVal(1, 8)
        underflow_idx = BitVecExpr("bvsub", [zero, one], 8)

        arr = Var("arr")
        size = Const(100)

        # When converted to int, 255 > 100, so should fail bounds check
        # BV2Int treats as unsigned, so 255 becomes integer 255
        bad_access = BufferOverflowCheck(arr, underflow_idx, size)

        result = checker.is_satisfiable(bad_access)
        assert not result, "Underflow creating large index should be detected"

    def test_tainted_index_with_sanitization(self):
        """Test that sanitized tainted input is safe"""
        checker = EntailmentChecker()

        # Tainted input from user
        inputs = Var("inputs")
        user_idx = Var("user_idx")

        # Sanitize by bounds checking
        arr = Var("arr")
        size = Const(100)

        formula = And(
            And(
                # Input is tainted
                TaintedArray(inputs, [Const(0)]),
                # user_idx comes from tainted input
                Eq(user_idx, ArraySelect(inputs, Const(0)))
            ),
            And(
                And(
                    # But we sanitize with bounds check
                    Lt(user_idx, size),
                    Ge(user_idx, Const(0))
                ),
                # So access is safe
                BufferOverflowCheck(arr, user_idx, size)
            )
        )

        result = checker.is_satisfiable(formula)
        assert result, "Properly sanitized tainted input should be safe"


class TestBitvectorWidthVariations:
    """Test operations across different bitvector widths"""

    def test_16bit_comparison(self):
        """Test comparison on 16-bit bitvectors"""
        checker = EntailmentChecker()

        # 1000 < 2000 (16-bit)
        left = BitVecVal(1000, 16)
        right = BitVecVal(2000, 16)
        result_bv = BitVecExpr("bvult", [left, right], 1)

        formula = Eq(result_bv, BitVecVal(1, 1))

        result = checker.is_satisfiable(formula)
        assert result, "1000 < 2000 should be true (16-bit)"

    def test_32bit_overflow(self):
        """Test overflow detection on 32-bit values"""
        checker = EntailmentChecker()

        # 2^31 + 2^31 overflows signed 32-bit
        large = Const(2**31)
        overflow_formula = IntegerOverflow("add", [large, large], width=32, signed=True)

        result = checker.is_satisfiable(overflow_formula)
        assert result, "2^31 + 2^31 should overflow signed 32-bit"

    def test_1bit_bitvector_operations(self):
        """Test operations on 1-bit bitvectors (booleans)"""
        checker = EntailmentChecker()

        # 1 & 0 = 0 (bitwise AND)
        one = BitVecVal(1, 1)
        zero = BitVecVal(0, 1)
        result_bv = BitVecExpr("bvand", [one, zero], 1)

        formula = Eq(result_bv, BitVecVal(0, 1))

        result = checker.is_satisfiable(formula)
        assert result, "1 & 0 should equal 0 (1-bit)"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
