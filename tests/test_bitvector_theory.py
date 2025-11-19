"""
Tests for Bitvector Theory (QF_BV) support

Tests bitvector operations, overflow detection, and bitwise operations.
"""

import pytest
from frame import EntailmentChecker
from frame.core.ast import (
    Var, Const, BitVecVal, BitVecExpr,
    Eq, And, Or, IntegerOverflow
)


class TestBitvectorBasics:
    """Test basic bitvector operations"""

    def test_bitvec_constant(self):
        """Test bitvector constant values"""
        checker = EntailmentChecker()

        # #x0F (15 in hex) = 15 in decimal
        bv = BitVecVal(15, 8)  # 8-bit bitvector with value 15
        formula = Eq(bv, bv)  # Reflexivity

        result = checker.is_satisfiable(formula)
        assert result, "Bitvector constant should be satisfiable"

    def test_bitvec_addition(self):
        """Test bitvector addition"""
        checker = EntailmentChecker()

        # 5 + 3 = 8 (8-bit)
        left = BitVecVal(5, 8)
        right = BitVecVal(3, 8)
        result_bv = BitVecExpr("bvadd", [left, right], 8)

        formula = Eq(result_bv, BitVecVal(8, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Bitvector addition should work"

    def test_bitvec_subtraction(self):
        """Test bitvector subtraction"""
        checker = EntailmentChecker()

        # 10 - 3 = 7 (8-bit)
        left = BitVecVal(10, 8)
        right = BitVecVal(3, 8)
        result_bv = BitVecExpr("bvsub", [left, right], 8)

        formula = Eq(result_bv, BitVecVal(7, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Bitvector subtraction should work"

    def test_bitvec_multiplication(self):
        """Test bitvector multiplication"""
        checker = EntailmentChecker()

        # 4 * 5 = 20 (8-bit)
        left = BitVecVal(4, 8)
        right = BitVecVal(5, 8)
        result_bv = BitVecExpr("bvmul", [left, right], 8)

        formula = Eq(result_bv, BitVecVal(20, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Bitvector multiplication should work"


class TestBitwiseOperations:
    """Test bitwise operations"""

    def test_bitwise_and(self):
        """Test bitwise AND operation"""
        checker = EntailmentChecker()

        # 0xFF & 0x0F = 0x0F
        left = BitVecVal(0xFF, 8)
        right = BitVecVal(0x0F, 8)
        result_bv = BitVecExpr("bvand", [left, right], 8)

        formula = Eq(result_bv, BitVecVal(0x0F, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Bitwise AND should work"

    def test_bitwise_or(self):
        """Test bitwise OR operation"""
        checker = EntailmentChecker()

        # 0xF0 | 0x0F = 0xFF
        left = BitVecVal(0xF0, 8)
        right = BitVecVal(0x0F, 8)
        result_bv = BitVecExpr("bvor", [left, right], 8)

        formula = Eq(result_bv, BitVecVal(0xFF, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Bitwise OR should work"

    def test_bitwise_xor(self):
        """Test bitwise XOR operation"""
        checker = EntailmentChecker()

        # 0xFF ^ 0xFF = 0x00
        left = BitVecVal(0xFF, 8)
        right = BitVecVal(0xFF, 8)
        result_bv = BitVecExpr("bvxor", [left, right], 8)

        formula = Eq(result_bv, BitVecVal(0x00, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Bitwise XOR should work"

    def test_bitwise_not(self):
        """Test bitwise NOT operation"""
        checker = EntailmentChecker()

        # ~0x0F = 0xF0 (for 8-bit)
        val = BitVecVal(0x0F, 8)
        result_bv = BitVecExpr("bvnot", [val], 8)

        formula = Eq(result_bv, BitVecVal(0xF0, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Bitwise NOT should work"

    def test_left_shift(self):
        """Test left shift operation"""
        checker = EntailmentChecker()

        # 0x01 << 3 = 0x08
        val = BitVecVal(0x01, 8)
        shift = BitVecVal(3, 8)
        result_bv = BitVecExpr("bvshl", [val, shift], 8)

        formula = Eq(result_bv, BitVecVal(0x08, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Left shift should work"

    def test_logical_right_shift(self):
        """Test logical right shift (zero-fill)"""
        checker = EntailmentChecker()

        # 0x80 >> 2 = 0x20 (logical, unsigned)
        val = BitVecVal(0x80, 8)
        shift = BitVecVal(2, 8)
        result_bv = BitVecExpr("bvlshr", [val, shift], 8)

        formula = Eq(result_bv, BitVecVal(0x20, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Logical right shift should work"


class TestIntegerOverflow:
    """Test integer overflow detection"""

    def test_unsigned_addition_overflow(self):
        """Test unsigned addition overflow detection"""
        checker = EntailmentChecker()

        # 255 + 1 overflows in 8-bit unsigned
        left = Var("x")
        right = Var("y")

        formula = And(
            And(
                Eq(left, Const(255)),
                Eq(right, Const(1))
            ),
            IntegerOverflow("add", [left, right], 8, signed=False)
        )

        result = checker.is_satisfiable(formula)
        assert result, "Unsigned addition overflow should be detected"

    def test_unsigned_addition_no_overflow(self):
        """Test unsigned addition without overflow"""
        checker = EntailmentChecker()

        # 100 + 50 = 150, no overflow in 8-bit unsigned
        left = Var("x")
        right = Var("y")

        formula = And(
            And(
                Eq(left, Const(100)),
                Eq(right, Const(50))
            ),
            IntegerOverflow("add", [left, right], 8, signed=False)
        )

        result = checker.is_satisfiable(formula)
        assert not result, "No overflow for 100 + 50 in 8-bit"

    def test_signed_addition_overflow(self):
        """Test signed addition overflow detection"""
        checker = EntailmentChecker()

        # 127 + 1 = 128 overflows in 8-bit signed (max is 127)
        left = Var("x")
        right = Var("y")

        formula = And(
            And(
                Eq(left, Const(127)),
                Eq(right, Const(1))
            ),
            IntegerOverflow("add", [left, right], 8, signed=True)
        )

        result = checker.is_satisfiable(formula)
        assert result, "Signed addition overflow should be detected"

    def test_unsigned_subtraction_underflow(self):
        """Test unsigned subtraction underflow"""
        checker = EntailmentChecker()

        # 5 - 10 underflows in unsigned arithmetic
        left = Var("x")
        right = Var("y")

        formula = And(
            And(
                Eq(left, Const(5)),
                Eq(right, Const(10))
            ),
            IntegerOverflow("sub", [left, right], 8, signed=False)
        )

        result = checker.is_satisfiable(formula)
        assert result, "Unsigned subtraction underflow should be detected"

    def test_multiplication_overflow(self):
        """Test multiplication overflow"""
        checker = EntailmentChecker()

        # 128 * 2 = 256 overflows in 8-bit unsigned (max is 255)
        left = Var("x")
        right = Var("y")

        formula = And(
            And(
                Eq(left, Const(128)),
                Eq(right, Const(2))
            ),
            IntegerOverflow("mul", [left, right], 8, signed=False)
        )

        result = checker.is_satisfiable(formula)
        assert result, "Multiplication overflow should be detected"

    def test_multiplication_no_overflow(self):
        """Test multiplication without overflow"""
        checker = EntailmentChecker()

        # 10 * 10 = 100, no overflow in 8-bit unsigned
        left = Var("x")
        right = Var("y")

        formula = And(
            And(
                Eq(left, Const(10)),
                Eq(right, Const(10))
            ),
            IntegerOverflow("mul", [left, right], 8, signed=False)
        )

        result = checker.is_satisfiable(formula)
        assert not result, "No overflow for 10 * 10 in 8-bit"


class TestBitvectorComparison:
    """Test bitvector comparison operations"""

    def test_unsigned_less_than(self):
        """Test unsigned less than comparison"""
        checker = EntailmentChecker()

        # 5 < 10 (unsigned)
        left = BitVecVal(5, 8)
        right = BitVecVal(10, 8)
        cmp = BitVecExpr("bvult", [left, right], 8)

        result = checker.is_satisfiable(cmp)
        assert result, "5 < 10 should be true"

    def test_unsigned_greater_than(self):
        """Test unsigned greater than comparison"""
        checker = EntailmentChecker()

        # 200 > 100 (unsigned)
        left = BitVecVal(200, 8)
        right = BitVecVal(100, 8)
        cmp = BitVecExpr("bvugt", [left, right], 8)

        result = checker.is_satisfiable(cmp)
        assert result, "200 > 100 should be true"

    def test_signed_less_than(self):
        """Test signed less than comparison"""
        checker = EntailmentChecker()

        # -5 < 10 (signed)
        left = BitVecVal(-5 & 0xFF, 8)  # Two's complement representation
        right = BitVecVal(10, 8)
        cmp = BitVecExpr("bvslt", [left, right], 8)

        result = checker.is_satisfiable(cmp)
        assert result, "-5 < 10 should be true (signed)"


class TestBitvectorWidths:
    """Test different bitvector widths"""

    def test_8bit_operations(self):
        """Test 8-bit bitvector operations"""
        checker = EntailmentChecker()

        # Max 8-bit unsigned value is 255
        max_val = BitVecVal(255, 8)
        formula = Eq(max_val, BitVecVal(255, 8))

        result = checker.is_satisfiable(formula)
        assert result, "8-bit operations should work"

    def test_16bit_operations(self):
        """Test 16-bit bitvector operations"""
        checker = EntailmentChecker()

        # Max 16-bit unsigned value is 65535
        max_val = BitVecVal(65535, 16)
        formula = Eq(max_val, BitVecVal(65535, 16))

        result = checker.is_satisfiable(formula)
        assert result, "16-bit operations should work"

    def test_32bit_operations(self):
        """Test 32-bit bitvector operations"""
        checker = EntailmentChecker()

        # Common 32-bit value
        val = BitVecVal(0xDEADBEEF, 32)
        formula = Eq(val, BitVecVal(0xDEADBEEF, 32))

        result = checker.is_satisfiable(formula)
        assert result, "32-bit operations should work"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
