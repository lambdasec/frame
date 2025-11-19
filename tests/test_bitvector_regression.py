"""
Regression tests for Array and Bitvector Theory

This file contains additional edge cases and regression tests to ensure
high coverage of array and bitvector functionality.
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


class TestCombinedArrayBitvectorScenarios:
    """Test realistic scenarios combining arrays and bitvectors"""

    def test_array_index_with_bitvector_arithmetic(self):
        """Test using bitvector arithmetic to compute array index"""
        checker = EntailmentChecker()

        # base_index = 2, offset = 3
        # final_index = base_index + offset = 5
        base = BitVecVal(2, 8)
        offset = BitVecVal(3, 8)
        final_index = BitVecExpr("bvadd", [base, offset], 8)

        arr = ArrayStore(ArrayConst(Const(0)), Const(5), Const(99))

        # arr[2 + 3] = arr[5] = 99
        formula = Eq(ArraySelect(arr, final_index), Const(99))

        result = checker.is_satisfiable(formula)
        assert result, "Array index from bitvector arithmetic should work"

    def test_bitvector_overflow_prevents_array_access(self):
        """Test that bitvector overflow can cause out-of-bounds access"""
        checker = EntailmentChecker()

        # If index overflows, it might wrap around and access wrong location
        # base = 250, offset = 10 => 260, but wraps to 4 in 8-bit
        base = BitVecVal(250, 8)
        offset = BitVecVal(10, 8)
        wrapped_index = BitVecExpr("bvadd", [base, offset], 8)  # = 4 (wraps from 260)

        arr = Var("arr")
        size = Const(100)

        # The wrapped index (4) is in bounds, but conceptually wrong!
        # This demonstrates why overflow checking is important
        formula = BufferOverflowCheck(arr, wrapped_index, size)

        result = checker.is_satisfiable(formula)
        assert result, "Wrapped index might pass bounds check incorrectly"


class TestBitvectorDivisionModuloEdgeCases:
    """Test edge cases in bitvector division and modulo operations"""

    def test_division_by_one(self):
        """Test division by 1 returns the numerator"""
        checker = EntailmentChecker()

        numerator = BitVecVal(42, 8)
        denominator = BitVecVal(1, 8)
        result_bv = BitVecExpr("bvudiv", [numerator, denominator], 8)

        formula = Eq(result_bv, BitVecVal(42, 8))

        result = checker.is_satisfiable(formula)
        assert result, "42 / 1 should equal 42"

    def test_zero_divided_by_nonzero(self):
        """Test 0 divided by any number is 0"""
        checker = EntailmentChecker()

        numerator = BitVecVal(0, 8)
        denominator = BitVecVal(7, 8)
        result_bv = BitVecExpr("bvudiv", [numerator, denominator], 8)

        formula = Eq(result_bv, BitVecVal(0, 8))

        result = checker.is_satisfiable(formula)
        assert result, "0 / 7 should equal 0"

    def test_modulo_by_one(self):
        """Test modulo by 1 always returns 0"""
        checker = EntailmentChecker()

        numerator = BitVecVal(42, 8)
        denominator = BitVecVal(1, 8)
        result_bv = BitVecExpr("bvurem", [numerator, denominator], 8)

        formula = Eq(result_bv, BitVecVal(0, 8))

        result = checker.is_satisfiable(formula)
        assert result, "42 % 1 should equal 0"

    def test_modulo_smaller_than_divisor(self):
        """Test modulo when numerator < divisor returns numerator"""
        checker = EntailmentChecker()

        numerator = BitVecVal(5, 8)
        denominator = BitVecVal(10, 8)
        result_bv = BitVecExpr("bvurem", [numerator, denominator], 8)

        formula = Eq(result_bv, BitVecVal(5, 8))

        result = checker.is_satisfiable(formula)
        assert result, "5 % 10 should equal 5"

    def test_signed_division_negative_result(self):
        """Test signed division with negative result"""
        checker = EntailmentChecker()

        # -20 / 4 = -5
        numerator = BitVecVal(256 - 20, 8)  # -20 in 8-bit two's complement
        denominator = BitVecVal(4, 8)
        result_bv = BitVecExpr("bvsdiv", [numerator, denominator], 8)

        expected = BitVecVal(256 - 5, 8)  # -5 in 8-bit two's complement
        formula = Eq(result_bv, expected)

        result = checker.is_satisfiable(formula)
        assert result, "-20 / 4 should equal -5 (signed)"


class TestBitvectorComparisonEdgeCases:
    """Test edge cases in bitvector comparisons"""

    def test_equal_values_not_less_than(self):
        """Test that equal values are not less than each other"""
        checker = EntailmentChecker()

        left = BitVecVal(10, 8)
        right = BitVecVal(10, 8)
        result_bv = BitVecExpr("bvult", [left, right], 1)

        # Should be false (0)
        formula = Eq(result_bv, BitVecVal(0, 1))

        result = checker.is_satisfiable(formula)
        assert result, "10 < 10 should be false"

    def test_unsigned_max_value_comparison(self):
        """Test comparison with maximum unsigned value"""
        checker = EntailmentChecker()

        # 255 is max for unsigned 8-bit
        max_val = BitVecVal(255, 8)
        smaller = BitVecVal(100, 8)

        # 100 < 255
        result_bv = BitVecExpr("bvult", [smaller, max_val], 1)
        formula = Eq(result_bv, BitVecVal(1, 1))

        result = checker.is_satisfiable(formula)
        assert result, "100 < 255 should be true"

    def test_signed_negative_comparison(self):
        """Test comparison between two negative signed values"""
        checker = EntailmentChecker()

        # -10 < -5 (in signed)
        neg_ten = BitVecVal(256 - 10, 8)  # -10 in two's complement
        neg_five = BitVecVal(256 - 5, 8)  # -5 in two's complement

        result_bv = BitVecExpr("bvslt", [neg_ten, neg_five], 1)
        formula = Eq(result_bv, BitVecVal(1, 1))

        result = checker.is_satisfiable(formula)
        assert result, "-10 < -5 should be true (signed)"

    def test_unsigned_greater_equal(self):
        """Test unsigned greater-than-or-equal"""
        checker = EntailmentChecker()

        # Test 10 >= 10 (should be true)
        left = BitVecVal(10, 8)
        right = BitVecVal(10, 8)
        result_bv = BitVecExpr("bvuge", [left, right], 1)

        formula = Eq(result_bv, BitVecVal(1, 1))

        result = checker.is_satisfiable(formula)
        assert result, "10 >= 10 should be true"


class TestAdvancedArrayOperations:
    """Test advanced array operations and edge cases"""

    def test_array_chain_of_updates(self):
        """Test a long chain of array updates"""
        checker = EntailmentChecker()

        # Build arr[0]=1, arr[1]=2, ..., arr[4]=5
        arr = ArrayConst(Const(0))
        for i in range(5):
            arr = ArrayStore(arr, Const(i), Const(i + 1))

        # Check all values
        formula = And(
            And(
                And(
                    Eq(ArraySelect(arr, Const(0)), Const(1)),
                    Eq(ArraySelect(arr, Const(1)), Const(2))
                ),
                And(
                    Eq(ArraySelect(arr, Const(2)), Const(3)),
                    Eq(ArraySelect(arr, Const(3)), Const(4))
                )
            ),
            Eq(ArraySelect(arr, Const(4)), Const(5))
        )

        result = checker.is_satisfiable(formula)
        assert result, "Chain of array updates should work"

    def test_array_overwrite_tracking(self):
        """Test that array overwrites are properly tracked"""
        checker = EntailmentChecker()

        # arr[5] = 10, then arr[5] = 20
        # Final value should be 20, not 10
        base = ArrayConst(Const(0))
        arr1 = ArrayStore(base, Const(5), Const(10))
        arr2 = ArrayStore(arr1, Const(5), Const(20))

        # arr2[5] should be 20, not 10
        formula = And(
            Eq(ArraySelect(arr2, Const(5)), Const(20)),
            Neq(ArraySelect(arr2, Const(5)), Const(10))
        )

        result = checker.is_satisfiable(formula)
        assert result, "Array overwrite should use latest value"

    def test_array_with_symbolic_index_bounds(self):
        """Test bounds checking with symbolic index"""
        checker = EntailmentChecker()

        arr = Var("arr")
        idx = Var("idx")
        size = Const(100)

        # If idx < 100, then access is safe
        formula = And(
            Lt(idx, size),
            BufferOverflowCheck(arr, idx, size)
        )

        result = checker.is_satisfiable(formula)
        assert result, "Symbolic index with constraint should be safe"

    def test_array_index_at_max_value(self):
        """Test array access at maximum valid index"""
        checker = EntailmentChecker()

        arr = Var("arr")
        size = Const(1000)
        # Max valid index is size - 1 = 999
        max_idx = Const(999)

        formula = BufferOverflowCheck(arr, max_idx, size)

        result = checker.is_satisfiable(formula)
        assert result, "Access at max valid index should be safe"

    def test_array_multiple_symbolic_accesses(self):
        """Test multiple symbolic accesses to same array"""
        checker = EntailmentChecker()

        arr = ArrayStore(
            ArrayStore(ArrayConst(Const(0)), Const(10), Const(100)),
            Const(20), Const(200)
        )

        i = Var("i")
        j = Var("j")

        # If i=10 and j=20, then arr[i]=100 and arr[j]=200
        formula = And(
            And(
                Eq(i, Const(10)),
                Eq(j, Const(20))
            ),
            And(
                Eq(ArraySelect(arr, i), Const(100)),
                Eq(ArraySelect(arr, j), Const(200))
            )
        )

        result = checker.is_satisfiable(formula)
        assert result, "Multiple symbolic accesses should work"


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
