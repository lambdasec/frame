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


class TestArraySymbolicIndices:
    """Test arrays with symbolic (variable) indices"""

    def test_symbolic_index_select(self):
        """Test array select with variable index"""
        checker = EntailmentChecker()

        # arr[i] where i is a variable
        arr = ArrayStore(ArrayConst(Const(0)), Const(5), Const(42))
        i = Var("i")

        # If i = 5, then arr[i] = 42
        formula = And(
            Eq(i, Const(5)),
            Eq(ArraySelect(arr, i), Const(42))
        )

        result = checker.is_satisfiable(formula)
        assert result, "Symbolic index select should work"

    def test_symbolic_index_store(self):
        """Test array store with variable index"""
        checker = EntailmentChecker()

        # arr2 = store(arr, i, 99) where i is variable
        arr = ArrayConst(Const(0))
        i = Var("i")
        arr2 = ArrayStore(arr, i, Const(99))

        # If i = 3, then arr2[3] = 99
        formula = And(
            Eq(i, Const(3)),
            Eq(ArraySelect(arr2, Const(3)), Const(99))
        )

        result = checker.is_satisfiable(formula)
        assert result, "Symbolic index store should work"

    def test_symbolic_bounds_check(self):
        """Test bounds checking with symbolic index"""
        checker = EntailmentChecker()

        arr = Var("arr")
        i = Var("i")
        size = Const(10)

        # If 0 <= i < 10, then access is safe
        formula = And(
            And(
                Ge(i, Const(0)),
                Lt(i, size)
            ),
            BufferOverflowCheck(arr, i, size)
        )

        result = checker.is_satisfiable(formula)
        assert result, "Symbolic bounds check should work"

    def test_symbolic_out_of_bounds(self):
        """Test symbolic index that's provably out of bounds"""
        checker = EntailmentChecker()

        arr = Var("arr")
        i = Var("i")
        size = Const(10)

        # If i >= 10, then access is unsafe
        formula = And(
            Ge(i, size),
            BufferOverflowCheck(arr, i, size)
        )

        result = checker.is_satisfiable(formula)
        assert not result, "Out of bounds symbolic access should be detected"


class TestArrayAliasing:
    """Test array aliasing and equality"""

    def test_array_alias_same_updates(self):
        """Test that aliased arrays see the same updates"""
        checker = EntailmentChecker()

        # arr1 = arr2 (aliasing)
        # store(arr1, 0, 42) should affect arr2
        arr1 = Var("arr1")
        arr2 = Var("arr2")
        arr1_updated = ArrayStore(arr1, Const(0), Const(42))

        formula = And(
            Eq(arr1, arr2),  # arr1 and arr2 are aliases
            Eq(ArraySelect(arr1_updated, Const(0)), ArraySelect(ArrayStore(arr2, Const(0), Const(42)), Const(0)))
        )

        result = checker.is_satisfiable(formula)
        assert result, "Aliased arrays should see same updates"

    def test_array_no_alias_different_updates(self):
        """Test that non-aliased arrays have independent updates"""
        checker = EntailmentChecker()

        arr1 = Var("arr1")
        arr2 = Var("arr2")

        # arr1 != arr2
        # store(arr1, 0, 42) should NOT affect arr2[0]
        arr1_updated = ArrayStore(arr1, Const(0), Const(42))

        formula = And(
            Neq(arr1, arr2),  # Different arrays
            And(
                Eq(ArraySelect(arr1_updated, Const(0)), Const(42)),
                Eq(ArraySelect(arr2, Const(0)), Const(10))  # arr2[0] still 10
            )
        )

        result = checker.is_satisfiable(formula)
        assert result, "Non-aliased arrays should have independent updates"


class TestArrayReadWriteConflicts:
    """Test read-after-write and write-after-read conflicts"""

    def test_read_after_write_same_index(self):
        """Test reading immediately after writing same index"""
        checker = EntailmentChecker()

        arr = ArrayConst(Const(0))
        # Write 42 to index 5, then read it back
        arr_written = ArrayStore(arr, Const(5), Const(42))
        value_read = ArraySelect(arr_written, Const(5))

        formula = Eq(value_read, Const(42))

        result = checker.is_satisfiable(formula)
        assert result, "Read after write should return written value"

    def test_read_after_write_different_index(self):
        """Test reading different index after write"""
        checker = EntailmentChecker()

        # Original array has all 0s
        arr = ArrayConst(Const(0))
        # Write 42 to index 5
        arr_written = ArrayStore(arr, Const(5), Const(42))
        # Read from index 3 (should still be 0)
        value_read = ArraySelect(arr_written, Const(3))

        formula = Eq(value_read, Const(0))

        result = checker.is_satisfiable(formula)
        assert result, "Read from unmodified index should return original value"

    def test_overwrite_same_index(self):
        """Test overwriting same index twice"""
        checker = EntailmentChecker()

        arr = ArrayConst(Const(0))
        # Write 42, then overwrite with 99
        arr1 = ArrayStore(arr, Const(5), Const(42))
        arr2 = ArrayStore(arr1, Const(5), Const(99))

        formula = Eq(ArraySelect(arr2, Const(5)), Const(99))

        result = checker.is_satisfiable(formula)
        assert result, "Second write should overwrite first"


class TestArrayBoundsEdgeCases:
    """Test edge cases in array bounds checking"""

    def test_zero_size_array(self):
        """Test array with size 0"""
        checker = EntailmentChecker()

        arr = Var("arr")
        size = Const(0)

        # Any index access on size 0 array should fail
        formula = BufferOverflowCheck(arr, Const(0), size)

        result = checker.is_satisfiable(formula)
        assert not result, "Size 0 array should reject all indices"

    def test_large_size_array(self):
        """Test array with very large size"""
        checker = EntailmentChecker()

        arr = Var("arr")
        size = Const(1000000)  # 1 million elements

        # Access at index 500000 should be safe
        formula = BufferOverflowCheck(arr, Const(500000), size)

        result = checker.is_satisfiable(formula)
        assert result, "Access within large array should be safe"

    def test_array_size_mismatch(self):
        """Test that arrays can't have conflicting sizes"""
        checker = EntailmentChecker()

        arr = Var("arr")

        # arr can't simultaneously have size 10 and size 20
        formula = And(
            ArrayBounds(arr, Const(10)),
            ArrayBounds(arr, Const(20))
        )

        result = checker.is_satisfiable(formula)
        assert not result, "Array can't have two different sizes"


class TestBitvectorSignedness:
    """Test signed vs unsigned bitvector operations"""

    def test_unsigned_addition_no_overflow(self):
        """Test unsigned addition that doesn't overflow"""
        checker = EntailmentChecker()

        # 100 + 50 = 150 (no overflow for 8-bit unsigned)
        formula = IntegerOverflow("add", [Const(100), Const(50)], width=8, signed=False)

        result = checker.is_satisfiable(formula)
        assert not result, "100 + 50 should not overflow unsigned 8-bit"

    def test_unsigned_addition_overflow(self):
        """Test unsigned addition that overflows"""
        checker = EntailmentChecker()

        # 200 + 100 = 300, but max unsigned 8-bit is 255 (overflow!)
        formula = IntegerOverflow("add", [Const(200), Const(100)], width=8, signed=False)

        result = checker.is_satisfiable(formula)
        assert result, "200 + 100 should overflow unsigned 8-bit"

    def test_signed_addition_positive_overflow(self):
        """Test signed addition with positive overflow"""
        checker = EntailmentChecker()

        # 100 + 50 = 150, but max signed 8-bit is 127 (overflow!)
        formula = IntegerOverflow("add", [Const(100), Const(50)], width=8, signed=True)

        result = checker.is_satisfiable(formula)
        assert result, "100 + 50 should overflow signed 8-bit"

    def test_signed_addition_negative_overflow(self):
        """Test signed addition with negative overflow"""
        checker = EntailmentChecker()

        # -100 + -50 = -150, but min signed 8-bit is -128 (underflow!)
        formula = IntegerOverflow("add", [Const(-100), Const(-50)], width=8, signed=True)

        result = checker.is_satisfiable(formula)
        assert result, "-100 + -50 should underflow signed 8-bit"


class TestBitvectorComparisons:
    """Test bitvector comparison operations"""

    def test_unsigned_less_than(self):
        """Test unsigned less than comparison"""
        checker = EntailmentChecker()

        # 5 < 10 (unsigned)
        left = BitVecVal(5, 8)
        right = BitVecVal(10, 8)
        result_bv = BitVecExpr("bvult", [left, right], 1)  # Returns 1-bit result

        # Should be true (1)
        result = checker.is_satisfiable(Eq(result_bv, BitVecVal(1, 1)))
        assert result, "5 < 10 should be true (unsigned)"

    def test_signed_less_than(self):
        """Test signed less than comparison"""
        checker = EntailmentChecker()

        # -5 < 5 (signed)
        # In 8-bit two's complement: -5 = 0xFB, 5 = 0x05
        left = BitVecVal(0xFB, 8)  # -5 in two's complement
        right = BitVecVal(5, 8)
        result_bv = BitVecExpr("bvslt", [left, right], 1)

        result = checker.is_satisfiable(Eq(result_bv, BitVecVal(1, 1)))
        assert result, "-5 < 5 should be true (signed)"

    def test_unsigned_vs_signed_comparison(self):
        """Test difference between signed and unsigned comparison"""
        checker = EntailmentChecker()

        # 0xFF = 255 (unsigned) or -1 (signed)
        # 0x01 = 1 (both)

        # Unsigned: 255 > 1 (true)
        left = BitVecVal(0xFF, 8)
        right = BitVecVal(0x01, 8)
        unsigned_gt = BitVecExpr("bvugt", [left, right], 1)

        # Signed: -1 < 1 (true), so NOT (-1 > 1)
        signed_gt = BitVecExpr("bvsgt", [left, right], 1)

        # Unsigned should be true, signed should be false
        formula = And(
            Eq(unsigned_gt, BitVecVal(1, 1)),  # 255 > 1 (unsigned) = true
            Eq(signed_gt, BitVecVal(0, 1))     # -1 > 1 (signed) = false
        )

        result = checker.is_satisfiable(formula)
        assert result, "Signed and unsigned comparisons should differ"


class TestBitvectorShiftEdgeCases:
    """Test edge cases in shift operations"""

    def test_shift_by_zero(self):
        """Test shifting by 0 (should return original value)"""
        checker = EntailmentChecker()

        val = BitVecVal(0x42, 8)
        shift = BitVecVal(0, 8)
        result_bv = BitVecExpr("bvshl", [val, shift], 8)

        formula = Eq(result_bv, val)

        result = checker.is_satisfiable(formula)
        assert result, "Shift by 0 should return original value"

    def test_shift_by_width(self):
        """Test shifting by full width (should be 0)"""
        checker = EntailmentChecker()

        # Shift left by 8 bits in 8-bit value = 0
        val = BitVecVal(0x42, 8)
        shift = BitVecVal(8, 8)
        result_bv = BitVecExpr("bvshl", [val, shift], 8)

        formula = Eq(result_bv, BitVecVal(0, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Shift by width should be 0"

    def test_arithmetic_vs_logical_right_shift(self):
        """Test difference between arithmetic and logical right shift"""
        checker = EntailmentChecker()

        # 0x80 = 10000000 (negative in signed 8-bit)
        val = BitVecVal(0x80, 8)
        shift = BitVecVal(1, 8)

        # Logical shift (zero-fill): 0x80 >> 1 = 0x40
        logical_shift = BitVecExpr("bvlshr", [val, shift], 8)

        # Arithmetic shift (sign-extend): 0x80 >> 1 = 0xC0
        arith_shift = BitVecExpr("bvashr", [val, shift], 8)

        # They should be different
        formula = Neq(logical_shift, arith_shift)

        result = checker.is_satisfiable(formula)
        assert result, "Logical and arithmetic shifts should differ for negative values"


class TestBitvectorArithmeticEdgeCases:
    """Test edge cases in bitvector arithmetic"""

    def test_division_by_zero(self):
        """Test division by zero behavior"""
        checker = EntailmentChecker()

        # In SMT-LIB, division by zero is unspecified/undefined
        # We test that it's satisfiable (solver assigns some value)
        numerator = BitVecVal(10, 8)
        denominator = BitVecVal(0, 8)
        result_bv = BitVecExpr("bvudiv", [numerator, denominator], 8)

        # Should be satisfiable (undefined value)
        formula = Eq(result_bv, Var("x"))

        result = checker.is_satisfiable(formula)
        assert result, "Division by zero should be satisfiable (undefined)"

    def test_modulo_by_zero(self):
        """Test modulo by zero behavior"""
        checker = EntailmentChecker()

        numerator = BitVecVal(10, 8)
        denominator = BitVecVal(0, 8)
        result_bv = BitVecExpr("bvurem", [numerator, denominator], 8)

        # Should be satisfiable (undefined value)
        formula = Eq(result_bv, Var("x"))

        result = checker.is_satisfiable(formula)
        assert result, "Modulo by zero should be satisfiable (undefined)"

    def test_multiplication_by_zero(self):
        """Test multiplication by zero (should always be zero)"""
        checker = EntailmentChecker()

        left = Var("x")  # Unknown value
        right = BitVecVal(0, 8)
        result_bv = BitVecExpr("bvmul", [left, right], 8)

        formula = Eq(result_bv, BitVecVal(0, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Multiplication by zero should be zero"

    def test_subtraction_wraparound(self):
        """Test subtraction wraparound (underflow)"""
        checker = EntailmentChecker()

        # 0 - 1 = 255 (for unsigned 8-bit)
        left = BitVecVal(0, 8)
        right = BitVecVal(1, 8)
        result_bv = BitVecExpr("bvsub", [left, right], 8)

        formula = Eq(result_bv, BitVecVal(255, 8))

        result = checker.is_satisfiable(formula)
        assert result, "Subtraction should wrap around"


