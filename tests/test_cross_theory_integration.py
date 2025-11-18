"""
Cross-Theory Integration Tests

Tests that combine multiple SMT theories to ensure integrated functionality:
- Separation Logic + String Theory (QF_S)
- Separation Logic + Array Theory (QF_AX)
- Separation Logic + Bitvector Theory (QF_BV)
- Array Theory + Bitvector Theory
- All theories combined (where supported)

These tests guard against regressions when theories interact.
"""

import pytest
from frame import EntailmentChecker
from frame.core.ast import (
    # Core
    Var, Const, Eq, And,
    # Separation Logic
    PointsTo, SepConj, Emp,
    # String Theory
    StrConcat, StrLiteral,
    # Array Theory
    ArraySelect, ArrayStore, BufferOverflowCheck,
    # Bitvector Theory
    BitVecExpr, BitVecVal,
)
from frame.core.parser import parse


class TestHeapPlusStrings:
    """Integration: Separation Logic + String Theory (QF_S)"""

    def test_heap_separation_with_strings(self):
        """Separating conjunction with string values"""
        checker = EntailmentChecker()

        # x |-> s1 * y |-> s2 & s1 = "hello"
        formula = And(
            SepConj(
                PointsTo(Var("x"), Var("s1")),
                PointsTo(Var("y"), Var("s2"))
            ),
            Eq(Var("s1"), StrLiteral("hello"))
        )

        assert checker.is_satisfiable(formula), "Heap separation with strings should work"

    def test_string_concat_with_heap(self):
        """String concatenation with heap-stored value"""
        checker = EntailmentChecker()

        # x |-> s1 & result = (s1 ++ " world") & s1 = "hello"
        formula = And(
            PointsTo(Var("x"), Var("s1")),
            And(
                Eq(Var("s1"), StrLiteral("hello")),
                Eq(Var("result"), StrConcat(Var("s1"), StrLiteral(" world")))
            )
        )

        assert checker.is_satisfiable(formula), "String concat with heap value should work"


class TestHeapPlusArrays:
    """Integration: Separation Logic + Array Theory (QF_AX)"""

    def test_points_to_with_array_value(self):
        """Points-to assertion with array value"""
        checker = EntailmentChecker()

        # x |-> arr & arr[5] = 42
        arr_with_value = ArrayStore(Var("arr"), Const(5), Const(42))
        formula = And(
            PointsTo(Var("x"), Var("arr")),
            Eq(ArraySelect(arr_with_value, Const(5)), Const(42))
        )

        assert checker.is_satisfiable(formula), "Heap with array value should be satisfiable"

    def test_heap_separation_with_arrays(self):
        """Multiple heap cells with array operations"""
        checker = EntailmentChecker()

        # x |-> arr1 * y |-> arr2 & arr1[0] = 1 & arr2[0] = 2
        arr1 = ArrayStore(Var("arr1_base"), Const(0), Const(1))
        arr2 = ArrayStore(Var("arr2_base"), Const(0), Const(2))

        formula = And(
            SepConj(
                PointsTo(Var("x"), Var("arr1")),
                PointsTo(Var("y"), Var("arr2"))
            ),
            And(
                Eq(ArraySelect(arr1, Const(0)), Const(1)),
                Eq(ArraySelect(arr2, Const(0)), Const(2))
            )
        )

        assert checker.is_satisfiable(formula), "Heap separation with arrays should work"

    def test_buffer_overflow_on_heap_array(self):
        """Buffer overflow check on heap-allocated array"""
        checker = EntailmentChecker()

        # x |-> buffer & BufferOverflowCheck(buffer, 10, 5)
        # Index 10 should overflow buffer of size 5
        formula = And(
            PointsTo(Var("x"), Var("buffer")),
            BufferOverflowCheck(Var("buffer"), Const(10), Const(5))
        )

        # Should be unsatisfiable (overflow detected)
        assert not checker.is_satisfiable(formula), "Buffer overflow should be detected"


class TestHeapPlusBitvectors:
    """Integration: Separation Logic + Bitvector Theory (QF_BV)"""

    def test_points_to_with_bitvector_value(self):
        """Points-to assertion with bitvector value"""
        checker = EntailmentChecker()

        # x |-> bv & bv = 0xFF
        formula = And(
            PointsTo(Var("x"), Var("bv")),
            Eq(Var("bv"), BitVecVal(255, 8))
        )

        assert checker.is_satisfiable(formula), "Heap with bitvector value should be satisfiable"

    def test_heap_separation_with_bitvectors(self):
        """Multiple heap cells with bitvector values"""
        checker = EntailmentChecker()

        # x |-> a * y |-> b & a = 5 & b = 3
        formula = And(
            SepConj(
                PointsTo(Var("x"), Var("a")),
                PointsTo(Var("y"), Var("b"))
            ),
            And(
                Eq(Var("a"), BitVecVal(5, 8)),
                Eq(Var("b"), BitVecVal(3, 8))
            )
        )

        assert checker.is_satisfiable(formula), "Heap separation with bitvectors should work"


class TestArraysPlusBitvectors:
    """Integration: Array Theory (QF_AX) + Bitvector Theory (QF_BV)"""

    def test_array_with_integer_values(self):
        """Array storing integer values with bitvector-sized indices"""
        checker = EntailmentChecker()

        # arr[8] = 42 where 8 = bvadd(5, 3) (calculated separately)
        arr = ArrayStore(Var("arr"), Const(8), Const(42))
        index_bv = BitVecExpr("bvadd", [BitVecVal(5, 8), BitVecVal(3, 8)], 8)

        # Test bitvector arithmetic separately
        formula = And(
            Eq(index_bv, BitVecVal(8, 8)),
            Eq(ArraySelect(arr, Const(8)), Const(42))
        )

        assert checker.is_satisfiable(formula), "Array with bitvector-computed index should work"

    def test_bitvector_overflow_prevents_array_access(self):
        """Integer overflow causing array bounds violation"""
        checker = EntailmentChecker()

        # size = bvmul(200, 200) in 8-bit = 64 (overflow)
        # arr = malloc(size) -> buffer of size 64
        # access arr[100] -> overflow
        size = BitVecExpr("bvmul", [BitVecVal(200, 8), BitVecVal(200, 8)], 8)

        formula = And(
            Eq(size, BitVecVal(64, 8)),  # 40000 mod 256 = 64
            BufferOverflowCheck(Var("arr"), Const(100), Const(64))
        )

        # Should be unsatisfiable (overflow detected)
        assert not checker.is_satisfiable(formula), "Overflow from bitvector should prevent array access"


class TestAllTheoriesCombined:
    """Integration: Heap + Arrays + Bitvectors"""

    def test_heap_with_array_and_bitvector_size(self):
        """Heap cell with array and bitvector size calculation"""
        checker = EntailmentChecker()

        # x |-> arr & size = bvadd(8, 2) & size = 10
        size_bv = BitVecExpr("bvadd", [BitVecVal(8, 8), BitVecVal(2, 8)], 8)

        formula = And(
            PointsTo(Var("x"), Var("arr")),
            And(
                Eq(Var("size"), BitVecVal(10, 8)),
                Eq(Var("size"), size_bv)
            )
        )

        assert checker.is_satisfiable(formula), "Heap with array and bitvector size should work"

    def test_buffer_overflow_with_bitvector_calculation(self):
        """Buffer overflow detection with bitvector size overflow"""
        checker = EntailmentChecker()

        # Scenario: malloc(size) where size overflows
        # x |-> buffer & size = bvmul(200, 200) & size = 64
        # Try to access buffer[100]

        size = BitVecExpr("bvmul", [BitVecVal(200, 8), BitVecVal(200, 8)], 8)

        formula = And(
            PointsTo(Var("x"), Var("buffer")),
            And(
                Eq(Var("size"), size),
                And(
                    Eq(size, BitVecVal(64, 8)),  # Overflow: 40000 mod 256 = 64
                    BufferOverflowCheck(Var("buffer"), Const(100), Const(64))
                )
            )
        )

        # Should be unsatisfiable (overflow detected)
        assert not checker.is_satisfiable(formula), "Buffer overflow should be detected across all theories"

    def test_heap_separation_with_arrays_and_bitvectors(self):
        """Heap separation with both arrays and bitvectors"""
        checker = EntailmentChecker()

        # x |-> arr * y |-> size & arr[0] = 5 & size = bvadd(3, 2)
        arr = ArrayStore(Var("arr_base"), Const(0), Const(5))
        size_bv = BitVecExpr("bvadd", [BitVecVal(3, 8), BitVecVal(2, 8)], 8)

        formula = And(
            SepConj(
                PointsTo(Var("x"), Var("arr")),
                PointsTo(Var("y"), Var("size"))
            ),
            And(
                Eq(ArraySelect(arr, Const(0)), Const(5)),
                And(
                    Eq(Var("size"), size_bv),
                    Eq(size_bv, BitVecVal(5, 8))
                )
            )
        )

        assert checker.is_satisfiable(formula), "Heap separation with arrays and bitvectors should work"


class TestRegressionGuards:
    """Guard against specific regression scenarios"""

    def test_bitvector_comparison_after_heap_operations(self):
        """Ensure bitvector comparisons work after heap operations"""
        checker = EntailmentChecker()

        # x |-> a * y |-> b & bvult(a, b)
        cmp_result = BitVecExpr("bvult", [BitVecVal(5, 8), BitVecVal(10, 8)], 1)

        formula = And(
            SepConj(
                PointsTo(Var("x"), Const(5)),
                PointsTo(Var("y"), Const(10))
            ),
            Eq(cmp_result, BitVecVal(1, 1))  # true
        )

        assert checker.is_satisfiable(formula), "Bitvector comparison after heap ops should work"

    def test_array_operations_with_heap_pointers(self):
        """Ensure array operations work with heap pointers"""
        checker = EntailmentChecker()

        # x |-> arr & arr[5] = 42
        arr = ArrayStore(Var("arr_base"), Const(5), Const(42))

        formula = And(
            PointsTo(Var("x"), Var("arr")),
            Eq(ArraySelect(arr, Const(5)), Const(42))
        )

        assert checker.is_satisfiable(formula), "Array ops with heap pointers should work"

    def test_multiple_heap_cells_with_mixed_types(self):
        """Ensure different value types work in separate heap cells"""
        checker = EntailmentChecker()

        # x |-> str * y |-> bv * z |-> int
        # Keep them separate to avoid mixing in same cell
        formula = And(
            SepConj(
                SepConj(
                    PointsTo(Var("x"), Var("str_val")),
                    PointsTo(Var("y"), Var("bv_val"))
                ),
                PointsTo(Var("z"), Var("int_val"))
            ),
            And(
                Eq(Var("str_val"), StrLiteral("test")),
                And(
                    Eq(Var("bv_val"), BitVecVal(42, 8)),
                    Eq(Var("int_val"), Const(100))
                )
            )
        )

        assert checker.is_satisfiable(formula), "Mixed types in separate heap cells should work"

    def test_integer_overflow_to_buffer_overflow(self):
        """Classic integer overflow leading to buffer overflow"""
        checker = EntailmentChecker()

        # width = 200, height = 200 (8-bit)
        # size = width * height = 40000 -> overflows to 64 (40000 mod 256)
        # malloc(64) then access[100] -> overflow

        width = BitVecVal(200, 8)
        height = BitVecVal(200, 8)
        size = BitVecExpr("bvmul", [width, height], 8)

        # Test 1: Verify overflow occurs
        overflow_formula = Eq(size, BitVecVal(64, 8))
        assert checker.is_satisfiable(overflow_formula), "Overflow should occur: 200*200=40000->64"

        # Test 2: Verify buffer overflow detected
        buffer_formula = BufferOverflowCheck(Var("buffer"), Const(100), Const(64))
        assert not checker.is_satisfiable(buffer_formula), "Buffer overflow should be detected"


class TestSecurityScenarios:
    """Real-world security vulnerability scenarios"""

    def test_heap_buffer_overflow(self):
        """Buffer overflow in heap-allocated buffer"""
        checker = EntailmentChecker()

        # Heap: x |-> buffer
        # Array: buffer has size 10
        # Access: buffer[15] (overflow)

        formula = And(
            PointsTo(Var("x"), Var("buffer")),
            BufferOverflowCheck(Var("buffer"), Const(15), Const(10))
        )

        assert not checker.is_satisfiable(formula), "Heap buffer overflow should be detected"

    def test_integer_overflow_in_size_calculation(self):
        """Integer overflow in malloc size calculation"""
        checker = EntailmentChecker()

        # Typical vulnerability: size = count * element_size
        # where count=256, element_size=256 in 8-bit arithmetic
        # Results in size=0 (overflow), but we try to use it

        count = BitVecVal(256 % 256, 8)  # 0 in 8-bit
        element_size = BitVecVal(256 % 256, 8)  # 0 in 8-bit
        size = BitVecExpr("bvmul", [count, element_size], 8)

        # If size=0, any positive access is an overflow
        formula = And(
            Eq(size, BitVecVal(0, 8)),
            BufferOverflowCheck(Var("buffer"), Const(1), Const(0))
        )

        assert not checker.is_satisfiable(formula), "Zero-size buffer overflow should be detected"

    def test_off_by_one_with_heap_and_bitvector(self):
        """Classic off-by-one error with heap buffer"""
        checker = EntailmentChecker()

        # Buffer size: 10 (computed with bitvectors)
        # Access: buffer[10] (should be buffer[0..9])

        size = BitVecVal(10, 8)

        formula = And(
            PointsTo(Var("x"), Var("buffer")),
            And(
                Eq(Var("size"), size),
                BufferOverflowCheck(Var("buffer"), Const(10), Const(10))
            )
        )

        # Accessing buffer[size] when size=10 is off-by-one
        assert not checker.is_satisfiable(formula), "Off-by-one should be detected"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
