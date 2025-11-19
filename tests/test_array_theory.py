"""
Tests for Array Theory (QF_AX) support

Tests array operations, taint tracking, and buffer overflow detection.
"""

import pytest
from frame import EntailmentChecker
from frame.core.ast import (
    Var, Const, ArraySelect, ArrayStore, ArrayConst,
    Eq, And, TaintedArray, BufferOverflowCheck, ArrayBounds
)


class TestArrayBasics:
    """Test basic array operations"""

    def test_array_select_store_axiom(self):
        """Test fundamental array axiom: select(store(arr, i, v), i) = v"""
        checker = EntailmentChecker()

        # Create formula: arr1 = store(arr, 0, 42) & x = select(arr1, 0) => x = 42
        arr = Var("arr")
        arr1 = ArrayStore(arr, Const(0), Const(42))
        x = ArraySelect(arr1, Const(0))

        formula = Eq(x, Const(42))

        # This should be satisfiable
        result = checker.is_satisfiable(formula)
        assert result, "Array store-select axiom should hold"

    def test_array_select_different_index(self):
        """Test: select(store(arr, i, v), j) = select(arr, j) when i != j"""
        checker = EntailmentChecker()

        # arr1 = store(arr, 0, 42)
        # select(arr1, 1) should equal select(arr, 1), not 42
        arr = Var("arr")
        arr1 = ArrayStore(arr, Const(0), Const(42))

        # If arr[1] = 10, then arr1[1] should also = 10
        formula = And(
            Eq(ArraySelect(arr, Const(1)), Const(10)),
            Eq(ArraySelect(arr1, Const(1)), Const(10))
        )

        result = checker.is_satisfiable(formula)
        assert result, "Array extensionality should hold"

    def test_array_constant(self):
        """Test constant array (all elements same value)"""
        checker = EntailmentChecker()

        # arr = const(0) means all elements are 0
        arr = ArrayConst(Const(0))

        # arr[5] = 0 and arr[100] = 0
        formula = And(
            Eq(ArraySelect(arr, Const(5)), Const(0)),
            Eq(ArraySelect(arr, Const(100)), Const(0))
        )

        result = checker.is_satisfiable(formula)
        assert result, "Constant array should have all elements equal"

    def test_array_multiple_stores(self):
        """Test chain of array stores"""
        checker = EntailmentChecker()

        # arr1 = store(arr, 0, 10)
        # arr2 = store(arr1, 1, 20)
        # arr3 = store(arr2, 2, 30)
        arr = Var("arr")
        arr1 = ArrayStore(arr, Const(0), Const(10))
        arr2 = ArrayStore(arr1, Const(1), Const(20))
        arr3 = ArrayStore(arr2, Const(2), Const(30))

        # Check all three values
        formula = And(
            And(
                Eq(ArraySelect(arr3, Const(0)), Const(10)),
                Eq(ArraySelect(arr3, Const(1)), Const(20))
            ),
            Eq(ArraySelect(arr3, Const(2)), Const(30))
        )

        result = checker.is_satisfiable(formula)
        assert result, "Multiple array stores should work"


class TestArrayBounds:
    """Test array bounds checking"""

    def test_in_bounds_access(self):
        """Test safe array access within bounds"""
        checker = EntailmentChecker()

        # bounds(arr, 10) & index = 5 => BufferOverflowCheck(arr, index, 10)
        arr = Var("arr")
        size = Const(10)
        index = Const(5)

        formula = And(
            ArrayBounds(arr, size),
            BufferOverflowCheck(arr, index, size)
        )

        result = checker.is_satisfiable(formula)
        assert result, "In-bounds access should be safe"

    def test_out_of_bounds_access(self):
        """Test buffer overflow detection"""
        checker = EntailmentChecker()

        # bounds(arr, 10) & index = 15 => NOT BufferOverflowCheck(arr, index, 10)
        arr = Var("arr")
        size = Const(10)
        index = Const(15)

        # This should detect overflow (index >= size)
        safe_access = BufferOverflowCheck(arr, index, size)

        result = checker.is_satisfiable(safe_access)
        assert not result, "Out-of-bounds access should be detected"

    def test_negative_index(self):
        """Test negative array index detection"""
        checker = EntailmentChecker()

        arr = Var("arr")
        size = Const(10)
        index = Const(-1)

        safe_access = BufferOverflowCheck(arr, index, size)

        result = checker.is_satisfiable(safe_access)
        assert not result, "Negative index should be detected"

    def test_boundary_cases(self):
        """Test boundary index values"""
        checker = EntailmentChecker()

        arr = Var("arr")
        size = Const(10)

        # index = 0 should be safe
        formula1 = BufferOverflowCheck(arr, Const(0), size)
        assert checker.is_satisfiable(formula1), "Index 0 should be safe"

        # index = 9 should be safe (last valid index)
        formula2 = BufferOverflowCheck(arr, Const(9), size)
        assert checker.is_satisfiable(formula2), "Index 9 should be safe for size 10"

        # index = 10 should fail (equal to size)
        formula3 = BufferOverflowCheck(arr, Const(10), size)
        assert not checker.is_satisfiable(formula3), "Index 10 should overflow for size 10"


class TestArrayTaint:
    """Test taint tracking through arrays"""

    def test_tainted_array_basic(self):
        """Test basic array taint tracking"""
        checker = EntailmentChecker()

        # TaintedArray(arr, [0, 2]) means arr[0] and arr[2] are tainted
        arr = Var("arr")
        tainted = TaintedArray(arr, [Const(0), Const(2)])

        result = checker.is_satisfiable(tainted)
        assert result, "Tainted array should be satisfiable"

    def test_tainted_array_propagation(self):
        """Test taint propagation through array operations"""
        checker = EntailmentChecker()

        # If arr[0] is tainted and we store arr[0] into arr[1],
        # then arr[1] should also be tainted
        arr = Var("arr")
        tainted_val = ArraySelect(arr, Const(0))
        arr2 = ArrayStore(arr, Const(1), tainted_val)

        formula = And(
            TaintedArray(arr, [Const(0)]),
            # arr2[1] = arr[0], so arr2[1] is tainted
            Eq(ArraySelect(arr2, Const(1)), ArraySelect(arr, Const(0)))
        )

        result = checker.is_satisfiable(formula)
        assert result, "Taint should propagate through array operations"

    def test_array_taint_with_bounds_check(self):
        """Test combining taint tracking with bounds checking"""
        checker = EntailmentChecker()

        # Tainted input used as array index - potential vulnerability
        arr = Var("arr")
        user_index = Var("user_index")  # Tainted input
        size = Const(100)

        # Safe if: user_index is sanitized OR in bounds check passes
        # Vulnerable if: user_index is tainted AND out of bounds
        formula = And(
            And(
                TaintedArray(Var("inputs"), [Const(0)]),  # inputs[0] is tainted
                Eq(user_index, ArraySelect(Var("inputs"), Const(0)))  # user_index = inputs[0]
            ),
            BufferOverflowCheck(arr, user_index, size)  # Check if in bounds
        )

        # This tests if a tainted index can still be used safely with bounds checking
        result = checker.is_satisfiable(formula)
        # Should be satisfiable if user_index < 100
        assert result, "Tainted index with bounds check should be safe"


class TestArrayEquality:
    """Test array equality and extensionality"""

    def test_array_equality(self):
        """Test that arrays with same contents are equal"""
        checker = EntailmentChecker()

        # arr1[0] = 1, arr1[1] = 2
        # arr2[0] = 1, arr2[1] = 2
        # If these are the only indices that matter, arr1 = arr2
        arr1 = ArrayStore(ArrayStore(ArrayConst(Const(0)), Const(0), Const(1)), Const(1), Const(2))
        arr2 = ArrayStore(ArrayStore(ArrayConst(Const(0)), Const(0), Const(1)), Const(1), Const(2))

        formula = Eq(arr1, arr2)

        result = checker.is_satisfiable(formula)
        assert result, "Arrays with same contents should be equal"

    def test_array_inequality(self):
        """Test that arrays with different contents are not equal"""
        checker = EntailmentChecker()

        # arr1[0] = 1
        # arr2[0] = 2
        # arr1 != arr2
        base = ArrayConst(Const(0))
        arr1 = ArrayStore(base, Const(0), Const(1))
        arr2 = ArrayStore(base, Const(0), Const(2))

        formula = Eq(arr1, arr2)

        result = checker.is_satisfiable(formula)
        assert not result, "Arrays with different contents should not be equal"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
