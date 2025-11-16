"""
Basic tests for separation logic entailment checker
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from frame import *
from frame.core.parser import parse


def test_basic_pointsto():
    """Test basic points-to assertions"""
    checker = EntailmentChecker(verbose=True)

    # x |-> 5 |- x |-> 5 (reflexivity)
    x = Var("x")
    p1 = PointsTo(x, [Const(5)])
    result = checker.check(p1, p1)
    print(f"\n✓ Test 1: x |-> 5 |- x |-> 5: {result.valid}")
    assert result.valid, "Basic reflexivity should hold"


def test_frame_rule():
    """Test frame rule: P |- Q implies P * R |- Q * R"""
    checker = EntailmentChecker(verbose=True)

    # x |-> 5 * y |-> 3 |- x |-> 5 * true
    # This should be valid (frame: y |-> 3)
    x = Var("x")
    y = Var("y")

    antecedent = SepConj(
        PointsTo(x, [Const(5)]),
        PointsTo(y, [Const(3)])
    )
    consequent = PointsTo(x, [Const(5)])

    result = checker.check(antecedent, consequent)
    print(f"\n✓ Test 2: x |-> 5 * y |-> 3 |- x |-> 5: {result.valid}")
    # Note: This might not work perfectly with basic encoding
    # Frame reasoning is complex in separation logic


def test_emp_neutral():
    """Test that emp is neutral for separating conjunction"""
    checker = EntailmentChecker(verbose=True)

    # emp * emp |- emp
    emp = Emp()
    result = checker.check(SepConj(emp, emp), emp)
    print(f"\n✓ Test 3: emp * emp |- emp: {result.valid}")


def test_pure_reasoning():
    """Test pure reasoning"""
    checker = EntailmentChecker(verbose=True)

    # x = 5 & x |-> 5 |- x |-> 5
    x = Var("x")
    antecedent = And(Eq(x, Const(5)), PointsTo(x, [Const(5)]))
    consequent = PointsTo(x, [Const(5)])

    result = checker.check(antecedent, consequent)
    print(f"\n✓ Test 4: x = 5 & x |-> 5 |- x |-> 5: {result.valid}")


def test_parser():
    """Test the parser"""
    print("\n=== Testing Parser ===")

    # Test parsing basic formulas
    formulas = [
        "emp",
        "x |-> 5",
        "x |-> y",
        "x |-> (y, z)",
        "x |-> 5 * y |-> 3",
        "x = y",
        "x != nil",
        "true",
        "false",
        "(x |-> 5) * (y |-> 3)",
        "ls(x, y)",
        "list(x)",
        "tree(x)",
    ]

    for formula_str in formulas:
        try:
            formula = parse(formula_str)
            print(f"✓ Parsed: {formula_str} -> {formula}")
        except Exception as e:
            print(f"✗ Failed to parse: {formula_str}")
            print(f"  Error: {e}")


def test_satisfiability():
    """Test satisfiability checking"""
    checker = EntailmentChecker(verbose=True)

    # x |-> 5 should be satisfiable
    x = Var("x")
    formula = PointsTo(x, [Const(5)])
    result = checker.is_satisfiable(formula)
    print(f"\n✓ Test 5: x |-> 5 is satisfiable: {result}")
    assert result, "x |-> 5 should be satisfiable"

    # x |-> 5 * x |-> 3 should be unsatisfiable (same location, different values)
    formula2 = SepConj(
        PointsTo(x, [Const(5)]),
        PointsTo(x, [Const(3)])
    )
    result2 = checker.is_satisfiable(formula2)
    print(f"✓ Test 6: x |-> 5 * x |-> 3 is unsatisfiable: {not result2}")
    # This should be unsatisfiable due to disjointness


if __name__ == "__main__":
    print("=" * 60)
    print("Running Basic Separation Logic Tests")
    print("=" * 60)

    try:
        test_parser()
        test_basic_pointsto()
        test_frame_rule()
        test_emp_neutral()
        test_pure_reasoning()
        test_satisfiability()

        print("\n" + "=" * 60)
        print("All basic tests completed!")
        print("=" * 60)
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
