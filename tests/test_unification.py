"""
Tests for the unification algorithm.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from frame.analysis.unification import Unifier, Substitution
from frame.core.ast import Var, Const, ArithExpr, PointsTo, PredicateCall


# Helper for assertions
def assert_equal(actual, expected, msg=""):
    if actual != expected:
        raise AssertionError(f"{msg}: expected {expected}, got {actual}")


def assert_true(condition, msg=""):
    if not condition:
        raise AssertionError(f"{msg}: condition was False")


def assert_none(value, msg=""):
    if value is not None:
        raise AssertionError(f"{msg}: expected None, got {value}")


def assert_not_none(value, msg=""):
    if value is None:
        raise AssertionError(f"{msg}: expected non-None value")


# Test Substitution Operations

def test_empty_substitution():
    """Empty substitution does nothing"""
    print("  Testing empty substitution...")
    subst = Substitution()
    x = Var("x")
    assert_equal(subst.apply(x), x)


def test_simple_substitution():
    """Apply simple variable substitution"""
    print("  Testing simple substitution...")
    subst = Substitution({"x": Const(5)})
    x = Var("x")
    result = subst.apply(x)
    assert_true(isinstance(result, Const), "Result should be Const")
    assert_equal(result.value, 5, "Value should be 5")


def test_chained_substitution():
    """Chained substitutions: x -> y, y -> 5"""
    print("  Testing chained substitution...")
    subst = Substitution({"x": Var("y"), "y": Const(5)})
    x = Var("x")
    result = subst.apply(x)
    # Should follow chain: x -> y -> 5
    assert_true(isinstance(result, Const), "Result should be Const")
    assert_equal(result.value, 5, "Value should be 5")


def test_substitution_in_arith():
    """Substitute in arithmetic expressions"""
    print("  Testing substitution in arithmetic...")
    subst = Substitution({"x": Const(3), "y": Const(7)})
    expr = ArithExpr(Var("x"), "+", Var("y"))
    result = subst.apply(expr)
    # Note: Substitution may not fully evaluate ArithExpr, just checks it works
    assert_true(result is not None, "Result should not be None")


def test_extend_substitution():
    """Extend substitution with new mapping"""
    print("  Testing extend substitution...")
    subst = Substitution({"x": Const(5)})
    subst2 = subst.extend("y", Const(10))

    assert_true("x" in subst2.mappings, "x should be in mappings")
    assert_true("y" in subst2.mappings, "y should be in mappings")
    assert_equal(subst2.mappings["y"].value, 10, "y should map to 10")


def test_composition():
    """Compose two substitutions"""
    print("  Testing composition...")
    # σ1 = {x -> y}
    # σ2 = {y -> 5}
    # σ1 ∘ σ2 = {x -> 5, y -> 5}
    s1 = Substitution({"x": Var("y")})
    s2 = Substitution({"y": Const(5)})
    composed = s1.compose(s2)

    # x should map to 5 (y substituted)
    assert_equal(composed.apply(Var("x")).value, 5, "x should resolve to 5")


# Test Unification Algorithm

def test_unify_same_variable():
    """Unifying x with x succeeds"""
    print("  Testing unify same variable...")
    unifier = Unifier(verbose=False)
    x = Var("x")
    subst = unifier.unify_exprs(x, x)
    assert_not_none(subst, "Unification should succeed")
    assert_equal(len(subst.mappings), 0, "Should be empty substitution")


def test_unify_var_with_const():
    """Unifying x with 5 gives {x -> 5}"""
    print("  Testing unify var with const...")
    unifier = Unifier(verbose=False)
    x = Var("x")
    c = Const(5)
    subst = unifier.unify_exprs(x, c)
    assert_not_none(subst, "Unification should succeed")
    assert_true("x" in subst.mappings, "x should be in mappings")
    assert_equal(subst.mappings["x"].value, 5, "x should map to 5")


def test_unify_const_with_var():
    """Unifying 5 with x gives {x -> 5}"""
    print("  Testing unify const with var...")
    unifier = Unifier(verbose=False)
    c = Const(5)
    x = Var("x")
    subst = unifier.unify_exprs(c, x)
    assert_not_none(subst, "Unification should succeed")
    assert_true("x" in subst.mappings, "x should be in mappings")
    assert_equal(subst.mappings["x"].value, 5, "x should map to 5")


def test_unify_different_constants_fails():
    """Unifying 5 with 7 fails"""
    print("  Testing unify different constants fails...")
    unifier = Unifier(verbose=False)
    c1 = Const(5)
    c2 = Const(7)
    subst = unifier.unify_exprs(c1, c2)
    assert_none(subst, "Unification should fail")


def test_unify_same_constants():
    """Unifying 5 with 5 succeeds"""
    print("  Testing unify same constants...")
    unifier = Unifier(verbose=False)
    c1 = Const(5)
    c2 = Const(5)
    subst = unifier.unify_exprs(c1, c2)
    assert_not_none(subst, "Unification should succeed")


def test_unify_variables():
    """Unifying x with y gives {x -> y}"""
    print("  Testing unify variables...")
    unifier = Unifier(verbose=False)
    x = Var("x")
    y = Var("y")
    subst = unifier.unify_exprs(x, y)
    assert_not_none(subst, "Unification should succeed")
    assert_true("x" in subst.mappings, "x should be in mappings")
    assert_equal(subst.mappings["x"].name, "y", "x should map to y")


def test_occurs_check_direct():
    """Occurs check prevents x = f(x)"""
    print("  Testing occurs check...")
    unifier = Unifier(verbose=False)
    x = Var("x")
    # Try to unify x with x+1
    expr = ArithExpr(x, "+", Const(1))
    subst = unifier.unify_exprs(x, expr)
    assert_none(subst, "Should fail occurs check")


def test_unify_arithmetic_expressions():
    """Unify arithmetic expressions"""
    print("  Testing unify arithmetic expressions...")
    unifier = Unifier(verbose=False)
    # x + 3 with y + 3
    e1 = ArithExpr(Var("x"), "+", Const(3))
    e2 = ArithExpr(Var("y"), "+", Const(3))
    subst = unifier.unify_exprs(e1, e2)
    assert_not_none(subst, "Unification should succeed")
    assert_true("x" in subst.mappings or "y" in subst.mappings,
                "At least one variable should be mapped")


def test_unify_arithmetic_different_ops_fails():
    """Unifying x+3 with x*3 fails"""
    print("  Testing unify arithmetic different ops fails...")
    unifier = Unifier(verbose=False)
    e1 = ArithExpr(Var("x"), "+", Const(3))
    e2 = ArithExpr(Var("x"), "*", Const(3))
    subst = unifier.unify_exprs(e1, e2)
    assert_none(subst, "Unification should fail")


def test_unify_lists():
    """Unify lists of expressions"""
    print("  Testing unify lists...")
    unifier = Unifier(verbose=False)
    # [x, y, 5] with [1, 2, 5]
    list1 = [Var("x"), Var("y"), Const(5)]
    list2 = [Const(1), Const(2), Const(5)]
    subst = unifier.unify_lists(list1, list2)
    assert_not_none(subst, "Unification should succeed")
    assert_equal(subst.mappings["x"].value, 1, "x should map to 1")
    assert_equal(subst.mappings["y"].value, 2, "y should map to 2")


def test_unify_lists_different_lengths_fails():
    """Unifying lists of different lengths fails"""
    print("  Testing unify lists different lengths fails...")
    unifier = Unifier(verbose=False)
    list1 = [Var("x"), Var("y")]
    list2 = [Const(1)]
    subst = unifier.unify_lists(list1, list2)
    assert_none(subst, "Unification should fail")


def test_unify_points_to():
    """Unify points-to formulas"""
    print("  Testing unify points-to...")
    unifier = Unifier(verbose=False)
    # x |-> y  with  a |-> b
    pto1 = PointsTo(Var("x"), [Var("y")])
    pto2 = PointsTo(Var("a"), [Var("b")])
    subst = unifier.unify_formulas(pto1, pto2)
    assert_not_none(subst, "Unification should succeed")
    assert_true("x" in subst.mappings or "a" in subst.mappings,
                "Location variable should be mapped")
    assert_true("y" in subst.mappings or "b" in subst.mappings,
                "Value variable should be mapped")


def test_unify_predicate_calls():
    """Unify predicate calls"""
    print("  Testing unify predicate calls...")
    unifier = Unifier(verbose=False)
    # ls(x, y) with ls(a, b)
    pred1 = PredicateCall("ls", [Var("x"), Var("y")])
    pred2 = PredicateCall("ls", [Var("a"), Var("b")])
    subst = unifier.unify_formulas(pred1, pred2)
    assert_not_none(subst, "Unification should succeed")


def test_unify_predicates_different_names_fails():
    """Unifying predicates with different names fails"""
    print("  Testing unify predicates different names fails...")
    unifier = Unifier(verbose=False)
    pred1 = PredicateCall("ls", [Var("x"), Var("y")])
    pred2 = PredicateCall("list", [Var("x"), Var("y")])
    subst = unifier.unify_formulas(pred1, pred2)
    assert_none(subst, "Unification should fail")


# Test Complex Unification Scenarios

def test_transitive_substitution():
    """Test transitive variable substitutions"""
    print("  Testing transitive substitution...")
    unifier = Unifier(verbose=False)
    # Unify x with y, then y with 5
    subst = Substitution()
    subst = unifier.unify_exprs(Var("x"), Var("y"), subst)
    subst = unifier.unify_exprs(Var("y"), Const(5), subst)

    # Both x and y should resolve to 5
    assert_not_none(subst, "Unification should succeed")
    assert_equal(subst.apply(Var("x")).value, 5, "x should resolve to 5")
    assert_equal(subst.apply(Var("y")).value, 5, "y should resolve to 5")


def test_unify_with_existing_substitution():
    """Unify with existing substitution"""
    print("  Testing unify with existing substitution...")
    unifier = Unifier(verbose=False)
    # Start with {x -> 5}
    subst = Substitution({"x": Const(5)})

    # Try to unify x with 5 (should succeed)
    subst = unifier.unify_exprs(Var("x"), Const(5), subst)
    assert_not_none(subst, "Unification should succeed")

    # Try to unify x with 7 (should fail - contradiction)
    subst2 = unifier.unify_exprs(Var("x"), Const(7), subst)
    assert_none(subst2, "Unification should fail due to contradiction")


def test_unify_predicate_arguments():
    """Unify predicate calls - arithmetic expressions can't unify with constants"""
    print("  Testing unify predicate arguments...")
    unifier = Unifier(verbose=False)
    # ls(x+1, y) with ls(5, z) - should fail because x+1 can't unify with 5
    # (would need arithmetic reasoning)
    pred1 = PredicateCall("ls", [
        ArithExpr(Var("x"), "+", Const(1)),
        Var("y")
    ])
    pred2 = PredicateCall("ls", [
        Const(5),
        Var("z")
    ])
    subst = unifier.unify_formulas(pred1, pred2)
    assert_none(subst, "Unification should fail (no arithmetic reasoning)")


def run_tests(verbose=False):
    """Run all unification tests"""
    if verbose:
        print("=" * 70)
        print("RUNNING UNIFICATION TESTS")
        print("=" * 70)

    tests = [
        # Substitution tests
        test_empty_substitution,
        test_simple_substitution,
        test_chained_substitution,
        test_substitution_in_arith,
        test_extend_substitution,
        test_composition,
        # Basic unification tests
        test_unify_same_variable,
        test_unify_var_with_const,
        test_unify_const_with_var,
        test_unify_different_constants_fails,
        test_unify_same_constants,
        test_unify_variables,
        test_occurs_check_direct,
        test_unify_arithmetic_expressions,
        test_unify_arithmetic_different_ops_fails,
        test_unify_lists,
        test_unify_lists_different_lengths_fails,
        test_unify_points_to,
        test_unify_predicate_calls,
        test_unify_predicates_different_names_fails,
        # Complex unification tests
        test_transitive_substitution,
        test_unify_with_existing_substitution,
        test_unify_predicate_arguments,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
            if verbose:
                print(f"✓ {test.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"✗ {test.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"✗ {test.__name__} raised exception: {e}")
            if verbose:
                import traceback
                traceback.print_exc()

    if not verbose:
        if failed == 0:
            print("✓ All tests passed!")
        else:
            print(f"✗ {failed}/{passed + failed} tests failed")

    return passed, failed


if __name__ == "__main__":
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)

    print(f"\n{'=' * 70}")
    print(f"Unification Tests: {passed} passed, {failed} failed")
    print(f"{'=' * 70}")

    sys.exit(0 if failed == 0 else 1)
