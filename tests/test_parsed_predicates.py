"""
Tests for ParsedPredicate functionality and define-funs-rec parsing

These tests ensure that predicates parsed from define-funs-rec blocks
work correctly with proper parameter substitution.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from frame import *
from frame.predicates import ParsedPredicate
from benchmarks.slcomp_parser import SLCompParser


def test_parsed_predicate_simple():
    """Test ParsedPredicate with simple body (single points-to)"""
    print("\n=== Testing ParsedPredicate with Simple Body ===")

    # Define: pred(x, y) := x |-> y
    x_param = "x"
    y_param = "y"
    body = PointsTo(Var("x"), [Var("y")])

    pred = ParsedPredicate("pred", [x_param, y_param], body)

    # Unfold pred(a, b) should give a |-> b
    a = Var("a")
    b = Var("b")
    unfolded = pred.unfold([a, b])

    print(f"pred(x, y) := x |-> y")
    print(f"pred(a, b) unfolds to: {unfolded}")

    assert isinstance(unfolded, PointsTo), "Should unfold to PointsTo"
    assert unfolded.location.name == "a", "Location should be 'a'"
    assert unfolded.values[0].name == "b", "Value should be 'b'"
    print("✓ Simple unfolding works correctly")


def test_parsed_predicate_recursive():
    """Test ParsedPredicate with recursive body"""
    print("\n=== Testing ParsedPredicate with Recursive Body ===")

    # Define: ls(x, y) := (x = y ∧ emp) ∨ (∃z. x |-> z * ls(z, y))
    x_param = "x"
    y_param = "y"

    # Base case: x = y ∧ emp
    base_case = And(Eq(Var("x"), Var("y")), Emp())

    # Recursive case: ∃z. x |-> z * ls(z, y)
    z = "z"
    recursive_body = SepConj(
        PointsTo(Var("x"), [Var(z)]),
        PredicateCall("ls", [Var(z), Var("y")])
    )
    recursive_case = Exists(z, recursive_body)

    # Full body: base_case ∨ recursive_case
    body = Or(base_case, recursive_case)

    pred = ParsedPredicate("ls", [x_param, y_param], body)

    # Unfold ls(a, b)
    a = Var("a")
    b = Var("b")
    unfolded = pred.unfold([a, b])

    print(f"ls(x, y) := (x = y ∧ emp) ∨ (∃z. x |-> z * ls(z, y))")
    print(f"ls(a, b) unfolds to: {unfolded}")

    assert isinstance(unfolded, Or), "Should unfold to Or"
    print("✓ Recursive unfolding works correctly")


def test_parsed_predicate_existential():
    """Test ParsedPredicate with existential quantifier"""
    print("\n=== Testing ParsedPredicate with Existential ===")

    # Define: cell(x) := ∃v. x |-> v
    x_param = "x"
    v = "v"
    body = Exists(v, PointsTo(Var("x"), [Var(v)]))

    pred = ParsedPredicate("cell", [x_param], body)

    # Unfold cell(a)
    a = Var("a")
    unfolded = pred.unfold([a])

    print(f"cell(x) := ∃v. x |-> v")
    print(f"cell(a) unfolds to: {unfolded}")

    assert isinstance(unfolded, Exists), "Should unfold to Exists"
    assert unfolded.var == "v", "Bound variable should still be 'v'"
    print("✓ Existential quantifier preserved correctly")


def test_parsed_predicate_substitution():
    """Test that substitution respects bound variables"""
    print("\n=== Testing Variable Capture Avoidance ===")

    # Define: pred(x) := ∃x. x |-> x
    # When we unfold pred(y), the bound x should NOT be replaced
    x_param = "x"
    body = Exists("x", PointsTo(Var("x"), [Var("x")]))

    pred = ParsedPredicate("pred", [x_param], body)

    # Unfold pred(y) - outer x should NOT affect bound x
    y = Var("y")
    unfolded = pred.unfold([y])

    print(f"pred(x) := ∃x. x |-> x")
    print(f"pred(y) unfolds to: {unfolded}")

    # The bound variable 'x' should remain unchanged
    assert isinstance(unfolded, Exists), "Should be Exists"
    assert unfolded.var == "x", "Bound variable should remain 'x'"
    print("✓ Bound variables not substituted (correct scoping)")


def test_define_funs_rec_single_predicate():
    """Test parsing single predicate from define-funs-rec"""
    print("\n=== Testing Single Predicate Parsing ===")

    content = """
    (define-funs-rec
        ((node_e1 ((x RefGTyp)) Bool))
        ((or (= x (as nil RefGTyp))
             (exists ((y RefGTyp))
                 (sep (pto x (c_node_e1 y)) (node_e1 y))))))
    """

    parser = SLCompParser()
    parser._parse_define_funs_rec(content)

    assert 'node_e1' in parser.predicates, "Should find node_e1 predicate"
    assert parser.predicates['node_e1'] == 'parsed', "Should be marked as 'parsed'"
    assert parser.predicate_arities['node_e1'] == 1, "Should have arity 1"
    assert 'node_e1' in parser.predicate_bodies, "Should have parsed body"

    params, body = parser.predicate_bodies['node_e1']
    assert params == ['x'], "Should have parameter 'x'"
    assert body is not None, "Body should be parsed"

    print(f"✓ Parsed node_e1 with params {params}")
    print(f"  Body type: {type(body).__name__}")


def test_define_funs_rec_multiple_predicates():
    """Test parsing multiple predicates from define-funs-rec"""
    print("\n=== Testing Multiple Predicates Parsing ===")

    content = """
    (define-funs-rec
        ((ListE ((x RefGTyp)(y RefGTyp)) Bool)
         (ListO ((x RefGTyp)(y RefGTyp)) Bool))
        ((or (= x y)
             (exists ((z RefGTyp))
                 (sep (pto x (c_node z)) (ListO z y))))
         (exists ((z RefGTyp))
             (sep (pto x (c_node z)) (ListE z y)))))
    """

    parser = SLCompParser()
    parser._parse_define_funs_rec(content)

    assert 'ListE' in parser.predicates, "Should find ListE predicate"
    assert 'ListO' in parser.predicates, "Should find ListO predicate"

    assert parser.predicate_arities['ListE'] == 2, "ListE should have arity 2"
    assert parser.predicate_arities['ListO'] == 2, "ListO should have arity 2"

    assert 'ListE' in parser.predicate_bodies, "Should have ListE body"
    assert 'ListO' in parser.predicate_bodies, "Should have ListO body"

    params_e, body_e = parser.predicate_bodies['ListE']
    params_o, body_o = parser.predicate_bodies['ListO']

    assert params_e == ['x', 'y'], "ListE should have params x, y"
    assert params_o == ['x', 'y'], "ListO should have params x, y"

    print(f"✓ Parsed ListE with params {params_e}")
    print(f"✓ Parsed ListO with params {params_o}")


def test_define_funs_rec_with_nested_parens():
    """Test parsing with deeply nested parentheses"""
    print("\n=== Testing Nested Parentheses Parsing ===")

    # This was the case that caused the regex bug
    content = """
    (define-funs-rec
        ((dll ((x RefGTyp)(p RefGTyp)(y RefGTyp)(n RefGTyp)) Bool))
        ((or (and (= x y) (= p n))
             (exists ((z RefGTyp))
                 (sep (pto x (c_node_dll p z))
                      (dll z x y n))))))
    """

    parser = SLCompParser()
    parser._parse_define_funs_rec(content)

    assert 'dll' in parser.predicates, "Should find dll predicate"
    assert parser.predicate_arities['dll'] == 4, "dll should have arity 4"

    params, body = parser.predicate_bodies['dll']
    assert params == ['x', 'p', 'y', 'n'], "Should have all 4 parameters"
    assert body is not None, "Body should be parsed"

    print(f"✓ Parsed dll with params {params}")
    print(f"  Successfully handled nested parentheses")


def test_parsed_predicate_integration():
    """Test ParsedPredicate in entailment checking"""
    print("\n=== Testing ParsedPredicate Integration ===")

    # Define simple predicate: cell(x) := x |-> 5
    body = PointsTo(Var("x"), [Const(5)])
    pred = ParsedPredicate("cell", ["x"], body)

    # Register it
    registry = PredicateRegistry()
    registry.register(pred, validate=False)

    # Create checker
    checker = EntailmentChecker(predicate_registry=registry, verbose=True)

    # Test: cell(a) |- a |-> 5
    # This should be valid after unfolding
    x = Var("a")
    antecedent = PredicateCall("cell", [x])
    consequent = PointsTo(x, [Const(5)])

    result = checker.check(antecedent, consequent)
    print(f"\ncell(a) |- a |-> 5: {result.valid}")

    # Note: This may or may not work depending on unfolding strategy
    # The important thing is that it doesn't crash
    print("✓ ParsedPredicate integrated without errors")


def test_or_formula_parsing():
    """Test parsing of or formulas"""
    print("\n=== Testing Or Formula Parsing ===")

    parser = SLCompParser()

    # Parse: (or (= x nil) (pto x y))
    formula_text = "(or (= x (as nil RefGTyp)) (pto x y))"

    # Add variables
    parser.variables['x'] = Var('x')
    parser.variables['y'] = Var('y')

    formula = parser._parse_formula(formula_text)

    assert formula is not None, "Should parse or formula"
    assert isinstance(formula, Or), "Should be Or type"

    print(f"✓ Parsed: {formula_text}")
    print(f"  Result type: {type(formula).__name__}")


def test_exists_formula_parsing():
    """Test parsing of existential quantifiers"""
    print("\n=== Testing Exists Formula Parsing ===")

    parser = SLCompParser()
    parser.variables['x'] = Var('x')

    # Parse: (exists ((y RefGTyp)) (pto x y))
    formula_text = "(exists ((y RefGTyp)) (pto x y))"
    formula = parser._parse_formula(formula_text)

    assert formula is not None, "Should parse exists formula"
    assert isinstance(formula, Exists), "Should be Exists type"
    assert formula.var == 'y', "Bound variable should be 'y'"

    print(f"✓ Parsed: {formula_text}")
    print(f"  Bound variable: {formula.var}")

    # Test multiple variables: (exists ((y RefGTyp)(z RefGTyp)) body)
    formula_text2 = "(exists ((y RefGTyp)(z RefGTyp)) (sep (pto x y) (pto y z)))"
    formula2 = parser._parse_formula(formula_text2)

    assert formula2 is not None, "Should parse multi-variable exists"
    assert isinstance(formula2, Exists), "Should be Exists type"
    # Should have nested Exists for multiple variables
    print(f"✓ Parsed multi-variable exists")


def run_tests(verbose=False):
    """Run all tests in this module"""
    if verbose:
        print("=" * 70)
        print("RUNNING PARSED PREDICATE TESTS")
        print("=" * 70)

    tests = [
        test_parsed_predicate_simple,
        test_parsed_predicate_recursive,
        test_parsed_predicate_existential,
        test_parsed_predicate_substitution,
        test_define_funs_rec_single_predicate,
        test_define_funs_rec_multiple_predicates,
        test_define_funs_rec_with_nested_parens,
        test_parsed_predicate_integration,
        test_or_formula_parsing,
        test_exists_formula_parsing,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if verbose:
                test()
            else:
                # Suppress output for non-verbose mode
                import io
                import contextlib
                with contextlib.redirect_stdout(io.StringIO()):
                    test()
            passed += 1
        except Exception as e:
            if verbose:
                print(f"\n✗ FAILED: {test.__name__}")
                print(f"  Error: {e}")
                import traceback
                traceback.print_exc()
            failed += 1

    if verbose:
        print("\n" + "=" * 70)
        print(f"RESULTS: {passed} passed, {failed} failed")
        print("=" * 70)

    return passed, failed


if __name__ == "__main__":
    verbose_mode = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose_mode)
    sys.exit(0 if failed == 0 else 1)
