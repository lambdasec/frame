"""
Tests for Magic Wand (-*) support

These tests ensure that the magic wand operator is properly:
1. Parsed from SMT-LIB format
2. Represented in the AST
3. Encoded to Z3
4. Used in lemmas
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from frame import *
from benchmarks.slcomp_parser import SLCompParser


def test_wand_ast():
    """Test that Wand is properly represented in AST"""
    print("\n=== Testing Wand AST ==")

    # Create: x |-> y -* ls(z, w)
    x = Var("x")
    y = Var("y")
    z = Var("z")
    w = Var("w")

    left = PointsTo(x, [y])
    right = PredicateCall("ls", [z, w])
    wand = Wand(left, right)

    print(f"Wand formula: {wand}")
    assert str(wand) == "(x |-> y -* ls(z, w))", f"Unexpected string: {str(wand)}"

    # Check that it's spatial
    assert wand.is_spatial(), "Wand should be spatial"

    # Check free variables
    free_vars = wand.free_vars()
    assert free_vars == {'x', 'y', 'z', 'w'}, f"Unexpected free vars: {free_vars}"

    print("✓ Wand AST works correctly")


def test_wand_parsing():
    """Test that wand can be parsed from SMT-LIB format"""
    print("\n=== Testing Wand Parsing ===")

    parser = SLCompParser()

    # Add variables
    parser.variables['x'] = Var('x')
    parser.variables['y'] = Var('y')
    parser.variables['z'] = Var('z')

    # Test parsing: (wand (pto x y) (ls y z))
    formula_text = "(wand (pto x y) (ls y z))"

    # Need to register ls predicate
    parser.predicates['ls'] = 'builtin'
    parser.predicate_arities['ls'] = 2

    formula = parser._parse_formula(formula_text)

    print(f"Parsed formula: {formula}")
    assert formula is not None, "Failed to parse wand"
    assert isinstance(formula, Wand), f"Expected Wand, got {type(formula)}"
    assert isinstance(formula.left, PointsTo), "Left should be PointsTo"
    assert isinstance(formula.right, PredicateCall), "Right should be PredicateCall"

    print("✓ Wand parsing works correctly")


def test_wand_in_sepconj():
    """Test wand in separating conjunction: (P -* Q) * P"""
    print("\n=== Testing Wand in SepConj ===")

    x = Var("x")
    y = Var("y")
    z = Var("z")

    # (x |-> y -* ls(x, z)) * x |-> y
    left_wand = Wand(PointsTo(x, [y]), PredicateCall("ls", [x, z]))
    right_pts = PointsTo(x, [y])

    formula = SepConj(left_wand, right_pts)

    print(f"Formula: {formula}")
    assert formula.is_spatial(), "Should be spatial"

    print("✓ Wand in SepConj works correctly")


def test_wand_lemma():
    """Test that wand lemma is in the library"""
    print("\n=== Testing Wand Lemma ===")

    from frame.lemmas.base import LemmaLibrary

    library = LemmaLibrary()

    # Check that wand modus ponens lemma exists
    wand_lemmas = [l for l in library.lemmas if 'wand' in l.name.lower()]

    print(f"Found {len(wand_lemmas)} wand lemmas:")
    for lemma in wand_lemmas:
        print(f"  - {lemma.name}: {lemma.description}")

    assert len(wand_lemmas) > 0, "Should have at least one wand lemma"

    # Check that at least one is modus ponens
    modus_ponens = [l for l in wand_lemmas if 'modus_ponens' in l.name]
    assert len(modus_ponens) > 0, "Should have modus ponens lemma"

    print("✓ Wand lemmas exist in library")


def test_wand_pattern_matching():
    """Test pattern matching with wand"""
    print("\n=== Testing Wand Pattern Matching ===")

    from frame.lemmas.base import LemmaLibrary

    library = LemmaLibrary()

    # Create a pattern: (ls(X, Y) -* ls(Z, W)) * ls(X, Y)
    x = Var("X")
    y = Var("Y")
    z = Var("Z")
    w = Var("W")

    pattern_wand = Wand(PredicateCall("ls", [x, y]), PredicateCall("ls", [z, w]))
    pattern = SepConj(pattern_wand, PredicateCall("ls", [x, y]))

    # Create a concrete formula: (ls(a, b) -* ls(c, d)) * ls(a, b)
    a = Var("a")
    b = Var("b")
    c = Var("c")
    d = Var("d")

    concrete_wand = Wand(PredicateCall("ls", [a, b]), PredicateCall("ls", [c, d]))
    concrete = SepConj(concrete_wand, PredicateCall("ls", [a, b]))

    # Try to match
    bindings = library.match_formula(pattern, concrete)

    print(f"Pattern: {pattern}")
    print(f"Concrete: {concrete}")
    print(f"Bindings: {bindings}")

    assert bindings is not None, "Should match"
    assert 'X' in bindings, "Should bind X"
    assert 'Y' in bindings, "Should bind Y"
    assert 'Z' in bindings, "Should bind Z"
    assert 'W' in bindings, "Should bind W"

    print("✓ Wand pattern matching works")


def test_wand_z3_encoding():
    """Test that wand can be encoded to Z3 (even if conservatively)"""
    print("\n=== Testing Wand Z3 Encoding ===")

    from frame.encoding.encoder import Z3Encoder

    encoder = Z3Encoder()

    x = Var("x")
    y = Var("y")
    z = Var("z")

    # Create wand formula: x |-> y -* ls(z, nil)
    wand = Wand(PointsTo(x, [y]), PredicateCall("ls", [z, Const(None)]))

    # Try to encode using the correct API (encode_formula, not encode_heap_assertion directly)
    try:
        import z3
        # Use encode_formula which properly creates heap_id
        constraints, heap_id, domain = encoder.encode_formula(wand)

        print(f"Encoded wand to Z3 (conservative encoding)")
        print(f"Constraints type: {type(constraints)}")
        print(f"Heap ID: {heap_id}")
        print(f"Domain: {domain}")

        assert constraints is not None, "Should produce some constraint"
        assert heap_id is not None, "Should produce heap ID"
        print("✓ Wand Z3 encoding works (conservative)")
    except Exception as e:
        print(f"✗ Failed to encode wand: {e}")
        raise


def run_tests(verbose=False):
    """Run all tests in this module"""
    if verbose:
        print("=" * 70)
        print("RUNNING MAGIC WAND TESTS")
        print("=" * 70)

    tests = [
        test_wand_ast,
        test_wand_parsing,
        test_wand_in_sepconj,
        test_wand_lemma,
        test_wand_pattern_matching,
        test_wand_z3_encoding,
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
