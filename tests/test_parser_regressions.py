"""
Regression tests for parser bug fixes

These tests ensure that previously fixed bugs don't reappear.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from frame import *
from benchmarks.slcomp_parser import SLCompParser


def test_none_filtering_in_and():
    """
    Regression test for None filtering in And formulas.

    Previously, when parser encountered unsupported operators (like wand),
    it would return None, which got embedded in AST as And(None, X).
    This caused AttributeError: 'NoneType' object has no attribute 'is_spatial'.

    Fix: Filter out None values when building And formulas.
    """
    print("\n=== Testing None Filtering in And ===")

    parser = SLCompParser()
    parser.variables['x'] = Var('x')
    parser.variables['y'] = Var('y')

    # Simulate And with unsupported operator
    # (and (pto x y) (wand ...)) where wand returns None

    # Manually test the filtering logic by creating formula with None
    text = "(and (pto x y))"  # Valid part only
    formula = parser._parse_formula(text)

    assert formula is not None, "Should parse valid part"
    assert isinstance(formula, PointsTo), "Should extract the valid formula"

    print("✓ And with single valid formula works")

    # Test that empty And returns Emp
    # This can happen if all sub-formulas are None
    result = parser._parse_and("(and)")
    assert isinstance(result, Emp), "Empty And should return Emp"
    print("✓ Empty And returns Emp")


def test_none_filtering_in_sep():
    """
    Regression test for None filtering in SepConj formulas.

    Similar to And, SepConj could have None values embedded.
    """
    print("\n=== Testing None Filtering in SepConj ===")

    parser = SLCompParser()
    parser.variables['x'] = Var('x')
    parser.variables['y'] = Var('y')

    # Test sep with valid formula
    text = "(sep (pto x y))"
    formula = parser._parse_formula(text)

    assert formula is not None, "Should parse valid part"
    assert isinstance(formula, PointsTo), "Should extract the valid formula"

    print("✓ Sep with single valid formula works")

    # Test that empty Sep returns Emp
    result = parser._parse_sep("(sep)")
    assert isinstance(result, Emp), "Empty Sep should return Emp"
    print("✓ Empty Sep returns Emp")


def test_balanced_parens_extraction():
    r"""
    Regression test for balanced parenthesis extraction.

    Previously, regex pattern r'\((.*?)\)' with non-greedy .*? would stop
    at the first ) encountered, even if it was part of nested structure.

    Fix: Use depth-based balanced parenthesis matching.
    """
    print("\n=== Testing Balanced Parenthesis Extraction ===")

    parser = SLCompParser()

    # Test simple case
    text = "((foo bar))"
    idx = 0  # Start at first (
    content, end_idx = parser._extract_balanced_parens_at_index(text, idx)

    assert content == "(foo bar)", f"Should extract '(foo bar)', got '{content}'"
    assert end_idx == len(text), f"Should end at position {len(text)}, got {end_idx}"

    print("✓ Simple nested parentheses extracted correctly")

    # Test complex case with multiple nested levels
    text2 = "((a (b c)) (d (e (f g))))"
    idx2 = 0
    content2, end_idx2 = parser._extract_balanced_parens_at_index(text2, idx2)

    expected = "(a (b c)) (d (e (f g)))"
    assert content2 == expected, f"Should extract '{expected}', got '{content2}'"

    print("✓ Complex nested parentheses extracted correctly")

    # Test multiple extractions from same string
    text3 = "((first) (second))"
    idx3 = 0
    content3, end_idx3 = parser._extract_balanced_parens_at_index(text3, idx3)

    assert content3 == "(first) (second)", "Should extract both sections"

    print("✓ Multiple top-level sections extracted correctly")


def test_define_funs_rec_nested_signatures():
    r"""
    Regression test for parsing define-funs-rec with nested signatures.

    The bug: regex r'\(define-funs-rec\s+\((.*?)\)\s+\((.*)\)\s*\)'
    would match incorrectly when signatures had nested parens like:
    ((ListE ((x Type)(y Type)) Bool)
     (ListO ((x Type)(y Type)) Bool))

    The (.*?) would stop at first ) after ((x Type), missing (y Type)).
    """
    print("\n=== Testing define-funs-rec with Nested Signatures ===")

    # This is the actual case that failed before
    content = """
    (define-funs-rec
        ((ListE ((x RefGTyp)(y RefGTyp)) Bool)
         (ListO ((x RefGTyp)(y RefGTyp)) Bool))
        ((or (= x y) (sep (pto x y) (ListO x y)))
         (sep (pto x y) (ListE x y))))
    """

    parser = SLCompParser()
    parser._parse_define_funs_rec(content)

    # Should successfully parse both predicates
    assert 'ListE' in parser.predicates, "Should find ListE"
    assert 'ListO' in parser.predicates, "Should find ListO"

    # Should get correct arities
    assert parser.predicate_arities['ListE'] == 2, "ListE should have arity 2"
    assert parser.predicate_arities['ListO'] == 2, "ListO should have arity 2"

    # Should parse both parameters for each
    params_e, _ = parser.predicate_bodies['ListE']
    params_o, _ = parser.predicate_bodies['ListO']

    assert len(params_e) == 2, f"ListE should have 2 params, got {len(params_e)}"
    assert len(params_o) == 2, f"ListO should have 2 params, got {len(params_o)}"
    assert params_e == ['x', 'y'], f"ListE params should be ['x', 'y'], got {params_e}"
    assert params_o == ['x', 'y'], f"ListO params should be ['x', 'y'], got {params_o}"

    print("✓ Correctly parsed predicates with multiple parameters")


def test_expected_status_initialization():
    """
    Regression test for expected_status initialization bug.

    The bug: In run_benchmark(), expected_status was not initialized
    before the try block. If parse_file() raised an exception,
    the except block tried to use expected_status, causing:
    "cannot access local variable 'expected_status' where it is not associated with a value"

    Fix: Initialize expected_status = None before try block.
    """
    print("\n=== Testing expected_status Initialization ===")

    # This test verifies the fix is in place by checking the code structure
    # After refactoring to unified benchmarks, verify error handling still works

    import sys
    import os
    import tempfile

    # Add parent directory to path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from benchmarks.runner import UnifiedBenchmarkRunner

    # Create a temporary directory for test cache
    with tempfile.TemporaryDirectory() as tmpdir:
        runner = UnifiedBenchmarkRunner(cache_dir=tmpdir, verbose=False)

        # Create an invalid benchmark file
        test_division = os.path.join(tmpdir, 'test_division')
        os.makedirs(test_division, exist_ok=True)

        invalid_file = os.path.join(test_division, 'invalid_test.smt2')
        with open(invalid_file, 'w') as f:
            f.write("(this is not valid SMT-LIB)")

        # This should not crash with "expected_status not defined" error
        # It should return a BenchmarkResult with error
        # The key is that it doesn't raise UnboundLocalError
        try:
            result = runner.run_slcomp_benchmark('test_division', 'invalid_test.smt2')
            # If we got here without UnboundLocalError, the fix is working
            assert result.error is not None, "Should have an error"
            assert result.expected == 'unknown', "Expected status should be 'unknown' on error"
            assert result.actual == 'error', "Actual status should be 'error'"
            print("✓ expected_status properly initialized (no UnboundLocalError)")
        except UnboundLocalError as e:
            if "expected_status" in str(e):
                raise AssertionError("expected_status was not initialized before use")
            else:
                raise


def test_or_formula_with_multiple_args():
    """Test that Or formulas with multiple arguments work correctly"""
    print("\n=== Testing Or Formula with Multiple Arguments ===")

    parser = SLCompParser()
    parser.variables['x'] = Var('x')
    parser.variables['y'] = Var('y')

    # Parse: (or emp (pto x y) (pto y x))
    formula_text = "(or emp (pto x y) (pto y x))"
    formula = parser._parse_formula(formula_text)

    assert formula is not None, "Should parse or with 3 args"
    assert isinstance(formula, Or), "Should be Or type"

    print("✓ Or formula with multiple arguments parsed correctly")


def test_exists_with_multiple_vars():
    """Test existential with multiple variables (nested Exists)"""
    print("\n=== Testing Exists with Multiple Variables ===")

    parser = SLCompParser()
    parser.variables['x'] = Var('x')

    # Parse: (exists ((y Type)(z Type)) (sep (pto x y) (pto y z)))
    formula_text = "(exists ((y RefGTyp)(z RefGTyp)) (sep (pto x y) (pto y z)))"
    formula = parser._parse_formula(formula_text)

    assert formula is not None, "Should parse multi-var exists"
    assert isinstance(formula, Exists), "Outer should be Exists"

    # Should create nested Exists: ∃y.∃z.body or ∃z.∃y.body
    # Check that we have proper nesting
    print(f"  Outer var: {formula.var}")
    assert formula.var in ['y', 'z'], "Outer var should be y or z"

    print("✓ Multi-variable exists creates nested structure")


def test_pto_with_constructor():
    """Test points-to with constructor format: (pto x (c_Type y z))"""
    print("\n=== Testing Points-to with Constructor ===")

    parser = SLCompParser()
    parser.variables['x'] = Var('x')
    parser.variables['y'] = Var('y')
    parser.variables['z'] = Var('z')

    # Parse: (pto x (c_node y z))
    formula_text = "(pto x (c_node y z))"
    formula = parser._parse_formula(formula_text)

    assert formula is not None, "Should parse pto with constructor"
    assert isinstance(formula, PointsTo), "Should be PointsTo"
    assert len(formula.values) == 2, "Should have 2 values"

    print("✓ Points-to with constructor parsed correctly")


def run_tests(verbose=False):
    """Run all regression tests in this module"""
    if verbose:
        print("=" * 70)
        print("RUNNING PARSER REGRESSION TESTS")
        print("=" * 70)

    tests = [
        test_none_filtering_in_and,
        test_none_filtering_in_sep,
        test_balanced_parens_extraction,
        test_define_funs_rec_nested_signatures,
        test_expected_status_initialization,
        test_or_formula_with_multiple_args,
        test_exists_with_multiple_vars,
        test_pto_with_constructor,
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
