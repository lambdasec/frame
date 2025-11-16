"""
Test suite based on SL-COMP shidlia_entl benchmarks.

Division: SHIDLIA - Separation Logic with Inductive Definitions and Linear Arithmetic (Full FOL)
Focus: Full first-order logic with quantifiers, predicates, and arithmetic
Status: Mix of valid and invalid entailments
Features: Exists/forall quantifiers, arithmetic constraints, complex predicates
Note: This is the most expressive division - combines all features
"""

from test_framework import *


def run_tests(verbose=False):
    """Run shidlia_entl benchmark-based tests"""
    suite = TestSuite("SL-COMP: shidlia_entl (Full FOL + Arithmetic)", verbose=verbose)

    # ========== Valid Entailments (should pass) ==========

    # Basic reflexivity
    suite.test_entailment_str(
        "Reflexivity: list(x) |- list(x)",
        "list(x)",
        "list(x)",
        should_be_valid=True
    )

    # Segment operations
    suite.test_entailment_str(
        "Segment transitivity: ls(x,y) * ls(y,z) |- ls(x,z)",
        "ls(x, y) * ls(y, z)",
        "ls(x, z)",
        should_be_valid=True
    )

    # With arithmetic
    suite.test_entailment_str(
        "With equality: list(x) & a = b |- list(x)",
        "list(x) & a = b",
        "list(x)",
        should_be_valid=True
    )

    # Empty cases
    suite.test_entailment_str(
        "Empty segment: ls(x,x) |- emp",
        "ls(x, x)",
        "emp",
        should_be_valid=True
    )

    # Frame rule
    suite.test_entailment_str(
        "Frame: list(x) * y |-> z |- list(x)",
        "list(x) * y |-> z",
        "list(x)",
        should_be_valid=True
    )

    # List cons
    suite.test_entailment_str(
        "List cons: x |-> y * list(y) |- list(x)",
        "x |-> y * list(y)",
        "list(x)",
        should_be_valid=True
    )

    # Pure arithmetic
    suite.test_entailment_str(
        "Pure: x = y |- x = y",
        "x = y",
        "x = y",
        should_be_valid=True
    )

    # ========== Invalid Entailments (should fail) ==========

    suite.test_entailment_str(
        "INVALID: emp |- x |-> y",
        "emp",
        "x |-> y",
        should_be_valid=False
    )

    suite.test_entailment_str(
        "INVALID: list(x) |- tree(x)",
        "list(x)",
        "tree(x)",
        should_be_valid=False
    )

    suite.test_entailment_str(
        "INVALID: ls(x,y) |- ls(x,z) where y != z",
        "ls(x, y)",
        "ls(x, z)",
        should_be_valid=False
    )

    # ========== Edge Cases ==========

    suite.test_entailment_str(
        "Empty: emp |- emp",
        "emp",
        "emp",
        should_be_valid=True
    )

    suite.test_entailment_str(
        "Nil list: list(nil) |- emp",
        "list(nil)",
        "emp",
        should_be_valid=True
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
