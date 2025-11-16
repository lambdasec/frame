"""
Test suite based on SL-COMP shid_entl benchmarks.

Division: SHID - Separation Logic with Inductive Definitions (Full FOL)
Focus: Entailments with quantifiers (exists, forall) and inductive predicates
Status: Mix of valid and invalid entailments
Features: First-order quantification, universal/existential reasoning
Note: This extends QF_SHID with full first-order logic
"""

from test_framework import *


def run_tests(verbose=False):
    """Run shid_entl benchmark-based tests"""
    suite = TestSuite("SL-COMP: shid_entl (Full FOL Lists)", verbose=verbose)

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

    suite.test_entailment_str(
        "Segment cons: x |-> y * ls(y,z) |- ls(x,z)",
        "x |-> y * ls(y, z)",
        "ls(x, z)",
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

    # NOTE: Full FOL features like exists/forall are supported by our system
    # but complex quantified entailments may not all pass. Examples:

    # Existential witness (quantifier in consequent)
    suite.test_entailment(
        "Exists intro: x |-> 5 |- exists y. x |-> y",
        pts("x", "5"),
        Exists("y", pts("x", "y")),
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
