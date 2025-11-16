"""
Test suite based on SL-COMP qf_shlid_entl benchmarks.

Division: QF_SHLID - Quantifier-Free Separation Logic with Inductive Definitions
Focus: Complex inductive predicates (DLL, nested lists, skip lists)
Status: Mix of valid (unsat) and invalid (sat) entailments
Features: Multiple heap sorts, recursive predicates, existential quantification
Note: Tests doubly-linked lists, nested lists (nll), skip lists (skl), special lists (lss)
"""

from test_framework import *


def run_tests(verbose=False):
    """Run qf_shlid_entl benchmark-based tests"""
    suite = TestSuite("SL-COMP: qf_shlid_entl (Complex Inductive Predicates)", verbose=verbose)

    # ========== Valid Entailments (should pass) ==========

    # Basic reflexivity
    suite.test_entailment_str(
        "Reflexivity: list(x) |- list(x)",
        "list(x)",
        "list(x)",
        should_be_valid=True
    )

    # Empty heap cases
    suite.test_entailment_str(
        "Empty segment: ls(x,x) |- emp",
        "ls(x, x)",
        "emp",
        should_be_valid=True
    )

    suite.test_entailment_str(
        "Empty list: emp |- list(nil)",
        "emp",
        "list(nil)",
        should_be_valid=True
    )

    # List segment operations
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

    # Frame rule
    suite.test_entailment_str(
        "Frame: list(x) * y |-> z |- list(x)",
        "list(x) * y |-> z",
        "list(x)",
        should_be_valid=True
    )

    # Multiple segments
    suite.test_entailment_str(
        "Multiple segments: ls(x,y) * ls(a,b) |- ls(x,y)",
        "ls(x, y) * ls(a, b)",
        "ls(x, y)",
        should_be_valid=True
    )

    # Chaining
    suite.test_entailment_str(
        "Segment chain: x |-> y * y |-> z * ls(z,nil) |- ls(x,nil)",
        "x |-> y * y |-> z * ls(z, nil)",
        "ls(x, nil)",
        should_be_valid=True
    )

    # List to segment
    suite.test_entailment_str(
        "List to segment: list(x) |- ls(x,nil)",
        "list(x)",
        "ls(x, nil)",
        should_be_valid=True
    )

    # Predicate reflexivity with separation
    suite.test_entailment_str(
        "Predicate with frame: list(x) * list(y) |- list(x) * list(y)",
        "list(x) * list(y)",
        "list(x) * list(y)",
        should_be_valid=True
    )

    # NOTE: DLL, NLL, SKL predicates require special definitions
    # Our current system has basic list/tree predicates but not DLL/NLL/SKL
    # The following tests are documented but commented out as they need
    # specialized predicate definitions not yet in our system:

    # DLL operations (doubly-linked list predicate)
    # Based on SL-COMP dll-vc05: dll(fr, bk, pr, nx)
    suite.test_entailment_str(
        "DLL cons: x |-> (w,nil) * dll(w,y,x,z) |- dll(x,y,nil,z)",
        "x |-> (w, nil) * dll(w, y, x, z)",
        "dll(x, y, nil, z)",
        should_be_valid=True
    )

    # Nested list operations (nested list predicate)
    suite.test_entailment_str(
        "NLL transitivity: nll(x,y,nil) * nll(y,z,nil) |- nll(x,z,nil)",
        "nll(x, y, nil) * nll(y, z, nil)",
        "nll(x, z, nil)",
        should_be_valid=True
    )

    # Skip list operations (skip list predicates)
    # Note: Cross-level composition (level 1 + level 2 -> level 2) is NOT semantically valid
    # in standard skip list semantics, as each level is separate.
    suite.test_entailment_str(
        "INVALID: SKL cross-level composition: skl1(x,y) * skl2(y,z) |- skl2(x,z)",
        "skl1(x, y) * skl2(y, z)",
        "skl2(x, z)",
        should_be_valid=False
    )

    # ========== Invalid Entailments (should fail) ==========

    # Cannot create heap from nothing
    suite.test_entailment_str(
        "INVALID: emp |- x |-> y",
        "emp",
        "x |-> y",
        should_be_valid=False
    )

    # Different predicates
    suite.test_entailment_str(
        "INVALID: list(x) |- tree(x)",
        "list(x)",
        "tree(x)",
        should_be_valid=False
    )

    # Different endpoints
    suite.test_entailment_str(
        "INVALID: ls(x,y) |- ls(x,z) where y != z",
        "ls(x, y)",
        "ls(x, z)",
        should_be_valid=False
    )

    # Cannot remove allocated cells
    suite.test_entailment_str(
        "INVALID: x |-> y * list(z) |- list(z)",
        "x |-> y * list(z)",
        "list(z)",
        should_be_valid=False
    )

    # Non-empty to empty
    suite.test_entailment_str(
        "INVALID: list(x) |- emp (unless list is nil)",
        "list(x)",
        "emp",
        should_be_valid=False
    )

    # Different structures (different predicates)
    suite.test_entailment_str(
        "INVALID: dll(x,y,z,w) |- nll(x,y,z)",
        "dll(x, y, z, w)",
        "nll(x, y, z)",
        should_be_valid=False
    )

    # Incompatible skip lists (different skip list levels)
    suite.test_entailment_str(
        "INVALID: skl2(x,y) |- skl3(x,y)",
        "skl2(x, y)",
        "skl3(x, y)",
        should_be_valid=False
    )

    # ========== Edge Cases ==========

    # Self-referencing
    suite.test_entailment_str(
        "Self-loop segment: ls(x,x) |- emp",
        "ls(x, x)",
        "emp",
        should_be_valid=True
    )

    # Nil pointers
    suite.test_entailment_str(
        "Nil list: list(nil) |- emp",
        "list(nil)",
        "emp",
        should_be_valid=True
    )

    # Reflexivity with nil
    suite.test_entailment_str(
        "Nil segment: ls(nil,nil) |- emp",
        "ls(nil, nil)",
        "emp",
        should_be_valid=True
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
