"""
Test suite based on SL-COMP qf_shid_entl benchmarks.

Division: QF_SHID - Quantifier-Free Separation Logic with Inductive Definitions
Focus: List entailments with inductive predicates
Status: Mix of valid (unsat) and invalid (sat) entailments
"""

from test_framework import *


def run_tests(verbose=False):
    """Run qf_shid_entl benchmark-based tests"""
    suite = TestSuite("SL-COMP: qf_shid_entl (List Entailments)", verbose=verbose)

    # ========== Valid Entailments (should pass) ==========
    # Based on 01.tst.smt2 - list transitivity

    # Reverse list cons (requires RList predicate)
    suite.test_entailment_str(
        "Reverse list cons: x |-> y * RList(y,z) |- RList(x,z)",
        "x |-> y * RList(y, z)",
        "RList(x, z)",
        should_be_valid=True
    )

    # ls(x, y) * ls(y, z) |- ls(x, z)
    # List segment transitivity
    suite.test_entailment_str(
        "Segment transitivity: ls(x,y) * ls(y,z) |- ls(x,z)",
        "ls(x, y) * ls(y, z)",
        "ls(x, z)",
        should_be_valid=True
    )

    # x |-> y * ls(y, z) |- ls(x, z)
    # Segment cons (already tested in bi-abduction but good to have here)
    suite.test_entailment_str(
        "Segment cons: x |-> y * ls(y,z) |- ls(x,z)",
        "x |-> y * ls(y, z)",
        "ls(x, z)",
        should_be_valid=True
    )

    # emp |- ls(x, x)
    # Empty segment
    suite.test_entailment_str(
        "Empty segment: emp |- ls(x,x)",
        "emp",
        "ls(x, x)",
        should_be_valid=True
    )

    # ls(x, x) |- emp
    # Empty segment reverse
    suite.test_entailment_str(
        "Empty segment reverse: ls(x,x) |- emp",
        "ls(x, x)",
        "emp",
        should_be_valid=True
    )

    # list(x) * list(y) |- list(x)
    # Frame rule
    suite.test_entailment_str(
        "Frame: list(x) * list(y) |- list(x)",
        "list(x) * list(y)",
        "list(x)",
        should_be_valid=True
    )

    # x |-> y |- x |-> y
    # Reflexivity on points-to
    suite.test_entailment_str(
        "Points-to reflexivity: x |-> y |- x |-> y",
        "x |-> y",
        "x |-> y",
        should_be_valid=True
    )

    # x |-> y * z |-> w |- x |-> y * z |-> w
    # Reflexivity on separation
    suite.test_entailment_str(
        "Separation reflexivity",
        "x |-> y * z |-> w",
        "x |-> y * z |-> w",
        should_be_valid=True
    )

    # Based on append tests
    # ls(x, y) * ls(y, nil) |- ls(x, nil)
    suite.test_entailment_str(
        "Append to nil: ls(x,y) * ls(y,nil) |- ls(x,nil)",
        "ls(x, y) * ls(y, nil)",
        "ls(x, nil)",
        should_be_valid=True
    )

    # x |-> y * y |-> nil |- ls(x, nil)
    # Two-element list (requires folding/abstraction)
    suite.test_entailment_str(
        "Two-element list: x |-> y * y |-> nil |- ls(x,nil)",
        "x |-> y * y |-> nil",
        "ls(x, nil)",
        should_be_valid=True
    )

    # ========== Invalid Entailments (should fail) ==========

    # emp |- x |-> y
    # Cannot create heap from nothing
    suite.test_entailment_str(
        "INVALID: emp |- x |-> y (cannot create heap)",
        "emp",
        "x |-> y",
        should_be_valid=False
    )

    # Footprint-aware Affine SL: x |-> y |- emp is INVALID
    # NOTE: In pure Affine SL this would be VALID (heap weakening)
    # But in footprint-aware Affine SL, we conservatively block dropping cells
    # with symbolic values (y) that could alias kept predicates
    suite.test_entailment_str(
        "INVALID (Footprint-aware Affine): x |-> y |- emp",
        "x |-> y",
        "emp",
        should_be_valid=False  # INVALID in footprint-aware affine SL
    )

    # ls(x, y) |- ls(x, z)
    # Different endpoints
    suite.test_entailment_str(
        "INVALID: ls(x,y) |- ls(x,z) (different endpoints)",
        "ls(x, y)",
        "ls(x, z)",
        should_be_valid=False
    )

    # x |-> y |- x |-> z
    # Different values
    suite.test_entailment_str(
        "INVALID: x |-> y |- x |-> z (different values)",
        "x |-> y",
        "x |-> z",
        should_be_valid=False
    )

    # list(x) |- list(x) * list(y)
    # Cannot create extra list
    suite.test_entailment_str(
        "INVALID: list(x) |- list(x) * list(y) (missing list)",
        "list(x)",
        "list(x) * list(y)",
        should_be_valid=False
    )

    # ls(x, y) * ls(z, w) |- ls(x, w)
    # Non-consecutive segments
    suite.test_entailment_str(
        "INVALID: ls(x,y) * ls(z,w) |- ls(x,w) (non-consecutive)",
        "ls(x, y) * ls(z, w)",
        "ls(x, w)",
        should_be_valid=False
    )

    # x |-> y * ls(z, w) |- ls(x, w)
    # Mismatched chain (y != z)
    suite.test_entailment_str(
        "INVALID: x |-> y * ls(z,w) |- ls(x,w) (broken chain)",
        "x |-> y * ls(z, w)",
        "ls(x, w)",
        should_be_valid=False
    )

    # ========== Edge Cases ==========

    # ls(nil, nil) |- emp
    # Nil segment is empty
    suite.test_entailment_str(
        "Nil segment: ls(nil,nil) |- emp",
        "ls(nil, nil)",
        "emp",
        should_be_valid=True
    )

    # x |-> y * emp |- x |-> y
    # Emp is neutral
    suite.test_entailment_str(
        "Emp neutral: x |-> y * emp |- x |-> y",
        "x |-> y * emp",
        "x |-> y",
        should_be_valid=True
    )

    # (x |-> y * ls(y, z)) * w |-> v |- ls(x, z) * w |-> v
    # Cons with frame
    suite.test_entailment_str(
        "Cons with frame: (x |-> y * ls(y,z)) * w |-> v |- ls(x,z) * w |-> v",
        "x |-> y * ls(y, z) * w |-> v",
        "ls(x, z) * w |-> v",
        should_be_valid=True
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
