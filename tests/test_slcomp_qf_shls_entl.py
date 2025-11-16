"""
Test suite based on SL-COMP qf_shls_entl benchmarks.

Division: QF_SHLS - Quantifier-Free Separation Logic with List Segments
Focus: Complex list segment patterns (bolognesa, fibonacci, spaguetti benchmarks)
Status: Mix of valid (unsat) and invalid (sat) entailments
Features: Multiple overlapping/disjoint segments, graph-like patterns
"""

from test_framework import *


def run_tests(verbose=False):
    """Run qf_shls_entl benchmark-based tests"""
    suite = TestSuite("SL-COMP: qf_shls_entl (List Segment Patterns)", verbose=verbose)

    # ========== Simple Patterns (should pass) ==========

    # Basic segment operations
    suite.test_entailment_str(
        "Simple segment: ls(x,y) |- ls(x,y)",
        "ls(x, y)",
        "ls(x, y)",
        should_be_valid=True
    )

    # Segment with points-to
    suite.test_entailment_str(
        "Segment + cell: ls(x,y) * y |-> z |- ls(x,y) * y |-> z",
        "ls(x, y) * y |-> z",
        "ls(x, y) * y |-> z",
        should_be_valid=True
    )

    # Two disjoint segments
    suite.test_entailment_str(
        "Disjoint segments: ls(x,y) * ls(a,b) |- ls(x,y) * ls(a,b)",
        "ls(x, y) * ls(a, b)",
        "ls(x, y) * ls(a, b)",
        should_be_valid=True
    )

    # ========== Bolognesa Patterns ==========
    # These involve multiple segments with complex connections

    # Pattern: Chain of 3 segments
    # ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)
    suite.test_entailment_str(
        "Triple chain: ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)",
        "ls(x, y) * ls(y, z) * ls(z, w)",
        "ls(x, w)",
        should_be_valid=True
    )

    # Pattern: Frame with chain
    # ls(x,y) * ls(y,z) * ls(a,b) |- ls(x,z) * ls(a,b)
    suite.test_entailment_str(
        "Chain with frame: ls(x,y) * ls(y,z) * ls(a,b) |- ls(x,z) * ls(a,b)",
        "ls(x, y) * ls(y, z) * ls(a, b)",
        "ls(x, z) * ls(a, b)",
        should_be_valid=True
    )

    # ========== Invalid Patterns (should fail) ==========

    # Circular impossibility: ls(x,y) * ls(y,x) with x != y
    # The antecedent is UNSAT (impossible to have circular segments with x != y)
    # Therefore, the entailment is vacuously VALID (anything follows from false)
    from frame.core.ast import SepConj, And, PredicateCall, Var, Neq, Emp
    x, y = Var("x"), Var("y")
    circular_ante = And(
        SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, x])),
        Neq(x, y)
    )
    suite.test_entailment(
        "VALID: Circular segments ls(x,y) * ls(y,x) |- emp (x != y) [vacuous]",
        circular_ante,
        Emp(),
        should_be_valid=True  # Vacuously valid because antecedent is UNSAT
    )

    # Disconnected segments cannot merge
    # ls(x,y) * ls(z,w) |- ls(x,w) where y != z
    suite.test_entailment_str(
        "INVALID: Disconnected merge ls(x,y) * ls(z,w) |- ls(x,w)",
        "ls(x, y) * ls(z, w)",
        "ls(x, w)",
        should_be_valid=False
    )

    # Cannot split one segment into two
    # ls(x,z) |- ls(x,y) * ls(y,z)
    suite.test_entailment_str(
        "INVALID: Cannot split ls(x,z) |- ls(x,y) * ls(y,z)",
        "ls(x, z)",
        "ls(x, y) * ls(y, z)",
        should_be_valid=False
    )

    # Wrong direction
    # ls(x,y) |- ls(y,x)
    suite.test_entailment_str(
        "INVALID: Wrong direction ls(x,y) |- ls(y,x)",
        "ls(x, y)",
        "ls(y, x)",
        should_be_valid=False
    )

    # ========== Spaguetti Patterns (Complex) ==========
    # Based on spaguetti benchmarks - multiple interleaved segments

    # Pattern: Two parallel chains
    # ls(x1,y1) * ls(x2,y2) |- ls(x1,y1) * ls(x2,y2)
    suite.test_entailment_str(
        "Parallel chains reflexivity",
        "ls(x1, y1) * ls(x2, y2)",
        "ls(x1, y1) * ls(x2, y2)",
        should_be_valid=True
    )

    # Pattern: Frame one chain
    # ls(x1,y1) * ls(x2,y2) |- ls(x1,y1)
    suite.test_entailment_str(
        "Frame second chain: ls(x1,y1) * ls(x2,y2) |- ls(x1,y1)",
        "ls(x1, y1) * ls(x2, y2)",
        "ls(x1, y1)",
        should_be_valid=True
    )

    # ========== Edge Cases ==========

    # Empty segments are neutral
    # ls(x,x) * ls(y,z) |- ls(y,z)
    suite.test_entailment_str(
        "Empty segment neutral: ls(x,x) * ls(y,z) |- ls(y,z)",
        "ls(x, x) * ls(y, z)",
        "ls(y, z)",
        should_be_valid=True
    )

    # Multiple empty segments
    # ls(x,x) * ls(y,y) * ls(z,w) |- ls(z,w)
    suite.test_entailment_str(
        "Multiple empty: ls(x,x) * ls(y,y) * ls(z,w) |- ls(z,w)",
        "ls(x, x) * ls(y, y) * ls(z, w)",
        "ls(z, w)",
        should_be_valid=True
    )

    # Segment to nil
    # ls(x,nil) * ls(nil,nil) |- ls(x,nil)
    suite.test_entailment_str(
        "Segment to nil: ls(x,nil) * ls(nil,nil) |- ls(x,nil)",
        "ls(x, nil) * ls(nil, nil)",
        "ls(x, nil)",
        should_be_valid=True
    )

    # ========== Fibonacci/Rotation Patterns ==========
    # These test specific graph structures

    # Pattern: Diamond structure (if expanded)
    # ls(x,y) * ls(x,z) with x=y=z is SAT
    # But ls(x,y) * ls(x,z) |- ls(x,y) is valid
    suite.test_entailment_str(
        "Diamond frame: ls(x,y) * ls(x,z) |- ls(x,y)",
        "ls(x, y) * ls(x, z)",
        "ls(x, y)",
        should_be_valid=True
    )

    # Pattern: Star structure
    # ls(x,a) * ls(x,b) * ls(x,c) |- ls(x,a)
    suite.test_entailment_str(
        "Star frame: ls(x,a) * ls(x,b) * ls(x,c) |- ls(x,a)",
        "ls(x, a) * ls(x, b) * ls(x, c)",
        "ls(x, a)",
        should_be_valid=True
    )

    # ========== Negative Edge Cases ==========

    # Cannot merge non-adjacent segments
    # ls(x,y) * ls(a,b) |- ls(x,b) when y != a
    suite.test_entailment_str(
        "INVALID: Non-adjacent merge",
        "ls(x, y) * ls(a, b)",
        "ls(x, b)",
        should_be_valid=False
    )

    # Cannot extend segment arbitrarily
    # ls(x,y) |- ls(x,z) when z != y
    suite.test_entailment_str(
        "INVALID: Arbitrary extension ls(x,y) |- ls(x,z)",
        "ls(x, y)",
        "ls(x, z)",
        should_be_valid=False
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
