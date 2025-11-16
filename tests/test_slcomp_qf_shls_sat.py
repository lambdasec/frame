"""
Test suite based on SL-COMP qf_shls_sat benchmarks.

Division: QF_SHLS - Quantifier-Free Separation Logic with List Segments (SAT)
Focus: Satisfiability of list segment formulas
Status: Mix of sat and unsat formulas
Features: List segments, separation, complex list patterns
Note: Tests list segment satisfiability without arithmetic
"""

from test_framework import *


def run_tests(verbose=False):
    """Run qf_shls_sat benchmark-based tests"""
    suite = TestSuite("SL-COMP: qf_shls_sat (List Segment SAT)", verbose=verbose)

    # ========== Satisfiable Formulas ==========

    suite.test_satisfiability(
        "SAT: emp is satisfiable",
        emp(),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: ls(x,y) is satisfiable",
        ls("x", "y"),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: ls(x,y) * ls(y,z) is satisfiable",
        sep(ls("x", "y"), ls("y", "z")),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: ls(x,y) * ls(a,b) is satisfiable",
        sep(ls("x", "y"), ls("a", "b")),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: x |-> y * ls(y,z) is satisfiable",
        sep(pts("x", "y"), ls("y", "z")),
        should_be_sat=True
    )

    # Self-loop segments
    suite.test_satisfiability(
        "SAT: ls(x,x) is satisfiable",
        ls("x", "x"),
        should_be_sat=True
    )

    # Multiple segments
    suite.test_satisfiability(
        "SAT: ls(x,y) * ls(y,z) * ls(z,w) is satisfiable",
        sep(ls("x", "y"), ls("y", "z"), ls("z", "w")),
        should_be_sat=True
    )

    # With points-to
    suite.test_satisfiability(
        "SAT: x |-> y * y |-> z * ls(z,w) is satisfiable",
        sep(pts("x", "y"), pts("y", "z"), ls("z", "w")),
        should_be_sat=True
    )

    # ========== Unsatisfiable Formulas ==========

    # Separation conflict
    suite.test_satisfiability(
        "UNSAT: x |-> y * x |-> z",
        sep(pts("x", "y"), pts("x", "z")),
        should_be_sat=False
    )

    # Empty contradiction
    suite.test_satisfiability(
        "UNSAT: x |-> y & emp",
        And(pts("x", "y"), emp()),
        should_be_sat=False
    )

    # Equality contradiction
    suite.test_satisfiability(
        "UNSAT: x = y & x != y",
        And(eq("x", "y"), neq("x", "y")),
        should_be_sat=False
    )

    # ========== Edge Cases ==========

    suite.test_satisfiability(
        "SAT: ls(nil,nil) is satisfiable",
        ls("nil", "nil"),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: ls(x,y) * x != y is satisfiable",
        And(ls("x", "y"), neq("x", "y")),
        should_be_sat=True
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
