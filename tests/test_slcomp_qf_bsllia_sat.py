"""
Test suite based on SL-COMP qf_bsllia_sat benchmarks.

Division: QF_BSLLIA - Quantifier-Free Basic Separation Logic with Linear Integer Arithmetic (SAT)
Focus: Satisfiability of basic heap formulas with arithmetic constraints
Status: Mix of sat and unsat formulas
Features: Points-to, emp, separation, arithmetic (no predicates)
Note: Tests heap satisfiability combined with linear arithmetic
"""

from test_framework import *


def run_tests(verbose=False):
    """Run qf_bsllia_sat benchmark-based tests"""
    suite = TestSuite("SL-COMP: qf_bsllia_sat (Basic Heap + Arithmetic SAT)", verbose=verbose)

    # ========== Satisfiable Formulas ==========

    suite.test_satisfiability(
        "SAT: emp is satisfiable",
        emp(),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: x |-> y is satisfiable",
        pts("x", "y"),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: x |-> y * z |-> w is satisfiable",
        sep(pts("x", "y"), pts("z", "w")),
        should_be_sat=True
    )

    # With arithmetic
    suite.test_satisfiability(
        "SAT: x |-> y & a = b is satisfiable",
        And(pts("x", "y"), eq("a", "b")),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: x |-> 5 & y = 3 is satisfiable",
        And(pts("x", "5"), eq("y", "3")),
        should_be_sat=True
    )

    # Inequality constraints
    suite.test_satisfiability(
        "SAT: x |-> y & a != b is satisfiable",
        And(pts("x", "y"), neq("a", "b")),
        should_be_sat=True
    )

    # Multiple cells with arithmetic
    suite.test_satisfiability(
        "SAT: x |-> a * y |-> b * z |-> c is satisfiable",
        sep(pts("x", "a"), pts("y", "b"), pts("z", "c")),
        should_be_sat=True
    )

    # Chains
    suite.test_satisfiability(
        "SAT: x |-> y * y |-> z is satisfiable",
        sep(pts("x", "y"), pts("y", "z")),
        should_be_sat=True
    )

    # ========== Unsatisfiable Formulas ==========

    # Separation conflict
    suite.test_satisfiability(
        "UNSAT: x |-> y * x |-> z (separation conflict)",
        sep(pts("x", "y"), pts("x", "z")),
        should_be_sat=False
    )

    # Contradictory equalities
    suite.test_satisfiability(
        "UNSAT: x = y & x != y",
        And(eq("x", "y"), neq("x", "y")),
        should_be_sat=False
    )

    # Empty heap contradiction
    suite.test_satisfiability(
        "UNSAT: x |-> y & emp (heap not empty)",
        And(pts("x", "y"), emp()),
        should_be_sat=False
    )

    # Arithmetic impossibility
    suite.test_satisfiability(
        "UNSAT: a = 5 & a = 3",
        And(eq("a", "5"), eq("a", "3")),
        should_be_sat=False
    )

    # ========== Edge Cases ==========

    suite.test_satisfiability(
        "SAT: emp * emp is satisfiable",
        sep(emp(), emp()),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: x = x is satisfiable",
        eq("x", "x"),
        should_be_sat=True
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
