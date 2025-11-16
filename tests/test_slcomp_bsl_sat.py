"""
Test suite based on SL-COMP bsl_sat benchmarks.

Division: BSL - Basic Separation Logic with Quantifiers (SAT)
Focus: Satisfiability with exists/forall quantifiers
Status: Mix of sat and unsat formulas
Features: Basic heap operations with full first-order logic
Note: Tests quantified formulas over heap structures
"""

from test_framework import *


def run_tests(verbose=False):
    """Run bsl_sat benchmark-based tests"""
    suite = TestSuite("SL-COMP: bsl_sat (Basic Heap with Quantifiers)", verbose=verbose)

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

    suite.test_satisfiability(
        "SAT: x |-> y * y |-> z is satisfiable",
        sep(pts("x", "y"), pts("y", "z")),
        should_be_sat=True
    )

    # With equality
    suite.test_satisfiability(
        "SAT: x |-> y & a = b is satisfiable",
        And(pts("x", "y"), eq("a", "b")),
        should_be_sat=True
    )

    # NOTE: Quantified formulas are supported but complex quantification
    # patterns may not be fully tested. Examples:

    # Existential witness
    x = Var("x")
    y = Var("y")
    suite.test_satisfiability(
        "SAT: exists y. x |-> y",
        Exists("y", PointsTo(x, [y])),
        should_be_sat=True
    )

    # ========== Unsatisfiable Formulas ==========

    suite.test_satisfiability(
        "UNSAT: x |-> y * x |-> z",
        sep(pts("x", "y"), pts("x", "z")),
        should_be_sat=False
    )

    suite.test_satisfiability(
        "UNSAT: x = y & x != y",
        And(eq("x", "y"), neq("x", "y")),
        should_be_sat=False
    )

    suite.test_satisfiability(
        "UNSAT: x |-> y & emp",
        And(pts("x", "y"), emp()),
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
