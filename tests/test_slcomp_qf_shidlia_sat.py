"""
Test suite based on SL-COMP qf_shidlia_sat benchmarks.

Division: QF_SHIDLIA - Quantifier-Free Separation Logic with Inductive Definitions
                       and Linear Arithmetic (SAT)
Focus: Satisfiability with predicates and arithmetic constraints
Status: Mix of sat and unsat formulas
Features: List/tree predicates, arithmetic, complex structures
Note: Tests predicate satisfiability with arithmetic reasoning
"""

from test_framework import *


def run_tests(verbose=False):
    """Run qf_shidlia_sat benchmark-based tests"""
    suite = TestSuite("SL-COMP: qf_shidlia_sat (Predicates + Arithmetic SAT)", verbose=verbose)

    # ========== Satisfiable Formulas ==========

    suite.test_satisfiability(
        "SAT: emp is satisfiable",
        emp(),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: list(x) is satisfiable",
        lst("x"),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: ls(x,y) is satisfiable",
        ls("x", "y"),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: tree(x) is satisfiable",
        tree("x"),
        should_be_sat=True
    )

    # With arithmetic
    suite.test_satisfiability(
        "SAT: list(x) & a = b is satisfiable",
        And(lst("x"), eq("a", "b")),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: ls(x,y) & x != y is satisfiable",
        And(ls("x", "y"), neq("x", "y")),
        should_be_sat=True
    )

    # Combined structures
    suite.test_satisfiability(
        "SAT: x |-> y * list(z) is satisfiable",
        sep(pts("x", "y"), lst("z")),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: list(x) * tree(y) is satisfiable",
        sep(lst("x"), tree("y")),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: ls(x,y) * ls(a,b) is satisfiable",
        sep(ls("x", "y"), ls("a", "b")),
        should_be_sat=True
    )

    # ========== Unsatisfiable Formulas ==========

    # Contradictions
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
        "SAT: list(nil) is satisfiable",
        lst("nil"),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: ls(x,x) is satisfiable",
        ls("x", "x"),
        should_be_sat=True
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
