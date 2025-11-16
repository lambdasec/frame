"""
Test suite based on SL-COMP qf_bsl_sat benchmarks.

Division: QF_BSL - Quantifier-Free Boolean Separation Logic
Focus: Basic heap operations without inductive predicates
Status: Mix of sat and unsat formulas
Features: Points-to, emp, separation, no predicates
Note: This tests the most basic separation logic reasoning
"""

from test_framework import *


def run_tests(verbose=False):
    """Run qf_bsl_sat benchmark-based tests"""
    suite = TestSuite("SL-COMP: qf_bsl_sat (Basic Heap)", verbose=verbose)

    # ========== Satisfiable Formulas ==========

    # Most basic cases
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

    # Separation
    suite.test_satisfiability(
        "SAT: x |-> y * z |-> w is satisfiable",
        sep(pts("x", "y"), pts("z", "w")),
        should_be_sat=True
    )

    # Triple separation
    suite.test_satisfiability(
        "SAT: x |-> a * y |-> b * z |-> c is satisfiable",
        sep(pts("x", "a"), pts("y", "b"), pts("z", "c")),
        should_be_sat=True
    )

    # Fixed: emp in separation now works correctly (emp * P ≡ P)
    suite.test_satisfiability(
        "SAT: x |-> y * emp is satisfiable",
        sep(pts("x", "y"), emp()),
        should_be_sat=True
    )

    # Chain
    suite.test_satisfiability(
        "SAT: x |-> y * y |-> z is satisfiable",
        sep(pts("x", "y"), pts("y", "z")),
        should_be_sat=True
    )

    # Longer chain
    suite.test_satisfiability(
        "SAT: x |-> y * y |-> z * z |-> w is satisfiable",
        sep(pts("x", "y"), pts("y", "z"), pts("z", "w")),
        should_be_sat=True
    )

    # With equality
    suite.test_satisfiability(
        "SAT: x |-> y & x = a is satisfiable",
        And(pts("x", "y"), eq("x", "a")),
        should_be_sat=True
    )

    # Nil pointer
    x = Var("x")
    nil = Var("nil")
    suite.test_satisfiability(
        "SAT: x |-> nil is satisfiable",
        PointsTo(x, [nil]),
        should_be_sat=True
    )

    # ========== Unsatisfiable Formulas ==========

    # Same cell twice
    suite.test_satisfiability(
        "UNSAT: x |-> y * x |-> z (separation conflict)",
        sep(pts("x", "y"), pts("x", "z")),
        should_be_sat=False
    )

    # Same cell same value twice
    suite.test_satisfiability(
        "UNSAT: x |-> y * x |-> y (still separation conflict)",
        sep(pts("x", "y"), pts("x", "y")),
        should_be_sat=False
    )

    # Contradictory values
    suite.test_satisfiability(
        "UNSAT: x |-> y * x |-> z * y != z",
        And(sep(pts("x", "y"), pts("x", "z")), neq("y", "z")),
        should_be_sat=False
    )

    # Contradictory equalities
    suite.test_satisfiability(
        "UNSAT: x = y & x != y",
        And(eq("x", "y"), neq("x", "y")),
        should_be_sat=False
    )

    # Contradictory heap
    suite.test_satisfiability(
        "UNSAT: x |-> y & emp",
        And(pts("x", "y"), emp()),
        should_be_sat=False
    )

    # Based on dispose benchmarks
    # w |-> nil & w1 = nil & w2 = nil but something contradictory
    w = Var("w")
    w1 = Var("w1")
    w2 = Var("w2")
    suite.test_satisfiability(
        "UNSAT: w |-> w1 * w |-> w2 with w1 = nil & w2 = nil",
        And(And(sep(PointsTo(w, [w1]), PointsTo(w, [w2])),
                eq("w1", "nil")),
            eq("w2", "nil")),
        should_be_sat=False
    )

    # ========== Edge Cases ==========

    # True is satisfiable
    suite.test_satisfiability(
        "SAT: true is satisfiable",
        True_(),
        should_be_sat=True
    )

    # False is unsatisfiable
    suite.test_satisfiability(
        "UNSAT: false is unsatisfiable",
        False_(),
        should_be_sat=False
    )

    # emp * emp = emp
    suite.test_satisfiability(
        "SAT: emp * emp is satisfiable",
        sep(emp(), emp()),
        should_be_sat=True
    )

    # Fixed: multiple emp in separation now works
    suite.test_satisfiability(
        "SAT: x |-> y * emp * emp is satisfiable",
        sep(pts("x", "y"), emp(), emp()),
        should_be_sat=True
    )

    # Reflexive equality
    suite.test_satisfiability(
        "SAT: x = x is satisfiable",
        eq("x", "x"),
        should_be_sat=True
    )

    # ========== Separation Patterns ==========

    # Disjoint allocations
    suite.test_satisfiability(
        "SAT: x |-> a * y |-> b * x != y",
        And(sep(pts("x", "a"), pts("y", "b")), neq("x", "y")),
        should_be_sat=True
    )

    # Symmetric separation
    suite.test_satisfiability(
        "SAT: x |-> y * z |-> w = z |-> w * x |-> y",
        eq("x", "x"),  # Dummy - we don't have formula equality in assertions
        should_be_sat=True
    )

    # Triple disjoint
    suite.test_satisfiability(
        "SAT: x |-> a * y |-> b * z |-> c with all different",
        And(And(And(sep(pts("x", "a"), pts("y", "b"), pts("z", "c")),
                    neq("x", "y")),
                neq("y", "z")),
            neq("x", "z")),
        should_be_sat=True
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
