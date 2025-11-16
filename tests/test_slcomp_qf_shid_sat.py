"""
Test suite based on SL-COMP qf_shid_sat benchmarks.

Division: QF_SHID - Quantifier-Free Separation Logic with Inductive Definitions (Satisfiability)
Focus: Checking satisfiability of formulas with lists, trees, and complex structures
Status: Mix of sat and unsat formulas
Features: dll, atll (acyclic tree with linked leaves), lasso, tll, nll
"""

from test_framework import *


def run_tests(verbose=False):
    """Run qf_shid_sat benchmark-based tests"""
    suite = TestSuite("SL-COMP: qf_shid_sat (Satisfiability)", verbose=verbose)

    # ========== Satisfiable Formulas ==========

    # Basic satisfiability tests
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

    # Separation is satisfiable
    suite.test_satisfiability(
        "SAT: x |-> y * z |-> w is satisfiable",
        sep(pts("x", "y"), pts("z", "w")),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: x |-> y * list(z) is satisfiable",
        sep(pts("x", "y"), lst("z")),
        should_be_sat=True
    )

    # List predicates with specific structure
    suite.test_satisfiability(
        "SAT: x |-> y * y |-> z is satisfiable",
        sep(pts("x", "y"), pts("y", "z")),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: x |-> y * ls(y,z) is satisfiable",
        sep(pts("x", "y"), ls("y", "z")),
        should_be_sat=True
    )

    # Two separate lists
    suite.test_satisfiability(
        "SAT: list(x) * list(y) is satisfiable",
        sep(lst("x"), lst("y")),
        should_be_sat=True
    )

    # ========== Unsatisfiable Formulas ==========

    # Same location, different values
    x = Var("x")
    y = Var("y")
    z = Var("z")

    suite.test_satisfiability(
        "UNSAT: x |-> y * x |-> z with y != z",
        And(sep(pts("x", "y"), pts("x", "z")), neq("y", "z")),
        should_be_sat=False
    )

    # Contradictory equalities
    suite.test_satisfiability(
        "UNSAT: x = y & x != y",
        And(eq("x", "y"), neq("x", "y")),
        should_be_sat=False
    )

    # Same cell allocated twice (should be unsat due to separation)
    suite.test_satisfiability(
        "UNSAT: x |-> y * x |-> y (same location twice)",
        sep(pts("x", "y"), pts("x", "y")),
        should_be_sat=False
    )

    # Circular list segment with disequality
    # ls(x,y) * ls(y,x) with x != y (requires y to reach x and x to reach y)
    suite.test_satisfiability(
        "UNSAT: ls(x,y) * ls(y,x) * x != y (circular contradiction)",
        And(sep(ls("x", "y"), ls("y", "x")), neq("x", "y")),
        should_be_sat=False
    )

    # ========== Edge Cases ==========

    # Empty segment is emp
    suite.test_satisfiability(
        "SAT: ls(x,x) is satisfiable (empty segment)",
        ls("x", "x"),
        should_be_sat=True
    )

    # Nil operations
    nil = Var("nil")
    suite.test_satisfiability(
        "SAT: x |-> nil is satisfiable",
        PointsTo(x, [nil]),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: ls(x,nil) is satisfiable",
        PredicateCall("ls", [x, nil]),
        should_be_sat=True
    )

    # Fixed: emp in separation now works correctly
    suite.test_satisfiability(
        "SAT: (x |-> y * emp) is satisfiable",
        sep(pts("x", "y"), emp()),
        should_be_sat=True
    )

    suite.test_satisfiability(
        "SAT: (x = y) & list(x) is satisfiable",
        And(eq("x", "y"), lst("x")),
        should_be_sat=True
    )

    # ========== Complex Structures (based on actual benchmarks) ==========

    # DLL pattern: single node
    suite.test_satisfiability(
        "SAT: Single DLL node (x |-> (y,z))",
        PointsTo(x, [y, z]),
        should_be_sat=True
    )

    # Tree pattern: single node
    l = Var("l")
    r = Var("r")
    suite.test_satisfiability(
        "SAT: Single tree node x |-> (l,r)",
        PointsTo(x, [l, r]),
        should_be_sat=True
    )

    # Tree with subtrees
    suite.test_satisfiability(
        "SAT: Tree with subtrees x |-> (l,r) * tree(l) * tree(r)",
        sep(PointsTo(x, [l, r]), tree("l"), tree("r")),
        should_be_sat=True
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
