"""
Test suite based on SL-COMP qf_shidlia_entl benchmarks.

Division: QF_SHIDLIA - Quantifier-Free Separation Logic with Inductive Definitions
                       and Linear Integer Arithmetic (Entailment)
Focus: Doubly-linked lists, list segments with length/data parameters
Status: Mix of valid (unsat) and invalid (sat) entailments
Features: DLL predicates, arithmetic constraints on lengths/data values
Note: This tests separation logic combined with linear arithmetic reasoning
"""

from test_framework import *


def run_tests(verbose=False):
    """Run qf_shidlia_entl benchmark-based tests"""
    suite = TestSuite("SL-COMP: qf_shidlia_entl (Lists + Arithmetic)", verbose=verbose)

    # Common variables for AST construction
    x, y, z = Var("x"), Var("y"), Var("z")
    n = Var("n")

    # ========== Valid Entailments (should pass) ==========

    # Basic list segment with length
    suite.test_entailment_str(
        "Empty segment: emp |- ls(x,x,0)",
        "emp",
        "ls(x, x, 0)",
        should_be_valid=True
    )

    # List segment transitivity with length composition
    suite.test_entailment_str(
        "Segment transitivity with lengths: ls(x,y,n1) * ls(y,z,n2) |- ls(x,z,n1+n2)",
        "ls(x, y, 5) * ls(y, z, 3)",
        "ls(x, z, 8)",
        should_be_valid=True
    )

    # Single node forms segment of length 1
    suite.test_entailment_str(
        "Single node segment: x |-> y |- ls(x,y,1)",
        "x |-> y",
        "ls(x, y, 1)",
        should_be_valid=True
    )

    # Reflexivity
    suite.test_entailment_str(
        "Reflexivity: list(x) |- list(x)",
        "list(x)",
        "list(x)",
        should_be_valid=True
    )

    # Frame rule with arithmetic
    suite.test_entailment_str(
        "Frame: x |-> y * list(z) |- x |-> y",
        "x |-> y * list(z)",
        "x |-> y",
        should_be_valid=True
    )

    # Pure arithmetic entailment
    suite.test_entailment_str(
        "Pure: x = y |- x = y",
        "x = y",
        "x = y",
        should_be_valid=True
    )

    # Combined spatial and pure
    suite.test_entailment_str(
        "Combined: x |-> y & a = b |- x |-> y",
        "x |-> y & a = b",
        "x |-> y",
        should_be_valid=True
    )

    # List with equality constraint
    suite.test_entailment_str(
        "List with equality: list(x) & x = y |- list(y)",
        "list(x) & x = y",
        "list(y)",
        should_be_valid=True
    )

    # Multiple segments
    suite.test_entailment_str(
        "Multiple segments: ls(x,y) * ls(a,b) |- ls(x,y)",
        "ls(x, y) * ls(a, b)",
        "ls(x, y)",
        should_be_valid=True
    )

    # Empty with arithmetic
    suite.test_entailment_str(
        "Empty with constraint: emp & n = 0 |- emp",
        "emp & n = 0",
        "emp",
        should_be_valid=True
    )

    # Segment cons (from bi-abduction)
    suite.test_entailment_str(
        "Segment cons: x |-> y * ls(y,z) |- ls(x,z)",
        "x |-> y * ls(y, z)",
        "ls(x, z)",
        should_be_valid=True
    )

    # Segment to nil
    suite.test_entailment_str(
        "Segment to nil: x |-> y * ls(y,nil) |- ls(x,nil)",
        "x |-> y * ls(y, nil)",
        "ls(x, nil)",
        should_be_valid=True
    )

    # Transitivity without arithmetic
    suite.test_entailment_str(
        "Segment transitivity: ls(x,y) * ls(y,z) |- ls(x,z)",
        "ls(x, y) * ls(y, z)",
        "ls(x, z)",
        should_be_valid=True
    )

    # ========== Invalid Entailments (should fail) ==========

    # Cannot create heap from nothing
    suite.test_entailment_str(
        "INVALID: emp |- x |-> y",
        "emp",
        "x |-> y",
        should_be_valid=False
    )

    # Different predicates don't entail each other
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

    # Contradictory arithmetic
    suite.test_entailment_str(
        "INVALID: n = 5 & m = 3 |- n = m",
        "n = 5 & m = 3",
        "n = m",
        should_be_valid=False
    )

    # Cannot eliminate allocated heap
    suite.test_entailment_str(
        "INVALID: x |-> y * list(z) |- list(z)",
        "x |-> y * list(z)",
        "list(z)",
        should_be_valid=False
    )

    # Incompatible structures
    suite.test_entailment_str(
        "INVALID: x |-> a |- x |-> b where a != b",
        "x |-> a",
        "x |-> b",
        should_be_valid=False
    )

    # ========== Edge Cases ==========

    # Self-loop segment
    suite.test_entailment_str(
        "Self-loop: ls(x,x) |- emp",
        "ls(x, x)",
        "emp",
        should_be_valid=True
    )

    # Empty heap both sides
    suite.test_entailment_str(
        "Both empty: emp |- emp",
        "emp",
        "emp",
        should_be_valid=True
    )

    # Reflexivity with separation
    suite.test_entailment_str(
        "Reflexive separation: x |-> y * z |-> w |- x |-> y * z |-> w",
        "x |-> y * z |-> w",
        "x |-> y * z |-> w",
        should_be_valid=True
    )

    # ========== Arithmetic Constraints (Advanced) ==========

    # NOTE: Most of these tests require sophisticated arithmetic reasoning
    # combined with separation logic. Our current implementation may not
    # handle them fully. Commenting out but documenting for future work.

    # Length-annotated transitivity (duplicate of earlier test)
    suite.test_entailment_str(
        "Length transitivity: ls(x,y,n) * ls(y,z,m) |- ls(x,z,n+m)",
        "ls(x, y, 5) * ls(y, z, 3)",
        "ls(x, z, 8)",
        should_be_valid=True
    )

    # Sorted list segment join (requires sorted list predicate with <= support)
    # Using AST construction because parser doesn't support <= yet
    a, b, c = Const(10), Const(20), Const(30)
    sorted_ante = And(
        And(
            SepConj(
                PredicateCall("sls", [x, a, y, b]),
                PredicateCall("sls", [y, b, z, c])
            ),
            Le(a, b)
        ),
        Le(b, c)
    )
    sorted_cons = PredicateCall("sls", [x, a, z, c])
    suite.test_entailment(
        "Sorted join: sls(x,a,y,b) * sls(y,b,z,c) & a <= b <= c |- sls(x,a,z,c)",
        sorted_ante,
        sorted_cons,
        should_be_valid=True
    )

    # DLL with length increment (requires parametric DLL)
    suite.test_entailment_str(
        "DLL cons: x |-> (y,p) * dll(y,x,z,t,n) |- dll(x,p,z,t,n+1)",
        "x |-> (y, p) * dll(y, x, z, t, 5)",
        "dll(x, p, z, t, 6)",
        should_be_valid=True
    )

    # Constraint propagation: non-empty list segment implies start != end
    # Using AST construction to ensure proper handling
    constraint_ante = And(
        PredicateCall("ls", [x, y, Const(5)]),
        Gt(Const(5), Const(0))
    )
    constraint_cons = Neq(x, y)
    suite.test_entailment(
        "Constraint: ls(x,y,n) & n > 0 |- x != y",
        constraint_ante,
        constraint_cons,
        should_be_valid=True
    )

    # VALID (Affine SL): Length weakening - can drop 2 cells
    suite.test_entailment_str(
        "VALID (Affine): ls(x,y,5) |- ls(x,y,3)",
        "ls(x, y, 5)",
        "ls(x, y, 3)",
        should_be_valid=True
    )

    # INVALID: Arithmetic contradiction
    # Using AST construction because parser doesn't support > yet
    arith_ante = Eq(n, Const(5))
    arith_cons = Gt(n, Const(10))
    suite.test_entailment(
        "INVALID: n = 5 |- n > 10",
        arith_ante,
        arith_cons,
        should_be_valid=False
    )

    return suite.report()


if __name__ == "__main__":
    import sys
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    passed, failed = run_tests(verbose=verbose)
    sys.exit(0 if failed == 0 else 1)
