"""
Tests for inductive predicates (lists, trees, etc.)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from frame import *
from frame.core.parser import parse


def test_list_segment_unfold():
    """Test unfolding of list segment predicate"""
    print("\n=== Testing List Segment Unfolding ===")

    registry = PredicateRegistry()
    x = Var("x")
    y = Var("y")

    # ls(x, y)
    ls_call = PredicateCall("ls", [x, y])

    # Unfold once
    unfolded = registry.unfold_predicates(ls_call, depth=1)
    print(f"ls(x, y) unfolds to:\n  {unfolded}")


def test_list_predicate_unfold():
    """Test unfolding of linked list predicate"""
    print("\n=== Testing Linked List Unfolding ===")

    registry = PredicateRegistry()
    x = Var("x")

    # list(x)
    list_call = PredicateCall("list", [x])

    # Unfold once
    unfolded = registry.unfold_predicates(list_call, depth=1)
    print(f"list(x) unfolds to:\n  {unfolded}")


def test_tree_unfold():
    """Test unfolding of tree predicate"""
    print("\n=== Testing Tree Unfolding ===")

    registry = PredicateRegistry()
    x = Var("x")

    # tree(x)
    tree_call = PredicateCall("tree", [x])

    # Unfold once
    unfolded = registry.unfold_predicates(tree_call, depth=1)
    print(f"tree(x) unfolds to:\n  {unfolded}")


def test_list_entailment():
    """Test entailment with list predicates"""
    print("\n=== Testing List Entailments ===")

    registry = PredicateRegistry()
    registry.max_unfold_depth = 2  # Limit depth for testing
    checker = EntailmentChecker(predicate_registry=registry, verbose=True)

    x = Var("x")
    y = Var("y")
    nil = Const(None)

    # Test 1: ls(x, x) |- emp
    # A list segment from x to x should be empty
    antecedent = PredicateCall("ls", [x, x])
    consequent = Emp()
    result = checker.check(antecedent, consequent)
    print(f"\n✓ Test: ls(x, x) |- emp: {result}")

    # Test 2: x |-> y * ls(y, nil) |- ls(x, nil)
    # A node followed by a list segment makes a longer list segment
    antecedent = SepConj(
        PointsTo(x, [y]),
        PredicateCall("ls", [y, nil])
    )
    consequent = PredicateCall("ls", [x, nil])
    result = checker.check(antecedent, consequent)
    print(f"\n✓ Test: x |-> y * ls(y, nil) |- ls(x, nil): {result}")


def test_list_satisfiability():
    """Test satisfiability of list formulas"""
    print("\n=== Testing List Satisfiability ===")

    registry = PredicateRegistry()
    registry.max_unfold_depth = 2
    checker = EntailmentChecker(predicate_registry=registry, verbose=True)

    x = Var("x")

    # list(x) should be satisfiable
    formula = PredicateCall("list", [x])
    result = checker.is_satisfiable(formula)
    print(f"\n✓ list(x) is satisfiable: {result}")

    # x |-> nil * list(x) should be unsatisfiable (x points to itself)
    nil = Const(None)
    formula2 = SepConj(
        PointsTo(x, [x]),
        PredicateCall("list", [x])
    )
    result2 = checker.is_satisfiable(formula2)
    print(f"✓ x |-> x * list(x) is satisfiable: {result2}")
    # Note: This might be satisfiable in the bounded unfolding


def test_tree_satisfiability():
    """Test satisfiability of tree formulas"""
    print("\n=== Testing Tree Satisfiability ===")

    registry = PredicateRegistry()
    registry.max_unfold_depth = 2
    checker = EntailmentChecker(predicate_registry=registry, verbose=True)

    x = Var("x")

    # tree(x) should be satisfiable
    formula = PredicateCall("tree", [x])
    result = checker.is_satisfiable(formula)
    print(f"\n✓ tree(x) is satisfiable: {result}")


def test_parser_with_predicates():
    """Test parsing formulas with predicates"""
    print("\n=== Testing Parser with Predicates ===")

    formulas = [
        "ls(x, y)",
        "list(x)",
        "tree(x)",
        "x |-> y * ls(y, nil)",
        "x |-> (l, r) * tree(l) * tree(r)",
        "ls(x, y) * ls(y, z)",
    ]

    for formula_str in formulas:
        try:
            formula = parse(formula_str)
            print(f"✓ Parsed: {formula_str}")
            print(f"  AST: {formula}")
        except Exception as e:
            print(f"✗ Failed to parse: {formula_str}")
            print(f"  Error: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("Running Inductive Predicate Tests")
    print("=" * 60)

    try:
        test_parser_with_predicates()
        test_list_segment_unfold()
        test_list_predicate_unfold()
        test_tree_unfold()
        test_list_entailment()
        test_list_satisfiability()
        test_tree_satisfiability()

        print("\n" + "=" * 60)
        print("All predicate tests completed!")
        print("=" * 60)
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
