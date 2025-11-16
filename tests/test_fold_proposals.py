"""
Test fold proposal system
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from frame.heap.graph import (
    HeapGraph, build_heap_graph, propose_folds, FoldProposal
)
from frame.core.ast import PointsTo, SepConj, Var, Const


def test_propose_list_fold():
    """Test proposing a list fold from chain"""
    # x |-> y * y |-> nil
    formula = SepConj(
        PointsTo(Var("x"), [Var("y")]),
        PointsTo(Var("y"), [Const(None)])
    )

    graph = build_heap_graph(formula)
    pto_atoms = [
        PointsTo(Var("x"), [Var("y")]),
        PointsTo(Var("y"), [Const(None)])
    ]

    proposals = propose_folds(graph, pto_atoms)

    print(f"Found {len(proposals)} proposals:")
    for i, prop in enumerate(proposals):
        print(f"  {i+1}. {prop.predicate_name}({', '.join(str(a) for a in prop.args)}) "
              f"[confidence: {prop.confidence}]")

    assert len(proposals) > 0, "Should propose at least one fold"

    # Should propose list(x) since it ends at nil
    list_proposals = [p for p in proposals if p.predicate_name == "list"]
    assert len(list_proposals) > 0, "Should propose list(x) for chain ending at nil"

    print("✓ test_propose_list_fold passed")


def test_propose_ls_fold():
    """Test proposing list segment fold"""
    # x |-> y * y |-> z
    formula = SepConj(
        PointsTo(Var("x"), [Var("y")]),
        PointsTo(Var("y"), [Var("z")])
    )

    graph = build_heap_graph(formula)
    pto_atoms = [
        PointsTo(Var("x"), [Var("y")]),
        PointsTo(Var("y"), [Var("z")])
    ]

    proposals = propose_folds(graph, pto_atoms)

    print(f"\nFound {len(proposals)} proposals:")
    for i, prop in enumerate(proposals):
        print(f"  {i+1}. {prop.predicate_name}({', '.join(str(a) for a in prop.args)}) "
              f"[confidence: {prop.confidence}]")

    assert len(proposals) > 0, "Should propose at least one fold"

    # Should propose ls(x, z)
    ls_proposals = [p for p in proposals if p.predicate_name == "ls"]
    assert len(ls_proposals) > 0, "Should propose ls(x, z) for chain"

    print("✓ test_propose_ls_fold passed")


def test_propose_single_cell_fold():
    """Test proposing fold for single cell"""
    # x |-> y
    formula = PointsTo(Var("x"), [Var("y")])

    graph = build_heap_graph(formula)
    pto_atoms = [PointsTo(Var("x"), [Var("y")])]

    proposals = propose_folds(graph, pto_atoms)

    print(f"\nFound {len(proposals)} proposals for single cell:")
    for i, prop in enumerate(proposals):
        print(f"  {i+1}. {prop.predicate_name}({', '.join(str(a) for a in prop.args)}) "
              f"[confidence: {prop.confidence}]")

    # May or may not propose something for single cell
    # This is okay - just verify it doesn't crash

    print("✓ test_propose_single_cell_fold passed")


def run_tests(verbose=False):
    """Run all tests"""
    if verbose:
        print("Running fold proposal tests...\n")

    tests = [
        test_propose_list_fold,
        test_propose_ls_fold,
        test_propose_single_cell_fold,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
            if verbose:
                print(f"✓ {test.__name__}")
        except AssertionError as e:
            print(f"✗ {test.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} error: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            failed += 1

    if verbose:
        print(f"\n{'='*60}")
        print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
        print(f"{'='*60}")

    return passed, failed


if __name__ == "__main__":
    passed, failed = run_tests(verbose=True)
    exit(0 if failed == 0 else 1)
