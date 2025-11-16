"""
Simple unit tests for heap graph analysis (no pytest required)
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from frame.heap.graph import HeapGraph, build_heap_graph, Chain, DLLPattern
from frame.core.ast import PointsTo, SepConj, Var, Const


def test_add_node():
    """Test adding nodes to the graph"""
    graph = HeapGraph()
    node = graph.add_node("x")
    assert node.name == "x", f"Expected name 'x', got {node.name}"
    assert "x" in graph.nodes, "Node 'x' not in graph"
    print("✓ test_add_node passed")


def test_add_edge():
    """Test adding edges between nodes"""
    graph = HeapGraph()
    graph.add_node("x")
    graph.add_node("y")
    graph.add_edge("x", "y", "next")

    assert len(graph.edges) == 1, f"Expected 1 edge, got {len(graph.edges)}"
    edge = graph.edges[0]
    assert edge.source == "x", f"Expected source 'x', got {edge.source}"
    assert edge.target == "y", f"Expected target 'y', got {edge.target}"
    assert edge.label == "next", f"Expected label 'next', got {edge.label}"
    print("✓ test_add_edge passed")


def test_get_successors():
    """Test getting successors of a node"""
    graph = HeapGraph()
    graph.add_node("x")
    graph.add_node("y")
    graph.add_node("z")
    graph.add_edge("x", "y", "next")
    graph.add_edge("x", "z", "prev")

    successors = graph.get_successors("x", "next")
    assert successors == ["y"], f"Expected ['y'], got {successors}"

    successors_prev = graph.get_successors("x", "prev")
    assert successors_prev == ["z"], f"Expected ['z'], got {successors_prev}"
    print("✓ test_get_successors passed")


def test_build_from_single_pto():
    """Test building graph from single points-to"""
    # x |-> y
    formula = PointsTo(Var("x"), Var("y"))
    graph = build_heap_graph(formula)

    assert "x" in graph.nodes, "Node 'x' not in graph"
    successors = graph.get_successors("x", "next")
    assert "y" in successors, f"Expected 'y' in successors, got {successors}"
    print("✓ test_build_from_single_pto passed")


def test_build_from_two_pto():
    """Test building graph from two points-to cells"""
    # x |-> y * y |-> z
    formula = SepConj(
        PointsTo(Var("x"), Var("y")),
        PointsTo(Var("y"), Var("z"))
    )
    graph = build_heap_graph(formula)

    assert "x" in graph.nodes, "Node 'x' not in graph"
    assert "y" in graph.nodes, "Node 'y' not in graph"

    # Check chain: x -> y -> z
    x_successors = graph.get_successors("x", "next")
    assert "y" in x_successors, f"Expected 'y' in x successors, got {x_successors}"

    y_successors = graph.get_successors("y", "next")
    assert "z" in y_successors, f"Expected 'z' in y successors, got {y_successors}"
    print("✓ test_build_from_two_pto passed")


def test_detect_single_node_chain():
    """Test detecting a single-node chain"""
    graph = HeapGraph()
    graph.add_node("x")

    chain = graph.chain_from("x")
    assert chain is not None, "Chain should not be None"
    assert chain.nodes == ["x"], f"Expected ['x'], got {chain.nodes}"
    assert chain.length == 1, f"Expected length 1, got {chain.length}"
    assert chain.head == "x", f"Expected head 'x', got {chain.head}"
    assert chain.tail == "x", f"Expected tail 'x', got {chain.tail}"
    print("✓ test_detect_single_node_chain passed")


def test_detect_two_node_chain():
    """Test detecting a two-node chain"""
    graph = HeapGraph()
    graph.add_node("x")
    graph.add_node("y")
    graph.add_edge("x", "y", "next")

    chain = graph.chain_from("x")
    assert chain is not None, "Chain should not be None"
    assert chain.nodes == ["x", "y"], f"Expected ['x', 'y'], got {chain.nodes}"
    assert chain.length == 2, f"Expected length 2, got {chain.length}"
    assert chain.head == "x", f"Expected head 'x', got {chain.head}"
    assert chain.tail == "y", f"Expected tail 'y', got {chain.tail}"
    print("✓ test_detect_two_node_chain passed")


def test_detect_three_node_chain():
    """Test detecting a three-node chain"""
    graph = HeapGraph()
    graph.add_node("x")
    graph.add_node("y")
    graph.add_node("z")
    graph.add_edge("x", "y", "next")
    graph.add_edge("y", "z", "next")

    chain = graph.chain_from("x")
    assert chain is not None, "Chain should not be None"
    assert chain.nodes == ["x", "y", "z"], f"Expected ['x', 'y', 'z'], got {chain.nodes}"
    assert chain.length == 3, f"Expected length 3, got {chain.length}"
    print("✓ test_detect_three_node_chain passed")


def test_detect_no_chain_with_branching():
    """Test that branching is detected (not a linear chain)"""
    graph = HeapGraph()
    graph.add_node("x")
    graph.add_node("y")
    graph.add_node("z")
    graph.add_edge("x", "y", "next")
    graph.add_edge("x", "z", "next")  # Branching

    chain = graph.chain_from("x")
    # Should return None because of branching
    assert chain is None, f"Expected None for branching pattern, got {chain}"
    print("✓ test_detect_no_chain_with_branching passed")


def test_list_segment_pattern():
    """Test detecting list segment pattern from pto cells"""
    # x |-> y * y |-> z * z |-> nil
    formula = SepConj(
        SepConj(
            PointsTo(Var("x"), Var("y")),
            PointsTo(Var("y"), Var("z"))
        ),
        PointsTo(Var("z"), Const(None))
    )

    graph = build_heap_graph(formula)
    chain = graph.chain_from("x")

    assert chain is not None, "Chain should not be None"
    assert chain.head == "x", f"Expected head 'x', got {chain.head}"
    assert len(chain.nodes) >= 3, f"Expected at least 3 nodes, got {len(chain.nodes)}"
    print("✓ test_list_segment_pattern passed")


def run_tests(verbose=False):
    """Run all tests"""
    if verbose:
        print("Running HeapGraph tests...\n")

    tests = [
        test_add_node,
        test_add_edge,
        test_get_successors,
        test_build_from_single_pto,
        test_build_from_two_pto,
        test_detect_single_node_chain,
        test_detect_two_node_chain,
        test_detect_three_node_chain,
        test_detect_no_chain_with_branching,
        test_list_segment_pattern,
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
            failed += 1

    if verbose:
        print(f"\n{'='*60}")
        print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
        print(f"{'='*60}")

    return passed, failed


if __name__ == "__main__":
    passed, failed = run_tests(verbose=True)
    exit(0 if failed == 0 else 1)
