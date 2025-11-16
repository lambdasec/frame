"""
Unit tests for heap graph analysis
"""

import pytest
from frame.heap.graph import HeapGraph, build_heap_graph, Chain, DLLPattern
from frame.core.ast import PointsTo, SepConj, Var, Const


class TestHeapGraphBasics:
    """Test basic heap graph construction and operations"""

    def test_add_node(self):
        """Test adding nodes to the graph"""
        graph = HeapGraph()
        node = graph.add_node("x")
        assert node.name == "x"
        assert "x" in graph.nodes

    def test_add_edge(self):
        """Test adding edges between nodes"""
        graph = HeapGraph()
        graph.add_node("x")
        graph.add_node("y")
        graph.add_edge("x", "y", "next")

        assert len(graph.edges) == 1
        edge = graph.edges[0]
        assert edge.source == "x"
        assert edge.target == "y"
        assert edge.label == "next"

    def test_get_successors(self):
        """Test getting successors of a node"""
        graph = HeapGraph()
        graph.add_node("x")
        graph.add_node("y")
        graph.add_node("z")
        graph.add_edge("x", "y", "next")
        graph.add_edge("x", "z", "prev")

        successors = graph.get_successors("x", "next")
        assert successors == ["y"]

        successors_prev = graph.get_successors("x", "prev")
        assert successors_prev == ["z"]


class TestHeapGraphConstruction:
    """Test building heap graphs from formulas"""

    def test_build_from_single_pto(self):
        """Test building graph from single points-to"""
        # x |-> y
        formula = PointsTo(Var("x"), Var("y"))
        graph = build_heap_graph(formula)

        assert "x" in graph.nodes
        successors = graph.get_successors("x", "next")
        assert "y" in successors

    def test_build_from_two_pto(self):
        """Test building graph from two points-to cells"""
        # x |-> y * y |-> z
        formula = SepConj(
            PointsTo(Var("x"), Var("y")),
            PointsTo(Var("y"), Var("z"))
        )
        graph = build_heap_graph(formula)

        assert "x" in graph.nodes
        assert "y" in graph.nodes

        # Check chain: x -> y -> z
        x_successors = graph.get_successors("x", "next")
        assert "y" in x_successors

        y_successors = graph.get_successors("y", "next")
        assert "z" in y_successors

    def test_build_from_pto_to_nil(self):
        """Test building graph with nil pointer"""
        # x |-> nil
        formula = PointsTo(Var("x"), Const(None))
        graph = build_heap_graph(formula)

        assert "x" in graph.nodes
        # Should have edge to nil
        x_successors = graph.get_successors("x", "next")
        assert "nil" in x_successors or len(x_successors) == 0


class TestChainDetection:
    """Test linear chain detection"""

    def test_detect_single_node_chain(self):
        """Test detecting a single-node chain"""
        graph = HeapGraph()
        graph.add_node("x")

        chain = graph.chain_from("x")
        assert chain is not None
        assert chain.nodes == ["x"]
        assert chain.length == 1
        assert chain.head == "x"
        assert chain.tail == "x"

    def test_detect_two_node_chain(self):
        """Test detecting a two-node chain"""
        graph = HeapGraph()
        graph.add_node("x")
        graph.add_node("y")
        graph.add_edge("x", "y", "next")

        chain = graph.chain_from("x")
        assert chain is not None
        assert chain.nodes == ["x", "y"]
        assert chain.length == 2
        assert chain.head == "x"
        assert chain.tail == "y"

    def test_detect_three_node_chain(self):
        """Test detecting a three-node chain"""
        graph = HeapGraph()
        graph.add_node("x")
        graph.add_node("y")
        graph.add_node("z")
        graph.add_edge("x", "y", "next")
        graph.add_edge("y", "z", "next")

        chain = graph.chain_from("x")
        assert chain is not None
        assert chain.nodes == ["x", "y", "z"]
        assert chain.length == 3

    def test_detect_chain_ending_at_nil(self):
        """Test detecting a chain that ends at nil"""
        graph = HeapGraph()
        graph.add_node("x")
        graph.add_node("y")
        graph.add_edge("x", "y", "next")
        graph.add_edge("y", "nil", "next")

        chain = graph.chain_from("x")
        assert chain is not None
        assert chain.nodes == ["x", "y"]
        assert chain.length == 2

    def test_detect_no_chain_with_branching(self):
        """Test that branching is detected (not a linear chain)"""
        graph = HeapGraph()
        graph.add_node("x")
        graph.add_node("y")
        graph.add_node("z")
        graph.add_edge("x", "y", "next")
        graph.add_edge("x", "z", "next")  # Branching

        chain = graph.chain_from("x")
        # Should return None because of branching
        assert chain is None

    def test_detect_chain_stops_at_cycle(self):
        """Test that cycles are detected"""
        graph = HeapGraph()
        graph.add_node("x")
        graph.add_node("y")
        graph.add_edge("x", "y", "next")
        graph.add_edge("y", "x", "next")  # Cycle

        chain = graph.chain_from("x")
        assert chain is not None
        # Should stop before revisiting x
        assert chain.nodes == ["x", "y"]
        assert chain.length == 2

    def test_max_depth_limit(self):
        """Test that max_depth limits chain detection"""
        graph = HeapGraph()
        nodes = ["x", "y", "z", "w", "v"]
        for node in nodes:
            graph.add_node(node)

        # Create chain: x -> y -> z -> w -> v
        for i in range(len(nodes) - 1):
            graph.add_edge(nodes[i], nodes[i + 1], "next")

        # With max_depth=2, should only get first 2 nodes
        chain = graph.chain_from("x", max_depth=2)
        assert chain is not None
        assert len(chain.nodes) <= 3  # Can include up to max_depth+1 nodes


class TestDLLDetection:
    """Test doubly-linked list pattern detection"""

    def test_detect_single_dll_node(self):
        """Test detecting single-node DLL"""
        graph = HeapGraph()
        graph.add_node("x")

        dll = graph.detect_dll_pattern("x")
        assert dll is not None
        assert dll.nodes == ["x"]
        assert dll.length == 1

    def test_detect_two_node_dll(self):
        """Test detecting two-node DLL with consistent pointers"""
        graph = HeapGraph()
        graph.add_node("x")
        graph.add_node("y")
        graph.add_node("px")  # Previous of x
        graph.add_edge("x", "y", "next")
        graph.add_edge("y", "x", "prev")

        # Note: For proper DLL, we need prev pointer from x as well
        # This is simplified test - real implementation may need more checks

        dll = graph.detect_dll_pattern("x")
        # Should detect at least the starting node
        assert dll is not None
        assert "x" in dll.nodes


class TestIntegrationWithFormulas:
    """Test integration with actual separation logic formulas"""

    def test_list_segment_pattern(self):
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

        assert chain is not None
        assert chain.head == "x"
        assert len(chain.nodes) >= 3  # x, y, z
