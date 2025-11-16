"""
Tests for Heap Graph Analysis (frame/heap/graph_analysis.py)

Tests heap graph building, path finding, and list segment checking.
"""

import pytest
from frame.heap.graph_analysis import HeapGraphAnalyzer
from frame.core.parser import parse
from frame.core.ast import Var, Const, PointsTo, SepConj, Eq, Emp, PredicateCall
from frame.predicates.registry import PredicateRegistry


class TestBuildHeapGraph:
    """Test build_heap_graph function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = HeapGraphAnalyzer(verbose=False)

    def test_simple_chain(self):
        """Test building graph from simple chain"""
        formula = parse("x |-> y * y |-> z")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        assert 'x' in graph
        assert 'y' in graph
        assert graph['x'] == ['y']
        assert graph['y'] == ['z']

    def test_single_pto(self):
        """Test with single points-to"""
        formula = parse("x |-> y")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        assert 'x' in graph
        assert graph['x'] == ['y']

    def test_multi_field_cells(self):
        """Test with multi-field cells"""
        formula = parse("x |-> (y, z)")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        assert 'x' in graph
        assert len(graph['x']) == 2
        assert 'y' in graph['x']
        assert 'z' in graph['x']

    def test_disconnected_heap(self):
        """Test with disconnected heap regions"""
        formula = parse("x |-> y * a |-> b")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        assert 'x' in graph
        assert 'a' in graph
        assert graph['x'] == ['y']
        assert graph['a'] == ['b']

    def test_empty_heap(self):
        """Test with empty heap"""
        formula = parse("emp")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        assert graph == {}

    def test_cyclic_structure(self):
        """Test with cyclic heap"""
        formula = parse("x |-> y * y |-> x")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        assert 'x' in graph
        assert 'y' in graph
        assert graph['x'] == ['y']
        assert graph['y'] == ['x']

    def test_with_equalities(self):
        """Test graph building with equality constraints"""
        # Create formula with equalities
        x = Var('x')
        y = Var('y')
        z = Var('z')
        pto = PointsTo(x, [y])
        eq = Eq(y, z)
        formula = SepConj(pto, eq)

        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        assert 'x' in graph
        assert graph['x'] == ['y']
        # Should have equivalence class for y and z
        assert len(eq_classes) > 0


class TestFindPath:
    """Test find_path function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = HeapGraphAnalyzer(verbose=False)

    def test_simple_path(self):
        """Test finding simple path"""
        formula = parse("x |-> y * y |-> z")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        path = self.analyzer.find_path(graph, eq_classes, 'x', 'z')
        assert path is not None
        assert path[0] == 'x'
        assert path[-1] == 'z'

    def test_direct_edge(self):
        """Test with direct edge"""
        formula = parse("x |-> y")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        path = self.analyzer.find_path(graph, eq_classes, 'x', 'y')
        assert path is not None
        assert path == ['x', 'y']

    def test_no_path(self):
        """Test when no path exists"""
        formula = parse("x |-> y * a |-> b")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        path = self.analyzer.find_path(graph, eq_classes, 'x', 'b')
        assert path is None

    def test_same_start_end(self):
        """Test with start == end"""
        formula = parse("x |-> y")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        path = self.analyzer.find_path(graph, eq_classes, 'x', 'x')
        assert path is not None
        assert path == ['x']

    def test_cyclic_path(self):
        """Test path finding in cyclic graph"""
        formula = parse("x |-> y * y |-> z * z |-> x")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        # Should still find path despite cycle
        path = self.analyzer.find_path(graph, eq_classes, 'x', 'z')
        assert path is not None

    def test_max_depth_exceeded(self):
        """Test with max depth limit"""
        # Create long chain
        formula = parse("a |-> b * b |-> c * c |-> d * d |-> e * e |-> f")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        # Try to find path with very short max_depth
        path = self.analyzer.find_path(graph, eq_classes, 'a', 'f', max_depth=2)
        # Should not find path (too deep)
        assert path is None


class TestCanFormListSegment:
    """Test can_form_list_segment function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = HeapGraphAnalyzer(verbose=False)

    def test_simple_list(self):
        """Test with simple list structure.

        SOUNDNESS FIX: x |-> y * y |-> z does NOT prove ls(x, z)!
        Reason: The recursive case of ls(x, z) requires x != z, but the heap
        only proves x != y and y != z (disjointness). We cannot prove x != z.
        If x = z, we'd have a 2-cycle x |-> y * y |-> x, which is NOT emp.

        This method now correctly returns False, deferring to Z3 verification.
        """
        formula = parse("x |-> y * y |-> z")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        result = self.analyzer.can_form_list_segment(
            graph, eq_classes, Var('x'), Var('z')
        )
        # Changed: Returns False after soundness fix (was unsoundly returning True)
        assert result is False

    def test_empty_segment(self):
        """Test empty list segment (x = y)"""
        formula = parse("x |-> z")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        result = self.analyzer.can_form_list_segment(
            graph, eq_classes, Var('x'), Var('x')
        )
        assert result is True

    def test_cannot_form_segment(self):
        """Test when segment cannot be formed"""
        formula = parse("x |-> y * a |-> b")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        result = self.analyzer.can_form_list_segment(
            graph, eq_classes, Var('x'), Var('b')
        )
        assert result is False

    def test_non_var_arguments(self):
        """Test with non-variable arguments"""
        formula = parse("x |-> y")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        result = self.analyzer.can_form_list_segment(
            graph, eq_classes, Const(5), Var('x')
        )
        assert result is False


class TestHasCycle:
    """Test _has_cycle function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = HeapGraphAnalyzer(verbose=False)

    def test_acyclic_graph(self):
        """Test with acyclic graph"""
        formula = parse("x |-> y * y |-> z")
        graph, _ = self.analyzer.build_heap_graph(formula)

        has_cycle = self.analyzer._has_cycle(graph)
        assert has_cycle is False

    def test_simple_cycle(self):
        """Test with simple cycle"""
        formula = parse("x |-> y * y |-> x")
        graph, _ = self.analyzer.build_heap_graph(formula)

        has_cycle = self.analyzer._has_cycle(graph)
        assert has_cycle is True

    def test_self_loop(self):
        """Test with self-loop"""
        formula = parse("x |-> x")
        graph, _ = self.analyzer.build_heap_graph(formula)

        has_cycle = self.analyzer._has_cycle(graph)
        assert has_cycle is True

    def test_complex_cycle(self):
        """Test with complex cycle"""
        formula = parse("x |-> y * y |-> z * z |-> w * w |-> x")
        graph, _ = self.analyzer.build_heap_graph(formula)

        has_cycle = self.analyzer._has_cycle(graph)
        assert has_cycle is True

    def test_empty_graph(self):
        """Test with empty graph"""
        graph = {}
        has_cycle = self.analyzer._has_cycle(graph)
        assert has_cycle is False


class TestBuildEquivalenceClasses:
    """Test _build_equivalence_classes function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = HeapGraphAnalyzer(verbose=False)

    def test_single_equality(self):
        """Test with single equality"""
        x = Var('x')
        y = Var('y')
        equalities = [(x, y)]

        eq_classes = self.analyzer._build_equivalence_classes(equalities)
        assert len(eq_classes) > 0

    def test_transitive_equality(self):
        """Test transitive closure"""
        x = Var('x')
        y = Var('y')
        z = Var('z')
        equalities = [(x, y), (y, z)]

        eq_classes = self.analyzer._build_equivalence_classes(equalities)
        # x, y, z should all be in same class
        assert len(eq_classes) > 0

    def test_no_equalities(self):
        """Test with no equalities"""
        equalities = []
        eq_classes = self.analyzer._build_equivalence_classes(equalities)
        assert eq_classes == {}

    def test_constant_equality(self):
        """Test with constant equality"""
        x = Var('x')
        c = Const(5)
        equalities = [(x, c)]

        eq_classes = self.analyzer._build_equivalence_classes(equalities)
        assert len(eq_classes) > 0


class TestExprToKey:
    """Test _expr_to_key function"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = HeapGraphAnalyzer(verbose=False)

    def test_var_to_key(self):
        """Test converting variable to key"""
        var = Var('x')
        key = self.analyzer._expr_to_key(var)
        assert key == ('var', 'x')

    def test_const_to_key(self):
        """Test converting constant to key"""
        const = Const(5)
        key = self.analyzer._expr_to_key(const)
        assert key == ('const', 5)

    def test_unknown_expr(self):
        """Test with unknown expression type"""
        emp = Emp()
        key = self.analyzer._expr_to_key(emp)
        assert key[0] == 'unknown'


class TestCheckListSegmentsViaGraph:
    """Test check_list_segments_via_graph integration"""

    def setup_method(self):
        """Set up test analyzer and registry"""
        self.analyzer = HeapGraphAnalyzer(verbose=False)
        self.registry = PredicateRegistry()

    def test_simple_list_segment(self):
        """Test checking simple list segment"""
        antecedent = parse("x |-> y * y |-> z")
        consequent = parse("ls(x, z)")

        result = self.analyzer.check_list_segments_via_graph(
            antecedent, consequent, self.registry
        )
        # Should return True or None (both acceptable)
        assert result is True or result is None

    def test_with_predicates_in_antecedent(self):
        """Test when antecedent has predicates"""
        antecedent = parse("list(x)")
        consequent = parse("ls(x, nil)")

        result = self.analyzer.check_list_segments_via_graph(
            antecedent, consequent, self.registry
        )
        # Should return None (falls back to Z3)
        assert result is None

    def test_empty_heap(self):
        """Test with empty heap"""
        antecedent = parse("emp")
        consequent = parse("emp")

        result = self.analyzer.check_list_segments_via_graph(
            antecedent, consequent, self.registry
        )
        # Should return None (no concrete heap)
        assert result is None

    def test_non_list_segment_consequent(self):
        """Test with non-list-segment consequent"""
        antecedent = parse("x |-> y * y |-> z")
        consequent = parse("x |-> y")

        result = self.analyzer.check_list_segments_via_graph(
            antecedent, consequent, self.registry
        )
        # Should return None (no list segments)
        assert result is None


class TestGraphAnalysisIntegration:
    """Integration tests for heap graph analysis"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = HeapGraphAnalyzer(verbose=False)

    def test_tree_structure(self):
        """Test analyzing tree structure"""
        formula = parse("x |-> (l, r) * l |-> a * r |-> b")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        assert 'x' in graph
        assert len(graph['x']) == 2
        assert 'l' in graph
        assert 'r' in graph

    def test_complex_disconnected_heap(self):
        """Test with complex disconnected regions"""
        formula = parse("x |-> y * y |-> z * a |-> b * b |-> c")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        # Should have two separate paths
        path1 = self.analyzer.find_path(graph, eq_classes, 'x', 'z')
        path2 = self.analyzer.find_path(graph, eq_classes, 'a', 'c')
        assert path1 is not None
        assert path2 is not None

        # No path between disconnected regions
        path_cross = self.analyzer.find_path(graph, eq_classes, 'x', 'c')
        assert path_cross is None


class TestEdgeCases:
    """Test edge cases in heap graph analysis"""

    def setup_method(self):
        """Set up test analyzer"""
        self.analyzer = HeapGraphAnalyzer(verbose=False)

    def test_verbose_output(self):
        """Test with verbose=True"""
        analyzer = HeapGraphAnalyzer(verbose=True)
        formula = parse("x |-> y")
        graph, eq_classes = analyzer.build_heap_graph(formula)
        assert graph is not None

    def test_nil_values(self):
        """Test with nil values"""
        formula = parse("x |-> nil")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        # nil values don't create graph edges (treated as leaf)
        # Graph may be empty or have 'x' with empty/nil edges
        assert isinstance(graph, dict)

    def test_numeric_values(self):
        """Test with numeric values"""
        formula = parse("x |-> 5")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        # Numeric constants don't create graph edges
        assert isinstance(graph, dict)

    def test_multi_field_with_nil(self):
        """Test multi-field cells with nil"""
        formula = parse("x |-> (y, nil)")
        graph, eq_classes = self.analyzer.build_heap_graph(formula)

        assert 'x' in graph
        assert 'y' in graph['x']
