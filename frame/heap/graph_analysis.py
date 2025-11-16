"""
Heap Graph Analysis

Provides heap graph building and analysis for checking list segments
and other heap-based entailments.
"""

from typing import Optional, Dict, List, Tuple
from collections import deque
from frame.core.ast import (
    Formula, Expr, Var, Const, Emp, PointsTo, SepConj, And, Or,
    Eq, True_, PredicateCall
)
from frame.analysis.formula import FormulaAnalyzer


class HeapGraphAnalyzer:
    """Analyzes heap structures using graph representations"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.analyzer = FormulaAnalyzer()

    def build_heap_graph(self, formula: Formula) -> Tuple[Dict[str, List[str]], dict]:
        """
        Build a heap graph from points-to facts in a formula.

        Returns a dictionary mapping locations to lists of next locations.
        For x |-> y, we have graph[x] = [y].
        For x |-> (y, z), we have graph[x] = [y, z].
        """
        graph = {}
        equalities = []

        def extract(f):
            if isinstance(f, PointsTo):
                if isinstance(f.location, Var):
                    loc = f.location.name
                    next_locs = []
                    for val in f.values:
                        if isinstance(val, Var):
                            next_locs.append(val.name)
                    if next_locs:
                        graph[loc] = next_locs
            elif isinstance(f, Eq):
                equalities.append((f.left, f.right))
            elif isinstance(f, (SepConj, And)):
                extract(f.left)
                extract(f.right)
            elif isinstance(f, Or):
                # Don't process disjunctions - too complex
                pass

        extract(formula)

        # Add edges from equalities
        eq_classes = self._build_equivalence_classes(equalities)

        return graph, eq_classes

    def find_path(self, graph: Dict[str, List[str]], eq_classes: dict,
                   start: str, end: str, max_depth: int = 10) -> Optional[List[str]]:
        """
        Find a path from start to end in the heap graph.
        Returns the path as a list of locations, or None if no path exists.
        Handles equivalence classes from equalities.
        """
        # Check if start == end (through equalities)
        start_key = ('var', start)
        end_key = ('var', end)

        def find(x):
            if x not in eq_classes:
                return x
            if eq_classes[x] != x:
                eq_classes[x] = find(eq_classes[x])
            return eq_classes[x]

        if find(start_key) == find(end_key):
            return [start]  # Start and end are the same

        # BFS to find shortest path
        queue = deque([(start, [start])])
        visited = {start}

        while queue:
            current, path = queue.popleft()

            if len(path) > max_depth:
                continue

            # Get all locations equivalent to current
            current_key = ('var', current)
            equiv_locs = [loc for (typ, loc) in eq_classes.keys()
                         if typ == 'var' and find(('var', loc)) == find(current_key)]

            # Try all equivalent locations
            for equiv_loc in [current] + equiv_locs:
                if equiv_loc not in graph:
                    continue

                for next_loc in graph[equiv_loc]:
                    # Check if we reached the end
                    next_key = ('var', next_loc)
                    if find(next_key) == find(end_key):
                        return path + [next_loc]

                    if next_loc not in visited:
                        visited.add(next_loc)
                        queue.append((next_loc, path + [next_loc]))

        return None

    def can_form_list_segment(self, graph: Dict[str, List[str]], eq_classes: dict,
                                start: Expr, end: Expr) -> bool:
        """
        Check if we can form a list segment ls(start, end) from the heap graph.
        This is true if:
        1. start == end (empty list segment), OR
        2. There's a path of length >= 2 from start to end

        SOUNDNESS: With distinctness constraints (distinct in out), a single edge
        x->y cannot prove ls(x,y) because we can't prove x != y from just x->y.
        We need at least 2 edges to guarantee a proper list segment.
        """
        if not isinstance(start, Var) or not isinstance(end, Var):
            return False

        # Check if start == end
        start_key = ('var', start.name)
        end_key = ('var', end.name)

        def find(x):
            if x not in eq_classes:
                return x
            if eq_classes[x] != x:
                eq_classes[x] = find(eq_classes[x])
            return eq_classes[x]

        if find(start_key) == find(end_key):
            return True  # Empty list segment

        # Check if there's a path from start to end
        path = self.find_path(graph, eq_classes, start.name, end.name)

        # SOUNDNESS FIX: Require at least 2 edges (3 nodes) for distinctness constraints
        # A single edge x->y cannot prove ls(x,y) without proving x != y
        # Path = [node1, node2, ...], so len(path) = #nodes, #edges = len(path)-1
        # We need #edges >= 2, so len(path) >= 3
        #
        # CRITICAL: Even with path length >= 3, we can't prove ls(start, end) if start
        # and end might be the same variable! Example:
        #   x |-> y * y |-> z with x=z gives cycle [x, y, x] (length 3)
        #   But ls(x, x) requires emp, not 2 cells!
        #   The recursive case requires x != x (contradiction!)
        #
        # The heap structure only proves disjointness of adjacent nodes in the path,
        # not that start != end. We need to be MORE conservative:
        # - DISABLE heap graph heuristic entirely for soundness
        # - Let Z3 verification handle distinctness constraints properly
        #
        # TODO: To re-enable this safely, we'd need to:
        #   1. Build a distinctness oracle from heap disjointness
        #   2. Check if start != end can be proved from the oracle
        #   3. Only return True if we can prove the distinctness

        # For now, DISABLE this heuristic to maintain soundness
        return False  # Always fall back to Z3 verification

    def check_list_segments_via_graph(self, antecedent: Formula, consequent: Formula,
                                       predicate_registry, unfold_depth: int = 3) -> Optional[bool]:
        """
        Use heap graph analysis to check if list segments can be formed.

        Returns:
            True if entailment is valid based on graph analysis
            False if entailment is invalid based on graph analysis
            None if graph analysis is inconclusive
        """
        # Only use heap graph for purely concrete heaps (no predicates in antecedent)
        # Mixed cases (predicates + concrete) are too complex
        if self.analyzer._has_predicates(antecedent):
            return None  # Fall back to Z3

        # First, unfold any predicates in the antecedent to get concrete heap
        antecedent_unfolded = predicate_registry.unfold_predicates(
            antecedent,
            depth=unfold_depth,
            adaptive=False
        )

        # Build heap graph from unfolded antecedent
        graph, eq_classes = self.build_heap_graph(antecedent_unfolded)

        if not graph:
            return None  # No concrete heap, can't use graph analysis

        # NOTE: Removed cycle check - cycles are fine for list segments!
        # We can still find paths in cyclic graphs (e.g., ls(x, y) in a larger cycle).
        # The path-finding algorithm handles cycles correctly with visited sets.

        # Extract list segment predicates from consequent
        cons_parts = self.analyzer._extract_sepconj_parts(consequent)
        list_segments = []
        other_parts = []

        for part in cons_parts:
            if isinstance(part, PredicateCall) and part.name == 'ls':
                if len(part.args) == 2:
                    list_segments.append((part.args[0], part.args[1]))
            elif not isinstance(part, (Emp, True_, And)):
                # Count only spatial parts
                if isinstance(part, PredicateCall) or isinstance(part, PointsTo):
                    other_parts.append(part)

        # If no list segments in consequent, graph analysis doesn't apply
        if not list_segments:
            return None

        # Only apply if consequent is mostly/purely list segments
        if len(other_parts) > len(list_segments):
            return None

        # Check if all required list segments can be formed from the heap graph
        for start, end in list_segments:
            if not self.can_form_list_segment(graph, eq_classes, start, end):
                if self.verbose:
                    print(f"Cannot form list segment ls({start}, {end}) from heap graph")
                # Fall back to Z3
                return None

        # All list segments can be formed from the heap graph
        if self.verbose:
            print(f"Heap graph: all {len(list_segments)} segment(s) can be formed")
        return True

    def _has_cycle(self, graph: Dict[str, List[str]]) -> bool:
        """
        Check if the heap graph contains any cycles using DFS.
        Returns True if there's a cycle, False otherwise.
        """
        visited = set()
        rec_stack = set()

        def dfs(node: str) -> bool:
            if node in rec_stack:
                return True  # Found a cycle
            if node in visited:
                return False

            visited.add(node)
            rec_stack.add(node)

            # Follow all outgoing edges
            if node in graph:
                for next_node in graph[node]:
                    if dfs(next_node):
                        return True

            rec_stack.remove(node)
            return False

        # Check for cycles starting from each node
        for node in graph.keys():
            if node not in visited:
                if dfs(node):
                    return True

        return False

    def _build_equivalence_classes(self, equalities):
        """Build equivalence classes from equality assertions"""
        # Use union-find structure
        parent = {}

        def find(x):
            if x not in parent:
                parent[x] = x
                return x
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Process all equalities
        for left, right in equalities:
            left_key = self._expr_to_key(left)
            right_key = self._expr_to_key(right)
            union(left_key, right_key)

        return parent

    def _expr_to_key(self, expr):
        """Convert expression to hashable key"""
        if isinstance(expr, Var):
            return ('var', expr.name)
        elif isinstance(expr, Const):
            return ('const', expr.value)
        else:
            return ('unknown', str(expr))
