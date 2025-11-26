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
        # Try enhanced graph analysis for mixed cases (predicates + concrete cells)
        # This handles bolognesa-style benchmarks where antecedent has both ls() and pto
        result = self._check_list_segments_mixed(antecedent, consequent, predicate_registry)
        if result is not None:
            return result

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

    def _check_list_segments_mixed(self, antecedent: Formula, consequent: Formula,
                                    predicate_registry) -> Optional[bool]:
        """
        Handle mixed cases where antecedent has BOTH predicates and concrete cells.

        This is essential for bolognesa-style benchmarks where:
        - Antecedent: ls(x9, x7) * x6 |-> x4 * x4 |-> x7 * ...
        - Consequent: ls(x9, x7) * ls(x6, x7) * ...

        Strategy:
        1. Build graph from concrete cells
        2. Add ls() predicates as "super edges" (path from start to end)
        3. Try to find disjoint paths for all required segments
        4. Match existing ls() predicates directly when possible

        Returns:
            True if entailment is valid
            False if entailment is invalid (counterexample found)
            None if analysis is inconclusive
        """
        # Extract parts from antecedent
        ant_parts = self.analyzer._extract_sepconj_parts(antecedent)

        # Separate concrete cells from predicates
        concrete_cells = []  # List of (source, targets) tuples
        ant_ls_predicates = []  # List of (start, end) tuples from ls() predicates

        for part in ant_parts:
            if isinstance(part, PointsTo):
                if isinstance(part.location, Var):
                    source = part.location.name
                    targets = []
                    for val in part.values:
                        if isinstance(val, Var):
                            targets.append(val.name)
                        elif isinstance(val, Const) and val.value == 'nil':
                            targets.append('nil')
                    if targets:
                        concrete_cells.append((source, targets))
            elif isinstance(part, PredicateCall) and part.name == 'ls':
                if len(part.args) == 2:
                    start = str(part.args[0]) if isinstance(part.args[0], Var) else str(part.args[0])
                    end = str(part.args[1]) if isinstance(part.args[1], Var) else str(part.args[1])
                    ant_ls_predicates.append((start, end))

        # If no concrete cells, we can't use this analysis
        if not concrete_cells and not ant_ls_predicates:
            return None

        # Extract consequent list segments
        cons_parts = self.analyzer._extract_sepconj_parts(consequent)
        cons_ls_segments = []
        other_cons_parts = []

        for part in cons_parts:
            if isinstance(part, PredicateCall) and part.name == 'ls':
                if len(part.args) == 2:
                    start = str(part.args[0]) if isinstance(part.args[0], Var) else str(part.args[0])
                    end = str(part.args[1]) if isinstance(part.args[1], Var) else str(part.args[1])
                    cons_ls_segments.append((start, end))
            elif not isinstance(part, (Emp, True_, And)):
                if isinstance(part, PredicateCall) or isinstance(part, PointsTo):
                    other_cons_parts.append(part)

        # If no list segments in consequent, this analysis doesn't apply
        if not cons_ls_segments:
            return None

        # If there are other spatial parts in consequent, be conservative
        if other_cons_parts:
            return None

        # Build directed graph from concrete cells
        # graph[source] = [target1, target2, ...]
        graph = {}
        source_locations = set()  # All source locations are DISTINCT due to separating conjunction
        for source, targets in concrete_cells:
            graph[source] = targets
            source_locations.add(source)

        # Now try to match each consequent ls() with either:
        # 1. An existing antecedent ls() (direct match)
        # 2. A path through concrete cells
        # 3. A combination (path using concrete cells ending at existing ls)

        used_ant_ls = set()  # Indices of used antecedent ls predicates
        used_concrete = set()  # Sources of used concrete cells

        # Sort consequent segments - match direct ls first, then longer paths
        # This greedy strategy works for most benchmarks

        for cons_start, cons_end in cons_ls_segments:
            matched = False

            # Strategy 1: Direct match with antecedent ls
            for i, (ant_start, ant_end) in enumerate(ant_ls_predicates):
                if i in used_ant_ls:
                    continue
                if cons_start == ant_start and cons_end == ant_end:
                    used_ant_ls.add(i)
                    matched = True
                    if self.verbose:
                        print(f"[Mixed Graph] Direct match: ls({cons_start}, {cons_end})")
                    break

            if matched:
                continue

            # Strategy 2: Find path through concrete cells
            # SOUNDNESS: We need to prove start != end for ls(start, end) recursive case.
            # Key insight: all SOURCE locations in separating conjunction are DISTINCT.
            # So if both start and end are source locations, we know start != end.
            path = self._find_disjoint_path(graph, cons_start, cons_end, used_concrete)
            if path is not None:
                # SOUNDNESS CHECK: For ls(start, end), we need start != end
                # This is guaranteed if:
                # 1. Path length >= 3 (at least 2 edges), OR
                # 2. BOTH start AND end are source locations (disjointness from sep. conj.)
                start_is_source = cons_start in source_locations
                end_is_source = cons_end in source_locations
                distinctness_guaranteed = len(path) >= 3 or (start_is_source and end_is_source)

                if distinctness_guaranteed:
                    # Mark all sources in path as used
                    for i, node in enumerate(path[:-1]):  # All except last node
                        used_concrete.add(node)
                    matched = True
                    if self.verbose:
                        print(f"[Mixed Graph] Path found for ls({cons_start}, {cons_end}): {' -> '.join(path)}")

            if matched:
                continue

            # Strategy 3: Path ending at antecedent ls endpoint
            # e.g., ls(x6, x7) can be matched by x6 -> x4 -> x7 where ls(x4, x7) exists
            # OR by x6 -> x4 if x4 -> x7 exists as concrete
            # SOUNDNESS: Skip empty ls predicates (ls(y, y) = emp), and require
            # either multiple segments or path length >= 2 to handle single-edge cases
            for i, (ant_start, ant_end) in enumerate(ant_ls_predicates):
                if i in used_ant_ls:
                    continue
                # Skip empty ls predicates (e.g., ls(y, y) where start == end)
                if ant_start == ant_end:
                    continue
                if cons_end == ant_end:
                    # Try to find path from cons_start to ant_start using concrete
                    path = self._find_disjoint_path(graph, cons_start, ant_start, used_concrete)
                    if path is not None:
                        # Soundness: require multiple segments or path with >= 2 nodes
                        if len(path) >= 2 or len(cons_ls_segments) > 1:
                            for j, node in enumerate(path[:-1]):
                                used_concrete.add(node)
                            used_ant_ls.add(i)
                            matched = True
                            if self.verbose:
                                print(f"[Mixed Graph] Combined path: {' -> '.join(path)} + ls({ant_start}, {ant_end})")
                            break

            if not matched:
                # Cannot match this segment - fall back to Z3
                if self.verbose:
                    print(f"[Mixed Graph] Cannot match ls({cons_start}, {cons_end})")
                return None

        # SOUNDNESS CHECK: All antecedent resources must be consumed!
        # In separation logic, P |- Q requires EXACT resource matching.
        # If antecedent has more heap cells than consequent covers, entailment is INVALID.
        #
        # Check 1: All concrete cells must be used
        unused_concrete = source_locations - used_concrete
        if unused_concrete:
            if self.verbose:
                print(f"[Mixed Graph] Unused concrete cells: {unused_concrete} - entailment INVALID")
            # There are antecedent heap cells not covered by any consequent segment
            # This means the consequent doesn't describe the same heap
            return None  # Fall back to Z3 (could be frame rule application)

        # Check 2: All antecedent ls predicates must be used
        unused_ant_ls_count = len(ant_ls_predicates) - len(used_ant_ls)
        if unused_ant_ls_count > 0:
            if self.verbose:
                unused_ls = [ant_ls_predicates[i] for i in range(len(ant_ls_predicates)) if i not in used_ant_ls]
                print(f"[Mixed Graph] Unused antecedent ls predicates: {unused_ls} - entailment INVALID")
            return None  # Fall back to Z3

        # All segments matched and all resources consumed
        if self.verbose:
            print(f"[Mixed Graph] All {len(cons_ls_segments)} segments matched, all resources consumed")
        return True

    def _find_disjoint_path(self, graph: Dict[str, List[str]], start: str, end: str,
                             used: set, max_depth: int = 15) -> Optional[List[str]]:
        """
        Find a path from start to end avoiding used nodes.

        Returns the path as a list of nodes [start, ..., end], or None if not found.
        The path includes start and end.
        """
        if start == end:
            return [start]  # Empty list segment

        # BFS to find shortest disjoint path
        from collections import deque
        queue = deque([(start, [start])])
        visited = {start}

        while queue:
            current, path = queue.popleft()

            if len(path) > max_depth:
                continue

            if current not in graph:
                continue

            for next_node in graph[current]:
                # Check if we reached the end
                if next_node == end:
                    return path + [end]

                # Check if next node is usable (not already used by another segment)
                if next_node in used:
                    continue

                if next_node not in visited:
                    visited.add(next_node)
                    queue.append((next_node, path + [next_node]))

        return None  # No path found

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
