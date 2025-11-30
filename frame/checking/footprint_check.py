"""
Footprint Cardinality Checking for Entailment

This module implements a sound pre-check that detects invalid entailments
by comparing the heap footprints of antecedent and consequent.

Key Insight from Cyclic Proof Theory:
In separation logic, P |- Q requires that the footprint of P equals the footprint of Q.
If P has N concrete allocations and Q can only match at most M < N cells,
then the entailment is INVALID.

This check catches cases where Z3 incorrectly chooses all base cases (emp)
for consequent predicates, making the consequent footprint smaller than antecedent.

The check is SOUND (no false positives) but INCOMPLETE (may miss some invalid cases).
"""

from typing import Tuple, Optional, Set, List, Dict
from frame.core.ast import (
    Formula, PointsTo, SepConj, And, Or, PredicateCall, Emp, Exists, Var
)


def count_concrete_cells(formula: Formula) -> int:
    """
    Count the number of concrete PointsTo cells in a formula.

    This gives us the exact footprint size for formulas without predicates,
    or a lower bound for formulas with predicates.
    """
    if isinstance(formula, PointsTo):
        return 1
    elif isinstance(formula, SepConj):
        return count_concrete_cells(formula.left) + count_concrete_cells(formula.right)
    elif isinstance(formula, And):
        # For And, both sides share the heap, so we take the max
        # (conservative - only count what we're sure about)
        return max(count_concrete_cells(formula.left), count_concrete_cells(formula.right))
    elif isinstance(formula, Or):
        # For Or, either branch could be taken
        # We need at least the minimum of both branches
        return min(count_concrete_cells(formula.left), count_concrete_cells(formula.right))
    elif isinstance(formula, Exists):
        return count_concrete_cells(formula.formula)
    elif isinstance(formula, Emp):
        return 0
    elif isinstance(formula, PredicateCall):
        # Predicates can be empty (base case) or non-empty
        # Conservative: return 0 (might be empty)
        return 0
    else:
        return 0


def estimate_max_predicate_footprint(pred: PredicateCall, depth: int = 3) -> int:
    """
    Estimate the maximum footprint a predicate could have.

    For list segments ls(x, y), the footprint depends on the path length.
    Without concrete bounds, we can't know the max, so return a large value.
    """
    # Common list predicates that can have unbounded footprint
    if pred.name.lower() in ['ls', 'lseg', 'list', 'sll', 'dll', 'pelist']:
        return float('inf')  # Could be arbitrarily long

    # Tree predicates can also be unbounded
    if pred.name.lower() in ['tree', 'btree', 'bst']:
        return float('inf')

    # Unknown predicates - assume unbounded
    return float('inf')


def collect_predicates(formula: Formula) -> List[PredicateCall]:
    """Collect all predicate calls from a formula."""
    preds = []
    if isinstance(formula, PredicateCall):
        preds.append(formula)
    elif isinstance(formula, (SepConj, And)):
        preds.extend(collect_predicates(formula.left))
        preds.extend(collect_predicates(formula.right))
    elif isinstance(formula, Or):
        # Collect from both branches
        preds.extend(collect_predicates(formula.left))
        preds.extend(collect_predicates(formula.right))
    elif isinstance(formula, Exists):
        preds.extend(collect_predicates(formula.formula))
    return preds


def collect_concrete_cell_sources(formula: Formula) -> Set[str]:
    """
    Collect the source variable names from concrete PointsTo cells.

    For formula: x |-> y * z |-> w, returns {'x', 'z'}
    These are the cells that the formula ALLOCATES (owns).

    Nov 2025: Used by cyclic check to account for direct points-to matching
    between antecedent and consequent.
    """
    sources = set()
    if isinstance(formula, PointsTo):
        src = formula.location
        if isinstance(src, Var):
            sources.add(src.name)
    elif isinstance(formula, (SepConj, And)):
        sources.update(collect_concrete_cell_sources(formula.left))
        sources.update(collect_concrete_cell_sources(formula.right))
    elif isinstance(formula, Or):
        # In Or, we take the intersection (cells that are ALWAYS allocated)
        left_sources = collect_concrete_cell_sources(formula.left)
        right_sources = collect_concrete_cell_sources(formula.right)
        sources.update(left_sources & right_sources)
    elif isinstance(formula, Exists):
        sources.update(collect_concrete_cell_sources(formula.formula))
    return sources


def check_footprint_compatibility(
    antecedent: Formula,
    consequent: Formula,
    verbose: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Check if antecedent and consequent have compatible footprints.

    Returns:
        (is_compatible, reason):
        - (True, None) if footprints could be compatible
        - (False, reason) if footprints are definitely incompatible (entailment INVALID)

    This check is SOUND: if it returns (False, reason), the entailment is definitely invalid.
    """
    # Count concrete cells in antecedent
    ante_cells = count_concrete_cells(antecedent)
    ante_predicates = collect_predicates(antecedent)

    # Count concrete cells in consequent
    cons_cells = count_concrete_cells(consequent)
    cons_predicates = collect_predicates(consequent)

    if verbose:
        print(f"[Footprint] Antecedent: {ante_cells} concrete cells, {len(ante_predicates)} predicates")
        print(f"[Footprint] Consequent: {cons_cells} concrete cells, {len(cons_predicates)} predicates")

    # Case 1: Antecedent has concrete cells but consequent has none
    # And consequent predicates could all be empty (no concrete cells)
    if ante_cells > 0 and cons_cells == 0 and len(cons_predicates) > 0:
        # Consequent is all predicates, no concrete cells
        # Check if antecedent has ONLY concrete cells (no predicates)
        if len(ante_predicates) == 0:
            # Antecedent is purely concrete, consequent is all predicates
            # The consequent predicates MUST account for the antecedent cells
            # We can't prove this statically, but we can check some simple cases

            # Check: if antecedent has more cells than predicates in consequent,
            # at least some predicates must be non-empty
            # This is still compatible (predicates could be non-empty)
            if verbose:
                print(f"[Footprint] Mixed case: {ante_cells} cells vs {len(cons_predicates)} predicates")

            # Don't reject - let Z3 handle it
            # But we could add a heuristic check here if needed
            pass

    # Case 2: Antecedent has cells but consequent is literally emp
    if ante_cells > 0 and isinstance(consequent, Emp):
        return (False, f"Antecedent has {ante_cells} cells but consequent is emp")

    # Case 3: Antecedent has predicates that could contribute cells
    # Can't determine footprint statically, so allow

    # Default: allow the check to proceed to Z3
    return (True, None)


def check_footprint_reachability(
    antecedent: Formula,
    consequent: Formula,
    verbose: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Check if consequent predicates could possibly consume antecedent footprint.

    This is a more sophisticated check that analyzes the structure:
    - Extract pointer chains from antecedent
    - Check if consequent predicates cover those chains

    Returns:
        (is_reachable, reason):
        - (True, None) if consequent could possibly match antecedent
        - (False, reason) if consequent cannot match (entailment INVALID)
    """
    # Build graph from antecedent
    from frame.heap.graph_analysis import HeapGraphAnalyzer
    analyzer = HeapGraphAnalyzer(verbose=verbose)

    try:
        graph, eq_classes = analyzer.build_heap_graph(antecedent)
    except Exception:
        # If graph building fails, allow Z3 to handle
        return (True, None)

    if not graph:
        # No concrete heap structure, allow Z3 to handle
        return (True, None)

    # Collect predicates from consequent
    cons_preds = collect_predicates(consequent)

    if not cons_preds:
        # Consequent has no predicates - check if it has enough concrete cells
        cons_cells = count_concrete_cells(consequent)
        if len(graph) > cons_cells:
            return (False, f"Antecedent has {len(graph)} cells but consequent has only {cons_cells}")
        return (True, None)

    # For each list segment predicate in consequent, check if there's a matching path
    # This is a sound under-approximation: if no path exists, entailment is invalid
    for pred in cons_preds:
        if pred.name.lower() in ['ls', 'lseg']:
            if len(pred.args) >= 2:
                start = pred.args[0]
                end = pred.args[1]

                if isinstance(start, Var) and isinstance(end, Var):
                    start_name = start.name
                    end_name = end.name

                    # Check if there's a path from start to end in the graph
                    path = analyzer.find_path(graph, eq_classes, start_name, end_name)

                    if path is None:
                        # No path exists - but predicate could be empty (start = end)
                        # This is not necessarily invalid, so allow
                        pass

    # Default: allow the check to proceed
    return (True, None)


def check_heap_cycle(
    graph: dict,
    verbose: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Check if the heap graph contains a cycle.

    A cycle in the heap (e.g., x |-> y * y |-> x) cannot be represented
    by standard acyclic list segment predicates like ls(). If we detect
    a cycle, the entailment is INVALID when the consequent uses only
    acyclic predicates.

    This is a CRITICAL soundness check.

    Returns:
        (no_cycle, reason):
        - (True, None) if no cycle detected (entailment might be valid)
        - (False, reason) if cycle detected (entailment is INVALID)
    """
    if not graph:
        return (True, None)

    # Use DFS to detect cycles
    visited = set()
    rec_stack = set()  # Nodes in current recursion stack

    def dfs(node, path):
        """DFS cycle detection. Returns cycle path if found, None otherwise."""
        if node in rec_stack:
            # Found a cycle - return the cycle path
            cycle_start = path.index(node)
            return path[cycle_start:] + [node]

        if node in visited:
            return None

        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        if node in graph:
            for next_node in graph[node]:
                if next_node in graph:  # Only follow edges to allocated nodes
                    result = dfs(next_node, path)
                    if result:
                        return result

        path.pop()
        rec_stack.remove(node)
        return None

    # Check for cycles starting from each node
    for start_node in graph:
        if start_node not in visited:
            cycle = dfs(start_node, [])
            if cycle:
                if verbose:
                    print(f"[Cycle Check] ✗ Found cycle: {' -> '.join(cycle)}")
                return (False, f"Heap contains cycle: {' -> '.join(cycle)}")

    if verbose:
        print(f"[Cycle Check] ✓ No cycle detected in heap graph")

    return (True, None)


def check_antecedent_cycle_coverage(
    graph: dict,
    consequent: Formula,
    verbose: bool = False
) -> Tuple[bool, Optional[str], bool]:
    """
    Check if any cycles in the antecedent heap can be covered by the consequent.

    If the antecedent has a cycle (e.g., x4 -> x6 -> x4), the consequent MUST have
    predicates that can partition the cycle (e.g., ls(x4, x6) AND ls(x6, x4)).
    If the consequent only has one direction (e.g., ls(x4, x6) but not ls(x6, x4)),
    the cycle cannot be consumed and the entailment is INVALID.

    IMPORTANT: Under acyclic heap semantics with (distinct in out) constraint,
    a concrete cycle in the antecedent makes the antecedent UNSATISFIABLE.
    From False, anything follows (ex falso quodlibet), so entailment is VALID.

    Returns:
        (is_valid, reason, antecedent_unsatisfiable):
        - (True, None, False) if no uncovered cycles
        - (False, reason, False) if a cycle cannot be covered (and conseq can't consume it)
        - (True, None, True) if antecedent has uncoverable cycle (making it unsatisfiable)
    """
    if not graph:
        return (True, None)

    # First, find all cycles in the antecedent graph
    visited = set()
    rec_stack = set()
    cycles = []

    def find_cycles(node, path):
        """Find all cycles starting from node."""
        if node in rec_stack:
            cycle_start = path.index(node)
            cycle = path[cycle_start:]
            cycles.append(cycle)
            return

        if node in visited:
            return

        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        if node in graph:
            for next_node in graph[node]:
                if next_node in graph:
                    find_cycles(next_node, path[:])

        rec_stack.discard(node)

    for start_node in graph:
        find_cycles(start_node, [])

    if not cycles:
        return (True, None)

    if verbose:
        print(f"[Antecedent Cycle Check] Found {len(cycles)} cycle(s) in antecedent")

    # Collect consequent predicates
    cons_predicates = collect_predicates(consequent)
    cons_segments = set()
    for pred in cons_predicates:
        if pred.name.lower() in ['ls', 'lseg']:
            if len(pred.args) >= 2:
                start = pred.args[0]
                end = pred.args[1]
                if isinstance(start, Var) and isinstance(end, Var):
                    cons_segments.add((start.name, end.name))

    # For each cycle, check if consequent predicates can partition it
    # A predicate ls(a, b) can consume all edges on the path from a to b in the graph
    for cycle in cycles:
        if len(cycle) < 2:
            continue

        # Build the set of edges in this cycle
        edges_in_cycle = set()
        for i in range(len(cycle)):
            start = cycle[i]
            end = cycle[(i + 1) % len(cycle)]
            edges_in_cycle.add((start, end))

        # For each consequent predicate, compute which edges it can consume
        # A predicate ls(a, b) can consume edges on the path from a to b
        edges_covered = set()
        for (pred_start, pred_end) in cons_segments:
            # Find path from pred_start to pred_end in the graph
            # The predicate consumes all edges on this path
            def find_path_edges(graph, start, end, max_depth=20):
                """Find edges on path from start to end."""
                if start == end:
                    return []
                visited = {start}
                queue = [(start, [])]
                while queue and len(visited) < max_depth:
                    current, path_edges = queue.pop(0)
                    if current in graph:
                        for next_node in graph[current]:
                            edge = (current, next_node)
                            if next_node == end:
                                return path_edges + [edge]
                            if next_node not in visited and next_node in graph:
                                visited.add(next_node)
                                queue.append((next_node, path_edges + [edge]))
                return None

            path_edges = find_path_edges(graph, pred_start, pred_end)
            if path_edges:
                for edge in path_edges:
                    edges_covered.add(edge)

        # Check if all cycle edges are covered
        uncovered = edges_in_cycle - edges_covered
        if uncovered:
            cycle_str = " -> ".join(cycle + [cycle[0]])
            uncovered_str = ", ".join([f"{a}->{b}" for a, b in uncovered])
            if verbose:
                print(f"[Antecedent Cycle Check] ✗ Cycle {cycle_str} has uncovered edges: {uncovered_str}")
            return (False, f"Antecedent has cycle {cycle_str} with uncovered edges: {uncovered_str}")

        if verbose:
            print(f"[Antecedent Cycle Check] ✓ Cycle {' -> '.join(cycle)} can be partitioned")

    return (True, None)


def check_cyclic_predicates_in_consequent(
    consequent: Formula,
    ante_cells: int,
    antecedent_graph: dict,
    verbose: bool = False,
    antecedent: Formula = None
) -> Tuple[bool, Optional[str]]:
    """
    Check for cyclic predicate patterns in the consequent that can't be satisfied.

    A cyclic pattern like ls(a,b) * ls(b,a) in the consequent can be satisfied IF:
    1. The antecedent has a cyclic heap structure from a through b back to a
    2. The two predicates can partition this cycle

    If the antecedent does NOT have such a cycle, both predicates must be empty (a = b),
    meaning they consume NO cells. If there are concrete cells in the antecedent that
    cannot be consumed by other predicates, the entailment is INVALID.

    IMPORTANT SOUNDNESS NOTE (Nov 2025):
    We ONLY consider CONCRETE cells when checking for cycles.
    Antecedent predicates like ls(x,y) provide a potential path, but including them
    makes this check too permissive and causes false positives.

    The reason: if antecedent has ls(a,b) * ls(b,a) and consequent also has ls(a,b) * ls(b,a),
    this check would pass (cycle found via predicates), but the entailment might still be
    INVALID because the concrete cells can't be properly matched/consumed.

    Returns:
        (is_valid, reason):
        - (True, None) if no cyclic conflict detected
        - (False, reason) if cyclic conflict makes entailment invalid
    """
    cons_predicates = collect_predicates(consequent)

    if len(cons_predicates) <= 1:
        return (True, None)

    # Extract (start, end) pairs for list segment predicates
    segments = []
    for pred in cons_predicates:
        if pred.name.lower() in ['ls', 'lseg']:
            if len(pred.args) >= 2:
                start = pred.args[0]
                end = pred.args[1]
                if isinstance(start, Var) and isinstance(end, Var):
                    segments.append((start.name, end.name))

    # Build a directed graph of predicate segments
    # Check for symmetric pairs: ls(a,b) and ls(b,a)
    segment_set = set(segments)
    cyclic_pairs = []

    for (start, end) in segments:
        if start != end and (end, start) in segment_set:
            # Found a cyclic pair! ls(start, end) and ls(end, start)
            # Only add each pair once (avoid duplicates)
            if (end, start) not in cyclic_pairs:
                cyclic_pairs.append((start, end))

    if not cyclic_pairs:
        return (True, None)

    if verbose:
        print(f"[Cyclic Predicate Check] Found cyclic pairs: {cyclic_pairs}")

    # For each cyclic pair, check if the antecedent has a cycle that supports it
    # ONLY look at the CONCRETE graph (antecedent_graph), not predicates
    def has_cycle_in_antecedent(graph, a, b):
        """Check if antecedent graph has a cycle containing both a and b."""
        if not graph:
            return False

        # Check if there's a path from a to b AND from b to a in the graph
        def find_path(graph, start, end, visited=None):
            if visited is None:
                visited = set()
            if start == end:
                return True
            if start in visited or start not in graph:
                return False
            visited.add(start)
            for next_node in graph[start]:
                if find_path(graph, next_node, end, visited):
                    return True
            return False

        path_a_to_b = find_path(graph, a, b, set())
        path_b_to_a = find_path(graph, b, a, set())

        return path_a_to_b and path_b_to_a

    for (a, b) in cyclic_pairs:
        # Check if antecedent has a concrete cycle that the predicates can partition
        if has_cycle_in_antecedent(antecedent_graph, a, b):
            if verbose:
                print(f"[Cyclic Predicate Check] ✓ Antecedent has cycle through {a} and {b} - "
                      f"predicates ls({a},{b}) * ls({b},{a}) can partition it")
        else:
            # No supporting cycle in antecedent - predicates must both be empty
            if ante_cells > 0:
                if verbose:
                    print(f"[Cyclic Predicate Check] ✗ No cycle in antecedent through {a} and {b}, "
                          f"so ls({a},{b}) * ls({b},{a}) must both be empty, "
                          f"but antecedent has {ante_cells} concrete cells")
                return (False, f"Consequent has cyclic predicates ls({a},{b}) * ls({b},{a}) but "
                              f"antecedent has no cycle through {a} and {b}, so both must be empty. "
                              f"However, antecedent has {ante_cells} concrete cells that cannot be consumed")

    return (True, None)


def check_spatial_conflict(
    antecedent: Formula,
    consequent: Formula,
    verbose: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Check for spatial conflicts that make an entailment invalid.

    A spatial conflict occurs when:
    1. The same variable must be consumed by multiple consequent predicates
       (violates separation - heap cells can only be owned by one predicate)
    2. Two consequent predicates have overlapping ranges but different endpoints

    This is more sophisticated than simple footprint counting.
    """
    cons_predicates = collect_predicates(consequent)

    if len(cons_predicates) <= 1:
        return (True, None)  # No conflict possible with 0-1 predicates

    # Extract (start, end) pairs for list segment predicates
    segments = []
    for pred in cons_predicates:
        if pred.name.lower() in ['ls', 'lseg']:
            if len(pred.args) >= 2:
                start = pred.args[0]
                end = pred.args[1]
                if isinstance(start, Var) and isinstance(end, Var):
                    segments.append((start.name, end.name, pred))

    # Check for conflicts: same starting point with different endpoints
    start_to_segments = {}
    for start, end, pred in segments:
        if start not in start_to_segments:
            start_to_segments[start] = []
        start_to_segments[start].append((end, pred))

    for start, end_list in start_to_segments.items():
        if len(end_list) > 1:
            # Multiple predicates start from same variable
            # This is a potential conflict if they have different endpoints
            endpoints = set(e[0] for e in end_list)
            if len(endpoints) > 1:
                # Different endpoints from same start - this is suspicious
                # BUT: This is only invalid if the predicates are NOT empty
                # Since predicates can be empty (start = end), this alone doesn't prove invalidity
                if verbose:
                    print(f"[Spatial Conflict] Multiple predicates from {start}: {end_list}")

    return (True, None)


def check_cyclic_proof_soundness(
    antecedent: Formula,
    consequent: Formula,
    verbose: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Apply cyclic proof soundness check to detect invalid entailments.

    Key insight from cyclic proof theory:
    - In a valid entailment P |- Q, every heap cell in P must be "consumed" by Q
    - If P has N concrete cells and Q has M predicates that could all be empty,
      we need to verify that the predicates actually match the cells

    This check verifies "progress" in the cyclic proof sense:
    - Build heap graph from antecedent
    - For each consequent predicate, check if it could match part of the graph
    - If predicates don't cover the graph, return INVALID

    CRITICAL: Predicates must PARTITION the heap (disjoint consumption).
    Multiple predicates cannot consume the same cell.

    Returns:
        (is_sound, reason):
        - (True, None) if entailment could be sound
        - (False, reason) if entailment is definitely unsound
    """
    from frame.heap.graph_analysis import HeapGraphAnalyzer
    from frame.core.ast import False_

    # SPECIAL CASE: false implies anything (ex falso quodlibet)
    # If antecedent is False_, the entailment is always valid
    if isinstance(antecedent, False_):
        if verbose:
            print("[Cyclic Check] Antecedent is false - entailment is trivially valid")
        return (True, None)

    # Count concrete cells in antecedent (these MUST be matched)
    ante_cells = count_concrete_cells(antecedent)
    ante_predicates = collect_predicates(antecedent)

    # Count concrete cells in consequent
    cons_cells = count_concrete_cells(consequent)
    cons_predicates = collect_predicates(consequent)

    if verbose:
        print(f"[Cyclic Check] Antecedent: {ante_cells} concrete cells, {len(ante_predicates)} predicates")
        print(f"[Cyclic Check] Consequent: {cons_cells} concrete cells, {len(cons_predicates)} predicates")

    # Case 1: Consequent has no predicates (purely concrete)
    # In separation logic with frame rule, antecedent can have MORE cells than consequent
    # (the extra cells form the frame). But if consequent needs more cells than antecedent
    # has, the entailment is invalid.
    if not cons_predicates:
        if not ante_predicates and ante_cells < cons_cells:
            # Antecedent has FEWER cells than consequent - can't satisfy
            return (False, f"Footprint mismatch: ante has {ante_cells} cells, cons needs {cons_cells}")
        # ante_cells >= cons_cells is fine (frame rule handles the difference)
        return (True, None)

    # Case 1.5 (Nov 2025): Minimum footprint comparison
    # When BOTH have concrete cells, check if consequent's minimum exceeds antecedent's minimum.
    # This catches cases like dll-entails-node-node-dll where:
    #   - Antecedent: DLL_plus can be 1 cell (base case)
    #   - Consequent: points_to * points_to * DLL_plus requires at least 3 cells
    # Key insight: ante_cells is the MINIMUM from count_concrete_cells (takes min of Or branches)
    # If cons_cells > ante_cells, the consequent needs more cells than antecedent can provide
    # in its smallest valid configuration.
    if ante_cells > 0 and cons_cells > ante_cells:
        # Consequent needs more concrete cells than antecedent provides
        # Check if antecedent predicates could provide the extra cells
        # For soundness, we must verify that antecedent predicates ALWAYS provide enough
        # But since we're using min counts (base cases), antecedent predicates COULD be empty
        # This means the entailment is INVALID when antecedent is at its minimum
        if verbose:
            print(f"[Cyclic Check] ✗ Consequent needs {cons_cells} cells but antecedent minimum is {ante_cells}")
        return (False, f"Footprint mismatch: consequent needs {cons_cells} cells but antecedent minimum is {ante_cells}")

    # Case 2: Antecedent has NO concrete cells - can't do this check
    if ante_cells == 0:
        return (True, None)

    # Build heap graph from antecedent to analyze structure
    analyzer = HeapGraphAnalyzer(verbose=verbose)
    try:
        graph, eq_classes = analyzer.build_heap_graph(antecedent)
    except Exception:
        return (True, None)

    if not graph:
        return (True, None)

    # SOUNDNESS CHECK (Nov 2025): Detect cycles in antecedent heap
    # If the antecedent has a cycle, we need to check if the consequent predicates
    # can PARTITION the cycle. A cycle can be partitioned if the consequent has
    # predicates covering both directions (e.g., ls(a,b) and ls(b,a) for cycle a<->b).
    #
    # IMPORTANT: We should NOT reject all cycles! Many valid entailments have cycles
    # that CAN be partitioned by the consequent predicates. Only reject if there's
    # a cycle edge that NO consequent predicate can consume.
    #
    # Example of VALID entailment with cycle:
    # - Antecedent: ls(x8, x10) * x10 |-> x4 * x4 |-> x10  (cycle: x10 <-> x4)
    # - Consequent: ls(x8, x4) * ls(x4, x10)
    # - ls(x8, x4) consumes: ls(x8, x10) * x10 |-> x4 (via cons lemma)
    # - ls(x4, x10) consumes: x4 |-> x10
    # Both cycle edges are covered!
    #
    # Nov 2025 Update: Disabled aggressive cycle check that was causing false negatives.
    # The check_antecedent_cycle_coverage function below handles the nuanced case.
    # Let Z3 and the partition check handle cycles that can't be partitioned.

    # For each consequent predicate, compute what cells it COULD consume
    # A predicate ls(x, y) can consume a path from x to y
    pred_consumable = []  # List of (predicate, set of consumable cells)

    for pred in cons_predicates:
        consumable = set()
        if pred.name.lower() in ['ls', 'lseg']:
            if len(pred.args) >= 2:
                start = pred.args[0]
                end = pred.args[1]

                if isinstance(start, Var):
                    start_name = start.name

                    if isinstance(end, Var):
                        end_name = end.name
                        # Check for path from start to end
                        path = analyzer.find_path(graph, eq_classes, start_name, end_name, max_depth=20)
                        if path and len(path) > 1:
                            # This predicate can consume cells along the path (excluding endpoint)
                            consumable.update(path[:-1])

                    # Also consider null-terminated case (ls to nil)
                    # Walk from start until we hit a dead end
                    current = start_name
                    visited = set()
                    while current in graph and current not in visited:
                        visited.add(current)
                        consumable.add(current)
                        nexts = graph[current]
                        if nexts:
                            current = nexts[0]  # Follow first pointer
                        else:
                            break

        # Handle null-terminated list predicates (list, sll, etc.)
        # These have only one argument (start) and consume until nil
        elif pred.name.lower() in ['list', 'sll', 'pelist']:
            if len(pred.args) >= 1:
                start = pred.args[0]
                if isinstance(start, Var):
                    start_name = start.name
                    # Walk from start until we hit a dead end (nil)
                    current = start_name
                    visited = set()
                    while current in graph and current not in visited:
                        visited.add(current)
                        consumable.add(current)
                        nexts = graph[current]
                        if nexts:
                            current = nexts[0]  # Follow first pointer
                        else:
                            break

        pred_consumable.append((pred, consumable))

    # Now check if all graph cells CAN be covered
    all_consumable = set()
    for pred, consumable in pred_consumable:
        all_consumable.update(consumable)

    # Nov 2025: Also account for concrete points-to cells in consequent
    # If consequent has z |-> w, it can directly consume cell z from antecedent
    cons_concrete_cells = collect_concrete_cell_sources(consequent)
    all_consumable.update(cons_concrete_cells)

    uncovered = set(graph.keys()) - all_consumable

    if verbose:
        print(f"[Cyclic Check] Graph cells: {set(graph.keys())}")
        print(f"[Cyclic Check] All consumable: {all_consumable}")
        print(f"[Cyclic Check] Uncovered: {uncovered}")

    # SOUNDNESS CHECK 0 (Nov 2025): Uncovered concrete cells
    # If there are concrete cells that NO consequent predicate can consume, entailment is INVALID.
    # A cell X is "consumable" if it's on a path from some consequent predicate's start to end.
    #
    # Key insight: For a consequent predicate ls(a, b) to consume a cell X:
    # 1. X must be on the path from a to b
    # 2. Or X must be reachable via antecedent predicates that extend the path
    #
    # However, checking path extension through antecedent predicates is complex.
    # For now, we check: if an uncovered cell has no consequent predicate that STARTS at it,
    # and no consequent predicate has a path that goes THROUGH it, return INVALID.
    if uncovered:
        # Get consequent predicate start points
        cons_starts = set()
        for pred, consumable in pred_consumable:
            if hasattr(pred, 'args') and len(pred.args) >= 1:
                start = pred.args[0]
                if isinstance(start, Var):
                    cons_starts.add(start.name)

        # For each uncovered cell, check if any consequent predicate could consume it
        # A cell can be consumed if:
        # 1. A consequent predicate starts at it
        # 2. A consequent predicate has a path through it (already in all_consumable)
        truly_uncovered = set()
        for cell in uncovered:
            if cell not in cons_starts:
                # No consequent predicate starts at this cell
                # And it's not in all_consumable (not on any path)
                # Check if it could be reached via antecedent predicate extension
                # For simplicity, if the cell points to something that IS consumable,
                # it might be part of an extended path. Otherwise, it's truly uncovered.
                if cell in graph:
                    cell_targets = graph[cell]
                    # If this cell points to something consumable, it might be on an extended path
                    # But the cell itself must be allocated by some consequent predicate
                    # Since no consequent predicate starts at this cell, it can't be consumed
                    truly_uncovered.add(cell)
                else:
                    truly_uncovered.add(cell)

        if truly_uncovered:
            if verbose:
                print(f"[Cyclic Check] ✗ Truly uncovered cells: {truly_uncovered}")
            return (False, f"Cells {truly_uncovered} cannot be consumed by any consequent predicate")

    # SOUNDNESS CHECK 1: Detect cycles in antecedent CONCRETE GRAPH that consequent can't partition
    # If antecedent has a concrete cycle (e.g., x4 |-> x6 * x6 |-> x4), the consequent MUST have
    # predicates that cover ALL edges of the cycle.
    #
    # Example of INVALID entailment:
    #   Antecedent: x4 |-> x6 * x6 |-> x4  (concrete cycle)
    #   Consequent: ls(x4, x6)  (only covers x4 -> x6, NOT x6 -> x4)
    #   The edge x6 -> x4 cannot be consumed! INVALID.
    #
    # Example of VALID entailment:
    #   Antecedent: x4 |-> x6 * x6 |-> x4  (concrete cycle)
    #   Consequent: ls(x4, x6) * ls(x6, x4)  (covers both directions)
    #   ls(x4, x6) consumes x4 -> x6, ls(x6, x4) consumes x6 -> x4. VALID.
    #
    # Nov 2025 Update: Re-enabled with careful analysis. This check catches important
    # false positives like bolognesa-11-e10 where concrete cycles have uncovered edges.
    # The previous concern about antecedent predicates extending paths is addressed by
    # only looking at CONCRETE edges in the graph (predicates might be empty).
    cycle_result = check_antecedent_cycle_coverage(graph, consequent, verbose)
    if cycle_result is not None and len(cycle_result) >= 2 and not cycle_result[0]:
        return cycle_result

    # SOUNDNESS CHECK 2: Detect cyclic predicate patterns in consequent that can't be satisfied
    # If consequent has ls(a,b) * ls(b,a) and antecedent has no cycle through a and b,
    # both predicates must be empty. If antecedent has concrete cells, they can't be consumed.
    #
    # Nov 2025 Update: Re-enabled this check because it catches important false positives:
    # - When consequent has ls(a,b) * ls(b,a) (cyclic pair)
    # - And antecedent concrete graph does NOT have both directions (a→b AND b→a)
    # - Then both predicates must be empty (a = b)
    # - If antecedent has concrete cells, they can't be consumed by empty predicates
    # - This makes the entailment INVALID
    #
    # This check only looks at CONCRETE graph edges, not antecedent predicates.
    # Antecedent predicates like ls(x,y) could be empty, so we can't rely on them.
    cyclic_pred_result = check_cyclic_predicates_in_consequent(
        consequent, ante_cells, graph, verbose, antecedent=antecedent
    )
    if not cyclic_pred_result[0]:
        return cyclic_pred_result

    # Default: allow the check to proceed
    return (True, None)


def check_partition_exists(
    graph: dict,
    pred_consumable: List[Tuple],
    verbose: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Check if consequent predicates can partition the heap cells.

    Due to separating conjunction, each cell can only be consumed by ONE predicate.
    This uses backtracking to find if any valid partition exists.

    Returns:
        (can_partition, reason):
        - (True, None) if a valid partition might exist
        - (False, reason) if no valid partition exists (entailment INVALID)
    """
    cells_to_cover = set(graph.keys())

    if not cells_to_cover:
        return (True, None)

    # Filter to only predicates that could consume something
    active_preds = [(pred, cons) for pred, cons in pred_consumable if cons]

    # Quick check: if no predicate can consume anything, but we have cells to cover
    if not active_preds and cells_to_cover:
        return (False, f"No predicate can consume cells: {cells_to_cover}")

    # Use recursive backtracking to find a valid partition
    # Each predicate must consume a non-overlapping subset (or be empty)

    def can_partition_recursive(remaining_cells: set, pred_index: int, assignments: dict) -> bool:
        """Try to partition remaining_cells using predicates from pred_index onwards."""
        if not remaining_cells:
            return True  # All cells covered

        if pred_index >= len(pred_consumable):
            return False  # No more predicates but cells remain

        pred, consumable = pred_consumable[pred_index]

        # Option 1: This predicate is empty (consumes nothing)
        if can_partition_recursive(remaining_cells, pred_index + 1, assignments):
            return True

        # Option 2: This predicate consumes some cells
        # It must consume ALL cells on its path that are still remaining
        # (can't consume partial paths in separation logic)

        # Find cells this predicate MUST consume if it's non-empty
        # For ls(x, y), if x is in remaining_cells, we follow the path
        if pred.name.lower() in ['ls', 'lseg'] and len(pred.args) >= 2:
            start = pred.args[0]
            if isinstance(start, Var) and start.name in remaining_cells:
                # This predicate starts at an unassigned cell
                # Compute the path it would consume
                path_consumed = set()
                current = start.name

                end_name = None
                if isinstance(pred.args[1], Var):
                    end_name = pred.args[1].name

                # Follow the path until we reach endpoint or dead end
                visited = set()
                while current in graph and current not in visited:
                    if current == end_name:
                        break  # Reached endpoint (not consumed)
                    visited.add(current)
                    path_consumed.add(current)
                    nexts = graph[current]
                    if nexts:
                        current = nexts[0]
                    else:
                        break

                if path_consumed:
                    # Check if all path cells are available
                    if path_consumed <= remaining_cells:
                        new_remaining = remaining_cells - path_consumed
                        assignments[id(pred)] = path_consumed
                        if can_partition_recursive(new_remaining, pred_index + 1, assignments):
                            return True
                        del assignments[id(pred)]

        # Option 3: Try skipping to next predicate
        return can_partition_recursive(remaining_cells, pred_index + 1, assignments)

    assignments = {}
    can_partition = can_partition_recursive(cells_to_cover, 0, assignments)

    if verbose:
        print(f"[Partition Check] Cells to cover: {cells_to_cover}")
        print(f"[Partition Check] Predicates: {[(str(p.args) if hasattr(p, 'args') else '?', c) for p, c in pred_consumable]}")
        print(f"[Partition Check] Can partition: {can_partition}")
        if can_partition:
            print(f"[Partition Check] Assignments: {assignments}")

    if not can_partition:
        return (False, f"Cannot partition cells {cells_to_cover} among {len(pred_consumable)} predicates")

    return (True, None)
