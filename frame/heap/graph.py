"""
Heap Graph Analysis for Pattern Detection and Multi-PTO Folding

This module provides heap graph abstraction for:
- Detecting multi-pto patterns that form inductive predicates
- Composing sequences of points-to cells into predicates
- Synthesizing arithmetic witnesses for lemma application
"""

from typing import Dict, List, Optional, Tuple, Set
from frame.core.ast import (
    Formula, Expr, Var, Const, PointsTo, SepConj, Emp,
    PredicateCall, And, ArithExpr
)
from frame.heap._heap_types import HeapNode, HeapEdge, Chain, DLLPattern, FoldProposal


class HeapGraph:
    """
    Heap graph representation for pattern detection.

    Nodes represent locations (variables), edges represent field pointers.
    """

    def __init__(self):
        self.nodes: Dict[str, HeapNode] = {}
        self.edges: List[HeapEdge] = []

    def add_node(self, name: str) -> HeapNode:
        """Add or get a node in the graph"""
        if name not in self.nodes:
            self.nodes[name] = HeapNode(name=name)
        return self.nodes[name]

    def add_edge(self, source: str, target: str, label: str):
        """Add an edge (field pointer) between two nodes"""
        edge = HeapEdge(source=source, target=target, label=label)
        self.edges.append(edge)

        # Add to node adjacency lists
        if source in self.nodes:
            self.nodes[source].outgoing.append(edge)
        if target in self.nodes:
            self.nodes[target].incoming.append(edge)

    def add_field(self, node: str, field: str, value: Expr):
        """Add a field value to a node"""
        if node in self.nodes:
            self.nodes[node].fields[field] = value

    def get_successors(self, node: str, field: str = "next") -> List[str]:
        """Get all successors of a node via a specific field"""
        if node not in self.nodes:
            return []

        successors = []
        for edge in self.nodes[node].outgoing:
            # Allow nil as a valid target even if it's not a node
            if edge.label == field and (edge.target in self.nodes or edge.target == "nil"):
                successors.append(edge.target)
        return successors

    def get_field_value(self, node: str, field: str) -> Optional[Expr]:
        """Get the value of a field for a node"""
        if node not in self.nodes:
            return None
        return self.nodes[node].fields.get(field)

    def chain_from(self, start: str, field: str = "next",
                   max_depth: int = 10) -> Optional[Chain]:
        """
        Detect a linear chain starting from a node.

        Returns a Chain object with nodes in order, or None if no valid chain.
        Stops at cycles, nil, or max_depth.
        """
        if start not in self.nodes:
            return None

        nodes = [start]
        visited = {start}
        current = start

        for _ in range(max_depth):
            successors = self.get_successors(current, field)

            # Stop conditions
            if not successors:
                # Reached end (no more successors)
                break

            if len(successors) > 1:
                # Branching - not a linear chain
                return None

            next_node = successors[0]

            # Check for nil/null
            if next_node == "nil" or next_node not in self.nodes:
                # Reached nil - valid chain
                break

            # Check for cycle
            if next_node in visited:
                # Cycle detected - could be circular list
                break

            nodes.append(next_node)
            visited.add(next_node)
            current = next_node

        return Chain(nodes=nodes, field=field, length=len(nodes))

    def detect_dll_pattern(self, start: str, max_depth: int = 10) -> Optional[DLLPattern]:
        """
        Detect a doubly-linked list pattern starting from a node.

        Verifies that next/prev pointers are consistent.
        """
        if start not in self.nodes:
            return None

        nodes = [start]
        visited = {start}
        current = start
        prev = None

        for _ in range(max_depth):
            # Check prev consistency
            if prev is not None:
                prev_successors = self.get_successors(prev, "next")
                if not prev_successors or prev_successors[0] != current:
                    # Inconsistent next pointer
                    return None

                prev_prevs = self.get_successors(current, "prev")
                if not prev_prevs:
                    # Current node has no prev pointer - this is the end of the segment
                    # Don't include this node in the pattern
                    break
                if prev_prevs[0] != prev:
                    # Inconsistent prev pointer
                    return None

            # Get next node
            successors = self.get_successors(current, "next")

            if not successors:
                break

            if len(successors) > 1:
                return None

            next_node = successors[0]

            if next_node == "nil" or next_node not in self.nodes:
                break

            if next_node in visited:
                break

            # Check if next_node has a valid prev pointer before including it
            next_prevs = self.get_successors(next_node, "prev")
            if not next_prevs:
                # next_node has no prev pointer - it's not part of the DLL segment
                break
            if next_prevs[0] != current:
                # Inconsistent prev pointer
                return None

            nodes.append(next_node)
            visited.add(next_node)
            prev = current
            current = next_node

        if len(nodes) >= 1:
            return DLLPattern(nodes=nodes, length=len(nodes))

        return None

    def detect_cycles(self, field: str = "next") -> List[List[str]]:
        """
        Detect all cycles in the heap graph for a given field.

        Returns:
            List of cycles, where each cycle is a list of node names forming the cycle.
            Each cycle is represented with the smallest node name first for normalization.
        """
        cycles = []
        visited_global = set()

        def dfs_cycle(node: str, path: List[str], path_set: Set[str]) -> None:
            """DFS to find cycles"""
            if node in path_set:
                # Found a cycle! Extract the cycle portion
                cycle_start_idx = path.index(node)
                cycle = path[cycle_start_idx:]
                # Normalize: rotate so smallest node is first
                if cycle:
                    min_idx = cycle.index(min(cycle))
                    normalized = cycle[min_idx:] + cycle[:min_idx]
                    # Check if we haven't seen this cycle before (avoid duplicates)
                    if normalized not in cycles:
                        cycles.append(normalized)
                return

            if node in visited_global:
                return

            visited_global.add(node)
            path.append(node)
            path_set.add(node)

            # Follow outgoing edges with the specified field
            for succ in self.get_successors(node, field):
                if succ != "nil" and succ in self.nodes:
                    dfs_cycle(succ, path, path_set)

            path.pop()
            path_set.remove(node)

        # Try starting from each node
        for node_name in self.nodes:
            if node_name not in visited_global:
                dfs_cycle(node_name, [], set())

        return cycles

    def detect_overlapping_segments(self, field: str = "next") -> List[Tuple[str, str, str]]:
        """
        Detect overlapping list segments in the heap graph.

        Returns segments that share nodes: [(start1, end1, shared_node), ...]
        Useful for detecting patterns like: ls(x,z) * ls(y,z) where paths converge.
        """
        overlaps = []

        # For each node, track which nodes can reach it
        reachability: Dict[str, Set[str]] = {node: set() for node in self.nodes}

        # Compute reachability for each starting node
        for start in self.nodes:
            visited = set()
            queue = [start]

            while queue:
                current = queue.pop(0)
                if current in visited or current == "nil":
                    continue

                visited.add(current)
                reachability[current].add(start)

                # Add successors
                for succ in self.get_successors(current, field):
                    if succ != "nil" and succ in self.nodes:
                        queue.append(succ)

        # Find nodes reached by multiple starting points
        for node, reaching_nodes in reachability.items():
            if len(reaching_nodes) > 1:
                # This node is reached by multiple paths
                reaching_list = sorted(list(reaching_nodes))
                for i in range(len(reaching_list)):
                    for j in range(i + 1, len(reaching_list)):
                        overlaps.append((reaching_list[i], reaching_list[j], node))

        return overlaps

    def find_all_paths(self, start: str, end: str, field: str = "next",
                       max_depth: int = 10) -> List[List[str]]:
        """
        Find ALL paths from start to end (not just the first one).

        Useful for detecting multiple list segments connecting the same endpoints.
        Returns list of paths, where each path is a list of node names.
        """
        if start not in self.nodes:
            return []

        all_paths = []

        def dfs(current: str, target: str, path: List[str], visited: Set[str]):
            if current == target:
                all_paths.append(path[:])  # Found a path!
                return

            if len(path) > max_depth:
                return

            for succ in self.get_successors(current, field):
                if succ == "nil":
                    continue
                if succ not in self.nodes:
                    continue
                if succ in visited:
                    continue

                visited.add(succ)
                path.append(succ)
                dfs(succ, target, path, visited)
                path.pop()
                visited.remove(succ)

        visited_set = {start}
        dfs(start, end, [start], visited_set)
        return all_paths

    def __str__(self) -> str:
        """String representation for debugging"""
        lines = ["HeapGraph:"]
        lines.append(f"  Nodes: {', '.join(self.nodes.keys())}")
        lines.append("  Edges:")
        for edge in self.edges:
            lines.append(f"    {edge.source} --{edge.label}--> {edge.target}")
        return "\n".join(lines)


def build_heap_graph(formula: Formula) -> HeapGraph:
    """
    Build a heap graph from a spatial formula.

    Extracts points-to cells and creates graph representation:
    - Nodes for each location variable
    - Edges for field pointers
    - Field values stored in nodes

    Args:
        formula: Spatial formula (may include PointsTo, SepConj, And, etc.)

    Returns:
        HeapGraph representing the heap structure
    """
    graph = HeapGraph()

    # Collect all PointsTo atoms
    pto_atoms = _collect_pto_atoms(formula)

    for pto in pto_atoms:
        # Add node for the source location
        if isinstance(pto.location, Var):
            source = pto.location.name
        elif isinstance(pto.location, Const):
            source = str(pto.location.value)
        else:
            continue  # Skip complex expressions for now

        graph.add_node(source)

        # Handle different value types
        values = pto.values  # List of values

        # Case 1: Simple value (x |-> y)
        if len(values) == 1:
            value = values[0]

            if isinstance(value, Var):
                graph.add_node(value.name)  # Ensure target node exists
                graph.add_field(source, "next", value)
                graph.add_edge(source, value.name, "next")

            elif isinstance(value, Const):
                if value.value is None or str(value.value).lower() == "nil":
                    graph.add_field(source, "next", value)
                    graph.add_edge(source, "nil", "next")
                else:
                    graph.add_field(source, "data", value)

        # Case 2: Struct/record with multiple fields (x |-> (y, z))
        # Assume first is "next", second is "prev" for DLL
        elif len(values) == 2:
            next_val, prev_val = values[0], values[1]

            # Handle next field
            if isinstance(next_val, Var):
                graph.add_node(next_val.name)  # Ensure target node exists
                graph.add_field(source, "next", next_val)
                graph.add_edge(source, next_val.name, "next")
            elif isinstance(next_val, Const):
                if next_val.value is None or str(next_val.value).lower() == "nil":
                    graph.add_field(source, "next", next_val)
                    graph.add_edge(source, "nil", "next")

            # Handle prev field
            if isinstance(prev_val, Var):
                if prev_val.name == "nil":
                    # Treat Var("nil") as nil constant
                    graph.add_field(source, "prev", prev_val)
                    graph.add_edge(source, "nil", "prev")
                else:
                    graph.add_node(prev_val.name)  # Ensure target node exists
                    graph.add_field(source, "prev", prev_val)
                    graph.add_edge(source, prev_val.name, "prev")
            elif isinstance(prev_val, Const):
                if prev_val.value is None or str(prev_val.value).lower() == "nil":
                    graph.add_field(source, "prev", prev_val)
                    graph.add_edge(source, "nil", "prev")

        # Case 3: More complex structs - handle as needed
        # TODO: Add proper struct field parsing for named fields

    return graph


def _collect_pto_atoms(formula: Formula) -> List[PointsTo]:
    """Recursively collect all PointsTo atoms from a formula"""
    pto_atoms = []

    if isinstance(formula, PointsTo):
        pto_atoms.append(formula)

    elif isinstance(formula, SepConj):
        pto_atoms.extend(_collect_pto_atoms(formula.left))
        pto_atoms.extend(_collect_pto_atoms(formula.right))

    elif isinstance(formula, And):
        pto_atoms.extend(_collect_pto_atoms(formula.left))
        pto_atoms.extend(_collect_pto_atoms(formula.right))

    # Ignore other formula types (Emp, PredicateCall, etc.) for now
    # We focus on concrete pto cells

    return pto_atoms


def _extract_spatial_atoms(formula: Formula) -> List[Formula]:
    """
    Extract spatial atoms (PointsTo, PredicateCall) from formula.

    Separates spatial parts from pure constraints.
    """
    atoms = []

    if isinstance(formula, (PointsTo, PredicateCall, Emp)):
        atoms.append(formula)

    elif isinstance(formula, SepConj):
        atoms.extend(_extract_spatial_atoms(formula.left))
        atoms.extend(_extract_spatial_atoms(formula.right))

    elif isinstance(formula, And):
        # For And, extract spatial parts from both sides
        atoms.extend(_extract_spatial_atoms(formula.left))
        atoms.extend(_extract_spatial_atoms(formula.right))

    return atoms


def propose_folds(graph: HeapGraph, pto_atoms: List[PointsTo],
                  max_proposals: int = 5, predicate_registry=None, formula=None) -> List[FoldProposal]:
    """
    Propose candidate folds from heap graph patterns.

    Analyzes the heap graph to detect patterns (chains, DLL, etc.)
    and proposes folding multi-pto cells into inductive predicates.

    Args:
        graph: The heap graph
        pto_atoms: List of PointsTo atoms available for folding
        max_proposals: Maximum number of proposals to return
        predicate_registry: Optional PredicateRegistry to check predicate arities
        formula: Optional formula to extract predicate calls from (for hierarchical folding)

    Returns:
        List of FoldProposal objects, sorted by confidence (high to low)
    """
    # Delegate to fold proposal module
    from frame.heap._fold_proposals import propose_folds as _propose_folds_impl
    return _propose_folds_impl(graph, pto_atoms, max_proposals, predicate_registry, formula)
