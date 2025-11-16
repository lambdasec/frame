"""
Fold Proposal Generation

This module handles proposing folds of multiple points-to cells into inductive predicates.
It's extracted from heap_graph.py to keep that file manageable.
"""

from typing import List
from frame.core.ast import Var, Const, PointsTo, Formula
from frame.heap.graph import FoldProposal


def propose_folds(graph, pto_atoms: List[PointsTo],
                 max_proposals: int = 10, predicate_registry=None) -> List[FoldProposal]:
    """
    Propose folds of pto atoms into inductive predicates.

    Args:
        graph: HeapGraph instance
        pto_atoms: List of PointsTo formulas to consider
        max_proposals: Maximum number of proposals to return
        predicate_registry: Optional PredicateRegistry to check predicate arities

    Returns:
        List of FoldProposal objects, ordered by confidence (high to low)
    """
    proposals = []

    # Generate different types of proposals
    proposals.extend(_propose_ls_folds(graph, pto_atoms))
    proposals.extend(_propose_dll_folds(graph, pto_atoms, predicate_registry))
    proposals.extend(_propose_cyclic_folds(graph, pto_atoms))  # NEW: Cyclic patterns

    # Enhanced ranking: score proposals more intelligently
    for proposal in proposals:
        proposal.confidence = _rank_proposal(proposal, graph, pto_atoms)

    # Sort by confidence (descending) and return top N
    proposals.sort(key=lambda p: p.confidence, reverse=True)
    return proposals[:max_proposals]


def _propose_ls_folds(graph, pto_atoms: List[PointsTo]) -> List[FoldProposal]:
    """
    Propose list segment folds from detected chains.

    For a chain x -> y -> z, proposes:
    - ls(x, z) with appropriate length
    - list(x) if ending at nil
    """
    proposals = []

    # Map locations to pto atoms for quick lookup
    pto_map = {}
    for pto in pto_atoms:
        if isinstance(pto.location, Var):
            pto_map[pto.location.name] = pto

    # Try starting from each node
    for node_name in list(graph.nodes.keys()):
        chain = graph.chain_from(node_name, max_depth=10)

        if chain is None or chain.length < 1:
            continue

        # Collect pto cells for this chain
        # CRITICAL FIX: Include all ptos from nodes in the chain, but exclude
        # the "wrap-around" edge in cycles (last node pointing back to earlier node).
        chain_ptos = []
        chain_nodes_set = set(chain.nodes)

        for i, node in enumerate(chain.nodes):
            if node in pto_map:
                pto = pto_map[node]

                # Check if this is the last node and it points back into the chain (cycle)
                if i == len(chain.nodes) - 1 and len(pto.values) > 0:
                    target = pto.values[0]
                    target_name = target.name if isinstance(target, Var) else str(target)
                    # Skip if last node points back to any earlier node in chain (cycle)
                    if target_name in chain_nodes_set:
                        continue

                # Include this pto
                chain_ptos.append(pto)

        if not chain_ptos:
            continue

        # Check if chain ends at nil
        tail_successors = graph.get_successors(chain.tail, "next")
        ends_at_nil = (not tail_successors or "nil" in tail_successors)

        # Proposal 1: list(x) if ends at nil and has at least 2 pto cells
        # IMPORTANT: We need at least 2 actual pto cells to form a proper list
        # A single x |-> nil is NOT a valid list (would need list(nil) base case)
        if ends_at_nil and len(chain_ptos) >= 2:
            proposal = FoldProposal(
                predicate_name="list",
                args=[Var(chain.head)],
                pto_cells=chain_ptos,
                side_conditions=[],
                confidence=0.9 if chain.length >= 3 else 0.7
            )
            proposals.append(proposal)

        # Proposal 2: ls(x, y) for list segment
        # Need at least 2 pto cells for a sound list segment
        # SOUNDNESS: With distinctness constraints (distinct in out), a single x|->y
        # cannot prove ls(x,y) because we can't prove x != y from just x|->y
        # (a cell can point to itself). We need at least 2 cells to form a valid chain.
        if chain.length >= 2 and len(chain_ptos) >= 2:
            # Find the tail variable
            # IMPORTANT: The tail should be the DESTINATION of the last pto cell,
            # not necessarily chain.tail (which may include nodes without pto)

            # Get the last pto cell in the chain
            last_pto = chain_ptos[-1]
            if len(last_pto.values) > 0:
                last_val = last_pto.values[0]
                # This is the destination of the last points-to
                if isinstance(last_val, Var):
                    tail_var = last_val
                elif isinstance(last_val, Const) and last_val.value is None:
                    tail_var = Const(None)  # nil
                else:
                    tail_var = last_val
            else:
                # No destination in pto?
                continue

            # CRITICAL FIX: Skip multi-cell cyclic proposals where head == tail
            # ls(x, x) should only be valid for the base case (x = x & emp), not for cycles.
            # A cycle like x -> y -> z -> x with multiple pto cells should NOT be folded
            # into ls(x, x), as this would be unsound.
            # However, we allow single-cell proposals x |-> y where y == x (self-loop),
            # as these can be valid in some structures.
            if isinstance(tail_var, Var) and tail_var.name == chain.head and len(chain_ptos) > 1:
                # This is a multi-cell cycle - skip this proposal
                # Single-cell self-loops are still allowed
                continue

            proposal = FoldProposal(
                predicate_name="ls",
                args=[Var(chain.head), tail_var],
                pto_cells=chain_ptos,
                side_conditions=[],
                confidence=0.85 if chain.length >= 3 else 0.6
            )
            proposals.append(proposal)

        # Proposal 3: ldll (length-annotated doubly-linked list) if applicable
        # Check if this looks like it might need length annotation
        # For now, propose ldll for chains of length 1-2
        if chain.length == 1:
            # Single cell: E1 |-> E2 can form ldll(E1, E1_p, 1, E2, E2_p, 0)
            pto = chain_ptos[0]
            if len(pto.values) == 1 and isinstance(pto.values[0], Var):
                next_var = pto.values[0]
                # This is a single-cell pattern
                # We'll need prev pointer info - check if available
                # For now, create a simpler proposal

                # Check successors to get E2
                tail_successors = graph.get_successors(chain.head, "next")
                if tail_successors and tail_successors[0] != "nil":
                    e2 = Var(tail_successors[0])

                    proposal = FoldProposal(
                        predicate_name="ldll",
                        args=[
                            Var(chain.head),  # E1
                            Var(f"{chain.head}_p"),  # E1_p (placeholder for prev)
                            Const(1),  # len1
                            e2,  # E2 (next)
                            Var(f"{e2.name}_p"),  # E2_p (placeholder)
                            Const(0)   # len2
                        ],
                        pto_cells=chain_ptos,
                        side_conditions=[],  # May need arithmetic constraints
                        confidence=0.5  # Lower confidence for single cell
                    )
                    proposals.append(proposal)

    return proposals


def _propose_dll_folds(graph, pto_atoms: List[PointsTo], predicate_registry=None) -> List[FoldProposal]:
    """
    Propose doubly-linked list folds from detected DLL patterns.

    Note: Only proposes dll folds if the dll predicate is registered with arity 4.
    Different SL-COMP divisions use different dll signatures (2-param vs 4-param).
    """
    proposals = []

    # Check if dll predicate is available and has the expected arity (4)
    # If no registry provided or dll has different arity, skip dll fold proposals
    if predicate_registry is None:
        return proposals  # Conservative: skip if no registry

    dll_pred = predicate_registry.get("dll")
    if dll_pred is None or dll_pred.arity != 4:
        # dll is not registered or has different arity (e.g., 2-param dll in qf_shid_entl)
        # Skip dll fold proposals to avoid arity mismatch errors
        return proposals

    # Map locations to pto atoms
    pto_map = {}
    for pto in pto_atoms:
        if isinstance(pto.location, Var):
            pto_map[pto.location.name] = pto

    # Try detecting DLL patterns from each node
    for node_name in list(graph.nodes.keys()):
        dll_pattern = graph.detect_dll_pattern(node_name, max_depth=10)

        if dll_pattern is None or dll_pattern.length < 1:
            continue

        # Collect pto cells for this DLL
        dll_ptos = []
        for node in dll_pattern.nodes:
            if node in pto_map:
                dll_ptos.append(pto_map[node])

        if not dll_ptos:
            continue

        # Propose dll predicate
        # dll(x, p, y, n) - head x with prev p, tail y with next n
        head_var = Var(dll_pattern.head)

        # Get prev of head (if available)
        head_prevs = graph.get_successors(dll_pattern.head, "prev")
        if head_prevs:
            if head_prevs[0] == "nil":
                prev_var = Const(None)  # nil constant
            else:
                prev_var = Var(head_prevs[0])
        else:
            prev_var = Var(f"{dll_pattern.head}_prev")  # placeholder

        # Get tail and its next
        tail_var = Var(dll_pattern.tail)
        tail_nexts = graph.get_successors(dll_pattern.tail, "next")
        if tail_nexts:
            if tail_nexts[0] == "nil":
                next_var = Const(None)  # nil constant
            else:
                next_var = Var(tail_nexts[0])
        else:
            next_var = Const(None)  # default to nil

        proposal = FoldProposal(
            predicate_name="dll",
            args=[head_var, tail_var, prev_var, next_var],  # dll(fr, bk, pr, nx)
            pto_cells=dll_ptos,
            side_conditions=[],
            confidence=0.8 if dll_pattern.length >= 2 else 0.6
        )
        proposals.append(proposal)

    return proposals


def _propose_cyclic_folds(graph, pto_atoms: List[PointsTo]) -> List[FoldProposal]:
    """
    Propose folds for cyclic heap structures.

    Detects cycles and proposes list segment folds that break the cycle at
    strategic points. This is crucial for SL-COMP benchmarks with cyclic
    structures like: x |-> y * y |-> z * z |-> x

    Strategy:
    - Detect all cycles in the graph
    - For each cycle, propose list segments between different nodes in the cycle
    - Use overlapping segment detection to find convergence points
    """
    proposals = []

    # Map locations to pto atoms
    pto_map = {}
    for pto in pto_atoms:
        if isinstance(pto.location, Var):
            pto_map[pto.location.name] = pto

    # Detect cycles
    cycles = graph.detect_cycles(field="next")

    for cycle in cycles:
        if len(cycle) < 2:
            continue  # Trivial cycle

        # For each pair of nodes in the cycle, propose list segments
        # This allows folding parts of the cycle
        for i in range(len(cycle)):
            for j in range(i + 1, len(cycle)):
                start_node = cycle[i]
                end_node = cycle[j]

                # Find all paths from start to end
                paths = graph.find_all_paths(start_node, end_node, field="next", max_depth=len(cycle) + 2)

                for path in paths:
                    if len(path) < 2:
                        continue

                    # Collect pto cells for this path
                    path_ptos = []
                    for node in path[:-1]:  # Exclude last node (it's the destination)
                        if node in pto_map:
                            path_ptos.append(pto_map[node])

                    if len(path_ptos) < 2:
                        continue  # Need at least 2 cells

                    # Propose ls(start, end) for this path
                    proposal = FoldProposal(
                        predicate_name="ls",
                        args=[Var(start_node), Var(end_node)],
                        pto_cells=path_ptos,
                        side_conditions=[],
                        confidence=0.7  # Moderate confidence for cyclic patterns
                    )
                    proposals.append(proposal)

    # Detect overlapping segments (convergence points)
    overlaps = graph.detect_overlapping_segments(field="next")

    for start1, start2, shared_node in overlaps:
        # Propose ls(start1, shared) and ls(start2, shared)
        # This handles patterns like: x->...->z, y->...->z

        # Find paths
        path1 = graph.find_all_paths(start1, shared_node, max_depth=10)
        path2 = graph.find_all_paths(start2, shared_node, max_depth=10)

        if path1 and path2:
            # Propose for path1
            if len(path1[0]) >= 2:
                ptos1 = []
                for node in path1[0][:-1]:
                    if node in pto_map:
                        ptos1.append(pto_map[node])

                if len(ptos1) >= 2:
                    proposal = FoldProposal(
                        predicate_name="ls",
                        args=[Var(start1), Var(shared_node)],
                        pto_cells=ptos1,
                        side_conditions=[],
                        confidence=0.75  # Good confidence for convergent paths
                    )
                    proposals.append(proposal)

            # Propose for path2
            if len(path2[0]) >= 2:
                ptos2 = []
                for node in path2[0][:-1]:
                    if node in pto_map:
                        ptos2.append(pto_map[node])

                if len(ptos2) >= 2:
                    proposal = FoldProposal(
                        predicate_name="ls",
                        args=[Var(start2), Var(shared_node)],
                        pto_cells=ptos2,
                        side_conditions=[],
                        confidence=0.75
                    )
                    proposals.append(proposal)

    return proposals


def _rank_proposal(proposal: FoldProposal, graph, pto_atoms: List[PointsTo]) -> float:
    """
    Intelligently rank a fold proposal based on multiple factors.

    Scoring factors (each contributes to final score):
    1. Chain length: Longer chains are better (more complete folding)
    2. Predicate simplicity: Prefer simpler predicates (ls > dll > ldll)
    3. Soundness indicators: Check for structural consistency
    4. Coverage: How much of the heap does this fold cover?

    Returns:
        Confidence score between 0.0 and 1.0
    """
    score = 0.0

    # Factor 1: Chain length (0.0 - 0.4 points)
    # Longer chains are more valuable - they fold more of the heap
    num_cells = len(proposal.pto_cells)
    if num_cells >= 5:
        score += 0.4
    elif num_cells >= 3:
        score += 0.3
    elif num_cells >= 2:
        score += 0.2
    else:
        score += 0.1

    # Factor 2: Predicate type (0.0 - 0.3 points)
    # Simpler predicates are more likely to be correct
    predicate_scores = {
        "ls": 0.3,      # Simple list segment - highest priority
        "list": 0.25,   # Null-terminated list - also good
        "dll": 0.2,     # Doubly-linked list - more complex
        "ldll": 0.15,   # Length-annotated DLL - very complex
        "tree": 0.1,    # Tree - complex structure
    }
    score += predicate_scores.get(proposal.predicate_name, 0.1)

    # Factor 3: Argument consistency (0.0 - 0.2 points)
    # Check if arguments are valid and consistent
    args_valid = True
    for arg in proposal.args:
        if isinstance(arg, Var):
            # Check if this variable appears in the heap
            if arg.name not in graph.nodes and arg.name != "nil":
                args_valid = False
                break

    if args_valid:
        score += 0.2

    # Factor 4: Side condition complexity (penalty)
    # Fewer side conditions are better
    if not proposal.side_conditions:
        score += 0.1  # Bonus for no side conditions
    elif len(proposal.side_conditions) > 2:
        score -= 0.1  # Penalty for complex side conditions

    # Factor 5: Coverage ratio (0.0 - 0.2 points)
    # What fraction of the total heap does this fold cover?
    total_pto_count = len(pto_atoms)
    if total_pto_count > 0:
        coverage = num_cells / total_pto_count
        score += 0.2 * coverage

    # Clamp score to [0.0, 1.0]
    return max(0.0, min(1.0, score))

