"""
Folding utilities and shared logic.

Common operations used across different folding strategies.
"""

from typing import List, Optional, Tuple
from frame.core.ast import Formula
from frame.heap.graph import HeapGraph, FoldProposal, build_heap_graph, propose_folds, _collect_pto_atoms


def generate_fold_proposals(
    formula: Formula,
    max_proposals: int = 20,
    min_pto_atoms: int = 1,
    predicate_registry=None
) -> Tuple[Optional[HeapGraph], List[FoldProposal]]:
    """
    Generate fold proposals from a formula.

    This is the shared pipeline used by both blind and goal-directed folding:
    1. Build heap graph from formula
    2. Collect points-to atoms
    3. Generate fold proposals

    Args:
        formula: Formula to generate proposals from
        max_proposals: Maximum number of proposals to generate
        min_pto_atoms: Minimum number of pto atoms needed (0 to allow empty)
        predicate_registry: Optional PredicateRegistry to check predicate arities

    Returns:
        Tuple of (heap_graph, proposals). Returns (None, []) if insufficient pto atoms.
    """
    # Build heap graph
    heap_graph = build_heap_graph(formula)

    # Collect points-to atoms
    pto_atoms = _collect_pto_atoms(formula)

    # Check if we have enough atoms
    if len(pto_atoms) < min_pto_atoms:
        return None, []

    # Generate proposals
    proposals = propose_folds(heap_graph, pto_atoms, max_proposals=max_proposals,
                            predicate_registry=predicate_registry)

    return heap_graph, proposals


def check_overlap(proposal1: FoldProposal, proposal2: FoldProposal) -> bool:
    """
    Check if two fold proposals overlap (share any pto cells).

    Two proposals overlap if they try to fold any of the same points-to cells
    (compared by location). Overlapping proposals cannot be applied simultaneously.

    Args:
        proposal1: First fold proposal
        proposal2: Second fold proposal

    Returns:
        True if proposals overlap, False otherwise
    """
    from typing import Set

    # Compare pto cells by their locations
    locs1: Set[str] = set()
    for pto in proposal1.pto_cells:
        if hasattr(pto.location, 'name'):
            locs1.add(pto.location.name)
        else:
            locs1.add(str(pto.location))

    locs2: Set[str] = set()
    for pto in proposal2.pto_cells:
        if hasattr(pto.location, 'name'):
            locs2.add(pto.location.name)
        else:
            locs2.add(str(pto.location))

    return bool(locs1 & locs2)
