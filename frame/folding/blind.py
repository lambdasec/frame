"""
Blind predicate folding.

This module implements blind/iterative folding: repeatedly folding
concrete heap structures into predicates without a specific goal.

Algorithm:
1. Build heap graph from formula
2. Generate fold proposals (unguided)
3. Verify proposals (unification + Z3)
4. Apply verified folds
5. Repeat until convergence or max iterations

Use this when you want to fold all possible predicates in a formula.
For goal-directed folding (more efficient), use goal_directed.py instead.
"""

from typing import List, Optional
from frame.core.ast import Formula
from frame.heap.graph import FoldProposal, _extract_spatial_atoms
from frame.folding.verify import verify_proposal_with_z3, verify_proposal_with_unification
from frame.folding.apply import apply_fold
from frame.folding.utils import generate_fold_proposals, check_overlap
from frame.encoding.encoder import Z3Encoder
from frame.predicates import PredicateRegistry
from frame.utils.formula_utils import extract_pure_formulas


# Tunable parameters
MAX_FOLDS = 50  # Maximum number of fold iterations
TOP_K = 3       # Number of top proposals to verify
MIN_CONFIDENCE = 0.5  # Minimum confidence to consider a proposal
MIN_CHAIN_LENGTH = 2  # Minimum chain length to fold


def fold_formula_blind(
    formula: Formula,
    predicate_registry: PredicateRegistry,
    timeout: int = 2000,
    verbose: bool = False
) -> Formula:
    """
    Blind folding: repeatedly fold concrete heap structures into predicates.

    This performs iterative, unguided folding until convergence or max iterations.
    It tries to fold all possible predicates without a specific goal.

    For goal-directed folding (more efficient), use fold_towards_goal() instead.

    Args:
        formula: The formula to fold
        predicate_registry: Registry of available predicates
        timeout: Z3 timeout per verification (milliseconds)
        verbose: Print debug information

    Returns:
        Transformed formula with predicates folded
    """
    if verbose:
        print(f"[Blind Folding] Starting")
        print(f"[Blind Folding] Original: {formula}")

    # Initialize encoder
    z3_encoder = Z3Encoder()

    # Extract pure constraints from formula (for verification)
    pure_constraints = extract_pure_formulas(formula)

    # Main folding loop
    current_formula = formula
    folds_applied = 0

    for iteration in range(MAX_FOLDS):
        if verbose:
            print(f"[Blind Folding] Iteration {iteration + 1}")

        # Generate fold proposals using shared logic
        heap_graph, proposals = generate_fold_proposals(
            current_formula,
            max_proposals=10,
            min_pto_atoms=MIN_CHAIN_LENGTH,
            predicate_registry=predicate_registry
        )

        if heap_graph is None:
            if verbose:
                print(f"[Blind Folding] Too few pto atoms to fold")
            break

        if not proposals:
            if verbose:
                print(f"[Blind Folding] No proposals generated")
            break

        # Filter by confidence threshold
        proposals = [p for p in proposals if p.confidence >= MIN_CONFIDENCE]

        if not proposals:
            if verbose:
                print(f"[Blind Folding] No proposals meet confidence threshold")
            break

        # Sort proposals by (confidence desc, size desc)
        proposals.sort(
            key=lambda p: (p.confidence, len(p.pto_cells)),
            reverse=True
        )

        if verbose:
            print(f"[Blind Folding] Generated {len(proposals)} proposals:")
            for i, p in enumerate(proposals):
                marker = " [TOP_K]" if i < TOP_K else ""
                print(f"  {i+1}. {p} (confidence: {p.confidence:.2f}){marker}")

        # Try to verify and apply top-K proposals
        applied_in_iteration = False

        for proposal in proposals[:TOP_K]:
            # Try unification-based verification first (faster and more precise)
            if verbose:
                print(f"[Blind Folding] Verifying proposal: {proposal}")

            # Try unification first - pass current_formula for cycle detection
            is_sound = verify_proposal_with_unification(
                proposal, predicate_registry, pure_constraints, verbose,
                full_antecedent=current_formula
            )

            # Fall back to Z3 if unification doesn't work
            if not is_sound:
                if verbose:
                    print(f"[Blind Folding] Unification verification failed, trying Z3...")
                is_sound = verify_proposal_with_z3(
                    proposal, pure_constraints, z3_encoder, timeout, predicate_registry
                )

            if is_sound:
                if verbose:
                    print(f"[Blind Folding] ✓ Verified! Applying fold...")

                # Apply the fold
                current_formula = apply_fold(proposal, current_formula)
                folds_applied += 1
                applied_in_iteration = True

                if verbose:
                    print(f"[Blind Folding] After fold: {current_formula}")

                # Break to re-analyze heap graph with updated formula
                break
            else:
                if verbose:
                    print(f"[Blind Folding] ✗ Verification failed, skipping")

        # If we didn't apply any fold this iteration, stop
        if not applied_in_iteration:
            if verbose:
                print(f"[Blind Folding] No folds applied this iteration, stopping")
            break

    if verbose:
        print(f"[Blind Folding] Finished: {folds_applied} folds applied")
        print(f"[Blind Folding] Final: {current_formula}")

    return current_formula


def fold_formula_batch(
    formula: Formula,
    predicate_registry: PredicateRegistry,
    max_proposals: int = 5,
    timeout: int = 2000,
    verbose: bool = False
) -> Formula:
    """
    Alternative folding strategy: batch verification and application.

    Instead of greedy one-at-a-time, this verifies multiple proposals
    and applies all non-overlapping verified proposals.

    Args:
        formula: Formula to fold
        predicate_registry: Registry of available predicates
        max_proposals: Maximum proposals to verify in parallel
        timeout: Z3 timeout per verification
        verbose: Print debug information

    Returns:
        Transformed formula with predicates folded
    """
    if verbose:
        print(f"[Folding Batch] Starting")

    z3_encoder = Z3Encoder()
    pure_constraints = extract_pure_formulas(formula)

    # Generate fold proposals using shared logic
    heap_graph, proposals = generate_fold_proposals(
        formula,
        max_proposals=max_proposals * 2,
        min_pto_atoms=MIN_CHAIN_LENGTH,
        predicate_registry=predicate_registry
    )

    if heap_graph is None or not proposals:
        return formula

    # Filter by confidence threshold
    proposals = [p for p in proposals if p.confidence >= MIN_CONFIDENCE]

    if not proposals:
        return formula

    # Sort by confidence and size
    proposals.sort(
        key=lambda p: (p.confidence, len(p.pto_cells)),
        reverse=True
    )

    # Verify top proposals
    verified_proposals = []

    for proposal in proposals[:max_proposals]:
        if verify_proposal_with_z3(proposal, pure_constraints, z3_encoder, timeout):
            verified_proposals.append(proposal)

    if not verified_proposals:
        if verbose:
            print(f"[Folding Batch] No proposals verified")
        return formula

    # Select non-overlapping proposals
    non_overlapping = _select_non_overlapping(verified_proposals)

    if verbose:
        print(f"[Folding Batch] Applying {len(non_overlapping)} non-overlapping folds")

    # Apply all non-overlapping folds
    result = formula
    for proposal in non_overlapping:
        result = apply_fold(proposal, result)

    return result


def _select_non_overlapping(proposals: List[FoldProposal]) -> List[FoldProposal]:
    """
    Select a maximal set of non-overlapping proposals.

    Uses a greedy algorithm: pick highest confidence proposals first,
    skip any that overlap with already selected ones.

    Args:
        proposals: List of verified proposals (sorted by priority)

    Returns:
        Subset of proposals that don't overlap
    """
    selected = []

    for proposal in proposals:
        # Check if this proposal overlaps with any already selected
        overlaps = False
        for selected_proposal in selected:
            if check_overlap(proposal, selected_proposal):
                overlaps = True
                break

        if not overlaps:
            selected.append(proposal)

    return selected
