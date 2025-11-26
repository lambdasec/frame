"""
Goal-Directed Predicate Folding

This module implements goal-directed folding: synthesizing predicates from
concrete heap structures that help prove a specific entailment.

Unlike blind folding (fold_antecedent), this takes BOTH the antecedent and
consequent, allowing it to prioritize fold proposals that match the goal.

Algorithm:
1. Extract target predicates from consequent (what we're trying to prove)
2. Generate fold proposals from antecedent's concrete heap
3. PRIORITIZE proposals that match target predicates
4. BASE CHECKING: Verify concrete heap matches predicate's base (S2S approach)
5. Verify proposals for soundness
6. Return matching proposals

MULTI-STEP FOLDING:
7. Apply successful fold to antecedent
8. Repeat steps 2-7 until no more folds possible or goal reached

BASE CHECKING INTEGRATION (NEW):
Before expensive verification, check if the concrete heap structure matches
the predicate's spatial base (computed compositionally via S2S approach).
This provides early soundness filtering and improves performance.

This is much more efficient than trying all proposals blindly, and multi-step
folding enables long chains like x|->y * y|->z * z|->w to fold completely.
"""

from typing import Optional, List, Set, Tuple
from frame.core.ast import Formula, Var, PredicateCall
from frame.heap.graph import FoldProposal
from frame.folding.utils import generate_fold_proposals
from frame.arithmetic.synth import extract_pure_constraints_z3
from frame.encoding.encoder import Z3Encoder
from frame.folding._goal_directed_helpers import (
    verify_proposal_soundness,
    synthesize_and_verify_arithmetic,
    check_proposal_matches_goal,
    extract_pure_parts
)


def extract_target_predicates(formula: Formula) -> Set[str]:
    """
    Extract predicate names from a formula.

    These are the "targets" we're trying to prove, so we should prioritize
    fold proposals that produce these predicates.

    Enhanced to handle:
    - Separating conjunctions: ls(x,y) * ls(z,w) → {"ls"}
    - Pure + spatial: (x=y) ∧ ls(x,z) → {"ls"}
    - Nested formulas: quantifiers, conjunctions, etc.

    Args:
        formula: Formula to extract from (usually the consequent)

    Returns:
        Set of predicate names (e.g., {"ls", "dll", "tree"})
    """
    targets = set()

    def extract(f: Formula):
        if isinstance(f, PredicateCall):
            targets.add(f.name)
        # Handle binary formulas (SepConj, And, Or, etc.)
        elif hasattr(f, 'left') and hasattr(f, 'right'):
            extract(f.left)
            extract(f.right)
        # Handle unary formulas (Not, quantifiers, etc.)
        elif hasattr(f, 'formula'):
            extract(f.formula)
        # Handle existentials/foralls
        elif hasattr(f, 'body'):
            extract(f.body)

    extract(formula)
    return targets


def prioritize_by_goal(proposals: List[FoldProposal], targets: Set[str]) -> List[FoldProposal]:
    """
    Reorder proposals to try matching targets first.

    Proposals that produce target predicates get boosted confidence,
    so they're tried before non-matching proposals.

    Args:
        proposals: List of fold proposals
        targets: Set of target predicate names

    Returns:
        Reordered list with matching proposals first
    """
    # Boost confidence for matching proposals
    for proposal in proposals:
        if proposal.predicate_name in targets:
            proposal.confidence += 0.5  # Boost by 0.5 to prioritize

    # Sort by confidence (descending)
    proposals.sort(key=lambda p: p.confidence, reverse=True)
    return proposals


def check_heap_matches_base(
    proposal: FoldProposal,
    predicate_registry,
    verbose: bool = False
) -> bool:
    """
    Check if concrete heap structure matches predicate's spatial base.

    This implements the S2S approach: before accepting a fold proposal,
    verify that the concrete heap cells satisfy the predicate's base
    constraints. This provides early soundness filtering.

    For example:
    - ls(x, y) has base: (x = y ∧ emp) ∨ (x ≠ nil)
    - Concrete heap: x |-> y satisfies base (x is allocated, so x ≠ nil)
    - Therefore, this fold is potentially sound

    Args:
        proposal: Fold proposal containing concrete heap cells
        predicate_registry: Registry with base computation support
        verbose: Enable debug output

    Returns:
        True if concrete heap matches base, False otherwise
    """
    try:
        # Get the predicate definition
        pred = predicate_registry.get(proposal.predicate_name)
        if pred is None:
            if verbose:
                print(f"[Base Check] Predicate {proposal.predicate_name} not found in registry")
            return False

        # Get or compute the spatial base
        base_registry = predicate_registry._get_base_registry()
        if base_registry is None:
            # Base computation disabled, skip check
            return True

        # Compute base if not cached
        spatial_base, numeric_base = base_registry.compute_base(pred)

        if verbose:
            print(f"[Base Check] Spatial base for {proposal.predicate_name}: {spatial_base}")
            print(f"[Base Check] Numeric base for {proposal.predicate_name}: {numeric_base}")

        # SOUNDNESS CHECK: Verify concrete heap matches base
        # For now, we use a simple heuristic:
        # 1. If proposal has pto cells, predicate should allow allocated heap
        # 2. If proposal is empty (no pto cells), predicate should allow emp

        from frame.core.ast import True_, Emp

        # Simple heuristic: if we have points-to cells, the base should not be just Emp
        if proposal.pto_cells:
            # We have concrete allocations
            # Base should allow non-empty heap (not be exactly Emp)
            if isinstance(spatial_base, Emp):
                if verbose:
                    print(f"[Base Check] ✗ Predicate base is emp, but proposal has allocations")
                return False

            # If base is True_, it means no constraints (always safe)
            if isinstance(spatial_base, True_):
                return True

            # More sophisticated check: base should be consistent with having allocations
            # For now, we accept if base is not just Emp
            if verbose:
                print(f"[Base Check] ✓ Concrete heap has allocations, base allows non-empty")
            return True
        else:
            # Proposal is empty (no pto cells)
            # This is unusual but can happen for emp predicates
            if verbose:
                print(f"[Base Check] ✓ Proposal has no allocations")
            return True

    except Exception as e:
        if verbose:
            print(f"[Base Check] Error: {e}")
        # On error, be conservative and accept the proposal
        # Full verification will catch any issues
        return True


def fold_towards_goal(
    antecedent: Formula,
    consequent: Formula,
    predicate_registry,
    timeout: int = 2000,
    verbose: bool = False
) -> Optional[str]:
    """
    Goal-directed folding: Try to fold antecedent to match consequent.

    This is more efficient than blind folding because it:
    1. Extracts target predicates from consequent
    2. Prioritizes proposals that match targets
    3. Returns early when a match is found

    Args:
        antecedent: The formula to fold (contains concrete heap)
        consequent: The goal we're trying to prove (contains target predicates)
        predicate_registry: Registry of available predicates
        timeout: Z3 timeout for arithmetic synthesis (milliseconds)
        verbose: Enable debug output

    Returns:
        Name of the fold applied (e.g., "graph_fold_dll") if successful, None otherwise
    """
    try:
        # Extract target predicates from consequent
        targets = extract_target_predicates(consequent)

        if verbose and targets:
            print(f"[Goal-Directed Folding] Targets: {targets}")

        # Generate fold proposals using shared logic
        graph, proposals = generate_fold_proposals(antecedent, max_proposals=30,
                                                  predicate_registry=predicate_registry)

        if graph is None or not proposals:
            return None

        # PRIORITIZE proposals that match targets
        proposals = prioritize_by_goal(proposals, targets)

        if verbose:
            print(f"[Goal-Directed Folding] Generated {len(proposals)} proposals (prioritized):")
            for i, p in enumerate(proposals):
                match = " [MATCHES GOAL]" if p.predicate_name in targets else ""
                print(f"  {i+1}. {p.predicate_name} (confidence: {p.confidence:.2f}){match}")

        # Create Z3 encoder for arithmetic synthesis and verification
        encoder = Z3Encoder()
        pure_constraints_z3 = extract_pure_constraints_z3(antecedent, encoder)

        # Extract pure parts for verification
        pure_parts = extract_pure_parts(antecedent)

        # Try each proposal (prioritized by goal matching)
        for proposal in proposals:
            # STEP 1: BASE CHECKING (S2S approach)
            if not check_heap_matches_base(proposal, predicate_registry, verbose=verbose):
                if verbose:
                    print(f"[Goal-Directed Folding] Proposal {proposal.predicate_name} failed base check")
                continue

            # STEP 2: SOUNDNESS VERIFICATION
            if not verify_proposal_soundness(proposal, predicate_registry, pure_parts, verbose=verbose, use_unification=True):
                continue

            # STEP 3: ARITHMETIC SYNTHESIS AND VERIFICATION
            if not synthesize_and_verify_arithmetic(proposal, graph, encoder, pure_constraints_z3, timeout_ms=1000, verbose=verbose):
                continue

            # STEP 4: CHECK IF PROPOSAL MATCHES GOAL
            # Get witness map for lemma naming
            from frame.arithmetic.synth import synthesize_arith_for_chain
            chain = None
            if proposal.pto_cells and isinstance(proposal.pto_cells[0].location, Var):
                chain = graph.chain_from(proposal.pto_cells[0].location.name)

            witness_map = None
            if chain:
                _, witness_map = synthesize_arith_for_chain(chain, proposal, encoder)

            lemma_name = check_proposal_matches_goal(proposal, consequent, witness_map, verbose=verbose)
            if lemma_name:
                return lemma_name

        if verbose:
            print(f"[Goal-Directed Folding] No matching proposals found")

        return None

    except Exception as e:
        if verbose:
            print(f"[Goal-Directed Folding] Error: {e}")
        return None


def apply_fold_to_formula(formula: Formula, proposal: FoldProposal) -> Formula:
    """
    Apply a fold proposal to a formula, replacing concrete cells with a predicate.

    Args:
        formula: The formula to transform
        proposal: The fold proposal to apply

    Returns:
        New formula with pto cells replaced by predicate call
    """
    from frame.analysis.formula import FormulaAnalyzer
    analyzer = FormulaAnalyzer()

    # Extract spatial parts
    parts = analyzer._extract_sepconj_parts(formula)

    # Remove the cells involved in the fold
    remaining_parts = []
    for part in parts:
        # Check if this part is one of the folded cells
        if any(analyzer.formulas_syntactically_equal(part, pto) for pto in proposal.pto_cells):
            continue  # Skip this cell, it's being folded
        remaining_parts.append(part)

    # Add the new predicate
    new_pred = proposal.to_predicate_call()
    remaining_parts.append(new_pred)

    # Rebuild formula
    if not remaining_parts:
        from frame.core.ast import Emp
        return Emp()

    return analyzer._build_sepconj(remaining_parts)


def has_spatial_conflict(proposal: FoldProposal, formula: Formula, verbose: bool = False) -> bool:
    """
    Check if folding a pto into a predicate would conflict with existing predicates.

    A spatial conflict occurs when:
    1. The pto's location X is being folded into a predicate
    2. There's already a predicate in the formula that starts at X

    For example, if we have:
        ldll(E2, ...) * E2 |-> (...)
    Then folding E2 |-> (...) into a dll would conflict because ldll(E2, ...)
    already (potentially) allocates E2.

    Args:
        proposal: The fold proposal containing the pto being folded
        formula: The current formula
        verbose: Enable debug output

    Returns:
        True if there's a conflict (fold should be rejected), False otherwise
    """
    from frame.core.ast import PredicateCall, SepConj, And, PointsTo

    # Get the location(s) being folded
    folded_locations = set()
    for pto in proposal.pto_cells:
        if hasattr(pto.location, 'name'):
            folded_locations.add(pto.location.name)
        else:
            folded_locations.add(str(pto.location))

    # Extract predicates from the formula
    def extract_predicates(f):
        predicates = []
        if isinstance(f, PredicateCall):
            predicates.append(f)
        elif isinstance(f, (SepConj, And)):
            predicates.extend(extract_predicates(f.left))
            predicates.extend(extract_predicates(f.right))
        elif hasattr(f, 'formula'):  # Quantifiers, Not, etc.
            predicates.extend(extract_predicates(f.formula))
        return predicates

    predicates = extract_predicates(formula)

    # Check each predicate for potential conflict
    for pred in predicates:
        if not pred.args:
            continue

        # Get the first argument (typically the head/start location)
        first_arg = pred.args[0]
        pred_start = first_arg.name if hasattr(first_arg, 'name') else str(first_arg)

        # If the predicate starts at a location we're folding, there's a conflict
        if pred_start in folded_locations:
            if verbose:
                print(f"[Spatial Conflict] ✗ Predicate {pred.name}({pred_start}, ...) "
                      f"conflicts with folding pto at {pred_start}")
            return True

    return False


def fold_towards_goal_multistep(
    antecedent: Formula,
    consequent: Formula,
    predicate_registry,
    max_iterations: int = 5,
    timeout: int = 2000,
    verbose: bool = False
) -> Tuple[Optional[Formula], int]:
    """
    Multi-step goal-directed folding: Iteratively fold antecedent to match consequent.

    This enhances fold_towards_goal by folding MULTIPLE times, enabling long
    chains to be fully folded into predicates.

    Example:
        Antecedent: x |-> y * y |-> z * z |-> w * w |-> nil
        Consequent: list(x)

        Step 1: Fold w |-> nil into ls(w, nil)
        Step 2: Fold z |-> w * ls(w, nil) into ls(z, nil)
        Step 3: Fold y |-> z * ls(z, nil) into ls(y, nil)
        Step 4: Fold x |-> y * ls(y, nil) into list(x)

    Args:
        antecedent: The formula to fold (contains concrete heap)
        consequent: The goal we're trying to prove (contains target predicates)
        predicate_registry: Registry of available predicates
        max_iterations: Maximum number of fold iterations
        timeout: Z3 timeout for arithmetic synthesis (milliseconds)
        verbose: Enable debug output

    Returns:
        (folded_formula, num_folds) if successful, (None, 0) otherwise
    """
    if verbose:
        print(f"[Multi-Step Folding] Starting with max_iterations={max_iterations}")
        print(f"[Multi-Step Folding] Antecedent: {antecedent}")
        print(f"[Multi-Step Folding] Consequent: {consequent}")

    current = antecedent
    total_folds = 0

    for iteration in range(max_iterations):
        if verbose:
            print(f"\n[Multi-Step Folding] Iteration {iteration + 1}/{max_iterations}")

        # Extract targets from consequent
        targets = extract_target_predicates(consequent)

        # Generate fold proposals
        graph, proposals = generate_fold_proposals(current, max_proposals=20,
                                                  predicate_registry=predicate_registry)

        if graph is None or not proposals:
            if verbose:
                print(f"[Multi-Step Folding] No proposals available, stopping")
            break

        # Prioritize by goal
        proposals = prioritize_by_goal(proposals, targets)

        # Create encoder for verification
        encoder = Z3Encoder()
        pure_constraints_z3 = extract_pure_constraints_z3(current, encoder)

        # Extract pure parts
        pure_parts = extract_pure_parts(current)

        # Try to apply ONE fold this iteration
        fold_applied = False

        for proposal in proposals:
            # STEP 0: SPATIAL CONFLICT CHECK (CRITICAL FOR SOUNDNESS)
            # Check if the pto being folded conflicts with existing predicates
            if has_spatial_conflict(proposal, current, verbose=verbose):
                if verbose:
                    print(f"[Multi-Step Folding] Proposal {proposal.predicate_name} rejected due to spatial conflict")
                continue

            # STEP 1: BASE CHECKING
            if not check_heap_matches_base(proposal, predicate_registry, verbose=verbose):
                if verbose:
                    print(f"[Multi-Step Folding] Proposal {proposal.predicate_name} failed base check")
                continue

            # STEP 2: SOUNDNESS VERIFICATION (use unification for speed and accuracy)
            if not verify_proposal_soundness(proposal, predicate_registry, pure_parts, verbose=verbose, use_unification=True):
                continue

            # STEP 3: ARITHMETIC SYNTHESIS AND VERIFICATION
            if not synthesize_and_verify_arithmetic(proposal, graph, encoder, pure_constraints_z3, timeout_ms=1000, verbose=verbose):
                continue

            # SUCCESS! Apply this fold
            if verbose:
                print(f"[Multi-Step Folding] ✓ Applying fold: {proposal.predicate_name}")

            current = apply_fold_to_formula(current, proposal)
            total_folds += 1
            fold_applied = True

            if verbose:
                print(f"[Multi-Step Folding] New formula: {current}")

            break  # Only apply one fold per iteration

        if not fold_applied:
            if verbose:
                print(f"[Multi-Step Folding] No valid fold found, stopping after {iteration} iterations")
            break

    if verbose:
        print(f"\n[Multi-Step Folding] Complete: {total_folds} folds applied")

    if total_folds > 0:
        return current, total_folds

    return None, 0
