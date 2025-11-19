"""
Goal-Directed Folding Helper Functions

Internal helper module for common verification and validation operations
used in goal-directed folding.
"""

from typing import Optional, Tuple, List, Any
from frame.core.ast import Formula, Var
from frame.heap.graph import FoldProposal


def verify_proposal_soundness(
    proposal: FoldProposal,
    predicate_registry,
    pure_parts: List[Formula],
    verbose: bool = False,
    use_unification: bool = True
) -> bool:
    """
    Verify that a fold proposal is sound.

    Args:
        proposal: The fold proposal to verify
        predicate_registry: Registry of predicates
        pure_parts: Pure (non-spatial) parts of the formula
        verbose: Enable debug output
        use_unification: Use unification-based verification (fast) vs Z3 (slower)

    Returns:
        True if proposal is sound, False otherwise
    """
    try:
        if use_unification:
            from frame.folding.verify import verify_proposal_with_unification
            is_sound = verify_proposal_with_unification(
                proposal,
                predicate_registry,
                pure_parts,
                verbose=verbose
            )
        else:
            from frame.folding.verify import verify_proposal_with_z3
            from frame.encoding.encoder import Z3Encoder
            encoder = Z3Encoder()
            is_sound = verify_proposal_with_z3(
                proposal,
                pure_parts,
                encoder,
                timeout=2000,
                predicate_registry=predicate_registry
            )

        if not is_sound and verbose:
            print(f"[Verification] Proposal {proposal.predicate_name} failed soundness check")

        return is_sound

    except Exception as e:
        if verbose:
            print(f"[Verification] Error during soundness check: {e}")
        return False


def synthesize_and_verify_arithmetic(
    proposal: FoldProposal,
    graph,
    encoder,
    pure_constraints_z3,
    timeout_ms: int = 1000,
    verbose: bool = False
) -> bool:
    """
    Synthesize arithmetic side conditions for a proposal and verify them.

    Args:
        proposal: The fold proposal
        graph: The heap graph
        encoder: Z3 encoder
        pure_constraints_z3: Pure constraints encoded in Z3
        timeout_ms: Timeout for verification (milliseconds)
        verbose: Enable debug output

    Returns:
        True if arithmetic conditions can be synthesized and verified, False otherwise
    """
    from frame.arithmetic.synth import synthesize_arith_for_chain
    from frame.arithmetic.check import verify_side_conditions

    # Get the chain from the graph if available
    chain = None
    if proposal.pto_cells:
        first_pto = proposal.pto_cells[0]
        if isinstance(first_pto.location, Var):
            chain = graph.chain_from(first_pto.location.name)

    if not chain:
        # No chain, no arithmetic needed
        return True

    # Synthesize arithmetic witnesses
    side_constraints, witness_map = synthesize_arith_for_chain(chain, proposal, encoder)

    if not side_constraints:
        # No constraints synthesized
        return True

    # Verify the side conditions
    is_valid = verify_side_conditions(side_constraints, pure_constraints_z3, timeout_ms=timeout_ms)

    if not is_valid and verbose:
        print(f"[Arithmetic] Side conditions failed for {proposal.predicate_name}")

    return is_valid


def check_proposal_matches_goal(
    proposal: FoldProposal,
    consequent: Formula,
    witness_map: Optional[dict] = None,
    verbose: bool = False
) -> Optional[str]:
    """
    Check if a fold proposal matches the goal (consequent).

    Args:
        proposal: The fold proposal
        consequent: The goal formula
        witness_map: Optional arithmetic witness map
        verbose: Enable debug output

    Returns:
        Lemma name if match found, None otherwise
    """
    from frame.lemmas._matcher import LemmaMatcher
    from frame.core.ast import PredicateCall
    from frame.analysis.formula import FormulaAnalyzer
    from frame.utils.formula_utils import extract_spatial_part

    matcher = LemmaMatcher()
    proposed_pred = proposal.to_predicate_call()

    # Direct match: consequent is a single predicate
    if isinstance(consequent, PredicateCall):
        if matcher.formulas_equal(proposed_pred, consequent):
            lemma_name = f"graph_fold_{proposal.predicate_name}"
            if witness_map:
                lemma_name += "_arith"

            if verbose:
                print(f"[Goal Match] ✓ Found match: {lemma_name}")

            return lemma_name

    # Partial match: consequent is a separating conjunction
    # Try to match the proposed predicate against ANY part of the consequent
    analyzer = FormulaAnalyzer()
    consequent_parts = analyzer._extract_sepconj_parts(consequent)

    for part in consequent_parts:
        if isinstance(part, PredicateCall):
            if matcher.formulas_equal(proposed_pred, part):
                lemma_name = f"graph_fold_{proposal.predicate_name}_partial"
                if witness_map:
                    lemma_name += "_arith"

                if verbose:
                    print(f"[Goal Match] ✓ Found partial match: {lemma_name}")
                    print(f"  Matched: {proposed_pred} against {part}")

                return lemma_name

    # Try matching spatial part of consequent (for pure + spatial formulas)
    consequent_spatial = extract_spatial_part(consequent)
    if consequent_spatial and isinstance(consequent_spatial, PredicateCall):
        if matcher.formulas_equal(proposed_pred, consequent_spatial):
            lemma_name = f"graph_fold_{proposal.predicate_name}"
            if witness_map:
                lemma_name += "_arith"

            if verbose:
                print(f"[Goal Match] ✓ Found spatial match: {lemma_name}")

            return lemma_name

    return None


def extract_pure_parts(formula: Formula) -> List[Formula]:
    """
    Extract pure (non-spatial) parts from a formula.

    Args:
        formula: The formula to analyze

    Returns:
        List of pure formula parts
    """
    from frame.analysis.formula import FormulaAnalyzer

    analyzer = FormulaAnalyzer()
    parts = analyzer._extract_sepconj_parts(formula)
    return [p for p in parts if not p.is_spatial()]
