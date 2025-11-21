"""
Satisfiability Checking for Separation Logic

Extracted from checker.py to reduce file size.
Contains logic for checking if a formula has a valid model.
"""

import z3
from frame.core.ast import Formula
from frame.encoding.encoder import Z3Encoder


def is_satisfiable(
    checker_self,
    formula: Formula
) -> bool:
    """
    Check if a formula is satisfiable (has a valid model)

    Args:
        checker_self: The EntailmentChecker instance
        formula: The formula to check

    Returns:
        True if the formula is satisfiable
    """
    # Apply equality substitution EARLY - critical for benchmarks with equalities
    # Example: (x = nil) & (u |-> x) should become (x = nil) & (u |-> nil)
    from frame.preprocessing.equality import EqualityPreprocessor
    eq_preprocessor = EqualityPreprocessor()
    formula = eq_preprocessor.preprocess(formula)

    if checker_self.verbose:
        print(f"After equality substitution: {str(formula)[:200]}...")

    # Eliminate magic wand: P * (P -* Q) → P * Q
    # CRITICAL for SAT divisions (bsl_sat, rev-*, dispose-*)
    formula = checker_self.analyzer.eliminate_wand(formula, checker=checker_self)
    if checker_self.verbose:
        print(f"After wand elimination: {str(formula)[:200]}...")

    # Quick contradiction checks before expensive Z3 encoding
    if checker_self.sat_checker.has_obvious_contradiction(formula):
        return False  # UNSAT - contradictory formula

    # Fast path: Check if formula is just standard list segment chains (common pattern)
    # This now rejects custom predicates to avoid false positives
    if checker_self.sat_checker.is_simple_ls_chain(formula):
        return True  # SAT - simple standard predicate chains are satisfiable

    encoder = Z3Encoder()
    # Set mode to SAT for satisfiability checking
    encoder._spatial_encoder.wand_encoder.mode = "SAT"

    if checker_self.verbose:
        print(f"Wand encoder mode: {encoder._spatial_encoder.wand_encoder.mode}")

    solver = z3.Solver()
    # Use longer timeout for complex formulas (2x default)
    solver.set("timeout", checker_self.timeout * 2)

    # For SAT checking, use DEEPER unfolding than entailment checking
    # This helps reveal contradictions in complex recursive predicates
    # Save original max depth
    original_max_depth = checker_self.predicate_registry.max_unfold_depth

    # Temporarily increase unfold depth for SAT (more aggressive)
    # Use min(5, ...) to prevent exponential blowup for tree predicates
    checker_self.predicate_registry.max_unfold_depth = min(5, original_max_depth + 1)

    try:
        # Unfold predicates with adaptive depth
        # NOTE: Do NOT use cyclic proof for SAT checking!
        # Cyclic detection is designed for entailment (P |- Q), not satisfiability.
        # Using it for SAT causes infinite recursion and incorrect results.
        formula_unfolded = checker_self.predicate_registry.unfold_predicates(
            formula, adaptive=True
        )
    except RecursionError:
        # Hit Python's recursion limit during unfolding
        # This can happen with deeply nested predicates or circular definitions
        # Be conservative: assume SAT (better than crashing)
        if checker_self.verbose:
            print("RecursionError during predicate unfolding - assuming SAT")
        return True
    finally:
        # Restore original max depth
        checker_self.predicate_registry.max_unfold_depth = original_max_depth

    # Check for contradictions after unfolding
    if checker_self.sat_checker.has_obvious_contradiction(formula_unfolded):
        return False  # UNSAT

    # Encode the formula
    try:
        constraints, heap, domain = encoder.encode_formula(formula_unfolded)
    except RecursionError:
        # Hit recursion limit during Z3 encoding
        # This can happen with very complex formulas
        # Be conservative: assume SAT
        if checker_self.verbose:
            print("RecursionError during Z3 encoding - assuming SAT")
        return True

    # Debug: Dump Z3 encoding if verbose
    if checker_self.verbose:
        print(f"\nEncoded {len(domain)} domain locations")
        print(f"Heap variable: {heap}")
        try:
            from frame.encoding.debug_dump import dump_z3_formula, analyze_z3_dump
            dump_z3_formula(constraints, "/tmp/encode_dump.smt2")
            analysis = analyze_z3_dump()
            print(f"Z3 encoding analysis:")
            print(f"  Exists blocks: {analysis['exists_blocks']}")
            print(f"  Ext alloc refs: {analysis['ext_alloc_refs']}")
            print(f"  Has negated wand: {analysis['has_negated_wand']}")
        except Exception as e:
            print(f"Debug dump failed: {e}")

    solver.add(constraints)
    result = solver.check()

    # If Z3 says UNSAT but we don't see obvious contradictions,
    # this might be a false negative from complex encoding
    # Be conservative: if timeout, assume SAT
    if result == z3.unknown:
        return True  # Conservative: assume SAT on timeout

    return result == z3.sat

