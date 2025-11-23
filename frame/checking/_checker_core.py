"""
Core Entailment Checking Logic

Extracted from checker.py to reduce file size.
Contains the main check() implementation with all phases of entailment checking.
"""

import z3
from typing import Optional
from frame.core.ast import Formula, Or
from frame.checking._formula_helpers import has_predicate_calls, has_concrete_spatial
from frame.checking._disjunct_handling import extract_disjuncts, score_disjuncts
from frame.preprocessing.equality import EqualityPreprocessor
from frame.encoding.encoder import Z3Encoder


def check_entailment_core(
    checker_self,
    antecedent: Formula,
    consequent: Formula
):
    """
    Core entailment checking logic.
    
    This is the main implementation of the check() method, extracted for maintainability.
    
    Args:
        checker_self: The EntailmentChecker instance
        antecedent: The left-hand side formula (P)
        consequent: The right-hand side formula (Q)
    
    Returns:
        EntailmentResult indicating whether the entailment is valid
    """
    from frame.checking.checker import EntailmentResult
    
    # Fast path: check syntactic equality first (P |- P is always valid)
    if checker_self.analyzer.formulas_syntactically_equal(antecedent, consequent):
        if checker_self.verbose:
            print(f"Checking: {antecedent} |- {consequent}")
            print("Fast path: formulas are syntactically equal")
        return EntailmentResult(valid=True)

    # CRITICAL: Check if antecedent is unsatisfiable
    # In classical logic, FALSE |- Q is always valid (ex falso quodlibet)
    # This is essential for handling cyclic heaps and other contradictions
    #
    # IMPORTANT: We must be careful about when to apply this check:
    # - For formulas with CONCRETE cycles (x->y->z->x), UNSAT is correct
    # - For formulas with PREDICATE cycles (ls(x,y) * ls(y,x)), may be SAT if empty
    #
    # Strategy: Only check UNSAT for concrete (non-predicate) spatial formulas
    # to avoid false positives from predicates that can be empty.
    # For mixed formulas, we rely on unfolding + Z3 to handle correctly.
    has_predicates = has_predicate_calls(antecedent)
    has_spatial = has_concrete_spatial(antecedent)

    # Only apply fast path if formula has concrete spatial BUT NO predicates.
    # Predicates can be empty, so is_satisfiable() might return False after
    # unfolding even when the formula is SAT (empty predicates).
    # For pure concrete heaps, cycles are always UNSAT.
    if has_spatial and not has_predicates and not checker_self.is_satisfiable(antecedent):
        if checker_self.verbose:
            print(f"Checking: {antecedent} |- {consequent}")
            print("Fast path: concrete antecedent is unsatisfiable (anything follows from false)")
        return EntailmentResult(valid=True, reason="Unsatisfiable antecedent (ex falso quodlibet)")

    # S2S optimization: Lazy disjunction splitting for consequent
    # When consequent is Q1 | Q2 | Q3, try disjuncts in order with early termination
    # This avoids checking all disjuncts when one succeeds (huge speedup!)
    from frame.core.ast import Or
    if isinstance(consequent, Or):
        if checker_self.verbose:
            print(f"Lazy disjunction: consequent is disjunction, trying branches...")

        # Extract all disjuncts
        disjuncts = extract_disjuncts(consequent)

        # Score and sort disjuncts by likelihood of success
        scored_disjuncts = score_disjuncts(antecedent, disjuncts)

        # Try each disjunct in order (early termination on success)
        for i, (score, disjunct) in enumerate(scored_disjuncts):
            if checker_self.verbose:
                print(f"  Trying disjunct {i+1}/{len(scored_disjuncts)} (score={score:.1f}): {disjunct}")

            result = checker_self.check(antecedent, disjunct)
            if result.valid:
                if checker_self.verbose:
                    print(f"  ✓ Disjunct {i+1} succeeded, early exit!")
                return EntailmentResult(valid=True, reason=f"disjunct_{i+1}_matched")

        # None succeeded
        if checker_self.verbose:
            print(f"  ✗ No disjunct succeeded")
        return EntailmentResult(valid=False, reason="no_disjunct_matched")

    # Apply equality substitution EARLY (before frame rule)
    eq_preprocessor = EqualityPreprocessor()
    eq_preprocessor._extract_equalities(antecedent)
    eq_preprocessor.substitution_map = {var: eq_preprocessor.uf.find(var)
                                          for var in eq_preprocessor.uf.parent.keys()
                                          if var not in eq_preprocessor.quantified_vars}

    # Apply substitutions if we have either simple or arithmetic substitutions
    if eq_preprocessor.substitution_map or eq_preprocessor.expr_substitution_map:
        antecedent = eq_preprocessor._substitute_formula(antecedent)
        consequent = eq_preprocessor._substitute_formula(consequent)
        if checker_self.verbose:
            print(f"After equality substitution:")
            print(f"  Antecedent: {antecedent}")
            print(f"  Consequent: {consequent}")

    # Eliminate magic wand: P * (P -* Q) → P * Q
    # This is critical for SAT divisions (bsl_sat, rev-*, dispose-*)
    # where wands should not create extension heaps
    antecedent = checker_self.analyzer.eliminate_wand(antecedent, checker=checker_self)
    consequent = checker_self.analyzer.eliminate_wand(consequent, checker=checker_self)
    if checker_self.verbose:
        print(f"After wand elimination:")
        print(f"  Antecedent: {antecedent}")
        print(f"  Consequent: {consequent}")

    # Apply frame rule to simplify if possible
    antecedent, consequent, simplified = checker_self.frame_rule_applicator.apply_frame_rule(antecedent, consequent)
    if simplified and checker_self.analyzer.formulas_syntactically_equal(antecedent, consequent):
        if checker_self.verbose:
            print("Frame rule reduced to trivial case")
        return EntailmentResult(valid=True)

    # Frame inference (bi-abduction): Match parts of consequent and apply frame rule
    # This is the key technique used by Sleek, Infer, and other SOTA solvers
    # NOW INTEGRATED: Uses abduce_frame() for automatic synthesis (when use_abduction=True)
    # Guard against recursion: frame_inference → abduce_frame → check → frame_inference
    if checker_self.use_folding and checker_self.use_lemmas and not checker_self._in_frame_inference:
        from frame.checking.frame_inference import FrameInferenceEngine
        checker_self._in_frame_inference = True  # Set guard
        try:
            frame_engine = FrameInferenceEngine(
                checker_self.predicate_registry,
                timeout=checker_self.timeout,
                verbose=checker_self.verbose,
                checker=checker_self if checker_self.use_abduction else None  # Only pass checker if abduction enabled
            )
            success, reason = frame_engine.try_frame_inference(antecedent, consequent)
            if success:
                # CRITICAL: Frame inference only matches SPATIAL parts.
                # We must also verify any PURE constraints in the consequent!
                # Example: dll-vc14 has consequent (x != z & dll(...))
                # Frame inference matches dll(...) but we must verify x != z separately.

                # Extract pure constraints from consequent
                from frame.utils.formula_utils import extract_pure_formulas
                pure_cons_parts = extract_pure_formulas(consequent)

                if pure_cons_parts:
                    # There are pure constraints - verify them with Z3
                    from frame.core.ast import And as AndFormula
                    pure_ant_parts = extract_pure_formulas(antecedent)

                    # Build pure entailment: pure_ant |- pure_cons
                    # Use Z3 to check if antecedent's pure part entails consequent's pure part
                    from frame.core.ast import And as AndFormula

                    # Build conjunction of pure constraints
                    pure_consequent = pure_cons_parts[0] if len(pure_cons_parts) == 1 else \
                                     AndFormula(pure_cons_parts[0], pure_cons_parts[1]) if len(pure_cons_parts) == 2 else \
                                     AndFormula(pure_cons_parts[0], AndFormula(pure_cons_parts[1], pure_cons_parts[2]))  # simplified

                    encoder = Z3Encoder()
                    solver = z3.Solver()
                    solver.set("timeout", checker_self.timeout)

                    # Encode: pure_ant & ~pure_cons (should be UNSAT if entailment holds)
                    if pure_ant_parts:
                        # Build conjunction of antecedent pure parts
                        for pure_ant in pure_ant_parts:
                            ant_constraint = encoder.encode_pure(pure_ant)
                            solver.add(ant_constraint)

                    cons_constraint = encoder.encode_pure(pure_consequent)
                    solver.add(z3.Not(cons_constraint))

                    pure_check = solver.check()

                    if pure_check == z3.unsat:
                        # Pure constraints entailed - frame inference success is valid!
                        if checker_self.verbose:
                            print(f"Frame inference: {reason}")
                            print(f"Pure constraints verified: {pure_consequent}")
                        return EntailmentResult(valid=True, reason=reason + " (pure constraints verified)")
                    else:
                        # Pure constraints NOT entailed - frame inference claimed false positive!
                        if checker_self.verbose:
                            print(f"Frame inference matched spatial parts but pure constraints FAILED")
                            print(f"Pure consequent not entailed: {pure_consequent}")
                        # Fall through to continue with other strategies
                else:
                    # No pure constraints in consequent - frame inference success is valid
                    if checker_self.verbose:
                        print(f"Frame inference: {reason}")
                    return EntailmentResult(valid=True, reason=reason)
        finally:
            checker_self._in_frame_inference = False  # Clear guard

    # Goal-directed folding: try to fold antecedent to match consequent
    # This is more efficient than blind folding because it prioritizes proposals matching the goal
    # Skip for SAT checks to avoid over-constraining the formula
    # NOTE: Folding verification checks concrete ⊢ predicate (correct direction for entailment)
    # Combined with acyclic heap assumptions, folding is sound for entailment checking
    if checker_self.use_folding and checker_self.use_lemmas:  # Use same flag as lemmas since this is a proving technique
        # Try multi-step folding first (more powerful, can handle long chains)
        # Phase 3/4 optimization: Increase max_iterations for complex SL-COMP benchmarks
        from frame.folding.goal_directed import fold_towards_goal_multistep
        folded_formula, num_folds = fold_towards_goal_multistep(
            antecedent, consequent, checker_self.predicate_registry,
            max_iterations=10, timeout=checker_self.timeout, verbose=checker_self.verbose
        )
        if folded_formula is not None and num_folds > 0:
            if checker_self.verbose:
                print(f"Multi-step folding: {num_folds} folds applied")
            # After folding, recursively check the folded formula
            # This allows the folded predicates to be proven
            try:
                folded_result = checker_self.check(folded_formula, consequent)
                if folded_result.valid:
                    return EntailmentResult(valid=True, reason=f"Multi-step folding: {num_folds} folds")
            except RecursionError:
                # Fall through to normal checking if recursion limit hit
                pass

    # Try to apply lemmas from the lemma library
    if checker_self.use_lemmas and checker_self.lemma_library:
        # Try multi-step lemma application first (more powerful, handles cases like multi-transitivity)
        multistep_result = checker_self.lemma_library.try_apply_lemma_multistep(
            antecedent, consequent, max_iterations=5, verbose=checker_self.verbose
        )
        if multistep_result is not None:
            lemma_desc, num_applications = multistep_result
            if checker_self.verbose:
                print(f"Multi-step lemma: {lemma_desc} ({num_applications} applications)")
            return EntailmentResult(valid=True, reason=f"Multi-step lemma: {lemma_desc}")

        # Fall back to single-step lemma application
        lemma_name = checker_self.lemma_library.try_apply_lemma(antecedent, consequent)
        if lemma_name:
            if checker_self.verbose:
                print(f"Lemma applied: {lemma_name}")
            return EntailmentResult(valid=True, reason=f"Lemma: {lemma_name}")

    # Heap graph-based list segment checking
    heap_graph_result = checker_self.graph_analyzer.check_list_segments_via_graph(
        antecedent, consequent, checker_self.predicate_registry)
    if heap_graph_result is not None:
        if checker_self.verbose:
            print(f"Heap graph check: {'valid' if heap_graph_result else 'invalid'}")
        return EntailmentResult(valid=heap_graph_result,
                              reason="Heap graph analysis" if not heap_graph_result else None)

    # Predicate matching: try to match antecedent against consequent predicate structure
    predicate_match_result = checker_self.predicate_matcher.try_predicate_matching(antecedent, consequent)
    if predicate_match_result is not None:
        if checker_self.verbose:
            print(f"Predicate matching: {'valid' if predicate_match_result else 'invalid'}")
        return EntailmentResult(valid=predicate_match_result,
                              reason="Predicate shape matching")

    # Sanity check: reject obviously invalid entailments
    sanity_result = checker_self.heuristic_checker.sanity_check_entailment(antecedent, consequent)
    if sanity_result is not None:
        if checker_self.verbose:
            print(f"Checking: {antecedent} |- {consequent}")
            print(f"Sanity check: {'valid' if sanity_result else 'invalid'}")
        return EntailmentResult(valid=sanity_result,
                              reason="Sanity check" if not sanity_result else None)

    # PREDICATE FOLDING: Synthesize predicates from concrete heap structures
    # This is done BEFORE unfolding to maximize effectiveness
    # Skip for SAT checks to avoid over-constraining the formula
    # NOTE: Folding verification checks concrete ⊢ predicate (correct direction)
    # The claim about bidirectional equivalence is incorrect - we only need concrete ⊢ predicate
    # for entailment checking, which is exactly what the verification ensures
    if checker_self.use_folding:
        from frame.folding.blind import fold_formula_blind
        try:
            antecedent_folded = fold_formula_blind(
                antecedent,
                checker_self.predicate_registry,
                timeout=min(2000, checker_self.timeout // 2),  # Use shorter timeout for folding
                verbose=checker_self.verbose
            )
            if antecedent_folded != antecedent:
                antecedent = antecedent_folded
                if checker_self.verbose:
                    print(f"After folding:")
                    print(f"  Antecedent: {antecedent}")

                # Re-check if folding made formulas equal
                if checker_self.analyzer.formulas_syntactically_equal(antecedent, consequent):
                    if checker_self.verbose:
                        print("Folding made formulas equal!")
                    return EntailmentResult(valid=True, reason="Predicate folding")

                # Recursively check the folded formula to allow lemma application
                # This is critical: folding may create predicates like list(x) that can be
                # proven via lemmas like list(x) |- ls(x, nil)
                try:
                    folded_result = checker_self.check(antecedent_folded, consequent)
                    if folded_result.valid:
                        return EntailmentResult(valid=True, reason="Blind folding + " + (folded_result.reason or "recursive check"))
                except RecursionError:
                    # Fall through to normal checking if recursion limit hit
                    if checker_self.verbose:
                        print("Recursion limit hit after blind folding, continuing...")
                    pass
        except Exception as e:
            # If folding fails, continue without it
            if checker_self.verbose:
                print(f"Folding failed with error: {e}")
                print("Continuing without folding...")

    encoder = Z3Encoder()
    # Set mode to ENTAILMENT for entailment checking
    encoder._spatial_encoder.wand_encoder.mode = "ENTAILMENT"

    solver = z3.Solver()
    solver.set("timeout", checker_self.timeout)

    if checker_self.verbose:
        print(f"Checking: {antecedent} |- {consequent}")

    # Unfold predicates if present (use adaptive depth if enabled)
    if checker_self.use_cyclic_proof:
        # Use cyclic proof-aware unfolding for antecedent
        from frame.folding.cyclic_unfold import unfold_with_cycles
        antecedent_unfolded = unfold_with_cycles(
            antecedent, checker_self.predicate_registry,
            adaptive=checker_self.adaptive_unfolding, verbose=checker_self.verbose
        )

        # Use S2S-style normalized unfolding for consequent if enabled
        if checker_self.use_s2s_normalization:
            from frame.checking.s2s_normalized import unfold_with_normalization
            consequent_unfolded = unfold_with_normalization(
                consequent, antecedent_unfolded, checker_self.predicate_registry,
                verbose=checker_self.verbose
            )
        else:
            consequent_unfolded = unfold_with_cycles(
                consequent, checker_self.predicate_registry,
                adaptive=checker_self.adaptive_unfolding, verbose=checker_self.verbose
            )
    else:
        # Use traditional bounded unfolding
        antecedent_unfolded = checker_self.predicate_registry.unfold_predicates(antecedent, adaptive=checker_self.adaptive_unfolding)

        if checker_self.use_s2s_normalization:
            from frame.checking.s2s_normalized import unfold_with_normalization
            consequent_unfolded = unfold_with_normalization(
                consequent, antecedent_unfolded, checker_self.predicate_registry,
                verbose=checker_self.verbose
            )
        else:
            consequent_unfolded = checker_self.predicate_registry.unfold_predicates(consequent, adaptive=checker_self.adaptive_unfolding)

    if checker_self.verbose and (antecedent_unfolded != antecedent or consequent_unfolded != consequent):
        print(f"After unfolding:")
        print(f"  Antecedent: {antecedent_unfolded}")
        print(f"  Consequent: {consequent_unfolded}")

    # Re-check syntactic equality after unfolding
    if checker_self.analyzer.formulas_syntactically_equal(antecedent_unfolded, consequent_unfolded):
        if checker_self.verbose:
            print("Formulas are syntactically equal after unfolding")
        return EntailmentResult(valid=True, reason="Syntactic equality after unfolding")

    # Try unification-based matching before Z3
    unification_result = checker_self._try_unification_matching(antecedent_unfolded, consequent_unfolded)
    if unification_result is not None:
        return unification_result

    # Encode the entailment
    entailment = encoder.encode_entailment(antecedent_unfolded, consequent_unfolded)

    # Check validity by checking if the entailment is a tautology
    # We check if the negation is UNSAT
    solver.add(z3.Not(entailment))

    result = solver.check()

    if checker_self.verbose:
        print(f"Z3 result: {result}")

    if result == z3.unsat:
        # Negation is UNSAT, so entailment is valid
        return EntailmentResult(valid=True)
    elif result == z3.sat:
        # Found a counterexample
        model = solver.model()
        return EntailmentResult(valid=False, model=model,
                              reason="Counterexample found")
    else:  # unknown
        return EntailmentResult(valid=False, reason="Z3 returned unknown (timeout or too complex)")

