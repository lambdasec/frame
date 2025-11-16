"""
Entailment Checker for Separation Logic

This module provides the main interface for checking entailments in separation logic.
"""

import z3
from typing import Optional
from frame.core.ast import Formula, PredicateCall
from frame.encoding.encoder import Z3Encoder
from frame.predicates import PredicateRegistry
from frame.lemmas.base import LemmaLibrary
from frame.preprocessing.equality import EqualityPreprocessor
from frame.analysis.formula import FormulaAnalyzer
from frame.checking.heuristics import HeuristicChecker
from frame.heap.graph_analysis import HeapGraphAnalyzer
from frame.analysis.predicate_matching import PredicateMatcher
from frame.utils.frame_rule import FrameRuleApplicator
from frame.utils.satisfiability import SatisfiabilityChecker
from frame.analysis.unification import Unifier

# Internal helper modules for checker
from frame.checking._formula_helpers import (
    has_predicate_calls, has_concrete_spatial,
    count_formulas_by_type, contains_formula_type
)
from frame.checking._disjunct_handling import extract_disjuncts, score_disjuncts
from frame.checking._frame_inference import find_frame, abduce_frame


class EntailmentResult:
    """Result of an entailment check"""

    def __init__(self, valid: bool, model: Optional[z3.ModelRef] = None,
                 reason: Optional[str] = None):
        self.valid = valid
        self.model = model
        self.reason = reason

    def __str__(self) -> str:
        if self.valid:
            return "Valid entailment"
        else:
            msg = "Invalid entailment"
            if self.reason:
                msg += f": {self.reason}"
            if self.model:
                msg += f"\nCounterexample: {self.model}"
            return msg

    def __bool__(self) -> bool:
        return self.valid


class EntailmentChecker:
    """
    Main entailment checker for separation logic.

    Checks whether one formula entails another: P |- Q
    """

    def __init__(self, predicate_registry: Optional[PredicateRegistry] = None,
                 timeout: int = 5000, verbose: bool = False, adaptive_unfolding: bool = True,
                 use_lemmas: bool = True, use_cyclic_proof: bool = True, use_folding: bool = True,
                 use_abduction: bool = False, use_s2s_normalization: bool = False):
        """
        Initialize the entailment checker.

        Args:
            predicate_registry: Registry of inductive predicates
            timeout: Z3 solver timeout in milliseconds
            verbose: Print debug information
            adaptive_unfolding: Use adaptive unfolding depth based on formula complexity
            use_lemmas: Use lemma library for proving entailments
            use_cyclic_proof: Use cyclic proof detection (enabled by default for improved accuracy)
            use_folding: Use predicate folding (both goal-directed and blind). Disable for SAT checks.
            use_abduction: Enable frame abduction for spec inference (DEFAULT: False).
                          When enabled, checker can synthesize missing preconditions.
                          Use for automatic specification inference, NOT standard entailment.
            use_s2s_normalization: Use S2S-style normalized unfolding to avoid disjunction explosion
                          (enabled by default for improved performance on benchmarks)
        """
        self.predicate_registry = predicate_registry or PredicateRegistry()
        self.timeout = timeout
        self.verbose = verbose
        self.adaptive_unfolding = adaptive_unfolding
        self.use_lemmas = use_lemmas
        self.use_cyclic_proof = use_cyclic_proof
        self.use_folding = use_folding
        self.use_abduction = use_abduction
        self.use_s2s_normalization = use_s2s_normalization
        # Pass predicate registry to lemma library for validation
        self.lemma_library = LemmaLibrary(self.predicate_registry) if use_lemmas else None

        # Initialize helper components
        self.analyzer = FormulaAnalyzer()
        self.heuristic_checker = HeuristicChecker(verbose=verbose, predicate_registry=self.predicate_registry)
        self.graph_analyzer = HeapGraphAnalyzer(verbose=verbose)
        self.predicate_matcher = PredicateMatcher(verbose=verbose)
        self.frame_rule_applicator = FrameRuleApplicator(verbose=verbose, lemma_library=self.lemma_library)
        self.sat_checker = SatisfiabilityChecker(verbose=verbose)
        self.unifier = Unifier(verbose=verbose)

        # Recursion guard: prevent infinite loops when frame inference calls abduce_frame
        self._in_frame_inference = False

    def check(self, antecedent: Formula, consequent: Formula) -> EntailmentResult:
        """
        Check if antecedent |- consequent (antecedent entails consequent)

        Args:
            antecedent: The left-hand side formula (P)
            consequent: The right-hand side formula (Q)

        Returns:
            EntailmentResult indicating whether the entailment is valid
        """
        # Fast path: check syntactic equality first (P |- P is always valid)
        if self.analyzer.formulas_syntactically_equal(antecedent, consequent):
            if self.verbose:
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
        if has_spatial and not has_predicates and not self.is_satisfiable(antecedent):
            if self.verbose:
                print(f"Checking: {antecedent} |- {consequent}")
                print("Fast path: concrete antecedent is unsatisfiable (anything follows from false)")
            return EntailmentResult(valid=True, reason="Unsatisfiable antecedent (ex falso quodlibet)")

        # S2S optimization: Lazy disjunction splitting for consequent
        # When consequent is Q1 | Q2 | Q3, try disjuncts in order with early termination
        # This avoids checking all disjuncts when one succeeds (huge speedup!)
        from frame.core.ast import Or
        if isinstance(consequent, Or):
            if self.verbose:
                print(f"Lazy disjunction: consequent is disjunction, trying branches...")

            # Extract all disjuncts
            disjuncts = extract_disjuncts(consequent)

            # Score and sort disjuncts by likelihood of success
            scored_disjuncts = score_disjuncts(antecedent, disjuncts)

            # Try each disjunct in order (early termination on success)
            for i, (score, disjunct) in enumerate(scored_disjuncts):
                if self.verbose:
                    print(f"  Trying disjunct {i+1}/{len(scored_disjuncts)} (score={score:.1f}): {disjunct}")

                result = self.check(antecedent, disjunct)
                if result.valid:
                    if self.verbose:
                        print(f"  ✓ Disjunct {i+1} succeeded, early exit!")
                    return EntailmentResult(valid=True, reason=f"disjunct_{i+1}_matched")

            # None succeeded
            if self.verbose:
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
            if self.verbose:
                print(f"After equality substitution:")
                print(f"  Antecedent: {antecedent}")
                print(f"  Consequent: {consequent}")

        # Eliminate magic wand: P * (P -* Q) → P * Q
        # This is critical for SAT divisions (bsl_sat, rev-*, dispose-*)
        # where wands should not create extension heaps
        antecedent = self.analyzer.eliminate_wand(antecedent, checker=self)
        consequent = self.analyzer.eliminate_wand(consequent, checker=self)
        if self.verbose:
            print(f"After wand elimination:")
            print(f"  Antecedent: {antecedent}")
            print(f"  Consequent: {consequent}")

        # Apply frame rule to simplify if possible
        antecedent, consequent, simplified = self.frame_rule_applicator.apply_frame_rule(antecedent, consequent)
        if simplified and self.analyzer.formulas_syntactically_equal(antecedent, consequent):
            if self.verbose:
                print("Frame rule reduced to trivial case")
            return EntailmentResult(valid=True)

        # Frame inference (bi-abduction): Match parts of consequent and apply frame rule
        # This is the key technique used by Sleek, Infer, and other SOTA solvers
        # NOW INTEGRATED: Uses abduce_frame() for automatic synthesis (when use_abduction=True)
        # Guard against recursion: frame_inference → abduce_frame → check → frame_inference
        if self.use_folding and self.use_lemmas and not self._in_frame_inference:
            from frame.checking.frame_inference import FrameInferenceEngine
            self._in_frame_inference = True  # Set guard
            try:
                frame_engine = FrameInferenceEngine(
                    self.predicate_registry,
                    timeout=self.timeout,
                    verbose=self.verbose,
                    checker=self if self.use_abduction else None  # Only pass checker if abduction enabled
                )
                success, reason = frame_engine.try_frame_inference(antecedent, consequent)
                if success:
                    if self.verbose:
                        print(f"Frame inference: {reason}")
                    return EntailmentResult(valid=True, reason=reason)
            finally:
                self._in_frame_inference = False  # Clear guard

        # Goal-directed folding: try to fold antecedent to match consequent
        # This is more efficient than blind folding because it prioritizes proposals matching the goal
        # Skip for SAT checks to avoid over-constraining the formula
        # NOTE: Folding verification checks concrete ⊢ predicate (correct direction for entailment)
        # Combined with acyclic heap assumptions, folding is sound for entailment checking
        if self.use_folding and self.use_lemmas:  # Use same flag as lemmas since this is a proving technique
            # Try multi-step folding first (more powerful, can handle long chains)
            # Phase 3/4 optimization: Increase max_iterations for complex SL-COMP benchmarks
            from frame.folding.goal_directed import fold_towards_goal_multistep
            folded_formula, num_folds = fold_towards_goal_multistep(
                antecedent, consequent, self.predicate_registry,
                max_iterations=10, timeout=self.timeout, verbose=self.verbose
            )
            if folded_formula is not None and num_folds > 0:
                if self.verbose:
                    print(f"Multi-step folding: {num_folds} folds applied")
                # After folding, recursively check the folded formula
                # This allows the folded predicates to be proven
                try:
                    folded_result = self.check(folded_formula, consequent)
                    if folded_result.valid:
                        return EntailmentResult(valid=True, reason=f"Multi-step folding: {num_folds} folds")
                except RecursionError:
                    # Fall through to normal checking if recursion limit hit
                    pass

        # Try to apply lemmas from the lemma library
        if self.use_lemmas and self.lemma_library:
            # Try multi-step lemma application first (more powerful, handles cases like multi-transitivity)
            multistep_result = self.lemma_library.try_apply_lemma_multistep(
                antecedent, consequent, max_iterations=5, verbose=self.verbose
            )
            if multistep_result is not None:
                lemma_desc, num_applications = multistep_result
                if self.verbose:
                    print(f"Multi-step lemma: {lemma_desc} ({num_applications} applications)")
                return EntailmentResult(valid=True, reason=f"Multi-step lemma: {lemma_desc}")

            # Fall back to single-step lemma application
            lemma_name = self.lemma_library.try_apply_lemma(antecedent, consequent)
            if lemma_name:
                if self.verbose:
                    print(f"Lemma applied: {lemma_name}")
                return EntailmentResult(valid=True, reason=f"Lemma: {lemma_name}")

        # Heap graph-based list segment checking
        heap_graph_result = self.graph_analyzer.check_list_segments_via_graph(
            antecedent, consequent, self.predicate_registry)
        if heap_graph_result is not None:
            if self.verbose:
                print(f"Heap graph check: {'valid' if heap_graph_result else 'invalid'}")
            return EntailmentResult(valid=heap_graph_result,
                                  reason="Heap graph analysis" if not heap_graph_result else None)

        # Predicate matching: try to match antecedent against consequent predicate structure
        predicate_match_result = self.predicate_matcher.try_predicate_matching(antecedent, consequent)
        if predicate_match_result is not None:
            if self.verbose:
                print(f"Predicate matching: {'valid' if predicate_match_result else 'invalid'}")
            return EntailmentResult(valid=predicate_match_result,
                                  reason="Predicate shape matching")

        # Sanity check: reject obviously invalid entailments
        sanity_result = self.heuristic_checker.sanity_check_entailment(antecedent, consequent)
        if sanity_result is not None:
            if self.verbose:
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
        if self.use_folding:
            from frame.folding.blind import fold_formula_blind
            try:
                antecedent_folded = fold_formula_blind(
                    antecedent,
                    self.predicate_registry,
                    timeout=min(2000, self.timeout // 2),  # Use shorter timeout for folding
                    verbose=self.verbose
                )
                if antecedent_folded != antecedent:
                    antecedent = antecedent_folded
                    if self.verbose:
                        print(f"After folding:")
                        print(f"  Antecedent: {antecedent}")

                    # Re-check if folding made formulas equal
                    if self.analyzer.formulas_syntactically_equal(antecedent, consequent):
                        if self.verbose:
                            print("Folding made formulas equal!")
                        return EntailmentResult(valid=True, reason="Predicate folding")

                    # Recursively check the folded formula to allow lemma application
                    # This is critical: folding may create predicates like list(x) that can be
                    # proven via lemmas like list(x) |- ls(x, nil)
                    try:
                        folded_result = self.check(antecedent_folded, consequent)
                        if folded_result.valid:
                            return EntailmentResult(valid=True, reason="Blind folding + " + (folded_result.reason or "recursive check"))
                    except RecursionError:
                        # Fall through to normal checking if recursion limit hit
                        if self.verbose:
                            print("Recursion limit hit after blind folding, continuing...")
                        pass
            except Exception as e:
                # If folding fails, continue without it
                if self.verbose:
                    print(f"Folding failed with error: {e}")
                    print("Continuing without folding...")

        encoder = Z3Encoder()
        # Set mode to ENTAILMENT for entailment checking
        encoder._spatial_encoder.wand_encoder.mode = "ENTAILMENT"

        solver = z3.Solver()
        solver.set("timeout", self.timeout)

        if self.verbose:
            print(f"Checking: {antecedent} |- {consequent}")

        # Unfold predicates if present (use adaptive depth if enabled)
        if self.use_cyclic_proof:
            # Use cyclic proof-aware unfolding for antecedent
            from frame.folding.cyclic_unfold import unfold_with_cycles
            antecedent_unfolded = unfold_with_cycles(
                antecedent, self.predicate_registry,
                adaptive=self.adaptive_unfolding, verbose=self.verbose
            )

            # Use S2S-style normalized unfolding for consequent if enabled
            if self.use_s2s_normalization:
                from frame.checking.s2s_normalized import unfold_with_normalization
                consequent_unfolded = unfold_with_normalization(
                    consequent, antecedent_unfolded, self.predicate_registry,
                    verbose=self.verbose
                )
            else:
                consequent_unfolded = unfold_with_cycles(
                    consequent, self.predicate_registry,
                    adaptive=self.adaptive_unfolding, verbose=self.verbose
                )
        else:
            # Use traditional bounded unfolding
            antecedent_unfolded = self.predicate_registry.unfold_predicates(antecedent, adaptive=self.adaptive_unfolding)

            if self.use_s2s_normalization:
                from frame.checking.s2s_normalized import unfold_with_normalization
                consequent_unfolded = unfold_with_normalization(
                    consequent, antecedent_unfolded, self.predicate_registry,
                    verbose=self.verbose
                )
            else:
                consequent_unfolded = self.predicate_registry.unfold_predicates(consequent, adaptive=self.adaptive_unfolding)

        if self.verbose and (antecedent_unfolded != antecedent or consequent_unfolded != consequent):
            print(f"After unfolding:")
            print(f"  Antecedent: {antecedent_unfolded}")
            print(f"  Consequent: {consequent_unfolded}")

        # Re-check syntactic equality after unfolding
        if self.analyzer.formulas_syntactically_equal(antecedent_unfolded, consequent_unfolded):
            if self.verbose:
                print("Formulas are syntactically equal after unfolding")
            return EntailmentResult(valid=True, reason="Syntactic equality after unfolding")

        # Try unification-based matching before Z3
        unification_result = self._try_unification_matching(antecedent_unfolded, consequent_unfolded)
        if unification_result is not None:
            return unification_result

        # Encode the entailment
        entailment = encoder.encode_entailment(antecedent_unfolded, consequent_unfolded)

        # Check validity by checking if the entailment is a tautology
        # We check if the negation is UNSAT
        solver.add(z3.Not(entailment))

        result = solver.check()

        if self.verbose:
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

    def check_entailment(self, entailment_text: str) -> EntailmentResult:
        """
        Check an entailment from a text string with turnstile |-

        This is a convenience method that parses the entailment and checks it.

        Args:
            entailment_text: String like "P |- Q"

        Returns:
            EntailmentResult indicating whether the entailment is valid

        Example:
            >>> checker = EntailmentChecker()
            >>> result = checker.check_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
            >>> print(result.valid)  # True
        """
        from frame.core.parser import parse_entailment
        antecedent, consequent = parse_entailment(entailment_text)
        return self.check(antecedent, consequent)

    def check_equiv(self, formula1: Formula, formula2: Formula) -> bool:
        """
        Check if two formulas are equivalent: P ≡ Q

        This checks both P |- Q and Q |- P
        """
        forward = self.check(formula1, formula2)
        backward = self.check(formula2, formula1)

        return forward.valid and backward.valid

    def is_satisfiable(self, formula: Formula) -> bool:
        """
        Check if a formula is satisfiable (has a valid model)

        Args:
            formula: The formula to check

        Returns:
            True if the formula is satisfiable
        """
        # Apply equality substitution EARLY - critical for benchmarks with equalities
        # Example: (x = nil) & (u |-> x) should become (x = nil) & (u |-> nil)
        from frame.preprocessing.equality import EqualityPreprocessor
        eq_preprocessor = EqualityPreprocessor()
        formula = eq_preprocessor.preprocess(formula)

        if self.verbose:
            print(f"After equality substitution: {str(formula)[:200]}...")

        # Eliminate magic wand: P * (P -* Q) → P * Q
        # CRITICAL for SAT divisions (bsl_sat, rev-*, dispose-*)
        formula = self.analyzer.eliminate_wand(formula, checker=self)
        if self.verbose:
            print(f"After wand elimination: {str(formula)[:200]}...")

        # Quick contradiction checks before expensive Z3 encoding
        if self.sat_checker.has_obvious_contradiction(formula):
            return False  # UNSAT - contradictory formula

        # Fast path: Check if formula is just standard list segment chains (common pattern)
        # This now rejects custom predicates to avoid false positives
        if self.sat_checker.is_simple_ls_chain(formula):
            return True  # SAT - simple standard predicate chains are satisfiable

        encoder = Z3Encoder()
        # Set mode to SAT for satisfiability checking
        encoder._spatial_encoder.wand_encoder.mode = "SAT"

        if self.verbose:
            print(f"Wand encoder mode: {encoder._spatial_encoder.wand_encoder.mode}")

        solver = z3.Solver()
        # Use longer timeout for complex formulas (2x default)
        solver.set("timeout", self.timeout * 2)

        # For SAT checking, use DEEPER unfolding than entailment checking
        # This helps reveal contradictions in complex recursive predicates
        # Save original max depth
        original_max_depth = self.predicate_registry.max_unfold_depth

        # Temporarily increase unfold depth for SAT (more aggressive)
        # Use min(5, ...) to prevent exponential blowup for tree predicates
        self.predicate_registry.max_unfold_depth = min(5, original_max_depth + 1)

        try:
            # Unfold predicates with adaptive depth
            # NOTE: Do NOT use cyclic proof for SAT checking!
            # Cyclic detection is designed for entailment (P |- Q), not satisfiability.
            # Using it for SAT causes infinite recursion and incorrect results.
            formula_unfolded = self.predicate_registry.unfold_predicates(
                formula, adaptive=True
            )
        finally:
            # Restore original max depth
            self.predicate_registry.max_unfold_depth = original_max_depth

        # Check for contradictions after unfolding
        if self.sat_checker.has_obvious_contradiction(formula_unfolded):
            return False  # UNSAT

        # Encode the formula
        constraints, heap, domain = encoder.encode_formula(formula_unfolded)

        # Debug: Dump Z3 encoding if verbose
        if self.verbose:
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

    def _try_unification_matching(self, antecedent: Formula, consequent: Formula) -> Optional[EntailmentResult]:
        """
        Try to prove entailment using unification-based matching.

        This handles cases where predicates with fresh variables (from unfolding)
        need to be matched against concrete heap structures.

        IMPORTANT: Only applies unification when consequent has "fresh" variables
        (ones starting with z_ from unfolding). Otherwise, returns None to avoid
        incorrectly unifying concrete variables that should remain distinct.

        Args:
            antecedent: Antecedent formula (may have concrete heap)
            consequent: Consequent formula (may have fresh variables from unfolding)

        Returns:
            EntailmentResult if unification succeeds, None otherwise
        """
        from frame.core.ast import SepConj, PointsTo, PredicateCall, Or, Exists, Var

        # Check if consequent has fresh variables (from unfolding)
        # Fresh variables start with "z_" followed by digits
        def has_fresh_vars(formula):
            """Check if formula contains fresh variables from unfolding"""
            from frame.core.ast import Exists, And, Not, Eq, Neq, ArithExpr

            if isinstance(formula, Var):
                return formula.name.startswith("z_") and formula.name[2:].replace("_", "").isdigit()
            elif isinstance(formula, PointsTo):
                return has_fresh_vars(formula.location) or any(has_fresh_vars(v) for v in formula.values)
            elif isinstance(formula, PredicateCall):
                return any(has_fresh_vars(arg) for arg in formula.args)
            elif isinstance(formula, (SepConj, Or, And)):
                return has_fresh_vars(formula.left) or has_fresh_vars(formula.right)
            elif isinstance(formula, Exists):
                # Check if the bound variable is fresh OR if the body contains fresh vars
                var_is_fresh = formula.var.startswith("z_") and formula.var[2:].replace("_", "").isdigit()
                return var_is_fresh or has_fresh_vars(formula.formula)
            elif isinstance(formula, Not):
                return has_fresh_vars(formula.formula)
            elif isinstance(formula, (Eq, Neq)):
                return has_fresh_vars(formula.left) or has_fresh_vars(formula.right)
            elif isinstance(formula, ArithExpr):
                return has_fresh_vars(formula.left) or has_fresh_vars(formula.right)
            else:
                return False

        # Only use unification if consequent has fresh variables
        if not has_fresh_vars(consequent):
            return None  # No fresh vars, don't use unification

        # Try to unify the two formulas
        subst = self.unifier.unify_formulas(antecedent, consequent)

        if subst is not None and subst:
            # Unification succeeded! Apply substitution and check equality
            ante_subst = self.unifier.apply_subst_formula(antecedent, subst)
            cons_subst = self.unifier.apply_subst_formula(consequent, subst)

            if self.analyzer.formulas_syntactically_equal(ante_subst, cons_subst):
                if self.verbose:
                    print(f"✓ Unification-based matching succeeded!")
                    print(f"  Substitution: {subst}")
                return EntailmentResult(valid=True, reason="Unification matching")

        # Component-wise matching also only applies with fresh variables
        # (Otherwise we might incorrectly match concrete structures)
        ante_parts = self.analyzer._extract_sepconj_parts(antecedent)
        cons_parts = self.analyzer._extract_sepconj_parts(consequent)

        # Check if any consequent parts have fresh vars
        if not any(has_fresh_vars(part) for part in cons_parts):
            return None

        # If consequent is smaller, try to find matching parts
        if len(cons_parts) <= len(ante_parts):
            # Try to match each consequent part with some antecedent part
            matched_count = 0
            current_subst = None

            for cons_part in cons_parts:
                # Skip non-spatial parts (And, Or, etc.)
                if not isinstance(cons_part, (PointsTo, PredicateCall)):
                    continue

                # Try to unify with each antecedent part
                found_match = False
                for ante_part in ante_parts:
                    if not isinstance(ante_part, (PointsTo, PredicateCall)):
                        continue

                    # Try unification
                    part_subst = self.unifier.unify_formulas(cons_part, ante_part, current_subst)
                    if part_subst is not None:
                        # Check if substitution is consistent
                        cons_applied = self.unifier.apply_subst_formula(cons_part, part_subst)
                        ante_applied = self.unifier.apply_subst_formula(ante_part, part_subst)

                        if self.analyzer.formulas_syntactically_equal(cons_applied, ante_applied):
                            matched_count += 1
                            current_subst = part_subst
                            found_match = True
                            break

                if not found_match:
                    # Couldn't match this consequent part
                    return None

            # If we matched all consequent parts AND matched at least one component, entailment is valid
            expected_matches = len([p for p in cons_parts if isinstance(p, (PointsTo, PredicateCall))])
            if matched_count > 0 and matched_count == expected_matches:
                if self.verbose:
                    print(f"✓ Component-wise unification succeeded!")
                    print(f"  Matched {matched_count} components")
                    if current_subst:
                        print(f"  Substitution: {current_subst}")
                return EntailmentResult(valid=True, reason="Component-wise unification")

        # Unification didn't help
        return None

    def find_frame(self, antecedent: Formula, consequent: Formula) -> Optional[Formula]:
        """Delegate to frame inference helper"""
        return find_frame(self, antecedent, consequent)

    def abduce_frame(self, antecedent: Formula, consequent: Formula) -> Optional[Formula]:
        """Delegate to frame inference helper"""
        return abduce_frame(self, antecedent, consequent)
