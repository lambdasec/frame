"""
Frame Inference for Separation Logic (Bi-Abduction)

This module implements frame inference to prove entailments by:
1. Matching parts of the consequent through folding
2. Applying frame rule to remove matched parts
3. Recursively proving the remainder

This is similar to bi-abduction in tools like Sleek and Infer.
"""

from typing import Optional, Tuple, List
from frame.core.ast import Formula, SepConj, Emp, PredicateCall, PointsTo
from frame.analysis.formula import FormulaAnalyzer
from frame.utils.frame_rule import FrameRuleApplicator
from frame.folding.goal_directed import extract_target_predicates
from frame.lemmas._matcher import LemmaMatcher


class FrameInferenceEngine:
    """
    Engine for frame inference (bi-abduction).

    Tries to prove P |- Q by:
    1. Finding parts of Q that can be matched in P (through folding or directly)
    2. Applying frame rule to remove matched parts
    3. Recursively proving remainder
    """

    def __init__(self, predicate_registry, timeout: int = 5000, verbose: bool = False, checker=None):
        self.predicate_registry = predicate_registry
        self.timeout = timeout
        self.verbose = verbose
        self.analyzer = FormulaAnalyzer()
        # Pass lemma library from checker for semantic matching in frame rule
        lemma_library = checker.lemma_library if checker and hasattr(checker, 'lemma_library') else None
        self.frame_applicator = FrameRuleApplicator(verbose=verbose, lemma_library=lemma_library)
        self.matcher = LemmaMatcher()
        self.checker = checker  # Reference to parent checker for abduce_frame()

    def try_frame_inference(
        self,
        antecedent: Formula,
        consequent: Formula,
        max_iterations: int = 8
    ) -> Tuple[bool, Optional[str]]:
        """
        Try to prove entailment using frame inference.

        Algorithm (ENHANCED):
        1. Extract parts of consequent (Q = Q1 * Q2 * ... * Qn)
        2. For each Qi, try multiple strategies:
           a) Direct syntactic match
           b) Lemma application (e.g., transitivity)
           c) Unfold antecedent predicates to expose concrete heap
           d) Fold concrete heap into matching predicate
           e) Unification-based matching
        3. If matched, remove Qi from both sides
        4. Recurse until all parts matched

        Args:
            antecedent: Left side of entailment
            consequent: Right side of entailment
            max_iterations: Maximum matching iterations

        Returns:
            (success, reason) - True if proved, with explanation
        """
        if self.verbose:
            print(f"[Frame Inference] Starting...")
            print(f"[Frame Inference] Antecedent: {antecedent}")
            print(f"[Frame Inference] Consequent: {consequent}")

        # Extract consequent parts to match
        cons_parts = self.analyzer._extract_sepconj_parts(consequent)
        if not cons_parts:
            if self.verbose:
                print(f"[Frame Inference] No consequent parts to match")
            return False, None

        # Remove emp parts
        cons_parts = [p for p in cons_parts if not isinstance(p, Emp)]

        if not cons_parts:
            # Consequent is emp - check if antecedent can be dropped
            if self.verbose:
                print(f"[Frame Inference] Consequent is emp")
            return False, None

        if self.verbose:
            print(f"[Frame Inference] Need to match {len(cons_parts)} consequent parts")

        # Try to match each consequent part
        current_ant = antecedent
        matched_parts = []
        strategies_used = []

        for iteration in range(max_iterations):
            if not cons_parts:
                # All parts matched!
                if self.verbose:
                    print(f"[Frame Inference] ✓ All parts matched!")
                strategy_str = ", ".join(set(strategies_used))
                return True, f"Frame inference: matched {len(matched_parts)} parts via {strategy_str}"

            # Try to match one part using multiple strategies
            matched_any = False

            for cons_part in list(cons_parts):
                if self.verbose:
                    print(f"[Frame Inference] Trying to match: {cons_part}")

                # Strategy 1: Direct syntactic match
                if self._try_direct_match(current_ant, cons_part):
                    if self.verbose:
                        print(f"[Frame Inference] ✓ Direct match found")

                    # Apply frame rule to remove this part
                    new_ant, new_cons, simplified = self.frame_applicator.apply_frame_rule(
                        current_ant,
                        self.analyzer._build_sepconj([cons_part])
                    )

                    if simplified or self._is_weaker(new_ant, current_ant):
                        current_ant = new_ant
                        cons_parts.remove(cons_part)
                        matched_parts.append(cons_part)
                        strategies_used.append("direct")
                        matched_any = True
                        break

                # Strategy 2: Try lemmas (e.g., ls transitivity, cons, etc.)
                if isinstance(cons_part, PredicateCall):
                    lemma_matched = self._try_lemma_match(current_ant, cons_part)
                    if lemma_matched:
                        if self.verbose:
                            print(f"[Frame Inference] ✓ Matched via lemma: {lemma_matched}")
                        cons_parts.remove(cons_part)
                        matched_parts.append(cons_part)
                        strategies_used.append("lemma")
                        matched_any = True
                        break

                # Strategy 3: Unfold-then-match (unfold antecedent to expose structure)
                if isinstance(cons_part, PredicateCall):
                    unfolded_match = self._try_unfold_and_match(current_ant, cons_part)
                    if unfolded_match:
                        if self.verbose:
                            print(f"[Frame Inference] ✓ Matched after unfolding antecedent")
                        current_ant = unfolded_match
                        cons_parts.remove(cons_part)
                        matched_parts.append(cons_part)
                        strategies_used.append("unfold")
                        matched_any = True
                        break

                # Strategy 4: Fold concrete heap to match predicate (multi-step)
                if isinstance(cons_part, PredicateCall):
                    # Try multi-step folding first (more powerful)
                    from frame.folding.goal_directed import fold_towards_goal_multistep

                    folded_formula, num_folds = fold_towards_goal_multistep(
                        current_ant, cons_part,
                        self.predicate_registry,
                        max_iterations=5,
                        timeout=self.timeout,
                        verbose=self.verbose
                    )

                    if folded_formula is not None and num_folds > 0:
                        if self.verbose:
                            print(f"[Frame Inference] ✓ Matched via multi-step folding ({num_folds} folds)")

                        # Update current antecedent with folded version
                        current_ant = folded_formula
                        cons_parts.remove(cons_part)
                        matched_parts.append(cons_part)
                        strategies_used.append(f"fold_x{num_folds}")
                        matched_any = True
                        break

                    # REMOVED UNSOUND FALLBACK: single-step folding
                    # The previous code called fold_towards_goal() which returns only a lemma name,
                    # not a modified formula. This caused frame inference to assume the fold was
                    # proven without actually applying it to current_ant, leading to false positives.
                    # The multi-step folding above already handles single folds correctly.

                # Strategy 5: Frame abduction (synthesize missing heap)
                # NEW: This is the key integration of abduce_frame()!
                # If we can't match cons_part directly, try to abduce what's missing
                # and add it to the antecedent
                if self.checker and not matched_any:
                    if self.verbose:
                        print(f"[Frame Inference] Trying frame abduction for: {cons_part}")

                    # Try to abduce the frame R such that current_ant * R |- cons_part
                    # abduce_frame() returns R where current_ant * R |- cons_part
                    # IMPORTANT: abduce_frame validates that current_ant * R |- cons_part before returning R!
                    abduced_frame = self.checker.abduce_frame(current_ant, cons_part)

                    if abduced_frame is not None:
                        if isinstance(abduced_frame, Emp):
                            # Emp means current_ant already entails cons_part
                            if self.verbose:
                                print(f"[Frame Inference] ✓ Already provable (emp frame)")
                            cons_parts.remove(cons_part)
                            matched_parts.append(cons_part)
                            strategies_used.append("abduction_emp")
                            matched_any = True
                            break
                        else:
                            # Got a non-emp frame R where current_ant * R |- cons_part was verified
                            if self.verbose:
                                print(f"[Frame Inference] ✓ Abduced frame: {abduced_frame}")
                                print(f"[Frame Inference] (already verified by abduce_frame)")

                            # The abduction is already verified! No need to check again.
                            # Update current antecedent to include the abduced frame
                            current_ant = SepConj(current_ant, abduced_frame)
                            cons_parts.remove(cons_part)
                            matched_parts.append(cons_part)
                            strategies_used.append("abduction")
                            matched_any = True
                            break

            if not matched_any:
                # Couldn't match any more parts
                if self.verbose:
                    print(f"[Frame Inference] ✗ No more matches found")
                    print(f"[Frame Inference] Remaining consequent parts: {cons_parts}")
                return False, None

        # Ran out of iterations
        if cons_parts:
            if self.verbose:
                print(f"[Frame Inference] ✗ Max iterations reached with {len(cons_parts)} parts unmatched")
            return False, None

        return True, f"Frame inference: matched {len(matched_parts)} parts"

    def _try_direct_match(self, antecedent: Formula, target: Formula) -> bool:
        """
        Check if target appears directly in antecedent.
        """
        ante_parts = self.analyzer._extract_sepconj_parts(antecedent)

        for ante_part in ante_parts:
            if self.matcher.formulas_equal(ante_part, target):
                return True

        return False

    def _is_weaker(self, f1: Formula, f2: Formula) -> bool:
        """
        Heuristic check if f1 is weaker than f2 (has fewer conjuncts).
        """
        parts1 = self.analyzer._extract_sepconj_parts(f1)
        parts2 = self.analyzer._extract_sepconj_parts(f2)
        return len(parts1) < len(parts2)

    def _try_lemma_match(self, antecedent: Formula, target: PredicateCall) -> Optional[str]:
        """
        Try to match target using lemmas (e.g., transitivity, cons, etc.)

        For example:
        - If target is ls(x, z) and antecedent has ls(x, y) * ls(y, z), use transitivity
        - If target is ls(x, y) and antecedent has x |-> z * ls(z, y), use cons

        Returns:
            Lemma name if matched, None otherwise
        """
        # Get lemma library from predicate registry
        from frame.lemmas.base import LemmaLibrary

        # Create temporary lemma library for this check
        lemma_lib = LemmaLibrary(self.predicate_registry)

        # Try to apply a lemma
        lemma_name = lemma_lib.try_apply_lemma(antecedent, target)

        return lemma_name

    def _try_unfold_and_match(self, antecedent: Formula, target: PredicateCall) -> Optional[Formula]:
        """
        Try unfolding antecedent predicates to expose structure that matches target.

        For example:
        - Antecedent: ls(x, y) * z |-> w
        - Target: ls(x, w)
        - Unfold ls(x, y) to get: x |-> y' * ls(y', y) * z |-> w
        - Then fold to get ls(x, w)

        Returns:
            Simplified antecedent if match found, None otherwise
        """
        # Extract predicates from antecedent
        ante_parts = self.analyzer._extract_sepconj_parts(antecedent)

        # Find predicates that could be unfolded
        for i, part in enumerate(ante_parts):
            if isinstance(part, PredicateCall):
                # Try unfolding this predicate once
                try:
                    unfolded = self.predicate_registry.unfold_predicates(
                        part,
                        depth=1,
                        adaptive=False
                    )

                    if unfolded != part:
                        # Build new antecedent with unfolded part
                        new_parts = ante_parts[:i] + [unfolded] + ante_parts[i+1:]
                        new_ant = self.analyzer._build_sepconj(new_parts)

                        # Try to match target in new antecedent
                        if self._try_direct_match(new_ant, target):
                            # Apply frame rule to remove matched part
                            final_ant, _, simplified = self.frame_applicator.apply_frame_rule(
                                new_ant,
                                target
                            )
                            if simplified:
                                return final_ant

                        # Try folding after unfolding
                        # Use multistep folding which returns the modified formula (sound)
                        from frame.folding.goal_directed import fold_towards_goal_multistep
                        folded_ant, num_folds = fold_towards_goal_multistep(
                            new_ant, target,
                            self.predicate_registry,
                            max_iterations=3,
                            timeout=min(1000, self.timeout // 4),
                            verbose=False
                        )

                        if folded_ant is not None and num_folds > 0:
                            return folded_ant

                except Exception:
                    continue

        return None
