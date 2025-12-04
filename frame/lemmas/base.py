"""
Base classes for lemma library

Contains the Lemma class and LemmaLibrary class with all matching/substitution logic.
"""

from typing import List, Optional, Dict, Tuple, TYPE_CHECKING
from frame.core.ast import *
from frame.lemmas._matcher import LemmaMatcher
from frame.lemmas._substitution import LemmaSubstitution
from frame.utils.formula_utils import extract_spatial_part

if TYPE_CHECKING:
    from frame.predicates.registry import PredicateRegistry


class Lemma:
    """Represents a separation logic lemma (axiom)"""

    def __init__(self, name: str, antecedent: Formula, consequent: Formula,
                 description: str = ""):
        self.name = name
        self.antecedent = antecedent
        self.consequent = consequent
        self.description = description

    def __str__(self):
        return f"{self.name}: {self.antecedent} |- {self.consequent}"


class LemmaLibrary:
    """Library of separation logic lemmas"""

    def __init__(self, predicate_registry: Optional['PredicateRegistry'] = None):
        self.lemmas: List[Lemma] = []
        self._matcher = LemmaMatcher()
        self._substitution = LemmaSubstitution()
        self._predicate_registry = predicate_registry
        self._validator = None
        self._skipped_lemmas = []
        self._validated_lemmas = []
        self._initialize_standard_lemmas()

        # Initialize validator if we have a registry
        if predicate_registry:
            self.set_predicate_registry(predicate_registry)
            # Validate all lemmas upfront if verbose logging is enabled
            import os
            if os.getenv('LEMMA_VALIDATION_VERBOSE'):
                self._validate_all_lemmas()

    def _initialize_standard_lemmas(self):
        """Initialize standard lemmas by calling category-specific initializers"""
        from frame.lemmas.list_lemmas import initialize_list_lemmas
        from frame.lemmas.dll_lemmas import initialize_dll_lemmas
        from frame.lemmas.other_lemmas import initialize_other_lemmas
        from frame.lemmas.wand_lemmas import initialize_wand_lemmas
        from frame.lemmas.compositional import install_compositional_lemmas, CompositionalAnalyzer

        initialize_list_lemmas(self)
        initialize_dll_lemmas(self)
        initialize_other_lemmas(self)
        initialize_wand_lemmas(self)

        # Install auto-generated compositional lemmas
        if self._predicate_registry:
            analyzer = CompositionalAnalyzer(self._predicate_registry)
            install_compositional_lemmas(self, analyzer)

    def add_lemma(self, name: str, antecedent: Formula, consequent: Formula,
                  description: str = ""):
        """Add a lemma to the library"""
        lemma = Lemma(name, antecedent, consequent, description)
        self.lemmas.append(lemma)

    # Delegate pattern matching to _matcher
    def match_formula(self, pattern: Formula, formula: Formula,
                     bindings: Optional[Dict[str, Expr]] = None) -> Optional[Dict[str, Expr]]:
        """Match a pattern formula against an actual formula"""
        return self._matcher.match_formula(pattern, formula, bindings)

    def match_expr(self, pattern: Expr, expr: Expr,
                   bindings: Optional[Dict[str, Expr]] = None) -> Optional[Dict[str, Expr]]:
        """Match a pattern expression against an actual expression"""
        return self._matcher.match_expr(pattern, expr, bindings)

    def _formulas_equal(self, f1: Formula, f2: Formula) -> bool:
        """Check if two formulas are structurally equal"""
        return self._matcher.formulas_equal(f1, f2)

    def _is_spatial_pattern(self, formula: Formula) -> bool:
        """Check if a formula is a spatial pattern"""
        return self._matcher._is_spatial_pattern(formula)

    # Delegate substitution to _substitution
    def substitute_bindings(self, formula: Formula, bindings: Dict[str, Expr]) -> Formula:
        """Substitute meta-variable bindings into a formula"""
        return self._substitution.substitute_bindings(formula, bindings)

    def substitute_expr(self, expr: Expr, bindings: Dict[str, Expr]) -> Expr:
        """Substitute meta-variable bindings into an expression"""
        return self._substitution.substitute_expr(expr, bindings)

    def _extract_equality_constraints(self, formula: Formula) -> Dict[str, Expr]:
        """Extract equality constraints from a formula"""
        return self._substitution.extract_equality_constraints(formula)

    def _apply_substitution_to_formula(self, formula: Formula, substitution: Dict[str, Expr]) -> Formula:
        """Apply variable substitution to a formula"""
        return self._substitution.apply_substitution_to_formula(formula, substitution)

    def set_predicate_registry(self, registry: 'PredicateRegistry'):
        """
        Set the predicate registry for lemma validation.

        This enables checking if lemmas are sound for the current predicate definitions.
        """
        self._predicate_registry = registry
        # Lazy-initialize validator when we have predicates
        if registry:
            from frame.lemmas.validator import LemmaValidator
            self._validator = LemmaValidator(registry.predicates)

    def _validate_all_lemmas(self):
        """
        Validate all lemmas upfront and categorize them.

        This is called during initialization if LEMMA_VALIDATION_VERBOSE is set.
        """
        if not self._validator:
            return

        print(f"\n{'='*70}")
        print(f"LEMMA LIBRARY VALIDATION")
        print(f"{'='*70}")
        print(f"Total lemmas: {len(self.lemmas)}")
        print(f"\nValidating against current predicate definitions...")
        print(f"{'-'*70}")

        for lemma in self.lemmas:
            is_sound, reason = self._validator.is_lemma_sound(
                lemma.name, lemma.antecedent, lemma.consequent
            )

            if is_sound:
                self._validated_lemmas.append(lemma.name)
            else:
                self._skipped_lemmas.append((lemma.name, reason))

        # Print summary
        print(f"\n✅ Validated (sound): {len(self._validated_lemmas)}")
        print(f"❌ Skipped (unsound): {len(self._skipped_lemmas)}")

        # Show skipped lemmas grouped by reason
        if self._skipped_lemmas:
            print(f"\n{'-'*70}")
            print("SKIPPED LEMMAS BY CATEGORY:")
            print(f"{'-'*70}")

            # Group by reason
            reason_groups = {}
            for name, reason in self._skipped_lemmas:
                # Extract key part of reason for grouping
                if "Transitivity invalid" in reason:
                    key = "Transitivity (distinctness constraint)"
                elif "Cons lemma invalid" in reason:
                    key = "Cons (distinctness constraint)"
                elif "Snoc/append lemma invalid" in reason:
                    key = "Snoc/Append (distinctness constraint)"
                elif "Undefined predicates" in reason:
                    key = "Undefined predicates"
                elif "Conservative rejection" in reason:
                    key = "Conservative rejection"
                else:
                    key = "Other"

                if key not in reason_groups:
                    reason_groups[key] = []
                reason_groups[key].append(name)

            # Print grouped
            for category, lemma_names in sorted(reason_groups.items()):
                print(f"\n{category} ({len(lemma_names)} lemmas):")
                for name in sorted(lemma_names):
                    print(f"  • {name}")

        print(f"\n{'='*70}\n")

    def _is_lemma_sound(self, lemma: Lemma, verbose: bool = False) -> bool:
        """
        Check if a lemma is sound for the current predicate definitions.

        Returns True if:
        - No validator is set (assume sound by default)
        - Validator confirms lemma is sound

        Returns False if validator determines lemma is unsound.
        """
        if not self._validator:
            # No validator means no custom predicates, so lemmas are sound
            return True

        # If we already validated upfront, use cached result
        if lemma.name in self._validated_lemmas:
            return True

        # Check if already in skipped list
        for skipped_name, _ in self._skipped_lemmas:
            if skipped_name == lemma.name:
                return False

        # Not cached, validate now
        is_sound, reason = self._validator.is_lemma_sound(
            lemma.name, lemma.antecedent, lemma.consequent
        )

        if is_sound:
            self._validated_lemmas.append(lemma.name)
        else:
            # Track skipped lemmas for analysis
            self._skipped_lemmas.append((lemma.name, reason))

            # Log if verbose or if LEMMA_VALIDATION_VERBOSE env var is set
            import os
            if verbose or os.getenv('LEMMA_VALIDATION_VERBOSE') == '2':
                # Only log individual lemmas if verbose level 2
                print(f"[LEMMA VALIDATION] Skipping {lemma.name}: {reason}")

        return is_sound

    def try_apply_lemma(self, antecedent: Formula, consequent: Formula) -> Optional[str]:
        """
        Try to apply a lemma to prove the entailment (delegate to _lemma_application).

        Two-phase matching strategy:
        1. Direct matching (fast path): syntactic pattern matching
        2. Constraint-aware matching: normalize with equality constraints

        Returns the name of the applied lemma if successful, None otherwise.
        """
        from frame.lemmas._lemma_application import try_apply_lemma as _try_apply_lemma
        return _try_apply_lemma(self, antecedent, consequent)

    def _convert_all_pto_to_ls(self, formula: Formula, verbose: bool = False,
                                antecedent_pure: List[Formula] = None) -> Tuple[Formula, int]:
        """
        Bulk conversion of PointsTo cells to ls predicates.

        For each x |-> y in the formula, convert to ls(x, y).
        This is a preprocessing step before multi-step lemma application
        that significantly speeds up folding for complex benchmarks.

        SOUNDNESS FIX (Nov 2025): Only convert if we can PROVE location != value.
        The conversion x |-> y |- ls(x, y) is UNSOUND if x = y because:
          - ls(x, x) = emp (base case)
          - x |-> x ⊢ emp is INVALID (non-empty cell cannot entail empty heap)

        We can prove loc != val if:
          1. loc and val are syntactically different AND
          2. val is a "terminal" (nil, null) that can't equal loc, OR
          3. There's explicit disequality loc != val in antecedent_pure

        CONSERVATIVE: For now, we DISABLE pto_to_ls bulk conversion to maintain soundness.
        This may reduce completeness but ensures no false positives.

        Returns:
            (converted_formula, num_conversions)
        """
        # SOUNDNESS FIX (Nov 2025): Disable bulk pto_to_ls conversion
        # The conversion x |-> y |- ls(x, y) requires x != y, but we can't always prove this.
        # Example: x |-> y * y |-> z |- ls(x, z) is INVALID when y = z
        # because y |-> z with y = z is y |-> y, and ls(y, y) = emp, but y |-> y ⊢ emp is INVALID.
        #
        # Without explicit disequality constraints, we can't safely convert arbitrary pto to ls.
        # Disabling this maintains soundness at the cost of some completeness.
        if verbose:
            print(f"[PTO->LS] Bulk conversion disabled for soundness")
        return formula, 0

    def try_apply_lemma_multistep(
        self,
        antecedent: Formula,
        consequent: Formula,
        max_iterations: int = 5,
        verbose: bool = False
    ) -> Optional[Tuple[str, int]]:
        """
        Try to apply lemmas iteratively to prove the entailment using GOAL-DIRECTED strategy.

        This enables proving entailments that require multiple lemma applications,
        such as: ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)
        which needs transitivity applied twice.

        GOAL-DIRECTED Algorithm (improved for SL-COMP benchmarks):
        1. Convert all PointsTo to ls predicates
        2. Identify predicates that already match the goal (preserve them)
        3. For remaining predicates, apply transitivity ONLY if the result
           would produce a predicate that exists in the goal
        4. Continue until all goal predicates are matched or no progress

        Args:
            antecedent: The formula to transform
            consequent: The goal formula to prove
            max_iterations: Maximum number of lemma applications
            verbose: Enable debug output

        Returns:
            (lemma_description, num_applications) if successful, None otherwise
        """
        from frame.analysis.formula import FormulaAnalyzer

        analyzer = FormulaAnalyzer()
        current = antecedent
        applications = []

        if verbose:
            print(f"[Multi-Step Lemma] Starting: {antecedent} |- {consequent}")

        # PREPROCESSING: Convert all PointsTo to ls in one step
        # This is crucial for benchmarks like bolognesa that have many pto cells
        current, num_pto_converted = self._convert_all_pto_to_ls(current, verbose)
        if num_pto_converted > 0:
            applications.extend(['pto_to_ls'] * num_pto_converted)
            if verbose:
                print(f"[Multi-Step Lemma] Preprocessing: converted {num_pto_converted} pto -> ls")
                print(f"[Multi-Step Lemma] After preprocessing: {current}")

        # Extract goal parts for goal-directed matching
        # Nov 2025: Extended to track ALL predicates, not just 'ls'
        goal_parts = analyzer._extract_sepconj_parts(consequent)
        goal_signatures = set()  # For ls predicates: (start, end)
        goal_predicate_sigs = {}  # For ALL predicates: pred_name -> set of argument tuples
        for gp in goal_parts:
            if isinstance(gp, PredicateCall) and len(gp.args) >= 2:
                # Create signature for this predicate
                pred_name = gp.name
                args_tuple = tuple(
                    arg.name if isinstance(arg, Var) else (str(arg.value) if isinstance(arg, Const) and arg.value is not None else 'nil' if isinstance(arg, Const) else str(arg))
                    for arg in gp.args
                )
                if pred_name not in goal_predicate_sigs:
                    goal_predicate_sigs[pred_name] = set()
                goal_predicate_sigs[pred_name].add(args_tuple)

                # Also add to legacy goal_signatures for ls predicates
                if pred_name == 'ls':
                    start_name = gp.args[0].name if isinstance(gp.args[0], Var) else str(gp.args[0])
                    end_name = gp.args[1].name if isinstance(gp.args[1], Var) else str(gp.args[1])
                    goal_signatures.add((start_name, end_name))

        if verbose:
            print(f"[Multi-Step Lemma] Goal signatures: {goal_signatures}")
            if goal_predicate_sigs:
                print(f"[Multi-Step Lemma] Goal predicate signatures: {goal_predicate_sigs}")

        # SOUNDNESS CHECK: Detect ls predicate cycles in antecedent
        # If predicates form a cycle (ls(a,b) * ls(b,c) * ls(c,a)), transitivity is unsound
        # because the cycle can only be satisfied if all are empty (a=b=c) or UNSAT.
        def detect_ls_cycles(formula_parts: List[Formula]) -> bool:
            """Check if ls predicates form a cycle."""
            # Build a graph of ls edges: start -> end
            edges = {}
            for part in formula_parts:
                if isinstance(part, PredicateCall) and part.name == 'ls' and len(part.args) >= 2:
                    start = part.args[0].name if isinstance(part.args[0], Var) else str(part.args[0])
                    end = part.args[1].name if isinstance(part.args[1], Var) else str(part.args[1])
                    if start != end:  # Skip reflexive ls(x,x) - these are always emp
                        if start not in edges:
                            edges[start] = set()
                        edges[start].add(end)

            # DFS to detect cycle
            visited = set()
            rec_stack = set()

            def dfs(node):
                visited.add(node)
                rec_stack.add(node)
                for neighbor in edges.get(node, []):
                    if neighbor not in visited:
                        if dfs(neighbor):
                            return True
                    elif neighbor in rec_stack:
                        return True
                rec_stack.remove(node)
                return False

            for node in edges:
                if node not in visited:
                    if dfs(node):
                        return True
            return False

        # Check for cycles in initial antecedent
        initial_parts = analyzer._extract_sepconj_parts(current)
        has_cycle = detect_ls_cycles(initial_parts)
        if has_cycle and verbose:
            print(f"[Multi-Step Lemma] ⚠ Formula contains ls predicate cycles - applying transitivity cautiously")

        for iteration in range(max_iterations):
            if verbose:
                print(f"\n[Multi-Step Lemma] Iteration {iteration + 1}/{max_iterations}")
                print(f"[Multi-Step Lemma] Current: {current}")

            # Check if we've reached the goal (normalize by removing emp first)
            current_normalized = self._remove_emp_parts(current, analyzer)
            consequent_normalized = self._remove_emp_parts(consequent, analyzer)

            if self._formulas_equal(current_normalized, consequent_normalized):
                if verbose:
                    print(f"[Multi-Step Lemma] ✓ Goal reached after {len(applications)} applications!")
                return (f"multi_step_lemma ({'+'.join(applications)})", len(applications))

            # Extract parts from current formula
            current_parts = analyzer._extract_sepconj_parts(current)

            # GOAL-DIRECTED: Check if current parts are a subset match of goal
            # (accounting for the frame rule)
            # Pass consequent to check for pure constraints
            current_matched = self._check_subset_match(current_parts, goal_parts, verbose, consequent=consequent)
            if current_matched:
                if verbose:
                    print(f"[Multi-Step Lemma] ✓ Subset match found!")
                return (f"multi_step_lemma ({'+'.join(applications)})", len(applications))

            # Identify PROTECTED predicates - those that already match a goal
            # These should NOT be consumed by transitivity
            protected_indices = set()
            for i, cp in enumerate(current_parts):
                for gp in goal_parts:
                    if self._formulas_equal(cp, gp):
                        protected_indices.add(i)
                        break

            if verbose and protected_indices:
                protected_names = [str(current_parts[i]) for i in protected_indices]
                print(f"[Multi-Step Lemma] Protected predicates: {protected_names}")

            # Try to find a GOAL-DIRECTED lemma application
            lemma_applied = False
            best_application = None
            best_is_goal_directed = False

            for lemma in self.lemmas:
                # Validate lemma before applying
                if not self._is_lemma_sound(lemma):
                    continue

                # PREVENT INFINITE LOOPS: Skip certain lemmas
                if lemma.name in ('emp_to_ls_empty', 'ls_empty', 'ls_frame_emp',
                                  'ls_convergent_identity', 'ls_with_eq'):
                    continue

                # Get lemma antecedent parts
                lemma_ante_parts = analyzer._extract_sepconj_parts(lemma.antecedent)

                # Try to match lemma antecedent against subset of current parts
                # EXCLUDING protected predicates
                available_parts = [p for i, p in enumerate(current_parts) if i not in protected_indices]
                available_indices = [i for i in range(len(current_parts)) if i not in protected_indices]

                if len(available_parts) < len(lemma_ante_parts):
                    continue  # Not enough unprotected parts

                bindings = self._try_match_subset(available_parts, lemma_ante_parts)

                if bindings is not None:
                    # SOUNDNESS CHECK 1: Detect aliasing in transitivity lemma
                    # Use the same check as single-step lemma application
                    if lemma.name in ('ls_transitivity', 'ls_triple_transitivity', 'ls_snoc'):
                        from frame.lemmas._lemma_application import (
                            _extract_disequalities, _extract_cell_locations, _can_apply_transitivity
                        )
                        disequalities = _extract_disequalities(antecedent)
                        cells_at = _extract_cell_locations(antecedent)

                        if not _can_apply_transitivity(lemma, bindings, disequalities, cells_at):
                            if verbose:
                                print(f"[Multi-Step Lemma] ✗ Skipping {lemma.name}: cannot prove endpoint disequality")
                            continue

                    # SOUNDNESS CHECK 2: Don't apply transitivity if formula has cycles
                    # Cycles can only be satisfied if all are empty, but transitivity
                    # might incorrectly "prove" entailments through the cycle.
                    if has_cycle and lemma.name in ('ls_transitivity', 'ls_triple_transitivity', 'ls_snoc'):
                        # Check if applying this lemma would involve cycle predicates
                        current_parts_check = analyzer._extract_sepconj_parts(current)
                        if detect_ls_cycles(current_parts_check):
                            if verbose:
                                print(f"[Multi-Step Lemma] ✗ Skipping {lemma.name}: formula contains ls cycles")
                            continue

                    # GOAL-DIRECTED CHECK: Would the result help us reach the goal?
                    instantiated_consequent = self.substitute_bindings(lemma.consequent, bindings)

                    # Check if result matches any goal predicate
                    # Nov 2025: Extended to check ALL predicates, not just 'ls'
                    result_in_goal = False
                    if isinstance(instantiated_consequent, PredicateCall):
                        pred_name = instantiated_consequent.name
                        if pred_name in goal_predicate_sigs and len(instantiated_consequent.args) >= 2:
                            # Build the result's argument tuple
                            result_args_tuple = tuple(
                                arg.name if isinstance(arg, Var) else (str(arg.value) if isinstance(arg, Const) and arg.value is not None else 'nil' if isinstance(arg, Const) else str(arg))
                                for arg in instantiated_consequent.args
                            )
                            result_in_goal = result_args_tuple in goal_predicate_sigs[pred_name]

                        # Legacy check for ls predicates
                        elif pred_name == 'ls' and len(instantiated_consequent.args) >= 2:
                            result_start = instantiated_consequent.args[0].name if isinstance(instantiated_consequent.args[0], Var) else str(instantiated_consequent.args[0])
                            result_end = instantiated_consequent.args[1].name if isinstance(instantiated_consequent.args[1], Var) else str(instantiated_consequent.args[1])
                            result_in_goal = (result_start, result_end) in goal_signatures

                    # ONLY apply goal-directed lemmas for transitivity
                    # Non-goal-directed transitivity often leads to dead ends
                    if result_in_goal:
                        # This is a high-priority match - apply immediately
                        best_application = (lemma, bindings, instantiated_consequent, lemma_ante_parts, available_parts, available_indices)
                        best_is_goal_directed = True
                        if verbose:
                            print(f"[Multi-Step Lemma] Found goal-directed match: {lemma.name} -> {instantiated_consequent}")
                        break
                    # Skip non-goal-directed transitivity - it often leads to dead ends
                    # elif best_application is None:
                    #     best_application = (lemma, bindings, instantiated_consequent, lemma_ante_parts, available_parts, available_indices)

            # Apply the best found lemma
            if best_application:
                lemma, bindings, instantiated_consequent, lemma_ante_parts, available_parts, available_indices = best_application

                # Build new formula: remove matched parts from available_parts, add consequent
                # IMPORTANT: Use the SAME bindings to ensure consistent matching
                # and prevent the same part from being matched twice
                matched_available_indices = set()
                for lemma_part in lemma_ante_parts:
                    for j, avail_part in enumerate(available_parts):
                        if j not in matched_available_indices:
                            # Use bindings to verify this part actually matches with the correct variables
                            part_bindings = self.match_formula(lemma_part, avail_part, dict(bindings))
                            if part_bindings is not None:
                                # Verify bindings are consistent
                                consistent = True
                                for k, v in part_bindings.items():
                                    if k in bindings:
                                        # Check if the binding values match
                                        old_v = bindings[k]
                                        if isinstance(old_v, Var) and isinstance(v, Var):
                                            if old_v.name != v.name:
                                                consistent = False
                                                break
                                        elif str(old_v) != str(v):
                                            consistent = False
                                            break
                                if consistent:
                                    matched_available_indices.add(j)
                                    break

                # Map back to original indices
                matched_original_indices = {available_indices[j] for j in matched_available_indices}

                # Build new formula with unmatched parts + instantiated consequent
                new_parts = [p for i, p in enumerate(current_parts) if i not in matched_original_indices]
                new_parts.append(instantiated_consequent)

                current = analyzer._build_sepconj(new_parts)
                applications.append(lemma.name)
                lemma_applied = True

                if verbose:
                    print(f"[Multi-Step Lemma] ✓ Applied {lemma.name}")
                    print(f"[Multi-Step Lemma] New formula: {current}")

            if not lemma_applied:
                if verbose:
                    print(f"[Multi-Step Lemma] ✗ No lemma applicable")
                break

        # Check final result (normalize by removing emp)
        current_normalized = self._remove_emp_parts(current, analyzer)
        consequent_normalized = self._remove_emp_parts(consequent, analyzer)

        if self._formulas_equal(current_normalized, consequent_normalized):
            if verbose:
                print(f"[Multi-Step Lemma] ✓ Success after {len(applications)} applications!")
            return (f"multi_step_lemma ({'+'.join(applications)})", len(applications))

        # Final check: subset match (frame rule)
        # Pass consequent to check for pure constraints
        current_parts = analyzer._extract_sepconj_parts(current_normalized)
        if self._check_subset_match(current_parts, goal_parts, verbose, consequent=consequent):
            if verbose:
                print(f"[Multi-Step Lemma] ✓ Success (frame) after {len(applications)} applications!")
            return (f"multi_step_lemma ({'+'.join(applications)})", len(applications))

        if verbose:
            print(f"[Multi-Step Lemma] ✗ Failed after {len(applications)} applications")
            print(f"[Multi-Step Lemma]   Final: {current_normalized}")
            print(f"[Multi-Step Lemma]   Goal:  {consequent_normalized}")

        return None

    def _check_subset_match(self, current_parts: List[Formula], goal_parts: List[Formula],
                           verbose: bool = False, consequent: Formula = None,
                           allow_frame: bool = False) -> bool:
        """
        Check if current parts match goal parts.

        Args:
            current_parts: Parts from current formula
            goal_parts: Parts from goal formula
            verbose: Enable debug output
            consequent: Original consequent for pure constraint checking
            allow_frame: If True, allow extra parts in current (for frame extraction)
                        If False, require exact match (for entailment checking)

        SOUNDNESS FIX (Nov 2025): Changed default behavior to exact match.

        In standard separation logic, P * R |- Q is NOT valid just because P matches Q.
        The remainder R MUST be empty (emp), otherwise the entailment is invalid.

        Example of UNSOUND subset matching:
          ls(x4, x6) * ls(x6, x4) |- ls(x4, x6)
          - Subset: ls(x4, x6) matches goal ✓
          - But: ls(x6, x4) is NOT emp (unless x6 = x4)!
          - So entailment is INVALID

        For entailment checking (allow_frame=False):
          Require ALL current parts to match some goal part (bidirectional match).

        For frame extraction (allow_frame=True):
          Allow extra parts in current - these become the extracted frame.

        IMPORTANT: Also check if consequent has PURE constraints that are not in the antecedent.
        If so, we can't claim a match (spatial match is not enough).
        """
        from frame.utils.formula_utils import extract_pure_formulas
        from frame.core.ast import Emp

        # SOUNDNESS CHECK: If consequent has pure constraints, we need to verify them
        # This prevents accepting emp |- (x = 5 & emp) via spatial-only matching
        if consequent is not None:
            pure_constraints = extract_pure_formulas(consequent)
            if pure_constraints:
                # There are pure constraints in consequent that we haven't verified
                # A spatial match is NOT sufficient
                if verbose:
                    print(f"[Subset Match] ✗ Consequent has pure constraints: {pure_constraints}")
                return False

        # Filter out emp parts from current (they're vacuous)
        current_spatial = [p for p in current_parts if not isinstance(p, Emp)]
        goal_spatial = [p for p in goal_parts if not isinstance(p, Emp)]

        # For exact matching (entailment checking): current must have same or fewer parts than goal
        # If current has MORE spatial parts than goal, those extras can't be consumed
        if not allow_frame and len(current_spatial) > len(goal_spatial):
            if verbose:
                print(f"[Subset Match] ✗ Current has {len(current_spatial)} parts, goal has {len(goal_spatial)}")
                print(f"[Subset Match]   Extra parts cannot be consumed by goal")
            return False

        # Check that every goal part has a matching current part
        goal_matched = [False] * len(goal_spatial)
        current_used = [False] * len(current_spatial)

        for i, goal_part in enumerate(goal_spatial):
            for j, current_part in enumerate(current_spatial):
                if not current_used[j] and self._formulas_equal(goal_part, current_part):
                    goal_matched[i] = True
                    current_used[j] = True
                    break

        # All goal parts must be matched
        if not all(goal_matched):
            if verbose:
                unmatched = [str(goal_spatial[i]) for i, m in enumerate(goal_matched) if not m]
                print(f"[Subset Match] ✗ Unmatched goal parts: {unmatched}")
            return False

        # For exact matching: all current parts must be used (no leftovers)
        # For frame extraction: leftovers are OK (they become the frame)
        if not allow_frame and not all(current_used):
            if verbose:
                leftovers = [str(current_spatial[i]) for i, u in enumerate(current_used) if not u]
                print(f"[Subset Match] ✗ Leftover current parts not in goal: {leftovers}")
            return False

        return True

    def _remove_emp_parts(self, formula: Formula, analyzer) -> Formula:
        """
        Remove vacuous emp conjuncts from formula for normalization.

        Only removes emp from SPATIAL conjunctions (SepConj), not from pure conjunctions (And).
        This preserves pure constraints while normalizing spatial formulas.
        """
        from frame.core.ast import Emp, SepConj, And

        def normalize(f: Formula) -> Formula:
            if isinstance(f, Emp):
                return Emp()
            elif isinstance(f, SepConj):
                left = normalize(f.left)
                right = normalize(f.right)

                # Remove emp from sepconj
                if isinstance(left, Emp):
                    return right
                if isinstance(right, Emp):
                    return left

                return SepConj(left, right)
            elif isinstance(f, And):
                # For And, normalize both sides but keep the And structure
                left = normalize(f.left)
                right = normalize(f.right)
                return And(left, right)
            else:
                # Other formulas remain unchanged
                return f

        return normalize(formula)

    def _try_match_subset(
        self,
        formula_parts: List[Formula],
        pattern_parts: List[Formula]
    ) -> Optional[Dict[str, Expr]]:
        """
        Try to match pattern parts against a subset of formula parts.

        This enables matching ls(x,y) * ls(y,z) within x|->a * ls(x,y) * ls(y,z) * z|->b

        IMPORTANT: We must try all PERMUTATIONS of how pattern parts map to formula parts,
        not just combinations. For example, with pattern [ls(X,Y), ls(Y,Z)] and formula
        parts [ls(a,b), ls(c,a)], we need to try:
          - pattern[0]->formula[0], pattern[1]->formula[1]: ls(X,Y)->ls(a,b), ls(Y,Z)->ls(c,a) - FAIL (Y=b != c)
          - pattern[0]->formula[1], pattern[1]->formula[0]: ls(X,Y)->ls(c,a), ls(Y,Z)->ls(a,b) - OK (X=c, Y=a, Z=b)

        Returns unified bindings if all pattern parts match, None otherwise.
        """
        if len(pattern_parts) > len(formula_parts):
            return None

        # Try all permutations of formula_parts that match the size of pattern_parts
        from itertools import combinations, permutations

        # First get all combinations of indices, then try all permutations of each
        for combo in combinations(range(len(formula_parts)), len(pattern_parts)):
            # Try all orderings of this combination
            for perm in permutations(combo):
                # Try to match this permutation
                bindings = {}
                matched = True

                for pattern_part, formula_idx in zip(pattern_parts, perm):
                    formula_part = formula_parts[formula_idx]
                    part_bindings = self.match_formula(pattern_part, formula_part, bindings)

                    if part_bindings is None:
                        matched = False
                        break

                    bindings = part_bindings

                if matched:
                    return bindings

        return None

    def get_applicable_lemmas(self, antecedent: Formula) -> List[Tuple[Lemma, Dict[str, Expr]]]:
        """
        Get all lemmas whose antecedent matches the given formula.

        Returns list of (lemma, bindings) pairs.
        """
        applicable = []
        for lemma in self.lemmas:
            bindings = self.match_formula(lemma.antecedent, antecedent)
            if bindings is not None:
                applicable.append((lemma, bindings))
        return applicable

    def get_validation_stats(self) -> Dict[str, int]:
        """
        Get statistics about lemma validation.

        Returns:
            Dictionary with validation statistics
        """
        stats = {
            'total_lemmas': len(self.lemmas),
            'validated_lemmas': len(self._validated_lemmas),
            'skipped_lemmas': len(self._skipped_lemmas),
        }

        return stats

    def print_validation_summary(self):
        """Print a summary of lemma validation results."""
        stats = self.get_validation_stats()

        print(f"\n{'='*70}")
        print(f"LEMMA VALIDATION SUMMARY")
        print(f"{'='*70}")
        print(f"Total lemmas: {stats['total_lemmas']}")
        print(f"✅ Validated (sound): {stats['validated_lemmas']}")
        print(f"❌ Skipped (unsound): {stats['skipped_lemmas']}")

        if stats['skipped_lemmas'] > 0:
            print(f"\nUse get_skipped_lemmas() for details or set LEMMA_VALIDATION_VERBOSE=1")

        print(f"{'='*70}\n")

    def get_skipped_lemmas(self) -> List[Tuple[str, str]]:
        """
        Get list of skipped lemmas and their reasons.

        Returns:
            List of (lemma_name, reason) tuples
        """
        if hasattr(self, '_skipped_lemmas'):
            return list(self._skipped_lemmas)
        return []

    def __len__(self):
        return len(self.lemmas)

    def __iter__(self):
        return iter(self.lemmas)
