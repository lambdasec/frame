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
        from frame.lemmas.tree_lemmas import initialize_tree_lemmas
        from frame.lemmas.graph_lemmas import initialize_graph_lemmas
        from frame.lemmas.skip_list_lemmas import initialize_skip_list_lemmas
        from frame.lemmas.compositional import install_compositional_lemmas, CompositionalAnalyzer

        # Initialize core lemma categories
        initialize_list_lemmas(self)
        initialize_dll_lemmas(self)
        initialize_other_lemmas(self)
        initialize_wand_lemmas(self)

        # Initialize new lemma categories (expanded library)
        initialize_tree_lemmas(self)
        initialize_graph_lemmas(self)
        initialize_skip_list_lemmas(self)

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

    def try_apply_lemma_multistep(
        self,
        antecedent: Formula,
        consequent: Formula,
        max_iterations: int = 5,
        verbose: bool = False
    ) -> Optional[Tuple[str, int]]:
        """
        Try to apply lemmas iteratively to prove the entailment.

        This enables proving entailments that require multiple lemma applications,
        such as: ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)
        which needs transitivity applied twice.

        Algorithm:
        1. Start with current = antecedent
        2. For each iteration:
           a. Try to find a lemma L where L.antecedent matches part of current
           b. If found, replace that part with L.consequent
           c. Check if result matches consequent (success!)
           d. Otherwise, continue with transformed formula
        3. Stop when consequent is reached or no more lemmas apply

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

            # Try to find a lemma that applies to some subset of parts
            lemma_applied = False

            for lemma in self.lemmas:
                # Validate lemma before applying
                if not self._is_lemma_sound(lemma):
                    continue

                # Get lemma antecedent parts
                lemma_ante_parts = analyzer._extract_sepconj_parts(lemma.antecedent)

                # Try to match lemma antecedent against subset of current parts
                # This allows matching ls(x,y) * ls(y,z) within larger formula
                bindings = self._try_match_subset(current_parts, lemma_ante_parts)

                if bindings is not None:
                    # Found a match! Apply the lemma
                    instantiated_consequent = self.substitute_bindings(lemma.consequent, bindings)

                    # Build new formula: remove matched parts, add consequent
                    matched_parts_set = set()
                    for lemma_part in lemma_ante_parts:
                        for i, current_part in enumerate(current_parts):
                            if i not in matched_parts_set:
                                part_bindings = self.match_formula(lemma_part, current_part)
                                if part_bindings is not None:
                                    matched_parts_set.add(i)
                                    break

                    # Build new formula with unmatched parts + instantiated consequent
                    new_parts = [p for i, p in enumerate(current_parts) if i not in matched_parts_set]
                    new_parts.append(instantiated_consequent)

                    current = analyzer._build_sepconj(new_parts)
                    applications.append(lemma.name)
                    lemma_applied = True

                    if verbose:
                        print(f"[Multi-Step Lemma] ✓ Applied {lemma.name}")
                        print(f"[Multi-Step Lemma] New formula: {current}")

                    break  # Apply one lemma per iteration

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

        if verbose:
            print(f"[Multi-Step Lemma] ✗ Failed after {len(applications)} applications")
            print(f"[Multi-Step Lemma]   Final: {current_normalized}")
            print(f"[Multi-Step Lemma]   Goal:  {consequent_normalized}")

        return None

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

        Returns unified bindings if all pattern parts match, None otherwise.
        """
        if len(pattern_parts) > len(formula_parts):
            return None

        # Try all combinations of formula_parts that match the size of pattern_parts
        from itertools import combinations

        for combo in combinations(range(len(formula_parts)), len(pattern_parts)):
            # Try to match this combination
            bindings = {}
            matched = True

            for pattern_part, formula_idx in zip(pattern_parts, combo):
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
