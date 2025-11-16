"""
Frame Rule Application

Implements the frame rule for separation logic entailments with:
1. Syntactic matching (fast path)
2. Semantic matching via lemmas (e.g., transitivity)
3. Substitution-based matching via unification
"""

from typing import Tuple, Optional, Dict, List
from frame.core.ast import Formula, Emp, And, True_, PredicateCall, PointsTo, Expr
from frame.analysis.formula import FormulaAnalyzer
from frame.analysis.footprint import FootprintAnalyzer


class FrameRuleApplicator:
    """Applies frame rule to simplify entailments"""

    def __init__(self, verbose: bool = False, lemma_library=None):
        self.verbose = verbose
        self.analyzer = FormulaAnalyzer()
        self.footprint_analyzer = FootprintAnalyzer(unfold_depth=1)
        self.lemma_library = lemma_library  # For semantic matching

    def set_lemma_library(self, lemma_library):
        """Set lemma library for semantic matching"""
        self.lemma_library = lemma_library

    def normalize_empty_predicates(self, formula: Formula) -> Formula:
        """
        Normalize predicates that are known to be empty to emp.
        For example: ls(nil, nil) -> emp, ls(x, x) -> emp
        """
        if isinstance(formula, PredicateCall):
            if formula.name == 'ls' and len(formula.args) == 2:
                arg0, arg1 = formula.args
                # Check if both args are syntactically equal
                if self.analyzer._expr_equal(arg0, arg1):
                    # ls(x, x) is equivalent to emp
                    return Emp()
                # Check if both are nil
                from frame.core.ast import Const
                if isinstance(arg0, Const) and arg0.value is None:
                    if isinstance(arg1, Const) and arg1.value is None:
                        return Emp()
        elif isinstance(formula, type(formula)) and hasattr(formula, 'left') and hasattr(formula, 'right'):
            from frame.core.ast import SepConj, Or
            left = self.normalize_empty_predicates(formula.left)
            right = self.normalize_empty_predicates(formula.right)

            # emp * P = P, P * emp = P
            if isinstance(formula, SepConj):
                if isinstance(left, Emp):
                    return right
                if isinstance(right, Emp):
                    return left

            if left != formula.left or right != formula.right:
                return type(formula)(left, right)
        elif hasattr(formula, 'formula'):
            from frame.core.ast import Not, Exists, Forall
            if isinstance(formula, (Not, Exists, Forall)):
                inner = self.normalize_empty_predicates(formula.formula)
                if inner != formula.formula:
                    if isinstance(formula, Not):
                        return Not(inner)
                    elif isinstance(formula, Exists):
                        return Exists(formula.var, inner)
                    elif isinstance(formula, Forall):
                        return Forall(formula.var, inner)

        return formula

    def _try_semantic_match(self, formula1: Formula, formula2: Formula) -> bool:
        """
        Check if two formulas are semantically equivalent via lemmas.

        Examples:
        - ls(x,y) * ls(y,z) ≡ ls(x,z) (via transitivity)
        - x |-> v * ls(x, y) ≡ ls(x, y) where x != y (via cons lemma)

        Returns True if semantically equivalent, False otherwise.
        """
        if not self.lemma_library:
            return False

        # Try both directions (lemmas may be directional)
        # Check if formula1 |- formula2
        lemma_name = self.lemma_library.try_apply_lemma(formula1, formula2)
        if lemma_name:
            if self.verbose:
                print(f"[Frame Rule] Semantic match via lemma: {lemma_name}")
            return True

        # Check if formula2 |- formula1
        lemma_name = self.lemma_library.try_apply_lemma(formula2, formula1)
        if lemma_name:
            if self.verbose:
                print(f"[Frame Rule] Semantic match via lemma (reverse): {lemma_name}")
            return True

        return False

    def _try_substitution_match(
        self,
        ante_part: Formula,
        cons_part: Formula
    ) -> Optional[Dict[str, Expr]]:
        """
        Try to match formulas via substitution (unification).

        Example:
        - ante_part: ls(x, y)
        - cons_part: ls(a, b)
        - Returns: {a → x, b → y}

        This enables partial matching where predicates have different variables.
        """
        # Only works for predicates (not arbitrary formulas)
        if not isinstance(ante_part, PredicateCall) or not isinstance(cons_part, PredicateCall):
            return None

        # Predicates must have same name
        if ante_part.name != cons_part.name:
            return None

        # Predicates must have same arity
        if len(ante_part.args) != len(cons_part.args):
            return None

        # Try to unify arguments
        from frame.analysis.unification import Unifier, Substitution
        unifier = Unifier(verbose=False)

        substitution = Substitution()
        for ante_arg, cons_arg in zip(ante_part.args, cons_part.args):
            # Try to unify these arguments
            result = unifier.unify_exprs(cons_arg, ante_arg, substitution)
            if result is None:
                # Unification failed
                return None
            substitution = result

        # Return the substitution as a dict for easier use
        if substitution and substitution.mappings and self.verbose:
            print(f"[Frame Rule] Substitution match: {substitution.mappings}")

        return substitution.mappings if substitution and substitution.mappings else None

    def apply_frame_rule(self, antecedent: Formula, consequent: Formula) -> Tuple[Formula, Formula, bool]:
        """
        Try to apply frame rule: P * R |- Q * R can be reduced to P |- Q
        Also handles empty heap simplifications.

        Returns:
            (simplified_antecedent, simplified_consequent, was_simplified)
        """
        # First normalize empty predicates
        antecedent = self.normalize_empty_predicates(antecedent)
        consequent = self.normalize_empty_predicates(consequent)

        # Normalize SepConj order for consistent matching (P * Q = Q * P)
        antecedent = self.analyzer.normalize_sepconj(antecedent)
        consequent = self.analyzer.normalize_sepconj(consequent)

        # Special case: emp * emp |- emp or similar
        if self.analyzer._is_all_emp(antecedent) and self.analyzer._is_all_emp(consequent):
            if self.verbose:
                print("Frame rule: both sides are emp")
            return Emp(), Emp(), True

        # Extract pure and spatial parts
        ante_pure = self._extract_pure_part(antecedent)
        cons_pure = self._extract_pure_part(consequent)

        # Extract spatial parts
        ante_parts = self.analyzer._extract_sepconj_parts(antecedent)
        cons_parts = self.analyzer._extract_sepconj_parts(consequent)

        # Remove emp parts (they're neutral in separating conjunction)
        ante_parts = [p for p in ante_parts if not isinstance(p, Emp)]
        cons_parts = [p for p in cons_parts if not isinstance(p, Emp)]

        # Find common parts using multiple matching strategies
        common_parts = []
        remaining_ante = list(ante_parts)
        remaining_cons = list(cons_parts)
        substitutions_used = []  # Track substitutions for debugging

        for ante_part in ante_parts:
            matched = False
            for cons_part in cons_parts:
                if ante_part not in remaining_ante or cons_part not in remaining_cons:
                    continue

                # Strategy 1: Syntactic matching (fast path)
                if self.analyzer.formulas_syntactically_equal(ante_part, cons_part):
                    common_parts.append(ante_part)
                    remaining_ante.remove(ante_part)
                    remaining_cons.remove(cons_part)
                    matched = True
                    if self.verbose:
                        print(f"[Frame Rule] Syntactic match: {ante_part}")
                    break

                # Strategy 2: Semantic matching via lemmas
                if self._try_semantic_match(ante_part, cons_part):
                    common_parts.append(ante_part)
                    remaining_ante.remove(ante_part)
                    remaining_cons.remove(cons_part)
                    matched = True
                    break

                # Strategy 3: Substitution-based matching (DISABLED FOR SOUNDNESS)
                # Unification matching like ls(x,y) ≈ ls(x,z) is UNSOUND for frame rule
                # because it would incorrectly treat different formulas as equivalent.
                # Substitution matching should only be used in contexts where we're
                # matching against patterns (e.g., in lemma application), not for
                # finding common subformulas.
                #
                # substitution = self._try_substitution_match(ante_part, cons_part)
                # if substitution is not None:
                #     # UNSOUND: ls(x,y) and ls(x,z) are NOT equivalent!
                #     common_parts.append(ante_part)
                #     remaining_ante.remove(ante_part)
                #     remaining_cons.remove(cons_part)
                #     substitutions_used.append((ante_part, cons_part, substitution))
                #     matched = True
                #     break

            if matched:
                continue  # Move to next ante_part

        # If we found common parts, check if safe to simplify
        if common_parts:
            # Build simplified spatial formulas
            simplified_ante_spatial = self.analyzer._build_sepconj(remaining_ante) if remaining_ante else Emp()
            simplified_cons_spatial = self.analyzer._build_sepconj(remaining_cons) if remaining_cons else Emp()

            # SOUNDNESS CHECK (Affine SL with footprint-aware + order-aware weakening):
            # If consequent becomes emp, check if remainder can be safely dropped
            if isinstance(simplified_cons_spatial, Emp) and not isinstance(simplified_ante_spatial, Emp):
                # Remainder ⊢ emp case - check footprints with order awareness
                # Create position map from original ante_parts
                pos_map = {id(p): idx for idx, p in enumerate(ante_parts)}

                # Order-aware check: use minimum positions for each group
                can_drop = True
                for r_part in remaining_ante:
                    r_pos = pos_map.get(id(r_part), 0)
                    for c_part in common_parts:
                        c_pos = pos_map.get(id(c_part), 0)
                        if not self.footprint_analyzer.can_drop_safely_order_aware(r_part, r_pos, c_part, c_pos):
                            can_drop = False
                            break
                    if not can_drop:
                        break

                if not can_drop:
                    # Unsafe to drop - footprints overlap or order prevents it
                    if self.verbose:
                        print(f"Frame rule: Cannot drop remainder (footprint overlap with common parts)")
                    # Don't simplify - return original
                    return antecedent, consequent, False
                else:
                    # Safe to drop - footprints are disjoint and order allows it
                    if self.verbose:
                        print(f"Frame rule: Safe to drop remainder (disjoint footprints)")
                    # Return emp ⊢ emp (trivially valid)
                    simplified_ante_spatial = Emp()

            # Combine with pure parts if they exist
            if ante_pure and not isinstance(ante_pure, True_):
                simplified_ante = And(ante_pure, simplified_ante_spatial)
            else:
                simplified_ante = simplified_ante_spatial

            if cons_pure and not isinstance(cons_pure, True_):
                simplified_cons = And(cons_pure, simplified_cons_spatial)
            else:
                simplified_cons = simplified_cons_spatial

            if self.verbose:
                print(f"Frame rule applied: removed {len(common_parts)} common part(s)")
            return simplified_ante, simplified_cons, True
        else:
            return antecedent, consequent, False

    def _extract_pure_part(self, formula: Formula) -> Formula:
        """Extract the pure (non-spatial) part of a formula"""
        if not formula.is_spatial():
            return formula
        elif isinstance(formula, And):
            left_pure = self._extract_pure_part(formula.left)
            right_pure = self._extract_pure_part(formula.right)

            if left_pure and not isinstance(left_pure, True_):
                if right_pure and not isinstance(right_pure, True_):
                    return And(left_pure, right_pure)
                else:
                    return left_pure
            elif right_pure and not isinstance(right_pure, True_):
                return right_pure

        return True_()
