"""
Unification-Based Matching for Entailment Checking

Extracted from checker.py to reduce file size.
Contains logic for proving entailments using unification of fresh variables.
"""

from typing import Optional
from frame.core.ast import (
    Formula, SepConj, PointsTo, PredicateCall, Or, Exists, Var,
    And, Not, Eq, Neq, ArithExpr
)


def try_unification_matching(
    checker_self,
    antecedent: Formula,
    consequent: Formula
) -> Optional['EntailmentResult']:
    """
    Try to prove entailment using unification-based matching.

    This handles cases where predicates with fresh variables (from unfolding)
    need to be matched against concrete heap structures.

    IMPORTANT: Only applies unification when consequent has "fresh" variables
    (ones starting with z_ from unfolding). Otherwise, returns None to avoid
    incorrectly unifying concrete variables that should remain distinct.

    Args:
        checker_self: The EntailmentChecker instance
        antecedent: Antecedent formula (may have concrete heap)
        consequent: Consequent formula (may have fresh variables from unfolding)

    Returns:
        EntailmentResult if unification succeeds, None otherwise
    """
    from frame.checking.checker import EntailmentResult
    
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
    subst = checker_self.unifier.unify_formulas(antecedent, consequent)

    if subst is not None and subst:
        # Unification succeeded! Apply substitution and check equality
        ante_subst = checker_self.unifier.apply_subst_formula(antecedent, subst)
        cons_subst = checker_self.unifier.apply_subst_formula(consequent, subst)

        if checker_self.analyzer.formulas_syntactically_equal(ante_subst, cons_subst):
            if checker_self.verbose:
                print(f"✓ Unification-based matching succeeded!")
                print(f"  Substitution: {subst}")
            return EntailmentResult(valid=True, reason="Unification matching")

    # Component-wise matching also only applies with fresh variables
    # (Otherwise we might incorrectly match concrete structures)
    ante_parts = checker_self.analyzer._extract_sepconj_parts(antecedent)
    cons_parts = checker_self.analyzer._extract_sepconj_parts(consequent)

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
                part_subst = checker_self.unifier.unify_formulas(cons_part, ante_part, current_subst)
                if part_subst is not None:
                    # Check if substitution is consistent
                    cons_applied = checker_self.unifier.apply_subst_formula(cons_part, part_subst)
                    ante_applied = checker_self.unifier.apply_subst_formula(ante_part, part_subst)

                    if checker_self.analyzer.formulas_syntactically_equal(cons_applied, ante_applied):
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
            if checker_self.verbose:
                print(f"✓ Component-wise unification succeeded!")
                print(f"  Matched {matched_count} components")
                if current_subst:
                    print(f"  Substitution: {current_subst}")
            return EntailmentResult(valid=True, reason="Component-wise unification")

    # Unification didn't help
    return None

