"""
Lemma validation against predicate definitions

This module checks if lemmas are sound for given predicate definitions.
For example, ls transitivity is only valid if the ls predicate doesn't
have additional constraints like (distinct in out).
"""

from typing import Dict, List, Optional, Set, Tuple
from frame.core.ast import *
from frame.predicates.base import InductivePredicate
from frame.predicates.parsed import ParsedPredicate


class PredicateConstraintAnalyzer:
    """
    Analyzes predicate definitions to extract semantic constraints.

    This is crucial for determining which lemmas are valid for a given predicate.
    """

    def __init__(self, predicate: InductivePredicate):
        self.predicate = predicate
        self.param_names = []

        # If it's a ParsedPredicate, we can analyze the body
        if isinstance(predicate, ParsedPredicate):
            self.param_names = predicate.params
            self.body = predicate.body
        else:
            # For other predicates, we can't analyze constraints
            self.body = None

    def has_distinctness_constraints(self) -> bool:
        """
        Check if predicate has (distinct x y) or (x != y) constraints on parameters.

        Example: SL-COMP's ls has (distinct in out) in the recursive case:
          (or
            (and (= in out) emp)
            (exists (u) (and (distinct in out) (sep (pto in u) (ls u out)))))

        This constraint makes ls transitivity invalid.
        """
        if not self.body:
            return False

        # Look for Neq constraints involving parameters
        return self._find_neq_on_params(self.body, set(self.param_names))

    def _find_neq_on_params(self, formula: Formula, param_set: Set[str]) -> bool:
        """Recursively search for Neq constraints on parameters"""
        if isinstance(formula, Neq):
            # Check if both sides are parameters
            left_is_param = isinstance(formula.left, Var) and formula.left.name in param_set
            right_is_param = isinstance(formula.right, Var) and formula.right.name in param_set

            if left_is_param and right_is_param:
                return True

        elif isinstance(formula, And):
            return (self._find_neq_on_params(formula.left, param_set) or
                   self._find_neq_on_params(formula.right, param_set))

        elif isinstance(formula, Or):
            # Check both branches - if either has the constraint, we consider it present
            return (self._find_neq_on_params(formula.left, param_set) or
                   self._find_neq_on_params(formula.right, param_set))

        elif isinstance(formula, Exists) or isinstance(formula, Forall):
            # Don't include quantified variables as parameters
            new_param_set = param_set - {formula.var}
            return self._find_neq_on_params(formula.formula, new_param_set)

        elif isinstance(formula, SepConj):
            return (self._find_neq_on_params(formula.left, param_set) or
                   self._find_neq_on_params(formula.right, param_set))

        elif isinstance(formula, Not):
            # (not (= x y)) is equivalent to (distinct x y)
            if isinstance(formula.formula, Eq):
                eq = formula.formula
                left_is_param = isinstance(eq.left, Var) and eq.left.name in param_set
                right_is_param = isinstance(eq.right, Var) and eq.right.name in param_set
                if left_is_param and right_is_param:
                    return True
            return self._find_neq_on_params(formula.formula, param_set)

        return False

    def get_parameter_constraints(self) -> Dict[str, List[str]]:
        """
        Extract all constraints on parameters.

        Returns:
            Dict mapping constraint type to list of descriptions
            e.g., {"distinctness": ["param0 != param1"], "ordering": ["param0 <= param1"]}
        """
        constraints = {"distinctness": [], "ordering": [], "other": []}

        if not self.body:
            return constraints

        if self.has_distinctness_constraints():
            # Try to identify which parameters have distinctness constraints
            if len(self.param_names) >= 2:
                constraints["distinctness"].append(
                    f"{self.param_names[0]} != {self.param_names[1]}"
                )

        return constraints


class LemmaValidator:
    """
    Validates lemmas against predicate definitions.

    Determines if a lemma is sound for the given predicate semantics.
    """

    def __init__(self, predicates: Dict[str, InductivePredicate]):
        """
        Args:
            predicates: Mapping from predicate name to predicate definition
        """
        self.predicates = predicates
        self.analyzers = {
            name: PredicateConstraintAnalyzer(pred)
            for name, pred in predicates.items()
        }

    def is_lemma_sound(self, lemma_name: str, lemma_ant: Formula, lemma_cons: Formula) -> Tuple[bool, str]:
        """
        Check if a lemma is sound for the current predicate definitions.

        Args:
            lemma_name: Name of the lemma (for specific validation rules)
            lemma_ant: Antecedent of the lemma
            lemma_cons: Consequent of the lemma

        Returns:
            (is_sound, reason) tuple
        """
        # Extract predicates used in the lemma
        ant_predicates = self._extract_predicate_names(lemma_ant)
        cons_predicates = self._extract_predicate_names(lemma_cons)

        all_predicates = ant_predicates | cons_predicates

        # Check if all predicates are defined
        undefined = all_predicates - set(self.predicates.keys())
        if undefined:
            # If predicates are not defined, we can't validate constraints
            # But we shouldn't reject the lemma entirely - it may still be sound
            # We'll just skip constraint-based validation and allow it through
            # unless it's a known-problematic lemma type
            pass

        # Specific validation rules for known lemmas
        if "transitivity" in lemma_name.lower():
            return self._validate_transitivity_lemma(lemma_ant, lemma_cons, lemma_name)

        elif "cons" in lemma_name.lower():
            return self._validate_cons_lemma(lemma_ant, lemma_cons, lemma_name)

        elif "snoc" in lemma_name.lower() or "append_node" in lemma_name.lower():
            return self._validate_snoc_lemma(lemma_ant, lemma_cons, lemma_name)

        elif "empty" in lemma_name.lower() and "ls" in lemma_name.lower():
            return self._validate_empty_lemma(lemma_ant, lemma_cons, lemma_name)

        elif "frame" in lemma_name.lower():
            # Frame lemmas are generally sound (just adding emp)
            return True, "Frame lemmas are sound"

        elif "list_to_ls" in lemma_name.lower() or "ls_to_list" in lemma_name.lower():
            # List <-> ls conversions are generally sound
            return True, "List conversion lemmas are sound"

        # For other lemmas involving predicates with distinctness constraints, be conservative
        for pred_name in all_predicates:
            if pred_name in self.analyzers:
                if self.analyzers[pred_name].has_distinctness_constraints():
                    # Only reject if it's a list-like predicate (ls, sls, nll, etc.)
                    if pred_name in ['ls', 'sls', 'nll', 'lso']:
                        return False, (
                            f"Lemma '{lemma_name}' involves {pred_name} which has distinctness constraints. "
                            f"Conservative rejection to ensure soundness."
                        )

        # Default: assume sound if no issues detected
        return True, "No issues detected"

    def _validate_transitivity_lemma(self, ant: Formula, cons: Formula, lemma_name: str) -> Tuple[bool, str]:
        """
        Validate transitivity lemmas like: ls(x,y) * ls(y,z) |- ls(x,z)

        Transitivity is INVALID if the predicate has distinctness constraints.

        Example: If ls requires (distinct in out) in recursive case, then:
          ls(x,x) = emp (base case only)
          ls(x,y) * ls(y,y) = ls(x,y) * emp = ls(x,y)
          But ls(x,y) does NOT imply ls(x,y) if x=y because ls(x,x) = emp
          So transitivity doesn't hold!
        """
        # Extract predicate names from the lemma
        predicates_in_lemma = self._extract_predicate_names(ant) | self._extract_predicate_names(cons)

        # Check each predicate for distinctness constraints
        for pred_name in predicates_in_lemma:
            if pred_name in self.analyzers:
                analyzer = self.analyzers[pred_name]

                if analyzer.has_distinctness_constraints():
                    return False, (
                        f"Transitivity invalid: {pred_name} has distinctness constraint. "
                        f"This breaks transitivity when endpoints are equal."
                    )

        return True, "Transitivity valid for predicates without distinctness constraints"

    def _validate_cons_lemma(self, ant: Formula, cons: Formula, lemma_name: str) -> Tuple[bool, str]:
        """
        Validate cons lemmas like: x |-> y * ls(y, z) |- ls(x, z)

        Cons is also affected by distinctness constraints.
        With (distinct in out), x |-> y * ls(y,z) |- ls(x,z) is invalid when x=z.
        """
        # Extract predicate names
        predicates_in_lemma = self._extract_predicate_names(ant) | self._extract_predicate_names(cons)

        # Check for distinctness constraints
        for pred_name in predicates_in_lemma:
            if pred_name in self.analyzers:
                analyzer = self.analyzers[pred_name]

                if analyzer.has_distinctness_constraints():
                    # Cons lemma is invalid with distinctness constraints
                    # Example: x |-> y * ls(y, x) doesn't entail ls(x, x) = emp
                    # because x |-> y * ls(y, x) requires x != x, which is false
                    return False, (
                        f"Cons lemma invalid: {pred_name} has distinctness constraint. "
                        f"Cannot guarantee endpoints are distinct in cons pattern."
                    )

        return True, "Cons valid for predicates without distinctness constraints"

    def _validate_snoc_lemma(self, ant: Formula, cons: Formula, lemma_name: str) -> Tuple[bool, str]:
        """
        Validate snoc/append lemmas like: ls(x, y) * y |-> z * ls(z, w) |- ls(x, w)

        Snoc is a composition lemma affected by distinctness constraints.
        """
        # Extract predicate names
        predicates_in_lemma = self._extract_predicate_names(ant) | self._extract_predicate_names(cons)

        # Check for distinctness constraints
        for pred_name in predicates_in_lemma:
            if pred_name in self.analyzers:
                analyzer = self.analyzers[pred_name]

                if analyzer.has_distinctness_constraints():
                    return False, (
                        f"Snoc/append lemma invalid: {pred_name} has distinctness constraint. "
                        f"Composition requires transitive closure which breaks with distinctness."
                    )

        return True, "Snoc valid for predicates without distinctness constraints"

    def _validate_empty_lemma(self, ant: Formula, cons: Formula, lemma_name: str) -> Tuple[bool, str]:
        """
        Validate empty list lemmas like: ls(x, x) |- emp

        These are generally sound even with distinctness constraints,
        since the base case allows x=x with emp.
        """
        # Empty lemmas are sound - the base case of ls handles this
        return True, "Empty list lemmas are sound"

    def _extract_predicate_names(self, formula: Formula) -> Set[str]:
        """Extract all predicate names used in a formula"""
        if isinstance(formula, PredicateCall):
            return {formula.name}

        elif isinstance(formula, (And, Or, SepConj)):
            return self._extract_predicate_names(formula.left) | self._extract_predicate_names(formula.right)

        elif isinstance(formula, Not):
            return self._extract_predicate_names(formula.formula)

        elif isinstance(formula, (Exists, Forall)):
            return self._extract_predicate_names(formula.formula)

        else:
            return set()
