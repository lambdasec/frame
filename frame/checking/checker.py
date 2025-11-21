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
from frame.checking._checker_core import check_entailment_core
from frame.checking._satisfiability_check import is_satisfiable as _is_satisfiable_impl
from frame.checking._unification_matching import try_unification_matching as _try_unification_matching_impl


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
                 use_abduction: bool = False, use_s2s_normalization: bool = False,
                 use_guided_unfolding: bool = True):
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
            use_guided_unfolding: Use goal-directed unfolding (only unfold predicates matching consequent).
                          Enabled by default for 2-3x speedup on complex benchmarks.
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
        self.use_guided_unfolding = use_guided_unfolding
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
        return check_entailment_core(self, antecedent, consequent)

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
        """Delegate to satisfiability checking helper"""
        return _is_satisfiable_impl(self, formula)

    def _try_unification_matching(self, antecedent: Formula, consequent: Formula) -> Optional[EntailmentResult]:
        """Delegate to unification matching helper"""
        return _try_unification_matching_impl(self, antecedent, consequent)

    def find_frame(self, antecedent: Formula, consequent: Formula) -> Optional[Formula]:
        """Delegate to frame inference helper"""
        return find_frame(self, antecedent, consequent)

    def abduce_frame(self, antecedent: Formula, consequent: Formula) -> Optional[Formula]:
        """Delegate to frame inference helper"""
        return abduce_frame(self, antecedent, consequent)
