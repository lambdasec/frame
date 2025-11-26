"""
Compositional property detection and lemma generation.

A predicate P is compositional if: P(x,a) * P(a,y) |- P(x,y)

This module detects compositional properties and auto-generates
multi-step composition lemmas.

References:
-----------
Le & Le, "An Efficient Cyclic Entailment Procedure in Separation Logic"
FoSSaCS 2023 - uses compositional predicates for efficiency
"""

from typing import List, Optional, Dict, Set, Tuple
from frame.core.ast import *
from frame.predicates.base import InductivePredicate
from frame.predicates.registry import PredicateRegistry


class CompositionalAnalyzer:
    """
    Analyzes predicates to detect compositional properties.

    A binary predicate P(x,y) is compositional if it satisfies:
      P(x, a) * P(a, y) |- P(x, y)

    DISABLED Nov 2025: Compositional reasoning is UNSOUND in separation logic!

    The property P(x,a) * P(a,y) |- P(x,y) is NOT valid when x = y is possible.
    For example, with ls:
    - ls(x,a) * ls(a,x) has heap cells if a != x
    - ls(x,x) = emp (empty heap)
    - A non-empty heap cannot entail an empty heap

    The comment "compositional under acyclic heap assumptions" was incorrect.
    Acyclicity prevents heap cycles, but not variable aliasing.

    The KNOWN_COMPOSITIONAL dictionary is now EMPTY to prevent unsound lemmas.
    """

    # DISABLED: These compositional lemmas are UNSOUND due to aliasing
    # Previously:
    # KNOWN_COMPOSITIONAL = {
    #     "ls": ("start", "end"),
    #     "path": ("from", "to"),
    #     "reach": ("from", "to"),
    #     "sls": ("start", "end", "min", "max"),
    # }
    KNOWN_COMPOSITIONAL = {}  # Empty to disable unsound lemmas

    def __init__(self, registry: PredicateRegistry):
        self.registry = registry
        self.compositional_cache: Dict[str, bool] = {}

    def is_compositional(self, pred_name: str) -> bool:
        """
        Check if a predicate is compositional.

        Currently uses syntactic analysis and known patterns.
        Future: Could test via SMT queries.
        """
        # Check cache
        if pred_name in self.compositional_cache:
            return self.compositional_cache[pred_name]

        # Check known compositional predicates
        if pred_name in self.KNOWN_COMPOSITIONAL:
            self.compositional_cache[pred_name] = True
            return True

        # Try syntactic heuristics
        # TODO: Could analyze predicate definition structure
        # For now, be conservative: only known predicates are compositional
        self.compositional_cache[pred_name] = False
        return False

    def get_composition_params(self, pred_name: str) -> Optional[Tuple[str, ...]]:
        """
        Get the parameter names for composition.

        For binary predicates like ls(x, y), returns ("start", "end")
        indicating that ls(x,a) * ls(a,y) |- ls(x,y)
        """
        if pred_name in self.KNOWN_COMPOSITIONAL:
            return self.KNOWN_COMPOSITIONAL[pred_name]
        return None

    def detect_composition_chain(
        self,
        predicates: List[PredicateCall]
    ) -> List[List[PredicateCall]]:
        """
        Detect chains of composable predicates.

        Example: [ls(x,y), ls(y,z), ls(z,w)] → one chain of 3
        Example: [ls(x,y), tree(a), ls(y,z)] → one chain of 2, tree separate

        Returns:
            List of predicate chains that can be composed
        """
        if not predicates:
            return []

        # Group by predicate name
        by_name: Dict[str, List[PredicateCall]] = {}
        for pred in predicates:
            if pred.name not in by_name:
                by_name[pred.name] = []
            by_name[pred.name].append(pred)

        chains = []

        # For each compositional predicate type
        for pred_name, pred_list in by_name.items():
            if not self.is_compositional(pred_name):
                continue

            # Find chains by matching endpoints
            # ls(x,y) * ls(y,z) * ls(z,w) forms a chain
            used = set()
            for i, pred in enumerate(pred_list):
                if i in used:
                    continue

                # Start a new chain
                chain = [pred]
                used.add(i)

                # Try to extend forward
                if len(pred.args) >= 2:
                    current_end = pred.args[1]  # End of current segment

                    while True:
                        found_next = False
                        for j, next_pred in enumerate(pred_list):
                            if j in used:
                                continue

                            if len(next_pred.args) >= 2:
                                next_start = next_pred.args[0]
                                # Check if endpoints match
                                if self._expr_equal(current_end, next_start):
                                    chain.append(next_pred)
                                    used.add(j)
                                    current_end = next_pred.args[1]
                                    found_next = True
                                    break

                        if not found_next:
                            break

                # Only add chains of length >= 2
                if len(chain) >= 2:
                    chains.append(chain)

        return chains

    def _expr_equal(self, e1: Expr, e2: Expr) -> bool:
        """Check if two expressions are syntactically equal"""
        if type(e1) != type(e2):
            return False
        if isinstance(e1, Var):
            return e1.name == e2.name
        if isinstance(e1, Const):
            return e1.value == e2.value
        return False


def generate_composition_lemmas(
    pred_name: str,
    max_chain_length: int = 4
) -> List[Tuple[str, Formula, Formula, str]]:
    """
    Generate composition lemmas for a compositional predicate.

    Args:
        pred_name: Name of the compositional predicate (e.g., "ls")
        max_chain_length: Maximum chain length to generate lemmas for

    Returns:
        List of (lemma_name, antecedent, consequent, description) tuples
    """
    lemmas = []

    # Generate meta-variables: X, Y, Z, W, V, U, ...
    # Use proper variable names (not '[' or '\')
    var_names = ['X', 'Y', 'Z', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P']
    vars = [Var(var_names[i]) for i in range(min(max_chain_length + 1, len(var_names)))]

    # Generate composition lemmas for chains of length 2, 3, 4, ...
    for chain_len in range(2, max_chain_length + 1):
        # Build antecedent: P(X0,X1) * P(X1,X2) * ... * P(Xn-1,Xn)
        antecedent_parts = []
        for i in range(chain_len):
            pred_call = PredicateCall(pred_name, [vars[i], vars[i + 1]])
            antecedent_parts.append(pred_call)

        # Build SepConj from parts
        if len(antecedent_parts) == 1:
            antecedent = antecedent_parts[0]
        else:
            antecedent = antecedent_parts[0]
            for part in antecedent_parts[1:]:
                antecedent = SepConj(antecedent, part)

        # Consequent: P(X0, Xn)
        consequent = PredicateCall(pred_name, [vars[0], vars[chain_len]])

        # Lemma name and description
        lemma_name = f"{pred_name}_composition_{chain_len}"
        description = f"{pred_name} composition (chain of {chain_len})"

        lemmas.append((lemma_name, antecedent, consequent, description))

    return lemmas


def install_compositional_lemmas(library, analyzer: CompositionalAnalyzer):
    """
    Install composition lemmas for all compositional predicates.

    Args:
        library: LemmaLibrary instance
        analyzer: CompositionalAnalyzer instance
    """
    # Get all registered predicates
    pred_names = list(analyzer.KNOWN_COMPOSITIONAL.keys())

    for pred_name in pred_names:
        if not analyzer.is_compositional(pred_name):
            continue

        # Generate composition lemmas for this predicate
        lemmas = generate_composition_lemmas(pred_name, max_chain_length=5)

        for lemma_name, antecedent, consequent, description in lemmas:
            # Add to library
            library.add_lemma(lemma_name, antecedent, consequent, description)


def detect_and_apply_composition(
    antecedent: Formula,
    consequent: Formula,
    analyzer: CompositionalAnalyzer
) -> Optional[str]:
    """
    Detect composition patterns and suggest lemma application.

    Returns:
        Lemma name if a composition pattern is detected, None otherwise
    """
    from frame.analysis.formula import FormulaAnalyzer

    fa = FormulaAnalyzer()

    # Extract predicate calls from antecedent
    ante_preds = _extract_predicate_calls(antecedent)

    # Check if consequent is a single predicate
    if not isinstance(consequent, PredicateCall):
        return None

    cons_pred = consequent

    # Look for composition chains
    chains = analyzer.detect_composition_chain(ante_preds)

    for chain in chains:
        if len(chain) < 2:
            continue

        # Check if this chain could compose to consequent
        # Chain: P(a,b) * P(b,c) * ... * P(y,z)
        # Should give: P(a, z)
        first = chain[0]
        last = chain[-1]

        if first.name == cons_pred.name and len(first.args) >= 2 and len(last.args) >= 2:
            # Check if endpoints match
            if (analyzer._expr_equal(first.args[0], cons_pred.args[0]) and
                analyzer._expr_equal(last.args[1], cons_pred.args[1])):
                # Found matching composition!
                chain_len = len(chain)
                return f"{first.name}_composition_{chain_len}"

    return None


def _extract_predicate_calls(formula: Formula) -> List[PredicateCall]:
    """Extract all predicate calls from a formula"""
    result = []

    if isinstance(formula, PredicateCall):
        result.append(formula)
    elif isinstance(formula, (SepConj, And, Or)):
        result.extend(_extract_predicate_calls(formula.left))
        result.extend(_extract_predicate_calls(formula.right))
    elif isinstance(formula, (Not, Exists, Forall)):
        result.extend(_extract_predicate_calls(formula.formula))

    return result
