"""
Disjunct handling and optimization

Provides functions for extracting and scoring disjuncts in disjunctive formulas.
This implements heuristics for trying disjuncts in an intelligent order.
"""

from typing import List, Tuple
from frame.core.ast import Formula
from frame.checking._formula_helpers import count_formulas_by_type, contains_formula_type


def extract_disjuncts(formula: Formula) -> List[Formula]:
    """
    Extract all disjuncts from a formula with nested disjunctions.
    E.g., (A | (B | C)) -> [A, B, C]
    """
    from frame.core.ast import Or

    if not isinstance(formula, Or):
        return [formula]

    disjuncts = []
    disjuncts.extend(extract_disjuncts(formula.left))
    disjuncts.extend(extract_disjuncts(formula.right))
    return disjuncts


def score_disjuncts(antecedent: Formula, disjuncts: List[Formula]) -> List[Tuple[float, Formula]]:
    """
    Score disjuncts by likelihood of success and sort in descending order.

    Scoring heuristics (S2S-inspired):
    - Prefer disjuncts with matching predicates (+10 per match)
    - Prefer disjuncts with matching points-to (+5 per match)
    - Prefer simpler disjuncts (-1 per predicate, prefer base cases)
    - Prefer disjuncts with emp (often base case, +3)

    Args:
        antecedent: The antecedent formula to match against
        disjuncts: List of disjunct formulas to score

    Returns:
        List of (score, disjunct) tuples sorted by score (highest first)
    """
    from frame.core.ast import PredicateCall, PointsTo, Emp

    # Extract facts from antecedent
    ant_predicates = count_formulas_by_type(antecedent, PredicateCall)
    ant_ptos = count_formulas_by_type(antecedent, PointsTo)

    scored = []
    for disjunct in disjuncts:
        score = 0.0

        # Count components in disjunct
        disj_predicates = count_formulas_by_type(disjunct, PredicateCall)
        disj_ptos = count_formulas_by_type(disjunct, PointsTo)

        # Prefer matching predicates (strong signal)
        matching_preds = min(ant_predicates, disj_predicates)
        score += matching_preds * 10

        # Prefer matching points-to (moderate signal)
        matching_ptos = min(ant_ptos, disj_ptos)
        score += matching_ptos * 5

        # Prefer simpler disjuncts (try base cases first)
        score -= disj_predicates * 1

        # Prefer emp (often a base case that's easy to prove)
        if contains_formula_type(disjunct, Emp):
            score += 3

        scored.append((score, disjunct))

    # Sort by score descending (highest first)
    return sorted(scored, key=lambda x: x[0], reverse=True)
