"""
Hierarchical Predicate Folding

Handles nested predicates where one predicate uses another internally.
For example, nll (nested list) uses lso (list segment) for inner lists.

Algorithm:
1. Detect multi-level structures (e.g., 2-field cells indicating nested lists)
2. Fold inner predicates first (bottom-up)
3. Then fold outer predicates using the folded inner predicates

This is critical for SL-COMP benchmarks with nested data structures.
"""

from typing import Optional, List, Dict, Set
from frame.core.ast import Formula, PointsTo, SepConj, PredicateCall, Var, Const
from frame.analysis.formula import FormulaAnalyzer


def has_multi_field_cells(formula: Formula) -> bool:
    """
    Check if formula contains cells with multiple fields (like x |-> (y, z)).

    This indicates a nested structure that needs hierarchical folding.
    """
    analyzer = FormulaAnalyzer()
    ptos = analyzer.extract_points_to(formula)

    for pto in ptos:
        if len(pto.values) > 1:
            return True
    return False


def identify_field_structure(formula: Formula) -> Dict[str, int]:
    """
    Analyze the field structure of cells in the formula.

    Returns:
        Dict mapping location names to number of fields
    """
    analyzer = FormulaAnalyzer()
    ptos = analyzer.extract_points_to(formula)

    structure = {}
    for pto in ptos:
        if isinstance(pto.location, Var):
            structure[pto.location.name] = len(pto.values)

    return structure


def extract_field_predicates(
    formula: Formula,
    field_index: int
) -> List[PredicateCall]:
    """
    Extract predicates that match a specific field index.

    For nested lists, field 0 is typically 'next' pointer,
    field 1 is 'down' pointer to inner list.

    Args:
        formula: Formula to analyze
        field_index: Which field to look at (0, 1, etc.)

    Returns:
        List of predicate calls that could be folded for this field
    """
    analyzer = FormulaAnalyzer()
    predicates = analyzer.extract_predicate_calls(formula)

    # Filter predicates that are likely for this field
    # For now, return all predicates - more sophisticated filtering later
    return predicates


def fold_hierarchical(
    antecedent: Formula,
    consequent: Formula,
    predicate_registry,
    verbose: bool = False
) -> Optional[Formula]:
    """
    Attempt hierarchical folding for nested predicates.

    Strategy:
    1. Check if we have multi-field cells (e.g., x |-> (y, z))
    2. Try to identify which predicates use which fields
    3. Fold bottom-up: inner predicates first, then outer

    Args:
        antecedent: Formula with concrete heap
        consequent: Target formula with nested predicates
        predicate_registry: Registry of available predicates
        verbose: Enable debug output

    Returns:
        Folded formula if successful, None otherwise
    """
    if not has_multi_field_cells(antecedent):
        # No multi-field cells, use regular folding
        return None

    if verbose:
        print("[Hierarchical Folding] Detected multi-field cells")

    # Analyze field structure
    structure = identify_field_structure(antecedent)
    if verbose:
        print(f"[Hierarchical Folding] Field structure: {structure}")

    # Get target predicate from consequent
    analyzer = FormulaAnalyzer()
    target_preds = analyzer.extract_predicate_calls(consequent)

    if not target_preds:
        return None

    target_pred = target_preds[0]  # Focus on first target

    if verbose:
        print(f"[Hierarchical Folding] Target: {target_pred.name}({', '.join(str(a) for a in target_pred.args)})")

    # Get predicate definition to understand its structure
    pred_def = predicate_registry.get(target_pred.name)
    if not pred_def:
        if verbose:
            print(f"[Hierarchical Folding] Predicate {target_pred.name} not found")
        return None

    # Unfold the predicate once to see its structure
    from frame.folding.apply import unfold_predicate_once
    unfolded = unfold_predicate_once(target_pred, predicate_registry)

    if verbose:
        print(f"[Hierarchical Folding] Target unfolds to: {unfolded}")

    # Try to match the structure
    # For now, return None to use existing folding
    # Full implementation would do sophisticated matching here

    return None


def generate_hierarchical_proposals(
    antecedent: Formula,
    consequent: Formula,
    predicate_registry,
    verbose: bool = False
) -> List:
    """
    Generate fold proposals for hierarchical predicates.

    This analyzes the target predicate's structure and generates
    proposals that match multi-field cells.

    Args:
        antecedent: Formula with concrete heap
        consequent: Target formula
        predicate_registry: Registry of predicates
        verbose: Debug output

    Returns:
        List of hierarchical fold proposals
    """
    proposals = []

    # TODO: Implement proposal generation for hierarchical predicates
    # For now, return empty list

    return proposals
