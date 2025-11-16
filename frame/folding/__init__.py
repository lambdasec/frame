"""
Predicate folding and unfolding operations.

This module handles the transformation of heap structures into
predicate calls (folding) and vice versa (unfolding), including
verification and cyclic handling.
"""

# Main folding strategies
from frame.folding.blind import fold_formula_blind, fold_formula_batch
from frame.folding.goal_directed import fold_towards_goal

# Verification and application
from frame.folding.verify import verify_proposal_with_unification, verify_proposal_with_z3
from frame.folding.apply import apply_fold, apply_multiple_folds

# Public API
__all__ = [
    # Folding strategies
    'fold_formula_blind',      # Iterative, unguided folding
    'fold_towards_goal',       # Goal-directed folding
    'fold_formula_batch',      # Batch folding
    # Verification
    'verify_proposal_with_unification',
    'verify_proposal_with_z3',
    # Application
    'apply_fold',
    'apply_multiple_folds',
]
