#!/usr/bin/env python3
"""
Debug hierarchical predicate folding for nll.

This script helps diagnose why nll folding isn't working by showing:
1. What fold proposals are being generated
2. Whether inner predicates are included
3. What verification says
4. What the final result is
"""

from frame.checking.checker import EntailmentChecker
from frame.core.parser import parse
from frame.folding.goal_directed import fold_towards_goal
from frame.analysis.formula import FormulaAnalyzer
import os

def debug_nll_test():
    """Debug nll-vc01.smt2 with verbose output"""

    test_file = "benchmarks/cache/qf_shlid_entl/nll-vc01.smt2"

    if not os.path.exists(test_file):
        print(f"Test file not found: {test_file}")
        return

    # Read the SMT2 file
    with open(test_file, 'r') as f:
        content = f.read()

    print("=" * 80)
    print("DEBUGGING: nll-vc01.smt2")
    print("=" * 80)
    print()

    # Extract the check-entail command
    lines = content.split('\n')
    entail_line = None
    for line in lines:
        if 'check-entail' in line:
            entail_line = line
            break

    if not entail_line:
        print("No check-entail command found")
        return

    print(f"Check-entail command:\n{entail_line}")
    print()

    # Parse the formulas
    # Format: (check-entail antecedent consequent)
    # We need to extract the two formulas
    checker = EntailmentChecker()

    # For now, let's manually extract the formulas from the file
    # The structure is typically:
    # (check-entail
    #   (antecedent formula)
    #   (consequent formula))

    # Let me look at the actual structure first
    print("Full file content (first 50 lines):")
    print('\n'.join(lines[:50]))
    print()

    # Try to run the checker with verbose mode
    print("=" * 80)
    print("RUNNING ENTAILMENT CHECK")
    print("=" * 80)

    try:
        # The checker should handle SMT2 files directly
        result = checker.check_entailment_from_file(test_file)

        print(f"\nResult: {result.valid}")
        print(f"Expected: unsat (valid entailment)")
        print(f"Actual: {'unsat' if result.valid else 'sat'}")
        print(f"Correct: {result.valid}")

    except Exception as e:
        print(f"Error running checker: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_nll_test()
