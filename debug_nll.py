#!/usr/bin/env python3
"""
Debug hierarchical predicate folding for nll test.

Run a single nll test with verbose output to see what proposals are generated.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from frame import EntailmentChecker, PredicateRegistry
from frame.predicates import ParsedPredicate
from benchmarks.slcomp_parser import SLCompParser

def debug_nll():
    """Debug nll-vc01.smt2 with detailed output"""

    test_file = "benchmarks/cache/qf_shlid_entl/nll-vc01.smt2"

    if not os.path.exists(test_file):
        print(f"Test file not found: {test_file}")
        return

    print("=" * 80)
    print("DEBUG: nll-vc01.smt2 Hierarchical Folding")
    print("=" * 80)
    print()

    # Read and parse the file
    with open(test_file, 'r') as f:
        content = f.read()

    parser = SLCompParser()
    antecedent, consequent, expected, problem_type, logic = parser.parse_file(content, division_hint='qf_shlid_entl')

    print(f"Problem Type: {problem_type}")
    print(f"Expected: {expected}")
    print(f"Logic: {logic}")
    print()

    print("Antecedent (concrete heap):")
    print(f"  {antecedent}")
    print()

    print("Consequent (should hold):")
    print(f"  {consequent}")
    print()

    # Register predicates
    registry = PredicateRegistry()
    registry.max_unfold_depth = 12

    print("Registering custom predicates:")
    for pred_name, (params, body_text) in parser.predicate_bodies.items():
        print(f"  - {pred_name}({', '.join(params)})")
        body_formula = parser._parse_formula(body_text)
        if body_formula:
            custom_pred = ParsedPredicate(pred_name, params, body_formula)
            registry.register(custom_pred, validate=False)
    print()

    # Create checker with verbose mode
    checker = EntailmentChecker(
        predicate_registry=registry,
        timeout=30000,
        use_folding=True,
        use_cyclic_proof=True,
        use_s2s_normalization=True,
        verbose=True  # VERBOSE MODE
    )

    print("=" * 80)
    print("RUNNING ENTAILMENT CHECK (VERBOSE)")
    print("=" * 80)
    print()

    result = checker.check(antecedent, consequent)

    print()
    print("=" * 80)
    print("RESULT")
    print("=" * 80)
    print(f"Valid: {result.valid}")
    print(f"Expected: {expected} (unsat = valid entailment)")
    print(f"Actual: {'unsat' if result.valid else 'sat'}")
    print(f"Correct: {result.valid and expected == 'unsat'}")
    print()

    if result.valid:
        print("✓ PASSED")
    else:
        print("✗ FAILED - hierarchical folding did not work")
        if result.reason:
            print(f"Reason: {result.reason}")

if __name__ == "__main__":
    debug_nll()
