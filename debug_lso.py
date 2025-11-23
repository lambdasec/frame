#!/usr/bin/env python3
"""
Debug why lso folding isn't working.

Check if we can manually fold inner lists into lso predicates.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from frame import EntailmentChecker, PredicateRegistry
from frame.predicates import ParsedPredicate
from frame.core.parser import parse
from benchmarks.slcomp_parser import SLCompParser

def test_lso_folding():
    """Test if we can fold into lso predicate"""

    test_file = "benchmarks/cache/qf_shlid_entl/nll-vc01.smt2"

    # Read and parse
    with open(test_file, 'r') as f:
        content = f.read()

    parser = SLCompParser()
    _, _, _, _, _ = parser.parse_file(content, division_hint='qf_shlid_entl')

    # Register predicates
    registry = PredicateRegistry()
    registry.max_unfold_depth = 12

    for pred_name, (params, body_text) in parser.predicate_bodies.items():
        body_formula = parser._parse_formula(body_text)
        if body_formula:
            custom_pred = ParsedPredicate(pred_name, params, body_formula)
            registry.register(custom_pred, validate=False)
            print(f"Registered: {pred_name}({', '.join(params)})")

    # Test simple lso folding
    # From the nll test, we have:
    # x1_1 |-> x1_2 * x1_2 |-> x1_3 * x1_3 |-> nil
    # This should fold into: lso(x1_1, nil)

    checker = EntailmentChecker(
        predicate_registry=registry,
        timeout=30000,
        use_folding=True,
        use_cyclic_proof=True,
        verbose=True  # VERBOSE!
    )

    # Test 1: Can we prove the simple lso entailment?
    print("\n" + "=" * 80)
    print("TEST 1: Simple lso entailment")
    print("=" * 80)

    antecedent_str = "x1_1 |-> x1_2 * x1_2 |-> x1_3 * x1_3 |-> nil"
    consequent_str = "lso(x1_1, nil)"

    print(f"Antecedent: {antecedent_str}")
    print(f"Consequent: {consequent_str}")

    antecedent = parse(antecedent_str)
    consequent = parse(consequent_str)

    result = checker.check(antecedent, consequent)
    print(f"Result: {'VALID' if result.valid else 'INVALID'}")

    if not result.valid:
        print("✗ Failed to prove simple lso entailment!")
        if result.reason:
            print(f"Reason: {result.reason}")
    else:
        print("✓ Simple lso entailment works!")

    # Test 2: What is the structure of lso?
    print("\n" + "=" * 80)
    print("TEST 2: Unfold lso predicate")
    print("=" * 80)

    lso_pred = registry.get("lso")
    if lso_pred:
        print(f"lso predicate arity: {lso_pred.arity}")

        # Unfold lso(x, nil)
        from frame.core.ast import Var, Const
        lso_call = parse("lso(x, nil)")
        unfolded = registry.unfold_predicates(lso_call, depth=2)
        print(f"lso(x, nil) unfolded (depth=2):")
        print(f"  {unfolded}")
    else:
        print("✗ lso predicate not registered!")

if __name__ == "__main__":
    test_lso_folding()
