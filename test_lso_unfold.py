#!/usr/bin/env python3
"""Test if lso predicate can be unfolded"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from frame import PredicateRegistry
from frame.predicates import ParsedPredicate
from frame.core.parser import parse
from benchmarks.slcomp_parser import SLCompParser

def test_unfold():
    test_file = "benchmarks/cache/qf_shlid_entl/nll-vc01.smt2"

    with open(test_file, 'r') as f:
        content = f.read()

    parser = SLCompParser()
    parser.parse_file(content, division_hint='qf_shlid_entl')

    # Register predicates
    registry = PredicateRegistry()

    for pred_name, (params, body_text) in parser.predicate_bodies.items():
        body_formula = parser._parse_formula(body_text)
        if body_formula:
            custom_pred = ParsedPredicate(pred_name, params, body_formula)
            registry.register(custom_pred, validate=False)

    # Test unfold lso
    print("Testing lso unfold...")
    lso_call = parse("lso(x, y)")
    print(f"lso call: {lso_call}")

    try:
        unfolded = registry.unfold_predicates(lso_call, depth=3)
        print(f"lso unfolded (depth 3): {unfolded}")
        print("✓ lso unfold succeeded")
    except Exception as e:
        print(f"✗ lso unfold failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_unfold()
