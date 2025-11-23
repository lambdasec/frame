#!/usr/bin/env python3
"""Test what proposals are generated for the lso test"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from frame import PredicateRegistry
from frame.predicates import ParsedPredicate
from frame.core.parser import parse
from frame.heap.graph import build_heap_graph, propose_folds, _collect_pto_atoms
from benchmarks.slcomp_parser import SLCompParser

def test_proposals():
    test_file = "benchmarks/cache/qf_shlid_entl/nll-vc01.smt2"

    with open(test_file, 'r') as f:
        content = f.read()

    parser = SLCompParser()
    ant, cons, _, _, _ = parser.parse_file(content, division_hint='qf_shlid_entl')

    # Register predicates
    registry = PredicateRegistry()

    for pred_name, (params, body_text) in parser.predicate_bodies.items():
        body_formula = parser._parse_formula(body_text)
        if body_formula:
            custom_pred = ParsedPredicate(pred_name, params, body_formula)
            registry.register(custom_pred, validate=False)

    # Test proposal generation for a simple lso case
    simple_formula = parse("x1_1 |-> x1_2 * x1_2 |-> x1_3 * x1_3 |-> nil")

    # Build heap graph
    graph = build_heap_graph(simple_formula)
    pto_atoms = _collect_pto_atoms(simple_formula)

    print(f"Formula: {simple_formula}")
    print(f"PTO atoms: {len(pto_atoms)}")
    print(f"Heap graph nodes: {len(graph.nodes)}")
    print()

    # Generate proposals
    proposals = propose_folds(graph, pto_atoms, max_proposals=20, predicate_registry=registry, formula=simple_formula)

    print(f"Generated {len(proposals)} proposals:")
    for i, p in enumerate(proposals, 1):
        print(f"  {i}. {p.predicate_name}({', '.join(str(a) for a in p.args)}) - {len(p.pto_cells)} cells, conf={p.confidence:.2f}")

    # Check if lso is in proposals
    lso_proposals = [p for p in proposals if p.predicate_name == 'lso']
    print(f"\nLSO proposals: {len(lso_proposals)}")
    for p in lso_proposals:
        print(f"  - lso({', '.join(str(a) for a in p.args)}) with {len(p.pto_cells)} cells")

if __name__ == "__main__":
    test_proposals()
