"""Visualize command implementation"""

import os
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from frame.core.ast import Formula, PointsTo, SepConj, PredicateCall
from benchmarks.slcomp_parser import SLCompParser


def cmd_visualize(args):
    """Visualize heap structure"""
    from frame.core.ast import PointsTo, PredicateCall, SepConj, And, Or, Exists, Forall, Not, Var

    # Determine file path
    if '/' in args.file:
        filepath = args.file
    else:
        # Assume it's in cache
        filepath = f"benchmarks/cache/qf_shls_entl/{args.file}"

    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return

    # Parse the file
    with open(filepath, 'r') as f:
        content = f.read()

    parser = SLCompParser()
    try:
        antecedent, consequent, expected_status, problem_type, logic = parser.parse_file(content)
    except Exception as e:
        print(f"Error parsing file: {e}")
        return

    # Extract heap edges and predicates
    def extract_heap_edges(formula):
        """Extract all points-to assertions"""
        edges = []
        def visit(f):
            if isinstance(f, PointsTo):
                loc = f.location.name if isinstance(f.location, Var) else str(f.location)
                if f.values:
                    val = f.values[0].name if isinstance(f.values[0], Var) else str(f.values[0])
                    edges.append((loc, val))
            elif isinstance(f, (SepConj, And, Or)):
                visit(f.left)
                visit(f.right)
            elif isinstance(f, (Exists, Forall, Not)):
                visit(f.formula)
        visit(formula)
        return edges

    def extract_predicates(formula):
        """Extract all predicate calls"""
        preds = []
        def visit(f):
            if isinstance(f, PredicateCall):
                args_str = ', '.join(arg.name if isinstance(arg, Var) else str(arg)
                                    for arg in f.args)
                preds.append((f.name, args_str, f.args))
            elif isinstance(f, (SepConj, And, Or)):
                visit(f.left)
                visit(f.right)
            elif isinstance(f, (Exists, Forall, Not)):
                visit(f.formula)
        visit(formula)
        return preds

    # Visualize
    print(f"\n{'='*80}")
    print(f"HEAP VISUALIZATION: {os.path.basename(filepath)}")
    print(f"{'='*80}")
    print(f"Expected: {expected_status}")
    print(f"Problem Type: {problem_type}\n")

    # Antecedent
    ante_edges = extract_heap_edges(antecedent)
    ante_preds = extract_predicates(antecedent)

    print("--- ANTECEDENT (What we have) ---")
    if ante_edges:
        print("Points-to edges:")
        for src, dst in ante_edges:
            print(f"  {src} |-> {dst}")

    if ante_preds:
        print("\nPredicates:")
        for name, args_str, _ in ante_preds:
            print(f"  {name}({args_str})")

    if not ante_edges and not ante_preds:
        print("  (empty heap)")

    # Consequent
    cons_edges = extract_heap_edges(consequent)
    cons_preds = extract_predicates(consequent)

    print("\n--- CONSEQUENT (What we need to prove) ---")
    if cons_edges:
        print("Points-to edges:")
        for src, dst in cons_edges:
            print(f"  {src} |-> {dst}")

    if cons_preds:
        print("\nPredicates:")
        for name, args_str, _ in cons_preds:
            print(f"  {name}({args_str})")

    if not cons_edges and not cons_preds:
        print("  (empty heap)")

    # Analysis
    print("\n--- ANALYSIS ---")
    print(f"Antecedent: {len(ante_edges)} points-to, {len(ante_preds)} predicates")
    print(f"Consequent: {len(cons_edges)} points-to, {len(cons_preds)} predicates")

    if problem_type == 'entl':
        print(f"\nFor entailment to be valid: antecedent must prove consequent")
        print(f"Expected result: {expected_status}")
    else:
        print(f"\nFor satisfiability check: formula must have a model")
        print(f"Expected result: {expected_status}")

    print("="*80 + "\n")
