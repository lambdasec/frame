"""
Debug utilities for Z3 encoding inspection
"""

import z3


def dump_z3_formula(z3expr, filename="/tmp/encode_dump.smt2"):
    """
    Dump Z3 expression to SMT-LIB file for inspection.

    Useful for debugging encoding issues.
    """
    with open(filename, "w") as f:
        f.write(z3expr.sexpr())
    print(f"Dumped Z3 expr to {filename}")


def analyze_z3_dump(filename="/tmp/encode_dump.smt2"):
    """
    Analyze a dumped SMT-LIB file for common issues.

    Returns dict with analysis results.
    """
    with open(filename, "r") as f:
        content = f.read()

    analysis = {
        'exists_blocks': content.count('exists'),
        'heap_main_refs': content.count('heap_main'),
        'ext_alloc_refs': content.count('ext_alloc'),
        'wand_refs': content.count('wand'),
        'has_negated_wand': '_negext_' in content or '_negunion_' in content,
        'total_lines': len(content.split('\n'))
    }

    return analysis
