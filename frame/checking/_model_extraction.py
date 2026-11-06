"""Concrete model extraction for satisfiable pure formulas.

`is_satisfiable` (see `_satisfiability_check.py`) answers only yes/no and throws
the solver's model away. The proof-carrying-findings layer needs the model: the
concrete integer assignment that makes a finding's path condition and triggering
condition hold together, so a finding can be turned into a test that calls the
code with exactly those inputs.

This helper is deliberately narrow. It serves the C integer-range findings
(CWE-190/191/194/195/197), whose candidate formulas are PURE arithmetic over the
program's scalar variables (no heap cells, no inductive predicates). For those,
the Z3 model is a plain map from variable name to integer. Anything with spatial
structure, or any solver error or timeout, returns None: the caller keeps the
finding, it simply carries no concrete input. The satisfiability decision is NOT
re-made here and never changes -- this only re-solves an already-SAT formula to
read off one witness, so it can add data to a finding but never add or drop one.
"""

from __future__ import annotations

from typing import Dict, Optional

import z3

from frame.core.ast import Formula, False_
from frame.encoding.encoder import Z3Encoder
from frame.utils.satisfiability import simplify_arithmetic_formula


def satisfying_model(checker_self, formula: Formula) -> Optional[Dict[str, int]]:
    """Return one integer assignment that satisfies a pure arithmetic formula.

    Returns a map from variable name to the integer value Z3 chose, or None when
    the formula is unsatisfiable, is not purely arithmetic, times out, or anything
    goes wrong. Never raises.
    """
    try:
        from frame.preprocessing.equality import EqualityPreprocessor
        formula = EqualityPreprocessor().preprocess(formula)
        formula = simplify_arithmetic_formula(formula)
        if isinstance(formula, False_):
            return None

        encoder = Z3Encoder()
        encoder.use_acyclicity_constraints = False
        constraints, _heap, _domain = encoder.encode_formula(formula)

        solver = z3.Solver()
        solver.set("timeout", checker_self.timeout * 2)
        solver.add(constraints)
        if solver.check() != z3.sat:
            return None

        model = solver.model()
        out: Dict[str, int] = {}
        for decl in model.decls():
            value = model[decl]
            if value is not None and hasattr(value, "as_long"):
                try:
                    out[decl.name()] = value.as_long()
                except Exception:
                    continue
        return out
    except Exception:
        return None
