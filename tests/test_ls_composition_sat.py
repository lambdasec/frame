"""
Test cases for list segment composition satisfiability

These tests verify the fix for the PredicateCall domain bug where
ls(x, y) * ls(y, z) was incorrectly encoding to False.

Bug: PredicateCall encoding was adding argument variables to the domain,
causing false disjointness constraints (e.g., y != y).

Fix: PredicateCall domain is now empty, since predicate parameters are not
allocated locations.
"""

import pytest
from frame import EntailmentChecker
from frame.core.ast import *
from frame.core.parser import parse
from frame.encoding.encoder import Z3Encoder
import z3


class TestListSegmentCompositionSAT:
    """Tests for list segment composition satisfiability"""

    def test_ls_composition_basic(self):
        """ls(x, y) * ls(y, z) should be SAT"""
        checker = EntailmentChecker()
        formula = parse("ls(x, y) * ls(y, z)")
        result = checker.is_satisfiable(formula)
        assert result, "List segment composition should be SAT"

    def test_ls_composition_three_segments(self):
        """ls(x, y) * ls(y, z) * ls(z, w) should be SAT"""
        checker = EntailmentChecker()
        formula = parse("ls(x, y) * ls(y, z) * ls(z, w)")
        result = checker.is_satisfiable(formula)
        assert result, "Three list segment composition should be SAT"

    def test_ls_composition_with_constraints(self):
        """ls(x, y) * ls(y, z) with x != z should be SAT"""
        checker = EntailmentChecker()
        # Build formula manually to avoid parser issues
        formula = And(
            Neq(Var('x'), Var('z')),
            SepConj(
                PredicateCall('ls', [Var('x'), Var('y')]),
                PredicateCall('ls', [Var('y'), Var('z')])
            )
        )
        result = checker.is_satisfiable(formula)
        assert result, "List segment composition with constraints should be SAT"

    def test_predicatecall_domain_empty(self):
        """PredicateCall encoding should return empty domain"""
        x = Var('x')
        y = Var('y')

        encoder = Z3Encoder()
        encoder._spatial_encoder.wand_encoder.mode = 'SAT'

        # Encode a PredicateCall
        heap_id = encoder.fresh_heap_id("Htest")
        constraints, domain = encoder._spatial_encoder.encode_heap_assertion(
            PredicateCall('ls', [x, y]),
            heap_id,
            set()
        )

        # Domain should be empty (not {x, y})
        assert len(domain) == 0, "PredicateCall domain should be empty"

    def test_sepconj_predicates_no_false(self):
        """SepConj of two predicates sharing variables should not be False"""
        x = Var('x')
        y = Var('y')
        z = Var('z')

        formula = SepConj(
            PredicateCall('ls', [x, y]),
            PredicateCall('ls', [y, z])
        )

        encoder = Z3Encoder()
        encoder._spatial_encoder.wand_encoder.mode = 'SAT'
        constraints, heap, domain = encoder.encode_formula(formula)

        # Simplify and check it's not False
        simplified = z3.simplify(constraints)
        assert not z3.is_false(simplified), "SepConj should not simplify to False"

        # Check satisfiability
        solver = z3.Solver()
        solver.add(constraints)
        result = solver.check()
        assert result == z3.sat, "Should be satisfiable"

    def test_multiple_disjoint_ls_sat(self):
        """Multiple disjoint list segments should be SAT"""
        checker = EntailmentChecker()
        formula = parse("ls(x1, y1) * ls(x2, y2) * ls(x3, y3)")
        result = checker.is_satisfiable(formula)
        assert result, "Disjoint list segments should be SAT"

    def test_ls_with_pto_sat(self):
        """List segment combined with points-to should be SAT"""
        checker = EntailmentChecker()
        formula = parse("ls(x, y) * (z |-> w)")
        result = checker.is_satisfiable(formula)
        assert result, "List segment with points-to should be SAT"

    def test_ls_circular_reference_sat(self):
        """Circular reference pattern should be SAT"""
        checker = EntailmentChecker()
        # This creates a pattern like: ls(x, y) * ls(y, x)
        # Should be SAT if both are empty (x = y)
        formula = And(
            Eq(Var('x'), Var('y')),
            SepConj(
                PredicateCall('ls', [Var('x'), Var('y')]),
                PredicateCall('ls', [Var('y'), Var('x')])
            )
        )
        result = checker.is_satisfiable(formula)
        assert result, "Circular reference with equality should be SAT"
