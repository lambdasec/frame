"""
Tests for SAT-specific wand encoding

These tests verify that the materialized witness encoding properly
constrains SAT problems, fixing the issue where implication-based
encoding was too weak.
"""

import pytest
from frame import EntailmentChecker
from frame.core.ast import *


class TestWandSATEncoding:
    """Test SAT-specific wand encoding with materialized witnesses"""

    def test_triple_allocation_unsat(self):
        """
        Test: u |-> 0 * (u |-> 0 -* (u |-> 0 * emp)) * u |-> 0

        This should be UNSAT because:
        - First pto allocates location u
        - Wand claims location u (from antecedent)
        - Third pto allocates location u
        - Three allocations of same location violate disjointness
        """
        checker = EntailmentChecker()

        u = Var("u")
        zero = Const(0)

        # Build: u |-> 0 * (u |-> 0 -* (u |-> 0 * emp)) * u |-> 0
        Q = SepConj(PointsTo(u, [zero]), Emp())
        wand = Wand(PointsTo(u, [zero]), Q)
        formula = SepConj(SepConj(PointsTo(u, [zero]), wand), PointsTo(u, [zero]))

        is_sat = checker.is_satisfiable(formula)

        assert not is_sat, "Formula should be UNSAT (three allocations of location u)"

    def test_wand_with_simple_contradiction(self):
        """
        Test: u |-> 5 * (u |-> 3 -* x |-> 7)

        With correct wand semantics (universal quantification), this should be SAT because:
        - Main heap has u |-> 5
        - Wand: ∀h'. (h # h' ∧ u |-> 3 ∈ h') → (x |-> 7 ∈ h ∪ h')
        - No extension h' can satisfy (u |-> 3) while being disjoint (u already in main)
        - Therefore the universal statement is VACUOUSLY TRUE
        - The formula becomes: u |-> 5 * TRUE = u |-> 5, which is SAT

        Note: This differs from the old existential witness encoding which required
        the wand to be "realizable" and would have made this UNSAT.
        """
        checker = EntailmentChecker()

        u = Var("u")
        x = Var("x")

        formula = SepConj(
            PointsTo(u, [Const(5)]),
            Wand(PointsTo(u, [Const(3)]), PointsTo(x, [Const(7)]))
        )

        is_sat = checker.is_satisfiable(formula)

        assert is_sat, "Formula should be SAT (wand is vacuously true when no disjoint extension satisfies P)"

    def test_simple_wand_sat(self):
        """
        Test: x |-> 5 * (u |-> 3 -* y |-> 7)

        This should be SAT because:
        - Main heap has x |-> 5
        - Wand requires: if ext has u |-> 3, then union has y |-> 7
        - Extension can have u |-> 3 (u not in main)
        - Union can have y |-> 7 (y not allocated)
        - All locations are different
        """
        checker = EntailmentChecker()

        x = Var("x")
        u = Var("u")
        y = Var("y")

        formula = SepConj(
            PointsTo(x, [Const(5)]),
            Wand(PointsTo(u, [Const(3)]), PointsTo(y, [Const(7)]))
        )

        is_sat = checker.is_satisfiable(formula)

        assert is_sat, "Formula should be SAT (all locations distinct)"

    def test_emp_wand_sat(self):
        """
        Test: (emp -* x |-> 5)

        This should be SAT because:
        - Wand antecedent is emp (satisfied by empty extension)
        - So consequent x |-> 5 must hold in union heap
        - Union heap can have x |-> 5
        """
        checker = EntailmentChecker()

        x = Var("x")
        wand = Wand(Emp(), PointsTo(x, [Const(5)]))

        is_sat = checker.is_satisfiable(wand)

        assert is_sat, "emp -* Q should be SAT"

    def test_entailment_mode_unchanged(self):
        """
        Verify that entailment checking still works correctly (uses ENTAILMENT mode)

        Test: x |-> 5 |- x |-> 5 (should be valid)
        """
        checker = EntailmentChecker()

        x = Var("x")
        P = PointsTo(x, [Const(5)])
        Q = PointsTo(x, [Const(5)])

        result = checker.check(P, Q)

        assert result.valid, "Reflexivity should still work in ENTAILMENT mode"

    def test_wand_entailment_still_works(self):
        """
        Test: (emp -* x |-> 5) * emp |- x |-> 5

        This should be valid (wand elimination lemma)
        """
        checker = EntailmentChecker()

        x = Var("x")
        wand = Wand(Emp(), PointsTo(x, [Const(5)]))
        P = SepConj(wand, Emp())
        Q = PointsTo(x, [Const(5)])

        result = checker.check(P, Q)

        assert result.valid, "Wand elimination should work in ENTAILMENT mode"


class TestWandSATBenchmarkPatterns:
    """Test patterns from actual SL-COMP benchmarks"""

    def test_rev_style_pattern(self):
        """
        Simplified pattern from rev-1-0.cvc4.smt2:

        (u |-> nil * emp) & !(u |-> x * (u |-> v -* Q) * u |-> y)

        With x = nil, y = nil, v = nil, this becomes:
        (u |-> nil * emp) & !(u |-> nil * (u |-> nil -* Q) * u |-> nil)

        The negated part has three allocations of u, so it's UNSAT.
        Therefore the whole formula is SAT iff (u |-> nil * emp) & !UNSAT = SAT
        Which is actually checking if (u |-> nil * emp) is SAT (yes) AND !(unsatisfiable) is SAT (yes tautology)

        Actually, the correct interpretation:
        - Inner: u |-> nil * wand * u |-> nil should be UNSAT (three u allocations)
        - So !(UNSAT) is a tautology (always true)
        - Combined with (u |-> nil * emp), the formula is SAT

        But wait, the benchmark expects UNSAT. Let me reconsider...

        The SMT2 file has multiple assertions that together are UNSAT.
        For now, let's test the core wand pattern.
        """
        checker = EntailmentChecker()

        u = Var("u")
        nil = Const(0)  # Represent nil as 0

        # Core pattern: u |-> nil * (u |-> nil -* Q) * u |-> nil
        Q = SepConj(PointsTo(u, [nil]), Emp())
        wand = Wand(PointsTo(u, [nil]), Q)
        inner = SepConj(SepConj(PointsTo(u, [nil]), wand), PointsTo(u, [nil]))

        is_sat_inner = checker.is_satisfiable(inner)

        assert not is_sat_inner, "Inner pattern should be UNSAT (three u allocations)"

    def test_dispose_pattern(self):
        """
        Test pattern inspired by dispose benchmarks:

        x |-> 5 * (x |-> nil -* emp)

        With correct wand semantics (universal quantification), this should be SAT because:
        - Main heap has x |-> 5
        - Wand: ∀h'. (h # h' ∧ x |-> nil ∈ h') → (emp ∈ h ∪ h')
        - No extension h' can have (x |-> nil) while being disjoint from main
          (x is already allocated with value 5, and strict disjointness prevents
          re-allocating x in the extension)
        - Therefore the universal statement is VACUOUSLY TRUE
        - The formula becomes: x |-> 5 * TRUE = x |-> 5, which is SAT

        Note: With the old existential witness encoding, this would have been UNSAT
        because no witness extension could be found. The new encoding correctly
        implements universal semantics where wands are vacuously true when the
        antecedent cannot be satisfied.
        """
        checker = EntailmentChecker()

        x = Var("x")
        y = Const(5)
        nil = Const(0)

        formula = SepConj(
            PointsTo(x, [y]),
            Wand(PointsTo(x, [nil]), Emp())
        )

        is_sat = checker.is_satisfiable(formula)

        assert is_sat, "Formula should be SAT (wand is vacuously true when antecedent cannot be satisfied)"


class TestWandDomainTracking:
    """Test that wand domain tracking works correctly"""

    def test_wand_claims_locations(self):
        """
        Verify that wand returns EMPTY domain (wands are propositions, not allocations)

        CRITICAL: Wands should NOT claim locations from their antecedent because:
        1. Wands are propositions about heap extensions, not allocations
        2. Claiming locations causes spurious disjointness in SepConj
        3. Example bug: (u |-> v) * (u |-> v -* Q) would generate u != u

        This test was updated after fixing the spurious domain claim bug.
        """
        from frame.encoding.encoder import Z3Encoder

        encoder = Z3Encoder()
        encoder._spatial_encoder.wand_encoder.mode = "SAT"

        u = Var("u")
        x = Var("x")

        wand = Wand(PointsTo(u, [Const(5)]), PointsTo(x, [Const(7)]))

        # Encode the wand
        import z3
        heap = z3.Array('test_heap', encoder.LocSort, encoder.ValSort)
        constraint, domain = encoder._spatial_encoder.wand_encoder.encode_wand(
            wand, heap, set(), {}, prefix=""
        )

        # Domain should be EMPTY - wands don't claim locations
        assert len(domain) == 0, "Wand should return empty domain (it's a proposition, not an allocation)"


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
