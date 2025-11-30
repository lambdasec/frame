"""
List segment lemmas initialization
"""

from frame.core.ast import *


def initialize_list_lemmas(library):
    """Initialize list segment lemmas"""
    
    # Create meta-variables for lemma templates
    x = Var("X")
    y = Var("Y")
    z = Var("Z")
    w = Var("W")
    nil = Const(None)

    # ============================================
    # LIST SEGMENT LEMMAS
    # ============================================

    # 1. Transitivity: ls(x,y) * ls(y,z) |- ls(x,z)
    # RE-ENABLED Nov 2025 with CONDITIONAL application (see _lemma_application.py).
    #
    # Transitivity is SOUND when we can PROVE x != z:
    #   1. Explicit disequality (x != z) in antecedent
    #   2. Structural proof: both x and z have concrete cells (separation implies difference)
    #
    # Without proof, transitivity is SKIPPED (see aliasing check in lemma application).
    # This maintains soundness while improving completeness for provably-safe cases.
    #
    # Example where transitivity is UNSOUND (x might equal z):
    #   ls(x,y) * ls(y,z) |- ls(x,z) with x = z
    #   - LHS: non-empty heap (if x != y and y != z)
    #   - RHS: ls(x,x) = emp
    #   - Non-empty ⊢ emp is INVALID!
    #
    # Benchmark ls-vc06 expects this to be INVALID (status=sat) - correctly handled
    # because the aliasing check prevents application when endpoints might be equal.
    library.add_lemma(
        "ls_transitivity",
        SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, z])),
        PredicateCall("ls", [x, z]),
        "List segment transitivity: concatenating list segments (requires x != z proof)"
    )

    # 1b. Triple transitivity: ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)
    # DISABLED Nov 2025: Same issue as ls_transitivity
    #
    # library.add_lemma(
    #     "ls_triple_transitivity",
    #     SepConj(
    #         SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, z])),
    #         PredicateCall("ls", [z, w])
    #     ),
    #     PredicateCall("ls", [x, w]),
    #     "List segment triple transitivity: three segments compose"
    # )

    # 2. Cons lemma: x |-> y * ls(y, z) |- ls(x, z)
    library.add_lemma(
        "ls_cons",
        SepConj(PointsTo(x, [y]), PredicateCall("ls", [y, z])),
        PredicateCall("ls", [x, z]),
        "Cons: prepending a cell to a list segment"
    )

    # 3. Snoc lemma: ls(x, y) * y |-> z * ls(z, w) |- ls(x, w)
    # DISABLED Nov 2025: Same issue as transitivity - requires x != w for soundness.
    #
    # library.add_lemma(
    #     "ls_snoc",
    #     SepConj(
    #         SepConj(PredicateCall("ls", [x, y]), PointsTo(y, [z])),
    #         PredicateCall("ls", [z, w])
    #     ),
    #     PredicateCall("ls", [x, w]),
    #     "Snoc: appending a cell in the middle of list segments"
    # )

    # 3b. Single cell to ls: x |-> y |- ls(x, y)
    # DISABLED Nov 2025: Requires x != y for soundness.
    # If x = y, then x |-> x is non-empty but ls(x,x) = emp.
    # Non-empty ⊢ emp is INVALID!
    #
    # library.add_lemma(
    #     "pto_to_ls",
    #     PointsTo(x, [y]),
    #     PredicateCall("ls", [x, y]),
    #     "Single cell is a one-element list segment"
    # )

    # 4. Empty list segment: ls(x, x) |- emp
    library.add_lemma(
        "ls_empty",
        PredicateCall("ls", [x, x]),
        Emp(),
        "Empty list segment is emp"
    )

    # 5. Empty list segment reverse: emp |- ls(x, x)
    # (with pure constraint x = x, which is always true)
    library.add_lemma(
        "emp_to_ls_empty",
        Emp(),
        PredicateCall("ls", [x, x]),
        "emp entails empty list segment"
    )

    # 6. List segment with nil: ls(x, nil) |- list(x)
    library.add_lemma(
        "ls_to_list",
        PredicateCall("ls", [x, nil]),
        PredicateCall("list", [x]),
        "List segment to nil is a list"
    )

    # 7. List to list segment: list(x) |- ls(x, nil)
    library.add_lemma(
        "list_to_ls",
        PredicateCall("list", [x]),
        PredicateCall("ls", [x, nil]),
        "List is a list segment to nil"
    )

    # 8. Append left: ls(x, y) * list(y) |- list(x)
    library.add_lemma(
        "ls_append_list_left",
        SepConj(PredicateCall("ls", [x, y]), PredicateCall("list", [y])),
        PredicateCall("list", [x]),
        "List segment followed by list is a list"
    )

    # ============================================
    # CYCLE DETECTION LEMMAS
    # (S2S Analysis - Critical for cyclic structure detection)
    # ============================================

    # 8a. Antisymmetry: ls(x,y) * ls(y,x) |- emp ∧ x=y (CRITICAL FOR CYCLES!)
    # UNSOUND! Removed Nov 2025.
    # This lemma incorrectly concludes emp & x=y for any ls(x,y) * ls(y,x).
    # The correct reasoning is: under acyclic heap semantics, ls(x,y) * ls(y,x)
    # is only SATISFIABLE if x=y and both are emp. But as a lemma, we can't
    # conclude this without proving x=y first.
    #
    # PREVIOUSLY:
    # library.add_lemma(
    #     "ls_antisymmetry",
    #     SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, x])),
    #     And(Emp(), Eq(x, y)),
    #     "Antisymmetry: cyclic list segments must be empty with equal endpoints"
    # )

    # 8b. Alternative antisymmetry: ls(x,y) * ls(y,x) |- x=y (without emp in consequent)
    # UNSOUND! Removed Nov 2025 (same issue as above).
    #
    # PREVIOUSLY:
    # library.add_lemma(
    #     "ls_antisymmetry_eq",
    #     SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, x])),
    #     Eq(x, y),
    #     "Antisymmetry: cyclic list segments imply equal endpoints"
    # )

    # 8c. Triple cycle detection: ls(x,y) * ls(y,z) * ls(z,x) |- emp ∧ x=y=z
    # UNSOUND! Removed Nov 2025 (same issue as above).
    #
    # PREVIOUSLY:
    # library.add_lemma(
    #     "ls_triple_cycle",
    #     SepConj(
    #         SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, z])),
    #         PredicateCall("ls", [z, x])
    #     ),
    #     And(And(Emp(), Eq(x, y)), Eq(y, z)),
    #     "Triple cycle: three segments forming a cycle must collapse to a point"
    # )

    # 8d. Cycle with segment: ls(x,y) * ls(y,z) * ls(z,x) * ls(x,w) |- ls(y,z) * ls(z,x) * ls(x,w)
    # Simplification: if we have a cycle, we can reason about it more simply
    # Actually this is too complex, skip for now

    # 8e. Partial cycle breaking: ls(x,y) * y |-> z * ls(z,x) |- (conditions for soundness)
    # This helps when we have a concrete cell in a cyclic structure
    # Skip for now - needs more careful formulation

    # ============================================
    # CONVERGENT PATH LEMMAS (for overlapping segments)
    # ============================================

    # 8f. Convergent paths: ls(x,z) * ls(y,z) with disjoint prefixes
    # This is tricky - we can't easily express "disjoint prefixes" in lemma language
    # But we can add helpful special cases

    # Two segments converging at a point remain as separate segments
    # This is already handled by basic separation logic, but explicit lemma helps
    library.add_lemma(
        "ls_convergent_identity",
        SepConj(PredicateCall("ls", [x, z]), PredicateCall("ls", [y, z])),
        SepConj(PredicateCall("ls", [x, z]), PredicateCall("ls", [y, z])),
        "Convergent paths identity: two segments to same endpoint"
    )

    # ============================================
    # ENHANCED MULTI-STEP COMPOSITION LEMMAS
    # (S2S Analysis recommendation for complex benchmarks)
    # ============================================

    # 9. Four-step transitivity: ls(x,y) * ls(y,z) * ls(z,w) * ls(w,v) |- ls(x,v)
    # UNSOUND! Removed Nov 2025 (same issue as ls_transitivity - aliasing)
    #
    # PREVIOUSLY:
    # library.add_lemma(
    #     "ls_four_step_transitivity",
    #     SepConj(
    #         SepConj(
    #             SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, z])),
    #             PredicateCall("ls", [z, w])
    #         ),
    #         PredicateCall("ls", [w, Var("V")])
    #     ),
    #     PredicateCall("ls", [x, Var("V")]),
    #     "Four-step list segment composition"
    # )

    # 10. Mixed composition with cells: x |-> y * y |-> z * ls(z, w) |- ls(x, w)
    library.add_lemma(
        "ls_two_cells_segment",
        SepConj(
            SepConj(PointsTo(x, [y]), PointsTo(y, [z])),
            PredicateCall("ls", [z, w])
        ),
        PredicateCall("ls", [x, w]),
        "Two cells followed by segment"
    )

    # 11. Three cells to segment: x |-> y * y |-> z * z |-> w |- ls(x, w)
    library.add_lemma(
        "ls_three_cells",
        SepConj(
            SepConj(PointsTo(x, [y]), PointsTo(y, [z])),
            PointsTo(z, [w])
        ),
        PredicateCall("ls", [x, w]),
        "Three cells form a segment"
    )

    # 12. Segment with trailing cells: ls(x, y) * y |-> z * z |-> w |- ls(x, w)
    library.add_lemma(
        "ls_segment_two_cells",
        SepConj(
            SepConj(PredicateCall("ls", [x, y]), PointsTo(y, [z])),
            PointsTo(z, [w])
        ),
        PredicateCall("ls", [x, w]),
        "Segment followed by two cells"
    )

    # 9. Append right: list(x) * ls(y, z) |- list(x) (if we ignore y,z)
    # This is more complex - skip for now

    # 10. Single cell is list segment: x |-> y |- ls(x, y)
    # Actually this is wrong - x |-> y means next pointer, but ls includes y
    # Let me fix: x |-> y |- ∃z. ls(x, z) where z could be y or beyond
    # Actually for single cell: x |-> y * ls(y, z) |- ls(x, z) is the cons lemma above

    # 11. Frame-based lemmas for list segments
    # ls(x, y) |- ls(x, y) * emp (frame rule with emp)
    library.add_lemma(
        "ls_frame_emp",
        PredicateCall("ls", [x, y]),
        SepConj(PredicateCall("ls", [x, y]), Emp()),
        "List segment with empty frame"
    )

    # ============================================
    # APPEND / CONCATENATION LEMMAS
    # ============================================

    # 12. Append with node in middle: ls(x, y) * y |-> z |- ls(x, z) (when z points somewhere)
    # This is a weaker form - the general case is handled by snoc above
    # But let's add a more explicit version
    library.add_lemma(
        "ls_append_node",
        SepConj(PredicateCall("ls", [x, y]), PointsTo(y, [z])),
        PredicateCall("ls", [x, z]),
        "Append node to end of list segment"
    )

    # 13. Split list segment: ls(x, z) |- ∃y. ls(x, y) * ls(y, z)
    # This is the reverse of transitivity - we can split at any point
    # But we can't express this easily without existentials in the consequent
    # Skip for now

    # 14. Circular list detection: ls(x, y) * ls(y, x) |- ... (complex)
    # Skip circular lists for now

    # 15. List segment with equality: ls(x, y) ∧ y = z |- ls(x, z)
    # This requires pure reasoning integration
    library.add_lemma(
        "ls_with_eq",
        And(PredicateCall("ls", [x, y]), Eq(y, z)),
        PredicateCall("ls", [x, z]),
        "List segment with endpoint equality"
    )

    # 16. Append two lists: list(x) * list(y) |- ... (needs append function)
    # For now, we can express simpler cases

    # 17. Non-empty list segment: x |-> y |- ls(x, y) (single cell)
    # Actually this is wrong - x |-> y means x points to y,
    # but ls(x, y) means a segment from x to y (ending at y, not including y)
    # So x |-> y * ls(y, z) |- ls(x, z) is correct (that's cons above)

    # 18. List append lemma for circular lists (cll)
    # cll(x) is a circular linked list starting at x
    # cll(x) * cll(y) might not make sense (they're circular)
    # ls(x, y) * cll(y) |- cll(x) (prepend segment to circular list)
    library.add_lemma(
        "ls_prepend_to_cll",
        SepConj(PredicateCall("ls", [x, y]), PredicateCall("cll", [y])),
        PredicateCall("cll", [x]),
        "Prepend list segment to circular list"
    )

    # 19. Circular list is non-empty: cll(x) |- x != nil
    # This is a pure constraint - skip for now

    # 20. Append for sorted lists: sorted_ls(x, y) * sorted_ls(y, z) ∧ max(seg1) ≤ min(seg2) |- sorted_ls(x, z)
    # Too complex for now

    # ============================================
    # SORTED LIST SEGMENT LEMMAS
    # ============================================

    # Create additional meta-variables for sorted lists
    a = Var("A")
    b = Var("B")
    c = Var("C")

    # DISABLED Nov 2025: Transitivity lemmas are UNSOUND due to aliasing!
    # When x = z, antecedent has heap cells but consequent sls(x,a,x,c) may be empty.
    # The ordering constraints (a <= b <= c) don't prevent variable aliasing.
    #
    # sls transitivity WITH ordering constraints: sls(x,a,y,b) * sls(y,b,z,c) & a <= b <= c |- sls(x,a,z,c)
    # library.add_lemma(
    #     "sls_transitivity",
    #     And(
    #         And(
    #             SepConj(
    #                 PredicateCall("sls", [x, a, y, b]),
    #                 PredicateCall("sls", [y, b, z, c])
    #             ),
    #             Le(a, b)
    #         ),
    #         Le(b, c)
    #     ),
    #     PredicateCall("sls", [x, a, z, c]),
    #     "Sorted list segment transitivity with ordering constraints"
    # )

    # sls transitivity WITHOUT ordering constraints (for data equality semantics)
    # UNSOUND! Removed Nov 2025 (same aliasing issue as ls_transitivity).
    #
    # PREVIOUSLY:
    # library.add_lemma(
    #     "sls_transitivity_no_constraints",
    #     SepConj(
    #         PredicateCall("sls", [x, a, y, b]),
    #         PredicateCall("sls", [y, b, z, c])
    #     ),
    #     PredicateCall("sls", [x, a, z, c]),
    #     "SLS transitivity without ordering (for data equality semantics)"
    # )

    # ============================================
    # LENGTH-PARAMETERIZED LIST SEGMENT LEMMAS
    # ============================================

    # Create meta-variables for length parameters
    n1 = Var("N1")
    n2 = Var("N2")
    n3 = Var("N3")

    # ls with length transitivity: ls(x,y,n1) * ls(y,z,n2) |- ls(x,z,n1+n2)
    # UNSOUND! Removed Nov 2025 (same aliasing issue as ls_transitivity).
    #
    # PREVIOUSLY:
    # from frame.core.ast import ArithExpr
    # library.add_lemma(
    #     "ls_length_compose",
    #     SepConj(
    #         PredicateCall("ls", [x, y, n1]),
    #         PredicateCall("ls", [y, z, n2])
    #     ),
    #     PredicateCall("ls", [x, z, ArithExpr('+', n1, n2)]),
    #     "List segment composition with length parameters"
    # )

    # ls with length cons: x |-> y * ls(y, z, n) |- ls(x, z, n+1)
    library.add_lemma(
        "ls_length_cons",
        SepConj(
            PointsTo(x, [y]),
            PredicateCall("ls", [y, z, n1])
        ),
        PredicateCall("ls", [x, z, ArithExpr('+', n1, Const(1))]),
        "Cons with length: prepending a cell increases length by 1"
    )

    # ============================================
    # NESTED LIST LEMMAS
    # ============================================

    # nll transitivity: nll(x,y,field) * nll(y,z,field) |- nll(x,z,field)
    # UNSOUND! Removed Nov 2025 (same aliasing issue as ls_transitivity).
    #
    # PREVIOUSLY:
    # library.add_lemma(
    #     "nll_transitivity",
    #     SepConj(
    #         PredicateCall("nll", [x, y, nil]),
    #         PredicateCall("nll", [y, z, nil])
    #     ),
    #     PredicateCall("nll", [x, z, nil]),
    #     "Nested list transitivity with matching field parameter"
    # )

    # ============================================
    # INDUCTION LEMMAS FOR CYCLIC STRUCTURES
    # (S2S-style inductive reasoning)
    # ============================================

    # Induction base: empty heap with equal points
    library.add_lemma(
        "induction_base_emp",
        And(Emp(), Eq(x, y)),
        PredicateCall("ls", [x, y]),
        "Induction base: empty heap with equal endpoints proves ls"
    )

    # Induction step: if we have x |-> y and can prove from y, we can prove from x
    # This is essentially the cons lemma but framed as induction
    library.add_lemma(
        "induction_step_cons",
        SepConj(PointsTo(x, [y]), PredicateCall("ls", [y, z])),
        PredicateCall("ls", [x, z]),
        "Induction step: cons for list segments"
    )

    # Cyclic induction: if ls(x,y) * ls(y,x), by induction both must be empty
    # UNSOUND! Removed Nov 2025 (same issue as ls_antisymmetry).
    #
    # PREVIOUSLY:
    # library.add_lemma(
    #     "cyclic_induction",
    #     SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, x])),
    #     And(Emp(), Eq(x, y)),
    #     "Cyclic induction: two-way segments collapse by induction"
    # )

    # Multi-node cyclic induction for larger cycles
    # UNSOUND! Removed Nov 2025 (same issue as ls_antisymmetry).
    #
    # PREVIOUSLY:
    # library.add_lemma(
    #     "four_cycle_induction",
    #     SepConj(
    #         SepConj(
    #             SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, z])),
    #             PredicateCall("ls", [z, w])
    #         ),
    #         PredicateCall("ls", [w, x])
    #     ),
    #     And(And(And(Emp(), Eq(x, y)), Eq(y, z)), Eq(z, w)),
    #     "Four-cycle induction: four segments forming cycle must all collapse"
    # )

    # ============================================
    # MUTUALLY RECURSIVE LIST LEMMAS (ListE/ListO from SL-COMP)
    # ============================================

    # Mutually recursive list predicates from SL-COMP benchmarks
    # ListE (even-length list) and ListO (odd-length list)
    #
    # ALL COMPOSITION LEMMAS BELOW ARE UNSOUND due to aliasing!
    # Removed Nov 2025 (same issue as ls_transitivity).
    #
    # Example: ListE(x, y) * ListO(y, x) would have odd cells on one side
    # but ListO(x, x) = undefined behavior
    #
    # PREVIOUSLY:
    # library.add_lemma(
    #     "ListE_ListO_comp",
    #     SepConj(
    #         PredicateCall("ListE", [x, y]),
    #         PredicateCall("ListO", [y, z])
    #     ),
    #     PredicateCall("ListO", [x, z]),
    #     "Even-length list + Odd-length list = Odd-length list"
    # )

    # library.add_lemma(
    #     "ListO_ListE_comp",
    #     SepConj(
    #         PredicateCall("ListO", [x, y]),
    #         PredicateCall("ListE", [y, z])
    #     ),
    #     PredicateCall("ListO", [x, z]),
    #     "Odd-length list + Even-length list = Odd-length list"
    # )

    # library.add_lemma(
    #     "ListE_ListE_comp",
    #     SepConj(
    #         PredicateCall("ListE", [x, y]),
    #         PredicateCall("ListE", [y, z])
    #     ),
    #     PredicateCall("ListE", [x, z]),
    #     "Even-length list + Even-length list = Even-length list"
    # )

    # library.add_lemma(
    #     "ListO_ListO_comp",
    #     SepConj(
    #         PredicateCall("ListO", [x, y]),
    #         PredicateCall("ListO", [y, z])
    #     ),
    #     PredicateCall("ListE", [x, z]),
    #     "Odd-length list + Odd-length list = Even-length list"
    # )

    # ============================================
    # DOUBLY-LINKED LIST LEMMAS
    # ============================================

