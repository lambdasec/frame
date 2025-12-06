"""
Doubly-linked list lemmas initialization
"""

from frame.core.ast import *


def initialize_dll_lemmas(library):
    """Initialize DLL lemmas"""

    # Create meta-variables
    x = Var("X")
    y = Var("Y")
    z = Var("Z")
    w = Var("W")
    nil = Const(None)
    p = Var("P")
    n = Var("N")
    m = Var("M")
    n1 = Var("N1")
    n2 = Var("N2")
    n3 = Var("N3")

    # DLL predicates in benchmarks typically have different signatures:
    # - SL-COMP standard (4-arg): dll(head, prev_of_head, tail, next_of_tail)
    # - With length (5-arg): dll(head, prev_of_head, tail, next_of_tail, length)
    #
    # IMPORTANT: DLL goes from HEAD to TAIL, not from head to the second parameter!
    # We provide lemmas for both signatures

    # ============================================
    # SL-COMP STANDARD DLL (4-arg: head, prev_head, tail, next_tail)
    # ============================================

    # DISABLED Nov 2025: Transitivity lemmas are UNSOUND due to aliasing!
    # When x = t2, the antecedent has heap cells but consequent DLL(x,y,x,n2) may be empty.
    # DLL transitivity (SL-COMP 4-arg, NO length): DLL(x,y,z,w) * DLL(z,w,t2,n2) |- DLL(x,y,t2,n2)
    # dll(x, y, z, w) where x=head, y=prev(head), z=tail, w=next(tail)
    # Compose dll(x,y,z,w) with dll(z,w,t2,n2):
    #   - First segment: from x to z, with prev(x)=y and next(z)=w
    #   - Second segment: from z to t2, with prev(z)=w (matches next(z)!) and next(t2)=n2
    #   - Result: from x to t2, with prev(x)=y and next(t2)=n2
    # NOTE: The uppercase DLL predicate must be case-insensitive
    t2 = Var("T2")
    n2 = Var("N2")
    # library.add_lemma(
    #     "DLL_transitivity_slcomp",
    #     SepConj(
    #         PredicateCall("DLL", [x, y, z, w]),
    #         PredicateCall("DLL", [z, w, t2, n2])
    #     ),
    #     PredicateCall("DLL", [x, y, t2, n2]),
    #     "DLL transitivity (SL-COMP 4-arg): compose two DLL segments"
    # )

    # Also add lowercase version for case-insensitive matching
    # library.add_lemma(
    #     "dll_transitivity_slcomp",
    #     SepConj(
    #         PredicateCall("dll", [x, y, z, w]),
    #         PredicateCall("dll", [z, w, t2, n2])
    #     ),
    #     PredicateCall("dll", [x, y, t2, n2]),
    #     "dll transitivity (SL-COMP 4-arg lowercase): compose two dll segments"
    # )

    # DLL cons (SL-COMP): x |-> (w, p) * dll(w, bk, x, next_tail) |- dll(x, bk, p, next_tail)
    # SL-COMP DLL signature: dll(fr, bk, pr, nx) where:
    #   fr = first/head of segment
    #   bk = back/last element of segment
    #   pr = prev of head (pointer back from head)
    #   nx = next of tail (pointer forward from tail)
    #
    # Prepending node x: x |-> (w, p) means x has next=w and prev=p
    # Pattern: dll(w, bk, x, nx) - segment from w to bk, with prev(w)=x (points back to x!)
    # Result: dll(x, bk, p, nx) - segment from x to bk, with prev(x)=p
    bk = Var("BK")  # back/tail element (unchanged during cons)
    next_tail = Var("NEXT_TAIL")
    library.add_lemma(
        "dll_cons_slcomp",
        SepConj(
            PointsTo(x, [w, p]),
            PredicateCall("dll", [w, bk, x, next_tail])  # dll[2]=x matches pto location
        ),
        PredicateCall("dll", [x, bk, p, next_tail]),
        "DLL cons (SL-COMP 4-arg): prepend a node to DLL segment"
    )

    # DLL to LS (4-arg DLL): dll(x, y, z, w) |- ls(x, w)
    # A doubly-linked list segment is also a (forward) list segment
    # DLL signature: dll(head, prev_of_head, tail, next_of_tail)
    # So dll(x, y, z, w) means DLL from x (head) to z (tail), with z pointing to w
    #
    # Key insight: 2-arg ls(x, y) means list from x with last cell pointing to y.
    # In 4-arg DLL, the last cell (tail=z) points to w (next_of_tail).
    # Therefore: dll(x, y, z, w) |- ls(x, w)  (NOT ls(x, z)!)
    library.add_lemma(
        "dll_to_ls_4arg",
        PredicateCall("dll", [x, y, z, w]),  # dll(head, prev, tail, next)
        PredicateCall("ls", [x, w]),  # forward list from head ending at next_of_tail
        "DLL (4-arg) is also a forward list segment ending at next_of_tail"
    )

    # DLL snoc (append at tail): dll(fr, tl, pr, nx) * nx |-> (nxt, tl) |- dll(fr, nx, pr, nxt)
    # SL-COMP DLL signature: dll(fr, bk, pr, nx) where:
    #   fr = first/head of segment
    #   bk = back/last element of segment
    #   pr = prev of head (pointer back from head)
    #   nx = next of tail (pointer forward from tail, i.e., what tail points to)
    #
    # Appending node nx: The dll ends with some cell pointing to nx.
    # nx |-> (nxt, tl) means nx has next=nxt and prev=tl (connecting back to the old tail)
    # Result: dll(fr, nx, pr, nxt) - segment now ends at nx, which points to nxt
    nxt = Var("NXT")
    tl = Var("TL")
    nx = Var("NX")  # next of current tail (will become new tail)
    library.add_lemma(
        "dll_snoc_slcomp",
        SepConj(
            PredicateCall("dll", [x, tl, p, nx]),  # dll ending at tl, which points to nx
            PointsTo(nx, [nxt, tl])  # nx has next=nxt, prev=tl (connects to old tail)
        ),
        PredicateCall("dll", [x, nx, p, nxt]),  # dll now ends at nx, pointing to nxt
        "DLL snoc (SL-COMP 4-arg): append a node to DLL segment"
    )

    # DLL snoc variant with y as back: dll(fr, bk, pr, y) * y |-> (nx, bk) |- dll(fr, y, pr, nx)
    # This handles the common pattern where y is the next pointer and becomes the new back
    library.add_lemma(
        "dll_snoc_slcomp_v2",
        SepConj(
            PredicateCall("dll", [x, bk, p, y]),  # dll ending with back=bk pointing to y
            PointsTo(y, [z, bk])  # y has next=z, prev=bk
        ),
        PredicateCall("dll", [x, y, p, z]),  # dll now ends at y, pointing to z
        "DLL snoc v2 (SL-COMP 4-arg): append a node using y as new back"
    )

    # ============================================
    # DLL_REV LEMMAS (REVERSED DOUBLY-LINKED LIST)
    # ============================================
    # Many shid_entl benchmarks use dll_rev predicate

    # dll_rev cons: dll_rev(hd, pr, tl, nx) * tl |-> (nx, y) |- dll_rev(hd, pr, tl, y)
    # dll_rev signature: dll_rev(head, prev_head, tail, next_tail)
    # Prepending on the reverse side
    hd = Var("HD")
    pr = Var("PR")
    library.add_lemma(
        "dll_rev_snoc",
        SepConj(
            PredicateCall("dll_rev", [hd, pr, tl, nx]),
            PointsTo(tl, [nx, y])
        ),
        PredicateCall("dll_rev", [hd, pr, tl, y]),
        "dll_rev snoc: extend dll_rev at tail"
    )

    # dll to dll_rev: dll(x, y, z, w) |- dll_rev(z, w, x, y)
    # A DLL can be viewed as its reverse
    library.add_lemma(
        "dll_to_dll_rev",
        PredicateCall("dll", [x, y, z, w]),
        PredicateCall("dll_rev", [z, w, x, y]),
        "DLL can be viewed as reversed DLL"
    )

    # dll_rev to dll: dll_rev(x, y, z, w) |- dll(z, w, x, y)
    # Reverse of above
    library.add_lemma(
        "dll_rev_to_dll",
        PredicateCall("dll_rev", [x, y, z, w]),
        PredicateCall("dll", [z, w, x, y]),
        "Reversed DLL can be viewed as DLL"
    )

    # DLL to BSLL (backward singly-linked list): DLL(x, y, z, w) |- BSLL(z, w)
    # From a DLL segment, extract the backward list segment
    # DLL(x, y, z, w) where z is prev(head) and w is next(tail)
    # Result: BSLL(z, w) is the backward list from z to w
    library.add_lemma(
        "DLL_to_BSLL",
        PredicateCall("DLL", [x, y, z, w]),
        PredicateCall("BSLL", [z, w]),
        "DLL (4-arg) implies backward singly-linked list segment"
    )

    # Also add lowercase version
    library.add_lemma(
        "dll_to_bsll",
        PredicateCall("dll", [x, y, z, w]),
        PredicateCall("bsll", [z, w]),
        "dll (4-arg lowercase) implies backward singly-linked list segment"
    )

    # DLL to LS (5-arg DLL with length): dll(hd, prev_hd, tail, next_tail, len) |- ls(hd, next_tail, len)
    # This matches SL-COMP benchmark signatures where dll has:
    #   param1: head, param2: prev of head, param3: tail, param4: next of tail, param5: length
    #
    # Key insight: ls(x, y, n) means n cells from x, with the LAST cell pointing to y.
    # dll(x, y, z, w, n) has the tail z pointing to w (next_tail).
    # Therefore: dll(x, y, z, w, n) |- ls(x, w, n)  (NOT ls(x, z, n)!)
    len_var = Var("LEN")
    library.add_lemma(
        "dll_to_ls_5arg",
        PredicateCall("dll", [x, y, z, w, len_var]),  # dll(head, prev_hd, tail, next_tail, len)
        PredicateCall("ls", [x, w, len_var]),  # ls(head, next_tail, length) - w is next_tail (param 4)
        "DLL (5-arg with length) is also a forward list segment ending at next_tail"
    )

    # NOTE: 4-arg DLL has NO length parameter, only 5-arg does!
    # The 4th parameter in 4-arg DLL is next_of_tail (a pointer), not a length.
    # Therefore, we only provide length composition for 5-arg DLL.

    # DISABLED Nov 2025: Composition lemmas are UNSOUND due to aliasing!
    # When h1 = tail2 or h1 = nt2, the aliasing causes soundness issues.
    #
    # DLL length composition (5-arg): dll(h1, ph1, tail1, nt1, len1) * dll(nt1, tail1, tail2, nt2, len2) |- dll(h1, ph1, tail2, nt2, len1+len2)
    # Signature: dll(head, prev_head, tail, next_tail, length)
    # Pattern: first segment from h1 to tail1, next(tail1)=nt1
    #          second segment from nt1 to tail2, prev(nt1)=tail1 (connects!)
    #          result: from h1 to tail2
    h1 = Var("H1")
    ph1 = Var("PH1")   # prev of head1
    tail1 = Var("TAIL1")   # tail of first segment
    nt1 = Var("NT1")   # next_tail of first segment (= head of second)
    tail2 = Var("TAIL2")   # tail of second segment
    nt2 = Var("NT2")   # next_tail of second segment
    len1 = Var("LEN1")
    len2 = Var("LEN2")
    # library.add_lemma(
    #     "dll_length_compose_5arg",
    #     SepConj(
    #         PredicateCall("dll", [h1, ph1, tail1, nt1, len1]),  # first: head1, prev(head1), tail1, next(tail1), len1
    #         PredicateCall("dll", [nt1, tail1, tail2, nt2, len2])   # second: head2, prev(head2), tail2, next(tail2), len2
    #     ),
    #     PredicateCall("dll", [h1, ph1, tail2, nt2, ArithExpr('+', len1, len2)]),  # result: head1, prev(head1), tail2, next(tail2), len1+len2
    #     "DLL composition (5-arg) with length parameters"
    # )

    # DLL length cons (5-arg): x |-> (nxt, prv) * dll(nxt, x, tl, n, len) |- dll(x, prv, tl, n, len+1)
    nxt = Var("NXT")
    prv = Var("PRV")
    tl = Var("TL")
    library.add_lemma(
        "dll_length_cons_5arg",
        SepConj(
            PointsTo(x, [nxt, prv]),
            PredicateCall("dll", [nxt, x, tl, n, len_var])
        ),
        PredicateCall("dll", [x, prv, tl, n, ArithExpr('+', len_var, Const(1))]),
        "DLL cons (5-arg) with length: prepending a node increases length by 1"
    )

    # ============================================
    # DLLNULL LEMMAS (NULL-TERMINATED DLL)
    # ============================================

    # dllnull(head, prev, length) - null-terminated doubly-linked list
    # Only 3 parameters: no tail parameter (tail is implicitly nil)

    # Define variables for dllnull lemmas
    t = Var("T")
    prev = Var("PREV")

    # dll with nil next_tail IS a dllnull: dll(x, y, t, nil, n) |- dllnull(x, y, n)
    # When the dll's next_tail parameter is nil, it's a null-terminated DLL
    # This is a critical lemma for the qf_shidlia_entl benchmarks
    library.add_lemma(
        "dll_nil_to_dllnull",
        PredicateCall("dll", [x, y, t, nil, len_var]),  # dll with next_tail = nil
        PredicateCall("dllnull", [x, y, len_var]),  # becomes dllnull
        "DLL with nil next_tail is a null-terminated DLL"
    )

    # DISABLED Nov 2025: Composition lemmas are UNSOUND due to aliasing!
    # When x = t (the head equals the second head), aliasing causes soundness issues.
    #
    # dll + dllnull composition: dll(x,y,z,t,n) * dllnull(t,z,m) |- dllnull(x,y,m+n)
    # This composes a dll segment with a dllnull segment
    # library.add_lemma(
    #     "dll_dllnull_compose",
    #     SepConj(
    #         PredicateCall("dll", [x, y, z, t, n1]),
    #         PredicateCall("dllnull", [t, z, n2])
    #     ),
    #     PredicateCall("dllnull", [x, y, ArithExpr('+', n2, n1)]),
    #     "DLL + dllnull composition: dll ending at t composed with dllnull starting at t"
    # )

    # dllnull transitivity: dllnull(x,p,n1) * dllnull(y,x,n2) might compose
    # (though less common pattern, adding for completeness)

    # dll + tail pto = dllnull: pto(t, (nil, prev)) * dll(x, y, prev, t, n) |- dllnull(x, y, n+1)
    # Appending a nil-pointing cell at the tail of a dll creates a dllnull
    library.add_lemma(
        "dll_append_nil_tail",
        SepConj(
            PointsTo(t, [nil, prev]),
            PredicateCall("dll", [x, y, prev, t, len_var])
        ),
        PredicateCall("dllnull", [x, y, ArithExpr('+', len_var, Const(1))]),
        "DLL + nil-pointing tail cell = dllnull with length+1"
    )

    # ============================================
    # LDLL LEMMAS (6-arg length-annotated DLL)
    # ============================================

    # ldll(E, P, len1, F, L, len2) - doubly-linked list with length
    # Parameters: first, prev_first, length, last, prev_last, length_again

    # Create meta-variables for ldll
    e1 = Var("E1")
    e2 = Var("E2")
    e1_p = Var("E1_P")
    e2_p = Var("E2_P")
    e3 = Var("E3")
    e3_p = Var("E3_P")
    len1 = Var("LEN1")
    len2 = Var("LEN2")
    len3 = Var("LEN3")

    # ldll cons: E1 |-> (E2, E1_p) * ldll(E2, E2_p, len2, F, L, len3) ⊢ ldll(E1, E1_p, len2+1, F, L, len3)
    # Note: Pure constraints (E1 = E2_p) are implicitly required but not in pattern
    # The pattern matcher will extract the spatial part from And formulas
    library.add_lemma(
        "ldll_cons_spatial",
        SepConj(
            PointsTo(e1, [e2, e1_p]),
            PredicateCall("ldll", [e2, e2_p, len2, e3, e3_p, len3])
        ),
        PredicateCall("ldll", [e1, e1_p, ArithExpr('+', len2, Const(1)), e3, e3_p, len3]),
        "ldll cons: prepend a cell to ldll (spatial pattern only)"
    )

    # NOTE: ldll_single_cell and ldll_single_cell_arith lemmas REMOVED for soundness
    #
    # These lemmas converted a points-to into an ldll predicate:
    #   E1 |-> (E2, E1_p) ⊢ ldll(E1, E1_p, 1, E2, E2_p, 0)
    #
    # The problem: When the Multi-Step Lemma phase applies this lemma to a points-to
    # that spatially overlaps with an existing ldll predicate (e.g., both allocate E1),
    # it creates an UNSOUND derivation. The lemma matcher doesn't verify spatial
    # disjointness before applying lemmas.
    #
    # Example (dll-entl-08.smt2):
    #   Antecedent: ldll(E1, ..., E2, ...) * E2 |-> (...) * ldll(E2, ..., E3, ...)
    #   If ldll(E2, ...) allocates E2, and we fold E2 |-> (...) into another ldll,
    #   we get an inconsistent heap (E2 allocated twice).
    #
    # Fix: Only allow such folding in goal-directed folding (frame/folding/goal_directed.py)
    # where disjointness is properly checked, not in the general lemma library.

    # NOTE: ldll_transitivity lemma REMOVED for soundness
    #
    # The problem: Multi-step lemma application doesn't verify spatial disjointness.
    # When the antecedent contains:
    #   ldll(E1, ..., E2, ...) * E2 |-> (...) * ldll(E2, ..., E3, ...)
    #
    # The lemma matcher would combine the two ldll predicates:
    #   ldll(E1, ...) * ldll(E2, ...) --> ldll(E1, ..., E3, ...)
    #
    # But this leaves E2 |-> (...) as "frame" - a spatial contradiction!
    # The second ldll starts at E2, so E2 is in its domain. Having both
    # ldll(E2, ...) and E2 |-> (...) means E2 is allocated twice.
    #
    # Example (dll-entl-08.smt2 - false positive):
    #   Antecedent: ldll(E1,...,E2,...) * E2 |-> (E3,E2_p) * ldll(E2,...,E3,...)
    #   Consequent: ldll(E1,...,E3,...)
    #   Expected: SAT (entailment does NOT hold due to heap overlap)
    #   Bug: ldll_transitivity combined the two ldll, got unsat (incorrectly valid)
    #
    # Fix: Remove this lemma. Transitivity should only be applied when we can
    # verify the two segments are ACTUALLY disjoint, which requires checking
    # there's no other spatial assertion on the connecting point.
    #
    # A future improvement could add disjointness checking to multi-step lemma
    # application, but for now removing the lemma ensures soundness.

    # ============================================
    # LS_PRE AND LSREV LEMMAS (BACKWARD/REVERSE LISTS)
    # ============================================

    # ls_pre(x, y, len) - list segment following prev pointers (backward)
    # lsrev(x, y, len) - reversed list segment

    # DLL to ls_pre: dll(x,y,z,t,n) |- ls_pre(z,y,n)
    # Extract the backward (prev) list segment from a DLL
    library.add_lemma(
        "dll_to_lspre",
        PredicateCall("dll", [x, y, z, t, len_var]),
        PredicateCall("ls_pre", [z, y, len_var]),
        "DLL implies backward list segment (following prev pointers)"
    )

    # DLL to lsrev: dll(x,y,z,t,n) |- lsrev(x,t,n)
    # Extract the reversed forward list segment from a DLL
    library.add_lemma(
        "dll_to_lsrev",
        PredicateCall("dll", [x, y, z, t, len_var]),
        PredicateCall("lsrev", [x, t, len_var]),
        "DLL implies reversed list segment"
    )

    # DISABLED Nov 2025: Transitivity lemmas are UNSOUND due to aliasing!
    # ls_pre transitivity: ls_pre(x,y,n1) * ls_pre(y,z,n2) |- ls_pre(x,z,n1+n2)
    # library.add_lemma(
    #     "lspre_transitivity",
    #     SepConj(
    #         PredicateCall("ls_pre", [x, y, n1]),
    #         PredicateCall("ls_pre", [y, z, n2])
    #     ),
    #     PredicateCall("ls_pre", [x, z, ArithExpr('+', n1, n2)]),
    #     "Backward list segment transitivity"
    # )

    # DISABLED Nov 2025: Transitivity lemmas are UNSOUND due to aliasing!
    # lsrev transitivity: lsrev(x,y,n1) * lsrev(y,z,n2) |- lsrev(x,z,n1+n2)
    # library.add_lemma(
    #     "lsrev_transitivity",
    #     SepConj(
    #         PredicateCall("lsrev", [x, y, n1]),
    #         PredicateCall("lsrev", [y, z, n2])
    #     ),
    #     PredicateCall("lsrev", [x, z, ArithExpr('+', n1, n2)]),
    #     "Reversed list segment transitivity"
    # )

    # ============================================
    # TREE LEMMAS
    # ============================================

    # 13. Empty tree: tree(nil) |- emp
    library.add_lemma(
        "tree_nil",
        PredicateCall("tree", [nil]),
        Emp(),
        "Empty tree is emp"
    )

    # ============================================
    # MAGIC WAND LEMMAS
    # ============================================

    # Create meta-variables for wand lemmas (P, Q are formulas)
    # We'll use placeholders - in practice, pattern matching handles these
    # For now, we add the most critical wand lemma using meta-variables

    # 14. Wand modus ponens: (P -* Q) * P |- Q
    # This is the fundamental property of the magic wand
    # P and Q will be matched against actual formulas
    P = Var("P")  # Meta-variable for formula P
    Q = Var("Q")  # Meta-variable for formula Q

    # Note: This lemma requires special handling in pattern matching
    # because P and Q are formula meta-variables, not expression meta-variables
    # For now, we add specific instances that are commonly needed

    # Common instance: (ls(x,y) -* ls(z,w)) * ls(x,y) |- ls(z,w)
    library.add_lemma(
        "wand_modus_ponens_ls",
        SepConj(
            Wand(PredicateCall("ls", [x, y]), PredicateCall("ls", [z, w])),
            PredicateCall("ls", [x, y])
        ),
        PredicateCall("ls", [z, w]),
        "Magic wand modus ponens for list segments"
    )

    # Instance: (emp -* Q) * emp |- Q (for any Q)
    # This is particularly useful
    # We'll add specific versions as needed

    # ============================================
    # ADDITIONAL COMPOSITION LEMMAS (for SL-COMP)
    # ============================================

    # NOTE: Many composition lemmas are too strong without proper constraint checking
    # For example, x |-> y * y |-> z does NOT always entail ls(x, z) because:
    # - We need x != z (distinct constraint)
    # - We need y != z (otherwise y |-> z is a self-loop)
    # - The lemma matcher doesn't verify pure constraints before applying lemmas
    #
    # For now, we keep only the safest lemmas that don't have these issues

    # DISABLED Nov 2025: Transitivity lemmas are UNSOUND due to aliasing!
    # The comment "safe because ls predicates include distinct constraints" is WRONG.
    # The issue is variable aliasing (x = w), not predicate constraints.
    # When x = w, antecedent has heap cells but consequent ls(x,x) = emp.
    #
    # Three-way transitivity: ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)
    # library.add_lemma(
    #     "ls_transitivity_3",
    #     SepConj(
    #         SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, z])),
    #         PredicateCall("ls", [z, w])
    #     ),
    #     PredicateCall("ls", [x, w]),
    #     "Three-way list segment transitivity"
    # )

    # Empty list segment equivalences
    # These are safe because they're about nil/emp
    library.add_lemma(
        "ls_nil_nil_to_emp",
        PredicateCall("ls", [nil, nil]),
        Emp(),
        "List segment from nil to nil is empty"
    )

    library.add_lemma(
        "emp_to_ls_nil_nil",
        Emp(),
        PredicateCall("ls", [nil, nil]),
        "Empty heap is list segment from nil to nil"
    )

    # ============================================
    # RLIST LEMMAS (RECURSIVE LIST WITH CONSTRAINTS)
    # ============================================

    # DISABLED Nov 2025: Transitivity lemmas are UNSOUND due to aliasing!
    # When x = z, antecedent has heap cells but consequent RList(x,x) = emp.
    #
    # RList transitivity: RList(x,y) * RList(y,z) |- RList(x,z)
    # RList is a recursive list predicate with distinct nil constraints
    # library.add_lemma(
    #     "rlist_transitivity",
    #     SepConj(
    #         PredicateCall("RList", [x, y]),
    #         PredicateCall("RList", [y, z])
    #     ),
    #     PredicateCall("RList", [x, z]),
    #     "RList transitivity: concatenating RList segments"
    # )

    # ============================================
    # LIST LEMMAS (for SL-COMP "List" predicate)
    # ============================================

