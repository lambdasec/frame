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

    # DLL transitivity (SL-COMP 4-arg, NO length): DLL(x,y,z,w) * DLL(z,w,t2,n2) |- DLL(x,y,t2,n2)
    # dll(x, y, z, w) where x=head, y=prev(head), z=tail, w=next(tail)
    # Compose dll(x,y,z,w) with dll(z,w,t2,n2):
    #   - First segment: from x to z, with prev(x)=y and next(z)=w
    #   - Second segment: from z to t2, with prev(z)=w (matches next(z)!) and next(t2)=n2
    #   - Result: from x to t2, with prev(x)=y and next(t2)=n2
    # NOTE: The uppercase DLL predicate must be case-insensitive
    t2 = Var("T2")
    n2 = Var("N2")
    library.add_lemma(
        "DLL_transitivity_slcomp",
        SepConj(
            PredicateCall("DLL", [x, y, z, w]),
            PredicateCall("DLL", [z, w, t2, n2])
        ),
        PredicateCall("DLL", [x, y, t2, n2]),
        "DLL transitivity (SL-COMP 4-arg): compose two DLL segments"
    )

    # Also add lowercase version for case-insensitive matching
    library.add_lemma(
        "dll_transitivity_slcomp",
        SepConj(
            PredicateCall("dll", [x, y, z, w]),
            PredicateCall("dll", [z, w, t2, n2])
        ),
        PredicateCall("dll", [x, y, t2, n2]),
        "dll transitivity (SL-COMP 4-arg lowercase): compose two dll segments"
    )

    # DLL cons (SL-COMP): x |-> (w, p) * dll(w, x, tail, next_tail) |- dll(x, p, tail, next_tail)
    # Prepending a node x to a DLL from w to tail
    # x has next=w and prev=p
    # dll(w, x, tail, next_tail) is segment from w to tail with prev(w)=x and next(tail)=next_tail
    # Result: dll(x, p, tail, next_tail) is segment from x to tail with prev(x)=p and next(tail)=next_tail
    tail = Var("TAIL")
    next_tail = Var("NEXT_TAIL")
    library.add_lemma(
        "dll_cons_slcomp",
        SepConj(
            PointsTo(x, [w, p]),
            PredicateCall("dll", [w, x, tail, next_tail])
        ),
        PredicateCall("dll", [x, p, tail, next_tail]),
        "DLL cons (SL-COMP 4-arg): prepend a node to DLL segment"
    )

    # DLL to LS (4-arg DLL): dll(x, y, z, w) |- ls(x, y)
    # A doubly-linked list segment is also a (forward) list segment
    # DLL signature: dll(head, prev_of_head, tail, next_of_tail)
    # So dll(x, y, z, w) means DLL from x (head) to z (tail)
    # Therefore it entails ls(x, z), not ls(x, y)!
    library.add_lemma(
        "dll_to_ls_4arg",
        PredicateCall("dll", [x, y, z, w]),  # dll(head, prev, tail, next)
        PredicateCall("ls", [x, z]),  # forward list from head to tail
        "DLL (4-arg) is also a forward list segment from head to tail"
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

    # DLL to LS (5-arg DLL with length): dll(hd, prev_hd, tail, next_tail, len) |- ls(hd, tail, len)
    # This matches SL-COMP benchmark signatures where dll has:
    #   param1: head, param2: prev of head, param3: tail, param4: next of tail, param5: length
    # IMPORTANT: param3 is TAIL, param4 is NEXT_TAIL (not prev_tail!)
    len_var = Var("LEN")
    library.add_lemma(
        "dll_to_ls_5arg",
        PredicateCall("dll", [x, y, z, w, len_var]),  # dll(head, prev_hd, tail, next_tail, len)
        PredicateCall("ls", [x, z, len_var]),  # ls(head, tail, length) - z is tail (param 3)
        "DLL (5-arg with length) is also a forward list segment"
    )

    # NOTE: 4-arg DLL has NO length parameter, only 5-arg does!
    # The 4th parameter in 4-arg DLL is next_of_tail (a pointer), not a length.
    # Therefore, we only provide length composition for 5-arg DLL.

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
    library.add_lemma(
        "dll_length_compose_5arg",
        SepConj(
            PredicateCall("dll", [h1, ph1, tail1, nt1, len1]),  # first: head1, prev(head1), tail1, next(tail1), len1
            PredicateCall("dll", [nt1, tail1, tail2, nt2, len2])   # second: head2, prev(head2), tail2, next(tail2), len2
        ),
        PredicateCall("dll", [h1, ph1, tail2, nt2, ArithExpr('+', len1, len2)]),  # result: head1, prev(head1), tail2, next(tail2), len1+len2
        "DLL composition (5-arg) with length parameters"
    )

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

    # dll + dllnull composition: dll(x,y,z,t,n) * dllnull(t,z,m) |- dllnull(x,y,m+n)
    # This composes a dll segment with a dllnull segment
    library.add_lemma(
        "dll_dllnull_compose",
        SepConj(
            PredicateCall("dll", [x, y, z, t, n1]),
            PredicateCall("dllnull", [t, z, n2])
        ),
        PredicateCall("dllnull", [x, y, ArithExpr('+', n2, n1)]),
        "DLL + dllnull composition: dll ending at t composed with dllnull starting at t"
    )

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

    # ldll single cell: E1 |-> (E2, E1_p) ⊢ ldll(E1, E1_p, 1, E2, E2_p, 0)
    # Base case: single cell forms ldll of length 1
    library.add_lemma(
        "ldll_single_cell",
        PointsTo(e1, [e2, e1_p]),
        PredicateCall("ldll", [e1, e1_p, Const(1), e2, e2_p, Const(0)]),
        "Single cell forms ldll of length 1"
    )

    # ldll single cell with arithmetic: E1 |-> (E2, E1_p) ⊢ ldll(E1, E1_p, len1, E2, E2_p, len2)
    # where len1 = len2 + 1 (constraint must be verified separately)
    # This is for patterns like: x1 = x2 + 1 & E1 |-> (E2, E1_p) ⊢ ldll(E1, E1_p, x1, E2, E2_p, x2)
    library.add_lemma(
        "ldll_single_cell_arith",
        PointsTo(e1, [e2, e1_p]),
        PredicateCall("ldll", [e1, e1_p, len1, e2, e2_p, len2]),
        "Single cell forms ldll with arithmetic lengths"
    )

    # ldll transitivity: ldll(E1, P1, len1, E2, P2, len2) * ldll(E2, P2, len2, E3, P3, len3)
    #                   ⊢ ldll(E1, P1, len1+len2, E3, P3, len3)
    # Note: Middle element must match exactly
    library.add_lemma(
        "ldll_transitivity",
        SepConj(
            PredicateCall("ldll", [e1, e1_p, len1, e2, e2_p, len2]),
            PredicateCall("ldll", [e2, e2_p, len2, e3, e3_p, len3])
        ),
        PredicateCall("ldll", [e1, e1_p, ArithExpr('+', len1, len2), e3, e3_p, len3]),
        "ldll transitivity: compose two ldll segments"
    )

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

    # ls_pre transitivity: ls_pre(x,y,n1) * ls_pre(y,z,n2) |- ls_pre(x,z,n1+n2)
    library.add_lemma(
        "lspre_transitivity",
        SepConj(
            PredicateCall("ls_pre", [x, y, n1]),
            PredicateCall("ls_pre", [y, z, n2])
        ),
        PredicateCall("ls_pre", [x, z, ArithExpr('+', n1, n2)]),
        "Backward list segment transitivity"
    )

    # lsrev transitivity: lsrev(x,y,n1) * lsrev(y,z,n2) |- lsrev(x,z,n1+n2)
    library.add_lemma(
        "lsrev_transitivity",
        SepConj(
            PredicateCall("lsrev", [x, y, n1]),
            PredicateCall("lsrev", [y, z, n2])
        ),
        PredicateCall("lsrev", [x, z, ArithExpr('+', n1, n2)]),
        "Reversed list segment transitivity"
    )

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

    # Three-way transitivity: ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)
    # This is safe because ls predicates already include distinct constraints
    library.add_lemma(
        "ls_transitivity_3",
        SepConj(
            SepConj(PredicateCall("ls", [x, y]), PredicateCall("ls", [y, z])),
            PredicateCall("ls", [z, w])
        ),
        PredicateCall("ls", [x, w]),
        "Three-way list segment transitivity"
    )

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

    # RList transitivity: RList(x,y) * RList(y,z) |- RList(x,z)
    # RList is a recursive list predicate with distinct nil constraints
    library.add_lemma(
        "rlist_transitivity",
        SepConj(
            PredicateCall("RList", [x, y]),
            PredicateCall("RList", [y, z])
        ),
        PredicateCall("RList", [x, z]),
        "RList transitivity: concatenating RList segments"
    )

    # ============================================
    # LIST LEMMAS (for SL-COMP "List" predicate)
    # ============================================

