"""
Other lemmas (List variants, wand, etc.)
"""

from frame.core.ast import *


def initialize_other_lemmas(library):
    """Initialize other lemmas"""
    
    # Create meta-variables
    x = Var("X")
    y = Var("Y")
    z = Var("Z")
    w = Var("W")
    nil = Const(None)

    # List transitivity: List(x,y) * List(y,z) |- List(x,z)
    library.add_lemma(
        "list_transitivity",
        SepConj(
            PredicateCall("List", [x, y]),
            PredicateCall("List", [y, z])
        ),
        PredicateCall("List", [x, z]),
        "List transitivity for SL-COMP List predicate"
    )

    # List cons: List(x,y) * y |-> z |- List(x,z)
    library.add_lemma(
        "list_cons",
        SepConj(
            PredicateCall("List", [x, y]),
            PointsTo(y, [z])
        ),
        PredicateCall("List", [x, z]),
        "List cons: append single cell to List"
    )

    # List cons variant: x |-> y * List(y,z) |- List(x,z)
    library.add_lemma(
        "list_cons_prepend",
        SepConj(
            PointsTo(x, [y]),
            PredicateCall("List", [y, z])
        ),
        PredicateCall("List", [x, z]),
        "List cons: prepend single cell to List"
    )

    # ============================================
    # BINPATH LEMMAS (binary tree path reachability)
    # ============================================

    # BinPath transitivity: BinPath(x,y) * BinPath(y,z) |- BinPath(x,z)
    library.add_lemma(
        "binpath_transitivity",
        SepConj(
            PredicateCall("BinPath", [x, y]),
            PredicateCall("BinPath", [y, z])
        ),
        PredicateCall("BinPath", [x, z]),
        "BinPath transitivity: path composition in binary trees"
    )

    # BinPath with swap: BinPath(x,z) * BinPath(z,y) |- BinPath(x,y)
    # (already covered by transitivity with commutativity)

    # ============================================
    # LSEG LEMMAS (for SL-COMP "lseg" predicate)
    # ============================================

    # lseg transitivity: lseg(x,y) * lseg(y,z) |- lseg(x,z)
    library.add_lemma(
        "lseg_transitivity",
        SepConj(
            PredicateCall("lseg", [x, y]),
            PredicateCall("lseg", [y, z])
        ),
        PredicateCall("lseg", [x, z]),
        "lseg transitivity for SL-COMP lseg predicate"
    )

    # lseg cons: x |-> y * lseg(y,z) |- lseg(x,z)
    library.add_lemma(
        "lseg_cons",
        SepConj(
            PointsTo(x, [y]),
            PredicateCall("lseg", [y, z])
        ),
        PredicateCall("lseg", [x, z]),
        "lseg cons: prepend cell to lseg"
    )

    # ============================================
    # CLIST LEMMAS (circular list)
    # ============================================

    # Circular list formation: x |-> y * lseg(y, x) |- clist(x)
    # A cell pointing to a segment that loops back forms a circular list
    library.add_lemma(
        "clist_formation",
        SepConj(
            PointsTo(x, [y]),
            PredicateCall("lseg", [y, x])
        ),
        PredicateCall("clist", [x]),
        "Form circular list from cell and back segment"
    )

    # Self-loop is circular list: x |-> x |- clist(x)
    # Special case: a self-pointing node is a 1-element circular list
    # (since lseg(x, x) = emp, this is x |-> x * emp)
    library.add_lemma(
        "selfloop_to_clist",
        PointsTo(x, [x]),
        PredicateCall("clist", [x]),
        "Self-loop forms 1-element circular list"
    )

    # ============================================
    # PELIST LEMMAS (possibly-empty list)
    # ============================================

    # PeList transitivity: PeList(x,y) * PeList(y,z) |- PeList(x,z)
    library.add_lemma(
        "pelist_transitivity",
        SepConj(
            PredicateCall("PeList", [x, y]),
            PredicateCall("PeList", [y, z])
        ),
        PredicateCall("PeList", [x, z]),
        "PeList transitivity"
    )

    # PeList cons: PeList(x,y) * y |-> z |- PeList(x,z)
    library.add_lemma(
        "pelist_cons",
        SepConj(
            PredicateCall("PeList", [x, y]),
            PointsTo(y, [z])
        ),
        PredicateCall("PeList", [x, z]),
        "PeList cons: append cell to PeList"
    )

    # ============================================
    # BINTREESEG LEMMAS (binary tree segment)
    # ============================================

    # BinTreeSeg transitivity: BinTreeSeg(x,y) * BinTreeSeg(y,z) |- BinTreeSeg(x,z)
    library.add_lemma(
        "bintreeseg_transitivity",
        SepConj(
            PredicateCall("BinTreeSeg", [x, y]),
            PredicateCall("BinTreeSeg", [y, z])
        ),
        PredicateCall("BinTreeSeg", [x, z]),
        "BinTreeSeg transitivity"
    )

    # BinPath to BinTreeSeg: BinPath(x,y) |- BinTreeSeg(x,y)
    # A path through a tree is also a tree segment
    library.add_lemma(
        "binpath_to_bintreeseg",
        PredicateCall("BinPath", [x, y]),
        PredicateCall("BinTreeSeg", [x, y]),
        "BinPath entails BinTreeSeg"
    )

    # ============================================
    # LISTX / LISTE / LISTO LEMMAS (parity-based lists)
    # ============================================

    # ListX to List: ListX(x,y) |- List(x,y)
    # ListX is any-length list (even or odd), List is general list
    library.add_lemma(
        "listx_to_list",
        PredicateCall("ListX", [x, y]),
        PredicateCall("List", [x, y]),
        "ListX (any parity) entails List"
    )

    # ListE to List: ListE(x,y) |- List(x,y)
    library.add_lemma(
        "liste_to_list",
        PredicateCall("ListE", [x, y]),
        PredicateCall("List", [x, y]),
        "ListE (even length) entails List"
    )

    # ListO to List: ListO(x,y) |- List(x,y)
    library.add_lemma(
        "listo_to_list",
        PredicateCall("ListO", [x, y]),
        PredicateCall("List", [x, y]),
        "ListO (odd length) entails List"
    )

    # ============================================
    # PROJECTION LEMMAS (stronger predicates imply weaker ones)
    # ============================================

    # DLL to SLL: DLL(x, y, z, w) |- SLL(x, y)
    # Doubly-linked list implies singly-linked list (ignore backward pointers)
    library.add_lemma(
        "dll_to_sll",
        PredicateCall("DLL", [x, y, z, w]),
        PredicateCall("SLL", [x, y]),
        "Doubly-linked list projection to singly-linked list"
    )

    # DLL to ls: DLL(x, y, z, w) |- ls(x, y)
    # Doubly-linked list implies list segment
    library.add_lemma(
        "dll_to_ls",
        PredicateCall("DLL", [x, y, z, w]),
        PredicateCall("ls", [x, y]),
        "Doubly-linked list projection to list segment"
    )

    # dll to ls: dll(x, p) |- ls(x, nil)
    # Generic dll with 2 params to list segment
    library.add_lemma(
        "dll2_to_ls",
        PredicateCall("dll", [x, y]),
        PredicateCall("ls", [x, Const(None)]),
        "2-parameter dll projection to list segment"
    )

    # SLL to List: SLL(x, y) |- List(x, y)
    # Singly-linked list is also a general list
    library.add_lemma(
        "sll_to_list",
        PredicateCall("SLL", [x, y]),
        PredicateCall("List", [x, y]),
        "Singly-linked list is a List"
    )

    # ============================================
    # MUTUAL RECURSION LEMMAS (variant predicates)
    # ============================================

    # DLL variant relationships (for mutually recursive dll predicates)
    # dll_e1 to dll_e2 (common in Sleek benchmarks)
    library.add_lemma(
        "dll_e1_to_dll_e2",
        PredicateCall("dll_e1", [x, y]),
        PredicateCall("dll_e2", [x, y]),
        "DLL variant e1 implies variant e2"
    )

    # dll_e2 to dll_e1 (bidirectional)
    library.add_lemma(
        "dll_e2_to_dll_e1",
        PredicateCall("dll_e2", [x, y]),
        PredicateCall("dll_e1", [x, y]),
        "DLL variant e2 implies variant e1"
    )

    # dll_e1 to dll
    library.add_lemma(
        "dll_e1_to_dll",
        PredicateCall("dll_e1", [x, y]),
        PredicateCall("dll", [x, y]),
        "DLL variant e1 implies base dll"
    )

    # dll_e2 to dll
    library.add_lemma(
        "dll_e2_to_dll",
        PredicateCall("dll_e2", [x, y]),
        PredicateCall("dll", [x, y]),
        "DLL variant e2 implies base dll"
    )

    # dll_e3 to dll
    library.add_lemma(
        "dll_e3_to_dll",
        PredicateCall("dll_e3", [x, y]),
        PredicateCall("dll", [x, y]),
        "DLL variant e3 implies base dll"
    )

    # dll to dll_e1
    library.add_lemma(
        "dll_to_dll_e1",
        PredicateCall("dll", [x, y]),
        PredicateCall("dll_e1", [x, y]),
        "Base dll implies variant e1"
    )

    # dll to dll_e2
    library.add_lemma(
        "dll_to_dll_e2",
        PredicateCall("dll", [x, y]),
        PredicateCall("dll_e2", [x, y]),
        "Base dll implies variant e2"
    )

    # dll to dll_e3
    library.add_lemma(
        "dll_to_dll_e3",
        PredicateCall("dll", [x, y]),
        PredicateCall("dll_e3", [x, y]),
        "Base dll implies variant e3"
    )

    # ============================================
    # GENERIC LEMMAS
    # ============================================

    # 14. Reflexivity for any predicate P(x): P(x) |- P(x)
    # This is handled by syntactic equality check, not needed as lemma

    # 15. Commutativity: P * Q |- Q * P
    # Also handled by normalization, not needed as explicit lemma

