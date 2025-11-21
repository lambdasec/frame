"""
Skip list lemmas

Skip lists are probabilistic data structures with multiple levels of linked lists.
Each level is a subset of the level below, providing O(log n) search time.

Structure:
- Level 0: Complete list
- Level 1: Every ~2nd element
- Level 2: Every ~4th element
- etc.
"""

from frame.core.ast import *


def initialize_skip_list_lemmas(library):
    """Initialize skip list lemmas"""

    # Create meta-variables
    x = Var("X")
    y = Var("Y")
    z = Var("Z")
    w = Var("W")
    nil = Const(None)

    # ============================================
    # SKIPLIST1 (SINGLE-LEVEL SKIP LIST)
    # ============================================

    # SkipList1 is essentially a list segment with one level of skipping
    # skiplist1(x, y) * skiplist1(y, z) |- skiplist1(x, z)
    library.add_lemma(
        "skiplist1_transitivity",
        SepConj(
            PredicateCall("skiplist1", [x, y]),
            PredicateCall("skiplist1", [y, z])
        ),
        PredicateCall("skiplist1", [x, z]),
        "SkipList1 transitivity"
    )

    # skiplist1 cons: x |-> (next, skip) * skiplist1(next, y) |- skiplist1(x, y)
    next_ptr = Var("NEXT")
    skip_ptr = Var("SKIP")
    library.add_lemma(
        "skiplist1_cons",
        SepConj(
            PointsTo(x, [next_ptr, skip_ptr]),
            PredicateCall("skiplist1", [next_ptr, y])
        ),
        PredicateCall("skiplist1", [x, y]),
        "SkipList1 cons: node with next/skip pointers"
    )

    # skiplist1 to ls: skiplist1(x, y) |- ls(x, y)
    # Skip list level 0 is a regular list
    library.add_lemma(
        "skiplist1_to_ls",
        PredicateCall("skiplist1", [x, y]),
        PredicateCall("ls", [x, y]),
        "SkipList1 implies list segment (level 0)"
    )

    # ============================================
    # SKIPLIST2 (TWO-LEVEL SKIP LIST)
    # ============================================

    # skiplist2 transitivity
    library.add_lemma(
        "skiplist2_transitivity",
        SepConj(
            PredicateCall("skiplist2", [x, y]),
            PredicateCall("skiplist2", [y, z])
        ),
        PredicateCall("skiplist2", [x, z]),
        "SkipList2 transitivity"
    )

    # skiplist2 to skiplist1: skiplist2(x, y) |- skiplist1(x, y)
    # Level 2 skip list implies level 1
    library.add_lemma(
        "skiplist2_to_skiplist1",
        PredicateCall("skiplist2", [x, y]),
        PredicateCall("skiplist1", [x, y]),
        "SkipList2 implies SkipList1"
    )

    # skiplist2 to ls: skiplist2(x, y) |- ls(x, y)
    library.add_lemma(
        "skiplist2_to_ls",
        PredicateCall("skiplist2", [x, y]),
        PredicateCall("ls", [x, y]),
        "SkipList2 implies list segment"
    )

    # ============================================
    # SKIPLIST3 (THREE-LEVEL SKIP LIST)
    # ============================================

    # skiplist3 transitivity
    library.add_lemma(
        "skiplist3_transitivity",
        SepConj(
            PredicateCall("skiplist3", [x, y]),
            PredicateCall("skiplist3", [y, z])
        ),
        PredicateCall("skiplist3", [x, z]),
        "SkipList3 transitivity"
    )

    # skiplist3 to skiplist2: skiplist3(x, y) |- skiplist2(x, y)
    library.add_lemma(
        "skiplist3_to_skiplist2",
        PredicateCall("skiplist3", [x, y]),
        PredicateCall("skiplist2", [x, y]),
        "SkipList3 implies SkipList2"
    )

    # skiplist3 to ls: skiplist3(x, y) |- ls(x, y)
    library.add_lemma(
        "skiplist3_to_ls",
        PredicateCall("skiplist3", [x, y]),
        PredicateCall("ls", [x, y]),
        "SkipList3 implies list segment"
    )

    # ============================================
    # GENERIC SKIPLIST LEMMAS
    # ============================================

    # skiplist (generic) transitivity
    library.add_lemma(
        "skiplist_transitivity",
        SepConj(
            PredicateCall("skiplist", [x, y]),
            PredicateCall("skiplist", [y, z])
        ),
        PredicateCall("skiplist", [x, z]),
        "SkipList transitivity (generic)"
    )

    # skiplist to ls: skiplist(x, y) |- ls(x, y)
    library.add_lemma(
        "skiplist_to_ls",
        PredicateCall("skiplist", [x, y]),
        PredicateCall("ls", [x, y]),
        "SkipList implies list segment"
    )

    # ============================================
    # MULTI-LIST LEMMAS (for SL-COMP multilist benchmarks)
    # ============================================

    # mlist (multi-list) transitivity
    # mlist is a list with multiple next pointers
    library.add_lemma(
        "mlist_transitivity",
        SepConj(
            PredicateCall("mlist", [x, y]),
            PredicateCall("mlist", [y, z])
        ),
        PredicateCall("mlist", [x, z]),
        "Multi-list transitivity"
    )

    # mlist to ls: mlist(x, y) |- ls(x, y)
    # Multi-list implies at least one list path exists
    library.add_lemma(
        "mlist_to_ls",
        PredicateCall("mlist", [x, y]),
        PredicateCall("ls", [x, y]),
        "Multi-list implies list segment"
    )

    # ============================================
    # SPARSE LIST LEMMAS (lists with gaps/sentinel nodes)
    # ============================================

    # sparselist transitivity
    library.add_lemma(
        "sparselist_transitivity",
        SepConj(
            PredicateCall("sparselist", [x, y]),
            PredicateCall("sparselist", [y, z])
        ),
        PredicateCall("sparselist", [x, z]),
        "Sparse list transitivity"
    )

    # ============================================
    # CASE VARIANTS (uppercase/lowercase)
    # ============================================

    # SkipList (mixed case)
    library.add_lemma(
        "SkipList_transitivity",
        SepConj(
            PredicateCall("SkipList", [x, y]),
            PredicateCall("SkipList", [y, z])
        ),
        PredicateCall("SkipList", [x, z]),
        "SkipList transitivity (mixed case)"
    )

    # SKIPLIST (all uppercase)
    library.add_lemma(
        "SKIPLIST_transitivity",
        SepConj(
            PredicateCall("SKIPLIST", [x, y]),
            PredicateCall("SKIPLIST", [y, z])
        ),
        PredicateCall("SKIPLIST", [x, z]),
        "SKIPLIST transitivity (all uppercase)"
    )

    # ============================================
    # LEVEL-SPECIFIC SKIP PATTERNS
    # ============================================

    # Express skip patterns: x points to next at level 0, skip to y at level 1
    # x |-> (next, skip1) * ls(next, y) * ls(skip1, z) ...
    # These are too complex without proper multi-level encoding, defer

    # ============================================
    # SENTINEL-BASED SKIP LISTS
    # ============================================

    # Some skip list implementations use sentinel nodes
    # skiplist_sentinel(x, y, sentinel) where sentinel marks boundaries
    # Defer for now

    # ============================================
    # PRIORITY SKIP LISTS (with priorities/keys)
    # ============================================

    # pskiplist(x, y, min_key, max_key) - skip list with key bounds
    # Similar to sorted lists but with skip pointers
    # Defer for now
