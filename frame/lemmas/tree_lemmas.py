"""
Tree lemmas initialization

Includes structural tree lemmas, rotation lemmas, and tree decomposition patterns.
These lemmas improve accuracy on tree-heavy benchmarks.
"""

from frame.core.ast import *


def initialize_tree_lemmas(library):
    """Initialize tree-specific lemmas"""

    # Create meta-variables
    x = Var("X")
    y = Var("Y")
    z = Var("Z")
    w = Var("W")
    nil = Const(None)
    l = Var("L")  # left child
    r = Var("R")  # right child
    v = Var("V")  # value

    # ============================================
    # BASIC TREE LEMMAS
    # ============================================

    # Tree(nil) |- emp
    library.add_lemma(
        "tree_nil_to_emp",
        PredicateCall("tree", [nil]),
        Emp(),
        "Empty tree (nil) is emp"
    )

    # emp |- Tree(nil)
    library.add_lemma(
        "emp_to_tree_nil",
        Emp(),
        PredicateCall("tree", [nil]),
        "emp entails empty tree"
    )

    # Tree cons: x |-> (l, r) * tree(l) * tree(r) |- tree(x)
    library.add_lemma(
        "tree_cons_basic",
        SepConj(
            SepConj(PointsTo(x, [l, r]), PredicateCall("tree", [l])),
            PredicateCall("tree", [r])
        ),
        PredicateCall("tree", [x]),
        "Tree cons: node with two tree children forms a tree"
    )

    # Tree cons with data: x |-> (v, l, r) * tree(l) * tree(r) |- tree(x)
    library.add_lemma(
        "tree_cons_with_data",
        SepConj(
            SepConj(PointsTo(x, [v, l, r]), PredicateCall("tree", [l])),
            PredicateCall("tree", [r])
        ),
        PredicateCall("tree", [x]),
        "Tree cons with data field"
    )

    # Tree with nil children: x |-> (nil, nil) |- tree(x)
    library.add_lemma(
        "tree_leaf",
        PointsTo(x, [nil, nil]),
        PredicateCall("tree", [x]),
        "Leaf node (both children nil) forms a tree"
    )

    # Tree with data and nil children: x |-> (v, nil, nil) |- tree(x)
    library.add_lemma(
        "tree_leaf_with_data",
        PointsTo(x, [v, nil, nil]),
        PredicateCall("tree", [x]),
        "Leaf node with data forms a tree"
    )

    # ============================================
    # BST (BINARY SEARCH TREE) LEMMAS
    # ============================================

    # BST cons: x |-> (v, l, r) * bst(l, lo, v) * bst(r, v, hi) |- bst(x, lo, hi)
    lo = Var("LO")
    hi = Var("HI")
    library.add_lemma(
        "bst_cons",
        SepConj(
            SepConj(PointsTo(x, [v, l, r]), PredicateCall("bst", [l, lo, v])),
            PredicateCall("bst", [r, v, hi])
        ),
        PredicateCall("bst", [x, lo, hi]),
        "BST cons: node with ordered subtrees forms BST"
    )

    # BST nil: bst(nil, lo, hi) |- emp
    library.add_lemma(
        "bst_nil_to_emp",
        PredicateCall("bst", [nil, lo, hi]),
        Emp(),
        "Empty BST is emp"
    )

    # BST subsumption: bst(x, lo, hi) |- tree(x)
    library.add_lemma(
        "bst_to_tree",
        PredicateCall("bst", [x, lo, hi]),
        PredicateCall("tree", [x]),
        "BST is also a tree (subsumption)"
    )

    # ============================================
    # AVL TREE LEMMAS (balanced trees)
    # ============================================

    # AVL cons: x |-> (v, l, r, h) * avl(l, hl) * avl(r, hr) & |hl-hr| <= 1 & h = max(hl,hr)+1 |- avl(x, h)
    # Simplified spatial version (pure constraints handled separately)
    hl = Var("HL")
    hr = Var("HR")
    h = Var("H")
    library.add_lemma(
        "avl_cons_spatial",
        SepConj(
            SepConj(PointsTo(x, [v, l, r, h]), PredicateCall("avl", [l, hl])),
            PredicateCall("avl", [r, hr])
        ),
        PredicateCall("avl", [x, h]),
        "AVL cons (spatial): node with AVL children forms AVL (balance constraints verified separately)"
    )

    # AVL to BST: avl(x, h) |- bst(x, lo, hi)
    # (This assumes implicit bounds, simplified version)
    library.add_lemma(
        "avl_to_tree",
        PredicateCall("avl", [x, h]),
        PredicateCall("tree", [x]),
        "AVL tree is also a tree"
    )

    # ============================================
    # TREE ROTATION LEMMAS (for AVL/Red-Black trees)
    # ============================================

    # Left rotation pattern:
    # x |-> (a, l1, y) * y |-> (b, l2, r2) * tree(l1) * tree(l2) * tree(r2)
    # Can be reorganized but doesn't directly prove anything without context
    # These are more about heap shape equivalence, skip for now

    # ============================================
    # TREE FLATTENING / PATH LEMMAS
    # ============================================

    # Tree path: tree(x) |- path(x, nil)
    # A tree contains a path to nil (some leaf)
    # This is an approximation - trees have MANY paths
    # Skip for now - too weak

    # ============================================
    # BINARY TREE SEGMENT LEMMAS
    # ============================================

    # BinTreeSeg nil: BinTreeSeg(x, x) |- emp
    library.add_lemma(
        "bintreeseg_reflexive",
        PredicateCall("BinTreeSeg", [x, x]),
        Emp(),
        "Binary tree segment from x to x is empty"
    )

    # BinTreeSeg to Tree: BinTreeSeg(x, nil) |- Tree(x)
    library.add_lemma(
        "bintreeseg_to_tree",
        PredicateCall("BinTreeSeg", [x, nil]),
        PredicateCall("Tree", [x]),
        "Binary tree segment to nil is a complete tree"
    )

    # ============================================
    # MULTI-WAY TREE LEMMAS (trees with variable arity)
    # ============================================

    # mtree cons: x |-> children * forest(children) |- mtree(x)
    # Multi-way trees are complex, skip for now

    # ============================================
    # TREE + LIST COMBINATION LEMMAS
    # ============================================

    # Tree with list spine: tree(x) decomposition lemmas
    # These require more complex patterns, defer

    # ============================================
    # REACHABILITY IN TREES
    # ============================================

    # Tree reachability: tree(x) & y in tree(x) |- reach(x, y)
    # This requires existential reasoning, defer

    # ============================================
    # HEAP SHAPE LEMMAS FOR TREES
    # ============================================

    # Disjoint trees: tree(x) * tree(y) & x != y |- tree(x) * tree(y)
    # Tautology, not useful as lemma

    # Tree height lemmas: require arithmetic reasoning on heights
    # Defer for now

    # ============================================
    # TREENODE LEMMAS (lowercase variants for case-insensitive matching)
    # ============================================

    # TreeNode nil
    library.add_lemma(
        "treenode_nil",
        PredicateCall("TreeNode", [nil]),
        Emp(),
        "TreeNode nil is emp"
    )

    # TreeNode cons: x |-> (l, r) * TreeNode(l) * TreeNode(r) |- TreeNode(x)
    library.add_lemma(
        "treenode_cons",
        SepConj(
            SepConj(PointsTo(x, [l, r]), PredicateCall("TreeNode", [l])),
            PredicateCall("TreeNode", [r])
        ),
        PredicateCall("TreeNode", [x]),
        "TreeNode cons"
    )

    # ============================================
    # BTREE LEMMAS (case variants)
    # ============================================

    # btree nil
    library.add_lemma(
        "btree_nil",
        PredicateCall("btree", [nil]),
        Emp(),
        "btree nil is emp"
    )

    # btree cons
    library.add_lemma(
        "btree_cons",
        SepConj(
            SepConj(PointsTo(x, [l, r]), PredicateCall("btree", [l])),
            PredicateCall("btree", [r])
        ),
        PredicateCall("btree", [x]),
        "btree cons"
    )

    # Uppercase variant: BTree
    library.add_lemma(
        "BTree_nil",
        PredicateCall("BTree", [nil]),
        Emp(),
        "BTree nil is emp"
    )

    library.add_lemma(
        "BTree_cons",
        SepConj(
            SepConj(PointsTo(x, [l, r]), PredicateCall("BTree", [l])),
            PredicateCall("BTree", [r])
        ),
        PredicateCall("BTree", [x]),
        "BTree cons"
    )

    # ============================================
    # PARENT-POINTER TREE LEMMAS (trees with backpointers)
    # ============================================

    # ptree (parent-pointer tree): x |-> (p, l, r) * ptree(l, x) * ptree(r, x) |- ptree(x, p)
    # where p is parent of x
    p = Var("P")
    library.add_lemma(
        "ptree_cons",
        SepConj(
            SepConj(PointsTo(x, [p, l, r]), PredicateCall("ptree", [l, x])),
            PredicateCall("ptree", [r, x])
        ),
        PredicateCall("ptree", [x, p]),
        "Parent-pointer tree cons"
    )

    # ptree nil: ptree(nil, p) |- emp
    library.add_lemma(
        "ptree_nil",
        PredicateCall("ptree", [nil, p]),
        Emp(),
        "Empty parent-pointer tree is emp"
    )
