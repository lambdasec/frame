"""
Graph and reachability lemmas

Includes path composition, reachability transitivity, and graph structure lemmas.
These handle benchmarks with general graph structures beyond lists and trees.
"""

from frame.core.ast import *


def initialize_graph_lemmas(library):
    """Initialize graph and reachability lemmas"""

    # Create meta-variables
    x = Var("X")
    y = Var("Y")
    z = Var("Z")
    w = Var("W")
    nil = Const(None)

    # ============================================
    # PATH COMPOSITION LEMMAS
    # ============================================

    # Path transitivity: path(x, y) * path(y, z) |- path(x, z)
    library.add_lemma(
        "path_transitivity",
        SepConj(
            PredicateCall("path", [x, y]),
            PredicateCall("path", [y, z])
        ),
        PredicateCall("path", [x, z]),
        "Path transitivity: paths compose"
    )

    # Path reflexivity: emp |- path(x, x)
    library.add_lemma(
        "path_reflexive",
        Emp(),
        PredicateCall("path", [x, x]),
        "Reflexive path: empty path from x to itself"
    )

    # Path empty: path(x, x) |- emp
    library.add_lemma(
        "path_empty",
        PredicateCall("path", [x, x]),
        Emp(),
        "Path from x to itself is empty"
    )

    # Single edge is path: x |-> y |- path(x, y)
    library.add_lemma(
        "edge_to_path",
        PointsTo(x, [y]),
        PredicateCall("path", [x, y]),
        "Single edge forms a path"
    )

    # Path cons: x |-> y * path(y, z) |- path(x, z)
    library.add_lemma(
        "path_cons",
        SepConj(PointsTo(x, [y]), PredicateCall("path", [y, z])),
        PredicateCall("path", [x, z]),
        "Path cons: edge followed by path"
    )

    # ============================================
    # REACHABILITY LEMMAS
    # ============================================

    # Reach transitivity: reach(x, y) * reach(y, z) |- reach(x, z)
    library.add_lemma(
        "reach_transitivity",
        SepConj(
            PredicateCall("reach", [x, y]),
            PredicateCall("reach", [y, z])
        ),
        PredicateCall("reach", [x, z]),
        "Reachability is transitive"
    )

    # Reach reflexive: emp |- reach(x, x)
    library.add_lemma(
        "reach_reflexive",
        Emp(),
        PredicateCall("reach", [x, x]),
        "Reflexive reachability"
    )

    # Edge implies reachability: x |-> y |- reach(x, y)
    library.add_lemma(
        "edge_to_reach",
        PointsTo(x, [y]),
        PredicateCall("reach", [x, y]),
        "Edge implies reachability"
    )

    # Path implies reachability: path(x, y) |- reach(x, y)
    library.add_lemma(
        "path_to_reach",
        PredicateCall("path", [x, y]),
        PredicateCall("reach", [x, y]),
        "Path implies reachability"
    )

    # ============================================
    # DISJOINT PATHS
    # ============================================

    # Two disjoint paths remain separate (identity lemma)
    # path(x, y) * path(z, w) |- path(x, y) * path(z, w)
    # This is tautological but useful for normalization
    library.add_lemma(
        "disjoint_paths_identity",
        SepConj(PredicateCall("path", [x, y]), PredicateCall("path", [z, w])),
        SepConj(PredicateCall("path", [x, y]), PredicateCall("path", [z, w])),
        "Disjoint paths remain separate"
    )

    # ============================================
    # GRAPH SEGMENTS
    # ============================================

    # GraphSeg transitivity: GraphSeg(x, y) * GraphSeg(y, z) |- GraphSeg(x, z)
    library.add_lemma(
        "graphseg_transitivity",
        SepConj(
            PredicateCall("GraphSeg", [x, y]),
            PredicateCall("GraphSeg", [y, z])
        ),
        PredicateCall("GraphSeg", [x, z]),
        "Graph segment transitivity"
    )

    # GraphSeg empty: GraphSeg(x, x) |- emp
    library.add_lemma(
        "graphseg_empty",
        PredicateCall("GraphSeg", [x, x]),
        Emp(),
        "Empty graph segment"
    )

    # ============================================
    # DAG (DIRECTED ACYCLIC GRAPH) LEMMAS
    # ============================================

    # DAG path composition: dag_path(x, y) * dag_path(y, z) |- dag_path(x, z)
    library.add_lemma(
        "dag_path_transitivity",
        SepConj(
            PredicateCall("dag_path", [x, y]),
            PredicateCall("dag_path", [y, z])
        ),
        PredicateCall("dag_path", [x, z]),
        "DAG path transitivity"
    )

    # DAG node: dag(x) implies existence of paths
    # Too abstract, skip for now

    # ============================================
    # CYCLE DETECTION LEMMAS
    # ============================================

    # Cyclic path: path(x, y) * path(y, x) with x != y would be a cycle
    # In acyclic heaps, this should be UNSAT
    # These lemmas detect contradictions

    # Anti-cycle: path(x, y) * path(y, x) |- x = y & emp
    # In acyclic heaps, bidirectional paths collapse to a point
    library.add_lemma(
        "path_antisymmetry",
        SepConj(PredicateCall("path", [x, y]), PredicateCall("path", [y, x])),
        And(Emp(), Eq(x, y)),
        "Path antisymmetry: bidirectional paths collapse in acyclic heaps"
    )

    # ============================================
    # MULTI-EDGE LEMMAS (edges with multiple successors)
    # ============================================

    # Node with two outgoing edges
    # x |-> (y, z) means x points to both y and z (tuple representation)
    # This doesn't directly form a path unless we specify which successor

    # ============================================
    # BINPATH (BINARY TREE PATH) LEMMAS
    # ============================================

    # BinPath four-step transitivity
    library.add_lemma(
        "binpath_four_step",
        SepConj(
            SepConj(
                SepConj(
                    PredicateCall("BinPath", [x, y]),
                    PredicateCall("BinPath", [y, z])
                ),
                PredicateCall("BinPath", [z, w])
            ),
            PredicateCall("BinPath", [w, Var("V")])
        ),
        PredicateCall("BinPath", [x, Var("V")]),
        "BinPath four-step transitivity"
    )

    # BinPath reflexive: BinPath(x, x) |- emp
    library.add_lemma(
        "binpath_reflexive",
        PredicateCall("BinPath", [x, x]),
        Emp(),
        "BinPath reflexive"
    )

    # ============================================
    # SPATIAL REACHABILITY (heap-bounded reachability)
    # ============================================

    # sreach (spatial reachability) with heap bounds
    # sreach(x, y, H) means x reaches y within heap H
    # These require more complex encoding, defer

    # ============================================
    # CONNECTIVITY LEMMAS
    # ============================================

    # connected(x, y) means there exists a path from x to y
    # Similar to reach but may have different semantics in benchmarks

    # Connected transitivity: connected(x, y) * connected(y, z) |- connected(x, z)
    library.add_lemma(
        "connected_transitivity",
        SepConj(
            PredicateCall("connected", [x, y]),
            PredicateCall("connected", [y, z])
        ),
        PredicateCall("connected", [x, z]),
        "Connectivity is transitive"
    )

    # Connected symmetric: connected(x, y) |- connected(y, x)
    # This is only true for undirected graphs, skip for now

    # ============================================
    # CASE-INSENSITIVE VARIANTS
    # ============================================

    # PATH (uppercase)
    library.add_lemma(
        "PATH_transitivity",
        SepConj(
            PredicateCall("PATH", [x, y]),
            PredicateCall("PATH", [y, z])
        ),
        PredicateCall("PATH", [x, z]),
        "PATH transitivity (uppercase variant)"
    )

    # REACH (uppercase)
    library.add_lemma(
        "REACH_transitivity",
        SepConj(
            PredicateCall("REACH", [x, y]),
            PredicateCall("REACH", [y, z])
        ),
        PredicateCall("REACH", [x, z]),
        "REACH transitivity (uppercase variant)"
    )

    # ============================================
    # WEAKENING LEMMAS (subgraph relationships)
    # ============================================

    # List segment is a path: ls(x, y) |- path(x, y)
    library.add_lemma(
        "ls_to_path",
        PredicateCall("ls", [x, y]),
        PredicateCall("path", [x, y]),
        "List segment is a path"
    )

    # Tree contains paths: tree(x) & y in tree(x) |- path(x, y)
    # Requires existential, defer

    # ============================================
    # MULTI-STEP COMPOSITION (for complex benchmarks)
    # ============================================

    # Five-step path: path(x,a) * path(a,b) * path(b,c) * path(c,d) * path(d,e) |- path(x,e)
    a = Var("A")
    b = Var("B")
    c = Var("C")
    d = Var("D")
    e = Var("E")
    library.add_lemma(
        "path_five_step",
        SepConj(
            SepConj(
                SepConj(
                    SepConj(
                        PredicateCall("path", [x, a]),
                        PredicateCall("path", [a, b])
                    ),
                    PredicateCall("path", [b, c])
                ),
                PredicateCall("path", [c, d])
            ),
            PredicateCall("path", [d, e])
        ),
        PredicateCall("path", [x, e]),
        "Five-step path composition"
    )
