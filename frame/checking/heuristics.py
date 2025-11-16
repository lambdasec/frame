"""
Heuristic Checks for Entailment

Provides fast sanity checks to quickly accept or reject entailments
before resorting to expensive Z3 encoding.
"""

from typing import Optional, Dict, List
from frame.core.ast import (
    Formula, Expr, Var, Const, Emp, PointsTo, SepConj, Wand, And, Or, Not,
    Eq, Neq, True_, False_, Exists, Forall, PredicateCall
)
from frame.analysis.formula import FormulaAnalyzer
from frame.checking._ls_heuristics import LSHeuristicsHelper


class HeuristicChecker:
    """Performs fast heuristic checks on entailments"""

    def __init__(self, verbose: bool = False, predicate_registry=None):
        self.verbose = verbose
        self.analyzer = FormulaAnalyzer()
        self._ls_helper = LSHeuristicsHelper(self.analyzer, verbose, predicate_registry)

    def sanity_check_entailment(self, antecedent: Formula, consequent: Formula) -> Optional[bool]:
        """
        Perform sanity checks to quickly reject obviously invalid entailments.

        Returns:
            True if obviously valid, False if obviously invalid, None if uncertain
        """
        # Check -3: Multi-segment composition and matching - DISABLED
        # This was causing false positives in benchmarks (-7 tests)
        # The frame rule and lemma library already handle these cases
        # TODO: Re-enable with more sophisticated verification
        # multi_segment_result = self._check_multi_segment_patterns(antecedent, consequent)
        # if multi_segment_result is not None:
        #     return multi_segment_result

        # Check -2: List segment transitivity
        transitivity_result = self._ls_helper.check_ls_transitivity(antecedent, consequent)
        if transitivity_result is not None:
            return transitivity_result

        # Check -1: Length-based heuristics for list segments
        length_result = self._ls_helper.check_length_reasoning(antecedent, consequent)
        if length_result is not None:
            return length_result

        # Check 0a: Detect opposite-direction list segments (circular patterns)
        if self._detect_opposite_list_segments(antecedent):
            if self.verbose:
                print("Detected opposite-direction list segments in antecedent (likely circular)")
            # Circular segments are unsatisfiable, making the entailment vacuously valid
            return True

        # Check 0: Simple cycle detection - only reject obvious small cycles
        ante_edges = self._extract_points_to_edges(antecedent)
        if len(ante_edges) <= 3 and self._has_cycle(ante_edges):
            # Only reject small cycles (2-3 nodes) with predicates in consequent
            if self.analyzer._has_predicates(consequent):
                if self.verbose:
                    print("Simple cycle detected in small antecedent")
                return False

        # Check 0b: Cell count heuristic
        ante_cells = self.analyzer._count_points_to(antecedent)
        ante_preds = self.analyzer._count_predicates(antecedent)
        cons_cells = self.analyzer._count_points_to(consequent)
        cons_preds = self.analyzer._count_predicates(consequent)

        if ante_cells > 0 and cons_cells == 0 and cons_preds > ante_cells + ante_preds + 2:
            # Too many predicates in consequent relative to heap size
            if self.verbose:
                print(f"Cell count mismatch: {ante_cells} concrete cells, but {cons_preds} predicates in consequent")
            return False

        # Check 1: emp does not entail non-emp spatial formulas
        if isinstance(antecedent, Emp):
            if isinstance(consequent, PointsTo):
                return False  # emp cannot create heap cells
            if isinstance(consequent, SepConj):
                if not self.analyzer._is_all_emp(consequent):
                    return False
            if isinstance(consequent, PredicateCall):
                if consequent.args and len(consequent.args) > 0:
                    first_arg = consequent.args[0]
                    # Check if it's nil
                    is_nil = False
                    if isinstance(first_arg, Var) and first_arg.name in ["nil", "null"]:
                        is_nil = True
                    elif isinstance(first_arg, Const) and str(first_arg) in ["nil", "null"]:
                        is_nil = True
                    if is_nil:
                        return None  # Let Z3/unfolding decide

                    # Check for ls(x,x,0) pattern (empty segment)
                    if consequent.name == "ls" and len(consequent.args) == 3:
                        x, y, n = consequent.args
                        if self.analyzer._expr_equal(x, y):
                            if isinstance(n, Const) and n.value == 0:
                                return None  # Let Z3/unfolding validate

                return False

        # Check 1b: Non-empty antecedent cannot entail emp
        if isinstance(consequent, Emp):
            if isinstance(antecedent, PointsTo):
                return False
            if isinstance(antecedent, PredicateCall):
                if antecedent.args and len(antecedent.args) > 0:
                    first_arg = antecedent.args[0]
                    is_nil = False
                    if isinstance(first_arg, Var) and first_arg.name in ["nil", "null"]:
                        is_nil = True
                    elif isinstance(first_arg, Const) and str(first_arg) in ["nil", "null"]:
                        is_nil = True
                    if is_nil:
                        return None
                return False
            if isinstance(antecedent, SepConj):
                parts = self.analyzer._extract_sepconj_parts(antecedent)
                for part in parts:
                    if isinstance(part, PointsTo):
                        return False
                    if isinstance(part, PredicateCall):
                        if part.args and len(part.args) > 0:
                            first_arg = part.args[0]
                            is_nil = False
                            if isinstance(first_arg, Var) and first_arg.name in ["nil", "null"]:
                                is_nil = True
                            elif isinstance(first_arg, Const) and str(first_arg) in ["nil", "null"]:
                                is_nil = True
                            if is_nil:
                                continue
                        return False

        # Check 2: Field count mismatch
        if isinstance(antecedent, PointsTo) and isinstance(consequent, PointsTo):
            if self.analyzer._expr_equal(antecedent.location, consequent.location):
                if len(antecedent.values) != len(consequent.values):
                    if len(antecedent.values) > len(consequent.values):
                        return False

        # Check 3: Points-to does not entail predicates
        if isinstance(antecedent, PointsTo) and isinstance(consequent, PredicateCall):
            # EXCEPTION: ls(x,y,1) can be entailed by x |-> y
            if consequent.name == "ls" and len(consequent.args) == 3:
                x, y, n = consequent.args
                if isinstance(n, Const) and n.value == 1:
                    if self.analyzer._expr_equal(antecedent.location, x):
                        if len(antecedent.values) == 1 and self.analyzer._expr_equal(antecedent.values[0], y):
                            return None
            # Let Z3 and folding decide - predicates like dll can be entailed from concrete heaps
            return None

        # Check 4: Different predicate arguments without unification
        if isinstance(antecedent, PredicateCall) and isinstance(consequent, PredicateCall):
            if antecedent.name == consequent.name:
                if len(antecedent.args) == len(consequent.args):
                    for a1, a2 in zip(antecedent.args, consequent.args):
                        if isinstance(a1, Var) and isinstance(a2, Var):
                            if a1.name != a2.name:
                                return False

        # Check 5: Points-to with different locations
        if isinstance(antecedent, PointsTo) and isinstance(consequent, PointsTo):
            if isinstance(antecedent.location, Var) and isinstance(consequent.location, Var):
                if antecedent.location.name != consequent.location.name:
                    return False

        return None  # Uncertain, need to use Z3

    def _extract_points_to_edges(self, formula: Formula) -> Dict[str, str]:
        """Extract points-to edges from a concrete formula (no predicates)"""
        edges = {}

        if isinstance(formula, PointsTo):
            if isinstance(formula.location, Var) and len(formula.values) == 1:
                if isinstance(formula.values[0], Var):
                    edges[formula.location.name] = formula.values[0].name
        elif isinstance(formula, SepConj):
            edges.update(self._extract_points_to_edges(formula.left))
            edges.update(self._extract_points_to_edges(formula.right))
        elif isinstance(formula, And):
            edges.update(self._extract_points_to_edges(formula.left))
            edges.update(self._extract_points_to_edges(formula.right))

        return edges

    def _has_cycle(self, edges: Dict[str, str]) -> bool:
        """Check if a points-to graph has cycles using DFS"""
        if not edges:
            return False

        visited = set()
        rec_stack = set()

        def dfs(node: str) -> bool:
            if node in rec_stack:
                return True  # Found a cycle
            if node in visited:
                return False

            visited.add(node)
            rec_stack.add(node)

            # Follow the edge if it exists
            if node in edges:
                next_node = edges[node]
                if dfs(next_node):
                    return True

            rec_stack.remove(node)
            return False

        # Check for cycles starting from each node
        for node in edges.keys():
            if node not in visited:
                if dfs(node):
                    return True

        return False

    def _detect_opposite_list_segments(self, formula: Formula) -> bool:
        """
        Detect if formula contains opposite-direction list segments like ls(x,y) * ls(y,x).
        This is a contradiction when x != y.
        """
        # Extract all list segment predicates
        segments = []

        def extract_ls(f: Formula):
            if isinstance(f, PredicateCall) and f.name == 'ls' and len(f.args) == 2:
                segments.append((f.args[0], f.args[1]))
            elif isinstance(f, (SepConj, And, Or)):
                extract_ls(f.left)
                extract_ls(f.right)
            elif isinstance(f, (Not, Exists, Forall)):
                extract_ls(f.formula)

        extract_ls(formula)

        # Check for opposite pairs
        for i, (x1, y1) in enumerate(segments):
            for j, (x2, y2) in enumerate(segments):
                if i < j:  # Avoid checking same pair twice
                    # Check if (x1,y1) and (x2,y2) are opposite directions
                    if self.analyzer._expr_equal(x1, y2) and self.analyzer._expr_equal(y1, x2):
                        # Only contradiction if they're definitely different
                        if not self.analyzer._expr_equal(x1, y1):
                            return True

        return False
