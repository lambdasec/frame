"""
List Segment Heuristics

This module contains heuristics specific to list segment reasoning.
It's extracted from heuristics.py to keep that file manageable.
"""

from typing import Optional, List
from frame.core.ast import Formula, Expr, Var, Const, PredicateCall, Neq, SepConj, And, Or, Not, Exists, Forall, Emp


class LSHeuristicsHelper:
    """Helper class for list segment reasoning heuristics"""

    def __init__(self, analyzer, verbose: bool = False, predicate_registry=None):
        self.analyzer = analyzer
        self.verbose = verbose
        self.predicate_registry = predicate_registry
        self._validator = None

        # Initialize validator if we have a registry
        if predicate_registry:
            try:
                from frame.lemmas.validator import LemmaValidator
                self._validator = LemmaValidator(predicate_registry.predicates)
            except:
                # If validation fails, proceed without it
                pass

    def check_multi_segment_patterns(self, antecedent: Formula, consequent: Formula) -> Optional[bool]:
        """
        Check complex multi-segment patterns that require composition or rearrangement.

        DISABLED Nov 2025: This uses transitivity-like reasoning which is UNSOUND!

        Patterns that WERE handled (but are unsound due to aliasing):
        1. Multiple segments composing into one: ls(x,y) * ls(y,z) * ls(z,w) |- ls(x,w)
        2. Segment subsumption: ls(x,y) * ls(y,z) |- ls(x,y)
        3. Multiple consequent segments from one: ls(x,z) |- ls(x,y) * ls(y,z)

        All of these are invalid when aliasing is possible (e.g., x = w in pattern 1).
        """
        # DISABLED - uses transitivity-like reasoning which is unsound
        return None

    def is_pure_ls_conjunction(self, formula: Formula) -> bool:
        """
        Check if formula is purely a conjunction of ls predicates (no And, no other predicates).
        This ensures we only apply subsumption to simple spatial-only cases.
        """
        if isinstance(formula, PredicateCall):
            return formula.name == "ls"
        elif isinstance(formula, SepConj):
            return self.is_pure_ls_conjunction(formula.left) and self.is_pure_ls_conjunction(formula.right)
        elif isinstance(formula, Emp):
            return True  # emp is fine
        else:
            # Any And, Or, PointsTo, etc. means it's not purely ls predicates
            return False

    def can_build_chain(self, segments: List[PredicateCall], start: Expr, end: Expr) -> bool:
        """
        Check if we can build a chain from start to end using the given segments.
        This is a graph reachability problem.
        """
        if not segments:
            return False

        # Build adjacency map: node -> list of nodes it connects to
        edges = {}
        for seg in segments:
            if len(seg.args) >= 2:
                s, e = seg.args[0], seg.args[1]
                s_key = self.expr_to_key(s)
                e_key = self.expr_to_key(e)
                if s_key not in edges:
                    edges[s_key] = []
                edges[s_key].append(e_key)

        # BFS to check if we can reach 'end' from 'start'
        start_key = self.expr_to_key(start)
        end_key = self.expr_to_key(end)

        visited = set()
        queue = [start_key]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            if current == end_key:
                return True

            if current in edges:
                for next_node in edges[current]:
                    if next_node not in visited:
                        queue.append(next_node)

        return False

    def segments_subsume(self, ante_segs: List[PredicateCall], cons_segs: List[PredicateCall]) -> bool:
        """
        Check if ante_segs contains all segments in cons_segs (possibly more).
        This handles the pattern: P * Q * R |- P * Q
        """
        # For each consequent segment, find a matching antecedent segment
        for cons_seg in cons_segs:
            found_match = False
            for ante_seg in ante_segs:
                if self.segments_equal(cons_seg, ante_seg):
                    found_match = True
                    break
            if not found_match:
                return False

        # All consequent segments found in antecedent
        return True

    def segments_equal(self, seg1: PredicateCall, seg2: PredicateCall) -> bool:
        """Check if two list segment predicates are equal"""
        if seg1.name != seg2.name:
            return False
        if len(seg1.args) != len(seg2.args):
            return False
        for a1, a2 in zip(seg1.args, seg2.args):
            if not self.analyzer._expr_equal(a1, a2):
                return False
        return True

    def expr_to_key(self, expr: Expr):
        """Convert expression to hashable key for graph algorithms"""
        if isinstance(expr, Var):
            return ('var', expr.name)
        elif isinstance(expr, Const):
            return ('const', str(expr.value))
        else:
            return ('unknown', str(expr))

    def check_ls_transitivity(self, antecedent: Formula, consequent: Formula) -> Optional[bool]:
        """
        Check list segment transitivity: ls(x,y) * ls(y,z) |- ls(x,z)

        DISABLED Nov 2025: This heuristic is UNSOUND!

        The transitivity lemma ls(x,y) * ls(y,z) |- ls(x,z) is NOT sound in
        separation logic because when x = z (aliasing):
        - Antecedent ls(x,y) * ls(y,x) can have heap cells (if y != x)
        - Consequent ls(x,x) = emp (base case)
        A non-empty heap cannot entail an empty heap.

        The comment "SOUND under acyclic heap assumptions" was incorrect.
        Acyclicity prevents the heap from having cycles, but it doesn't prevent
        the variables x and z from aliasing.

        This heuristic should NEVER be used. Return None unconditionally.
        """
        # DISABLED - transitivity is unsound
        return None

    def check_length_reasoning(self, antecedent: Formula, consequent: Formula) -> Optional[bool]:
        """
        Check length-based reasoning for list segments:
        1. ls(x,y,n) & n > 0 |- x != y (non-empty segment implies distinct endpoints)
        2. ls(x,y,n) |- ls(x,y,m) where n >= m (affine semantics/length subsumption)
        """
        # Check pattern 1: ls(x,y,n) & n > 0 |- x != y
        if isinstance(consequent, Neq):
            # Extract ls predicates from antecedent
            ls_preds = self.extract_ls_predicates(antecedent)
            for ls_pred in ls_preds:
                if len(ls_pred.args) == 3:  # Length-parameterized ls
                    x, y, n = ls_pred.args
                    # Check if consequent is x != y
                    if (self.analyzer._expr_equal(consequent.left, x) and
                        self.analyzer._expr_equal(consequent.right, y)):
                        # Check if length n > 0
                        if isinstance(n, Const) and n.value is not None:
                            if isinstance(n.value, int) and n.value > 0:
                                if self.verbose:
                                    print(f"Length reasoning: ls with length {n.value} > 0 implies x != y")
                                return True
                        # Check for explicit n > 0 constraint in antecedent
                        if self.has_positive_constraint(antecedent, n):
                            if self.verbose:
                                print("Length reasoning: n > 0 constraint implies x != y")
                            return True

        # Check pattern 2: ls(x,y,n) |- ls(x,y,m) where n >= m (affine semantics)
        if isinstance(consequent, PredicateCall) and consequent.name == "ls":
            if len(consequent.args) == 3:  # Length-parameterized consequent
                cons_x, cons_y, cons_n = consequent.args

                # Extract ls predicates from antecedent
                ls_preds = self.extract_ls_predicates(antecedent)
                for ls_pred in ls_preds:
                    if len(ls_pred.args) == 3:  # Length-parameterized antecedent
                        ante_x, ante_y, ante_n = ls_pred.args

                        # Check if endpoints match
                        if (self.analyzer._expr_equal(ante_x, cons_x) and
                            self.analyzer._expr_equal(ante_y, cons_y)):

                            # Check if ante_n >= cons_n
                            if isinstance(ante_n, Const) and isinstance(cons_n, Const):
                                if (ante_n.value is not None and cons_n.value is not None and
                                    isinstance(ante_n.value, int) and isinstance(cons_n.value, int)):
                                    if ante_n.value >= cons_n.value:
                                        if self.verbose:
                                            print(f"Affine semantics: ls({ante_n.value}) entails ls({cons_n.value})")
                                        return True

        return None

    def extract_ls_predicates(self, formula: Formula) -> List[PredicateCall]:
        """Extract all ls predicates from a formula"""
        ls_preds = []

        def extract(f: Formula):
            if isinstance(f, PredicateCall) and f.name == "ls":
                ls_preds.append(f)
            elif isinstance(f, (SepConj, And, Or)):
                extract(f.left)
                extract(f.right)
            elif isinstance(f, (Not, Exists, Forall)):
                if hasattr(f, 'formula'):
                    extract(f.formula)
                elif hasattr(f, 'body'):
                    extract(f.body)

        extract(formula)
        return ls_preds

    def has_positive_constraint(self, formula: Formula, var: Expr) -> bool:
        """Check if formula contains a constraint that var > 0"""
        from frame.core.ast import Gt, Ge

        def check(f: Formula) -> bool:
            if isinstance(f, (Gt, Ge)):
                # Check for var > 0 or var >= 1
                if self.analyzer._expr_equal(f.left, var):
                    if isinstance(f.right, Const):
                        if isinstance(f, Gt) and f.right.value == 0:
                            return True
                        if isinstance(f, Ge) and f.right.value == 1:
                            return True
                # Check for 0 < var
                if isinstance(f.left, Const) and f.left.value == 0:
                    if isinstance(f, Gt) and self.analyzer._expr_equal(f.right, var):
                        return True
            elif isinstance(f, (And, Or, SepConj)):
                return check(f.left) or check(f.right)
            elif isinstance(f, (Exists, Forall)):
                if hasattr(f, 'formula'):
                    return check(f.formula)
                elif hasattr(f, 'body'):
                    return check(f.body)

            return False

        return check(formula)
