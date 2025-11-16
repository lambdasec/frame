"""
Tests for Predicate Pattern Matching (frame/analysis/predicate_matching.py)

Tests the pattern matching functions that prove entailments without unfolding.
"""

import pytest
from frame.analysis.predicate_matching import PredicateMatcher
from frame import EntailmentChecker
from frame.core.parser import parse


class TestPredicateMatcherBasics:
    """Test basic PredicateMatcher functionality"""

    def setup_method(self):
        """Set up matcher for each test"""
        self.matcher = PredicateMatcher(verbose=False)

    def test_matcher_initialization(self):
        """Test matcher can be initialized"""
        assert self.matcher is not None
        assert self.matcher.analyzer is not None

    def test_verbose_mode(self):
        """Test matcher with verbose mode"""
        verbose_matcher = PredicateMatcher(verbose=True)
        assert verbose_matcher.verbose is True


class TestListConsMatching:
    """Test _match_list_cons pattern matching"""

    def setup_method(self):
        """Set up matcher and checker"""
        self.matcher = PredicateMatcher()
        self.checker = EntailmentChecker()

    def test_basic_list_cons(self):
        """Test x |-> y * list(y) |- list(x)"""
        ante = parse("x |-> y * list(y)")
        cons = parse("list(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_list_cons_with_actual_checker(self):
        """Test list cons pattern with full entailment checker"""
        result = self.checker.check_entailment("x |-> y * list(y) |- list(x)")
        assert result.valid

    def test_list_cons_reverse_order(self):
        """Test list(y) * x |-> y |- list(x)"""
        ante = parse("list(y) * x |-> y")
        cons = parse("list(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_list_cons_with_nil(self):
        """Test x |-> nil * list(nil) |- list(x)"""
        result = self.checker.check_entailment("x |-> nil * list(nil) |- list(x)")
        assert result.valid

    def test_list_cons_mismatch(self):
        """Test x |-> y * list(z) where y != z"""
        ante = parse("x |-> y * list(z)")
        cons = parse("list(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        # Should not match since y != z
        assert result is None or result is False

    def test_list_cons_missing_list(self):
        """Test x |-> y |- list(x) without list predicate"""
        ante = parse("x |-> y")
        cons = parse("list(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None

    def test_list_cons_missing_pointsto(self):
        """Test list(y) |- list(x) without points-to"""
        ante = parse("list(y)")
        cons = parse("list(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None


class TestListSegmentConsMatching:
    """Test _match_ls_cons pattern matching"""

    def setup_method(self):
        """Set up matcher and checker"""
        self.matcher = PredicateMatcher()
        self.checker = EntailmentChecker()

    def test_basic_ls_cons(self):
        """Test x |-> y * ls(y, z) |- ls(x, z)"""
        ante = parse("x |-> y * ls(y, z)")
        cons = parse("ls(x, z)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_ls_cons_with_checker(self):
        """Test ls cons with full entailment checker"""
        result = self.checker.check_entailment("x |-> y * ls(y, z) |- ls(x, z)")
        assert result.valid

    def test_ls_cons_reverse_order(self):
        """Test ls(y, z) * x |-> y |- ls(x, z)"""
        ante = parse("ls(y, z) * x |-> y")
        cons = parse("ls(x, z)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_ls_cons_chain(self):
        """Test x |-> y * y |-> z |- ls(x, z).

        SOUNDNESS FIX: This pattern is INVALID with distinctness constraints!
        The recursive case of ls(x, z) requires x != z, but the heap only proves
        x != y and y != z. We cannot prove x != z from disjointness alone.

        The unsound heuristic that accepted this pattern has been disabled.
        """
        ante = parse("x |-> y * y |-> z")
        cons = parse("ls(x, z)")
        result = self.matcher.try_predicate_matching(ante, cons)
        # Changed: Now returns None after soundness fix (was unsoundly returning True)
        assert result is None  # Heuristic no longer matches unsound pattern

    def test_ls_cons_long_chain(self):
        """Test x |-> y * y |-> w * ls(w, z) |- ls(x, z)"""
        result = self.checker.check_entailment("x |-> y * y |-> w * ls(w, z) |- ls(x, z)")
        assert result.valid

    def test_ls_cons_endpoint_mismatch(self):
        """Test x |-> y * ls(y, z) |- ls(x, w) where z != w"""
        ante = parse("x |-> y * ls(y, z)")
        cons = parse("ls(x, w)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None or result is False


class TestTreeConsMatching:
    """Test _match_tree_cons pattern matching"""

    def setup_method(self):
        """Set up matcher and checker"""
        self.matcher = PredicateMatcher()
        self.checker = EntailmentChecker()

    def test_basic_tree_cons(self):
        """Test x |-> (l, r) * tree(l) * tree(r) |- tree(x)"""
        ante = parse("x |-> (l, r) * tree(l) * tree(r)")
        cons = parse("tree(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_tree_cons_with_checker(self):
        """Test tree cons with full entailment checker"""
        result = self.checker.check_entailment("x |-> (l, r) * tree(l) * tree(r) |- tree(x)")
        assert result.valid

    def test_tree_cons_different_order(self):
        """Test tree(l) * x |-> (l, r) * tree(r) |- tree(x)"""
        ante = parse("tree(l) * x |-> (l, r) * tree(r)")
        cons = parse("tree(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_tree_cons_one_subtree_missing(self):
        """Test x |-> (l, r) * tree(l) |- tree(x) missing one subtree"""
        ante = parse("x |-> (l, r) * tree(l)")
        cons = parse("tree(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None

    def test_tree_cons_wrong_children(self):
        """Test x |-> (l, r) * tree(a) * tree(b) where a,b != l,r"""
        ante = parse("x |-> (l, r) * tree(a) * tree(b)")
        cons = parse("tree(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None or result is False


class TestRListConsMatching:
    """Test _match_rlist_cons pattern matching"""

    def setup_method(self):
        """Set up matcher"""
        self.matcher = PredicateMatcher()

    def test_basic_rlist_cons(self):
        """Test x |-> y * RList(y, z) |- RList(x, z)"""
        ante = parse("x |-> y * RList(y, z)")
        cons = parse("RList(x, z)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_rlist_cons_reverse_order(self):
        """Test RList(y, z) * x |-> y |- RList(x, z)"""
        ante = parse("RList(y, z) * x |-> y")
        cons = parse("RList(x, z)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_rlist_cons_mismatch(self):
        """Test x |-> y * RList(w, z) where y != w"""
        ante = parse("x |-> y * RList(w, z)")
        cons = parse("RList(x, z)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None or result is False


class TestNLLConsMatching:
    """Test _match_nll_cons pattern matching"""

    def setup_method(self):
        """Set up matcher"""
        self.matcher = PredicateMatcher()

    def test_basic_nll_cons(self):
        """Test x |-> (n, z) * nll(n, y, z) |- nll(x, y, z)"""
        ante = parse("x |-> (n, z) * nll(n, y, z)")
        cons = parse("nll(x, y, z)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_nll_cons_reverse_order(self):
        """Test nll(n, y, z) * x |-> (n, z) |- nll(x, y, z)"""
        ante = parse("nll(n, y, z) * x |-> (n, z)")
        cons = parse("nll(x, y, z)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_nll_cons_wrong_nested_value(self):
        """Test x |-> (n, w) * nll(n, y, z) where w != z"""
        ante = parse("x |-> (n, w) * nll(n, y, z)")
        cons = parse("nll(x, y, z)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None or result is False


class TestMultiplePredicates:
    """Test with multiple predicate calls"""

    def setup_method(self):
        """Set up matcher"""
        self.matcher = PredicateMatcher()

    def test_multiple_predicates_in_consequent(self):
        """Test when consequent has multiple predicates"""
        ante = parse("x |-> y * list(y)")
        cons = parse("list(x) * emp")
        result = self.matcher.try_predicate_matching(ante, cons)
        # Should extract the single predicate
        assert result is True or result is None

    def test_no_predicates_in_consequent(self):
        """Test when consequent has no predicates"""
        ante = parse("x |-> y * list(y)")
        cons = parse("x |-> y")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None


class TestIntegrationWithChecker:
    """Integration tests with EntailmentChecker"""

    def setup_method(self):
        """Set up checker"""
        self.checker = EntailmentChecker()

    def test_list_cons_full_entailment(self):
        """Test full entailment with list cons"""
        result = self.checker.check_entailment("x |-> y * list(y) |- list(x)")
        assert result.valid

    def test_ls_cons_full_entailment(self):
        """Test full entailment with ls cons"""
        result = self.checker.check_entailment("x |-> y * ls(y, z) |- ls(x, z)")
        assert result.valid

    def test_tree_cons_full_entailment(self):
        """Test full entailment with tree cons"""
        result = self.checker.check_entailment("x |-> (l, r) * tree(l) * tree(r) |- tree(x)")
        assert result.valid

    def test_complex_chain_entailment(self):
        """Test complex chain with multiple steps"""
        result = self.checker.check_entailment(
            "x |-> y * y |-> z * z |-> w * ls(w, end) |- ls(x, end)"
        )
        assert result.valid


class TestEdgeCases:
    """Test edge cases in predicate matching"""

    def setup_method(self):
        """Set up matcher"""
        self.matcher = PredicateMatcher()

    def test_empty_antecedent(self):
        """Test with empty heap"""
        ante = parse("emp")
        cons = parse("list(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None

    def test_with_pure_constraints(self):
        """Test pattern matching with pure constraints"""
        ante = parse("x |-> y * list(y)")
        cons = parse("list(x)")
        # Should still match the spatial pattern
        result = self.matcher.try_predicate_matching(ante, cons)
        # Should match
        assert result is True

    def test_unknown_predicate_type(self):
        """Test with unknown predicate type"""
        ante = parse("x |-> y * unknown_pred(y)")
        cons = parse("unknown_pred(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None

    def test_self_loop(self):
        """Test self-loop pattern x |-> x"""
        ante = parse("x |-> x")
        cons = parse("list(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        assert result is None

    def test_multi_field_pointsto(self):
        """Test with multi-field points-to"""
        ante = parse("x |-> (a, b, c) * list(a)")
        cons = parse("list(x)")
        result = self.matcher.try_predicate_matching(ante, cons)
        # Should check if first field matches
        assert result in [True, None]


class TestVerboseMode:
    """Test verbose output"""

    def test_verbose_list_cons(self):
        """Test verbose mode outputs messages"""
        matcher = PredicateMatcher(verbose=True)
        ante = parse("x |-> y * list(y)")
        cons = parse("list(x)")
        # Should not crash and should match
        result = matcher.try_predicate_matching(ante, cons)
        assert result is True

    def test_verbose_ls_cons(self):
        """Test verbose mode with ls cons"""
        matcher = PredicateMatcher(verbose=True)
        ante = parse("x |-> y * ls(y, z)")
        cons = parse("ls(x, z)")
        result = matcher.try_predicate_matching(ante, cons)
        assert result is True
