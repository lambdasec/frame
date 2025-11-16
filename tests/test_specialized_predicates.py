"""
Tests for Specialized Predicates

Tests skiplist, sorted, dll, lsso predicates to improve coverage.
"""

import pytest
from frame import EntailmentChecker, PredicateRegistry
from frame.predicates.skiplist_predicates import SkipList1, SkipList2, SkipList3
from frame.predicates.sorted_predicates import SortedListSegment
from frame.predicates.dll_predicates import DoublyLinkedList
from frame.predicates.lsso_predicates import ListSegmentSentinel
from frame.predicates.tree_predicates import Tree
from frame.predicates.list_predicates import NestedList, ReverseList
from frame.core.ast import *


class TestSkipListPredicates:
    """Test skiplist predicates coverage"""

    def test_skiplist1_creation(self):
        """Test creating SkipList1"""
        pred = SkipList1()
        assert pred.name == "skl1"
        assert pred.arity == 2

    def test_skiplist1_unfold(self):
        """Test unfolding SkipList1"""
        pred = SkipList1()
        unfolded = pred.unfold([Var("x"), Var("y")])
        assert unfolded is not None

    def test_skiplist2_creation(self):
        """Test creating SkipList2"""
        pred = SkipList2()
        assert pred.name == "skl2"

    def test_skiplist3_creation(self):
        """Test creating SkipList3"""
        pred = SkipList3()
        assert pred.name == "skl3"


class TestSortedListPredicate:
    """Test sorted list predicate"""

    def test_sorted_creation(self):
        """Test creating SortedListSegment"""
        pred = SortedListSegment()
        assert pred.name == "sls"
        assert pred.arity == 4

    def test_sorted_unfold(self):
        """Test unfolding sorted list"""
        pred = SortedListSegment()
        unfolded = pred.unfold([Var("x"), Var("alpha"), Var("y"), Var("beta")])
        assert unfolded is not None


class TestDLLPredicate:
    """Test doubly-linked list predicate"""

    def test_dll_creation(self):
        """Test creating DoublyLinkedList"""
        pred = DoublyLinkedList()
        assert pred.name == "dll"
        assert pred.arity == 4

    def test_dll_unfold(self):
        """Test unfolding DLL"""
        pred = DoublyLinkedList()
        unfolded = pred.unfold([Var("x"), Var("p"), Var("y"), Var("n")])
        assert unfolded is not None


class TestListSegmentSentinel:
    """Test list segment sentinel predicate"""

    def test_lsso_creation(self):
        """Test creating ListSegmentSentinel"""
        pred = ListSegmentSentinel()
        assert pred.name == "lsso"
        assert pred.arity == 2

    def test_lsso_unfold(self):
        """Test unfolding list segment sentinel"""
        pred = ListSegmentSentinel()
        unfolded = pred.unfold([Var("x"), Var("y")])
        assert unfolded is not None


class TestTreePredicate:
    """Test tree predicate coverage"""

    def test_tree_creation(self):
        """Test creating Tree predicate"""
        pred = Tree()
        assert pred.name == "tree"
        assert pred.arity == 1

    def test_tree_unfold(self):
        """Test unfolding tree"""
        pred = Tree()
        unfolded = pred.unfold([Var("x")])
        assert unfolded is not None

    def test_tree_nil_case(self):
        """Test tree with nil"""
        pred = Tree()
        unfolded = pred.unfold([Const(None)])
        assert unfolded is not None


class TestNestedListPredicate:
    """Test nested list predicate"""

    def test_nested_list_creation(self):
        """Test creating NestedList"""
        pred = NestedList()
        assert pred.name == "nll"
        assert pred.arity >= 1

    def test_nested_list_unfold(self):
        """Test unfolding nested list"""
        pred = NestedList()
        # NLL has arity 3
        unfolded = pred.unfold([Var("x"), Var("y"), Var("z")])
        assert unfolded is not None


class TestReverseListPredicate:
    """Test reverse list predicate"""

    def test_reverse_list_creation(self):
        """Test creating ReverseList"""
        pred = ReverseList()
        assert pred.name == "RList"
        assert pred.arity >= 1

    def test_reverse_list_unfold(self):
        """Test unfolding reverse list"""
        pred = ReverseList()
        # RList has arity 2
        unfolded = pred.unfold([Var("x"), Var("y")])
        assert unfolded is not None


class TestPredicateRegistration:
    """Test predicate registration"""

    def test_default_registry_has_predicates(self):
        """Test that default registry has built-in predicates"""
        registry = PredicateRegistry()
        # Check that some predicates are registered
        assert len(registry.predicates) > 0
        assert "ls" in registry.predicates
        assert "list" in registry.predicates
        assert "tree" in registry.predicates

    def test_register_custom_predicate(self):
        """Test registering a custom predicate"""
        registry = PredicateRegistry()
        initial_count = len(registry.predicates)

        # Register a new instance (will replace existing)
        custom_tree = Tree()
        registry.register(custom_tree)

        # Should still have same or more predicates
        assert len(registry.predicates) >= initial_count


class TestPredicateValidation:
    """Test predicate validation"""

    def test_predicate_has_unfold_method(self):
        """Test that all predicates have unfold method"""
        predicates = [
            SkipList1(),
            SortedListSegment(),
            DoublyLinkedList(),
            ListSegmentSentinel(),
            Tree(),
            NestedList(),
            ReverseList()
        ]

        for pred in predicates:
            assert hasattr(pred, 'unfold')
            assert hasattr(pred, 'name')
            assert hasattr(pred, 'arity')

    def test_predicate_free_vars(self):
        """Test that predicates implement free_vars"""
        pred = Tree()
        call = PredicateCall("tree", [Var("x"), Var("y")])

        # Should have free_vars method
        fv = call.free_vars()
        assert 'x' in fv
        assert 'y' in fv


class TestPredicateUsageInEntailments:
    """Test using specialized predicates in actual entailments"""

    def test_tree_reflexivity(self):
        """Test tree(x) |- tree(x)"""
        checker = EntailmentChecker()
        result = checker.check_entailment("tree(x) |- tree(x)")
        assert result.valid

    def test_dll_reflexivity(self):
        """Test dll reflexivity"""
        checker = EntailmentChecker()
        result = checker.check_entailment("dll(x,p,y,n) |- dll(x,p,y,n)")
        assert result.valid

    def test_nested_list_reflexivity(self):
        """Test nll(x) |- nll(x)"""
        checker = EntailmentChecker()
        result = checker.check_entailment("nll(x) |- nll(x)")
        assert result.valid


class TestPredicateCombinations:
    """Test combining predicates"""

    def test_tree_with_points_to(self):
        """Test tree combined with points-to"""
        checker = EntailmentChecker()
        # Just test that it doesn't crash
        result = checker.check_entailment("tree(x) * y |-> z |- tree(x)")
        assert result is not None

    def test_dll_with_sepconj(self):
        """Test DLL with separating conjunction"""
        checker = EntailmentChecker()
        # Just test that it doesn't crash
        result = checker.check_entailment("dll(x,p,y,n) * y |-> z |- dll(x,p,y,n)")
        assert result is not None
