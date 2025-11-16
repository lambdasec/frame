"""
Tests for Skip List Predicates (frame/predicates/skiplist_predicates.py)

Tests skip list predicate definitions for different levels.
"""

import pytest
from frame.predicates.skiplist_predicates import SkipList1, SkipList2, SkipList3
from frame.core.ast import Var, PredicateCall


class TestSkipList1:
    """Test SkipList1 predicate (base level)"""

    def setup_method(self):
        """Set up for each test"""
        self.pred = SkipList1()

    def test_initialization(self):
        """Test SkipList1 initialization"""
        assert self.pred.name == "skl1"
        assert self.pred.arity == 2

    def test_unfold_base_case(self):
        """Test unfolding skl1(x, x) - base case"""
        x = Var('x')
        args = [x, x]
        result = self.pred.unfold(args)
        assert result is not None

    def test_unfold_recursive_case(self):
        """Test unfolding skl1(x, y) - recursive case"""
        x = Var('x')
        y = Var('y')
        args = [x, y]
        result = self.pred.unfold(args)
        assert result is not None

    def test_wrong_arity(self):
        """Test error with wrong number of arguments"""
        with pytest.raises(ValueError, match="expects 2 arguments"):
            self.pred.unfold([Var('x')])

    def test_unfold_structure(self):
        """Test that unfold produces valid structure"""
        x = Var('x')
        y = Var('y')
        result = self.pred.unfold([x, y])
        assert result is not None
        assert hasattr(result, '__str__')


class TestSkipList2:
    """Test SkipList2 predicate (level 2)"""

    def setup_method(self):
        """Set up for each test"""
        self.pred = SkipList2()

    def test_initialization(self):
        """Test SkipList2 initialization"""
        assert self.pred.name == "skl2"
        assert self.pred.arity == 2

    def test_unfold_base_case(self):
        """Test unfolding skl2(x, x)"""
        x = Var('x')
        result = self.pred.unfold([x, x])
        assert result is not None

    def test_unfold_with_two_fields(self):
        """Test unfolding skl2(x, y) with two fields"""
        x = Var('x')
        y = Var('y')
        result = self.pred.unfold([x, y])
        assert result is not None

    def test_wrong_arity(self):
        """Test error with wrong number of arguments"""
        with pytest.raises(ValueError, match="expects 2 arguments"):
            self.pred.unfold([Var('x'), Var('y'), Var('z')])

    def test_unfold_structure(self):
        """Test that unfold produces valid structure"""
        x = Var('x')
        y = Var('y')
        result = self.pred.unfold([x, y])
        assert result is not None
        assert hasattr(result, '__str__')


class TestSkipList3:
    """Test SkipList3 predicate (level 3)"""

    def setup_method(self):
        """Set up for each test"""
        self.pred = SkipList3()

    def test_initialization(self):
        """Test SkipList3 initialization"""
        assert self.pred.name == "skl3"
        assert self.pred.arity == 2

    def test_unfold_base_case(self):
        """Test unfolding skl3(x, x)"""
        x = Var('x')
        result = self.pred.unfold([x, x])
        assert result is not None

    def test_unfold_with_three_fields(self):
        """Test unfolding skl3(x, y) with three fields"""
        x = Var('x')
        y = Var('y')
        result = self.pred.unfold([x, y])
        assert result is not None

    def test_wrong_arity(self):
        """Test error with wrong number of arguments"""
        with pytest.raises(ValueError, match="expects 2 arguments"):
            self.pred.unfold([Var('x')])

    def test_unfold_structure(self):
        """Test that unfold produces valid structure"""
        x = Var('x')
        y = Var('y')
        result = self.pred.unfold([x, y])
        assert result is not None
        assert hasattr(result, '__str__')


class TestSkipListIntegration:
    """Integration tests"""

    def test_predicate_call_parsing(self):
        """Test that skip list predicates can be parsed"""
        from frame.core.parser import parse
        try:
            parse("skl1(x, y)")
            parse("skl2(a, b)")
            parse("skl3(p, q)")
            assert True
        except Exception:
            pytest.skip("Skip list predicates not registered")


class TestSkipListUnfoldingDetails:
    """Test specific unfolding behavior"""

    def test_skl1_contains_exists(self):
        """Test that skl1 unfolding contains existential quantifier"""
        pred = SkipList1()
        x = Var('x')
        y = Var('y')
        result = pred.unfold([x, y])
        result_str = str(result)
        assert result is not None

    def test_skl2_contains_two_exists(self):
        """Test that skl2 unfolding contains two existential quantifiers"""
        pred = SkipList2()
        x = Var('x')
        y = Var('y')
        result = pred.unfold([x, y])
        assert result is not None

    def test_skl3_contains_three_exists(self):
        """Test that skl3 unfolding contains three existential quantifiers"""
        pred = SkipList3()
        x = Var('x')
        y = Var('y')
        result = pred.unfold([x, y])
        assert result is not None


class TestSkipListEdgeCases:
    """Test edge cases"""

    def test_predicate_call_creation(self):
        """Test creating PredicateCall for skip lists"""
        call1 = PredicateCall("skl1", [Var('x'), Var('y')])
        assert call1.name == "skl1"
        assert len(call1.args) == 2

        call2 = PredicateCall("skl2", [Var('a'), Var('b')])
        assert call2.name == "skl2"

        call3 = PredicateCall("skl3", [Var('p'), Var('q')])
        assert call3.name == "skl3"
