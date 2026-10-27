"""Regression tests for operator tokenization in the formula parser."""

from frame import EntailmentChecker
from frame.core.ast import And, Neq, Not, PointsTo
from frame.core.parser import parse


def test_neq_is_one_token():
    # The lexer used to match `!` (NOT) before `!=`, so `x != y` never parsed.
    assert isinstance(parse("x != y"), Neq)
    assert isinstance(parse("x |-> 5 & x != nil"), And)


def test_negation_still_parses():
    assert isinstance(parse("!(x = y)"), Not)
    assert isinstance(parse("x |-> 5"), PointsTo)


def test_neq_entailments_from_text():
    checker = EntailmentChecker()
    assert checker.check_entailment("x != y |- x != y").valid
    assert checker.check_entailment("x |-> 5 & x != nil |- x |-> 5").valid
    assert not checker.check_entailment("x = y |- x != y").valid
