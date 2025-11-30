"""
Soundness regression tests for critical bugs.

These tests prevent regressions that cause false positive validations
(claiming valid when actually invalid - a soundness bug).
"""

import pytest
from test_framework import *


# Shared fixture for checker
@pytest.fixture
def checker():
    return EntailmentChecker(predicate_registry=PredicateRegistry(), timeout=10000)


# Soundness Bug #1: Or distribution causing false positives on data benchmarks
# These tests come from qf_shidlia_entl benchmarks that regressed with Phase 1
# They should return INVALID (sat means entailment doesn't hold)
# But Phase 1 Or distribution was incorrectly returning VALID (unsat)

def test_dll_entl_02_pattern_invalid(checker):
    """dll-entl-02 pattern (should be INVALID)"""
    result = checker.check_entailment("ls(x, y) |- ls(a, b)")
    assert not result.valid


def test_reflexivity_still_works(checker):
    """Reflexivity still works"""
    result = checker.check_entailment("ls(x, y) |- ls(x, y)")
    assert result.valid


def test_different_list_segments_dont_entail(checker):
    """Different list segments don't entail each other"""
    result = checker.check_entailment("ls(x, y) * emp |- ls(a, b)")
    assert not result.valid


def test_frame_rule_works_correctly(checker):
    """Frame rule works correctly

    NOTE (Nov 2025): In exact semantics (SL-COMP), ls(x, y) * ls(a, b) |- ls(x, y)
    is INVALID because we cannot drop ls(a, b). Frame rule only applies when
    the frame appears on BOTH sides.

    Test the correct frame rule: ls(x, y) * ls(a, b) |- ls(x, y) * ls(a, b)
    """
    result = checker.check_entailment("ls(x, y) * ls(a, b) |- ls(x, y) * ls(a, b)")
    assert result.valid


def test_cannot_frame_away_too_much(checker):
    """Cannot frame away too much"""
    result = checker.check_entailment("ls(x, y) |- ls(x, y) * ls(a, b)")
    assert not result.valid
