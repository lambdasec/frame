"""
Test Framework for Separation Logic Entailment Checker

Provides utilities for writing comprehensive regression tests.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from frame import *
from frame.core.parser import parse
from typing import Optional, List, Tuple

# Import helper classes from non-test file to avoid pytest collection warnings
from tests.framework_helpers import SuiteResult, SuiteRunner


def build_formula(*args) -> Formula:
    """Helper to build formulas more concisely"""
    if len(args) == 1:
        return args[0]
    elif len(args) == 2:
        return SepConj(args[0], args[1])
    else:
        return SepConj(args[0], build_formula(*args[1:]))


# Common test formulas
def emp() -> Formula:
    return Emp()


def pts(var_name: str, val) -> Formula:
    """Points-to: var |-> val"""
    var = Var(var_name)
    if isinstance(val, int):
        return PointsTo(var, [Const(val)])
    elif isinstance(val, str):
        return PointsTo(var, [Var(val)])
    elif isinstance(val, list):
        vals = [Var(v) if isinstance(v, str) else Const(v) for v in val]
        return PointsTo(var, vals)
    else:
        return PointsTo(var, [val])


def sep(*formulas) -> Formula:
    """Separating conjunction"""
    return build_formula(*formulas)


def eq(var1: str, var2_or_val) -> Formula:
    """Equality"""
    if isinstance(var2_or_val, str):
        return Eq(Var(var1), Var(var2_or_val))
    else:
        return Eq(Var(var1), Const(var2_or_val))


def neq(var1: str, var2_or_val) -> Formula:
    """Disequality"""
    if isinstance(var2_or_val, str):
        return Neq(Var(var1), Var(var2_or_val))
    else:
        return Neq(Var(var1), Const(var2_or_val))


def ls(start: str, end: str) -> Formula:
    """List segment"""
    return PredicateCall("ls", [Var(start), Var(end)])


def lst(start: str) -> Formula:
    """Linked list"""
    return PredicateCall("list", [Var(start)])


def tree(root: str) -> Formula:
    """Binary tree"""
    return PredicateCall("tree", [Var(root)])


# Backward compatibility aliases (for legacy tests that import these names)
# These are now imported from framework_helpers to avoid pytest collection warnings
_TestResult = SuiteResult
_TestSuite = SuiteRunner
TestResult = SuiteResult
TestSuite = SuiteRunner
