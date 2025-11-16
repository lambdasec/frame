"""
Entailment checking and heuristic reasoning.

This module contains the main entailment checker and various
heuristic checks for fast verification without invoking Z3.
"""

from frame.checking.checker import EntailmentChecker, EntailmentResult
from frame.checking.heuristics import HeuristicChecker
