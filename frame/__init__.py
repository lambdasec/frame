"""
Separation Logic Entailment Checker using Z3

A Python library for checking entailments in separation logic,
supporting basic assertions and inductive predicates for data structures.

The library is organized into logical modules:
- core: AST and parser
- encoding: Z3 SMT encoding
- checking: Entailment checking and heuristics
- analysis: Formula analysis and reasoning
- heap: Heap graph and pattern detection
- folding: Predicate folding/unfolding
- arithmetic: Arithmetic reasoning
- preprocessing: Formula preprocessing
- predicates: Inductive predicate definitions
- lemmas: Lemma library
- utils: Utilities and proof management
"""

# Core abstractions
from frame.core.ast import (
    Formula, Emp, PointsTo, SepConj, Wand, And, Or, Not, Eq, Neq,
    Lt, Le, Gt, Ge, True_, False_, Exists, Forall, Var, Const, PredicateCall,
    # String expressions
    StrLiteral, StrConcat, StrLen, StrSubstr, StrContains, StrMatches,
    # Security and taint tracking
    Taint, Sanitized, Source, Sink,
    # Error states for incorrectness logic
    Error, NullDeref, UseAfterFree, BufferOverflow
)
from frame.core.parser import parse, parse_entailment

# Main checker
from frame.checking.checker import EntailmentChecker

# Predicates
from frame.predicates import (
    PredicateRegistry, InductivePredicate, PredicateValidationError,
    ListSegment, Tree, GenericPredicate
)

__version__ = "0.0.1"
__all__ = [
    # Core formulas and expressions
    "Formula", "Emp", "PointsTo", "SepConj", "Wand", "And", "Or", "Not",
    "Eq", "Neq", "Lt", "Le", "Gt", "Ge", "True_", "False_", "Exists", "Forall", "Var", "Const",
    "PredicateCall",
    # String expressions
    "StrLiteral", "StrConcat", "StrLen", "StrSubstr", "StrContains", "StrMatches",
    # Security and taint
    "Taint", "Sanitized", "Source", "Sink",
    # Error states
    "Error", "NullDeref", "UseAfterFree", "BufferOverflow",
    # Checker and predicates
    "EntailmentChecker", "PredicateRegistry",
    "InductivePredicate", "PredicateValidationError",
    "ListSegment", "Tree", "GenericPredicate",
    # Parser
    "parse", "parse_entailment"
]
