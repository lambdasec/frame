"""
Abstract Syntax Tree for Separation Logic Formulas

This module defines the AST classes for representing separation logic formulas,
including spatial formulas (emp, points-to, separating conjunction) and
pure formulas (boolean, arithmetic).

This file re-exports all AST nodes from thematic submodules for backward compatibility.
All imports from frame.core.ast continue to work as before.
"""

# Re-export base classes
from frame.core._ast_base import Expr, Formula

# Re-export expression nodes
from frame.core._ast_expressions import Var, Const, ArithExpr

# Re-export spatial formulas
from frame.core._ast_spatial import (
    Emp, PointsTo, SepConj, Wand,
    ArrayPointsTo, ArrayBounds
)

# Re-export pure formulas
from frame.core._ast_pure import (
    True_, False_,
    Eq, Neq, Lt, Le, Gt, Ge,
    And, Or, Not
)

# Re-export quantifiers and predicates
from frame.core._ast_quantifiers import Exists, Forall, PredicateCall

# Re-export string operations
from frame.core._ast_strings import (
    StrLiteral, StrConcat, StrLen, StrSubstr,
    StrContains, StrMatches
)

# Re-export security and taint tracking
from frame.core._ast_security import (
    Taint, Sanitized, Source, Sink
)

# Re-export error states and heap lifecycle
from frame.core._ast_errors import (
    Error, NullDeref, UseAfterFree, BufferOverflow,
    Allocated, Freed
)

# Re-export array and bitvector operations
from frame.core._ast_arrays_bitvecs import (
    ArraySelect, ArrayStore, ArrayConst,
    BitVecVal, BitVecExpr,
    TaintedArray, BufferOverflowCheck, IntegerOverflow
)

# Define __all__ for explicit exports
__all__ = [
    # Base classes
    'Expr', 'Formula',

    # Expressions
    'Var', 'Const', 'ArithExpr',

    # Spatial formulas
    'Emp', 'PointsTo', 'SepConj', 'Wand',
    'ArrayPointsTo', 'ArrayBounds',

    # Pure formulas
    'True_', 'False_',
    'Eq', 'Neq', 'Lt', 'Le', 'Gt', 'Ge',
    'And', 'Or', 'Not',

    # Quantifiers and predicates
    'Exists', 'Forall', 'PredicateCall',

    # String operations
    'StrLiteral', 'StrConcat', 'StrLen', 'StrSubstr',
    'StrContains', 'StrMatches',

    # Security and taint tracking
    'Taint', 'Sanitized', 'Source', 'Sink',

    # Error states and heap lifecycle
    'Error', 'NullDeref', 'UseAfterFree', 'BufferOverflow',
    'Allocated', 'Freed',

    # Array theory (QF_AX)
    'ArraySelect', 'ArrayStore', 'ArrayConst',

    # Bitvector theory (QF_BV)
    'BitVecVal', 'BitVecExpr',

    # Array and bitvector security predicates
    'TaintedArray', 'BufferOverflowCheck', 'IntegerOverflow',
]
