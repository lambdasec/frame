"""
Core type definitions for Frame SIL.

This module defines the fundamental types used throughout the SIL:
- Identifiers and program variables
- Source locations for error reporting
- Type representations
- Expression AST nodes
"""

from dataclasses import dataclass, field
from typing import List, Optional, Union, Dict, Any
from enum import Enum, auto


# =============================================================================
# Identifiers and Variables
# =============================================================================

@dataclass(frozen=True)
class Ident:
    """
    Identifier - a temporary variable introduced by analysis.

    These are SSA-style temporaries used to hold intermediate values.
    The stamp provides uniqueness for SSA numbering.

    Example: $tmp_0, $call_result_1
    """
    name: str
    stamp: int = 0

    def __str__(self) -> str:
        if self.stamp:
            return f"${self.name}_{self.stamp}"
        return f"${self.name}"

    def __repr__(self) -> str:
        return f"Ident({self.name!r}, {self.stamp})"


@dataclass(frozen=True)
class PVar:
    """
    Program variable - a variable from the source code.

    These correspond directly to variables in the original program.

    Example: user_input, query, result
    """
    name: str

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"PVar({self.name!r})"


@dataclass(frozen=True)
class Location:
    """
    Source location for error reporting.

    Tracks where in the original source code an instruction originated.
    """
    file: str
    line: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def __str__(self) -> str:
        if self.column:
            return f"{self.file}:{self.line}:{self.column}"
        return f"{self.file}:{self.line}"

    def __repr__(self) -> str:
        return f"Location({self.file!r}, {self.line}, {self.column})"

    @classmethod
    def unknown(cls) -> 'Location':
        """Create an unknown location"""
        return cls("<unknown>", 0)


# =============================================================================
# Types
# =============================================================================

class TypeKind(Enum):
    """Basic type kinds"""
    INT = auto()
    FLOAT = auto()
    BOOL = auto()
    STRING = auto()
    BYTES = auto()
    POINTER = auto()
    ARRAY = auto()
    LIST = auto()
    DICT = auto()
    STRUCT = auto()
    CLASS = auto()
    FUNCTION = auto()
    VOID = auto()
    NONE = auto()
    UNKNOWN = auto()


@dataclass
class Typ:
    """
    Type representation.

    Supports basic types, pointers, arrays, and composite types.
    """
    kind: TypeKind
    pointee: Optional['Typ'] = None           # For pointers
    element: Optional['Typ'] = None           # For arrays/lists
    key_type: Optional['Typ'] = None          # For dicts
    value_type: Optional['Typ'] = None        # For dicts
    fields: Dict[str, 'Typ'] = field(default_factory=dict)  # For structs/classes
    name: Optional[str] = None                # Named types (classes, etc.)
    params: List['Typ'] = field(default_factory=list)  # For functions
    ret_type: Optional['Typ'] = None          # For functions

    def __str__(self) -> str:
        if self.name:
            return self.name
        if self.kind == TypeKind.POINTER and self.pointee:
            return f"*{self.pointee}"
        if self.kind == TypeKind.ARRAY and self.element:
            return f"[]{self.element}"
        if self.kind == TypeKind.LIST and self.element:
            return f"List[{self.element}]"
        if self.kind == TypeKind.DICT and self.key_type and self.value_type:
            return f"Dict[{self.key_type}, {self.value_type}]"
        return self.kind.name.lower()

    @classmethod
    def int_type(cls) -> 'Typ':
        return cls(TypeKind.INT)

    @classmethod
    def string_type(cls) -> 'Typ':
        return cls(TypeKind.STRING)

    @classmethod
    def bool_type(cls) -> 'Typ':
        return cls(TypeKind.BOOL)

    @classmethod
    def void_type(cls) -> 'Typ':
        return cls(TypeKind.VOID)

    @classmethod
    def unknown_type(cls) -> 'Typ':
        return cls(TypeKind.UNKNOWN)

    @classmethod
    def pointer_to(cls, pointee: 'Typ') -> 'Typ':
        return cls(TypeKind.POINTER, pointee=pointee)

    @classmethod
    def array_of(cls, element: 'Typ') -> 'Typ':
        return cls(TypeKind.ARRAY, element=element)

    @classmethod
    def list_of(cls, element: 'Typ') -> 'Typ':
        return cls(TypeKind.LIST, element=element)

    @classmethod
    def dict_of(cls, key: 'Typ', value: 'Typ') -> 'Typ':
        return cls(TypeKind.DICT, key_type=key, value_type=value)

    @classmethod
    def class_type(cls, name: str, fields: Dict[str, 'Typ'] = None) -> 'Typ':
        return cls(TypeKind.CLASS, name=name, fields=fields or {})


# =============================================================================
# Expressions
# =============================================================================

@dataclass
class Exp:
    """Base class for expressions"""

    def __str__(self) -> str:
        return "<exp>"

    def free_vars(self) -> set:
        """Return set of free variables in this expression"""
        return set()


@dataclass
class ExpVar(Exp):
    """
    Variable reference.

    Can be either an Ident (temporary) or PVar (program variable).
    """
    var: Union[Ident, PVar]

    def __str__(self) -> str:
        return str(self.var)

    def __repr__(self) -> str:
        return f"ExpVar({self.var!r})"

    def free_vars(self) -> set:
        if isinstance(self.var, PVar):
            return {self.var.name}
        return {str(self.var)}


@dataclass
class ExpConst(Exp):
    """
    Constant value.

    Includes integers, floats, strings, booleans, and None/null.
    """
    value: Union[int, float, str, bool, None]
    typ: Typ = field(default_factory=Typ.unknown_type)

    def __str__(self) -> str:
        if self.value is None:
            return "null"
        if isinstance(self.value, str):
            # Escape for display
            escaped = self.value.replace('\\', '\\\\').replace('"', '\\"')
            if len(escaped) > 50:
                escaped = escaped[:47] + "..."
            return f'"{escaped}"'
        if isinstance(self.value, bool):
            return "true" if self.value else "false"
        return str(self.value)

    def __repr__(self) -> str:
        return f"ExpConst({self.value!r})"

    @classmethod
    def null(cls) -> 'ExpConst':
        return cls(None, Typ(TypeKind.NONE))

    @classmethod
    def integer(cls, n: int) -> 'ExpConst':
        return cls(n, Typ.int_type())

    @classmethod
    def string(cls, s: str) -> 'ExpConst':
        return cls(s, Typ.string_type())

    @classmethod
    def boolean(cls, b: bool) -> 'ExpConst':
        return cls(b, Typ.bool_type())


@dataclass
class ExpBinOp(Exp):
    """
    Binary operation.

    Supports arithmetic, comparison, and logical operators.
    """
    op: str  # "+", "-", "*", "/", "%", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "&", "|", "^"
    left: Exp
    right: Exp

    def __str__(self) -> str:
        return f"({self.left} {self.op} {self.right})"

    def __repr__(self) -> str:
        return f"ExpBinOp({self.op!r}, {self.left!r}, {self.right!r})"

    def free_vars(self) -> set:
        return self.left.free_vars() | self.right.free_vars()


@dataclass
class ExpUnOp(Exp):
    """
    Unary operation.

    Includes negation, logical not, dereference, and address-of.
    """
    op: str  # "-" (negate), "!" (not), "*" (deref), "&" (addr-of), "~" (bitwise not)
    operand: Exp

    def __str__(self) -> str:
        if self.op in ("*", "&"):
            return f"{self.op}{self.operand}"
        return f"{self.op}({self.operand})"

    def __repr__(self) -> str:
        return f"ExpUnOp({self.op!r}, {self.operand!r})"

    def free_vars(self) -> set:
        return self.operand.free_vars()


@dataclass
class ExpFieldAccess(Exp):
    """
    Field access.

    Handles both struct.field and ptr->field access patterns.
    """
    base: Exp
    field_name: str
    is_arrow: bool = False  # True for ptr->field, False for struct.field

    def __str__(self) -> str:
        op = "->" if self.is_arrow else "."
        return f"{self.base}{op}{self.field_name}"

    def __repr__(self) -> str:
        return f"ExpFieldAccess({self.base!r}, {self.field_name!r}, {self.is_arrow})"

    def free_vars(self) -> set:
        return self.base.free_vars()


@dataclass
class ExpIndex(Exp):
    """
    Array/list indexing.

    Represents base[index] access.
    """
    base: Exp
    index: Exp

    def __str__(self) -> str:
        return f"{self.base}[{self.index}]"

    def __repr__(self) -> str:
        return f"ExpIndex({self.base!r}, {self.index!r})"

    def free_vars(self) -> set:
        return self.base.free_vars() | self.index.free_vars()


@dataclass
class ExpCast(Exp):
    """
    Type cast expression.
    """
    exp: Exp
    typ: Typ

    def __str__(self) -> str:
        return f"({self.typ}){self.exp}"

    def __repr__(self) -> str:
        return f"ExpCast({self.exp!r}, {self.typ!r})"

    def free_vars(self) -> set:
        return self.exp.free_vars()


@dataclass
class ExpStringConcat(Exp):
    """
    String concatenation.

    Security-relevant: tracks how strings are built from potentially tainted parts.
    This is crucial for detecting injection vulnerabilities.
    """
    parts: List[Exp]

    def __str__(self) -> str:
        return " ++ ".join(str(p) for p in self.parts)

    def __repr__(self) -> str:
        return f"ExpStringConcat({self.parts!r})"

    def free_vars(self) -> set:
        result = set()
        for part in self.parts:
            result |= part.free_vars()
        return result


@dataclass
class ExpCall(Exp):
    """
    Function call expression (for calls that return values used in expressions).

    Different from the Call instruction - this is for nested calls like f(g(x)).
    """
    func: Exp
    args: List[Exp]

    def __str__(self) -> str:
        args_str = ", ".join(str(a) for a in self.args)
        return f"{self.func}({args_str})"

    def __repr__(self) -> str:
        return f"ExpCall({self.func!r}, {self.args!r})"

    def free_vars(self) -> set:
        result = self.func.free_vars()
        for arg in self.args:
            result |= arg.free_vars()
        return result


@dataclass
class ExpTernary(Exp):
    """
    Ternary conditional expression: cond ? true_exp : false_exp
    """
    condition: Exp
    true_exp: Exp
    false_exp: Exp

    def __str__(self) -> str:
        return f"({self.condition} ? {self.true_exp} : {self.false_exp})"

    def __repr__(self) -> str:
        return f"ExpTernary({self.condition!r}, {self.true_exp!r}, {self.false_exp!r})"

    def free_vars(self) -> set:
        return self.condition.free_vars() | self.true_exp.free_vars() | self.false_exp.free_vars()


# =============================================================================
# Helper functions
# =============================================================================

def var(name: str) -> ExpVar:
    """Create a variable expression from a name"""
    return ExpVar(PVar(name))


def const(value: Any) -> ExpConst:
    """Create a constant expression"""
    if value is None:
        return ExpConst.null()
    if isinstance(value, bool):
        return ExpConst.boolean(value)
    if isinstance(value, int):
        return ExpConst.integer(value)
    if isinstance(value, str):
        return ExpConst.string(value)
    return ExpConst(value)


def binop(op: str, left: Exp, right: Exp) -> ExpBinOp:
    """Create a binary operation expression"""
    return ExpBinOp(op, left, right)


def field(base: Exp, name: str) -> ExpFieldAccess:
    """Create a field access expression"""
    return ExpFieldAccess(base, name)


def index(base: Exp, idx: Exp) -> ExpIndex:
    """Create an index expression"""
    return ExpIndex(base, idx)


def concat(*parts: Exp) -> ExpStringConcat:
    """Create a string concatenation expression"""
    return ExpStringConcat(list(parts))
