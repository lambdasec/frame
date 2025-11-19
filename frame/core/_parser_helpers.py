"""Parser Helper Functions

Large parsing methods extracted from parser.py to reduce file size.
These are internal implementation details.
"""

from typing import List, Optional
from frame.core.ast import (
    Formula, Expr, Var, Const, PointsTo, PredicateCall,
    Eq, Neq, Lt, Le, Gt, Ge, True_, False_, Emp,
    And, Or, Not, Exists, Forall,
    StrLiteral, StrConcat, StrLen, StrSubstr, StrContains, StrMatches,
    ArraySelect, ArrayStore, ArrayConst,
    ArithExpr, BitVecVal, BitVecExpr,
    TaintedArray, BufferOverflowCheck, IntegerOverflow
)
from frame.core._lexer import ParseError


def parse_primary(parser_self) -> Formula:
    """Parse primary formulas (keywords and parenthesized)

    Args:
        parser_self: The Parser instance

    Returns:
        Parsed formula
    """
    token = parser_self.current_token()

    if not token:
        raise ParseError("Unexpected end of input")

    # True
    if token.type == 'TRUE':
        parser_self.advance()
        return True_()

    # False
    if token.type == 'FALSE':
        parser_self.advance()
        return False_()

    # emp
    if token.type == 'EMP':
        parser_self.advance()
        return Emp()

    # Parenthesized expression
    if token.type == 'LPAREN':
        parser_self.advance()
        formula = parser_self.parse()
        parser_self.expect('RPAREN')
        return formula

    # Existential: exists x. P
    if token.type == 'EXISTS':
        parser_self.advance()
        var_name = parser_self.expect('IDENT').value
        var = Var(var_name)
        parser_self.expect('DOT')
        body = parser_self.parse()
        return Exists(var, body)

    # Universal: forall x. P
    if token.type == 'FORALL':
        parser_self.advance()
        var_name = parser_self.expect('IDENT').value
        var = Var(var_name)
        parser_self.expect('DOT')
        body = parser_self.parse()
        return Forall(var, body)

    # String theory atoms
    if token.type == 'STRING':
        return parser_self.parse_string_atom()

    # Array/bitvector atoms
    if token.type in ('ARRAY', 'BITVEC'):
        return parser_self.parse_array_bv_atom()

    # Taint/sanitization tracking
    if token.type == 'TAINT':
        return parser_self.parse_taint()
    if token.type == 'SANITIZED':
        return parser_self.parse_sanitized()
    if token.type == 'SOURCE':
        return parser_self.parse_source()
    if token.type == 'SINK':
        return parser_self.parse_sink()

    # Error detection atoms
    if token.type == 'ERROR':
        return parser_self.parse_error()
    if token.type == 'NULL_DEREF':
        return parser_self.parse_null_deref()
    if token.type == 'USE_AFTER_FREE':
        return parser_self.parse_use_after_free()
    if token.type == 'BUFFER_OVERFLOW':
        return parser_self.parse_buffer_overflow()

    # Otherwise, must be an atom (identifier-based)
    return parser_self.parse_atom()


def parse_atom(parser_self) -> Formula:
    """Parse atomic formulas (identifier-based)

    Args:
        parser_self: The Parser instance

    Returns:
        Parsed formula
    """
    token = parser_self.current_token()

    # Handle nil specially for comparisons
    if token.type == 'NIL':
        parser_self.advance()
        expr = Const(None)
        # Nil can only appear in comparisons in this simplified parser
        # For now, we'll return an error
        raise ParseError("nil can only appear in comparisons like 'x = nil' or 'x != nil'")

    # Must be an identifier
    name = parser_self.expect('IDENT').value
    token = parser_self.current_token()

    # Array indexing: arr[idx]
    if token and token.type == 'LBRACKET':
        parser_self.advance()  # consume '['
        index = parser_self.parse_expr()
        parser_self.expect('RBRACKET')
        arr_select = ArraySelect(Var(name), index)

        # Must be followed by comparison
        token = parser_self.current_token()
        if token and token.type in ('EQ', 'NEQ', 'LT', 'LE', 'GT', 'GE'):
            op = token.type
            parser_self.advance()
            right = parser_self.parse_expr()

            if op == 'EQ':
                return Eq(arr_select, right)
            elif op == 'NEQ':
                return Neq(arr_select, right)
            elif op == 'LT':
                return Lt(arr_select, right)
            elif op == 'LE':
                return Le(arr_select, right)
            elif op == 'GT':
                return Gt(arr_select, right)
            elif op == 'GE':
                return Ge(arr_select, right)
        else:
            raise ParseError(f"Array indexing must be followed by comparison operator")

    # Predicate call: pred(args)
    if token and token.type == 'LPAREN':
        parser_self.advance()
        args = parser_self.parse_expr_list()
        parser_self.expect('RPAREN')
        return PredicateCall(name, args)

    # Points-to: x |-> y
    if token and token.type == 'ARROW':
        parser_self.advance()
        location = Var(name)
        values = parser_self.parse_pointsto_values()
        return PointsTo(location, values)

    # Equality, disequality, or comparisons: x = y, x != y, x < y, x <= y, x > y, x >= y
    if token and token.type in ('EQ', 'NEQ', 'LT', 'LE', 'GT', 'GE'):
        op = token.type
        parser_self.advance()
        left = Var(name)
        right = parser_self.parse_expr()

        if op == 'EQ':
            return Eq(left, right)
        elif op == 'NEQ':
            return Neq(left, right)
        elif op == 'LT':
            return Lt(left, right)
        elif op == 'LE':
            return Le(left, right)
        elif op == 'GT':
            return Gt(left, right)
        elif op == 'GE':
            return Ge(left, right)

    # String contains: x contains y
    if token and token.type == 'CONTAINS':
        parser_self.advance()
        left = Var(name)
        right = parser_self.parse_expr()
        return StrContains(left, right)

    # String matches: x matches /regex/
    if token and token.type == 'MATCHES':
        parser_self.advance()
        regex_token = parser_self.expect('REGEX')
        # Remove slashes from /pattern/
        regex = regex_token.value[1:-1]
        return StrMatches(Var(name), regex)

    # Just a variable in a pure context - this is a problem
    raise ParseError(f"Unexpected variable {name} without operator (expected |-> , =, !=, contains, matches, or function call)")


def parse_primary_expr(parser_self) -> Expr:
    """Parse primary expressions

    Args:
        parser_self: The Parser instance

    Returns:
        Parsed expression
    """
    token = parser_self.current_token()

    if not token:
        raise ParseError("Unexpected end of input in expression")

    # Number literal
    if token.type == 'NUMBER':
        value = int(token.value)
        parser_self.advance()
        return Const(value)

    # String literal
    if token.type == 'STRING':
        value = token.value[1:-1]  # Remove quotes
        # Unescape common sequences
        value = value.replace('\\n', '\n').replace('\\t', '\t').replace('\\\\', '\\').replace('\\"', '"')
        parser_self.advance()
        return StrLiteral(value)

    # BitVector literal: 0bxNNNN where x is binary/hex and NNNN is width
    if token.type == 'BITVEC_LITERAL':
        parser_self.advance()
        return BitVecVal(token.value, token.width)

    # Nil
    if token.type == 'NIL':
        parser_self.advance()
        return Const(None)

    # Parenthesized expression
    if token.type == 'LPAREN':
        parser_self.advance()
        expr = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return expr

    # String length: len(x)
    if token.type == 'LEN':
        return parser_self.parse_str_len()

    # String substring: substr(x, start, len)
    if token.type == 'SUBSTR':
        return parser_self.parse_str_substr()

    # String contains: contains(s, sub)
    if token.type == 'CONTAINS':
        return parser_self.parse_str_contains()

    # String matches: matches(s, pattern)
    if token.type == 'MATCHES':
        return parser_self.parse_str_matches()

    # Array select: select(arr, idx)
    if token.type == 'SELECT':
        return parser_self.parse_array_select()

    # Array store: store(arr, idx, val)
    if token.type == 'STORE':
        parser_self.advance()
        parser_self.expect('LPAREN')
        arr = parser_self.parse_expr()
        parser_self.expect('COMMA')
        index = parser_self.parse_expr()
        parser_self.expect('COMMA')
        value = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return ArrayStore(arr, index, value)

    # Bitvector operations
    if token.type in ('BVNOT', 'BVNEG'):
        op = token.type
        parser_self.advance()
        parser_self.expect('LPAREN')
        operand = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        if op == 'BVNOT':
            return BitVecExpr("bvnot", [operand])
        else:  # BVNEG
            return BitVecExpr("bvneg", [operand])

    # Bitvector concat: bvconcat(x, y)
    if token.type == 'BVCONCAT':
        parser_self.advance()
        parser_self.expect('LPAREN')
        left = parser_self.parse_expr()
        parser_self.expect('COMMA')
        right = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return BitVecExpr("bvconcat", [left, right])

    # Bitvector extract: bvextract(x, high, low)
    if token.type == 'BVEXTRACT':
        parser_self.advance()
        parser_self.expect('LPAREN')
        bv = parser_self.parse_expr()
        parser_self.expect('COMMA')
        high_token = parser_self.expect('NUMBER')
        high = int(high_token.value)
        parser_self.expect('COMMA')
        low_token = parser_self.expect('NUMBER')
        low = int(low_token.value)
        parser_self.expect('RPAREN')
        # bvextract stores high/low as metadata, not operands
        # For now, create a simple wrapper - the encoder will handle it
        result = BitVecExpr("bvextract", [bv])
        result.high = high
        result.low = low
        return result

    # Variable or identifier
    if token.type == 'IDENT':
        name = token.value
        parser_self.advance()
        return Var(name)

    raise ParseError(f"Unexpected token in expression: {token}")


def parse_bv_op(parser_self) -> Formula:
    """Parse bitvector comparison operations

    Args:
        parser_self: The Parser instance

    Returns:
        Parsed formula
    """
    token = parser_self.current_token()

    if token.type == 'BVULT':
        parser_self.advance()
        parser_self.expect('LPAREN')
        left = parser_self.parse_expr()
        parser_self.expect('COMMA')
        right = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return BitVecExpr("bvult", [left, right])
    elif token.type == 'BVULE':
        parser_self.advance()
        parser_self.expect('LPAREN')
        left = parser_self.parse_expr()
        parser_self.expect('COMMA')
        right = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return BitVecExpr("bvule", [left, right])
    elif token.type == 'BVUGT':
        parser_self.advance()
        parser_self.expect('LPAREN')
        left = parser_self.parse_expr()
        parser_self.expect('COMMA')
        right = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return BitVecExpr("bvugt", [left, right])
    elif token.type == 'BVUGE':
        parser_self.advance()
        parser_self.expect('LPAREN')
        left = parser_self.parse_expr()
        parser_self.expect('COMMA')
        right = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return BitVecExpr("bvuge", [left, right])
    elif token.type == 'BVSLT':
        parser_self.advance()
        parser_self.expect('LPAREN')
        left = parser_self.parse_expr()
        parser_self.expect('COMMA')
        right = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return BitVecExpr("bvslt", [left, right])
    elif token.type == 'BVSLE':
        parser_self.advance()
        parser_self.expect('LPAREN')
        left = parser_self.parse_expr()
        parser_self.expect('COMMA')
        right = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return BitVecExpr("bvsle", [left, right])
    elif token.type == 'BVSGT':
        parser_self.advance()
        parser_self.expect('LPAREN')
        left = parser_self.parse_expr()
        parser_self.expect('COMMA')
        right = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return BitVecExpr("bvsgt", [left, right])
    elif token.type == 'BVSGE':
        parser_self.advance()
        parser_self.expect('LPAREN')
        left = parser_self.parse_expr()
        parser_self.expect('COMMA')
        right = parser_self.parse_expr()
        parser_self.expect('RPAREN')
        return BitVecExpr("bvsge", [left, right])
    else:
        raise ParseError(f"Unknown bitvector comparison operator: {token}")
