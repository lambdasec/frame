"""
Parser for Separation Logic Formulas

A simple parser for parsing separation logic formulas from strings.
Supports basic syntax for practical use.

Syntax:
    - emp: empty heap
    - x |-> y: points-to (single field)
    - x |-> (y, z): points-to (multiple fields)
    - P * Q: separating conjunction
    - P & Q: logical conjunction
    - P | Q: logical disjunction
    - !P: negation
    - x = y: equality
    - x != y: disequality
    - true, false: boolean literals
    - nil: null pointer
    - exists x. P: existential quantification
    - forall x. P: universal quantification
    - ls(x, y): list segment
    - list(x): linked list
    - tree(x): binary tree
"""

import re
from typing import List, Optional, Tuple
from frame.core.ast import *
from frame.core._lexer import Lexer, Token, ParseError
from frame.core import _parser_helpers


class Parser:
    """Parser for separation logic formulas"""

    def __init__(self, text: str):
        self.lexer = Lexer(text)
        self.tokens = self.lexer.tokens
        self.pos = 0

    def current_token(self) -> Optional[Token]:
        """Get the current token"""
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def advance(self):
        """Move to the next token"""
        self.pos += 1

    def expect(self, token_type: str) -> Token:
        """Expect a specific token type"""
        token = self.current_token()
        if token is None:
            raise ParseError(f"Expected {token_type}, got EOF")
        if token.type != token_type:
            raise ParseError(f"Expected {token_type}, got {token.type} at position {token.pos}")
        self.advance()
        return token

    def parse(self) -> Formula:
        """Parse a formula"""
        return self.parse_or()

    def parse_or(self) -> Formula:
        """Parse disjunction: P | Q"""
        left = self.parse_and()

        while self.current_token() and self.current_token().type == 'OR':
            self.advance()
            right = self.parse_and()
            left = Or(left, right)

        return left

    def parse_and(self) -> Formula:
        """Parse conjunction: P & Q"""
        left = self.parse_sepconj()

        while self.current_token() and self.current_token().type == 'AND':
            self.advance()
            right = self.parse_sepconj()
            left = And(left, right)

        return left

    def parse_sepconj(self) -> Formula:
        """Parse separating conjunction: P * Q"""
        left = self.parse_unary()

        while self.current_token() and self.current_token().type == 'SEPCONJ':
            self.advance()
            right = self.parse_unary()
            left = SepConj(left, right)

        return left

    def parse_unary(self) -> Formula:
        """Parse unary operators: !P, exists x. P, forall x. P"""
        token = self.current_token()

        if token and token.type == 'NOT':
            self.advance()
            formula = self.parse_unary()
            return Not(formula)

        if token and token.type == 'EXISTS':
            self.advance()
            var = self.expect('IDENT').value
            self.expect('DOT')
            formula = self.parse()
            return Exists(var, formula)

        if token and token.type == 'FORALL':
            self.advance()
            var = self.expect('IDENT').value
            self.expect('DOT')
            formula = self.parse()
            return Forall(var, formula)

        return self.parse_primary()

    def parse_primary(self) -> Formula:
        """Delegate to parser helpers"""
        return _parser_helpers.parse_primary(self)

    def parse_string_atom(self) -> Formula:
        """Parse formulas starting with string literals"""
        token = self.expect('STRING')
        # Remove quotes and handle escape sequences
        value = token.value[1:-1]
        value = value.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace('\\\\', '\\')
        str_literal = StrLiteral(value)

        token = self.current_token()
        if not token:
            raise ParseError("Unexpected EOF after string literal")

        # String comparisons
        if token.type in ('EQ', 'NEQ'):
            op = token.type
            self.advance()
            right = self.parse_expr()
            if op == 'EQ':
                return Eq(str_literal, right)
            elif op == 'NEQ':
                return Neq(str_literal, right)

        # String contains
        if token.type == 'CONTAINS':
            self.advance()
            needle = self.parse_expr()
            return StrContains(str_literal, needle)

        # String matches
        if token.type == 'MATCHES':
            self.advance()
            regex_token = self.expect('REGEX')
            # Remove slashes from /pattern/
            regex = regex_token.value[1:-1]
            return StrMatches(str_literal, regex)

        raise ParseError(f"Unexpected token after string literal: {token}")

    def parse_array_bv_atom(self) -> Formula:
        """Parse formulas starting with array/bitvector operations"""
        # Parse the expression (array/bitvector operation)
        expr = self.parse_expr()

        token = self.current_token()
        if not token:
            raise ParseError("Unexpected EOF after array/bitvector operation")

        # Array/bitvector operations must be in comparisons
        if token.type in ('EQ', 'NEQ', 'LT', 'LE', 'GT', 'GE'):
            op = token.type
            self.advance()
            right = self.parse_expr()

            if op == 'EQ':
                return Eq(expr, right)
            elif op == 'NEQ':
                return Neq(expr, right)
            elif op == 'LT':
                return Lt(expr, right)
            elif op == 'LE':
                return Le(expr, right)
            elif op == 'GT':
                return Gt(expr, right)
            elif op == 'GE':
                return Ge(expr, right)

        raise ParseError(f"Unexpected token after array/bitvector operation: {token}")

    def parse_atom(self) -> Formula:
        """Delegate to parser helpers"""
        return _parser_helpers.parse_atom(self)

    def parse_pointsto_values(self) -> List[Expr]:
        """Parse values in points-to: y or (y, z, ...)"""
        token = self.current_token()

        if token and token.type == 'LPAREN':
            # Multiple values: (y, z, ...)
            self.advance()
            values = self.parse_expr_list()
            self.expect('RPAREN')
            return values
        else:
            # Single value: y
            return [self.parse_expr()]

    def parse_expr_list(self) -> List[Expr]:
        """Parse comma-separated list of expressions"""
        exprs = [self.parse_expr()]

        while self.current_token() and self.current_token().type == 'COMMA':
            self.advance()
            exprs.append(self.parse_expr())

        return exprs

    def parse_expr(self) -> Expr:
        """Parse an expression with arithmetic and string operators"""
        return self.parse_concat()

    def parse_concat(self) -> Expr:
        """Parse string concatenation: e1 ++ e2"""
        left = self.parse_additive()

        while self.current_token() and self.current_token().type == 'CONCAT':
            self.advance()
            right = self.parse_additive()
            left = StrConcat(left, right)

        return left

    def parse_additive(self) -> Expr:
        """Parse additive expression: e1 + e2 or e1 - e2"""
        left = self.parse_primary_expr()

        while self.current_token() and self.current_token().type in ('PLUS', 'MINUS'):
            op_token = self.current_token()
            self.advance()
            right = self.parse_primary_expr()

            from frame.core.ast import ArithExpr
            op = '+' if op_token.type == 'PLUS' else '-'
            left = ArithExpr(op, left, right)

        return left
    def parse_primary_expr(self) -> Expr:
        """Delegate to parser helpers"""
        return _parser_helpers.parse_primary_expr(self)

    # String function parsing

    def parse_str_len(self) -> Expr:
        """Parse len(s) function"""
        self.expect('LEN')
        self.expect('LPAREN')
        string = self.parse_expr()
        self.expect('RPAREN')
        return StrLen(string)

    def parse_str_substr(self) -> Expr:
        """Parse substr(s, start, end) function"""
        self.expect('SUBSTR')
        self.expect('LPAREN')
        string = self.parse_expr()
        self.expect('COMMA')
        start = self.parse_expr()
        self.expect('COMMA')
        end = self.parse_expr()
        self.expect('RPAREN')
        return StrSubstr(string, start, end)

    # Security predicate parsing

    def parse_taint(self) -> Formula:
        """Parse taint(x) predicate"""
        self.expect('TAINT')
        self.expect('LPAREN')
        var = self.parse_expr()
        self.expect('RPAREN')
        return Taint(var)

    def parse_sanitized(self) -> Formula:
        """Parse sanitized(x) predicate"""
        self.expect('SANITIZED')
        self.expect('LPAREN')
        var = self.parse_expr()
        self.expect('RPAREN')
        return Sanitized(var)

    def parse_source(self) -> Formula:
        """Parse source(x, "type") predicate"""
        self.expect('SOURCE')
        self.expect('LPAREN')
        var = self.parse_expr()
        self.expect('COMMA')
        source_type_token = self.expect('STRING')
        # Remove quotes from string
        source_type = source_type_token.value[1:-1]
        self.expect('RPAREN')
        return Source(var, source_type)

    def parse_sink(self) -> Formula:
        """Parse sink(x, "type") predicate"""
        self.expect('SINK')
        self.expect('LPAREN')
        var = self.parse_expr()
        self.expect('COMMA')
        sink_type_token = self.expect('STRING')
        # Remove quotes from string
        sink_type = sink_type_token.value[1:-1]
        self.expect('RPAREN')
        return Sink(var, sink_type)

    # Error state parsing

    def parse_error(self) -> Formula:
        """Parse error() or error("kind") predicate"""
        self.expect('ERROR')
        self.expect('LPAREN')

        # Check if there's a kind argument
        if self.current_token() and self.current_token().type == 'STRING':
            kind_token = self.expect('STRING')
            kind = kind_token.value[1:-1]  # Remove quotes
            self.expect('RPAREN')
            return Error(kind=kind)
        else:
            self.expect('RPAREN')
            return Error()

    def parse_null_deref(self) -> Formula:
        """Parse null_deref(x) predicate"""
        self.expect('NULL_DEREF')
        self.expect('LPAREN')
        var = self.parse_expr()
        self.expect('RPAREN')
        return NullDeref(var)

    def parse_use_after_free(self) -> Formula:
        """Parse use_after_free(x) predicate"""
        self.expect('USE_AFTER_FREE')
        self.expect('LPAREN')
        var = self.parse_expr()
        self.expect('RPAREN')
        return UseAfterFree(var)

    def parse_buffer_overflow(self) -> Formula:
        """Parse buffer_overflow(arr, index, size) predicate"""
        self.expect('BUFFER_OVERFLOW')
        self.expect('LPAREN')
        array = self.parse_expr()
        self.expect('COMMA')
        index = self.parse_expr()
        self.expect('COMMA')
        size = self.parse_expr()
        self.expect('RPAREN')
        return BufferOverflow(array, index, size)

    # Array theory parsing

    def parse_array_select(self) -> Expr:
        """Parse select(array, index) operation"""
        self.expect('SELECT')
        self.expect('LPAREN')
        array = self.parse_expr()
        self.expect('COMMA')
        index = self.parse_expr()
        self.expect('RPAREN')
        return ArraySelect(array, index)

    def parse_array_store(self) -> Expr:
        """Parse store(array, index, value) operation"""
        self.expect('STORE')
        self.expect('LPAREN')
        array = self.parse_expr()
        self.expect('COMMA')
        index = self.parse_expr()
        self.expect('COMMA')
        value = self.parse_expr()
        self.expect('RPAREN')
        return ArrayStore(array, index, value)

    def parse_array_const(self) -> Expr:
        """Parse const(default_value) operation"""
        self.expect('CONST')
        self.expect('LPAREN')
        default = self.parse_expr()
        self.expect('RPAREN')
        return ArrayConst(default)

    # Bitvector theory parsing

    def parse_bv_hex(self) -> Expr:
        """Parse bitvector hex literal: #x0F"""
        token = self.expect('BVHEX')
        # Extract hex value (skip #x prefix)
        hex_str = token.value[2:]
        value = int(hex_str, 16)
        # Width is 4 bits per hex digit
        width = len(hex_str) * 4
        return BitVecVal(value, width)

    def parse_bv_bin(self) -> Expr:
        """Parse bitvector binary literal: #b1010"""
        token = self.expect('BVBIN')
        # Extract binary value (skip #b prefix)
        bin_str = token.value[2:]
        value = int(bin_str, 2)
        # Width is number of bits
        width = len(bin_str)
        return BitVecVal(value, width)
    def parse_bv_op(self) -> Formula:
        """Delegate to parser helpers"""
        return _parser_helpers.parse_bv_op(self)


# Module-level parsing functions

def parse(text: str) -> Formula:
    """
    Parse a separation logic formula from a string.

    Args:
        text: String representation of the formula

    Returns:
        Parsed Formula object

    Example:
        >>> parse("x |-> 5 * y |-> 3")
        SepConj(PointsTo(x, [5]), PointsTo(y, [3]))
    """
    parser = Parser(text)
    return parser.parse()


def parse_entailment(text: str) -> Tuple[Formula, Formula]:
    """
    Parse an entailment from a string with turnstile |-

    Args:
        text: String representation of the entailment (e.g., "P |- Q")

    Returns:
        Tuple of (antecedent, consequent) Formula objects

    Example:
        >>> ante, cons = parse_entailment("x |-> 5 * y |-> 3 |- x |-> 5")
        >>> # ante = SepConj(PointsTo(x, [5]), PointsTo(y, [3]))
        >>> # cons = PointsTo(x, [5])
    """
    # Find the turnstile symbol (|- not followed by >)
    # We need to distinguish |- (turnstile) from |-> (points-to arrow)
    import re

    # Find all occurrences of |- that are NOT followed by >
    pattern = r'\|-(?!>)'
    matches = list(re.finditer(pattern, text))

    if len(matches) == 0:
        raise ParseError("Entailment must contain '|-' symbol (turnstile). Use parse() for single formulas.")

    if len(matches) > 1:
        raise ParseError("Entailment must have exactly one '|-' turnstile symbol")

    # Split at the turnstile position
    match = matches[0]
    turnstile_pos = match.start()

    antecedent_text = text[:turnstile_pos].strip()
    consequent_text = text[turnstile_pos + 2:].strip()  # +2 to skip '|-'

    if not antecedent_text:
        raise ParseError("Antecedent (left side of |-) cannot be empty")
    if not consequent_text:
        raise ParseError("Consequent (right side of |-) cannot be empty")

    antecedent = parse(antecedent_text)
    consequent = parse(consequent_text)

    return antecedent, consequent
