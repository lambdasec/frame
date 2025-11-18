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


class ParseError(Exception):
    """Exception raised for parsing errors"""
    pass


class Token:
    """Token in the input stream"""

    def __init__(self, type: str, value: str, pos: int):
        self.type = type
        self.value = value
        self.pos = pos

    def __repr__(self):
        return f"Token({self.type}, {self.value!r}, {self.pos})"


class Lexer:
    """Lexical analyzer for separation logic formulas"""

    TOKEN_PATTERNS = [
        ('STRING', r'"([^"\\]|\\.)*"'),  # String literals with escape support
        ('REGEX', r'/([^/\\]|\\.)+/'),  # Regex patterns like /pattern/
        ('BVHEX', r'#x[0-9a-fA-F]+'),  # Bitvector hex literal: #x0F
        ('BVBIN', r'#b[01]+'),  # Bitvector binary literal: #b1010
        ('ARROW', r'\|->'),
        ('CONCAT', r'\+\+'),  # Must come before PLUS
        ('LE', r'<='),
        ('GE', r'>='),
        ('LT', r'<'),
        ('GT', r'>'),
        ('PLUS', r'\+'),
        ('MINUS', r'-'),
        ('SEPCONJ', r'\*'),
        ('AND', r'&'),
        ('OR', r'\|'),
        ('NOT', r'!'),
        ('EQ', r'==?'),
        ('NEQ', r'!='),
        ('LPAREN', r'\('),
        ('RPAREN', r'\)'),
        ('LBRACKET', r'\['),
        ('RBRACKET', r'\]'),
        ('COMMA', r','),
        ('DOT', r'\.'),
        # Keywords (order matters - more specific first)
        # Array operations (with word boundaries to avoid matching prefixes)
        ('SELECT', r'select\b'),
        ('STORE', r'store\b'),
        ('CONST', r'const\b'),
        # Bitvector operations (alphabetical for easier maintenance)
        ('BVADD', r'bvadd'),
        ('BVAND', r'bvand'),
        ('BVASHR', r'bvashr'),
        ('BVLSHR', r'bvlshr'),
        ('BVMUL', r'bvmul'),
        ('BVNOT', r'bvnot'),
        ('BVOR', r'bvor'),
        ('BVSDIV', r'bvsdiv'),
        ('BVSGE', r'bvsge'),
        ('BVSGT', r'bvsgt'),
        ('BVSHL', r'bvshl'),
        ('BVSLE', r'bvsle'),
        ('BVSLT', r'bvslt'),
        ('BVSREM', r'bvsrem'),
        ('BVSUB', r'bvsub'),
        ('BVUDIV', r'bvudiv'),
        ('BVUGE', r'bvuge'),
        ('BVUGT', r'bvugt'),
        ('BVULE', r'bvule'),
        ('BVULT', r'bvult'),
        ('BVUREM', r'bvurem'),
        ('BVXOR', r'bvxor'),
        # Other keywords
        ('CONTAINS', r'contains'),
        ('MATCHES', r'matches'),
        ('EXISTS', r'exists'),
        ('FORALL', r'forall'),
        ('TAINT', r'taint'),
        ('SANITIZED', r'sanitized'),
        ('SOURCE', r'source'),
        ('SINK', r'sink'),
        ('ERROR', r'error'),
        ('NULL_DEREF', r'null_deref'),
        ('USE_AFTER_FREE', r'use_after_free'),
        ('BUFFER_OVERFLOW', r'buffer_overflow'),
        ('LEN', r'len'),
        ('SUBSTR', r'substr'),
        ('EMP', r'emp'),
        ('TRUE', r'true'),
        ('FALSE', r'false'),
        ('NIL', r'nil'),
        ('IDENT', r'[a-zA-Z_][a-zA-Z0-9_]*'),
        ('NUMBER', r'\d+'),
        ('WHITESPACE', r'\s+'),
    ]

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.tokens: List[Token] = []
        self._tokenize()

    def _tokenize(self):
        """Tokenize the input text"""
        while self.pos < len(self.text):
            matched = False
            for token_type, pattern in self.TOKEN_PATTERNS:
                regex = re.compile(pattern)
                match = regex.match(self.text, self.pos)
                if match:
                    value = match.group(0)
                    if token_type != 'WHITESPACE':
                        self.tokens.append(Token(token_type, value, self.pos))
                    self.pos = match.end()
                    matched = True
                    break

            if not matched:
                raise ParseError(f"Invalid character at position {self.pos}: {self.text[self.pos]!r}")


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
        """Parse primary formulas"""
        token = self.current_token()

        if token is None:
            raise ParseError("Unexpected EOF")

        # Parenthesized formula
        if token.type == 'LPAREN':
            self.advance()
            formula = self.parse()
            self.expect('RPAREN')
            return formula

        # emp
        if token.type == 'EMP':
            self.advance()
            return Emp()

        # true
        if token.type == 'TRUE':
            self.advance()
            return True_()

        # false
        if token.type == 'FALSE':
            self.advance()
            return False_()

        # Security predicates
        if token.type == 'TAINT':
            return self.parse_taint()

        if token.type == 'SANITIZED':
            return self.parse_sanitized()

        if token.type == 'SOURCE':
            return self.parse_source()

        if token.type == 'SINK':
            return self.parse_sink()

        # Error states
        if token.type == 'ERROR':
            return self.parse_error()

        if token.type == 'NULL_DEREF':
            return self.parse_null_deref()

        if token.type == 'USE_AFTER_FREE':
            return self.parse_use_after_free()

        if token.type == 'BUFFER_OVERFLOW':
            return self.parse_buffer_overflow()

        # String literal (can appear in comparisons)
        if token.type == 'STRING':
            return self.parse_string_atom()

        # Array/bitvector operations (can appear in comparisons)
        if token.type in ('SELECT', 'STORE', 'CONST', 'BVHEX', 'BVBIN',
                          'BVADD', 'BVSUB', 'BVMUL', 'BVUDIV', 'BVUREM', 'BVSDIV', 'BVSREM',
                          'BVAND', 'BVOR', 'BVXOR', 'BVNOT', 'BVSHL', 'BVLSHR', 'BVASHR',
                          'BVULT', 'BVULE', 'BVUGT', 'BVUGE', 'BVSLT', 'BVSLE', 'BVSGT', 'BVSGE'):
            return self.parse_array_bv_atom()

        # Identifier (could be variable, predicate call, or points-to)
        if token.type == 'IDENT' or token.type == 'NIL':
            return self.parse_atom()

        raise ParseError(f"Unexpected token: {token}")

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
        """Parse atomic formulas (identifier-based)"""
        token = self.current_token()

        # Handle nil specially for comparisons
        if token.type == 'NIL':
            self.advance()
            expr = Const(None)
            # Nil can only appear in comparisons in this simplified parser
            # For now, we'll return an error
            raise ParseError("nil can only appear in comparisons like 'x = nil' or 'x != nil'")

        # Must be an identifier
        name = self.expect('IDENT').value
        token = self.current_token()

        # Array indexing: arr[idx]
        if token and token.type == 'LBRACKET':
            self.advance()  # consume '['
            index = self.parse_expr()
            self.expect('RBRACKET')
            arr_select = ArraySelect(Var(name), index)

            # Must be followed by comparison
            token = self.current_token()
            if token and token.type in ('EQ', 'NEQ', 'LT', 'LE', 'GT', 'GE'):
                op = token.type
                self.advance()
                right = self.parse_expr()

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
            self.advance()
            args = self.parse_expr_list()
            self.expect('RPAREN')
            return PredicateCall(name, args)

        # Points-to: x |-> y
        if token and token.type == 'ARROW':
            self.advance()
            location = Var(name)
            values = self.parse_pointsto_values()
            return PointsTo(location, values)

        # Equality, disequality, or comparisons: x = y, x != y, x < y, x <= y, x > y, x >= y
        if token and token.type in ('EQ', 'NEQ', 'LT', 'LE', 'GT', 'GE'):
            op = token.type
            self.advance()
            left = Var(name)
            right = self.parse_expr()

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
            self.advance()
            left = Var(name)
            right = self.parse_expr()
            return StrContains(left, right)

        # String matches: x matches /regex/
        if token and token.type == 'MATCHES':
            self.advance()
            regex_token = self.expect('REGEX')
            # Remove slashes from /pattern/
            regex = regex_token.value[1:-1]
            return StrMatches(Var(name), regex)

        # Just a variable in a pure context - this is a problem
        raise ParseError(f"Unexpected variable {name} without operator (expected |-> , =, !=, contains, matches, or function call)")

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
        """Parse a primary expression (variable, constant, string literal, function call)"""
        token = self.current_token()

        if token is None:
            raise ParseError("Expected expression, got EOF")

        # String literal
        if token.type == 'STRING':
            self.advance()
            # Remove quotes and handle escape sequences
            value = token.value[1:-1]  # Remove surrounding quotes
            value = value.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace('\\\\', '\\')
            return StrLiteral(value)

        # String function calls
        if token.type == 'LEN':
            return self.parse_str_len()

        if token.type == 'SUBSTR':
            return self.parse_str_substr()

        # Array operations
        if token.type == 'SELECT':
            return self.parse_array_select()

        if token.type == 'STORE':
            return self.parse_array_store()

        if token.type == 'CONST':
            return self.parse_array_const()

        # Bitvector literals
        if token.type == 'BVHEX':
            return self.parse_bv_hex()

        if token.type == 'BVBIN':
            return self.parse_bv_bin()

        # Bitvector operations
        if token.type in ('BVADD', 'BVSUB', 'BVMUL', 'BVUDIV', 'BVUREM', 'BVSDIV', 'BVSREM',
                          'BVAND', 'BVOR', 'BVXOR', 'BVNOT', 'BVSHL', 'BVLSHR', 'BVASHR',
                          'BVULT', 'BVULE', 'BVUGT', 'BVUGE', 'BVSLT', 'BVSLE', 'BVSGT', 'BVSGE'):
            return self.parse_bv_op()

        # Parenthesized expression
        if token.type == 'LPAREN':
            self.advance()
            expr = self.parse_expr()
            self.expect('RPAREN')
            return expr

        if token.type == 'IDENT':
            self.advance()
            # Check for array indexing: arr[idx]
            if self.current_token() and self.current_token().type == 'LBRACKET':
                self.advance()  # consume '['
                index = self.parse_expr()
                self.expect('RBRACKET')
                return ArraySelect(Var(token.value), index)
            # Check for function call
            if self.current_token() and self.current_token().type == 'LPAREN':
                # This might be a predicate call, let the caller handle it
                # For now, just return a variable
                self.pos -= 1  # Back up
                return Var(token.value)
            return Var(token.value)

        if token.type == 'NUMBER':
            self.advance()
            return Const(int(token.value))

        if token.type == 'NIL':
            self.advance()
            return Const(None)

        raise ParseError(f"Expected expression, got {token}")

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

    def parse_bv_op(self) -> Expr:
        """Parse bitvector operations: bvadd(x, y), bvand(x, y), etc."""
        op_token = self.current_token()
        op = op_token.value  # bvadd, bvand, etc.
        self.advance()

        self.expect('LPAREN')

        # Parse operands
        operands = []
        operands.append(self.parse_expr())

        # For unary operations like bvnot, there's only one operand
        if op != 'bvnot':
            while self.current_token() and self.current_token().type == 'COMMA':
                self.advance()
                operands.append(self.parse_expr())

        self.expect('RPAREN')

        # Infer width from operands (for now, use a default or require explicit width)
        # In full SMT-LIB parser, width would be tracked via type system
        # For simplicity, we'll use a default width of 32 bits
        width = 32  # Default width

        return BitVecExpr(op, operands, width)


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
