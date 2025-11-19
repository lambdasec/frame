"""
Lexical Analyzer for Separation Logic Formulas

Tokenizes input strings for the parser.
Extracted from parser.py to improve modularity.
"""

import re
from typing import List


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
