"""
Regular Expression Parser for Z3

Converts regex patterns to Z3 regex AST for string matching.

Supported patterns:
- Character classes: [0-9], [a-z], [A-Z], [a-zA-Z0-9]
- Quantifiers: *, +, ?
- Alternation: |
- Concatenation (implicit)
- Literal characters
- Dot: . (any character)
- Anchors: ^, $ (start/end - simplified)
"""

import z3
from typing import List, Tuple


class RegexParseError(Exception):
    """Error parsing regex pattern"""
    pass


class RegexParser:
    """Parse regex patterns and convert to Z3 regex AST"""

    def __init__(self, pattern: str):
        self.pattern = pattern
        self.pos = 0

    def parse(self) -> z3.ReRef:
        """Parse the regex pattern and return Z3 regex

        Returns:
            Z3 regex expression
        """
        if not self.pattern:
            return z3.Re("")

        return self._parse_alternation()

    def _peek(self) -> str:
        """Peek at current character without consuming"""
        if self.pos < len(self.pattern):
            return self.pattern[self.pos]
        return None

    def _consume(self) -> str:
        """Consume and return current character"""
        if self.pos < len(self.pattern):
            ch = self.pattern[self.pos]
            self.pos += 1
            return ch
        return None

    def _parse_alternation(self) -> z3.ReRef:
        """Parse alternation (|)"""
        alternatives = [self._parse_concatenation()]

        while self._peek() == '|':
            self._consume()  # consume '|'
            alternatives.append(self._parse_concatenation())

        if len(alternatives) == 1:
            return alternatives[0]
        return z3.Union(*alternatives)

    def _parse_concatenation(self) -> z3.ReRef:
        """Parse concatenation (implicit)"""
        parts = []

        while True:
            ch = self._peek()
            if ch is None or ch in ['|', ')']:
                break

            parts.append(self._parse_quantified())

        if len(parts) == 0:
            return z3.Re("")
        elif len(parts) == 1:
            return parts[0]
        else:
            return z3.Concat(*parts)

    def _parse_quantified(self) -> z3.ReRef:
        """Parse quantified expression (*, +, ?)"""
        base = self._parse_atom()

        ch = self._peek()
        if ch == '*':
            self._consume()
            return z3.Star(base)
        elif ch == '+':
            self._consume()
            return z3.Plus(base)
        elif ch == '?':
            self._consume()
            return z3.Option(base)
        else:
            return base

    def _parse_atom(self) -> z3.ReRef:
        """Parse atomic regex element"""
        ch = self._peek()

        if ch is None:
            raise RegexParseError(f"Unexpected end of pattern at position {self.pos}")

        # Character class [...]
        if ch == '[':
            return self._parse_character_class()

        # Grouping (...)
        elif ch == '(':
            self._consume()  # consume '('
            result = self._parse_alternation()
            if self._peek() != ')':
                raise RegexParseError(f"Expected ')' at position {self.pos}")
            self._consume()  # consume ')'
            return result

        # Dot (any character)
        elif ch == '.':
            self._consume()
            return self._any_char()

        # Anchors (simplified - just consume them)
        elif ch == '^':
            self._consume()
            return z3.Re("")  # Start anchor - simplified to empty

        elif ch == '$':
            self._consume()
            return z3.Re("")  # End anchor - simplified to empty

        # Escape sequences
        elif ch == '\\':
            self._consume()
            escaped = self._consume()
            if escaped is None:
                raise RegexParseError(f"Incomplete escape at position {self.pos}")
            return self._parse_escape(escaped)

        # Literal character
        else:
            self._consume()
            return z3.Re(ch)

    def _parse_character_class(self) -> z3.ReRef:
        """Parse character class like [0-9], [a-zA-Z]"""
        self._consume()  # consume '['

        # Check for negation
        negated = False
        if self._peek() == '^':
            self._consume()
            negated = True
            # For now, we'll throw an error for negated classes
            raise RegexParseError(f"Negated character classes not yet supported")

        ranges = []

        while True:
            ch = self._peek()

            if ch is None:
                raise RegexParseError(f"Unclosed character class at position {self.pos}")

            if ch == ']':
                self._consume()
                break

            # Check for range (a-z)
            start_ch = self._consume()

            if self._peek() == '-':
                self._consume()  # consume '-'
                end_ch = self._peek()

                if end_ch is None or end_ch == ']':
                    # Literal '-' at end
                    ranges.append(z3.Re(start_ch))
                    ranges.append(z3.Re('-'))
                else:
                    self._consume()
                    ranges.append(z3.Range(start_ch, end_ch))
            else:
                # Single character
                ranges.append(z3.Re(start_ch))

        if len(ranges) == 0:
            return z3.Re("")
        elif len(ranges) == 1:
            return ranges[0]
        else:
            return z3.Union(*ranges)

    def _parse_escape(self, escaped: str) -> z3.ReRef:
        """Parse escape sequences"""
        # Common escape sequences
        if escaped == 'd':  # digits
            return z3.Range('0', '9')
        elif escaped == 'w':  # word characters
            return z3.Union(
                z3.Range('a', 'z'),
                z3.Range('A', 'Z'),
                z3.Range('0', '9'),
                z3.Re('_')
            )
        elif escaped == 's':  # whitespace
            return z3.Union(z3.Re(' '), z3.Re('\t'), z3.Re('\n'), z3.Re('\r'))
        elif escaped == 'n':
            return z3.Re('\n')
        elif escaped == 't':
            return z3.Re('\t')
        elif escaped == 'r':
            return z3.Re('\r')
        elif escaped == '\\':
            return z3.Re('\\')
        elif escaped in ['.', '*', '+', '?', '|', '(', ')', '[', ']', '{', '}', '^', '$']:
            # Escaped special characters
            return z3.Re(escaped)
        else:
            # Unknown escape - treat as literal
            return z3.Re(escaped)

    def _any_char(self) -> z3.ReRef:
        """Create regex for any character (.)"""
        # In Z3, we can use a union of common character ranges
        # For simplicity, use printable ASCII
        return z3.Union(
            z3.Range(' ', '~'),  # Printable ASCII
            z3.Re('\n'),
            z3.Re('\t'),
            z3.Re('\r')
        )


def parse_regex(pattern: str) -> z3.ReRef:
    """Parse a regex pattern and return Z3 regex expression

    Args:
        pattern: Regex pattern string

    Returns:
        Z3 regex expression

    Raises:
        RegexParseError: If pattern is invalid
    """
    parser = RegexParser(pattern)
    return parser.parse()
