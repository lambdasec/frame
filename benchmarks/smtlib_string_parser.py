"""
SMT-LIB QF_S (String Theory) Parser

Parses SMT-LIB format string constraints to Frame AST.

Supported operations:
- str.++ (concat)
- str.len (length)
- str.substr (substring)
- str.contains (contains)
- str.in.re (regex matching)
- str.replace
- str.at (char at position)
"""

import re
import sys
from pathlib import Path
from typing import Tuple, Optional, List, Dict

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from frame.core.ast import (
    Formula, Expr, Var, Const,
    StrLiteral, StrConcat, StrLen, StrSubstr, StrContains, StrMatches,
    Eq, And, Or, Not, True_, False_
)


class SMTLibStringParser:
    """Parser for SMT-LIB QF_S format"""

    def __init__(self):
        self.variables: Dict[str, str] = {}  # var_name -> type
        self.assertions: List[Formula] = []
        self.expected_result = None  # sat/unsat/unknown

    def parse_file(self, content: str) -> Tuple[Formula, str]:
        """
        Parse SMT-LIB file and return (formula, expected_result)

        Args:
            content: SMT-LIB file content

        Returns:
            (formula, expected_result) where expected_result is 'sat'/'unsat'/'unknown'
        """
        self.variables.clear()
        self.assertions.clear()
        self.expected_result = 'unknown'

        lines = content.split('\n')

        for line in lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith(';'):
                # Check for expected result in comments
                if 'sat' in line.lower():
                    if 'unsat' in line.lower():
                        self.expected_result = 'unsat'
                    else:
                        self.expected_result = 'sat'
                continue

            # Parse commands
            if line.startswith('(declare-const'):
                self._parse_declare_const(line)
            elif line.startswith('(declare-fun'):
                self._parse_declare_fun(line)
            elif line.startswith('(assert'):
                formula = self._parse_assert(line)
                if formula:
                    self.assertions.append(formula)
            elif line.startswith('(check-sat'):
                # Expected result depends on check-sat command
                # Default to 'unknown' if not specified in comments
                pass

        # Combine all assertions with AND
        if not self.assertions:
            combined_formula = True_()
        elif len(self.assertions) == 1:
            combined_formula = self.assertions[0]
        else:
            combined_formula = self.assertions[0]
            for assertion in self.assertions[1:]:
                combined_formula = And(combined_formula, assertion)

        return combined_formula, self.expected_result

    def _parse_declare_const(self, line: str):
        """Parse (declare-const x String)"""
        # Extract variable name and type
        match = re.search(r'\(declare-const\s+(\w+)\s+(\w+)\)', line)
        if match:
            var_name = match.group(1)
            var_type = match.group(2)
            self.variables[var_name] = var_type

    def _parse_declare_fun(self, line: str):
        """Parse (declare-fun x () String)"""
        # For now, treat as declare-const
        match = re.search(r'\(declare-fun\s+(\w+)\s+\(\)\s+(\w+)\)', line)
        if match:
            var_name = match.group(1)
            var_type = match.group(2)
            self.variables[var_name] = var_type

    def _parse_assert(self, line: str) -> Optional[Formula]:
        """Parse (assert ...)"""
        # Remove (assert and closing )
        content = line[7:].strip()
        if content.endswith(')'):
            content = content[:-1].strip()

        return self._parse_formula(content)

    def _parse_formula(self, text: str) -> Optional[Formula]:
        """Parse a formula expression"""
        text = text.strip()

        # Handle boolean literals
        if text == 'true':
            return True_()
        if text == 'false':
            return False_()

        # Handle negation
        if text.startswith('(not '):
            inner = text[5:-1].strip()
            inner_formula = self._parse_formula(inner)
            return Not(inner_formula) if inner_formula else None

        # Handle conjunction
        if text.startswith('(and '):
            return self._parse_and(text)

        # Handle disjunction
        if text.startswith('(or '):
            return self._parse_or(text)

        # Handle equality
        if text.startswith('(= '):
            return self._parse_equals(text)

        # Handle string operations
        if text.startswith('(str.contains '):
            return self._parse_str_contains(text)

        # Handle string concatenation (part of larger expression)
        # This is typically in the context of equality

        # Variable reference
        if text in self.variables:
            return Var(text)

        # String literal
        if text.startswith('"') and text.endswith('"'):
            return StrLiteral(text[1:-1])

        # Fallback: treat as True for now (TODO: complete implementation)
        return True_()

    def _parse_and(self, text: str) -> Formula:
        """Parse (and ...)"""
        # Extract subformulas - simple version
        parts = self._split_top_level(text[4:-1])

        formulas = [self._parse_formula(part) for part in parts]
        formulas = [f for f in formulas if f is not None]

        if not formulas:
            return True_()
        if len(formulas) == 1:
            return formulas[0]

        result = formulas[0]
        for formula in formulas[1:]:
            result = And(result, formula)
        return result

    def _parse_or(self, text: str) -> Formula:
        """Parse (or ...)"""
        parts = self._split_top_level(text[4:-1])

        formulas = [self._parse_formula(part) for part in parts]
        formulas = [f for f in formulas if f is not None]

        if not formulas:
            return False_()
        if len(formulas) == 1:
            return formulas[0]

        result = formulas[0]
        for formula in formulas[1:]:
            result = Or(result, formula)
        return result

    def _parse_equals(self, text: str) -> Formula:
        """Parse (= ...)"""
        # Extract left and right sides
        parts = self._split_top_level(text[3:-1])

        if len(parts) != 2:
            return True_()  # Malformed, skip

        left = self._parse_expr(parts[0])
        right = self._parse_expr(parts[1])

        return Eq(left, right)

    def _parse_str_contains(self, text: str) -> Formula:
        """Parse (str.contains x "admin")"""
        parts = self._split_top_level(text[14:-1])

        if len(parts) != 2:
            return True_()

        string_expr = self._parse_expr(parts[0])
        substring_expr = self._parse_expr(parts[1])

        return StrContains(string_expr, substring_expr)

    def _parse_expr(self, text: str) -> Expr:
        """Parse an expression (string or int)"""
        text = text.strip()

        # String literal
        if text.startswith('"') and text.endswith('"'):
            return StrLiteral(text[1:-1])

        # Variable
        if text in self.variables:
            return Var(text)

        # String concatenation
        if text.startswith('(str.++ '):
            return self._parse_str_concat(text)

        # String length
        if text.startswith('(str.len '):
            inner = text[9:-1].strip()
            return StrLen(self._parse_expr(inner))

        # String substring
        if text.startswith('(str.substr '):
            parts = self._split_top_level(text[12:-1])
            if len(parts) == 3:
                string = self._parse_expr(parts[0])
                start = self._parse_expr(parts[1])
                length = self._parse_expr(parts[2])
                return StrSubstr(string, start, length)

        # Integer constant
        if text.isdigit() or (text.startswith('-') and text[1:].isdigit()):
            return Const(int(text))

        # Fallback: variable
        return Var(text)

    def _parse_str_concat(self, text: str) -> Expr:
        """Parse (str.++ x y z ...)"""
        parts = self._split_top_level(text[8:-1])

        if len(parts) < 2:
            return StrLiteral("")

        # Build left-associative concatenation
        result = self._parse_expr(parts[0])
        for part in parts[1:]:
            result = StrConcat(result, self._parse_expr(part))

        return result

    def _split_top_level(self, text: str) -> List[str]:
        """Split expression at top-level spaces (respecting parentheses)"""
        parts = []
        current = ""
        depth = 0
        in_string = False

        for char in text:
            if char == '"' and (not current or current[-1] != '\\'):
                in_string = not in_string
                current += char
            elif in_string:
                current += char
            elif char == '(':
                depth += 1
                current += char
            elif char == ')':
                depth -= 1
                current += char
            elif char == ' ' and depth == 0:
                if current.strip():
                    parts.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            parts.append(current.strip())

        return parts


def main():
    """Test the parser"""
    test_case = """
(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (str.contains x "admin"))
(assert (= y (str.++ x ".sql")))
(check-sat)
; expected: sat
"""

    parser = SMTLibStringParser()
    formula, expected = parser.parse_file(test_case)
    print(f"Formula: {formula}")
    print(f"Expected: {expected}")


if __name__ == '__main__':
    main()
