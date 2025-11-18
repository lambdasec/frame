"""
SMT-LIB Parser for QF_AX (Arrays) and QF_BV (Bitvectors)

Parses SMT-LIB format benchmarks to Frame AST.

Supported:
- QF_AX: Array operations (select, store), equality
- QF_BV: Bitvector operations (bvadd, bvand, etc.), literals
- Basic: declare-const, assert, check-sat
"""

import re
import sys
from pathlib import Path
from typing import Tuple, Optional, List, Dict, Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from frame.core.ast import (
    Formula, Expr, Var, Const,
    ArraySelect, ArrayStore, ArrayConst,
    BitVecVal, BitVecExpr,
    Eq, Neq, And, Or, Not, True_, False_, Lt, Le, Gt, Ge
)


class SMTLibParser:
    """Parser for SMT-LIB format (QF_AX, QF_BV)"""

    def __init__(self):
        self.variables: Dict[str, str] = {}  # var_name -> type
        self.assertions: List[Formula] = []
        self.expected_result = None  # sat/unsat/unknown
        self.logic = None  # QF_AX, QF_BV, etc.

    def parse_file(self, content: str) -> Tuple[Formula, str, str]:
        """
        Parse SMT-LIB file and return (formula, expected_result, logic)

        Args:
            content: SMT-LIB file content

        Returns:
            (formula, expected_result, logic) tuple
        """
        self.variables = {}
        self.assertions = []
        self.expected_result = None
        self.logic = None

        lines = content.split('\n')

        for line in lines:
            line = line.strip()

            # Extract expected result from comments
            if line.startswith(';'):
                if 'expected:' in line.lower():
                    result_match = re.search(r'expected:\s*(sat|unsat|unknown)', line.lower())
                    if result_match:
                        self.expected_result = result_match.group(1)
                continue

            # Parse set-logic
            if line.startswith('(set-logic'):
                logic_match = re.search(r'\(set-logic\s+(\w+)\)', line)
                if logic_match:
                    self.logic = logic_match.group(1)
                continue

            # Parse variable declarations
            if line.startswith('(declare-const'):
                self._parse_declaration(line)
                continue

            # Parse assertions
            if line.startswith('(assert'):
                try:
                    formula = self._parse_assertion(line)
                    if formula:
                        self.assertions.append(formula)
                except Exception as e:
                    # Skip unparseable assertions for now
                    pass
                continue

            # Parse check-sat
            if line.startswith('(check-sat'):
                continue

        # Combine all assertions
        if not self.assertions:
            formula = True_()
        elif len(self.assertions) == 1:
            formula = self.assertions[0]
        else:
            formula = self.assertions[0]
            for assertion in self.assertions[1:]:
                formula = And(formula, assertion)

        return formula, self.expected_result or 'unknown', self.logic or 'UNKNOWN'

    def _parse_declaration(self, line: str):
        """Parse (declare-const var type) declaration"""
        # Extract variable name and type
        match = re.search(r'\(declare-const\s+(\S+)\s+(.+)\)', line)
        if match:
            var_name = match.group(1)
            var_type = match.group(2).strip()
            self.variables[var_name] = var_type

    def _parse_assertion(self, line: str) -> Optional[Formula]:
        """Parse (assert formula) assertion"""
        # Remove (assert ...) wrapper
        match = re.search(r'\(assert\s+(.+)\)\s*$', line)
        if not match:
            return None

        formula_str = match.group(1)
        return self._parse_formula(formula_str)

    def _parse_formula(self, s: str) -> Formula:
        """Parse a formula expression"""
        s = s.strip()

        # Boolean literals
        if s == 'true':
            return True_()
        if s == 'false':
            return False_()

        # S-expression
        if s.startswith('('):
            return self._parse_sexp(s)

        # Variable or constant
        if s.isdigit() or (s.startswith('-') and s[1:].isdigit()):
            return Const(int(s))
        else:
            return Var(s)

    def _parse_sexp(self, s: str) -> Formula:
        """Parse S-expression"""
        s = s.strip()
        if not s.startswith('(') or not s.endswith(')'):
            raise ValueError(f"Invalid S-expression: {s}")

        # Remove outer parens
        inner = s[1:-1].strip()

        # Split by whitespace, handling nested parens
        tokens = self._tokenize(inner)
        if not tokens:
            raise ValueError(f"Empty S-expression: {s}")

        op = tokens[0]

        # Logical operators
        if op == 'and':
            formulas = [self._parse_formula(t) for t in tokens[1:]]
            result = formulas[0]
            for f in formulas[1:]:
                result = And(result, f)
            return result

        if op == 'or':
            formulas = [self._parse_formula(t) for t in tokens[1:]]
            result = formulas[0]
            for f in formulas[1:]:
                result = Or(result, f)
            return result

        if op == 'not':
            return Not(self._parse_formula(tokens[1]))

        # Comparison operators
        if op == '=':
            left = self._parse_expr(tokens[1])
            right = self._parse_expr(tokens[2])
            return Eq(left, right)

        if op == 'distinct':
            # (distinct x y) = (not (= x y))
            left = self._parse_expr(tokens[1])
            right = self._parse_expr(tokens[2])
            return Neq(left, right)

        if op == '<':
            left = self._parse_expr(tokens[1])
            right = self._parse_expr(tokens[2])
            return Lt(left, right)

        if op == '<=':
            left = self._parse_expr(tokens[1])
            right = self._parse_expr(tokens[2])
            return Le(left, right)

        if op == '>':
            left = self._parse_expr(tokens[1])
            right = self._parse_expr(tokens[2])
            return Gt(left, right)

        if op == '>=':
            left = self._parse_expr(tokens[1])
            right = self._parse_expr(tokens[2])
            return Ge(left, right)

        # Try to parse as expression and wrap in equality
        expr = self._parse_expr(s)
        # For boolean expressions in QF_BV (bvult, etc.)
        return expr if isinstance(expr, Formula) else Eq(expr, Const(1))

    def _parse_expr(self, s: str) -> Expr:
        """Parse an expression"""
        s = s.strip()

        # Constants
        if s.isdigit() or (s.startswith('-') and s[1:].isdigit()):
            return Const(int(s))

        # Bitvector hex literals: #xAB
        if s.startswith('#x'):
            hex_str = s[2:]
            value = int(hex_str, 16)
            width = len(hex_str) * 4
            return BitVecVal(value, width)

        # Bitvector binary literals: #b1010
        if s.startswith('#b'):
            bin_str = s[2:]
            value = int(bin_str, 2)
            width = len(bin_str)
            return BitVecVal(value, width)

        # S-expression
        if s.startswith('('):
            return self._parse_expr_sexp(s)

        # Variable
        return Var(s)

    def _parse_expr_sexp(self, s: str) -> Expr:
        """Parse expression S-expression"""
        s = s.strip()
        if not s.startswith('(') or not s.endswith(')'):
            raise ValueError(f"Invalid S-expression: {s}")

        # Remove outer parens
        inner = s[1:-1].strip()
        tokens = self._tokenize(inner)
        if not tokens:
            raise ValueError(f"Empty S-expression: {s}")

        op = tokens[0]

        # Array operations
        if op == 'select':
            array = self._parse_expr(tokens[1])
            index = self._parse_expr(tokens[2])
            return ArraySelect(array, index)

        if op == 'store':
            array = self._parse_expr(tokens[1])
            index = self._parse_expr(tokens[2])
            value = self._parse_expr(tokens[3])
            return ArrayStore(array, index, value)

        # Constant array: ((as const (Array Int Int)) 0)
        if op == 'as' and len(tokens) >= 4 and tokens[1] == 'const':
            default_val = self._parse_expr(tokens[-1]) if len(tokens) > 3 else Const(0)
            return ArrayConst(default_val)

        # Bitvector operations
        if op.startswith('bv'):
            operands = [self._parse_expr(t) for t in tokens[1:]]
            width = 32  # Default width, should infer from operands
            return BitVecExpr(op, operands, width)

        # Arithmetic
        if op == '+':
            left = self._parse_expr(tokens[1])
            right = self._parse_expr(tokens[2])
            from frame.core.ast import ArithExpr
            return ArithExpr('+', left, right)

        if op == '-':
            left = self._parse_expr(tokens[1])
            right = self._parse_expr(tokens[2])
            from frame.core.ast import ArithExpr
            return ArithExpr('-', left, right)

        if op == '*':
            left = self._parse_expr(tokens[1])
            right = self._parse_expr(tokens[2])
            from frame.core.ast import ArithExpr
            return ArithExpr('*', left, right)

        # Bitvector literals with explicit width: (_ BitVec 8)
        if op == '_' and len(tokens) >= 3:
            return self._parse_expr(tokens[1])

        # Default: return as variable (will fail later if not supported)
        return Var(s)

    def _tokenize(self, s: str) -> List[str]:
        """Tokenize S-expression, handling nested parens"""
        tokens = []
        current = []
        depth = 0

        for char in s:
            if char == '(':
                depth += 1
                current.append(char)
            elif char == ')':
                depth -= 1
                current.append(char)
            elif char.isspace() and depth == 0:
                if current:
                    tokens.append(''.join(current))
                    current = []
            else:
                current.append(char)

        if current:
            tokens.append(''.join(current))

        return tokens


# Convenience function
def parse_smtlib_file(filepath: str) -> Tuple[Formula, str, str]:
    """Parse SMT-LIB file and return (formula, expected_result, logic)"""
    with open(filepath, 'r') as f:
        content = f.read()
    parser = SMTLibParser()
    return parser.parse_file(content)
