"""
Parser for SL-COMP SMT-LIB format benchmarks

Converts SL-COMP format to Frame's internal representation
"""

import re
from typing import Dict, List, Tuple, Optional
from frame.core.ast import *

# Import internal helper modules
from benchmarks._slcomp_utils import extract_balanced_parens, split_top_level
from benchmarks._slcomp_predicates import parse_predicates
from benchmarks._slcomp_functions import parse_function_defs, expand_function_call
from benchmarks._slcomp_formulas import parse_and, parse_sep, parse_wand, parse_or, parse_not, parse_exists
from benchmarks._slcomp_terms import (
    parse_pto, parse_predicate_call, parse_expr,
    parse_equality, parse_distinct, parse_comparison
)


class SLCompParser:
    """Parser for SL-COMP SMT-LIB format"""

    # Maximum recursion depth for function expansion to prevent infinite recursion
    MAX_RECURSION_DEPTH = 3

    def __init__(self):
        self.variables: Dict[str, Var] = {}
        self.predicates: Dict[str, str] = {}  # name -> 'custom' or 'builtin' or 'parsed'
        self.predicate_arities: Dict[str, int] = {}  # name -> arity
        self.predicate_bodies: Dict[str, Tuple[List[str], Formula]] = {}  # name -> (params, body)
        self.function_defs: Dict[str, Tuple[List[str], str]] = {}  # name -> (params, body_text)
        self.logic = None
        self.status = None

    def parse_file(self, content: str, division_hint: str = None) -> Tuple[Optional[Formula], Optional[Formula], str, str, str]:
        """
        Parse SL-COMP benchmark file

        Args:
            content: The SMT-LIB file content
            division_hint: Optional division name to help determine problem type (e.g., 'qf_shls_sat')

        Returns:
            (antecedent, consequent, expected_status, problem_type, logic)

        For entailment P |- Q, the file has:
            (assert P)
            (assert (not Q))
            problem_type = 'entl'

        For satisfiability, the file has:
            (assert P)
            problem_type = 'sat'

        Logic is the SMT-LIB logic (e.g., 'QF_BSL', 'BSL', 'QF_SHLS')
        """
        lines = content.split('\n')

        # Extract metadata
        for line in lines:
            if '(set-logic' in line:
                self.logic = re.search(r'set-logic\s+(\w+)', line).group(1)
            if ':status' in line:
                match = re.search(r':status\s+(\w+)', line)
                if match:
                    self.status = match.group(1)

        # Extract variable declarations
        for line in lines:
            if '(declare-const' in line:
                match = re.search(r'declare-const\s+(\w+)', line)
                if match:
                    var_name = match.group(1)
                    self.variables[var_name] = Var(var_name)

        # Extract predicate definitions (define-fun-rec)
        pred_results = parse_predicates(content)
        self.predicates, self.predicate_arities, self.predicate_bodies, _ = pred_results

        # Extract function definitions (define-fun)
        self.function_defs = parse_function_defs(content)

        # Also register functions as predicates so they can be used when recursion limit is reached
        for func_name, (param_names, _) in self.function_defs.items():
            if func_name not in self.predicates:
                self.predicates[func_name] = 'custom'
                self.predicate_arities[func_name] = len(param_names)

        # Extract assertions
        antecedent = None
        consequent = None
        problem_type = 'entl'  # Default to entailment

        # Find the two assert statements (need to handle multi-line)
        # Strategy: find all (assert ...) blocks
        asserts = []
        i = 0
        while i < len(content):
            if content[i:i+7] == '(assert':
                # Find the matching closing paren
                depth = 0
                start = i + 7  # After '(assert'
                j = i
                while j < len(content):
                    if content[j] == '(':
                        depth += 1
                    elif content[j] == ')':
                        depth -= 1
                        if depth == 0:
                            # Found the end of this assert
                            asserts.append(content[start:j].strip())
                            i = j + 1
                            break
                    j += 1
            i += 1

        # Determine problem type
        # Use division hint if available (most reliable)
        if division_hint and '_sat' in division_hint:
            problem_type = 'sat'
        elif division_hint and '_entl' in division_hint:
            problem_type = 'entl'
        else:
            # Fall back to heuristics based on number of assertions
            problem_type = 'entl'  # Default

        # Parse assertions based on problem type and structure
        if problem_type == 'sat' or (len(asserts) == 1):
            # SAT problem: combine all assertions
            problem_type = 'sat'
            if len(asserts) == 1:
                antecedent_text = asserts[0].strip()
                antecedent = self._parse_formula(antecedent_text)
            else:
                # Multiple assertions - combine with AND
                antecedent_formulas = []
                for assert_text in asserts:
                    formula = self._parse_formula(assert_text.strip())
                    if formula:
                        antecedent_formulas.append(formula)

                if antecedent_formulas:
                    antecedent = antecedent_formulas[0]
                    for formula in antecedent_formulas[1:]:
                        antecedent = And(antecedent, formula)
        elif len(asserts) == 2:
            # ENTL problem: two assertions (P and not Q)
            problem_type = 'entl'
            # First assert is the antecedent
            antecedent_text = asserts[0].strip()
            antecedent = self._parse_formula(antecedent_text)

            # Second assert is (not consequent)
            consequent_text = asserts[1].strip()
            if consequent_text.startswith('(not'):
                # Extract what's inside the not
                # Skip past '(not ' to get to the inner formula
                rest = consequent_text[4:].strip()
                inner = extract_balanced_parens(rest)
                consequent = self._parse_formula(inner)
        elif len(asserts) > 2:
            # Multiple assertions: could be SAT or ENTL
            # Check if last assertion is (not ...) - if so, it's ENTL
            last_assert = asserts[-1].strip()
            if last_assert.startswith('(not'):
                # ENTL problem: all but last are antecedents, last is negated consequent
                problem_type = 'entl'

                # Combine all antecedent assertions with AND
                if len(asserts) == 2:
                    antecedent = self._parse_formula(asserts[0].strip())
                else:
                    # Multiple antecedent assertions - combine with And
                    antecedent_formulas = []
                    for assert_text in asserts[:-1]:
                        formula = self._parse_formula(assert_text.strip())
                        if formula:
                            antecedent_formulas.append(formula)

                    if antecedent_formulas:
                        antecedent = antecedent_formulas[0]
                        for formula in antecedent_formulas[1:]:
                            antecedent = And(antecedent, formula)

                # Parse consequent
                rest = last_assert[4:].strip()
                inner = extract_balanced_parens(rest)
                consequent = self._parse_formula(inner)
            else:
                # SAT problem: all assertions must be satisfied
                problem_type = 'sat'

                # Combine all assertions with AND
                antecedent_formulas = []
                for assert_text in asserts:
                    formula = self._parse_formula(assert_text.strip())
                    if formula:
                        antecedent_formulas.append(formula)

                if antecedent_formulas:
                    antecedent = antecedent_formulas[0]
                    for formula in antecedent_formulas[1:]:
                        antecedent = And(antecedent, formula)

        return antecedent, consequent, self.status, problem_type, self.logic

    def _parse_formula(self, text: str, depth: int = 0) -> Optional[Formula]:
        """Parse a formula from SMT-LIB format

        Args:
            text: Formula text to parse
            depth: Current recursion depth for function expansion (prevents infinite recursion)
        """
        text = text.strip()

        if not text:
            return None

        # Handle true
        if text == 'true':
            return True_()

        # Handle (and ...)
        if text.startswith('(and'):
            return parse_and(text, self.variables, self._parse_formula, depth)

        # Handle (or ...)
        if text.startswith('(or'):
            return parse_or(text, self.variables, self._parse_formula, depth)

        # Handle (not ...)
        if text.startswith('(not'):
            return parse_not(text, self.variables, self._parse_formula, depth)

        # Handle (exists ...)
        if text.startswith('(exists'):
            return parse_exists(text, self.variables, self._parse_formula, depth)

        # Handle (sep ...) - separating conjunction
        if text.startswith('(sep'):
            return parse_sep(text, self.variables, self._parse_formula, depth)

        # Handle (wand ...) - magic wand
        if text.startswith('(wand'):
            return parse_wand(text, self.variables, self._parse_formula, depth)

        # Handle comparison operators (check <= and >= before = to avoid misparsing)
        if text.startswith('(<='):
            return parse_comparison(text, '<=', self.variables)
        if text.startswith('(>='):
            return parse_comparison(text, '>=', self.variables)
        if text.startswith('(<'):
            return parse_comparison(text, '<', self.variables)
        if text.startswith('(>'):
            return parse_comparison(text, '>', self.variables)

        # Handle (= x y)
        if text.startswith('(='):
            return parse_equality(text, self.variables)

        # Handle (distinct x y) - inequality
        if text.startswith('(distinct'):
            return parse_distinct(text, self.variables)

        # Handle (pto x (c_Sll_t y)) - points-to
        if text.startswith('(pto'):
            return parse_pto(text, self.variables)

        # Handle function calls (define-fun macros) - expand them first
        if text.startswith('('):
            func_match = re.match(r'\((\w+)', text)
            if func_match:
                func_name = func_match.group(1)
                if func_name in self.function_defs:
                    # Check recursion depth to prevent infinite recursion
                    if depth >= self.MAX_RECURSION_DEPTH:
                        # Reached max depth - treat as predicate call instead of expanding
                        # This handles recursive define-fun functions
                        return parse_predicate_call(text, self.variables)

                    # Extract arguments and expand the function
                    args_text = text[len(func_name)+1:].strip()
                    if args_text.endswith(')'):
                        args_text = args_text[:-1]
                    args = split_top_level(args_text)
                    expanded = expand_function_call(func_name, args, self.function_defs)
                    if expanded:
                        # Recursively parse the expanded body with incremented depth
                        return self._parse_formula(expanded, depth + 1)

        # Handle predicate calls like (ls x y), (RList x y), etc.
        # Check if this matches any known predicate
        if text.startswith('('):
            pred_match = re.match(r'\((\w+)', text)
            if pred_match:
                pred_name = pred_match.group(1)
                if pred_name in self.predicates:
                    return parse_predicate_call(text, self.variables)

        # Handle (_ emp RefSll_t Sll_t)
        if '(_ emp' in text or text == 'emp':
            return Emp()

        return None

    # Expose extracted methods for backward compatibility with tests
    def _parse_and(self, text: str, depth: int = 0) -> Formula:
        """Delegate to formula parser"""
        return parse_and(text, self.variables, self._parse_formula, depth)

    def _parse_sep(self, text: str, depth: int = 0) -> Formula:
        """Delegate to formula parser"""
        return parse_sep(text, self.variables, self._parse_formula, depth)

    def _extract_balanced_parens_at_index(self, text: str, start_idx: int):
        """Delegate to utils"""
        from benchmarks._slcomp_utils import extract_balanced_parens_at_index
        return extract_balanced_parens_at_index(text, start_idx)

    def _parse_define_funs_rec(self, content: str):
        """Delegate to predicates parser"""
        from benchmarks._slcomp_predicates import _parse_define_funs_rec
        return _parse_define_funs_rec(content, self.predicates, self.predicate_arities, self.predicate_bodies, self._parse_formula)
