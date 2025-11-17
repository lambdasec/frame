"""
Parser for SL-COMP SMT-LIB format benchmarks

Converts SL-COMP format to Frame's internal representation
"""

import re
from typing import Dict, List, Tuple, Optional
from frame.core.ast import *


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

    def parse_file(self, content: str, division_hint: str = None) -> Tuple[Optional[Formula], Optional[Formula], str, str]:
        """
        Parse SL-COMP benchmark file

        Args:
            content: The SMT-LIB file content
            division_hint: Optional division name to help determine problem type (e.g., 'qf_shls_sat')

        Returns:
            (antecedent, consequent, expected_status, problem_type)

        For entailment P |- Q, the file has:
            (assert P)
            (assert (not Q))
            problem_type = 'entl'

        For satisfiability, the file has:
            (assert P)
            problem_type = 'sat'
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
        self._parse_predicates(content)

        # Extract function definitions (define-fun)
        self._parse_function_defs(content)

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
                inner = self._extract_balanced_parens(rest)
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
                inner = self._extract_balanced_parens(rest)
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

        return antecedent, consequent, self.status, problem_type

    def _parse_predicates(self, content: str):
        """Extract predicate definitions from define-fun-rec and define-funs-rec"""
        import re

        # Find all single predicate definitions (define-fun-rec) and extract bodies
        # Format: (define-fun-rec pred_name ((arg1 Type) (arg2 Type) ...) RetType body)
        self._parse_define_fun_rec(content)

        # Find all mutually recursive predicate definitions (define-funs-rec)
        # Format: (define-funs-rec ((pred1 ((args...)) Bool) (pred2 ((args...)) Bool)) (...))
        if 'define-funs-rec' in content:
            # Try to parse the full define-funs-rec block with bodies
            self._parse_define_funs_rec(content)

        # Mark builtin predicates (only if not already defined with custom arity)
        if 'define-fun-rec ls' in content and 'ls' not in self.predicates:
            self.predicates['ls'] = 'builtin'
            self.predicate_arities['ls'] = 2

    def _parse_define_fun_rec(self, content: str):
        """
        Parse single define-fun-rec declarations to extract predicate signatures and bodies.

        Format:
        (define-fun-rec pred_name ((param1 Type1)(param2 Type2)) RetType
            body)
        """
        import re

        # Find all define-fun-rec declarations
        idx = 0
        while True:
            # Find next define-fun-rec
            start_idx = content.find('(define-fun-rec', idx)
            if start_idx == -1:
                break

            # Extract the full definition using balanced parenthesis matching
            # Note: _extract_balanced_parens_at_index returns content WITHOUT outer parens
            full_def, end_idx = self._extract_balanced_parens_at_index(content, start_idx)
            if not full_def:
                idx = start_idx + 1
                continue

            # Parse the definition
            # Format: define-fun-rec pred_name ((param1 Type1)(param2 Type2)) RetType body
            # (outer parens already removed by _extract_balanced_parens_at_index)
            inner = full_def.strip()
            if inner.startswith('define-fun-rec'):
                inner = inner[14:].strip()  # Skip 'define-fun-rec'

            # Extract predicate name
            match = re.match(r'(\w+)\s+', inner)
            if not match:
                idx = end_idx
                continue

            pred_name = match.group(1)
            inner = inner[match.end():].strip()

            # Extract parameters section - should be ((param1 Type1)(param2 Type2)...)
            if not inner.startswith('('):
                idx = end_idx
                continue

            params_text, params_end = self._extract_balanced_parens_at_index(inner, 0)
            if not params_text:
                idx = end_idx
                continue

            # Parse parameters
            params = []
            param_pattern = r'\((\w+)\s+\w+\)'
            for param_match in re.finditer(param_pattern, params_text):
                params.append(param_match.group(1))

            # Move past parameters and return type
            inner = inner[params_end:].strip()

            # Skip return type (usually Bool or a sort name)
            ret_type_match = re.match(r'(\w+)\s+', inner)
            if ret_type_match:
                inner = inner[ret_type_match.end():].strip()

            # The rest is the body
            # NOTE: Don't use rstrip(')') as it strips ALL trailing parens, corrupting
            # nested structures. The body is already properly balanced from
            # _extract_balanced_parens_at_index
            body = inner

            # Store the predicate info
            # Mark as 'parsed' since we have the full body
            self.predicates[pred_name] = 'parsed'
            self.predicate_arities[pred_name] = len(params)
            self.predicate_bodies[pred_name] = (params, body)

            # Move to next definition
            idx = end_idx

    def _parse_define_funs_rec(self, content: str):
        """
        Parse define-funs-rec to extract predicate signatures, parameters, and bodies.

        Format:
        (define-funs-rec
            ((pred1 ((param1 Type1)(param2 Type2)) Bool)
             (pred2 ((param3 Type3)) Bool))
            (body1
             body2))
        """
        import re

        # Find the define-funs-rec block
        define_idx = content.find('(define-funs-rec')
        if define_idx == -1:
            # Fallback to basic parsing without bodies
            pred_sig_pattern = r'\((\w+)\s+\(\((.*?)\)\)\s+Bool'
            pred_matches = re.findall(pred_sig_pattern, content, re.DOTALL)
            for pred_name, args_text in pred_matches:
                self.predicates[pred_name] = 'custom'
                args_text = args_text.strip()
                if ')' in args_text:
                    arity = args_text.count(')') + 1
                else:
                    arity = 1 if args_text else 0
                self.predicate_arities[pred_name] = arity
            return

        # Find the start of the first parenthesized section (signatures)
        idx = define_idx + len('(define-funs-rec')
        while idx < len(content) and content[idx] in ' \t\n':
            idx += 1

        if idx >= len(content) or content[idx] != '(':
            return

        # Extract signatures section using balanced parenthesis matching
        signatures_text, idx = self._extract_balanced_parens_at_index(content, idx)

        # Skip whitespace to find bodies section
        while idx < len(content) and content[idx] in ' \t\n':
            idx += 1

        if idx >= len(content) or content[idx] != '(':
            return

        # Extract bodies section using balanced parenthesis matching
        bodies_text, _ = self._extract_balanced_parens_at_index(content, idx)

        # Parse signatures to get predicate names and parameters
        # Format: (pred_name ((param1 Type1)(param2 Type2)...) Bool)
        sig_pattern = r'\((\w+)\s+\(\((.*?)\)\)\s+\w+\s*\)'
        signatures = []

        for sig_match in re.finditer(sig_pattern, signatures_text, re.DOTALL):
            pred_name = sig_match.group(1)
            params_text = sig_match.group(2).strip()

            # Extract parameter names
            # Format: "param1 Type1)(param2 Type2" or "param1 Type1"
            param_names = []
            if ')' in params_text:
                # Multiple parameters
                param_parts = params_text.split(')')
                for part in param_parts:
                    part = part.strip().lstrip('(')
                    if part:
                        param_name = part.split()[0] if part.split() else ''
                        if param_name:
                            param_names.append(param_name)
            elif params_text:
                # Single parameter
                param_name = params_text.split()[0] if params_text.split() else ''
                if param_name:
                    param_names.append(param_name)

            signatures.append((pred_name, param_names))
            self.predicates[pred_name] = 'parsed'
            self.predicate_arities[pred_name] = len(param_names)

        # Parse bodies - extract top-level expressions matching signature count
        bodies = self._extract_predicate_bodies(bodies_text, len(signatures))

        # Store parsed predicates with their bodies
        # Note: Store body_text (string) not body_formula (Formula object)
        # The body will be parsed later in run_slcomp.py when creating ParsedPredicate
        for (pred_name, param_names), body_text in zip(signatures, bodies):
            # Validate that the body parses correctly, but store the text
            body_formula = self._parse_formula(body_text)
            if body_formula:
                self.predicate_bodies[pred_name] = (param_names, body_text)

    def _extract_balanced_parens_at_index(self, text: str, start_idx: int) -> Tuple[str, int]:
        """
        Extract content between balanced parentheses starting at start_idx.

        Args:
            text: Full text
            start_idx: Index of opening '('

        Returns:
            (content_without_outer_parens, index_after_closing_paren)
        """
        if start_idx >= len(text) or text[start_idx] != '(':
            return '', start_idx

        depth = 0
        idx = start_idx

        while idx < len(text):
            if text[idx] == '(':
                depth += 1
            elif text[idx] == ')':
                depth -= 1
                if depth == 0:
                    # Found matching closing paren
                    # Return content without outer parens
                    return text[start_idx + 1:idx], idx + 1

            idx += 1

        # Unmatched parens
        return text[start_idx + 1:], idx

    def _extract_predicate_bodies(self, bodies_text: str, count: int) -> List[str]:
        """Extract individual predicate bodies from the bodies section"""
        bodies = []
        depth = 0
        current_body = []

        i = 0
        while i < len(bodies_text) and len(bodies) < count:
            char = bodies_text[i]

            if char == '(':
                depth += 1
                current_body.append(char)
            elif char == ')':
                depth -= 1
                current_body.append(char)

                # If we've closed all parens, we have a complete body
                if depth == 0 and current_body:
                    body_str = ''.join(current_body).strip()
                    if body_str:
                        bodies.append(body_str)
                    current_body = []
            elif depth > 0:
                current_body.append(char)

            i += 1

        return bodies

    def _parse_function_defs(self, content: str):
        """
        Parse define-fun declarations (non-recursive function definitions/macros).

        Format: (define-fun func_name ((param1 Type1) (param2 Type2) ...) RetType body)

        These are stored as macros and expanded when encountered.
        """
        idx = 0
        while idx < len(content):
            # Find next define-fun (but not define-fun-rec)
            start_idx = content.find('(define-fun ', idx)
            if start_idx == -1:
                break

            # Make sure this is not define-fun-rec
            if content[start_idx:start_idx+16] == '(define-fun-rec ':
                idx = start_idx + 16
                continue

            # Extract the full define-fun block
            full_def = None
            depth = 0
            i = start_idx
            while i < len(content):
                if content[i] == '(':
                    depth += 1
                elif content[i] == ')':
                    depth -= 1
                    if depth == 0:
                        full_def = content[start_idx:i+1]
                        break
                i += 1

            if not full_def:
                idx = start_idx + 12
                continue

            # Parse the define-fun
            # Format: (define-fun name ((params...)) RetType body)
            inner = self._extract_balanced_parens(full_def)
            if not inner:
                idx = start_idx + 12
                continue

            # Strip outer parens and 'define-fun ' prefix
            if inner.startswith('(') and inner.endswith(')'):
                inner = inner[1:-1].strip()

            if inner.startswith('define-fun '):
                inner = inner[11:].strip()  # Skip 'define-fun '

            # Extract function name
            parts = inner.split(None, 1)
            if len(parts) < 2:
                idx = start_idx + 12
                continue

            func_name = parts[0]
            rest = parts[1].strip()

            # Extract parameters
            if not rest.startswith('('):
                idx = start_idx + 12
                continue

            params_text = self._extract_balanced_parens(rest)
            if not params_text:
                idx = start_idx + 12
                continue

            # Parse parameter names (skip types for now, just get names)
            param_names = []
            param_tokens = params_text.strip('()').split('(')
            for token in param_tokens:
                token = token.strip()
                if token:
                    # Format: param_name Type)
                    param_parts = token.split()
                    if param_parts:
                        param_names.append(param_parts[0])

            # Skip past parameters to get body
            rest = rest[len(params_text) + 2:].strip()  # +2 for parentheses

            # Skip return type (next token)
            ret_type_parts = rest.split(None, 1)
            if len(ret_type_parts) < 2:
                idx = start_idx + 12
                continue

            body_text = ret_type_parts[1].strip()

            # Store the function definition
            self.function_defs[func_name] = (param_names, body_text)

            # Also register as a predicate so it can be used when recursion limit is reached
            self.predicates[func_name] = 'custom'
            self.predicate_arities[func_name] = len(param_names)

            idx = start_idx + 12

    def _expand_function_call(self, func_name: str, args: List[str]) -> str:
        """
        Expand a function call by substituting arguments into the function body.

        Args:
            func_name: Name of the function to expand
            args: List of argument expressions (as strings)

        Returns:
            The expanded body with arguments substituted
        """
        if func_name not in self.function_defs:
            return None

        param_names, body_text = self.function_defs[func_name]

        if len(args) != len(param_names):
            return None

        # Perform substitution: replace each parameter with its argument
        # We need to be careful to do whole-word replacement
        result = body_text
        for param, arg in zip(param_names, args):
            # Use word boundary replacement to avoid partial matches
            # Simple approach: replace with regex word boundaries
            import re
            result = re.sub(r'\b' + re.escape(param) + r'\b', arg, result)

        return result

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
            return self._parse_and(text, depth)

        # Handle (or ...)
        if text.startswith('(or'):
            return self._parse_or(text, depth)

        # Handle (not ...)
        if text.startswith('(not'):
            return self._parse_not(text, depth)

        # Handle (exists ...)
        if text.startswith('(exists'):
            return self._parse_exists(text, depth)

        # Handle (sep ...) - separating conjunction
        if text.startswith('(sep'):
            return self._parse_sep(text, depth)

        # Handle (wand ...) - magic wand
        if text.startswith('(wand'):
            return self._parse_wand(text, depth)

        # Handle comparison operators (check <= and >= before = to avoid misparsing)
        if text.startswith('(<='):
            return self._parse_comparison(text, '<=')
        if text.startswith('(>='):
            return self._parse_comparison(text, '>=')
        if text.startswith('(<'):
            return self._parse_comparison(text, '<')
        if text.startswith('(>'):
            return self._parse_comparison(text, '>')

        # Handle (= x y)
        if text.startswith('(='):
            return self._parse_equality(text)

        # Handle (distinct x y) - inequality
        if text.startswith('(distinct'):
            return self._parse_distinct(text)

        # Handle (pto x (c_Sll_t y)) - points-to
        if text.startswith('(pto'):
            return self._parse_pto(text)

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
                        return self._parse_predicate_call(text)

                    # Extract arguments and expand the function
                    args_text = text[len(func_name)+1:].strip()
                    if args_text.endswith(')'):
                        args_text = args_text[:-1]
                    args = self._split_top_level(args_text)
                    expanded = self._expand_function_call(func_name, args)
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
                    return self._parse_predicate_call(text)

        # Handle (_ emp RefSll_t Sll_t)
        if '(_ emp' in text or text == 'emp':
            return Emp()

        return None

    def _parse_and(self, text: str, depth: int = 0) -> Formula:
        """Parse (and ...) into And formula"""
        # Extract arguments
        args_text = text[4:].strip()  # Remove '(and'
        if args_text.endswith(')'):
            args_text = args_text[:-1]  # Remove trailing )

        args = self._split_top_level(args_text)

        if len(args) == 0:
            return Emp()  # Empty and
        elif len(args) == 1:
            return self._parse_formula(args[0], depth)
        else:
            # Build nested And, filtering out None values
            result = None
            for arg in args:
                parsed = self._parse_formula(arg, depth)
                if parsed:
                    if result is None:
                        result = parsed
                    else:
                        result = And(result, parsed)
            return result if result is not None else Emp()

    def _parse_sep(self, text: str, depth: int = 0) -> Formula:
        """Parse (sep ...) into SepConj formula"""
        # Extract arguments
        args_text = text[4:].strip()  # Remove '(sep'
        if args_text.endswith(')'):
            args_text = args_text[:-1]  # Remove trailing )

        args = self._split_top_level(args_text)

        if len(args) == 0:
            return Emp()
        elif len(args) == 1:
            return self._parse_formula(args[0], depth)
        else:
            # Parse all arguments first
            parsed_args = []
            for arg in args:
                parsed = self._parse_formula(arg, depth)
                if parsed:
                    parsed_args.append(parsed)

            if not parsed_args:
                return Emp()

            # Build balanced binary tree instead of left-associative tree
            # This improves Z3 performance and formula analysis
            return self._build_balanced_sepconj(parsed_args)

    def _parse_wand(self, text: str, depth: int = 0) -> Formula:
        """Parse (wand P Q) into Wand formula"""
        # Extract arguments
        args_text = text[5:].strip()  # Remove '(wand'
        if args_text.endswith(')'):
            args_text = args_text[:-1]  # Remove trailing )

        args = self._split_top_level(args_text)

        if len(args) < 2:
            # Malformed wand, return None
            return None

        # Parse left and right formulas
        left = self._parse_formula(args[0], depth)
        right = self._parse_formula(args[1], depth)

        if left and right:
            return Wand(left, right)

        return None

    def _parse_or(self, text: str, depth: int = 0) -> Formula:
        """Parse (or ...) into Or formula"""
        # Extract arguments
        args_text = text[3:].strip()  # Remove '(or'
        if args_text.endswith(')'):
            args_text = args_text[:-1]  # Remove trailing )

        args = self._split_top_level(args_text)

        if len(args) == 0:
            return Emp()
        elif len(args) == 1:
            return self._parse_formula(args[0], depth)
        else:
            # Build nested Or, filtering out None values
            result = None
            for arg in args:
                parsed = self._parse_formula(arg, depth)
                if parsed:
                    if result is None:
                        result = parsed
                    else:
                        result = Or(result, parsed)
            return result if result is not None else Emp()

    def _parse_not(self, text: str, depth: int = 0) -> Formula:
        """Parse (not ...) into Not formula"""
        # Extract argument
        args_text = text[4:].strip()  # Remove '(not'
        if args_text.endswith(')'):
            args_text = args_text[:-1]  # Remove trailing )

        # Parse the inner formula
        inner = self._parse_formula(args_text.strip(), depth)

        if inner:
            return Not(inner)

        return None

    def _parse_exists(self, text: str, depth: int = 0) -> Formula:
        """
        Parse (exists ((var1 Type1)(var2 Type2)...) body) into Exists formula.

        Note: We only support single variable exists for now, as that's what Exists AST node supports.
        For multiple variables, we nest multiple Exists nodes.
        """
        import re

        # Extract variables and body using balanced parenthesis matching
        # Format: (exists (vars...) body) or (exists ((vars...)) body)
        text = text.strip()
        if not text.startswith('(exists'):
            return None

        # Skip past '(exists' and whitespace
        idx = 7  # len('(exists')
        while idx < len(text) and text[idx] in ' \t\n':
            idx += 1

        if idx >= len(text) or text[idx] != '(':
            return None

        # Extract the variables section using balanced parens
        vars_text = self._extract_balanced_parens(text[idx:])
        if not vars_text:
            return None

        # Move idx past the variables section
        # Note: _extract_balanced_parens already includes the outer parens
        idx += len(vars_text)

        # Skip whitespace
        while idx < len(text) and text[idx] in ' \t\n':
            idx += 1

        # Extract the body - everything until the final closing paren
        body_start = idx
        # Find the matching closing paren for the outermost '(exists'
        depth_counter = 1  # We're inside (exists already (renamed to avoid parameter collision)
        idx = 7  # Start from after '(exists'
        while idx < len(text) and depth_counter > 0:
            if text[idx] == '(':
                depth_counter += 1
            elif text[idx] == ')':
                depth_counter -= 1
            idx += 1

        body_text = text[body_start:idx-1].strip()  # -1 to exclude the final ')'

        # Parse variable names
        # Format: "var1 Type1)(var2 Type2" or "var1 Type1"
        var_names = []
        if ')' in vars_text:
            # Multiple variables
            var_parts = vars_text.split(')')
            for part in var_parts:
                part = part.strip().lstrip('(')
                if part:
                    var_name = part.split()[0] if part.split() else ''
                    if var_name:
                        var_names.append(var_name)
        elif vars_text:
            # Single variable
            var_name = vars_text.split()[0] if vars_text.split() else ''
            if var_name:
                var_names.append(var_name)

        # Parse body
        body_formula = self._parse_formula(body_text, depth)
        if not body_formula:
            return None

        # Create nested Exists for each variable (innermost first)
        result = body_formula
        for var_name in reversed(var_names):
            result = Exists(var_name, result)

        return result

    def _parse_pto(self, text: str) -> PointsTo:
        """Parse (pto x (c_Sll_t y)) or (pto x y) into PointsTo"""
        text = text.strip()

        # Try structured format: (pto x (c_Type y1 y2 ...))
        # Handle values that can be: variable names, or (as nil Type)
        match = re.match(r'\(pto\s+(\w+)\s+\(c_\w+\s+(.+)\)\s*\)', text, re.DOTALL)
        if match:
            var_name = match.group(1)
            vals_text = match.group(2).strip()

            var = self.variables.get(var_name, Var(var_name))
            vals = []

            # Parse values - they can be simple variables or (as nil Type)
            # Use a simple state machine to handle nested parens
            i = 0
            current = []
            depth = 0
            while i < len(vals_text):
                ch = vals_text[i]
                if ch == '(':
                    depth += 1
                    current.append(ch)
                elif ch == ')':
                    depth -= 1
                    current.append(ch)
                    if depth == 0 and current:
                        # Completed a value
                        val_text = ''.join(current).strip()
                        if 'nil' in val_text or val_text.startswith('(as'):
                            vals.append(Const(None))
                        else:
                            vals.append(self.variables.get(val_text, Var(val_text)))
                        current = []
                elif ch.isspace() and depth == 0:
                    # Whitespace at top level - possible separator
                    if current:
                        val_text = ''.join(current).strip()
                        if val_text:
                            if 'nil' in val_text or val_text.startswith('(as'):
                                vals.append(Const(None))
                            else:
                                vals.append(self.variables.get(val_text, Var(val_text)))
                        current = []
                else:
                    current.append(ch)
                i += 1

            # Don't forget the last value
            if current:
                val_text = ''.join(current).strip()
                if val_text:
                    if 'nil' in val_text or val_text.startswith('(as'):
                        vals.append(Const(None))
                    else:
                        vals.append(self.variables.get(val_text, Var(val_text)))

            return PointsTo(var, vals)

        # Try simple format: (pto x y)
        match = re.search(r'\(pto\s+(\w+)\s+(\w+)\s*\)', text)
        if match:
            var_name = match.group(1)
            val_name = match.group(2)

            var = self.variables.get(var_name, Var(var_name))
            val = self.variables.get(val_name, Var(val_name))

            return PointsTo(var, [val])

        # Try format with (as nil Type)
        match = re.search(r'\(pto\s+(\w+)\s+(\(as nil [^)]+\))\s*\)', text)
        if match:
            var_name = match.group(1)
            var = self.variables.get(var_name, Var(var_name))
            return PointsTo(var, [Const(None)])

        return None

    def _parse_predicate_call(self, text: str) -> PredicateCall:
        """Parse (ls x y) or (dll x y (as nil Type) z) into PredicateCall"""
        # Extract predicate name and arguments
        text = text.strip()
        if not text.startswith('('):
            return None

        # Find the predicate name
        match = re.match(r'\((\w+)\s+(.+)\)', text, re.DOTALL)
        if match:
            pred_name = match.group(1)
            args_text = match.group(2).strip()
            if args_text.endswith(')'):
                args_text = args_text[:-1]  # Remove trailing paren from group match

            # Split arguments properly, respecting parentheses for (as nil Type)
            arg_strings = self._split_top_level(args_text)

            args = []
            for arg_str in arg_strings:
                arg_str = arg_str.strip()
                # Check if this is (as nil Type) - if so, treat as nil
                if arg_str.startswith('(as nil') or arg_str == 'nil':
                    args.append(Const(None))
                else:
                    args.append(self.variables.get(arg_str, Var(arg_str)))

            return PredicateCall(pred_name, args)

        return None

    def _parse_expr(self, text: str) -> Expr:
        """Parse an expression (variable, constant, or arithmetic expression)"""
        from frame.core.ast import ArithExpr

        text = text.strip()

        # Handle nil
        if 'nil' in text or text.startswith('(as nil'):
            return Const(None)

        # Handle arithmetic operators: +, -, *, div, mod
        if text.startswith('('):
            # Check for arithmetic operators
            arith_ops = {'+': '+', '-': '-', '*': '*', 'div': 'div', 'mod': 'mod'}
            for op_name, op_symbol in arith_ops.items():
                if text.startswith(f'({op_name} ') or text.startswith(f'({op_name}\t'):
                    # Extract operands
                    inner = text[len(op_name)+1:].strip()
                    if inner.endswith(')'):
                        inner = inner[:-1]

                    parts = self._split_top_level(inner)
                    if len(parts) >= 2:
                        left = self._parse_expr(parts[0])
                        right = self._parse_expr(parts[1])
                        return ArithExpr(op_symbol, left, right)

        # Handle integer constants
        try:
            int_val = int(text)
            return Const(int_val)
        except ValueError:
            pass

        # Handle variables
        return self.variables.get(text, Var(text))

    def _parse_equality(self, text: str) -> Eq:
        """Parse (= x y) or (= (- x 1) 0) into Eq"""
        text = text.strip()
        if text.startswith('(='):
            # Extract the two arguments
            inner = text[2:].strip()
            if inner.endswith(')'):
                inner = inner[:-1]

            # Split into two parts
            parts = self._split_top_level(inner)
            if len(parts) >= 2:
                left = self._parse_expr(parts[0])
                right = self._parse_expr(parts[1])
                return Eq(left, right)

        return None

    def _parse_distinct(self, text: str) -> Formula:
        """Parse (distinct x y) into Neq"""
        text = text.strip()
        if text.startswith('(distinct'):
            # Extract the two arguments
            inner = text[9:].strip()  # Skip '(distinct'
            if inner.endswith(')'):
                inner = inner[:-1]

            # Split into two parts
            parts = self._split_top_level(inner)
            if len(parts) >= 2:
                left = self._parse_expr(parts[0])
                right = self._parse_expr(parts[1])
                return Neq(left, right)

        return None

    def _parse_comparison(self, text: str, op: str) -> Formula:
        """Parse comparison operators: (<, >, <=, >=) into Lt, Gt, Le, Ge"""
        text = text.strip()
        op_len = len(op) + 1  # Length of '(op' (e.g., '(<' is 2 chars)

        if text.startswith(f'({op}'):
            # Extract the two arguments
            inner = text[op_len:].strip()
            if inner.endswith(')'):
                inner = inner[:-1]

            # Split into two parts
            parts = self._split_top_level(inner)
            if len(parts) >= 2:
                left = self._parse_expr(parts[0])
                right = self._parse_expr(parts[1])

                # Import comparison operators from ast
                from frame.core.ast import Lt, Le, Gt, Ge

                if op == '<':
                    return Lt(left, right)
                elif op == '<=':
                    return Le(left, right)
                elif op == '>':
                    return Gt(left, right)
                elif op == '>=':
                    return Ge(left, right)

        return None

    def _parse_distinct_old(self, text: str) -> Formula:
        """OLD VERSION - Parse (distinct x y) into Neq (or Not(Eq(...)))"""
        # Handle (distinct (as nil Type) x) or (distinct x y)
        text = text.strip()
        if text.startswith('(distinct'):
            # Extract the two arguments
            inner = text[9:].strip()  # Skip '(distinct'
            if inner.endswith(')'):
                inner = inner[:-1]

            # Split into two parts
            parts = self._split_top_level(inner)
            if len(parts) >= 2:
                left_text = parts[0]
                right_text = parts[1]

                # Parse left side
                if 'nil' in left_text or left_text.startswith('(as nil'):
                    left = Const(None)
                else:
                    left = self.variables.get(left_text, Var(left_text))

                # Parse right side
                if 'nil' in right_text or right_text.startswith('(as nil'):
                    right = Const(None)
                else:
                    right = self.variables.get(right_text, Var(right_text))

                # Return as inequality (Neq)
                return Neq(left, right)

        return None

    def _split_top_level(self, text: str) -> List[str]:
        """Split text at top-level spaces (not inside parens)"""
        result = []
        current = ""
        depth = 0

        for char in text:
            if char == '(':
                depth += 1
                current += char
            elif char == ')':
                depth -= 1
                current += char
            elif char.isspace() and depth == 0:
                if current.strip():
                    result.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            result.append(current.strip())

        return result

    def _build_balanced_sepconj(self, formulas: List[Formula]) -> Formula:
        r"""
        Build a balanced binary tree of SepConj nodes from a list of formulas.

        This creates a balanced tree instead of a left-associative chain, which
        improves Z3 performance and formula analysis.

        For example, [a, b, c, d, e, f] becomes:
                *
               / \
              *   *
             / \ / \
            *  * *  f
           / \   / \
          a  b  c  d

        Instead of the left-associative: ((((((a * b) * c) * d) * e) * f)

        Args:
            formulas: List of parsed formulas

        Returns:
            Balanced SepConj tree
        """
        if len(formulas) == 0:
            return Emp()
        elif len(formulas) == 1:
            return formulas[0]
        elif len(formulas) == 2:
            return SepConj(formulas[0], formulas[1])
        else:
            # Split into two halves and recursively build balanced subtrees
            mid = len(formulas) // 2
            left_tree = self._build_balanced_sepconj(formulas[:mid])
            right_tree = self._build_balanced_sepconj(formulas[mid:])
            return SepConj(left_tree, right_tree)

    def _extract_balanced_parens(self, text: str) -> str:
        """Extract content inside balanced parentheses, including the parens"""
        text = text.strip()
        if not text.startswith('('):
            return text

        depth = 0
        for i, char in enumerate(text):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    return text[:i+1]  # Include opening and closing parens

        return text
