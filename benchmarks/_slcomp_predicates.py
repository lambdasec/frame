"""
Predicate parsing for SL-COMP parser

Internal module for parsing define-fun-rec and define-funs-rec declarations.
"""

import re
from typing import Dict, List, Tuple
from benchmarks._slcomp_utils import (
    extract_balanced_parens_at_index,
    extract_predicate_bodies
)


def parse_predicates(content: str) -> Tuple[Dict[str, str], Dict[str, int], Dict[str, Tuple[List[str], str]], object]:
    """
    Extract predicate definitions from define-fun-rec and define-funs-rec.

    Returns:
        (predicates, predicate_arities, predicate_bodies, parse_formula_placeholder)
        - predicates: Dict[str, str] - name -> 'custom' or 'builtin' or 'parsed'
        - predicate_arities: Dict[str, int] - name -> arity
        - predicate_bodies: Dict[str, Tuple[List[str], str]] - name -> (params, body_text)
        - parse_formula_placeholder: None (placeholder for backward compatibility)
    """
    predicates = {}
    predicate_arities = {}
    predicate_bodies = {}

    # Find all single predicate definitions (define-fun-rec) and extract bodies
    _parse_define_fun_rec(content, predicates, predicate_arities, predicate_bodies)

    # Find all mutually recursive predicate definitions (define-funs-rec)
    if 'define-funs-rec' in content:
        _parse_define_funs_rec(content, predicates, predicate_arities, predicate_bodies, None)

    # Mark builtin predicates (only if not already defined with custom arity)
    if 'define-fun-rec ls' in content and 'ls' not in predicates:
        predicates['ls'] = 'builtin'
        predicate_arities['ls'] = 2

    return predicates, predicate_arities, predicate_bodies, None


def _parse_define_fun_rec(content: str, predicates: Dict, predicate_arities: Dict, predicate_bodies: Dict):
    """
    Parse single define-fun-rec declarations to extract predicate signatures and bodies.

    Format:
    (define-fun-rec pred_name ((param1 Type1)(param2 Type2)) RetType
        body)
    """
    # Find all define-fun-rec declarations
    idx = 0
    while True:
        # Find next define-fun-rec
        start_idx = content.find('(define-fun-rec', idx)
        if start_idx == -1:
            break

        # Extract the full definition using balanced parenthesis matching
        # Note: extract_balanced_parens_at_index returns content WITHOUT outer parens
        full_def, end_idx = extract_balanced_parens_at_index(content, start_idx)
        if not full_def:
            idx = start_idx + 1
            continue

        # Parse the definition
        # Format: define-fun-rec pred_name ((param1 Type1)(param2 Type2)) RetType body
        # (outer parens already removed by extract_balanced_parens_at_index)
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

        params_text, params_end = extract_balanced_parens_at_index(inner, 0)
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
        # extract_balanced_parens_at_index
        body = inner

        # Store the predicate info
        # Mark as 'parsed' since we have the full body
        predicates[pred_name] = 'parsed'
        predicate_arities[pred_name] = len(params)
        predicate_bodies[pred_name] = (params, body)

        # Move to next definition
        idx = end_idx


def _parse_define_funs_rec(content: str, predicates: Dict, predicate_arities: Dict, predicate_bodies: Dict, parse_formula_fn):
    """
    Parse define-funs-rec to extract predicate signatures, parameters, and bodies.

    Format:
    (define-funs-rec
        ((pred1 ((param1 Type1)(param2 Type2)) Bool)
         (pred2 ((param3 Type3)) Bool))
        (body1
         body2))
    """
    # Find the define-funs-rec block
    define_idx = content.find('(define-funs-rec')
    if define_idx == -1:
        # Fallback to basic parsing without bodies
        pred_sig_pattern = r'\((\w+)\s+\(\((.*?)\)\)\s+Bool'
        pred_matches = re.findall(pred_sig_pattern, content, re.DOTALL)
        for pred_name, args_text in pred_matches:
            predicates[pred_name] = 'custom'
            args_text = args_text.strip()
            if ')' in args_text:
                arity = args_text.count(')') + 1
            else:
                arity = 1 if args_text else 0
            predicate_arities[pred_name] = arity
        return

    # Find the start of the first parenthesized section (signatures)
    idx = define_idx + len('(define-funs-rec')
    while idx < len(content) and content[idx] in ' \t\n':
        idx += 1

    if idx >= len(content) or content[idx] != '(':
        return

    # Extract signatures section using balanced parenthesis matching
    signatures_text, idx = extract_balanced_parens_at_index(content, idx)

    # Skip whitespace to find bodies section
    while idx < len(content) and content[idx] in ' \t\n':
        idx += 1

    if idx >= len(content) or content[idx] != '(':
        return

    # Extract bodies section using balanced parenthesis matching
    bodies_text, _ = extract_balanced_parens_at_index(content, idx)

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
        predicates[pred_name] = 'parsed'
        predicate_arities[pred_name] = len(param_names)

    # Parse bodies - extract top-level expressions matching signature count
    bodies = extract_predicate_bodies(bodies_text, len(signatures))

    # Store parsed predicates with their bodies
    # Note: Store body_text (string) not body_formula (Formula object)
    # The body will be parsed later when creating ParsedPredicate
    for (pred_name, param_names), body_text in zip(signatures, bodies):
        # We don't validate parsing here anymore - just store the text
        # Validation happens later in the main parser when needed
        predicate_bodies[pred_name] = (param_names, body_text)
