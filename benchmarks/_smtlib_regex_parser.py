"""
SMT-LIB Regex Parsing Utilities

Internal helper module for parsing SMT-LIB regex expressions
and converting them to Python regex patterns.
"""

from typing import List


def decode_string_literal(s: str) -> str:
    """Decode SMT-LIB string literal with Unicode escapes

    Supports:
    - \\u{XXXX} format (SMT-LIB 2.6)
    - Standard escape sequences: \\n, \\t, \\r, \\\\, \\"
    """
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            next_char = s[i + 1]
            # Unicode escape: \u{XXXX}
            if next_char == 'u' and i + 2 < len(s) and s[i + 2] == '{':
                # Find closing }
                close_idx = s.find('}', i + 3)
                if close_idx != -1:
                    hex_code = s[i + 3:close_idx]
                    try:
                        char_code = int(hex_code, 16)
                        result.append(chr(char_code))
                        i = close_idx + 1
                        continue
                    except ValueError:
                        # Invalid hex, treat as literal
                        result.append(s[i])
                        i += 1
                        continue
            # Standard escapes
            elif next_char == 'n':
                result.append('\n')
                i += 2
                continue
            elif next_char == 't':
                result.append('\t')
                i += 2
                continue
            elif next_char == 'r':
                result.append('\r')
                i += 2
                continue
            elif next_char == '\\':
                result.append('\\')
                i += 2
                continue
            elif next_char == '"':
                result.append('"')
                i += 2
                continue
            else:
                # Unknown escape, keep backslash
                result.append(s[i])
                i += 1
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)


def split_top_level(text: str) -> List[str]:
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


def parse_smt_regex(text: str) -> str:
    """Parse SMT-LIB regex expression and convert to string pattern

    Supports:
    - (str.to_re "lit") → "lit"
    - (re.++ r1 r2) → concatenation
    - (re.* r) → r*
    - (re.+ r) → r+
    - (re.union r1 r2) → (r1|r2)
    - (re.range "a" "z") → [a-z]
    - ((_ re.loop n m) r) → r{n,m}
    - (re.opt r) → r?
    - (re.comp r) → [^r] (simplified)
    - (re.allchar) → .
    """
    text = text.strip()

    # String to regex: (str.to_re "hello")
    if text.startswith('(str.to_re '):
        inner = text[11:-1].strip()
        if inner.startswith('"') and inner.endswith('"'):
            # Decode Unicode escapes first
            literal = decode_string_literal(inner[1:-1])
            # Escape special regex characters in the literal
            for char in r'\.^$*+?{}[]()':
                literal = literal.replace(char, '\\' + char)
            return literal
        return "."

    # Regex concatenation: (re.++ r1 r2 ...)
    if text.startswith('(re.++ '):
        parts = split_top_level(text[7:-1])
        return ''.join(parse_smt_regex(p) for p in parts)

    # Kleene star: (re.* r)
    if text.startswith('(re.* '):
        inner = text[6:-1].strip()
        inner_regex = parse_smt_regex(inner)
        # Wrap in parens if it's complex
        if len(inner_regex) > 1:
            return f"({inner_regex})*"
        return inner_regex + "*"

    # Kleene plus: (re.+ r)
    if text.startswith('(re.+ '):
        inner = text[6:-1].strip()
        inner_regex = parse_smt_regex(inner)
        if len(inner_regex) > 1:
            return f"({inner_regex})+"
        return inner_regex + "+"

    # Optional: (re.opt r)
    if text.startswith('(re.opt '):
        inner = text[8:-1].strip()
        inner_regex = parse_smt_regex(inner)
        if len(inner_regex) > 1:
            return f"({inner_regex})?"
        return inner_regex + "?"

    # Union: (re.union r1 r2 ...)
    if text.startswith('(re.union '):
        parts = split_top_level(text[10:-1])
        regex_parts = [parse_smt_regex(p) for p in parts]
        return '(' + '|'.join(regex_parts) + ')'

    # Character range: (re.range "a" "z")
    if text.startswith('(re.range '):
        parts = split_top_level(text[10:-1])
        if len(parts) == 2:
            start = parts[0].strip('"')
            end = parts[1].strip('"')
            return f"[{start}-{end}]"
        return "."

    # Bounded repetition: ((_ re.loop n m) r)
    if text.startswith('((_ re.loop '):
        # Extract n, m, and the regex
        # Format: ((_ re.loop n m) regex)
        inner = text[12:]  # Skip "((_ re.loop "
        # Find the closing ) for the loop parameters
        depth = 1
        i = 0
        while i < len(inner) and depth > 0:
            if inner[i] == '(':
                depth += 1
            elif inner[i] == ')':
                depth -= 1
            i += 1

        params = inner[:i-1].strip()  # Get "n m"
        rest = inner[i:].strip()  # Get "regex)"

        # Parse n and m
        param_parts = params.split()
        if len(param_parts) >= 2:
            n = param_parts[0]
            m = param_parts[1]
            # Get the regex part (remove trailing ')')
            if rest.endswith(')'):
                rest = rest[:-1].strip()
            regex = parse_smt_regex(rest)
            if n == m:
                return f"({regex}){{{n}}}"
            else:
                return f"({regex}){{{n},{m}}}"
        return "."

    # All characters: (re.allchar) or re.allchar
    if text == '(re.allchar)' or text == 're.allchar':
        return "."

    # Complement: (re.comp r) - simplified to .* (matches anything)
    if text.startswith('(re.comp '):
        # Complement is complex to represent in basic regex
        # For now, just match any string
        return ".*"

    # Fallback for unknown regex operations
    return "."
