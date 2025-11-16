"""
Taint Propagation Lemmas for Security Analysis

This module defines proven lemmas about how taint propagates through
string operations, heap structures, and program transformations.

These lemmas enable compositional reasoning about security properties
without requiring full symbolic execution.
"""

from frame.lemmas.base import Lemma
from frame.core.parser import parse


# =============================================================================
# String Operation Taint Lemmas
# =============================================================================

taint_concat_left = Lemma(
    name="taint_concat_left",
    antecedent=parse("taint(s1)"),
    consequent=parse("taint(s1 ++ s2)"),
    description="Taint propagates from left operand of concatenation"
)

taint_concat_right = Lemma(
    name="taint_concat_right",
    antecedent=parse("taint(s2)"),
    consequent=parse("taint(s1 ++ s2)"),
    description="Taint propagates from right operand of concatenation"
)

taint_substr = Lemma(
    name="taint_substr",
    antecedent=parse("taint(s)"),
    consequent=parse("taint(substr(s, i, j))"),
    description="Substring of tainted string is tainted"
)

taint_length_independent = Lemma(
    name="taint_length_independent",
    antecedent=parse("taint(s)"),
    consequent=parse("true"),  # Length is not tainted even if string is
    description="String length does not propagate taint (it's just a number)"
)


# =============================================================================
# Sanitization Lemmas
# =============================================================================

sanitize_removes_taint = Lemma(
    name="sanitize_removes_taint",
    antecedent=parse("taint(dirty) * clean = sanitize(dirty)"),  # Note: sanitize is conceptual
    consequent=parse("sanitized(clean)"),
    description="Sanitization operation removes taint"
)

sanitized_not_tainted = Lemma(
    name="sanitized_not_tainted",
    antecedent=parse("sanitized(x)"),
    consequent=parse("!taint(x)"),
    description="Sanitized values are not tainted (mutually exclusive)"
)


# =============================================================================
# Source and Sink Lemmas
# =============================================================================

source_is_tainted = Lemma(
    name="source_is_tainted",
    antecedent=parse('source(x, "user")'),
    consequent=parse("taint(x)"),
    description="Taint sources are always tainted"
)

tainted_source_to_sink_is_vulnerability = Lemma(
    name="tainted_source_to_sink_is_vulnerability",
    antecedent=parse('source(input, "user") * taint(input) * output = input * sink(output, "sql")'),
    consequent=parse('error("taint_flow")'),
    description="Direct taint flow from source to sink is a vulnerability"
)


# =============================================================================
# Heap-Based Taint Lemmas
# =============================================================================

heap_taint_propagation = Lemma(
    name="heap_taint_propagation",
    antecedent=parse("x |-> s * taint(s)"),
    consequent=parse("taint(x)"),
    description="If heap location x stores tainted value s, then x is tainted"
)

heap_load_taint = Lemma(
    name="heap_load_taint",
    antecedent=parse("x |-> y * taint(x)"),
    consequent=parse("taint(y)"),
    description="Loading from tainted pointer yields tainted value"
)

alias_preserves_taint = Lemma(
    name="alias_preserves_taint",
    antecedent=parse("taint(x) * y = x"),
    consequent=parse("taint(y)"),
    description="Aliasing preserves taint (y points to same tainted data as x)"
)


# =============================================================================
# Transitive Taint Lemmas
# =============================================================================

taint_transitivity = Lemma(
    name="taint_transitivity",
    antecedent=parse("taint(x) * y = x * z = y"),
    consequent=parse("taint(z)"),
    description="Taint is transitive through equality chain"
)

concat_chain_taint = Lemma(
    name="concat_chain_taint",
    antecedent=parse("taint(x) * y = prefix ++ x * z = y ++ suffix"),
    consequent=parse("taint(z)"),
    description="Taint propagates through concatenation chain"
)


# =============================================================================
# Specific Vulnerability Patterns
# =============================================================================

sql_injection_pattern = Lemma(
    name="sql_injection_pattern",
    antecedent=parse(
        'source(user_input, "user") * '
        'taint(user_input) * '
        'query = "SELECT * FROM users WHERE id=" ++ user_input * '
        'sink(query, "sql")'
    ),
    consequent=parse('error("SQL_INJECTION")'),
    description="SQL injection: tainted user input in SQL query"
)

xss_pattern = Lemma(
    name="xss_pattern",
    antecedent=parse(
        'source(user_input, "user") * '
        'taint(user_input) * '
        'html = "<div>" ++ user_input ++ "</div>" * '
        'sink(html, "html")'
    ),
    consequent=parse('error("XSS")'),
    description="Cross-site scripting: tainted user input in HTML"
)

command_injection_pattern = Lemma(
    name="command_injection_pattern",
    antecedent=parse(
        'source(user_input, "user") * '
        'taint(user_input) * '
        'cmd = "ls " ++ user_input * '
        'sink(cmd, "shell")'
    ),
    consequent=parse('error("COMMAND_INJECTION")'),
    description="Command injection: tainted user input in shell command"
)

path_traversal_pattern = Lemma(
    name="path_traversal_pattern",
    antecedent=parse(
        'source(user_input, "user") * '
        'taint(user_input) * '
        'path = "/var/www/" ++ user_input * '
        'sink(path, "filesystem") * '
        'path contains ".."'
    ),
    consequent=parse('error("PATH_TRAVERSAL")'),
    description="Path traversal: tainted user input with '..' in filesystem path"
)


# =============================================================================
# Safe Patterns (No Vulnerability)
# =============================================================================

sanitized_to_sink_safe = Lemma(
    name="sanitized_to_sink_safe",
    antecedent=parse(
        'source(user_input, "user") * '
        'clean = sanitize(user_input) * '
        'sanitized(clean) * '
        'sink(clean, "sql")'
    ),
    consequent=parse("true"),  # No error
    description="Sanitized data flowing to sink is safe"
)

constant_to_sink_safe = Lemma(
    name="constant_to_sink_safe",
    antecedent=parse('query = "SELECT * FROM users" * sink(query, "sql")'),
    consequent=parse("true"),  # No error
    description="Constant (non-tainted) data to sink is safe"
)


# =============================================================================
# Lemma Collections
# =============================================================================

STRING_TAINT_LEMMAS = [
    taint_concat_left,
    taint_concat_right,
    taint_substr,
    taint_length_independent,
]

SANITIZATION_LEMMAS = [
    sanitize_removes_taint,
    sanitized_not_tainted,
]

SOURCE_SINK_LEMMAS = [
    source_is_tainted,
    tainted_source_to_sink_is_vulnerability,
]

HEAP_TAINT_LEMMAS = [
    heap_taint_propagation,
    heap_load_taint,
    alias_preserves_taint,
]

TRANSITIVITY_LEMMAS = [
    taint_transitivity,
    concat_chain_taint,
]

VULNERABILITY_PATTERNS = [
    sql_injection_pattern,
    xss_pattern,
    command_injection_pattern,
    path_traversal_pattern,
]

SAFE_PATTERNS = [
    sanitized_to_sink_safe,
    constant_to_sink_safe,
]

ALL_TAINT_LEMMAS = (
    STRING_TAINT_LEMMAS +
    SANITIZATION_LEMMAS +
    SOURCE_SINK_LEMMAS +
    HEAP_TAINT_LEMMAS +
    TRANSITIVITY_LEMMAS +
    VULNERABILITY_PATTERNS +
    SAFE_PATTERNS
)


# =============================================================================
# Lemma Application Helper
# =============================================================================

def get_lemmas_for_source_type(source_type: str):
    """Get relevant lemmas for a specific taint source type

    Args:
        source_type: Type of taint source ("user", "network", "file", etc.)

    Returns:
        List of relevant lemmas
    """
    # For now, return all lemmas
    # In the future, could filter based on source type
    return ALL_TAINT_LEMMAS


def get_lemmas_for_sink_type(sink_type: str):
    """Get relevant lemmas for a specific taint sink type

    Args:
        sink_type: Type of taint sink ("sql", "shell", "html", etc.)

    Returns:
        List of relevant lemmas
    """
    sink_patterns = {
        "sql": [sql_injection_pattern],
        "html": [xss_pattern],
        "shell": [command_injection_pattern],
        "filesystem": [path_traversal_pattern],
    }

    specific = sink_patterns.get(sink_type, [])
    return specific + SOURCE_SINK_LEMMAS + STRING_TAINT_LEMMAS


def get_vulnerability_pattern_for_sink(sink_type: str):
    """Get the specific vulnerability pattern lemma for a sink type

    Args:
        sink_type: Type of taint sink

    Returns:
        Vulnerability pattern lemma or None
    """
    patterns = {
        "sql": sql_injection_pattern,
        "html": xss_pattern,
        "shell": command_injection_pattern,
        "filesystem": path_traversal_pattern,
    }
    return patterns.get(sink_type)
