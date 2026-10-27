"""One finding model for every domain: a category (what kind of weakness) and an evidence
level (how strongly it is proven). Both are reported in the JSON and SARIF output.

Evidence, weakest to strongest:
- ``matched``: a usage or a pattern, with no data flow (a weak hash call, a hardcoded key,
  a protection switched off).
- ``llm-detected``: proposed by the LLM layer, not grounded in a sink Frame recognises.
- ``llm-verified``: proposed by the LLM layer and grounded in a sink Frame recognises.
- ``data-flow``: a source-to-sink path found by the taint analysis.
- ``solver-verified``: a path the solver proved reachable (incorrectness logic witness).
- ``exploit-confirmed``: reproduced against a live target (``frame exploit``).

Categories: ``taint`` (injection and other attacker-data flows), ``memory`` (C/C++ memory and
undefined behaviour), ``crypto``, ``secret``, ``access-control``, ``hardening``, and, for the
domains still to come, ``dependency``, ``iac``, ``container`` and ``ai``.
"""

from __future__ import annotations

EVIDENCE_LEVELS = ("matched", "llm-detected", "llm-verified", "data-flow", "solver-verified",
                   "exploit-confirmed")
CATEGORIES = ("taint", "memory", "crypto", "secret", "access-control", "hardening",
              "dependency", "iac", "container", "ai")

_GROUPS = {
    "memory": {
        "null_dereference", "use_after_free", "buffer_overflow", "buffer_underflow", "double_free",
        "memory_leak", "mismatched_free", "return_stack_address", "invalid_free", "resource_leak",
        "format_string", "integer_overflow", "integer_underflow", "uninitialized_var",
        "divide_by_zero", "type_confusion", "sign_extension", "oob_write", "oob_read",
        "oob_underwrite", "oob_underread", "unbounded_allocation", "excessive_allocation",
        "uncontrolled_recursion", "infinite_loop", "dead_store", "improper_lock", "unchecked_loop",
        "data_sentinel", "unicode_handling", "assertion_failure", "incomplete_cleanup",
        "improper_init", "dangerous_function", "unchecked_return"},
    "crypto": {
        "weak_crypto", "insecure_random", "predictable_value", "weak_hash", "improper_cert_validation",
        "insufficient_key_size", "weak_rsa_padding", "missing_encryption",
        "insufficient_credential_protection", "insecure_cookie", "insecure_cookie_httponly"},
    "secret": {
        "hardcoded_secret", "secret_exposure", "sensitive_data_exposure", "sensitive_data_logged",
        "weak_password"},
    "access-control": {
        "authorization_bypass", "idor", "mass_assignment", "csrf", "session_fixation",
        "broken_authentication", "credential_stuffing", "business_logic_flaw", "race_condition",
        "privilege_management", "incorrect_permissions", "trust_boundary_violation",
        "cors_misconfiguration"},
    "dependency": {"vulnerable_dependency"},
    "hardening": {
        "debug_enabled", "security_misconfiguration", "error_disclosure", "ci_cd_vulnerability",
        "code_integrity", "insufficient_logging", "unhandled_exception", "improper_error_handling",
        "insecure_temp_file", "untrusted_path"},
}
_CATEGORY_OF = {t: c for c, types in _GROUPS.items() for t in types}


def category_of(vuln_type: str, explicit: str = "") -> str:
    """The finding's category: an explicit one (set by a domain, e.g. ``hardening``), else
    the group of its type, else ``taint``."""
    return explicit or _CATEGORY_OF.get(vuln_type, "taint")


def evidence_of_check(verified: bool, has_flow: bool) -> str:
    """Evidence for a finding from the symbolic analysis."""
    if verified and has_flow:
        return "solver-verified"
    return "data-flow" if has_flow else "matched"
