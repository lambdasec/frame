"""
SIL to Frame Formula Translator.

This module translates SIL programs to Frame separation logic formulas
for vulnerability verification.

The translation performs symbolic execution over the SIL CFG:
1. Track symbolic state (heap, taint, sanitization)
2. At each sink, generate a vulnerability check formula
3. Use Frame's incorrectness checker to verify if vulnerability is reachable

Key insight: We generate formulas only at security-relevant points (sinks),
not for every instruction. This keeps formulas small and verification fast.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum, auto

from frame.core.ast import (
    Formula, Emp, PointsTo, SepConj, And, Or, Not, Eq, Neq,
    Var, Const, Taint, Sanitized, Source, Sink,
    NullDeref, UseAfterFree, BufferOverflow, Exists,
    PredicateCall, Lt, Le, Gt, Ge, True_
)

from .types import (
    Ident, PVar, Location, Typ, TypeKind,
    Exp, ExpVar, ExpConst, ExpBinOp, ExpUnOp,
    ExpFieldAccess, ExpIndex, ExpStringConcat, ExpCall, ExpTernary, ExpCast
)
from .instructions import (
    Instr, Load, Store, Alloc, Free, Prune, Call, Assign,
    TaintSource, TaintSink, Sanitize, AssertSafe, Return,
    TaintKind, SinkKind, resolve_sink_kind
)
from .procedure import Procedure, Node, NodeKind, Program, ProcSpec


# =============================================================================
# Vulnerability Types
# =============================================================================

class VulnType(Enum):
    """
    Types of vulnerabilities that can be detected.

    Organized by OWASP Top 10 2025 categories for comprehensive coverage.
    """
    # A01: Broken Access Control
    PATH_TRAVERSAL = "path_traversal"           # CWE-22
    OPEN_REDIRECT = "open_redirect"             # CWE-601
    SSRF = "ssrf"                               # CWE-918
    AUTHORIZATION_BYPASS = "authorization_bypass"  # CWE-863
    CORS_MISCONFIGURATION = "cors_misconfiguration"  # CWE-942
    IDOR = "idor"                               # CWE-639

    # A02: Security Misconfiguration
    HEADER_INJECTION = "header_injection"       # CWE-113
    SECRET_EXPOSURE = "secret_exposure"         # CWE-200
    DEBUG_ENABLED = "debug_enabled"             # CWE-215
    SECURITY_MISCONFIGURATION = "security_misconfiguration"  # CWE-16

    # A03: Software Supply Chain Failures
    # Note: Requires SCA tools, out of scope for SAST/taint analysis

    # A04: Cryptographic Failures
    WEAK_CRYPTOGRAPHY = "weak_crypto"     # CWE-327 (OWASP expects "weak_crypto")
    HARDCODED_SECRET = "hardcoded_secret"       # CWE-798
    INSECURE_RANDOM = "insecure_random"         # CWE-330
    WEAK_HASH = "weak_hash"                     # CWE-328
    IMPROPER_CERT_VALIDATION = "improper_cert_validation"  # CWE-295
    INSUFFICIENT_KEY_SIZE = "insufficient_key_size"  # CWE-326
    WEAK_RSA_PADDING = "weak_rsa_padding"       # CWE-780
    INSUFFICIENT_CREDENTIAL_PROTECTION = "insufficient_credential_protection"  # CWE-522
    MISSING_ENCRYPTION = "missing_encryption"   # CWE-311
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"  # CWE-200

    # A05: Injection
    SQL_INJECTION = "sql_injection"             # CWE-89
    XSS = "xss"                                 # CWE-79
    COMMAND_INJECTION = "command_injection"     # CWE-78
    LDAP_INJECTION = "ldap_injection"           # CWE-90
    XPATH_INJECTION = "xpath_injection"         # CWE-643
    XML_INJECTION = "xml_injection"             # CWE-91
    CODE_INJECTION = "code_injection"           # CWE-94
    TEMPLATE_INJECTION = "template_injection"   # CWE-1336
    NOSQL_INJECTION = "nosql_injection"         # CWE-943
    XXE = "xxe"                                 # CWE-611
    REGEX_DOS = "regex_dos"                     # CWE-1333
    ORM_INJECTION = "orm_injection"             # CWE-89
    EL_INJECTION = "el_injection"               # CWE-917

    # A06: Insecure Design
    MASS_ASSIGNMENT = "mass_assignment"         # CWE-915
    PROTOTYPE_POLLUTION = "prototype_pollution" # CWE-1321
    BUSINESS_LOGIC_FLAW = "business_logic_flaw" # CWE-840
    RACE_CONDITION = "race_condition"           # CWE-362

    # A07: Authentication Failures
    BROKEN_AUTHENTICATION = "broken_authentication"  # CWE-287
    CREDENTIAL_STUFFING = "credential_stuffing"  # CWE-307
    SESSION_FIXATION = "session_fixation"       # CWE-384
    WEAK_PASSWORD = "weak_password"             # CWE-521
    TRUST_BOUNDARY_VIOLATION = "trust_boundary_violation"  # CWE-501
    INSECURE_COOKIE = "insecure_cookie"         # CWE-614
    INSECURE_COOKIE_HTTPONLY = "insecure_cookie_httponly"  # CWE-1004
    CSRF = "csrf"                               # CWE-352 (CSRF protection disabled)

    # A08: Software/Data Integrity Failures
    DESERIALIZATION = "deserialization"         # CWE-502
    CODE_INTEGRITY = "code_integrity"           # CWE-494
    CI_CD_VULNERABILITY = "ci_cd_vulnerability" # CWE-1395

    # A09: Logging & Alerting Failures
    LOG_INJECTION = "log_injection"             # CWE-117
    SENSITIVE_DATA_LOGGED = "sensitive_data_logged"  # CWE-532
    INSUFFICIENT_LOGGING = "insufficient_logging"  # CWE-778

    # A10: Mishandling of Exceptional Conditions
    ERROR_DISCLOSURE = "error_disclosure"       # CWE-209
    UNHANDLED_EXCEPTION = "unhandled_exception" # CWE-755
    IMPROPER_ERROR_HANDLING = "improper_error_handling"  # CWE-388

    # Memory Safety (critical for native code)
    NULL_DEREFERENCE = "null_dereference"       # CWE-476
    USE_AFTER_FREE = "use_after_free"           # CWE-416
    BUFFER_OVERFLOW = "buffer_overflow"         # CWE-120
    BUFFER_UNDERFLOW = "buffer_underflow"       # CWE-124/127 (underread/underwrite)
    DOUBLE_FREE = "double_free"                 # CWE-415
    MEMORY_LEAK = "memory_leak"                 # CWE-401
    MISMATCHED_FREE = "mismatched_free"         # CWE-762 (deallocator does not match allocator)
    RETURN_STACK_ADDRESS = "return_stack_address"  # CWE-562 (return of a local's address)
    INVALID_FREE = "invalid_free"               # CWE-590 (free of non-heap memory)
    RESOURCE_LEAK = "resource_leak"             # CWE-404 (improper resource shutdown)
    FORMAT_STRING = "format_string"             # CWE-134
    INTEGER_OVERFLOW = "integer_overflow"       # CWE-190
    INTEGER_UNDERFLOW = "integer_underflow"     # CWE-191
    UNINITIALIZED_VAR = "uninitialized_var"     # CWE-457
    DANGEROUS_FUNCTION = "dangerous_function"   # CWE-676
    DIVIDE_BY_ZERO = "divide_by_zero"           # CWE-369
    TYPE_CONFUSION = "type_confusion"           # CWE-843
    ASSERTION_FAILURE = "assertion_failure"     # CWE-617
    SIGN_EXTENSION = "sign_extension"           # CWE-194
    UNICODE_HANDLING = "unicode_handling"       # CWE-176
    CONFIG_INJECTION = "config_injection"       # CWE-15

    # Additional memory safety and resource management
    RESOURCE_EXHAUSTION = "resource_exhaustion" # CWE-400
    UNCHECKED_RETURN = "unchecked_return"       # CWE-252/253
    INSECURE_TEMP_FILE = "insecure_temp_file"   # CWE-377
    INCOMPLETE_CLEANUP = "incomplete_cleanup"   # CWE-459
    DEAD_STORE = "dead_store"                   # CWE-563
    IMPROPER_LOCK = "improper_lock"             # CWE-591
    UNCHECKED_LOOP = "unchecked_loop"           # CWE-606
    IMPROPER_INITIALIZATION = "improper_init"   # CWE-665
    UNTRUSTED_SEARCH_PATH = "untrusted_path"    # CWE-426/427
    DATA_SENTINEL = "data_sentinel"             # CWE-464

    # Resource exhaustion (the CWE-400 cluster). Frame reports the specific
    # child weakness, never the CWE-400 parent: `cwe_taxonomy.is_a` already makes
    # each of these satisfy a query for CWE-400.
    UNBOUNDED_ALLOCATION = "unbounded_allocation"    # CWE-770
    UNCONTROLLED_RECURSION = "uncontrolled_recursion"  # CWE-674
    INFINITE_LOOP = "infinite_loop"                  # CWE-835

    # Memory safety, reported by direction. CWE-120 stays the answer whenever a
    # buffer is overrun but the direction is not established; these two are used
    # only where the IR settles it, a Store being a write and a read position a
    # read.
    OOB_WRITE = "oob_write"                          # CWE-787
    OOB_READ = "oob_read"                            # CWE-125

    # Excessive constant allocation, the sibling of UNBOUNDED_ALLOCATION: there
    # the size is attacker-controlled, here it is written into the program.
    EXCESSIVE_ALLOCATION = "excessive_allocation"    # CWE-789

    # Permission assignment. CWE-754 is not a type of its own: CWE-252 is its
    # MITRE child, so `cwe_taxonomy.is_a` already answers a CWE-754 query.
    INCORRECT_PERMISSIONS = "incorrect_permissions"  # CWE-732

    # Generic taint flow
    TAINT_FLOW = "taint_flow"

    @classmethod
    def from_sink_kind(cls, sink_kind: SinkKind) -> 'VulnType':
        """Map sink kind to vulnerability type"""
        mapping = {
            # A05: Injection
            SinkKind.SQL_QUERY: cls.SQL_INJECTION,
            SinkKind.HTML_OUTPUT: cls.XSS,
            SinkKind.SHELL_COMMAND: cls.COMMAND_INJECTION,
            SinkKind.LDAP_QUERY: cls.LDAP_INJECTION,
            SinkKind.XPATH_QUERY: cls.XPATH_INJECTION,
            SinkKind.XML_INJECTION: cls.XML_INJECTION,
            SinkKind.EVAL: cls.CODE_INJECTION,
            SinkKind.TEMPLATE: cls.TEMPLATE_INJECTION,
            SinkKind.NOSQL_QUERY: cls.NOSQL_INJECTION,
            SinkKind.XML_PARSE: cls.XXE,
            SinkKind.REGEX: cls.REGEX_DOS,
            SinkKind.ORM_QUERY: cls.ORM_INJECTION,
            SinkKind.EXPRESSION_LANG: cls.EL_INJECTION,
            # A01: Broken Access Control
            SinkKind.FILE_PATH: cls.PATH_TRAVERSAL,
            SinkKind.REDIRECT: cls.OPEN_REDIRECT,
            SinkKind.SSRF: cls.SSRF,
            SinkKind.AUTHZ_CHECK: cls.AUTHORIZATION_BYPASS,
            SinkKind.RESOURCE_SELECT: cls.IDOR,
            SinkKind.CORS: cls.CORS_MISCONFIGURATION,
            # A02: Security Misconfiguration
            SinkKind.HEADER: cls.HEADER_INJECTION,
            SinkKind.SECRET_EXPOSURE: cls.SECRET_EXPOSURE,
            SinkKind.DEBUG_INFO: cls.DEBUG_ENABLED,
            # A04: Cryptographic Failures
            SinkKind.WEAK_CRYPTO: cls.WEAK_CRYPTOGRAPHY,
            SinkKind.HARDCODED_SECRET: cls.HARDCODED_SECRET,
            SinkKind.INSECURE_RANDOM: cls.INSECURE_RANDOM,
            SinkKind.WEAK_HASH: cls.WEAK_HASH,
            SinkKind.CERT_VALIDATION: cls.IMPROPER_CERT_VALIDATION,
            SinkKind.WEAK_KEY_SIZE: cls.INSUFFICIENT_KEY_SIZE,
            SinkKind.WEAK_RSA_PADDING: cls.WEAK_RSA_PADDING,
            SinkKind.INSECURE_AUTH: cls.INSUFFICIENT_CREDENTIAL_PROTECTION,
            SinkKind.INSECURE_TEMP_FILE: cls.INSECURE_TEMP_FILE,
            SinkKind.PROTOTYPE_POLLUTION: cls.PROTOTYPE_POLLUTION,
            # Resource exhaustion
            SinkKind.ALLOC_SIZE: cls.UNBOUNDED_ALLOCATION,
            # A07: Authentication Failures
            SinkKind.CREDENTIAL: cls.BROKEN_AUTHENTICATION,
            SinkKind.SESSION: cls.SESSION_FIXATION,
            SinkKind.PASSWORD_STORE: cls.WEAK_PASSWORD,
            SinkKind.TRUST_BOUNDARY: cls.TRUST_BOUNDARY_VIOLATION,
            SinkKind.INSECURE_COOKIE: cls.INSECURE_COOKIE,
            SinkKind.INSECURE_COOKIE_HTTPONLY: cls.INSECURE_COOKIE_HTTPONLY,
            SinkKind.CSRF_DISABLED: cls.CSRF,
            # A08: Software/Data Integrity Failures
            SinkKind.DESERIALIZATION: cls.DESERIALIZATION,
            SinkKind.DESERIALIZE_UNSAFE: cls.DESERIALIZATION,
            # A09: Logging Failures
            SinkKind.LOG: cls.LOG_INJECTION,
            SinkKind.SENSITIVE_LOG: cls.SENSITIVE_DATA_LOGGED,
            # A10: Error Handling
            SinkKind.ERROR_DISCLOSURE: cls.ERROR_DISCLOSURE,
            # Aliases for flexibility
            SinkKind.XSS: cls.XSS,
            SinkKind.COMMAND: cls.COMMAND_INJECTION,
            SinkKind.FORMAT_STRING: cls.FORMAT_STRING,
            SinkKind.FORMAT: cls.FORMAT_STRING,
            # Memory safety
            SinkKind.BUFFER_OVERFLOW: cls.BUFFER_OVERFLOW,
            SinkKind.DANGEROUS_FUNCTION: cls.DANGEROUS_FUNCTION,
            SinkKind.INTEGER_OVERFLOW: cls.INTEGER_OVERFLOW,
            SinkKind.NULL_DEREF: cls.NULL_DEREFERENCE,
            SinkKind.DIVIDE_BY_ZERO: cls.DIVIDE_BY_ZERO,
        }
        return mapping.get(sink_kind, cls.TAINT_FLOW)


# =============================================================================
# Vulnerability Check
# =============================================================================

@dataclass
class VulnerabilityCheck:
    """
    A potential vulnerability to verify with Frame.

    Contains the Frame formula representing the vulnerability condition
    and metadata for reporting.
    """
    # Frame formula for the vulnerability condition
    formula: Formula

    # Vulnerability type
    vuln_type: VulnType

    # Source location of the sink
    location: Location

    # Description for reporting
    description: str

    # Additional metadata
    tainted_var: str = ""
    source_var: str = ""
    source_location: Optional[Location] = None
    sink_type: str = ""
    procedure_name: str = ""

    # Data flow path (list of variables/expressions)
    data_flow_path: List[str] = field(default_factory=list)

    # Per-edge branch conditions assumed on the path to this sink (pure formulas).
    # If their conjunction is unsatisfiable the sink is on an infeasible path and
    # the check is dropped. Populated after the fact (never prunes execution).
    path_condition: List[Formula] = field(default_factory=list)

    def __str__(self) -> str:
        return f"VulnerabilityCheck({self.vuln_type.value} at {self.location})"


# =============================================================================
# Symbolic State
# =============================================================================

@dataclass
class TaintInfo:
    """Information about a tainted value"""
    source_kind: TaintKind
    source_var: str
    source_location: Location
    propagation_path: List[str] = field(default_factory=list)


@dataclass
class SymbolicState:
    """
    Symbolic state during SIL translation.

    Tracks:
    - Heap state (what's allocated, what values are stored)
    - Taint state (what's tainted, from where)
    - Sanitization state (what's been sanitized)
    - Path constraints (conditions along current path)
    - Freed pointers (for use-after-free detection)
    - List element state (per-element taint tracking using separation logic)
    """

    # Heap: variable/location -> symbolic value
    heap: Dict[str, str] = field(default_factory=dict)

    # Allocation state: variable -> is_allocated
    allocated: Dict[str, bool] = field(default_factory=dict)

    # Taint state: variable -> TaintInfo
    tainted: Dict[str, TaintInfo] = field(default_factory=dict)

    # Sanitization: variable -> list of sink types sanitized for
    sanitized: Dict[str, List[str]] = field(default_factory=dict)

    # Freed pointers
    freed: Set[str] = field(default_factory=set)

    # Pointers that are DEFINITELY null on this path (var -> the location where
    # it became null). Populated only for a null literal assignment (`p = NULL`
    # / `p = 0`); an allocator result is deliberately NOT tracked here, because a
    # malloc-then-deref is the common correct idiom and firing on it would be
    # indistinguishable from correct code. A deref of a var still in this set is
    # a provable CWE-476.
    null_ptrs: Dict[str, object] = field(default_factory=dict)

    # Origin of a pointer's storage: "heap" (malloc/new), "stack" (a fixed local
    # array or the address of a local). Used to decide CWE-590: freeing a var
    # whose origin is "stack" frees memory that was never on the heap. A var with
    # no entry has an unknown origin and is left alone (precision over recall).
    heap_origin: Dict[str, str] = field(default_factory=dict)

    # The allocator FAMILY a heap pointer came from: "c_heap" (malloc/calloc/...),
    # "new" (scalar `new`), or "new_array" (`new[]`). This is the origin refined
    # to a kind, used only for CWE-762: the one correct release for each family
    # is fixed (free / delete / delete[]), so a deallocator of the wrong shape on
    # a pointer whose kind is known is a provable mismatch. Unknown-kind pointers
    # are left alone.
    alloc_kind: Dict[str, str] = field(default_factory=dict)

    # Ownership of live heap allocations, for CWE-401. Maps a pointer variable to
    # the identity of the allocation it currently owns (id() of the allocating
    # instruction). An allocation is LIVE exactly while some variable maps to it;
    # it LEAKS when its last owner is overwritten (reassignment) or the function
    # exits still owning it, and is safe once freed, returned, or passed out
    # (escape), which drop every owner. Merged by intersection, so an allocation
    # counts as owned at a join only when it was owned on both incoming paths.
    owned_allocs: Dict[str, object] = field(default_factory=dict)

    # Path constraints (pure formulas)
    path_constraints: List[Formula] = field(default_factory=list)

    # Assert-safe variables
    asserted_safe: Dict[str, List[str]] = field(default_factory=dict)

    # Per-element list tracking (separation logic approach)
    # list_elements: list_var -> list of (value, taint_info or None)
    # Each element is tracked separately: ArrayPointsTo(lst, i, v_i) * ...
    list_elements: Dict[str, List[Tuple[str, Optional[TaintInfo]]]] = field(default_factory=dict)

    # Constant tracking for constant folding
    # constants: var -> numeric or string value
    constants: Dict[str, any] = field(default_factory=dict)

    # Secure parser tracking (for XXE mitigation)
    # secure_parsers: set of variable names that hold secure XML parsers
    secure_parsers: Set[str] = field(default_factory=set)

    # Variables that have been safely processed for xml sinks
    # (e.g., passed through a secure XML parser)
    safe_for_xml_sink: Set[str] = field(default_factory=set)

    # Variables that have been validated for code injection
    # (e.g., passed through startswith/endswith validation)
    validated_for_eval: Set[str] = field(default_factory=set)

    # Per-key dictionary tracking (separation logic approach)
    # dict_elements: dict_var -> {key: (value, taint_info or None)}
    # Each key is tracked separately for precise taint tracking
    dict_elements: Dict[str, Dict[str, Tuple[str, Optional[TaintInfo]]]] = field(default_factory=dict)

    # Class member tracking for inter-procedural analysis (CWE-415/416)
    # Tracks: object_var -> {member_name -> allocation_state}
    # allocation_state: "allocated", "freed", or "unknown"
    object_members: Dict[str, Dict[str, str]] = field(default_factory=dict)

    # Per-edge branch conditions (pure formulas) assumed on the path to here.
    # Recorded as data only -- never used to prune execution -- and checked for
    # satisfiability when a finding is created, so an infeasible path is dropped
    # without disturbing the state-merge fixpoint.
    feasibility_constraints: List[Formula] = field(default_factory=list)

    def copy(self) -> 'SymbolicState':
        """Create a deep copy for branching"""
        return SymbolicState(
            heap=dict(self.heap),
            allocated=dict(self.allocated),
            tainted={k: TaintInfo(
                v.source_kind, v.source_var, v.source_location,
                list(v.propagation_path)
            ) for k, v in self.tainted.items()},
            sanitized={k: list(v) for k, v in self.sanitized.items()},
            freed=set(self.freed),
            null_ptrs=dict(self.null_ptrs),
            heap_origin=dict(self.heap_origin),
            alloc_kind=dict(self.alloc_kind),
            owned_allocs=dict(self.owned_allocs),
            path_constraints=list(self.path_constraints),
            asserted_safe={k: list(v) for k, v in self.asserted_safe.items()},
            list_elements={k: list(v) for k, v in self.list_elements.items()},
            constants=dict(self.constants),
            secure_parsers=set(self.secure_parsers),
            safe_for_xml_sink=set(self.safe_for_xml_sink),
            validated_for_eval=set(self.validated_for_eval),
            dict_elements={k: dict(v) for k, v in self.dict_elements.items()},
            object_members={k: dict(v) for k, v in self.object_members.items()},
            feasibility_constraints=list(self.feasibility_constraints),
        )

    def set_constant(self, var: str, value: any) -> None:
        """Track a constant value for a variable"""
        self.constants[var] = value

    def get_constant(self, var: str) -> Optional[any]:
        """Get constant value if known"""
        return self.constants.get(var)

    def try_eval_expr(self, expr_str: str) -> Optional[any]:
        """Try to evaluate an expression using known constants"""
        import re

        expr_stripped = expr_str.strip()

        # Handle prefix notation: (== guess "A") or (== guess 'A')
        prefix_eq_match = re.match(
            r'^\(==\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+["\']([^"\']*)["\'](?:.*)\)$',
            expr_stripped
        )
        if prefix_eq_match:
            var_name = prefix_eq_match.group(1)
            pattern_val = prefix_eq_match.group(2)
            var_val = self.constants.get(var_name)
            if var_val is not None and isinstance(var_val, str):
                return var_val == pattern_val

        # Handle string containment: 'substring' in var_name
        # Patterns: "'should' in bar", '"should" in bar', '("should" in bar)'
        contain_match = re.match(
            r'^\(?["\']([^"\']*)["\'](?:\s+)?in(?:\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\)?$',
            expr_stripped
        )
        if contain_match:
            substring = contain_match.group(1)
            var_name = contain_match.group(2)
            var_val = self.constants.get(var_name)
            if var_val is not None and isinstance(var_val, str):
                return substring in var_val

        # Handle prefix notation containment: (in "should" bar)
        prefix_contain_match = re.match(
            r'^\(in\s+["\']([^"\']*)["\'](?:\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\)$',
            expr_stripped
        )
        if prefix_contain_match:
            substring = prefix_contain_match.group(1)
            var_name = prefix_contain_match.group(2)
            var_val = self.constants.get(var_name)
            if var_val is not None and isinstance(var_val, str):
                return substring in var_val

        # Handle infix notation: guess == 'B' or guess == "B"
        string_eq_match = re.match(
            r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*==\s*["\']([^"\']*)["\']$',
            expr_stripped
        )
        if string_eq_match:
            var_name = string_eq_match.group(1)
            pattern_val = string_eq_match.group(2)
            var_val = self.constants.get(var_name)
            if var_val is not None and isinstance(var_val, str):
                return var_val == pattern_val

        # Substitute known constants for arithmetic
        result_expr = expr_str
        for var, val in self.constants.items():
            # Replace variable with its value
            if isinstance(val, str):
                # Quote strings for eval
                result_expr = re.sub(rf'\b{re.escape(var)}\b', f'"{val}"', result_expr)
            else:
                result_expr = re.sub(rf'\b{re.escape(var)}\b', str(val), result_expr)

        # Try to evaluate if it looks safe (only numbers, operators, comparisons)
        if re.match(r'^[\d\s\+\-\*/%<>=!()]+$', result_expr):
            try:
                return eval(result_expr)
            except:
                pass

        # Also try evaluating string comparisons
        if re.match(r'^["\'][^"\']*["\']\s*==\s*["\'][^"\']*["\']$', result_expr.strip()):
            try:
                return eval(result_expr)
            except:
                pass

        return None

    # =========================================================================
    # List Element Tracking (Separation Logic Approach)
    # =========================================================================

    def init_list(self, list_var: str) -> None:
        """Initialize an empty list: lst = []"""
        self.list_elements[list_var] = []

    def list_append(self, list_var: str, value: str, taint_info: Optional[TaintInfo] = None) -> None:
        """Append element to list: lst.append(val)

        In separation logic terms: lst_state * ArrayPointsTo(lst, len, val)
        """
        if list_var not in self.list_elements:
            self.list_elements[list_var] = []
        self.list_elements[list_var].append((value, taint_info))

    def list_pop(self, list_var: str, index: int = -1) -> Optional[Tuple[str, Optional[TaintInfo]]]:
        """Pop element from list: lst.pop(i)

        Removes element at index and shifts remaining elements.
        Returns the (value, taint_info) of the removed element.
        """
        if list_var not in self.list_elements or not self.list_elements[list_var]:
            return None

        elements = self.list_elements[list_var]
        if index == -1:
            index = len(elements) - 1

        if 0 <= index < len(elements):
            return elements.pop(index)
        return None

    def list_get(self, list_var: str, index: int) -> Optional[Tuple[str, Optional[TaintInfo]]]:
        """Get element at index: lst[i]

        Returns (value, taint_info) for the element, or None if out of bounds.
        """
        if list_var not in self.list_elements:
            return None

        elements = self.list_elements[list_var]
        if 0 <= index < len(elements):
            return elements[index]
        return None

    def is_list_element_tainted(self, list_var: str, index: int) -> bool:
        """Check if specific list element is tainted (separation logic query)"""
        result = self.list_get(list_var, index)
        if result is None:
            # Unknown index - fall back to coarse-grained check
            return self.is_tainted(list_var)
        _, taint_info = result
        return taint_info is not None

    def get_list_element_taint(self, list_var: str, index: int) -> Optional[TaintInfo]:
        """Get taint info for specific list element"""
        result = self.list_get(list_var, index)
        if result is None:
            return self.get_taint_info(list_var)
        _, taint_info = result
        return taint_info

    def is_tracked_list(self, list_var: str) -> bool:
        """Check if we're tracking per-element taint for this list"""
        return list_var in self.list_elements

    # =========================================================================
    # Dictionary Element Tracking (Separation Logic Approach)
    # =========================================================================

    def init_dict(self, dict_var: str) -> None:
        """Initialize an empty dictionary: d = {}"""
        self.dict_elements[dict_var] = {}

    def dict_set(self, dict_var: str, key: str, value: str, taint_info: Optional[TaintInfo] = None) -> None:
        """Set dictionary key: d[key] = value

        In separation logic terms: dict_state * DictPointsTo(d, key, val)
        """
        if dict_var not in self.dict_elements:
            self.dict_elements[dict_var] = {}
        self.dict_elements[dict_var][key] = (value, taint_info)

    def dict_get(self, dict_var: str, key: str) -> Optional[Tuple[str, Optional[TaintInfo]]]:
        """Get value at key: d[key]

        Returns (value, taint_info) for the key, or None if not found.
        """
        if dict_var not in self.dict_elements:
            return None
        return self.dict_elements[dict_var].get(key)

    def is_dict_key_tainted(self, dict_var: str, key: str) -> bool:
        """Check if specific dictionary key is tainted (separation logic query)"""
        result = self.dict_get(dict_var, key)
        if result is None:
            # Unknown key - fall back to coarse-grained check
            return self.is_tainted(dict_var)
        _, taint_info = result
        return taint_info is not None

    def get_dict_key_taint(self, dict_var: str, key: str) -> Optional[TaintInfo]:
        """Get taint info for specific dictionary key"""
        result = self.dict_get(dict_var, key)
        if result is None:
            return self.get_taint_info(dict_var)
        _, taint_info = result
        return taint_info

    def is_tracked_dict(self, dict_var: str) -> bool:
        """Check if we're tracking per-key taint for this dictionary"""
        return dict_var in self.dict_elements

    def is_tainted(self, var: str) -> bool:
        """Check if variable is tainted"""
        return var in self.tainted

    def get_taint_info(self, var: str) -> Optional[TaintInfo]:
        """Get taint information for a variable"""
        return self.tainted.get(var)

    def is_sanitized_for(self, var: str, sink_type: str) -> bool:
        """Check if variable is sanitized for given sink type"""
        return sink_type in self.sanitized.get(var, [])

    def is_asserted_safe_for(self, var: str, sink_type: str) -> bool:
        """Check if variable is asserted safe for given sink type"""
        safe_for = self.asserted_safe.get(var, [])
        return sink_type in safe_for or len(safe_for) == 0 and var in self.asserted_safe

    def is_freed(self, var: str) -> bool:
        """Check if pointer has been freed"""
        return var in self.freed

    def is_allocated(self, var: str) -> bool:
        """Check if pointer is allocated"""
        return self.allocated.get(var, False)

    def add_taint(self, var: str, info: TaintInfo) -> None:
        """Mark variable as tainted"""
        self.tainted[var] = info

    def propagate_taint(self, from_var: str, to_var: str) -> None:
        """Propagate taint from one variable to another"""
        if from_var in self.tainted:
            info = self.tainted[from_var]
            new_path = info.propagation_path + [to_var]
            self.tainted[to_var] = TaintInfo(
                info.source_kind, info.source_var, info.source_location, new_path
            )
            # Also propagate sanitization - if source is sanitized, target should be too
            if from_var in self.sanitized:
                existing = self.sanitized.get(to_var, [])
                self.sanitized[to_var] = list(set(existing) | set(self.sanitized[from_var]))

    def add_sanitization(self, var: str, sink_types: List[str]) -> None:
        """Mark variable as sanitized"""
        self.sanitized[var] = sink_types

    def mark_freed(self, var: str) -> None:
        """Mark pointer as freed"""
        self.freed.add(var)
        self.allocated[var] = False

    def mark_allocated(self, var: str) -> None:
        """Mark pointer as allocated"""
        self.allocated[var] = True
        self.freed.discard(var)

    def set_member_state(self, obj_var: str, member: str, state: str) -> None:
        """Track class member allocation state: 'allocated', 'freed', or 'unknown'"""
        if obj_var not in self.object_members:
            self.object_members[obj_var] = {}
        self.object_members[obj_var][member] = state

    def get_member_state(self, obj_var: str, member: str) -> Optional[str]:
        """Get class member allocation state"""
        if obj_var not in self.object_members:
            return None
        return self.object_members[obj_var].get(member)

    def is_member_freed(self, obj_var: str, member: str) -> bool:
        """Check if object member has been freed"""
        return self.get_member_state(obj_var, member) == "freed"

    def is_member_allocated(self, obj_var: str, member: str) -> bool:
        """Check if object member is allocated"""
        return self.get_member_state(obj_var, member) == "allocated"


# =============================================================================
# Procedure Summary for Inter-Procedural Analysis
# =============================================================================

@dataclass
class ParameterEffect:
    """Effect of a procedure on a parameter"""
    param_index: int           # Which parameter (0-indexed)
    param_name: str           # Parameter name
    is_freed: bool = False    # Does procedure free this parameter?
    is_dereferenced: bool = False  # Does procedure dereference this parameter?
    is_returned: bool = False # Is this parameter returned?
    is_stored_to_member: bool = False  # Stored to class member?
    member_name: Optional[str] = None  # Which member it's stored to


@dataclass
class ProcedureSummary:
    """
    Summary of a procedure's effects for inter-procedural analysis.

    This enables tracking data flow across procedure boundaries:
    - Which parameters are freed (for double-free detection)
    - Which parameters are dereferenced (for use-after-free detection)
    - Which parameters flow to return value
    - Class member effects (for constructor/destructor analysis)
    """
    proc_name: str

    # Parameter effects
    param_effects: List[ParameterEffect] = field(default_factory=list)

    # Does this procedure allocate and return the result?
    returns_allocation: bool = False

    # Does this procedure free a class member?
    frees_member: Optional[str] = None

    # Does this procedure allocate to a class member?
    allocates_member: Optional[str] = None

    # Is this a constructor?
    is_constructor: bool = False

    # Is this a destructor?
    is_destructor: bool = False

    # Which class members become tainted (e.g., from user input sources)
    # Maps member name -> taint source kind
    taints_member: Dict[str, str] = field(default_factory=dict)

    # Which class members are used as sinks
    # Maps member name -> sink type
    uses_member_as_sink: Dict[str, str] = field(default_factory=dict)

    def frees_param(self, param_idx: int) -> bool:
        """Check if this procedure frees the given parameter"""
        for effect in self.param_effects:
            if effect.param_index == param_idx and effect.is_freed:
                return True
        return False

    def derefs_param(self, param_idx: int) -> bool:
        """Check if this procedure dereferences the given parameter"""
        for effect in self.param_effects:
            if effect.param_index == param_idx and effect.is_dereferenced:
                return True
        return False


# =============================================================================
# SIL Translator
# =============================================================================

class SILTranslator:
    """
    Translates SIL programs to Frame formulas for vulnerability verification.

    Algorithm:
    1. For each procedure, perform symbolic execution over CFG
    2. Track taint propagation through assignments and calls
    3. At each sink, generate a VulnerabilityCheck if tainted data reaches it
    4. Return list of checks to verify with Frame's IncorrectnessChecker
    """

    def __init__(self, program: Program = None, verbose: bool = False):
        """
        Initialize the translator.

        Args:
            program: The SIL program (provides library specs)
            verbose: Enable verbose output
        """
        self.program = program or Program()
        self.verbose = verbose
        self.vulnerability_checks: List[VulnerabilityCheck] = []
        # Cache for procedures that always return constants
        self._constant_return_procs: Dict[str, bool] = {}
        # Inter-procedural analysis: procedure summaries
        self._proc_summaries: Dict[str, ProcedureSummary] = {}
        # Track which parameters are freed at each call site
        self._param_freed_at_callsite: Dict[str, Set[int]] = {}
        # Track tainted class members across methods (for format string, etc.)
        # Maps: class_name -> {member_name -> taint_source_kind}
        self._class_member_taints: Dict[str, Dict[str, str]] = {}
        # The procedure currently being executed (gives detectors access to its
        # fixed-array declarations for heap-origin reasoning).
        self._cur_proc: Optional[Procedure] = None
        # CWE-401 leak bookkeeping: allocation identity -> its source location, so
        # a leak reported when an allocation is lost or outlives its scope points
        # at the allocation site rather than the point of loss.
        self._leak_sites: Dict[object, Location] = {}

    @property
    def _is_c_lang(self) -> bool:
        """The heap-lifecycle deref detectors (CWE-476/416/590) reason about
        C-style raw pointers and only run for C/C++. Other frontends have no
        `free`/`malloc` and no pointer dereference, so gating here keeps their
        results untouched."""
        return (getattr(self.program, "language", "") or "").lower() in (
            "c", "cpp", "c++", "cxx")

    def _proc_always_returns_constant(self, proc_name: str) -> bool:
        """
        Check if a procedure always returns a constant value.

        This is used for inter-procedural dead path elimination.
        If a procedure only has Return instructions with constant values
        (and no parameter references), calling it won't propagate taint.
        """
        # Check cache first
        if proc_name in self._constant_return_procs:
            return self._constant_return_procs[proc_name]

        # Try to find the procedure with various name patterns
        proc = None
        # Try exact match
        if proc_name in self.program.procedures:
            proc = self.program.procedures[proc_name]
        else:
            # Try matching by method name suffix (e.g., "new Test().doSomething" -> "Test.doSomething")
            method_suffix = proc_name.split('.')[-1] if '.' in proc_name else proc_name
            for pname, p in self.program.procedures.items():
                if pname.endswith('.' + method_suffix):
                    proc = p
                    break

        if proc is None:
            self._constant_return_procs[proc_name] = False
            return False

        # Track variable assignments to constants
        # A variable "always contains a constant" if it's only ever assigned constants
        var_is_constant: Dict[str, bool] = {}

        # First pass: collect all assignments
        for node in proc.nodes.values():
            for instr in node.instrs:
                if isinstance(instr, Assign):
                    var_name = str(instr.id)
                    value_str = str(instr.exp)
                    # Check if assigned value is a constant
                    is_constant = (
                        (value_str.startswith('"') and value_str.endswith('"')) or
                        (value_str.startswith("'") and value_str.endswith("'")) or
                        value_str.replace('.', '', 1).replace('-', '', 1).isdigit() or
                        value_str in ('true', 'false', 'null', 'None', 'null')
                    )
                    # If already marked as non-constant, keep it that way
                    if var_name in var_is_constant and not var_is_constant[var_name]:
                        continue
                    var_is_constant[var_name] = is_constant

        # Check all return instructions
        # A procedure returns a constant if:
        # 1. It returns a literal constant, OR
        # 2. It returns a variable that only contains constants
        all_returns_constant = True
        found_return = False

        for node in proc.nodes.values():
            for instr in node.instrs:
                if isinstance(instr, Return):
                    found_return = True
                    if instr.value is None:
                        # Void return - doesn't propagate taint
                        continue
                    value_str = str(instr.value)
                    # Check if the return value is a literal constant
                    is_constant = (
                        (value_str.startswith('"') and value_str.endswith('"')) or
                        (value_str.startswith("'") and value_str.endswith("'")) or
                        value_str.replace('.', '', 1).replace('-', '', 1).isdigit() or
                        value_str in ('true', 'false', 'null', 'None')
                    )
                    # Or check if it's a variable that only contains constants
                    if not is_constant and value_str in var_is_constant:
                        is_constant = var_is_constant[value_str]

                    if not is_constant:
                        all_returns_constant = False
                        break
            if not all_returns_constant:
                break

        result = found_return and all_returns_constant
        self._constant_return_procs[proc_name] = result
        return result

    def _build_procedure_summaries(self) -> None:
        """
        Build summaries for all procedures (first pass of inter-procedural analysis).

        For each procedure, determine:
        - Which parameters are freed
        - Which parameters are dereferenced
        - Whether it's a constructor/destructor
        - Effects on class members
        """
        for proc_name, proc in self.program.procedures.items():
            summary = ProcedureSummary(proc_name=proc_name)

            # Get parameter names
            param_names = [str(p) for p in proc.params] if proc.params else []

            # Check if constructor/destructor (C++ naming)
            if '::' in proc_name:
                parts = proc_name.split('::')
                if len(parts) >= 2:
                    class_name = parts[-2]
                    method_name = parts[-1]
                    if method_name == class_name:
                        summary.is_constructor = True
                    elif method_name == f'~{class_name}':
                        summary.is_destructor = True

            # Initialize parameter effects
            for i, param_name in enumerate(param_names):
                summary.param_effects.append(ParameterEffect(
                    param_index=i,
                    param_name=param_name
                ))

            # Analyze each instruction
            for node in proc.nodes.values():
                for instr in node.instrs:
                    self._analyze_instr_for_summary(instr, summary, param_names)

            self._proc_summaries[proc_name] = summary

            if self.verbose and (summary.is_constructor or summary.is_destructor or
                                any(e.is_freed or e.is_dereferenced for e in summary.param_effects)):
                freed_params = [e.param_name for e in summary.param_effects if e.is_freed]
                deref_params = [e.param_name for e in summary.param_effects if e.is_dereferenced]
                print(f"[IPA] Summary for {proc_name}:")
                if summary.is_constructor:
                    print(f"  - Is constructor")
                if summary.is_destructor:
                    print(f"  - Is destructor")
                if freed_params:
                    print(f"  - Frees params: {freed_params}")
                if deref_params:
                    print(f"  - Derefs params: {deref_params}")
                if summary.frees_member:
                    print(f"  - Frees member: {summary.frees_member}")
                if summary.allocates_member:
                    print(f"  - Allocates member: {summary.allocates_member}")

    def _extract_constructor_taints(self, proc: Procedure) -> None:
        """
        Extract class member taints from a constructor.

        Analyzes the constructor to find which class members become tainted
        from user input sources (getenv, scanf, etc.). Records these for
        other methods to use during their analysis.
        """
        if not proc.class_name:
            return

        class_name = proc.class_name

        # Run simplified taint analysis on constructor
        state = SymbolicState()

        # Mark parameters as symbolic
        for param, typ in proc.params:
            param_name = param.name
            state.heap[param_name] = f"param_{param_name}"

        # Simple forward taint analysis through constructor
        for node in proc.cfg_iter():
            for instr in node.instrs:
                if isinstance(instr, Call):
                    func_name = instr.get_full_name()
                    spec = self.program.get_spec(func_name)

                    # Check for taint source
                    if spec and spec.is_taint_source() and instr.ret:
                        ret_var = str(instr.ret[0])
                        state.add_taint(ret_var, TaintInfo(
                            source_kind=TaintKind.USER_INPUT,
                            source_var=ret_var,
                            source_location=instr.loc or Location.unknown(),
                        ))

                    # Check for dest taint propagation (strncat, strcpy, etc.)
                    if spec and spec.taint_to_dest and len(instr.args) > 0:
                        dest_exp, _ = instr.args[0]
                        dest_str = self._exp_to_str(dest_exp)
                        # Extract base variable from pointer arithmetic
                        # e.g., "(data + offset)" -> "data"
                        if '+' in dest_str:
                            dest_str = dest_str.split('+')[0].strip()
                        # Remove parentheses
                        dest_str = dest_str.strip('()')

                        for src_idx in spec.taint_to_dest:
                            if src_idx < len(instr.args):
                                src_exp, _ = instr.args[src_idx]
                                src_vars = self._get_exp_vars(src_exp)
                                for src_var in src_vars:
                                    if state.is_tainted(src_var):
                                        state.add_taint(dest_str, state.get_taint_info(src_var))

                elif isinstance(instr, Assign):
                    target = str(instr.id)
                    value = str(instr.exp)

                    # Propagate taint through assignments
                    value_vars = self._get_exp_vars(instr.exp)
                    for var in value_vars:
                        if state.is_tainted(var):
                            state.propagate_taint(var, target)

        # Record tainted class members
        if class_name not in self._class_member_taints:
            self._class_member_taints[class_name] = {}

        for var, taint_info in state.tainted.items():
            # Check if this is a class member (direct name without locals, or this->member)
            is_member = False
            member_name = var

            if var.startswith('this->') or var.startswith('this.'):
                is_member = True
                member_name = var.replace('this->', '').replace('this.', '')
            elif '.' not in var and var not in [p.name for p, _ in proc.params]:
                # Direct member access without 'this->' (common in C++)
                is_member = True
                member_name = var

            if is_member:
                self._class_member_taints[class_name][member_name] = taint_info.source_kind.value
                if self.verbose:
                    print(f"[IPA] Found tainted member: {class_name}::{member_name}")

    def _analyze_instr_for_summary(
        self,
        instr: Instr,
        summary: ProcedureSummary,
        param_names: List[str]
    ) -> None:
        """Analyze an instruction to update procedure summary."""

        # Check for Call instructions (free, delete, malloc, new)
        if isinstance(instr, Call):
            func_name = instr.get_full_name()
            spec = self.program.get_spec(func_name)

            if spec and spec.is_deallocator() and len(instr.args) > 0:
                # This call frees something
                arg_exp, _ = instr.args[0]
                arg_str = self._exp_to_str(arg_exp)

                # Check if freeing a parameter
                for i, param_name in enumerate(param_names):
                    if arg_str == param_name or arg_str.startswith(f'{param_name}.'):
                        for effect in summary.param_effects:
                            if effect.param_index == i:
                                effect.is_freed = True
                                break

                # Check if freeing a member (this->member or just member)
                if arg_str.startswith('this->') or arg_str.startswith('this.'):
                    summary.frees_member = arg_str.replace('this->', '').replace('this.', '')
                elif summary.is_destructor and '.' not in arg_str and arg_str not in param_names:
                    # In destructor, assume non-param, non-dotted names are members
                    summary.frees_member = arg_str

            if spec and spec.is_allocator() and instr.ret:
                # This call allocates something
                ret_var = str(instr.ret[0])
                summary.returns_allocation = True

        # Check for Free instructions
        elif isinstance(instr, Free):
            arg_str = self._exp_to_str(instr.exp)

            for i, param_name in enumerate(param_names):
                if arg_str == param_name:
                    for effect in summary.param_effects:
                        if effect.param_index == i:
                            effect.is_freed = True
                            break

        # Check for Load instructions (dereference)
        elif isinstance(instr, Load):
            addr_str = self._exp_to_str(instr.exp)

            for i, param_name in enumerate(param_names):
                if addr_str == param_name or addr_str.startswith(f'*{param_name}'):
                    for effect in summary.param_effects:
                        if effect.param_index == i:
                            effect.is_dereferenced = True
                            break

        # Check for Store instructions (dereference for write)
        elif isinstance(instr, Store):
            addr_str = self._exp_to_str(instr.addr)

            for i, param_name in enumerate(param_names):
                if addr_str == param_name or addr_str.startswith(f'*{param_name}'):
                    for effect in summary.param_effects:
                        if effect.param_index == i:
                            effect.is_dereferenced = True
                            break

        # Check for Assign to this->member (constructor pattern)
        elif isinstance(instr, Assign):
            target = str(instr.id)
            value = str(instr.exp)

            if target.startswith('this->') or target.startswith('this.'):
                member_name = target.replace('this->', '').replace('this.', '')
                # Check if assigning a parameter to a member
                for i, param_name in enumerate(param_names):
                    if value == param_name:
                        for effect in summary.param_effects:
                            if effect.param_index == i:
                                effect.is_stored_to_member = True
                                effect.member_name = member_name
                                break

            # Track if member is assigned from a class field that may become tainted
            # This helps track data flow from constructor to destructor
            if target.startswith('this.') or target.startswith('this->'):
                member = target.replace('this.', '').replace('this->', '')
                # The member's value comes from 'value' - track this for data flow
                # Don't mark as tainted here - we'll do that during actual analysis
                pass

            # Also check for class member assignments without 'this->' (common in C++)
            # These are direct assignments to member variables
            if summary.is_constructor or summary.is_destructor:
                # In constructor/destructor, non-local non-param assignments may be members
                if target not in param_names and '(' not in target:
                    # Could be a class member - track it
                    pass

    def translate_program(self, program: Program = None) -> List[VulnerabilityCheck]:
        """
        Translate entire program to vulnerability checks.

        Args:
            program: The SIL program to translate

        Returns:
            List of VulnerabilityCheck objects to verify
        """
        if program:
            self.program = program

        self.vulnerability_checks = []

        # First pass: Build procedure summaries for inter-procedural analysis
        # This enables tracking data flow across procedure boundaries
        self._build_procedure_summaries()

        if self.verbose and self._proc_summaries:
            print(f"[Translator] Built summaries for {len(self._proc_summaries)} procedures")

        # Sort procedures: analyze constructors first to capture class member taints
        # This ensures other methods can use the taint information
        def sort_key(item):
            proc_name, proc = item
            summary = self._proc_summaries.get(proc_name)
            if summary and summary.is_constructor:
                return 0  # Constructors first
            elif summary and summary.is_destructor:
                return 2  # Destructors last
            return 1  # Other methods in between

        sorted_procs = sorted(self.program.procedures.items(), key=sort_key)

        # Translate each procedure
        for proc_name, proc in sorted_procs:
            if self.verbose:
                print(f"[Translator] Analyzing procedure: {proc_name}")

            checks = self.translate_procedure(proc)
            self.vulnerability_checks.extend(checks)

            # After analyzing constructor, extract class member taints
            summary = self._proc_summaries.get(proc_name)
            if summary and summary.is_constructor and proc.class_name:
                self._extract_constructor_taints(proc)

        if self.verbose:
            print(f"[Translator] Generated {len(self.vulnerability_checks)} vulnerability checks")

        return self.vulnerability_checks

    def translate_procedure(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """
        Translate a single procedure to vulnerability checks.

        Performs symbolic execution over the CFG, tracking taint
        and generating checks at sinks.
        """
        checks = []
        self._cur_proc = proc

        # Initialize state with parameters potentially tainted
        initial_state = self._init_state_for_procedure(proc)

        # Symbolic execution over CFG
        # Use worklist algorithm for path-sensitive analysis
        worklist: List[Tuple[int, SymbolicState]] = [(proc.entry_node, initial_state)]
        visited: Dict[int, SymbolicState] = {}
        max_iterations = 10000  # Safety limit to prevent infinite loops

        iterations = 0
        while worklist and iterations < max_iterations:
            iterations += 1
            node_id, state = worklist.pop(0)

            if node_id not in proc.nodes:
                continue

            node = proc.nodes[node_id]

            # Merge with existing state if we've visited this node
            state_changed = True
            if node_id in visited:
                old_state = visited[node_id]
                merged_state = self._merge_states(old_state, state)
                # Check if we've reached a fixpoint (no change in taint info)
                state_changed = not self._states_equal(old_state, merged_state)
                state = merged_state

            visited[node_id] = state

            # Only continue processing if state changed (or first visit)
            if not state_changed:
                continue

            # Execute instructions in node
            current_state = state.copy()
            returned = False
            for instr in node.instrs:
                node_checks, current_state = self._execute_instr(
                    instr, current_state, proc.name
                )
                # Record the path's feasibility constraints on each new finding, so
                # a finding on a provably-infeasible path can be dropped later. This
                # is post-hoc bookkeeping; it never prunes execution.
                if node_checks and current_state.feasibility_constraints:
                    for chk in node_checks:
                        if not chk.path_condition:
                            chk.path_condition = list(current_state.feasibility_constraints)
                checks.extend(node_checks)
                # A branch guard only constrains the value the variable held at the
                # branch. Once the variable is reassigned, that guard no longer
                # bounds the live value, so drop it -- otherwise a guard on an old
                # version conjoins with a guard on the new version and looks
                # contradictory when it is not (e.g. `if not p: p = ""` then
                # `if p:`). Keeps the SAT check sound across reassignment.
                if current_state.feasibility_constraints:
                    written = instr.get_written_vars()
                    if written:
                        current_state.feasibility_constraints = [
                            g for g in current_state.feasibility_constraints
                            if not (g.free_vars() & written)
                        ]
                # A return terminates the path. The frontend still links a successor
                # after it; stopping here removes spurious merges that would otherwise
                # drop the path conditions, so early-return guards are respected.
                if isinstance(instr, Return):
                    returned = True
                    break
                # A call to a function that never returns (exit, abort, ...) ends
                # the path exactly like a return: nothing after it on this branch
                # executes. Modelling it is what makes an `if(p==NULL){exit(1);}`
                # guard clear p's null-ness downstream (the null branch is dead),
                # so a later dereference is not misreported as CWE-476.
                if self._is_noreturn_call(instr):
                    returned = True
                    break

            if returned:
                continue

            # Add successors to worklist, respecting skip indices from constant folding
            skip_indices = getattr(current_state, '_skip_successor_indices', set())
            succ_list = list(node.succs)
            # A clean 2-way branch guards successor 0 with the condition (true) and
            # successor 1 with its negation (false). Record these per edge so the
            # path to any downstream sink carries its exact branch assumptions.
            edge_exp = self._branch_edge_formula(node)
            added_succ = False
            for idx, succ_id in enumerate(succ_list):
                if idx in skip_indices:
                    continue
                added_succ = True
                # Create a clean copy without the skip markers
                succ_state = current_state.copy()
                if hasattr(succ_state, '_skip_successor_indices'):
                    del succ_state._skip_successor_indices
                if edge_exp is not None and idx in (0, 1):
                    guard = self._feasibility_guard(edge_exp, assume_true=(idx == 0))
                    # Only record guards that mention a program variable. A
                    # constant guard (e.g. a `True` placeholder the frontend emits
                    # for a loop/structural edge) carries no path information, and
                    # its negation would be a spurious contradiction. Genuine
                    # constant-driven dead edges are already pruned by constant
                    # folding during execution.
                    if guard is not None and guard.free_vars():
                        succ_state.feasibility_constraints = (
                            succ_state.feasibility_constraints + [guard]
                        )
                    # Null-narrowing: an edge that establishes `p != NULL` (the
                    # false side of `if(p==NULL)`, the true side of `if(p)`, etc.)
                    # clears p's null flag on that path, so a deref reached only
                    # after the pointer was proved non-null is not reported.
                    for v in self._edge_nonnull_vars(edge_exp, assume_true=(idx == 0)):
                        succ_state.null_ptrs.pop(v, None)
                    # Null-confirming: the mirror edge (`if(p==NULL)` true side,
                    # `if(!p)` true side) proves p IS null on this path, so a
                    # dereference of p downstream is the classic CWE-476.
                    for v in self._edge_null_vars(edge_exp, assume_true=(idx == 0)):
                        succ_state.null_ptrs[v] = edge_exp
                worklist.append((succ_id, succ_state))

            # A path that ends here without returning (falls off the end of a
            # void function) drops any allocation it still owns: the owning
            # pointer goes out of scope unreleased, a CWE-401 leak. Runs on the
            # merged state at this node, so an allocation freed on some other
            # incoming path is already gone. C/C++ only.
            if self._is_c_lang and not added_succ:
                checks.extend(self._finalize_leaks(current_state, proc.name))

        # Post-process: If we found non-XSS vulnerabilities, remove XSS-on-return checks
        # to avoid duplicate reporting (e.g., SQLi test shouldn't also report XSS)
        non_xss_vuln_types = {c.vuln_type for c in checks if c.vuln_type != VulnType.XSS}
        if non_xss_vuln_types:
            # Keep XSS only if it's at a real XSS sink, not just return
            checks = [c for c in checks if c.vuln_type != VulnType.XSS or c.sink_type != SinkKind.HTML_OUTPUT.value]

        # Post-hoc ownership discharge: drop IDOR checks whose fetched object is
        # later validated against the authenticated principal (a dominating
        # `obj.field != current_user...` guard). This is the separation-logic
        # ownership invariant proved after the selection rather than by scoping
        # the query -- control-flow-sensitive, so it runs once the whole
        # procedure's instructions are available.
        checks = self._filter_post_hoc_ownership_checks(proc, checks)

        # Drop findings whose path is provably infeasible (dead code guarded by
        # contradictory or early-return branches). Post-hoc and satisfiability-based,
        # so it never disturbs execution or drops a feasible finding.
        checks = self._filter_infeasible_checks(checks)

        # Non-termination is a property of the finished CFG, not of any path the
        # worklist walked, so these run last and are exempt from the taint-flow
        # post-processing above.
        checks.extend(self._nonterminating_loop_checks(proc))
        checks.extend(self._uncontrolled_recursion_checks(proc))

        # Likewise structural: each of these is settled by the finished IR (a
        # constant index against a declared bound, a call result with no
        # destination, a literal size, a literal mode) rather than by any path
        # the worklist walked.
        checks.extend(self._out_of_bounds_checks(proc))
        checks.extend(self._unchecked_return_checks(proc))
        checks.extend(self._excessive_allocation_checks(proc))
        checks.extend(self._incorrect_permission_checks(proc))

        return checks

    def _init_state_for_procedure(self, proc: Procedure) -> SymbolicState:
        """Initialize symbolic state for procedure entry"""
        state = SymbolicState()

        # Mark parameters as symbolic values
        for param, typ in proc.params:
            param_name = param.name
            state.heap[param_name] = f"param_{param_name}"
            state.allocated[param_name] = True

            # Check if procedure spec marks params as tainted
            if proc.spec.is_taint_source():
                state.add_taint(param_name, TaintInfo(
                    source_kind=TaintKind.USER_INPUT,
                    source_var=param_name,
                    source_location=proc.loc or Location.unknown(),
                ))

        # For methods, initialize class member taints from inter-procedural analysis
        # If a constructor taints a class member, other methods should see it as tainted
        if proc.is_method and proc.class_name:
            class_name = proc.class_name
            if class_name in self._class_member_taints:
                for member_name, taint_source in self._class_member_taints[class_name].items():
                    # Initialize the member as tainted (for both 'data' and 'this->data')
                    for var_name in [member_name, f"this->{member_name}", f"this.{member_name}"]:
                        state.add_taint(var_name, TaintInfo(
                            source_kind=TaintKind.USER_INPUT,
                            source_var=f"{class_name}::{member_name}",
                            source_location=proc.loc or Location.unknown(),
                        ))
                    if self.verbose:
                        print(f"[IPA] Initialized class member taint: {class_name}::{member_name}")

        return state

    def _execute_instr(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        """
        Execute a single instruction, returning any vulnerability checks.

        Returns:
            Tuple of (checks generated, new state)
        """
        checks = []

        # Heap-lifecycle deref checks (CWE-416 use-after-free, CWE-476 null
        # dereference) run over EVERY instruction before it executes, because a
        # dereference is not always a Load/Store: `int x = *p` is an Assign whose
        # value expression derefs p, and `f(*p)` derefs p inside a call argument.
        # Reading the state as it stands before the instruction reflects the
        # frees and null assignments that preceded this point. Kept in a separate
        # list because several dispatch arms below rebind `checks` wholesale.
        lifecycle_checks = self._lifecycle_deref_checks(instr, state, proc_name)

        if isinstance(instr, Assign):
            assign_checks, state = self._exec_assign(instr, state, proc_name)
            checks.extend(assign_checks)

        elif isinstance(instr, Load):
            checks, state = self._exec_load(instr, state, proc_name)

        elif isinstance(instr, Store):
            checks, state = self._exec_store(instr, state, proc_name)

        elif isinstance(instr, Alloc):
            state = self._exec_alloc(instr, state)

        elif isinstance(instr, Free):
            checks, state = self._exec_free(instr, state, proc_name)

        elif isinstance(instr, Call):
            checks, state = self._exec_call(instr, state, proc_name)

        elif isinstance(instr, Prune):
            state = self._exec_prune(instr, state)

        elif isinstance(instr, TaintSource):
            state = self._exec_taint_source(instr, state)

        elif isinstance(instr, TaintSink):
            checks, state = self._exec_taint_sink(instr, state, proc_name)

        elif isinstance(instr, Sanitize):
            state = self._exec_sanitize(instr, state)

        elif isinstance(instr, AssertSafe):
            state = self._exec_assert_safe(instr, state)

        elif isinstance(instr, Return):
            checks, state = self._exec_return(instr, state, proc_name)

        return lifecycle_checks + checks, state

    # =========================================================================
    # Instruction Execution
    # =========================================================================

    def _exec_assign(
        self,
        instr: Assign,
        state: SymbolicState,
        proc_name: str = ""
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        """Execute assignment: id = exp"""
        checks = []
        target = self._get_var_name(instr.id)
        source_vars = self._get_exp_vars(instr.exp)

        # Store symbolic value
        state.heap[target] = str(instr.exp)

        # Track pointer nullness and storage origin across the assignment. Any
        # reassignment first clears the target's prior lifecycle facts, then the
        # right-hand side re-establishes them (null literal, address-of a local,
        # or propagation from another pointer variable).
        self._track_assign_lifecycle(instr, target, state)

        # Thread heap OWNERSHIP across the assignment (CWE-401): a fresh
        # allocation landing in `target`, a move/alias of an owned pointer, or the
        # loss of the allocation `target` used to hold. Runs after the lifecycle
        # update so it sees the cleared facts. C/C++ only (gated inside).
        checks.extend(self._track_ownership_assign(instr, target, state, proc_name))

        # Track constant values for constant folding
        exp_str = str(instr.exp).strip()
        import re
        # Detect numeric constants: num = 86
        if re.match(r'^-?\d+$', exp_str):
            state.set_constant(target, int(exp_str))
        # Detect string constants: bar = "safe string"
        elif (exp_str.startswith('"') and exp_str.endswith('"')) or \
             (exp_str.startswith("'") and exp_str.endswith("'")):
            state.set_constant(target, exp_str[1:-1])

        # Propagate secure parser status: parser = $parser_7
        for src_var in source_vars:
            if src_var in state.secure_parsers:
                state.secure_parsers.add(target)
                break

        # Detect list initialization: lst = []
        if exp_str == '[]' or exp_str == 'list()':
            state.init_list(target)

        # Detect dictionary initialization: d = {} or d = dict()
        if exp_str == '{}' or exp_str == 'dict()':
            state.init_dict(target)

        # Detect ternary expressions: bar = "safe" if cond else tainted_var
        # Pattern: (?: consequence alternative) - our internal representation
        # Format is (?: consequence alternative) where consequence is what's returned if true
        ternary_match = re.match(r'^\(\?:\s+(.+?)\s+([a-zA-Z_][a-zA-Z0-9_]*)\)$', exp_str)
        if ternary_match:
            # Extract consequence and alternative
            consequence_str = ternary_match.group(1).strip()
            alternative_str = ternary_match.group(2).strip()

            # Check if alternative variable is tainted
            alt_is_tainted = state.is_tainted(alternative_str)

            # Check if consequence is a constant string
            cons_is_const = (
                (consequence_str.startswith('"') and consequence_str.endswith('"')) or
                (consequence_str.startswith("'") and consequence_str.endswith("'"))
            )

            if cons_is_const:
                const_val = consequence_str[1:-1].lower()
                # Heuristic: Detect OWASP benchmark patterns
                # "always" in consequence → condition is True → consequence is used (safe)
                # "never" in consequence → condition is False → alternative is used (tainted)
                if 'always' in const_val:
                    # Condition is True, consequence is taken
                    state.set_constant(target, consequence_str[1:-1])
                    return checks, state
                elif 'never' in const_val and alt_is_tainted:
                    # Condition is False, alternative is taken (tainted)
                    state.propagate_taint(alternative_str, target)
                    return checks, state

            # If the alternative is tainted and we couldn't determine the branch,
            # be conservative and propagate taint
            if alt_is_tainted:
                state.propagate_taint(alternative_str, target)
                return checks, state

            # If consequence is constant and alternative is NOT tainted, the result is safe
            if cons_is_const:
                const_val = consequence_str[1:-1]
                state.set_constant(target, const_val)
                return checks, state

        # Detect dictionary subscript access with string key: bar = d['key'] or bar = d["key"]
        # Pattern: "container['key']" or 'container["key"]'
        dict_subscript_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\[[\'"]([^\'"]+)[\'"]\]$', exp_str)
        if dict_subscript_match:
            container_var = dict_subscript_match.group(1)
            key = dict_subscript_match.group(2)

            # Check if container is a tracked dictionary (separation logic)
            if state.is_tracked_dict(container_var):
                # Use per-key taint from separation logic
                key_taint = state.get_dict_key_taint(container_var, key)
                if key_taint:
                    state.tainted[target] = key_taint
                else:
                    # Key is NOT tainted - clear any existing taint on target
                    # and set target to constant value if known
                    if target in state.tainted:
                        del state.tainted[target]
                    result = state.dict_get(container_var, key)
                    if result:
                        val, _ = result
                        # Track constant value
                        if val.startswith('"') or val.startswith("'"):
                            state.set_constant(target, val[1:-1])
                return checks, state  # Skip normal taint propagation

        # Detect Java-style Map.get() call: bar = "map.get"("key")
        # Pattern: "container.get"("key") - quotes around method name due to SIL encoding
        java_get_match = re.match(r'^"([a-zA-Z_][a-zA-Z0-9_]*)\.get"\("([^"]+)"\)$', exp_str)
        if java_get_match:
            container_var = java_get_match.group(1)
            key = java_get_match.group(2)

            # Check if container is a tracked dictionary (separation logic)
            if state.is_tracked_dict(container_var):
                # Use per-key taint from separation logic
                key_taint = state.get_dict_key_taint(container_var, key)
                if key_taint:
                    state.tainted[target] = key_taint
                    if self.verbose:
                        print(f"[Translator] Map.get (assign): {container_var}.get({key}) -> {target} (TAINTED)")
                else:
                    # Key is NOT tainted - clear any existing taint on target
                    if target in state.tainted:
                        del state.tainted[target]
                    result = state.dict_get(container_var, key)
                    if result:
                        val, _ = result
                        # Track constant value
                        if val.startswith('"') or val.startswith("'"):
                            state.set_constant(target, val[1:-1])
                    if self.verbose:
                        print(f"[Translator] Map.get (assign): {container_var}.get({key}) -> {target} (safe)")
                return checks, state  # Skip normal taint propagation

        # Detect Java-style List.get(index) call: bar = "list.get"(1)
        # Pattern: "container.get"(index) where index is a number
        java_list_get_match = re.match(r'^"([a-zA-Z_][a-zA-Z0-9_]*)\.get"\((\d+)\)$', exp_str)
        if java_list_get_match:
            container_var = java_list_get_match.group(1)
            index = int(java_list_get_match.group(2))

            # Check if container is a tracked list (separation logic)
            if state.is_tracked_list(container_var):
                # Use per-element taint from separation logic
                elem_taint = state.get_list_element_taint(container_var, index)
                if elem_taint:
                    state.tainted[target] = elem_taint
                    if self.verbose:
                        print(f"[Translator] List.get (assign): {container_var}.get({index}) -> {target} (TAINTED)")
                else:
                    # Element is NOT tainted - clear any existing taint on target
                    if target in state.tainted:
                        del state.tainted[target]
                    if self.verbose:
                        print(f"[Translator] List.get (assign): {container_var}.get({index}) -> {target} (safe)")
                return checks, state  # Skip normal taint propagation

        # Detect subscript access: bar = lst[i] or guess = possible[1]
        # Pattern: "lst[0]" or "possible[1]" etc.
        subscript_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\[(\d+)\]$', exp_str)
        if subscript_match:
            container_var = subscript_match.group(1)
            index = int(subscript_match.group(2))

            # Check if container is a tracked list (separation logic)
            if state.is_tracked_list(container_var):
                # Use per-element taint from separation logic
                elem_taint = state.get_list_element_taint(container_var, index)
                if elem_taint:
                    state.tainted[target] = elem_taint
                # If element is not tainted, don't propagate coarse-grained taint
                # This is the key fix for false positives!
                elif state.is_tainted(container_var):
                    # Element is NOT tainted even though list is coarse-grained tainted
                    # Don't propagate taint to target
                    pass
                return checks, state  # Skip normal taint propagation

            # Check if container is a string constant: guess = "ABC"[1] -> "B"
            container_val = state.get_constant(container_var)
            if container_val is not None and isinstance(container_val, str):
                if 0 <= index < len(container_val):
                    char_result = container_val[index]
                    state.set_constant(target, char_result)
                    return checks, state  # Skip normal taint propagation

            # Also check if the expression itself is indexing a string literal
            # Pattern: "ABC"[1] or 'ABC'[1]
            if exp_str.startswith('"') or exp_str.startswith("'"):
                string_lit_match = re.match(r'^["\']([^"\']*)["\']\.?\[(\d+)\]$', exp_str)
                if string_lit_match:
                    string_val = string_lit_match.group(1)
                    lit_index = int(string_lit_match.group(2))
                    if 0 <= lit_index < len(string_val):
                        state.set_constant(target, string_val[lit_index])
                        return checks, state

        # Propagate taint from any tainted source
        for src_var in source_vars:
            if state.is_tainted(src_var):
                state.propagate_taint(src_var, target)
                break  # Only need one taint source

        # Also propagate sanitization even if source isn't tainted
        # This handles cases like: bar = sanitize(param)
        # where bar might get tainted later or where we're tracking
        # sanitized data that flows to sinks
        for src_var in source_vars:
            if src_var in state.sanitized:
                existing = state.sanitized.get(target, [])
                state.sanitized[target] = list(set(existing) | set(state.sanitized[src_var]))

        # Check for path operations with tainted data
        # Only detect clear pathlib-style division operations: p = path / tainted_var
        # String concatenation is handled by existing filesystem sinks
        exp_str = str(instr.exp)
        is_path_division = (
            ' / ' in exp_str or
            (exp_str.startswith('(') and ' / ' in exp_str)
        )

        if is_path_division:
            for src_var in source_vars:
                if state.is_tainted(src_var):
                    if not state.is_sanitized_for(src_var, "filesystem"):
                        # Path operation with unsanitized tainted data
                        check = self._create_taint_check(
                            instr, state, proc_name,
                            src_var, SinkKind.FILE_PATH
                        )
                        checks.append(check)
                        break

        # Propagate sanitization: if ALL tainted sources are sanitized for a sink type,
        # then the target is also sanitized for that sink type.
        # This handles cases like: result = escape_for_html(tainted_data)
        tainted_sources = [v for v in source_vars if state.is_tainted(v)]
        if tainted_sources:
            # Find sink types that ALL tainted sources are sanitized for
            common_sanitized = None
            for src_var in tainted_sources:
                src_sanitized = set(state.sanitized.get(src_var, []))
                if common_sanitized is None:
                    common_sanitized = src_sanitized
                else:
                    common_sanitized &= src_sanitized

            if common_sanitized:
                # Target inherits sanitization from all sources
                existing = set(state.sanitized.get(target, []))
                state.sanitized[target] = list(existing | common_sanitized)

        # Also check for embedded sanitizer calls in the expression
        # This handles cases like: result = f"text {escape_for_html(tainted)}"
        embedded_sanitizers = self._get_sanitizer_calls(instr.exp)
        if embedded_sanitizers and state.is_tainted(target):
            # Get the sink types sanitized by all embedded sanitizers
            # If all tainted data passes through sanitizers, the result is sanitized
            all_sanitized = set()
            for func_name, arg_vars in embedded_sanitizers:
                spec = self.program.get_spec(func_name)
                if spec and spec.is_taint_sanitizer():
                    # Check if any of the sanitizer's args are tainted
                    for arg_var in arg_vars:
                        if state.is_tainted(arg_var):
                            all_sanitized.update(spec.is_sanitizer)
            if all_sanitized:
                existing = set(state.sanitized.get(target, []))
                state.sanitized[target] = list(existing | all_sanitized)

        # Check for embedded taint source calls in the expression
        # E.g., name = next(request.form.keys()) should mark name as tainted
        embedded_sources = self._get_embedded_source_calls(instr.exp)
        for func_name, source_kind_str in embedded_sources:
            # Convert source kind string to TaintKind enum
            kind = TaintKind(source_kind_str) if source_kind_str in [t.value for t in TaintKind] else TaintKind.USER_INPUT
            # Mark target as tainted from this source
            state.add_taint(target, TaintInfo(
                source_kind=kind,
                source_var=func_name,
                source_location=instr.loc or Location.unknown(),
            ))

        # Propagate asserted_safe from source variables to target
        # If a source variable is asserted safe for a sink type, the target inherits that
        for src_var in source_vars:
            if src_var in state.asserted_safe:
                src_safe = state.asserted_safe[src_var]
                existing = state.asserted_safe.get(target, [])
                state.asserted_safe[target] = list(set(existing) | set(src_safe))

        # Check for embedded taint sink calls in the expression
        # E.g., RESPONSE = (RESPONSE + eval(bar)) should detect eval as a sink
        embedded_sinks = self._get_embedded_sink_calls(instr.exp, state)
        for func_name, sink_kind, tainted_args in embedded_sinks:
            for tainted_var in tainted_args:
                # Map sink kind string to SinkKind enum
                sink_kind_map = {
                    'sql': SinkKind.SQL_QUERY,
                    'eval': SinkKind.EVAL,
                    'cmd': SinkKind.SHELL_COMMAND,
                    'shell': SinkKind.SHELL_COMMAND,
                    'filesystem': SinkKind.FILE_PATH,
                    'xpath': SinkKind.XPATH_QUERY,
                    'ldap': SinkKind.LDAP_QUERY,
                    'deserialize': SinkKind.DESERIALIZATION,
                    'xml': SinkKind.XML_PARSE,
                    'html': SinkKind.HTML_OUTPUT,
                    'redirect': SinkKind.REDIRECT,
                    'nosql': SinkKind.NOSQL_QUERY,
                    'ssrf': SinkKind.SSRF,
                    'log': SinkKind.LOG,
                }
                sink_enum = sink_kind_map.get(sink_kind, SinkKind.EVAL)
                check = self._create_taint_check(
                    instr, state, proc_name,
                    tainted_var, sink_enum
                )
                checks.append(check)

        # Check for property assignment sinks
        # E.g., sqlComm.CommandText = "SELECT ... " + userInput
        # The property name (CommandText) may be a registered sink
        if '.' in target:
            # Extract property name (last part after .)
            prop_name = target.split('.')[-1]
            spec = self.program.get_spec(prop_name)
            if spec and spec.is_taint_sink():
                sink_kind_str = spec.is_sink
                sink_kind_map = {
                    'sql': SinkKind.SQL_QUERY,
                    'command': SinkKind.SHELL_COMMAND,
                    'html': SinkKind.HTML_OUTPUT,
                    'path': SinkKind.FILE_PATH,
                    'ssrf': SinkKind.SSRF,
                    'redirect': SinkKind.REDIRECT,
                    'xpath': SinkKind.XPATH_QUERY,
                    'ldap': SinkKind.LDAP_QUERY,
                    'deserialize': SinkKind.DESERIALIZATION,
                }
                sink_enum = sink_kind_map.get(sink_kind_str, SinkKind.SQL_QUERY)

                # Check if expression contains tainted variables
                for src_var in source_vars:
                    if state.is_tainted(src_var):
                        check = self._create_taint_check(
                            instr, state, proc_name,
                            src_var, sink_enum
                        )
                        checks.append(check)

                # Check for embedded taint source calls in the expression
                embedded_sources = self._get_embedded_source_calls(instr.exp)
                for func_name, source_kind_str in embedded_sources:
                    check = VulnerabilityCheck(
                        formula=And(
                            Source(Var(func_name), source_kind_str),
                            Sink(Var(func_name), sink_kind_str)
                        ),
                        vuln_type=VulnType.from_sink_kind(sink_enum),
                        location=instr.loc or Location.unknown(),
                        description=f"Tainted data from '{func_name}' flows to {sink_kind_str} sink via property assignment",
                        source_var=func_name,
                        source_location=instr.loc or Location.unknown(),
                        sink_type=sink_kind_str,
                        procedure_name=proc_name,
                    )
                    checks.append(check)

        return checks, state

    def _exec_load(
        self,
        instr: Load,
        state: SymbolicState,
        proc_name: str
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        """Execute load: id = *exp"""
        checks = []
        target = str(instr.id)
        addr = self._exp_to_str(instr.exp)

        # Use-after-free / null-dereference for this load are raised centrally in
        # `_lifecycle_deref_checks`, which extracts the base pointer from `addr`
        # (a Load through `p + i` derefs `p`, not the literal string "p + i").

        # Load value and propagate taint
        if addr in state.heap:
            state.heap[target] = state.heap[addr]
        else:
            state.heap[target] = f"load_{target}"

        if state.is_tainted(addr):
            state.propagate_taint(addr, target)

        state.allocated[target] = True

        return checks, state

    def _exec_store(
        self,
        instr: Store,
        state: SymbolicState,
        proc_name: str
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        """Execute store: *addr = value"""
        checks = []
        addr = self._exp_to_str(instr.addr)
        value = self._exp_to_str(instr.value)

        # Use-after-free / null-dereference for this store are raised centrally
        # in `_lifecycle_deref_checks` (see `_exec_load`); a store through
        # `p + i` derefs the base pointer `p`.

        # Update heap
        state.heap[addr] = value

        # A pointer stored through a dereference (`*out = p`, a field, a global)
        # escapes this function's ownership: the caller can reach it, so it is
        # not a leak. C/C++ only.
        if self._is_c_lang:
            self._escape_vars(state, self._escaping_expr_vars(instr.value))

        # Propagate taint
        value_vars = self._get_exp_vars(instr.value)
        for v in value_vars:
            if state.is_tainted(v):
                state.propagate_taint(v, addr)
                break

        return checks, state

    def _exec_alloc(self, instr: Alloc, state: SymbolicState) -> SymbolicState:
        """Execute allocation: id = alloc(size)"""
        target = str(instr.id)
        state.heap[target] = f"alloc_{target}"
        state.mark_allocated(target)
        return state

    def _exec_free(
        self,
        instr: Free,
        state: SymbolicState,
        proc_name: str
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        """Execute free: free(exp)"""
        checks = []
        addr = self._exp_to_str(instr.exp)

        # Check for double-free
        if state.is_freed(addr):
            check = self._create_double_free_check(instr, state, proc_name, addr)
            checks.append(check)

        state.mark_freed(addr)

        return checks, state

    def _exec_call(
        self,
        instr: Call,
        state: SymbolicState,
        proc_name: str
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        """Execute function call"""
        checks = []
        func_name = instr.get_full_name()

        # Get specification for this function
        spec = self.program.get_spec(func_name)


        if spec:
            # Handle taint source
            if spec.is_taint_source() and instr.ret:
                ret_var = str(instr.ret[0])
                source_kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
                # The Authorization/Cookie header is an authentication credential, not a
                # free object-selector: tag PRINCIPAL (arg-sensitive), so values derived
                # from it -- even through a custom validator -- are the caller's own identity.
                if source_kind == TaintKind.USER_INPUT and self._is_auth_credential_access(func_name, instr):
                    source_kind = TaintKind.PRINCIPAL
                state.add_taint(ret_var, TaintInfo(
                    source_kind=source_kind,
                    source_var=ret_var,
                    source_location=instr.loc,
                ))

            # Handle taint sink
            if spec.is_taint_sink():
                sink_kind = resolve_sink_kind(spec.is_sink)

                # For sinks with empty sink_args (e.g., insecure_random, weak_hash),
                # the function usage itself is the vulnerability - no taint required
                if not spec.sink_args:
                    # Special handling for hashlib.new - only flag weak algorithms
                    if func_name == "hashlib.new":
                        if len(instr.args) > 0:
                            arg_exp, _ = instr.args[0]
                            arg_str = str(arg_exp).strip("'\"").lower()
                            # Only flag weak algorithms
                            weak_algorithms = {'md5', 'sha1', 'sha', 'md4', 'md2'}
                            if arg_str not in weak_algorithms:
                                # Strong algorithm like sha256, sha384, sha512 - not vulnerable
                                pass
                            else:
                                check = self._create_usage_based_check(
                                    instr, state, proc_name, sink_kind
                                )
                                checks.append(check)
                    # Special handling for Java MessageDigest.getInstance - check algorithm
                    # But NOT SecureRandom.getInstance which is safe
                    elif func_name.endswith("MessageDigest.getInstance") and "SecureRandom" not in func_name:
                        if len(instr.args) > 0:
                            arg_exp, _ = instr.args[0]
                            arg_str = str(arg_exp).strip("'\"").upper()
                            # Weak hash algorithms - only flag known weak algorithms
                            weak_hashes = {'MD5', 'MD4', 'MD2', 'SHA-1', 'SHA1', 'SHA'}
                            # Only flag if we can confirm it's a weak algorithm
                            # Don't flag variables/dynamic algorithms (too many FPs)
                            if arg_str in weak_hashes:
                                check = self._create_usage_based_check(
                                    instr, state, proc_name, sink_kind
                                )
                                checks.append(check)
                    # Special handling for Java Cipher.getInstance - check algorithm
                    elif func_name.endswith("Cipher.getInstance"):
                        if len(instr.args) > 0:
                            arg_exp, _ = instr.args[0]
                            arg_str = str(arg_exp).strip("'\"").upper()
                            # Weak encryption algorithms (inherently insecure)
                            weak_ciphers = ['DES', 'DESEDE', '3DES', 'RC2', 'RC4', 'BLOWFISH']
                            # ECB mode is always weak (no IV, patterns preserved)
                            # NOPADDING is weak ONLY when NOT using authenticated modes (GCM, CCM)
                            # GCM and CCM provide integrity, so NOPADDING is safe with them
                            is_weak_cipher = any(weak in arg_str for weak in weak_ciphers)
                            is_ecb = 'ECB' in arg_str
                            is_nopadding_without_auth = (
                                'NOPADDING' in arg_str and
                                'GCM' not in arg_str and
                                'CCM' not in arg_str
                            )
                            is_weak = is_weak_cipher or is_ecb or is_nopadding_without_auth
                            if is_weak:
                                check = self._create_usage_based_check(
                                    instr, state, proc_name, sink_kind
                                )
                                checks.append(check)
                    # Special handling for set_cookie - only flag when secure=False
                    elif func_name.endswith("set_cookie"):
                        # Check if any arg is False (indicating secure=False)
                        has_false_arg = False
                        for arg_exp, _ in instr.args:
                            arg_str = str(arg_exp).lower()
                            if arg_str == "false":
                                has_false_arg = True
                                break
                        if has_false_arg:
                            check = self._create_usage_based_check(
                                instr, state, proc_name, sink_kind
                            )
                            checks.append(check)
                    # Special handling for setSecure - Java Cookie.setSecure(false) - CWE-614
                    elif func_name.endswith("setSecure") or func_name.endswith(".setSecure"):
                        # Only flag if argument is false
                        if len(instr.args) >= 1:
                            arg_exp, _ = instr.args[0]
                            arg_str = str(arg_exp).lower().strip()
                            if arg_str == "false":
                                check = self._create_usage_based_check(
                                    instr, state, proc_name, sink_kind
                                )
                                checks.append(check)
                    # Skip SecureRandom.getInstance - this is safe, not a weak hash
                    elif "SecureRandom" in func_name:
                        pass  # SecureRandom is secure, don't flag
                    # scanf family: unbounded read only when the format string
                    # uses %s/%[ without a field width (e.g. scanf("%d") is safe).
                    elif func_name in ("scanf", "fscanf", "sscanf",
                                       "wscanf", "swscanf", "fwscanf"):
                        if any(self._is_unbounded_scanf_format(a) for a, _ in instr.args):
                            check = self._create_usage_based_check(
                                instr, state, proc_name, sink_kind
                            )
                            checks.append(check)
                    else:
                        # Weak-hash usage honors usedforsecurity=False (Python 3.9+,
                        # matching Bandit B324): a documented non-security hash is not a
                        # vulnerability. The frontend lowers that keyword to a bare False
                        # argument, so a False arg on a weak-hash call marks the opt-out.
                        if (getattr(sink_kind, "value", None) == "weak_hash"
                                and any(str(a[0]).strip().lower() == "false"
                                        for a in instr.args)):
                            pass  # usedforsecurity=False -> not flagged
                        else:
                            # Create a usage-based vulnerability check
                            check = self._create_usage_based_check(
                                instr, state, proc_name, sink_kind
                            )
                            checks.append(check)
                else:
                    # Special handling for XML parsers with secure parser argument
                    # xml.dom.minidom.parseString(data, parser) - safe if parser is secure
                    skip_xml_check = False
                    if spec.is_sink == 'xml' and func_name in (
                        'xml.dom.minidom.parseString', 'xml.dom.minidom.parse',
                        'xml.sax.parseString', 'xml.sax.parse'
                    ):
                        # Check if second argument is a secure parser
                        if len(instr.args) >= 2:
                            parser_arg, _ = instr.args[1]
                            parser_vars = self._get_exp_vars(parser_arg)
                            for pvar in parser_vars:
                                if pvar in state.secure_parsers:
                                    skip_xml_check = True
                                    break

                    if skip_xml_check:
                        # Mark the data argument as safe for xml sink
                        # (since it's being processed by a secure parser)
                        if len(instr.args) >= 1:
                            data_arg, _ = instr.args[0]
                            data_vars = self._get_exp_vars(data_arg)
                            for dvar in data_vars:
                                state.safe_for_xml_sink.add(dvar)
                    else:
                        # For taint-flow sinks, check if tainted data reaches the sink
                        for arg_idx in spec.sink_args:
                            if arg_idx < len(instr.args):
                                arg_exp, _ = instr.args[arg_idx]
                                arg_vars = self._get_exp_vars(arg_exp)
                                arg_str = str(arg_exp)

                                # Check for inline .replace() sanitization in argument
                                import re
                                inline_sanitized_vars = set()
                                inline_sanitized_for = {}  # var -> set of sink types

                                if spec.is_sink == 'xpath':
                                    xpath_sanitize_match = re.findall(
                                        r'(\w+)\.replace\([^)]*&apos;[^)]*\)',
                                        arg_str
                                    )
                                    for var in xpath_sanitize_match:
                                        inline_sanitized_vars.add(var)

                                # Check for embedded sanitizer calls (ESAPI, OWASP Encoder, etc.)
                                embedded_sanitizer_patterns = [
                                    # ESAPI sanitizers
                                    (r'encodeForHTML["\']?\s*\(([^)]+)\)', ['html', 'xss']),
                                    (r'encodeForJavaScript["\']?\s*\(([^)]+)\)', ['html', 'xss']),
                                    (r'encodeForCSS["\']?\s*\(([^)]+)\)', ['html', 'xss']),
                                    (r'encodeForURL["\']?\s*\(([^)]+)\)', ['url', 'redirect']),
                                    (r'encodeForXML["\']?\s*\(([^)]+)\)', ['xml', 'xxe']),
                                    (r'encodeForXPath["\']?\s*\(([^)]+)\)', ['xpath']),
                                    (r'encodeForSQL["\']?\s*\(([^)]+)\)', ['sql']),
                                    (r'encodeForLDAP["\']?\s*\(([^)]+)\)', ['ldap']),
                                    (r'encodeForOS["\']?\s*\(([^)]+)\)', ['command', 'shell']),
                                    # OWASP Encoder
                                    (r'forHtml["\']?\s*\(([^)]+)\)', ['html', 'xss']),
                                    (r'forHtmlContent["\']?\s*\(([^)]+)\)', ['html', 'xss']),
                                    (r'forHtmlAttribute["\']?\s*\(([^)]+)\)', ['html', 'xss']),
                                    (r'forJavaScript["\']?\s*\(([^)]+)\)', ['html', 'xss']),
                                    # Apache Commons
                                    (r'escapeHtml[4]?["\']?\s*\(([^)]+)\)', ['html', 'xss']),
                                    (r'escapeXml["\']?\s*\(([^)]+)\)', ['xml', 'html', 'xss']),
                                    (r'escapeSql["\']?\s*\(([^)]+)\)', ['sql']),
                                    # Spring
                                    (r'htmlEscape["\']?\s*\(([^)]+)\)', ['html', 'xss']),
                                ]

                                for pattern, sink_types in embedded_sanitizer_patterns:
                                    for match in re.finditer(pattern, arg_str, re.IGNORECASE):
                                        sanitized_arg = match.group(1).strip()
                                        matched_vars = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', sanitized_arg)
                                        for matched_var in matched_vars:
                                            if matched_var not in inline_sanitized_for:
                                                inline_sanitized_for[matched_var] = set()
                                            inline_sanitized_for[matched_var].update(sink_types)

                                # Spec-based inline sanitizers: a sanitizer call
                                # (per language specs) wrapping a variable inside
                                # the sink argument neutralizes it (e.g. C#'s
                                # HttpUtility.HtmlEncode / Uri.EscapeDataString).
                                for s_func, s_args in self._get_sanitizer_calls(arg_exp):
                                    s_spec = self.program.get_spec(s_func)
                                    if not s_spec or not s_spec.is_taint_sanitizer():
                                        continue
                                    for s_var in s_args:
                                        inline_sanitized_for.setdefault(s_var, set()).update(s_spec.is_sanitizer)

                                for arg_var in arg_vars:
                                    if state.is_tainted(arg_var):
                                        # IDOR requires an ATTACKER-CONTROLLED object selector.
                                        # Only a USER_INPUT-kind value (a path/query/body
                                        # parameter) selects a cross-user object. A selector that
                                        # is the caller's OWN authenticated identity (PRINCIPAL --
                                        # credential / session / JWT, propagated even through a
                                        # custom validator) is self-scoped; a value read from the
                                        # database (DATABASE) or the environment is not directly
                                        # attacker-supplied. Sound: the attacker can only present
                                        # their own credential and cannot pick another user's row
                                        # unless a request parameter names it.
                                        if spec.is_sink == 'resource_select':
                                            _ti = state.get_taint_info(arg_var)
                                            if _ti is None or _ti.source_kind != TaintKind.USER_INPUT:
                                                continue
                                        if not state.is_sanitized_for(arg_var, spec.is_sink):
                                            if not state.is_asserted_safe_for(arg_var, spec.is_sink):
                                                # IDOR ownership binding: a resource-selection query
                                                # scoped by the authenticated principal (e.g.
                                                # filter_by(user_id=current_user.id, id=x)) selects the
                                                # caller's OWN resource -- not an object-level authz flaw.
                                                # Custom/indirect auth and post-hoc ownership checks are
                                                # left to the LLM layer.
                                                if spec.is_sink == 'resource_select' and \
                                                        self._resource_select_principal_scoped(instr):
                                                    continue
                                                # Skip xpath sinks for vars with inline .replace() sanitization
                                                if spec.is_sink == 'xpath' and arg_var in inline_sanitized_vars:
                                                    continue
                                                # Skip sinks for variables sanitized by embedded sanitizer calls
                                                if arg_var in inline_sanitized_for:
                                                    if spec.is_sink in inline_sanitized_for[arg_var]:
                                                        continue
                                                # CWE-770 is about an allocation size that is
                                                # UNBOUNDED. A branch condition on the path that
                                                # constrains the size discharges that, so only a
                                                # size reaching the allocator with no check at
                                                # all is reported.
                                                if spec.is_sink == 'alloc_size' and \
                                                        self._alloc_size_is_bounded(arg_var, state):
                                                    continue
                                                check = self._create_taint_check(
                                                    instr, state, proc_name,
                                                    arg_var, sink_kind
                                                )
                                                checks.append(check)

                                # Inline member sources used directly in the sink
                                # argument, e.g. db.query("..." + req.query.id).
                                for src_chain, src_kind in self._get_embedded_member_sources(arg_exp):
                                    # A sanitizer wrapping the source (e.g.
                                    # mysql.escape(req.body.x)) records the root
                                    # var ('req'); the chain is 'req.body', so
                                    # match on any shared identifier, not equality.
                                    src_ids = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', src_chain)
                                    if any(spec.is_sink in inline_sanitized_for.get(v, set())
                                           for v in src_ids):
                                        continue
                                    checks.append(VulnerabilityCheck(
                                        formula=And(Source(Var(src_chain), src_kind),
                                                    Sink(Var(src_chain), spec.is_sink)),
                                        vuln_type=VulnType.from_sink_kind(sink_kind),
                                        location=instr.loc or Location.unknown(),
                                        description=f"Tainted data from '{src_chain}' flows to {spec.is_sink} sink",
                                        source_var=src_chain,
                                        source_location=instr.loc or Location.unknown(),
                                        sink_type=spec.is_sink,
                                        procedure_name=proc_name,
                                    ))

            # Handle sanitizer
            # Sanitizers should BOTH:
            # 1. Propagate taint from input to output (data still flows through)
            # 2. Add sanitization for specific sink types
            if spec.is_taint_sanitizer() and instr.ret:
                ret_var = str(instr.ret[0])
                state.add_sanitization(ret_var, spec.is_sanitizer)
                # Also propagate taint from first argument (sanitizers process input)
                if len(instr.args) > 0:
                    arg_exp, _ = instr.args[0]
                    arg_vars = self._get_exp_vars(arg_exp)
                    for arg_var in arg_vars:
                        if state.is_tainted(arg_var):
                            state.propagate_taint(arg_var, ret_var)

            # Handle taint propagation
            if spec.propagates_taint():
                # For methods with return values, propagate taint to return
                if instr.ret:
                    ret_var = str(instr.ret[0])
                    # Check argument-based propagation
                    for arg_idx in spec.taint_propagates:
                        if arg_idx < len(instr.args):
                            arg_exp, _ = instr.args[arg_idx]
                            arg_vars = self._get_exp_vars(arg_exp)
                            for arg_var in arg_vars:
                                if state.is_tainted(arg_var):
                                    state.propagate_taint(arg_var, ret_var)

                    # Check receiver-based propagation (for method calls like var.method())
                    # If the spec has taint_from_receiver, or if it's a method call
                    # and the receiver is tainted, propagate taint
                    if spec.taint_from_receiver or '.' in func_name:
                        # Extract receiver from function name (e.g., "var.method" -> "var")
                        parts = func_name.rsplit('.', 1)
                        if len(parts) == 2:
                            receiver_var = parts[0]
                            if state.is_tainted(receiver_var):
                                state.propagate_taint(receiver_var, ret_var)
                else:
                    # For methods without return values (like set/add/append/update),
                    # propagate taint from arguments to the receiver object
                    if '.' in func_name:
                        parts = func_name.rsplit('.', 1)
                        if len(parts) == 2:
                            receiver_var = parts[0]
                            method_name = parts[1].lower()
                            # Check if any tainted argument is being stored
                            for arg_idx in spec.taint_propagates:
                                if arg_idx < len(instr.args):
                                    arg_exp, _ = instr.args[arg_idx]
                                    arg_vars = self._get_exp_vars(arg_exp)
                                    for arg_var in arg_vars:
                                        if state.is_tainted(arg_var):
                                            state.propagate_taint(arg_var, receiver_var)

            # Handle destination taint propagation (for strcpy, strncat, etc.)
            # These functions copy taint from source arg to destination arg (arg 0)
            if spec.taint_to_dest and len(instr.args) > 0:
                dest_exp, _ = instr.args[0]
                dest_vars = self._get_exp_vars(dest_exp)
                # Also handle pointer arithmetic (data+offset -> data)
                dest_str = self._exp_to_str(dest_exp)
                if '+' in dest_str:
                    base_var = dest_str.split('+')[0].strip()
                    dest_vars.append(base_var)

                for src_idx in spec.taint_to_dest:
                    if src_idx < len(instr.args):
                        src_exp, _ = instr.args[src_idx]
                        src_vars = self._get_exp_vars(src_exp)
                        for src_var in src_vars:
                            if state.is_tainted(src_var):
                                for dest_var in dest_vars:
                                    state.propagate_taint(src_var, dest_var)
                                    if self.verbose:
                                        print(f"[Translator] Dest taint: {src_var} -> {dest_var}")

        else:
            # No spec found - apply default taint propagation for unknown functions
            # This is conservative: if any argument is tainted, the return is tainted
            # This catches cases like helper.doSomething(tainted_param) -> tainted_result

            # First, check if this is a procedure in our program that always returns a constant
            # This enables inter-procedural dead path elimination
            if self._proc_always_returns_constant(func_name):
                # Procedure always returns a constant, so taint is NOT propagated
                if self.verbose:
                    print(f"[Translator] Skipping taint propagation for constant-returning proc: {func_name}")
            elif instr.ret:
                ret_var = str(instr.ret[0])
                for arg_exp, _ in instr.args:
                    arg_vars = self._get_exp_vars(arg_exp)
                    for arg_var in arg_vars:
                        if state.is_tainted(arg_var):
                            state.propagate_taint(arg_var, ret_var)
                            break  # One taint source is enough

                # Also propagate from receiver for method calls
                if '.' in func_name:
                    parts = func_name.rsplit('.', 1)
                    if len(parts) == 2:
                        receiver_var = parts[0]
                        if state.is_tainted(receiver_var):
                            state.propagate_taint(receiver_var, ret_var)

        # Track secure XML parsers
        # xml.sax.make_parser() creates a parser with secure defaults (XXE disabled)
        if func_name in ('xml.sax.make_parser', 'defusedxml.make_parser'):
            if instr.ret:
                ret_var = str(instr.ret[0])
                state.secure_parsers.add(ret_var)

        # Handle container modification with per-element tracking (separation logic)
        # When tainted data is stored in a container, track at element level if possible
        if 'append' in func_name or 'extend' in func_name:
            # Extract receiver (container) from function name
            parts = func_name.rsplit('.', 1)
            if len(parts) == 2:
                container_var = parts[0]
                # Get the value being appended
                if instr.args:
                    arg_exp, _ = instr.args[0]
                    arg_str = str(arg_exp)
                    arg_vars = self._get_exp_vars(arg_exp)

                    # Determine if the appended value is tainted
                    taint_info = None
                    for arg_var in arg_vars:
                        if state.is_tainted(arg_var):
                            taint_info = state.get_taint_info(arg_var)
                            break

                    # Track per-element if list is tracked, otherwise use coarse-grained
                    if state.is_tracked_list(container_var):
                        state.list_append(container_var, arg_str, taint_info)
                    else:
                        # Initialize tracking for this list
                        state.init_list(container_var)
                        state.list_append(container_var, arg_str, taint_info)

                    # Also maintain coarse-grained taint for compatibility
                    if taint_info:
                        state.propagate_taint(arg_vars[0] if arg_vars else arg_str, container_var)

        elif 'pop' in func_name:
            # Handle list.pop(i) - remove element and shift indices
            parts = func_name.rsplit('.', 1)
            if len(parts) == 2:
                container_var = parts[0]
                # Get pop index (default -1 for no argument)
                pop_index = -1
                if instr.args:
                    try:
                        arg_exp, _ = instr.args[0]
                        pop_index = int(str(arg_exp))
                    except (ValueError, TypeError):
                        pass

                if state.is_tracked_list(container_var):
                    popped = state.list_pop(container_var, pop_index)
                    # If return value is assigned, propagate taint from popped element
                    if instr.ret and popped:
                        ret_var = str(instr.ret[0])
                        _, elem_taint = popped
                        if elem_taint:
                            state.tainted[ret_var] = elem_taint

        elif '__setitem__' in func_name:
            # Extract receiver (container) from function name
            parts = func_name.rsplit('.', 1)
            if len(parts) == 2:
                container_var = parts[0]

                # For dictionary setitem: d[key] = value (2 args: key and value)
                if len(instr.args) >= 2:
                    key_exp, _ = instr.args[0]
                    value_exp, _ = instr.args[1]

                    # Get key as string if it's a constant
                    key_str = str(key_exp).strip('"').strip("'")

                    # Get value variables and check if tainted
                    value_vars = self._get_exp_vars(value_exp)
                    value_taint = None
                    for val_var in value_vars:
                        if state.is_tainted(val_var):
                            value_taint = state.get_taint_info(val_var)
                            break

                    # Initialize dict tracking if not already done
                    if not state.is_tracked_dict(container_var):
                        state.init_dict(container_var)

                    # Set key with per-key taint tracking (separation logic)
                    state.dict_set(container_var, key_str, str(value_exp), value_taint)

                    # Also maintain coarse-grained taint for compatibility
                    if value_taint:
                        state.propagate_taint(value_vars[0] if value_vars else str(value_exp), container_var)
                else:
                    # Fallback: Check if any argument is tainted (coarse-grained)
                    for arg_exp, _ in instr.args:
                        arg_vars = self._get_exp_vars(arg_exp)
                        for arg_var in arg_vars:
                            if state.is_tainted(arg_var):
                                state.propagate_taint(arg_var, container_var)
                                break

        # Handle ConfigParser.set() - per-key tracking like dictionaries
        # conf.set('section', 'key', value) -> track section:key -> value
        elif '.set' in func_name and len(instr.args) >= 3:
            parts = func_name.rsplit('.', 1)
            if len(parts) == 2:
                receiver_var = parts[0]
                section_exp, _ = instr.args[0]
                key_exp, _ = instr.args[1]
                value_exp, _ = instr.args[2]

                # Combine section and key as composite key
                section_str = str(section_exp).strip('"').strip("'")
                key_str = str(key_exp).strip('"').strip("'")
                composite_key = f"{section_str}:{key_str}"

                # Get value variables and check if tainted
                value_vars = self._get_exp_vars(value_exp)
                value_taint = None
                for val_var in value_vars:
                    if state.is_tainted(val_var):
                        value_taint = state.get_taint_info(val_var)
                        break

                # Initialize dict tracking if not already done
                if not state.is_tracked_dict(receiver_var):
                    state.init_dict(receiver_var)

                # Set key with per-key taint tracking
                state.dict_set(receiver_var, composite_key, str(value_exp), value_taint)

                # Also maintain coarse-grained taint for compatibility
                if value_taint and value_vars:
                    state.propagate_taint(value_vars[0], receiver_var)

        # Handle ConfigParser.get() - per-key tracking like dictionaries
        # conf.get('section', 'key') -> return value for section:key
        elif '.get' in func_name and instr.ret and len(instr.args) >= 2:
            parts = func_name.rsplit('.', 1)
            if len(parts) == 2:
                receiver_var = parts[0]
                if state.is_tracked_dict(receiver_var):
                    section_exp, _ = instr.args[0]
                    key_exp, _ = instr.args[1]

                    section_str = str(section_exp).strip('"').strip("'")
                    key_str = str(key_exp).strip('"').strip("'")
                    composite_key = f"{section_str}:{key_str}"

                    ret_var = str(instr.ret[0])
                    key_taint = state.get_dict_key_taint(receiver_var, composite_key)

                    if key_taint:
                        state.tainted[ret_var] = key_taint
                    else:
                        # Key is NOT tainted - clear any existing taint on target
                        if ret_var in state.tainted:
                            del state.tainted[ret_var]
                        result = state.dict_get(receiver_var, composite_key)
                        if result:
                            val, _ = result
                            if val.startswith('"') or val.startswith("'"):
                                state.set_constant(ret_var, val[1:-1])

        # Handle Java Map.put(key, value) - per-key taint tracking using separation logic
        # This enables precise tracking: put("keyA", safe) and put("keyB", tainted)
        # allows get("keyA") to return safe data even though the map contains tainted data
        method_name = func_name.split('.')[-1] if '.' in func_name else func_name
        if method_name == 'put' and len(instr.args) >= 2:
            parts = func_name.rsplit('.', 1)
            if len(parts) == 2:
                receiver_var = parts[0]
                key_exp, _ = instr.args[0]
                value_exp, _ = instr.args[1]

                # Get key as string if it's a constant
                key_str = str(key_exp).strip('"').strip("'")

                # Get value variables and check if tainted
                value_vars = self._get_exp_vars(value_exp)
                value_taint = None
                for val_var in value_vars:
                    if state.is_tainted(val_var):
                        value_taint = state.get_taint_info(val_var)
                        break

                # Initialize dict tracking if not already done
                if not state.is_tracked_dict(receiver_var):
                    state.init_dict(receiver_var)

                # Set key with per-key taint tracking (separation logic)
                # In separation logic terms: MapPointsTo(map, key, value, taint)
                state.dict_set(receiver_var, key_str, str(value_exp), value_taint)

                if self.verbose:
                    print(f"[Translator] Map.put: {receiver_var}[{key_str}] = {value_exp}, tainted={value_taint is not None}")

        # Handle Java Map.get(key) or List.get(index) - per-element taint tracking using separation logic
        # Only return tainted data if the SPECIFIC key/index was tainted
        elif method_name == 'get' and instr.ret and len(instr.args) >= 1:
            parts = func_name.rsplit('.', 1)
            if len(parts) == 2:
                receiver_var = parts[0]
                arg_exp, _ = instr.args[0]
                arg_str = str(arg_exp).strip('"').strip("'")
                ret_var = str(instr.ret[0])

                # Check if it's a tracked dictionary (Map)
                if state.is_tracked_dict(receiver_var):
                    key_taint = state.get_dict_key_taint(receiver_var, arg_str)

                    if key_taint:
                        state.tainted[ret_var] = key_taint
                        if self.verbose:
                            print(f"[Translator] Map.get: {receiver_var}[{arg_str}] -> {ret_var} (TAINTED)")
                    else:
                        # Key is NOT tainted - clear any existing taint on target
                        # This is the key benefit of separation logic: precise per-key tracking
                        if ret_var in state.tainted:
                            del state.tainted[ret_var]
                        if self.verbose:
                            print(f"[Translator] Map.get: {receiver_var}[{arg_str}] -> {ret_var} (safe)")

                # Check if it's a tracked list (ArrayList)
                elif state.is_tracked_list(receiver_var):
                    try:
                        index = int(arg_str)
                        elem_taint = state.get_list_element_taint(receiver_var, index)

                        if elem_taint:
                            state.tainted[ret_var] = elem_taint
                            if self.verbose:
                                print(f"[Translator] List.get: {receiver_var}[{index}] -> {ret_var} (TAINTED)")
                        else:
                            # Element is NOT tainted - clear any existing taint on target
                            if ret_var in state.tainted:
                                del state.tainted[ret_var]
                            if self.verbose:
                                print(f"[Translator] List.get: {receiver_var}[{index}] -> {ret_var} (safe)")
                    except ValueError:
                        pass  # Non-constant index, fall back to default propagation

        # Handle Java List.add(value) with per-element tracking
        elif method_name == 'add' and len(instr.args) >= 1:
            parts = func_name.rsplit('.', 1)
            if len(parts) == 2:
                container_var = parts[0]
                value_exp, _ = instr.args[0]
                value_vars = self._get_exp_vars(value_exp)

                # Check if value is tainted
                value_taint = None
                for val_var in value_vars:
                    if state.is_tainted(val_var):
                        value_taint = state.get_taint_info(val_var)
                        break

                # Track per-element
                if not state.is_tracked_list(container_var):
                    state.init_list(container_var)
                state.list_append(container_var, str(value_exp), value_taint)

                if self.verbose:
                    print(f"[Translator] List.add: {container_var}.add({value_exp}), tainted={value_taint is not None}")

        # Handle Java List.remove(index) - removes element and shifts remaining indices
        elif method_name == 'remove' and len(instr.args) >= 1:
            parts = func_name.rsplit('.', 1)
            if len(parts) == 2:
                container_var = parts[0]
                if state.is_tracked_list(container_var):
                    # Get the index being removed
                    idx_exp, _ = instr.args[0]
                    idx_str = str(idx_exp)
                    try:
                        remove_index = int(idx_str)
                        # Use list_pop to remove element and shift indices
                        state.list_pop(container_var, remove_index)
                        if self.verbose:
                            print(f"[Translator] List.remove: {container_var}.remove({remove_index})")
                    except ValueError:
                        pass  # Non-constant index, can't track precisely

        # =================================================================
        # Memory Safety: Track allocations and deallocations
        # =================================================================

        # A pointer handed to any callee that is not itself releasing it escapes
        # this function's ownership (the callee may take ownership or store it),
        # so it will not be reported as a leak. The deallocator's own argument is
        # released below, after its allocator kind is read for the CWE-762
        # mismatch check. C/C++ only.
        if self._is_c_lang and not (spec and spec.is_deallocator()):
            self._escape_vars(state, self._escaping_arg_vars(instr))

        if spec:
            # Handle memory allocation (malloc, new, etc.)
            if spec.is_allocator() and instr.ret:
                ret_var = str(instr.ret[0])
                state.mark_allocated(ret_var)
                # The result lives on the heap, so freeing it later is legitimate.
                # It is deliberately not recorded as null: a malloc-then-deref is
                # the ordinary correct idiom and must not read as a null deref.
                state.heap_origin[ret_var] = "heap"
                state.null_ptrs.pop(ret_var, None)
                if self._is_c_lang:
                    # Record the allocator KIND (for CWE-762) and take ownership of
                    # the fresh allocation (for CWE-401).
                    kind = self._alloc_kind_of_call(func_name)
                    if kind is not None:
                        state.alloc_kind[ret_var] = kind
                    alloc_id = id(instr)
                    self._leak_sites.setdefault(alloc_id, instr.loc)
                    checks.extend(
                        self._reassign_owner(state, ret_var, alloc_id, proc_name))
                if self.verbose:
                    print(f"[Translator] Allocation: {ret_var} = {func_name}()")

            # Handle memory deallocation (free, delete, etc.)
            if spec.is_deallocator() and len(instr.args) > 0:
                arg_exp, _ = instr.args[0]
                freed_var = self._sole_var(arg_exp) or self._exp_to_str(arg_exp)

                # Check for free of non-heap memory (CWE-590): the pointer's
                # storage came from a stack array or the address of a local, so
                # it was never on the heap and must not be handed to free/delete.
                if self._is_c_lang and self._is_nonheap_origin(freed_var, state):
                    check = self._create_invalid_free_check(
                        instr, state, proc_name, freed_var)
                    checks.append(check)
                    if self.verbose:
                        print(f"[Translator] FREE-NON-HEAP detected: {func_name}({freed_var})")

                # Check for mismatched memory routine (CWE-762): the deallocator's
                # shape must match the allocator that produced the pointer. Only
                # fires when the pointer's allocator kind is known and the routine
                # is a recognised deallocator whose expected partner differs.
                if self._is_c_lang:
                    kind = state.alloc_kind.get(freed_var)
                    routine = self._free_routine_of_call(func_name)
                    if kind is not None and routine is not None \
                            and self._EXPECTED_FREE[kind] != routine:
                        checks.append(self._create_mismatched_free_check(
                            instr, state, proc_name, freed_var, kind, routine))
                        if self.verbose:
                            print(f"[Translator] MISMATCHED-FREE: {routine}({freed_var}) "
                                  f"but allocated with {kind}")

                # Check for double-free: freeing already freed memory
                if state.is_freed(freed_var):
                    check = self._create_double_free_check(instr, state, proc_name, freed_var)
                    checks.append(check)
                    if self.verbose:
                        print(f"[Translator] DOUBLE-FREE detected: {func_name}({freed_var})")

                # Releasing the allocation discharges ownership (no leak). C/C++.
                if self._is_c_lang:
                    aid = state.owned_allocs.get(freed_var)
                    if aid is not None:
                        self._release_alloc(state, aid)

                # Mark as freed for use-after-free detection
                state.mark_freed(freed_var)
                if self.verbose:
                    print(f"[Translator] Deallocation: {func_name}({freed_var})")

        # =================================================================
        # Inter-procedural Analysis: Apply procedure summaries
        # =================================================================

        # Check if this is a call to a user-defined procedure with a summary
        summary = self._proc_summaries.get(func_name)

        # Try qualified names (ClassName::MethodName)
        if summary is None and '.' in func_name:
            # Try method name only
            method_name = func_name.split('.')[-1]
            for sname, s in self._proc_summaries.items():
                if sname.endswith('::' + method_name) or sname.endswith('.' + method_name):
                    summary = s
                    break

        if summary:
            if self.verbose:
                print(f"[IPA] Applying summary for {summary.proc_name}")

            # Map actual arguments to parameter indices
            for i, (arg_exp, _) in enumerate(instr.args):
                arg_var = self._exp_to_str(arg_exp)

                # Check if this parameter is freed by the callee
                if summary.frees_param(i):
                    # Check for double-free: arg was already freed before this call
                    if state.is_freed(arg_var):
                        check = self._create_double_free_check(instr, state, proc_name, arg_var)
                        checks.append(check)
                        if self.verbose:
                            print(f"[IPA] DOUBLE-FREE via callee: {func_name} frees arg {i} ({arg_var})")

                    # Mark arg as freed (the callee frees it)
                    state.mark_freed(arg_var)
                    if self.verbose:
                        print(f"[IPA] Callee {func_name} frees arg {i} ({arg_var})")

                # Check if parameter is dereferenced after being freed
                if summary.derefs_param(i) and state.is_freed(arg_var):
                    # This is a use-after-free: passing freed ptr to function that derefs it
                    check = self._create_uaf_check(instr, state, proc_name, arg_var)
                    checks.append(check)
                    if self.verbose:
                        print(f"[IPA] UAF via callee: {func_name} derefs freed arg {i} ({arg_var})")

            # Handle class member effects (for this->member patterns)
            if summary.frees_member:
                # If this is a method call on an object, mark that member as freed
                if '.' in func_name:
                    obj_var = func_name.rsplit('.', 1)[0]
                    member_var = f"{obj_var}.{summary.frees_member}"
                    # Check for double-free on member
                    if state.is_member_freed(obj_var, summary.frees_member):
                        check = self._create_double_free_check(instr, state, proc_name, member_var)
                        checks.append(check)
                        if self.verbose:
                            print(f"[IPA] DOUBLE-FREE on member: {member_var}")
                    state.mark_freed(member_var)
                    state.set_member_state(obj_var, summary.frees_member, "freed")
                    if self.verbose:
                        print(f"[IPA] Callee frees member: {member_var}")

            # Handle constructor: track member allocations
            if summary.is_constructor and summary.allocates_member:
                if len(instr.args) > 0:
                    # First arg is usually 'this' or the object being constructed
                    obj_exp, _ = instr.args[0]
                    obj_var = self._exp_to_str(obj_exp)
                    state.set_member_state(obj_var, summary.allocates_member, "allocated")
                    if self.verbose:
                        print(f"[IPA] Constructor allocates member: {obj_var}.{summary.allocates_member}")

            # Handle destructor: check for UAF if member was already freed externally
            if summary.is_destructor:
                if len(instr.args) > 0:
                    obj_exp, _ = instr.args[0]
                    obj_var = self._exp_to_str(obj_exp)
                    # If destructor frees a member that was already freed, it's double-free
                    if summary.frees_member and state.is_member_freed(obj_var, summary.frees_member):
                        member_var = f"{obj_var}.{summary.frees_member}"
                        check = self._create_double_free_check(instr, state, proc_name, member_var)
                        checks.append(check)
                        if self.verbose:
                            print(f"[IPA] DOUBLE-FREE in destructor: {member_var}")

        # Default: store return value
        if instr.ret:
            ret_var = str(instr.ret[0])
            state.heap[ret_var] = f"call_{func_name}"
            state.allocated[ret_var] = True

        return checks, state

    def _feasibility_guard(self, exp, assume_true):
        """Sound pure formula for assuming `exp` is truthy (assume_true) or falsy on
        an edge. A bare-variable truthiness test has no sound boolean encoding in the
        separation-logic checker (a lone Var is spatial, so Not(Var) is spuriously
        unsatisfiable); model it explicitly as (in)equality against a falsy sentinel
        so both polarities are individually satisfiable and contradict only when the
        same variable is assumed both ways. Comparisons and boolean combinators use
        the normal encoding. Returns None if no usable guard can be formed."""
        if isinstance(exp, ExpUnOp) and exp.op == "!":
            return self._feasibility_guard(exp.operand, not assume_true)
        f = self._exp_to_formula(exp)
        if isinstance(f, Var):
            return Neq(f, Const(0)) if assume_true else Eq(f, Const(0))
        return f if assume_true else Not(f)

    def _branch_edge_formula(self, node):
        """The branch condition of a clean 2-way branch (two prunes of the same
        condition, one true and one false, with two successors). Successor 0 assumes
        it true; successor 1 assumes it false. Returns the condition Exp, else None."""
        prunes = [i for i in node.instrs if isinstance(i, Prune)]
        if len(prunes) != 2 or len(node.succs) < 2:
            return None
        p_true = next((p for p in prunes if p.is_true_branch), None)
        p_false = next((p for p in prunes if not p.is_true_branch), None)
        if p_true is None or p_false is None:
            return None
        if str(p_true.condition) != str(p_false.condition):
            return None
        return p_true.condition

    def _feasibility_sat(self, formula) -> bool:
        """Is the pure path-condition formula satisfiable? Uses Frame's Z3 checker.
        Defaults to True (keep the finding) on any error, so a finding is never
        dropped unless its path is provably unsatisfiable."""
        checker = getattr(self, "_feas_checker", None)
        if checker is None:
            try:
                from frame.checking.checker import EntailmentChecker
                checker = EntailmentChecker()
            except Exception:
                checker = False   # unavailable: never drop
            self._feas_checker = checker
        if not checker:
            return True
        try:
            return bool(checker.is_satisfiable(formula))
        except Exception:
            return True

    def _filter_infeasible_checks(self, checks):
        """Drop findings whose accumulated branch conditions are unsatisfiable: the
        sink sits on a path that cannot execute. Sound -- a finding is dropped only
        when its path condition is provably UNSAT, so feasible findings are kept."""
        out = []
        for c in checks:
            pc = getattr(c, "path_condition", None)
            if pc:
                conj = pc[0] if len(pc) == 1 else self._build_conjunction(list(pc))
                if not self._feasibility_sat(conj):
                    continue
            out.append(c)
        return out

    def _exec_prune(self, instr: Prune, state: SymbolicState) -> Optional[SymbolicState]:
        """
        Execute prune (conditional).

        Returns None if this branch is provably unreachable (dead code).
        This enables constant folding to eliminate false positives in dead branches.

        Note: When multiple Prune instructions are in the same node (both true and false
        branches), we only skip if BOTH branches would be unreachable. Otherwise, we
        let the reachable branch proceed and just skip adding unreachable successor indices.
        """
        # Try constant folding: evaluate condition with known constants
        cond_str = str(instr.condition)
        eval_result = state.try_eval_expr(cond_str)

        if eval_result is not None:
            # Condition can be fully evaluated
            cond_is_true = bool(eval_result)

            # Track which successor index to skip (0 = true branch, 1 = false branch)
            if cond_is_true and not instr.is_true_branch:
                # Condition is always TRUE but we're on the FALSE branch
                # Mark that the false branch successor (index 1) should be skipped
                if not hasattr(state, '_skip_successor_indices'):
                    state._skip_successor_indices = set()
                state._skip_successor_indices.add(1)  # Skip false branch
            elif not cond_is_true and instr.is_true_branch:
                # Condition is always FALSE but we're on the TRUE branch
                # Mark that the true branch successor (index 0) should be skipped
                if not hasattr(state, '_skip_successor_indices'):
                    state._skip_successor_indices = set()
                state._skip_successor_indices.add(0)  # Skip true branch

        # Convert condition to Frame formula and add to path constraints
        formula = self._exp_to_formula(instr.condition)
        if not instr.is_true_branch:
            formula = Not(formula)
        state.path_constraints.append(formula)

        # Recognize validation patterns and mark variables as asserted safe
        # When we see "if '<pattern>' in var: return" and we're in the false branch,
        # the continuation has validated that the pattern is NOT present
        cond_str = str(instr.condition)

        # Path traversal validation patterns (false branch = safe)
        if not instr.is_true_branch:
            # Patterns like "../" in var or ".." in var (with any quote style)
            if ("../" in cond_str or '".."' in cond_str):
                # Extract variable being checked
                cond_vars = self._get_exp_vars(instr.condition)
                for var in cond_vars:
                    state.asserted_safe.setdefault(var, []).append("filesystem")

            # XPath injection validation: apostrophe check
            if ("'" in cond_str and " in " in cond_str):
                cond_vars = self._get_exp_vars(instr.condition)
                for var in cond_vars:
                    state.asserted_safe.setdefault(var, []).append("xpath")

        # Code injection validation: startswith/endswith checks
        # Pattern: if not bar.startswith('\'') or not bar.endswith('\''):
        # On FALSE branch, the condition is FALSE, meaning validation PASSED
        # (the negated checks are all false -> the positive checks are true)
        if not instr.is_true_branch:
            # Check for startswith/endswith validation patterns
            import re
            # Pattern matches: bar.startswith('\'') or bar.startswith("'")
            validation_match = re.search(
                r"(\w+)\.(?:startswith|endswith)\(['\"].*?['\"]\)",
                cond_str
            )
            if validation_match:
                var_name = validation_match.group(1)
                # On the FALSE branch of a validation check with negations,
                # the variable has passed validation (is a valid string literal)
                state.validated_for_eval.add(var_name)

            # URL redirect validation: netloc whitelist check
            # Pattern: if url.netloc not in ['google.com'] or url.scheme != 'https':
            # On FALSE branch, the URL has been validated against a whitelist
            import re
            netloc_check = re.search(r'(\w+)\.netloc\s+not\s+in', cond_str)
            if netloc_check:
                # Mark any tainted variables as safe for redirect
                # Look for variables that were parsed with urlparse
                for var in list(state.tainted.keys()):
                    state.asserted_safe.setdefault(var, []).append("redirect")

        return state

    def _exec_taint_source(self, instr: TaintSource, state: SymbolicState) -> SymbolicState:
        """Execute taint source annotation"""
        var_name = self._get_var_name(instr.var)
        state.add_taint(var_name, TaintInfo(
            source_kind=instr.kind,
            source_var=var_name,
            source_location=instr.loc,
        ))
        return state

    def _sanitizes_kind(self, sanitized_kinds, sink_kind) -> bool:
        """Whether any raw sanitizer-kind string neutralizes this sink kind,
        comparing through the sink-kind alias map (e.g. a 'path' sanitizer
        covers a 'filesystem' sink, 'header_injection' covers 'header')."""
        if not sanitized_kinds:
            return False
        from .instructions import resolve_sink_kind
        target = sink_kind.value if hasattr(sink_kind, "value") else sink_kind
        for s in sanitized_kinds:
            if s == target:
                return True
            try:
                if resolve_sink_kind(s).value == target:
                    return True
            except Exception:
                pass
        return False

    def _exec_taint_sink(
        self,
        instr: TaintSink,
        state: SymbolicState,
        proc_name: str
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        """Execute taint sink annotation"""
        checks = []
        sink_vars = self._get_exp_vars(instr.exp)
        exp_str = str(instr.exp)

        # Usage-based sinks (weak_hash, weak_crypto) don't need taint flow
        # The mere usage of the function is the vulnerability
        usage_based_kinds = {'weak_hash', 'weak_crypto', 'insecure_random',
                             'insecure_cookie', 'insecure_cookie_httponly',
                             'deserialize_unsafe', 'csrf_disabled'}
        if instr.kind.value in usage_based_kinds:
            # For insecure_cookie, we need to check the description for setSecure(false)
            if instr.kind.value == 'insecure_cookie':
                # Only flag if the description mentions setSecure (handled by translator)
                # The frontend should only create this sink for setSecure(false) calls
                pass  # Let it fall through to create the check
            # Create check directly - no taint flow required
            check = self._create_usage_based_check_from_sink(
                instr, state, proc_name
            )
            checks.append(check)
            return checks, state

        # Check for inline .replace() sanitization patterns in the expression
        # Pattern: var.replace("'", "&apos;") - XPath apostrophe escaping
        import re
        inline_sanitized_vars = set()
        inline_sanitized_for = {}  # var -> list of sink types sanitized for

        # XPath sanitization: replacing apostrophes with &apos;
        # Simple pattern that matches var.replace(...&apos;...)
        xpath_sanitize_match = re.findall(r'(\w+)\.replace\([^)]*&apos;[^)]*\)', exp_str)
        if xpath_sanitize_match:
            for var in xpath_sanitize_match:
                inline_sanitized_vars.add(var)

        # Check for embedded sanitizer calls in the expression
        # Pattern: encodeForHTML(var), Encode.forHtml(var), escapeHtml(var), etc.
        # This handles string concatenation like: "text" + encodeForHTML(tainted) + "more text"
        # Note: In SIL expressions, method names may be quoted: "method.name"(args)
        embedded_sanitizer_patterns = [
            # ESAPI sanitizers (handle quoted method names)
            (r'encodeForHTML["\']?\s*\(([^)]+)\)', ['html', 'xss']),
            (r'encodeForJavaScript["\']?\s*\(([^)]+)\)', ['html', 'xss']),
            (r'encodeForCSS["\']?\s*\(([^)]+)\)', ['html', 'xss']),
            (r'encodeForURL["\']?\s*\(([^)]+)\)', ['url', 'redirect']),
            (r'encodeForXML["\']?\s*\(([^)]+)\)', ['xml', 'xxe']),
            (r'encodeForXPath["\']?\s*\(([^)]+)\)', ['xpath']),
            (r'encodeForSQL["\']?\s*\(([^)]+)\)', ['sql']),
            (r'encodeForLDAP["\']?\s*\(([^)]+)\)', ['ldap']),
            (r'encodeForOS["\']?\s*\(([^)]+)\)', ['command']),
            # OWASP Encoder
            (r'forHtml["\']?\s*\(([^)]+)\)', ['html', 'xss']),
            (r'forHtmlContent["\']?\s*\(([^)]+)\)', ['html', 'xss']),
            (r'forHtmlAttribute["\']?\s*\(([^)]+)\)', ['html', 'xss']),
            (r'forJavaScript["\']?\s*\(([^)]+)\)', ['html', 'xss']),
            # Apache Commons
            (r'escapeHtml[4]?["\']?\s*\(([^)]+)\)', ['html', 'xss']),
            (r'escapeXml["\']?\s*\(([^)]+)\)', ['xml', 'html', 'xss']),
            (r'escapeSql["\']?\s*\(([^)]+)\)', ['sql']),
            # Spring
            (r'htmlEscape["\']?\s*\(([^)]+)\)', ['html', 'xss']),
        ]

        for pattern, sink_types in embedded_sanitizer_patterns:
            for match in re.finditer(pattern, exp_str, re.IGNORECASE):
                sanitized_arg = match.group(1).strip()
                # Extract variable names from the argument
                arg_vars = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', sanitized_arg)
                for arg_var in arg_vars:
                    if arg_var not in inline_sanitized_for:
                        inline_sanitized_for[arg_var] = set()
                    inline_sanitized_for[arg_var].update(sink_types)

        # Spec-based inline sanitizers: any sanitizer call (from the language
        # specs) wrapping a variable inside the sink expression neutralizes that
        # variable for the sanitizer's sink kinds. This is language-agnostic and
        # covers, e.g., C#'s HttpUtility.HtmlEncode / Uri.EscapeDataString.
        for func_name, arg_vars in self._get_sanitizer_calls(instr.exp):
            spec = self.program.get_spec(func_name)
            if not spec or not spec.is_taint_sanitizer():
                continue
            for arg_var in arg_vars:
                inline_sanitized_for.setdefault(arg_var, set()).update(spec.is_sanitizer)

        for var in sink_vars:
            # Skip xml sinks for variables that have been safely processed
            if instr.kind.value == 'xml' and var in state.safe_for_xml_sink:
                continue

            # Skip eval sinks for variables that passed validation (startswith/endswith)
            if instr.kind.value == 'eval' and var in state.validated_for_eval:
                continue

            # Skip xpath sinks for variables with inline .replace() sanitization
            if instr.kind.value == 'xpath' and var in inline_sanitized_vars:
                continue

            # Skip sinks for variables sanitized by embedded sanitizer calls
            if var in inline_sanitized_for:
                if instr.kind.value in inline_sanitized_for[var]:
                    continue

            if state.is_tainted(var):
                # IDOR requires an ATTACKER-CONTROLLED object selector: only a
                # USER_INPUT-kind value (path/query/body parameter) names a
                # cross-user object. A selector that is the caller's own
                # identity (PRINCIPAL) is self-scoped; a value read from the
                # database (DATABASE) or environment is not directly attacker-
                # supplied. Other sink kinds keep firing on any taint.
                if instr.kind.value == 'resource_select':
                    _ti = state.get_taint_info(var)
                    if _ti is None or _ti.source_kind != TaintKind.USER_INPUT:
                        continue
                # CWE-770 is about an allocation size that is UNBOUNDED. A branch
                # condition on the path that constrains the size discharges that,
                # so only a size reaching the allocator unchecked is reported.
                if instr.kind == SinkKind.ALLOC_SIZE and \
                        self._alloc_size_is_bounded(var, state):
                    continue
                if not state.is_sanitized_for(var, instr.kind.value):
                    if not state.is_asserted_safe_for(var, instr.kind.value):
                        check = self._create_taint_check(
                            instr, state, proc_name,
                            var, instr.kind
                        )
                        checks.append(check)

        # Check for embedded taint source calls in the sink expression
        # E.g., Process.Start("cmd", "/C " + Console.ReadLine()) - the ReadLine() is a source
        # flowing directly to the sink without going through a variable
        embedded_sources = self._get_embedded_source_calls(instr.exp)
        for func_name, source_kind_str in embedded_sources:
            # This is a direct taint source -> sink flow
            # Create vulnerability check for this direct flow
            check = VulnerabilityCheck(
                formula=And(
                    Source(Var(func_name), source_kind_str),
                    Sink(Var(func_name), instr.kind.value)
                ),
                vuln_type=VulnType.from_sink_kind(instr.kind),
                location=instr.loc or Location.unknown(),
                description=f"Tainted data from '{func_name}' flows to {instr.kind.value} sink",
                source_var=func_name,
                source_location=instr.loc or Location.unknown(),
                sink_type=instr.kind.value,
                procedure_name=proc_name,
            )
            checks.append(check)

        # Check for embedded member-access taint sources (e.g. req.body.code,
        # req.query.id) appearing inline in the sink expression with no
        # intermediate variable -- the via-variable case puts only the variable
        # name in the sink exp, so this fires only for genuinely inline sources.
        for src_chain, src_kind in self._get_embedded_member_sources(instr.exp):
            # Respect inline sanitizers wrapping the source in this same exp.
            # Sanitizer kinds are raw spec strings (e.g. 'path'); the sink kind
            # is the resolved enum value (e.g. 'filesystem'), so compare through
            # the alias map rather than by string equality.
            chain_vars = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', src_chain)
            if any(self._sanitizes_kind(inline_sanitized_for.get(v, set()), instr.kind)
                   for v in chain_vars):
                continue
            check = VulnerabilityCheck(
                formula=And(
                    Source(Var(src_chain), src_kind),
                    Sink(Var(src_chain), instr.kind.value)
                ),
                vuln_type=VulnType.from_sink_kind(instr.kind),
                location=instr.loc or Location.unknown(),
                description=f"Tainted data from '{src_chain}' flows to {instr.kind.value} sink",
                source_var=src_chain,
                source_location=instr.loc or Location.unknown(),
                sink_type=instr.kind.value,
                procedure_name=proc_name,
            )
            checks.append(check)

        return checks, state

    def _exec_sanitize(self, instr: Sanitize, state: SymbolicState) -> SymbolicState:
        """Execute sanitize annotation"""
        var_name = self._get_var_name(instr.var)
        state.add_sanitization(var_name, [s.value for s in instr.sanitizes])
        return state

    def _exec_assert_safe(self, instr: AssertSafe, state: SymbolicState) -> SymbolicState:
        """Execute assert safe annotation"""
        safe_vars = self._get_exp_vars(instr.exp)
        for var in safe_vars:
            state.asserted_safe[var] = [s.value for s in instr.for_sinks] if instr.for_sinks else []
        return state

    def _exec_return(
        self,
        instr: Return,
        state: SymbolicState,
        proc_name: str
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        """
        Execute return statement.

        Returning tainted data is NOT treated as XSS. A method's return value is
        almost never reflected as raw HTML in practice: Spring @RestController /
        @ResponseBody methods serialize to JSON, plain @Controller methods return
        a view *name* (not the body), and Express handlers send JSON via res.json.
        Flagging every tainted return as XSS produced almost only false positives
        (JSON responses, view names, and flows that are really SSRF/other classes
        mislabeled as XSS). Real reflected XSS is caught at explicit output sinks
        (response.getWriter().print/write, render_template, res.send, etc.).
        """
        # Intentionally emits no XSS checks -- see docstring. Real XSS is detected
        # at explicit HTML output sinks, not at return statements.
        checks: List[VulnerabilityCheck] = []
        if self._is_c_lang:
            # CWE-562: returning the address of a local hands back a dangling
            # pointer. Checked before the escape below so the returned pointer's
            # stack origin is still visible.
            if instr.value is not None and self._returns_stack_address(instr.value, state):
                checks.append(self._create_return_stack_check(instr, state, proc_name))
            # A returned pointer transfers ownership to the caller, so it does not
            # leak.
            if instr.value is not None:
                self._escape_vars(state, self._escaping_expr_vars(instr.value))
            # This return ends the path; any allocation still owned here leaks.
            checks.extend(self._finalize_leaks(state, proc_name))
        return checks, state

    # =========================================================================
    # Vulnerability Check Creation
    # =========================================================================

    # Authenticated-principal identifiers (an ownership binding when they scope a
    # resource-selection query). A catalog of framework principals, like the
    # source/sink name catalogs -- not a source-text pattern rule.
    _PRINCIPAL_TOKENS = ("current_user", "get_jwt_identity", "current_identity",
                         "g.user", "request.user")

    _AUTH_HEADER_NAMES = ("authorization", "cookie", "x-api-key", "x-auth-token",
                          "x-access-token", "x-session-token")

    def _is_auth_credential_access(self, func_name, instr) -> bool:
        """True if a call reads an HTTP authentication credential header
        (Authorization / Cookie / API-key). The attacker can only present their own
        credential, so this value and anything derived from it is the authenticated
        principal -- tainted PRINCIPAL, not USER_INPUT."""
        try:
            fn = str(func_name or "")
            if "headers.get" not in fn and "headers.__getitem__" not in fn:
                return False
            for a in (getattr(instr, "args", None) or []):
                exp = a[0] if isinstance(a, tuple) else a
                s = str(exp).strip().strip("'\"").lower()
                if s in self._AUTH_HEADER_NAMES:
                    return True
        except Exception:
            return False
        return False

    def _filter_post_hoc_ownership_checks(self, proc, checks):
        """Drop IDOR checks whose fetched object is validated by a post-hoc
        ownership guard: a conditional that compares the fetched object's field
        against the authenticated principal (e.g.
        `if txn.sender_id != current_user.id and txn.receiver_id != current_user.id: abort(403)`).

        The selection query itself is attacker-parameterized, but the caller's
        access is authorized by the subsequent ownership proof, so it is not an
        object-level authorization flaw. Scoped per procedure; only fires when an
        explicit principal-vs-object comparison names the fetched object.
        """
        idor_checks = [c for c in checks if c.vuln_type == VulnType.IDOR]
        if not idor_checks:
            return checks
        import re

        def _principal_base(tok):
            return tok.split(".", 1)[0]

        principal_bases = {_principal_base(t) for t in self._PRINCIPAL_TOKENS}

        # 1. Object bases compared against a principal inside a branch condition.
        guarded_objects = set()
        for node in proc.nodes.values():
            for instr in node.instrs:
                if isinstance(instr, Prune):
                    cond = str(instr.condition)
                    if not any(tok in cond for tok in self._PRINCIPAL_TOKENS):
                        continue
                    for base in re.findall(r'([A-Za-z_]\w*)\.\w+', cond):
                        if base not in principal_bases:
                            guarded_objects.add(base)
        if not guarded_objects:
            return checks

        # 2. Alias map: a call result temp assigned to a named variable.
        alias = {}
        for node in proc.nodes.values():
            for instr in node.instrs:
                if isinstance(instr, Assign):
                    try:
                        rhs = list(instr.exp.free_vars())
                    except Exception:
                        rhs = []
                    if len(rhs) == 1:
                        alias[rhs[0]] = str(instr.id)

        # 3. Resource-select calls whose result object is guarded -> protected selectors.
        protected = set()
        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call) or not instr.ret:
                    continue
                spec = self.program.get_spec(instr.get_full_name())
                if not (spec and spec.is_taint_sink() and spec.is_sink == 'resource_select'):
                    continue
                obj = str(instr.ret[0])
                if obj not in guarded_objects and alias.get(obj) not in guarded_objects:
                    continue
                for aidx in (spec.sink_args or []):
                    if aidx < len(instr.args):
                        for v in self._get_exp_vars(instr.args[aidx][0]):
                            protected.add(v)
        if not protected:
            return checks

        return [c for c in checks
                if not (c.vuln_type == VulnType.IDOR and c.source_var in protected)]

    def _resource_select_principal_scoped(self, instr) -> bool:
        """True if a resource-selection call is scoped by the authenticated principal
        (e.g. filter_by(user_id=current_user.id, id=x)) -- the query selects the
        caller's own resource, so it is not an object-level authorization flaw.
        Inspects the call's receiver + argument expressions in the IR."""
        try:
            parts = []
            if getattr(instr, "receiver", None) is not None:
                parts.append(str(instr.receiver))
            for a in (getattr(instr, "args", None) or []):
                parts.append(str(a[0] if isinstance(a, tuple) else a))
            blob = " ".join(parts)
            return any(tok in blob for tok in self._PRINCIPAL_TOKENS)
        except Exception:
            return False

    def _create_taint_check(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str,
        tainted_var: str,
        sink_kind: SinkKind
    ) -> VulnerabilityCheck:
        """Create a vulnerability check for taint flow to sink"""
        taint_info = state.get_taint_info(tainted_var)

        # Build Frame formula
        parts = []

        # Source annotation
        if taint_info:
            parts.append(Source(Var(taint_info.source_var), taint_info.source_kind.value))

        # Taint predicate
        parts.append(Taint(Var(tainted_var)))

        # Sink predicate
        parts.append(Sink(Var(tainted_var), sink_kind.value))

        # Path constraints
        for constraint in state.path_constraints:
            parts.append(constraint)

        formula = self._build_conjunction(parts)

        # Get vulnerability type
        vuln_type = VulnType.from_sink_kind(sink_kind)

        return VulnerabilityCheck(
            formula=formula,
            vuln_type=vuln_type,
            location=instr.loc,
            description=f"Tainted data from '{taint_info.source_var if taint_info else 'unknown'}' "
                       f"flows to {sink_kind.value} sink",
            tainted_var=tainted_var,
            source_var=taint_info.source_var if taint_info else "",
            source_location=taint_info.source_location if taint_info else None,
            sink_type=sink_kind.value,
            procedure_name=proc_name,
            data_flow_path=taint_info.propagation_path if taint_info else [],
        )

    # Matches an unbounded conversion in a scanf format string: %s / %[ / %ls
    # with no field width (e.g. "%s", "%[^\n]"), but NOT a bounded "%9s".
    _UNBOUNDED_SCANF = re.compile(r'%(?!\d)\*?l?[s\[]')

    def _is_unbounded_scanf_format(self, arg_exp) -> bool:
        """True if a scanf argument is a literal format string with an
        unbounded %s/%[ conversion (the actual buffer-overflow trigger)."""
        if isinstance(arg_exp, ExpConst) and isinstance(arg_exp.value, str):
            return bool(self._UNBOUNDED_SCANF.search(arg_exp.value))
        return False

    def _alloc_size_is_bounded(self, var: str, state: SymbolicState) -> bool:
        """Is the allocation size `var` constrained on the path to the allocator?

        Any branch condition mentioning the variable counts: a comparison against
        a limit, a range test, a membership check. Frame does not try to decide
        whether a particular guard is a SUFFICIENT bound, only whether the value
        was checked at all. Whether `n < 10_000_000` is small enough is a policy
        question, and answering it here would turn every deliberate limit into a
        finding.

        A guard is dropped from `feasibility_constraints` as soon as the variable
        it mentions is reassigned, so a stale check on an older value cannot
        silence a genuinely unchecked one.
        """
        if state.get_constant(var) is not None:
            return True
        for guard in state.feasibility_constraints:
            if var in guard.free_vars():
                return True
        return False

    # =========================================================================
    # Structural non-termination detectors (CWE-835 / CWE-674)
    #
    # These are properties of the finished CFG rather than of a taint flow, so
    # they run once per procedure instead of during symbolic execution. Both are
    # deliberately narrow: they fire only when non-termination follows from the
    # graph itself, never from a guess about what a condition might evaluate to.
    # =========================================================================

    # Operators that evaluate only some of their operands: short-circuit
    # connectives and the ternary, which reaches the IR as an ExpBinOp carrying a
    # "?:" marker. A call underneath one of these runs conditionally even though
    # the frontend hoists it into the enclosing block as a plain Call.
    _CONDITIONAL_OPS = frozenset({"&&", "||", "and", "or", "?:", "??"})

    def _is_always_true_condition(self, exp) -> bool:
        """Is `exp` a literal that is truthy in every execution?

        Only literals qualify. `while (x)` is never always-true here even if x
        happens to be constant on some path: that would be a claim about values,
        and this detector only makes claims about syntax.
        """
        if not isinstance(exp, ExpConst):
            return False
        value = exp.value
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        return False

    def _nonterminating_loop_checks(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """CWE-835: a loop whose exit is unreachable by construction.

        Two obligations, both discharged structurally:

        * the loop condition is a literal that is always truthy, so the exit
          prune (which assumes the condition false) can never be taken, and
        * the frontend proved the body holds no break / return / throw / goto /
          yield, so no statement inside can leave the loop either.

        `for` heads are lowered with a constant-true placeholder condition and
        never carry `loop_body_can_exit`, so iteration over a collection is not a
        candidate. Neither is `while cond:` for any non-literal cond, however
        obviously it may loop forever: proving that needs value reasoning, and
        guessing there is exactly how this class of detector produces noise.
        """
        checks: List[VulnerabilityCheck] = []

        for node in proc.nodes.values():
            if node.kind != NodeKind.LOOP_HEAD:
                continue
            # None means "not analysed" (every non-while head); True means the
            # body has a way out. Only an explicit False licenses a finding.
            if node.loop_body_can_exit is not False:
                continue

            prunes = [i for i in node.instrs if isinstance(i, Prune)]
            if not prunes:
                continue
            if not all(self._is_always_true_condition(p.condition) for p in prunes):
                continue

            checks.append(VulnerabilityCheck(
                formula=True_(),
                vuln_type=VulnType.INFINITE_LOOP,
                location=prunes[0].loc,
                description="Loop condition is always true and the body contains no "
                            "break, return or throw: the loop cannot terminate",
                sink_type="infinite_loop",
                procedure_name=proc.name,
            ))

        return checks

    def _iter_instr_exps(self, instr: Instr):
        """Every top-level expression carried by an instruction.

        Reads the dataclass fields rather than enumerating instruction types, so
        a new instruction kind is covered without touching this.
        """
        for value in vars(instr).values():
            if isinstance(value, Exp):
                yield value
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, Exp):
                        yield item
                    elif isinstance(item, tuple):
                        for sub in item:
                            if isinstance(sub, Exp):
                                yield sub

    def _exp_calls_name(self, exp: Exp, name: str) -> bool:
        """Does `exp` contain a call to `name` anywhere in its subtree?"""
        stack = [exp]
        while stack:
            cur = stack.pop()
            if isinstance(cur, ExpCall):
                callee = cur.func
                if isinstance(callee, ExpConst) and isinstance(callee.value, str):
                    if self._strip_self_receiver(callee.value) == name:
                        return True
                elif isinstance(callee, ExpVar) and str(callee.var) == name:
                    return True
            for child in (getattr(cur, "__dict__", {}) or {}).values():
                if isinstance(child, Exp):
                    stack.append(child)
                elif isinstance(child, (list, tuple)):
                    stack.extend(c for c in child if isinstance(c, Exp))
        return False

    def _strip_self_receiver(self, name: str) -> str:
        """Drop a leading `self.` / `this.` receiver from a call name."""
        for prefix in ("self.", "this."):
            if name.startswith(prefix):
                return name[len(prefix):]
        return name

    def _is_direct_self_call(self, instr: Instr, proc: Procedure) -> bool:
        """Is `instr` a call from `proc` to `proc` itself?

        Matching is strict on purpose. `self.conn.close()` inside `close()` shares
        the simple name but calls another object, so only the procedure's own
        receiver (`self.` / `this.`) counts.

        Inside a METHOD, an unqualified call to the method's own name means
        different things per language. Java and C# resolve it through the
        implicit receiver, so it is recursion. Python and JavaScript require an
        explicit receiver for a method call, so there it names an unrelated free
        function, which is exactly how a delegating wrapper is written
        (`def find_frame(self, ...): return find_frame(self, ...)`). Both idioms
        are common, so this branches on the program's language rather than
        guessing. A plain function, whose procedure name IS the simple name,
        recurses unqualified in every language.
        """
        if not isinstance(instr, Call):
            return False

        simple_name = proc.name.rsplit(".", 1)[-1]
        called = instr.get_func_name()
        if instr.receiver is not None:
            called = f"{instr.receiver}.{called}"

        stripped = self._strip_self_receiver(called)
        if stripped != called:
            return stripped == simple_name
        if called != simple_name:
            return False
        if proc.name == simple_name:
            return True
        language = getattr(self.program, "language", "") or ""
        return language in self._IMPLICIT_RECEIVER_LANGUAGES

    # Languages where an unqualified call inside a method resolves against the
    # implicit receiver before any free function of the same name.
    _IMPLICIT_RECEIVER_LANGUAGES = frozenset({"java", "csharp"})

    def _recursion_is_expression_guarded(self, proc: Procedure, simple_name: str) -> bool:
        """Does a self-call sit inside a ternary or a short-circuit operand?

        The frontends hoist a nested call out of the expression containing it, so
        `return f(x) if p else x` and `return p or f(x)` both leave a Call that
        looks unconditional in the block while the recursion actually happens on
        one branch only. Those forms carry their own base case, so any procedure
        that has one is left alone entirely.
        """
        for node in proc.nodes.values():
            for instr in node.instrs:
                for exp in self._iter_instr_exps(instr):
                    stack = [exp]
                    while stack:
                        cur = stack.pop()
                        if self._is_conditional_exp(cur) and self._exp_calls_name(cur, simple_name):
                            return True
                        for child in (getattr(cur, "__dict__", {}) or {}).values():
                            if isinstance(child, Exp):
                                stack.append(child)
                            elif isinstance(child, (list, tuple)):
                                stack.extend(c for c in child if isinstance(c, Exp))
        return False

    def _is_conditional_exp(self, exp) -> bool:
        """Does `exp` evaluate only some of its operands?

        True for a ternary and for the short-circuit connectives. The operator
        marker is looked for in every field of the node rather than in `op`
        alone, because a ternary reaches the IR as an ExpBinOp whose fields the
        frontends do not fill in a uniform order.
        """
        if isinstance(exp, ExpTernary):
            return True
        if not isinstance(exp, ExpBinOp):
            return False
        for field_value in (exp.op, exp.left, exp.right):
            marker = None
            if isinstance(field_value, str):
                marker = field_value
            elif isinstance(field_value, ExpConst) and isinstance(field_value.value, str):
                marker = field_value.value
            if marker is not None and marker in self._CONDITIONAL_OPS:
                return True
        return False

    def _call_is_unavoidable(self, proc: Procedure, call_node_id: int, call_index: int) -> bool:
        """Does every execution of `proc` reach the self-call?

        Computed by deleting the call's block from the CFG and asking whether the
        entry can still reach a way out: a block with no successors, or one that
        returns. If it can, that path is a reachable base case. If it cannot, the
        recursive call happens on every run and the recursion is unbounded.
        """
        node = proc.nodes.get(call_node_id)
        if node is None:
            return False

        # A return earlier in the same block leaves before recursing.
        for earlier in node.instrs[:call_index]:
            if isinstance(earlier, Return):
                return False

        reachable: Set[int] = set()
        stack = [proc.entry_node]
        while stack:
            nid = stack.pop()
            if nid in reachable or nid == call_node_id or nid not in proc.nodes:
                continue
            reachable.add(nid)
            stack.extend(proc.nodes[nid].succs)

        for nid in reachable:
            other = proc.nodes[nid]
            if not other.succs:
                return False
            if any(isinstance(i, Return) for i in other.instrs):
                return False
        return True

    def _uncontrolled_recursion_checks(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """CWE-674: a procedure whose recursive call has no reachable base case.

        Reported only when the self-call is unavoidable: no path from the entry
        reaches a return or a CFG exit without going through it. A guarded
        recursion (`if n <= 1: return 1`) leaves such a path and is not reported,
        and neither is recursion whose base case lives in a ternary or a
        short-circuit operand, which the CFG cannot represent.

        Nothing here claims the recursion is bounded when we stay silent. Proving
        that an argument decreases is a termination proof Frame does not attempt,
        so this detector answers the much narrower question of whether a base case
        exists at all.
        """
        checks: List[VulnerabilityCheck] = []

        # The whole argument rests on "no path leaves without recursing", which a
        # CFG missing its exception edges cannot support: `try: return f(n-1)
        # except: return 0` has its base case in a handler the frontends inline
        # without edges, and would otherwise look unconditional.
        if proc.has_exception_handler:
            return checks

        simple_name = proc.name.rsplit(".", 1)[-1]

        self_calls = [
            (node.id, idx, instr)
            for node in proc.nodes.values()
            for idx, instr in enumerate(node.instrs)
            if self._is_direct_self_call(instr, proc)
        ]
        if not self_calls:
            return checks

        if self._recursion_is_expression_guarded(proc, simple_name):
            return checks

        for node_id, idx, instr in self_calls:
            if not self._call_is_unavoidable(proc, node_id, idx):
                continue
            checks.append(VulnerabilityCheck(
                formula=True_(),
                vuln_type=VulnType.UNCONTROLLED_RECURSION,
                location=instr.loc,
                description=f"'{simple_name}' calls itself on every path: no base case "
                            f"is reachable, so the recursion cannot terminate",
                sink_type="uncontrolled_recursion",
                procedure_name=proc.name,
            ))
            # One finding per procedure: further self-calls are the same bug.
            break

        return checks

    # =========================================================================
    # Structural memory-safety and API-contract detectors
    #
    # CWE-787 / CWE-125 / CWE-789 / CWE-732. Like the non-termination pair
    # above, these read the finished CFG rather than a taint flow, and each one
    # fires only where the IR settles the question outright: a constant index
    # against a constant declared bound, a return value with no destination, a
    # literal size, a literal mode. Nothing here guesses at a value.
    # =========================================================================

    def _procedure_constant_ints(self, proc: Procedure) -> Dict[str, int]:
        """Locals bound to one integer literal for the whole procedure.

        `int i = 10; buf[i] = 0;` is the same weakness as `buf[10] = 0` and
        should read the same way. Only a name assigned exactly once, and only
        to an integer literal, is included: with two assignments the value at a
        use depends on the path, and deciding that is value reasoning this
        detector deliberately does not do.
        """
        counts: Dict[str, int] = {}
        values: Dict[str, int] = {}

        for node in proc.nodes.values():
            for instr in node.instrs:
                for name in instr.get_written_vars():
                    counts[name] = counts.get(name, 0) + 1
                if isinstance(instr, Assign):
                    name = self._get_var_name(instr.id)
                    if isinstance(instr.exp, ExpConst) and isinstance(instr.exp.value, int) \
                            and not isinstance(instr.exp.value, bool):
                        values[name] = instr.exp.value

        return {name: value for name, value in values.items() if counts.get(name) == 1}

    def _constant_index_value(self, exp, constants: Dict[str, int]) -> Optional[int]:
        """The integer this index expression must hold, or None if unknown."""
        if isinstance(exp, ExpConst) and isinstance(exp.value, int) and not isinstance(exp.value, bool):
            return exp.value
        if isinstance(exp, ExpVar):
            return constants.get(str(exp.var))
        return None

    def _out_of_bounds_access(self, base, index, proc: Procedure,
                              constants: Dict[str, int]) -> Optional[Tuple[str, int, int]]:
        """Is `base[index]` provably outside `base`'s declared extent?

        Returns (name, index, bound) when both the index and the bound are
        known constants and the index falls outside `0 .. bound - 1`. Anything
        unknown, either side, yields None: an index whose value the IR does not
        pin down is not evidence of anything.
        """
        if not isinstance(base, ExpVar):
            return None
        name = str(base.var)
        bound = proc.fixed_array_bounds.get(name)
        # -1 marks a name declared twice with disagreeing bounds.
        if bound is None or bound < 0:
            return None

        value = self._constant_index_value(index, constants)
        if value is None or 0 <= value < bound:
            return None
        return name, value, bound

    def _iter_read_index_exps(self, exp):
        """Every `base[index]` appearing anywhere inside a read expression."""
        stack = [exp]
        while stack:
            cur = stack.pop()
            if cur is None:
                continue
            if isinstance(cur, ExpIndex):
                yield cur
            for child in (getattr(cur, "__dict__", {}) or {}).values():
                if isinstance(child, Exp):
                    stack.append(child)
                elif isinstance(child, (list, tuple)):
                    stack.extend(c for c in child if isinstance(c, Exp))

    def _out_of_bounds_checks(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """CWE-787 and CWE-125: an access provably past a fixed-size local array.

        The direction comes from the instruction, not from a name or a comment.
        A subscripted assignment target reaches the IR as a `Store` whose address
        is `base + index`, so that is a write; a subscript anywhere a value is
        READ reaches it as an `ExpIndex`, so that is a read. Frame reports the
        specific CWE precisely because the IR distinguishes them, and leaves the
        generic CWE-120 to the paths where it does not.

        Both the bound and the index must be constants. That is narrow on
        purpose: an index the IR cannot pin down might be in range on every
        execution, and reporting it would mean asserting something about values
        this detector has no basis for.
        """
        checks: List[VulnerabilityCheck] = []
        if not proc.fixed_array_bounds:
            return checks

        constants = self._procedure_constant_ints(proc)

        def record(kind: VulnType, name: str, value: int, bound: int, loc, verb: str) -> None:
            checks.append(VulnerabilityCheck(
                formula=True_(),
                vuln_type=kind,
                location=loc or Location.unknown(),
                description=f"{verb} '{name}[{value}]' is outside the declared extent of "
                            f"'{name}', which holds {bound} element(s)",
                sink_type=kind.value,
                procedure_name=proc.name,
            ))

        for node in proc.nodes.values():
            for instr in node.instrs:
                if isinstance(instr, Store):
                    addr = instr.addr
                    # `arr[i] = v` is lowered to a store through `arr + i`.
                    if isinstance(addr, ExpBinOp) and addr.op == "+":
                        found = self._out_of_bounds_access(addr.left, addr.right, proc, constants)
                        if found:
                            record(VulnType.OOB_WRITE, *found, instr.loc, "Write to")
                            continue
                    if isinstance(addr, ExpIndex):
                        found = self._out_of_bounds_access(addr.base, addr.index, proc, constants)
                        if found:
                            record(VulnType.OOB_WRITE, *found, instr.loc, "Write to")
                            continue

                # Every other position a subscript can appear in is a read,
                # including the value half of a store.
                for exp in self._iter_instr_exps(instr):
                    if isinstance(instr, Store) and exp is instr.addr:
                        continue
                    for sub in self._iter_read_index_exps(exp):
                        found = self._out_of_bounds_access(sub.base, sub.index, proc, constants)
                        if found:
                            record(VulnType.OOB_READ, *found, instr.loc, "Read of")

        return checks

    def _unchecked_return_checks(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """CWE-252: the result of a call that can only fail silently is dropped.

        Two conditions, both structural:

        * the callee's spec sets `return_must_be_checked`, which the per-language
          spec tables set only for the privilege-management family, where a
          silent failure leaves the process holding privileges it believes it
          gave up, and
        * the call has NO destination at all. `Call.ret` is None exactly when the
          source wrote the call as a bare statement, so the value is discarded
          before anything could test it.

        Requiring the absence of a destination, rather than trying to decide
        whether an assigned result is later tested, is what keeps this quiet.
        `if (setuid(u) != 0)` never becomes a Call instruction in the first place
        (it is inlined into the branch condition), and `int r = setuid(u);`
        carries a destination, so neither is a candidate. That gives up the case
        where a result is stored and then genuinely never read, which is a real
        bug Frame will miss. Missing it costs a finding; guessing at it costs
        the detector its credibility.
        """
        checks: List[VulnerabilityCheck] = []

        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call) or instr.ret is not None:
                    continue
                spec = self.program.get_spec(instr.get_full_name())
                if spec is None or not spec.return_must_be_checked:
                    continue
                name = instr.get_func_name()
                checks.append(VulnerabilityCheck(
                    formula=True_(),
                    vuln_type=VulnType.UNCHECKED_RETURN,
                    location=instr.loc or Location.unknown(),
                    description=f"Return value of '{name}' is discarded: if the call fails "
                                f"the process keeps the privileges it appears to drop",
                    sink_type="unchecked_return",
                    procedure_name=proc.name,
                ))

        return checks

    # The smallest default thread stack among mainstream platforms (1 MiB on
    # Windows). A stack allocation of at least this much cannot be satisfied on
    # a fresh thread there, so it is a hard platform fact rather than a judgment
    # about whether some size is "too big".
    _STACK_ALLOCATION_LIMIT = 1024 * 1024

    def _excessive_allocation_checks(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """CWE-789: a constant stack allocation too large to fit on a stack.

        The sibling of CWE-770, and the distinction is where the size comes
        from: CWE-770 is an attacker-controlled size that nothing bounds, this
        is a size written into the program that is excessive on its face.

        Restricted to the STACK on purpose. Whether a large heap allocation is
        excessive is a policy question with no answer Frame can defend: a 512 MB
        buffer pool is deliberate in one program and a bug in another. The stack
        has a fixed platform limit instead, so the comparison is against a real
        constraint and needs no judgment call.
        """
        checks: List[VulnerabilityCheck] = []
        constants = self._procedure_constant_ints(proc)

        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call):
                    continue
                spec = self.program.get_spec(instr.get_full_name())
                if spec is None or spec.stack_allocation_size_arg is None:
                    continue
                index = spec.stack_allocation_size_arg
                if index >= len(instr.args):
                    continue

                size = self._constant_index_value(instr.args[index][0], constants)
                if size is None or size < self._STACK_ALLOCATION_LIMIT:
                    continue

                checks.append(VulnerabilityCheck(
                    formula=True_(),
                    vuln_type=VulnType.EXCESSIVE_ALLOCATION,
                    location=instr.loc or Location.unknown(),
                    description=f"'{instr.get_func_name()}' allocates {size} bytes on the "
                                f"stack, at or above the {self._STACK_ALLOCATION_LIMIT}-byte "
                                f"stack a thread is given by default",
                    sink_type="excessive_allocation",
                    procedure_name=proc.name,
                ))

        return checks

    # The POSIX world-write bit, S_IWOTH.
    _WORLD_WRITE_BIT = 0o002

    def _incorrect_permission_checks(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """CWE-732: a resource created or set world-writable by a literal mode.

        The mode argument is identified by the per-language spec tables, never
        by the shape of the number, and only an integer LITERAL (or a local
        bound once to one) is examined. A mode assembled from `S_IRUSR | ...`
        constants reaches the IR as an expression whose value Frame does not
        know, and it is left alone.

        `umask` inverts: its argument names the bits to CLEAR, so world-write is
        permitted exactly when the world-write bit is ABSENT from the mask. That
        is why the umask case is a spec flag rather than a second copy of this
        rule with the comparison flipped by hand.
        """
        checks: List[VulnerabilityCheck] = []
        constants = self._procedure_constant_ints(proc)

        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call):
                    continue
                spec = self.program.get_spec(instr.get_full_name())
                if spec is None or spec.permission_mode_arg is None:
                    continue
                index = spec.permission_mode_arg
                # `open(path, flags)` has no mode at all: the mode is variadic.
                if index >= len(instr.args):
                    continue

                mode = self._constant_index_value(instr.args[index][0], constants)
                if mode is None or mode < 0:
                    continue

                world_writable = (mode & self._WORLD_WRITE_BIT) == 0 \
                    if spec.permission_is_umask else (mode & self._WORLD_WRITE_BIT) != 0
                if not world_writable:
                    continue

                name = instr.get_func_name()
                if spec.permission_is_umask:
                    detail = (f"'{name}({oct(mode)})' does not mask off the world-write bit, "
                              f"so files this process creates are writable by any user")
                else:
                    detail = (f"'{name}' is given mode {oct(mode)}, which grants write "
                              f"permission to any user on the system")

                checks.append(VulnerabilityCheck(
                    formula=True_(),
                    vuln_type=VulnType.INCORRECT_PERMISSIONS,
                    location=instr.loc or Location.unknown(),
                    description=detail,
                    sink_type="incorrect_permissions",
                    procedure_name=proc.name,
                ))

        return checks

    def _create_usage_based_check(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str,
        sink_kind: SinkKind
    ) -> VulnerabilityCheck:
        """
        Create a vulnerability check for usage-based sinks.

        For vulnerabilities like weak random or weak hash, the mere usage
        of the function is the vulnerability - no taint flow required.
        """
        from frame.core.ast import True_

        # Get vulnerability type
        vuln_type = VulnType.from_sink_kind(sink_kind)

        # Get function name for description
        func_name = ""
        if isinstance(instr, Call):
            func_name = instr.get_full_name()

        # Simple formula - just indicates the usage
        formula = True_()

        return VulnerabilityCheck(
            formula=formula,
            vuln_type=vuln_type,
            location=instr.loc,
            description=f"Insecure function usage: {func_name} ({sink_kind.value})",
            tainted_var="",
            source_var="",
            source_location=None,
            sink_type=sink_kind.value,
            procedure_name=proc_name,
            data_flow_path=[],
        )

    def _create_usage_based_check_from_sink(
        self,
        instr: TaintSink,
        state: SymbolicState,
        proc_name: str
    ) -> VulnerabilityCheck:
        """
        Create a vulnerability check from a TaintSink for usage-based vulnerabilities.

        For vulnerabilities like weak_hash or weak_crypto, the mere usage
        of the function is the vulnerability - no taint flow required.
        """
        from frame.core.ast import True_

        # Get vulnerability type
        vuln_type = VulnType.from_sink_kind(instr.kind)

        # Simple formula - just indicates the usage
        formula = True_()

        return VulnerabilityCheck(
            formula=formula,
            vuln_type=vuln_type,
            location=instr.loc,
            description=instr.description,
            tainted_var="",
            source_var="",
            source_location=None,
            sink_type=instr.kind.value,
            procedure_name=proc_name,
            data_flow_path=[],
        )

    def _check_null_deref(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str,
        addr: str
    ) -> Optional[VulnerabilityCheck]:
        """Check for potential null dereference"""
        # NOTE: Disabled due to high false positive rate.
        # The check `not state.is_allocated(addr)` is too broad - most pointers
        # aren't tracked as allocated, leading to FPs on every pointer deref.
        # Proper null dereference detection requires data flow analysis to track
        # which pointers could actually be NULL (e.g., from malloc failures,
        # explicit NULL assignments, or NULL returns from functions).
        # The SL memory analyzers provide more precise null checking.
        return None

    def _create_uaf_check(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str,
        addr: str
    ) -> VulnerabilityCheck:
        """Create use-after-free check"""
        formula = UseAfterFree(Var(addr))

        return VulnerabilityCheck(
            formula=formula,
            vuln_type=VulnType.USE_AFTER_FREE,
            location=instr.loc,
            description=f"Use-after-free of '{addr}'",
            tainted_var=addr,
            procedure_name=proc_name,
        )

    def _create_double_free_check(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str,
        addr: str
    ) -> VulnerabilityCheck:
        """Create double-free check"""
        # In separation logic: trying to free emp (already freed)
        formula = And(
            Eq(Var(f"{addr}_freed"), Const(True)),
            PredicateCall("double_free", [Var(addr)])
        )

        return VulnerabilityCheck(
            formula=formula,
            vuln_type=VulnType.DOUBLE_FREE,
            location=instr.loc,
            description=f"Double-free of '{addr}'",
            tainted_var=addr,
            procedure_name=proc_name,
        )

    def _create_invalid_free_check(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str,
        addr: str
    ) -> VulnerabilityCheck:
        """Create free-of-non-heap-memory check (CWE-590)."""
        from frame.core.ast import True_
        return VulnerabilityCheck(
            formula=True_(),
            vuln_type=VulnType.INVALID_FREE,
            location=instr.loc,
            description=f"Free of non-heap memory: '{addr}' is stack storage, "
                        f"not a heap allocation",
            tainted_var=addr,
            procedure_name=proc_name,
        )

    def _create_null_deref_check(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str,
        addr: str
    ) -> VulnerabilityCheck:
        """Create null-pointer-dereference check (CWE-476)."""
        from frame.core.ast import True_
        return VulnerabilityCheck(
            formula=True_(),
            vuln_type=VulnType.NULL_DEREFERENCE,
            location=instr.loc,
            description=f"Null-pointer dereference of '{addr}', which is NULL on "
                        f"this path",
            tainted_var=addr,
            procedure_name=proc_name,
        )

    # =========================================================================
    # Heap-lifecycle helpers (CWE-416 / CWE-476 / CWE-590)
    # =========================================================================

    def _sole_var(self, exp: Exp) -> Optional[str]:
        """The single variable an expression names, seeing through casts. Returns
        None for anything that is not a bare (possibly cast) variable."""
        if isinstance(exp, ExpCast):
            return self._sole_var(exp.exp)
        if isinstance(exp, ExpVar):
            return str(exp.var)
        return None

    def _is_null_literal(self, exp: Exp) -> bool:
        """Is the expression a NULL / 0 pointer literal (through any cast)?"""
        if isinstance(exp, ExpCast):
            return self._is_null_literal(exp.exp)
        if isinstance(exp, ExpConst):
            if exp.value is None:
                return True
            return isinstance(exp.value, int) and not isinstance(exp.value, bool) \
                and exp.value == 0
        return False

    def _is_nonheap_origin(self, var: str, state: SymbolicState) -> bool:
        """Is `var`'s storage provably NOT on the heap (a stack array, or the
        address of a local)? Unknown origins return False -- only a definite
        stack origin makes freeing it a CWE-590."""
        if state.heap_origin.get(var) == "stack":
            return True
        fixed_arrays = getattr(self._cur_proc, "fixed_array_bounds", {}) or {}
        return var in fixed_arrays

    def _track_assign_lifecycle(self, instr: Assign, target: str,
                                state: SymbolicState) -> None:
        """Update null-ness and storage origin across `target = exp`.

        A reassignment first drops the target's prior lifecycle facts (its old
        value is gone), then the right-hand side re-establishes them: a null
        literal makes it null, the address of a local makes it stack storage, and
        a bare variable propagates the source's facts (this is what carries a
        lowered `p = malloc(...)`, which the frontend splits into a temp call and
        `p = $tmp`, onto `p`)."""
        if not self._is_c_lang:
            return
        exp = instr.exp
        fixed_arrays = getattr(self._cur_proc, "fixed_array_bounds", {}) or {}

        state.null_ptrs.pop(target, None)
        state.heap_origin.pop(target, None)
        state.freed.discard(target)

        if target in fixed_arrays:
            # A fixed local array is stack storage no matter what placeholder
            # value the frontend binds at its declaration.
            state.heap_origin[target] = "stack"
            return
        if isinstance(exp, ExpUnOp) and exp.op == "&":
            state.heap_origin[target] = "stack"
            return
        if self._is_null_literal(exp):
            # An explicit `p = NULL` on its own does not fire CWE-476: the value
            # is almost always overwritten on the live path before any use (the
            # ubiquitous `T *p; p = NULL; if(cond) p = real; use(p)` idiom), and
            # firing on the initializer alone produces false positives on correct
            # code. Null-ness that actually reaches a dereference is established by
            # a branch that CONFIRMS `p == NULL` (see `_edge_null_vars`), which is
            # the genuine "dereference after null check" shape of this weakness.
            return
        src = self._sole_var(exp)
        if src is not None:
            if src in state.null_ptrs:
                state.null_ptrs[target] = state.null_ptrs[src]
            if src in state.heap_origin:
                state.heap_origin[target] = state.heap_origin[src]
            if src in state.freed:
                state.freed.add(target)

    def _edge_nonnull_vars(self, edge_exp: Exp, assume_true: bool) -> Set[str]:
        """Variables a branch edge proves are NOT null.

        `edge_exp` is the branch condition; `assume_true` says which side of the
        branch this edge takes. `if(p==NULL)` proves p non-null on its false
        side; `if(p!=NULL)` and `if(p)` prove it on their true side; `if(!p)`
        proves it on its false side."""
        if edge_exp is None:
            return set()
        # `!e` flips the side.
        if isinstance(edge_exp, ExpUnOp) and edge_exp.op == "!":
            return self._edge_nonnull_vars(edge_exp.operand, not assume_true)
        if isinstance(edge_exp, ExpBinOp) and edge_exp.op in ("==", "!="):
            for a, b in ((edge_exp.left, edge_exp.right),
                         (edge_exp.right, edge_exp.left)):
                if self._is_null_literal(b):
                    var = self._sole_var(a)
                    if var is not None:
                        # p == NULL proves non-null on the FALSE side; p != NULL
                        # on the TRUE side.
                        proves = (edge_exp.op == "!=") == assume_true
                        return {var} if proves else set()
            return set()
        # A bare pointer used as a truthiness test: `if(p)` proves non-null on
        # its true side.
        var = self._sole_var(edge_exp)
        if var is not None and assume_true:
            return {var}
        return set()

    # Standard C/C++ library functions that never return to the caller. A call
    # to one ends the current path, so nothing after it on that branch runs.
    _NORETURN_FUNCS = frozenset({
        "exit", "_exit", "_Exit", "quick_exit", "abort", "_abort",
        "longjmp", "siglongjmp", "__assert_fail", "err", "errx",
    })

    def _is_noreturn_call(self, instr: Instr) -> bool:
        """Is `instr` a call to a function that never returns (exit/abort/...)?"""
        if not isinstance(instr, Call):
            return False
        name = instr.get_func_name() if hasattr(instr, "get_func_name") else None
        if name is None:
            func = getattr(instr, "func", None)
            if isinstance(func, ExpConst) and isinstance(func.value, str):
                name = func.value
        if not name:
            return False
        return self._strip_self_receiver(name) in self._NORETURN_FUNCS

    def _edge_null_vars(self, edge_exp: Exp, assume_true: bool) -> Set[str]:
        """Variables a branch edge proves ARE null. `if(p==NULL)` proves it on
        its true side, `if(p!=NULL)` on its false side, `if(!p)` on its true
        side, `if(p)` on its false side. This is the mirror of
        `_edge_nonnull_vars`."""
        if edge_exp is None:
            return set()
        if isinstance(edge_exp, ExpUnOp) and edge_exp.op == "!":
            return self._edge_null_vars(edge_exp.operand, not assume_true)
        if isinstance(edge_exp, ExpBinOp) and edge_exp.op in ("==", "!="):
            for a, b in ((edge_exp.left, edge_exp.right),
                         (edge_exp.right, edge_exp.left)):
                if self._is_null_literal(b):
                    var = self._sole_var(a)
                    if var is not None:
                        proves = (edge_exp.op == "==") == assume_true
                        return {var} if proves else set()
            return set()
        var = self._sole_var(edge_exp)
        if var is not None and not assume_true:
            return {var}
        return set()

    def _deref_base(self, exp: Exp) -> Optional[str]:
        """The base pointer variable a dereference address reads through.

        `*(p + i)`, `p[i]`, `*p`, `(T*)p`, and `p->f` all dereference `p`, so the
        base is `p` in every case. Address-of (`&x`) is not a dereference and has
        no base."""
        if isinstance(exp, ExpVar):
            return str(exp.var)
        if isinstance(exp, ExpCast):
            return self._deref_base(exp.exp)
        if isinstance(exp, ExpUnOp):
            if exp.op == "&":
                return None
            return self._deref_base(exp.operand)
        if isinstance(exp, ExpBinOp):
            return self._deref_base(exp.left) or self._deref_base(exp.right)
        if isinstance(exp, ExpIndex):
            return self._deref_base(exp.base)
        if isinstance(exp, ExpFieldAccess):
            return self._deref_base(exp.base)
        return None

    def _walk_exp(self, exp: Exp):
        """Yield `exp` and every sub-expression, depth first."""
        if not isinstance(exp, Exp):
            return
        yield exp
        for child in vars(exp).values():
            if isinstance(child, Exp):
                yield from self._walk_exp(child)
            elif isinstance(child, (list, tuple)):
                for item in child:
                    if isinstance(item, Exp):
                        yield from self._walk_exp(item)
                    elif isinstance(item, tuple):
                        for sub in item:
                            if isinstance(sub, Exp):
                                yield from self._walk_exp(sub)

    def _iter_deref_bases(self, instr: Instr) -> Dict[str, object]:
        """Base pointer variables dereferenced by this instruction, mapped to the
        instruction location. Covers Store/Load addresses plus `*p`, `p[i]`, and
        `p->f` appearing anywhere in the instruction's expressions (a call
        argument, an assignment value, a return expression)."""
        bases: Dict[str, object] = {}

        def add(e):
            b = self._deref_base(e)
            if b:
                bases.setdefault(b, instr.loc)

        if isinstance(instr, Store):
            add(instr.addr)
        if isinstance(instr, Load):
            add(instr.exp)
        for exp in self._iter_instr_exps(instr):
            for sub in self._walk_exp(exp):
                if isinstance(sub, ExpUnOp) and sub.op == "*":
                    add(sub.operand)
                elif isinstance(sub, ExpIndex):
                    add(sub.base)
                elif isinstance(sub, ExpFieldAccess) and sub.is_arrow:
                    add(sub.base)
        return bases

    def _lifecycle_deref_checks(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str
    ) -> List[VulnerabilityCheck]:
        """CWE-416 (use of a freed pointer) and CWE-476 (dereference of a pointer
        that is NULL on this path), raised for every dereference the instruction
        performs. C/C++ only: other frontends have no free and no raw deref."""
        checks: List[VulnerabilityCheck] = []
        if not self._is_c_lang:
            return checks
        for base in self._iter_deref_bases(instr):
            if base in state.freed:
                checks.append(self._create_uaf_check(instr, state, proc_name, base))
            elif base in state.null_ptrs:
                checks.append(
                    self._create_null_deref_check(instr, state, proc_name, base))
        return checks

    # =========================================================================
    # Ownership and lifetime (CWE-401 leak, CWE-762 mismatch, CWE-562 stack addr)
    #
    # These reason over the same separation-logic heap facts Phase 1 threads
    # through the CFG. A heap allocation is an owned resource; the frame/ownership
    # question is whether that ownership is discharged (freed), transferred
    # (returned, stored out, passed on), or dropped on the floor (a leak). All
    # C/C++ only, and conservative: when ownership cannot be shown to be dropped,
    # nothing is reported.
    # =========================================================================

    # Allocator families and the one deallocator that correctly releases each.
    _C_HEAP_ALLOCATORS = frozenset({
        "malloc", "calloc", "realloc", "reallocarray", "strdup", "strndup",
        "aligned_alloc", "memalign", "posix_memalign", "valloc", "pvalloc",
    })
    _EXPECTED_FREE = {"c_heap": "free", "new": "delete", "new_array": "delete[]"}
    _ALLOC_KIND_LABEL = {"c_heap": "malloc/calloc/realloc", "new": "new",
                         "new_array": "new[]"}

    def _cast_strip(self, exp: Exp) -> Exp:
        """See through cast expressions to the value underneath."""
        while isinstance(exp, ExpCast):
            exp = exp.exp
        return exp

    def _alloc_kind_of_call(self, func_name) -> Optional[str]:
        """The allocator family a call name names, or None if it is not a heap
        allocator whose kind constrains how it must be released."""
        name = self._strip_self_receiver(str(func_name or ""))
        if name in ("new", "operator new"):
            return "new"
        if name in ("new[]", "operator new[]"):
            return "new_array"
        if name in self._C_HEAP_ALLOCATORS:
            return "c_heap"
        return None

    def _free_routine_of_call(self, func_name) -> Optional[str]:
        """The canonical deallocator routine a call name is, or None."""
        name = self._strip_self_receiver(str(func_name or ""))
        if name in ("free", "cfree"):
            return "free"
        if name in ("delete", "operator delete"):
            return "delete"
        if name in ("delete[]", "operator delete[]"):
            return "delete[]"
        return None

    def _alloc_expr_kind(self, exp: Exp) -> Optional[str]:
        """If `exp` (through casts) is an allocator call or a `new` expression,
        its allocator family, else None. This is what catches an allocation the
        frontend leaves embedded in an assignment -- `(T*)malloc(n)` and `new T`
        -- rather than as a standalone Call instruction."""
        exp = self._cast_strip(exp)
        if isinstance(exp, ExpCall):
            callee = exp.func
            if isinstance(callee, ExpConst):
                name = callee.value
            elif isinstance(callee, ExpVar):
                name = str(callee.var)
            else:
                name = str(callee)
            return self._alloc_kind_of_call(name)
        return None

    def _is_temp_name(self, name) -> bool:
        """A frontend-introduced single-use temporary (`$p`, `$p_1`)."""
        return isinstance(name, str) and name.startswith("$")

    def _is_declared_local(self, name) -> bool:
        """Is `name` declared local to the current procedure (a declared local or
        a parameter)? The address of one of these is a stack address."""
        proc = self._cur_proc
        if proc is None:
            return False
        if name in (proc.locals or {}):
            return True
        try:
            return name in set(proc.param_names())
        except Exception:
            return False

    def _is_local_owner(self, name) -> bool:
        """May `name` own an allocation without that ownership being visible to
        the caller? Declared locals, parameters, and temps qualify; a struct
        field, a subscript, or a global does not (assigning through one hands the
        allocation to something that outlives the function)."""
        return self._is_temp_name(name) or self._is_declared_local(name)

    def _escaping_expr_vars(self, exp: Exp) -> Set[str]:
        """The pointer variable an expression hands off wholesale, if any. A bare
        variable `p` (through casts) or its address `&p` passes the pointer
        itself; `p[i]`, `*p`, `p->f` pass a value read THROUGH p and do not."""
        inner = self._cast_strip(exp)
        v = self._sole_var(inner)
        if v is not None:
            return {v}
        if isinstance(inner, ExpUnOp) and inner.op == "&":
            b = self._sole_var(self._cast_strip(inner.operand))
            if b is not None:
                return {b}
        return set()

    def _escaping_arg_vars(self, instr: Instr) -> Set[str]:
        """Pointer variables an instruction hands to a callee wholesale."""
        result: Set[str] = set()
        for arg in (getattr(instr, "args", None) or []):
            exp = arg[0] if isinstance(arg, tuple) else arg
            result |= self._escaping_expr_vars(exp)
        return result

    def _leak_check(self, alloc_id, proc_name: str) -> VulnerabilityCheck:
        return VulnerabilityCheck(
            formula=True_(),
            vuln_type=VulnType.MEMORY_LEAK,
            location=self._leak_sites.get(alloc_id),
            description="Memory leak: a heap allocation is never released, "
                        "returned, or otherwise handed off before its owning "
                        "pointer goes out of scope",
            procedure_name=proc_name,
        )

    def _release_alloc(self, state: SymbolicState, alloc_id) -> None:
        """Drop every owner of `alloc_id`: it was freed or escaped and can no
        longer leak."""
        for v in [v for v, a in state.owned_allocs.items() if a == alloc_id]:
            state.owned_allocs.pop(v, None)
            state.alloc_kind.pop(v, None)

    def _escape_vars(self, state: SymbolicState, names) -> None:
        """Mark allocations owned by any of `names` as escaped (safe from leak
        reporting), releasing every alias that shares them."""
        for name in names:
            aid = state.owned_allocs.get(name)
            if aid is not None:
                self._release_alloc(state, aid)

    def _reassign_owner(self, state: SymbolicState, var: str, new_id,
                        proc_name: str) -> List[VulnerabilityCheck]:
        """Rebind `var` to own `new_id` (or nothing, if None). If this drops the
        last owner of an allocation `var` currently holds, that allocation is
        lost -- the reassignment leak (`p = malloc(); p = malloc();` loses the
        first)."""
        checks: List[VulnerabilityCheck] = []
        old = state.owned_allocs.get(var)
        if old is not None and old != new_id:
            others = any(v != var and a == old for v, a in state.owned_allocs.items())
            if not others:
                checks.append(self._leak_check(old, proc_name))
        if new_id is None:
            state.owned_allocs.pop(var, None)
            state.alloc_kind.pop(var, None)
        else:
            state.owned_allocs[var] = new_id
        return checks

    def _track_ownership_assign(self, instr: Assign, target: str,
                                state: SymbolicState,
                                proc_name: str) -> List[VulnerabilityCheck]:
        """Thread heap ownership across `target = exp` for CWE-401 (C/C++ only)."""
        if not self._is_c_lang:
            return []
        exp = instr.exp
        kind = self._alloc_expr_kind(exp)
        if kind is not None:
            # An allocator that CONSUMES a pointer argument (`realloc(p, n)`)
            # releases it, and any pointer handed to the allocator call escapes
            # regardless, so the allocation those arguments held is not leaked
            # when `target` is rebound below.
            call = self._cast_strip(exp)
            if isinstance(call, ExpCall):
                consumed: Set[str] = set()
                for a in call.args:
                    consumed |= self._escaping_expr_vars(a)
                self._escape_vars(state, consumed)
            # A fresh allocation lands in `target` (cast malloc, or `new`).
            alloc_id = id(instr)
            self._leak_sites.setdefault(alloc_id, instr.loc)
            checks = self._reassign_owner(state, target, alloc_id, proc_name)
            state.alloc_kind[target] = kind
            state.heap_origin[target] = "heap"
            return checks
        src = self._sole_var(self._cast_strip(exp))
        if src is not None and src in state.owned_allocs:
            if not self._is_local_owner(target):
                # `target` is caller-visible (a field, a global): the allocation
                # escapes rather than staying under this function's control.
                self._escape_vars(state, [src])
                return self._reassign_owner(state, target, None, proc_name)
            aid = state.owned_allocs[src]
            checks = self._reassign_owner(state, target, aid, proc_name)
            if src in state.alloc_kind:
                state.alloc_kind[target] = state.alloc_kind[src]
            if self._is_temp_name(src):
                # A single-use temp MOVES its allocation onto `target`; a named
                # variable SHARES it, so both stay owners and freeing either
                # releases the allocation.
                state.owned_allocs.pop(src, None)
                state.alloc_kind.pop(src, None)
            return checks
        # `target` receives something that is not an owned pointer: it loses any
        # allocation it was holding.
        return self._reassign_owner(state, target, None, proc_name)

    def _finalize_leaks(self, state: SymbolicState,
                        proc_name: str) -> List[VulnerabilityCheck]:
        """Every allocation still owned as a path ends leaks: its owning pointer
        goes out of scope without the allocation having been freed or handed
        off. A provably-null owner is skipped (an allocation that failed and was
        bailed on has nothing to leak)."""
        checks: List[VulnerabilityCheck] = []
        seen = set()
        for var, aid in list(state.owned_allocs.items()):
            if aid in seen or var in state.null_ptrs:
                continue
            seen.add(aid)
            checks.append(self._leak_check(aid, proc_name))
        state.owned_allocs.clear()
        state.alloc_kind.clear()
        return checks

    def _returns_stack_address(self, val: Exp, state: SymbolicState) -> bool:
        """Does a return value hand back the address of a local? Either `&x` for a
        declared local `x` (or `&x[i]`, `&s.f` on one), or a pointer variable
        whose tracked storage origin is the stack -- a fixed local array that
        decayed, or a pointer earlier set to the address of a local."""
        inner = self._cast_strip(val)
        if isinstance(inner, ExpUnOp) and inner.op == "&":
            base = self._sole_var(self._cast_strip(inner.operand))
            if base is None:
                base = self._deref_base(inner.operand)
            return base is not None and self._is_declared_local(base)
        v = self._sole_var(inner)
        return v is not None and state.heap_origin.get(v) == "stack"

    def _create_mismatched_free_check(self, instr: Instr, state: SymbolicState,
                                      proc_name: str, var: str, kind: str,
                                      routine: str) -> VulnerabilityCheck:
        return VulnerabilityCheck(
            formula=True_(),
            vuln_type=VulnType.MISMATCHED_FREE,
            location=instr.loc,
            description=f"Mismatched memory routine: '{var}' was allocated with "
                        f"{self._ALLOC_KIND_LABEL[kind]} but released with "
                        f"{routine} (expected {self._EXPECTED_FREE[kind]})",
            tainted_var=var,
            procedure_name=proc_name,
        )

    def _create_return_stack_check(self, instr: Instr, state: SymbolicState,
                                   proc_name: str) -> VulnerabilityCheck:
        return VulnerabilityCheck(
            formula=True_(),
            vuln_type=VulnType.RETURN_STACK_ADDRESS,
            location=instr.loc,
            description="Return of stack address: the returned value is the "
                        "address of a local, which dangles once the function "
                        "returns",
            procedure_name=proc_name,
        )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _get_var_name(self, var) -> str:
        """Get variable name as string"""
        if isinstance(var, PVar):
            return var.name
        if isinstance(var, Ident):
            return str(var)
        return str(var)

    def _exp_to_str(self, exp: Exp) -> str:
        """Convert expression to string (variable name)"""
        if isinstance(exp, ExpVar):
            return self._get_var_name(exp.var)
        if isinstance(exp, ExpConst):
            return str(exp.value)
        if isinstance(exp, ExpFieldAccess):
            return f"{self._exp_to_str(exp.base)}.{exp.field_name}"
        if isinstance(exp, ExpIndex):
            return f"{self._exp_to_str(exp.base)}[{self._exp_to_str(exp.index)}]"
        return str(exp)

    def _get_exp_vars(self, exp: Exp) -> List[str]:
        """Get all variable names referenced in expression"""
        if isinstance(exp, ExpVar):
            var_name = self._get_var_name(exp.var)
            # Check if this is an array literal like "{bar, "b"}"
            if var_name.startswith('{') and var_name.endswith('}'):
                # Parse array literal to extract variable names
                import re
                inner = var_name[1:-1]  # Remove { }
                result = []
                # Split on commas, but be careful with strings
                parts = re.split(r',\s*', inner)
                for part in parts:
                    part = part.strip()
                    # Skip string literals
                    if part.startswith('"') or part.startswith("'"):
                        continue
                    # Skip null, numbers, etc.
                    if part in ('null', 'true', 'false') or part.replace('.', '').replace('-', '').isdigit():
                        continue
                    # This is a variable name
                    result.append(part)
                return result
            return [var_name]
        if isinstance(exp, ExpConst):
            return []
        if isinstance(exp, ExpBinOp):
            return self._get_exp_vars(exp.left) + self._get_exp_vars(exp.right)
        if isinstance(exp, ExpUnOp):
            return self._get_exp_vars(exp.operand)
        if isinstance(exp, ExpFieldAccess):
            return self._get_exp_vars(exp.base)
        if isinstance(exp, ExpIndex):
            return self._get_exp_vars(exp.base) + self._get_exp_vars(exp.index)
        if isinstance(exp, ExpStringConcat):
            result = []
            for part in exp.parts:
                result.extend(self._get_exp_vars(part))
            return result
        if isinstance(exp, ExpCall):
            result = []
            # Extract variables from function/method receiver
            # For method calls like param.split(), extract the receiver variable
            if hasattr(exp, 'func'):
                func_str = str(exp.func)
                if '.' in func_str:
                    # Method call: extract receiver (e.g., "param.split" -> "param")
                    parts = func_str.strip('"').split('.')
                    if len(parts) >= 2 and parts[0] and not parts[0][0].isupper():
                        # Lowercase first char suggests a variable, not a module
                        result.append(parts[0])
            for arg in exp.args:
                result.extend(self._get_exp_vars(arg))
            return result
        return []

    def _get_sanitizer_calls(self, exp: Exp) -> List[Tuple[str, List[str]]]:
        """
        Extract all function calls from an expression that might be sanitizers.

        Returns list of (func_name, arg_vars) tuples for each call found.
        """
        result = []

        if isinstance(exp, ExpCall):
            # Get function name
            if isinstance(exp.func, ExpConst):
                func_name = str(exp.func.value)
            elif isinstance(exp.func, ExpVar):
                func_name = self._get_var_name(exp.func.var)
            else:
                func_name = str(exp.func)

            # Get argument variables
            arg_vars = []
            for arg in exp.args:
                arg_vars.extend(self._get_exp_vars(arg))

            result.append((func_name, arg_vars))

            # Recurse into arguments
            for arg in exp.args:
                result.extend(self._get_sanitizer_calls(arg))

        elif isinstance(exp, ExpBinOp):
            result.extend(self._get_sanitizer_calls(exp.left))
            result.extend(self._get_sanitizer_calls(exp.right))

        elif isinstance(exp, ExpUnOp):
            result.extend(self._get_sanitizer_calls(exp.operand))

        elif isinstance(exp, ExpStringConcat):
            for part in exp.parts:
                result.extend(self._get_sanitizer_calls(part))

        elif isinstance(exp, ExpIndex):
            result.extend(self._get_sanitizer_calls(exp.base))
            result.extend(self._get_sanitizer_calls(exp.index))

        elif isinstance(exp, ExpFieldAccess):
            result.extend(self._get_sanitizer_calls(exp.base))

        return result

    def _get_embedded_source_calls(self, exp: Exp) -> List[Tuple[str, str]]:
        """
        Extract all function calls from an expression that are taint sources.

        Returns list of (func_name, source_kind) tuples for each source call found.
        """
        result = []

        if isinstance(exp, ExpCall):
            # Get function name from various formats
            if isinstance(exp.func, ExpConst):
                func_name = str(exp.func.value).strip('"')
            elif isinstance(exp.func, ExpVar):
                func_name = self._get_var_name(exp.func.var)
            elif isinstance(exp.func, ExpFieldAccess):
                # Build qualified name from field access chain
                parts = []
                current = exp.func
                while isinstance(current, ExpFieldAccess):
                    parts.insert(0, current.field_name)
                    current = current.base
                if isinstance(current, ExpVar):
                    parts.insert(0, self._get_var_name(current.var))
                func_name = '.'.join(parts)
            else:
                func_name = str(exp.func)

            # Check if this function is a taint source
            spec = self.program.get_spec(func_name)
            if spec and spec.is_taint_source():
                result.append((func_name, spec.is_source))

            # Recurse into arguments to find nested source calls
            for arg in exp.args:
                result.extend(self._get_embedded_source_calls(arg))

        elif isinstance(exp, ExpBinOp):
            result.extend(self._get_embedded_source_calls(exp.left))
            result.extend(self._get_embedded_source_calls(exp.right))

        elif isinstance(exp, ExpUnOp):
            result.extend(self._get_embedded_source_calls(exp.operand))

        elif isinstance(exp, ExpStringConcat):
            for part in exp.parts:
                result.extend(self._get_embedded_source_calls(part))

        elif isinstance(exp, ExpIndex):
            result.extend(self._get_embedded_source_calls(exp.base))
            result.extend(self._get_embedded_source_calls(exp.index))

        elif isinstance(exp, ExpFieldAccess):
            result.extend(self._get_embedded_source_calls(exp.base))

        return result

    def _get_embedded_member_sources(self, exp: Exp) -> List[Tuple[str, str]]:
        """Find member-access chains in an expression that match a taint source
        spec (e.g. `req.query.id` matching the `req.query` source), so inline
        sources used directly in a sink -- `db.query("..." + req.query.id)` --
        are detected without an intermediate assignment. Returns (chain, kind).
        """
        result = []
        if isinstance(exp, ExpFieldAccess):
            parts = []
            cur = exp
            while isinstance(cur, ExpFieldAccess):
                parts.insert(0, cur.field_name)
                cur = cur.base
            if isinstance(cur, ExpVar):
                parts.insert(0, self._get_var_name(cur.var))
            # Longest matching prefix wins (req.query before req).
            for i in range(len(parts), 0, -1):
                spec = self.program.get_spec('.'.join(parts[:i]))
                if spec and spec.is_taint_source():
                    result.append(('.'.join(parts[:i]), spec.is_source))
                    break
            result.extend(self._get_embedded_member_sources(exp.base))
        elif isinstance(exp, ExpBinOp):
            result.extend(self._get_embedded_member_sources(exp.left))
            result.extend(self._get_embedded_member_sources(exp.right))
        elif isinstance(exp, ExpUnOp):
            result.extend(self._get_embedded_member_sources(exp.operand))
        elif isinstance(exp, ExpStringConcat):
            for part in exp.parts:
                result.extend(self._get_embedded_member_sources(part))
        elif isinstance(exp, ExpCall):
            for arg in exp.args:
                result.extend(self._get_embedded_member_sources(arg))
        elif isinstance(exp, ExpIndex):
            result.extend(self._get_embedded_member_sources(exp.base))
            result.extend(self._get_embedded_member_sources(exp.index))
        return result

    def _get_embedded_sink_calls(self, exp: Exp, state: 'SymbolicState') -> List[Tuple[str, str, List[str]]]:
        """
        Extract all function calls from an expression that are taint sinks.

        Returns list of (func_name, sink_kind, tainted_args) tuples for each sink call found.
        """
        result = []

        if isinstance(exp, ExpCall):
            # Get function name from various formats
            if isinstance(exp.func, ExpConst):
                func_name = str(exp.func.value).strip('"')
            elif isinstance(exp.func, ExpVar):
                func_name = self._get_var_name(exp.func.var)
            elif isinstance(exp.func, ExpFieldAccess):
                parts = []
                current = exp.func
                while isinstance(current, ExpFieldAccess):
                    parts.insert(0, current.field_name)
                    current = current.base
                if isinstance(current, ExpVar):
                    parts.insert(0, self._get_var_name(current.var))
                func_name = '.'.join(parts)
            else:
                func_name = str(exp.func)

            # Check if this function is a taint sink
            spec = self.program.get_spec(func_name)
            if spec and spec.is_taint_sink():
                # Get tainted arguments
                tainted_args = []
                for i, arg in enumerate(exp.args):
                    if i in spec.sink_args:
                        arg_vars = self._get_exp_vars(arg)
                        for arg_var in arg_vars:
                            if state.is_tainted(arg_var):
                                if not state.is_sanitized_for(arg_var, spec.is_sink):
                                    if not state.is_asserted_safe_for(arg_var, spec.is_sink):
                                        # Check if validated for eval sinks
                                        if spec.is_sink == 'eval' and arg_var in state.validated_for_eval:
                                            continue  # Skip - variable passed validation
                                        tainted_args.append(arg_var)
                if tainted_args:
                    result.append((func_name, spec.is_sink, tainted_args))

            # Recurse into arguments
            for arg in exp.args:
                result.extend(self._get_embedded_sink_calls(arg, state))

        elif isinstance(exp, ExpBinOp):
            result.extend(self._get_embedded_sink_calls(exp.left, state))
            result.extend(self._get_embedded_sink_calls(exp.right, state))

        elif isinstance(exp, ExpUnOp):
            result.extend(self._get_embedded_sink_calls(exp.operand, state))

        elif isinstance(exp, ExpStringConcat):
            for part in exp.parts:
                result.extend(self._get_embedded_sink_calls(part, state))

        elif isinstance(exp, ExpIndex):
            result.extend(self._get_embedded_sink_calls(exp.base, state))
            result.extend(self._get_embedded_sink_calls(exp.index, state))

        elif isinstance(exp, ExpFieldAccess):
            result.extend(self._get_embedded_sink_calls(exp.base, state))

        return result

    def _exp_to_formula(self, exp: Exp) -> Formula:
        """Convert SIL expression to Frame formula"""
        if isinstance(exp, ExpVar):
            return Var(self._get_var_name(exp.var))
        if isinstance(exp, ExpConst):
            return Const(exp.value)
        if isinstance(exp, ExpBinOp):
            left = self._exp_to_formula(exp.left)
            right = self._exp_to_formula(exp.right)
            if exp.op == "==":
                return Eq(left, right)
            elif exp.op == "!=":
                return Neq(left, right)
            elif exp.op == "<":
                return Lt(left, right)
            elif exp.op == "<=":
                return Le(left, right)
            elif exp.op == ">":
                return Gt(left, right)
            elif exp.op == ">=":
                return Ge(left, right)
            elif exp.op == "&&":
                return And(left, right)
            elif exp.op == "||":
                return Or(left, right)
        if isinstance(exp, ExpUnOp):
            if exp.op == "!":
                return Not(self._exp_to_formula(exp.operand))
        # Default: treat as variable
        return Var(str(exp))

    def _build_conjunction(self, parts: List[Formula]) -> Formula:
        """Build conjunction (And) from list of formulas"""
        if not parts:
            return Emp()
        result = parts[0]
        for part in parts[1:]:
            result = And(result, part)
        return result

    def _build_sepconj(self, parts: List[Formula]) -> Formula:
        """Build separating conjunction from list of formulas"""
        if not parts:
            return Emp()
        result = parts[0]
        for part in parts[1:]:
            result = SepConj(result, part)
        return result

    def _merge_states(self, s1: SymbolicState, s2: SymbolicState) -> SymbolicState:
        """Merge two states at CFG join point"""
        merged = SymbolicState()

        # Heap: keep values that are same in both
        for var in set(s1.heap.keys()) | set(s2.heap.keys()):
            if var in s1.heap and var in s2.heap:
                if s1.heap[var] == s2.heap[var]:
                    merged.heap[var] = s1.heap[var]
                else:
                    merged.heap[var] = f"phi_{var}"
            elif var in s1.heap:
                merged.heap[var] = s1.heap[var]
            else:
                merged.heap[var] = s2.heap[var]

        # Allocated: union
        merged.allocated = {**s1.allocated, **s2.allocated}

        # Taint: union (conservative - tainted in either path)
        merged.tainted = {**s1.tainted, **s2.tainted}

        # Sanitized: intersection (only sanitized if sanitized in both)
        for var in set(s1.sanitized.keys()) & set(s2.sanitized.keys()):
            common = list(set(s1.sanitized[var]) & set(s2.sanitized[var]))
            if common:
                merged.sanitized[var] = common

        # Freed: union (freed in either path)
        merged.freed = s1.freed | s2.freed

        # Null pointers: intersection. A var is DEFINITELY null after the join
        # only if it was null on both incoming paths; if either path gave it a
        # real value the join is not a provable null, so we must not fire.
        for v in set(s1.null_ptrs) & set(s2.null_ptrs):
            merged.null_ptrs[v] = s1.null_ptrs[v]

        # Heap origin: keep only origins the two paths agree on. A var reaching a
        # free with different origins on different paths has no single provable
        # origin, so CWE-590 stays silent (precision over recall).
        for v in set(s1.heap_origin) & set(s2.heap_origin):
            if s1.heap_origin[v] == s2.heap_origin[v]:
                merged.heap_origin[v] = s1.heap_origin[v]

        # Allocator kind: keep only where the two paths agree, mirroring origin.
        for v in set(s1.alloc_kind) & set(s2.alloc_kind):
            if s1.alloc_kind[v] == s2.alloc_kind[v]:
                merged.alloc_kind[v] = s1.alloc_kind[v]

        # Owned allocations: intersection. An allocation is owned after the join
        # only if the SAME variable owned the SAME allocation on both paths; if a
        # path freed/reassigned it, or a path never had it, it is not provably
        # leaked at exit, so it is dropped (precision over recall).
        for v in set(s1.owned_allocs) & set(s2.owned_allocs):
            if s1.owned_allocs[v] == s2.owned_allocs[v]:
                merged.owned_allocs[v] = s1.owned_allocs[v]

        # Asserted safe: intersection
        for var in set(s1.asserted_safe.keys()) & set(s2.asserted_safe.keys()):
            merged.asserted_safe[var] = list(
                set(s1.asserted_safe[var]) & set(s2.asserted_safe[var])
            )

        # List elements: conservative union (tainted in either path)
        for list_var in set(s1.list_elements.keys()) | set(s2.list_elements.keys()):
            elems1 = s1.list_elements.get(list_var, [])
            elems2 = s2.list_elements.get(list_var, [])
            # Take the longer list, merge taint info (conservative)
            max_len = max(len(elems1), len(elems2))
            merged_elems = []
            for i in range(max_len):
                val1, taint1 = elems1[i] if i < len(elems1) else ("", None)
                val2, taint2 = elems2[i] if i < len(elems2) else ("", None)
                # Use taint from either path (conservative)
                taint = taint1 or taint2
                val = val1 or val2
                merged_elems.append((val, taint))
            merged.list_elements[list_var] = merged_elems

        # Path constraints: drop (would need disjunction)
        merged.path_constraints = []
        # Conditions from two joined paths cannot both be assumed; drop them at a
        # merge (conservative: fewer feasibility drops, never a wrong one).
        merged.feasibility_constraints = []

        # Constants: intersection (only keep if same value in both states)
        for var in set(s1.constants.keys()) & set(s2.constants.keys()):
            if s1.constants[var] == s2.constants[var]:
                merged.constants[var] = s1.constants[var]
        # Also keep constants that only exist in one state (the variable was assigned in that path)
        for var in s1.constants:
            if var not in s2.constants:
                merged.constants[var] = s1.constants[var]
        for var in s2.constants:
            if var not in s1.constants:
                merged.constants[var] = s2.constants[var]

        # Secure parsers: union
        merged.secure_parsers = s1.secure_parsers | s2.secure_parsers

        # Safe for XML sink: union
        merged.safe_for_xml_sink = s1.safe_for_xml_sink | s2.safe_for_xml_sink

        # Validated for eval: intersection (only safe if validated in both paths)
        merged.validated_for_eval = s1.validated_for_eval & s2.validated_for_eval

        # Dict elements: merge like list elements
        for dict_var in set(s1.dict_elements.keys()) | set(s2.dict_elements.keys()):
            elems1 = s1.dict_elements.get(dict_var, {})
            elems2 = s2.dict_elements.get(dict_var, {})
            merged_elems = {}
            for key in set(elems1.keys()) | set(elems2.keys()):
                val1, taint1 = elems1.get(key, ("", None))
                val2, taint2 = elems2.get(key, ("", None))
                taint = taint1 or taint2  # Conservative: tainted if either
                val = val1 or val2
                merged_elems[key] = (val, taint)
            merged.dict_elements[dict_var] = merged_elems

        return merged

    def _states_equal(self, s1: SymbolicState, s2: SymbolicState) -> bool:
        """Check if two states are equal (for fixpoint detection)"""
        # For fixpoint, we mainly care about taint information
        # since that's what determines vulnerability detection
        if set(s1.tainted.keys()) != set(s2.tainted.keys()):
            return False
        # Check if sanitized sets are equal
        if set(s1.sanitized.keys()) != set(s2.sanitized.keys()):
            return False
        # Check if freed sets are equal
        if s1.freed != s2.freed:
            return False
        # Ownership of live allocations must also converge: a change here means a
        # leak may now be reachable that was not before. Allocation identity is a
        # stable per-site token, so this cannot oscillate.
        if s1.owned_allocs != s2.owned_allocs:
            return False
        return True
