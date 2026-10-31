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

import dataclasses
import re
from dataclasses import dataclass, field
from collections import deque
from typing import Dict, FrozenSet, List, Optional, Set, Tuple, Any, NamedTuple
from enum import Enum, auto

from frame.core.ast import (
    Formula, Emp, PointsTo, SepConj, And, Or, Not, Eq, Neq,
    Var, Const, Taint, Sanitized, Source, Sink,
    NullDeref, UseAfterFree, BufferOverflow, Exists,
    PredicateCall, Lt, Le, Gt, Ge, True_, False_, ArithExpr, Expr
)

from .types import (
    LITERAL_COLLECTION,
    Ident, PVar, Location, Typ, TypeKind,
    Exp, ExpVar, ExpConst, ExpBinOp, ExpUnOp,
    ExpFieldAccess, ExpIndex, ExpStringConcat, ExpCall, ExpTernary, ExpCast
)
from .instructions import (
    Instr, Load, Store, Alloc, Free, Prune, Call, Assign,
    TaintSource, TaintSink, Sanitize, AssertSafe, Return,
    TaintKind, SinkKind, resolve_sink_kind, _SINK_KIND_ALIASES, RequestType
)
from .procedure import Procedure, Node, NodeKind, Program, ProcSpec
from .specs.unpredictable import arguments_for, must_be_unpredictable
from . import c_facts as _c_facts
from .c_int_model import INT_TYPES, int_range, may_be_negative
from .specs.parser_hardening import load as _parser_hardening
from .specs.weak_algorithms import load as _weak_algorithms, weak_algorithm
from .specs.guards import load as _load_guards
from .specs.principals import load as _principals
from .kinds import check as _kinds_check, load as _load_kinds

_KINDS = _load_kinds()

# A plain local variable name: no field, element or call in it.
_PLAIN_LOCAL = re.compile(r'[A-Za-z_$][\w$]*$')
# A C/C++ brace initialiser holding only string / number literals.
_LITERAL_BRACE_LIST = re.compile(
    r'\{(?:\s|[{},]|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)+\'|-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)[uUlL]*)*\}$')


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
    UNVERIFIED_SIGNATURE = "unverified_signature"    # CWE-347
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
    PREDICTABLE_VALUE = "predictable_value"     # CWE-338 (weak PRNG output where unpredictability matters)
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"  # CWE-1395 (attacker data reaches a vulnerable library function)
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
    PROMPT_INJECTION = "prompt_injection"       # CWE-1427
    MCP_HIDDEN_INSTRUCTIONS = "mcp_hidden_instructions"      # CWE-1427: invisible text in MCP tool metadata
    MCP_DYNAMIC_TOOL_METADATA = "mcp_dynamic_tool_metadata"  # CWE-1427: a tool description set at run time
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
    PRIVILEGE_MANAGEMENT = "privilege_management"  # CWE-269
    SIGN_EXTENSION = "sign_extension"           # CWE-194
    SIGNED_TO_UNSIGNED = "signed_to_unsigned"   # CWE-195
    NUMERIC_TRUNCATION = "numeric_truncation"   # CWE-197
    UNICODE_HANDLING = "unicode_handling"       # CWE-176
    CONFIG_INJECTION = "config_injection"       # CWE-15
    PROCESS_CONTROL = "process_control"         # CWE-114
    OMITTED_BREAK = "omitted_break"             # CWE-484
    FIXED_ADDRESS = "fixed_address"             # CWE-587
    TOCTOU = "toctou"                           # CWE-367
    HARDCODED_KEY = "hardcoded_key"             # CWE-321
    NULL_RESULT_DEREF = "null_result_deref"     # CWE-690

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
    BUFFER_OVERREAD = "buffer_overread"              # CWE-126

    # Directional memory safety, the below-the-start pair of OOB_WRITE/OOB_READ.
    # Used only where the IR settles that the access is provably before element
    # zero (a negative index), so the specific under-* weakness is reported rather
    # than the generic over-the-top 787/125.
    OOB_UNDERWRITE = "oob_underwrite"                # CWE-124 (buffer underwrite)
    OOB_UNDERREAD = "oob_underread"                  # CWE-127 (buffer under-read)

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
        """The finding type a flow into this sink kind reports (`specs/data/kinds.toml`)."""
        vt = _KINDS.sink_vuln.get(sink_kind.value)
        return cls(vt) if vt else cls.TAINT_FLOW


_kinds_check([s.value for s in SinkKind], [v.value for v in VulnType], _KINDS)    # a broken table fails every scan


# =============================================================================
# Vulnerability Check
# =============================================================================


def _display_name(var: str) -> str:
    """A frontend temporary (`$reply_4`, the value of `reply = ...`) as the program names it."""
    m = re.fullmatch(r"\$+([A-Za-z_][\w.]*?)_\d+", var or "")
    return m.group(1) if m else var


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
    sink_call: str = ""     # the sink call (canonical id, else its text): links SCA advisories to flows
    source_kind: str = ""   # the TaintKind value of the flow's source (`llm`: model output -> category ai)

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
    # source_kind REQUEST: what the request object holds (its client properties and methods)
    request: Optional[RequestType] = None
    # data read from a request object: the property path read (`("query", "dir")`; a method's last
    # part ends in "()"), relative to the object a procedure received, for path-aware summaries
    read: Tuple[str, ...] = ()


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

    # Declared locals that have NO reaching definition on this path, for CWE-457.
    # A local enters the set at its bare declaration (`int x;`, lowered to
    # `x = null` and flagged `is_uninit_decl`) and leaves it the moment the path
    # gives it a real value (any non-declaration write) or its address is taken /
    # it is passed to a function (a possible out-parameter). A value-read of a var
    # still in the set is a use of an uninitialized variable. Merged by UNION,
    # which is the intersection of the dual "initialized" sets: a var initialized
    # on only one incoming branch is still uninitialized at the join.
    uninitialized: Set[str] = field(default_factory=set)

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
    # Variables assigned a non-literal value on some path: not a constant after a join,
    # even if another path assigned them one (`i = 0` ... `i = i + 1`).
    nonconst: Set[str] = field(default_factory=set)

    # Secure parser tracking (for XXE mitigation)
    # secure_parsers: set of variable names that hold secure XML parsers
    secure_parsers: Set[str] = field(default_factory=set)

    # Variables that have been safely processed for xml sinks
    # (e.g., passed through a secure XML parser)
    safe_for_xml_sink: Set[str] = field(default_factory=set)

    # Variables that have been validated for code injection
    # (e.g., passed through startswith/endswith validation)

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
                list(v.propagation_path), v.request, v.read
            ) for k, v in self.tainted.items()},
            sanitized={k: list(v) for k, v in self.sanitized.items()},
            freed=set(self.freed),
            heap_origin=dict(self.heap_origin),
            alloc_kind=dict(self.alloc_kind),
            owned_allocs=dict(self.owned_allocs),
            uninitialized=set(self.uninitialized),
            path_constraints=list(self.path_constraints),
            asserted_safe={k: list(v) for k, v in self.asserted_safe.items()},
            list_elements={k: list(v) for k, v in self.list_elements.items()},
            constants=dict(self.constants),
            nonconst=set(self.nonconst),
            secure_parsers=set(self.secure_parsers),
            safe_for_xml_sink=set(self.safe_for_xml_sink),
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
        """Check if variable is sanitized for given sink type (aliases such as
        `path`/`filesystem` name the same kind)."""
        have = self.sanitized.get(var, [])
        if sink_type in have:
            return True
        kind = _SINK_KIND_ALIASES.get(sink_type, sink_type)
        return any(_SINK_KIND_ALIASES.get(k, k) == kind for k in have)

    def is_asserted_safe_for(self, var: str, sink_type: str) -> bool:
        """Check if variable is asserted safe for given sink type"""
        safe_for = self.asserted_safe.get(var, [])
        if len(safe_for) == 0 and var in self.asserted_safe:
            return True
        kind = _SINK_KIND_ALIASES.get(sink_type, sink_type)
        return any(_SINK_KIND_ALIASES.get(k, k) == kind for k in safe_for)

    def is_freed(self, var: str) -> bool:
        """Check if pointer has been freed"""
        return var in self.freed

    def is_allocated(self, var: str) -> bool:
        """Check if pointer is allocated"""
        return self.allocated.get(var, False)

    def _keeps_attacker_taint(self, var: str, kind: TaintKind) -> bool:
        """A value that carries attacker data and a weak random number (`'v' + Math.random() + req.q`)
        is attacker data: weak-random taint never replaces it (a strong update has already cleared
        what an assignment overwrites)."""
        cur = self.tainted.get(var)
        return (kind == TaintKind.WEAK_RANDOM and cur is not None and cur.source_kind != TaintKind.WEAK_RANDOM
                and not cur.source_var.startswith("@param:"))      # a summary's parameter seed is not data

    def add_taint(self, var: str, info: TaintInfo) -> None:
        """Mark variable as tainted"""
        if self._keeps_attacker_taint(var, info.source_kind):
            return
        self.tainted[var] = info

    def propagate_taint(self, from_var: str, to_var: str) -> None:
        """Propagate taint from one variable to another"""
        if from_var in self.tainted:
            info = self.tainted[from_var]
            if self._keeps_attacker_taint(to_var, info.source_kind):
                return
            new_path = info.propagation_path + [to_var]
            self.tainted[to_var] = TaintInfo(
                info.source_kind, info.source_var, info.source_location, new_path, info.request, info.read
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

ProcRef = Tuple[str, str]     # (file key, procedure name); the file key is "" for a lone file


class Callee(NamedTuple):
    """A procedure a call resolves to: in this file, or (with a project) another."""
    ref: ProcRef
    proc: Procedure


@dataclass
class ReturnSummary:
    """What reaches a procedure's return value, over every analysed path.

    `source`: attacker data the procedure reads itself (`return request.args[..]`),
    with the sink kinds every such return was sanitized for. `params`: each
    parameter whose taint reaches the return, with the kinds every path from it
    sanitized it for (`return shlex.quote(x)` -> {x: {shell, ...}})."""
    source: Optional[TaintInfo] = None
    source_sanitized: Optional[Set[str]] = None
    params: Dict[str, Set[str]] = field(default_factory=dict)
    # Fields of the receiver each parameter is stored into (`this.target = target`
    # in a constructor or setter): field -> param -> kinds every path sanitized.
    stores: Dict[str, Dict[str, Set[str]]] = field(default_factory=dict)
    # Fields of a parameter holding attacker data when the procedure returns
    # (middleware: `req.filter = req.query.filter`): param -> field -> taint.
    param_fields: Dict[str, Dict[str, Tuple[TaintInfo, Set[str]]]] = field(default_factory=dict)
    # Parameters holding a request object at entry: the paths read off it that reach the return
    # (`return req.query.dir`), and those whose object itself does (`return req`).
    param_reads: Dict[str, Set[Tuple[str, ...]]] = field(default_factory=dict)
    param_whole: Set[str] = field(default_factory=set)

    def key(self):
        return (self.source.source_var if self.source else None,
                frozenset(self.source_sanitized or ()),
                tuple(sorted((p, frozenset(k)) for p, k in self.params.items())),
                tuple(sorted((f, p, frozenset(k)) for f, ps in self.stores.items()
                             for p, k in ps.items())),
                tuple(sorted((p, f, frozenset(k)) for p, fs in self.param_fields.items()
                             for f, (_, k) in fs.items())),
                tuple(sorted((p, frozenset(r)) for p, r in self.param_reads.items())),
                frozenset(self.param_whole))


@dataclass
class IPAState:
    """Inter-procedural taint summaries, shared by the translators of every file
    in a project (or private to one lone file's translator).

    - `entry_taints`: proc -> param -> (taint, sink kinds EVERY call that passes
      attacker data had sanitized it for), recorded at call sites.
    - `return_summaries`: what reaches each procedure's return value.
    - `callers`: proc -> the procedures that call it, so a changed return summary
      re-analyses exactly them.
    - `dirty`: procedures whose inputs changed since they were last analysed.
    - `entry_markers`: the `<file>::<proc>(<param>)` tag a parameter's taint
      carries, so a return can be traced back to the parameter it came from.
    """
    entry_taints: Dict[ProcRef, Dict[str, Tuple[TaintInfo, Set[str]]]] = field(default_factory=dict)
    return_summaries: Dict[ProcRef, ReturnSummary] = field(default_factory=dict)
    callers: Dict[ProcRef, Set[ProcRef]] = field(default_factory=dict)
    dirty: Set[ProcRef] = field(default_factory=set)
    entry_markers: Dict[str, Tuple[ProcRef, str]] = field(default_factory=dict)
    # (file, app object) -> request field -> taint: what middleware registered with
    # `app.use(mw)` stores on the request every handler of that app receives.
    middleware_fields: Dict[Tuple[str, str], Dict[str, Tuple[TaintInfo, Set[str]]]] = field(default_factory=dict)
    # Request attribute name -> taint a servlet Filter stores under it, and the
    # procedures that read request attributes (re-analysed when it changes).
    request_attributes: Dict[str, Tuple[TaintInfo, Set[str]]] = field(default_factory=dict)
    attribute_readers: Set[ProcRef] = field(default_factory=set)
    # Set when the fixpoint ran out of its visit budget: the summaries may be
    # missing flows (reported by the scan as an incomplete analysis).
    incomplete: bool = False
    # Python decorators of the project: decorator -> the functions it wraps (`@token_required`),
    # which its wrapper calls through the decorator's parameter (`f(user, *args)`).
    decorated: Dict[ProcRef, List["Callee"]] = field(default_factory=dict)


# The fixpoint analyses each procedure once, then again only when something it
# depends on changed. A procedure normally needs one or two visits (taint moves
# one call hop per visit, so a chain of L calls costs about L extra visits); the
# budget stops a pathological oscillation, and `IPAState.incomplete` says so.
IPA_VISITS_PER_PROC = 25
IPA_EXTRA_VISITS = 1000


def run_ipa_fixpoint(translators: Dict[str, "SILTranslator"], ipa: IPAState) -> None:
    """Compute entry taints and return summaries for every procedure of
    `translators` (file key -> translator sharing `ipa`) to a fixpoint, with the
    checks they produce discarded: a caller analysed before its callee would
    otherwise report with the callee's effects unknown, and a reported check
    cannot be withdrawn. Every procedure is analysed once, in a fixed order; a
    procedure is analysed again (queued behind the rest, once) whenever an entry
    taint it receives or a return summary it uses changes."""
    for tr in translators.values():
        tr._prepare()
        tr._ipa_on = True
        tr._ipa_summarising = True
    for key, tr in sorted(translators.items()):
        tr._record_decorated()
    queue = deque(sorted((key, name) for key, tr in translators.items()
                         for name in tr.program.procedures))
    queued = set(queue)
    budget = IPA_VISITS_PER_PROC * len(queue) + IPA_EXTRA_VISITS
    try:
        while queue:
            if budget <= 0:
                ipa.incomplete = True
                break
            budget -= 1
            ref = queue.popleft()
            queued.discard(ref)
            tr = translators.get(ref[0])
            proc = tr.program.procedures.get(ref[1]) if tr else None
            if proc is None:
                continue
            ipa.dirty = set()
            tr.translate_procedure(proc)
            for changed in sorted(ipa.dirty):
                if changed not in queued:
                    queue.append(changed)
                    queued.add(changed)
    finally:
        ipa.dirty = set()
        for tr in translators.values():
            tr._ipa_summarising = False
            tr._ipa_fixed = True

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

def _note_sink_call(checks: List["VulnerabilityCheck"], instr: Instr) -> None:
    """Record the call each check's sink is (for frame/sca: an advisory is reached only through
    its own function), where the code that made the check did not already say."""
    if isinstance(instr, Call):
        name = instr.canonical or str(getattr(instr.func, "value", instr.func)).strip('"')
    elif isinstance(instr, TaintSink):
        name = instr.call.strip('"')
    else:
        return
    for c in checks:
        if not c.sink_call:
            c.sink_call = name


class SILTranslator:
    """
    Translates SIL programs to Frame formulas for vulnerability verification.

    Algorithm:
    1. For each procedure, perform symbolic execution over CFG
    2. Track taint propagation through assignments and calls
    3. At each sink, generate a VulnerabilityCheck if tainted data reaches it
    4. Return list of checks to verify with Frame's IncorrectnessChecker
    """

    def __init__(self, program: Program = None, verbose: bool = False,
                 ipa: Optional["IPAState"] = None, file_key: str = "",
                 project: Any = None):
        """
        Initialize the translator.

        Args:
            program: The SIL program (provides library specs)
            verbose: Enable verbose output
            ipa: Inter-procedural summaries shared with the other files of a
                project; a lone file gets its own
            file_key: This file's key in the project (procedures are keyed by
                (file key, name))
            project: With `ipa`, the project (`ProjectContext`): resolves a call
                to a procedure of another file
        """
        self.program = program or Program()
        self.verbose = verbose
        self._ipa = ipa if ipa is not None else IPAState()
        self._file_key = file_key
        self._project = project
        self.vulnerability_checks: List[VulnerabilityCheck] = []
        # Cache for procedures that always return constants
        self._constant_return_procs: Dict[str, bool] = {}
        # Procedure -> does every non-null return hand back an XXE-hardened
        # parser? (_record_secure_parser_return / _track_xml_hardening)
        self._secure_parser_returns: Dict[str, bool] = {}
        self._summarising_parsers = False
        # Inter-procedural taint between the procedures of one file (Python,
        # JS/TS; `_ipa_applies`). Summaries are computed to a fixpoint before the
        # pass that reports (`translate_program`):
        # - entry taints: proc -> param -> (taint, sink kinds every call that
        #   passes attacker data had sanitized it for) (`_record_entry_taints`);
        # - return summaries: what reaches each procedure's return value
        #   (`ReturnSummary`, `_accumulate_return`), applied at call sites
        #   (`_apply_return_summary`) and inside expressions (`_arg_taint_leaves`).
        self._ipa_on = False           # summaries are in play (set by the fixpoint)
        self._ipa_summarising = False  # computing them: the only time they change
        self._capture_children: Dict[str, List[Procedure]] = {}
        self._ipa_fixed = False        # a project already ran the fixpoint
        self._prepared = False
        self._sorted_procs: List[Tuple[str, Procedure]] = []
        self._return_acc: Optional["ReturnSummary"] = None
        self._value_class: Dict[str, Tuple[str, str]] = {}
        self._literal_tables: Set[str] = set()
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
        self._ownership_guards: Dict[str, Set[str]] = {}   # procedure -> objects checked against the caller
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
        program = getattr(self, "program", None)
        return (getattr(program, "language", "") or "").lower() in (
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
                    spec = self.program.spec_for_call(instr)

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
            spec = self.program.spec_for_call(instr)

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

    def _prepare(self) -> None:
        """What every pass over the program needs first: the C/C++ procedure
        summaries, the procedure order, and the hardened-parser prepass.
        Idempotent (a project prepares each file's translator before the
        fixpoint, then reports with the same translator)."""
        if self._prepared:
            return
        self._prepared = True

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

        self._sorted_procs = sorted(self.program.procedures.items(), key=sort_key)
        self._capture_children = {}
        for proc in self.program.procedures.values():
            if proc.parent and proc.captures and proc.parent in self.program.procedures:
                self._capture_children.setdefault(proc.parent, []).append(proc)

        # Helpers that build a hardened XML parser (`getDocumentBuilder()`)
        # are summarised before their callers run: analyse each procedure that
        # makes a hardening call once up front, keeping only the summary.
        self._secure_parser_returns = {}
        self._summarising_parsers = True
        try:
            for proc_name, proc in self._sorted_procs:
                if any(isinstance(i, Call) and i.ret is None
                       and self._xml_hardening_receiver(i.get_full_name(), i.args)
                       for node in proc.nodes.values() for i in node.instrs):
                    self.translate_procedure(proc)
        finally:
            self._summarising_parsers = False

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
            self._prepared = False

        self.vulnerability_checks = []
        self._prepare()

        # Inter-procedural summaries first, to a fixpoint (`run_ipa_fixpoint`).
        # A project has already done this for all its files at once.
        if not self._ipa_fixed:
            self._ipa_on = self._ipa_applies()
            if self._ipa_on:
                run_ipa_fixpoint({self._file_key: self}, self._ipa)
                self._ipa_fixed = False   # a later program starts afresh

        # Translate each procedure
        for proc_name, proc in self._sorted_procs:
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
        """Translate a procedure, recording what reaches its return value when
        inter-procedural taint is on (`ReturnSummary`)."""
        if not self._ipa_on:
            return self._kind_matched(self._translate_procedure(proc))
        outer, self._return_acc = self._return_acc, ReturnSummary()
        try:
            checks = self._kind_matched(self._translate_procedure(proc))
            # Summaries change only while they are being computed; the reporting
            # pass reads them, so results never depend on the order files are
            # reported in.
            if self._ipa_summarising:
                ref = (self._file_key, proc.name)
                previous = self._ipa.return_summaries.get(ref)
                if previous is None or previous.key() != self._return_acc.key():
                    self._ipa.dirty.update(self._ipa.callers.get(ref, ()))
                self._ipa.return_summaries[ref] = self._return_acc
            return checks
        finally:
            self._return_acc = outer

    @staticmethod
    def _kind_matched(checks: List[VulnerabilityCheck]) -> List[VulnerabilityCheck]:
        """Drop taint checks whose source kind does not fit the sink (_create_taint_check)."""
        return [c for c in checks if not getattr(c, "kind_mismatch", False)]

    def _translate_procedure(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """
        Translate a single procedure to vulnerability checks.

        Performs symbolic execution over the CFG, tracking taint
        and generating checks at sinks.
        """
        checks = []
        self._cur_proc = proc
        self._ownership_guards[proc.name] = set()      # objects compared with the caller (this walk)
        # CWE-338 by destination: does this function's name say its result must be unpredictable?
        self._unpredictable_output = must_be_unpredictable(proc.simple_name.rsplit("::", 1)[-1])
        self._param_names = {str(p) for p, _ in proc.params}
        # Temporaries holding the result of a project method with a declared class
        # return type (`Tool.of(...)` -> Tool), for `Tool.of(..).run(v)` chains.
        self._value_class: Dict[str, Tuple[str, str]] = {}
        # C/C++ locals initialised with a brace list of literals only (`= {{"home", "/home"}}`).
        self._literal_tables: Set[str] = set()
        self._null_candidates = []
        self._uninit_candidates = []
        self._overflow_candidates = []
        self._toctou_candidates = []
        self._maybe_null_candidates = []
        self._branch_node_clean = False

        # Initialize state with parameters potentially tainted
        initial_state = self._init_state_for_procedure(proc)

        # Symbolic execution over CFG
        # Use worklist algorithm for path-sensitive analysis
        worklist: List[Tuple[int, SymbolicState]] = [(proc.entry_node, initial_state)]
        visited: Dict[int, SymbolicState] = {}
        fact_reopens: Dict[int, int] = {}
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
                # A change in what the path knows also reopens the node, a few times: the
                # back edge of `for (i = 0; i < 3; i++)` weakens `i == 0`, and only then is
                # the loop's exit feasible. Without it nothing after such a loop was analysed.
                if not state_changed and fact_reopens.get(node_id, 0) < 3 and \
                        {str(c) for c in old_state.feasibility_constraints} != \
                        {str(c) for c in merged_state.feasibility_constraints}:
                    fact_reopens[node_id] = fact_reopens.get(node_id, 0) + 1
                    state_changed = True
                state = merged_state

            visited[node_id] = state

            # Only continue processing if state changed (or first visit)
            if not state_changed:
                continue

            # Execute instructions in node
            current_state = state.copy()
            returned = False
            self._branch_node_clean = self._branch_edge_formula(node) is not None
            for instr_idx, instr in enumerate(node.instrs):
                self._cur_pos = (node_id, instr_idx)
                node_checks, current_state = self._execute_instr(
                    instr, current_state, proc.name
                )
                if node_checks:
                    _note_sink_call(node_checks, instr)
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
                if self._is_c_lang:
                    # C/C++: maintain the path facts (drop, havoc, and record the
                    # assignment as `x == rhs`) -- see _advance_path_facts.
                    current_state.feasibility_constraints = self._advance_path_facts(
                        current_state.feasibility_constraints, instr)
                elif current_state.feasibility_constraints:
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
                guard = None
                if edge_exp is not None and idx in (0, 1):
                    guard = self._feasibility_guard(edge_exp, assume_true=(idx == 0))
                    # Only record guards that mention a program variable. A
                    # constant guard (e.g. a `True` placeholder the frontend emits
                    # for a loop/structural edge) carries no path information, and
                    # its negation would be a spurious contradiction. Genuine
                    # constant-driven dead edges are already pruned by constant
                    # folding during execution.
                    if guard is not None and not guard.free_vars():
                        guard = None
                    # An edge the solver proves this path cannot take is not
                    # followed. Otherwise a provably dead path can be the FIRST to
                    # reach a join; the feasible path that arrives later with the
                    # same taint is then never analysed, and the finding it would
                    # have produced survives only if a later join happens to forget
                    # the contradiction. `_feasibility_sat` answers True when
                    # undecided, so only a proven contradiction prunes.
                    if guard is not None and not self._edge_feasible(
                            current_state.feasibility_constraints, guard):
                        continue
                added_succ = True
                # Create a clean copy without the skip markers
                succ_state = current_state.copy()
                if hasattr(succ_state, '_skip_successor_indices'):
                    del succ_state._skip_successor_indices
                if edge_exp is not None and idx in (0, 1):
                    self._apply_branch_guards(succ_state, edge_exp, is_true_branch=(idx == 0))
                if guard is not None:
                    succ_state.feasibility_constraints = (
                        succ_state.feasibility_constraints + [guard]
                    )
                worklist.append((succ_id, succ_state))

            # A path that ends here without returning (falls off the end of a
            # void function) drops any allocation it still owns: the owning
            # pointer goes out of scope unreleased, a CWE-401 leak. Runs on the
            # merged state at this node, so an allocation freed on some other
            # incoming path is already gone. C/C++ only.
            if self._ipa_summarising and not added_succ:
                self._accumulate_param_fields(current_state)
            if self._is_c_lang and not added_succ:
                checks.extend(self._finalize_leaks(current_state, proc.name))

        # CWE-476 is decided only now, against the fixpoint of the path facts
        # (_path_fact_fixpoint): the walk above does not re-analyse a node when
        # only its path condition changes, so a verdict taken during the walk
        # could rest on one branch's facts alone.
        if self._null_candidates or self._uninit_candidates or self._overflow_candidates \
                or self._toctou_candidates or self._maybe_null_candidates:
            checks.extend(self._confirm_path_candidates(proc))

        # (A handler with another finding used to lose its XSS checks here so
        # that a one-label benchmark file scored no extra report; that is
        # benchmark scoring, applied by `scanner.collapse_per_file_cwe`. A
        # handler with SQLi and reflected XSS has both.)

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
        checks.extend(self._loop_bound_checks(proc))
        checks.extend(self._unchecked_return_checks(proc))
        checks.extend(self._excessive_allocation_checks(proc))
        checks.extend(self._incorrect_permission_checks(proc))

        return checks

    _ENTRY_TAINT_ROUNDS = 6
    _ENTRY_TAINT_LANGUAGES = frozenset({"python", "javascript", "typescript", "csharp", "c", "cpp"})
    _ALL_SINK_KINDS = frozenset(k.value for k in SinkKind) | frozenset(_SINK_KIND_ALIASES)
    _SEED_PREFIX = "@param:"

    def _ipa_applies(self) -> bool:
        """Inter-procedural taint runs for Python, JS/TS, C# and C/C++ files in which
        some procedure calls another of the file's procedures. (Java taints every
        String parameter already.)"""
        lang = (getattr(self.program, "language", "") or "").lower()
        if lang not in self._ENTRY_TAINT_LANGUAGES:
            return False
        def nested_calls(e):
            if isinstance(e, ExpCall):
                yield self._call_exp_name(e)
                for a in e.args:
                    yield from nested_calls(a)
            elif isinstance(e, ExpBinOp):
                yield from nested_calls(e.left)
                yield from nested_calls(e.right)
            elif isinstance(e, ExpUnOp):
                yield from nested_calls(e.operand)
            elif isinstance(e, ExpStringConcat):
                for part in e.parts:
                    yield from nested_calls(part)
            elif isinstance(e, ExpTernary):
                yield from nested_calls(e.true_exp)
                yield from nested_calls(e.false_exp)
            elif isinstance(e, (ExpFieldAccess, ExpIndex, ExpCast)):
                yield from nested_calls(e.base if not isinstance(e, ExpCast) else e.exp)

        def calls_in(instr):
            if isinstance(instr, Call):
                yield instr.get_full_name()
                for a, _ in instr.args:
                    yield from nested_calls(a)
            for attr in ("exp", "value"):
                e = getattr(instr, attr, None)
                if isinstance(e, Exp):
                    yield from nested_calls(e)

        saved = self._cur_proc
        try:
            for proc in self.program.procedures.values():
                self._cur_proc = proc
                for node in proc.nodes.values():
                    for instr in node.instrs:
                        for name in calls_in(instr):
                            if self._is_c_lang and f"{name}#2" in self.program.procedures:
                                return True              # a C++ overload set (_record_overload_entry_taints)
                            callee = self._resolve_callee(name)
                            if callee is not None and callee.ref != (self._file_key, proc.name):
                                return True
                for text, index in proc.passed_as:       # Python: wrapped by a decorator of the project
                    if lang == "python" and index == 0 and any(a.name == text for a in proc.annotations):
                        callee = self._resolve_callee(text)
                        if callee is not None and callee.ref != (self._file_key, proc.name):
                            return True
            return False
        finally:
            self._cur_proc = saved

    @staticmethod
    def _plain_callee(proc: Procedure) -> bool:
        """A procedure whose own spec says what it does (a frontend-marked
        source, sink or sanitizer) is left to that spec, not summarised."""
        spec = proc.spec
        return not (spec.is_taint_source() or spec.is_taint_sink() or spec.is_taint_sanitizer())

    def _same_file_proc(self, func_name: str) -> Optional[Procedure]:
        """The procedure of this file a call names, or None. `f(...)` is the
        function `f`; `self.m(...)` / `this.m(...)` / `cls.m(...)` is method `m`
        of the caller's class. Nothing else resolves (an `obj.m(...)` receiver
        of unknown type could be anything), and neither does a name two
        procedures share."""
        procs = self.program.procedures
        caller = self._cur_proc
        if "." not in func_name:
            proc = procs.get(func_name)
            if proc is None and caller is not None:
                passed = self._callback_argument(func_name, caller)
                if passed is not None:
                    return passed
            if proc is None and caller is not None and caller.class_name \
                    and (getattr(self.program, "language", "") or "").lower() == "csharp":
                own = [p for p in procs.values() if p.is_method and p.class_name == caller.class_name
                       and p.simple_name == func_name]
                return own[0] if len(own) == 1 else None      # `Helper(x)` inside a class method
            if proc is None or f"{func_name}#2" in procs or proc.is_method:
                return None
            return proc
        head, _, method = func_name.rpartition(".")
        if head in ("self", "this", "cls") and caller is not None and caller.class_name:
            owner = caller.class_name.rsplit(".", 1)[-1]
        else:
            owner = self._in_file_receiver_class(head, caller)
            if owner is None:
                return None
        hits = [p for p in procs.values()
                if p.is_method and p.class_name and p.class_name.rsplit(".", 1)[-1] == owner
                and p.simple_name == method]
        return hits[0] if len(hits) == 1 else None

    def _request_proxies(self) -> Dict[str, Optional["RequestType"]]:
        """The names this file reaches a module-level request proxy by (`request` after `from flask
        import request`, `cherrypy.request` after `import cherrypy`), with the request type the
        applied packs give it (`[[request_type]] proxies`). Inside a request such a proxy is that
        request's object. An identity proxy (`[[identity]] proxies`: Flask-Login's
        `current_user`) maps to None: it is the authenticated caller."""
        cache = self.__dict__.get("_request_proxy_cache")
        if cache is None:
            proxies: Dict[str, Optional["RequestType"]] = {}
            for pack in getattr(self.program, "active_packs", ()):
                for proxy, rid in getattr(pack, "request_proxies", {}).items():
                    proxies.setdefault(proxy, pack.request_types[rid])
                for proxy in getattr(pack, "identity_proxies", ()):
                    proxies.setdefault(proxy, None)        # the authenticated caller, not a request
            cache = {}
            for local, qualified in (self.program.imports or {}).items():
                q = str(qualified)
                for proxy, rtype in proxies.items():
                    if proxy == q:
                        cache[local] = rtype
                    elif proxy.startswith(q + "."):
                        cache[local + proxy[len(q):]] = rtype
            self.__dict__["_request_proxy_cache"] = cache
        return cache

    def _rebound_names(self, proc: Procedure) -> Set[str]:
        """Names the procedure (or the module) binds itself: a parameter or an assigned local of an
        imported name is a different object."""
        out = {p.name for p, _ in proc.params} | set(proc.locals)
        for p in (proc, self.program.procedures.get("<module>")):
            if p is None:
                continue
            for node in p.nodes.values():
                for instr in node.instrs:
                    if isinstance(instr, Assign):
                        out.add(self._get_var_name(instr.id))
        return out

    def _seed_request_proxies(self, proc: Procedure, state: "SymbolicState") -> None:
        if proc.name.startswith("<"):              # module code runs at import, outside any request
            return
        proxies = self._request_proxies()
        if not proxies:
            return
        rebound = self._rebound_names(proc)
        for name, rtype in proxies.items():
            if name.split(".", 1)[0] in rebound:
                continue
            if rtype is None:                        # an identity proxy (`flask_login.current_user`)
                state.add_taint(name, TaintInfo(TaintKind.IDENTITY, name, proc.loc or Location.unknown()))
                continue
            state.add_taint(name, TaintInfo(TaintKind.REQUEST, name, proc.loc or Location.unknown(),
                                            request=rtype))

    def _record_decorated(self) -> None:
        """Python: each function of this file a decorator of the project wraps (`@token_required`
        def view(user, id)` -> `ipa.decorated[token_required]`), the decorator resolved like a call
        of it from the function's own file."""
        if (getattr(self.program, "language", "") or "").lower() != "python":
            return
        saved = self._cur_proc
        try:
            for proc in self.program.procedures.values():
                for text, index in proc.passed_as:
                    if index != 0 or not any(a.name == text for a in proc.annotations):
                        continue
                    self._cur_proc = proc
                    decorator = self._resolve_callee(text)
                    if decorator is None or decorator.ref == (self._file_key, proc.name):
                        continue
                    wrapped = self._ipa.decorated.setdefault(decorator.ref, [])
                    if all(c.ref != (self._file_key, proc.name) for c in wrapped):
                        wrapped.append(Callee((self._file_key, proc.name), proc))
        finally:
            self._cur_proc = saved

    def _decorated_targets(self, name: str) -> List["Callee"]:
        """`f(user, *args, **kwargs)` inside a decorator's wrapper, `f` being the decorator's
        parameter (seen through the wrapper's captures): every function the decorator wraps."""
        scope, seen = self._cur_proc, set()
        while scope is not None and id(scope) not in seen:
            seen.add(id(scope))
            params = [p.name for p, _ in scope.params]
            if name in params:
                if params.index(name) != 0:
                    return []
                return list(self._ipa.decorated.get((self._file_key, scope.name), ()))
            if name not in scope.captures:
                return []
            scope = self.program.procedures.get(scope.parent) if scope.parent else None
        return []

    def _callback_argument(self, name: str, caller: Procedure) -> Optional[Procedure]:
        """`cb(x)` inside `withName(req, cb)`: the one function of this file that is passed as
        that argument to `withName`. Resolved only when a single function is ever passed there."""
        scope, seen = caller, set()
        while scope is not None and id(scope) not in seen:       # a nested callback sees its parents' parameters
            seen.add(id(scope))
            params = [p.name for p, _ in scope.params]
            if name in params:
                index, owner = params.index(name), scope.simple_name
                hits = [p for p in self.program.procedures.values() if (owner, index) in p.passed_as]
                return hits[0] if len(hits) == 1 else None
            if name not in scope.captures:
                return None
            scope = self.program.procedures.get(scope.parent) if scope.parent else None
        return None

    _CTOR_RECEIVER = re.compile(r"^(?:new\s+)?([A-Za-z_]\w*)\(.*\)$")

    def _in_file_receiver_class(self, receiver: str, caller: Optional[Procedure]) -> Optional[str]:
        """The class of this file a method receiver is an instance of: `Reports().m(...)`
        (the written constructor call) or a variable assigned from such a call in the caller
        (`r = Reports(); r.m(...)`). A variable assigned two different classes has none."""
        classes = {p.class_name.rsplit(".", 1)[-1] for p in self.program.procedures.values() if p.class_name}
        m = self._CTOR_RECEIVER.match(receiver)
        if m:
            return m.group(1) if m.group(1) in classes else None
        if caller is None or not receiver.replace("$", "_").isidentifier():
            return None
        declared = caller.var_types.get(receiver)
        if declared and declared.rsplit(".", 1)[-1] in classes:
            return declared.rsplit(".", 1)[-1]
        cache = self.__dict__.setdefault("_var_class_cache", {})
        if id(caller) not in cache:
            seen: Dict[str, Optional[str]] = {}
            pending: Dict[str, str] = {}
            for node in caller.nodes.values():
                for ins in node.instrs:
                    if isinstance(ins, Call) and ins.ret is not None:
                        name = self._call_exp_name(ExpCall(ins.func, []))
                        name = name[4:] if name.startswith("new ") else name
                        if name in classes:
                            pending[str(ins.ret[0])] = name
                    elif isinstance(ins, Assign) and isinstance(ins.exp, ExpVar):
                        cls = pending.get(str(ins.exp.var))
                        if cls is not None:
                            target = str(ins.id)
                            seen[target] = cls if seen.get(target, cls) == cls else None
                    elif isinstance(ins, Assign) and isinstance(ins.exp, ExpCall):   # `const r = new R()`
                        name = self._call_exp_name(ins.exp)
                        name = name[4:] if name.startswith("new ") else name
                        if name in classes:
                            target = str(ins.id)
                            seen[target] = name if seen.get(target, name) == name else None
            cache[id(caller)] = seen
        found = cache[id(caller)].get(receiver)
        if found is None and receiver not in cache[id(caller)]:
            # bound outside the caller: an enclosing function's or the module's `const r = new R()`
            from .value_origins import MODULE, _definitions
            if receiver not in _definitions(caller) and caller.name != MODULE:
                outer = self.program.procedures.get(getattr(caller, "parent", None) or MODULE)
                if outer is not None and outer is not caller:
                    return self._in_file_receiver_class(receiver, outer)
        return found

    def _resolve_callee(self, func_name: str) -> Optional[Callee]:
        """The procedure a call makes: one of this file's (which wins over an
        import of the same name), else -- in a project -- a function of another
        file the call's name resolves to through the imports."""
        local = self._same_file_proc(func_name)
        if local is not None:
            return Callee((self._file_key, local.name), local) if self._plain_callee(local) else None
        if f"{func_name}#2" in self.program.procedures and "." not in func_name:
            return None
        if self._project is None:
            return None
        ref = self._project.resolve_call(
            self._file_key, func_name,
            self._cur_proc.class_name if self._cur_proc is not None else None)
        if (ref is None and "." in func_name
                and (getattr(self.program, "language", "") or "").lower() in ("java", "csharp")):
            owner, _, method = func_name.rpartition(".")
            if func_name[:1].isupper():                           # `Params.path(req)` nested in an expression
                ref = self._project.resolve_java_call(self._file_key, owner, method, None)
            elif self._cur_proc is not None and owner in self._cur_proc.var_types:
                # `_service.Describe(x)` nested in an expression: the receiver's declared type
                ref = self._project.resolve_java_call(
                    self._file_key, self._cur_proc.var_types[owner], method, None)
        proc = self._project.procedure(ref) if ref is not None else None
        if proc is None or not self._plain_callee(proc):
            return None
        return Callee(ref, proc)

    def _resolve_call_instr(self, instr: Call, func_name: str) -> Optional[Callee]:
        """`_resolve_callee`, and for a Java call in a project the method of the class the frontend
        says the call names (`Call.callee_class`), found through imports, packages, supertypes and
        the single implementation of an interface (`ProjectContext.resolve_java_call`)."""
        callee = self._resolve_callee(func_name)
        if callee is None:
            callee = self._resolve_constructor(func_name)
        if callee is not None or self._project is None:
            return callee
        target = self._java_call_target(instr, func_name)
        if target is None:
            return None
        key, owner, method = target
        ref = self._project.resolve_java_call(key, owner, method,
                                              getattr(instr, "arg_types", None))
        proc = self._project.procedure(ref) if ref is not None else None
        if proc is None or not self._plain_callee(proc):
            return None
        return Callee(ref, proc)

    def _java_call_target(self, instr: Call, func_name: str) -> Optional[Tuple[str, str, str]]:
        """(file the class name is resolved from, class, method) a Java/C# call names."""
        lang = (getattr(self.program, "language", "") or "").lower()
        if lang not in ("java", "csharp"):
            return None
        owner = getattr(instr, "callee_class", None)
        method = func_name.rsplit(".", 1)[-1]
        if func_name.startswith("new "):             # `new Job(v)`: the class's constructor
            owner = func_name[len("new "):].split("<", 1)[0].strip().rsplit(".", 1)[-1]
            method = "ctor" if lang == "csharp" else "<init>"
        key = self._file_key
        if not owner and lang == "csharp" and func_name.isidentifier() \
                and self._cur_proc is not None and self._cur_proc.class_name:
            # `Query(x)` inside a class: its own method, perhaps declared in another
            # file of a partial class.
            owner = self._cur_proc.class_name.rsplit(".", 1)[-1]
        if not owner:
            # `Tool.of(..).run(v)`: the receiver is the result of a project method whose
            # declared return type names the class (resolved in that method's file).
            held = getattr(self, "_value_class", {}).get(func_name.rpartition(".")[0])
            if held is not None:
                key, owner = held
        return (key, owner, method) if owner else None

    def _record_overload_entry_taints(self, instr: Call, func_name: str, state: SymbolicState) -> None:
        """C++ `f(buf)` with several overloads of f in this file: the call may run any
        one taking that many arguments, so each receives the arguments' taint (one
        whose parameter cannot hold the payload simply has no sink to reach)."""
        if not self._ipa_summarising or not self._is_c_lang or "." in func_name \
                or f"{func_name}#2" not in self.program.procedures:
            return
        for proc in list(self.program.procedures.values()):
            n = len(proc.params)
            fits = n == len(instr.args) or (proc.has_varargs and len(instr.args) >= n - 1)
            if proc.simple_name == func_name and not proc.is_method and fits and self._plain_callee(proc):
                callee = Callee((self._file_key, proc.name), proc)
                self._record_entry_taints(callee, instr, func_name, state)

    def _record_dispatch_entry_taints(self, instr: Call, func_name: str, state: SymbolicState) -> None:
        """A call through an interface several project classes implement may run any of
        them: each implementation's parameters receive the arguments' taint."""
        if not self._ipa_summarising or self._project is None:
            return
        target = self._java_call_target(instr, func_name)
        if target is None or target[2] in ("<init>", "ctor"):
            return
        refs = self._project.java_dispatch_targets(*target, getattr(instr, "arg_types", None))
        if len(refs) < 2:
            return
        for ref in refs:
            proc = self._project.procedure(ref)
            if proc is not None and self._plain_callee(proc):
                callee = Callee(ref, proc)
                self._record_entry_taints(callee, instr, func_name, state)
                self._record_field_entry_taints(callee, instr, func_name, state)

    def _extension_call(self, instr: Call, func_name: str) -> Optional[Tuple[Callee, Call]]:
        """`arg.RunAsCommand()` (C#) calling an extension method of the project: the
        callee, and the call with the receiver passed as the first argument."""
        if self._project is None or (getattr(self.program, "language", "") or "").lower() != "csharp":
            return None
        head, _, method = func_name.rpartition(".")
        if not head or not _PLAIN_LOCAL.match(head):
            return None
        ref = self._project.resolve_extension(self._file_key, method, len(instr.args))
        proc = self._project.procedure(ref) if ref is not None else None
        if proc is None or not self._plain_callee(proc):
            return None
        call = Call(loc=instr.loc, ret=instr.ret, func=instr.func,
                    args=[(ExpVar(PVar(head)), Typ.unknown_type())] + list(instr.args))
        return Callee(ref, proc), call

    def _partial_call(self, instr: Call, func_name: str) -> Optional[Tuple[Callee, Call]]:
        """`run_echo(text)` where `run_echo = functools.partial(shell, "echo")`: the wrapped
        function, called with the bound arguments first (constants as far as this call
        can tell, so untainted placeholders)."""
        if self._project is None or (getattr(self.program, "language", "") or "").lower() != "python":
            return None
        found = self._project.resolve_partial(self._file_key, func_name)
        proc = self._project.procedure(found[0]) if found is not None else None
        if proc is None or not self._plain_callee(proc):
            return None
        bound = [(ExpConst.string(""), Typ.unknown_type())] * found[1]
        return Callee(found[0], proc), Call(loc=instr.loc, ret=instr.ret, func=instr.func,
                                            args=bound + list(instr.args))

    # Lookups that return an element of the container (or its end), never the key.
    _TABLE_LOOKUPS = _c_facts.library().container_lookups          # specs/data/c-library.toml

    def _literal_table_lookup(self, func_name: str) -> bool:
        head, _, method = func_name.rpartition(".")
        return self._is_c_lang and method in self._TABLE_LOOKUPS and head in self._literal_tables

    def _member_alloc_kind(self, name: str) -> Optional[str]:
        """The allocator kind the current class's constructors store into member `name`
        (`: data_(new unsigned char[n])` -> array new), for a release in another method
        (`~FrameBuffer() { delete data_; }`). None when unknown or not one kind."""
        proc = self._cur_proc
        if proc is None or not proc.class_name:
            return None
        table = self.__dict__.get("_member_alloc_table")
        if table is None:
            table = self._member_alloc_table = {}
            for p in self.program.procedures.values():
                cls = (p.class_name or "").rsplit("::", 1)[-1]
                if not cls or p.name.rsplit("::", 1)[-1] != cls:
                    continue                      # constructors only
                params = {v.name for v, _ in p.params}
                pending: Dict[str, str] = {}
                for node in p.nodes.values():
                    for ins in node.instrs:
                        if isinstance(ins, Assign) and isinstance(ins.exp, ExpCall):
                            k = self._alloc_kind_of_call(self._call_exp_name(ins.exp))
                            if k is not None:
                                pending[str(ins.id)] = k
                        elif isinstance(ins, Assign) and isinstance(ins.exp, ExpVar) \
                                and str(ins.exp.var) in pending and str(ins.id) not in params:
                            key = (p.class_name, str(ins.id).replace("this->", ""))
                            k = pending[str(ins.exp.var)]
                            table[key] = k if table.get(key, k) == k else None
        return table.get((proc.class_name, name.replace("this->", "")))

    def _resolve_constructor(self, func_name: str) -> Optional[Callee]:
        """`Job(v)` (Python) / `new Job(v)` (JS): the class's constructor, resolved the way
        `Job.__init__(...)` / `Job.constructor(...)` would be."""
        lang = (getattr(self.program, "language", "") or "").lower()
        ctor = {"python": "__init__", "javascript": "constructor", "typescript": "constructor"}.get(lang)
        if ctor is None:
            return None
        cls = func_name[len("new "):] if func_name.startswith("new ") else func_name
        if not cls or cls.endswith(ctor) or not all(_PLAIN_LOCAL.match(p) for p in cls.split(".")):
            return None
        local = self.program.procedures.get(f"{cls}.{ctor}")
        if local is not None and local.class_name == cls:
            return Callee((self._file_key, local.name), local) if self._plain_callee(local) else None
        if self._project is None or cls in self.program.procedures:
            return None                              # a function of this file, not a class
        index = self._project.index
        owner = index.resolve_class(self._file_key, cls)
        ref = index._find_method(owner, ctor) if owner is not None else None
        proc = self._project.procedure(ref) if ref is not None else None
        if proc is None or proc.simple_name != ctor or not self._plain_callee(proc):
            return None
        return Callee(ref, proc)

    @property
    def _cur_ref(self) -> ProcRef:
        return (self._file_key, self._cur_proc.name if self._cur_proc is not None else "")

    @staticmethod
    def _call_params(callee: Procedure, func_name: str) -> List[str]:
        """The callee's parameters in call-argument order (a method called
        through `self.`/`this.` does not pass `self`; a function never has one
        to drop, however its call is spelled)."""
        params = [p.name for p, _ in callee.params]
        if callee.is_method and params and params[0] in ("self", "cls"):
            params = params[1:]
        return params

    def _call_exp_name(self, exp: "ExpCall") -> str:
        if isinstance(exp.func, ExpConst):
            return str(exp.func.value).strip('"')
        if isinstance(exp.func, ExpVar):
            return self._get_var_name(exp.func.var)
        if isinstance(exp.func, ExpFieldAccess):
            parts, cur = [], exp.func
            while isinstance(cur, ExpFieldAccess):
                parts.insert(0, cur.field_name)
                cur = cur.base
            if isinstance(cur, ExpVar):
                parts.insert(0, self._get_var_name(cur.var))
            elif isinstance(cur, ExpCall):
                parts.insert(0, self._call_exp_name(cur) + "()")   # `new Exporter().handle`: the receiver is built here
            return '.'.join(parts)
        return str(exp.func)

    def _arg_taint_leaves(self, exp: Exp, state: SymbolicState,
                          wrap: frozenset = frozenset()) -> List[Tuple[TaintInfo, Set[str]]]:
        """`_arg_taint_leaves_any`, attacker data first: callers that keep one leaf keep it, not a
        weak random number concatenated before it (`key + "=" + code`)."""
        return sorted(self._arg_taint_leaves_any(exp, state, wrap),
                      key=lambda leaf: leaf[0].source_kind == TaintKind.WEAK_RANDOM)

    def _arg_taint_leaves_any(self, exp: Exp, state: SymbolicState,
                              wrap: frozenset = frozenset()) -> List[Tuple[TaintInfo, Set[str]]]:
        """Each piece of attacker data an expression carries, with the sink
        kinds it is sanitized for: tainted variables (with their sanitization),
        inline request reads and source calls, and what a same-file callee's
        return summary says its result carries. `wrap` is the kinds of the
        sanitizer calls enclosing `exp`."""
        out: List[Tuple[TaintInfo, Set[str]]] = []
        loc = Location.unknown()
        if isinstance(exp, ExpCall):
            name = self._call_exp_name(exp)
            callee = self._resolve_callee(name) if self._ipa_on else None
            summary = self._ipa.return_summaries.get(callee.ref) if callee else None
            if summary is not None:
                if summary.source is not None:
                    out.append((summary.source, set(wrap) | set(summary.source_sanitized or ())))
                params = self._call_params(callee.proc, name)
                for arg, param in zip(exp.args, params):
                    if param in summary.params:
                        out.extend(self._summary_param_leaves(summary, param, arg, state, wrap, at=name))
                for cap in callee.proc.captures:          # a closure returning an enclosing variable
                    if cap in summary.params and cap not in params:
                        out.extend(self._summary_param_leaves(summary, cap, ExpVar(PVar(cap)), state, wrap,
                                                              at=name))
                return out
            called = self._request_call(name, state, exp.args)
            if called is not self._NOT_REQUEST:          # `req.get("Host")`: the request type decides
                if called:
                    out.append((state.get_taint_info(called), set(wrap)))
                return out
            spec = self._spec_of_name(name)
            if spec and spec.is_taint_source():
                out.append((TaintInfo(
                    source_kind=TaintKind(spec.is_source)
                    if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT,
                    source_var=name, source_location=loc), set(wrap)))
            if spec and spec.is_taint_sanitizer():
                wrap = wrap | frozenset(spec.is_sanitizer)
            for arg in exp.args:
                out.extend(self._arg_taint_leaves(arg, state, wrap))
            # `name.trim()` / `req.query.q.toLowerCase()`: a method called on attacker data
            # returns data derived from it, as when the same call is assigned to a variable.
            parts = name.split(".")
            if isinstance(exp.func, ExpFieldAccess) and not isinstance(exp.func.base, (ExpVar, ExpFieldAccess)) \
                    and not (spec and spec.is_taint_sanitizer()):
                out.extend(self._arg_taint_leaves(exp.func.base, state, wrap))   # `x["k"].split(" ")`
            elif len(parts) > 1 and not (spec and spec.is_taint_sanitizer()):
                head = parts[0]
                if state.is_tainted(head) and not (len(parts) > 2 and self._is_request_value(head, state)):
                    out.append((state.get_taint_info(head),
                                set(wrap) | set(state.sanitized.get(head, []))))
                elif len(parts) > 2 and all(p.isidentifier() for p in parts):
                    receiver: Exp = ExpVar(PVar(head))        # `req.query.q` of `req.query.q.trim()`
                    for attr in parts[1:-1]:
                        receiver = ExpFieldAccess(receiver, attr)
                    out.extend(self._arg_taint_leaves(receiver, state, wrap))
            return out
        if isinstance(exp, ExpVar):
            var = self._get_var_name(exp.var)
            if state.is_tainted(var):
                out.append((state.get_taint_info(var),
                            set(wrap) | set(state.sanitized.get(var, []))))
            return out
        if isinstance(exp, (ExpFieldAccess, ExpIndex)):
            credential = self._request_header_credential(exp, state)
            if credential is not None:
                out.append((state.get_taint_info(credential), set(wrap)))
                return out
            if isinstance(exp, ExpFieldAccess):
                dotted = self._field_path(exp)
                resolved = self._request_path(dotted, state) if dotted else self._NOT_REQUEST
                if resolved is not self._NOT_REQUEST:      # a request object's client data or server state
                    if resolved:
                        out.append((state.get_taint_info(resolved),
                                    set(wrap) | set(state.sanitized.get(resolved, []))))
                    return out
            members = self._get_embedded_member_sources(exp)
            if members:
                src, kind = members[0]
                out.append((TaintInfo(
                    source_kind=TaintKind(kind) if kind in [t.value for t in TaintKind]
                    else TaintKind.USER_INPUT, source_var=src, source_location=loc), set(wrap)))
                return out
            # a field of a value is never the request object as a whole (only the object's own name is)
            out.extend(leaf for leaf in self._arg_taint_leaves(exp.base, state, wrap)
                       if leaf[0].source_kind != TaintKind.REQUEST or isinstance(exp, ExpIndex))
            if isinstance(exp, ExpIndex):
                out.extend(self._arg_taint_leaves(exp.index, state, wrap))
            return out
        children: List[Exp] = []
        if isinstance(exp, ExpBinOp):
            children = [exp.left, exp.right]
        elif isinstance(exp, ExpUnOp):
            children = [exp.operand]
        elif isinstance(exp, ExpStringConcat):
            children = list(exp.parts)
        elif isinstance(exp, ExpTernary):
            children = [exp.true_exp, exp.false_exp]
        elif isinstance(exp, ExpCast):
            children = [exp.exp]
        for c in children:
            out.extend(self._arg_taint_leaves(c, state, wrap))
        return out

    def _record_entry_taints(self, callee: Callee, instr, func_name: str,
                             state: SymbolicState) -> None:
        """Taint the parameters of a callee that this call passes attacker data.
        A parameter stays sanitized for a sink kind only if every such call
        passed it sanitized for that kind. Also records that this procedure
        calls the callee, so a change to the callee's return summary
        re-analyses it. Only while summaries are being computed."""
        if not self._ipa_summarising:
            return
        self._ipa.callers.setdefault(callee.ref, set()).add(self._cur_ref)
        if callee.ref == self._cur_ref:
            return
        for (arg_exp, _), param in zip(instr.args, self._call_params(callee.proc, func_name)):
            leaves = [(i, k) for i, k in self._arg_taint_leaves(arg_exp, state)
                      if not i.source_var.startswith(self._SEED_PREFIX)]
            if not leaves:
                continue
            sanitized = set.intersection(*(k for _, k in leaves))
            entry = self._ipa.entry_taints.setdefault(callee.ref, {})
            known = entry.get(param)
            if known is None:
                # Names the first call that passed attacker data, then the
                # parameter it reached: the `data_flow` entry of a finding.
                where = getattr(instr.loc, "line", None)
                caller = f"{self._file_key}:{where} -> " if self._file_key and where else ""
                marker = f"{caller}{callee.ref[0]}::{callee.ref[1]}({param})".lstrip(":")
                self._ipa.entry_markers[marker] = (callee.ref, param)
                info = leaves[0][0]
                entry[param] = (TaintInfo(source_kind=info.source_kind, source_var=info.source_var, request=info.request, read=(),
                                          source_location=info.source_location,
                                          propagation_path=[marker]), sanitized)
                self._ipa.dirty.add(callee.ref)
            elif not known[1] <= sanitized:
                entry[param] = (known[0], known[1] & sanitized)
                self._ipa.dirty.add(callee.ref)

    # Which library calls test characters, parse URLs, normalise paths, match regexes or test
    # membership: specs/data/guards.toml.
    _GUARDS = _load_guards()
    _CHARSET_METHODS = _GUARDS.charset_methods
    _CONST_NAME = re.compile(r"[A-Z][A-Z0-9_]*$")
    _HOST_KINDS = frozenset({"ssrf", "redirect"})
    _HOST_PARSERS = _GUARDS.url_parsers
    _LITERAL_COLLECTION = re.compile(
        r"^(?:[\w.]+\.)?(?:%s)\.(?:%s)" % ("|".join(_GUARDS.literal_collection_types),
                                           "|".join(_GUARDS.literal_collection_factories))
        + r"\((\s*\"[^\"]*\"\s*(?:,\s*\"[^\"]*\"\s*)*)\)\.(?:%s)$" % "|".join(sorted(_GUARDS.membership_methods)))

    # Path containment: `x.startsWith(BASE)` confines x to BASE only when x is normalised
    # (no `..` left). `_call_guard` marks the prefix test; `_apply_branch_guards` turns
    # it into a filesystem sanitisation when x came from one of these calls.
    _CONTAINED = "@contained"
    _PATH_SEPARATORS = _GUARDS.path_separators
    _PATH_NORMALIZERS = _GUARDS.path_normalizers

    @classmethod
    def _constant_prefix(cls, exp) -> bool:
        """Is `exp` a directory prefix built from constants (`BASE`, `BASE + path.sep`,
        `"/srv/data/"`), not just a separator (every absolute path starts with "/")?"""
        parts = []

        def flatten(e):
            if isinstance(e, ExpBinOp) and e.op in ("+", "++"):
                flatten(e.left)
                flatten(e.right)
            elif isinstance(e, ExpStringConcat):
                for p in e.parts:
                    flatten(p)
            else:
                parts.append(e)
        flatten(exp)
        named = False
        for p in parts:
            if isinstance(p, ExpConst) and isinstance(p.value, str):
                named = named or bool(p.value.strip("/\\"))
            elif isinstance(p, ExpVar) and cls._CONST_NAME.match(str(p.var)):
                named = True
            elif cls._flatten(p) not in cls._PATH_SEPARATORS:
                return False
        return named

    def _is_normalized_path(self, var: str, state: "SymbolicState") -> bool:
        """Was `var` (through plain copies) produced by a path-normalising call?"""
        for _ in range(8):
            value = state.heap.get(var)
            if not isinstance(value, str):
                return False
            if value.startswith("call_"):
                func = value[len("call_"):]
                return func in self._PATH_NORMALIZERS or func.rsplit(".", 1)[-1] in self._PATH_NORMALIZERS
            if not _PLAIN_LOCAL.match(value):
                return False
            var = value
        return False

    # one atom of a safe-charset regex: a class of letters / digits / underscore / hyphen
    # (or \d, \w) with an optional quantifier. Anything else -- `.`, alternation, a
    # negated class, an escaped metacharacter -- makes the pattern unprovable.
    _SAFE_REGEX_ATOM = re.compile(
        r"(?:\[(?:A-Z|a-z|0-9|[A-Za-z0-9_]|\\d|\\w|\\\.|\.|-)+\]|\\d|\\w)(?:[+*?]|\{\d+(?:,\d*)?\})?")
    # kinds a dot in the charset (`[a-z0-9.-]`, hostnames) still leaves harmless: not path traversal
    _DOT_UNSAFE_KINDS = frozenset({"filesystem", "path"})

    @classmethod
    def _safe_charset_regex(cls, pattern: str):
        """(anchored at start, anchored at end, has a dot) for a pattern that matches only
        letters, digits, underscores, hyphens and (in a class) dots; None for any other."""
        p = pattern
        start = p.startswith(("^", "\\A"))
        if start:
            p = p[1:] if p.startswith("^") else p[2:]
        end = p.endswith(("$", "\\Z")) and not p.endswith("\\$")
        if end:
            p = p[:-1] if p.endswith("$") else p[:-2]
        pos = 0
        if not p:
            return None
        while pos < len(p):
            m = cls._SAFE_REGEX_ATOM.match(p, pos)
            if not m:
                return None
            pos = m.end()
        has_dot = bool(re.search(r"\[[^\]]*\.[^\]]*\]", p))
        return start, end, has_dot

    @classmethod
    def _regex_text(cls, exp, language: str):
        """The pattern behind a regex literal argument, or None. The frontends keep the
        literal as written: `r"..."`, `"..."`, `/.../flags`."""
        if not isinstance(exp, ExpConst) or not isinstance(exp.value, str):
            return None
        text = exp.value
        m = re.fullmatch(r"[rRuU]?('{3}|\"{3}|'|\")(.*)\1", text, re.S)
        if m:
            text = m.group(2)
            if language in ("java", "csharp"):
                text = text.replace("\\\\", "\\")
            return text
        m = re.fullmatch(r"/(.*)/([a-z]*)", text, re.S)
        if m and "m" not in m.group(2):
            return m.group(1)
        if "/" in text[:1]:
            return None
        return text.replace("\\\\", "\\") if language in ("java", "csharp") else text

    @staticmethod
    def _flatten(exp) -> Optional[str]:
        """`a.b.c` for a callee written as a name, an attribute chain or a dotted string."""
        if isinstance(exp, ExpConst) and isinstance(exp.value, str):
            return exp.value
        if isinstance(exp, ExpVar):
            return str(exp.var)
        if isinstance(exp, ExpFieldAccess):
            base = SILTranslator._flatten(exp.base)
            return f"{base}.{exp.field_name}" if base else None
        return None

    @classmethod
    def _host_var(cls, exp) -> Optional[str]:
        """`u` for `urlparse(u).hostname` / `new URL(u).host`."""
        if isinstance(exp, ExpFieldAccess) and exp.field_name in cls._GUARDS.host_fields \
                and isinstance(exp.base, ExpCall) and exp.base.args and isinstance(exp.base.args[0], ExpVar):
            parser = cls._flatten(exp.base.func) or ""
            if parser in cls._HOST_PARSERS or parser.rsplit(".", 1)[-1] in cls._HOST_PARSERS:
                return str(exp.base.args[0].var)
        return None

    @classmethod
    def _guard_facts(cls, cond, regexes=None, language: str = "", strings=None):
        """[(variable, sanitized kinds, truth value of the condition under which they hold)]
        for the guards that prove a value harmless -- a character class (`x.isdigit()`, an
        anchored safe-charset regex, literal or compiled), membership in a constant collection
        (`x in ALLOWED`, `ALLOWED.includes(x)`, `ALLOWED.contains(x)`, `Set.of("a").contains(x)`),
        a URL host in an allowlist -- combined with and / or / not."""
        out = []
        for truth in (True, False):
            for var, kinds in sorted(cls._guard_vars(cond, truth, regexes or {}, language, strings or {}).items()):
                out.append((var, sorted(kinds), truth))
        return out

    @classmethod
    def _guard_vars(cls, exp, truth: bool, regexes: dict, language: str, strings: Optional[dict] = None) -> dict:
        """{variable: kinds it is harmless for} when `exp` evaluates to `truth`."""
        everything = frozenset(cls._ALLOWLIST_KINDS)
        if isinstance(exp, ExpUnOp) and exp.op == "!":
            return cls._guard_vars(exp.operand, not truth, regexes, language, strings)
        if isinstance(exp, ExpBinOp) and exp.op in ("&&", "||", "and", "or"):
            facts = [cls._guard_vars(exp.left, truth, regexes, language, strings),
                     cls._guard_vars(exp.right, truth, regexes, language, strings)]
            if (exp.op in ("&&", "and")) == truth:        # `a && b` true / `a || b` false: both hold
                merged: dict = {}
                for f in facts:
                    for var, kinds in f.items():
                        merged[var] = merged.get(var, frozenset()) | kinds
                return merged
            common = set(facts[0]) & set(facts[1])
            return {v: facts[0][v] & facts[1][v] for v in common}
        if isinstance(exp, ExpBinOp) and exp.op in ("in", "not in"):
            if truth != (exp.op == "in"):
                return {}
            return cls._member_fact(exp.left, exp.right)
        if isinstance(exp, ExpBinOp) and exp.op in ("==", "!="):
            return cls._c_equality_fact(exp.left, exp.right, truth == (exp.op == "=="), strings)
        if isinstance(exp, ExpCall) and not truth and cls._call_base_name(exp) in cls._C_STRCMP | {"strncmp"}:
            return cls._c_equality_fact(exp, ExpConst(0), True, strings)      # `!strcmp(x, "a")`
        prefix = cls._literal_prefix_test(exp)
        if prefix is not None:                          # `x.startsWith("/")`, either way
            return {prefix[0]: frozenset({(cls._STARTS if truth else cls._NOT_STARTS) + prefix[1]})}
        if not truth or not isinstance(exp, ExpCall):
            return {}
        return cls._call_guard(exp, regexes, language)

    # What a prefix test with a literal proves, as markers the branch guard combines: `x` starts
    # (or does not start) with the literal. A same-origin path starts with "/" and not with "//"
    # (RFC 3986 4.2: "//" begins a network-path reference, another host).
    _STARTS, _NOT_STARTS = "@starts:", "@not-starts:"

    @classmethod
    def _literal_prefix_test(cls, exp):
        """(variable, literal) for `x.<prefix method>("lit")`, else None."""
        if not isinstance(exp, ExpCall) or len(exp.args) != 1 or not isinstance(exp.args[0], ExpConst) \
                or not isinstance(exp.args[0].value, str):
            return None
        m = re.fullmatch(r"(\w+)\.(\w+)", cls._flatten(exp.func) or "")
        if not m or m.group(2) not in cls._GUARDS.prefix_methods:
            return None
        text = exp.args[0].value
        q = re.fullmatch(r"(['\"`])(.*)\1", text, re.S)
        return m.group(1), (q.group(2) if q else text)

    @classmethod
    def _same_origin_path(cls, kinds) -> bool:
        return cls._STARTS + "/" in kinds and cls._NOT_STARTS + "//" in kinds

    # C string comparisons: zero means equal.
    _C_STRCMP = _c_facts.library().string_compares                 # specs/data/c-library.toml
    _C_SAFE_CHARSET = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")

    @classmethod
    def _call_base_name(cls, call) -> str:
        return (cls._flatten(call.func) or "").rsplit("::", 1)[-1] if isinstance(call, ExpCall) else ""

    @classmethod
    def _c_prefix_fact(cls, args, strings: dict) -> dict:
        """`strncmp(x, P, strlen(P)) == 0`: x starts with P. A prefix that names a scheme
        and a host (`https://api.example/`) fixes where x points: not an SSRF or open
        redirect, whatever follows it."""
        x, prefix, n = args
        text = prefix.value if isinstance(prefix, ExpConst) and isinstance(prefix.value, str) \
            else strings.get(str(prefix.var)) if isinstance(prefix, ExpVar) else None
        if not isinstance(x, ExpVar) or text is None:
            return {}
        covers = (cls._call_base_name(n) == "strlen" and len(n.args) == 1 and str(n.args[0]) == str(prefix)) \
            or (isinstance(n, ExpConst) and isinstance(n.value, int) and n.value >= len(text))
        if covers and re.match(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#@\s]+/", text):
            return {str(x.var): cls._HOST_KINDS}
        return {}

    @classmethod
    def _c_equality_fact(cls, left, right, equal: bool, strings: Optional[dict] = None) -> dict:
        """What `left == right` proves when it holds (`equal`) about a C string:
        `strcmp(x, "lit") == 0` makes x that constant; `strspn(x, "set") == strlen(x)`
        limits x to the characters of the set."""
        if not equal:
            return {}
        for call, other in ((left, right), (right, left)):
            name = cls._call_base_name(call)
            if name in cls._C_STRCMP and isinstance(other, ExpConst) and other.value == 0 \
                    and len(call.args) == 2:
                a, b = call.args
                var, lit = (a, b) if isinstance(b, ExpConst) else (b, a)
                if isinstance(var, ExpVar) and isinstance(lit, ExpConst) and isinstance(lit.value, str):
                    return {str(var.var): cls._EXACT_VALUE_KINDS}
            if name == "strncmp" and isinstance(other, ExpConst) and other.value == 0 and len(call.args) == 3:
                fact = cls._c_prefix_fact(call.args, strings or {})
                if fact:
                    return fact
            if name == "strspn" and len(call.args) == 2 and cls._call_base_name(other) == "strlen" \
                    and len(other.args) == 1 and str(other.args[0]) == str(call.args[0]) \
                    and isinstance(call.args[0], ExpVar) and isinstance(call.args[1], ExpConst) \
                    and isinstance(call.args[1].value, str):
                chars = set(call.args[1].value)
                if chars <= cls._C_SAFE_CHARSET:
                    return {str(call.args[0].var): frozenset(cls._ALLOWLIST_KINDS)}
                if chars <= cls._C_SAFE_CHARSET | {"."}:
                    return {str(call.args[0].var): frozenset(cls._ALLOWLIST_KINDS) - cls._DOT_UNSAFE_KINDS}
        return {}

    @classmethod
    def _member_fact(cls, subject, collection) -> dict:
        everything = cls._EXACT_VALUE_KINDS
        constant = (isinstance(collection, ExpVar) and cls._CONST_NAME.match(str(collection.var))) \
            or (isinstance(collection, ExpConst) and isinstance(collection.value, str)
                and cls._CONST_NAME.match(collection.value)) \
            or (isinstance(collection, ExpCall) and isinstance(collection.func, ExpConst)
                and collection.func.value == LITERAL_COLLECTION)
        if not constant:
            return {}
        if isinstance(subject, ExpVar):
            return {str(subject.var): everything}
        host = cls._host_var(subject)
        return {host: cls._HOST_KINDS} if host else {}

    @classmethod
    def _call_guard(cls, call: ExpCall, regexes: dict, language: str) -> dict:
        everything = frozenset(cls._ALLOWLIST_KINDS)
        func, args = call.func, call.args
        # `/^\d+$/.test(v)`: a regex literal receiver
        g = cls._GUARDS
        if isinstance(func, ExpFieldAccess) and isinstance(func.base, ExpConst) \
                and func.field_name in g.literal_methods and len(args) == 1 and isinstance(args[0], ExpVar):
            pat = cls._regex_text(func.base, language)
            kinds = cls._regex_proves(pat, g.literal_methods[func.field_name]) if pat is not None else None
            return {str(args[0].var): kinds} if kinds else {}
        # Object.values(CONST).includes(x): an attribute call on a call
        if isinstance(func, ExpFieldAccess) and func.field_name in g.membership_methods and len(args) == 1 \
                and isinstance(func.base, ExpCall) and len(func.base.args) == 1 \
                and cls._flatten(func.base.func) in g.collection_views:
            return cls._member_fact(args[0], func.base.args[0])
        text = cls._flatten(func)
        if not text:
            return {}
        m = re.fullmatch(r"(\w+)\.(\w+)", text)
        recv, meth = (m.group(1), m.group(2)) if m else (None, None)
        if recv and meth in cls._CHARSET_METHODS and not args:
            return {recv: everything}
        # compiled constant: HOST.fullmatch(x) / HOST.test(x) / HOST.IsMatch(x)
        if recv in regexes and len(args) == 1 and isinstance(args[0], ExpVar):
            how = g.compiled_methods.get(meth)
            kinds = cls._regex_proves(regexes[recv], how) if how else None
            return {str(args[0].var): kinds} if kinds else {}
        # Java: HOST.matcher(x).matches()
        m = re.fullmatch(r"(\w+)\.%s\((\w+)\)\.(\w+)" % re.escape(g.matcher), text)
        if m and not args and m.group(1) in regexes and m.group(3) in g.matcher_methods:
            kinds = cls._regex_proves(regexes[m.group(1)], g.matcher_methods[m.group(3)])
            return {m.group(2): kinds} if kinds else {}
        # re.fullmatch("lit", x), Pattern.matches("lit", x), Regex.IsMatch(x, "lit")
        fn = g.regex_function(text)
        if fn is not None and len(args) == 2 and isinstance(args[fn.subject_arg], ExpVar):
            pat = cls._regex_text(args[fn.pattern_arg], language)
            kinds = cls._regex_proves(pat, fn.how) if pat is not None else None
            return {str(args[fn.subject_arg].var): kinds} if kinds else {}
        # String.matches("lit") is a full match of the receiver
        if recv and meth in g.subject_methods and len(args) == 1:
            pat = cls._regex_text(args[0], language)
            kinds = cls._regex_proves(pat, g.subject_methods[meth]) if pat is not None else None
            return {recv: kinds} if kinds else {}
        # `full.startsWith(BASE + path.sep)`: a prefix built from constants. It confines
        # only a normalised path ("/srv/a/../etc" passes too); the caller checks that.
        if recv and meth in g.prefix_methods and len(args) == 1 \
                and cls._constant_prefix(args[0]):
            return {recv: frozenset({cls._CONTAINED})}
        # membership: ALLOWED.includes(x) / .contains(x), Object.values(ALLOWED).includes(x),
        # Set.of("a", "b").contains(x)
        if len(args) == 1:
            subject = args[0]
            if recv and cls._CONST_NAME.match(recv) and meth in g.membership_methods:
                return cls._member_fact(subject, ExpVar(PVar(recv)))
            m = re.fullmatch(r"(?:%s)\(\s*([A-Z][A-Z0-9_]*)\s*\)\.(?:%s)" % (
                "|".join(re.escape(v) for v in sorted(g.collection_views)),
                "|".join(sorted(g.membership_methods))), text)
            if m:
                return cls._member_fact(subject, ExpVar(PVar(m.group(1))))
            if cls._LITERAL_COLLECTION.match(text):
                return cls._member_fact(subject, ExpVar(PVar("LITERAL_COLLECTION")))
        return {}

    @classmethod
    def _regex_proves(cls, pattern: str, how: str):
        """The sink kinds a match of `pattern` (`how` = full | prefix | search) makes the whole
        value harmless for -- it is made of letters, digits, underscores, hyphens (and dots) --
        or None when the pattern proves nothing."""
        anchors = cls._safe_charset_regex(pattern)
        if anchors is None:
            return None
        start, end, has_dot = anchors
        if not (how == "full" or (how == "prefix" and end) or (how == "search" and start and end)):
            return None
        kinds = frozenset(cls._ALLOWLIST_KINDS)
        return kinds - cls._DOT_UNSAFE_KINDS if has_dot else kinds

    # Set while a clean two-way branch node executes: its guards are applied per outgoing
    # edge instead (see _exec_prune / _apply_branch_guards).
    _branch_node_clean = False

    _ALLOWLIST_KINDS = ["filesystem", "path", "command", "shell", "shell_command", "sql", "nosql", "redirect",
                        "ssrf", "html", "xss", "eval", "code", "ldap", "xpath", "xml", "template", "header",
                        "regex", "log"]
    # A value proven to be one of a few constants (membership in a constant collection, an exact
    # comparison) is not attacker-chosen at all, so it also cannot reach a vulnerable library
    # function as attacker data. A character class is not enough there (a long digit string is
    # still a ReDoS input), so these kinds are added for exact-value guards only.
    _EXACT_VALUE_KINDS = frozenset(_ALLOWLIST_KINDS) | {"vulnerable_dependency"}

    @staticmethod
    def _has_local_redirect_prefix(exp: Exp) -> bool:
        """Whether a redirect target starts with a constant path (`"/login?x=" + v`):
        that stays on this origin, whatever follows. `//host` and `/\\host` are not local."""
        first = exp
        while True:
            if isinstance(first, ExpStringConcat) and first.parts:
                first = first.parts[0]
            elif isinstance(first, ExpBinOp) and str(getattr(first, "op", "")) in ("+", "Plus", "BinOp.ADD", "add"):
                first = first.left
            else:
                break
        if not isinstance(first, ExpConst) or not isinstance(first.value, str):
            return False
        v = first.value
        return len(v) >= 2 and v[0] == "/" and v[1] not in "/\\"

    # Containers whose members are not the object's own data: storing request data on
    # them does not make the whole object attacker data. The language's own receivers and the
    # JavaScript runtime's globals; a framework's or library's value (a request object, a name
    # bound to a library call: `res`, `app`) is such a container too (`_is_framework_value`).
    _NON_AGGREGATE_BASES = frozenset({"this", "self", "cls", "module", "exports", "window", "global",
                                      "globalThis", "document", "process", "console"})

    def _spec_of_name(self, name: str):
        """The spec of a call written as `name` inside an expression (no Call instruction, so no
        callee id): the row under that name, else the row of the type the head's value has in
        this scope (`res.json(await db.query(q))` with `db` a pg Pool)."""
        spec = self.program.get_spec(name)
        if spec is not None or "." not in name or self._cur_proc is None:
            return spec
        from .value_origins import origin_in_scope, typed_names
        head, rest = name.split(".", 1)
        origin = origin_in_scope(self.program, self._cur_proc.name, head)
        if not origin and "." in rest:                  # a field of an imported module's export
            field, rest2 = rest.split(".", 1)
            origin = origin_in_scope(self.program, self._cur_proc.name, f"{head}.{field}", imports=False)
            rest = rest2 if origin else rest
        if not origin:
            return None
        for key in typed_names(f"{origin}.{rest}", self.program.language or "",
                               getattr(self.program, "value_returns", None)):
            spec = self.program.library_specs.get(key)
            if spec is not None:
                return spec
        return None

    def _is_framework_value(self, name: str, state: "SymbolicState") -> bool:
        if self._is_request_value(name, state):
            return True
        from .value_origins import origin_in_scope
        proc = self._cur_proc
        return proc is not None and origin_in_scope(self.program, proc.name, name) is not None

    def _taint_from_embedded_sources(self, instr: Assign, state: SymbolicState) -> None:
        """`filter = { origin: req.body.tags }` lowers to `filter = req.body.tags`: a request
        read inside the assigned expression (no call that could convert or sanitize it) taints the
        target; and `obj.key = <tainted>` makes `obj` carry it for later `find(obj)`."""
        if getattr(self.program, "language", "") not in ("javascript", "typescript"):
            return                      # the JS frontend folds object literals into their values
        target = self._get_var_name(instr.id)
        if not state.is_tainted(target) and not self._exp_has_call(instr.exp):
            sources = self._get_embedded_member_sources(instr.exp)
            if sources:
                chain, kind = sources[0]
                state.add_taint(target, TaintInfo(
                    source_kind=TaintKind(kind) if kind in [t.value for t in TaintKind] else TaintKind.USER_INPUT,
                    source_var=chain, source_location=instr.loc or Location.unknown()))
        if state.is_tainted(target) and ("." in target or "[" in target):
            base = re.split(r"[.\[]", target, maxsplit=1)[0]
            if base and base not in self._NON_AGGREGATE_BASES and not state.is_tainted(base) \
                    and not self._is_framework_value(base, state):
                info = state.get_taint_info(target)
                if info is not None:
                    state.add_taint(base, TaintInfo(
                        source_kind=info.source_kind, source_var=info.source_var, request=info.request, read=info.read,
                        source_location=info.source_location,
                        propagation_path=list(info.propagation_path) + [base]))

    @staticmethod
    def _exp_has_call(exp: Exp) -> bool:
        if isinstance(exp, ExpCall):
            return True
        if isinstance(exp, ExpBinOp):
            return SILTranslator._exp_has_call(exp.left) or SILTranslator._exp_has_call(exp.right)
        if isinstance(exp, ExpUnOp):
            return SILTranslator._exp_has_call(exp.operand)
        if isinstance(exp, ExpStringConcat):
            return any(SILTranslator._exp_has_call(p) for p in exp.parts)
        if isinstance(exp, ExpIndex):
            return SILTranslator._exp_has_call(exp.base) or SILTranslator._exp_has_call(exp.index)
        if isinstance(exp, ExpFieldAccess):
            return SILTranslator._exp_has_call(exp.base)
        return False

    def _closure_captured_vars(self, exp: Exp, sink_kind) -> List[str]:
        """Enclosing-procedure variables that reach `exp` through a call to a
        nested closure whose return carries them (and is not sanitized for the
        sink)."""
        out: List[str] = []
        if not self._ipa_on:
            return out

        def walk(e: Exp) -> None:
            if isinstance(e, ExpCall):
                name = self._call_exp_name(e)
                callee = self._resolve_callee(name)
                summary = self._ipa.return_summaries.get(callee.ref) if callee else None
                if summary is not None:
                    params = self._call_params(callee.proc, name)
                    for cap in callee.proc.captures:
                        if (cap in summary.params and cap not in params
                                and not self._sanitizes_kind(summary.params[cap], sink_kind)):
                            out.append(cap)
                for a in e.args:
                    walk(a)
            elif isinstance(e, ExpBinOp):
                walk(e.left)
                walk(e.right)
            elif isinstance(e, ExpUnOp):
                walk(e.operand)
            elif isinstance(e, ExpStringConcat):
                for part in e.parts:
                    walk(part)
            elif isinstance(e, ExpIndex):
                walk(e.base)
                walk(e.index)
            elif isinstance(e, ExpFieldAccess):
                walk(e.base)

        walk(exp)
        return out

    def _record_capture_taints(self, instr: Instr, state: SymbolicState) -> None:
        """A nested function sees its enclosing procedure's variables. Whatever
        attacker data those variables carry while the enclosing procedure runs is
        treated as entry taint of the nested one (flow-insensitive over the
        enclosing procedure, as a closure can run at any later point). Only
        while summaries are being computed."""
        children = self._capture_children.get(self._cur_ref[1]) if self._cur_ref else None
        if not children:
            return
        for child in children:
            ref = (self._file_key, child.name)
            for name in child.captures:
                leaves = [(i, k) for i, k in self._arg_taint_leaves(ExpVar(PVar(name)), state)
                          if not i.source_var.startswith(self._SEED_PREFIX)]
                if not leaves:
                    continue
                sanitized = set.intersection(*(k for _, k in leaves))
                entry = self._ipa.entry_taints.setdefault(ref, {})
                known = entry.get(name)
                if known is None:
                    where = getattr(instr.loc, "line", None)
                    caller = f"{self._file_key}:{where} -> " if self._file_key and where else ""
                    marker = f"{caller}{ref[0]}::{ref[1]}({name})".lstrip(":")
                    self._ipa.entry_markers[marker] = (ref, name)
                    info = leaves[0][0]
                    entry[name] = (TaintInfo(source_kind=info.source_kind, source_var=info.source_var, request=info.request, read=(),
                                             source_location=info.source_location,
                                             propagation_path=[marker]), sanitized)
                    self._ipa.dirty.add(ref)
                elif not known[1] <= sanitized:
                    entry[name] = (known[0], known[1] & sanitized)
                    self._ipa.dirty.add(ref)

    def _record_nested_entry_taints(self, instr: Instr, state: SymbolicState) -> None:
        roots: List[Exp] = []
        if isinstance(instr, Call):
            roots = [a for a, _ in instr.args]
        for attr in ("exp", "value"):
            e = getattr(instr, attr, None)
            if isinstance(e, Exp):
                roots.append(e)
        stack = list(roots)
        while stack:
            e = stack.pop()
            if isinstance(e, ExpCall):
                name = self._call_exp_name(e)
                callee = self._resolve_callee(name) or self._resolve_constructor(name)
                call = Call(loc=instr.loc, ret=None, func=e.func,
                            args=[(a, Typ.unknown_type()) for a in e.args])
                if callee is None:
                    ext = self._extension_call(call, name) or self._partial_call(call, name)
                    if ext is not None:
                        callee, call = ext
                if callee is not None:
                    self._record_entry_taints(callee, call, name, state)
                    self._record_field_entry_taints(callee, call, name, state)
                stack.extend(e.args)
            elif isinstance(e, ExpBinOp):
                stack.extend([e.left, e.right])
            elif isinstance(e, ExpUnOp):
                stack.append(e.operand)
            elif isinstance(e, ExpStringConcat):
                stack.extend(e.parts)
            elif isinstance(e, ExpTernary):
                stack.extend([e.true_exp, e.false_exp])
            elif isinstance(e, (ExpFieldAccess, ExpIndex)):
                stack.append(e.base)
            elif isinstance(e, ExpCast):
                stack.append(e.exp)

    def _accumulate_return(self, value: Exp, state: SymbolicState, proc_name: str) -> None:
        """Fold what this return hands back into the procedure's summary."""
        acc = self._return_acc
        for info, kinds in self._arg_taint_leaves(value, state):
            origin = self._ipa.entry_markers.get(info.propagation_path[0]) \
                if info.propagation_path else None
            if origin is not None and origin[0] == self._cur_ref:
                param = origin[1]
                acc.params[param] = set(kinds) if param not in acc.params \
                    else acc.params[param] & kinds
                if info.source_kind == TaintKind.REQUEST and not info.read:
                    acc.param_whole.add(param)            # the request object itself
                elif info.read:
                    acc.param_reads.setdefault(param, set()).add(info.read)
            elif info.source_var.startswith(self._SEED_PREFIX):
                continue
            else:
                if acc.source is None:
                    acc.source = info
                acc.source_sanitized = set(kinds) if acc.source_sanitized is None \
                    else acc.source_sanitized & kinds

    # `this.f`, `self.f`, `this->f`: a field of the receiver.
    _RECEIVER_FIELD = re.compile(r"(?:this|self)(?:\.|->)([A-Za-z_$][\w$]*)$")
    _CONSTRUCTOR_NAMES = frozenset({"<init>", "__init__", "constructor", "ctor"})

    def _fold_condition(self, exp: Exp, state: SymbolicState):
        """The value of a condition over the constants the path knows (`(7*42) - num > 200`
        with `num = 106`), or None when any part is unknown."""
        if isinstance(exp, ExpConst):
            return exp.value
        if isinstance(exp, ExpVar):
            return state.get_constant(self._get_var_name(exp.var))
        if isinstance(exp, ExpStringConcat):         # Python lowers every `+` as this
            parts = [self._fold_condition(p, state) for p in exp.parts]
            if parts and all(isinstance(p, (int, float)) and not isinstance(p, bool) for p in parts):
                return sum(parts)
            if parts and all(isinstance(p, str) for p in parts):
                return "".join(parts)
            return None
        if isinstance(exp, ExpUnOp):
            v = self._fold_condition(exp.operand, state)
            if v is None:
                return None
            return (not v) if exp.op in ("!", "not") else (-v if exp.op == "-" and isinstance(v, (int, float)) else None)
        if isinstance(exp, ExpBinOp):
            a, b = self._fold_condition(exp.left, state), self._fold_condition(exp.right, state)
            op = exp.op
            # a condition is read by its truthiness, in C (`1 && 0`) as in Python (`x and ""`)
            if op in ("and", "&&"):
                if (a is not None and not a) or (b is not None and not b):
                    return False
                return True if a is not None and b is not None else None
            if op in ("or", "||"):
                if (a is not None and a) or (b is not None and b):
                    return True
                return False if a is not None and b is not None else None
            if a is None or b is None:
                return None
            try:
                if op in ("in", "not in") and isinstance(a, str) and isinstance(b, str):
                    return (a in b) if op == "in" else (a not in b)
                if isinstance(a, bool) or isinstance(b, bool) or not isinstance(a, (int, float)) \
                        or not isinstance(b, (int, float)):
                    return (a == b) if op == "==" else (a != b) if op == "!=" else None
                return {"+": lambda: a + b, "-": lambda: a - b, "*": lambda: a * b,
                        "/": lambda: a / b, "//": lambda: a // b, "%": lambda: a % b,
                        "<": lambda: a < b, ">": lambda: a > b, "<=": lambda: a <= b,
                        ">=": lambda: a >= b, "==": lambda: a == b, "!=": lambda: a != b}[op]()
            except (KeyError, ZeroDivisionError, TypeError):
                return None
        return None

    def _accumulate_store(self, target: str, value: Exp, state: SymbolicState) -> None:
        """Record which parameters this method stores into a field of its receiver."""
        if self._return_acc is None:
            return
        m = self._RECEIVER_FIELD.match(target)
        fld = m.group(1) if m else self._bare_field(target)
        if fld is None:
            return
        stores = self._return_acc.stores
        for info, kinds in self._arg_taint_leaves(value, state):
            origin = self._ipa.entry_markers.get(info.propagation_path[0]) \
                if info.propagation_path else None
            if origin is None or origin[0] != self._cur_ref:
                continue
            fields = stores.setdefault(fld, {})
            param = origin[1]
            fields[param] = set(kinds) if param not in fields else fields[param] & kinds

    def _bare_field(self, name: str) -> Optional[str]:
        """`_target = target` in Java/C#/C++: a write to a declared field of the
        method's class by its bare name (not shadowed by a parameter)."""
        proc = self._cur_proc
        if proc is None or not proc.is_method or not proc.class_name \
                or (getattr(self.program, "language", "") or "").lower() not in ("java", "csharp", "cpp"):
            return None
        fields = self.program.declared_fields.get(proc.class_name) \
            or self.program.declared_fields.get(proc.class_name.rsplit(".", 1)[-1], set())
        if name not in fields or name in {p.name for p, _ in proc.params}:
            return None
        return name

    def _call_receiver(self, callee: Callee, instr: Call, func_name: str) -> Optional[str]:
        """The local variable a call acts on: the new object for a constructor, else
        `x` in `x.m(...)`."""
        if callee.proc.simple_name in self._CONSTRUCTOR_NAMES or func_name.startswith("new "):
            return str(instr.ret[0]) if instr.ret else None
        head = func_name.rpartition(".")[0]
        return head if head and _PLAIN_LOCAL.match(head) else None

    def _apply_field_stores(self, callee: Callee, summary: ReturnSummary, instr: Call,
                            func_name: str, state: SymbolicState) -> None:
        """`new Job(v)` / `job.setTarget(v)` with attacker data in v: the receiver's
        field the callee stores v into (`job.target`) now carries v's taint."""
        if not summary.stores:
            return
        recv = self._call_receiver(callee, instr, func_name)
        if recv is None:
            return
        args = dict(zip(self._call_params(callee.proc, func_name), (a for a, _ in instr.args)))
        for fld, params in summary.stores.items():
            leaves = [(info, kinds | params[p]) for p in params if p in args
                      for info, kinds in self._arg_taint_leaves(args[p], state)]
            if not leaves:
                continue
            key = f"{recv}.{fld}"
            info = leaves[0][0]
            state.add_taint(key, TaintInfo(
                source_kind=info.source_kind, source_var=info.source_var, request=info.request, read=info.read,
                source_location=info.source_location,
                propagation_path=list(info.propagation_path) + [key]))
            sanitized = set.intersection(*(k for _, k in leaves))
            if sanitized:
                state.add_sanitization(key, sorted(sanitized))
            else:
                state.sanitized.pop(key, None)

    def _accumulate_param_fields(self, state: SymbolicState) -> None:
        """At the end of a path: fields of a parameter that now hold attacker data
        (`req.filter = req.query.filter` in middleware)."""
        if self._return_acc is None or self._cur_proc is None:
            return
        params = {p.name for p, _ in self._cur_proc.params} - {"self", "this", "cls"}
        for key, info in state.tainted.items():
            head, _, fld = key.partition(".")
            # C/C++: the parameter itself is a buffer the function filled (`out[i] = ...`),
            # recorded under the empty field name.
            buffer = self._is_c_lang and key in params and not fld
            if head not in params or not (buffer or _PLAIN_LOCAL.match(fld)) \
                    or info.source_var.startswith(self._SEED_PREFIX):
                continue
            if info.propagation_path and info.propagation_path[0] in self._ipa.entry_markers:
                continue                             # came in with the argument, not set here
            kinds = set(state.sanitized.get(key, []))
            fields = self._return_acc.param_fields.setdefault(head, {})
            # Sanitized for a kind only if every path that sets the field sanitized it.
            fields[fld] = (info, kinds) if fld not in fields else (fields[fld][0], fields[fld][1] & kinds)

    def _pack_entries(self, attr: str) -> list:
        """The entries of kind `attr` of the packs applied to this program (`Program.active_packs`)."""
        return [e for p in getattr(self.program, "active_packs", ()) for e in getattr(p, attr, ())]

    def _record_middleware(self, instr: Call, func_name: str, state: SymbolicState) -> None:
        """`app.use(mw)` (a packs' `[[middleware]]` method): the request fields mw sets reach every
        handler of `app`."""
        head, _, method = func_name.rpartition(".")
        if not self._ipa_summarising or method not in self._pack_entries("middleware_methods") \
                or not _PLAIN_LOCAL.match(head or "-"):
            return
        for arg, _ in instr.args:
            if not isinstance(arg, ExpVar):
                continue
            callee = self._resolve_callee(str(arg.var))
            if callee is None or not callee.proc.params:
                continue
            self._ipa.callers.setdefault(callee.ref, set()).add(self._cur_ref)
            summary = self._ipa.return_summaries.get(callee.ref)
            fields = summary.param_fields.get(callee.proc.params[0][0].name) if summary else None
            if not fields:
                continue
            known = self._ipa.middleware_fields.setdefault((self._file_key, head), {})
            changed = False
            for f, (info, kinds) in fields.items():
                if f not in known:
                    known[f] = (info, set(kinds))
                    changed = True
                elif not known[f][1] <= kinds:
                    known[f] = (known[f][0], known[f][1] & kinds)
                    changed = True
            if not changed:
                continue
            for proc in self.program.procedures.values():
                if any(c.rpartition(".")[0] == head for c, _ in proc.passed_as):
                    self._ipa.dirty.add((self._file_key, proc.name))

    # Filters run before the servlet; what they store on the request is read there (the packs'
    # `[[request_attribute]]`: java/servlet).

    def _request_receiver(self, func_name: str, receiver_type: Optional[str], entry) -> bool:
        """Is `x.m(...)` called on a request of `entry.request_types` (declared type, or a parameter
        declared as one)?"""
        request_types = set(entry.request_types)
        head = func_name.rpartition(".")[0]
        if (receiver_type or "").rsplit(".", 1)[-1] in request_types:
            return True
        proc = self._cur_proc
        if proc is None or not _PLAIN_LOCAL.match(head or "-"):
            return False
        names = [p.name for p, _ in proc.params]
        types = getattr(proc, "param_type_names", None) or []
        return head in names and names.index(head) < len(types) \
            and (types[names.index(head)] or "").rsplit(".", 1)[-1] in request_types

    def _record_request_attribute(self, instr: Call, func_name: str, state: SymbolicState) -> None:
        """`request.setAttribute("tenant", value)` in a servlet Filter with attacker
        data in value: what every `getAttribute("tenant")` in the project reads."""
        entry = next((e for e in self._pack_entries("request_attributes")
                       if func_name.endswith("." + e.set)), None)
        if not self._ipa_summarising or entry is None or len(instr.args) != 2:
            return
        key = instr.args[0][0]
        cls = self.program.class_info.get((self._cur_proc.class_name or "").rsplit(".", 1)[-1]) \
            if self._cur_proc is not None else None
        if not (isinstance(key, ExpConst) and isinstance(key.value, str)) or cls is None \
                or not set(entry.writer_bases) & set(cls.canonical_bases) \
                or not self._request_receiver(func_name, getattr(instr, "receiver_type", None), entry):
            return
        leaves = [(i, k) for i, k in self._arg_taint_leaves(instr.args[1][0], state)
                  if not i.source_var.startswith(self._SEED_PREFIX)]
        if not leaves:
            return
        kinds = set.intersection(*(k for _, k in leaves))
        attrs = self._ipa.request_attributes
        known = attrs.get(key.value)
        if known is None:
            attrs[key.value] = (leaves[0][0], kinds)
        elif not known[1] <= kinds:
            attrs[key.value] = (known[0], known[1] & kinds)
        else:
            return
        self._ipa.dirty.update(self._ipa.attribute_readers)

    def _read_request_attribute(self, exp: Exp, target: str, state: SymbolicState,
                                receiver_type: Optional[str] = None) -> None:
        """`x = request.getAttribute("tenant")`: x carries what a filter stored there."""
        if not isinstance(exp, ExpCall) or len(exp.args) != 1:
            return
        name = self._call_exp_name(exp)
        key = exp.args[0]
        entry = next((e for e in self._pack_entries("request_attributes") if name.endswith("." + e.get)), None)
        if entry is None or not (isinstance(key, ExpConst) and isinstance(key.value, str)) \
                or not self._request_receiver(name, receiver_type, entry):
            return
        if self._ipa_summarising:
            self._ipa.attribute_readers.add(self._cur_ref)
        known = self._ipa.request_attributes.get(key.value)
        if known is None:
            return
        info, kinds = known
        state.add_taint(target, TaintInfo(
            source_kind=info.source_kind, source_var=info.source_var, request=info.request, read=info.read,
            source_location=info.source_location,
            propagation_path=list(info.propagation_path) + [f"request attribute \"{key.value}\""]))
        if kinds:
            state.add_sanitization(target, sorted(kinds))

    def _class_properties(self, class_name: str) -> List[Tuple[ProcRef, Procedure]]:
        """The `@property` methods of the Python class `class_name` names here
        (this file's, or one the imports resolve to)."""
        if not all(_PLAIN_LOCAL.match(p) for p in class_name.split(".")):
            return []
        is_prop = lambda p: any(a.name == "property" for a in p.annotations)
        if class_name in self.program.class_info:
            return [((self._file_key, p.name), p) for p in self.program.procedures.values()
                    if p.class_name == class_name and is_prop(p)]
        if self._project is None or class_name in self.program.procedures:
            return []
        owner = self._project.index.resolve_class(self._file_key, class_name)
        if owner is None:
            return []
        mod = self._project.index.modules.get(owner[0])
        out = []
        for name in (mod.classes.get(owner[1], {}) if mod else {}).values():
            proc = self._project.procedure((owner[0], name))
            if proc is not None and is_prop(proc):
                out.append(((owner[0], name), proc))
        return out

    def _apply_property_sources(self, class_name: str, recv: str, state: SymbolicState) -> None:
        """`ctx = Ctx()` where Ctx has a `@property` returning attacker data: reading
        `ctx.<property>` is a call with no parentheses, so `ctx.<property>` carries it."""
        if (getattr(self.program, "language", "") or "").lower() != "python":
            return
        for ref, proc in self._class_properties(class_name):
            if self._ipa_summarising:
                self._ipa.callers.setdefault(ref, set()).add(self._cur_ref)
            summary = self._ipa.return_summaries.get(ref)
            if summary is None or summary.source is None:
                continue
            key = f"{recv}.{proc.simple_name}"
            info = summary.source
            state.add_taint(key, TaintInfo(
                source_kind=info.source_kind, source_var=info.source_var, request=info.request, read=info.read,
                source_location=info.source_location,
                propagation_path=list(info.propagation_path) + [key]))
            if summary.source_sanitized:
                state.add_sanitization(key, sorted(summary.source_sanitized))

    def _apply_filled_buffers(self, callee: Callee, summary: ReturnSummary, instr: Call,
                              func_name: str, state: SymbolicState) -> None:
        """C/C++: a helper that leaves data in a buffer it was passed (`fill(out, n)` writing
        `out[i]`) leaves it in the caller's buffer too."""
        if not self._is_c_lang or not summary.param_fields:
            return
        for (arg, _), param in zip(instr.args, self._call_params(callee.proc, func_name)):
            filled = summary.param_fields.get(param, {}).get("")
            var = self._sole_var(self._cast_strip(arg)) if filled is not None else None
            if var is None:
                continue
            info, kinds = filled
            state.add_taint(var, TaintInfo(
                source_kind=info.source_kind, source_var=info.source_var, request=info.request, read=info.read,
                source_location=info.source_location,
                propagation_path=list(info.propagation_path) + [f"{callee.ref[1]}({param})"]))
            if kinds:
                state.add_sanitization(var, sorted(kinds))

    def _record_field_entry_taints(self, callee: Callee, instr: Call, func_name: str,
                                   state: SymbolicState) -> None:
        """A method called on an object whose fields carry attacker data starts with
        those fields tainted (`job.go()` after `new Job(v)`). Only while summarising."""
        if not self._ipa_summarising or not callee.proc.is_method:
            return
        if callee.proc.simple_name in self._CONSTRUCTOR_NAMES or func_name.startswith("new "):
            return
        recv = self._call_receiver(callee, instr, func_name)
        if recv is None:
            return
        prefix = recv + "."
        for key in [k for k in state.tainted if k.startswith(prefix)]:
            fld = key[len(prefix):]
            if not _PLAIN_LOCAL.match(fld):
                continue
            leaves = [(i, k) for i, k in self._arg_taint_leaves(ExpVar(PVar(key)), state)
                      if not i.source_var.startswith(self._SEED_PREFIX)]
            if not leaves:
                continue
            sanitized = set.intersection(*(k for _, k in leaves))
            entry = self._ipa.entry_taints.setdefault(callee.ref, {})
            name = f"this.{fld}"
            known = entry.get(name)
            if known is None:
                where = getattr(instr.loc, "line", None)
                caller = f"{self._file_key}:{where} -> " if self._file_key and where else ""
                marker = f"{caller}{callee.ref[0]}::{callee.ref[1]}({name})".lstrip(":")
                self._ipa.entry_markers[marker] = (callee.ref, name)
                info = leaves[0][0]
                entry[name] = (TaintInfo(source_kind=info.source_kind, source_var=info.source_var, request=info.request, read=(),
                                         source_location=info.source_location,
                                         propagation_path=[marker]), sanitized)
                self._ipa.dirty.add(callee.ref)
            elif not known[1] <= sanitized:
                entry[name] = (known[0], known[1] & sanitized)
                self._ipa.dirty.add(callee.ref)

    def _apply_return_summary(self, callee: Callee, summary: ReturnSummary,
                              instr: Call, func_name: str, state: SymbolicState) -> None:
        """The call's result carries what the callee's return does: its own
        source, and the taint of each argument whose parameter reaches the
        return, sanitized as both the caller and the callee left it."""
        if not instr.ret:
            return
        ret_var = str(instr.ret[0])
        leaves: List[Tuple[TaintInfo, Set[str]]] = []
        if summary.source is not None:
            leaves.append((summary.source, set(summary.source_sanitized or ())))
        params = self._call_params(callee.proc, func_name)
        for (arg_exp, _), param in zip(instr.args, params):
            if param in summary.params:
                leaves.extend(self._summary_param_leaves(summary, param, arg_exp, state, at=ret_var))
        for cap in callee.proc.captures:                  # a closure returning an enclosing variable
            if cap in summary.params and cap not in params:
                leaves.extend(self._summary_param_leaves(summary, cap, ExpVar(PVar(cap)), state, at=ret_var))
        if not leaves:
            return
        info = leaves[0][0]
        state.add_taint(ret_var, TaintInfo(
            source_kind=info.source_kind, source_var=info.source_var, request=info.request, read=info.read,
            source_location=info.source_location,
            propagation_path=list(info.propagation_path) + [ret_var]))
        sanitized = set.intersection(*(k for _, k in leaves))
        if sanitized:
            state.add_sanitization(ret_var, sorted(sanitized))

    def _summary_inline_sanitized(self, exp: Exp) -> Dict[str, Set[str]]:
        """Variables inside same-file calls in `exp`, with the sink kinds the
        call's return is sanitized for on the way from them (every kind, when
        the argument does not reach the return at all)."""
        out: Dict[str, Set[str]] = {}
        if not self._ipa_on:
            return out

        def walk(e: Exp) -> None:
            if isinstance(e, ExpCall):
                name = self._call_exp_name(e)
                callee = self._resolve_callee(name)
                summary = self._ipa.return_summaries.get(callee.ref) if callee else None
                if summary is not None:
                    for arg, param in zip(e.args, self._call_params(callee.proc, name)):
                        kinds = summary.params.get(param, self._ALL_SINK_KINDS)
                        for v in self._get_exp_vars(arg):
                            out[v] = (out[v] & set(kinds)) if v in out else set(kinds)
                for a in e.args:
                    walk(a)
            elif isinstance(e, ExpBinOp):
                walk(e.left)
                walk(e.right)
            elif isinstance(e, ExpUnOp):
                walk(e.operand)
            elif isinstance(e, ExpStringConcat):
                for part in e.parts:
                    walk(part)
            elif isinstance(e, (ExpFieldAccess, ExpIndex)):
                walk(e.base)
        walk(exp)
        return out

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

        self._seed_request_proxies(proc, state)
        # Parameters a same-file call passes attacker data (`_record_entry_taints`).
        entry = self._ipa.entry_taints.get((self._file_key, proc.name), {})
        params = {p.name for p, _ in proc.params}
        for param_name, (info, sanitized) in entry.items():
            names = [param_name]
            if param_name.startswith("this."):        # a receiver field (_record_field_entry_taints)
                fld = param_name[len("this."):]
                names += [f"self.{fld}", f"this->{fld}"]
                # Java, C# and C++ read a field by its bare name (unless a parameter shadows it).
                if fld not in params and self.program.language in ("java", "csharp", "cpp"):
                    names.append(fld)
            for name in names:
                state.add_taint(name, info)
                if sanitized:
                    state.add_sanitization(name, sorted(sanitized))
        # A handler registered on an app (`app.get(path, handler)`) receives the request
        # fields that app's middleware set (`_record_middleware`).
        if proc.params and proc.passed_as:
            req = proc.params[0][0].name
            for callee, _ in proc.passed_as:
                head = callee.rpartition(".")[0]
                for fld, (info, kinds) in self._ipa.middleware_fields.get((self._file_key, head), {}).items():
                    state.add_taint(f"{req}.{fld}", info)
                    if kinds:
                        state.add_sanitization(f"{req}.{fld}", sorted(kinds))
        # While summarising, every other parameter carries a seed taint, so the
        # return summary learns which parameters reach the return whether or
        # not a caller has passed attacker data yet. Seeds are never reported
        # (summary-phase checks are discarded) nor passed on as entry taint.
        if self._ipa_summarising:
            for param, _ in proc.params:
                if param.name in entry or param.name in ("self", "cls", "this"):
                    continue
                marker = f"{self._file_key}::{proc.name}({param.name})"
                self._ipa.entry_markers[marker] = ((self._file_key, proc.name), param.name)
                state.add_taint(param.name, TaintInfo(
                    source_kind=TaintKind.USER_INPUT, source_var=self._SEED_PREFIX + marker,
                    source_location=proc.loc or Location.unknown(),
                    propagation_path=[marker]))

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
        self._state = state           # request-object reads resolve against it (_request_path)
        try:
            return self._execute_instr_in(instr, state, proc_name)
        finally:
            self._state = None

    def _execute_instr_in(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        if self._ipa_summarising and self._capture_children:
            self._record_capture_taints(instr, state)
        checks = []
        weak_before = self._weak_random_vars(state)

        # A same-file call nested in an expression (`os.system(f(x))`, `return
        # g(h(y))`) has no Call instruction of its own; it still passes its
        # arguments' taint to the callee.
        if self._ipa_on:
            self._record_nested_entry_taints(instr, state)

        # Heap-lifecycle deref checks (CWE-416 use-after-free, CWE-476 null
        # dereference) run over EVERY instruction before it executes, because a
        # dereference is not always a Load/Store: `int x = *p` is an Assign whose
        # value expression derefs p, and `f(*p)` derefs p inside a call argument.
        # Reading the state as it stands before the instruction reflects the
        # frees and null assignments that preceded this point. Kept in a separate
        # list because several dispatch arms below rebind `checks` wholesale.
        lifecycle_checks = self._lifecycle_deref_checks(instr, state, proc_name)

        # Numeric/value defects (CWE-457 use of an uninitialized variable, CWE-369
        # divide by zero) also read the pre-instruction state, and the uninit pass
        # additionally UPDATES the reaching-definition facts for this instruction.
        # Both run before the dispatch, which only mutates the state in place.
        numeric_checks = self._uninit_checks(instr, state, proc_name)
        numeric_checks += self._divzero_checks(instr, state, proc_name)
        # A tainted array index with no path guard below the array bound is the
        # classic out-of-bounds write/read. Reads the pre-instruction taint and
        # path condition, like the divide check above.
        numeric_checks += self._tainted_index_checks(instr, state, proc_name)
        numeric_checks += self._tainted_format_overflow_checks(instr, state, proc_name)
        numeric_checks += self._cookie_header_checks(instr, state, proc_name)
        numeric_checks += self._unpredictable_arg_checks(instr, state, proc_name)
        # A copy/fill of a compile-time-constant size into a buffer whose capacity
        # is also a compile-time constant: provably out of bounds, taint-free.
        numeric_checks += self._constant_copy_overflow_checks(instr, proc_name)

        if isinstance(instr, Assign):
            assign_checks, state = self._exec_assign(instr, state, proc_name)
            checks.extend(assign_checks)
            self._taint_from_embedded_sources(instr, state)

        elif isinstance(instr, Load):
            checks, state = self._exec_load(instr, state, proc_name)

        elif isinstance(instr, Store):
            checks, state = self._exec_store(instr, state, proc_name)

        elif isinstance(instr, Alloc):
            state = self._exec_alloc(instr, state)

        elif isinstance(instr, Free):
            checks, state = self._exec_free(instr, state, proc_name)

        elif isinstance(instr, Call):
            self._client_receiver = None
            called = self._request_call(instr.get_full_name(), state, [a for a, _ in instr.args])
            receiver = self._client_receiver
            # a method of a request object: the request type says what it returns, not a source
            # row its name suffix-matches (`request.session.get` is not Flask's `session.get`)
            self._spec_sources_off = called is not self._NOT_REQUEST
            try:
                checks, state = self._exec_call(instr, state, proc_name)
            finally:
                self._spec_sources_off = False
            if receiver and instr.ret and receiver in state.tainted and not state.is_tainted(str(instr.ret[0])):
                # a method of a request's client data (`request.query.get("k")`, a dict / str method)
                # returns data derived from it, whatever library row its name suffix-matches
                spec = self.program.spec_for_call(instr)
                if not (spec and spec.is_taint_sanitizer()):
                    info, ret = state.tainted[receiver], str(instr.ret[0])
                    state.tainted[ret] = TaintInfo(info.source_kind, receiver, info.source_location,
                                                   list(info.propagation_path) + [ret], read=info.read)
            if called is not self._NOT_REQUEST and instr.ret:
                # a method of a request object: its result is what the request type says, never the
                # request object itself (default receiver propagation would make it one)
                ret = str(instr.ret[0])
                if called:
                    state.tainted[ret] = TaintInfo(
                        state.tainted[called].source_kind, called, state.tainted[called].source_location,
                        list(state.tainted[called].propagation_path) + [ret])
                elif self._is_request_value(ret, state):
                    state.tainted.pop(ret, None)

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

        destination_checks = self._unpredictable_destination_checks(instr, weak_before, state, proc_name)
        return lifecycle_checks + numeric_checks + checks + destination_checks, state

    def _weak_random_calls_in(self, exp: Exp) -> List[Tuple[str, str]]:
        """Generator calls written inside an expression, at any depth of a call chain
        (`Math.random().toString(36).slice(2)`), as (name, kind)."""
        out = []
        for sub in self._walk_exp(exp):
            if isinstance(sub, ExpCall):
                name = self._call_exp_name(sub)
                spec = self._spec_of_name(name) if name else None
                if spec is not None and spec.is_source == TaintKind.WEAK_RANDOM.value:
                    out.append((name, spec.is_source))
        return out

    def _weak_random_vars(self, state: SymbolicState) -> Set[str]:
        return {v for v, info in state.tainted.items()
                if info.source_kind == TaintKind.WEAK_RANDOM and not info.source_var.startswith(self._SEED_PREFIX)}

    def _unpredictable_destination_checks(self, instr: Instr, weak_before: Set[str], state: SymbolicState,
                                          proc_name: str) -> List[VulnerabilityCheck]:
        """CWE-338 by destination: weak-random data written to something whose name says it must
        be unpredictable (`specs/data/unpredictable.toml` [destinations]): a variable, field or
        buffer (`token`, `session.csrf_token`, `nonce[i]`), or, in a function so named
        (`new_session_token`), one of its parameters (a C out-parameter) or its return value.
        Only a write made by this instruction counts, so each is reported where it happens."""
        out: List[VulnerabilityCheck] = []
        written = self._weak_random_vars(state) - weak_before
        for var in sorted(written):
            root = var.split(".", 1)[0]
            if must_be_unpredictable(var) or (self._unpredictable_output and root in self._param_names):
                check = self._create_taint_check(instr, state, proc_name, var, SinkKind.UNPREDICTABLE)
                check.description = (f"Predictable value: '{var}' must be unpredictable but holds output "
                                     f"of a non-cryptographic random generator")
                out.append(check)
        if isinstance(instr, Return) and self._unpredictable_output and instr.value is not None:
            description = (f"Predictable value: {proc_name} returns output of a non-cryptographic "
                           f"random generator as its result")
            for var in self._get_exp_vars(instr.value):
                info = state.get_taint_info(var) if state.is_tainted(var) else None
                if info is not None and info.source_kind == TaintKind.WEAK_RANDOM \
                        and not info.source_var.startswith(self._SEED_PREFIX):
                    check = self._create_taint_check(instr, state, proc_name, var, SinkKind.UNPREDICTABLE)
                    check.description = description
                    out.append(check)
                    break
            else:
                # `return Math.random().toString(36)`: the generator call written in the result
                for func, kind in self._weak_random_calls_in(instr.value):
                    if kind == TaintKind.WEAK_RANDOM.value:
                        out.append(VulnerabilityCheck(
                            formula=And(Source(Var(func), kind), Sink(Var(func), SinkKind.UNPREDICTABLE.value)),
                            vuln_type=VulnType.from_sink_kind(SinkKind.UNPREDICTABLE),
                            location=instr.loc or Location.unknown(), description=description,
                            source_var=func, source_location=instr.loc or Location.unknown(),
                            sink_type=SinkKind.UNPREDICTABLE.value, procedure_name=proc_name,
                            source_kind=kind))
                        break
        return out

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

        if self._is_c_lang:
            self._note_overflow_candidates(instr, state, proc_name)
        if self._is_c_lang and _PLAIN_LOCAL.match(target):
            if _LITERAL_BRACE_LIST.match(str(instr.exp).strip()):
                self._literal_tables.add(target)
            else:
                self._literal_tables.discard(target)
        # A strong update: assigning a plain local replaces its value, so what it held
        # before (taint, sanitization, asserted safety) is gone unless the new value
        # reads it (`x = x + y`). `if (bad(next)) next = "/home";` leaves next clean.
        # Fields and elements are left alone: the name may stand for more than one
        # location.
        if _PLAIN_LOCAL.match(target) and target not in source_vars:
            state.tainted.pop(target, None)
            state.sanitized.pop(target, None)
            state.asserted_safe.pop(target, None)
        # Whatever constant it held is stale now (`i = i + 1`); a literal sets a new one below.
        state.constants.pop(target, None)
        state.nonconst.add(target)
        if self._ipa_on:
            self._accumulate_store(target, instr.exp, state)
        if isinstance(instr.exp, ExpVar) and str(instr.exp.var) in getattr(self, "_value_class", {}):
            self._value_class[target] = self._value_class[str(instr.exp.var)]
        # A copy of an object carries the taint of its fields (`job = $job_1`), and
        # only those: whatever fields the target held before are replaced.
        if isinstance(instr.exp, ExpVar) and _PLAIN_LOCAL.match(target):
            prefix = str(instr.exp.var) + "."
            for key in [k for k in state.tainted if k.startswith(target + ".")]:
                del state.tainted[key]
                state.sanitized.pop(key, None)
            for key in [k for k in state.tainted if k.startswith(prefix)]:
                copy = target + key[len(prefix) - 1:]
                state.tainted[copy] = state.tainted[key]
                if key in state.sanitized:
                    state.sanitized[copy] = list(state.sanitized[key])
        # `job = new Job(v)` written as one assignment (JS): the fields the
        # constructor stores v into.
        if self._ipa_on and isinstance(instr.exp, ExpCall) and _PLAIN_LOCAL.match(target):
            name = self._call_exp_name(instr.exp)
            callee = self._resolve_callee(name) or self._resolve_constructor(name)
            summary = self._ipa.return_summaries.get(callee.ref) if callee is not None else None
            if summary is not None and summary.stores:
                self._apply_field_stores(
                    callee, summary,
                    Call(loc=instr.loc, ret=(PVar(target), Typ.unknown_type()), func=instr.exp.func,
                         args=[(a, Typ.unknown_type()) for a in instr.exp.args]),
                    name, state)

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
            state.nonconst.discard(target)
        # Detect string constants: bar = "safe string"
        elif (exp_str.startswith('"') and exp_str.endswith('"')) or \
             (exp_str.startswith("'") and exp_str.endswith("'")):
            state.set_constant(target, exp_str[1:-1])
            state.nonconst.discard(target)

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

        # A conditional value: the branch the condition takes when it folds over the
        # constants this path knows, else either branch (never the condition itself).
        if isinstance(instr.exp, ExpTernary):
            taken = self._fold_condition(instr.exp.condition, state)
            # truthiness, as both C (`1 ? a : b`) and Python (`a if "" else b`) read a condition
            branches = [instr.exp.true_exp, instr.exp.false_exp] if taken is None \
                else [instr.exp.true_exp] if taken else [instr.exp.false_exp]
            if len(branches) == 1:
                return self._exec_assign(Assign(loc=instr.loc, id=instr.id, exp=branches[0]), state, proc_name)
            leaves = sorted((v for b in branches for v in self._get_exp_vars(b) if state.is_tainted(v)),
                            key=lambda v: state.tainted[v].source_kind == TaintKind.WEAK_RANDOM)
            if leaves:
                state.propagate_taint(leaves[0], target)
                common = set.intersection(*(set(state.sanitized.get(v, [])) for v in leaves))
                if common:
                    state.sanitized[target] = sorted(common)
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

        # Propagate taint from any tainted source. The pointer a size-only
        # allocator (malloc/calloc/alloca) returns is fresh memory, not data derived
        # from its size argument, so it does not inherit that argument's taint.
        if not self._is_size_only_alloc(instr.exp):
            tainted_srcs = [v for v in source_vars if state.is_tainted(v)]
            if tainted_srcs:                   # one source; attacker data before a weak random number
                state.propagate_taint(min(tainted_srcs, key=lambda v: state.tainted[v].source_kind
                                          == TaintKind.WEAK_RANDOM), target)

        # After the receiver's own taint: a request attribute a Filter stored.
        if self._ipa_on and isinstance(instr.exp, ExpCall):
            self._read_request_attribute(instr.exp, target, state)

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
        # `/` joins paths only for Python's pathlib; in every other language
        # (and for Python numbers) it is division.
        exp_str = str(instr.exp)
        is_path_division = (
            getattr(self.program, "language", "") == "python" and ' / ' in exp_str
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
                spec = self._spec_of_name(func_name)
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
                # A kind this table does not list but SinkKind knows (integer_overflow,
                # buffer_overflow, memory, ...) must keep its own identity; only a
                # genuinely unknown kind falls back to EVAL.
                sink_enum = sink_kind_map.get(sink_kind) or resolve_sink_kind(
                    sink_kind, default=SinkKind.EVAL)
                check = self._create_taint_check(
                    instr, state, proc_name,
                    tainted_var, sink_enum
                )
                check.sink_call = str(func_name).strip('"')
                checks.append(check)

        # Check for property assignment sinks
        # E.g., sqlComm.CommandText = "SELECT ... " + userInput
        # The property name (CommandText) may be a registered sink. Not in
        # Python: its sink specs are all calls, and an attribute named like one
        # (`response.raw = resp`) is not Django's `Manager.raw()`.
        lang = (getattr(self.program, "language", "") or "").lower()
        if '.' in target and lang != "python":
            # Extract property name (last part after .)
            prop_name = target.split('.')[-1]
            spec = self._spec_of_name(prop_name)
            if spec and spec.is_taint_sink():
                sink_kind_str = spec.is_sink
                # Through the alias map like every other sink: a hand-rolled
                # table with a SQL fallback reported unlisted kinds as SQLi.
                sink_enum = resolve_sink_kind(sink_kind_str)

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
                    if self._inline_kind_mismatch(source_kind_str, sink_kind_str):
                        continue
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

        # C/C++: `buf[i] = v` / `*(buf + i) = v` puts v's bytes in the buffer, so the buffer
        # carries v's taint (a weak update: what it held before stays). A source call inside
        # the stored value counts too (`tok[i] = charset[rand() % 16]`).
        if self._is_c_lang:
            base = self._store_buffer(instr.addr)
            if base is not None:
                info = next((state.get_taint_info(v) for v in value_vars if state.is_tainted(v)), None)
                if info is None:
                    found = self._get_embedded_source_calls(instr.value)
                    if found:
                        func, kind = found[0]
                        info = TaintInfo(
                            source_kind=TaintKind(kind) if kind in {t.value for t in TaintKind} else TaintKind.USER_INPUT,
                            source_var=func, source_location=instr.loc or Location.unknown())
                held = state.get_taint_info(base) if state.is_tainted(base) else None
                if info is not None and (held is None or held.source_var.startswith(self._SEED_PREFIX)):
                    state.add_taint(base, info)

        return checks, state

    def _field_chains(self, exp: Exp) -> List[str]:
        """Every dotted path `v.a.b` (and its prefixes `v.a`) written in `exp`."""
        out: List[str] = []

        def chain(e) -> Optional[str]:
            if isinstance(e, ExpVar):
                return str(e.var)
            if isinstance(e, ExpFieldAccess):
                base = chain(e.base)
                return f"{base}.{e.field_name}" if base else None
            return None

        def walk(e):
            if isinstance(e, ExpFieldAccess):
                c = chain(e)
                if c and "." in c:
                    parts = c.split(".")
                    out.extend(".".join(parts[:i]) for i in range(2, len(parts) + 1))
                walk(e.base)
            elif isinstance(e, ExpCall):
                walk(e.func)
                for a in e.args:
                    walk(a)
            elif isinstance(e, ExpBinOp):
                walk(e.left)
                walk(e.right)
            elif isinstance(e, ExpUnOp):
                walk(e.operand)
            elif isinstance(e, ExpStringConcat):
                for part in e.parts:
                    walk(part)
            elif isinstance(e, ExpIndex):
                walk(e.base)
                walk(e.index)
            elif isinstance(e, ExpTernary):
                walk(e.true_exp)
                walk(e.false_exp)
            elif isinstance(e, ExpCast):
                walk(e.exp)
        walk(exp)
        return list(dict.fromkeys(out))

    def _store_buffer(self, addr: Exp) -> Optional[str]:
        """The buffer variable a C store writes into: `buf` for `*(buf + i)`, `buf[i]`, `*buf`."""
        e = self._cast_strip(addr)
        if isinstance(e, ExpUnOp) and e.op == "*":
            e = self._cast_strip(e.operand)
        if isinstance(e, ExpIndex):
            e = self._cast_strip(e.base)
        if isinstance(e, ExpBinOp) and e.op in ("+", "-"):
            e = self._cast_strip(e.left)
        return str(e.var) if isinstance(e, ExpVar) and _PLAIN_LOCAL.match(str(e.var)) else None

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

    def _call_taint_inputs(self, instr: Call, spec, func_name: str) -> List[str]:
        """The variables whose taint reaches a call's result, by the same rules
        _exec_call propagates with: a sanitizer's first argument, a propagator's
        taint_propagates arguments and receiver, or -- for a callee with no spec
        -- every argument and the receiver."""
        args = [self._get_exp_vars(a) for a, _ in instr.args]
        recv = func_name.rsplit('.', 1)[0] if '.' in func_name else None
        if spec is None:
            if self._proc_always_returns_constant(func_name):
                return []
            out = [v for vs in args for v in vs]
            return out + [recv] if recv else out
        out: List[str] = []
        if spec.is_taint_sanitizer() and args:
            out += args[0]
        if spec.propagates_taint():
            for i in spec.taint_propagates:
                if i < len(args):
                    out += args[i]
            if recv and (spec.taint_from_receiver or '.' in func_name):
                out.append(recv)
        return out

    def _call_input_sanitization(self, instr: Call, spec, func_name: str,
                                 state: SymbolicState) -> List[set]:
        """Sanitized kinds of each TAINTED input of the call, snapshotted before
        the call executes. Empty when the call has no result or no tainted input."""
        if not instr.ret:
            return []
        wrapped = self._wrapped_var_kinds([a for a, _ in instr.args])
        return [set(state.sanitized.get(v, [])) | wrapped.get(v, set())
                for v in self._call_taint_inputs(instr, spec, func_name)
                if state.is_tainted(v)]

    def _wrapped_var_kinds(self, exps: List[Exp]) -> Dict[str, Set[str]]:
        """For each variable read inside `exps`, the sink kinds the sanitizer calls
        enclosing it neutralize: `basename(name)` inside `join(base, basename(name))`
        sanitizes `name` for paths even though `name` itself is raw. A variable that also
        appears unwrapped keeps only what every occurrence has (the unwrapped one has none)."""
        out: Dict[str, Set[str]] = {}

        def walk(e: Exp, wrap: frozenset) -> None:
            if isinstance(e, ExpVar):
                v = self._get_var_name(e.var)
                out[v] = (out[v] & set(wrap)) if v in out else set(wrap)
                return
            if isinstance(e, ExpFieldAccess):          # `req.query.name`: the read is tracked under its path
                dotted = self._field_path(e)
                if dotted:
                    out[dotted] = (out[dotted] & set(wrap)) if dotted in out else set(wrap)
            if isinstance(e, ExpCall):
                spec = self._spec_of_name(self._call_exp_name(e))
                inner = wrap | frozenset(spec.is_sanitizer) if spec and spec.is_taint_sanitizer() else wrap
                for a in e.args:
                    walk(a, inner)
                return
            for child in self._walk_children(e):
                walk(child, wrap)

        for e in exps:
            walk(e, frozenset())
        return out

    @staticmethod
    def _walk_children(e: Exp) -> List[Exp]:
        if isinstance(e, ExpBinOp):
            return [e.left, e.right]
        if isinstance(e, ExpUnOp):
            return [e.operand]
        if isinstance(e, ExpStringConcat):
            return list(e.parts)
        if isinstance(e, ExpTernary):
            return [e.true_exp, e.false_exp]
        if isinstance(e, ExpCast):
            return [e.exp]
        if isinstance(e, (ExpFieldAccess, ExpIndex)):
            return [e.base] + ([e.index] if isinstance(e, ExpIndex) else [])
        return []

    def _settle_call_sanitization(self, instr: Call, spec, state: SymbolicState,
                                  input_kinds: List[set]) -> None:
        """A call result is sanitized for a kind only if EVERY tainted input
        reaching it was, plus the callee's own sanitizer kinds.

        propagate_taint unions the sanitized kinds of each input into the
        result, so one sanitized argument -- os.path.basename(p) beside a raw q
        in os.path.join -- would launder the raw ones. The result replaces the
        target's value, so its kinds are recomputed rather than accumulated.
        Kinds are compared through the sink-kind alias map (e.g. 'xxe' ~ 'xml'),
        so inputs sanitized under different names for the same sink still agree.
        """
        ret_var = str(instr.ret[0])
        if not input_kinds or not state.is_tainted(ret_var):
            return
        if spec is not None and spec.is_taint_source():
            return  # a fresh source value; its sanitization is not derived from inputs

        def canon(kinds):
            return {_SINK_KIND_ALIASES.get(k, k) for k in kinds}

        canon_inputs = [canon(k) for k in input_kinds]
        kinds = {k for k in set().union(*input_kinds)
                 if all(_SINK_KIND_ALIASES.get(k, k) in c for c in canon_inputs)}
        if spec is not None:
            kinds |= set(spec.is_sanitizer or [])
        if kinds:
            state.sanitized[ret_var] = sorted(kinds)
        else:
            state.sanitized.pop(ret_var, None)

    def _exec_call(
        self,
        instr: Call,
        state: SymbolicState,
        proc_name: str
    ) -> Tuple[List[VulnerabilityCheck], SymbolicState]:
        """Execute function call"""
        checks = []
        func_name = instr.get_full_name()
        # `TABLE.get(key[, default])` on a constant table: a constant or the default, never the key
        head, _, method = func_name.rpartition(".")
        if method == "get" and instr.args and head in getattr(self.program, "constant_tables", ()):
            instr = dataclasses.replace(instr, args=[(ExpConst(""), instr.args[0][1])] + list(instr.args[1:]))

        # Get specification for this function
        spec = self.program.spec_for_call(instr)
        if spec is None or not (spec.is_taint_sink() or spec.is_taint_source() or spec.is_taint_sanitizer()):
            # storing into a request's server-side session, whatever propagation row the method's
            # name matches (`__setitem__`)
            spec = self._request_session_store(instr, state) or spec
        if self._is_c_lang and spec is not None and spec.size_args:
            self._note_size_arg_candidates(instr, spec, state, proc_name)
        if self._is_c_lang and spec is not None and spec.uses_path is not None:
            self._note_toctou_candidate(instr, state, proc_name)
        if self._is_c_lang and spec is not None and spec.key_args:
            checks.extend(self._hardcoded_key_checks(instr, spec, state, proc_name))
        if spec is not None and spec.digest_of:
            self._apply_digest(instr, spec, state)
        if self._is_c_lang and spec is not None and spec.algorithm_arg is not None \
                and spec.algorithm_arg < len(instr.args):
            checks.extend(self._weak_algorithm_id_checks(instr, spec, state, proc_name))

        # Whose identity the result is: a verified token decoded from the caller's credential
        # (`identity_arg`), or the record a resource selection scoped by the caller returns
        # (`User.query.get(claims["sub"])` is the caller's own user).
        if spec is not None and instr.ret:
            idx, ret_var = spec.identity_arg, str(instr.ret[0])
            token = [info for info, _ in self._arg_taint_leaves(instr.args[idx][0], state)] \
                if idx is not None and idx < len(instr.args) else []
            if token and spec.sink_args == [] and self._usage_sink_applies(spec, instr):
                # decoded with the signature check off: the claims are whatever the token says
                info = token[0]
                state.tainted[ret_var] = TaintInfo(info.source_kind, info.source_var, info.source_location,
                                                   list(info.propagation_path) + [ret_var], read=info.read)
            elif token or (spec.is_sink == "resource_select" and self._resource_select_principal_scoped(instr, state)):
                # a verified token is one the server issued: its claims are the presenter's own identity
                state.tainted[ret_var] = TaintInfo(TaintKind.IDENTITY, ret_var, instr.loc, [ret_var])

        # A call to a procedure of this file: pass its argument taint on, and
        # take the result's taint from the callee's return summary (or, before
        # the callee has one, by default argument->result propagation).
        callee = self._resolve_call_instr(instr, func_name) if self._ipa_on else None
        ipa_instr = instr
        if callee is None and self._ipa_on:
            ext = self._extension_call(instr, func_name) or self._partial_call(instr, func_name)
            if ext is not None:
                callee, ipa_instr = ext
        if callee is None and self._ipa_on and "." not in func_name:
            for wrapped in self._decorated_targets(func_name):     # a decorator's wrapper calling it
                self._record_entry_taints(wrapped, ipa_instr, func_name, state)
        if callee is not None:
            self._record_entry_taints(callee, ipa_instr, func_name, state)
            self._record_field_entry_taints(callee, ipa_instr, func_name, state)
            returned = (getattr(callee.proc, "ret_type_name", None) or "").split("<", 1)[0]
            if instr.ret and returned[:1].isupper():
                self._value_class[str(instr.ret[0])] = (callee.ref[0], returned)
            summary = self._ipa.return_summaries.get(callee.ref)
            if summary is not None:
                self._apply_return_summary(callee, summary, ipa_instr, func_name, state)
                self._apply_field_stores(callee, summary, ipa_instr, func_name, state)
                self._apply_filled_buffers(callee, summary, ipa_instr, func_name, state)
                spec = ProcSpec()
            else:
                spec = None
        elif self._ipa_on:
            self._record_dispatch_entry_taints(instr, func_name, state)
            self._record_overload_entry_taints(instr, func_name, state)
        if self._ipa_on and instr.ret:
            self._apply_property_sources(func_name, str(instr.ret[0]), state)
        if self._ipa_summarising:
            self._record_middleware(instr, func_name, state)
            self._record_request_attribute(instr, func_name, state)

        # Sanitization of the tainted inputs as they stand BEFORE this call runs
        # (the result may overwrite one of them, e.g. q = join(q, basename(p))).
        pre_call_input_kinds = self._call_input_sanitization(
            instr, spec, func_name, state)

        # A sink call nested inside an argument -- the `new FileReader(path)` in
        # `new BufferedReader(new FileReader(path))` -- is evaluated too, though
        # the frontend lowered only the outer call to an instruction.
        for arg_exp, _ in instr.args:
            for _f, inner_kind, tainted_args in self._get_embedded_sink_calls(arg_exp, state):
                for tainted_var in tainted_args:
                    inner = self._create_taint_check(
                        instr, state, proc_name, tainted_var,
                        resolve_sink_kind(inner_kind, default=SinkKind.EVAL))
                    inner.sink_call = str(_f).strip('"')
                    checks.append(inner)

        # C/C++: a taint-source call nested inside an argument -- the `getenv(...)`
        # in `atoi(getenv("X"))` -- never reaches the IR as its own instruction, so
        # its taint would be lost at the point the enclosing call consumes it. If
        # any argument expression contains a call to a known taint source, the
        # value this call returns is derived from attacker input, so its result is
        # tainted. Gated to C/C++ so no other frontend's taint flow shifts.
        if self._is_c_lang and instr.ret and self._arg_has_source_call(instr):
            ret_var = str(instr.ret[0])
            state.add_taint(ret_var, TaintInfo(
                source_kind=TaintKind.USER_INPUT,
                source_var=ret_var,
                source_location=instr.loc,
            ))

        # C/C++ input functions fill a buffer / out-parameter with attacker data
        # (fgets(buf,...), scanf("%d",&n), read(fd,buf,...)); taint the variable
        # each named argument designates (`buf` or `&n`, through casts).
        # A non-cryptographic PRNG filling a buffer (`Random.nextBytes(b)`, `random.shuffle(xs)`) in
        # any language: the buffer holds weak-random data.
        weak_fill = bool(spec and spec.taint_out_args and spec.is_source == TaintKind.WEAK_RANDOM.value)
        if spec and spec.taint_out_args and (self._is_c_lang or weak_fill):
            for idx in spec.taint_out_args:
                if idx >= len(instr.args):
                    continue
                inner = self._cast_strip(instr.args[idx][0])
                if isinstance(inner, ExpUnOp) and inner.op == "&":
                    inner = self._cast_strip(inner.operand)
                out_var = self._sole_var(inner)
                if out_var is not None:
                    state.add_taint(out_var, TaintInfo(
                        source_kind=TaintKind.WEAK_RANDOM if weak_fill else TaintKind.USER_INPUT,
                        source_var=out_var,
                        source_location=instr.loc,
                    ))

        if spec:
            # Handle taint source
            if spec.is_taint_source() and instr.ret and not self._spec_sources_off:
                ret_var = str(instr.ret[0])
                source_kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
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
                    # The spec row says what makes the call weak: an algorithm named by a literal
                    # (`hashlib.new("md5")`, `Cipher.getInstance("DES/...")`; a variable is not
                    # known, so not reported), an explicit off value (`set_cookie(...,
                    # secure=False)`), an unbounded scanf conversion; or the call itself.
                    if self._usage_sink_applies(spec, instr):
                        checks.append(self._create_usage_based_check(instr, state, proc_name, sink_kind))
                else:
                    # Special handling for XML parsers with secure parser argument
                    # xml.dom.minidom.parseString(data, parser) - safe if parser is secure
                    skip_xml_check = False
                    # A parser hardened against external entities (see
                    # _track_xml_hardening) is not an XXE sink for any input.
                    hardened_parser = (
                        sink_kind == SinkKind.XML_PARSE and '.' in func_name
                        and func_name.rsplit('.', 1)[0] in state.secure_parsers)
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

                    if hardened_parser:
                        pass
                    elif skip_xml_check:
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
                                if spec.is_sink in ('redirect', 'ssrf') and self._has_local_redirect_prefix(arg_exp):
                                    continue          # "/p/" + id stays on this origin
                                arg_vars = self._get_exp_vars(arg_exp)
                                # a closure called in the argument hands back what it captured
                                # (`db.query(buildQuery())`), as at a TaintSink
                                arg_vars += [c for c in self._closure_captured_vars(arg_exp, sink_kind)
                                             if c not in arg_vars]
                                arg_str = str(arg_exp)

                                # Check for inline .replace() sanitization in argument
                                import re
                                inline_sanitized_vars = set()
                                inline_sanitized_for = {}  # var -> set of sink types

                                # Spec-based inline sanitizers: a sanitizer call
                                # (per language specs) wrapping a variable inside
                                # the sink argument neutralizes it (e.g. C#'s
                                # HttpUtility.HtmlEncode / Uri.EscapeDataString).
                                for s_func, s_args in self._get_sanitizer_calls(arg_exp):
                                    s_spec = self._spec_of_name(s_func)
                                    if not s_spec or not s_spec.is_taint_sanitizer():
                                        continue
                                    for s_var in s_args:
                                        inline_sanitized_for.setdefault(s_var, set()).update(s_spec.is_sanitizer)
                                for s_var, kinds in self._summary_inline_sanitized(arg_exp).items():
                                    inline_sanitized_for.setdefault(s_var, set()).update(kinds)

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
                                                        self._resource_select_principal_scoped(instr, state):
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
                                                if self._copy_size_sink(func_name, spec.is_sink) and \
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

                                # Inline source CALLS in the sink argument, e.g.
                                # requests.get(request.args.get("u")) inside a
                                # return expression, where the frontend emits the
                                # Call but no TaintSink. Not through a sanitizer
                                # for this sink.
                                for src_func, src_kind in self._get_embedded_source_calls(
                                        arg_exp, sink_kind):
                                    if self._inline_kind_mismatch(src_kind, spec.is_sink):
                                        continue
                                    checks.append(VulnerabilityCheck(
                                        formula=And(Source(Var(src_func), src_kind),
                                                    Sink(Var(src_func), spec.is_sink)),
                                        vuln_type=VulnType.from_sink_kind(sink_kind),
                                        location=instr.loc or Location.unknown(),
                                        description=f"Tainted data from '{src_func}' flows to {spec.is_sink} sink",
                                        source_var=src_func,
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

                was_tainted = {d for d in dest_vars if state.is_tainted(d)}
                tainted_srcs = []
                wrapped: Dict[str, Set[str]] = {}       # `atoi(req)`: what the wrapper sanitizes
                for src_idx in spec.taint_to_dest:
                    if src_idx < len(instr.args):
                        src_exp, _ = instr.args[src_idx]
                        src_vars = self._get_exp_vars(src_exp)
                        wrapper = self._spec_of_name(self._call_exp_name(src_exp)) \
                            if isinstance(src_exp, ExpCall) else None
                        for src_var in src_vars:
                            if state.is_tainted(src_var):
                                tainted_srcs.append(src_var)
                                if wrapper is not None and wrapper.is_taint_sanitizer():
                                    wrapped[src_var] = wrapped.get(src_var, set()) | set(wrapper.is_sanitizer)
                                for dest_var in dest_vars:
                                    state.propagate_taint(src_var, dest_var)
                                    if self.verbose:
                                        print(f"[Translator] Dest taint: {src_var} -> {dest_var}")
                # The buffer is sanitized for what every tainted source was (`snprintf(cmd,
                # .., term)` after a check that term is a constant), and for what it already
                # was when it held tainted data before (`strcat`).
                if tainted_srcs:
                    common = set.intersection(*(set(state.sanitized.get(v, [])) | wrapped.get(v, set())
                                                for v in tainted_srcs))
                    for dest_var in dest_vars:
                        kinds = common & set(state.sanitized.get(dest_var, [])) \
                            if dest_var in was_tainted else set(common)
                        if kinds:
                            state.sanitized[dest_var] = sorted(kinds)
                        else:
                            state.sanitized.pop(dest_var, None)

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
            elif instr.ret and self._literal_table_lookup(func_name):
                # `kTargets.find(key)` in a table of literals: the result is one of its
                # entries (or the end), never the key, so the key's taint stops here.
                pass
            elif instr.ret:
                ret_var = str(instr.ret[0])

                def carries(var: str) -> bool:
                    # a request object handed to an unknown call does not make its result the
                    # request (`request_wrapper(request)` returns a wrapper): only data does
                    return state.is_tainted(var) and state.tainted[var].source_kind != TaintKind.REQUEST
                for arg_exp, _ in instr.args:
                    arg_vars = self._get_exp_vars(arg_exp)
                    for arg_var in arg_vars:
                        if carries(arg_var):
                            state.propagate_taint(arg_var, ret_var)
                            break  # One taint source is enough

                # Also propagate from receiver for method calls
                if '.' in func_name:
                    parts = func_name.rsplit('.', 1)
                    if len(parts) == 2:
                        receiver_var = parts[0]
                        if carries(receiver_var):
                            state.propagate_taint(receiver_var, ret_var)

        if instr.ret:
            self._settle_call_sanitization(
                instr, spec, state, pre_call_input_kinds)

        # Parser factories whose parsers do not expand external entities (parser-hardening.toml)
        if func_name in _parser_hardening().safe_parser_factories:
            if instr.ret:
                ret_var = str(instr.ret[0])
                state.secure_parsers.add(ret_var)
        self._track_xml_hardening(instr, func_name, state)

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
                # alloca() is the exception: its result is stack storage, freed
                # automatically, so it is never leaked and must not be free()d.
                stack_alloc = spec.stack_allocation_size_arg is not None
                state.heap_origin[ret_var] = "stack" if stack_alloc else "heap"
                if self._is_c_lang and not stack_alloc:
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
                    kind = state.alloc_kind.get(freed_var) or self._member_alloc_kind(freed_var)
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

        # A source call written inside the arguments (JS keeps `String(Math.random())` nested; Python
        # and Java hoist theirs): its taint reaches the result by the call's own propagation rules.
        if instr.ret and not state.is_tainted(str(instr.ret[0])):
            sanitizer = bool(spec and spec.is_taint_sanitizer())       # passes its input on, sanitized
            idxs = [0] if sanitizer else range(len(instr.args)) if spec is None else (
                spec.taint_propagates if spec.propagates_taint() else [])
            for i in idxs:
                found = self._get_embedded_source_calls(instr.args[i][0]) if i < len(instr.args) else []
                if found:
                    src, kind = found[0]
                    state.add_taint(str(instr.ret[0]), TaintInfo(
                        source_kind=TaintKind(kind) if kind in {t.value for t in TaintKind} else TaintKind.USER_INPUT,
                        source_var=src, source_location=instr.loc))
                    if sanitizer:
                        state.add_sanitization(str(instr.ret[0]), spec.is_sanitizer)
                    break

        # Default: store return value
        if instr.ret:
            ret_var = str(instr.ret[0])
            state.heap[ret_var] = f"call_{func_name}"
            state.allocated[ret_var] = True
            # Last, so the receiver's own taint does not overwrite it: a request
            # attribute a servlet Filter stored.
            if self._ipa_on:
                self._read_request_attribute(ExpCall(instr.func, [a for a, _ in instr.args]),
                                             ret_var, state, getattr(instr, "receiver_type", None))

        return checks, state

    def _feasibility_guard(self, exp, assume_true):
        """Sound pure formula for assuming `exp` is truthy (assume_true) or falsy on
        an edge. A bare-variable truthiness test has no sound boolean encoding in the
        separation-logic checker (a lone Var is spatial, so Not(Var) is spuriously
        unsatisfiable); model it explicitly as (in)equality against a falsy sentinel
        so both polarities are individually satisfiable and contradict only when the
        same variable is assumed both ways. `!`, `&&` and `||` push the polarity
        down to their operands; comparisons use the normal encoding. Returns None
        if no usable guard can be formed."""
        if isinstance(exp, ExpUnOp) and exp.op == "!":
            return self._feasibility_guard(exp.operand, not assume_true)
        # Push the polarity down through `&&` / `||` (De Morgan) so every leaf,
        # including a bare call-result inside a combinator, gets the sentinel
        # encoding. Otherwise e.g. the false edge of `!ok(s) || bad(s)` becomes
        # `Not(Or(Not(Var), Var))`, which is spuriously UNSAT and silently drops
        # the findings on the continuation of an early-exit guard.
        if isinstance(exp, ExpBinOp) and exp.op in ("&&", "||"):
            left = self._feasibility_guard(exp.left, assume_true)
            right = self._feasibility_guard(exp.right, assume_true)
            if left is None or right is None:
                return None
            return And(left, right) if (exp.op == "&&") == assume_true else Or(left, right)
        # A constant leaf is encoded by its truthiness: the checker reads any
        # Const as true, so `Not(Const(0))` would make the false edge of
        # `a || 0` spuriously UNSAT.
        if isinstance(exp, ExpConst):
            return True_() if bool(exp.value) == assume_true else False_()
        f = self._exp_to_formula(exp)
        if isinstance(f, (Var, ArithExpr)):
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
        self._note_ownership_guard(instr.condition, state)
        return self._exec_prune_in(instr, state)

    def _exec_prune_in(self, instr: Prune, state: SymbolicState) -> Optional[SymbolicState]:
        """
        Execute prune (conditional).

        Returns None if this branch is provably unreachable (dead code).
        This enables constant folding to eliminate false positives in dead branches.

        Note: When multiple Prune instructions are in the same node (both true and false
        branches), we only skip if BOTH branches would be unreachable. Otherwise, we
        let the reachable branch proceed and just skip adding unreachable successor indices.
        """
        # Constant folding over the expression tree and the path's known constants. Only a
        # comparison or a connective counts: a bare literal condition is an opaque name.
        eval_result = None
        if isinstance(instr.condition, (ExpBinOp, ExpUnOp, ExpVar)):
            eval_result = self._fold_condition(instr.condition, state)
            if not isinstance(eval_result, (bool, int, float)):
                eval_result = None

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

        # What the condition proves about its variables (an allowlist, a character-class
        # check, a same-origin test) holds on ONE branch, so for a clean two-way branch the
        # walker applies it to the matching outgoing edge (_apply_branch_guards). Applying it
        # here would hand it to both successors: `if x.isdigit(): pass` followed by a sink
        # would look validated, and the early-return form only worked by accident.
        if not self._branch_node_clean:
            self._apply_branch_guards(state, instr.condition, instr.is_true_branch)
        return state

    def _defining_call(self, var: str) -> Optional[ExpCall]:
        """The call that is `var`'s only definition in this procedure (`u = urlparse(x)`)."""
        proc = self._cur_proc
        if proc is None:
            return None
        assigns, calls = [], {}
        for node in proc.nodes.values():
            for ins in node.instrs:
                if isinstance(ins, Assign) and self._get_var_name(ins.id) == var:
                    assigns.append(ins.exp)
                elif isinstance(ins, Call) and ins.ret:
                    calls.setdefault(str(ins.ret[0]), []).append(ExpCall(ins.func, [a for a, _ in ins.args]))
        # Python lowers `u = f(x)` as the call into `u`'s temporary, then `u = <temporary>`.
        if len(assigns) != 1 or len(calls.get(var, [])) > 1:
            return None
        e = assigns[0]
        if isinstance(e, ExpVar) and len(calls.get(str(e.var), [])) == 1:
            return calls[str(e.var)][0]
        return e if isinstance(e, ExpCall) else None

    def _inline_parsed_urls(self, exp):
        """`u.netloc` -> `urlparse(x).netloc` where `u`'s only definition in the procedure is a
        URL parser call, so a host test on a parsed local reads like the inline form."""
        if isinstance(exp, ExpFieldAccess) and isinstance(exp.base, ExpVar):
            d = self._defining_call(str(exp.base.var))
            if isinstance(d, ExpCall) and self._host_var(ExpFieldAccess(d, exp.field_name, False)):
                return ExpFieldAccess(d, exp.field_name, False)
            return exp
        if isinstance(exp, ExpBinOp):
            return ExpBinOp(exp.op, self._inline_parsed_urls(exp.left), self._inline_parsed_urls(exp.right))
        if isinstance(exp, ExpUnOp):
            return ExpUnOp(exp.op, self._inline_parsed_urls(exp.operand))
        return exp

    def _apply_branch_guards(self, state: SymbolicState, condition, is_true_branch: bool) -> SymbolicState:
        """Record what `condition` proves about its variables on the branch where it
        evaluates to `is_true_branch`: sanitization for the sinks it rules out."""
        # Values proven harmless by the condition: a constant allowlist (`x in ALLOWED`,
        # `ALLOWED.includes(x)`), a character class (`x.isdigit()`, an anchored safe-charset
        # regex), a URL host in an allowlist. Only constant-looking collections count
        # (UPPER_CASE names or literals), never an arbitrary array.
        for var, kinds, holds_when in self._guard_facts(
                self._inline_parsed_urls(condition), getattr(self.program, "constant_regexes", None),
                getattr(self.program, "language", ""), getattr(self.program, "string_macros", None)):
            if holds_when == is_true_branch:
                kinds = set(kinds)
                if self._same_origin_path(kinds):           # `/x` and not `//host`
                    state.asserted_safe.setdefault(var, []).append("redirect")
                kinds = {k for k in kinds if not k.startswith((self._STARTS, self._NOT_STARTS))}
                if self._CONTAINED in kinds:
                    kinds.discard(self._CONTAINED)
                    if self._is_normalized_path(var, state):
                        kinds.add("filesystem")
                if kinds:
                    state.add_sanitization(var, list(kinds))

        return state

    def _exec_taint_source(self, instr: TaintSource, state: SymbolicState) -> SymbolicState:
        """Execute taint source annotation"""
        var_name = self._get_var_name(instr.var)
        state.add_taint(var_name, TaintInfo(
            source_kind=instr.kind,
            source_var=var_name,
            source_location=instr.loc,
            request=getattr(instr, "request", None) if instr.kind == TaintKind.REQUEST else None,
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
        if instr.kind.value in ("redirect", "ssrf") and self._has_local_redirect_prefix(instr.exp):
            return checks, state          # "/products/" + id stays on this origin
        if instr.call and self._ipa_on:
            callee = self._resolve_callee(instr.call)
            if callee is not None and (callee.ref[0] != self._file_key or callee.proc.is_method):
                return checks, state          # the project's own method, analysed on its own
        sink_vars = self._get_exp_vars(instr.exp)
        # A field path the sink reads (`self.options.additional.join(..)`) that carries
        # taint of its own (field stores, constructor-filled fields).
        sink_vars += [c for c in self._field_chains(instr.exp) if c in state.tainted and c not in sink_vars]
        exp_str = str(instr.exp)

        # Usage-based sinks (weak_hash, weak_crypto) don't need taint flow
        # The mere usage of the function is the vulnerability
        usage_based_kinds = {'weak_hash', 'weak_crypto', 'insecure_random',
                             'insecure_cookie', 'insecure_cookie_httponly',
                             'deserialize_unsafe', 'csrf_disabled',
                             'cert_validation'}
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

        inline_sanitized_vars = set()
        inline_sanitized_for = {}  # var -> list of sink types sanitized for

        # Spec-based inline sanitizers: any sanitizer call (from the language
        # specs) wrapping a variable inside the sink expression neutralizes that
        # variable for the sanitizer's sink kinds. This is language-agnostic and
        # covers, e.g., C#'s HttpUtility.HtmlEncode / Uri.EscapeDataString.
        for func_name, arg_vars in self._get_sanitizer_calls(instr.exp):
            spec = self._spec_of_name(func_name)
            if not spec or not spec.is_taint_sanitizer():
                continue
            for arg_var in arg_vars:
                inline_sanitized_for.setdefault(arg_var, set()).update(spec.is_sanitizer)
        for arg_var, kinds in self._summary_inline_sanitized(instr.exp).items():
            inline_sanitized_for.setdefault(arg_var, set()).update(kinds)

        if instr.kind == SinkKind.XML_PARSE and instr.receiver in state.secure_parsers:
            return checks, state  # hardened parser: see _track_xml_hardening

        for var in sink_vars:
            # Skip xml sinks for variables that have been safely processed
            if instr.kind.value == 'xml' and var in state.safe_for_xml_sink:
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
                # A copy length checked on the path (`if (len > MAX) return;`), likewise.
                if self._copy_size_sink(instr.call or "", instr.kind.value) \
                        and self._alloc_size_is_bounded(var, state):
                    continue
                if not state.is_sanitized_for(var, instr.kind.value):
                    if not state.is_asserted_safe_for(var, instr.kind.value):
                        check = self._create_taint_check(
                            instr, state, proc_name,
                            var, instr.kind
                        )
                        checks.append(check)

        # A call to a closure whose return carries a variable it captured from
        # this procedure (`find(searchCriteria())`, `searchCriteria` reading `threshold`).
        for cap in self._closure_captured_vars(instr.exp, instr.kind):
            if (state.is_tainted(cap) and not state.is_sanitized_for(cap, instr.kind.value)
                    and not state.is_asserted_safe_for(cap, instr.kind.value)):
                checks.append(self._create_taint_check(instr, state, proc_name, cap, instr.kind))

        # Check for embedded taint source calls in the sink expression
        # E.g., Process.Start("cmd", "/C " + Console.ReadLine()) - the ReadLine() is a source
        # flowing directly to the sink without going through a variable
        embedded_sources = self._get_embedded_source_calls(instr.exp, instr.kind)
        for func_name, source_kind_str in embedded_sources:
            if self._inline_kind_mismatch(source_kind_str, instr.kind.value):
                continue
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

    def _xml_hardening_receiver(self, func_name: str, args) -> Optional[str]:
        """The object a call hardens against XXE, if it does: a factory/parser
        `setFeature`, `setAttribute`/`setProperty` with a hardening value, or
        `setEntityResolver` with a non-null resolver (which then decides every
        external entity, as Tomcat's WebdavResolver does). The features and attributes are
        `specs/data/parser-hardening.toml` `[xxe]`."""
        if '.' not in func_name:
            return None
        recv, method = func_name.rsplit('.', 1)
        vals = [str(a).strip() for a, _ in args]
        if method == "setFeature" and len(vals) >= 2:
            uri = vals[0].strip('"\'')
            return recv if any(
                uri.endswith(feature) and vals[1].lower() == value
                for feature, value in _parser_hardening().xxe_features.items()) else None
        if method in ("setAttribute", "setProperty") and len(vals) >= 2:
            name = vals[0].strip('"\'')
            return recv if (name.endswith(_parser_hardening().xxe_access_attributes)
                            and vals[1] in ('""', "''")) else None
        if method == "setEntityResolver" and vals:
            return recv if vals[0].lower() not in ("null", "none") else None
        return None

    def _track_xml_hardening(self, instr: Call, func_name: str, state: SymbolicState) -> None:
        """Record parsers that cannot resolve external entities: the receiver
        of a hardening call, the product of a hardened factory, and the result
        of a same-class helper whose every non-null return is hardened."""
        hardened = self._xml_hardening_receiver(func_name, instr.args)
        if hardened:
            state.secure_parsers.add(hardened)
        if not instr.ret:
            return
        ret_var = str(instr.ret[0])
        if '.' in func_name:
            recv, method = func_name.rsplit('.', 1)
            if method in _parser_hardening().xml_parser_products and recv in state.secure_parsers:
                state.secure_parsers.add(ret_var)
                return
        callee = self._same_class_callee(func_name, len(instr.args), instr.arg_types)
        if callee is not None and self._secure_parser_returns.get(callee):
            state.secure_parsers.add(ret_var)

    def _same_class_callee(self, func_name: str, n_args: int,
                           arg_types=None) -> Optional[str]:
        """The procedure an unqualified (or `this.`) call names in the class
        being analysed, if the program defines it; for an overloaded name, the
        one overload the argument count selects."""
        name = func_name[5:] if func_name.startswith("this.") else func_name
        cls = getattr(self._cur_proc, "class_name", None)
        if '.' in name or not cls:
            return None
        if getattr(self.program, "language", "") == "java" and arg_types is not None:
            target = self.program.resolve_java_call(cls, name, list(arg_types))
            return target.name if target is not None else None
        matches = [p.name for p in self.program.procedures.values()
                   if p.class_name == cls and p.simple_name == name
                   and p.accepts_arity(n_args)]
        return matches[0] if len(matches) == 1 else None

    def _record_secure_parser_return(self, instr: Return, state: SymbolicState,
                                     proc_name: str) -> None:
        """Summary for _track_xml_hardening: does every non-null return of
        `proc_name` hand back a hardened parser?"""
        value = instr.value
        if not self._summarising_parsers or value is None \
                or str(value).lower() in ("null", "none"):
            return
        returned = self._sole_var(value)
        secure = returned is not None and returned in state.secure_parsers
        self._secure_parser_returns[proc_name] = (
            self._secure_parser_returns.get(proc_name, True) and secure)

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
        self._record_secure_parser_return(instr, state, proc_name)
        if self._return_acc is not None and instr.value is not None:
            self._accumulate_return(instr.value, state, proc_name)
        if self._ipa_summarising:
            self._accumulate_param_fields(state)
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

    _AUTH_HEADER_NAMES = _principals().credential_headers        # specs/data/principals.toml
    # the caller's own identity (the server's) or credential (theirs): either scopes a selection
    # to the caller's own objects
    _SELF_SCOPED = (TaintKind.IDENTITY, TaintKind.PRINCIPAL)

    def _carries_identity(self, exp: Exp, state: "SymbolicState") -> bool:
        return any(info is not None and info.source_kind in self._SELF_SCOPED
                   for info, _ in self._arg_taint_leaves(exp, state))

    def _note_ownership_guard(self, cond: Exp, state: "SymbolicState") -> None:
        """`if txn.sender_id != current_user.id and ...: abort(403)`: a comparison of an object's
        field with the authenticated caller's identity (or credential) checks the object's owner;
        the object is recorded for this procedure (`_filter_post_hoc_ownership_checks`)."""
        if self._cur_proc is None:
            return
        guarded = self._ownership_guards.setdefault(self._cur_proc.name, set())
        stack = [cond]
        while stack:
            e = stack.pop()
            if isinstance(e, ExpUnOp):
                stack.append(e.operand)
                continue
            if not isinstance(e, ExpBinOp):
                continue
            op = str(getattr(e.op, "value", e.op))
            if op in ("and", "or", "&&", "||"):
                stack.extend((e.left, e.right))
                continue
            if op not in ("==", "!=", "===", "!==", "is", "is not"):
                continue
            for side, other in ((e.left, e.right), (e.right, e.left)):
                if isinstance(side, ExpFieldAccess) and isinstance(side.base, ExpVar) \
                        and not self._carries_identity(side, state) and self._carries_identity(other, state):
                    guarded.add(self._get_var_name(side.base.var))

    def _filter_post_hoc_ownership_checks(self, proc, checks):
        """Drop IDOR checks whose fetched object is validated by a post-hoc
        ownership guard: a conditional that compares the fetched object's field
        against the authenticated caller (e.g.
        `if txn.sender_id != current_user.id and txn.receiver_id != current_user.id: abort(403)`),
        recorded by `_note_ownership_guard` from the taint of the compared values.

        The selection query itself is attacker-parameterized, but the caller's
        access is authorized by the subsequent ownership proof, so it is not an
        object-level authorization flaw. Scoped per procedure.
        """
        idor_checks = [c for c in checks if c.vuln_type == VulnType.IDOR]
        if not idor_checks:
            return checks
        guarded_objects = self._ownership_guards.get(proc.name, set())
        if not guarded_objects:
            return checks

        # Alias map: a call result temp assigned to a named variable.
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

        # Resource-select calls whose result object is guarded -> protected selectors.
        protected = set()
        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call) or not instr.ret:
                    continue
                spec = self.program.spec_for_call(instr)
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

    def _resource_select_principal_scoped(self, instr, state: "SymbolicState") -> bool:
        """True if a resource-selection call is scoped by the authenticated caller: an argument
        (`filter_by(user_id=current_user.id, id=x)`) or the query it is called on carries the
        caller's identity or credential, so it selects the caller's own resource and is not an
        object-level authorization flaw."""
        exps = [a for a, _ in (getattr(instr, "args", None) or [])]
        name = instr.get_full_name().strip('"') if isinstance(instr, Call) else ""
        parts = name.split(".")[:-1]
        if parts and all(p.isidentifier() or p.startswith("$") for p in parts):
            receiver: Exp = ExpVar(PVar(parts[0]))
            for attr in parts[1:]:
                receiver = ExpFieldAccess(receiver, attr)
            exps.append(receiver)
        return any(self._carries_identity(e, state) for e in exps)

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

        check = VulnerabilityCheck(
            formula=formula,
            vuln_type=vuln_type,
            location=instr.loc,
            description=f"Tainted data from '{_display_name(taint_info.source_var) if taint_info else 'unknown'}' "
                       f"flows to {sink_kind.value} sink",
            tainted_var=tainted_var,
            source_var=taint_info.source_var if taint_info else "",
            source_location=taint_info.source_location if taint_info else None,
            sink_type=sink_kind.value,
            procedure_name=proc_name,
            data_flow_path=taint_info.propagation_path if taint_info else [],
            source_kind=taint_info.source_kind.value if taint_info else "",
        )
        # Predictable (weak PRNG) data matters only where a value must be unpredictable,
        # and such a sink only for predictable data: any other pairing is no finding
        # (dropped by translate_procedure).
        weak = taint_info is not None and taint_info.source_kind == TaintKind.WEAK_RANDOM
        if weak != (sink_kind == SinkKind.UNPREDICTABLE):
            check.kind_mismatch = True
        # A request object as a whole is not attacker data: only what its type lists is (read from it
        # by _request_path / _request_call), so the object itself reaching a sink is no finding.
        if taint_info is not None and taint_info.source_kind == TaintKind.REQUEST:
            check.kind_mismatch = True
        # The authenticated caller as the server knows it is not attacker data: it only scopes a
        # resource selection or proves ownership (_resource_select_principal_scoped).
        if taint_info is not None and taint_info.source_kind == TaintKind.IDENTITY:
            check.kind_mismatch = True
        # A number read off the wire is a size, not text: it matters only where it sizes an allocation.
        if taint_info is not None and taint_info.source_kind == TaintKind.WIRE_SIZE \
                and sink_kind != SinkKind.ALLOC_SIZE:
            check.kind_mismatch = True
        # Model output is attacker-steerable, not confidential: it matters at injection sinks,
        # not where a secret or personal data would leak (logs, error pages, responses).
        if taint_info is not None and taint_info.source_kind in (TaintKind.LLM_OUTPUT, TaintKind.RETRIEVED) \
                and sink_kind in self._CONFIDENTIALITY_SINKS:
            check.kind_mismatch = True
        if isinstance(instr, Call):
            check.sink_call = instr.canonical or str(getattr(instr.func, "value", instr.func)).strip('"')
        return check

    _CONFIDENTIALITY_SINKS = frozenset({SinkKind.SENSITIVE_LOG, SinkKind.SENSITIVE_EXPOSURE, SinkKind.SECRET_EXPOSURE,
                                        SinkKind.ERROR_DISCLOSURE, SinkKind.CREDENTIAL, SinkKind.HARDCODED_SECRET})

    def _usage_sink_applies(self, spec, instr) -> bool:
        """Whether a usage sink (no `sink_args`) holds for this call, by the row's fields."""
        args = [a for a, _ in instr.args]
        names = list(getattr(instr, "kwarg_names", None) or [])
        for key, literal in spec.safe_kwargs.items():
            if any(n == key and isinstance(a, ExpConst) and str(a.value) == literal for n, a in zip(names, args)):
                return False
        if spec.algorithm_name_arg is not None:
            if spec.algorithm_name_arg >= len(args):
                return False
            arg = args[spec.algorithm_name_arg]
            return isinstance(arg, ExpConst) and isinstance(arg.value, str) \
                and weak_algorithm(str(spec.is_sink), arg.value) is not None
        if spec.sink_if_arg_literal:
            return any(str(a).strip().strip('"') in spec.sink_if_arg_literal for a in args)
        if spec.sink_if_kwarg:
            entries = getattr(instr, "dict_kwargs", None) or {}
            for key, literal in spec.sink_if_kwarg.items():
                kw, _, inner = key.partition(".")
                if inner and entries.get(kw, {}).get(inner) == literal:
                    return True
                if not inner and any(n == kw and str(getattr(a, "value", a)) == literal for n, a in zip(names, args)):
                    return True
            return False
        if spec.scanf_format_arg is not None:
            return spec.scanf_format_arg < len(args) and self._is_unbounded_scanf_format(args[spec.scanf_format_arg])
        return True

    # Matches an unbounded conversion in a scanf format string: %s / %[ / %ls
    # with no field width (e.g. "%s", "%[^\n]"), but NOT a bounded "%9s".
    _UNBOUNDED_SCANF = re.compile(r'%(?!\d)\*?l?[s\[]')

    def _is_unbounded_scanf_format(self, arg_exp) -> bool:
        """True if a scanf argument is a literal format string with an
        unbounded %s/%[ conversion (the actual buffer-overflow trigger)."""
        if isinstance(arg_exp, ExpConst) and isinstance(arg_exp.value, str):
            return bool(self._UNBOUNDED_SCANF.search(arg_exp.value))
        return False

    _COPY_SIZE_SINKS = _c_facts.library().length_sinks

    def _copy_size_sink(self, func_name: str, kind: str) -> bool:
        """The sink is the length argument of a memory copy (memcpy/memmove/bcopy)."""
        return kind in ("buffer", "buffer_overflow") and func_name.rsplit("::", 1)[-1] in self._COPY_SIZE_SINKS

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

        simple_name = proc.simple_name
        called = instr.get_func_name()
        if instr.receiver is not None:
            called = f"{instr.receiver}.{called}"
        language = getattr(self.program, "language", "") or ""
        # Java: resolve the call the way the compiler does, by argument and
        # parameter types (Program.resolve_java_call), so `h(n - 1)` inside
        # `h(int)` is recursion while `h(s)` there calls `h(String)`. A call the
        # file cannot settle -- an inherited overload could take it -- is not
        # claimed as a self-call.
        if language == "java" and proc.class_name and instr.arg_types is not None:
            if self._strip_self_receiver(called) != simple_name:
                return False
            target = self.program.resolve_java_call(
                proc.class_name, simple_name, list(instr.arg_types))
            return target is proc
        # An overloaded name is a self-call only when this overload is the one
        # the argument count selects (`f(x)` calling `f(x, 0)` is delegation).
        if not proc.accepts_arity(len(instr.args)):
            return False
        # C#: the argument count must at least fit THIS method; an overload
        # with another arity may be inherited and invisible in this file.
        if language in self._IMPLICIT_RECEIVER_LANGUAGES and not self._arity_fits(proc, len(instr.args)):
            return False

        stripped = self._strip_self_receiver(called)
        js = language in ("javascript", "typescript")
        if stripped != called:
            # JS: `this.f()` calls the procedure itself only from a method of a class; in an
            # arrow function or a callback `this` is the enclosing object, not the function.
            if js and not proc.class_name:
                return False
            return stripped == simple_name
        if called != simple_name:
            return False
        # JS: a call the frontend marked as made on some other object (`a.b().f()` is lowered
        # as `f`) is not an unqualified call of this function.
        if js and getattr(instr, "receiver_type", None) is not None:
            return False
        if proc.name == simple_name:
            return True
        language = getattr(self.program, "language", "") or ""
        return language in self._IMPLICIT_RECEIVER_LANGUAGES

    @staticmethod
    def _arity_fits(proc: Procedure, n_args: int) -> bool:
        n = len(proc.params)
        return n_args == n or (proc.has_varargs and n_args >= n - 1)

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

        simple_name = proc.simple_name

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
        if isinstance(exp, ExpUnOp) and exp.op == "-":
            inner = self._constant_index_value(exp.operand, constants)
            return -inner if inner is not None else None
        return None

    # ---- Regions: where a pointer points ---------------------------------------------------
    #
    # `base[i]`, `*(p + i)`, `*p` and the buffer a library call writes or reads are accesses to a
    # REGION at a constant element OFFSET: a fixed local array (whose element count is its bound)
    # or the start of a block an allocator returned (`malloc`, `calloc`, `alloca`, `new[]`;
    # offset 0 is its first element, so anything below is before it; its extent is not used).
    # A pointer is followed through its single definition (`p = buf`, `p = buf + 3`,
    # `p = q - 8`) only when every hop has the region's element type (pointer arithmetic counts
    # elements of the pointer's own type, and the frontend drops casts), and never when its
    # address is taken (a callee may move it). Whether an access is outside is a question for the
    # solver over the path facts (see `_out_of_bounds_checks`, `_tainted_index_checks`).

    def _region_of(self, base: Exp, proc: Procedure,
                   constants: Dict[str, int]) -> Optional[Tuple[str, int, Optional[int]]]:
        """(region, offset, bound): bound is the element count of a fixed array, None for a heap
        or alloca block. None when `base` does not certainly point into one."""
        base = self._cast_strip(base)
        if not isinstance(base, ExpVar):
            return None
        name = str(base.var)
        bounds = proc.fixed_array_bounds or {}
        if name in bounds:                                   # the array itself
            return (name, 0, bounds[name]) if bounds[name] >= 0 else None
        elements = getattr(proc, "element_types", None) or {}
        unit = elements.get(name)
        if not unit:
            return None
        offset, seen = 0, set()
        saved, self._cur_proc = self._cur_proc, proc
        try:
            taken = self._proc_address_taken()
            while True:
                if elements.get(name) != unit:
                    return None
                if name in bounds:
                    return (name, offset, bounds[name]) if bounds[name] >= 0 else None
                if name in seen or name in taken:
                    return None
                seen.add(name)
                d = self._single_def(name)
                d = self._cast_strip(d) if d is not None else None
                if isinstance(d, ExpVar):
                    name = str(d.var)
                elif isinstance(d, ExpBinOp) and d.op in ("+", "-") and isinstance(self._cast_strip(d.left), ExpVar):
                    step = self._constant_index_value(d.right, constants)
                    if step is None:
                        return None
                    offset += step if d.op == "+" else -step
                    name = str(self._cast_strip(d.left).var)
                elif isinstance(d, ExpCall) and isinstance(d.func, ExpConst) \
                        and str(d.func.value).split("::")[-1] in self._BLOCK_ALLOCATORS:
                    return name, offset, None
                else:
                    return None
        finally:
            self._cur_proc = saved

    @property
    def _BLOCK_ALLOCATORS(self) -> FrozenSet[str]:
        return _c_facts.allocators("heap", "stack", "new_array", returning=True) | {"new[]"}

    def _out_of_bounds_access(self, base, index, proc: Procedure,
                              constants: Dict[str, int]) -> Optional[Tuple[str, int, int]]:
        """Is `base[index]` certainly outside its region, with the index a known constant?
        Returns (region, element, bound; bound -1 for a block)."""
        region = self._region_of(base, proc, constants)
        if region is None:
            return None
        name, offset, bound = region
        value = self._constant_index_value(index, constants)
        if value is None:
            return None
        value += offset
        if value >= 0 and (bound is None or value < bound):
            return None
        return name, value, -1 if bound is None else bound

    def _iter_deref_reads(self, exp):
        """Every `*(p + c)`, `*(p - c)` and `*p` read inside an expression, as (p, index)."""
        stack = [exp]
        while stack:
            cur = stack.pop()
            if cur is None:
                continue
            if isinstance(cur, ExpUnOp) and cur.op == "*":
                inner = self._cast_strip(cur.operand)
                if isinstance(inner, ExpBinOp) and inner.op in ("+", "-") and isinstance(inner.left, ExpVar):
                    yield inner.left, (inner.right if inner.op == "+" else ExpUnOp("-", inner.right))
                elif isinstance(inner, ExpVar):
                    yield inner, ExpConst(0)
            for child in (getattr(cur, "__dict__", {}) or {}).values():
                if isinstance(child, Exp):
                    stack.append(child)
                elif isinstance(child, (list, tuple)):
                    stack.extend(c for c in child if isinstance(c, Exp))

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

    def _accesses(self, instr: Instr):
        """Every element access the instruction performs: (base, index, is_write). A store
        through `base + i` / `base - i` / `base[i]` / `p` is a write; a subscript or a
        dereference anywhere a value is read is a read."""
        if isinstance(instr, Store):
            addr = instr.addr
            if isinstance(addr, ExpBinOp) and addr.op in ("+", "-"):
                yield addr.left, (addr.right if addr.op == "+" else ExpUnOp("-", addr.right)), True
            elif isinstance(addr, ExpIndex):
                yield addr.base, addr.index, True
            elif isinstance(addr, ExpVar):
                yield addr, ExpConst(0), True
        for exp in self._iter_instr_exps(instr):
            if isinstance(instr, Store) and exp is instr.addr:
                continue
            for sub in self._iter_read_index_exps(exp):
                yield sub.base, sub.index, False
            for base, index in self._iter_deref_reads(exp):
                yield base, index, False

    def _index_term(self, index: Exp) -> Optional[Formula]:
        """The index as an arithmetic term over variables and integer literals, or None when it
        holds anything else (a call, a field, an element): an opaque term would be an
        unconstrained number, so any question about it would be answered by nothing."""
        def arithmetic(e: Exp) -> bool:
            e = self._cast_strip(e)
            if isinstance(e, ExpVar):
                return True
            if isinstance(e, ExpConst):
                return isinstance(e.value, int) and not isinstance(e.value, bool)
            if isinstance(e, ExpUnOp) and e.op == "-":
                return arithmetic(e.operand)
            if isinstance(e, ExpBinOp) and e.op in ("+", "-", "*"):
                return arithmetic(e.left) and arithmetic(e.right)
            return False
        if not arithmetic(index):
            return None
        f = self._exp_to_formula(self._cast_strip(index))
        return f if isinstance(f, (Var, Const, ArithExpr)) else None

    def _entailed(self, pc: List[Formula], goal: Formula) -> bool:
        """pc |- goal: the facts are satisfiable and contradict `not goal`. `_feasibility_sat`
        answers True when undecided, so an undecided query is never a proof."""
        key = (tuple(str(g) for g in pc), str(goal))
        cache = self.__dict__.setdefault("_entail_cache", {})
        if key not in cache:
            facts = self._build_conjunction(list(pc)) if pc else True_()
            cache[key] = (self._feasibility_sat(facts)
                          and not self._feasibility_sat(And(facts, Not(goal)) if pc else Not(goal)))
        return cache[key]

    # Library calls that write / read a buffer from its first element: name -> [(buffer argument,
    # count argument or None when the call always touches at least one element)].
    _ELEMENT_WRITES = _c_facts.library().element_writes            # specs/data/c-library.toml
    _ELEMENT_READS = _c_facts.library().element_reads

    def _call_element_accesses(self, instr: Instr):
        """(buffer, count, is_write) for the buffers a library call writes or reads from their
        first element (`_ELEMENT_WRITES`, `_ELEMENT_READS`)."""
        if not isinstance(instr, Call):
            return
        name = instr.get_full_name().rsplit("::", 1)[-1]
        args = [a for a, _ in instr.args]
        for table, is_write in ((self._ELEMENT_WRITES, True), (self._ELEMENT_READS, False)):
            for buf_i, n_i in table.get(name, ()):
                if buf_i < len(args) and (n_i is None or n_i < len(args)):
                    yield args[buf_i], (args[n_i] if n_i is not None else None), is_write

    def _out_of_bounds_checks(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """CWE-787 / CWE-125 / CWE-124 / CWE-127: an access certainly outside its region.

        The direction comes from the instruction (a store is a write, a subscript or a
        dereference that is read is a read), the side from the index: below element 0 is
        before the start (124/127), at or past a fixed array's bound is past the end (787/125).
        "Certainly" is decided by the solver: the path facts at the access (the fixpoint of
        `_path_fact_fixpoint`, replayed through the node) must entail `offset + index < 0` or
        `>= bound`. A constant index (one the procedure assigns exactly once) is the simplest
        case and is settled without a query. An index nothing pins down is not evidence."""
        checks: List[VulnerabilityCheck] = []
        if not self._is_c_lang:
            return checks
        constants = self._procedure_constant_ints(proc)
        entry: Optional[Dict[int, List[Formula]]] = None

        def record(is_write: bool, name: str, value, bound: Optional[int], loc, verb: str, below: bool) -> None:
            if below:
                kind = VulnType.OOB_UNDERWRITE if is_write else VulnType.OOB_UNDERREAD
                where = f"before the start of '{name}'"
            else:
                kind = VulnType.OOB_WRITE if is_write else VulnType.OOB_READ
                where = f"past the end of '{name}', which holds {bound} element(s)"
            checks.append(VulnerabilityCheck(
                formula=True_(), vuln_type=kind, location=loc or Location.unknown(),
                description=f"{verb} element {value} of '{name}', {where}",
                sink_type=kind.value, procedure_name=proc.name))

        for node_id, node in proc.nodes.items():
            pc: Optional[List[Formula]] = None
            for idx, instr in enumerate(node.instrs):
                seen = set()
                for base, index, is_write in self._accesses(instr):
                    key = (str(base), str(index), is_write)
                    if key in seen:
                        continue
                    seen.add(key)
                    verb = "Write to" if is_write else "Read of"
                    found = self._out_of_bounds_access(base, index, proc, constants)
                    if found:
                        name, value, bound = found
                        record(is_write, name, value, bound, instr.loc, verb, below=value < 0)
                        continue
                    region = self._region_of(base, proc, constants)
                    term = self._index_term(index) if region is not None else None
                    if term is None or self._constant_index_value(index, constants) is not None:
                        continue
                    if pc is None:
                        if entry is None:
                            entry = self._path_fact_fixpoint(proc)
                        if node_id not in entry:
                            break
                        pc = list(entry[node_id])
                        for prev in node.instrs[:idx]:
                            pc = self._advance_path_facts(pc, prev, ghosts=False)
                    name, offset, bound = region
                    at = ArithExpr("+", term, Const(offset)) if offset else term
                    shown = f"{index}{offset:+d}" if offset else str(index)
                    if self._entailed(pc, Lt(at, Const(0))):
                        record(is_write, name, shown, bound, instr.loc, verb, below=True)
                    elif bound is not None and self._entailed(pc, Ge(at, Const(bound))):
                        record(is_write, name, shown, bound, instr.loc, verb, below=False)
                for buf, count, is_write in self._call_element_accesses(instr):
                    # `memcpy(p, src, n)` with p before its region's start writes there as soon
                    # as it writes anything: the offset is negative and, when the call takes a
                    # count, the path facts entail it is positive.
                    region = self._region_of(buf, proc, constants)
                    if region is None or region[1] >= 0:
                        continue
                    if count is not None:
                        n = self._constant_index_value(self._cast_strip(count), constants)
                        if n is None:
                            term = self._index_term(count)
                            if term is None:
                                continue
                            if pc is None:
                                if entry is None:
                                    entry = self._path_fact_fixpoint(proc)
                                if node_id not in entry:
                                    break
                                pc = list(entry[node_id])
                                for prev in node.instrs[:idx]:
                                    pc = self._advance_path_facts(pc, prev, ghosts=False)
                            if not self._entailed(pc, Gt(term, Const(0))):
                                continue
                        elif n <= 0:
                            continue
                    name, offset, bound = region
                    verb = (f"{instr.get_full_name()} writes" if is_write else f"{instr.get_full_name()} reads")
                    record(is_write, name, offset, bound, instr.loc, verb, below=True)
                if pc is not None:
                    pc = self._advance_path_facts(pc, instr, ghosts=False)
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
                spec = self.program.spec_for_call(instr)
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
                spec = self.program.spec_for_call(instr)
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
                spec = self.program.spec_for_call(instr)
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

    def _apply_digest(self, instr: Call, spec, state: SymbolicState) -> None:
        """`SHA256(raw, n, md)`: the digest is as predictable as its input, so weak-random taint
        in a `digest_of` argument reaches `digest_into` (an argument's buffer, `md + k` included,
        or the result). No other kind crosses a digest."""
        weak = None
        for idx in spec.digest_of:
            if idx < len(instr.args):
                for v in self._get_exp_vars(instr.args[idx][0]):
                    info = state.get_taint_info(v) if state.is_tainted(v) else None
                    if info is not None and info.source_kind == TaintKind.WEAK_RANDOM:
                        weak = v
        if weak is None:
            return
        if spec.digest_into is None:
            targets = [str(instr.ret[0])] if instr.ret else []
        elif spec.digest_into < len(instr.args):
            dest = self._cast_strip(instr.args[spec.digest_into][0])
            if isinstance(dest, ExpUnOp) and dest.op == "&":
                dest = self._cast_strip(dest.operand)
            if isinstance(dest, ExpBinOp) and dest.op in ("+", "-"):
                dest = self._cast_strip(dest.left)
            targets = [self._get_var_name(dest.var)] if isinstance(dest, ExpVar) else []
        else:
            targets = []
        for t in targets:
            state.propagate_taint(weak, t)

    def _hardcoded_key_checks(self, instr: Call, spec, state: SymbolicState,
                              proc_name: str) -> List["VulnerabilityCheck"]:
        """A key argument (`key_args`) that is a literal, or a variable the path shows holds one
        (a string, or a local initialised with a brace list of literals): CWE-321."""
        out = []
        for idx in spec.key_args:
            if idx >= len(instr.args):
                continue
            arg = self._strip_casts(instr.args[idx][0])
            if isinstance(arg, ExpUnOp) and arg.op == "&":
                arg = self._strip_casts(arg.operand)
            literal = isinstance(arg, ExpConst) and isinstance(arg.value, str)
            name = self._get_var_name(arg.var) if isinstance(arg, ExpVar) else None
            if name is not None:
                literal = isinstance(state.get_constant(name), str) or name in self._literal_tables
            if not literal:
                continue
            check = self._create_usage_based_check(instr, state, proc_name, SinkKind.UNPREDICTABLE)
            check.vuln_type = VulnType.HARDCODED_KEY
            check.sink_type = VulnType.HARDCODED_KEY.value
            check.tainted_var = name or ""
            check.description = (f"Hard-coded cryptographic key: {instr.get_full_name()} is given "
                                 f"{'the literal in ' + repr(name) if name else 'a literal'} as its key")
            out.append(check)
        return out

    def _weak_algorithm_id_checks(self, instr: Call, spec, state: SymbolicState,
                                  proc_name: str) -> List["VulnerabilityCheck"]:
        """`CryptCreateHash(prov, CALG_MD5, ...)`: the algorithm argument is a constant naming a
        weak hash (CWE-328) or cipher (CWE-327)."""
        arg = instr.args[spec.algorithm_arg][0]
        name = self._get_var_name(arg.var) if isinstance(arg, ExpVar) else str(arg)
        weak = _weak_algorithms()
        algorithm = weak.windows_alg_ids.get(name)
        if algorithm is None:
            return []
        kind = SinkKind.WEAK_HASH if algorithm in weak.hashes else SinkKind.WEAK_CRYPTO
        check = self._create_usage_based_check(instr, state, proc_name, kind)
        check.description = f"{instr.get_full_name()} selects {name} ({algorithm}), a weak algorithm"
        return [check]

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
        return VulnerabilityCheck(
            formula=NullDeref(Var(addr)),
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

    # =========================================================================
    # Path facts (C/C++)
    #
    # The path condition is a list of pure formulas over program variables that
    # Frame's separation-logic checker decides with Z3. Branch edges add the
    # guard (`_feasibility_guard`); an assignment adds `x == rhs`; a write, a call
    # or a store through a pointer removes every fact it may invalidate. At a
    # join the two incoming conditions are combined as `common & (rest1 | rest2)`.
    # Null-ness is nothing more than the fact `p == nil`, so a CWE-476 is the
    # entailment `pc |- p == nil` -- the same UNSAT query the divide-by-zero
    # check asks about its divisor -- and the finding carries `null_deref(p)` for
    # the incorrectness checker to discharge into a concrete witness.
    # =========================================================================

    # A disjunction at a join is dropped (keeping only the shared facts) once it
    # grows past this many atoms, bounding solver cost on long branch chains.
    _MAX_JOIN_ATOMS = 48

    def _fact_term(self, exp: Exp) -> Optional[Expr]:
        """`exp` as a pure term the solver can reason about: integer and null
        literals, variables, and + - * over them. Anything else is None. Unlike
        `_exp_to_arith` this never substitutes tracked constants, so the result
        depends on the expression alone and can be replayed from any state."""
        exp = self._cast_strip(exp)
        if isinstance(exp, ExpConst):
            if exp.value is None:
                return Const(None)
            if isinstance(exp.value, int) and not isinstance(exp.value, bool):
                return Const(exp.value)
            return None
        if isinstance(exp, ExpVar):
            return Var(self._get_var_name(exp.var))
        if isinstance(exp, ExpBinOp) and exp.op in ("+", "-", "*"):
            left, right = self._fact_term(exp.left), self._fact_term(exp.right)
            if left is None or right is None:
                return None
            return ArithExpr(exp.op, left, right)
        if isinstance(exp, ExpUnOp) and exp.op == "-":
            inner = self._fact_term(exp.operand)
            return None if inner is None else ArithExpr("-", Const(0), inner)
        return None

    def _assignment_fact(self, instr: Instr) -> Optional[Formula]:
        """`x == rhs` for an assignment the solver can model, else None. A bare
        declaration is not an assignment, an array name denotes storage (never
        a value), and `x = x + 1` has no equational reading without SSA."""
        if not isinstance(instr, Assign) or getattr(instr, "is_uninit_decl", False):
            return None
        target = self._get_var_name(instr.id)
        proc = self._cur_proc
        if proc is not None and (target in (proc.fixed_array_bounds or {})
                                 or target in (proc.array_locals or ())):
            return None
        term = self._fact_term(instr.exp)
        if term is None or target in term.free_vars():
            return None
        return Eq(Var(target), term)

    def _havoc_vars(self, instr: Instr, pc: List[Formula]) -> Set[str]:
        """Variables an instruction may change without naming them. A store
        through a pointer may write any local whose address was taken; a call may
        additionally write any non-local (a global, a field) mentioned by a fact.
        Their facts no longer describe the live values."""
        has_call = isinstance(instr, Call) or any(
            isinstance(sub, ExpCall)
            for e in self._iter_instr_exps(instr) for sub in self._walk_exp(e))
        if not has_call and not isinstance(instr, Store):
            return set()
        out = set(self._proc_address_taken())
        if has_call:
            proc = self._cur_proc
            params = {str(p) for p, _ in (proc.params if proc is not None else [])}
            for fact in pc:
                for v in fact.free_vars():
                    if v.endswith(self._UNINIT_GHOST):
                        continue   # definedness is not memory a callee can reach
                    if not (self._is_temp_name(v) or v in params
                            or self._is_declared_local(v)):
                        out.add(v)
        return out

    def _advance_path_facts(self, pc: List[Formula], instr: Instr,
                            ghosts: bool = False) -> List[Formula]:
        """The path condition after `instr`: drop the facts on anything it writes
        or may write, then record the assignment it performs. With `ghosts`, also
        track each declared-without-initializer local's definedness as the fact
        `x#uninit == 1` / `== 0`. A pure function of its arguments, so it can be
        replayed from a merged state."""
        drop = set(instr.get_written_vars()) | self._havoc_vars(instr, pc)
        if ghosts and drop:
            drop |= {v + self._CHECKED_GHOST for v in drop}      # a rewritten path is not the checked one
        if drop and pc:
            pc = self._forget(pc, drop)
        fact = self._assignment_fact(instr)
        if fact is not None:
            pc = list(pc) + [fact]
        pc = list(pc) + self._length_bound_facts(instr)
        if ghosts:
            pc = self._advance_definedness(pc, instr)
            checked = self._checked_path(instr)
            if checked is not None:
                ghost = checked + self._CHECKED_GHOST
                pc = self._forget(pc, {ghost}) + [Eq(Var(ghost), Const(1))]
        return pc

    # CWE-367: `p#checked == 1` after a call that checks the file `p` names (`checks_path`: stat,
    # access), forgotten when p is written. A call that then opens or changes `p` (`uses_path`) is
    # reported when the path facts entail the ghost: the check and the use name the same path and
    # nothing in between gave p another value.
    _CHECKED_GHOST = "#checked"

    def _path_arg(self, instr: Instr, field_name: str) -> Optional[str]:
        if not isinstance(instr, Call) or not self._is_c_lang:
            return None
        spec = self.program.spec_for_call(instr)
        idx = getattr(spec, field_name, None) if spec is not None else None
        if idx is None or idx >= len(instr.args):
            return None
        arg = self._strip_casts(instr.args[idx][0])
        return self._get_var_name(arg.var) if isinstance(arg, ExpVar) else None

    def _checked_path(self, instr: Instr) -> Optional[str]:
        return self._path_arg(instr, "checks_path")

    def _note_toctou_candidate(self, instr: Call, state: SymbolicState, proc_name: str) -> None:
        var = self._path_arg(instr, "uses_path")
        if var is None:
            return
        check = self._create_usage_based_check(instr, state, proc_name, SinkKind.INTEGER_OVERFLOW)
        check.vuln_type = VulnType.TOCTOU
        check.sink_type = VulnType.TOCTOU.value
        check.tainted_var = var
        check.description = (f"Time-of-check to time-of-use race: '{var}' is checked, then "
                             f"{instr.get_full_name()} uses it; the file can change in between")
        self._toctou_candidates.append((getattr(self, "_cur_pos", None), check, var))

    def _length_bound_facts(self, instr: Instr) -> List[Formula]:
        """`n = strlen(buf)` with buf a fixed local array of N elements: the string ends
        inside its storage, so `0 <= n <= N - 1`; through a pointer into the array at element
        k (`_region_of`), `0 <= n <= N - 1 - k`."""
        if not isinstance(instr, Call) or not instr.ret or len(instr.args) != 1:
            return []
        func = instr.func
        name = (str(func.value) if isinstance(func, ExpConst) else str(func)).strip('"').rsplit("::", 1)[-1]
        if name not in ("strlen", "wcslen", "strnlen"):
            return []
        proc = self._cur_proc
        buf = self._sole_var(self._cast_strip(instr.args[0][0]))
        bound = (proc.fixed_array_bounds or {}).get(buf) if proc is not None and buf else None
        offset = 0
        if bound is None and proc is not None and buf:
            constants = getattr(proc, "_const_ints_cache", None)
            if constants is None:
                constants = proc._const_ints_cache = self._procedure_constant_ints(proc)
            region = self._region_of(ExpVar(PVar(buf)), proc, constants)
            if region is not None and region[2] is not None and region[1] >= 0:
                _, offset, bound = region
        if bound is None or bound - offset <= 0:
            return []
        n = Var(str(instr.ret[0]))
        return [Ge(n, Const(0)), Le(n, Const(bound - 1 - offset))]

    # Suffix of the ghost variable that records "this local has no value yet".
    _UNINIT_GHOST = "#uninit"

    def _uninit_decl_vars(self) -> Set[str]:
        """Locals of the current procedure declared without an initializer that
        the CWE-457 analysis tracks. Computed once per procedure."""
        proc = self._cur_proc
        if proc is None:
            return set()
        cached = getattr(proc, "_uninit_decl_cache", None)
        if cached is None:
            cached = set()
            for node in proc.nodes.values():
                for instr in node.instrs:
                    if isinstance(instr, Assign) and getattr(instr, "is_uninit_decl", False):
                        name = self._get_var_name(instr.id)
                        if self._uninit_trackable(name):
                            cached.add(name)
            proc._uninit_decl_cache = cached
        return cached

    def _advance_definedness(self, pc: List[Formula], instr: Instr) -> List[Formula]:
        """Ghost facts for CWE-457: a bare declaration sets `x#uninit == 1`, and
        anything `_uninit_inits` counts as giving x a value sets it to 0."""
        tracked = self._uninit_decl_vars()
        if not tracked:
            return pc
        if isinstance(instr, Assign) and getattr(instr, "is_uninit_decl", False):
            changed = {self._get_var_name(instr.id)} & tracked
            value = 1
        else:
            changed = self._uninit_inits(instr) & tracked
            value = 0
        for v in changed:
            ghost = v + self._UNINIT_GHOST
            pc = self._forget(pc, {ghost}) + [Eq(Var(ghost), Const(value))]
        return pc

    def _forget(self, pc: List[Formula], names: Set[str]) -> List[Formula]:
        """The facts with every atom about `names` forgotten: each such atom is
        replaced by `true` where it occurs positively and `false` under a
        negation, which only ever WEAKENS a fact (an over-approximation of
        `exists names. fact`). Dropping a whole fact instead would also throw away
        everything a disjunction says about unrelated variables -- e.g. that
        `rport` is defined exactly on the branch where `raddr` is set."""
        out: List[Formula] = []
        for fact in pc:
            if not (fact.free_vars() & names):
                out.append(fact)
                continue
            weaker = self._forget_atoms(fact, names, positive=True)
            if not isinstance(weaker, True_):
                out.append(weaker)
        return out

    @classmethod
    def _forget_atoms(cls, f: Formula, names: Set[str], positive: bool) -> Formula:
        if not (f.free_vars() & names):
            return f
        if isinstance(f, And):
            a = cls._forget_atoms(f.left, names, positive)
            b = cls._forget_atoms(f.right, names, positive)
            if isinstance(a, False_) or isinstance(b, False_):
                return False_()
            if isinstance(a, True_):
                return b
            if isinstance(b, True_):
                return a
            return And(a, b)
        if isinstance(f, Or):
            a = cls._forget_atoms(f.left, names, positive)
            b = cls._forget_atoms(f.right, names, positive)
            if isinstance(a, True_) or isinstance(b, True_):
                return True_()
            if isinstance(a, False_):
                return b
            if isinstance(b, False_):
                return a
            return Or(a, b)
        if isinstance(f, Not):
            inner = cls._forget_atoms(f.formula, names, not positive)
            if isinstance(inner, True_):
                return False_()
            if isinstance(inner, False_):
                return True_()
            return Not(inner)
        # An atom about a forgotten name: no longer known either way.
        return True_() if positive else False_()

    @classmethod
    def _formula_atoms(cls, f) -> int:
        if isinstance(f, (And, Or)):
            return cls._formula_atoms(f.left) + cls._formula_atoms(f.right)
        if isinstance(f, Not):
            return cls._formula_atoms(f.formula)
        return 1

    def _join_path_conditions(self, pc1: List[Formula],
                              pc2: List[Formula]) -> List[Formula]:
        """pc1 | pc2 as a fact list: the facts both share, plus one disjunction of
        what is left on each side. If either side has nothing beyond the shared
        facts the disjunction is just those facts. Over-long disjunctions are
        dropped, which only ever weakens the condition (never unsound)."""
        k1 = {str(g) for g in pc1}
        k2 = {str(g) for g in pc2}
        common = [g for g in pc1 if str(g) in k2]
        rest1 = [g for g in pc1 if str(g) not in k2]
        rest2 = [g for g in pc2 if str(g) not in k1]
        if not rest1 or not rest2:
            return common
        disj = Or(self._build_conjunction(rest1), self._build_conjunction(rest2))
        if self._formula_atoms(disj) > self._MAX_JOIN_ATOMS:
            # Widen before giving up: first forget the atoms about memory and
            # call results (fields, globals, `f(x) == 0`), which the next call
            # invalidates anyway, keeping what the branches say about locals.
            # Only if that is still too large keep just the shared facts.
            volatile = {v for g in rest1 + rest2 for v in g.free_vars()
                        if not self._is_stable_name(v)}
            rest1 = self._forget(rest1, volatile)
            rest2 = self._forget(rest2, volatile)
            if not rest1 or not rest2:
                return common
            disj = Or(self._build_conjunction(rest1), self._build_conjunction(rest2))
            if self._formula_atoms(disj) > self._MAX_JOIN_ATOMS:
                return common
        return common + [disj]

    def _is_stable_name(self, name: str) -> bool:
        """A name whose value only this procedure's own writes change: a local,
        a parameter, a temporary, or a definedness ghost. Everything else in a
        fact (a field, a global, the text of a call) is memory a call may reach."""
        if name.endswith(self._UNINIT_GHOST) or self._is_temp_name(name):
            return True
        proc = self._cur_proc
        if proc is not None and name in {str(p) for p, _ in proc.params}:
            return True
        return self._is_declared_local(name)

    def _edge_feasible(self, pc: List[Formula], guard: Formula) -> bool:
        """Can a path whose condition is `pc` take an edge guarded by `guard`?
        Only the facts connected to the guard's variables can contradict it, so
        just those are sent to the solver (the rest of `pc` is satisfiable by
        construction: an unsatisfiable condition is never propagated)."""
        facts = self._connected_facts(guard.free_vars(), pc)
        if not facts:
            return True
        key = (tuple(str(g) for g in facts), str(guard))
        cache = self.__dict__.setdefault("_edge_query_cache", {})
        if key not in cache:
            cache[key] = self._feasibility_sat(self._build_conjunction(facts + [guard]))
        return cache[key]

    @staticmethod
    def _connected_facts(names: Set[str], pc: List[Formula]) -> List[Formula]:
        """The facts reachable from `names` through shared variables, in order."""
        want = set(names)
        chosen: Set[int] = set()
        changed = True
        while changed:
            changed = False
            for i, fact in enumerate(pc):
                if i in chosen:
                    continue
                fv = fact.free_vars()
                if fv & want:
                    chosen.add(i)
                    want |= fv
                    changed = True
        return [pc[i] for i in sorted(chosen)]

    @staticmethod
    def _relevant_facts(var: str, pc: List[Formula]) -> List[Formula]:
        """The facts connected to `var` through shared variables (its cone of
        influence), in path order. Facts on unrelated variables cannot change
        whether the path forces `var`'s value, so they are left out of the query."""
        want = {var}
        chosen: Set[int] = set()
        changed = True
        while changed:
            changed = False
            for i, fact in enumerate(pc):
                if i in chosen:
                    continue
                fv = fact.free_vars()
                if fv & want:
                    chosen.add(i)
                    want |= fv
                    changed = True
        return [pc[i] for i in sorted(chosen)]

    def _provably_null(self, var: str, pc: List[Formula]) -> bool:
        """Does the path condition force `var` to nil? True only when the facts
        about `var` are satisfiable and `var != nil` is UNSATISFIABLE with them.
        The solver is asked through `_feasibility_sat`, which answers True on any
        error or timeout, so an undecided query never yields a finding."""
        if not pc:
            return False
        facts = self._relevant_facts(var, pc)
        if not facts:
            return False
        key = (var, tuple(str(g) for g in facts))
        cache = self.__dict__.setdefault("_null_query_cache", {})
        if key not in cache:
            cond = self._build_conjunction(facts)
            cache[key] = (self._feasibility_sat(cond)
                          and not self._feasibility_sat(
                              And(cond, Neq(Var(var), Const(None)))))
        return cache[key]

    def _path_fact_fixpoint(self, proc: Procedure) -> Dict[int, List[Formula]]:
        """The path condition holding on entry to every node, as a dataflow
        fixpoint over the CFG. Transfer: `_advance_path_facts` per instruction (a
        return or a call that never returns ends the path). Edges: the branch
        guard from `_feasibility_guard`. Join: `_join_path_conditions`. A join
        only ever weakens a node's condition and over-long disjunctions collapse
        to the shared facts, so the iteration terminates; it is also capped."""
        entry: Dict[int, List[Formula]] = {proc.entry_node: []}
        joined_arrivals: Dict[int, Set[Tuple[str, ...]]] = {}
        work = [proc.entry_node]
        budget = 50 * max(len(proc.nodes), 1)
        while work and budget > 0:
            budget -= 1
            node_id = work.pop(0)
            node = proc.nodes.get(node_id)
            if node is None:
                continue
            pc = entry[node_id]
            ended = False
            for instr in node.instrs:
                pc = self._advance_path_facts(pc, instr, ghosts=True)
                if isinstance(instr, Return) or self._is_noreturn_call(instr):
                    ended = True
                    break
            if ended:
                continue
            edge_exp = self._branch_edge_formula(node)
            for idx, succ in enumerate(node.succs):
                arrival = pc
                if edge_exp is not None and idx in (0, 1):
                    guard = self._feasibility_guard(edge_exp, assume_true=(idx == 0))
                    if isinstance(guard, False_):
                        continue   # a constant-false edge (`while (1)` exit) never runs
                    if guard is not None and guard.free_vars():
                        arrival = pc + [guard]
                key = tuple(str(g) for g in arrival)
                seen = joined_arrivals.setdefault(succ, set())
                if key in seen:
                    continue
                seen.add(key)
                if succ not in entry:
                    entry[succ] = arrival
                    work.append(succ)
                    continue
                merged = self._join_path_conditions(entry[succ], arrival)
                if [str(g) for g in merged] != [str(g) for g in entry[succ]]:
                    entry[succ] = merged
                    work.append(succ)
        return entry

    def _confirm_path_candidates(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """Decide this procedure's CWE-476 and CWE-457 candidates against the
        path-fact fixpoint. The facts at each site are replayed from its node's
        entry condition, then:

        * CWE-476 needs the pointer to be provably nil (`pc |- p == nil`);
        * CWE-457 needs SOME feasible path on which the variable is still
          uninitialized (`pc & x#uninit == 1` satisfiable).

        Each finding records the facts it rests on."""
        out: List[VulnerabilityCheck] = []
        entry = self._path_fact_fixpoint(proc)

        def facts_at(pos):
            node_id, idx = pos
            node = proc.nodes.get(node_id)
            if node is None or node_id not in entry:
                return None
            pc = list(entry[node_id])
            for prev in node.instrs[:idx]:
                pc = self._advance_path_facts(pc, prev, ghosts=True)
            return pc

        seen = set()
        for pos, instr, base, proc_name in self._null_candidates:
            if pos is None or ("null", pos, base) in seen:
                continue
            seen.add(("null", pos, base))
            pc = facts_at(pos)
            if pc is None or not self._provably_null(base, pc):
                continue
            check = self._create_null_deref_check(instr, None, proc_name, base)
            check.path_condition = self._relevant_facts(base, pc)
            out.append(check)

        for pos, instr, var, proc_name in self._uninit_candidates:
            if pos is None or ("uninit", pos, var) in seen:
                continue
            seen.add(("uninit", pos, var))
            pc = facts_at(pos)
            if pc is None or not self._maybe_uninitialized(var, pc):
                continue
            check = self._create_uninit_check(instr, None, proc_name, var)
            check.path_condition = [g for g in pc
                                    if not any(v.endswith(self._UNINIT_GHOST)
                                               for v in g.free_vars())]
            out.append(check)

        for pos, check, parts in self._overflow_candidates:
            key = ("range", pos, check.vuln_type, tuple(str(g) for g in parts))
            if pos is None or key in seen:
                continue
            seen.add(key)
            pc = facts_at(pos)
            if pc is None or not self._exceeds_type_range(parts, pc):
                continue
            names = set().union(*(g.free_vars() for g in parts))
            check.path_condition = [g for g in pc if g.free_vars() & names]
            out.append(check)

        for pos, check, var in self._toctou_candidates:
            key = ("toctou", pos, var)
            if pos is None or key in seen:
                continue
            seen.add(key)
            pc = facts_at(pos)
            ghost = Var(var + self._CHECKED_GHOST)
            if not pc or not self._feasibility_sat(self._build_conjunction(pc)) \
                    or self._feasibility_sat(self._build_conjunction(list(pc) + [Neq(ghost, Const(1))])):
                continue
            out.append(check)

        for pos, check, var in self._maybe_null_candidates:
            key = ("null-result", pos, var)
            if pos is None or key in seen:
                continue
            seen.add(key)
            pc = facts_at(pos)
            if pc is None or not self._feasibility_sat(
                    self._build_conjunction(list(pc) + [Eq(Var(var), Const(None))])):
                continue
            check.path_condition = self._relevant_facts(var, pc)
            out.append(check)

        self._null_candidates = []
        self._uninit_candidates = []
        self._overflow_candidates = []
        self._toctou_candidates = []
        self._maybe_null_candidates = []
        return out

    # ---- CWE-190/191/194/195/197: attacker integers leaving the range of their type ------------
    #
    # C/C++ only. Each candidate is a question for the solver: with the path facts and each
    # operand's range (its declared integer type), can the value leave the range that matters?
    #
    # * `*`, `+`, constant `<<` past the maximum of the type the usual arithmetic conversions give
    #   (CWE-190); `-`, `*` below its minimum (CWE-191);
    # * a value assigned to a narrower declared type, outside that type's range (CWE-197);
    # * a signed value passed where the callee takes a size (`size_args`: `memcpy`'s length,
    #   `malloc`'s size), when it can be negative: CWE-194 from a type narrower than `int` (it is
    #   sign-extended), CWE-195 otherwise.
    #
    # Operands are plain variables of a type in `_INT_TYPES` (`Procedure.scalar_types`) or
    # integer literals; a width that depends on the platform (`long`, `size_t`) is not guessed.
    # A guard that keeps the value in range (`if (d < 1000)` before `d * 2`) makes the question
    # unsatisfiable. Weak-random data and IPA seeds are not attacker data here.

    _INT_TYPES = INT_TYPES

    @staticmethod
    def _int_range(bits: int, signed: bool) -> Tuple[int, int]:
        return int_range(bits, signed)

    def _declared_int_type(self, var: str) -> Optional[Tuple[int, bool]]:
        declared = (getattr(self._cur_proc, "scalar_types", None) or {}).get(var)
        return self._INT_TYPES.get(declared or "")

    def _operand_int_type(self, exp: Exp) -> Optional[Tuple[int, bool]]:
        """(bits, signed) after integer promotion, or None when not known."""
        if isinstance(exp, ExpConst) and isinstance(exp.value, int) and not isinstance(exp.value, bool):
            return (32, True) if -(1 << 31) <= exp.value < (1 << 31) else None
        if isinstance(exp, ExpVar):
            t = self._declared_int_type(self._get_var_name(exp.var))
            if t is None:
                return None
            return (32, True) if t[0] < 32 else t
        return None

    def _var_range_facts(self, exps) -> List[Formula]:
        out: List[Formula] = []
        for x in exps:
            if isinstance(x, ExpVar):
                name = self._get_var_name(x.var)
                lo, hi = self._int_range(*self._declared_int_type(name))
                out += [Ge(Var(name), Const(lo)), Le(Var(name), Const(hi))]
        return out

    def _attacker_tainted(self, var: str, state: SymbolicState) -> bool:
        info = state.get_taint_info(var)
        return (state.is_tainted(var) and info is not None
                and info.source_kind not in (TaintKind.WEAK_RANDOM,)
                and not info.source_var.startswith(self._SEED_PREFIX))

    def _range_candidate(self, instr: Instr, state: SymbolicState, proc_name: str, var: str,
                         vuln_type: "VulnType", parts: List[Formula], description: str) -> None:
        check = self._create_taint_check(instr, state, proc_name, var, SinkKind.INTEGER_OVERFLOW)
        check.vuln_type = vuln_type
        check.sink_type = vuln_type.value
        check.description = description
        self._overflow_candidates.append((getattr(self, "_cur_pos", None), check, parts))

    @staticmethod
    def _strip_casts(e: Exp) -> Exp:
        while isinstance(e, ExpCast):
            e = e.exp
        return e

    def _note_overflow_candidates(self, instr: Assign, state: SymbolicState, proc_name: str) -> None:
        stack = [instr.exp]
        while stack:
            e = self._strip_casts(stack.pop())
            if not isinstance(e, ExpBinOp):
                continue
            stack.extend((e.left, e.right))
            left, right = self._strip_casts(e.left), self._strip_casts(e.right)
            if e.op not in ("*", "+", "<<", "-"):
                continue
            lt, rt = self._operand_int_type(left), self._operand_int_type(right)
            if lt is None or rt is None:
                continue
            tainted = [self._get_var_name(x.var) for x in (left, right)
                       if isinstance(x, ExpVar) and self._attacker_tainted(self._get_var_name(x.var), state)]
            if not tainted:
                continue
            if e.op == "<<":
                if not (isinstance(right, ExpConst) and isinstance(right.value, int) and 0 <= right.value < 64):
                    continue
                formula = ArithExpr("*", self._exp_to_formula(left), Const(1 << right.value))
                bits, signed = lt
            else:
                formula = self._exp_to_formula(ExpBinOp(e.op, left, right))
                bits = max(lt[0], rt[0])
                signed = all(t[1] for t in (lt, rt) if t[0] == bits)
            if not isinstance(formula, ArithExpr):
                continue
            lo, hi = self._int_range(bits, signed)
            bounds = self._var_range_facts((left, right))
            if e.op in ("*", "+", "<<"):
                self._range_candidate(instr, state, proc_name, tainted[0], VulnType.INTEGER_OVERFLOW,
                                      bounds + [Gt(formula, Const(hi))],
                                      f"Integer overflow: attacker data in '{tainted[0]}' can take "
                                      f"{e.op} past the maximum of its type ({hi})")
            if e.op in ("*", "-"):
                self._range_candidate(instr, state, proc_name, tainted[0], VulnType.INTEGER_UNDERFLOW,
                                      bounds + [Lt(formula, Const(lo))],
                                      f"Integer underflow: attacker data in '{tainted[0]}' can take "
                                      f"{e.op} below the minimum of its type ({lo})")
        self._note_truncation_candidate(instr, state, proc_name)

    def _note_truncation_candidate(self, instr: Assign, state: SymbolicState, proc_name: str) -> None:
        """`short s = i;` / `char c = (char)i;`: CWE-197 when the attacker value can fall outside
        the narrower declared type of the target."""
        target = self._get_var_name(instr.id)
        to = self._declared_int_type(target)
        value = self._strip_casts(instr.exp)
        if to is None or not isinstance(value, ExpVar):
            return
        src = self._get_var_name(value.var)
        frm = self._declared_int_type(src)
        if frm is None or frm[0] <= to[0] or not self._attacker_tainted(src, state):
            return
        lo, hi = self._int_range(*to)
        v = Var(src)
        self._range_candidate(instr, state, proc_name, src, VulnType.NUMERIC_TRUNCATION,
                              self._var_range_facts((value,)) + [Or(Lt(v, Const(lo)), Gt(v, Const(hi)))],
                              f"Numeric truncation: attacker data in '{src}' can lie outside the range "
                              f"of '{target}' ({lo}..{hi})")

    def _note_size_arg_candidates(self, instr: Call, spec, state: SymbolicState, proc_name: str) -> None:
        """A signed attacker value passed as a size (`spec.size_args`) that can be negative."""
        for idx in getattr(spec, "size_args", None) or ():
            if idx >= len(instr.args):
                continue
            arg = self._strip_casts(instr.args[idx][0])
            if not isinstance(arg, ExpVar):
                continue
            name = self._get_var_name(arg.var)
            t = self._declared_int_type(name)
            if t is None or not t[1] or not self._attacker_tainted(name, state):
                continue
            vt = VulnType.SIGN_EXTENSION if t[0] < 32 else VulnType.SIGNED_TO_UNSIGNED
            self._range_candidate(instr, state, proc_name, name, vt,
                                  self._var_range_facts((arg,)) + [Lt(Var(name), Const(0))],
                                  f"Signed to unsigned: attacker data in '{name}' can be negative where "
                                  f"'{instr.get_full_name()}' takes a size, and becomes a huge value")

    def _exceeds_type_range(self, parts: List[Formula], pc: List[Formula]) -> bool:
        """Can the candidate's condition hold on this path? Undecided (solver error or timeout)
        keeps the candidate, as `_maybe_uninitialized` does."""
        key = tuple(str(g) for g in list(pc) + list(parts))
        cache = self.__dict__.setdefault("_overflow_query_cache", {})
        if key not in cache:
            cache[key] = self._feasibility_sat(self._build_conjunction(list(pc) + list(parts)))
        return cache[key]

    def _maybe_uninitialized(self, var: str, pc: List[Formula]) -> bool:
        """Is there a feasible path here on which `var` has no value yet? The
        whole path condition must be satisfiable together with `var#uninit == 1`.
        `_feasibility_sat` answers True when undecided, which keeps the finding,
        matching the reaching-definition analysis this refines."""
        ghost = Eq(Var(var + self._UNINIT_GHOST), Const(1))
        key = (var, tuple(str(g) for g in pc))
        cache = self.__dict__.setdefault("_uninit_query_cache", {})
        if key not in cache:
            cache[key] = self._feasibility_sat(self._build_conjunction(list(pc) + [ghost]))
        return cache[key]

    def _proc_address_taken(self) -> Set[str]:
        """Locals of the current procedure whose address is taken anywhere (`&x`):
        any callee or pointer write may then change them. Computed once."""
        proc = self._cur_proc
        if proc is None:
            return set()
        cached = getattr(proc, "_address_taken_cache", None)
        if cached is None:
            cached = set()
            for node in proc.nodes.values():
                for instr in node.instrs:
                    cached |= self._addr_taken_vars(instr)
            proc._address_taken_cache = cached
        return cached

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
            # Null-ness is a path fact (`p == nil`), recorded by
            # _advance_path_facts and decided by the solver, not tracked here.
            return
        src = self._sole_var(exp)
        if src is not None:
            if src in state.heap_origin:
                state.heap_origin[target] = state.heap_origin[src]
            if src in state.freed:
                state.freed.add(target)

    # Standard C/C++ library functions that never return to the caller. A call
    # to one ends the current path, so nothing after it on that branch runs.
    _NORETURN_FUNCS = frozenset({
        "__frame_goto__",   # the C frontend's lowering of `goto`
    }) | _c_facts.noreturn()                                         # C: specs/data/c.toml

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
        name = self._strip_self_receiver(name)
        # a pack's [[function]] (flask.abort), or a spec row of the language (sys.exit, process.exit)
        facts = getattr(self.program, "library_facts", None) or {}
        canonical = getattr(instr, "canonical", None)
        fact = facts.get(name) or (facts.get(canonical) if canonical else None)
        spec = self.program.library_specs.get(name)
        return name in self._NORETURN_FUNCS or bool(fact and fact.noreturn) or bool(spec and spec.noreturn)

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

    def _cur_proc_unreliable(self) -> bool:
        """Did the current C/C++ function parse with errors? Its CFG may then be
        missing statements, so path-dataflow defect checks stay silent on it."""
        return bool(getattr(self._cur_proc, "has_parse_errors", False))

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
        if not self._is_c_lang or self._cur_proc_unreliable():
            return checks
        for base in self._iter_deref_bases(instr):
            if base in state.freed:
                checks.append(self._create_uaf_check(instr, state, proc_name, base))
            elif self._provably_null(base, state.feasibility_constraints):
                # Candidate only: decided against the path-fact fixpoint in
                # _confirm_path_candidates.
                self._null_candidates.append(
                    (getattr(self, "_cur_pos", None), instr, base, proc_name))
        checks.extend(self._null_result_deref_checks(instr, state, proc_name))
        return checks

    # ---- CWE-690: dereferencing a result that is null as an ordinary outcome -----------------
    #
    # `returns_null = "normally"` in the c/cpp tables (getenv, fopen, strchr, readdir...): null is
    # one of the function's ordinary results, so its result must be checked before it is read
    # through. A dereference (`*p`, `p->f`, `p[i]`, or a `dereferences` argument of a call such as
    # strlen's) of a variable whose single definition is such a call is a candidate, reported when
    # the path facts allow `p == nil` (`if (!p) return;` before it makes that unsatisfiable). The
    # call written straight into a dereferenced argument (`strlen(getenv("HOME"))`) cannot have
    # been checked. Allocators (`returns_null = "on_exhaustion"`) are not reported.

    def _returns_null_normally(self, call: Exp) -> Optional[str]:
        if not isinstance(call, ExpCall):
            return None
        name = self._call_exp_name(call).rsplit("::", 1)[-1]
        spec = self._spec_of_name(name) if name else None
        return name if spec is not None and spec.returns_null == "normally" else None

    def _null_result_deref_checks(self, instr: Instr, state: SymbolicState,
                                  proc_name: str) -> List[VulnerabilityCheck]:
        checks: List[VulnerabilityCheck] = []
        bases = [b for b in self._iter_deref_bases(instr) if b not in state.freed]
        if isinstance(instr, Call):
            spec = self.program.spec_for_call(instr)
            positions = (spec.dereferences if spec is not None else None) or []
            args = [self._cast_strip(a) for a, _ in instr.args]
            picked = range(len(args)) if -1 in positions else [i for i in positions if i < len(args)]
            for i in picked:
                if isinstance(args[i], ExpVar):
                    bases.append(self._get_var_name(args[i].var))
                else:
                    callee = self._returns_null_normally(args[i])
                    if callee is not None:
                        checks.append(self._null_result_check(instr, proc_name, f"{callee}()", callee))
        for base in dict.fromkeys(bases):
            callee = self._returns_null_normally(self._single_def(base))
            if callee is not None:
                check = self._null_result_check(instr, proc_name, base, callee)
                self._maybe_null_candidates.append((getattr(self, "_cur_pos", None), check, base))
        return checks

    def _null_result_check(self, instr: Instr, proc_name: str, what: str, callee: str) -> VulnerabilityCheck:
        return VulnerabilityCheck(
            formula=NullDeref(Var(what)), vuln_type=VulnType.NULL_RESULT_DEREF, location=instr.loc,
            description=f"'{what}' is read through, but {callee}() returns NULL as an ordinary result "
                        f"and nothing on this path excludes it",
            tainted_var=what, sink_type=VulnType.NULL_RESULT_DEREF.value, procedure_name=proc_name)

    # =========================================================================
    # Numeric / value defects (CWE-457 uninitialized read, CWE-369 divide by zero)
    #
    # Both reason over the same per-path dataflow the rest of the translator
    # threads: CWE-457 over a reaching-definition set (which locals still have no
    # value on this path), CWE-369 over the accumulated path condition fed to
    # Frame's Z3 satisfiability check. C/C++ only; precision is the priority, so
    # each declines to fire wherever the defect cannot be proven.
    # =========================================================================

    def _uninit_aggregate_locals(self) -> Set[str]:
        """Locals that are arrays or aggregates, which the scalar reaching-def
        model does not track: a fixed-size array, or any local ever used as the
        base of a field access (`s.f`). Their storage is addressable and reading
        the name yields an address, not an uninitialized scalar, so tracking them
        would only manufacture false positives. Computed once per procedure."""
        proc = self._cur_proc
        if proc is None:
            return set()
        cached = getattr(proc, "_uninit_aggregates", None)
        if cached is not None:
            return cached
        agg: Set[str] = set(proc.fixed_array_bounds or {}) | set(proc.array_locals or ())
        for node in proc.nodes.values():
            for instr in node.instrs:
                for exp in self._iter_instr_exps(instr):
                    for sub in self._walk_exp(exp):
                        if isinstance(sub, ExpFieldAccess):
                            v = self._sole_var(self._cast_strip(sub.base))
                            if v is not None:
                                agg.add(v)
        proc._uninit_aggregates = agg
        return agg

    def _uninit_trackable(self, name: str) -> bool:
        """Should the reaching-definition analysis track `name`? Only a scalar or
        pointer declared local qualifies; arrays and aggregates are excluded."""
        return bool(name) and name not in self._uninit_aggregate_locals()

    def _collect_value_reads(self, exp: Exp, out: Set[str]) -> None:
        """Variables whose SCALAR VALUE `exp` reads. Address-of (`&x`), the base of
        a field access (`s.f`) and the base of an index (`a[i]`) are not value
        reads: the first takes an address, the other two use the base as storage.
        A dereference (`*p`), a cast, and every arithmetic/logical operand ARE
        value reads of what they contain."""
        if isinstance(exp, ExpVar):
            out.add(str(exp.var))
        elif isinstance(exp, ExpConst):
            return
        elif isinstance(exp, ExpCast):
            self._collect_value_reads(exp.exp, out)
        elif isinstance(exp, ExpUnOp):
            if exp.op == "&":
                return
            self._collect_value_reads(exp.operand, out)
        elif isinstance(exp, ExpBinOp):
            self._collect_value_reads(exp.left, out)
            self._collect_value_reads(exp.right, out)
        elif isinstance(exp, ExpIndex):
            # The base is storage, not a scalar value; the index is a value read.
            self._collect_value_reads(exp.index, out)
        elif isinstance(exp, ExpFieldAccess):
            return
        elif isinstance(exp, ExpTernary):
            self._collect_value_reads(exp.condition, out)
            self._collect_value_reads(exp.true_exp, out)
            self._collect_value_reads(exp.false_exp, out)
        elif isinstance(exp, ExpStringConcat):
            for part in exp.parts:
                self._collect_value_reads(part, out)
        elif isinstance(exp, ExpCall):
            for arg in exp.args:
                if self._arg_may_define(arg, exp.func):
                    continue
                self._collect_value_reads(arg, out)

    # C macros/functions that take a bare aggregate (va_list, jmp_buf) and
    # initialise it: the one place a plain C argument is an out-parameter.
    _C_BARE_OUT_PARAM_CALLS = _c_facts.library().bare_out_params   # specs/data/c-library.toml

    def _arg_may_define(self, arg: Exp, func: Optional[Exp] = None) -> bool:
        """May passing `arg` initialise the variable it names?

        `&x` always may (the callee gets a location). A bare `x` may only in C++,
        where it can bind to a reference out-parameter; in C arguments are passed
        by value, so a bare scalar argument is a READ of x -- the exact shape of
        Juliet's CWE-457 (`int data; printIntLine(data);`). The few C macros that
        take a bare aggregate are exempt."""
        inner = self._cast_strip(arg)
        if isinstance(inner, ExpUnOp) and inner.op == "&":
            return True
        if not isinstance(inner, ExpVar):
            return False
        lang = (getattr(self.program, "language", "") or "").lower()
        if lang != "c":
            return True
        name = ""
        if isinstance(func, ExpConst):
            name = str(func.value)
        elif func is not None:
            name = str(func)
        name = name.strip('"')
        # A function-like macro defined in this file is expanded in place and
        # may assign its arguments (`GET_ADDR(x, ...)`); only a real function
        # call passes a bare variable by value.
        if name in (getattr(self.program, "function_macros", None) or ()):
            return True
        return name in self._C_BARE_OUT_PARAM_CALLS

    def _is_addressable_arg(self, arg: Exp) -> bool:
        """Is a call argument a bare variable `x` or its address `&x` (through
        casts)? Passing one hands the callee a location it may write, so it is
        treated as a possible initialization rather than a value read. A compound
        argument (`x + 1`, `f(x)`) cannot be an out-parameter and IS a value
        read."""
        inner = self._cast_strip(arg)
        if isinstance(inner, ExpVar):
            return True
        if isinstance(inner, ExpUnOp) and inner.op == "&":
            return True
        return False

    def _uninit_value_reads(self, instr: Instr) -> Set[str]:
        """The scalar-value reads an instruction performs, for CWE-457. A write
        target is not a read; a bare-variable or `&var` call argument is treated
        as a possible out-parameter initialization, not a read."""
        reads: Set[str] = set()
        exps: List[Exp] = []
        if isinstance(instr, Assign):
            exps.append(instr.exp)
        elif isinstance(instr, Store):
            exps.append(instr.value)
        elif isinstance(instr, Load):
            exps.append(instr.exp)
        elif isinstance(instr, Return):
            if instr.value is not None:
                exps.append(instr.value)
        elif isinstance(instr, Prune):
            exps.append(instr.condition)
        elif isinstance(instr, TaintSink):
            exps.append(instr.exp)
        elif isinstance(instr, Call):
            for arg, _ in instr.args:
                if self._arg_may_define(arg, instr.func):
                    continue
                exps.append(arg)
            if instr.receiver is not None:
                exps.append(instr.receiver)
        for e in exps:
            self._collect_value_reads(e, reads)
        return reads

    def _addr_taken_vars(self, instr: Instr) -> Set[str]:
        """Every local whose address is taken anywhere in the instruction (`&x`).
        Taking a local's address hands out a location that may be written, so it
        counts as a possible initialization of that local."""
        taken: Set[str] = set()
        for exp in self._iter_instr_exps(instr):
            for sub in self._walk_exp(exp):
                if isinstance(sub, ExpUnOp) and sub.op == "&":
                    v = self._sole_var(self._cast_strip(sub.operand))
                    if v is not None:
                        taken.add(v)
        return taken

    def _uninit_inits(self, instr: Instr) -> Set[str]:
        """Locals this instruction gives a value to, so they leave the
        uninitialized set: a normal (non-declaration) assignment target, a load
        or call result, and any local whose address is taken or that is passed as
        a bare argument to a call (a possible out-parameter)."""
        inits: Set[str] = set(self._addr_taken_vars(instr))
        if isinstance(instr, Assign) and not getattr(instr, "is_uninit_decl", False):
            inits.add(self._get_var_name(instr.id))
        elif isinstance(instr, Load):
            inits.add(str(instr.id))
        elif isinstance(instr, Alloc):
            inits.add(str(instr.id))
        elif isinstance(instr, Call):
            if instr.ret:
                inits.add(str(instr.ret[0]))
            for arg, _ in instr.args:
                if self._arg_may_define(arg, instr.func):
                    inits.add(self._sole_var(self._cast_strip(arg)))
        inits.discard(None)
        return inits

    def _uninit_checks(self, instr: Instr, state: SymbolicState,
                       proc_name: str) -> List[VulnerabilityCheck]:
        """CWE-457: a value-read of a declared local with no reaching definition on
        this path. Also UPDATES the reaching-definition set for this instruction:
        a bare declaration marks its target uninitialized; any real write, an
        address-of, or a bare/`&` call argument marks the target initialized. The
        read check runs against the pre-instruction state, before the update, so a
        read on the right of its own reinitialization is still caught."""
        checks: List[VulnerabilityCheck] = []
        if not self._is_c_lang:
            return checks

        if state.uninitialized and not self._cur_proc_unreliable():
            for v in self._uninit_value_reads(instr):
                if v in state.uninitialized:
                    # Candidate only: the walk merges "maybe uninitialized" as a
                    # set, which cannot see branch correlation. The read is
                    # reported only if the solver finds a feasible path to it on
                    # which v is still uninitialized (_confirm_path_candidates).
                    self._uninit_candidates.append(
                        (getattr(self, "_cur_pos", None), instr, v, proc_name))

        if isinstance(instr, Assign) and getattr(instr, "is_uninit_decl", False):
            target = self._get_var_name(instr.id)
            if self._uninit_trackable(target):
                state.uninitialized.add(target)
        else:
            for v in self._uninit_inits(instr):
                state.uninitialized.discard(v)
        return checks

    def _create_uninit_check(self, instr: Instr, state: SymbolicState,
                             proc_name: str, var: str) -> VulnerabilityCheck:
        return VulnerabilityCheck(
            formula=True_(),
            vuln_type=VulnType.UNINITIALIZED_VAR,
            location=instr.loc,
            description=f"Use of uninitialized variable '{var}': it is read on a "
                        f"path where it has no reaching definition",
            tainted_var=var,
            procedure_name=proc_name,
        )

    def _exp_to_arith(self, exp: Exp, state: SymbolicState) -> Optional[Expr]:
        """A SIL expression as a Frame arithmetic term, with known integer
        constants substituted in. Returns None for anything not purely integer
        arithmetic (a string, a call, a field/index), which keeps the divide check
        from reasoning about values it cannot model."""
        exp = self._cast_strip(exp)
        if isinstance(exp, ExpConst):
            if isinstance(exp.value, bool):
                return None
            if isinstance(exp.value, int):
                return Const(exp.value)
            return None
        if isinstance(exp, ExpVar):
            name = str(exp.var)
            cv = state.constants.get(name)
            if isinstance(cv, int) and not isinstance(cv, bool):
                return Const(cv)
            return Var(name)
        if isinstance(exp, ExpBinOp):
            op_map = {"+": "+", "-": "-", "*": "*", "/": "div", "%": "mod"}
            mapped = op_map.get(exp.op)
            if mapped is None:
                return None
            left = self._exp_to_arith(exp.left, state)
            right = self._exp_to_arith(exp.right, state)
            if left is None or right is None:
                return None
            return ArithExpr(mapped, left, right)
        if isinstance(exp, ExpUnOp) and exp.op == "-":
            inner = self._exp_to_arith(exp.operand, state)
            return None if inner is None else ArithExpr("-", Const(0), inner)
        return None

    def _divisor_provably_zero(self, divisor: Exp, state: SymbolicState) -> bool:
        """Is the divisor forced to zero on this path? True only when
        `divisor != 0` is UNSATISFIABLE (a literal 0, a variable the path pins to
        0, or an expression like `x - x`), conjoined with the path condition. An
        unconstrained divisor keeps `divisor != 0` satisfiable and is never
        flagged, so an ordinary `a / b` cannot fire. The path condition alone is
        checked feasible first, so an UNSAT there is not misattributed to the
        divisor. `_feasibility_sat` is conservative (True on any error), so a
        divisor is called zero only on a genuine, provable UNSAT."""
        term = self._exp_to_arith(divisor, state)
        if term is None:
            return False
        nonzero = Neq(term, Const(0))
        constraints = list(state.feasibility_constraints)
        if constraints:
            cond = self._build_conjunction(constraints)
            if not self._feasibility_sat(cond):
                return False
            return not self._feasibility_sat(And(cond, nonzero))
        return not self._feasibility_sat(nonzero)

    def _divzero_checks(self, instr: Instr, state: SymbolicState,
                        proc_name: str) -> List[VulnerabilityCheck]:
        """CWE-369: a division or modulo whose divisor is provably zero on this
        path. One finding per divisor location. C/C++ only."""
        checks: List[VulnerabilityCheck] = []
        if not self._is_c_lang:
            return checks
        seen = set()
        for exp in self._iter_instr_exps(instr):
            for sub in self._walk_exp(exp):
                if not (isinstance(sub, ExpBinOp) and sub.op in ("/", "%")):
                    continue
                key = str(sub)
                if key in seen:
                    continue
                seen.add(key)
                if self._divisor_provably_zero(sub.right, state):
                    checks.append(
                        self._create_divzero_check(instr, state, proc_name, sub))
        return checks

    def _create_divzero_check(self, instr: Instr, state: SymbolicState,
                              proc_name: str, div: ExpBinOp) -> VulnerabilityCheck:
        op = "modulo" if div.op == "%" else "division"
        return VulnerabilityCheck(
            formula=True_(),
            vuln_type=VulnType.DIVIDE_BY_ZERO,
            location=instr.loc,
            description=f"Divide by zero: the {op} '{div}' has a divisor that is "
                        f"provably zero on this path",
            tainted_var=str(div.right),
            procedure_name=proc_name,
        )

    # =========================================================================
    # Variable and tainted buffer bounds (CWE-787 / CWE-125 / CWE-124 / CWE-127).
    #
    # Tier 1 (`_out_of_bounds_checks`) settles the case where BOTH the array bound
    # and the index are compile-time constants. These two detectors extend that to
    # the two remaining SOUND, high-value cases, and nothing else:
    #
    #  * a loop counter whose guard permits the index to reach or pass the array
    #    bound (`_loop_bound_checks`, structural over the finished CFG), and
    #  * an attacker-controlled index with no path guard bounding it below the
    #    array size (`_tainted_index_checks`, per-path over the symbolic state).
    #
    # Both read the extent from `fixed_array_bounds`, which is an ELEMENT count and
    # therefore a correct bound for an array of any element type. The direction --
    # over the top (787/125) versus before the start (124/127) -- and the write /
    # read distinction come from the IR, exactly as in Tier 1. Where the index
    # range cannot be resolved and the index is not tainted, neither fires.
    # =========================================================================

    def _arg_has_source_call(self, instr: Call) -> bool:
        """Does any argument of this call contain a nested call to a taint source?

        `atoi(getenv("X"))` lowers to a single `atoi` Call whose argument is an
        `ExpCall` to `getenv`; the inner source never executes on its own, so its
        taint has to be recovered from the argument expression here.
        """
        for arg_exp, _ in instr.args:
            for sub in self._walk_exp(arg_exp):
                if isinstance(sub, ExpCall):
                    callee = sub.func
                    name = None
                    if isinstance(callee, ExpConst) and isinstance(callee.value, str):
                        name = callee.value
                    elif isinstance(callee, ExpVar):
                        name = str(callee.var)
                    if name:
                        spec = self._spec_of_name(name)
                        if spec is not None and spec.is_taint_source():
                            return True
        return False

    def _subscript_accesses(self, instr: Instr):
        """Every `base[index]` this instruction performs, as (base, index, is_write).

        A subscripted assignment target reaches the IR as a `Store` through
        `base + index` (or an `ExpIndex` address), so that is a write; a subscript
        anywhere a value is read is an `ExpIndex`, so that is a read. The value
        half of a store is a read even though it sits inside a `Store`.
        """
        if isinstance(instr, Store):
            addr = instr.addr
            if isinstance(addr, ExpBinOp) and addr.op == "+":
                yield addr.left, addr.right, True
            elif isinstance(addr, ExpIndex):
                yield addr.base, addr.index, True

        for exp in self._iter_instr_exps(instr):
            if isinstance(instr, Store) and exp is instr.addr:
                continue
            for sub in self._walk_exp(exp):
                if isinstance(sub, ExpIndex):
                    yield sub.base, sub.index, False

    def _stack_array_bound(self, base: Exp, proc: Procedure) -> Optional[int]:
        """The declared element count of the fixed local array `base` names, or
        None when `base` is not such an array (or its bound is ambiguous)."""
        base = self._cast_strip(base)
        if not isinstance(base, ExpVar):
            return None
        name = str(base.var)
        bound = (proc.fixed_array_bounds or {}).get(name)
        if bound is None and name not in proc.array_locals \
                and name not in {p.name for p, _ in proc.params}:
            # A file-scope array (`static int per_op[NUM_OPS];`) no local shadows.
            bound = getattr(self.program, "global_array_bounds", {}).get(name)
        # -1 marks a name declared twice with disagreeing bounds.
        if bound is None or bound < 0:
            return None
        return bound

    def _index_is_tainted(self, index: Exp, state: SymbolicState) -> bool:
        """Is any variable in this index expression tainted on the path?"""
        for var in self._get_exp_vars(index):
            if state.is_tainted(var):
                return True
        return False

    def _tainted_index_checks(self, instr: Instr, state: SymbolicState,
                              proc_name: str) -> List[VulnerabilityCheck]:
        """CWE-787 / CWE-125 and CWE-124 / CWE-127: an attacker-controlled index into a region
        (a fixed array, also through a pointer into one, or a heap block) that the path does not
        keep inside it. C/C++ only.

        The trigger is TAINT: an ordinary opaque parameter index is never flagged. Each access
        is a candidate decided by `_confirm_path_candidates` against the path-fact fixpoint:
        past the end when `pc & offset + index >= bound` is satisfiable (fixed arrays), before
        the start when `pc & ranges & offset + index < 0` is (attacker data only, not a PRNG's,
        which is never negative). The ranges are the declared types of the index's variables, so
        an `unsigned` or `size_t` index is never negative; an index of unknown signedness is not
        asked. A guard (`if (i < B)`, `if (i >= 0)`) makes the matching question unsatisfiable."""
        if not self._is_c_lang or self._cur_proc_unreliable():
            return []
        proc = self._cur_proc
        if proc is None:
            return []
        constants = getattr(proc, "_const_ints_cache", None)
        if constants is None:
            constants = proc._const_ints_cache = self._procedure_constant_ints(proc)
        seen = set()
        for base, index, is_write in self._accesses(instr):
            if not self._index_is_tainted(index, state):
                continue
            key = (str(base), str(index), is_write)
            if key in seen:
                continue
            seen.add(key)
            region = self._region_of(base, proc, constants)
            if region is None:
                bound = self._stack_array_bound(base, proc)          # a file-scope array
                if bound is None:
                    continue
                stripped = self._cast_strip(base)
                region = (str(stripped.var) if isinstance(stripped, ExpVar) else str(base), 0, bound)
            name, offset, bound = region
            term = self._index_term(index)
            if term is None:
                continue
            at = ArithExpr("+", term, Const(offset)) if offset else term
            tainted = [v for v in self._get_exp_vars(index) if state.is_tainted(v)]
            verb = "Write to" if is_write else "Read of"
            if bound is not None:
                kind = VulnType.OOB_WRITE if is_write else VulnType.OOB_READ
                self._index_candidate(instr, state, proc_name, tainted[0], kind, [Ge(at, Const(bound))],
                                      f"{verb} '{name}[{index}]' uses an attacker-controlled index with "
                                      f"no guard bounding it below {bound}, the extent of '{name}'")
            attacker = [v for v in tainted if self._attacker_tainted(v, state)]
            ranges = self._signed_ranges(index)
            if attacker and ranges is not None:
                kind = VulnType.OOB_UNDERWRITE if is_write else VulnType.OOB_UNDERREAD
                self._index_candidate(instr, state, proc_name, attacker[0], kind, ranges + [Lt(at, Const(0))],
                                      f"{verb} '{name}[{index}]' uses an attacker-controlled index that "
                                      f"can be negative: before the start of '{name}'")
        return []

    def _signed_ranges(self, index: Exp) -> Optional[List[Formula]]:
        """Facts the declared types of the index's variables give (an `int`'s range, `>= 0` for
        an unsigned type), or None when some variable's signedness is not known."""
        out: List[Formula] = []
        declared = getattr(self._cur_proc, "scalar_types", None) or {}
        for v in self._get_exp_vars(index):
            t = declared.get(v, "")
            neg = may_be_negative(t)
            if neg is None:
                return None
            if t in INT_TYPES:
                lo, hi = int_range(*INT_TYPES[t])
                out += [Ge(Var(v), Const(lo)), Le(Var(v), Const(hi))]
            elif not neg:
                out.append(Ge(Var(v), Const(0)))
        return out

    def _index_candidate(self, instr: Instr, state: SymbolicState, proc_name: str, var: str,
                         kind: "VulnType", parts: List[Formula], description: str) -> None:
        check = VulnerabilityCheck(formula=True_(), vuln_type=kind, location=instr.loc,
                                   description=description, tainted_var=var, procedure_name=proc_name)
        taint = state.get_taint_info(var)
        if taint is not None:
            check.source_var = taint.source_var
            check.source_location = taint.source_location
        self._overflow_candidates.append((getattr(self, "_cur_pos", None), check, parts))

    # name -> (index of the destination buffer, index of the byte-count argument
    # or None). The byte count is either an explicit argument or, for the string
    # copies, the length of a literal source argument (see the checker below).
    _BOUNDED_WRITES = _c_facts.library().bounded_writes            # specs/data/c-library.toml
    _LITERAL_COPIES = _c_facts.library().literal_copies
    # Calls that read a constant number of bytes from a buffer: (source index, size index).
    _BOUNDED_READS = _c_facts.library().bounded_reads

    def _const_int(self, exp: Exp) -> Optional[int]:
        """Integer value of a compile-time constant expression (literals joined
        by + - * and casts), else None. Names and sizeof are NOT resolved."""
        exp = self._cast_strip(exp)
        if isinstance(exp, ExpConst):
            v = exp.value
            return v if isinstance(v, int) and not isinstance(v, bool) else None
        if isinstance(exp, ExpBinOp) and exp.op in ("+", "-", "*"):
            a, b = self._const_int(exp.left), self._const_int(exp.right)
            if a is None or b is None:
                return None
            return a + b if exp.op == "+" else a - b if exp.op == "-" else a * b
        return None

    def _single_def(self, var: str) -> Optional[Exp]:
        """The one expression `var` is ever assigned in this procedure (its
        declaration placeholder excluded), or None if it has none or several."""
        proc = self._cur_proc
        if proc is None:
            return None
        cache = getattr(proc, "_single_def_cache", None)
        if cache is None:
            defs: Dict[str, List[Exp]] = {}
            call_rets: Dict[str, Instr] = {}
            for node in proc.nodes.values():
                for ins in node.instrs:
                    if isinstance(ins, Assign) and not getattr(ins, "is_uninit_decl", False):
                        defs.setdefault(self._get_var_name(ins.id), []).append(ins.exp)
                    elif isinstance(ins, Call) and ins.ret:
                        call_rets[str(ins.ret[0])] = ins
            cache = proc._single_def_cache = {}
            for name, exps in defs.items():
                if len(exps) != 1:
                    continue
                e = self._cast_strip(exps[0])
                # `p = malloc(K)` lowered as a temp call plus `p = $tmp`.
                if isinstance(e, ExpVar) and str(e.var) in call_rets:
                    c = call_rets[str(e.var)]
                    cache[name] = ExpCall(c.func, [a for a, _ in c.args])
                else:
                    cache[name] = e
        return cache.get(var)

    def _buffer_capacity(self, dest: Exp) -> Optional[int]:
        """Byte capacity of the buffer `dest` names, when it is certain: a fixed
        character array local, or a pointer whose single definition is such an
        array or a constant-size malloc/calloc/alloca. Anything else is None."""
        proc = self._cur_proc
        base = self._cast_strip(dest)
        if proc is None or not isinstance(base, ExpVar):
            return None
        name = str(base.var)
        if name in proc.char_array_locals:
            return self._stack_array_bound(base, proc)
        seen = set()
        while name not in seen:
            seen.add(name)
            d = self._single_def(name)
            if d is None:
                return None
            if isinstance(d, ExpVar):
                src = str(d.var)
                if src in proc.char_array_locals:
                    return self._stack_array_bound(ExpVar(PVar(src)), proc)
                name = src
                continue
            if isinstance(d, ExpCall) and isinstance(d.func, ExpConst) \
                    and str(d.func.value) in ("malloc", "alloca") and len(d.args) == 1:
                return self._const_int(d.args[0])
            return None
        return None

    @staticmethod
    def _literal_len(value: object) -> Optional[int]:
        """Bytes a C string literal occupies including its NUL, escapes folded."""
        if not isinstance(value, str):
            return None
        text = value
        if "\\" in text:
            text = re.sub(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)", "?", text)
        return len(text) + 1

    def _constant_copy_overflow_checks(self, instr: Instr,
                                       proc_name: str) -> List[VulnerabilityCheck]:
        """CWE-120/121/122: a copy or fill whose size is a compile-time constant
        bigger than the destination's compile-time-constant capacity.

        Fully static, no taint or path reasoning: the destination is a local
        character array or a pointer provably aliasing one (or a constant-size
        malloc), and the size is either an explicit constant argument or the
        length of a string-literal source. Only certain facts are used, so an
        unknown size, an unresolved macro, or a pointer with several possible
        definitions is never flagged. C/C++ only."""
        if not self._is_c_lang or not isinstance(instr, Call):
            return []
        func = instr.func
        fname = (str(func.value) if isinstance(func, ExpConst) else str(func)).strip('"')
        args = [a for a, _ in instr.args]
        reads = self._constant_copy_overread_checks(fname, args, instr, proc_name)
        return reads + self._constant_copy_write_checks(fname, args, instr, proc_name)

    def _constant_copy_overread_checks(self, fname: str, args: List[Exp], instr: Instr,
                                       proc_name: str) -> List[VulnerabilityCheck]:
        """CWE-126: a constant number of bytes read from a buffer whose constant capacity is
        smaller (`memcpy(dst, src, 2048)` with `char src[100]`). Same certainty rules as the
        write side."""
        out = []
        for src_i, n_i in self._BOUNDED_READS.get(fname, ()):
            if max(src_i, n_i) >= len(args):
                continue
            need, cap = self._const_int(args[n_i]), self._buffer_capacity(args[src_i])
            if need is None or cap is None or need <= cap:
                continue
            src_name = self._exp_to_str(self._cast_strip(args[src_i]))
            out.append(VulnerabilityCheck(
                formula=True_(), vuln_type=VulnType.BUFFER_OVERREAD, location=instr.loc,
                description=f"Buffer over-read: {fname}() reads {need} bytes from '{src_name}', "
                            f"which holds only {cap} bytes",
                tainted_var=src_name, procedure_name=proc_name))
        return out

    def _constant_copy_write_checks(self, fname: str, args: List[Exp], instr: Instr,
                                    proc_name: str) -> List[VulnerabilityCheck]:
        need = None
        what = ""
        if fname in self._BOUNDED_WRITES:
            dest_i, n_i = self._BOUNDED_WRITES[fname]
            if dest_i >= len(args) or n_i >= len(args):
                return []
            need = self._const_int(args[n_i])
            dest = args[dest_i]
            what = f"{fname}() of {need} bytes"
        elif fname in self._LITERAL_COPIES and len(args) > self._LITERAL_COPIES[fname]:
            src = self._cast_strip(args[self._LITERAL_COPIES[fname]])
            if not (isinstance(src, ExpConst) and isinstance(src.value, str)):
                return []
            if fname == "sprintf" and "%" in src.value:
                return []   # formatted output length is not a constant
            need = self._literal_len(src.value)
            dest = args[0]
            what = f"{fname}() of a {need}-byte string (with NUL)"
        else:
            return []
        if need is None or need <= 0:
            return []
        cap = self._buffer_capacity(dest)
        if cap is None or need <= cap:
            return []
        dest_name = self._exp_to_str(self._cast_strip(dest))
        return [VulnerabilityCheck(
            formula=True_(),
            vuln_type=VulnType.BUFFER_OVERFLOW,
            location=instr.loc,
            description=f"Buffer overflow: {what} into '{dest_name}', which holds "
                        f"only {cap} bytes",
            tainted_var=dest_name,
            procedure_name=proc_name,
        )]


    def _cookie_header_checks(self, instr: Instr, state: SymbolicState,
                              proc_name: str) -> List[VulnerabilityCheck]:
        """CWE-338: a value written into a `Set-Cookie` header (a session or auth token)
        that comes from a non-cryptographic PRNG, at a call that writes headers (`writes_headers`
        on a c/cpp spec row or a C pack's [[function]]). The header is recognised by its name in
        a literal argument (`printf("Set-Cookie: sid=%s", t)`,
        `MHD_add_response_header(r, "Set-Cookie", t)`); every other argument is a value
        that must be unpredictable."""
        if not self._is_c_lang or not isinstance(instr, Call):
            return []
        func = instr.func
        fname = (str(func.value) if isinstance(func, ExpConst) else str(func)).strip('"').rsplit("::", 1)[-1]
        spec = self.program.library_specs.get(fname)
        fact = (getattr(self.program, "library_facts", None) or {}).get(fname)
        if not ((spec and spec.writes_headers) or (fact and fact.writes_headers)):     # spec rows, C packs
            return []
        args = [a for a, _ in instr.args]
        literal = [a for a in args if isinstance(a, ExpConst) and isinstance(a.value, str)]
        if not any("set-cookie" in a.value.lower() for a in literal):
            return []
        checks = []
        for arg in args:
            if isinstance(arg, ExpConst):
                continue
            for var in self._get_exp_vars(arg):
                info = state.get_taint_info(var) if state.is_tainted(var) else None
                if info is not None and info.source_kind == TaintKind.WEAK_RANDOM:
                    checks.append(self._create_taint_check(instr, state, proc_name, var, SinkKind.UNPREDICTABLE))
                    break
        return checks

    @staticmethod
    def _inline_kind_mismatch(source_kind: object, sink_kind: object) -> bool:
        """A source call written inside a sink's argument whose kind does not fit the sink, as
        `_create_taint_check` decides for variables: weak-random output matters only where a value
        must be unpredictable, and only weak-random output does there."""
        if str(source_kind) in (TaintKind.IDENTITY.value, TaintKind.REQUEST.value):
            return True
        weak = str(source_kind) == TaintKind.WEAK_RANDOM.value
        return weak != (str(getattr(sink_kind, "value", sink_kind)) == SinkKind.UNPREDICTABLE.value)

    def _unpredictable_arg_checks(self, instr: Instr, state: SymbolicState,
                                  proc_name: str) -> List[VulnerabilityCheck]:
        """CWE-338: weak-random data (`weak_random`) in an argument that must be unpredictable, a
        cookie's value or a key / IV / salt (specs/data/unpredictable.toml), also for a call
        written inside another's arguments (`resp.addCookie(new Cookie(n, token))`); the C/C++
        ones are in c_specs and `_cookie_header_checks`."""
        if self._is_c_lang or not isinstance(instr, Call):
            return []
        func = instr.func
        name = (str(func.value) if isinstance(func, ExpConst) else str(func)).strip('"')
        calls = [(instr.canonical, name, [a for a, _ in instr.args], list(getattr(instr, "kwarg_names", None) or []))]
        stack = [a for a, _ in instr.args]
        while stack:                                       # calls nested in the arguments
            exp = stack.pop()
            if isinstance(exp, ExpCall):
                calls.append((None, self._call_exp_name(exp), list(exp.args), []))
                stack.extend(exp.args)
            elif isinstance(exp, ExpBinOp):
                stack.extend([exp.left, exp.right])
            elif isinstance(exp, ExpStringConcat):
                stack.extend(exp.parts)
        checks: List[VulnerabilityCheck] = []
        for canonical, call_name, args, kwnames in calls:
            want = arguments_for(self.program.language, canonical, call_name or "")
            if want is None:
                continue
            positions, keywords = want
            for i, arg in enumerate(args):
                kw = kwnames[i] if i < len(kwnames) else None
                if (kw is None and i in positions) or (kw is not None and kw in keywords):
                    check = self._weak_random_in(arg, instr, state, proc_name)
                    if check is not None:
                        checks.append(check)
        return checks

    def _weak_random_in(self, arg: Exp, instr: Instr, state: SymbolicState,
                        proc_name: str) -> Optional[VulnerabilityCheck]:
        for var in self._get_exp_vars(arg):
            info = state.get_taint_info(var) if state.is_tainted(var) else None
            if info is not None and info.source_kind == TaintKind.WEAK_RANDOM:
                return self._create_taint_check(instr, state, proc_name, var, SinkKind.UNPREDICTABLE)
        for src, kind in self._get_embedded_source_calls(arg, SinkKind.UNPREDICTABLE):   # `hmac.new(random.randbytes(16))`
            if kind == TaintKind.WEAK_RANDOM.value:
                return VulnerabilityCheck(
                    formula=And(Source(Var(src), kind), Sink(Var(src), SinkKind.UNPREDICTABLE.value)),
                    vuln_type=VulnType.from_sink_kind(SinkKind.UNPREDICTABLE),
                    location=instr.loc or Location.unknown(),
                    description=f"Weak random value from '{src}' flows to unpredictable sink",
                    source_var=src, source_location=instr.loc or Location.unknown(),
                    sink_type=SinkKind.UNPREDICTABLE.value, procedure_name=proc_name)
        return None

    # Widest output of a numeric conversion (sign included), by conversion letter.
    _NUMERIC_WIDTH = {"d": 11, "i": 11, "u": 10, "x": 8, "X": 8, "o": 11, "c": 1, "p": 18}
    _LONG_NUMERIC_WIDTH = {"d": 20, "i": 20, "u": 20, "x": 16, "X": 16, "o": 22}
    _FORMAT_SPEC = re.compile(r"%(?:%|([-+ #0]*)(\d*)(?:\.(\d+))?(hh|h|ll|l|z|j|t)?([diouxXcsp]))")

    def _tainted_format_overflow_checks(self, instr: Instr, state: SymbolicState,
                                        proc_name: str) -> List[VulnerabilityCheck]:
        """CWE-120: `sprintf(dest, fmt, ...)` where a `%s` argument holds attacker data
        and the longest output the format can produce does not fit `dest`. The longest
        output is the literal text, each `%s` argument's own capacity (or precision),
        and the widest numeric conversions; only certain bounds are used, so an
        unknown buffer, an unknown conversion or an untainted `%s` is never flagged."""
        if not self._is_c_lang or not isinstance(instr, Call):
            return []
        func = instr.func
        fname = (str(func.value) if isinstance(func, ExpConst) else str(func)).strip('"')
        args = [a for a, _ in instr.args]
        if fname not in ("sprintf", "vsprintf") or len(args) < 2:
            return []
        fmt = self._cast_strip(args[1])
        if not (isinstance(fmt, ExpConst) and isinstance(fmt.value, str)):
            return []
        cap = self._buffer_capacity(args[0])
        if cap is None:
            return []
        need, pos, tainted, last = 1, 2, False, 0
        text = fmt.value
        for m in self._FORMAT_SPEC.finditer(text):
            need += m.start() - last
            last = m.end()
            if m.group(0) == "%%":
                need += 1
                continue
            width = int(m.group(2)) if m.group(2) else 0
            conv = m.group(5)
            if pos >= len(args):
                return []
            arg = args[pos]
            pos += 1
            if conv == "s":
                var = self._sole_var(self._cast_strip(arg))
                src_cap = self._buffer_capacity(arg) if var is not None else None
                if m.group(3) is not None:
                    longest = int(m.group(3))
                elif src_cap is not None:
                    longest = src_cap - 1
                else:
                    return []                      # no bound on this argument's length
                tainted = tainted or (var is not None and state.is_tainted(var))
            else:
                table = self._LONG_NUMERIC_WIDTH if m.group(4) in ("l", "ll", "z", "j", "t") else self._NUMERIC_WIDTH
                if conv not in table:
                    return []
                longest = table[conv]
            need += max(width, longest)
        need += len(text) - last
        if not tainted or need <= cap:
            return []
        dest_name = self._exp_to_str(self._cast_strip(args[0]))
        return [VulnerabilityCheck(
            formula=True_(),
            vuln_type=VulnType.BUFFER_OVERFLOW,
            location=instr.loc,
            description=f"Buffer overflow: sprintf() of up to {need} bytes of attacker-controlled "
                        f"text into '{dest_name}', which holds only {cap} bytes",
            tainted_var=dest_name,
            procedure_name=proc_name,
        )]

    def _loop_guard_upper(self, cond: Exp) -> Optional[Tuple[str, int]]:
        """Read a loop-entry guard `i < K` / `i <= K` (either operand order) as
        the induction variable name and the largest value it can take INSIDE the
        body. `i < K` gives K-1; `i <= K` gives K. Anything else yields None."""
        if not isinstance(cond, ExpBinOp):
            return None
        left = self._cast_strip(cond.left)
        right = self._cast_strip(cond.right)

        def as_var(e):
            return str(e.var) if isinstance(e, ExpVar) else None

        def as_int(e):
            return e.value if isinstance(e, ExpConst) and isinstance(e.value, int) \
                and not isinstance(e.value, bool) else None

        # i < K  /  i <= K
        var, k = as_var(left), as_int(right)
        if var is not None and k is not None:
            if cond.op == "<":
                return var, k - 1
            if cond.op == "<=":
                return var, k
            return None
        # K > i  /  K >= i  (mirror image)
        k, var = as_int(left), as_var(right)
        if var is not None and k is not None:
            if cond.op == ">":
                return var, k - 1
            if cond.op == ">=":
                return var, k
        return None

    def _unit_increment_var(self, proc: Procedure, head_id: int) -> Set[str]:
        """Variables incremented by exactly one on a back edge to `head_id`.

        A loop counter is exactly a variable the body advances by `+1` before
        control returns to the loop head. Restricting to a unit step is what makes
        `i <= K` sound as `i reaches K`: with step one the counter takes every
        integer in its range, so the boundary value genuinely occurs.
        """
        result: Set[str] = set()
        for node in proc.nodes.values():
            if head_id not in node.succs:
                continue
            for ins in node.instrs:
                if not isinstance(ins, Assign):
                    continue
                target = self._get_var_name(ins.id)
                exp = self._cast_strip(ins.exp)
                if not (isinstance(exp, ExpBinOp) and exp.op == "+"):
                    continue
                a, b = self._cast_strip(exp.left), self._cast_strip(exp.right)
                one_plus_var = (isinstance(a, ExpVar) and str(a.var) == target
                                and isinstance(b, ExpConst) and b.value == 1)
                var_plus_one = (isinstance(b, ExpVar) and str(b.var) == target
                                and isinstance(a, ExpConst) and a.value == 1)
                if one_plus_var or var_plus_one:
                    result.add(target)
        return result

    def _constant_inits(self, proc: Procedure) -> Dict[str, Set[int]]:
        """Every integer literal a variable is ever directly assigned, per name.

        Used only to establish that a loop counter STARTS at a known non-negative
        value, so the loop is entered and counts upward from within range.
        """
        inits: Dict[str, Set[int]] = {}
        for node in proc.nodes.values():
            for ins in node.instrs:
                if isinstance(ins, Assign):
                    exp = self._cast_strip(ins.exp)
                    if isinstance(exp, ExpConst) and isinstance(exp.value, int) \
                            and not isinstance(exp.value, bool):
                        inits.setdefault(self._get_var_name(ins.id), set()).add(exp.value)
        return inits

    def _loop_bound_checks(self, proc: Procedure) -> List[VulnerabilityCheck]:
        """CWE-787 / CWE-125: a fixed-array access inside a counting loop whose
        guard lets the counter reach or pass the array bound. C/C++ only.

        Structural over the finished CFG. For each loop head with an entry guard
        `i < K` / `i <= K`, the counter's largest in-body value is K-1 / K. When
        `i` is a unit-step counter that starts at a known value in `0 .. bound`,
        the body accesses `arr[i]`, and that largest value is >= the array's
        element count, the access overruns the array on the final iteration. The
        classic `for(i=0;i<B;i++)` has largest value B-1 < B and never fires; the
        off-by-one `i<=B` reaches B and does.
        """
        checks: List[VulnerabilityCheck] = []
        if not self._is_c_lang or not proc.fixed_array_bounds:
            return checks

        inits = self._constant_inits(proc)

        for head_id, head in proc.nodes.items():
            if head.kind != NodeKind.LOOP_HEAD:
                continue
            enter = next((i for i in head.instrs
                          if isinstance(i, Prune) and i.is_true_branch), None)
            if enter is None:
                continue
            guard = self._loop_guard_upper(enter.condition)
            if guard is None:
                continue
            counter, i_max = guard

            if counter not in self._unit_increment_var(proc, head_id):
                continue
            # The counter must start at a known value within the array's index
            # space, so the loop is entered and sweeps upward from inside it. An
            # unknown or negative start is not evidence of an overrun.
            starts = inits.get(counter)
            if not starts or any(s < 0 for s in starts):
                continue
            start = min(starts)

            for node in proc.nodes.values():
                for ins in node.instrs:
                    for base, index, is_write in self._subscript_accesses(ins):
                        idx = self._cast_strip(index)
                        if not (isinstance(idx, ExpVar) and str(idx.var) == counter):
                            continue
                        bound = self._stack_array_bound(base, proc)
                        if bound is None or start > i_max:
                            continue
                        if i_max < bound:
                            continue  # every in-body index is in range
                        kind = VulnType.OOB_WRITE if is_write else VulnType.OOB_READ
                        verb = "Write to" if is_write else "Read of"
                        base_name = str(self._cast_strip(base).var)
                        checks.append(VulnerabilityCheck(
                            formula=True_(),
                            vuln_type=kind,
                            location=ins.loc,
                            description=f"{verb} '{base_name}[{counter}]' in a loop whose "
                                        f"guard lets '{counter}' reach {i_max}, at or past "
                                        f"{bound}, the extent of '{base_name}'",
                            tainted_var=counter,
                            procedure_name=proc.name,
                        ))
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
    _C_HEAP_ALLOCATORS = _c_facts.allocators("heap")              # specs/data/c.toml
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

    # libc functions that read or write THROUGH a pointer argument but never
    # retain it (no stored copy, no ownership transfer). Passing an owned pointer
    # to one of these is a use, not an escape, so the allocation can still leak.
    # Deliberately excludes anything that may keep the pointer: strtok, setbuf,
    # setvbuf, realloc, atexit, signal, pthread_*, bsearch/qsort callbacks.
    _NON_RETAINING_CALLS = _c_facts.library().non_retaining        # specs/data/c-library.toml

    def _is_size_only_alloc(self, exp: Exp) -> bool:
        """Is `exp` (through casts) a call to malloc/calloc/alloca? Their result is
        new memory; the arguments only say how much."""
        inner = self._cast_strip(exp)
        if not (isinstance(inner, ExpCall) and isinstance(inner.func, ExpConst)):
            return False
        return str(inner.func.value).strip('"') in ("malloc", "calloc", "alloca") \
            and self._is_c_lang

    def _escaping_arg_vars(self, instr: Instr) -> Set[str]:
        """Pointer variables an instruction hands to a callee wholesale.

        For a known non-retaining libc callee only the `&p` form counts: a bare
        `p` is merely read or written through, while `&p` could be stored."""
        result: Set[str] = set()
        func = getattr(instr, "func", None)
        fname = (str(func.value) if isinstance(func, ExpConst) else str(func or "")).strip('"')
        non_retaining = fname in self._NON_RETAINING_CALLS
        for arg in (getattr(instr, "args", None) or []):
            exp = arg[0] if isinstance(arg, tuple) else arg
            if non_retaining:
                inner = self._cast_strip(exp)
                if not (isinstance(inner, ExpUnOp) and inner.op == "&"):
                    continue
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
            if aid in seen or self._provably_null(var, state.feasibility_constraints):
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

    def _field_path(self, exp: Exp) -> Optional[str]:
        """`a.b.c` for a chain of field reads on a plain variable, else None."""
        parts = []
        while isinstance(exp, ExpFieldAccess):
            parts.append(exp.field_name)
            exp = exp.base
        if isinstance(exp, ExpVar):
            return ".".join([self._get_var_name(exp.var)] + parts[::-1])
        return None

    # -- request objects (TaintKind.REQUEST) -----------------------------------------------
    # A framework's request object is a value the taint state carries (an entry point marks the
    # handler's parameter; copies, calls and closures pass it on). What reading it gives is its
    # RequestType's: a client property or method is attacker data, anything else is server state.
    _NOT_REQUEST = object()
    _state: Optional["SymbolicState"] = None
    _client_receiver: Optional[str] = None       # set by _request_call: the client-data receiver it read
    _spec_sources_off = False                    # _exec_call of a request object's method

    def _request_path(self, path: str, state: Optional["SymbolicState"]):
        """For a read of the dotted `path` (`req.query.q`) whose nearest tainted prefix is a request
        object: the name now holding what the read gives (materialised from the request type:
        client data, or a request sub-object like Koa's `ctx.request`), or None for server state.
        `_NOT_REQUEST` when no request object is involved (a plain or explicitly stored taint)."""
        if state is None or not path:
            return self._NOT_REQUEST
        parts = path.split(".")
        for i in range(len(parts) - 1, 0, -1):          # the nearest tainted proper prefix
            prefix = ".".join(parts[:i])
            info = state.tainted.get(prefix)
            if info is None:
                continue
            if info.source_kind != TaintKind.REQUEST or info.request is None:
                return self._NOT_REQUEST
            if path in state.tainted:                    # stored on the request (`req.filter`) or done
                return path
            rest = tuple(parts[i:])
            if info.request.is_identity(rest):           # `request.user`: the authenticated caller
                state.tainted[path] = TaintInfo(TaintKind.IDENTITY, path, info.source_location,
                                                list(info.propagation_path) + [path])
                return path
            if info.request.is_client_field(rest):
                if path not in state.tainted:
                    state.tainted[path] = TaintInfo(
                        info.request.kind_of(rest), path, info.source_location,
                        list(info.propagation_path) + [path], read=info.read + rest)
                return path
            sub = info.request.within(rest)
            if sub is not None:
                if path not in state.tainted:
                    state.tainted[path] = TaintInfo(
                        TaintKind.REQUEST, path, info.source_location,
                        list(info.propagation_path) + [path], sub, info.read + rest)
                return path
            return None
        return self._NOT_REQUEST

    def _request_credential(self, info: TaintInfo, rest: Tuple[str, ...], key: Optional[Exp], name: str,
                            state: "SymbolicState") -> Optional[str]:
        """A lookup of a credential header (`principals.toml`) by literal name in a header map of
        the request (`request.headers.get("Authorization")`): the caller's own credential, held
        under `name` as PRINCIPAL. None for any other read."""
        if info.request is None or not info.request.is_header_map(rest) or not isinstance(key, ExpConst):
            return None
        if not isinstance(key.value, str) or key.value.strip("'\"").lower() not in self._AUTH_HEADER_NAMES:
            return None
        if name not in state.tainted:
            state.tainted[name] = TaintInfo(TaintKind.PRINCIPAL, name, info.source_location,
                                            list(info.propagation_path) + [name], read=info.read + rest)
        return name

    # MutableMapping's storing methods (Python's data model; `x[k] = v` is `x.__setitem__(k, v)`):
    # the position of the stored value
    _MAPPING_STORES = {"__setitem__": [1], "setdefault": [1], "update": [0]}

    def _request_session_store(self, instr: Call, state: "SymbolicState") -> Optional[ProcSpec]:
        """`request.session["k"] = v` with `session` a session path of the request's type: a
        trust-boundary sink on the stored value (CWE-501)."""
        parts = instr.get_full_name().strip('"').split(".")
        if len(parts) < 3 or parts[-1] not in self._MAPPING_STORES:
            return None
        for i in range(len(parts) - 2, 0, -1):
            info = state.tainted.get(".".join(parts[:i]))
            if info is None:
                continue
            if info.source_kind != TaintKind.REQUEST or info.request is None \
                    or not info.request.is_session(tuple(parts[i:-1])):
                return None
            return ProcSpec(is_sink="trust_boundary", sink_args=list(self._MAPPING_STORES[parts[-1]]),
                            description=f"{'.'.join(parts[:-1])}: the server-side session (trust boundary)")
        return None

    def _request_header_credential(self, exp: Exp, state: Optional["SymbolicState"]) -> Optional[str]:
        """`request.headers["Authorization"]` (and JavaScript's `req.headers.authorization`): a
        credential header read by name off a request's header map."""
        if state is None:
            return None
        if isinstance(exp, ExpIndex):
            base, key = exp.base, exp.index
        elif isinstance(exp, ExpFieldAccess):
            base, key = exp.base, ExpConst.string(exp.field_name)
        else:
            return None
        path = self._field_path(base)
        if not path:
            return None
        parts = path.split(".")
        for i in range(len(parts) - 1, 0, -1):
            info = state.tainted.get(".".join(parts[:i]))
            if info is None:
                continue
            if info.source_kind != TaintKind.REQUEST:
                return None
            if not isinstance(key, ExpConst):
                return None
            return self._request_credential(info, tuple(parts[i:]), key, f"{path}[{key.value}]", state)
        return None

    def _request_call(self, func_text: str, state: Optional["SymbolicState"], args=None):
        """For a method call `<receiver>.<m>(...)` on a request object (`req.get("Host")`,
        `req.isAuthenticated()`): the name holding its result when the request type lists the
        method as client data (materialised), else None. `_NOT_REQUEST` when the receiver is not
        a request object (or is client data already: `req.query.q.trim()` keeps its own taint;
        a credential header looked up in its header map is the caller's PRINCIPAL)."""
        if state is None or "." not in func_text:
            return self._NOT_REQUEST
        parts = func_text.strip('"').split(".")
        if not all(p.isidentifier() or p.startswith("$") for p in parts):
            return self._NOT_REQUEST
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i])
            info = state.tainted.get(prefix)
            if info is None:
                continue
            if info.source_kind != TaintKind.REQUEST or info.request is None:
                return self._NOT_REQUEST
            rest = tuple(parts[i:])
            if info.request.is_client_field(rest[:-1]):
                key = args[0] if args else None
                credential = self._request_credential(
                    info, rest[:-1], key, f"{'.'.join(parts)}({getattr(key, 'value', '')})", state)
                if credential is not None:
                    return credential
                self._client_receiver = self._request_path(".".join(parts[:-1]), state)  # client data
                return self._NOT_REQUEST
            if info.request.is_identity(rest):           # `request.auser()`
                name = f"{'.'.join(parts)}()"
                state.tainted.setdefault(name, TaintInfo(TaintKind.IDENTITY, name, info.source_location,
                                                         list(info.propagation_path) + [name]))
                return name
            if info.request.is_client_method(rest):
                name = f"{'.'.join(parts)}()"
                if name not in state.tainted:
                    state.tainted[name] = TaintInfo(
                        TaintKind.USER_INPUT, name, info.source_location,
                        list(info.propagation_path) + [name],
                        read=info.read + rest[:-1] + (rest[-1] + "()",))
                return name
            return None
        return self._NOT_REQUEST

    @staticmethod
    def _request_read_result(arg: TaintInfo, read: Tuple[str, ...], at: str) -> Optional[TaintInfo]:
        """What reading `read` (a summary's path) off the request object `arg` gives."""
        request = arg.request
        if request is None:
            return None
        if read and read[-1].endswith("()"):
            ok, sub = request.is_client_method(read[:-1] + (read[-1][:-2],)), None
        else:
            ok, sub = request.is_client_field(read), request.within(read)
        name = f"{arg.source_var}.{'.'.join(read)}"
        if ok:
            return TaintInfo(request.kind_of(read) if sub is None and not read[-1].endswith("()")
                             else TaintKind.USER_INPUT, name, arg.source_location,
                             list(arg.propagation_path) + [at], read=arg.read + read)
        if sub is not None:
            return TaintInfo(TaintKind.REQUEST, name, arg.source_location,
                             list(arg.propagation_path) + [at], sub, arg.read + read)
        return None

    def _summary_param_leaves(self, summary: "ReturnSummary", param: str, arg_exp: Exp,
                              state: "SymbolicState", wrap: frozenset = frozenset(),
                              at: str = "") -> List[Tuple[TaintInfo, Set[str]]]:
        """The argument's taint the callee's return carries through `param`. A request object
        passed in gives what the callee reads off it (`return req.query.dir`), or itself only
        when the callee returns the object (`return req`)."""
        out: List[Tuple[TaintInfo, Set[str]]] = []
        kinds = set(summary.params.get(param, set()))
        for info, k in self._arg_taint_leaves(arg_exp, state, wrap):
            if info.source_kind != TaintKind.REQUEST:
                out.append((info, k | kinds))
                continue
            reads = summary.param_reads.get(param, set())
            if param in summary.param_whole or not reads:
                out.append((info, k | kinds))
            for read in sorted(reads):
                got = self._request_read_result(info, read, at)
                if got is not None:
                    out.append((got, k | kinds))
        return out

    def _is_request_value(self, name: str, state: Optional["SymbolicState"]) -> bool:
        info = state.tainted.get(name) if state is not None else None
        return info is not None and info.source_kind == TaintKind.REQUEST

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
            credential = self._request_header_credential(exp, self._state)
            if credential is not None:
                return [credential]
            dotted = self._field_path(exp)
            state = self._state
            resolved = self._request_path(dotted, state) if dotted else self._NOT_REQUEST
            if resolved is not self._NOT_REQUEST:
                return [resolved] if resolved else []
            # a field read never carries a request object as a whole (only its own name does)
            names = [n for n in self._get_exp_vars(exp.base) if not self._is_request_value(n, state)]
            # `req.filter` written earlier (a middleware stores request data on the request)
            # is tracked under its own name: reading it must look that name up too
            return names + [dotted] if dotted else names
        if isinstance(exp, ExpIndex):
            credential = self._request_header_credential(exp, self._state)
            if credential is not None:
                return [credential]
            if self._constant_table_index(exp):
                return self._get_exp_vars(exp.base)        # one of the table's constants, whatever the key
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
                called = self._request_call(func_str, self._state, exp.args) if '.' in func_str else self._NOT_REQUEST
                if called is not self._NOT_REQUEST:
                    if called:
                        result.append(called)
                elif '.' in func_str:
                    # Method call: extract receiver (e.g., "param.split" -> "param")
                    parts = func_str.strip('"').split('.')
                    if len(parts) >= 2 and parts[0] and not parts[0][0].isupper() \
                            and not (len(parts) > 2 and self._is_request_value(parts[0], self._state)):
                        # Lowercase first char suggests a variable, not a module
                        result.append(parts[0])
                    if len(parts) > 2 and self._is_request_value(parts[0], self._state):
                        result.append(".".join(parts[:-1]))          # `req.query.q.trim()`: req.query.q
                # a method of a value that is not a plain name (`request.headers["Authorization"].split(" ")`):
                # the value read as an expression
                if isinstance(exp.func, ExpFieldAccess) and not isinstance(exp.func.base, (ExpVar, ExpFieldAccess)):
                    result.extend(self._get_exp_vars(exp.func.base))
            for arg in exp.args:
                result.extend(self._get_exp_vars(arg))
            result.extend(self._summary_request_reads(exp))
            return result
        return []

    def _summary_request_reads(self, exp: "ExpCall") -> List[str]:
        """A project function called with a request object (`getDir(req)`): the names holding what
        its return summary says it hands back of it (`req.query.dir`), materialised in the current
        state. The argument's own name only carries the object, which is never data."""
        state = self._state
        if state is None or not self._ipa_on:
            return []
        name = self._call_exp_name(exp)
        callee = self._resolve_callee(name)
        summary = self._ipa.return_summaries.get(callee.ref) if callee is not None else None
        if summary is None or not summary.param_reads:
            return []
        out: List[str] = []
        for arg, param in zip(exp.args, self._call_params(callee.proc, name)):
            if not isinstance(arg, ExpVar) or param not in summary.param_reads:
                continue
            info = state.tainted.get(self._get_var_name(arg.var))
            if info is None or info.source_kind != TaintKind.REQUEST:
                continue
            for read in sorted(summary.param_reads[param]):
                got = self._request_read_result(info, read, f"{name}()")
                if got is None:
                    continue
                key = f"{name}({self._get_var_name(arg.var)}).{'.'.join(read)}"
                state.tainted.setdefault(key, got)
                kinds = summary.params.get(param)              # what every path sanitized it for
                if kinds:
                    state.sanitized[key] = sorted(kinds)
                out.append(key)
        return out

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

    def _get_embedded_source_calls(self, exp: Exp,
                                   sink_kind=None) -> List[Tuple[str, str]]:
        """
        Extract all function calls from an expression that are taint sources.

        With `sink_kind`, a source nested inside a call that sanitizes for that
        sink (`shlex.quote(request.args.get("d"))` under a command sink) does
        not count.

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

            # A same-file callee with a return summary: its own source, and the
            # sources in the arguments whose parameters reach its return,
            # unless the callee sanitizes that path for this sink.
            callee = self._resolve_callee(func_name) if self._ipa_on else None
            summary = self._ipa.return_summaries.get(callee.ref) if callee else None
            if summary is not None:
                if summary.source is not None and not (
                        sink_kind is not None
                        and self._sanitizes_kind(summary.source_sanitized, sink_kind)):
                    result.append((func_name, summary.source.source_kind.value))
                for arg, param in zip(exp.args, self._call_params(callee.proc, func_name)):
                    if param not in summary.params:
                        continue
                    if sink_kind is not None and self._sanitizes_kind(
                            summary.params[param], sink_kind):
                        continue
                    result.extend(self._get_embedded_source_calls(arg, sink_kind))
                return result

            # Check if this function is a taint source (a method of a request object is its request
            # type's to decide, whatever row its name suffix-matches)
            spec = self._spec_of_name(func_name)
            if spec and spec.is_taint_source() and not self._rooted_at_request(func_name.split(".")[:-1]):
                result.append((func_name, spec.is_source))
            if sink_kind is not None and spec and spec.is_taint_sanitizer() \
                    and self._sanitizes_kind(spec.is_sanitizer, sink_kind):
                return result

            # Recurse into arguments to find nested source calls
            for arg in exp.args:
                result.extend(self._get_embedded_source_calls(arg, sink_kind))

        elif isinstance(exp, ExpBinOp):
            result.extend(self._get_embedded_source_calls(exp.left, sink_kind))
            result.extend(self._get_embedded_source_calls(exp.right, sink_kind))

        elif isinstance(exp, ExpUnOp):
            result.extend(self._get_embedded_source_calls(exp.operand, sink_kind))

        elif isinstance(exp, ExpStringConcat):
            for part in exp.parts:
                result.extend(self._get_embedded_source_calls(part, sink_kind))

        elif isinstance(exp, ExpIndex):
            result.extend(self._get_embedded_source_calls(exp.base, sink_kind))
            if not self._constant_table_index(exp):
                result.extend(self._get_embedded_source_calls(exp.index, sink_kind))

        elif isinstance(exp, ExpFieldAccess):
            result.extend(self._get_embedded_source_calls(exp.base, sink_kind))

        return result

    def _get_embedded_member_sources(self, exp: Exp,
                                     _in_call: bool = False) -> List[Tuple[str, str]]:
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
            # Longest matching prefix wins (req.query before req). A read off a request object is
            # its request type's to decide (`request.session` is server state), not a row's.
            for i in range(len(parts), 0, -1) if not self._rooted_at_request(parts) else ():
                spec = self._spec_of_name('.'.join(parts[:i]))
                if spec and spec.is_taint_source():
                    result.append(('.'.join(parts[:i]), spec.is_source))
                    break
            result.extend(self._get_embedded_member_sources(exp.base, _in_call))
        elif isinstance(exp, ExpBinOp):
            result.extend(self._get_embedded_member_sources(exp.left, _in_call))
            result.extend(self._get_embedded_member_sources(exp.right, _in_call))
        elif isinstance(exp, ExpUnOp):
            result.extend(self._get_embedded_member_sources(exp.operand, _in_call))
        elif isinstance(exp, ExpStringConcat):
            for part in exp.parts:
                result.extend(self._get_embedded_member_sources(part, _in_call))
        elif isinstance(exp, ExpCall):
            for arg in exp.args:
                result.extend(self._get_embedded_member_sources(arg, True))
        elif isinstance(exp, ExpIndex):
            # A subscript read of a source container -- `request.args["d"]` --
            # is the `<chain>.__getitem__` spec, which the assignment form
            # (`d = request.args["d"]`) already matches; inline in a sink it
            # was missed. Only a bare read: wrapped in a call (`int(...)`,
            # `shlex.quote(...)`) it may be converted or sanitized.
            parts = []
            cur = exp.base
            while isinstance(cur, ExpFieldAccess):
                parts.insert(0, cur.field_name)
                cur = cur.base
            if isinstance(cur, ExpVar) and parts and not _in_call:
                parts.insert(0, self._get_var_name(cur.var))
                chain = '.'.join(parts)
                spec = self._spec_of_name(chain + '.__getitem__') if not self._rooted_at_request(parts) else None
                if spec and spec.is_taint_source():
                    result.append((chain, spec.is_source))
            result.extend(self._get_embedded_member_sources(exp.base, _in_call))
            if not self._constant_table_index(exp):
                result.extend(self._get_embedded_member_sources(exp.index, _in_call))
        return result

    def _rooted_at_request(self, parts: List[str]) -> bool:
        """Is the dotted chain `parts` a read off a request object in the current state?"""
        state = self._state
        if state is None:
            return False
        return any(self._is_request_value(".".join(parts[:i]), state) for i in range(1, len(parts) + 1))

    def _constant_table_index(self, exp) -> bool:
        """`TABLE[key]` on a constant table (`Program.constant_tables`): the result is one of
        the table's literals, so the key's taint does not reach it."""
        return isinstance(exp, ExpIndex) and isinstance(exp.base, ExpVar) and \
            self._get_var_name(exp.base.var) in getattr(self.program, "constant_tables", ())

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
            spec = self._spec_of_name(func_name)
            if spec and spec.is_taint_sink():
                # Get tainted arguments
                tainted_args = []
                for i, arg in enumerate(exp.args):
                    if i in spec.sink_args:
                        arg_vars = self._get_exp_vars(arg)
                        # a sanitizer written around the value inside the argument
                        # (`mark_safe(escape(x))` nested in another call)
                        inline: Dict[str, Set[str]] = {}
                        for s_func, s_args in self._get_sanitizer_calls(arg):
                            s_spec = self._spec_of_name(s_func)
                            if s_spec and s_spec.is_taint_sanitizer():
                                for s_var in s_args:
                                    inline.setdefault(s_var, set()).update(s_spec.is_sanitizer)
                        for s_var, kinds in self._summary_inline_sanitized(arg).items():
                            inline.setdefault(s_var, set()).update(kinds)
                        for arg_var in arg_vars:
                            if state.is_tainted(arg_var):
                                if self._sanitizes_kind(inline.get(arg_var, ()), spec.is_sink):
                                    continue
                                if not state.is_sanitized_for(arg_var, spec.is_sink):
                                    if not state.is_asserted_safe_for(arg_var, spec.is_sink):
                                        tainted_args.append(arg_var)
                        # a source written inline in the argument (`f(g(req.query.n))`): the
                        # same member-access sources the TaintSink path reads
                        for chain, src_kind in self._get_embedded_member_sources(arg):
                            if chain not in tainted_args:
                                if not state.is_tainted(chain):
                                    state.add_taint(chain, TaintInfo(
                                        source_kind=TaintKind(src_kind) if src_kind in TaintKind._value2member_map_
                                        else TaintKind.USER_INPUT,
                                        source_var=chain, source_location=Location.unknown()))
                                tainted_args.append(chain)
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
        if self._is_c_lang:
            # C: casts do not change the value the solver reasons about, and
            # arithmetic is real arithmetic over the program variables -- not an
            # opaque name like "(nbits % 4)" that no write or call would know to
            # invalidate, and that cannot relate to a guard on `nbits`.
            if isinstance(exp, ExpCast):
                return self._exp_to_formula(exp.exp)
            if isinstance(exp, ExpBinOp) and exp.op in ("+", "-", "*", "/", "%"):
                left = self._exp_to_formula(exp.left)
                right = self._exp_to_formula(exp.right)
                if isinstance(left, (Var, Const, ArithExpr)) and isinstance(right, (Var, Const, ArithExpr)):
                    return ArithExpr({"/": "div", "%": "mod"}.get(exp.op, exp.op), left, right)
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
        # A variable tainted on one path only gets its merged taint from that path,
        # so that path's sanitization holds: `if (bad(x)) x = "/home";` leaves the
        # validated x on one side and a constant on the other.
        for one, other in ((s1, s2), (s2, s1)):
            for var in one.sanitized.keys() - other.sanitized.keys():
                if var in one.tainted and var not in other.tainted:
                    merged.sanitized[var] = list(one.sanitized[var])

        # Freed: union (freed in either path)
        merged.freed = s1.freed | s2.freed

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

        # Uninitialized locals: UNION (a var that lacked a reaching definition on
        # EITHER incoming path is still uninitialized at the join). This is the
        # intersection of the dual initialized sets. CWE-457.
        merged.uninitialized = s1.uninitialized | s2.uninitialized

        # Asserted safe: intersection (or one path's, as for `sanitized` above)
        for var in set(s1.asserted_safe.keys()) & set(s2.asserted_safe.keys()):
            merged.asserted_safe[var] = list(
                set(s1.asserted_safe[var]) & set(s2.asserted_safe[var])
            )
        for one, other in ((s1, s2), (s2, s1)):
            for var in one.asserted_safe.keys() - other.asserted_safe.keys():
                if var in one.tainted and var not in other.tainted:
                    merged.asserted_safe[var] = list(one.asserted_safe[var])

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
        # Conditions from two joined paths cannot both be assumed. Keep what the
        # join knows -- the shared facts plus the DISJUNCTION of the rest
        # (pc1 | pc2) -- so the solver still sees, e.g., that p is null exactly on
        # the path where n == 0, or that a guard taken before an if/else still
        # holds after it. This is never stronger than either incoming condition.
        merged.feasibility_constraints = self._join_path_conditions(
            s1.feasibility_constraints, s2.feasibility_constraints)

        # Constants: intersection (only keep if same value in both states)
        for var in set(s1.constants.keys()) & set(s2.constants.keys()):
            if s1.constants[var] == s2.constants[var]:
                merged.constants[var] = s1.constants[var]
        # Also keep constants that only exist in one state (the variable was assigned in that
        # path) -- unless the other path assigned it something that is not that constant.
        merged.nonconst = s1.nonconst | s2.nonconst
        for var in s1.constants:
            if var not in s2.constants and var not in s2.nonconst:
                merged.constants[var] = s1.constants[var]
        for var in s2.constants:
            if var not in s1.constants and var not in s1.nonconst:
                merged.constants[var] = s2.constants[var]
        for var in list(merged.constants):
            if var in s1.nonconst and var not in s1.constants or var in s2.nonconst and var not in s2.constants:
                merged.constants.pop(var, None)

        # Secure parsers: union
        # "Hardened" must hold on every incoming path.
        merged.secure_parsers = s1.secure_parsers & s2.secure_parsers

        # Safe for XML sink: union
        merged.safe_for_xml_sink = s1.safe_for_xml_sink | s2.safe_for_xml_sink

        # Validated for eval: intersection (only safe if validated in both paths)

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
        # Uninitialized-variable facts must also converge: a var that becomes
        # may-be-uninitialized at a join (union) can make a downstream read a new
        # CWE-457, so a change here has to reopen the node. The set is drawn from
        # the finite pool of declared locals and grows monotonically at joins, so
        # this cannot oscillate.
        if s1.uninitialized != s2.uninitialized:
            return False
        # A parser hardened on only some incoming paths is not hardened at the
        # join, and that can expose a downstream XXE sink. The set only shrinks
        # at joins (intersection), so this cannot oscillate.
        if s1.secure_parsers != s2.secure_parsers:
            return False
        return True
