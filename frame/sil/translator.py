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

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum, auto

from frame.core.ast import (
    Formula, Emp, PointsTo, SepConj, And, Or, Not, Eq, Neq,
    Var, Const, Taint, Sanitized, Source, Sink,
    NullDeref, UseAfterFree, BufferOverflow, Exists,
    PredicateCall, Lt, Le, Gt, Ge
)

from .types import (
    Ident, PVar, Location, Typ, TypeKind,
    Exp, ExpVar, ExpConst, ExpBinOp, ExpUnOp,
    ExpFieldAccess, ExpIndex, ExpStringConcat, ExpCall
)
from .instructions import (
    Instr, Load, Store, Alloc, Free, Prune, Call, Assign,
    TaintSource, TaintSink, Sanitize, AssertSafe, Return,
    TaintKind, SinkKind
)
from .procedure import Procedure, Node, Program, ProcSpec


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
    WEAK_CRYPTOGRAPHY = "weak_cryptography"     # CWE-327
    HARDCODED_SECRET = "hardcoded_secret"       # CWE-798
    INSECURE_RANDOM = "insecure_random"         # CWE-330
    WEAK_HASH = "weak_hash"                     # CWE-328
    MISSING_ENCRYPTION = "missing_encryption"   # CWE-311
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"  # CWE-200

    # A05: Injection
    SQL_INJECTION = "sql_injection"             # CWE-89
    XSS = "xss"                                 # CWE-79
    COMMAND_INJECTION = "command_injection"     # CWE-78
    LDAP_INJECTION = "ldap_injection"           # CWE-90
    XPATH_INJECTION = "xpath_injection"         # CWE-643
    CODE_INJECTION = "code_injection"           # CWE-94
    TEMPLATE_INJECTION = "template_injection"   # CWE-1336
    NOSQL_INJECTION = "nosql_injection"         # CWE-943
    XXE = "xxe"                                 # CWE-611
    REGEX_DOS = "regex_dos"                     # CWE-1333
    ORM_INJECTION = "orm_injection"             # CWE-89
    EL_INJECTION = "el_injection"               # CWE-917

    # A06: Insecure Design
    MASS_ASSIGNMENT = "mass_assignment"         # CWE-915
    BUSINESS_LOGIC_FLAW = "business_logic_flaw" # CWE-840
    RACE_CONDITION = "race_condition"           # CWE-362

    # A07: Authentication Failures
    BROKEN_AUTHENTICATION = "broken_authentication"  # CWE-287
    CREDENTIAL_STUFFING = "credential_stuffing"  # CWE-307
    SESSION_FIXATION = "session_fixation"       # CWE-384
    WEAK_PASSWORD = "weak_password"             # CWE-521
    TRUST_BOUNDARY_VIOLATION = "trust_boundary_violation"  # CWE-501
    INSECURE_COOKIE = "insecure_cookie"         # CWE-614

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
    DOUBLE_FREE = "double_free"                 # CWE-415
    MEMORY_LEAK = "memory_leak"                 # CWE-401

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
            # A07: Authentication Failures
            SinkKind.CREDENTIAL: cls.BROKEN_AUTHENTICATION,
            SinkKind.SESSION: cls.SESSION_FIXATION,
            SinkKind.PASSWORD_STORE: cls.WEAK_PASSWORD,
            SinkKind.TRUST_BOUNDARY: cls.TRUST_BOUNDARY_VIOLATION,
            SinkKind.INSECURE_COOKIE: cls.INSECURE_COOKIE,
            # A08: Software/Data Integrity Failures
            SinkKind.DESERIALIZATION: cls.DESERIALIZATION,
            # A09: Logging Failures
            SinkKind.LOG: cls.LOG_INJECTION,
            SinkKind.SENSITIVE_LOG: cls.SENSITIVE_DATA_LOGGED,
            # A10: Error Handling
            SinkKind.ERROR_DISCLOSURE: cls.ERROR_DISCLOSURE,
            # Aliases for flexibility
            SinkKind.XSS: cls.XSS,
            SinkKind.COMMAND: cls.COMMAND_INJECTION,
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
            path_constraints=list(self.path_constraints),
            asserted_safe={k: list(v) for k, v in self.asserted_safe.items()},
            list_elements={k: list(v) for k, v in self.list_elements.items()},
            constants=dict(self.constants),
            secure_parsers=set(self.secure_parsers),
            safe_for_xml_sink=set(self.safe_for_xml_sink),
            validated_for_eval=set(self.validated_for_eval),
            dict_elements={k: dict(v) for k, v in self.dict_elements.items()},
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

        # Translate each procedure
        for proc_name, proc in self.program.procedures.items():
            if self.verbose:
                print(f"[Translator] Analyzing procedure: {proc_name}")

            checks = self.translate_procedure(proc)
            self.vulnerability_checks.extend(checks)

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
            for instr in node.instrs:
                node_checks, current_state = self._execute_instr(
                    instr, current_state, proc.name
                )
                checks.extend(node_checks)

            # Add successors to worklist, respecting skip indices from constant folding
            skip_indices = getattr(current_state, '_skip_successor_indices', set())
            succ_list = list(node.succs)
            for idx, succ_id in enumerate(succ_list):
                if idx not in skip_indices:
                    # Create a clean copy without the skip markers
                    succ_state = current_state.copy()
                    if hasattr(succ_state, '_skip_successor_indices'):
                        del succ_state._skip_successor_indices
                    worklist.append((succ_id, succ_state))

        # Post-process: If we found non-XSS vulnerabilities, remove XSS-on-return checks
        # to avoid duplicate reporting (e.g., SQLi test shouldn't also report XSS)
        non_xss_vuln_types = {c.vuln_type for c in checks if c.vuln_type != VulnType.XSS}
        if non_xss_vuln_types:
            # Keep XSS only if it's at a real XSS sink, not just return
            checks = [c for c in checks if c.vuln_type != VulnType.XSS or c.sink_type != SinkKind.HTML_OUTPUT.value]

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

        return checks, state

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

        # Check for null dereference
        check = self._check_null_deref(instr, state, proc_name, addr)
        if check:
            checks.append(check)

        # Check for use-after-free
        if state.is_freed(addr):
            check = self._create_uaf_check(instr, state, proc_name, addr)
            checks.append(check)

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

        # Check for null dereference
        check = self._check_null_deref(instr, state, proc_name, addr)
        if check:
            checks.append(check)

        # Check for use-after-free
        if state.is_freed(addr):
            check = self._create_uaf_check(instr, state, proc_name, addr)
            checks.append(check)

        # Update heap
        state.heap[addr] = value

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
                state.add_taint(ret_var, TaintInfo(
                    source_kind=source_kind,
                    source_var=ret_var,
                    source_location=instr.loc,
                ))

            # Handle taint sink
            if spec.is_taint_sink():
                sink_kind = SinkKind(spec.is_sink) if spec.is_sink in [s.value for s in SinkKind] else SinkKind.SQL_QUERY

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
                                if spec.is_sink == 'xpath':
                                    xpath_sanitize_match = re.findall(
                                        r'(\w+)\.replace\([^)]*&apos;[^)]*\)',
                                        arg_str
                                    )
                                    for var in xpath_sanitize_match:
                                        inline_sanitized_vars.add(var)

                                for arg_var in arg_vars:
                                    if state.is_tainted(arg_var):
                                        if not state.is_sanitized_for(arg_var, spec.is_sink):
                                            if not state.is_asserted_safe_for(arg_var, spec.is_sink):
                                                # Skip xpath sinks for vars with inline .replace() sanitization
                                                if spec.is_sink == 'xpath' and arg_var in inline_sanitized_vars:
                                                    continue
                                                check = self._create_taint_check(
                                                    instr, state, proc_name,
                                                    arg_var, sink_kind
                                                )
                                                checks.append(check)

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

        else:
            # No spec found - apply default taint propagation for unknown functions
            # This is conservative: if any argument is tainted, the return is tainted
            # This catches cases like helper.doSomething(tainted_param) -> tainted_result
            if instr.ret:
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

        # Default: store return value
        if instr.ret:
            ret_var = str(instr.ret[0])
            state.heap[ret_var] = f"call_{func_name}"
            state.allocated[ret_var] = True

        return checks, state

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

        # Check for inline .replace() sanitization patterns in the expression
        # Pattern: var.replace("'", "&apos;") - XPath apostrophe escaping
        import re
        inline_sanitized_vars = set()

        # XPath sanitization: replacing apostrophes with &apos;
        # Simple pattern that matches var.replace(...&apos;...)
        xpath_sanitize_match = re.findall(r'(\w+)\.replace\([^)]*&apos;[^)]*\)', exp_str)
        if xpath_sanitize_match:
            for var in xpath_sanitize_match:
                inline_sanitized_vars.add(var)

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

            if state.is_tainted(var):
                if not state.is_sanitized_for(var, instr.kind.value):
                    if not state.is_asserted_safe_for(var, instr.kind.value):
                        check = self._create_taint_check(
                            instr, state, proc_name,
                            var, instr.kind
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

        For web applications, returning tainted data can be XSS if the response
        goes to a client. However, we disable this check because:
        1. It's too aggressive - causes many FPs for other vulnerability types
        2. Real XSS is better caught at explicit sinks (render_template, response.set_data)
        3. Most Flask routes return templates, not raw strings
        """
        checks = []

        # XSS-on-return check - catch XSS when returning tainted strings
        # This is filtered in post-processing if we find other vulnerabilities
        if instr.value:
            return_vars = self._get_exp_vars(instr.value)

            for var in return_vars:
                if state.is_tainted(var):
                    # Only flag XSS if taint originated from user input, not database
                    taint_info = state.get_taint_info(var)
                    is_user_taint = (
                        taint_info and
                        taint_info.source_kind and
                        taint_info.source_kind.value in ("user", "file", "env")
                    )

                    if is_user_taint:
                        # Check if sanitized for XSS
                        if not state.is_sanitized_for(var, "html"):
                            if not state.is_asserted_safe_for(var, "html"):
                                # Returning tainted data - potential XSS
                                check = self._create_taint_check(
                                    instr, state, proc_name,
                                    var, SinkKind.HTML_OUTPUT
                                )
                                checks.append(check)

        return checks, state

    # =========================================================================
    # Vulnerability Check Creation
    # =========================================================================

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

    def _check_null_deref(
        self,
        instr: Instr,
        state: SymbolicState,
        proc_name: str,
        addr: str
    ) -> Optional[VulnerabilityCheck]:
        """Check for potential null dereference"""
        # Only flag if we can't prove it's allocated
        if not state.is_allocated(addr):
            formula = And(
                Eq(Var(addr), Const(None)),
                NullDeref(Var(addr))
            )

            return VulnerabilityCheck(
                formula=formula,
                vuln_type=VulnType.NULL_DEREFERENCE,
                location=instr.loc,
                description=f"Potential null pointer dereference of '{addr}'",
                tainted_var=addr,
                procedure_name=proc_name,
            )

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
            return [self._get_var_name(exp.var)]
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
        return True
