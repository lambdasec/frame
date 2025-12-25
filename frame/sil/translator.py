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
        )

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

            # Add successors to worklist
            for succ_id in node.succs:
                worklist.append((succ_id, current_state.copy()))

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
            state = self._exec_assign(instr, state)

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

        return checks, state

    # =========================================================================
    # Instruction Execution
    # =========================================================================

    def _exec_assign(self, instr: Assign, state: SymbolicState) -> SymbolicState:
        """Execute assignment: id = exp"""
        target = self._get_var_name(instr.id)
        source_vars = self._get_exp_vars(instr.exp)

        # Store symbolic value
        state.heap[target] = str(instr.exp)

        # Propagate taint from any tainted source
        for src_var in source_vars:
            if state.is_tainted(src_var):
                state.propagate_taint(src_var, target)
                break  # Only need one taint source

        return state

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
                for arg_idx in spec.sink_args:
                    if arg_idx < len(instr.args):
                        arg_exp, _ = instr.args[arg_idx]
                        arg_vars = self._get_exp_vars(arg_exp)

                        for arg_var in arg_vars:
                            if state.is_tainted(arg_var):
                                if not state.is_sanitized_for(arg_var, spec.is_sink):
                                    if not state.is_asserted_safe_for(arg_var, spec.is_sink):
                                        check = self._create_taint_check(
                                            instr, state, proc_name,
                                            arg_var, sink_kind
                                        )
                                        checks.append(check)

            # Handle sanitizer
            if spec.is_taint_sanitizer() and instr.ret:
                ret_var = str(instr.ret[0])
                state.add_sanitization(ret_var, spec.is_sanitizer)

            # Handle taint propagation
            if spec.propagates_taint() and instr.ret:
                ret_var = str(instr.ret[0])
                for arg_idx in spec.taint_propagates:
                    if arg_idx < len(instr.args):
                        arg_exp, _ = instr.args[arg_idx]
                        arg_vars = self._get_exp_vars(arg_exp)
                        for arg_var in arg_vars:
                            if state.is_tainted(arg_var):
                                state.propagate_taint(arg_var, ret_var)

        # Default: store return value
        if instr.ret:
            ret_var = str(instr.ret[0])
            state.heap[ret_var] = f"call_{func_name}"
            state.allocated[ret_var] = True

        return checks, state

    def _exec_prune(self, instr: Prune, state: SymbolicState) -> SymbolicState:
        """Execute prune (conditional)"""
        # Convert condition to Frame formula and add to path constraints
        formula = self._exp_to_formula(instr.condition)
        if not instr.is_true_branch:
            formula = Not(formula)
        state.path_constraints.append(formula)
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

        for var in sink_vars:
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
            for arg in exp.args:
                result.extend(self._get_exp_vars(arg))
            return result
        return []

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

        # Path constraints: drop (would need disjunction)
        merged.path_constraints = []

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
