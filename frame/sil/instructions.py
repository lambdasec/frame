"""
SIL instruction definitions.

This module defines all instructions in the Frame SIL:

Core Instructions (inspired by Infer SIL):
- Load: Read from memory (id = *exp)
- Store: Write to memory (*exp = val)
- Alloc: Heap allocation
- Free: Heap deallocation
- Call: Function/method call
- Prune: Conditional branch (assume)
- Assign: Direct assignment (no memory)

Security Extensions (Frame-specific):
- TaintSource: Mark data as coming from untrusted source
- TaintSink: Mark data flowing to sensitive sink
- Sanitize: Mark data as sanitized/validated
- AssertSafe: Defensive assertion
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import Enum, auto

from .types import Ident, PVar, Exp, ExpVar, ExpConst, Typ, Location


# =============================================================================
# Enumerations
# =============================================================================

class PruneKind(Enum):
    """Kind of prune instruction (what control flow construct it came from)"""
    IF_TRUE = auto()      # True branch of if statement
    IF_FALSE = auto()     # False branch of if statement
    LOOP_ENTER = auto()   # Loop entry condition
    LOOP_EXIT = auto()    # Loop exit condition
    WHILE_TRUE = auto()   # While loop true branch
    WHILE_FALSE = auto()  # While loop false branch
    FOR_ENTER = auto()    # For loop entry
    FOR_EXIT = auto()     # For loop exit
    SWITCH_CASE = auto()  # Switch case match
    ASSERT = auto()       # Assert statement
    TRY_ENTER = auto()    # Try block entry
    EXCEPT_ENTER = auto() # Exception handler entry


class TaintKind(Enum):
    """Types of taint sources"""
    USER_INPUT = "user"         # Direct user input (forms, query params)
    FILE_INPUT = "file"         # File contents
    NETWORK_INPUT = "network"   # Network data (sockets, HTTP)
    ENV_VAR = "env"             # Environment variables
    DATABASE = "database"       # Database query results
    COMMAND_OUTPUT = "command"  # Command execution output
    DESERIALIZED = "deserialize"  # Deserialized data
    # The authenticated caller's own identity: derived from an authentication
    # credential (Authorization header, session, cookie, JWT). Distinct from
    # USER_INPUT object-selectors because an attacker can only present their OWN
    # credential -- so a resource selected by a PRINCIPAL-derived value is self-
    # scoped, not a cross-user (IDOR) access. Propagates through custom validators.
    PRINCIPAL = "principal"
    # The authenticated caller as the server knows it (Flask-Login's `current_user`, Django's
    # `request.user`, a verified JWT's identity): set by the server, never attacker data at a
    # sink. It matters where it scopes a resource selection or is compared with an object's
    # owner (IDOR), and only there.
    IDENTITY = "identity"
    # Output of a non-cryptographic PRNG (rand(), random()): not attacker data, but
    # predictable. It matters only where a value must be unpredictable
    # (SinkKind.UNPREDICTABLE), and only there.
    WEAK_RANDOM = "weak_random"
    # What a language model returned (OWASP LLM05: improper output handling). It can be steered
    # by a prompt injection anywhere in what the model read, so it is attacker data for every
    # sink; findings from it are in the `ai` category.
    LLM_OUTPUT = "llm"
    # What an LLM app feeds its model from outside: a retrieved document, an MCP tool's result
    # or resource. Whoever wrote it can put instructions in it (indirect prompt injection), so it
    # is attacker data at every injection sink, in the `ai` category, and not confidential.
    RETRIEVED = "retrieved"
    # A number read off a binary stream or buffer (DataInputStream.readInt, ByteBuffer.getInt):
    # a length or count a peer sent. It is not text, so it matters only as the size of an
    # allocation (SinkKind.ALLOC_SIZE), and only there.
    WIRE_SIZE = "wire_size"
    # A web framework's request object as a whole (`req` of an Express handler): not attacker data
    # itself. Its client properties are (`req.query`, `req.get("Host")`: what the RequestType it
    # carries lists), its server state is not (`req.session`, `req.user`). Never reported at a sink.
    REQUEST = "request"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class RequestType:
    """What a framework's request object holds (a pack's `[[request_type]]`): the property paths
    and the method paths whose values are client data. With `all_fields`, every property and
    method is client data except the names in `server_state` (Django's HttpRequest: everything
    but `user`, `session`, ...). A path that leads into a listed one (`request` for Koa's
    `ctx.request.body`) is itself a request object, of the type `within` gives; so is a path
    `objects` names (a Django class-based view's `self.request`, an HttpRequest). `headers` are
    the paths of its header maps, where a lookup of a credential header by name is the caller's
    own credential (`principals.toml`); `sessions` the paths of its server-side session (Django's
    `request.session`), where storing client data crosses a trust boundary (CWE-501)."""
    name: str
    fields: Tuple[Tuple[str, ...], ...] = ()
    methods: Tuple[Tuple[str, ...], ...] = ()
    all_fields: bool = False
    server_state: Tuple[str, ...] = ()
    kinds: Tuple[Tuple[Tuple[str, ...], str], ...] = ()     # path -> TaintKind value other than "user"
    objects: Tuple[Tuple[Tuple[str, ...], "RequestType"], ...] = ()   # path -> the request object there
    headers: Tuple[Tuple[str, ...], ...] = ()
    sessions: Tuple[Tuple[str, ...], ...] = ()
    identities: Tuple[str, ...] = ()      # server-state names holding the authenticated caller (`user`)
    origin: str = ""                      # its value origin: calls on it are named `<origin>.<method>`

    def _object_at(self, path: Tuple[str, ...]) -> Optional[Tuple["RequestType", Tuple[str, ...]]]:
        best = None
        for p, t in self.objects:
            if path[:len(p)] == p and (best is None or len(p) > len(best[0])):
                best = (p, t)
        return (best[1], path[len(best[0]):]) if best is not None else None

    def kind_of(self, path: Tuple[str, ...]) -> "TaintKind":
        """The source kind of client data read at `path` (uploads are file contents)."""
        obj = self._object_at(path)
        if obj is not None:
            return obj[0].kind_of(obj[1])
        for p, k in self.kinds:
            if path[:len(p)] == p:
                return TaintKind(k)
        return TaintKind.USER_INPUT

    def is_client_field(self, path: Tuple[str, ...]) -> bool:
        """Is the property at `path` (or a value inside it) client data?"""
        if not path:
            return False
        obj = self._object_at(path)
        if obj is not None:
            return obj[0].is_client_field(obj[1])
        if self.all_fields:
            return path[0] not in self.server_state
        return any(path[:len(f)] == f for f in self.fields)

    def is_client_method(self, path: Tuple[str, ...]) -> bool:
        """Does calling the method at `path` (`("get",)`, `("cookies", "get")`) return client data?"""
        if not path:
            return False
        obj = self._object_at(path)
        if obj is not None:
            return obj[0].is_client_method(obj[1])
        if self.all_fields:
            return path[0] not in self.server_state
        return path in self.methods or self.is_client_field(path[:-1])

    def is_header_map(self, path: Tuple[str, ...]) -> bool:
        """Is the property at `path` one of the request's header maps?"""
        obj = self._object_at(path)
        if obj is not None:
            return obj[0].is_header_map(obj[1])
        return path in self.headers

    def is_identity(self, path: Tuple[str, ...]) -> bool:
        """Does the read (or method call) at `path` give the authenticated caller?"""
        obj = self._object_at(path)
        if obj is not None:
            return obj[0].is_identity(obj[1])
        return bool(path) and path[0] in self.identities

    def is_session(self, path: Tuple[str, ...]) -> bool:
        """Is the property at `path` the request's server-side session?"""
        obj = self._object_at(path)
        if obj is not None:
            return obj[0].is_session(obj[1])
        return path in self.sessions

    def within(self, path: Tuple[str, ...]) -> Optional["RequestType"]:
        """The request object at `path` when `objects` names it or it leads into a listed field
        or method (Koa's `ctx.request`), else None."""
        if not path:
            return None
        obj = self._object_at(path)
        if obj is not None:
            return obj[0] if not obj[1] else obj[0].within(obj[1])
        if self.all_fields:
            return None
        fields = tuple(f[len(path):] for f in self.fields if len(f) > len(path) and f[:len(path)] == path)
        methods = tuple(m[len(path):] for m in self.methods if len(m) > len(path) and m[:len(path)] == path)
        if not fields and not methods:
            return None
        kinds = tuple((p[len(path):], k) for p, k in self.kinds if len(p) > len(path) and p[:len(path)] == path)
        headers = tuple(h[len(path):] for h in self.headers if len(h) > len(path) and h[:len(path)] == path)
        return RequestType(f"{self.name}.{'.'.join(path)}", fields, methods, kinds=kinds, headers=headers)


class SinkKind(Enum):
    """
    Types of security-sensitive sinks.

    Mapped to OWASP Top 10 2025 categories:
    - A01: Broken Access Control (SSRF, redirect, file access, authz)
    - A02: Security Misconfiguration (secrets, debug, headers)
    - A03: Software Supply Chain Failures (package integrity)
    - A04: Cryptographic Failures (weak crypto, hardcoded keys)
    - A05: Injection (SQL, command, LDAP, XPath, template, etc.)
    - A06: Insecure Design (mass assignment, IDOR)
    - A07: Authentication Failures (credential handling, session)
    - A08: Software/Data Integrity Failures (deserialize, code signing)
    - A09: Logging & Alerting Failures (log injection, sensitive logging)
    - A10: Mishandling of Exceptional Conditions (error disclosure)
    """
    # A05: Injection - Various injection attacks
    SQL_QUERY = "sql"           # SQL query execution (CWE-89)
    HTML_OUTPUT = "html"        # HTML output - XSS (CWE-79)
    SHELL_COMMAND = "shell"     # Shell command execution (CWE-78)
    LDAP_QUERY = "ldap"         # LDAP query (CWE-90)
    XPATH_QUERY = "xpath"       # XPath query (CWE-643)
    XML_INJECTION = "xml_injection"  # XML injection via raw write (CWE-91)
    EVAL = "eval"               # Dynamic code evaluation (CWE-94)
    TEMPLATE = "template"       # Template injection (CWE-1336)
    PROMPT = "prompt"           # Untrusted data in a model's system instructions (CWE-1427, OWASP LLM01)
    NOSQL_QUERY = "nosql"       # NoSQL injection (CWE-943)
    XML_PARSE = "xml"           # XXE - XML External Entity (CWE-611)
    REGEX = "regex"             # ReDoS via regex (CWE-1333)
    ORM_QUERY = "orm"           # ORM injection (CWE-89)
    EXPRESSION_LANG = "el"      # Expression language injection (CWE-917)

    # A01: Broken Access Control
    FILE_PATH = "filesystem"    # File path operations (CWE-22)
    REDIRECT = "redirect"       # URL redirect (CWE-601)
    SSRF = "ssrf"               # Server-side request forgery (CWE-918)
    AUTHZ_CHECK = "authz"       # Authorization bypass (CWE-863)
    RESOURCE_SELECT = "resource_select"  # Object-level resource selection by id -- IDOR/BOLA (CWE-639)
    CORS = "cors"               # CORS misconfiguration (CWE-942)
    UNVERIFIED_SIGNATURE = "unverified_signature"   # a token decoded with its signature check off (CWE-347)

    # Resource exhaustion
    ALLOC_SIZE = "alloc_size"   # Size/count argument of an allocation (CWE-770)

    # A02: Security Misconfiguration
    HEADER = "header"           # HTTP header injection (CWE-113)
    SECRET_EXPOSURE = "secret"  # Secret/credential exposure (CWE-200)
    DEBUG_INFO = "debug"        # Debug information exposure (CWE-215)

    # A04: Cryptographic Failures
    WEAK_CRYPTO = "weak_crypto" # Weak cryptography (CWE-327)
    HARDCODED_SECRET = "hardcoded_secret"  # Hardcoded credentials (CWE-798)
    INSECURE_RANDOM = "insecure_random"    # Insecure randomness (CWE-330)
    # A value that must be unpredictable: a cryptographic key, IV, salt or seed, a
    # session / auth token set as a cookie. Reached by WEAK_RANDOM data only (CWE-338).
    UNPREDICTABLE = "unpredictable"
    # A06: Vulnerable and Outdated Components -- a function an advisory names as vulnerable in
    # the resolved version of a dependency (frame/sca), reached by attacker data (CWE-1395).
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    WEAK_HASH = "weak_hash"     # Weak hashing (CWE-328)
    INSECURE_TEMP_FILE = "insecure_temp_file"  # Insecure temp file / race (CWE-377)
    CERT_VALIDATION = "cert_validation"  # Improper certificate validation (CWE-295)
    WEAK_KEY_SIZE = "weak_key_size"      # Insufficient key size (CWE-326)
    WEAK_RSA_PADDING = "weak_rsa_padding"  # RSA without OAEP padding (CWE-780)

    # A07: Authentication Failures
    CREDENTIAL = "credential"   # Credential handling (CWE-522)
    INSECURE_AUTH = "insecure_auth"  # Insufficiently protected credentials (CWE-522)
    SESSION = "session"         # Session management (CWE-384)
    PASSWORD_STORE = "password" # Password storage (CWE-257)
    TRUST_BOUNDARY = "trust_boundary"  # Trust boundary violation (CWE-501)
    INSECURE_COOKIE = "insecure_cookie"  # Insecure cookie - missing Secure (CWE-614)
    INSECURE_COOKIE_HTTPONLY = "insecure_cookie_httponly"  # Cookie missing HttpOnly (CWE-1004)

    # A08: Software/Data Integrity Failures
    DESERIALIZATION = "deserialize"  # Object deserialization (CWE-502)
    DESERIALIZE_UNSAFE = "deserialize_unsafe"  # Inherently-unsafe deserializer, usage-based (CWE-502)
    CSRF_DISABLED = "csrf_disabled"  # CSRF protection disabled in security config (CWE-352)

    # A09: Logging & Alerting Failures
    LOG = "log"                 # Log injection (CWE-117)
    SENSITIVE_LOG = "sensitive_log"  # Logging sensitive data (CWE-532)

    # A10: Mishandling of Exceptional Conditions
    ERROR_DISCLOSURE = "error_disclosure"  # Error message disclosure (CWE-209)

    # Additional injection types (aliases for flexibility)
    XSS = "xss"                 # XSS alias for HTML_OUTPUT (CWE-79)
    COMMAND = "command"         # Command injection alias (CWE-78)
    FORMAT_STRING = "format_string"  # Format string vulnerability (CWE-134)
    FORMAT = "format"           # Format string alias (CWE-134)

    # Memory Safety (not in OWASP web but critical for native)
    MEMORY = "memory"           # Memory safety sink
    BUFFER_OVERFLOW = "buffer_overflow"  # Buffer overflow (CWE-122)
    INTEGER_OVERFLOW = "integer_overflow"  # Integer overflow (CWE-190)
    NULL_DEREF = "null_deref"   # NULL pointer dereference (CWE-476)
    DIVIDE_BY_ZERO = "divide_by_zero"  # Division by zero (CWE-369)
    DANGEROUS_FUNCTION = "dangerous_function"  # Inherently unsafe API (CWE-676)
    PROTOTYPE_POLLUTION = "prototype_pollution"  # JS prototype pollution (CWE-1321)
    ASSERTION = "assertion"     # Reachable assertion on attacker data (CWE-617)
    RACE = "race"               # Time-of-check/time-of-use file race (CWE-367)
    SENSITIVE_EXPOSURE = "sensitive_exposure"  # Sensitive data exposed (CWE-200)
    PRIVILEGE = "privilege"     # Privilege management on attacker data (CWE-269)
    SYSTEM_CONFIG = "system_config"  # A system setting chosen by attacker data (CWE-15)
    LIBRARY_LOAD = "library_load"    # A library loaded from a path attacker data chooses (CWE-114)

    def __str__(self) -> str:
        return self.value


# Spec sink-kind strings that don't equal a SinkKind value but mean a specific kind
# (`aliases` in specs/data/kinds.toml). Without them they silently fell back to SQL_QUERY
# (spurious CWE-89).
from frame.sil.kinds import load as _load_kinds  # noqa: E402

_SINK_KIND_ALIASES = _load_kinds().aliases


def resolve_sink_kind(kind_str, default: "SinkKind" = None) -> "SinkKind":
    """Resolve a spec sink-kind string to a SinkKind, honoring aliases.

    Returns ``default`` (SinkKind.SQL_QUERY if not given) only for a genuinely
    unknown kind -- known alias strings like 'code'/'xxe' resolve correctly
    instead of silently becoming SQL.
    """
    if default is None:
        default = SinkKind.SQL_QUERY
    if kind_str in _SINK_KIND_ALIASES:
        kind_str = _SINK_KIND_ALIASES[kind_str]
    try:
        return SinkKind(kind_str)
    except (ValueError, TypeError):
        return default


# =============================================================================
# Base Instruction
# =============================================================================

@dataclass
class Instr:
    """
    Base class for all SIL instructions.

    Every instruction has a source location for error reporting.
    """
    loc: Location

    def __str__(self) -> str:
        return "<instr>"

    def get_read_vars(self) -> set:
        """Return variables read by this instruction"""
        return set()

    def get_written_vars(self) -> set:
        """Return variables written by this instruction"""
        return set()


# =============================================================================
# Core Memory Instructions
# =============================================================================

@dataclass
class Load(Instr):
    """
    Load from memory: id = *exp

    Reads the value at heap address `exp` into identifier `id`.

    In separation logic semantics:
    - Requires: exp |-> v (for some v)
    - Produces: id holds value v

    This is used for:
    - Pointer dereference: *ptr
    - Field access through pointer: ptr->field
    - Array access: arr[i]

    Security implications:
    - Can trigger null pointer dereference
    - Can trigger use-after-free
    - Can trigger buffer overflow (array access)
    """
    id: Ident               # Destination identifier
    exp: Exp                # Source address expression
    typ: Typ                # Type of loaded value

    def __str__(self) -> str:
        return f"{self.id} = *{self.exp} : {self.typ}"

    def get_read_vars(self) -> set:
        return self.exp.free_vars()

    def get_written_vars(self) -> set:
        return {str(self.id)}


@dataclass
class Store(Instr):
    """
    Store to memory: *addr = value

    Writes `value` to heap address `addr`.

    In separation logic semantics:
    - Requires: addr |-> _ (addr is allocated)
    - Produces: addr |-> value

    Security implications:
    - Can trigger null pointer dereference
    - Can trigger use-after-free
    - Can trigger buffer overflow
    - Taint propagates from value to memory location
    """
    addr: Exp               # Destination address
    value: Exp              # Value to store
    typ: Typ                # Type of stored value

    def __str__(self) -> str:
        return f"*{self.addr} = {self.value} : {self.typ}"

    def get_read_vars(self) -> set:
        return self.addr.free_vars() | self.value.free_vars()


@dataclass
class Alloc(Instr):
    """
    Heap allocation: id = alloc(size)

    Allocates `size` bytes of fresh heap memory.

    In separation logic semantics:
    - Requires: emp (nothing)
    - Produces: id |-> _ (fresh allocated memory)

    Security implications:
    - Integer overflow in size calculation → undersized buffer
    - Allocation failure → null pointer
    """
    id: Ident               # Identifier for allocated address
    size: Exp               # Size to allocate (in bytes or elements)
    typ: Typ                # Type of allocated object
    is_array: bool = False  # True for array allocation
    count: Optional[Exp] = None  # Number of elements (for arrays)

    def __str__(self) -> str:
        if self.is_array and self.count:
            return f"{self.id} = alloc_array({self.count}) : {self.typ}"
        return f"{self.id} = alloc({self.size}) : {self.typ}"

    def get_read_vars(self) -> set:
        result = self.size.free_vars()
        if self.count:
            result |= self.count.free_vars()
        return result

    def get_written_vars(self) -> set:
        return {str(self.id)}


@dataclass
class Free(Instr):
    """
    Heap deallocation: free(exp)

    Deallocates the heap memory at address `exp`.

    In separation logic semantics:
    - Requires: exp |-> _ (exp is allocated)
    - Produces: emp (memory is freed)
    - Side effect: exp is now "freed" (accessing it is use-after-free)

    Security implications:
    - Double-free: freeing already freed memory
    - Use-after-free: accessing memory after free
    """
    exp: Exp                # Address to free

    def __str__(self) -> str:
        return f"free({self.exp})"

    def get_read_vars(self) -> set:
        return self.exp.free_vars()


# =============================================================================
# Control Flow Instructions
# =============================================================================

@dataclass
class Prune(Instr):
    """
    Conditional prune: assume(condition)

    Blocks execution if condition is false (or true, depending on is_true_branch).
    Used to encode branches in the CFG.

    For an if statement:
        if (x > 0) { A } else { B }

    Becomes:
        Node1: prune(x > 0, true)  → Node2 (A)
        Node1: prune(x > 0, false) → Node3 (B)

    This allows path-sensitive analysis.
    """
    condition: Exp          # Condition to assume
    is_true_branch: bool    # True = assume condition, False = assume negation
    kind: PruneKind = PruneKind.IF_TRUE

    def __str__(self) -> str:
        branch = "true" if self.is_true_branch else "false"
        return f"prune({self.condition}, {branch})"

    def get_read_vars(self) -> set:
        return self.condition.free_vars()


@dataclass
class Assign(Instr):
    """
    Direct assignment: id = exp (no memory access)

    Assigns the value of expression to identifier.
    This is for non-pointer assignments.

    Security implications:
    - Taint propagates from exp to id
    """
    id: Union[Ident, PVar]  # Destination
    exp: Exp                # Source expression
    literal: str = ""       # JS/TS: "object" / "array" when the value was written as that literal

    # True only for a bare declaration with no initializer (`int x;`), which the
    # frontend lowers to `x = null` exactly like `int *p = NULL;`. The two are
    # otherwise indistinguishable in the IR, so this flag is the only structural
    # signal that the target has no reaching definition yet (drives CWE-457).
    is_uninit_decl: bool = False

    def __str__(self) -> str:
        return f"{self.id} = {self.exp}"

    def get_read_vars(self) -> set:
        return self.exp.free_vars()

    def get_written_vars(self) -> set:
        if isinstance(self.id, PVar):
            return {self.id.name}
        return {str(self.id)}


# =============================================================================
# Function Call
# =============================================================================

@dataclass
class Call(Instr):
    """
    Function call: ret = func(args)

    Represents a procedure/method invocation.

    For compositional analysis, calls use procedure specifications:
    - requires: precondition (what must hold before call)
    - ensures: postcondition (what holds after call)
    - modifies: which variables/heap locations are modified

    Security implications:
    - Function may be a taint source (e.g., input())
    - Function may be a taint sink (e.g., execute())
    - Function may sanitize input
    - Taint may propagate through arguments to return value
    """
    ret: Optional[Tuple[Ident, Typ]]  # Return value (None for void)
    func: Exp                          # Function to call (name or expression)
    args: List[Tuple[Exp, Typ]]       # Arguments with types

    # Call metadata
    is_virtual: bool = False           # Virtual/dynamic dispatch
    is_static: bool = False            # Static method call
    receiver: Optional[Exp] = None     # Object receiver for method calls
    # Declared type of the receiver, when the frontend knows it (Java): specs
    # are then matched by type, not by the receiver variable's name.
    receiver_type: Optional[str] = None
    receiver_exact: bool = False       # receiver's runtime class IS receiver_type
    # Static type of each argument where the frontend knows it, else None.
    arg_types: Optional[List[Optional[str]]] = None
    # The class whose method this call names, when the frontend can say (Java): the
    # receiver's declared type, a class used as a qualifier (`Shell.run`), or the
    # calling class for an unqualified call. Project-wide call resolution starts here.
    callee_class: Optional[str] = None
    # Best-effort fully qualified callee id resolved through the file's imports
    # (`flask.request.args.get`, `java.sql.Statement.executeQuery`); None when it
    # cannot be resolved. Set by the frontend's post-pass (see metadata.py). Nothing
    # in the analysis reads it yet; framework packs match on it, name as fallback.
    canonical: Optional[str] = None
    # Keyword-argument names parallel to `args` (None for a positional argument),
    # for languages that have them (Python, C# named arguments). None = no names.
    kwarg_names: Optional[List[Optional[str]]] = None
    # keyword arguments written as a dict literal: keyword -> {string key: literal value as written}
    # (`options={"verify_signature": False}`), which the argument expression itself does not keep
    dict_kwargs: Optional[Dict[str, Dict[str, str]]] = None
    # A ProcSpec a framework pack resolved for THIS call (canonical id, then
    # name), already merged over the built-in spec; Program.spec_for_call
    # returns it before any name lookup. See frame/sil/packs.
    pack_spec: Optional[Any] = None
    # Forms of arguments the frontend could not choose before the call's spec is known: argument
    # index -> ("json", exp) for an object / array literal a JSON-sending sink serialises, or
    # ("render", exp) for the data a template prints raw (packs.apply.finish_call_arguments).
    arg_forms: Optional[dict] = None

    def __str__(self) -> str:
        args_str = ", ".join(f"{e}" for e, t in self.args)
        if self.receiver:
            call_str = f"{self.receiver}.{self.func}({args_str})"
        else:
            call_str = f"{self.func}({args_str})"

        if self.ret:
            return f"{self.ret[0]} = {call_str}"
        return call_str

    def get_func_name(self) -> str:
        """Get the function name as a string"""
        if isinstance(self.func, ExpVar):
            return str(self.func.var)
        if isinstance(self.func, ExpConst) and isinstance(self.func.value, str):
            return self.func.value  # Return raw string value without quotes
        return str(self.func)

    def get_full_name(self) -> str:
        """Get full qualified name including receiver"""
        if self.receiver:
            return f"{self.receiver}.{self.get_func_name()}"
        return self.get_func_name()

    def get_read_vars(self) -> set:
        result = self.func.free_vars()
        for arg, _ in self.args:
            result |= arg.free_vars()
        if self.receiver:
            result |= self.receiver.free_vars()
        return result

    def get_written_vars(self) -> set:
        if self.ret:
            return {str(self.ret[0])}
        return set()


# =============================================================================
# Security Extension Instructions
# =============================================================================

@dataclass
class TaintSource(Instr):
    """
    Mark variable as tainted from an untrusted source.

    This instruction is inserted when data enters the program from
    an untrusted source (user input, file, network, etc.).

    In Frame formula: source(var, kind) * taint(var)

    Examples:
    - User input: request.args.get('id')
    - File read: open(path).read()
    - Environment: os.environ.get('KEY')
    """
    var: Union[Ident, PVar]  # Variable that receives tainted data
    kind: TaintKind          # What kind of source
    description: str = ""    # Human-readable description
    request: Optional[RequestType] = None   # kind REQUEST: what the request object holds

    def __str__(self) -> str:
        return f"taint_source({self.var}, {self.kind.value})"

    def get_written_vars(self) -> set:
        if isinstance(self.var, PVar):
            return {self.var.name}
        return {str(self.var)}


@dataclass
class TaintSink(Instr):
    """
    Mark expression as flowing to a security-sensitive sink.

    This instruction is inserted when data is used in a potentially
    dangerous operation (SQL query, shell command, HTML output, etc.).

    If tainted data reaches a sink without sanitization → vulnerability!

    In Frame formula: sink(exp, kind)
    Vulnerability check: taint(exp) * sink(exp, kind) is satisfiable

    Examples:
    - SQL sink: cursor.execute(query)
    - Shell sink: os.system(cmd)
    - HTML sink: render_template_string(html)
    """
    exp: Exp                 # Expression flowing to sink
    kind: SinkKind           # What kind of sink
    description: str = ""    # Human-readable description
    arg_index: int = 0       # Which argument is the sink (for calls)
    # Object whose method is the sink (`builder` in `builder.parse(x)`), when
    # the sink's safety depends on how that object was configured.
    receiver: Optional[str] = None
    # The call this sink was derived from, when it comes from a call spec. A call
    # that resolves to a project method is the project's code, not the library
    # function the name matches, so the translator drops the name-based sink.
    call: str = ""

    def __str__(self) -> str:
        return f"taint_sink({self.exp}, {self.kind.value})"

    def get_read_vars(self) -> set:
        return self.exp.free_vars()


@dataclass
class Sanitize(Instr):
    """
    Mark variable as sanitized for specific sink types.

    This instruction is inserted when data passes through a sanitizer
    (escape function, validator, encoder, etc.).

    Sanitization is sink-specific:
    - html.escape() sanitizes for HTML but not SQL
    - parameterized queries sanitize for SQL

    In Frame formula: sanitized(var)
    """
    var: Union[Ident, PVar]  # Variable that is sanitized
    sanitizes: List[SinkKind]  # Which sink types this sanitizes for
    description: str = ""    # Human-readable description

    def __str__(self) -> str:
        kinds = ", ".join(k.value for k in self.sanitizes)
        return f"sanitize({self.var}, [{kinds}])"

    def get_written_vars(self) -> set:
        # An annotation, not a write: the value (and what the path knows about it)
        # is unchanged; only what it is safe for is recorded.
        return set()


@dataclass
class AssertSafe(Instr):
    """
    Assert that expression is safe (defensive annotation).

    Used for:
    - Developer annotations (@safe, @trusted)
    - Validation results (if validate(x): ...)
    - Framework guarantees (ORM sanitizes by default)

    This suppresses vulnerability reports for this data flow.
    """
    exp: Exp                 # Expression asserted to be safe
    reason: str = ""         # Why it's considered safe
    for_sinks: List[SinkKind] = field(default_factory=list)  # Safe for which sinks

    def __str__(self) -> str:
        if self.for_sinks:
            kinds = ", ".join(k.value for k in self.for_sinks)
            return f"assert_safe({self.exp}, [{kinds}])"
        return f"assert_safe({self.exp})"

    def get_read_vars(self) -> set:
        return self.exp.free_vars()


# =============================================================================
# Additional Instructions
# =============================================================================

@dataclass
class Return(Instr):
    """
    Return from function.

    Optional return value for non-void functions.
    """
    value: Optional[Exp] = None

    def __str__(self) -> str:
        if self.value:
            return f"return {self.value}"
        return "return"

    def get_read_vars(self) -> set:
        if self.value:
            return self.value.free_vars()
        return set()


@dataclass
class Throw(Instr):
    """
    Throw exception.
    """
    exception: Exp

    def __str__(self) -> str:
        return f"throw {self.exception}"

    def get_read_vars(self) -> set:
        return self.exception.free_vars()


@dataclass
class Metadata(Instr):
    """
    Metadata instruction (no semantic effect).

    Used for:
    - Source mapping
    - Debug info
    - Scope markers
    """
    kind: str
    data: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return f"// {self.kind}: {self.data}"


# =============================================================================
# Instruction builders (convenience functions)
# =============================================================================

def load(id: Ident, exp: Exp, typ: Typ = None, loc: Location = None) -> Load:
    """Create a Load instruction"""
    return Load(
        loc=loc or Location.unknown(),
        id=id,
        exp=exp,
        typ=typ or Typ.unknown_type()
    )


def store(addr: Exp, value: Exp, typ: Typ = None, loc: Location = None) -> Store:
    """Create a Store instruction"""
    return Store(
        loc=loc or Location.unknown(),
        addr=addr,
        value=value,
        typ=typ or Typ.unknown_type()
    )


def alloc(id: Ident, size: Exp, typ: Typ = None, loc: Location = None) -> Alloc:
    """Create an Alloc instruction"""
    return Alloc(
        loc=loc or Location.unknown(),
        id=id,
        size=size,
        typ=typ or Typ.unknown_type()
    )


def free_mem(exp: Exp, loc: Location = None) -> Free:
    """Create a Free instruction"""
    return Free(loc=loc or Location.unknown(), exp=exp)


def call(func: str, args: List[Exp], ret_id: Ident = None, loc: Location = None) -> Call:
    """Create a Call instruction"""
    from .types import ExpConst
    return Call(
        loc=loc or Location.unknown(),
        ret=(ret_id, Typ.unknown_type()) if ret_id else None,
        func=ExpConst.string(func),
        args=[(arg, Typ.unknown_type()) for arg in args]
    )


def assign(id: Union[Ident, PVar], exp: Exp, loc: Location = None) -> Assign:
    """Create an Assign instruction"""
    return Assign(loc=loc or Location.unknown(), id=id, exp=exp)


def prune(condition: Exp, is_true: bool = True, loc: Location = None) -> Prune:
    """Create a Prune instruction"""
    return Prune(
        loc=loc or Location.unknown(),
        condition=condition,
        is_true_branch=is_true
    )


def taint_source(var: Union[Ident, PVar], kind: TaintKind, loc: Location = None) -> TaintSource:
    """Create a TaintSource instruction"""
    return TaintSource(loc=loc or Location.unknown(), var=var, kind=kind)


def taint_sink(exp: Exp, kind: SinkKind, loc: Location = None) -> TaintSink:
    """Create a TaintSink instruction"""
    return TaintSink(loc=loc or Location.unknown(), exp=exp, kind=kind)


def sanitize(var: Union[Ident, PVar], sinks: List[SinkKind], loc: Location = None) -> Sanitize:
    """Create a Sanitize instruction"""
    return Sanitize(loc=loc or Location.unknown(), var=var, sanitizes=sinks)
