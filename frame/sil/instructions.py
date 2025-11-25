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
from typing import List, Optional, Tuple, Union
from enum import Enum, auto

from .types import Ident, PVar, Exp, ExpVar, Typ, Location


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

    def __str__(self) -> str:
        return self.value


class SinkKind(Enum):
    """Types of security-sensitive sinks"""
    SQL_QUERY = "sql"           # SQL query execution
    HTML_OUTPUT = "html"        # HTML output (XSS)
    SHELL_COMMAND = "shell"     # Shell command execution
    FILE_PATH = "filesystem"    # File path operations
    LDAP_QUERY = "ldap"         # LDAP query
    XPATH_QUERY = "xpath"       # XPath query
    EVAL = "eval"               # Dynamic code evaluation
    DESERIALIZATION = "deserialize"  # Object deserialization
    REDIRECT = "redirect"       # URL redirect
    HEADER = "header"           # HTTP header injection
    LOG = "log"                 # Log injection
    REGEX = "regex"             # ReDoS via regex
    SSRF = "ssrf"               # Server-side request forgery
    TEMPLATE = "template"       # Template injection

    def __str__(self) -> str:
        return self.value


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
        if isinstance(self.var, PVar):
            return {self.var.name}
        return {str(self.var)}


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
