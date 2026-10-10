"""
Procedure and Control Flow Graph definitions for Frame SIL.

This module defines:
- Node: A basic block in the CFG
- Procedure: A function/method with its CFG
- ProcSpec: Procedure specification (pre/post conditions)
- Program: A complete program with all procedures

The CFG representation enables:
- Path-sensitive analysis
- Compositional analysis via procedure specs
- Inter-procedural analysis via call graph
"""

from dataclasses import dataclass, field
from typing import Callable, List, Dict, Optional, Set, Tuple, Iterator
from enum import Enum, auto

from .types import Ident, PVar, Typ, Location
from .instructions import Instr, TaintKind, SinkKind


# =============================================================================
# Procedure Specification
# =============================================================================

def typed_spec_lookup(specs, recv_type: str, func_name: str, exact: bool,
                      by_name, receivers) -> Optional["ProcSpec"]:
    """Spec for `recv.method(...)` whose receiver has the declared type
    `recv_type`; `receivers(type)` names the spec keys for a type (Java:
    java_specs.type_spec_receivers).

    - A spec keyed on the type (`documentBuilder.parse` for DocumentBuilder)
      wins over any name-based match.
    - An `exact_class` spec (`Random.nextInt`) needs the receiver's runtime
      class to be known (`exact`); a value merely DECLARED Random may be a
      SecureRandom, and then nothing is reported.
    - Otherwise fall back to the name-based lookup (`by_name()`), except for a
      sink that needs no taint at all (`sink_args == []`): its name alone is
      not evidence once the receiver's type is known to be something else.
    """
    method = func_name.rsplit('.', 1)[1]
    for receiver in receivers(recv_type):
        spec = specs.get(f"{receiver}.{method}")
        if spec:
            return spec if (exact or not spec.exact_class) else None
    spec = by_name()
    if spec is not None and spec.is_sink and spec.sink_args == []:
        return None
    return spec


# `Call.receiver_type` values a frontend sets for a method call's receiver
# when it is not a declared type: DB_HANDLE for a known database handle,
# RECEIVER_UNKNOWN for a receiver of unknown kind (a chained call's IR name is
# only the method, so the name alone cannot tell it has a receiver). Any other
# kind ("Array", "module:crypto", ...) is known not to be a database handle.
DB_HANDLE = "DbHandle"
RECEIVER_UNKNOWN = "Unknown"


def db_method_applies(spec: Optional["ProcSpec"], func_name: str,
                      receiver_type: Optional[str]) -> bool:
    """False when `spec` is a database-handle method that this call cannot be:
    a call without a receiver (`find(xs, fn)`, a local function) or a receiver
    known to be something else (an array, a hash, a user object)."""
    if spec is None or not spec.db_method:
        return True
    if receiver_type in (DB_HANDLE, RECEIVER_UNKNOWN):
        return True
    if receiver_type is None:
        return '.' in func_name     # no receiver information: the name decides
    return False


# Receivers through which a member call still reaches a global function
# (`window.setTimeout`); see ProcSpec.global_only.
GLOBAL_OBJECTS = frozenset({"window", "global", "globalThis"})


@dataclass
class ProcSpec:
    """
    Procedure specification for compositional analysis.

    This captures the contract of a procedure:
    - What must hold before the call (requires)
    - What holds after the call (ensures)
    - What the procedure modifies

    For library functions, this also captures security-relevant behavior:
    - Is this a taint source?
    - Is this a taint sink?
    - Does it sanitize input?
    - How does taint propagate through it?
    """

    # Pre-condition: what must hold before call
    # This is a Frame formula string
    requires: Optional[str] = None

    # Post-condition: what holds after call
    # This is a Frame formula string
    ensures: Optional[str] = None

    # Modified variables/locations
    modifies: Set[str] = field(default_factory=set)

    # =========================================================================
    # Security-specific specifications
    # =========================================================================

    # Is this function a taint source?
    # If set, the return value is tainted with this kind
    is_source: Optional[str] = None

    # Is this function a taint sink?
    # If set, arguments at specified positions flow to this sink
    is_sink: Optional[str] = None

    # Which argument positions are sinks (0-indexed)
    # Default: [0] (first argument)
    sink_args: List[int] = field(default_factory=lambda: [0])

    # Is this function a sanitizer?
    # List of sink kinds that the return value is sanitized for
    is_sanitizer: List[str] = field(default_factory=list)

    # Taint propagation: which argument indices propagate taint to return
    # If [0, 1], then if arg0 or arg1 is tainted, return is tainted
    taint_propagates: List[int] = field(default_factory=list)

    # Taint propagation to destination: which args propagate taint to dest (arg 0)
    # For functions like strncat(dest, src, n) - src taint flows to dest
    # If [1], then if arg1 is tainted, arg0 becomes tainted
    taint_to_dest: List[int] = field(default_factory=list)

    # Does this function propagate taint from receiver (self/this)?
    taint_from_receiver: bool = False

    # =========================================================================
    # Memory specifications
    # =========================================================================

    # Does this function allocate memory?
    allocates: bool = False

    # Does this function free memory?
    frees: bool = False

    # Can this function return null?
    may_return_null: bool = False

    # =========================================================================
    # Structural weakness specifications
    #
    # These describe a property of the API itself rather than of a taint flow,
    # so the detectors that consult them are structural (they read the finished
    # CFG) instead of running during symbolic execution.
    # =========================================================================

    # Is discarding this function's return value a defect? (CWE-252)
    # Set only for APIs where the return is the ONLY failure signal and a
    # silent failure is a security event, for example the privilege-dropping
    # family. Most functions have a legitimately ignorable return, so the
    # default of False is the right one for nearly everything.
    return_must_be_checked: bool = False

    # Index of a POSIX permission-mode argument, if any (CWE-732).
    permission_mode_arg: Optional[int] = None

    # Does `permission_mode_arg` name a umask rather than a mode? A umask
    # CLEARS the bits it names, so the world-writable test inverts for it.
    permission_is_umask: bool = False

    # Index of a size argument allocated on the CALL STACK, if any (CWE-789).
    # Distinct from a heap allocation: the stack has a hard, small platform
    # limit, so an excessive constant here is provably unsatisfiable rather
    # than merely large.
    stack_allocation_size_arg: Optional[int] = None

    # Argument positions whose POINTEE the call fills with externally supplied
    # data (C input functions): the buffer of fgets/read/recv, the out-parameters
    # of scanf. `is_source` taints only the return value, but these functions are
    # normally called for their effect with the result ignored, so without this
    # the attacker data they deliver never becomes tainted.
    taint_out_args: List[int] = field(default_factory=list)

    # Does this spec name a GLOBAL function (`setTimeout`, `eval`)? Frontends
    # match a dotless spec key against the last segment of a member call
    # (`models.sequelize.query` -> `query`); for a global function that would
    # make any same-named method a sink (`req.setTimeout(ms, cb)` is the HTTP
    # request timeout, not the timer that evaluates strings). When set, a
    # member call matches only through the global object (`window.eval`).
    global_only: bool = False

    # Index of a verification-callback argument, if any (CWE-295). Installing
    # a verifier is not itself a flaw -- `setHostnameVerifier(getVerifier())`
    # usually installs a stricter one -- so such a sink fires only when the
    # callback provably accepts everything (a lambda / anonymous class whose
    # every return is `true`, or a library object documented as permissive).
    permissive_callback_arg: Optional[int] = None

    # Is the flaw specific to this exact class, not to every subtype? A value
    # DECLARED `java.util.Random` may be a SecureRandom, so `Random.nextInt` is
    # only matched when the class is named at the call (`new Random().nextInt`,
    # name-based lookup), never through a receiver's declared type.
    exact_class: bool = False

    # Is this a method of a DATABASE HANDLE (a MongoDB collection, a Mongoose
    # model or query)? The names -- find, update, remove, count -- are shared
    # with arrays, hashes, lodash and user code, so the spec applies only to a
    # call with a receiver, and not when the frontend knows the receiver is
    # some other kind of value (`Call.receiver_type` other than DB_HANDLE).
    db_method: bool = False

    # =========================================================================
    # Additional metadata
    # =========================================================================

    # Human-readable description
    description: str = ""

    # Is this a pure function (no side effects)?
    is_pure: bool = False

    def is_taint_source(self) -> bool:
        """Check if this function is a taint source"""
        return self.is_source is not None

    def is_taint_sink(self) -> bool:
        """Check if this function is a taint sink"""
        return self.is_sink is not None

    def is_taint_sanitizer(self) -> bool:
        """Check if this function sanitizes taint"""
        return len(self.is_sanitizer) > 0

    def propagates_taint(self) -> bool:
        """Check if this function can propagate taint"""
        return len(self.taint_propagates) > 0 or self.taint_from_receiver

    def is_allocator(self) -> bool:
        """Check if this function allocates memory (malloc, new, etc.)"""
        return self.allocates

    def is_deallocator(self) -> bool:
        """Check if this function frees memory (free, delete, etc.)"""
        return self.frees


# =============================================================================
# CFG Node
# =============================================================================

class NodeKind(Enum):
    """Kind of CFG node"""
    ENTRY = auto()        # Function entry point
    EXIT = auto()         # Function exit point
    NORMAL = auto()       # Normal basic block
    BRANCH = auto()       # Branch point (if/switch)
    JOIN = auto()         # Join point (merge of branches)
    LOOP_HEAD = auto()    # Loop header
    EXCEPTION = auto()    # Exception handler
    FINALLY = auto()      # Finally block


@dataclass
class Node:
    """
    A node in the Control Flow Graph.

    Each node is a basic block: a sequence of instructions with:
    - Single entry point (first instruction)
    - Single exit point (last instruction)
    - No branches in the middle

    Control flow is represented by successor/predecessor edges.
    """

    # Unique identifier within procedure
    id: int

    # Instructions in this basic block
    instrs: List[Instr] = field(default_factory=list)

    # Control flow edges
    succs: List[int] = field(default_factory=list)    # Successor node IDs
    preds: List[int] = field(default_factory=list)    # Predecessor node IDs

    # Exception handling edges
    exn_succs: List[int] = field(default_factory=list)  # Exception handler nodes

    # Node metadata
    kind: NodeKind = NodeKind.NORMAL
    label: Optional[str] = None  # Optional label for debugging

    # LOOP_HEAD nodes only: does the loop body contain a statement that can
    # transfer control out of the loop (break / return / throw / goto / yield)?
    # `break` has no SIL instruction, so the CFG alone cannot answer this; the
    # frontend records it from the parse tree. None means "not analysed", which
    # is what every other node carries, so a consumer must treat None as unknown.
    loop_body_can_exit: Optional[bool] = None

    def __str__(self) -> str:
        lines = [f"Node {self.id} ({self.kind.name}):"]
        for instr in self.instrs:
            lines.append(f"  {instr}")
        if self.succs:
            lines.append(f"  -> {self.succs}")
        return "\n".join(lines)

    def add_instr(self, instr: Instr) -> None:
        """Add an instruction to this node"""
        self.instrs.append(instr)

    def add_succ(self, node_id: int) -> None:
        """Add a successor edge"""
        if node_id not in self.succs:
            self.succs.append(node_id)

    def add_pred(self, node_id: int) -> None:
        """Add a predecessor edge"""
        if node_id not in self.preds:
            self.preds.append(node_id)

    def is_empty(self) -> bool:
        """Check if this node has no instructions"""
        return len(self.instrs) == 0

    def first_instr(self) -> Optional[Instr]:
        """Get the first instruction"""
        return self.instrs[0] if self.instrs else None

    def last_instr(self) -> Optional[Instr]:
        """Get the last instruction"""
        return self.instrs[-1] if self.instrs else None


# =============================================================================
# Procedure
# =============================================================================

@dataclass
class Procedure:
    """
    A procedure (function/method) in SIL.

    Contains:
    - Signature (name, parameters, return type)
    - Local variables
    - Control flow graph (CFG)
    - Specification (for compositional analysis)
    """

    # Procedure name (fully qualified)
    name: str

    # Parameters with types
    params: List[Tuple[PVar, Typ]] = field(default_factory=list)

    # Return type (None for void)
    ret_type: Optional[Typ] = None

    # Local variables
    locals: Dict[str, Typ] = field(default_factory=dict)

    # Control flow graph
    nodes: Dict[int, Node] = field(default_factory=dict)
    entry_node: int = 0
    exit_node: int = -1

    # Specification
    spec: ProcSpec = field(default_factory=ProcSpec)

    # Source location
    loc: Optional[Location] = None

    # Additional metadata
    is_method: bool = False           # Is this a method (has self/this)?
    class_name: Optional[str] = None  # Class name if method
    is_static: bool = False           # Is this a static method?
    is_constructor: bool = False      # Is this a constructor?

    # Does the body contain a try/catch? The frontends translate handler bodies
    # inline instead of giving them their own edges, so for a procedure with one
    # the CFG understates the ways control can leave. Any analysis that concludes
    # something from the ABSENCE of an exit path must abstain when this is set.
    has_exception_handler: bool = False

    # Locals declared as a fixed-size array, mapped to their element count, for
    # example `char buf[10]` -> {"buf": 10}. The IR lowers such a declaration to
    # `buf = null` and keeps no type, so the bound is a syntactic fact only the
    # frontend can see, in the same way `loop_body_can_exit` is. A name declared
    # more than once with different bounds is omitted rather than guessed at.
    fixed_array_bounds: Dict[str, int] = field(default_factory=dict)

    # Locals in `fixed_array_bounds` whose element type is a one-byte character
    # type (`char`, `unsigned char`, `signed char`, `uint8_t`, ...), so the
    # element count is also the capacity in bytes. Absent for every other
    # element type: byte-level copy checks only reason about these.
    char_array_locals: Set[str] = field(default_factory=set)

    # Every local declared with array syntax, whatever its size expression
    # (`char b[64]`, `char b[SOME_MACRO]`, `int m[N][M]`). `fixed_array_bounds`
    # only holds literal sizes, but a macro-sized array is still an array: its
    # name denotes storage, never an uninitialized scalar.
    array_locals: Set[str] = field(default_factory=set)

    # The function's source did not parse cleanly (typically unexpanded statement
    # macros such as `Py_BEGIN_ALLOW_THREADS` with no semicolon). tree-sitter
    # error-recovers, so the CFG can drop whole statements and loops; dataflow
    # facts derived from it (null-ness, definedness, freed state) are unreliable.
    has_parse_errors: bool = False

    # Procedures sharing one name (overloads; see Program.add_procedure): the
    # group's (parameter count, has varargs) and this one's position in it.
    # Members after the first are named `name#2`, `name#3`, ...; empty when
    # the name is unique.
    overload_arities: List[Tuple[int, bool]] = field(default_factory=list)
    overload_index: int = 0
    has_varargs: bool = False         # last parameter takes any number of args
    # Declared parameter types where the frontend knows them (Java), else
    # None per parameter; lets a call whose argument types differ be told
    # apart from a same-arity overload (e.g. one inherited from a superclass).
    param_type_names: List[Optional[str]] = field(default_factory=list)
    ret_type_name: Optional[str] = None
    # Does the enclosing class declare supertypes (extends / implements)? Then
    # an inherited overload, invisible in this file, may take a call.
    class_open: bool = True

    @property
    def simple_name(self) -> str:
        """The method/function name as called: `f` for `A.f` and `A.f#2`."""
        return self.name.rsplit(".", 1)[-1].split("#", 1)[0]

    def accepts_arity(self, n_args: int) -> bool:
        """Can a call with `n_args` arguments resolve to this overload? With no
        overload information, any call by this name can."""
        if not self.overload_arities:
            return True
        accepting = [i for i, (n, varargs) in enumerate(self.overload_arities)
                     if n_args == n or (varargs and n_args >= n - 1)]
        return accepting == [self.overload_index]

    # Internal state for building CFG
    _next_node_id: int = field(default=0, repr=False)

    def __str__(self) -> str:
        params_str = ", ".join(f"{p.name}: {t}" for p, t in self.params)
        ret_str = f" -> {self.ret_type}" if self.ret_type else ""
        return f"def {self.name}({params_str}){ret_str}"

    # =========================================================================
    # CFG Construction
    # =========================================================================

    def new_node(self, kind: NodeKind = NodeKind.NORMAL) -> Node:
        """Create a new CFG node"""
        node = Node(id=self._next_node_id, kind=kind)
        self._next_node_id += 1
        return node

    def add_node(self, node: Node) -> None:
        """Add a node to the CFG"""
        self.nodes[node.id] = node

    def connect(self, from_id: int, to_id: int) -> None:
        """Connect two nodes with an edge"""
        if from_id in self.nodes and to_id in self.nodes:
            self.nodes[from_id].add_succ(to_id)
            self.nodes[to_id].add_pred(from_id)

    def get_node(self, node_id: int) -> Optional[Node]:
        """Get a node by ID"""
        return self.nodes.get(node_id)

    # =========================================================================
    # CFG Traversal
    # =========================================================================

    def cfg_iter(self) -> Iterator[Node]:
        """Iterate over nodes in CFG order (BFS from entry)"""
        if self.entry_node not in self.nodes:
            return

        visited = set()
        queue = [self.entry_node]

        while queue:
            node_id = queue.pop(0)
            if node_id in visited or node_id not in self.nodes:
                continue

            visited.add(node_id)
            yield self.nodes[node_id]

            queue.extend(self.nodes[node_id].succs)

    def reverse_postorder(self) -> List[Node]:
        """Get nodes in reverse postorder (useful for dataflow)"""
        visited = set()
        postorder = []

        def dfs(node_id: int):
            if node_id in visited or node_id not in self.nodes:
                return
            visited.add(node_id)
            for succ_id in self.nodes[node_id].succs:
                dfs(succ_id)
            postorder.append(self.nodes[node_id])

        dfs(self.entry_node)
        return list(reversed(postorder))

    def get_all_instrs(self) -> Iterator[Instr]:
        """Iterate over all instructions in the procedure"""
        for node in self.cfg_iter():
            yield from node.instrs

    # =========================================================================
    # Analysis helpers
    # =========================================================================

    def get_param_names(self) -> List[str]:
        """Get list of parameter names"""
        return [p.name for p, _ in self.params]

    def get_local_names(self) -> List[str]:
        """Get list of local variable names"""
        return list(self.locals.keys())

    def get_all_vars(self) -> Set[str]:
        """Get all variable names (params + locals)"""
        result = set(self.get_param_names())
        result.update(self.get_local_names())
        return result


# =============================================================================
# Program
# =============================================================================

@dataclass
class Program:
    """
    A complete SIL program.

    Contains:
    - All procedures
    - Global variables
    - Library specifications (for known APIs)
    """

    # All procedures indexed by name
    procedures: Dict[str, Procedure] = field(default_factory=dict)

    # Global variables
    globals: Dict[str, Typ] = field(default_factory=dict)

    # Library specifications for external functions
    library_specs: Dict[str, ProcSpec] = field(default_factory=dict)

    # Source file information
    source_files: List[str] = field(default_factory=list)

    # Source language, set by the frontend. Needed where two languages give the
    # same SIL shape different meanings: an unqualified call to the enclosing
    # method's own name is recursion in Java and C#, which resolve it through the
    # implicit receiver, but names an unrelated free function in Python and
    # JavaScript, which require `self.` / `this.` for a method call.
    language: str = ""

    # C/C++: names of function-like macros defined in the translation unit. A
    # call to one may write its bare-variable arguments (see the translator's
    # `_arg_may_define`).
    function_macros: Set[str] = field(default_factory=set)

    # Language-specific map from a receiver's declared type to the receiver
    # names its specs are keyed under (Java: java_specs.type_spec_receivers);
    # used by spec_for_call when a Call carries `receiver_type`.
    type_spec_receivers: Optional[Callable[[str], tuple]] = None

    # Declared supertypes of each class in the program (Java), for overload
    # resolution's subtype test.
    class_supertypes: Dict[str, List[str]] = field(default_factory=dict)

    def __str__(self) -> str:
        lines = [f"Program with {len(self.procedures)} procedures:"]
        for name in self.procedures:
            lines.append(f"  - {name}")
        return "\n".join(lines)

    # =========================================================================
    # Procedure management
    # =========================================================================

    # -- Java overload resolution (JLS 15.12, approximated soundly) ------------

    _WIDENING = {
        "byte": {"short", "int", "long", "float", "double"},
        "short": {"int", "long", "float", "double"},
        "char": {"int", "long", "float", "double"},
        "int": {"long", "float", "double"},
        "long": {"float", "double"},
        "float": {"double"},
        "double": set(), "boolean": set(),
    }
    _BOX = {"int": "Integer", "long": "Long", "short": "Short", "byte": "Byte",
            "char": "Character", "float": "Float", "double": "Double", "boolean": "Boolean"}
    # Every supertype of these final JDK types: nothing else accepts them.
    _NUMBER_SUPERS = frozenset({"Object", "Number", "Comparable", "Serializable",
                                "Constable", "ConstantDesc"})
    _FINAL_SUPERTYPES = dict.fromkeys(("Integer", "Long", "Short", "Byte", "Float", "Double"),
                                      _NUMBER_SUPERS)
    _FINAL_SUPERTYPES.update({
        "String": frozenset({"Object", "CharSequence", "Comparable", "Serializable",
                             "Constable", "ConstantDesc"}),
        "Boolean": frozenset({"Object", "Comparable", "Serializable", "Constable"}),
        "Character": frozenset({"Object", "Comparable", "Serializable", "Constable"}),
    })

    def _supertypes(self, cls: str) -> Optional[set]:
        """All supertypes of an in-file class, or None when its hierarchy
        leaves the file (an unknown superclass could be anything)."""
        if cls not in self.class_supertypes:
            return None
        seen, todo, known = set(), [cls], True
        while todo:
            c = todo.pop()
            if c in seen:
                continue
            seen.add(c)
            if c not in self.class_supertypes:
                if c != cls:
                    known = False
                continue
            todo.extend(self.class_supertypes[c])
        seen.discard(cls)
        return (seen | {"Object"}) if known else None

    def java_convertible(self, arg: Optional[str], param: Optional[str]) -> str:
        """Can an argument of static type `arg` be passed for `param`?
        "yes", "no", or "maybe" when the types do not settle it."""
        if arg is None or param is None:
            return "maybe"
        if arg == param:
            return "yes"
        prim = self._WIDENING
        if arg == "null":
            return "no" if param in prim else "yes"
        if param == "Object":
            return "yes"
        if arg in prim:
            if param in prim:
                return "yes" if param in prim[arg] else "no"
            if param == self._BOX[arg] or param in ("Number", "Comparable", "Serializable") \
                    and arg != "boolean":
                return "yes"
            return "no"
        if param in prim:
            unboxed = {v: k for k, v in self._BOX.items()}.get(arg)
            if unboxed is None:
                return "no"
            return "yes" if unboxed == param or param in prim[unboxed] else "no"
        if arg.endswith("[]") or param.endswith("[]"):
            if arg.endswith("[]") and param.endswith("[]"):
                a_elem, p_elem = arg[:-2], param[:-2]
                if a_elem in prim or p_elem in prim:   # no widening of primitive arrays
                    return "yes" if a_elem == p_elem else "no"
                return self.java_convertible(a_elem, p_elem)
            if arg.endswith("[]"):
                return "yes" if param in ("Cloneable", "Serializable") else "no"
            return "no"
        if arg in self._FINAL_SUPERTYPES:
            return "yes" if param in self._FINAL_SUPERTYPES[arg] else "no"
        supers = self._supertypes(arg)
        if supers is not None:
            return "yes" if param in supers else "no"
        return "maybe"

    def resolve_java_call(self, class_name: str, method: str,
                          arg_types: List[Optional[str]]) -> Optional[Procedure]:
        """The procedure an unqualified call `method(args)` inside
        `class_name` invokes, or None when the file cannot settle it.

        Candidates are the class's methods of that name whose arity fits and
        none of whose parameters provably rejects its argument. The call
        resolves only to a single remaining candidate, and only if no hidden
        overload could win: every argument matches its parameter exactly (no
        inherited method is more specific than an exact match), or the class
        has no supertypes at all."""
        n = len(arg_types)
        cands = []
        for p in self.procedures.values():
            if p.class_name != class_name or p.simple_name != method:
                continue
            params = p.param_type_names or [None] * len(p.params)
            if not (n == len(params) or (p.has_varargs and n >= len(params) - 1)):
                continue
            verdicts = []
            for i, a in enumerate(arg_types):
                if p.has_varargs and i >= len(params) - 1:
                    last = params[-1]
                    if n == len(params) and self.java_convertible(a, last) == "yes":
                        verdicts.append("yes")
                        continue
                    t = last[:-2] if last and last.endswith("[]") else None
                else:
                    t = params[i]
                verdicts.append(self.java_convertible(a, t))
            if "no" not in verdicts:
                cands.append((p, verdicts, params))
        def exact(params):
            return len(arg_types) == len(params) and all(
                a is not None and a == t for a, t in zip(arg_types, params))

        # An exact match is the most specific applicable method: any other
        # applicable overload (here or inherited) takes supertypes of these
        # argument types, so Java picks the exact one.
        exact_cands = [p for p, _, params in cands if exact(params)]
        if len(exact_cands) == 1:
            return exact_cands[0]
        if len(cands) != 1:
            return None
        p, verdicts, params = cands[0]
        # Only one candidate here: it is the method called unless a supertype
        # of the class could contribute an overload this file does not show.
        return None if p.class_open else p

    def add_procedure(self, proc: Procedure) -> None:
        """Add a procedure to the program.

        A second procedure with a name already present -- a Java/C#/C++
        overload, a Python property setter, the other arm of a C `#ifdef` -- is
        kept as `name#2`, `name#3`, ... rather than replacing the first, whose
        body would otherwise never be analysed. Every member of such a group
        records the group's arities so calls resolve to the right one
        (Procedure.accepts_arity)."""
        if self.procedures.get(proc.name) is proc:
            return
        base = proc.name
        if base in self.procedures:
            group = [p for p in self.procedures.values()
                     if p.name == base or p.name.startswith(base + "#")]
            proc.name = f"{base}#{len(group) + 1}"
            group.append(proc)
            arities = [(len(p.params), p.has_varargs) for p in group]
            for i, p in enumerate(group):
                p.overload_arities = list(arities)
                p.overload_index = i
        self.procedures[proc.name] = proc

    def get_procedure(self, name: str) -> Optional[Procedure]:
        """Get a procedure by name"""
        return self.procedures.get(name)

    def has_procedure(self, name: str) -> bool:
        """Check if procedure exists"""
        return name in self.procedures

    # =========================================================================
    # Specification lookup
    # =========================================================================

    def spec_for_call(self, call) -> Optional[ProcSpec]:
        """Spec for a Call instruction: by the receiver's declared type first
        (`DocumentBuilder b; b.parse` -> `documentBuilder.parse`), then by name."""
        spec = self._spec_for_call(call)
        if not db_method_applies(spec, call.get_full_name(), getattr(call, "receiver_type", None)):
            return None
        return spec

    def _spec_for_call(self, call) -> Optional[ProcSpec]:
        func_name = call.get_full_name()
        recv_type = getattr(call, "receiver_type", None)
        if recv_type:
            # A method defined in this program (`m(x)` inside the class that
            # declares m, or a call on a variable of a class in this file) is
            # that procedure, not a same-named library API: no library spec, so
            # the translator's default handling of program calls applies
            # (argument taint flows to the result). Returning the procedure's
            # own empty ProcSpec would switch that propagation off.
            method = func_name.rsplit('.', 1)[-1]
            for proc in self.procedures.values():
                if proc.class_name == recv_type and proc.simple_name == method:
                    return None
        if recv_type and self.type_spec_receivers and '.' in func_name:
            return typed_spec_lookup(
                self.library_specs, recv_type, func_name,
                getattr(call, "receiver_exact", False),
                lambda: self.get_spec(func_name), self.type_spec_receivers)
        return self.get_spec(func_name)

    def get_spec(self, func_name: str) -> Optional[ProcSpec]:
        """
        Get specification for a function.

        Looks up in order:
        1. User-defined procedure specs
        2. Library specs (exact match)
        3. Library specs (method name match for var.method patterns)

        A database-handle method (`db_method`) never matches an unqualified
        call; with a receiver, see spec_for_call.
        """
        spec = self._get_spec(func_name)
        return spec if db_method_applies(spec, func_name, None) else None

    def _get_spec(self, func_name: str) -> Optional[ProcSpec]:
        # Check user procedures first
        if func_name in self.procedures:
            return self.procedures[func_name].spec

        # Check library specs (exact match)
        spec = self.library_specs.get(func_name)
        if spec:
            return spec

        # For method calls like "var.method", try matching just the method name
        # This handles cases like "__nested_4.decode" matching "str.decode" or "bytes.decode"
        if '.' in func_name:
            # First try suffix match for chained patterns like getWriter().format
            # This gives priority to more specific patterns like getWriter().format over String.format
            parts = func_name.split('.')
            for i in range(1, len(parts)):
                suffix = '.'.join(parts[i:])
                spec = self.library_specs.get(suffix)
                if spec:
                    if spec.global_only and '.'.join(parts[:i]) not in GLOBAL_OBJECTS:
                        return None
                    return spec

            method_name = parts[-1]
            # A capitalised receiver names a class or a module constant
            # (`GSSManager.getInstance`, `SUBPROCESS_OPTIONS.get`), whose type
            # is not ours to guess: guessing made every `Calendar.getInstance()`
            # a MessageDigest.getInstance and every WeakMap lookup a request.get.
            receiver = '.'.join(parts[:-1])
            if receiver.rsplit('.', 1)[-1][:1].isupper():
                return None
            # Try common type prefixes for the method (Python and Java)
            for prefix in ['str', 'bytes', 'list', 'dict', 'set', 'object',
                           'ConfigParser', 'configparser.ConfigParser',
                           # Java prefixes
                           'request', 'response', 'session', 'connection',
                           'statement', 'PreparedStatement', 'Statement',
                           'Runtime', 'runtime', 'ProcessBuilder', 'processBuilder',
                           'URLDecoder', 'URLEncoder', 'java.net.URLDecoder', 'java.net.URLEncoder',
                           'Base64', 'java.util.Base64',
                           'String', 'StringBuilder', 'StringBuffer',
                           'MessageDigest', 'Cipher', 'SecretKeySpec',
                           'ObjectInputStream', 'ObjectOutputStream',
                           'FileInputStream', 'FileOutputStream', 'File',
                           'DocumentBuilder', 'SAXParser', 'XMLReader',
                           'XPath', 'xpath', 'DirContext', 'ldapTemplate']:
                qualified_name = f"{prefix}.{method_name}"
                spec = self.library_specs.get(qualified_name)
                # A guessed type is not evidence for a sink that fires on mere
                # use (`getFactory().getInstance()` is not MessageDigest's).
                if spec and not (spec.exact_class or
                                 (spec.is_sink and spec.sink_args == [])):
                    return spec
            # Also try bare method name (e.g., "xpath" for "root.xpath")
            spec = self.library_specs.get(method_name)
            if spec and not spec.global_only:
                return spec

        return None

    def add_library_spec(self, func_name: str, spec: ProcSpec) -> None:
        """Add a library specification"""
        self.library_specs[func_name] = spec

    def is_source(self, func_name: str) -> bool:
        """Check if function is a taint source"""
        spec = self.get_spec(func_name)
        return spec.is_taint_source() if spec else False

    def is_sink(self, func_name: str) -> bool:
        """Check if function is a taint sink"""
        spec = self.get_spec(func_name)
        return spec.is_taint_sink() if spec else False

    def is_sanitizer(self, func_name: str) -> bool:
        """Check if function is a sanitizer"""
        spec = self.get_spec(func_name)
        return spec.is_taint_sanitizer() if spec else False

    # =========================================================================
    # Analysis
    # =========================================================================

    def get_call_graph(self) -> Dict[str, Set[str]]:
        """
        Build the call graph.

        Returns a dict mapping procedure name to set of called procedure names.
        """
        from .instructions import Call

        call_graph = {}

        for proc_name, proc in self.procedures.items():
            callees = set()

            for instr in proc.get_all_instrs():
                if isinstance(instr, Call):
                    callee = instr.get_func_name()
                    callees.add(callee)

            call_graph[proc_name] = callees

        return call_graph

    def get_entry_points(self) -> List[str]:
        """
        Get likely entry point procedures.

        Heuristics:
        - Functions named 'main'
        - Functions not called by anyone else
        - HTTP handlers (for web frameworks)
        """
        call_graph = self.get_call_graph()

        # Find all callees
        all_callees = set()
        for callees in call_graph.values():
            all_callees.update(callees)

        # Entry points are procedures not called by others
        entry_points = []
        for proc_name in self.procedures:
            if proc_name not in all_callees:
                entry_points.append(proc_name)

            # Also include 'main' even if called
            if proc_name in ('main', '__main__'):
                if proc_name not in entry_points:
                    entry_points.append(proc_name)

        return entry_points

    def iter_all_instrs(self) -> Iterator[Tuple[str, Node, Instr]]:
        """Iterate over all instructions in all procedures"""
        for proc_name, proc in self.procedures.items():
            for node in proc.cfg_iter():
                for instr in node.instrs:
                    yield proc_name, node, instr
