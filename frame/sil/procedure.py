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
from typing import List, Dict, Optional, Set, Tuple, Iterator
from enum import Enum, auto

from .types import Ident, PVar, Typ, Location
from .instructions import Instr, TaintKind, SinkKind


# =============================================================================
# Procedure Specification
# =============================================================================

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

    def __str__(self) -> str:
        lines = [f"Program with {len(self.procedures)} procedures:"]
        for name in self.procedures:
            lines.append(f"  - {name}")
        return "\n".join(lines)

    # =========================================================================
    # Procedure management
    # =========================================================================

    def add_procedure(self, proc: Procedure) -> None:
        """Add a procedure to the program"""
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

    def get_spec(self, func_name: str) -> Optional[ProcSpec]:
        """
        Get specification for a function.

        Looks up in order:
        1. User-defined procedure specs
        2. Library specs (exact match)
        3. Library specs (method name match for var.method patterns)
        """
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
            method_name = func_name.split('.')[-1]
            # Try common type prefixes for the method
            for prefix in ['str', 'bytes', 'list', 'dict', 'set', 'object',
                           'ConfigParser', 'configparser.ConfigParser']:
                qualified_name = f"{prefix}.{method_name}"
                spec = self.library_specs.get(qualified_name)
                if spec:
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
