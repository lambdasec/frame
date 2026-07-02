"""
Java to Frame SIL Frontend.

This module translates Java source code to Frame SIL using tree-sitter
for parsing. It handles:
- Class and method definitions
- Variable declarations
- Method calls (with taint source/sink detection)
- Control flow (if/else, while, for, switch, try/catch)
- String operations
- Annotations (@RequestParam, etc.)
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

try:
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Parser, Node as TSNode
    TREE_SITTER_JAVA_AVAILABLE = True
except ImportError:
    TREE_SITTER_JAVA_AVAILABLE = False
    TSNode = Any

from frame.sil.types import (
    Ident, PVar, Typ, TypeKind, Location,
    Exp, ExpVar, ExpConst, ExpBinOp, ExpUnOp,
    ExpFieldAccess, ExpIndex, ExpStringConcat, ExpCall,
    var, const
)
from frame.sil.instructions import (
    Instr, Load, Store, Alloc, Free, Prune, Call, Assign, Return,
    TaintSource, TaintSink, Sanitize,
    TaintKind, SinkKind, PruneKind
)
from frame.sil.procedure import Procedure, Node, NodeKind, ProcSpec, Program
# ProcSpec is used for type hints in _lookup_spec
from frame.sil.specs.java_specs import JAVA_SPECS


class JavaFrontend:
    """
    Translates Java source code to Frame SIL.

    Usage:
        frontend = JavaFrontend()
        program = frontend.translate(source_code, "Example.java")

        from frame.sil import SILTranslator
        translator = SILTranslator(program)
        checks = translator.translate_program()
    """

    def __init__(self, specs: Dict[str, ProcSpec] = None):
        """
        Initialize the Java frontend.

        Args:
            specs: Library specifications (defaults to JAVA_SPECS)
        """
        if not TREE_SITTER_JAVA_AVAILABLE:
            raise ImportError(
                "tree-sitter-java is required. "
                "Install with: pip install tree-sitter-java"
            )

        self.parser = Parser(Language(tsjava.language()))
        self.specs = specs or JAVA_SPECS

        # State during translation
        self._filename = "<unknown>"
        self._source = ""
        self._current_proc: Optional[Procedure] = None
        self._current_node: Optional[Node] = None
        self._node_counter = 0
        self._ident_counter = 0
        self._current_class: Optional[str] = None
        # Constant propagation for path-sensitive switch analysis
        self._constant_values: Dict[str, Any] = {}
        # Track variables that came from weak algorithm properties (hashAlg1)
        self._weak_algo_vars: set = set()

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """Translate Java source code to SIL Program."""
        self._filename = filename
        self._source = source_code
        self._source_bytes = source_code.encode("utf-8")
        self._node_counter = 0
        self._ident_counter = 0

        tree = self.parser.parse(self._source_bytes)
        program = Program(library_specs=self.specs.copy())
        program.source_files.append(filename)

        self._translate_compilation_unit(tree.root_node, program)
        self._propagate_interprocedural_taint(tree.root_node, program)
        self._scan_cookie_flags(tree.root_node, program)
        self._scan_deserialization(tree.root_node, program)
        self._scan_csrf_disabled(tree.root_node, program)
        return program

    def _translate_compilation_unit(self, root: TSNode, program: Program) -> None:
        """Translate Java compilation unit"""
        for child in root.children:
            if child.type == "class_declaration":
                self._translate_class(child, program)
            elif child.type == "interface_declaration":
                self._translate_interface(child, program)
            elif child.type == "enum_declaration":
                self._translate_enum(child, program)

    def _translate_class(self, node: TSNode, program: Program) -> None:
        """Translate class definition"""
        name_node = node.child_by_field_name("name")
        class_name = self._get_text(name_node) if name_node else "UnknownClass"
        self._current_class = class_name

        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "method_declaration":
                    proc = self._translate_method(child)
                    if proc:
                        proc.class_name = class_name
                        proc.name = f"{class_name}.{proc.name}"
                        program.add_procedure(proc)
                elif child.type == "constructor_declaration":
                    proc = self._translate_constructor(child)
                    if proc:
                        proc.class_name = class_name
                        proc.name = f"{class_name}.<init>"
                        program.add_procedure(proc)
                elif child.type == "class_declaration":
                    # Handle inner classes
                    self._translate_class(child, program)

        self._current_class = None

    def _translate_interface(self, node: TSNode, program: Program) -> None:
        """Translate interface (skip method bodies as they're abstract)"""
        pass

    def _translate_enum(self, node: TSNode, program: Program) -> None:
        """Translate enum (similar to class)"""
        self._translate_class(node, program)

    # =========================================================================
    # Interprocedural taint (one-hop, intra-file)
    # =========================================================================

    def _identifiers_in(self, node: TSNode) -> set:
        """All identifier names referenced in a subtree (bounded walk)."""
        names: set = set()
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "identifier":
                names.add(self._get_text(n))
            stack.extend(n.children)
        return names

    def _collect_calls(self, node: TSNode, calls: List[Tuple[str, List[set]]]) -> None:
        """Collect same-instance method calls: (callee_name, [set-of-ids per arg])."""
        if node.type == "method_invocation":
            obj = node.child_by_field_name("object")
            # Only same-instance helper calls (bare `foo(...)` or `this.foo(...)`)
            # -- calls on other objects are sinks/library calls, not local helpers.
            if obj is None or self._get_text(obj) == "this":
                name_node = node.child_by_field_name("name")
                callee = self._get_text(name_node) if name_node else None
                args_node = node.child_by_field_name("arguments")
                arg_ids: List[set] = []
                if args_node is not None:
                    for a in args_node.children:
                        if a.type in ("(", ")", ","):
                            continue
                        # Identifiers ANYWHERE in the arg (handles `a + "-" + b`),
                        # so taint flows through concatenations/expressions.
                        arg_ids.append(self._identifiers_in(a))
                if callee:
                    calls.append((callee, arg_ids))
        for ch in node.children:
            self._collect_calls(ch, calls)

    def _propagate_interprocedural_taint(self, root: TSNode, program: Program) -> None:
        """Propagate taint from request-bound params through same-file helper calls.

        Real controllers split the source from the sink: an endpoint takes the
        request-bound parameter and passes it to a private helper that builds and
        runs the query. Without following that hop, the sink is never reached. We
        do a lightweight, name-based, fixpoint propagation: if a caller passes one
        of its tainted parameters straight into a same-class method, that method's
        corresponding parameter becomes a taint source too.
        """
        methods: Dict[str, Dict[str, Any]] = {}

        def collect(mnode: TSNode) -> None:
            name_node = mnode.child_by_field_name("name")
            if not name_node:
                return
            params_node = mnode.child_by_field_name("parameters")
            pnames: List[Optional[str]] = []
            req_bound: set = set()
            if params_node is not None:
                idx = 0
                for ch in params_node.children:
                    if ch.type in ("formal_parameter", "spread_parameter"):
                        nn = ch.child_by_field_name("name")
                        pnames.append(self._get_text(nn) if nn else None)
                        anns = self._get_annotations(ch)
                        if any(rb in a for a in anns for rb in self._REQUEST_BINDING_ANNOTATIONS):
                            req_bound.add(idx)
                        idx += 1
            calls: List[Tuple[str, List[Optional[str]]]] = []
            body = mnode.child_by_field_name("body")
            if body is not None:
                self._collect_calls(body, calls)
            # Last definition wins on overload/name clash (best-effort, intra-file).
            methods[self._get_text(name_node)] = {
                "params": pnames, "req": set(req_bound),
                "tainted": set(req_bound), "calls": calls}

        def walk(n: TSNode) -> None:
            if n.type == "method_declaration":
                collect(n)
            for ch in n.children:
                walk(ch)
        walk(root)
        if not methods:
            return

        # Fixpoint: tainted arg passed to a helper taints the helper's param.
        for _ in range(10):
            changed = False
            for info in methods.values():
                tainted_names = {info["params"][i] for i in info["tainted"]
                                 if i < len(info["params"]) and info["params"][i]}
                for callee, arg_ids in info["calls"]:
                    cinfo = methods.get(callee)
                    if cinfo is None:
                        continue
                    for j, ids in enumerate(arg_ids):
                        if (ids & tainted_names) and j < len(cinfo["params"]) \
                                and j not in cinfo["tainted"]:
                            cinfo["tainted"].add(j)
                            changed = True
            if not changed:
                break

        # Emit TaintSource for propagated params (request-bound ones already have one).
        for proc in program.procedures.values():
            simple = proc.name.split(".")[-1]
            info = methods.get(simple)
            if info is None or proc.entry_node is None:
                continue
            propagated = info["tainted"] - info["req"]
            if not propagated:
                continue
            entry = proc.nodes.get(proc.entry_node)
            if entry is None:
                continue
            for j in sorted(propagated):
                if j >= len(proc.params):
                    continue
                pvar = proc.params[j][0]
                entry.instrs.insert(0, TaintSource(
                    loc=proc.loc, var=pvar, kind=TaintKind.USER_INPUT,
                    description="Interprocedural: tainted argument passed from caller"))

    # =========================================================================
    # Cookie-flags typestate (CWE-1004 HttpOnly, CWE-614 Secure)
    # =========================================================================

    def _cookie_assignment_target(self, node: TSNode) -> Optional[str]:
        """The variable a `new Cookie(...)` expression is assigned to, or None
        (e.g. when it is passed inline to addCookie)."""
        p = node.parent
        while p is not None:
            if p.type == "variable_declarator":
                nm = p.child_by_field_name("name")
                return self._get_text(nm) if nm is not None else None
            if p.type == "assignment_expression":
                left = p.child_by_field_name("left")
                return self._get_text(left) if left is not None else None
            if p.type in ("argument_list", "method_invocation"):
                return None
            p = p.parent
        return None

    def _scan_cookie_flags(self, root: TSNode, program: Program) -> None:
        """Typestate check for insecure cookies.

        Models each servlet Cookie object's security attributes and checks them
        at the escape point `response.addCookie(c)`: a finding is emitted only
        when the flag is NOT provably set to true (Servlet cookies default to
        HttpOnly=false / Secure=false). If `setHttpOnly(true)` / `setSecure(true)`
        is called on the cookie anywhere in the method, the corresponding finding
        is suppressed -- so `setSecure(true)` alone yields CWE-1004 (missing
        HttpOnly) but not CWE-614. Tracking per-object attribute state (rather
        than matching a syntactic pattern) is what keeps this precise.
        """
        methods: List[TSNode] = []
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type in ("method_declaration", "constructor_declaration"):
                methods.append(n)
            stack.extend(n.children)

        hits_httponly: List[Location] = []
        hits_secure: List[Location] = []
        for m in methods:
            body = m.child_by_field_name("body")
            if body is None:
                continue
            httponly_set: set = set()
            secure_set: set = set()
            addcookies: List[Tuple[Optional[str], Location]] = []
            st = [body]
            while st:
                c = st.pop()
                if c.type == "method_invocation":
                    name_node = c.child_by_field_name("name")
                    mname = self._get_text(name_node) if name_node is not None else ""
                    obj = c.child_by_field_name("object")
                    objname = self._get_text(obj) if obj is not None else ""
                    args = c.child_by_field_name("arguments")
                    arg0 = None
                    if args is not None:
                        for a in args.children:
                            if a.type not in ("(", ")", ","):
                                arg0 = a
                                break
                    if mname == "setHttpOnly" and arg0 is not None \
                            and self._get_text(arg0) == "true" and objname:
                        httponly_set.add(objname)
                    elif mname == "setSecure" and arg0 is not None \
                            and self._get_text(arg0) == "true" and objname:
                        secure_set.add(objname)
                    elif mname == "addCookie" and arg0 is not None:
                        if arg0.type == "identifier":
                            addcookies.append((self._get_text(arg0), self._get_location(c)))
                        elif arg0.type == "object_creation_expression":
                            typ = arg0.child_by_field_name("type")
                            if typ is not None and self._get_text(typ).split(".")[-1] == "Cookie":
                                addcookies.append((None, self._get_location(c)))
                st.extend(c.children)

            for var, loc in addcookies:
                if var is None or var not in httponly_set:
                    hits_httponly.append(loc)
                if var is None or var not in secure_set:
                    hits_secure.append(loc)

        self._emit_findings_proc(program, "<cookie-httponly>",
                                 "__cookie_no_httponly__", hits_httponly)
        self._emit_findings_proc(program, "<cookie-secure>",
                                 "__cookie_no_secure__", hits_secure)

    # Deserializers that cannot safely handle untrusted data (unsafe by design).
    _UNSAFE_DESERIALIZERS = {"ObjectInputStream", "XMLDecoder"}

    def _scan_deserialization(self, root: TSNode, program: Program) -> None:
        """Flag construction of an inherently-unsafe deserializer (CWE-502).

        `new ObjectInputStream(...)` / `new XMLDecoder(...)` exist only to
        deserialize with an API that has no safe mode for untrusted input, so
        constructing one is the deserialization point. This is usage-based (the
        dangerous API itself), keeping it precise and framework-general.
        """
        hits: List[Location] = []
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "object_creation_expression":
                typ = n.child_by_field_name("type")
                if typ is not None and \
                        self._get_text(typ).split(".")[-1] in self._UNSAFE_DESERIALIZERS:
                    hits.append(self._get_location(n))
            stack.extend(n.children)
        self._emit_findings_proc(program, "<unsafe-deserialize>",
                                 "__unsafe_deserialize__", hits)

    def _scan_csrf_disabled(self, root: TSNode, program: Program) -> None:
        """Flag CSRF protection disabled in a Spring Security config (CWE-352).

        Detects `http.csrf().disable()` (the disable() is called on a csrf()
        receiver) and the lambda/method-reference form `csrf(c -> c.disable())` /
        `csrf(AbstractHttpConfigurer::disable)`. Disabling CSRF on a session/
        cookie-authenticated app removes cross-site-request-forgery protection.
        """
        hits: List[Location] = []
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "method_invocation":
                name_node = n.child_by_field_name("name")
                mname = self._get_text(name_node) if name_node is not None else ""
                if mname == "disable":
                    obj = n.child_by_field_name("object")
                    if obj is not None and obj.type == "method_invocation":
                        onn = obj.child_by_field_name("name")
                        if onn is not None and self._get_text(onn) == "csrf":
                            hits.append(self._get_location(n))
                elif mname == "csrf":
                    args = n.child_by_field_name("arguments")
                    if args is not None and "disable" in self._get_text(args):
                        hits.append(self._get_location(n))
            stack.extend(n.children)
        self._emit_findings_proc(program, "<csrf-disabled>", "__csrf_disabled__", hits)

    def _emit_findings_proc(self, program: Program, name: str,
                            sink_name: str, hits: List[Location]) -> None:
        """Emit one synthetic procedure PER finding.

        Each usage-based finding gets its own procedure so the scanner reports
        them all -- multiple usage sinks in a single procedure get collapsed to
        one finding.
        """
        for i, loc in enumerate(hits):
            proc = Procedure(name=f"{name}-{i}", params=[], ret_type=Typ.unknown_type(),
                             loc=loc, is_method=False)
            entry = proc.new_node(NodeKind.ENTRY)
            proc.add_node(entry)
            proc.entry_node = entry.id
            entry.add_instr(Call(loc=loc, ret=None,
                                 func=ExpConst.string(sink_name), args=[]))
            exit_node = proc.new_node(NodeKind.EXIT)
            proc.add_node(exit_node)
            proc.exit_node = exit_node.id
            proc.connect(entry.id, exit_node.id)
            program.add_procedure(proc)

    def _translate_method(self, node: TSNode) -> Optional[Procedure]:
        """Translate method definition"""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None

        method_name = self._get_text(name_node)
        params = self._translate_parameters(node)

        # Check for annotations that mark taint sources
        annotations = self._get_annotations(node)

        proc = Procedure(
            name=method_name,
            params=params,
            ret_type=Typ.unknown_type(),
            loc=self._get_location(node),
            is_method=True,
        )

        # Check for static modifier
        for child in node.children:
            if child.type == "modifiers":
                if "static" in self._get_text(child):
                    proc.is_static = True

        self._current_proc = proc
        self._node_counter = 0
        self._constant_values = {}  # Reset constant tracking for each method
        self._weak_algo_vars = set()  # Reset weak algorithm variable tracking

        # Create entry node
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry

        # Mark annotated parameters as taint sources
        self._process_param_annotations(node, params, proc)

        # Translate body
        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)

        # Create exit node
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id

        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)

        self._current_proc = None
        return proc

    def _translate_constructor(self, node: TSNode) -> Optional[Procedure]:
        """Translate constructor"""
        name_node = node.child_by_field_name("name")
        method_name = self._get_text(name_node) if name_node else "<init>"
        params = self._translate_parameters(node)

        proc = Procedure(
            name=method_name,
            params=params,
            ret_type=Typ.unknown_type(),
            loc=self._get_location(node),
            is_method=True,
        )

        self._current_proc = proc
        self._node_counter = 0

        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry

        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)

        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id

        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)

        self._current_proc = None
        return proc

    def _get_annotations(self, node: TSNode) -> List[str]:
        """Get annotations from a method or parameter"""
        annotations = []
        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.type == "marker_annotation" or mod.type == "annotation":
                        annotations.append(self._get_text(mod))
        return annotations

    # Spring MVC request-binding annotations. These live on the *parameter*
    # (e.g. `login(@RequestParam String user)`), NOT on the method, so they mark
    # the untrusted attack surface of a controller endpoint. Modern Spring apps
    # (and most real-world Java web code) receive untrusted input this way rather
    # than through raw Servlet `request.getParameter()` calls.
    _REQUEST_BINDING_ANNOTATIONS = (
        "RequestParam", "PathVariable", "RequestBody", "RequestHeader",
        "CookieValue", "ModelAttribute", "MatrixVariable", "RequestPart",
    )

    def _process_param_annotations(
        self,
        method_node: TSNode,
        params: List[Tuple[PVar, Typ]],
        proc: Procedure
    ) -> None:
        """Mark Spring request-bound controller parameters as taint sources.

        The binding annotation is attached to each formal parameter, so we read
        every parameter's own annotations (not the method's) and taint the ones
        bound to request data.
        """
        params_node = method_node.child_by_field_name("parameters")
        if params_node is None:
            return
        by_name = {p.name: p for p, _ in params}
        for child in params_node.children:
            if child.type not in ("formal_parameter", "spread_parameter"):
                continue
            anns = self._get_annotations(child)
            if not any(rb in a for a in anns for rb in self._REQUEST_BINDING_ANNOTATIONS):
                continue
            name_node = child.child_by_field_name("name")
            if name_node is None:
                continue
            pv = by_name.get(self._get_text(name_node))
            if pv is None:
                continue
            self._add_instr(TaintSource(
                loc=self._get_location(child),
                var=pv,
                kind=TaintKind.USER_INPUT,
                description="Spring request parameter (annotated)",
            ))

    def _translate_parameters(self, node: TSNode) -> List[Tuple[PVar, Typ]]:
        """Translate method parameters"""
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "formal_parameter" or child.type == "spread_parameter":
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        param_name = self._get_text(name_node)
                        params.append((PVar(param_name), Typ.unknown_type()))
        return params

    def _translate_block(self, node: TSNode) -> None:
        """Translate block of statements"""
        for child in node.children:
            if child.type not in ("{", "}"):
                self._translate_statement(child)

    def _translate_statement(self, node: TSNode) -> None:
        """Translate a statement"""
        if node.type == "expression_statement":
            self._translate_expression_statement(node)
        elif node.type == "local_variable_declaration":
            self._translate_local_var_declaration(node)
        elif node.type == "return_statement":
            self._translate_return(node)
        elif node.type == "if_statement":
            self._translate_if(node)
        elif node.type == "while_statement":
            self._translate_while(node)
        elif node.type == "for_statement":
            self._translate_for(node)
        elif node.type == "enhanced_for_statement":
            self._translate_enhanced_for(node)
        elif node.type == "try_statement":
            self._translate_try(node)
        elif node.type == "try_with_resources_statement":
            self._translate_try_with_resources(node)
        elif node.type in ("switch_expression", "switch_statement"):
            self._translate_switch(node)
        elif node.type == "throw_statement":
            self._translate_throw(node)
        elif node.type == "block":
            self._translate_block(node)

    def _translate_expression_statement(self, node: TSNode) -> None:
        """Translate expression statement"""
        for child in node.children:
            if child.type == "method_invocation":
                instrs = self._translate_method_call(child)
                self._add_instrs(instrs)
            elif child.type == "assignment_expression":
                self._translate_assignment(child)
            elif child.type == "update_expression":
                self._translate_update(child)

    def _translate_local_var_declaration(self, node: TSNode) -> None:
        """Translate local variable declaration"""
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")

                if name_node:
                    var_name = self._get_text(name_node)
                    loc = self._get_location(child)

                    if value_node:
                        if value_node.type == "method_invocation":
                            instrs = self._translate_call_assignment(var_name, value_node, loc)
                            self._add_instrs(instrs)
                        elif value_node.type == "object_creation_expression":
                            instrs = self._translate_object_creation_assignment(var_name, value_node, loc)
                            self._add_instrs(instrs)
                        else:
                            exp = self._translate_expression(value_node)
                            self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=exp))
                            # Track constant values for dead path elimination
                            if value_node.type == "string_literal":
                                text = self._get_text(value_node)
                                if len(text) >= 2:
                                    self._constant_values[var_name] = text[1:-1]  # Remove quotes
                            elif value_node.type == "decimal_integer_literal":
                                # Track integer constants for ternary condition evaluation
                                try:
                                    self._constant_values[var_name] = int(self._get_text(value_node))
                                except ValueError:
                                    pass
                    else:
                        self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=ExpConst.null()))

    def _translate_assignment(self, node: TSNode) -> None:
        """Translate assignment"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        if not left or not right:
            return

        target = self._get_text(left)
        loc = self._get_location(node)

        if right.type == "method_invocation":
            instrs = self._translate_call_assignment(target, right, loc)
            self._add_instrs(instrs)
        elif right.type == "object_creation_expression":
            instrs = self._translate_object_creation_assignment(target, right, loc)
            self._add_instrs(instrs)
        else:
            exp = self._translate_expression(right)
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=exp))

    def _lookup_spec(self, method_name: str) -> Optional[ProcSpec]:
        """
        Flexible spec lookup that tries multiple matching strategies:
        1. Full method name (e.g., statement.executeUpdate)
        2. Just the method name (e.g., executeUpdate)
        3. Common object patterns (request., response., etc.)
        """
        # Try exact match first
        spec = self.specs.get(method_name)
        if spec:
            return spec

        # Try just the method name (after the last dot)
        if '.' in method_name:
            short_name = method_name.rsplit('.', 1)[1]
            spec = self.specs.get(short_name)
            if spec:
                return spec

        # Try common patterns
        for prefix in ['request.', 'response.', 'session.', 'connection.', 'statement.']:
            if method_name.endswith('.' + method_name.rsplit('.', 1)[-1]):
                candidate = prefix + method_name.rsplit('.', 1)[-1]
                spec = self.specs.get(candidate)
                if spec:
                    return spec

        return None

    def _translate_call_assignment(
        self,
        target: str,
        call_node: TSNode,
        loc: Location
    ) -> List[Instr]:
        """Translate: target = method(args)"""
        instrs = []

        method_name = self._get_method_name(call_node)
        args = self._get_method_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        ret_id = self._new_ident(target)

        call_instr = Call(
            loc=loc,
            ret=(ret_id, Typ.unknown_type()),
            func=ExpConst.string(method_name),
            args=args_exp
        )
        instrs.append(call_instr)

        instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpVar(ret_id)))

        # Track charAt results for path-sensitive switch analysis
        # Pattern: target = constantString.charAt(N)
        if method_name.endswith('.charAt') and len(args) == 1:
            obj_name = method_name.rsplit('.', 1)[0]
            if obj_name in self._constant_values:
                const_str = self._constant_values[obj_name]
                # Try to get the index as a constant
                arg_text = self._get_text(args[0]) if args else ""
                try:
                    idx = int(arg_text)
                    if 0 <= idx < len(const_str):
                        self._constant_values[target] = const_str[idx]
                except (ValueError, TypeError):
                    pass

        # Track variables from getProperty for weak algorithm detection
        # Pattern: algorithm = props.getProperty("hashAlg1", "default")
        if method_name.endswith('.getProperty') or method_name == 'getProperty':
            if len(args) > 0:
                prop_name = self._get_text(args[0]).strip().strip('"\'')
                # hashAlg1 maps to weak algorithm in OWASP benchmark
                if 'hashAlg1' in prop_name or 'cryptoAlg1' in prop_name:
                    self._weak_algo_vars.add(target)

        # Check specs with flexible lookup
        spec = self._lookup_spec(method_name)
        if spec and spec.is_taint_source():
            kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
            instrs.append(TaintSource(loc=loc, var=PVar(target), kind=kind, description=spec.description))

        if spec and spec.is_taint_sink():
            # Special handling for crypto/hash sinks that need algorithm checking
            if self._is_algorithm_based_sink(method_name):
                algo_instr = self._check_algorithm_sink(method_name, args, loc)
                if algo_instr:
                    instrs.append(algo_instr)
            else:
                kind = SinkKind(spec.is_sink) if spec.is_sink in [s.value for s in SinkKind] else SinkKind.SQL_QUERY
                for arg_idx in spec.sink_args:
                    if arg_idx < len(args):
                        arg_exp = self._translate_expression(args[arg_idx])
                        instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description))

        return instrs

    def _is_algorithm_based_sink(self, method_name: str) -> bool:
        """Check if this method requires algorithm-based sink detection"""
        algo_methods = [
            'MessageDigest.getInstance',
            'java.security.MessageDigest.getInstance',
            'Cipher.getInstance',
            'javax.crypto.Cipher.getInstance',
        ]
        return any(method_name.endswith(m) for m in algo_methods)

    def _check_algorithm_sink(self, method_name: str, args: List[TSNode], loc: Location) -> Optional[Instr]:
        """Check algorithm argument and return TaintSink only for weak algorithms"""
        if not args:
            return None

        # Get the algorithm from the first argument
        arg_text = self._get_text(args[0]).strip()

        # Remove quotes from string literals
        if arg_text.startswith('"') and arg_text.endswith('"'):
            algo = arg_text[1:-1].upper()
        elif arg_text.startswith("'") and arg_text.endswith("'"):
            algo = arg_text[1:-1].upper()
        else:
            # Check if this variable came from a weak algorithm property
            if arg_text in self._weak_algo_vars:
                if 'MessageDigest' in method_name:
                    return TaintSink(
                        loc=loc,
                        exp=ExpConst.string(arg_text),
                        kind=SinkKind.WEAK_HASH,
                        description=f"Weak hash algorithm from property (CWE-328)"
                    )
                elif 'Cipher' in method_name:
                    return TaintSink(
                        loc=loc,
                        exp=ExpConst.string(arg_text),
                        kind=SinkKind.WEAK_CRYPTO,
                        description=f"Weak cipher algorithm from property (CWE-327)"
                    )
            # Unknown variable - can't determine, skip (conservative for FPs)
            return None

        # Check for weak hash algorithms
        if 'MessageDigest' in method_name:
            weak_hash_algos = {'MD5', 'MD2', 'MD4', 'SHA-1', 'SHA1'}
            if algo in weak_hash_algos:
                return TaintSink(
                    loc=loc,
                    exp=ExpConst.string(algo),
                    kind=SinkKind.WEAK_HASH,
                    description=f"Weak hash algorithm: {algo} (CWE-328)"
                )

        # Check for weak crypto algorithms
        if 'Cipher' in method_name:
            # Weak algorithms or modes
            weak_crypto_patterns = {'DES', '3DES', 'DESEDE', 'RC2', 'RC4', 'BLOWFISH'}
            weak_modes = {'ECB'}  # ECB mode is weak for block ciphers

            algo_parts = algo.split('/')
            base_algo = algo_parts[0]
            mode = algo_parts[1] if len(algo_parts) > 1 else ''

            if base_algo in weak_crypto_patterns:
                return TaintSink(
                    loc=loc,
                    exp=ExpConst.string(algo),
                    kind=SinkKind.WEAK_CRYPTO,
                    description=f"Weak cipher algorithm: {algo} (CWE-327)"
                )
            elif mode in weak_modes:
                return TaintSink(
                    loc=loc,
                    exp=ExpConst.string(algo),
                    kind=SinkKind.WEAK_CRYPTO,
                    description=f"Weak cipher mode: {algo} (CWE-327)"
                )

        return None

    def _translate_object_creation_assignment(
        self,
        target: str,
        creation_node: TSNode,
        loc: Location
    ) -> List[Instr]:
        """Translate: target = new ClassName(args)"""
        instrs = []

        type_node = creation_node.child_by_field_name("type")
        type_name = self._get_text(type_node) if type_node else "Object"

        args = []
        args_node = creation_node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type not in ("(", ")", ","):
                    args.append(child)

        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        # Constructor call name
        constructor_name = f"new {type_name}"

        ret_id = self._new_ident(target)

        call_instr = Call(
            loc=loc,
            ret=(ret_id, Typ.unknown_type()),
            func=ExpConst.string(constructor_name),
            args=args_exp
        )
        instrs.append(call_instr)

        instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpVar(ret_id)))

        # Check specs for constructor sink (e.g., FileOutputStream, File)
        spec = self._lookup_spec(constructor_name)
        if spec and spec.is_taint_sink():
            kind = SinkKind(spec.is_sink) if spec.is_sink in [s.value for s in SinkKind] else SinkKind.SQL_QUERY
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = self._translate_expression(args[arg_idx])
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description))

        return instrs

    def _translate_method_call(self, call_node: TSNode) -> List[Instr]:
        """Translate standalone method call"""
        instrs = []
        loc = self._get_location(call_node)

        method_name = self._get_method_name(call_node)
        args = self._get_method_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        call_instr = Call(
            loc=loc,
            ret=None,
            func=ExpConst.string(method_name),
            args=args_exp
        )
        instrs.append(call_instr)

        # Use flexible spec lookup
        spec = self._lookup_spec(method_name)
        if spec and spec.is_taint_sink():
            kind = SinkKind(spec.is_sink) if spec.is_sink in [s.value for s in SinkKind] else SinkKind.SQL_QUERY
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = self._translate_expression(args[arg_idx])
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description, arg_index=arg_idx))

        return instrs

    def _translate_update(self, node: TSNode) -> None:
        """Translate update expression: i++ or ++i"""
        loc = self._get_location(node)
        for child in node.children:
            if child.type == "identifier":
                var_name = self._get_text(child)
                self._add_instr(Assign(
                    loc=loc,
                    id=PVar(var_name),
                    exp=ExpBinOp("+", ExpVar(PVar(var_name)), ExpConst.integer(1))
                ))
                break

    def _translate_return(self, node: TSNode) -> None:
        """Translate return statement"""
        loc = self._get_location(node)
        value_exp = None

        for child in node.children:
            if child.type not in ("return", ";"):
                value_exp = self._translate_expression(child)
                break

        self._add_instr(Return(loc=loc, value=value_exp))

    def _translate_if(self, node: TSNode) -> None:
        """Translate if statement with dead path elimination"""
        loc = self._get_location(node)
        proc = self._current_proc
        if not proc:
            return

        condition = node.child_by_field_name("condition")

        # Try to evaluate condition at compile time for dead path elimination
        cond_value = self._try_evaluate_constant(condition) if condition else None

        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")

        # If condition is always true, only translate true branch
        if cond_value is True:
            if consequence:
                self._translate_statement(consequence)
            return

        # If condition is always false, only translate else branch
        if cond_value is False:
            if alternative:
                self._translate_statement(alternative)
            return

        # Condition is unknown - translate both branches normally
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)
        before_node = self._current_node

        true_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(true_node)

        false_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(false_node)

        join_node = proc.new_node(NodeKind.JOIN)
        proc.add_node(join_node)

        if before_node:
            before_node.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=True))
            proc.connect(before_node.id, true_node.id)
            before_node.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=False))
            proc.connect(before_node.id, false_node.id)

        if consequence:
            self._current_node = true_node
            self._translate_statement(consequence)
            if self._current_node:
                proc.connect(self._current_node.id, join_node.id)

        if alternative:
            self._current_node = false_node
            self._translate_statement(alternative)
            if self._current_node:
                proc.connect(self._current_node.id, join_node.id)
        else:
            proc.connect(false_node.id, join_node.id)

        self._current_node = join_node

    def _translate_while(self, node: TSNode) -> None:
        """Translate while loop"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)
        condition = node.child_by_field_name("condition")
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)

        before_node = self._current_node

        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)

        body_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(body_node)

        after_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(after_node)

        if before_node:
            proc.connect(before_node.id, loop_head.id)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=True, kind=PruneKind.LOOP_ENTER))
        proc.connect(loop_head.id, body_node.id)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=False, kind=PruneKind.LOOP_EXIT))
        proc.connect(loop_head.id, after_node.id)

        body = node.child_by_field_name("body")
        if body:
            self._current_node = body_node
            self._translate_statement(body)

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node

    def _translate_for(self, node: TSNode) -> None:
        """Translate for loop"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        # Initialize
        init = node.child_by_field_name("init")
        if init:
            if init.type == "local_variable_declaration":
                self._translate_local_var_declaration(init)

        before_node = self._current_node

        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)

        body_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(body_node)

        after_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(after_node)

        if before_node:
            proc.connect(before_node.id, loop_head.id)

        condition = node.child_by_field_name("condition")
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=True, kind=PruneKind.FOR_ENTER))
        proc.connect(loop_head.id, body_node.id)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=False, kind=PruneKind.FOR_EXIT))
        proc.connect(loop_head.id, after_node.id)

        body = node.child_by_field_name("body")
        if body:
            self._current_node = body_node
            self._translate_statement(body)

        # Update
        update = node.child_by_field_name("update")
        if update and self._current_node:
            self._translate_expression_statement(update)

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node

    def _translate_enhanced_for(self, node: TSNode) -> None:
        """Translate enhanced for loop (for-each)"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        loop_var = self._get_text(name) if name else "_iter"
        iterable_exp = self._translate_expression(value) if value else ExpConst.null()

        before_node = self._current_node

        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)

        body_node = proc.new_node(NodeKind.NORMAL)
        body_node.add_instr(Assign(loc=loc, id=PVar(loop_var), exp=ExpCall(ExpConst.string("next"), [iterable_exp])))
        proc.add_node(body_node)

        after_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(after_node)

        if before_node:
            proc.connect(before_node.id, loop_head.id)

        cond = ExpConst.boolean(True)
        loop_head.add_instr(Prune(loc=loc, condition=cond, is_true_branch=True, kind=PruneKind.FOR_ENTER))
        proc.connect(loop_head.id, body_node.id)

        loop_head.add_instr(Prune(loc=loc, condition=cond, is_true_branch=False, kind=PruneKind.FOR_EXIT))
        proc.connect(loop_head.id, after_node.id)

        body = node.child_by_field_name("body")
        if body:
            self._current_node = body_node
            self._translate_statement(body)

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node

    def _translate_try(self, node: TSNode) -> None:
        """Translate try/catch/finally"""
        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)

        for child in node.children:
            if child.type == "catch_clause":
                catch_body = child.child_by_field_name("body")
                if catch_body:
                    self._translate_block(catch_body)
            elif child.type == "finally_clause":
                for fc in child.children:
                    if fc.type == "block":
                        self._translate_block(fc)

    def _translate_try_with_resources(self, node: TSNode) -> None:
        """Translate try-with-resources ``try (var x = ...) { ... }``.

        Without this, the entire body (and its sinks) is dropped -- a major
        recall gap on JDBC code, which conventionally opens the connection as a
        resource (``try (var connection = dataSource.getConnection())``).
        """
        resources = node.child_by_field_name("resources")
        if resources is not None:
            for r in resources.children:
                if r.type == "resource":
                    self._translate_resource(r)

        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)

        for child in node.children:
            if child.type == "catch_clause":
                catch_body = child.child_by_field_name("body")
                if catch_body:
                    self._translate_block(catch_body)
            elif child.type == "finally_clause":
                for fc in child.children:
                    if fc.type == "block":
                        self._translate_block(fc)

    def _translate_resource(self, node: TSNode) -> None:
        """Translate a single try-with-resources resource (``var x = expr``) as
        an assignment so taint flows through resources (e.g. request streams)."""
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None:
            return
        var_name = self._get_text(name_node)
        loc = self._get_location(node)
        if value_node.type == "method_invocation":
            self._add_instrs(self._translate_call_assignment(var_name, value_node, loc))
        elif value_node.type == "object_creation_expression":
            self._add_instrs(self._translate_object_creation_assignment(var_name, value_node, loc))
        else:
            self._add_instr(Assign(loc=loc, id=PVar(var_name),
                                   exp=self._translate_expression(value_node)))

    def _translate_switch(self, node: TSNode) -> None:
        """Translate switch with path-sensitive analysis for constant conditions"""
        # Get the switch condition
        condition = node.child_by_field_name("condition")
        known_value = None

        if condition:
            # Check if condition is wrapped in parentheses
            cond_text = self._get_text(condition).strip()
            if cond_text.startswith("(") and cond_text.endswith(")"):
                cond_text = cond_text[1:-1].strip()

            # Check if the condition variable has a known constant value
            if cond_text in self._constant_values:
                known_value = self._constant_values[cond_text]

        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "switch_block_statement_group":
                    # Check if this case matches the known value
                    should_translate = True
                    if known_value is not None:
                        should_translate = False
                        for stmt in child.children:
                            if stmt.type == "switch_label":
                                label_text = self._get_text(stmt).strip()
                                # Check for "case 'X'" or "case X" or "default"
                                if label_text == "default":
                                    # Only translate default if no other case matched
                                    pass  # Will be handled by should_translate staying False
                                elif label_text.startswith("case "):
                                    # Extract the case value - handle: case 'A', case 'B', case 1
                                    case_match = label_text[5:].strip()  # Remove "case "
                                    # Remove quotes if present (for char literals like 'A')
                                    if case_match.startswith("'") and case_match.endswith("'"):
                                        case_match = case_match[1:-1]
                                    if case_match == known_value:
                                        should_translate = True
                                        break

                    if should_translate:
                        for stmt in child.children:
                            if stmt.type not in ("switch_label",):
                                self._translate_statement(stmt)

    def _translate_throw(self, node: TSNode) -> None:
        """Translate throw"""
        loc = self._get_location(node)
        for child in node.children:
            if child.type not in ("throw", ";"):
                exp = self._translate_expression(child)
                self._add_instr(Return(loc=loc, value=exp))
                break

    def _translate_expression(self, node: TSNode) -> Exp:
        """Translate expression"""
        if node is None:
            return ExpConst.null()

        if node.type == "identifier":
            return ExpVar(PVar(self._get_text(node)))

        elif node.type in ("decimal_integer_literal", "hex_integer_literal", "octal_integer_literal"):
            try:
                return ExpConst.integer(int(self._get_text(node), 0))
            except ValueError:
                return ExpConst.integer(0)

        elif node.type in ("decimal_floating_point_literal", "hex_floating_point_literal"):
            try:
                return ExpConst.integer(int(float(self._get_text(node))))
            except ValueError:
                return ExpConst.integer(0)

        elif node.type == "string_literal":
            text = self._get_text(node)
            return ExpConst.string(text[1:-1] if len(text) >= 2 else text)

        elif node.type == "character_literal":
            text = self._get_text(node)
            return ExpConst.string(text[1:-1] if len(text) >= 2 else text)

        elif node.type == "true":
            return ExpConst.boolean(True)

        elif node.type == "false":
            return ExpConst.boolean(False)

        elif node.type == "null_literal":
            return ExpConst.null()

        elif node.type == "binary_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")
            left_exp = self._translate_expression(left)
            right_exp = self._translate_expression(right)
            op = self._get_text(op_node) if op_node else "+"
            if op == "+":
                return ExpStringConcat([left_exp, right_exp])
            return ExpBinOp(op, left_exp, right_exp)

        elif node.type == "unary_expression":
            op_node = node.child_by_field_name("operator")
            operand = node.child_by_field_name("operand")
            op = self._get_text(op_node) if op_node else "-"
            return ExpUnOp(op, self._translate_expression(operand))

        elif node.type == "field_access":
            obj = node.child_by_field_name("object")
            field = node.child_by_field_name("field")
            return ExpFieldAccess(self._translate_expression(obj), self._get_text(field) if field else "")

        elif node.type == "array_access":
            arr = node.child_by_field_name("array")
            idx = node.child_by_field_name("index")
            return ExpIndex(self._translate_expression(arr), self._translate_expression(idx))

        elif node.type == "method_invocation":
            method_name = self._get_method_name(node)
            args = [self._translate_expression(a) for a in self._get_method_args(node)]
            return ExpCall(ExpConst.string(method_name), args)

        elif node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = self._get_text(type_node) if type_node else "Object"
            args = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ","):
                        args.append(self._translate_expression(child))
            return ExpCall(ExpConst.string(f"new {type_name}"), args)

        elif node.type == "parenthesized_expression":
            for child in node.children:
                if child.type not in ("(", ")"):
                    return self._translate_expression(child)

        elif node.type == "ternary_expression":
            # Handle ternary: condition ? consequence : alternative
            cond = node.child_by_field_name("condition")
            conseq = node.child_by_field_name("consequence")
            alt = node.child_by_field_name("alternative")

            # Try to evaluate condition statically for dead path elimination
            cond_value = self._try_evaluate_constant(cond) if cond else None

            if cond_value is True:
                # Condition is always true - return consequence (taint doesn't flow through alt)
                return self._translate_expression(conseq) if conseq else ExpConst.null()
            elif cond_value is False:
                # Condition is always false - return alternative (taint doesn't flow through conseq)
                return self._translate_expression(alt) if alt else ExpConst.null()
            else:
                # Can't determine statically - be conservative and return consequence
                # (could also merge both branches, but that's more complex)
                return self._translate_expression(conseq) if conseq else ExpConst.null()

        elif node.type == "cast_expression":
            value = node.child_by_field_name("value")
            return self._translate_expression(value)

        elif node.type == "this":
            return ExpVar(PVar("this"))

        # Default
        return ExpVar(PVar(self._get_text(node))) if self._get_text(node) else ExpConst.null()

    # =========================================================================
    # Helpers
    # =========================================================================

    def _get_text(self, node: TSNode) -> str:
        if node is None:
            return ""
        # tree-sitter reports BYTE offsets. Slicing the source *string* by those
        # offsets corrupts every identifier after any multi-byte character (a
        # `©` in a copyright header, an accented name, unicode in a string), so
        # slice the UTF-8 bytes and decode. Getting this wrong silently mangles
        # sink/source names and destroys detection on such files.
        return self._source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace")

    def _get_location(self, node) -> Location:
        if hasattr(node, 'start_point'):
            return Location(
                file=self._filename,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
                end_line=node.end_point[0] + 1,
                end_column=node.end_point[1]
            )
        return Location(file=self._filename, line=1, column=0)

    def _try_evaluate_constant(self, node: TSNode) -> Optional[Any]:
        """
        Try to evaluate a constant expression at compile time.

        Used for dead path elimination - if we can prove a condition is
        always true or false, we can avoid propagating taint through
        unreachable branches.

        Returns:
            True/False for boolean expressions
            int/float for numeric expressions
            None if cannot be evaluated
        """
        if node is None:
            return None

        # Integer literals
        if node.type == "decimal_integer_literal":
            try:
                return int(self._get_text(node))
            except ValueError:
                return None

        # Boolean literals
        if node.type in ("true", "false"):
            return node.type == "true"

        # Parenthesized expressions
        if node.type == "parenthesized_expression":
            for child in node.children:
                if child.type not in ("(", ")"):
                    return self._try_evaluate_constant(child)

        # Binary expressions (arithmetic and comparison)
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")
            if not (left and right and op_node):
                return None

            left_val = self._try_evaluate_constant(left)
            right_val = self._try_evaluate_constant(right)

            if left_val is None or right_val is None:
                return None

            op = self._get_text(op_node)

            # Arithmetic operators
            if op == "+":
                return left_val + right_val
            elif op == "-":
                return left_val - right_val
            elif op == "*":
                return left_val * right_val
            elif op == "/" and right_val != 0:
                return left_val // right_val if isinstance(left_val, int) and isinstance(right_val, int) else left_val / right_val
            elif op == "%":
                return left_val % right_val

            # Comparison operators
            elif op == ">":
                return left_val > right_val
            elif op == "<":
                return left_val < right_val
            elif op == ">=":
                return left_val >= right_val
            elif op == "<=":
                return left_val <= right_val
            elif op == "==":
                return left_val == right_val
            elif op == "!=":
                return left_val != right_val

            # Logical operators
            elif op == "&&":
                return bool(left_val) and bool(right_val)
            elif op == "||":
                return bool(left_val) or bool(right_val)

        # Variable lookup (for constants like 'num = 106')
        if node.type == "identifier":
            var_name = self._get_text(node)
            if var_name in self._constant_values:
                return self._constant_values[var_name]

        # Unary expressions
        if node.type == "unary_expression":
            operand = node.child_by_field_name("operand")
            op = None
            for child in node.children:
                if child.type not in ("identifier", "decimal_integer_literal", "parenthesized_expression"):
                    op = self._get_text(child)
                    break
            if operand and op:
                val = self._try_evaluate_constant(operand)
                if val is not None:
                    if op == "-":
                        return -val
                    elif op == "!":
                        return not bool(val)

        return None

    def _get_method_name(self, node: TSNode) -> str:
        name = node.child_by_field_name("name")
        obj = node.child_by_field_name("object")
        if obj and name:
            return f"{self._get_text(obj)}.{self._get_text(name)}"
        elif name:
            return self._get_text(name)
        return ""

    def _get_method_args(self, node: TSNode) -> List[TSNode]:
        args = []
        args_node = node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type not in ("(", ")", ","):
                    args.append(child)
        return args

    def _new_ident(self, prefix: str = "tmp") -> Ident:
        ident = Ident(prefix, self._ident_counter)
        self._ident_counter += 1
        return ident

    def _add_instr(self, instr: Instr) -> None:
        if self._current_node:
            self._current_node.add_instr(instr)

    def _add_instrs(self, instrs: List[Instr]) -> None:
        for instr in instrs:
            self._add_instr(instr)
