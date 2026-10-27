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

import os
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field


def _aggressive_detectors() -> bool:
    """Context-dependent detectors (CSRF-disable, field-initializer secrets) are
    OFF by default -- they add false positives the sound layer can't adjudicate.
    Enable them (FRAME_AGGRESSIVE_DETECTORS=1) only alongside LLM triage, which
    drops the context-dependent FPs while keeping the real ones."""
    return bool(os.environ.get("FRAME_AGGRESSIVE_DETECTORS"))

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
    TaintKind, SinkKind, PruneKind, resolve_sink_kind
)
from frame.sil.frontends._literal_fields import literal_init_procedure
from frame.sil.procedure import Procedure, Node, NodeKind, ProcSpec, Program, typed_spec_lookup
from frame.sil.frontends._syntax import first_syntax_error_line
from frame.sil.loop_exit import body_can_exit_loop
from frame.sil.metadata import (
    ClassInfo, ImportTable, annotate_program_calls, parse_annotation,
)
from frame.sil.packs import finish_program
# ProcSpec is used for type hints in _lookup_spec
from frame.sil.specs.java_specs import (
    JAVA_SPECS, PERMISSIVE_VERIFIERS, type_spec_receivers,
    JAVA_FACTORY_RETURN_TYPES, JAVA_RETURN_TYPES, JAKARTA_MIGRATED, JAVA_LAMBDA_PARAMS)


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

    packs = None   # a frame.sil.packs.PackSet; None = the built-in packs

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
        # Declared type of each name visible in the method being translated
        # (fields of the enclosing class, then parameters and locals), so a
        # call is matched to the specs of its receiver's type, not its name.
        self._field_types: Dict[str, str] = {}
        self._var_types: Dict[str, str] = {}
        # Locals whose RUNTIME class is their declared type: initialised with
        # `new T(...)` of that type and never re-assigned (see exact_class).
        self._exact_vars: set = set()
        # Methods declared by the class being translated: an unqualified (or
        # `this.`) call to one of them is that method, never a library API.
        self._class_methods: set = set()
        self._current_class_annotations: list = []
        self._nested_calls: Dict[Tuple[int, int], str] = {}
        self._lambda_names: Dict[int, str] = {}
        self._spec_receivers: set = {k.split(".")[0] for k in JAVA_SPECS if "." in k}
        self._lambda_parents: List[Tuple[Procedure, Procedure]] = []
        self._receiver_facts: Dict[str, set] = {}
        self._handler_lambdas: set = set()
        self._qualified_names: set = set()
        self._method_refs: List[Tuple[Optional[str], str, str]] = []
        self._program: Optional[Program] = None
        self._in_call_args = False
        self._imports = ImportTable()
        self._last_lambdas: List[Tuple[str, TSNode]] = []
        self._static_members: Dict[str, str] = {}
        self._static_star: List[str] = []
        self._package = ""
        self._local_types: Dict[str, str] = {}
        # Overload resolution: static types (primitives and arrays included),
        # type variables in scope, return types of the class's methods.
        self._field_static_types: Dict[str, str] = {}
        self._static_types: Dict[str, str] = {}
        self._class_type_vars: set = set()
        self._type_vars: set = set()
        self._class_method_returns: Dict[str, set] = {}

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """Translate Java source code to SIL Program."""
        self._filename = filename
        self._source = source_code
        self._source_bytes = source_code.encode("utf-8")
        self._node_counter = 0
        self._ident_counter = 0
        self._nested_calls = {}
        self._lambda_names = {}
        self._lambda_parents = []
        self._handler_lambdas = set()
        self._method_refs = []
        self._in_call_args = False

        tree = self.parser.parse(self._source_bytes)
        program = Program(library_specs=self.specs.copy(), language="java",
                          type_spec_receivers=type_spec_receivers)
        program.source_files.append(filename)
        program.syntax_error_line = first_syntax_error_line(tree.root_node)
        self._program = program

        self._imports, self._package, self._local_types = self._collect_declarations(tree.root_node)
        self._static_members, self._static_star = self._collect_static_imports(tree.root_node)
        # simple names the file also spells with a package (`java.sql.Statement st`): library types
        self._qualified_names = set(re.findall(r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\.([A-Z]\w*)", source_code))
        program.imports = self._imports.as_dict()

        self._receiver_facts = self._collect_receiver_facts(tree.root_node)
        self._translate_compilation_unit(tree.root_node, program)
        self._apply_method_references(program)
        for lam, parent in self._lambda_parents:             # the parents' names are final now
            lam.parent = parent.name
        annotate_program_calls(program, self._imports, self._local_types)
        self._propagate_interprocedural_taint(tree.root_node, program)
        self._scan_cookie_flags(tree.root_node, program)
        self._scan_deserialization(tree.root_node, program)
        # Context-dependent detector: only when aggressive mode is enabled (pair
        # with LLM triage, which drops the stateless-API CSRF false positives).
        if _aggressive_detectors():
            self._scan_csrf_disabled(tree.root_node, program)
        program.import_wildcards = list(self._imports.wildcards)
        finish_program(program, self.packs, source_code)
        self._apply_neutral_specs(program)
        return program

    def _collect_static_imports(self, root: TSNode):
        """({member -> qualified class} of `import static a.B.m;`, [qualified classes] of
        `import static a.B.*;`)."""
        members: Dict[str, str] = {}
        star: List[str] = []
        for child in root.children:
            if child.type != "import_declaration" or not any(c.type == "static" or self._get_text(c) == "static"
                                                             for c in child.children):
                continue
            ident = next((c for c in child.named_children if c.type in ("scoped_identifier", "identifier")), None)
            if ident is None:
                continue
            name = self._get_text(ident)
            if any(c.type == "asterisk" for c in child.children):
                star.append(name)
            elif "." in name:
                cls, member = name.rsplit(".", 1)
                members[member] = cls
        return members, star

    def _collect_declarations(self, root: TSNode):
        """(import table, package, {declared type -> qualified name}) for the file."""
        table = ImportTable()
        package = ""
        for child in root.children:
            if child.type == "package_declaration":
                ident = next((c for c in child.named_children
                              if c.type in ("scoped_identifier", "identifier")), None)
                package = self._get_text(ident) if ident is not None else ""
            elif child.type == "import_declaration":
                ident = next((c for c in child.named_children
                              if c.type in ("scoped_identifier", "identifier")), None)
                if ident is None:
                    continue
                name = self._get_text(ident)
                if any(c.type == "asterisk" for c in child.children):
                    table.wildcards.append(name)
                else:
                    table.bind(name.rsplit(".", 1)[-1], name)
        types: Dict[str, str] = {}
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type in ("class_declaration", "interface_declaration", "enum_declaration",
                          "record_declaration", "annotation_type_declaration"):
                nm = n.child_by_field_name("name")
                if nm is not None:
                    simple = self._get_text(nm)
                    types.setdefault(simple, f"{package}.{simple}" if package else simple)
            stack.extend(n.children)
        return table.finish(), package, types

    def _declared_bases(self, node: TSNode) -> List[str]:
        """Superclass and interfaces of a type declaration, as written (no generics)."""
        holders = [node.child_by_field_name(f) for f in ("superclass", "interfaces")]
        holders += [c for c in node.named_children if c.type == "extends_interfaces"]  # `interface A extends B, C`
        found = [t for h in holders if h is not None
                 for t in self._descendants(h, stop=("type_arguments",))
                 if t.type in ("type_identifier", "scoped_type_identifier")
                 and t.parent is not None and t.parent.type != "scoped_type_identifier"]
        found.sort(key=lambda t: t.start_byte)
        return [self._get_text(t).split("<")[0] for t in found]

    def _record_class_info(self, node: TSNode, program: Program, kind: str) -> None:
        nm = node.child_by_field_name("name")
        if nm is None:
            return
        name = self._get_text(nm)
        bases = self._declared_bases(node)
        fields: List[str] = []
        body = node.child_by_field_name("body")
        for member in (body.named_children if body is not None else ()):
            if member.type == "field_declaration":
                # Fields that something else fills in or that never change are not the object's
                # externally-bound state: injected collaborators, constants.
                managed = any(a.name in ("Inject", "Autowired", "Resource", "EJB", "Value", "PersistenceContext",
                                         "Mock", "MockBean", "Spy")
                              for a in (parse_annotation(t, self._imports, value_alias=True)
                                        for t in self._get_annotations(member)))
                mods = next((c for c in member.children if c.type == "modifiers"), None)
                fixed = mods is not None and bool(re.search(r"\b(static|final)\b", self._get_text(mods)))
                if managed or fixed:
                    continue
                for d in member.named_children:
                    if d.type == "variable_declarator" and d.child_by_field_name("name") is not None:
                        fields.append(self._get_text(d.child_by_field_name("name")))
        program.class_info[name] = ClassInfo(
            name=name, kind=kind, bases=bases, fields=fields,
            canonical_bases=[self._imports.resolve(b) or self._local_types.get(b) or b for b in bases],
            annotations=[parse_annotation(a, self._imports, value_alias=True)
                         for a in self._get_annotations(node)],
            package=self._package or None)

    def _translate_compilation_unit(self, root: TSNode, program: Program) -> None:
        """Translate Java compilation unit"""
        for child in root.children:
            if child.type == "class_declaration":
                self._translate_class(child, program)
            elif child.type == "interface_declaration":
                self._translate_interface(child, program)
            elif child.type == "enum_declaration":
                self._translate_enum(child, program)

    @staticmethod
    def _class_members(body: Optional[TSNode]) -> List[TSNode]:
        """The members of a class body; an enum's methods and fields sit one level down, in its
        `enum_body_declarations`."""
        out: List[TSNode] = []
        for c in (body.children if body is not None else ()):
            if c.type == "enum_body_declarations":
                out.extend(c.children)
            elif c.is_named:
                out.append(c)
        return out

    def _translate_class(self, node: TSNode, program: Program) -> None:
        """Translate class definition"""
        name_node = node.child_by_field_name("name")
        class_name = self._get_text(name_node) if name_node else "UnknownClass"
        outer_class, outer_fields = self._current_class, self._field_types
        outer_methods = self._class_methods
        self._current_class = class_name
        self._record_class_info(node, program, {"enum_declaration": "enum", "interface_declaration": "interface"}
                                .get(node.type, "class"))
        outer_class_anns = self._current_class_annotations
        self._current_class_annotations = program.class_info[class_name].annotations \
            if class_name in program.class_info else []

        body = node.child_by_field_name("body")
        members = self._class_members(body)
        self._class_methods = {
            self._get_text(c.child_by_field_name("name"))
            for c in members
            if c.type == "method_declaration" and c.child_by_field_name("name") is not None}
        outer_static, outer_tvars = self._field_static_types, self._class_type_vars
        outer_returns = self._class_method_returns
        self._class_type_vars = outer_tvars | self._type_params(node)
        self._type_vars = set(self._class_type_vars)
        self._field_types = {}
        self._field_static_types = {}
        for f in members:
            if f.type == "field_declaration":
                for d in f.named_children:
                    if d.type == "variable_declarator":
                        fname = self._get_text(d.child_by_field_name("name"))
                        t = self._type_name(f.child_by_field_name("type"),
                                            d.child_by_field_name("value"))
                        if t:
                            self._field_types[fname] = t
                        st = self._static_type(f.child_by_field_name("type"), d.child_by_field_name("value"))
                        if st:
                            self._field_static_types[fname] = st
        self._var_types = dict(self._field_types)
        self._static_types = dict(self._field_static_types)
        # Return types of the class's methods, by name (overloads may differ).
        self._class_method_returns = {}
        for c in members:
            if c.type == "method_declaration" and c.child_by_field_name("name") is not None:
                self._class_method_returns.setdefault(
                    self._get_text(c.child_by_field_name("name")), set()).add(
                    self._static_type(c.child_by_field_name("type")))
        # Declared supertypes: a class without any is closed for overload
        # resolution (no inherited overload can hide behind it).
        supers = []
        for field_name in ("superclass", "interfaces"):
            sn = node.child_by_field_name(field_name)
            if sn is not None:
                supers += [self._get_text(t).split("<")[0].rsplit(".", 1)[-1]
                           for t in self._descendants(sn, stop=("type_arguments",))
                           if t.type in ("type_identifier", "scoped_type_identifier")
                           and t.parent is not None and t.parent.type != "scoped_type_identifier"]
        program.class_supertypes[class_name] = supers
        if body:
            for child in members:
                if child.type == "method_declaration":
                    if child.child_by_field_name("body") is None:
                        # `abstract`/`native`: no body, so no procedure. An empty one would be
                        # what a call resolves to (hiding the subclass that implements it).
                        continue
                    proc = self._translate_method(child)
                    if proc:
                        proc.class_name = class_name
                        proc.class_open = bool(supers)
                        proc.name = f"{class_name}.{proc.name}"
                        program.add_procedure(proc)
                elif child.type == "constructor_declaration":
                    proc = self._translate_constructor(child)
                    if proc:
                        proc.class_name = class_name
                        proc.class_open = bool(supers)
                        proc.name = f"{class_name}.<init>"
                        program.add_procedure(proc)
                elif child.type == "class_declaration":
                    # Handle inner classes
                    self._translate_class(child, program)
            self._var_types = dict(self._field_types)
            # Field-initializer translation: aggressive mode only (pair with LLM
            # triage, which tells a real secret from a benign config constant).
            if _aggressive_detectors():
                self._translate_field_initializers(body, class_name, program)
            else:
                self._translate_literal_fields(body, class_name, program)

        self._current_class, self._field_types = outer_class, outer_fields
        self._current_class_annotations = outer_class_anns
        self._class_methods = outer_methods
        self._field_static_types, self._class_type_vars = outer_static, outer_tvars
        self._class_method_returns = outer_returns

    def _translate_field_initializers(self, body: TSNode, class_name: str,
                                      program: Program) -> None:
        """Translate class field initializers into a synthetic <clinit> procedure.

        field_declaration nodes carry variable_declarator children just like a
        local variable declaration, so we reuse _translate_local_var_declaration.
        This lets the usage-based/taint sinks (insecure random, weak crypto,
        hardcoded secret) fire on field initializers, and populates constant
        tracking for later value resolution (e.g. a weak Cipher spec constant).
        """
        fields = [c for c in body.children if c.type == "field_declaration"]
        has_init = any(
            any(gc.type == "variable_declarator" and gc.child_by_field_name("value")
                for gc in f.children)
            for f in fields)
        if not has_init:
            return
        proc = Procedure(name=f"{class_name}.<clinit>", params=[],
                         ret_type=Typ.unknown_type(),
                         loc=self._get_location(body), is_method=True)
        proc.is_static = True
        self._current_proc = proc
        self._node_counter = 0
        self._constant_values = {}
        self._weak_algo_vars = set()
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry
        for f in fields:
            self._translate_local_var_declaration(f)
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)
        self._current_proc = None
        program.add_procedure(proc)

    def _translate_literal_fields(self, body: TSNode, class_name: str,
                                  program: Program) -> None:
        """Lower plain string-literal field initializers (``String password =
        "..."``) so hardcoded credentials in fields are visible to the literal
        scanner. Narrower than ``_translate_field_initializers`` (no sinks)."""
        assigns = []
        for field_node in body.children:
            if field_node.type != "field_declaration":
                continue
            for decl in field_node.children:
                if decl.type != "variable_declarator":
                    continue
                name = decl.child_by_field_name("name")
                value = decl.child_by_field_name("value")
                if name is None or value is None or value.type != "string_literal":
                    continue
                assigns.append(Assign(loc=self._get_location(decl),
                                      id=PVar(self._get_text(name)),
                                      exp=self._translate_expression(value)))
        proc = literal_init_procedure(f"{class_name}.<clinit>",
                                      self._get_location(body), assigns)
        if proc is not None:
            program.add_procedure(proc)

    def _translate_interface(self, node: TSNode, program: Program) -> None:
        """Translate interface (skip method bodies as they're abstract), except the methods whose
        annotation IS the implementation: a MyBatis mapper's `@Select("... ${name} ...")`."""
        self._record_class_info(node, program, "interface")
        name_node = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        if name_node is None or body is None:
            return
        iface = self._get_text(name_node)
        for member in body.named_children:
            if member.type == "method_declaration":
                proc = self._mybatis_mapper_method(member, iface)
                if proc is not None:
                    program.add_procedure(proc)
        if any(m.type == "method_declaration" and m.child_by_field_name("body") is not None
               for m in body.named_children):
            # `default` / `static` methods have bodies: analysed like a class's methods
            self._translate_class(node, program)

    _MYBATIS_STATEMENTS = ("Select", "Update", "Delete", "Insert")
    _MYBATIS_SUBSTITUTION = re.compile(r"\$\{\s*([A-Za-z_][\w]*)")

    def _mybatis_mapper_method(self, member: TSNode, iface: str) -> Optional[Procedure]:
        """A mapper method whose SQL text substitutes a parameter with `${...}` (spliced into the
        statement, unlike the bound `#{...}`): a procedure that sinks those parameters."""
        sql = ""
        annotations = self._get_annotations(member)
        parsed = [parse_annotation(a, self._imports, value_alias=True) for a in annotations]
        if not any(a.name in self._MYBATIS_STATEMENTS for a in parsed):
            return None
        mods = next((c for c in member.children if c.type == "modifiers"), None)
        for ann in (mods.children if mods is not None else ()):
            if ann.type == "annotation" and self._get_text(ann.child_by_field_name("name")) in self._MYBATIS_STATEMENTS:
                sql += " ".join(self._get_text(n).strip('"') for n in self._descendants(ann, stop=())
                                if n.type == "string_fragment")
        roots = set(self._MYBATIS_SUBSTITUTION.findall(sql))
        if not roots:
            return None
        params_node = member.child_by_field_name("parameters")
        names: List[Tuple[str, str]] = []           # (java name, name the SQL uses)
        for ch in (params_node.children if params_node is not None else ()):
            if ch.type != "formal_parameter":
                continue
            nm = ch.child_by_field_name("name")
            if nm is None:
                continue
            java = self._get_text(nm)
            sql_name = java
            for a in self._get_annotations(ch):
                pa = parse_annotation(a, self._imports, value_alias=True)
                if pa.name == "Param" and pa.args.get("value"):
                    sql_name = str(pa.args["value"]).strip('"')
            names.append((java, sql_name))
        hit = [j for j, sn in names if sn in roots]
        if not hit and len(names) == 1:                   # a lone parameter is `${anything}`
            hit = [names[0][0]]
        if not hit:
            return None
        loc = self._get_location(member)
        proc = Procedure(name=f"{iface}.{self._get_text(member.child_by_field_name('name'))}",
                         params=[(PVar(j), Typ.unknown_type()) for j, _ in names],
                         ret_type=Typ.unknown_type(), loc=loc, is_method=True)
        proc.class_name = iface
        proc.annotations = parsed
        proc.param_type_names = self._param_type_names(member)
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        for j in hit:
            entry.add_instr(TaintSink(loc=loc, exp=ExpVar(PVar(j)), kind=SinkKind.SQL_QUERY,
                                      description=f"MyBatis ${{{j}}} splices the value into the SQL text"))
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        proc.connect(entry.id, exit_node.id)
        return proc

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
                        if a.type in ("(", ")", ",", "line_comment", "block_comment"):
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
        overloaded: set = set()

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
            # Last definition wins on overload/name clash (best-effort, intra-file); an
            # overloaded name is not propagated into at all (see below).
            if self._get_text(name_node) in methods:
                overloaded.add(self._get_text(name_node))
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
                    if cinfo is None or callee in overloaded:
                        continue        # which overload is called is not decided by the name
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
                            if a.type not in ("(", ")", ",", "line_comment", "block_comment"):
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

            for cookie_var, loc in addcookies:
                if cookie_var is None or cookie_var not in httponly_set:
                    hits_httponly.append(loc)
                if cookie_var is None or cookie_var not in secure_set:
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
        proc.has_varargs = self._has_varargs(node)
        proc.param_type_names = self._param_type_names(node)
        proc.ret_type_name = self._static_type(node.child_by_field_name("type"))
        proc.annotations = [parse_annotation(a, self._imports, value_alias=True) for a in annotations]
        pnode = node.child_by_field_name("parameters")
        for ch in (pnode.children if pnode is not None else ()):
            if ch.type in ("formal_parameter", "spread_parameter"):
                pn = ch.child_by_field_name("name")
                anns = self._get_annotations(ch)
                if pn is not None and anns:
                    proc.param_annotations[self._get_text(pn)] = [
                        parse_annotation(a, self._imports, value_alias=True) for a in anns]
                tn = ch.child_by_field_name("type")
                if pn is not None and tn is not None:
                    proc.param_types[self._get_text(pn)] = self._get_text(tn).split("<")[0].strip()

        # Check for static modifier
        for child in node.children:
            if child.type == "modifiers":
                if "static" in self._get_text(child):
                    proc.is_static = True

        self._current_proc = proc
        self._node_counter = 0
        self._constant_values = {}  # Reset constant tracking for each method
        self._weak_algo_vars = set()  # Reset weak algorithm variable tracking
        self._var_types = self._method_var_types(node)

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
        proc.has_varargs = self._has_varargs(node)
        proc.param_type_names = self._param_type_names(node)
        proc.ret_type_name = self._static_type(node.child_by_field_name("type"))

        self._current_proc = proc
        self._node_counter = 0
        self._var_types = self._method_var_types(node)

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

    def _param_type_names(self, node: TSNode) -> List[Optional[str]]:
        """Static parameter types (overload resolution); a varargs parameter
        `T... xs` is `T[]`, a type variable is None."""
        saved = self._type_vars
        self._type_vars = self._class_type_vars | self._type_params(node)
        try:
            params = node.child_by_field_name("parameters")
            out = []
            for c in (params.named_children if params else ()):
                if c.type == "formal_parameter":
                    out.append(self._static_type(c.child_by_field_name("type")))
                elif c.type == "spread_parameter":
                    t = next((x for x in c.named_children if x.type not in
                              ("modifiers", "variable_declarator", "identifier")), None)
                    st = self._static_type(t)
                    out.append(st + "[]" if st else None)
            return out
        finally:
            self._type_vars = saved

    _NUMERIC_RANK = {"byte": 1, "short": 2, "char": 2, "int": 3, "long": 4, "float": 5, "double": 6}
    _BOXED = {"Integer": "int", "Long": "long", "Short": "short", "Byte": "byte",
              "Character": "char", "Float": "float", "Double": "double", "Boolean": "boolean"}
    # Result types of common String methods, by name.
    _STRING_METHOD_TYPES = {
        "substring": "String", "trim": "String", "strip": "String", "toLowerCase": "String",
        "toUpperCase": "String", "replace": "String", "replaceAll": "String", "concat": "String",
        "repeat": "String", "intern": "String", "formatted": "String",
        "length": "int", "indexOf": "int", "lastIndexOf": "int", "compareTo": "int",
        "charAt": "char", "equals": "boolean", "isEmpty": "boolean", "isBlank": "boolean",
        "startsWith": "boolean", "endsWith": "boolean", "contains": "boolean",
        "matches": "boolean", "equalsIgnoreCase": "boolean", "split": "String[]",
        "getBytes": "byte[]", "toCharArray": "char[]"}

    def _promote(self, a: Optional[str], b: Optional[str]) -> Optional[str]:
        """Binary numeric promotion (JLS 5.6.2), through unboxing."""
        a, b = self._BOXED.get(a, a), self._BOXED.get(b, b)
        if a not in self._NUMERIC_RANK or b not in self._NUMERIC_RANK:
            return None
        wider = max(a, b, key=lambda t: self._NUMERIC_RANK[t])
        return "int" if self._NUMERIC_RANK[wider] < 3 else wider

    def _arg_type(self, arg: TSNode, depth: int = 0) -> Optional[str]:
        """Static type of an expression when the file makes it evident (JLS
        typing of literals, variables, operators, casts, `new`, the class's own
        methods and common String methods); None when unknown."""
        if arg is None or depth > 8:
            return None
        t = arg.type
        if t in ("decimal_integer_literal", "hex_integer_literal", "octal_integer_literal",
                 "binary_integer_literal"):
            return "long" if self._get_text(arg).lower().endswith("l") else "int"
        if t in ("decimal_floating_point_literal", "hex_floating_point_literal"):
            return "float" if self._get_text(arg).lower().endswith("f") else "double"
        if t in ("true", "false"):
            return "boolean"
        if t == "character_literal":
            return "char"
        if t in ("string_literal", "text_block"):
            return "String"
        if t == "null_literal":
            return "null"
        if t == "this":
            return self._current_class
        if t == "identifier":
            return self._static_types.get(self._get_text(arg))
        if t == "parenthesized_expression" and arg.named_child_count == 1:
            return self._arg_type(arg.named_children[0], depth + 1)
        if t == "cast_expression":
            return self._static_type(arg.child_by_field_name("type"))
        if t == "object_creation_expression":
            return self._static_type(arg.child_by_field_name("type"))
        if t == "array_creation_expression":
            elem = self._static_type(arg.child_by_field_name("type"))
            dims = sum(self._get_text(c).count("[") for c in arg.children
                       if c.type in ("dimensions_expr", "dimensions"))
            return elem + "[]" * max(dims, 1) if elem else None
        if t == "field_access":
            obj = arg.child_by_field_name("object")
            if obj is not None and obj.type == "this":
                return self._field_static_types.get(self._get_text(arg.child_by_field_name("field")))
            return None
        if t == "update_expression":
            return self._arg_type(arg.named_children[0], depth + 1) if arg.named_children else None
        if t == "unary_expression":
            op = self._get_text(arg.child_by_field_name("operator") or arg)
            operand = self._arg_type(arg.child_by_field_name("operand"), depth + 1)
            if op == "!":
                return "boolean"
            return self._promote(operand, "int") if operand else None
        if t == "binary_expression":
            op_node = arg.child_by_field_name("operator")
            op = self._get_text(op_node) if op_node is not None else ""
            left = self._arg_type(arg.child_by_field_name("left"), depth + 1)
            right = self._arg_type(arg.child_by_field_name("right"), depth + 1)
            if op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||", "instanceof"):
                return "boolean"
            if op == "+" and "String" in (left, right):
                return "String"
            if op in ("<<", ">>", ">>>"):
                return self._promote(left, "int")
            if op in ("&", "|", "^") and left == right == "boolean":
                return "boolean"
            return self._promote(left, right)
        if t == "ternary_expression":
            a = self._arg_type(arg.child_by_field_name("consequence"), depth + 1)
            b = self._arg_type(arg.child_by_field_name("alternative"), depth + 1)
            return a if a == b else None
        if t == "method_invocation":
            name_n, obj = arg.child_by_field_name("name"), arg.child_by_field_name("object")
            name = self._get_text(name_n) if name_n is not None else ""
            if obj is None or obj.type == "this":
                returns = self._class_method_returns.get(name)
                if returns and len(returns) == 1:
                    return next(iter(returns))
                return None
            if name in ("toString", "name") and not self._get_method_args(arg):
                return "String"
            if name == "hashCode" and not self._get_method_args(arg):
                return "int"
            if self._arg_type(obj, depth + 1) == "String":
                return self._STRING_METHOD_TYPES.get(name)
            if self._get_text(obj) == "String" and name in ("valueOf", "format", "join"):
                return "String"
            return JAVA_FACTORY_RETURN_TYPES.get(name)
        return None

    @staticmethod
    def _has_varargs(node: TSNode) -> bool:
        params = node.child_by_field_name("parameters")
        return params is not None and any(c.type == "spread_parameter" for c in params.named_children)

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

    @staticmethod
    def _peel_cast_call(node: Optional[TSNode]) -> Optional[TSNode]:
        """`return (String) xp.evaluate(q, doc)`: the call under a cast, so it is lowered as a call."""
        cur = node
        if cur is None or cur.type != "cast_expression":
            return None
        while cur is not None and cur.type in ("cast_expression", "parenthesized_expression"):
            cur = cur.child_by_field_name("value") if cur.type == "cast_expression" else \
                next((c for c in cur.named_children), None)
        return cur if cur is not None and cur.type == "method_invocation" else None

    @staticmethod
    def _peel_cast_chain(node: Optional[TSNode]) -> Optional[TSNode]:
        """`(Article) em.createQuery(q).getSingleResult()` -> the call: a cast around a CHAINED
        call changes nothing about the data, and the call must be lowered as a call. (A cast
        around a plain `map.get(k)` is left alone: it is analysed in its cast form.)"""
        cur = node
        while cur is not None and cur.type in ("cast_expression", "parenthesized_expression"):
            inner = cur.child_by_field_name("value") if cur.type == "cast_expression" else \
                next((c for c in cur.named_children), None)
            cur = inner
        if cur is not None and cur.type == "method_invocation":
            obj = cur.child_by_field_name("object")
            if obj is not None and obj.type == "method_invocation":
                return cur
        return node

    def _translate_local_var_declaration(self, node: TSNode) -> None:
        """Translate local variable declaration"""
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value_node = self._peel_cast_chain(child.child_by_field_name("value"))

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
                        elif value_node.type == "lambda_expression" and self._program is not None:
                            lam = self._lower_lambda(value_node, "<assign>")
                            self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=ExpConst.string(lam)))
                            self._add_instrs(self._invoke_lambda(lam, value_node, "", loc))
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
        right = self._peel_cast_chain(node.child_by_field_name("right"))

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
        elif right.type == "lambda_expression" and self._program is not None:
            lam = self._lower_lambda(right, "<assign>")
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=ExpConst.string(lam)))
            self._add_instrs(self._invoke_lambda(lam, right, "", loc))
        else:
            exp = self._translate_expression(right)
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=exp))

    # -- declared types ------------------------------------------------------

    _NO_TYPE = ""  # a name declared with conflicting types: type unknown

    def _type_name(self, type_node: Optional[TSNode], value: Optional[TSNode] = None) -> Optional[str]:
        """The class a declared type names, as spec keys spell it: generics
        and package qualifiers dropped (`java.util.List<String>` -> `List`).
        `var` takes the class of a `new T(...)` initializer or a documented
        factory's return type (JAVA_FACTORY_RETURN_TYPES). Primitives and
        arrays have no methods to match, so None."""
        if type_node is None:
            return None
        if type_node.type == "generic_type":
            type_node = next((c for c in type_node.named_children
                              if c.type in ("type_identifier", "scoped_type_identifier")), None)
            if type_node is None:
                return None
        if type_node.type == "scoped_type_identifier":
            parts = self._get_text(type_node).split(".")
            owners = [p for p in parts[:-1] if p[:1].isupper()]
            # `Request.Builder` / `Map.Entry`: a nested class keeps its outer class's name
            return ".".join(owners[-1:] + parts[-1:])
        if type_node.type == "type_identifier":
            text = self._get_text(type_node)
            if text == "var":
                if value is not None and value.type == "object_creation_expression":
                    return self._type_name(value.child_by_field_name("type"))
                if value is not None and value.type == "method_invocation":
                    name = value.child_by_field_name("name")
                    return JAVA_FACTORY_RETURN_TYPES.get(self._get_text(name)) if name else None
                return None
            return text
        return None

    def _declared_types(self, root: TSNode, typer=None) -> Dict[str, str]:
        """Declared type of every name declared under `root` (parameters,
        locals, for-each variables, resources, catch and lambda parameters).
        Nested class bodies are not entered. A name
        declared with two different types maps to _NO_TYPE."""
        typer = typer or self._type_name
        types: Dict[str, str] = {}

        def record(name_node, type_name):
            if name_node is None:
                return
            name = self._get_text(name_node)
            if type_name is None:
                types[name] = self._NO_TYPE
            elif types.get(name, type_name) != type_name:
                types[name] = self._NO_TYPE
            else:
                types[name] = type_name

        stack = [root]
        while stack:
            n = stack.pop()
            t = n.type
            if t in ("local_variable_declaration", "field_declaration"):
                type_node = n.child_by_field_name("type")
                for d in n.named_children:
                    if d.type == "variable_declarator":
                        record(d.child_by_field_name("name"),
                               typer(type_node, d.child_by_field_name("value")))
            elif t in ("formal_parameter", "spread_parameter", "resource"):
                record(n.child_by_field_name("name"),
                       typer(n.child_by_field_name("type"),
                                       n.child_by_field_name("value")))
            elif t == "enhanced_for_statement":
                # `value` is the iterable, not an initializer.
                record(n.child_by_field_name("name"),
                       typer(n.child_by_field_name("type")))
            elif t == "catch_formal_parameter":
                record(n.child_by_field_name("name"), None)
            elif t == "inferred_parameters":
                for p in n.named_children:
                    record(p, None)
            elif t == "lambda_expression":
                params = n.child_by_field_name("parameters")
                if params is not None and params.type == "identifier":
                    record(params, None)
            if t == "class_body":
                continue  # a nested class's names are not in scope here
            stack.extend(n.named_children)
        return types

    def _method_var_types(self, method_node: TSNode) -> Dict[str, str]:
        """Field types of the enclosing class, overridden by the method's own
        parameters and locals."""
        types = dict(self._field_types)
        types.update(self._declared_types(method_node))
        types = {k: v for k, v in types.items() if v}
        self._exact_vars = self._exactly_typed_locals(method_node, types)
        self._type_vars = self._class_type_vars | self._type_params(method_node)
        static = dict(self._field_static_types)
        static.update(self._declared_types(method_node, self._static_type))
        self._static_types = {k: v for k, v in static.items() if v}
        return types

    # -- static types (overload resolution) ----------------------------------

    _PRIMITIVE_NODES = ("integral_type", "floating_point_type", "boolean_type")

    def _type_params(self, decl: Optional[TSNode]) -> set:
        """Names of the type parameters a class / method declares (`<T>`)."""
        tps = decl.child_by_field_name("type_parameters") if decl is not None else None
        out = set()
        for tp in (tps.named_children if tps is not None else ()):
            ident = next((c for c in tp.named_children if c.type in ("type_identifier", "identifier")), None)
            if ident is not None:
                out.add(self._get_text(ident))
        return out

    def _static_type(self, type_node: Optional[TSNode], value: Optional[TSNode] = None) -> Optional[str]:
        """A declared type as overload resolution needs it: primitives
        (`int`), arrays (`byte[]`), classes without generics or package; a
        type variable (`T`) or an inferred `var` without evidence is None."""
        if type_node is None:
            return None
        if type_node.type in self._PRIMITIVE_NODES:
            return self._get_text(type_node)
        if type_node.type == "array_type":
            elem = self._static_type(type_node.child_by_field_name("element"))
            dims = type_node.child_by_field_name("dimensions")
            n = self._get_text(dims).count("[") if dims is not None else 1
            return elem + "[]" * n if elem else None
        name = self._type_name(type_node, value)
        if name == "var" or name in getattr(self, "_type_vars", ()):
            return None
        return name


    def _exactly_typed_locals(self, method_node: TSNode, types: Dict[str, str]) -> set:
        """Locals declared `T x = new T(...)` (or `var x = new T(...)`) and never
        re-assigned in the method: their runtime class is exactly T."""
        created, assigned = set(), set()
        for n in self._descendants(method_node, stop=("class_body",)):
            if n.type == "variable_declarator":
                value = n.child_by_field_name("value")
                name = self._get_text(n.child_by_field_name("name"))
                if (value is not None and value.type == "object_creation_expression"
                        and n.parent is not None and n.parent.type == "local_variable_declaration"
                        and self._type_name(value.child_by_field_name("type")) == types.get(name)):
                    created.add(name)
            elif n.type in ("assignment_expression", "update_expression"):
                left = n.child_by_field_name("left")
                if left is not None:
                    assigned.add(self._get_text(left))
        return created - assigned

    def _receiver_type(self, call_node: Optional[TSNode]) -> Optional[str]:
        """Declared type of the object a call is made on (`b` or `this.b` in
        `b.parse(x)`), if the frontend knows it."""
        if call_node is None:
            return None
        obj = call_node.child_by_field_name("object")
        if obj is None or obj.type == "this":
            # `m(x)` / `this.m(x)` calling a method this class declares.
            name = call_node.child_by_field_name("name")
            if name is not None and self._get_text(name) in self._class_methods:
                return self._current_class
            return None
        if obj.type == "identifier":
            return self._var_types.get(self._get_text(obj))
        if obj.type == "field_access":
            target = obj.child_by_field_name("object")
            if target is not None and target.type == "this":
                return self._field_types.get(self._get_text(obj.child_by_field_name("field"))) or None
        if obj.type == "method_invocation":
            return self._call_result_type(obj)
        if obj.type == "object_creation_expression":
            return self._type_name(obj.child_by_field_name("type"))
        return None

    def _call_result_type(self, call_node: TSNode) -> Optional[str]:
        """Declared type a documented API call returns (`JAVA_RETURN_TYPES`), so the next call of
        a chain has a receiver type."""
        name = call_node.child_by_field_name("name")
        obj = call_node.child_by_field_name("object")
        if name is None or obj is None:
            return None
        if obj.type == "identifier":
            text = self._get_text(obj)
            owner = self._var_types.get(text) or (text if text[:1].isupper() else None)
        elif obj.type == "method_invocation":
            owner = self._call_result_type(obj)
        elif obj.type == "object_creation_expression":
            owner = self._type_name(obj.child_by_field_name("type"))
        else:
            owner = None
        qualified = JAVA_RETURN_TYPES.get(f"{owner}.{self._get_text(name)}") if owner else None
        return self._implicit_import(qualified) if qualified else None

    def _implicit_import(self, qualified: str) -> str:
        """The simple name of a documented return type, made resolvable to its canonical name
        (the file need not import a type it only reaches through a chain)."""
        parts = qualified.split(".")
        first_class = next((i for i, p in enumerate(parts) if p[:1].isupper()), len(parts) - 1)
        outer = parts[first_class]
        simple = ".".join(parts[first_class:])          # `HttpRequest.Builder` keeps its outer class
        if outer in self._imports.names or outer in self._local_types:
            return simple
        if qualified.startswith(JAKARTA_MIGRATED) and any(
                v.startswith("jakarta.") for v in self._imports.names.values()):
            qualified = "jakarta." + qualified[len("javax."):]
            parts = qualified.split(".")
        self._imports.names[outer] = ".".join(parts[:first_class + 1])
        return simple

    def _hoist_creation_receiver(self, call_node: TSNode, loc: Location) -> Tuple[List[Instr], str]:
        """`new ProcessBuilder(cmd).start()`: the creation is a call of its own (a sink in its own
        right), bound to a temporary that the method is then called on. Without this the whole
        creation text became the method's name and neither call was analysed."""
        name = self._get_method_name(call_node)
        obj = call_node.child_by_field_name("object")
        method = call_node.child_by_field_name("name")
        if obj is not None and obj.type == "object_creation_expression" and method is not None:
            tmp = f"$new{self._ident_counter}"
            self._ident_counter += 1
            # `new File(userName).getName()` is the base-name idiom: the path is cut down to its
            # last element, so the constructor is not a path sink here.
            basename = (self._get_text(method) == "getName"
                        and self._type_name(obj.child_by_field_name("type")) == "File")
            return (self._translate_object_creation_assignment(tmp, obj, loc, sink=not basename),
                    f"{tmp}.{self._get_text(method)}")
        if obj is not None and obj.type == "method_invocation" and method is not None:
            pre: List[Instr] = []
            root = self._builder_chain_root(obj, loc, pre)
            if root is not None:
                # `sb.append(a).append(b).toString()`: every link acts on the one builder.
                return pre, f"{root}.{self._get_text(method)}"
            # `em.createQuery(q).getResultList()`, `http.get().uri(url)`: the outer call keeps
            # its textual name; the inner call is analysed as a call of its own so its
            # arguments reach its own sink / source / project callee.
            tmp = f"$ch{self._ident_counter}"
            self._ident_counter += 1
            inner = self._translate_call_assignment(tmp, obj, loc)
            if not self._chain_keyed(name) and (
                    self._lookup_spec(name, call_node) is None or self._call_result_type(obj) is not None):
                # No spec is keyed on the chain's text: the outer call is made on the inner
                # call's RESULT, so its taint (a source such as `uriInfo.getQueryParameters()`)
                # reaches the outer call's result by the ordinary receiver rule.
                return inner, f"{tmp}.{self._get_text(method)}"
            return inner, name
        return [], name

    def _chain_keyed(self, name: str) -> bool:
        """True when a spec is keyed on the CHAIN's own text (`getWriter().println`,
        `Runtime.getRuntime().exec`): then the call keeps that name. Any other chain call is
        made on the inner call's result."""
        parts = name.split(".")
        return any("(" in ".".join(parts[i:]) and ".".join(parts[i:]) in self.specs
                   for i in range(len(parts)))

    # Methods that return the receiver (or a view of it), so a chain of them is a sequence of
    # calls on the first receiver.
    _BUILDER_METHODS = frozenset({"append", "insert", "appendCodePoint", "reverse", "replace",
                                  "delete", "deleteCharAt", "concat"})
    _BUILDER_TYPES = frozenset({"StringBuilder", "StringBuffer"})

    def _builder_chain_root(self, node: TSNode, loc: Location, pre: List[Instr]) -> Optional[str]:
        """For `root.append(a).append(b)` (node = the chain up to the last builder call) where root
        is a StringBuilder/StringBuffer variable or `new StringBuilder(..)`: emit each link as a
        call on the root into `pre` and return the root's name; None if this is not such a chain."""
        links: List[TSNode] = []
        cur = node
        while cur is not None and cur.type == "method_invocation":
            nm = cur.child_by_field_name("name")
            if nm is None or self._get_text(nm) not in self._BUILDER_METHODS:
                return None
            links.append(cur)
            cur = cur.child_by_field_name("object")
        if cur is None:
            return None
        if cur.type == "identifier" and self._var_types.get(self._get_text(cur)) in self._BUILDER_TYPES:
            root = self._get_text(cur)
        elif cur.type == "object_creation_expression" and \
                self._type_name(cur.child_by_field_name("type")) in self._BUILDER_TYPES:
            root = f"$new{self._ident_counter}"
            self._ident_counter += 1
            pre.extend(self._translate_object_creation_assignment(root, cur, loc))
        else:
            return None
        for link in reversed(links):
            name = self._get_text(link.child_by_field_name("name"))
            args = self._get_method_args(link)
            hoisted, args_exp = self._translate_args(args, loc)
            pre.extend(hoisted)
            pre.append(Call(loc=loc, ret=None, func=ExpConst.string(f"{root}.{name}"), args=args_exp,
                            receiver_type=self._var_types.get(root) or "StringBuilder"))
        return root

    def _callee_class(self, call_node: Optional[TSNode]) -> Optional[str]:
        """The class a call's method belongs to: the receiver's declared type, a class name
        used as a qualifier (`Shell.run(x)`: an identifier that is no variable and starts upper
        case), or this class for `m(x)` / `this.m(x)` (which may be inherited)."""
        if call_node is None:
            return None
        obj = call_node.child_by_field_name("object")
        if obj is None:
            # `run(x)` with `import static a.B.run`: the method belongs to B unless this class declares one
            name = self._get_text(call_node.child_by_field_name("name"))
            if name not in self._class_methods:
                if name in self._static_members:
                    return self._static_members[name]
                if len(self._static_star) == 1:
                    return self._static_star[0]
        if obj is None or obj.type == "this":
            return self._current_class
        if obj.type == "identifier":
            name = self._get_text(obj)
            if name in self._var_types:
                return self._var_types[name]
            return name if name[:1].isupper() else None
        if obj.type == "field_access":
            target = obj.child_by_field_name("object")
            if target is not None and target.type == "this":
                return self._field_types.get(self._get_text(obj.child_by_field_name("field"))) or None
            return None
        if obj.type == "object_creation_expression":
            return self._type_name(obj.child_by_field_name("type"))
        return None

    def _receiver_exact(self, call_node: Optional[TSNode]) -> bool:
        obj = call_node.child_by_field_name("object") if call_node is not None else None
        return obj is not None and obj.type == "identifier" and self._get_text(obj) in self._exact_vars

    def _lookup_spec(self, method_name: str, call_node: Optional[TSNode] = None) -> Optional[ProcSpec]:
        """
        Flexible spec lookup that tries multiple matching strategies:
        0. The receiver's declared type (`DocumentBuilder b; b.parse` ->
           documentBuilder.parse), see java_specs.type_spec_receivers
        1. Full method name (e.g., statement.executeUpdate)
        2. Just the method name (e.g., executeUpdate)
        3. Common object patterns (request., response., etc.)
        """
        recv_type = self._receiver_type(call_node)
        if call_node is not None and self._receiver_tag(call_node) == "hardened" \
                and method_name.rsplit(".", 1)[-1] in self._TAG_SENSITIVE["hardened"]:
            return None
        if recv_type and recv_type == self._current_class and (
                '.' not in method_name or method_name.startswith("this.")):
            return None  # the class's own method: its body is analysed instead
        # A receiver of one of the project's own classes (`service.search(q)`), or a class that is
        # not what a bare method name (`search`, `execute`, `evaluate`) is about, is not that
        # library API: only a spec keyed on the type or on the exact written name applies.
        vetoed = self._name_spec_vetoed(method_name, recv_type)
        by_name = (lambda: self.specs.get(method_name)) if vetoed \
            else (lambda: self._lookup_spec_by_name(method_name))
        if recv_type and '.' in method_name:
            return typed_spec_lookup(self.specs, recv_type, method_name,
                                     self._receiver_exact(call_node),
                                     by_name, type_spec_receivers)
        return by_name()

    def _name_spec_vetoed(self, method_name: str, recv_type: Optional[str]) -> bool:
        """The receiver's type is known and is not what a bare-name spec (`search`, `execute`) is
        about: that call is a project method or another library's method of the same name. Only a
        spec keyed on the type applies (the caller already tried those)."""
        if '.' not in method_name:
            return False
        if recv_type and (self._is_project_type(recv_type) or self._not_a_name_only_receiver(recv_type, method_name)):
            return True
        # a class used as the qualifier (`Pattern.compile`, `Velocity.evaluate`)
        head = method_name.rsplit(".", 1)[0]
        return (not recv_type and head[:1].isupper() and "." not in head and head not in self._var_types
                and self._not_a_name_only_receiver(head, method_name))

    def _set_neutral_spec(self, call: Call, call_node: TSNode, method_name: str, nargs: int) -> None:
        """A configured deserialiser's call is neutral for good (`pack_spec`, ahead of any pack rule);
        a call whose bare-name library spec is vetoed gets the neutral spec only if no pack rule
        claims it (`neutral_spec`, applied after the packs)."""
        spec = self._neutral_spec(call_node, method_name, nargs)
        if spec is None:
            return
        if self._receiver_tag(call_node) == "hardened":
            call.pack_spec = spec
        else:
            call.neutral_spec = spec

    def _apply_neutral_specs(self, program: Program) -> None:
        for proc in program.procedures.values():
            for node in proc.nodes.values():
                for instr in node.instrs:
                    spec = getattr(instr, "neutral_spec", None)
                    if spec is not None and getattr(instr, "pack_spec", None) is None:
                        instr.pack_spec = spec

    def _neutral_spec(self, call_node: TSNode, method_name: str, nargs: int) -> Optional[ProcSpec]:
        """For a call whose bare-name spec is vetoed and that has no spec of its own: a spec that
        is neither source nor sink and keeps the default argument / receiver -> result flow, set on
        the Call so the translator's own name lookup cannot turn it into a sink either."""
        recv_type = self._receiver_type(call_node)
        if self._receiver_tag(call_node) == "hardened" \
                and method_name.rsplit(".", 1)[-1] in self._TAG_SENSITIVE["hardened"]:
            return ProcSpec(taint_propagates=list(range(nargs)), taint_from_receiver=True,
                            description="deserialiser configured with a type allow-list / safe constructor")
        if not self._name_spec_vetoed(method_name, recv_type):
            return None
        if self._lookup_spec(method_name, call_node) is not None \
                or self._lookup_spec_by_name(method_name) is None:
            return None
        return ProcSpec(taint_propagates=list(range(nargs)), taint_from_receiver=True,
                        description="project / non-matching receiver: no library spec")

    # -- configured receivers (hardened / polymorphic deserialisers) ----------------------------

    _XSTREAM_HARDENING = frozenset({"allowTypes", "allowTypesByWildcard", "allowTypesByRegExp",
                                    "addPermission", "setupDefaultSecurity"})
    _JACKSON_POLYMORPHIC = frozenset({"enableDefaultTyping", "activateDefaultTyping",
                                      "enableDefaultTypingAsProperty"})

    def _collect_receiver_facts(self, root: TSNode) -> Dict[str, set]:
        """Per variable name: the methods called on it and the text it was initialised with, over the
        whole file, so `xstream.allowTypes(...)` anywhere marks that XStream as configured."""
        facts: Dict[str, set] = {}
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "variable_declarator":
                nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
                if nm is not None and val is not None:
                    facts.setdefault(self._get_text(nm), set()).add("init:" + self._get_text(val))
            elif n.type == "assignment_expression":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and right is not None:
                    lname = self._get_text(left).replace("this.", "")
                    facts.setdefault(lname, set()).add("init:" + self._get_text(right))
            elif n.type == "method_invocation":
                obj, nm = n.child_by_field_name("object"), n.child_by_field_name("name")
                if nm is not None:
                    method = self._get_text(nm)
                    if obj is not None and obj.type in ("identifier", "field_access"):
                        facts.setdefault(self._get_text(obj).replace("this.", ""), set()).add("call:" + method)
                    # `XStream.setupDefaultSecurity(x)`: the argument is configured
                    if method in self._XSTREAM_HARDENING:
                        for a in self._get_method_args(n):
                            if a.type == "identifier":
                                facts.setdefault(self._get_text(a), set()).add("call:" + method)
            stack.extend(n.children)
        return facts

    def _receiver_tag(self, call_node: Optional[TSNode]) -> Optional[str]:
        """`hardened` for an XStream with a type allow-list / a SnakeYAML `Yaml(new SafeConstructor())`,
        `polymorphic` for a Jackson ObjectMapper with default typing; else None."""
        if call_node is None:
            return None
        obj = call_node.child_by_field_name("object")
        if obj is None or obj.type not in ("identifier", "field_access"):
            return None
        name = self._get_text(obj).replace("this.", "")
        facts = self._receiver_facts.get(name, set())
        typ = self._receiver_type(call_node)
        if typ == "XStream" and any(f.startswith("call:") and f[5:] in self._XSTREAM_HARDENING for f in facts):
            return "hardened"
        if typ == "XStream" and any("setupDefaultSecurity" in f or "allowTypes" in f or "addPermission" in f
                                    for f in facts):
            return "hardened"
        if typ == "Yaml" and any(f.startswith("init:") and "SafeConstructor" in f for f in facts):
            return "hardened"
        if typ == "ObjectMapper" and any(
                (f.startswith("call:") and f[5:] in self._JACKSON_POLYMORPHIC)
                or (f.startswith("init:") and any(m in f for m in self._JACKSON_POLYMORPHIC)) for f in facts):
            return "polymorphic"
        return None

    _TAG_SENSITIVE = {"hardened": frozenset({"fromXML", "load", "loadAs", "loadAll", "unmarshal"}),
                      "polymorphic": frozenset({"readValue", "readValues", "convertValue", "treeToValue"})}

    def _tag_sinks(self, call_node: TSNode, method_name: str, args_exp: list, loc: Location) -> List[Instr]:
        """A Jackson mapper with default typing instantiates whatever class the JSON names."""
        if self._receiver_tag(call_node) == "polymorphic" and args_exp \
                and method_name.rsplit(".", 1)[-1] in self._TAG_SENSITIVE["polymorphic"]:
            return [TaintSink(loc=loc, exp=args_exp[0][0], kind=SinkKind.DESERIALIZATION,
                              description="Jackson with default typing instantiates the class the JSON names",
                              receiver=self._call_receiver(method_name))]
        return []

    # A bare method name that is a sink only on some library types (`execute` runs SQL on a JDBC
    # statement / template, not on a Vert.x query, an Executor or a Command).
    _NAME_ONLY_RECEIVERS = {
        "execute": re.compile(r"(Statement|Template|Connection|Operations|Session|Manager|Runner|Context|Client)$"),
        "evaluate": re.compile(r"X[Pp]ath"),
        "compile": re.compile(r"X[Pp]ath"),
        "search": re.compile(r"(Context|Ldap|LDAP|Dir|Directory)"),
        "lookup": re.compile(r"(Ldap|LDAP|Dir)"),
    }

    def _not_a_name_only_receiver(self, recv_type: str, method_name: str) -> bool:
        pattern = self._NAME_ONLY_RECEIVERS.get(method_name.rsplit(".", 1)[-1])
        if pattern is None:
            return False
        simple = recv_type.rsplit(".", 1)[-1]
        return not pattern.search(simple) or simple in ("PreparedQuery", "RowSet", "SqlResult")

    _JAVA_LANG_TYPES = frozenset({
        "String", "StringBuilder", "StringBuffer", "Object", "Runtime", "Process", "ProcessBuilder",
        "System", "Thread", "Class", "ClassLoader", "Math", "Integer", "Long", "Double", "Float",
        "Short", "Byte", "Character", "Boolean", "Number", "Throwable", "Exception", "Iterable",
        "Runnable", "Comparable", "CharSequence", "Enum", "Record", "Void"})

    def _is_project_type(self, type_name: str) -> bool:
        """True when `type_name` is known to be one of this project's own classes: declared in
        this file, or neither imported nor java.lang and no wildcard import could supply it (same
        package), or imported from a package sharing this file's package root. A type that might
        come from a library (wildcard imports, any other import) is not."""
        simple = type_name.rsplit(".", 1)[-1]
        if simple in self._local_types:
            return True
        if simple in self._JAVA_LANG_TYPES or "." in type_name or simple in self._qualified_names:
            return False
        imported = self._imports.names.get(simple)
        if imported is not None:
            return self._same_project_package(imported.rsplit(".", 1)[0])
        if self._spec_receivers & set(type_spec_receivers(simple)):
            return False                                   # a library type the specs know by name
        return not self._imports.wildcards or all(
            self._same_project_package(w) for w in self._imports.wildcards)

    def _same_project_package(self, package: str) -> bool:
        own = self._package.split(".") if self._package else []
        other = package.removesuffix(".*").split(".")
        if len(own) < 2 or len(other) < 2:
            return False
        shared = 0
        for a, b in zip(own, other):
            if a != b:
                break
            shared += 1
        return shared >= (3 if own[0] in ("org", "net", "io") else 2)

    def _lookup_spec_by_name(self, method_name: str) -> Optional[ProcSpec]:
        """Name-based lookup (receiver type unknown, or no typed spec)."""

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

        pre, method_name = self._hoist_creation_receiver(call_node, loc)
        args = self._get_method_args(call_node)
        instrs, args_exp = self._translate_args(args, loc, via=self._get_method_name(call_node))
        lams = self._last_lambdas
        instrs = pre + instrs

        ret_id = self._new_ident(target)

        call_instr = Call(
            loc=loc,
            ret=(ret_id, Typ.unknown_type()),
            func=ExpConst.string(method_name),
            args=args_exp,
            receiver_type=self._receiver_type(call_node),
            receiver_exact=self._receiver_exact(call_node),
            arg_types=[self._arg_type(a) for a in args],
            callee_class=self._callee_class(call_node),
        )
        self._set_neutral_spec(call_instr, call_node, method_name, len(args))
        instrs.append(call_instr)
        instrs.extend(self._invoke_lambdas(lams, method_name, loc))

        instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpVar(ret_id)))
        instrs.extend(self._getter_receiver_flow(target, call_node, loc))

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
        spec = self._lookup_spec(method_name, call_node)
        if spec and spec.is_taint_source():
            kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
            instrs.append(TaintSource(loc=loc, var=PVar(target), kind=kind, description=spec.description))

        instrs.extend(self._tag_sinks(call_node, method_name, args_exp, loc))
        if spec and spec.is_taint_sink() and self._sink_applies(spec, args):
            # Special handling for crypto/hash sinks that need algorithm checking
            if self._is_algorithm_based_sink(method_name):
                algo_instr = self._check_algorithm_sink(method_name, args, loc)
                if algo_instr:
                    instrs.append(algo_instr)
            else:
                kind = resolve_sink_kind(spec.is_sink)
                for arg_idx in spec.sink_args:
                    if arg_idx < len(args):
                        arg_exp = args_exp[arg_idx][0]
                        instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description,
                                                receiver=self._call_receiver(method_name)))

        return instrs

    def _hoist_nested_call(self, node: TSNode) -> Optional[Exp]:
        """A call written inside an expression (`new RedirectView(service.page(next))`,
        `"/a/" + UriUtils.encodePath(x)`) is lowered like `tmp = call` right before the statement
        that uses it, so its spec (source, sink, sanitizer) and, in a project, its callee's
        summary apply. As an ExpCall it was only a name that a few places looked at."""
        if self._current_node is None or self._current_proc is None or not self._in_call_args:
            return None
        key = (node.start_byte, node.end_byte)
        tmp = self._nested_calls.get(key)
        if tmp is None:
            tmp = f"$nc{self._ident_counter}"
            self._ident_counter += 1
            self._nested_calls[key] = tmp
            self._add_instrs(self._translate_call_assignment(tmp, node, self._get_location(node)))
        return ExpVar(PVar(tmp))

    _GETTER = re.compile(r"^(get|is)[A-Z]\w*$")

    def _is_bean_getter(self, call_node: TSNode) -> Optional[str]:
        """`form.getName()`: a no-argument getter called on a local/parameter whose declared type is
        one of the project's own classes. Returns the receiver variable, else None."""
        obj = call_node.child_by_field_name("object")
        name = call_node.child_by_field_name("name")
        if obj is None or name is None or obj.type != "identifier" or self._get_method_args(call_node):
            return None
        var = self._get_text(obj)
        typ = self._var_types.get(var)
        if typ and self._GETTER.match(self._get_text(name)) and self._is_project_type(typ):
            return var
        return None

    def _is_receiver_getter_arg(self, call_node: TSNode) -> bool:
        """`save(file.getOriginalFilename())`: a no-argument getter on a variable, as an argument.
        Inline it has no instruction of its own, so a callee in another file never learns that
        the argument is tainted; lowered to a temporary it is an ordinary call result."""
        obj = call_node.child_by_field_name("object")
        name = call_node.child_by_field_name("name")
        return (obj is not None and name is not None and obj.type == "identifier"
                and not self._get_method_args(call_node) and bool(self._GETTER.match(self._get_text(name))))

    def _getter_receiver_flow(self, target: str, call_node: TSNode, loc: Location) -> List[Instr]:
        """The value a getter returns is state of its receiver. A getter that is resolved to the
        project's own method (a bean bound from the request: @RequestBody / @ModelAttribute / a
        Struts action) is summarised by what its PARAMETERS contribute, which is nothing, so the
        receiver's taint is carried to the result here."""
        var = self._is_bean_getter(call_node)
        if var is None:
            return []
        return [Assign(loc=loc, id=PVar(target),
                       exp=ExpBinOp("+", ExpVar(PVar(target)), ExpVar(PVar(var))))]

    # -- lambdas and method references ------------------------------------------------

    def _lambda_param_nodes(self, node: TSNode) -> List[Tuple[str, Optional[str]]]:
        """(name, written type or None) of a lambda's parameters."""
        params = node.child_by_field_name("parameters")
        out: List[Tuple[str, Optional[str]]] = []
        if params is None:
            return out
        if params.type == "identifier":
            out.append((self._get_text(params), None))
        elif params.type == "inferred_parameters":
            out += [(self._get_text(c), None) for c in params.named_children if c.type == "identifier"]
        else:
            for c in params.named_children:
                if c.type in ("formal_parameter", "spread_parameter"):
                    nm = c.child_by_field_name("name")
                    tn = c.child_by_field_name("type")
                    if nm is not None:
                        out.append((self._get_text(nm), self._type_name(tn) if tn is not None else None))
        return out

    def _framework_lambda_types(self, via: str) -> Tuple[str, ...]:
        """Qualified parameter types for a lambda handed to this registration call."""
        values = list(self._imports.names.values()) + list(self._imports.wildcards)
        for prefixes, pattern, types in JAVA_LAMBDA_PARAMS:
            if any(v.startswith(pre) or v.startswith(pre.rstrip(".")) for v in values for pre in prefixes) \
                    and re.search(pattern, via):
                return types
        return ()

    def _lower_lambda(self, node: TSNode, via: str) -> str:
        """A lambda is a procedure of its own (handlers are lambdas in Spark, Javalin, Vert.x, ...):
        its parameters are typed from the registration it is passed to, `registered_via` names that
        call, and the enclosing method's variables it reads are recorded as `captures`."""
        cached = self._lambda_names.get(node.id)
        if cached is not None:
            return cached
        program = self._program
        row, col = node.start_point
        cls = self._current_class or ""
        name = f"{cls}.lambda@{row + 1}_{col}"
        self._lambda_names[node.id] = name
        pnodes = self._lambda_param_nodes(node)
        inferred = self._framework_lambda_types(via)
        if inferred:
            self._handler_lambdas.add(name)
        outer_types = dict(self._var_types)
        params: List[Tuple[PVar, Typ]] = []
        proc = Procedure(name=name, params=params, ret_type=Typ.unknown_type(),
                         loc=self._get_location(node), is_method=False)
        proc.class_name = cls or None
        proc.registered_via.append(via)
        proc.span = (node.start_byte, node.end_byte)
        local_types = dict(outer_types)
        for i, (pname, written) in enumerate(pnodes):
            params.append((PVar(pname), Typ.unknown_type()))
            local_types.pop(pname, None)
            qualified = None
            if written is None and i < len(inferred):
                qualified = inferred[i]
            if written:
                proc.param_types[pname] = written
                local_types[pname] = written
            elif qualified:
                simple = self._implicit_import(qualified)
                if self._imports.names.get(simple) == qualified:
                    proc.param_types[pname] = simple
                    local_types[pname] = simple
                else:                                   # the simple name means another type here
                    proc.param_types[pname] = qualified
                    local_types[pname] = simple
        body = node.child_by_field_name("body")
        own = {p.name for p, _ in params}
        enclosing = set(self._current_proc.param_types) | {p.name for p, _ in self._current_proc.params} \
            if self._current_proc is not None else set()
        enclosing |= set(outer_types)
        if body is not None:
            proc.captures = sorted((enclosing - own) & self._identifiers_in(body))
        saved = (self._current_proc, self._current_node, self._node_counter, self._var_types,
                 self._constant_values, self._weak_algo_vars, self._in_call_args)
        parent_proc = self._current_proc
        if parent_proc is not None:
            self._lambda_parents.append((proc, parent_proc))        # linked by final name later
        self._current_proc = proc
        self._node_counter = 0
        self._var_types = local_types
        self._constant_values = {}
        self._weak_algo_vars = set()
        self._in_call_args = False
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry
        if body is not None:
            if body.type == "block":
                self._translate_block(body)
            else:
                self._translate_lambda_value(body)
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)
        (self._current_proc, self._current_node, self._node_counter, self._var_types,
         self._constant_values, self._weak_algo_vars, self._in_call_args) = saved
        program.add_procedure(proc)
        return name

    _IDENT = re.compile(r"^[A-Za-z_$][\w$]*$")

    def _invoke_lambdas(self, lams: List[Tuple[str, TSNode]], call_name: str, loc: Location) -> List[Instr]:
        out: List[Instr] = []
        for lam, node in lams:
            out.extend(self._invoke_lambda(lam, node, call_name, loc))
        return out

    def _invoke_lambda(self, lam: str, node: TSNode, via: str, loc: Location) -> List[Instr]:
        """A lambda handed to a call (`pool.submit(() -> run(v))`, `names.forEach(n -> run(n))`)
        is invoked by whatever receives it, so the file's analysis sees a call: the variables it
        captures reach its body, and a receiver collection (`names`) is what its parameter holds.
        A framework handler (`get("/x", (req, res) -> ...)`) is called by the framework instead."""
        if lam in self._handler_lambdas:
            return []
        recv = via.rsplit(".", 1)[0] if "." in via else ""
        args = []
        if recv and self._IDENT.match(recv) and self._lambda_param_nodes(node):
            args = [(ExpVar(PVar(recv)), Typ.unknown_type())]
        return [self._lambda_call(lam, args, loc)]

    def _lambda_call(self, lam: str, args: list, loc: Location) -> Call:
        """The call that runs lambda `lam` of this class: `this.lambda@R_C(...)`, which the
        translator resolves like a method call on the class."""
        proc = self._program.procedures.get(lam)
        if proc is not None:
            proc.is_method = True
        return Call(loc=loc, ret=None, func=ExpConst.string("this." + lam.rsplit(".", 1)[-1]), args=args)

    def _lower_anonymous_class(self, creation: TSNode, loc: Location) -> List[Instr]:
        """`new Runnable() { public void run() { ... } }`: each method of the anonymous class body is
        a procedure of its own (like a lambda; the enclosing variables it reads are captures), and
        creating the object is where the file's analysis sees it called."""
        body = next((c for c in creation.children if c.type == "class_body"), None)
        if body is None:
            return []
        type_name = self._get_text(creation.child_by_field_name("type"))
        out: List[Instr] = []
        for m in body.named_children:
            if m.type == "method_declaration" and m.child_by_field_name("body") is not None:
                name = self._lower_lambda(m, f"new {type_name}")
                out.append(self._lambda_call(name, [], loc))
        return out

    def _translate_lambda_value(self, expr: TSNode) -> None:
        """`ctx -> service.find(ctx.param("id"))`: the expression is the lambda's result."""
        loc = self._get_location(expr)
        if expr.type in ("method_invocation", "object_creation_expression"):
            tmp = f"$ret{self._ident_counter}"
            self._ident_counter += 1
            if expr.type == "method_invocation":
                self._add_instrs(self._translate_call_assignment(tmp, expr, loc))
            else:
                self._add_instrs(self._translate_object_creation_assignment(tmp, expr, loc))
            self._add_instrs(self._handler_return_sinks(expr, loc))
            self._add_instr(Return(loc=loc, value=ExpVar(PVar(tmp))))
        else:
            self._add_instrs(self._handler_return_sinks(expr, loc))
            self._add_instr(Return(loc=loc, value=self._translate_expression(expr)))

    def _note_method_reference(self, node: TSNode, via: str) -> None:
        """`router.get("/x").handler(this::show)` / `Handlers::show`: the referenced method of a
        class in this file is registered with that call (resolved when the file is done)."""
        kids = [c for c in node.children if c.type not in ("::",)]
        if len(kids) < 2:
            return
        owner, method = self._get_text(kids[0]), self._get_text(kids[-1])
        self._method_refs.append((self._current_class if owner == "this" else owner, method, via))

    def _apply_method_references(self, program: Program) -> None:
        for owner, method, via in self._method_refs:
            for proc in program.procedures.values():
                if proc.simple_name == method and (owner is None or proc.class_name == owner):
                    if via not in proc.registered_via:
                        proc.registered_via.append(via)

    def _translate_args(self, args: List[TSNode], loc: Location, via: str = ""):
        """Arguments of a call as SIL expressions, plus the instructions that
        must run first. An argument that is itself a call to a taint SOURCE
        (`parse(req.getInputStream())`) is hoisted into a temporary
        (`$a = req.getInputStream(); parse($a)`), so its taint flows through
        the outer call by the ordinary rules -- a propagator propagates it, a
        sanitizer cleans it -- instead of existing only inside an expression
        that nothing but a sink ever looks into."""
        instrs: List[Instr] = []
        exps = []
        lams: List[Tuple[str, TSNode]] = []
        for a in args:
            if a.type == "lambda_expression" and self._program is not None:
                lam = self._lower_lambda(a, via or "<call>")
                exps.append((ExpConst.string(lam), Typ.unknown_type()))
                lams.append((lam, a))
                continue
            if a.type == "object_creation_expression" and self._program is not None:
                instrs.extend(self._lower_anonymous_class(a, loc))
            if a.type == "method_reference":
                self._note_method_reference(a, via or "<call>")
            if a.type == "method_invocation":
                spec = self._lookup_spec(self._get_method_name(a), a)
                if (spec is not None and spec.is_taint_source()) or self._is_receiver_getter_arg(a):
                    tmp = f"$arg{self._ident_counter}"
                    self._ident_counter += 1
                    instrs.extend(self._translate_call_assignment(tmp, a, loc))
                    exps.append((ExpVar(PVar(tmp)), Typ.unknown_type()))
                    continue
            outer, self._in_call_args = self._in_call_args, True
            try:
                exps.append((self._translate_expression(a), Typ.unknown_type()))
            finally:
                self._in_call_args = outer
        self._last_lambdas = lams
        return instrs, exps

    def _sink_applies(self, spec: ProcSpec, args: List[TSNode]) -> bool:
        """A spec with `permissive_callback_arg` is a sink only when that
        argument is a callback that accepts everything."""
        idx = spec.permissive_callback_arg
        if idx is None:
            return True
        return idx < len(args) and self._is_permissive_callback(args[idx])

    def _is_permissive_callback(self, node: TSNode, depth: int = 0) -> bool:
        """Does `node` evaluate to a verifier that accepts every input? True for
        a lambda or anonymous class whose boolean result is `true` on every
        return, for a library object documented as permissive, and for a
        local or field initialised with one of those. Anything else (a getter,
        a parameter, a verifier with real logic) is not provably permissive."""
        if node is None or depth > 3:
            return False
        if node.type == "parenthesized_expression" and node.named_child_count == 1:
            return self._is_permissive_callback(node.named_children[0], depth + 1)
        if node.type == "lambda_expression":
            return self._always_returns_true(node.child_by_field_name("body"))
        if node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = self._get_text(type_node) if type_node else ""
            if type_name.rsplit(".", 1)[-1] in PERMISSIVE_VERIFIERS:
                return True
            body = next((c for c in node.children if c.type == "class_body"), None)
            if body is None:
                return False
            methods = [m for m in body.named_children if m.type == "method_declaration"
                       and m.child_by_field_name("type") is not None
                       and m.child_by_field_name("type").type == "boolean_type"]
            return bool(methods) and all(
                self._always_returns_true(m.child_by_field_name("body")) for m in methods)
        if node.type in ("field_access", "identifier", "scoped_identifier"):
            text = self._get_text(node)
            if text in PERMISSIVE_VERIFIERS or text.split(".", 1)[-1] in PERMISSIVE_VERIFIERS:
                return True
            if node.type == "identifier":
                init = self._find_initializer(node, text)
                return init is not None and self._is_permissive_callback(init, depth + 1)
        return False

    def _always_returns_true(self, body: Optional[TSNode]) -> bool:
        """A lambda / method body whose result is the literal `true` on every
        path: an expression body `true`, or a block with at least one return
        where every return (outside nested classes and lambdas) is `true`."""
        if body is None:
            return False
        if body.type == "true":
            return True
        if body.type != "block":
            return False
        returns = []
        stack = list(body.named_children)
        while stack:
            n = stack.pop()
            if n.type in ("lambda_expression", "class_body"):
                continue
            if n.type == "return_statement":
                returns.append(n)
                continue
            stack.extend(n.named_children)
        return bool(returns) and all(
            r.named_child_count == 1 and r.named_children[0].type == "true"
            for r in returns)

    def _find_initializer(self, use: TSNode, name: str) -> Optional[TSNode]:
        """The initializer of the local variable (enclosing method) or field
        (enclosing class) `name` visible at `use`. A name that is ever
        re-assigned has no single initializer, so None."""
        scope = use.parent
        while scope is not None:
            if scope.type in ("method_declaration", "constructor_declaration"):
                body = self._descendants(scope, stop=("class_body",))
                decls = body
            elif scope.type == "class_body":
                body = self._descendants(scope, stop=())
                decls = [d for f in scope.named_children if f.type == "field_declaration"
                         for d in f.named_children]
            else:
                scope = scope.parent
                continue
            inits = [d.child_by_field_name("value") for d in decls
                     if d.type == "variable_declarator"
                     and self._get_text(d.child_by_field_name("name")) == name]
            if inits:
                reassigned = any(
                    d.type == "assignment_expression"
                    and self._get_text(d.child_by_field_name("left")) in (name, "this." + name)
                    for d in body)
                return None if reassigned or len(inits) > 1 else inits[0]
            if scope.type == "class_body":
                return None
            scope = scope.parent
        return None

    @staticmethod
    def _descendants(root: TSNode, stop: tuple) -> List[TSNode]:
        """All named descendants of `root`, not entering nodes of a `stop` type."""
        out, stack = [], list(root.named_children)
        while stack:
            n = stack.pop()
            out.append(n)
            if n.type not in stop:
                stack.extend(n.named_children)
        return out

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
        loc: Location,
        sink: bool = True,
    ) -> List[Instr]:
        """Translate: target = new ClassName(args)"""
        instrs = []

        type_node = creation_node.child_by_field_name("type")
        type_name = self._get_text(type_node) if type_node else "Object"

        args = []
        args_node = creation_node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type not in ("(", ")", ",", "line_comment", "block_comment"):
                    args.append(child)

        instrs, args_exp = self._translate_args(args, loc, via=f"new {type_name}")
        instrs.extend(self._lower_anonymous_class(creation_node, loc))

        # Constructor call name (a creation whose own sinks are off is named so no spec matches it)
        constructor_name = f"new {type_name}" if sink else f"new {type_name}$value"

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
        spec = self._lookup_spec(constructor_name) if sink else None
        if spec and spec.is_taint_sink() and self._sink_applies(spec, args):
            kind = resolve_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = args_exp[arg_idx][0]
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description))

        return instrs

    def _translate_method_call(self, call_node: TSNode) -> List[Instr]:
        """Translate standalone method call"""
        instrs = []
        loc = self._get_location(call_node)

        pre, method_name = self._hoist_creation_receiver(call_node, loc)
        instrs.extend(pre)
        args = self._get_method_args(call_node)
        hoisted, args_exp = self._translate_args(args, loc, via=self._get_method_name(call_node))
        lams = self._last_lambdas
        instrs.extend(hoisted)

        call_instr = Call(
            loc=loc,
            ret=None,
            func=ExpConst.string(method_name),
            args=args_exp,
            receiver_type=self._receiver_type(call_node),
            receiver_exact=self._receiver_exact(call_node),
            arg_types=[self._arg_type(a) for a in args],
            callee_class=self._callee_class(call_node),
        )
        self._set_neutral_spec(call_instr, call_node, method_name, len(args))
        instrs.append(call_instr)
        instrs.extend(self._invoke_lambdas(lams, method_name, loc))

        # Use flexible spec lookup
        spec = self._lookup_spec(method_name, call_node)
        instrs.extend(self._tag_sinks(call_node, method_name, args_exp, loc))
        if spec and spec.is_taint_sink() and self._sink_applies(spec, args):
            kind = resolve_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = args_exp[arg_idx][0]
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description,
                                            arg_index=arg_idx, receiver=self._call_receiver(method_name)))

        return instrs

    @staticmethod
    def _call_receiver(method_name: str) -> Optional[str]:
        """`builder` for `builder.parse`; None for an unqualified call."""
        return method_name.rsplit('.', 1)[0] if '.' in method_name else None

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
                plain = self._peel_cast_call(child)
                child = plain if plain is not None else self._peel_cast_chain(child)
                if child.type in ("method_invocation", "object_creation_expression"):
                    # `return f(x)`: lower the call like `tmp = f(x)` so its
                    # spec (source, sink, sanitizer) applies, then return tmp.
                    # As a bare expression the call was never analysed.
                    tmp = f"$ret{self._ident_counter}"
                    self._ident_counter += 1
                    if child.type == "method_invocation":
                        self._add_instrs(self._translate_call_assignment(tmp, child, loc))
                    else:
                        self._add_instrs(self._translate_object_creation_assignment(tmp, child, loc))
                    value_exp = ExpVar(PVar(tmp))
                else:
                    value_exp = self._translate_expression(child)
                self._add_instrs(self._handler_return_sinks(child, loc))
                break

        self._add_instr(Return(loc=loc, value=value_exp))

    _HANDLER_ANNOTATIONS = ("Mapping", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "Path",
                            "Get", "Post", "Put", "Delete", "Patch", "Head", "Options", "Trace")
    _HTML_LITERAL = re.compile(r"<\s*[A-Za-z/!]")

    def _is_web_handler(self) -> bool:
        proc = self._current_proc
        return proc is not None and (
            proc.name in self._handler_lambdas or any(
                a.name.endswith("Mapping") or a.name in self._HANDLER_ANNOTATIONS for a in proc.annotations))

    def _handler_return_sinks(self, expr: TSNode, loc: Location) -> List[Instr]:
        """Sinks that are the VALUE a web handler returns (no call to hang a spec on):
        `return "redirect:" + url;` (Spring redirect view), `return "<p>" + name + "</p>";` (the
        body is the HTML response), and a tainted view name returned from a @Controller
        (Thymeleaf / FreeMarker view-name expression injection)."""
        if not self._is_web_handler():
            return []
        out: List[Instr] = []
        literal_html = any(
            self._HTML_LITERAL.search(self._get_text(n)) for n in self._descendants(expr, stop=())
            if n.type == "string_literal")
        if expr.type == "binary_expression" and literal_html:
            out.append(TaintSink(loc=loc, exp=self._hoisted_expression(expr), kind=SinkKind.HTML_OUTPUT,
                                 description="Handler returns a string with raw HTML around user data (XSS)"))
        for n in self._descendants(expr, stop=()):
            # `ResponseEntity.ok("<p>" + x + "</p>")` / `String.format("<p>%s</p>", x)`
            if n is expr:
                continue
            if n.type == "binary_expression" and n.parent is not None and n.parent.type == "argument_list" \
                    and any(self._HTML_LITERAL.search(self._get_text(m)) for m in self._descendants(n, stop=())
                            if m.type == "string_literal"):
                out.append(TaintSink(loc=loc, exp=self._hoisted_expression(n), kind=SinkKind.HTML_OUTPUT,
                                     description="Handler responds with raw HTML around user data (XSS)"))
        # redirect views
        first = expr
        while first.type == "binary_expression" and first.child_by_field_name("left") is not None:
            first = first.child_by_field_name("left")
        if first.type == "string_literal" and self._get_text(first).strip('"').startswith("redirect:") \
                and expr.type == "binary_expression":
            out.append(TaintSink(loc=loc, exp=self._hoisted_expression(expr), kind=SinkKind.REDIRECT,
                                 description="Spring redirect view built from user data (open redirect)"))
        elif self._returns_view_name(expr):
            out.append(TaintSink(loc=loc, exp=self._hoisted_expression(expr), kind=SinkKind.TEMPLATE,
                                 description="View name built from user data (template / view-name injection)"))
        return out

    def _hoisted_expression(self, expr: TSNode) -> Exp:
        """`_translate_expression` with the calls inside lowered to temporaries first."""
        outer, self._in_call_args = self._in_call_args, True
        try:
            return self._translate_expression(expr)
        finally:
            self._in_call_args = outer

    def _returns_view_name(self, expr: TSNode) -> bool:
        """A String returned from a @Controller (not @RestController / @ResponseBody) handler is a
        view name; user data in it selects (and with Thymeleaf evaluates) the template."""
        proc = self._current_proc
        # Spring's view-resolving @Controller only (Micronaut / JAX-RS controllers return bodies)
        is_spring = any(a.name == "Controller" and (a.canonical or "").startswith("org.springframework")
                        for a in (self._current_class_annotations or ()))
        if proc is None or not is_spring or proc.ret_type_name != "String":
            return False
        if "ResponseBody" in {a.name for a in proc.annotations}:
            return False
        if expr.type == "identifier":
            return True
        if expr.type == "binary_expression":
            return any(n.type == "identifier" for n in self._descendants(expr, stop=()))
        return False

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

        # `break` has no SIL representation, so record here, the only place the
        # loop's parse tree is still available, whether any statement in the body
        # can transfer control out of the loop. The translator pairs this with the
        # loop condition to decide whether the loop can terminate at all.
        loop_head.loop_body_can_exit = body_can_exit_loop(node.child_by_field_name("body"))

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
        if value is not None and value.type == "method_invocation":
            # `for (String r : dao.findByCustomer(c))`: the iterated call is evaluated once,
            # before the loop, as a call of its own (its sinks, sources and callee apply).
            tmp = f"$iter{self._ident_counter}"
            self._ident_counter += 1
            self._add_instrs(self._translate_call_assignment(tmp, value, loc))
            iterable_exp = ExpVar(PVar(tmp))
        else:
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
        # The handler's control flow is not modelled below, so record that this
        # procedure's CFG understates how control can leave it.
        if self._current_proc:
            self._current_proc.has_exception_handler = True

        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)
        self._translate_handlers(node)

    def _translate_handlers(self, node: TSNode) -> None:
        """Lower the catch clauses of a try as branches, then the finally.

        A catch runs only when the body throws, so it is an alternative to the
        normal exit, not a continuation of it: lowering it in sequence made
        every path run every handler (and a handler that rethrows ended every
        path). Exceptions are approximated as leaving the body at its end:
        after the body, control either skips the handlers or enters one of
        them, and all of these paths join before the finally block."""
        proc = self._current_proc
        catches = [c.child_by_field_name("body") for c in node.children
                   if c.type == "catch_clause"]
        catches = [c for c in catches if c is not None]
        if proc and catches and self._current_node is not None:
            after_body = self._current_node
            join_node = proc.new_node(NodeKind.JOIN)
            proc.add_node(join_node)
            proc.connect(after_body.id, join_node.id)
            for catch_body in catches:
                handler = proc.new_node(NodeKind.NORMAL)
                proc.add_node(handler)
                proc.connect(after_body.id, handler.id)
                self._current_node = handler
                self._translate_block(catch_body)
                if self._current_node is not None:
                    proc.connect(self._current_node.id, join_node.id)
            self._current_node = join_node
        for child in node.children:
            if child.type == "finally_clause":
                for fc in child.children:
                    if fc.type == "block":
                        self._translate_block(fc)

    def _translate_try_with_resources(self, node: TSNode) -> None:
        """Translate try-with-resources ``try (var x = ...) { ... }``.

        Without this, the entire body (and its sinks) is dropped -- a major
        recall gap on JDBC code, which conventionally opens the connection as a
        resource (``try (var connection = dataSource.getConnection())``).
        """
        # The handler's control flow is not modelled below, so record that this
        # procedure's CFG understates how control can leave it.
        if self._current_proc:
            self._current_proc.has_exception_handler = True

        resources = node.child_by_field_name("resources")
        if resources is not None:
            for r in resources.children:
                if r.type == "resource":
                    self._translate_resource(r)

        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)
        self._translate_handlers(node)

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
        """Translate throw: the path leaves the method without a return value
        (the exception object is not what the method returns)."""
        self._add_instr(Return(loc=self._get_location(node), value=None))

    _SHELL_BINARIES = frozenset({"sh", "/bin/sh", "bash", "/bin/bash", "zsh", "/bin/zsh", "dash", "ksh",
                                 "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"})

    def _shell_command_array(self, node: TSNode) -> Optional[Exp]:
        """`new String[] {"/bin/sh", "-c", cmd}`: an argument vector that hands `cmd` to a shell is
        one command string (the elements joined), not separate arguments, so it carries `cmd`'s
        taint. Any other vector (`{"ping", "-c", "1", host}`) is left as it was."""
        init = node.child_by_field_name("value")
        if init is None or init.type != "array_initializer":
            return None
        items = [c for c in init.named_children if c.type not in ("line_comment", "block_comment")]
        if len(items) < 3 or items[0].type != "string_literal" or items[1].type != "string_literal":
            return None
        if self._get_text(items[0])[1:-1].lower() not in self._SHELL_BINARIES \
                or self._get_text(items[1])[1:-1].lower() not in ("-c", "/c", "-command", "/k"):
            return None
        return ExpStringConcat([self._translate_expression(i) for i in items[2:]])

    def _starts_with_test(self, node: TSNode, args: List[Exp]) -> Optional[Exp]:
        """`next.startsWith("/")` written as a method on the variable (`next.startsWith(...)`),
        the shape the translator's same-origin redirect guard reads from the condition text."""
        name, obj = node.child_by_field_name("name"), node.child_by_field_name("object")
        if (name is None or obj is None or obj.type != "identifier" or self._get_text(name) != "startsWith"
                or len(args) != 1 or not isinstance(args[0], ExpConst) or not isinstance(args[0].value, str)):
            return None
        return ExpCall(ExpFieldAccess(ExpVar(PVar(self._get_text(obj))), "startsWith"), args)

    def _url_host_access(self, node: TSNode) -> Optional[Exp]:
        """`new URL(u).getHost()` / `new URI(u).getHost()` as the field read `new URL(u).host`: the
        shape the translator's allow-list guard (`HOSTS.contains(new URL(u).getHost())`) reads."""
        name = node.child_by_field_name("name")
        obj = node.child_by_field_name("object")
        if (name is None or obj is None or self._get_text(name) != "getHost"
                or obj.type != "object_creation_expression"
                or self._get_text(obj.child_by_field_name("type")) not in ("URL", "URI", "java.net.URL", "java.net.URI")):
            return None
        if node.child_by_field_name("arguments") is not None and node.child_by_field_name("arguments").named_child_count:
            return None
        return ExpFieldAccess(self._translate_expression(obj), "host")

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
            fname = self._get_text(field) if field else ""
            if (obj is not None and obj.type == "this" and fname in self._field_types
                    and self._current_proc is not None
                    and fname not in {p.name for p, _ in self._current_proc.params}):
                # `this.username` reads the field `username` (when no parameter shadows it):
                # one name for one value, so a field an entry point taints is seen either way.
                return ExpVar(PVar(fname))
            return ExpFieldAccess(self._translate_expression(obj), fname)

        elif node.type == "array_access":
            arr = node.child_by_field_name("array")
            idx = node.child_by_field_name("index")
            return ExpIndex(self._translate_expression(arr), self._translate_expression(idx))

        elif node.type == "method_invocation":
            hoisted = self._hoist_nested_call(node)
            if hoisted is not None:
                return hoisted
            host = self._url_host_access(node)
            if host is not None:
                return host
            method_name = self._get_method_name(node)
            args = [self._translate_expression(a) for a in self._get_method_args(node)]
            starts = self._starts_with_test(node, args)
            if starts is not None:
                return starts
            return ExpCall(ExpConst.string(method_name), args)

        elif node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            type_name = self._get_text(type_node) if type_node else "Object"
            args = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ",", "line_comment", "block_comment"):
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

        elif node.type == "array_creation_expression":
            shell = self._shell_command_array(node)
            if shell is not None:
                return shell

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
                if child.type not in ("(", ")", ",", "line_comment", "block_comment"):
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
