"""
C# to Frame SIL Frontend.

This module translates C# source code to Frame SIL using tree-sitter
for parsing. It handles:
- Class and method definitions
- Properties and fields
- Method calls (with taint source/sink detection)
- Control flow (if/else, while, for, foreach, switch)
- LINQ expressions
- Attributes ([FromQuery], [HttpGet], etc.)
- Async/await patterns
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

try:
    import tree_sitter_c_sharp as tscsharp
    from tree_sitter import Language, Parser, Node as TSNode
    TREE_SITTER_CSHARP_AVAILABLE = True
except ImportError:
    TREE_SITTER_CSHARP_AVAILABLE = False
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
from frame.sil.procedure import Procedure, Node, NodeKind, ProcSpec, Program
from frame.sil.frontends._syntax import first_syntax_error_line
from frame.sil.loop_exit import body_can_exit_loop
from frame.sil.metadata import (
    Annotation, ClassInfo, ImportTable, canonical_call, parse_annotation,
)
from frame.sil.packs import finish_program
from frame.sil.specs.csharp_specs import CSHARP_SPECS
from frame.sil.specs.passthrough import load as _passthrough


class CSharpFrontend:
    """
    Translates C# source code to Frame SIL.

    Usage:
        frontend = CSharpFrontend()
        program = frontend.translate(source_code, "Example.cs")

        from frame.sil import SILTranslator
        translator = SILTranslator(program)
        checks = translator.translate_program()
    """

    packs = None   # a frame.sil.packs.PackSet; None = the built-in packs

    def __init__(self, specs: Dict[str, ProcSpec] = None):
        """
        Initialize the C# frontend.

        Args:
            specs: Library specifications (defaults to CSHARP_SPECS)
        """
        if not TREE_SITTER_CSHARP_AVAILABLE:
            raise ImportError(
                "tree-sitter-c-sharp is required. "
                "Install with: pip install tree-sitter-c-sharp"
            )

        self.parser = Parser(Language(tscsharp.language()))
        self.specs = specs or CSHARP_SPECS

        # State during translation
        self._filename = "<unknown>"
        self._source = ""
        self._current_proc: Optional[Procedure] = None
        self._current_node: Optional[Node] = None
        self._node_counter = 0
        self._ident_counter = 0
        self._current_class: Optional[str] = None
        self._current_namespace: Optional[str] = None
        self._imports = ImportTable()
        self._local_types: Dict[str, str] = {}
        self._class_fields: Dict[str, str] = {}
        self._class_fields_of: Dict[str, Dict[str, str]] = {}
        self._declared_methods: Dict[str, set] = {}
        self._class_has_bases: Dict[str, bool] = {}
        self._proc_types: Dict[int, Dict[str, str]] = {}
        self._hoisted: Dict[Tuple[int, int], str] = {}
        # variable -> XML parser configuration flags seen in the procedure being translated
        self._xml_flags: Dict[str, set] = {}
        # Member-access values whose mere reference is insecure config. Emitted
        # as a Call so the usage-based sink path fires regardless of kind.
        self._DANGEROUS_MEMBER_VALUES = {
            "HashAlgorithmName.MD5", "HashAlgorithmName.SHA1", "CipherMode.ECB",
            "TypeNameHandling.All", "TypeNameHandling.Auto", "TypeNameHandling.Objects",
            "TypeNameHandling.Arrays",
            "ContextOptions.SimpleBind",   # LDAP simple bind (CWE-522)
            "AuthType.Basic",              # LDAP basic auth in cleartext (CWE-522)
        }
        # Members whose assignment disables TLS certificate validation (CWE-295).
        self._CERT_CALLBACK_MEMBERS = {
            "ServerCertificateValidationCallback",
            "ServerCertificateCustomValidationCallback",
        }
        # Asymmetric-crypto providers whose ctor int arg is a key size (CWE-326).
        self._WEAK_KEYSIZE_TYPES = {
            "RSACryptoServiceProvider", "DSACryptoServiceProvider",
            "RSACng", "DSACng",
        }
        # Property assignments that flow the RHS into a sink (obj.Prop = value).
        self._ASSIGNMENT_SINK_PROPS = {
            "CommandText": "sql",
            "Sql": "sql",              # EF MigrationStatement.Sql = "..."+input
            "InnerHtml": "html", "InnerHTML": "html",
        }

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """Translate C# source code to SIL Program."""
        self._filename = filename
        self._source = source_code
        self._source_bytes = source_code.encode("utf-8")
        self._node_counter = 0
        self._ident_counter = 0

        tree = self.parser.parse(self._source_bytes)
        program = Program(library_specs=self.specs.copy(), language="csharp")
        program.source_files.append(filename)
        program.syntax_error_line = first_syntax_error_line(tree.root_node)

        self._imports, self._local_types = self._collect_declarations(tree.root_node)
        program.imports = self._imports.as_dict()
        self._proc_types = {}
        self._hoisted = {}

        self._translate_compilation_unit(tree.root_node, program)
        self._record_method_group_registrations(tree.root_node, program)
        self._annotate_calls(program)
        program.import_wildcards = list(self._imports.wildcards)
        finish_program(program, self.packs, source_code)
        return program

    # -- canonical ids and declaration facts ---------------------------------

    def _collect_declarations(self, root: TSNode):
        """(using table, {declared type -> namespace-qualified name})."""
        table = ImportTable()
        types: Dict[str, str] = {}

        def walk(node: TSNode, namespace: str) -> None:
            for child in node.children:
                if child.type == "using_directive":
                    names = [c for c in child.named_children
                             if c.type in ("identifier", "qualified_name")]
                    is_static = any(c.type == "static" or self._get_text(c) == "static" for c in child.children)
                    if is_static:
                        continue
                    if any(c.type == "=" for c in child.children) and len(names) >= 2:
                        table.bind(self._get_text(names[0]), self._get_text(names[-1]))
                    elif names:
                        table.wildcards.append(self._get_text(names[-1]))
                elif child.type in ("namespace_declaration", "file_scoped_namespace_declaration"):
                    nm = child.child_by_field_name("name")
                    ns = self._get_text(nm) if nm is not None else ""
                    inner = f"{namespace}.{ns}" if namespace and ns else (ns or namespace)
                    body = child.child_by_field_name("body")
                    walk(body if body is not None else child, inner)
                elif child.type in ("class_declaration", "struct_declaration", "interface_declaration",
                                    "enum_declaration", "record_declaration"):
                    nm = child.child_by_field_name("name")
                    if nm is not None:
                        simple = self._get_text(nm)
                        types.setdefault(simple, f"{namespace}.{simple}" if namespace else simple)
                    body = child.child_by_field_name("body")
                    if body is not None:
                        walk(body, namespace)
                elif child.type == "declaration_list":
                    walk(child, namespace)

        walk(root, "")
        return table.finish(), types

    def _declared_types(self, node: TSNode) -> Dict[str, str]:
        """Variable / parameter / field name -> declared type in the subtree; a name
        declared with two different types is dropped."""
        found: Dict[str, str] = {}
        conflicts: set = set()

        def type_text(t: Optional[TSNode]) -> str:
            text = self._get_text(t).split("<")[0].rstrip("?").strip() if t is not None else ""
            head, dot, rest = text.partition(".")
            alias = self._imports.names.get(head) if dot else None
            return f"{alias}.{rest}" if alias else text     # `using Repo = App.Data;` ... `Repo.UserRepository`

        def add(name: str, typ: str) -> None:
            if not name or not typ:
                return
            if name in found and found[name] != typ:
                conflicts.add(name)
            found[name] = typ

        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "parameter":
                nm = n.child_by_field_name("name")
                add(self._get_text(nm) if nm is not None else "", type_text(n.child_by_field_name("type")))
            elif n.type == "variable_declaration":
                tnode = n.child_by_field_name("type") or (n.named_children[0] if n.named_children else None)
                typ = type_text(tnode)
                for d in n.named_children:
                    if d.type != "variable_declarator":
                        continue
                    nm = d.child_by_field_name("name") or next(
                        (c for c in d.children if c.type == "identifier"), None)
                    t = typ
                    if typ == "var":
                        creation = next((c for c in self._descendants_of(d)
                                         if c.type == "object_creation_expression"), None)
                        t = type_text(creation.child_by_field_name("type")) if creation is not None else ""
                    add(self._get_text(nm) if nm is not None else "", t)
            stack.extend(n.children)
        for c in conflicts:
            found.pop(c, None)
        return found

    @staticmethod
    def _descendants_of(node: TSNode):
        stack = list(node.children)
        while stack:
            n = stack.pop()
            yield n
            stack.extend(n.children)

    def _annotate_calls(self, program: Program) -> None:
        """Fill `Call.canonical` from the receiver's declared type (C# calls carry no
        receiver type of their own; nothing else reads what is computed here)."""
        for proc in program.procedures.values():
            types = {**self._class_fields_of.get(proc.class_name or "", {}),
                     **self._proc_types.get(id(proc), {})}
            proc.var_types = {k: v for k, v in types.items() if v and v != "var"}
            own_class = (proc.class_name or "").rsplit(".", 1)[-1]
            own_methods = {p.name.rsplit(".", 1)[-1] for p in program.procedures.values()
                           if p.class_name == proc.class_name} | self._declared_methods.get(proc.class_name, set())
            for node in proc.nodes.values():
                for instr in node.instrs:
                    if not isinstance(instr, Call) or instr.canonical is not None:
                        continue
                    func = str(getattr(instr.func, "value", instr.func))
                    head, dot, rest = func.partition(".")
                    receiver = None
                    if not dot:
                        if func in own_methods:
                            receiver = own_class or None
                        elif func[:1].isupper() and canonical_call(
                                "csharp", f"{func}.<init>", self._imports, receiver_type=func,
                                local_types=self._local_types):
                            instr.canonical = canonical_call(
                                "csharp", f"new {func}", self._imports, local_types=self._local_types)
                            continue
                        elif func.isidentifier() and own_class and self._class_has_bases.get(proc.class_name):
                            instr.callee_class = own_class        # `Helper(x)`: may be inherited
                            continue
                    elif "." not in rest:
                        receiver = types.get(head) or (head if head[:1].isupper() else None)
                    elif head in ("System", "Microsoft"):
                        receiver = func.rsplit(".", 1)[0]
                    if receiver is None:
                        continue
                    method = func.rsplit(".", 1)[-1]
                    instr.callee_class = receiver
                    instr.canonical = canonical_call(
                        "csharp", f"{receiver}.{method}", self._imports,
                        receiver_type=receiver, local_types=self._local_types)

    def _translate_compilation_unit(self, root: TSNode, program: Program) -> None:
        """Translate C# compilation unit"""
        top_level = [c for c in root.children if c.type == "global_statement"]
        if top_level:
            self._translate_top_level(top_level, program)
        for child in root.children:
            if child.type == "namespace_declaration":
                self._translate_namespace(child, program)
            elif child.type == "class_declaration":
                self._translate_class(child, program)
            elif child.type == "interface_declaration":
                pass  # Skip interfaces
            elif child.type in ("struct_declaration", "record_declaration"):
                self._translate_class(child, program)  # Treat struct / record like class
            elif child.type == "file_scoped_namespace_declaration":
                self._translate_file_scoped_namespace(child, program)

    def _translate_namespace(self, node: TSNode, program: Program) -> None:
        """Translate namespace declaration"""
        name_node = node.child_by_field_name("name")
        ns_name = self._get_text(name_node) if name_node else ""

        old_ns = self._current_namespace
        self._current_namespace = ns_name

        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type in ("class_declaration", "struct_declaration", "record_declaration"):
                    self._translate_class(child, program)
                elif child.type == "namespace_declaration":
                    self._translate_namespace(child, program)

        self._current_namespace = old_ns

    def _translate_file_scoped_namespace(self, node: TSNode, program: Program) -> None:
        """Translate file-scoped namespace (C# 10+)"""
        name_node = node.child_by_field_name("name")
        self._current_namespace = self._get_text(name_node) if name_node else ""

        for child in node.children:
            if child.type in ("class_declaration", "struct_declaration", "record_declaration"):
                self._translate_class(child, program)

    def _translate_class(self, node: TSNode, program: Program) -> None:
        """Translate class definition"""
        name_node = node.child_by_field_name("name")
        class_name = self._get_text(name_node) if name_node else "UnknownClass"

        # Full class name with namespace
        full_class_name = class_name
        if self._current_namespace:
            full_class_name = f"{self._current_namespace}.{class_name}"

        old_class = self._current_class
        self._current_class = full_class_name
        self._record_class_info(node, program, class_name, full_class_name)

        body = node.child_by_field_name("body")
        if body:
            fields = {}
            for member in body.children:
                if member.type == "field_declaration":
                    fields.update(self._declared_types(member))
            self._class_fields_of[full_class_name] = fields
            program.declared_fields[full_class_name] = set(fields)
            self._declared_methods[full_class_name] = {
                self._get_text(c.child_by_field_name("name")) for c in body.children
                if c.type == "method_declaration" and c.child_by_field_name("name") is not None}
            self._class_has_bases[full_class_name] = any(c.type == "base_list" for c in node.children)
            for child in body.children:
                if child.type == "method_declaration":
                    if child.child_by_field_name("body") is None:
                        # `abstract` / `extern` / interface member: no body, so no procedure. An empty
                        # one is what a call would resolve to, hiding the override that implements it.
                        continue
                    proc = self._translate_method(child)
                    if proc:
                        proc.class_name = full_class_name
                        proc.name = f"{full_class_name}.{proc.name}"
                        program.add_procedure(proc)
                        self._translate_lambdas(child, proc, program)
                elif child.type in ("class_declaration", "struct_declaration", "record_declaration"):
                    # a nested type: its members belong to Outer.Inner
                    saved_ns = self._current_namespace
                    self._current_namespace = full_class_name
                    self._translate_class(child, program)
                    self._current_namespace = saved_ns
                    self._current_class = full_class_name
                elif child.type == "constructor_declaration":
                    proc = self._translate_constructor(child)
                    if proc:
                        proc.class_name = full_class_name
                        proc.name = f"{full_class_name}..ctor"
                        program.add_procedure(proc)
                        self._translate_lambdas(child, proc, program)
                elif child.type == "property_declaration":
                    # Properties can have getters/setters
                    procs = self._translate_property(child)
                    for proc in procs:
                        if proc:
                            proc.class_name = full_class_name
                            program.add_procedure(proc)
            self._translate_literal_fields(body, full_class_name, program)

        self._current_class = old_class

    def _record_class_info(self, node: TSNode, program: Program, name: str, full_name: str) -> None:
        bases: List[str] = []
        for c in node.children:
            if c.type == "base_list":
                bases = [self._get_text(b).split("<")[0] for b in c.named_children
                         if b.type in ("identifier", "qualified_name", "generic_name")]
        attrs = [self._get_text(a) for lst in node.children if lst.type == "attribute_list"
                 for a in lst.children if a.type == "attribute"]
        kind = {"struct_declaration": "struct", "interface_declaration": "interface",
                "enum_declaration": "enum"}.get(node.type, "class")
        members = node.child_by_field_name("body")
        fields, field_annotations, settable = self._members(members)
        program.class_info[name] = ClassInfo(
            name=name, kind=kind, bases=bases, fields=fields, field_annotations=field_annotations,
            settable_fields=settable,
            canonical_bases=[self._imports.resolve(b) or self._local_types.get(b) or b for b in bases],
            annotations=[parse_annotation(a, self._imports) for a in attrs],
            package=self._current_namespace or None)

    def _members(self, body: Optional[TSNode]
                 ) -> Tuple[List[str], Dict[str, List[Annotation]], List[str]]:
        """`ClassInfo.fields`, `field_annotations` and `settable_fields` for C#: every instance field
        and property, the attributes each carries, and the public ones code outside the class can
        assign (not `readonly`, a property with a `set`/`init` accessor). Which of them a framework
        fills from the request is the packs' business (`fields = "annotated"` / `"settable"`)."""
        names: List[str] = []
        annotations: Dict[str, List[Annotation]] = {}
        settable: List[str] = []
        if body is None:
            return names, annotations, settable
        for member in body.children:
            if member.type not in ("property_declaration", "field_declaration"):
                continue
            mods = {self._get_text(c) for c in member.children if c.type == "modifier"}
            if "static" in mods or "const" in mods:
                continue
            can_set = "public" in mods and "readonly" not in mods
            if member.type == "property_declaration":
                acc = next((c for c in member.children if c.type == "accessor_list"), None)
                text = self._get_text(acc) if acc is not None else ""
                can_set = can_set and bool(re.search(r"\b(set|init)\b", text))
                nm = member.child_by_field_name("name")
                declared = [self._get_text(nm)] if nm is not None else []
            else:
                declared = []
                for d in self._descendants_of(member):
                    if d.type == "variable_declarator":
                        nm = d.child_by_field_name("name") or next(
                            (c for c in d.children if c.type == "identifier"), None)
                        if nm is not None:
                            declared.append(self._get_text(nm))
            attrs = [parse_annotation(a, self._imports) for a in self._get_attributes(member)]
            for n in declared:
                names.append(n)
                if attrs:
                    annotations[n] = attrs
                if can_set:
                    settable.append(n)
        return names, annotations, settable

    _STRING_LITERAL_TYPES = frozenset({
        "string_literal", "verbatim_string_literal", "raw_string_literal"})

    def _literal_of(self, node: TSNode) -> Optional[TSNode]:
        """The string-literal initializer under a declarator/property, if any
        (directly, or wrapped in an ``equals_value_clause`` by older grammars)."""
        for c in node.children:
            if c.type in self._STRING_LITERAL_TYPES:
                return c
            if c.type == "equals_value_clause":
                for cc in c.children:
                    if cc.type in self._STRING_LITERAL_TYPES:
                        return cc
        return None

    def _translate_literal_fields(self, body: TSNode, class_name: str,
                                  program: Program) -> None:
        """Lower string-literal field and property initializers (``string
        password = "..."``) so hardcoded credentials declared outside a method
        body reach the literal scanner. Adds no sources or sinks."""
        assigns = []

        def add(name_node, lit):
            if name_node is not None and lit is not None:
                assigns.append(Assign(loc=self._get_location(name_node),
                                      id=PVar(self._get_text(name_node)),
                                      exp=self._translate_expression(lit)))

        for member in body.children:
            if member.type == "field_declaration":
                for vd in member.children:
                    if vd.type != "variable_declaration":
                        continue
                    for decl in vd.children:
                        if decl.type == "variable_declarator":
                            name = decl.child_by_field_name("name") or next(
                                (c for c in decl.children if c.type == "identifier"), None)
                            add(name, self._literal_of(decl))
            elif member.type == "property_declaration":
                name = member.child_by_field_name("name")
                add(name, self._literal_of(member))
        proc = literal_init_procedure(f"{class_name}..cctor",
                                      self._get_location(body), assigns)
        if proc is not None:
            program.add_procedure(proc)

    def _translate_method(self, node: TSNode) -> Optional[Procedure]:
        """Translate method definition"""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None

        method_name = self._get_text(name_node)
        params = self._translate_parameters(node)

        # Get attributes
        attributes = self._get_attributes(node)

        proc = Procedure(
            name=method_name,
            params=params,
            ret_type=Typ.unknown_type(),
            loc=self._get_location(node),
            is_method=True,
        )
        proc.has_varargs = self._has_params_array(node)
        proc.annotations = [parse_annotation(a, self._imports) for a in attributes]
        # `static string Run(this string arg)`: an extension method, called as `arg.Run()`.
        first = next((c for c in (node.child_by_field_name("parameters") or node).children
                      if c.type == "parameter"), None)
        proc.is_extension = first is not None and any(
            c.type == "modifier" and self._get_text(c) == "this" for c in first.children)
        self._proc_types[id(proc)] = self._declared_types(node)
        self._xml_flags = self._collect_xml_flags(node)
        pl = node.child_by_field_name("parameters")
        for prm in (pl.children if pl is not None else ()):
            if prm.type == "parameter":
                pn = prm.child_by_field_name("name")
                attrs = self._get_attributes(prm)
                if pn is not None and attrs:
                    proc.param_annotations[self._get_text(pn)] = [
                        parse_annotation(a, self._imports) for a in attrs]
                tn = prm.child_by_field_name("type")
                if pn is not None and tn is not None:
                    proc.param_types[self._get_text(pn)] = self._get_text(tn).split("<")[0].rstrip("?").strip()

        # Modifiers as written (packs match on them: a public method of a controller is an action)
        proc.modifiers = [self._get_text(c) for c in node.children if c.type == "modifier"]
        proc.is_static = "static" in proc.modifiers

        self._current_proc = proc
        self._node_counter = 0

        # Create entry node
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry

        # Mark Main method args as taint source (command line arguments)
        if method_name == "Main":
            for param, _ in params:
                if param.name == "args":
                    self._add_instr(TaintSource(
                        loc=self._get_location(node),
                        var=param,
                        kind=TaintKind.USER_INPUT,
                        description="Command line argument"
                    ))

        # Translate body
        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)

        # Handle expression body (=>)
        expr_body = None
        for child in node.children:
            if child.type == "arrow_expression_clause":
                expr_body = child
                break

        if expr_body:
            self._translate_arrow_expression(expr_body)

        # Create exit node
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id

        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)

        self._current_proc = None
        return proc

    # -- lambdas and top-level statements --------------------------------------
    #
    # A lambda passed to a call (`app.MapGet("/x", (string q) => ...)`,
    # `Task.Run(() => { ... })`) is the handler in minimal APIs, so it becomes a
    # procedure of its own: its parameters are real parameters (typed, attributed)
    # and `registered_via` names the call it was passed to. The enclosing
    # procedure still sees the lambda's body expression inline, as before.

    _LAMBDA_TYPES = ("lambda_expression", "anonymous_method_expression")

    def _lambda_args(self, root: TSNode):
        """Outermost lambdas in `root` that are arguments of an invocation, with the call."""
        out = []
        stack = list(root.children)
        while stack:
            n = stack.pop()
            if n.type in self._LAMBDA_TYPES:
                arg = n.parent
                call = arg.parent.parent if (arg is not None and arg.type == "argument"
                                             and arg.parent is not None and arg.parent.parent is not None) else None
                if call is not None and call.type == "invocation_expression":
                    out.append((n, call))
                    continue            # nested lambdas are found when this one is translated
            stack.extend(n.children)
        out.sort(key=lambda t: t[0].start_byte)
        return out

    def _record_method_group_registrations(self, root: TSNode, program: Program) -> None:
        """`app.MapGet("/x", Handlers.Get)`: a method passed by name is registered with that call
        (like a lambda passed to it). Only an unambiguous name in this file is followed."""
        for n in self._descendants_of(root):
            if n.type != "invocation_expression":
                continue
            args = n.child_by_field_name("arguments")
            if args is None:
                continue
            callee = None
            for a in args.children:
                inner = a.children[0] if a.type == "argument" and a.children else a
                if inner.type not in ("identifier", "member_access_expression"):
                    continue
                text = self._get_text(inner)
                hits = [p for p in program.procedures.values()
                        if p.name == text or p.name.endswith("." + text)]
                if len(hits) != 1:
                    continue
                callee = callee or self._get_method_name(n)
                if callee and callee not in hits[0].registered_via:
                    hits[0].registered_via.append(callee)

    def _translate_lambdas(self, owner_node: TSNode, owner: Procedure, program: Program) -> None:
        owner_types = self._proc_types.get(id(owner), {})
        for lam, call in self._lambda_args(owner_node):
            proc = self._translate_lambda(lam, call, owner.name, owner.class_name, owner_types, program)
            if proc is not None:
                # the enclosing variables the lambda reads: attacker data they hold reaches its body
                proc.parent = owner.name
                body = lam.child_by_field_name("body") or lam
                enclosing = (set(owner_types) | {p.name for p, _ in owner.params}) - {p.name for p, _ in proc.params}
                used = {self._get_text(n) for n in self._descendants_of(body) if n.type == "identifier"}
                proc.captures = sorted(enclosing & used)
                self._translate_lambdas(lam, proc, program)

    def _translate_lambda(self, lam: TSNode, call: TSNode, owner_name: str, class_name: Optional[str],
                          outer_types: Dict[str, str], program: Program) -> Optional[Procedure]:
        params: List[Tuple[PVar, Typ]] = []
        ptypes: Dict[str, str] = {}
        pann: Dict[str, list] = {}
        plist = lam.child_by_field_name("parameters")
        if plist is None:
            plist = next((c for c in lam.children if c.type in ("implicit_parameter", "parameter_list")), None)
        if plist is not None and plist.type in ("implicit_parameter", "identifier"):
            params.append((PVar(self._get_text(plist)), Typ.unknown_type()))
        elif plist is not None:
            for prm in plist.children:
                if prm.type == "implicit_parameter":
                    params.append((PVar(self._get_text(prm)), Typ.unknown_type()))
                elif prm.type == "parameter":
                    nm = prm.child_by_field_name("name")
                    if nm is None:
                        continue
                    pname = self._get_text(nm)
                    params.append((PVar(pname), Typ.unknown_type()))
                    attrs = self._get_attributes(prm)
                    if attrs:
                        pann[pname] = [parse_annotation(a, self._imports) for a in attrs]
                    tn = prm.child_by_field_name("type")
                    if tn is not None:
                        ptypes[pname] = self._get_text(tn).split("<")[0].rstrip("?").strip()
        base = f"{owner_name}.lambda_L{lam.start_point[0] + 1}"
        name = base
        if program.has_procedure(name):
            name = f"{base}C{lam.start_point[1] + 1}"
        proc = Procedure(name=name, params=params, ret_type=Typ.unknown_type(),
                         loc=self._get_location(lam), is_method=True)
        proc.class_name = class_name
        proc.param_annotations = pann
        proc.param_types = ptypes
        proc.annotations = [parse_annotation(a, self._imports) for a in self._get_attributes(lam)]
        callee = self._get_method_name(call)
        proc.registered_via = [callee] if callee else []
        proc.has_varargs = False
        types = {**outer_types, **self._declared_types(lam)}
        self._proc_types[id(proc)] = types
        saved_xml = self._xml_flags
        self._xml_flags = self._collect_xml_flags(lam)

        saved = (self._current_proc, self._current_node, self._node_counter)
        self._current_proc = proc
        self._node_counter = 0
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry
        body = lam.child_by_field_name("body")
        if body is None:
            body = next((c for c in lam.children if c.type == "block"), None)
        if body is not None and body.type == "block":
            self._translate_block(body)
        elif body is not None:
            self._translate_lambda_expression_body(body)
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)
        self._current_proc, self._current_node, self._node_counter = saved
        self._xml_flags = saved_xml
        program.add_procedure(proc)
        return proc

    def _translate_lambda_expression_body(self, body: TSNode) -> None:
        """`x => Results.Redirect(x)`: the call is a statement-level call and the returned value."""
        loc = self._get_location(body)
        inner = body
        if inner.type == "await_expression":
            inner = next((c for c in inner.children if c.type not in ("await",)), inner)
        if inner.type == "invocation_expression":
            self._add_instrs(self._translate_invocation(inner))
        elif inner.type == "object_creation_expression":
            self._add_instrs(self._translate_object_creation(inner, None, loc))
        elif inner.type == "assignment_expression":
            self._translate_assignment(inner)
        self._add_instr(Return(loc=loc, value=self._translate_expression(body)))

    def _translate_top_level(self, statements: List[TSNode], program: Program) -> None:
        """C# 9 top-level statements (`Program.cs` of a minimal API) form one procedure."""
        proc = Procedure(name="TopLevelStatements", params=[], ret_type=Typ.unknown_type(),
                         loc=self._get_location(statements[0]), is_method=False)
        self._current_proc = proc
        self._node_counter = 0
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry
        types: Dict[str, str] = {}
        self._xml_flags = {}
        for gs in statements:
            types.update(self._declared_types(gs))
            for k, v in self._collect_xml_flags(gs).items():
                self._xml_flags.setdefault(k, set()).update(v)
        self._proc_types[id(proc)] = types
        for gs in statements:
            for child in gs.children:
                self._translate_statement(child)
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)
        self._current_proc = None
        program.add_procedure(proc)
        for gs in statements:
            self._translate_lambdas(gs, proc, program)

    def _has_params_array(self, node: TSNode) -> bool:
        """Does the last parameter carry the `params` modifier (varargs)?"""
        params = node.child_by_field_name("parameters")
        # The grammar does not always wrap a `params` parameter in a
        # `parameter` node, so look at the tokens of the list itself.
        return params is not None and bool(
            re.search(r"[(,]\s*params\s", self._get_text(params)))

    def _translate_constructor(self, node: TSNode) -> Optional[Procedure]:
        """Translate constructor"""
        name_node = node.child_by_field_name("name")
        method_name = self._get_text(name_node) if name_node else ".ctor"
        params = self._translate_parameters(node)

        proc = Procedure(
            name=method_name,
            params=params,
            ret_type=Typ.unknown_type(),
            loc=self._get_location(node),
            is_method=True,
        )
        proc.has_varargs = self._has_params_array(node)

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

    def _translate_property(self, node: TSNode) -> List[Optional[Procedure]]:
        """Translate property with getter/setter"""
        procs = []
        name_node = node.child_by_field_name("name")
        prop_name = self._get_text(name_node) if name_node else "Property"

        for child in node.children:
            if child.type == "accessor_list":
                for accessor in child.children:
                    if accessor.type == "accessor_declaration":
                        accessor_type = None
                        for ac in accessor.children:
                            if ac.type in ("get", "set"):
                                accessor_type = self._get_text(ac)
                                break

                        body = accessor.child_by_field_name("body")
                        if body and accessor_type:
                            proc_name = f"{prop_name}.{accessor_type}"
                            proc = Procedure(
                                name=proc_name,
                                params=[],
                                ret_type=Typ.unknown_type(),
                                loc=self._get_location(accessor),
                                is_method=True,
                            )

                            self._current_proc = proc
                            self._node_counter = 0

                            entry = proc.new_node(NodeKind.ENTRY)
                            proc.add_node(entry)
                            proc.entry_node = entry.id
                            self._current_node = entry

                            self._translate_block(body)

                            exit_node = proc.new_node(NodeKind.EXIT)
                            proc.add_node(exit_node)
                            proc.exit_node = exit_node.id

                            if self._current_node:
                                proc.connect(self._current_node.id, exit_node.id)

                            self._current_proc = None
                            procs.append(proc)

        return procs

    def _get_attributes(self, node: TSNode) -> List[str]:
        """Get attributes from a method or parameter"""
        attributes = []
        for child in node.children:
            if child.type == "attribute_list":
                for attr in child.children:
                    if attr.type == "attribute":
                        attributes.append(self._get_text(attr))
        return attributes

    def _translate_parameters(self, node: TSNode) -> List[Tuple[PVar, Typ]]:
        """Translate method parameters"""
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "parameter":
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        param_name = self._get_text(name_node)
                        params.append((PVar(param_name), Typ.unknown_type()))
        return params

    # C# value types cannot carry an injection payload, so model-bound params of
    # these types are not treated as taint sources (only string/object/models).
    _NON_INJECTABLE_TYPES = frozenset({
        "int", "long", "short", "byte", "sbyte", "uint", "ulong", "ushort",
        "bool", "double", "float", "decimal", "char", "nint", "nuint",
        "Guid", "DateTime", "DateTimeOffset", "TimeSpan", "Int32", "Int64",
        "Boolean", "Double", "Decimal",
    })

    def _injectable_param_names(self, method_node: TSNode) -> set:
        """Names of parameters whose declared type can carry an injection
        payload (string/object/model classes), excluding C# value types."""
        result = set()
        params_node = method_node.child_by_field_name("parameters")
        if not params_node:
            return result
        for child in params_node.children:
            if child.type != "parameter":
                continue
            name_node = child.child_by_field_name("name")
            type_node = child.child_by_field_name("type")
            if not name_node:
                continue
            type_txt = self._get_text(type_node).rstrip("?").strip() if type_node else ""
            if type_txt not in self._NON_INJECTABLE_TYPES:
                result.add(self._get_text(name_node))
        return result

    def _translate_block(self, node: TSNode) -> None:
        """Translate block of statements"""
        for child in node.children:
            if child.type not in ("{", "}"):
                self._translate_statement(child)

    def _translate_arrow_expression(self, node: TSNode) -> None:
        """Translate arrow expression clause (=> expr)"""
        for child in node.children:
            if child.type not in ("=>",):
                exp = self._translate_expression(child)
                loc = self._get_location(node)
                self._add_instr(Return(loc=loc, value=exp))

    def _translate_statement(self, node: TSNode) -> None:
        """Translate a statement"""
        if node.type == "expression_statement":
            self._translate_expression_statement(node)
        elif node.type == "local_declaration_statement":
            self._translate_local_declaration(node)
        elif node.type == "return_statement":
            self._translate_return(node)
        elif node.type == "if_statement":
            self._translate_if(node)
        elif node.type == "while_statement":
            self._translate_while(node)
        elif node.type == "for_statement":
            self._translate_for(node)
        elif node.type == "foreach_statement":
            self._translate_foreach(node)
        elif node.type == "do_statement":
            self._translate_do_while(node)
        elif node.type == "switch_statement":
            self._translate_switch(node)
        elif node.type == "try_statement":
            self._translate_try(node)
        elif node.type == "throw_statement":
            self._translate_throw(node)
        elif node.type == "block":
            self._translate_block(node)
        elif node.type == "using_statement":
            self._translate_using(node)

    def _translate_expression_statement(self, node: TSNode) -> None:
        """Translate expression statement"""
        for child in node.children:
            if child.type == "invocation_expression":
                instrs = self._translate_invocation(child)
                self._add_instrs(instrs)
            elif child.type == "object_creation_expression":
                self._add_instrs(self._translate_object_creation(
                    child, None, self._get_location(child)))
            elif child.type == "assignment_expression":
                self._translate_assignment(child)
            elif child.type == "postfix_unary_expression" or child.type == "prefix_unary_expression":
                self._translate_update(child)
            elif child.type == "await_expression":
                self._translate_await(child)
            elif child.type != ";":
                # Other expression
                exp = self._translate_expression(child)

    def _translate_local_declaration(self, node: TSNode) -> None:
        """Translate local variable declaration"""
        for child in node.children:
            if child.type == "variable_declaration":
                for decl in child.children:
                    if decl.type == "variable_declarator":
                        name_node = decl.child_by_field_name("name")
                        if not name_node:
                            # Try identifier
                            for nc in decl.children:
                                if nc.type == "identifier":
                                    name_node = nc
                                    break

                        value_node = None
                        # First check for equals_value_clause (some tree-sitter versions)
                        for nc in decl.children:
                            if nc.type == "equals_value_clause":
                                for vc in nc.children:
                                    if vc.type != "=":
                                        value_node = vc
                                        break
                        # Also check for direct invocation/expression child
                        # Note: Don't match 'identifier' here as it's the variable name, not the value
                        if not value_node:
                            for nc in decl.children:
                                if nc.type in ("invocation_expression", "object_creation_expression",
                                              "await_expression", "binary_expression",
                                              "literal_expression", "string_literal", "interpolated_string_expression",
                                              "member_access_expression", "element_access_expression"):
                                    value_node = nc
                                    break
                        if not value_node:
                            # the initializer is whatever follows `=` (a cast, `c ? a : b`, `a ?? b`, `x!`, ...)
                            kids = decl.children
                            for i, nc in enumerate(kids[:-1]):
                                if nc.type == "=":
                                    value_node = kids[i + 1]
                                    break

                        if name_node:
                            var_name = self._get_text(name_node)
                            loc = self._get_location(decl)

                            if value_node:
                                if value_node.type == "invocation_expression" and self._source_in(value_node) is None:
                                    instrs = self._translate_call_assignment(var_name, value_node, loc)
                                    self._add_instrs(instrs)
                                elif value_node.type == "object_creation_expression":
                                    self._add_instrs(self._translate_object_creation(value_node, var_name, loc))
                                elif value_node.type == "await_expression":
                                    self._translate_await_assignment(var_name, value_node, loc)
                                else:
                                    exp = self._translate_expression(value_node)
                                    self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=exp))
                                    self._emit_member_source(value_node, var_name, loc)
                            else:
                                self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=ExpConst.null()))

    def _get_member_chain(self, node: TSNode) -> str:
        """Extract a dotted member chain (e.g. 'Request.QueryString') from a
        member/element access expression, identifier, or invocation receiver."""
        if node is None:
            return ""
        t = node.type
        if t == "identifier":
            return self._get_text(node)
        if t == "member_access_expression":
            expr = node.child_by_field_name("expression")
            name = node.child_by_field_name("name")
            base = self._get_member_chain(expr)
            nm = self._get_text(name) if name else ""
            return f"{base}.{nm}" if base else nm
        if t == "element_access_expression":
            return self._get_member_chain(node.child_by_field_name("expression"))
        if t == "parenthesized_expression":
            for c in node.children:
                if c.type not in ("(", ")"):
                    return self._get_member_chain(c)
        return ""

    _REQUEST_TYPES = frozenset({"HttpRequest", "HttpRequestBase", "HttpRequestMessage"})

    def _request_chain(self, chain: str) -> str:
        """`req.Query` where `req` is declared as an HttpRequest reads like `Request.Query`
        (the source specs are written against the conventional property name)."""
        head, dot, rest = chain.partition(".")
        if dot and head != "Request" and self._current_proc is not None:
            types = self._proc_types.get(id(self._current_proc), {})
            if types.get(head) in self._REQUEST_TYPES:
                return f"Request.{rest}"
        return chain

    def _source_accesses(self, node: Optional[TSNode]):
        """Property / indexer accesses a value expression is made of, looking through casts, parentheses,
        `a ?? b`, `c ? a : b`, `x + y` and pass-through methods (`.ToString()`, `.Trim()`...;
        `specs/data/passthrough.toml`)."""
        if node is None:
            return
        t = node.type
        if t in ("member_access_expression", "element_access_expression"):
            yield node
        elif t == "parenthesized_expression":
            for c in node.children:
                if c.type not in ("(", ")"):
                    yield from self._source_accesses(c)
        elif t == "cast_expression":
            yield from self._source_accesses(node.child_by_field_name("value"))
        elif t == "as_expression":
            yield from self._source_accesses(node.child_by_field_name("left"))
        elif t == "await_expression":
            for c in node.children:
                if c.type != "await":
                    yield from self._source_accesses(c)
        elif t == "conditional_expression":
            yield from self._source_accesses(node.child_by_field_name("consequence"))
            yield from self._source_accesses(node.child_by_field_name("alternative"))
        elif t == "binary_expression":
            op = node.child_by_field_name("operator")
            if op is not None and self._get_text(op) in ("+", "??"):
                yield from self._source_accesses(node.child_by_field_name("left"))
                yield from self._source_accesses(node.child_by_field_name("right"))
        elif t == "invocation_expression":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "member_access_expression":
                name = fn.child_by_field_name("name")
                if name is not None and self._get_text(name) in _passthrough().csharp_methods:
                    yield from self._source_accesses(fn.child_by_field_name("expression"))

    def _member_source_spec(self, node: TSNode) -> Optional[ProcSpec]:
        if node is None or node.type not in ("member_access_expression", "element_access_expression"):
            return None
        chain = self._get_member_chain(node)
        if not chain:
            return None
        chain = self._request_chain(chain)
        if chain == "Request" and node.type == "element_access_expression":
            chain = "Request.Item"            # classic ASP.NET: Request["id"] searches query, form, cookies
        spec = self.specs.get(chain)
        if not spec and '.' in chain:
            parts = chain.split('.')
            for i in range(1, len(parts)):
                spec = self.specs.get('.'.join(parts[i:]))
                if spec:
                    break
            if not spec:
                # a property of a source (`Request.Path.Value`, `Request.Host.Value`) reads the source
                for i in range(len(parts) - 1, 1, -1):
                    spec = self.specs.get('.'.join(parts[:i]))
                    if spec and spec.is_taint_source():
                        break
                    spec = None
        return spec if spec and spec.is_taint_source() else None

    def _source_in(self, value_node: Optional[TSNode]) -> Optional[ProcSpec]:
        for access in self._source_accesses(value_node):
            spec = self._member_source_spec(access)
            if spec is not None:
                return spec
        return None

    def _emit_member_source(self, value_node: TSNode, target: str, loc: Location) -> None:
        """Emit a TaintSource if value_node is (or is made of) a property/indexer taint source
        (e.g. Request.QueryString[...], Request.Query["a"].ToString(), User.Identity.Name).

        C# web sources are property/indexer accesses, not method calls, so the
        invocation path never tainted them -- this is the keystone fix that lets
        SQL/command/path/LDAP/etc. taint flows be detected at all.
        """
        spec = self._source_in(value_node)
        if spec is not None:
            kind = (TaintKind(spec.is_source)
                    if spec.is_source in [t.value for t in TaintKind]
                    else TaintKind.USER_INPUT)
            self._add_instr(TaintSource(loc=loc, var=PVar(target),
                                        kind=kind, description=spec.description))

    def _translate_assignment(self, node: TSNode) -> None:
        """Translate assignment expression"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        if not left or not right:
            return

        target = self._get_text(left)
        loc = self._get_location(node)

        if right.type == "invocation_expression" and self._source_in(right) is None:
            instrs = self._translate_call_assignment(target, right, loc)
            self._add_instrs(instrs)
        elif right.type == "object_creation_expression":
            self._add_instrs(self._translate_object_creation(right, target, loc))
        elif right.type == "await_expression" and self._source_in(right) is None:
            self._translate_await_assignment(target, right, loc)
        else:
            exp = self._translate_expression(right)
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=exp))
            self._emit_member_source(right, target, loc)

        # Assignment to a sink property (e.g. cmd.CommandText = "..."+input)
        # flows the right-hand value into a sink.
        prop = (left.child_by_field_name("name")
                if left.type == "member_access_expression" else None)
        # Overriding a TLS certificate-validation callback (= or += an always-true
        # delegate) is improper certificate validation regardless of the RHS.
        if prop and self._get_text(prop) in self._CERT_CALLBACK_MEMBERS:
            self._add_instr(Call(loc=loc, ret=None,
                                 func=ExpConst.string("ServerCertificateValidationCallback"),
                                 args=[]))
        if prop is not None:
            recv_node = left.child_by_field_name("expression")
            recv_chain = self._get_member_chain(recv_node)
            recv_type = self._receiver_types().get(recv_chain, recv_chain)
            self._add_instrs(self._config_flag_instrs(recv_type, self._get_text(prop), right, loc))
        sink_kind_str = self._ASSIGNMENT_SINK_PROPS.get(self._get_text(prop)) if prop else None
        if sink_kind_str is None and prop is not None:
            recv = self._get_member_chain(left.child_by_field_name("expression"))
            rtype = self._proc_types.get(id(self._current_proc), {}).get(recv, "") if self._current_proc else ""
            sink_kind_str = self._typed_prop_sink(rtype, self._get_text(prop))
        if sink_kind_str and right.type not in ("invocation_expression",
                                                "object_creation_expression"):
            self._add_instr(TaintSink(
                loc=loc, exp=self._translate_expression(right),
                kind=resolve_sink_kind(sink_kind_str),
                description=f"assignment to {self._get_text(prop)} sink", arg_index=0))

    # Properties that are a sink only on a particular declared type (`FileName` on any
    # other type is just a name): (type, property) -> sink kind.
    _TYPED_PROP_SINKS = {
        ("ProcessStartInfo", "FileName"): "command",
        ("ProcessStartInfo", "Arguments"): "command",
        ("DirectorySearcher", "Filter"): "ldap",
    }

    # -- configuration that switches a protection off -----------------------------
    #
    # `new CookieOptions { Secure = false }`, `options.Cookie.HttpOnly = false`,
    # `handler.ServerCertificateCustomValidationCallback = (...) => true`: the source says so
    # outright, so (like the other usage sinks) no taint is needed. Only the explicit off switch
    # counts; an absent option is a default, not a finding.

    def _config_flag_instrs(self, owner: str, prop: str, rhs: Optional[TSNode], loc: Location) -> List[Instr]:
        if rhs is None:
            return []
        text = self._get_text(rhs).strip()
        owner_l = owner.lower()
        kind = desc = None
        if "cookie" in owner_l:
            if prop == "HttpOnly" and (text == "false" or text.endswith("HttpOnlyPolicy.None")):
                kind, desc = "insecure_cookie_httponly", "cookie without HttpOnly"
            elif prop == "Secure" and text == "false" or (
                    prop == "SecurePolicy" and text.endswith(("CookieSecurePolicy.None", "CookieSecurePolicy.SameAsRequest"))):
                kind, desc = "insecure_cookie", "cookie without Secure"
        if kind is None and prop in ("ServerCertificateCustomValidationCallback",
                                     "ServerCertificateValidationCallback") and self._always_true_callback(rhs):
            kind, desc = "cert_validation", "TLS certificate validation disabled"
        if kind is None:
            return []
        return [TaintSink(loc=loc, exp=ExpConst.string(text), kind=resolve_sink_kind(kind),
                          description=f"{owner}.{prop} = {text}: {desc}", arg_index=0)]

    def _always_true_callback(self, node: Optional[TSNode]) -> bool:
        """`(m, c, ch, e) => true`, `delegate { return true; }`, `DangerousAcceptAnyServerCertificateValidator`."""
        if node is None:
            return False
        if node.type == "member_access_expression":
            return self._get_text(node).endswith("DangerousAcceptAnyServerCertificateValidator")
        if node.type in self._LAMBDA_TYPES:
            body = node.child_by_field_name("body") or next((c for c in node.children if c.type == "block"), None)
            if body is None:
                return False
            if body.type in ("true_literal", "boolean_literal") and self._get_text(body) == "true":
                return True
            return bool(re.fullmatch(r"\{\s*return\s+true\s*;\s*\}", self._get_text(body).strip()))
        return False

    def _is_html_content_result(self, type_name: str, init: TSNode, lhs: Optional[TSNode]) -> bool:
        """`new ContentResult { Content = x, ContentType = "text/html" }`: the content is markup
        only when the initializer says so (the default content type is text/plain)."""
        if type_name.split(".")[-1] != "ContentResult" or lhs is None or self._get_text(lhs) != "Content":
            return False
        for c in init.children:
            if c.type == "assignment_expression":
                left, right = c.child_by_field_name("left"), c.child_by_field_name("right")
                if left is not None and right is not None and self._get_text(left) == "ContentType":
                    return "html" in self._get_text(right).lower()
        return False

    def _typed_prop_sink(self, type_name: str, prop: str) -> Optional[str]:
        return self._TYPED_PROP_SINKS.get((type_name.split(".")[-1], prop))

    # -- XML parser hardening ----------------------------------------------------
    #
    # `new XmlDocument()` / `new XmlTextReader(x)` are XXE sinks unless the parser is configured:
    # `XmlResolver = null` or `DtdProcessing = Prohibit|Ignore` makes them safe, and XmlReader.Create
    # is unsafe only with settings that parse DTDs AND resolve external resources. The flags are
    # read from the syntax tree of the procedure (assignments and object initializers).

    def _xml_member_flags(self, prop: str, rhs: Optional[TSNode]) -> set:
        text = self._get_text(rhs).strip() if rhs is not None else ""
        flags = set()
        if prop == "XmlResolver":
            flags.add("null_resolver" if text == "null" else "resolver")
        elif prop == "DtdProcessing":
            if text.endswith("Parse"):
                flags.add("parse")
            elif text.endswith(("Prohibit", "Ignore")):
                flags.add("no_dtd")
        elif prop == "ProhibitDtd":
            flags.add("no_dtd" if text == "true" else "parse")
        return flags

    def _collect_xml_flags(self, root: TSNode) -> Dict[str, set]:
        out: Dict[str, set] = {}
        for n in self._descendants_of(root):
            if n.type == "assignment_expression":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and left.type == "member_access_expression":
                    prop = left.child_by_field_name("name")
                    recv = self._get_member_chain(left.child_by_field_name("expression"))
                    if prop is not None and recv:
                        out.setdefault(recv, set()).update(self._xml_member_flags(self._get_text(prop), right))
            elif n.type == "variable_declarator":
                name = n.child_by_field_name("name") or next((c for c in n.children if c.type == "identifier"), None)
                create = next((c for c in n.children if c.type == "object_creation_expression"), None)
                if create is None:
                    eq = next((c for c in n.children if c.type == "equals_value_clause"), None)
                    create = next((c for c in (eq.children if eq is not None else ())
                                   if c.type == "object_creation_expression"), None)
                if name is not None and create is not None:
                    flags = self._initializer_xml_flags(create)
                    if flags:
                        out.setdefault(self._get_text(name), set()).update(flags)
        self._derive_reader_flags(root, out)
        return out

    def _derive_reader_flags(self, root: TSNode, flags: Dict[str, set]) -> None:
        """`var reader = XmlReader.Create(input, settings)` is as hardened as `settings`, and an
        `XmlDocument` that is only ever loaded from hardened readers (`doc.Load(reader)`) is too: the
        reader, not the document, decides what the parse resolves."""
        def hard(var: str) -> bool:
            f = flags.get(var, set())
            return "null_resolver" in f or "no_dtd" in f

        loads: Dict[str, List[bool]] = {}
        nodes = list(self._descendants_of(root))
        for n in nodes:
            if n.type == "variable_declarator":
                name = n.child_by_field_name("name") or next((c for c in n.children if c.type == "identifier"), None)
                call = next((c for c in self._descendants_of(n) if c.type == "invocation_expression"), None)
                if name is None or call is None:
                    continue
                fn = self._get_method_name(call)
                args = self._get_method_args(call)
                if fn.endswith("XmlReader.Create") and len(args) >= 2 and hard(self._get_text(args[1])):
                    flags.setdefault(self._get_text(name), set()).add("no_dtd")
        for n in nodes:
            if n.type == "invocation_expression":
                recv, _, method = self._get_method_name(n).rpartition(".")
                args = self._get_method_args(n)
                if recv and method in ("Load", "LoadXml"):
                    loads.setdefault(recv, []).append(method == "Load" and len(args) == 1
                                                      and hard(self._get_text(args[0])))
        for recv, results in loads.items():
            if results and all(results):
                flags.setdefault(recv, set()).add("no_dtd")

    def _initializer_xml_flags(self, create: TSNode) -> set:
        flags: set = set()
        init = create.child_by_field_name("initializer")
        for child in (init.children if init is not None else ()):
            if child.type == "assignment_expression":
                left, right = child.child_by_field_name("left"), child.child_by_field_name("right")
                if left is not None:
                    flags |= self._xml_member_flags(self._get_text(left), right)
        return flags

    def _xml_parser_hardened(self, var: Optional[str]) -> bool:
        flags = self._xml_flags.get(var or "", set())
        return "null_resolver" in flags or "no_dtd" in flags

    def _xml_settings_unsafe(self, node: Optional[TSNode]) -> bool:
        """Settings that parse DTDs and resolve external resources (a variable or an inline `new`)."""
        if node is None:
            return False
        if node.type == "object_creation_expression":
            flags = self._initializer_xml_flags(node)
        else:
            flags = self._xml_flags.get(self._get_text(node), set())
        return "parse" in flags and "resolver" in flags and "null_resolver" not in flags

    def _xml_create_instrs(self, call_node: TSNode, loc: Location) -> List[Instr]:
        """`XmlReader.Create(input, settings)` with unsafe settings parses attacker XML with DTDs."""
        name = self._get_method_name(call_node)
        if name.split(".")[-1] != "Create" or "XmlReader" not in name:
            return []
        args = self._get_method_args(call_node)
        if len(args) >= 2 and self._xml_settings_unsafe(args[1]):
            return [TaintSink(loc=loc, exp=self._translate_expression(args[0]),
                              kind=resolve_sink_kind("xxe"),
                              description="XmlReader.Create with DTD processing and an XmlResolver (XXE)",
                              arg_index=0)]
        return []

    def _hardened_xml_call(self, call_node: TSNode) -> bool:
        """`doc.Load(...)` / `doc.LoadXml(...)` on an XmlDocument whose resolver is disabled."""
        name = self._get_method_name(call_node)
        recv, _, method = name.rpartition(".")
        return (method in ("Load", "LoadXml") and bool(recv) and self._xml_parser_hardened(recv)
                and self._proc_types.get(id(self._current_proc), {}).get(recv, "") == "XmlDocument")

    def _receiver_types(self) -> Dict[str, str]:
        """Declared types of the variables visible in the procedure being translated."""
        proc = self._current_proc
        if proc is None:
            return {}
        return {**self._class_fields_of.get(self._current_class or proc.class_name or "", {}),
                **self._proc_types.get(id(proc), {})}

    def _lookup_spec(self, name: str) -> Optional[ProcSpec]:
        """The library spec of a call: the written name (`File.ReadAllText`), then the declared type of
        the receiver (`_http.GetStringAsync` with `HttpClient _http` -> `HttpClient.GetStringAsync`),
        then the bare method name (`context.Database.ExecuteSqlCommand` -> `ExecuteSqlCommand`)."""
        spec = self.specs.get(name)
        if spec or "." not in name:
            return spec
        recv, _, method = name.rpartition(".")
        rtype = self._receiver_types().get(recv)
        if rtype:
            spec = self.specs.get(f"{rtype}.{method}")
            if spec and not (spec.is_taint_source() and not spec.is_taint_sink()):
                return spec               # (typed receivers add sinks / sanitizers, never new sources)
        return self.specs.get(method)

    def _sanitizer_spec(self, name: str) -> bool:
        spec = self._lookup_spec(name)
        return bool(spec and spec.is_sanitizer and not spec.is_taint_sink())

    def _arg_initializer_instrs(self, call_node: TSNode, loc: Location) -> List[Instr]:
        """Configuration switched off in an object initializer written as an argument:
        `Cookies.Append(k, v, new CookieOptions { Secure = false })`."""
        out: List[Instr] = []
        args = call_node.child_by_field_name("arguments")
        stack = list(args.children) if args is not None else []
        while stack:
            n = stack.pop()
            if n.type in self._LAMBDA_TYPES:
                continue
            if n.type == "object_creation_expression":
                type_node = n.child_by_field_name("type")
                init = n.child_by_field_name("initializer")
                for child in (init.children if init is not None else ()):
                    if child.type == "assignment_expression" and type_node is not None:
                        lhs = child.child_by_field_name("left")
                        out.extend(self._config_flag_instrs(
                            self._get_text(type_node), self._get_text(lhs) if lhs else "",
                            child.child_by_field_name("right"), self._get_location(child)))
            stack.extend(n.children)
        return out

    def _own_method_call(self, call: TSNode) -> bool:
        """`Lookup(x)` / `this.Lookup(x)` inside a class, for a method the class declares or may
        inherit: lowered to a call of its own (not left inside an expression) so the project can
        resolve it to the declaring class's method."""
        cls = self._current_class or ""
        name = self._get_method_name(call)
        if name.startswith("this."):
            name = name[5:]
        if not name.isidentifier() or self._lookup_spec(name) is not None:
            return False
        return name in self._declared_methods.get(cls, set()) or bool(self._class_has_bases.get(cls))

    def _hoist_sanitizers(self, call_node: TSNode) -> List[Instr]:
        """A sanitizer call nested in another call's argument (`GetFullPath(Combine(d,
        GetFileName(x)))`) is lowered to a call of its own first, so the taint that comes
        out of it is the sanitized value; the outer call then reads a temporary."""
        found: List[TSNode] = []
        args = call_node.child_by_field_name("arguments")
        stack = list(args.children) if args is not None else []
        while stack:
            n = stack.pop()
            if n.type in self._LAMBDA_TYPES:
                continue
            if n.type == "invocation_expression" and (n.start_byte, n.end_byte) not in self._hoisted \
                    and (self._sanitizer_spec(self._get_method_name(n)) or self._own_method_call(n)
                         or self._created_receiver(n) is not None):
                found.append(n)
            stack.extend(n.children)
        instrs: List[Instr] = []
        for n in sorted(found, key=lambda x: x.end_byte - x.start_byte):      # innermost first
            if (n.start_byte, n.end_byte) in self._hoisted:
                continue
            tmp = f"$san{len(self._hoisted)}"
            instrs.extend(self._hoist_sanitizers(n))
            created = self._created_receiver(n)
            if created is not None:
                instrs.extend(self._translate_created_receiver_call(tmp, n, *created))
            else:
                instrs.extend(self._translate_call_assignment(tmp, n, self._get_location(n)))
            self._hoisted[(n.start_byte, n.end_byte)] = tmp
        return instrs

    def _created_receiver(self, call: TSNode) -> Optional[Tuple[TSNode, str, str]]:
        """`new Job(q).Go()` on a type no spec describes: (the creation, its type, the
        method). Library types keep their own handling (`new Regex(p).IsMatch(s)`)."""
        func = call.child_by_field_name("function")
        if func is None or func.type != "member_access_expression":
            return None
        obj, name = func.child_by_field_name("expression"), func.child_by_field_name("name")
        if obj is None or name is None or obj.type != "object_creation_expression":
            return None
        type_node = obj.child_by_field_name("type")
        type_name = self._get_text(type_node) if type_node else ""
        if not type_name or self.specs.get(type_name) is not None:
            return None
        return obj, type_name, self._get_text(name)

    def _translate_created_receiver_call(self, target: str, call: TSNode, creation: TSNode,
                                         type_name: str, method: str) -> List[Instr]:
        """`tmp = new Job(q).Go()` as `$newN = new Job(q); tmp = $newN.Go()`, so the
        project resolves both the constructor and the method."""
        loc = self._get_location(call)
        obj = f"$new{self._ident_counter}"
        self._ident_counter += 1
        instrs = self._translate_object_creation(creation, obj, loc)
        ret = self._new_ident(target)
        instrs.append(Call(loc=loc, ret=(ret, Typ.unknown_type()), func=ExpConst.string(f"{obj}.{method}"),
                           args=[(self._translate_expression(a), Typ.unknown_type())
                                 for a in self._get_method_args(call)],
                           callee_class=type_name.split("<", 1)[0]))
        instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpVar(ret)))
        return instrs

    def _translate_call_assignment(
        self,
        target: str,
        call_node: TSNode,
        loc: Location
    ) -> List[Instr]:
        """Translate: target = method(args)"""
        instrs = self._hoist_sanitizers(call_node)

        method_name = self._get_method_name(call_node)
        args = self._get_method_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        ret_id = self._new_ident(target)

        call_instr = Call(
            loc=loc,
            ret=(ret_id, Typ.unknown_type()),
            func=ExpConst.string(method_name),
            args=args_exp,
            kwarg_names=self._named_arg_names(call_node)
        )
        instrs.append(call_instr)
        instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpVar(ret_id)))

        # Check specs - try full method name first, then just the last part
        spec = self._lookup_spec(method_name)

        if spec and spec.is_taint_source():
            kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
            instrs.append(TaintSource(loc=loc, var=PVar(target), kind=kind, description=spec.description))

        if spec and spec.is_taint_sink():
            kind = resolve_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = self._translate_expression(args[arg_idx])
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description))

        instrs.extend(self._receiver_chain_instrs(call_node))
        instrs.extend(self._rsa_padding_instrs(call_node, loc))
        instrs.extend(self._xml_create_instrs(call_node, loc))
        instrs.extend(self._arg_initializer_instrs(call_node, loc))
        return instrs

    def _translate_object_creation(self, node: TSNode, target: Optional[str],
                                   loc: Location) -> List[Instr]:
        """Translate `new Type(args)` so constructor sinks fire: usage-based
        sinks (new MD5CryptoServiceProvider(), new BinaryFormatter()) via the
        emitted Call, and taint-arg sinks (new SqlCommand(q),
        new DirectorySearcher(filter)) via an explicit TaintSink."""
        instrs = []
        type_node = node.child_by_field_name("type")
        type_name = self._get_text(type_node) if type_node else "Object"
        args = self._get_method_args(node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        # Object initializer: new T { Prop = value, ... }. Translate the value
        # expressions so dangerous configuration values (e.g.
        # TypeNameHandling = TypeNameHandling.All) are seen by the member hook.
        init = node.child_by_field_name("initializer")
        if init:
            for child in init.children:
                if child.type == "assignment_expression":
                    rhs = child.child_by_field_name("right")
                    if rhs:
                        self._translate_expression(rhs)
                        lhs = child.child_by_field_name("left")
                        kind = self._typed_prop_sink(type_name, self._get_text(lhs) if lhs else "")
                        if kind is None and self._is_html_content_result(type_name, init, lhs):
                            kind = "html"
                        instrs.extend(self._config_flag_instrs(
                            type_name, self._get_text(lhs) if lhs else "", rhs, self._get_location(child)))
                        if kind:
                            instrs.append(TaintSink(
                                loc=self._get_location(child), exp=self._translate_expression(rhs),
                                kind=resolve_sink_kind(kind),
                                description=f"{type_name} initializer sets {self._get_text(lhs)}",
                                arg_index=0))

        # A parser configured not to resolve external entities is not an XXE sink.
        if type_name.split(".")[-1] in ("XmlDocument", "XmlTextReader") and (
                self._xml_parser_hardened(target)
                or {"null_resolver", "no_dtd"} & self._initializer_xml_flags(node)):
            if target is not None:
                instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpConst.null()))
            return instrs

        # Emit a Call named after the type so the translator's usage-based sink
        # path (empty sink_args) can fire on the constructor.
        instrs.append(Call(loc=loc, ret=None,
                           func=ExpConst.string(type_name), args=args_exp))
        spec = self.specs.get(type_name)
        if target is not None and spec is None:
            # A type no spec describes (the project's own `new Job(q)`): the variable is
            # bound to the constructor call, so the project can resolve the constructor
            # and follow what it stores in the new object's fields.
            ret = self._new_ident(target)
            instrs.append(Call(loc=loc, ret=(ret, Typ.unknown_type()),
                               func=ExpConst.string(f"new {type_name}"), args=args_exp))
            instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpVar(ret)))
        elif target is not None:
            instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpConst.null()))

        if spec and spec.is_taint_sink():
            kind = resolve_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    instrs.append(TaintSink(
                        loc=loc, exp=self._translate_expression(args[arg_idx]),
                        kind=kind, description=spec.description, arg_index=arg_idx))

        # Insufficient asymmetric key size: new RSACryptoServiceProvider(1024)
        # etc. with an integer-literal key size below 2048 bits (CWE-326).
        short_type = type_name.split('.')[-1]
        if short_type in self._WEAK_KEYSIZE_TYPES and args:
            ksize = self._int_literal(args[0])
            if ksize is not None and ksize < 2048:
                instrs.append(Call(loc=loc, ret=None,
                                   func=ExpConst.string("__weak_key_size__"), args=[]))
        return instrs

    def _rsa_padding_instrs(self, call_node: TSNode, loc: Location) -> List[Instr]:
        """rsa.Encrypt(data, fOAEP=false) selects PKCS#1 v1.5 padding, which is
        vulnerable to padding-oracle attacks (CWE-780)."""
        name = self._get_method_name(call_node)
        if name.split('.')[-1] != "Encrypt":
            return []
        args = self._get_method_args(call_node)
        if len(args) == 2 and self._get_text(args[1]).strip() == "false":
            return [Call(loc=loc, ret=None,
                         func=ExpConst.string("__weak_rsa_padding__"), args=[])]
        return []

    def _int_literal(self, node: TSNode):
        """Return the int value of a numeric-literal node, else None."""
        if node is not None and node.type == "integer_literal":
            try:
                return int(self._get_text(node))
            except ValueError:
                return None
        return None

    def _receiver_chain_instrs(self, call_node: TSNode) -> List[Instr]:
        """Emit sinks for nested invocations buried in a method-chain receiver --
        e.g. `ctx.Students.FromSql(q).ToList()` must still flag the FromSql sink
        even though the outer call is the benign ToList(). Emits TaintSink only
        (the outer caller already emits the Call) to avoid double-counting."""
        instrs: List[Instr] = []
        func = call_node.child_by_field_name("function")
        recv = func.child_by_field_name("expression") if (
            func and func.type == "member_access_expression") else None
        while recv is not None:
            if recv.type == "invocation_expression":
                loc = self._get_location(recv)
                name = self._get_method_name(recv)
                # The inner call also gets a Call of its own, so framework packs see it
                # (`conn.Query<T>(sql).ToList()`); it defines nothing.
                instrs.append(Call(loc=loc, ret=None, func=ExpConst.string(name),
                                   args=[(self._translate_expression(a), Typ.unknown_type())
                                         for a in self._get_method_args(recv)],
                                   kwarg_names=self._named_arg_names(recv)))
                spec = self._lookup_spec(name)
                if spec and spec.is_taint_sink():
                    kind = resolve_sink_kind(spec.is_sink)
                    rargs = self._get_method_args(recv)
                    for arg_idx in spec.sink_args:
                        if arg_idx < len(rargs):
                            instrs.append(TaintSink(
                                loc=loc, exp=self._translate_expression(rargs[arg_idx]),
                                kind=kind, description=spec.description, arg_index=arg_idx))
                f = recv.child_by_field_name("function")
                recv = f.child_by_field_name("expression") if (
                    f and f.type == "member_access_expression") else None
            elif recv.type == "member_access_expression":
                recv = recv.child_by_field_name("expression")
            elif recv.type == "object_creation_expression":
                # `new Regex(pattern).IsMatch(s)`: the creation is a call (and a sink) of its own
                instrs.extend(self._translate_object_creation(recv, None, self._get_location(recv)))
                break
            else:
                break
        return instrs

    def _translate_invocation(self, call_node: TSNode) -> List[Instr]:
        """Translate standalone method invocation"""
        instrs = self._hoist_sanitizers(call_node)
        loc = self._get_location(call_node)
        if self._hardened_xml_call(call_node):
            return instrs

        method_name = self._get_method_name(call_node)
        args = self._get_method_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        call_instr = Call(
            loc=loc,
            ret=None,
            func=ExpConst.string(method_name),
            args=args_exp,
            kwarg_names=self._named_arg_names(call_node)
        )
        instrs.append(call_instr)

        # Check specs - try full method name first, then just the last part
        spec = self._lookup_spec(method_name)

        if spec and spec.is_taint_sink():
            kind = resolve_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = self._translate_expression(args[arg_idx])
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description, arg_index=arg_idx))

        instrs.extend(self._receiver_chain_instrs(call_node))
        instrs.extend(self._rsa_padding_instrs(call_node, loc))
        instrs.extend(self._xml_create_instrs(call_node, loc))
        instrs.extend(self._arg_initializer_instrs(call_node, loc))
        return instrs

    def _translate_await(self, node: TSNode) -> None:
        """Translate await expression (standalone)"""
        for child in node.children:
            if child.type == "invocation_expression":
                instrs = self._translate_invocation(child)
                self._add_instrs(instrs)

    def _translate_await_assignment(self, target: str, node: TSNode, loc: Location) -> None:
        """Translate await expression with assignment"""
        for child in node.children:
            if child.type == "invocation_expression":
                instrs = self._translate_call_assignment(target, child, loc)
                self._add_instrs(instrs)

    def _translate_update(self, node: TSNode) -> None:
        """Translate update expression: i++ or ++i"""
        loc = self._get_location(node)
        operand = node.child_by_field_name("operand")
        if operand and operand.type == "identifier":
            var_name = self._get_text(operand)
            text = self._get_text(node)
            if "++" in text:
                self._add_instr(Assign(
                    loc=loc,
                    id=PVar(var_name),
                    exp=ExpBinOp("+", ExpVar(PVar(var_name)), ExpConst.integer(1))
                ))
            elif "--" in text:
                self._add_instr(Assign(
                    loc=loc,
                    id=PVar(var_name),
                    exp=ExpBinOp("-", ExpVar(PVar(var_name)), ExpConst.integer(1))
                ))

    def _translate_return(self, node: TSNode) -> None:
        """Translate return statement"""
        loc = self._get_location(node)
        value_exp = None

        for child in node.children:
            if child.type not in ("return", ";"):
                # A call/constructor in the returned value must still be analyzed
                # as a sink -- e.g. `return File.ReadAllText("../" + tainted)` is
                # a path traversal, not just a returned value.
                inner = child
                if inner.type == "await_expression":        # `return await client.GetStringAsync(url);`
                    inner = next((c for c in inner.children if c.type != "await"), inner)
                if inner.type == "invocation_expression":
                    self._add_instrs(self._translate_invocation(inner))
                elif inner.type == "object_creation_expression":
                    self._add_instrs(self._translate_object_creation(inner, None, loc))
                value_exp = self._translate_expression(child)
                break

        self._add_instr(Return(loc=loc, value=value_exp))

    def _translate_if(self, node: TSNode) -> None:
        """Translate if statement"""
        loc = self._get_location(node)
        proc = self._current_proc
        if not proc:
            return

        condition = node.child_by_field_name("condition")
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

        consequence = node.child_by_field_name("consequence")
        if consequence:
            self._current_node = true_node
            self._translate_statement(consequence)
            if self._current_node:
                proc.connect(self._current_node.id, join_node.id)

        alternative = node.child_by_field_name("alternative")
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
        init = node.child_by_field_name("initializer")
        if init:
            self._translate_statement(init)

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
        incrementors = node.child_by_field_name("incrementors")
        if incrementors and self._current_node:
            for child in incrementors.children:
                if child.type not in (",",):
                    self._translate_expression_statement(child)

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node

    def _translate_foreach(self, node: TSNode) -> None:
        """Translate foreach loop"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        # Get loop variable
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        loop_var = self._get_text(left) if left else "_iter"
        iterable_exp = self._translate_expression(right) if right else ExpConst.null()

        before_node = self._current_node

        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)

        body_node = proc.new_node(NodeKind.NORMAL)
        body_node.add_instr(Assign(loc=loc, id=PVar(loop_var), exp=ExpCall(ExpConst.string("GetEnumerator.Current"), [iterable_exp])))
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

    def _translate_do_while(self, node: TSNode) -> None:
        """Translate do-while loop"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        before_node = self._current_node

        body_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(body_node)

        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)

        after_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(after_node)

        if before_node:
            proc.connect(before_node.id, body_node.id)

        body = node.child_by_field_name("body")
        if body:
            self._current_node = body_node
            self._translate_statement(body)

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        condition = node.child_by_field_name("condition")
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=True, kind=PruneKind.LOOP_ENTER))
        proc.connect(loop_head.id, body_node.id)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=False, kind=PruneKind.LOOP_EXIT))
        proc.connect(loop_head.id, after_node.id)

        self._current_node = after_node

    def _translate_switch(self, node: TSNode) -> None:
        """Translate switch statement (simplified)"""
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "switch_section":
                    for stmt in child.children:
                        if stmt.type not in ("case_switch_label", "default_switch_label", "break_statement"):
                            self._translate_statement(stmt)

    def _translate_try(self, node: TSNode) -> None:
        """Translate try/catch/finally"""
        # The handler's control flow is not modelled below, so record that this
        # procedure's CFG understates how control can leave it.
        if self._current_proc:
            self._current_proc.has_exception_handler = True

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

    def _translate_throw(self, node: TSNode) -> None:
        """Translate throw statement"""
        loc = self._get_location(node)
        for child in node.children:
            if child.type not in ("throw", ";"):
                exp = self._translate_expression(child)
                self._add_instr(Return(loc=loc, value=exp))
                break

    def _translate_using(self, node: TSNode) -> None:
        """Translate using statement"""
        # `using (var cmd = new SqlCommand(...))`: the resource is an ordinary local declaration
        # (its constructor and call sinks apply like any other)
        self._translate_local_declaration(node)

        # Translate the body
        body = node.child_by_field_name("body")
        if body:
            self._translate_statement(body)

    def _translate_expression(self, node: TSNode) -> Exp:
        """Translate expression"""
        if node is None:
            return ExpConst.null()

        if node.type == "identifier":
            return ExpVar(PVar(self._get_text(node)))

        elif node.type in ("integer_literal", "real_literal"):
            text = self._get_text(node)
            try:
                if "." in text:
                    return ExpConst.integer(int(float(text)))
                else:
                    return ExpConst.integer(int(text.rstrip("LlUuMm"), 0))
            except ValueError:
                return ExpConst.integer(0)

        elif node.type == "string_literal" or node.type == "verbatim_string_literal":
            text = self._get_text(node)
            # Remove quotes
            if text.startswith("@\""):
                text = text[2:-1]
            elif text.startswith("\""):
                text = text[1:-1]
            return ExpConst.string(text)

        elif node.type == "interpolated_string_expression":
            parts = []
            for child in node.children:
                if child.type == "interpolation":
                    for ic in child.children:
                        if ic.type not in ("{", "}"):
                            parts.append(self._translate_expression(ic))
                elif child.type == "interpolated_string_text":
                    parts.append(ExpConst.string(self._get_text(child)))
            return ExpStringConcat(parts) if parts else ExpConst.string("")

        elif node.type == "character_literal":
            text = self._get_text(node)
            return ExpConst.string(text[1:-1] if len(text) >= 2 else text)

        elif node.type == "true_literal":
            return ExpConst.boolean(True)

        elif node.type == "false_literal":
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

        elif node.type == "prefix_unary_expression":
            # the grammar names neither field: `!x` is the operator token then the operand
            op_node = node.child_by_field_name("operator") or (node.children[0] if node.children else None)
            operand = node.child_by_field_name("operand") or (node.named_children[-1] if node.named_children else None)
            op = self._get_text(op_node) if op_node else "-"
            if op == "!":
                local = self._local_url_exp(operand)
                if local is not None:             # !IsLocalUrl(x)  ==  !x.startsWith("/") || x.startsWith("//")
                    var_exp, slash, double = local
                    return ExpBinOp("||", ExpUnOp("!", slash), double)
            return ExpUnOp(op, self._translate_expression(operand))

        elif node.type == "member_access_expression":
            expr = node.child_by_field_name("expression")
            name = node.child_by_field_name("name")
            # Some member-access values are inherently insecure configuration
            # (e.g. TypeNameHandling.All, HashAlgorithmName.MD5, CipherMode.ECB).
            # Emit a Call named after the value so the usage-based sink path
            # (its spec has empty sink_args) fires on the mere reference.
            chain = self._get_member_chain(node)
            short = ".".join(chain.split(".")[-2:]) if "." in chain else chain
            if chain in self._DANGEROUS_MEMBER_VALUES or short in self._DANGEROUS_MEMBER_VALUES:
                self._add_instr(Call(loc=self._get_location(node), ret=None,
                                     func=ExpConst.string(short), args=[]))
            return ExpFieldAccess(self._translate_expression(expr), self._get_text(name) if name else "")

        elif node.type == "element_access_expression":
            expr = node.child_by_field_name("expression")
            args = node.child_by_field_name("arguments")
            idx_exp = ExpConst.integer(0)
            if args:
                for child in args.children:
                    if child.type not in ("[", "]", ","):
                        idx_exp = self._translate_expression(child)
                        break
            return ExpIndex(self._translate_expression(expr), idx_exp)

        elif node.type == "invocation_expression":
            hoisted = self._hoisted.get((node.start_byte, node.end_byte))
            if hoisted is not None:
                return ExpVar(PVar(hoisted))
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "member_access_expression":
                name = fn.child_by_field_name("name")
                recv = fn.child_by_field_name("expression")
                if (name is not None and self._get_text(name) in _passthrough().csharp_methods
                        and self._source_in(recv) is not None):
                    return self._translate_expression(recv)   # Request.Query["a"].ToString() reads like Request.Query["a"]
            local = self._local_url_exp(node)
            if local is not None:                 # IsLocalUrl(x)  ==  x.startsWith("/") && !x.startsWith("//")
                _, slash, double = local
                return ExpBinOp("&&", slash, ExpUnOp("!", double))
            method_name = self._get_method_name(node)
            if method_name.endswith(".StartsWith"):
                # the shared guard recognition (same-origin redirect targets) is written against `startsWith`
                method_name = method_name[:-len("StartsWith")] + "startsWith"
                return ExpCall(ExpVar(PVar(method_name)),
                               [self._translate_expression(a) for a in self._get_method_args(node)[:1]])
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

        elif node.type == "conditional_expression":
            cond = node.child_by_field_name("condition")
            conseq = node.child_by_field_name("consequence")
            alt = node.child_by_field_name("alternative")
            if cond is not None and conseq is not None and alt is not None:
                self._translate_expression(cond)
                # either branch can be the value: the result carries the taint of both
                return ExpBinOp("?:", self._translate_expression(conseq), self._translate_expression(alt))
            return self._translate_expression(conseq) if conseq else ExpConst.null()

        elif node.type == "cast_expression":
            value = node.child_by_field_name("value")
            return self._translate_expression(value)

        elif node.type == "this_expression":
            return ExpVar(PVar("this"))

        elif node.type == "await_expression":
            for child in node.children:
                if child.type == "invocation_expression":
                    return self._translate_expression(child)

        elif node.type == "lambda_expression":
            # Simplified lambda handling
            body = node.child_by_field_name("body")
            return self._translate_expression(body) if body else ExpConst.null()

        # Default
        text = self._get_text(node)
        if text:
            return ExpVar(PVar(text))
        return ExpConst.null()

    # =========================================================================
    # Helpers
    # =========================================================================

    def _local_url_exp(self, node: Optional[TSNode]):
        """For `Url.IsLocalUrl(x)` (or `IsLocalUrl(x)`, parenthesised or not) on a plain variable,
        the expressions `x.startsWith("/")` and `x.startsWith("//")` that say the same thing."""
        while node is not None and node.type == "parenthesized_expression":
            node = next((c for c in node.children if c.type not in ("(", ")")), None)
        if node is None or node.type != "invocation_expression":
            return None
        name = self._get_method_name(node)
        if name.split(".")[-1] != "IsLocalUrl":
            return None
        args = self._get_method_args(node)
        if len(args) != 1 or args[0].type != "identifier":
            return None
        var = self._get_text(args[0])
        start = ExpVar(PVar(f"{var}.startsWith"))
        return (ExpVar(PVar(var)),
                ExpCall(start, [ExpConst.string("/")]),
                ExpCall(start, [ExpConst.string("//")]))

    def _get_text(self, node: TSNode) -> str:
        if node is None:
            return ""
        # Slice UTF-8 bytes (tree-sitter uses byte offsets), not the source
        # string -- otherwise multi-byte characters corrupt every later token.
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

    _GENERIC_ARGS = re.compile(r"<[^<>()]*(?:<[^<>()]*>[^<>()]*)*>")

    # Response helpers whose body is HTML unless the content type says otherwise: with an explicit
    # non-HTML content-type literal the call is renamed so the XSS sink spec does not match it.
    _HTML_RESPONSE_CALLS = frozenset({"Content", "Results.Content", "TypedResults.Content"})
    _NON_HTML_RESPONSE_SUFFIX = "<non-html>"

    def _get_method_name(self, node: TSNode) -> str:
        func = node.child_by_field_name("function")
        if func:
            name = self._strip_generics(self._get_text(func))
            if name.rsplit(".", 2)[-1] == "Content" or name in self._HTML_RESPONSE_CALLS:
                args = self._get_method_args(node)
                if len(args) >= 2 and args[1].type in ("string_literal", "verbatim_string_literal") \
                        and "html" not in self._get_text(args[1]).lower():
                    return name + self._NON_HTML_RESPONSE_SUFFIX
            return name

        # Try expression field
        expr = node.child_by_field_name("expression")
        if expr:
            return self._strip_generics(self._get_text(expr))

        return ""

    def _strip_generics(self, name: str) -> str:
        """`conn.Query<Product>` names the method `conn.Query`: type arguments do not select a spec."""
        return self._GENERIC_ARGS.sub("", name) if "<" in name else name

    def _named_arg_names(self, node: TSNode) -> Optional[List[Optional[str]]]:
        """Names of C# named arguments (`f(a: x)`), parallel to `_get_method_args`;
        None when no argument is named."""
        out: List[Optional[str]] = []
        args_node = node.child_by_field_name("arguments")
        for child in (args_node.children if args_node else []):
            if child.type in ("(", ")", ",", "argument_list"):
                continue
            if child.type == "argument":
                colon = next((c for c in child.children if c.type == ":"), None)
                label = child.children[0] if colon is not None else None
                name = self._get_text(label) if label is not None else None
                for ac in child.children:
                    if ac.type not in (":", "ref", "out", "in"):
                        # the label node itself is also emitted by _get_method_args
                        out.append(None if (label is not None and ac.id == label.id) else name)
            else:
                out.append(None)
        return out if any(n is not None for n in out) else None

    def _get_method_args(self, node: TSNode) -> List[TSNode]:
        args = []
        args_node = node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type not in ("(", ")", ",", "argument_list"):
                    if child.type == "argument":
                        for ac in child.children:
                            if ac.type not in (":", "ref", "out", "in"):
                                args.append(ac)
                    else:
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
