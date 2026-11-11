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

from frame.sil.specs.dotnet_api import load as _dotnet
from frame.sil.packs import annotation_marks_entry as _glob_any, default_packs
from frame.sil.specs.parser_hardening import load as _parser_hardening
from frame.sil.specs.guards import load as _guards
from frame.sil.types import (
    Ident, PVar, Typ, TypeKind, Location,
    Exp, ExpVar, ExpConst, ExpBinOp, ExpUnOp,
    ExpFieldAccess, ExpIndex, ExpStringConcat, ExpCall, LITERAL_COLLECTION,
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
    Annotation, ClassInfo, ImportTable, _inherited_member, canonical_call, csharp_without_namespace, library_base, parse_annotation,
    qualify_type,
)
from frame.sil.packs import finish_program
from frame.sil.specs.csharp_specs import CSHARP_SPECS
from frame.sil.specs.passthrough import load as _passthrough


# a pack [[setting]]'s kind -> the sink kind its finding is reported under
_SETTING_SINK_KINDS = {"cookie_secure": "insecure_cookie", "cookie_httponly": "insecure_cookie_httponly"}


def _source_or_sink(spec: ProcSpec) -> bool:
    """A row that decides a flow (a source, a sink or a sanitizer), as opposed to a propagator."""
    return bool(spec.is_source or spec.is_sink or spec.is_sanitizer)


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
        # node types lowered as their source text (`Program.unlowered_syntax`)
        self._unlowered: Dict[str, int] = {}
        self._tables: set = set()           # this file's constant tables (`_constant_tables`)
        self._extensions: Dict[str, List[Tuple[str, int]]] = {}  # method -> (static class, arity)
        self._tuple_vars: Dict[str, Dict[str, TSNode]] = {}     # the method's tuple locals by element
        # > 0 while an expression is read without running it (a lambda's body, seen from its owner)
        self._quiet = 0
        self._return_type: Optional[str] = None     # the declared return type of the method
        # (break target, continue target) of the enclosing loops and switches, innermost last
        self._jumps: List[Tuple[Optional[Node], Optional[Node]]] = []

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """Translate C# source code to SIL Program."""
        self._filename = filename
        self._source = source_code
        self._source_bytes = source_code.encode("utf-8")
        self._node_counter = 0
        self._ident_counter = 0
        self._unlowered = {}
        self._quiet = 0

        tree = self.parser.parse(self._source_bytes)
        program = Program(library_specs=self.specs.copy(), language="csharp")
        self._program = program                 # the classes seen so far: inherited members' ids
        program.source_files.append(filename)
        program.syntax_error_line = first_syntax_error_line(tree.root_node)

        self._imports, self._local_types = self._collect_declarations(tree.root_node)
        from frame.sil.dotnet_project import usings_for
        project = usings_for(filename)                  # implicit and global usings of the .csproj
        for ns in project.wildcards:
            if ns not in self._imports.wildcards:
                self._imports.wildcards.append(ns)
        for alias, target in project.aliases.items():
            if self._imports.resolve(alias) is None:
                self._imports.bind(alias, target)
        program.imports = self._imports.as_dict()
        self._proc_types = {}
        self._hoisted = {}
        self._scopes: List[Tuple[int, int, Procedure]] = []    # (start, end, procedure): registrations' scope

        self._tables = self._constant_tables(tree.root_node)
        self._extensions = self._extension_methods(tree.root_node)
        self._translate_compilation_unit(tree.root_node, program)
        self._record_method_group_registrations(tree.root_node, program)
        self._annotate_calls(program)
        program.import_wildcards = list(self._imports.wildcards)
        program.unlowered_syntax = dict(self._unlowered)
        finish_program(program, self.packs, source_code)
        program.constant_tables = set(program.constant_tables) | self._tables
        return program

    _LITERAL_TYPES = ("string_literal", "verbatim_string_literal", "raw_string_literal", "character_literal",
                      "integer_literal", "real_literal", "boolean_literal", "null_literal")

    def _literal_collection(self, node: Optional[TSNode]) -> bool:
        """`new[] { "a", "b" }`, `{ "a" }`, `new List<string> { "a" }`, `new Dictionary<string, string>
        { ["k"] = "v" }` / `{ { "k", "v" } }`, `["a", "b"]`: a collection written out of literals (a
        constructor given arguments is not: `new List<string>(other)`)."""
        node = self._unwrap_value(node)
        if node is None:
            return False
        if node.type in self._CREATIONS:
            args = self._arguments_node(node)
            if args is not None and any(c.type == "argument" for c in args.children):
                return False
            init = self._initializer_of(node)
            return init is not None and self._literal_elements(init)
        if node.type in ("array_creation_expression", "implicit_array_creation_expression", "initializer_expression",
                         "collection_expression"):
            init = node if node.type in ("initializer_expression", "collection_expression") \
                else self._initializer_of(node)
            return init is not None and self._literal_elements(init)
        return False

    def _literal_elements(self, init: TSNode) -> bool:
        for c in init.named_children:
            if c.type == "comment" or c.type.endswith("_type") or c.type == "array_rank_specifier":
                continue
            if c.type in ("initializer_expression", "collection_expression"):
                if not self._literal_elements(c):
                    return False
            elif c.type == "assignment_expression":           # `["k"] = "v"`
                left, right = c.child_by_field_name("left"), c.child_by_field_name("right")
                keys = [self._unwrap_value(self._argument_value(a)) for a in self._descendants_of(left)
                        if a.type == "argument"] if left is not None else []
                if left is None or left.type != "element_binding_expression" or right is None or not keys \
                        or (self._unwrap_value(right) or right).type not in self._LITERAL_TYPES \
                        or not all(k is not None and k.type in self._LITERAL_TYPES for k in keys):
                    return False
            elif c.type == "expression_element":              # `[a, b]`
                if not all(x.type in self._LITERAL_TYPES for x in c.named_children if x.type != "comment"):
                    return False
            elif self._unwrap_value(c).type not in self._LITERAL_TYPES:
                return False
        return True

    def _constant_tables(self, root: TSNode) -> set:
        """C# constant tables (`Program.constant_tables`): a name declared once in the file, initialised
        with a collection of literals, and never written, rebound, passed to a call or used with a
        method other than a reading one (`read_only_collection_methods`). `TABLE[key]` is then one of
        its literals, whatever the key."""
        declared: Dict[str, int] = {}
        literal: set = set()
        spoiled: set = set()
        reading = _dotnet().read_only_collection_methods

        def root_name(n: Optional[TSNode]) -> Optional[str]:
            while n is not None:
                n = self._unwrap_value(n)
                if n is None:
                    return None
                if n.type == "identifier":
                    return self._get_text(n)
                if n.type == "member_access_expression":
                    e = n.child_by_field_name("expression")
                    if e is not None and e.type in self._THIS:
                        n = n.child_by_field_name("name")
                        continue
                    n = e
                elif n.type == "element_access_expression":
                    n = n.child_by_field_name("expression")
                else:
                    return None
            return None

        for n in [root, *self._descendants_of(root)]:
            t = n.type
            if t == "variable_declarator":
                nm = n.child_by_field_name("name") or next((c for c in n.children if c.type == "identifier"), None)
                if nm is not None:
                    name = self._get_text(nm)
                    declared[name] = declared.get(name, 0) + 1
                    if self._literal_collection(self._declarator_value(n)):
                        literal.add(name)
            elif t in ("parameter", "declaration_expression", "foreach_statement", "catch_declaration"):
                nm = n.child_by_field_name("name") or n.child_by_field_name("left")
                if nm is not None and nm.type == "identifier":
                    declared[self._get_text(nm)] = declared.get(self._get_text(nm), 0) + 2
            elif t == "assignment_expression":
                name = root_name(n.child_by_field_name("left"))
                if name:
                    spoiled.add(name)
            elif t in ("postfix_unary_expression", "prefix_unary_expression"):
                name = root_name(next((c for c in n.named_children), None))
                if name and any(c.type in ("++", "--", "&") for c in n.children):
                    spoiled.add(name)
            elif t == "argument":
                name = root_name(self._argument_value(n))
                value = self._unwrap_value(self._argument_value(n))
                if name and value is not None and value.type in ("identifier", "member_access_expression"):
                    spoiled.add(name)                      # handed to a call (which may change it)
            elif t == "invocation_expression":
                parts = self._member_parts(n.child_by_field_name("function"))
                if parts is not None:
                    name = root_name(parts[0])
                    if name and self._strip_generics(self._get_text(parts[1])) not in reading:
                        spoiled.add(name)
        return {name for name in literal if declared.get(name) == 1 and name not in spoiled}

    # -- canonical ids and declaration facts ---------------------------------

    def _collect_declarations(self, root: TSNode):
        """(using table, {declared type -> namespace-qualified name})."""
        table = ImportTable()
        types: Dict[str, str] = {}

        def walk(node: TSNode, namespace: str) -> None:
            for child in self._declarations(node):
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

        # In source order: `var cmd = conn.CreateCommand()` needs conn's type, declared above it
        # (a parameter, or a local initialised earlier).
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
                        # the type the initializer creates (never one created inside its arguments)
                        value = self._unwrap_value(self._declarator_value(d))
                        t = type_text(value.child_by_field_name("type")) \
                            if value is not None and value.type == "object_creation_expression" else ""
                        if not t:
                            t = self._call_result_type(d, found) or ""
                    add(self._get_text(nm) if nm is not None else "", t)
            stack.extend(reversed(n.children))
        for c in conflicts:
            found.pop(c, None)
        return found

    def _call_result_type(self, declarator: TSNode, known: Dict[str, str]) -> Optional[str]:
        """`var cmd = _db.CreateCommand();`: the documented return type of a call on a receiver of
        known type (value-types.toml [csharp.returns]), as a simple name."""
        call = next((c for c in declarator.named_children if c.type == "invocation_expression"), None)
        fn = call.child_by_field_name("function") if call is not None else None
        if fn is None or fn.type != "member_access_expression":
            return None
        obj, name = fn.child_by_field_name("expression"), fn.child_by_field_name("name")
        if obj is not None and obj.type == "member_access_expression" and \
                (obj.child_by_field_name("expression") or obj).type in self._THIS:
            obj = obj.child_by_field_name("name")          # `this._db.CreateCommand()`: the field _db
        if obj is None or name is None or obj.type != "identifier":
            return None
        owner = known.get(self._get_text(obj)) or self._class_fields_of.get(self._current_class or "", {}).get(self._get_text(obj))
        qualified = qualify_type("csharp", owner, self._imports, self._local_types) if owner else None
        from frame.sil.value_origins import load as _value_types
        returned = _value_types().get("csharp", ({}, {}))[0].get(f"{qualified}.{self._get_text(name)}") if qualified else None
        return returned.rsplit(".", 1)[-1] if returned else None

    @staticmethod
    def _descendants_of(node: TSNode):
        stack = list(node.children)
        while stack:
            n = stack.pop()
            yield n
            stack.extend(n.children)

    # -- syntax helpers ------------------------------------------------------------

    # `this` is a keyword token in tree-sitter-c-sharp (older grammars: `this_expression`)
    _THIS = ("this", "this_expression")
    _CREATIONS = ("object_creation_expression", "implicit_object_creation_expression")

    @staticmethod
    def _unqualified(name: str) -> str:
        """`this._db.Query` is a call on the field `_db` (`base.Redirect`: the inherited `Redirect`):
        the receiver's type is the member's, never that of a variable called `this`."""
        for prefix in ("this.", "base."):
            if name.startswith(prefix):
                return name[len(prefix):]
        return name

    @staticmethod
    def _declarator_value(decl: TSNode) -> Optional[TSNode]:
        """The initializer of a `variable_declarator`: whatever follows `=` (directly, or wrapped in
        an `equals_value_clause` by older grammars)."""
        for nc in decl.children:
            if nc.type == "equals_value_clause":
                return next((vc for vc in nc.children if vc.type != "="), None)
        kids = decl.children
        for i, nc in enumerate(kids[:-1]):
            if nc.type == "=":
                return kids[i + 1]
        return None

    def _unwrap_value(self, node: Optional[TSNode]) -> Optional[TSNode]:
        """`(x)` and `x!` are the value x."""
        while node is not None:
            if node.type == "parenthesized_expression":
                node = next((c for c in node.named_children), None)
            elif node.type == "postfix_unary_expression" and any(c.type == "!" for c in node.children):
                node = next((c for c in node.named_children), None)
            else:
                break
        return node

    @staticmethod
    def _argument_value(arg: TSNode) -> Optional[TSNode]:
        """The value an `argument` passes (`a: q` is q, `ref x` is x, `out var y` its declaration)."""
        label = arg.child_by_field_name("name")
        return next((c for c in reversed(arg.named_children)
                     if c.type != "comment" and (label is None or c.id != label.id)), None)

    @staticmethod
    def _member_parts(node: Optional[TSNode]) -> Optional[Tuple[TSNode, TSNode]]:
        """(receiver, member name) of `a.M` and of `a?.M` (the null check does not change which
        member is read), else None."""
        if node is None:
            return None
        if node.type == "member_access_expression":
            recv, name = node.child_by_field_name("expression"), node.child_by_field_name("name")
        elif node.type == "conditional_access_expression":
            recv = node.child_by_field_name("condition")
            binding = next((c for c in node.named_children if c.type == "member_binding_expression"), None)
            name = binding.child_by_field_name("name") if binding is not None else None
        else:
            return None
        return (recv, name) if recv is not None and name is not None else None

    def _callee_text(self, func: TSNode) -> str:
        """A callee as written, with `a?.M` and `a!.M` read as `a.M`: the `?` of a conditional access
        and the `!` of a null-forgiving operator are dropped (from the syntax tree, not by matching
        text); neither changes which method is called."""
        raw = self._source_bytes[func.start_byte:func.end_byte]
        if b"?" not in raw and b"!" not in raw:
            return raw.decode("utf-8", errors="replace")
        cuts = sorted(c.start_byte - func.start_byte for n in [func, *self._descendants_of(func)]
                      for c in n.children
                      if (n.type == "conditional_access_expression" and c.type == "?")
                      or (n.type == "postfix_unary_expression" and c.type == "!"))   # `q!.Trim`: q.Trim
        out, last = [], 0
        for cut in cuts:
            out.append(raw[last:cut])
            last = cut + 1
        out.append(raw[last:])
        return b"".join(out).decode("utf-8", errors="replace")

    def _is_nameof(self, call: TSNode) -> bool:
        """`nameof(x)`: the operator (a constant), unless the class declares a method so named."""
        fn = call.child_by_field_name("function")
        return fn is not None and fn.type == "identifier" and self._get_text(fn) == "nameof" \
            and "nameof" not in self._declared_methods.get(self._current_class or "", set())

    def _type_text(self, t: Optional[TSNode]) -> str:
        return self._get_text(t).split("<")[0].rstrip("?").strip() if t is not None else ""

    def _emit(self, instr: Instr) -> None:
        """An instruction an expression makes happen (a pattern binding, an assignment written inside
        an expression), unless the expression is only being read (a lambda body seen from its owner)."""
        if self._quiet == 0 and self._current_proc is not None:
            self._add_instr(instr)

    def _record_unlowered(self, key: str) -> None:
        self._unlowered[key] = self._unlowered.get(key, 0) + 1

    def _annotate_calls(self, program: Program) -> None:
        """Fill `Call.canonical` from the receiver's declared type (C# calls carry no
        receiver type of their own; nothing else reads what is computed here)."""
        from frame.sil.value_origins import typed_names
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
                    if func.endswith(self._STREAM_OVERLOAD_SUFFIX):
                        continue                                  # not the overload the type's id names
                    built = re.match(r"new ([A-Za-z_][\w.]*)\s*\([^()]*\)\.(.+)$", func)
                    if built:                                     # `new CorsPolicyBuilder().AllowAnyOrigin()`
                        q = qualify_type("csharp", built.group(1), self._imports, self._local_types)
                        chain = built.group(2)
                        if q and q not in self._local_types.values() and \
                                ("." not in chain or typed_names(f"{q}.{chain}", "csharp")):
                            instr.canonical = f"{q}.{chain}"
                        continue
                    # `this._db.Query(sql)` is a call on the field _db; `base.Redirect(q)` the inherited one
                    via_base = func.startswith("base.")
                    func = self._unqualified(func)
                    head, dot, rest = func.partition(".")
                    receiver = None
                    if not dot:
                        if func in own_methods and not via_base:
                            receiver = own_class or None
                        elif func[:1].isupper() and canonical_call(
                                "csharp", f"{func}.<init>", self._imports, receiver_type=func,
                                local_types=self._local_types):
                            instr.canonical = canonical_call(
                                "csharp", f"new {func}", self._imports, local_types=self._local_types)
                            continue
                        elif func.isidentifier() and own_class and self._class_has_bases.get(proc.class_name):
                            instr.callee_class = own_class        # `Helper(x)`: may be inherited
                            instr.canonical = _inherited_member(program, proc, func, self._imports, self._local_types)
                            continue
                    elif "." not in rest:
                        receiver = types.get(head) or (head if head[:1].isupper() else None)
                    elif types.get(head):                         # `_db.Database.SqlQueryRaw(sql)`
                        lib = self._library_base(program, types[head], rest.split(".", 1)[0])
                        if lib:
                            instr.canonical = f"{lib}.{rest}"
                            continue
                        q = qualify_type("csharp", types[head], self._imports, self._local_types)
                        if q and typed_names(f"{q}.{rest}", "csharp"):
                            instr.canonical = f"{q}.{rest}"          # `policy.AllowAnyHeader().AllowAnyOrigin()`
                            continue
                    elif head[:1].isupper() and qualify_type("csharp", head, self._imports, self._local_types):
                        q = qualify_type("csharp", head, self._imports, self._local_types)
                        instr.canonical = f"{q}.{rest}"              # `HtmlEncoder.Default.Encode(x)`
                        continue
                    elif head in ("System", "Microsoft"):
                        receiver = func.rsplit(".", 1)[0]
                    if receiver is None:
                        instr.canonical = _inherited_member(program, proc, func, self._imports, self._local_types)
                        continue
                    method = func.rsplit(".", 1)[-1]
                    instr.callee_class = receiver
                    instr.canonical = canonical_call(
                        "csharp", f"{receiver}.{method}", self._imports,
                        receiver_type=receiver, local_types=self._local_types) or \
                        _inherited_member(program, proc, func, self._imports, self._local_types)

    def _library_base(self, program: Program, type_name: str, member: str) -> Optional[str]:
        return library_base(program, type_name, member, self._imports, self._local_types)

    _PREPROC_ARMS = ("preproc_if", "preproc_ifdef", "preproc_elif", "preproc_else")

    def _declarations(self, node: TSNode) -> List[TSNode]:
        """The children of a declaration list (a class body, a namespace, the file), with the members of
        every `#if` / `#elif` / `#else` arm among them: which arm is compiled depends on the build, so
        each arm's members are declared (they used to be dropped)."""
        out: List[TSNode] = []
        for child in node.children:
            out.extend(self._arm_members(child) if child.type in self._PREPROC_ARMS else [child])
        return out

    def _arm_members(self, arm: TSNode) -> List[TSNode]:
        out: List[TSNode] = []
        for i, c in enumerate(arm.children):
            if arm.field_name_for_child(i) == "condition" or not c.is_named:
                continue
            out.extend(self._arm_members(c) if c.type in self._PREPROC_ARMS else [c])
        return out

    def _translate_compilation_unit(self, root: TSNode, program: Program) -> None:
        """Translate C# compilation unit"""
        top_level = [c for c in root.children if c.type == "global_statement"]
        if top_level:
            self._translate_top_level(top_level, program)
        for child in self._declarations(root):
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
            for child in self._declarations(body):
                if child.type in ("class_declaration", "struct_declaration", "record_declaration"):
                    self._translate_class(child, program)
                elif child.type == "namespace_declaration":
                    self._translate_namespace(child, program)

        self._current_namespace = old_ns

    def _translate_file_scoped_namespace(self, node: TSNode, program: Program) -> None:
        """Translate file-scoped namespace (C# 10+)"""
        name_node = node.child_by_field_name("name")
        self._current_namespace = self._get_text(name_node) if name_node else ""

        for child in self._declarations(node):
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
        # C# 12 primary constructor (`class Repo(SqlConnection conn) { ... }`, a positional record):
        # its parameters are in scope, with their declared types, in every member of the class
        primary = next((c for c in node.children if c.type == "parameter_list"), None)
        primary_types = self._declared_types(primary) if primary is not None else {}
        if body:
            fields = dict(primary_types)
            for member in self._declarations(body):
                if member.type == "field_declaration":
                    fields.update(self._declared_types(member))
                elif member.type == "property_declaration":    # `[Inject] NavigationManager Navigation { get; set; }`
                    pn, pt = member.child_by_field_name("name"), member.child_by_field_name("type")
                    if pn is not None and pt is not None:
                        fields[self._get_text(pn)] = self._get_text(pt).split("<")[0].rstrip("?").strip()
            if any(c.type == "modifier" and self._get_text(c) == "partial" for c in node.children):
                # the class's other parts (a WebForms page's designer file declares its controls)
                from frame.sil.dotnet_project import partial_fields
                for name, typ in partial_fields(self._filename, self._current_namespace or "", class_name).items():
                    fields.setdefault(name, typ.removeprefix("global::"))
            self._class_fields_of[full_class_name] = fields
            program.declared_fields[full_class_name] = set(fields)
            self._declared_methods[full_class_name] = {
                self._get_text(c.child_by_field_name("name")) for c in self._declarations(body)
                if c.type == "method_declaration" and c.child_by_field_name("name") is not None}
            self._class_has_bases[full_class_name] = any(c.type == "base_list" for c in node.children)
            for child in self._declarations(body):
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
                        self._record_member_sources(child, proc)
                        self._scopes.append((child.start_byte, child.end_byte, proc))
                        self._translate_lambdas(child, proc, program)
                        self._translate_local_functions(child, proc, program)
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
                        self._record_member_sources(child, proc)
                        self._scopes.append((child.start_byte, child.end_byte, proc))
                        self._translate_lambdas(child, proc, program)
                        self._translate_local_functions(child, proc, program)
                elif child.type == "property_declaration":
                    # Properties can have getters/setters
                    procs = self._translate_property(child)
                    for proc in procs:
                        if proc:
                            proc.class_name = full_class_name
                            program.add_procedure(proc)
            self._translate_literal_fields(body, full_class_name, program)
            if primary is not None:
                self._translate_primary_constructor(primary, node, full_class_name, program)

        self._current_class = old_class

    def _translate_primary_constructor(self, plist: TSNode, cls: TSNode, class_name: str, program: Program) -> None:
        """The constructor a primary constructor declares: it stores each parameter where the class's
        members read it (`this.conn`), so `new Repo(q)` carries q into a member that reads `conn`."""
        params = self._translate_parameters(cls) or [
            (PVar(self._get_text(p.child_by_field_name("name"))), Typ.unknown_type())
            for p in plist.named_children if p.type == "parameter" and p.child_by_field_name("name") is not None]
        if not params:
            return
        proc = Procedure(name=f"{class_name}..ctor", params=params, ret_type=Typ.unknown_type(),
                         loc=self._get_location(plist), is_method=True)
        proc.class_name = class_name
        self._proc_types[id(proc)] = self._declared_types(plist)
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        for p, _ in params:
            entry.add_instr(Assign(loc=proc.loc, id=PVar(f"this.{p.name}"), exp=ExpVar(PVar(p.name))))
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        proc.connect(entry.id, exit_node.id)
        program.add_procedure(proc)

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
        for member in self._declarations(body):
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

        for member in self._declarations(body):
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
        saved_tuples, self._tuple_vars = self._tuple_vars, self._tuple_variables(node)
        saved_jumps, self._jumps = self._jumps, []

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

        # Translate body: a block, or `=> e` (an expression-bodied method)
        returns = node.child_by_field_name("returns") or node.child_by_field_name("type")
        saved_return, self._return_type = self._return_type, self._type_text(returns) or None
        body = node.child_by_field_name("body")
        if body is not None and body.type == "arrow_expression_clause":
            self._translate_expression_body(body, returns=self._get_text(returns).strip() != "void")
        elif body:
            self._translate_block(body)
        self._return_type = saved_return
        outs = self._out_parameters(node)
        if outs:
            self._out_returns(proc, outs)
        elif body is not None and self._is_iterator(body) and self._current_node is not None:
            # an iterator that runs to its end returns what it yielded
            self._current_node.add_instr(Return(loc=proc.loc, value=ExpVar(PVar(self._YIELDED))))

        # Create exit node
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id

        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)

        self._current_proc = None
        self._tuple_vars, self._jumps = saved_tuples, saved_jumps
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
            if n.type == "local_function_statement":
                continue                # translated with the local function (`_translate_local_functions`)
            stack.extend(n.children)
        out.sort(key=lambda t: t[0].start_byte)
        return out

    def _local_functions(self, root: TSNode) -> List[TSNode]:
        """The outermost local functions declared in `root` (nested ones belong to them)."""
        out = []
        stack = list(root.children)
        while stack:
            n = stack.pop()
            if n.type == "local_function_statement":
                out.append(n)
                continue
            if n.type in self._LAMBDA_TYPES:
                continue
            stack.extend(n.children)
        return sorted(out, key=lambda n: n.start_byte)

    def _translate_local_functions(self, owner_node: TSNode, owner: Procedure, program: Program,
                                   top_level: bool = False) -> None:
        """`string Id(string s) => s;` declared inside a method (or among top-level statements) is a
        procedure of its own: a call `Id(q)` resolves to it (to a method of the same class, or, at
        top level, a function), a method group passes it as a handler (`app.MapGet("/x", Ping)`),
        and the enclosing variables it reads carry their data in (as a lambda's do). Its body used
        to be dropped, sinks and all."""
        owner_types = self._proc_types.get(id(owner), {})
        for node in self._local_functions(owner_node):
            saved_class = self._current_class
            if top_level:
                self._current_class = None
            proc = self._translate_method(node)
            self._current_class = saved_class
            if proc is None:
                continue
            if top_level:
                proc.is_method = False                    # a function of the program, called by its name
                if program.has_procedure(proc.name):
                    proc.name = f"{owner.name}.{proc.name}"
            else:
                proc.class_name = owner.class_name or self._current_class
                proc.name = f"{owner.name}.{proc.name}"
            own = self._proc_types.get(id(proc), {})
            self._proc_types[id(proc)] = {**owner_types, **own}
            proc.parent = owner.name
            enclosing = (set(owner_types) | {p.name for p, _ in owner.params}) - {p.name for p, _ in proc.params}
            used = {self._get_text(n) for n in self._descendants_of(node) if n.type == "identifier"}
            proc.captures = sorted(enclosing & used)
            program.add_procedure(proc)
            self._record_member_sources(node, proc)
            self._scopes.append((node.start_byte, node.end_byte, proc))
            self._translate_lambdas(node, proc, program)
            self._translate_local_functions(node, proc, program)

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
                arg_index = [c for c in args.children if c.type == "argument"].index(a) if a.type == "argument" else 0
                self._register(n, arg_index, hits[0], self._scope_of(n), program)

    def _scope_of(self, node: TSNode) -> Optional[Procedure]:
        """The innermost procedure translated from source enclosing `node`."""
        inside = [(e - b, p) for b, e, p in self._scopes if b <= node.start_byte and node.end_byte <= e]
        return min(inside, key=lambda t: t[0])[1] if inside else None

    def _register(self, call: TSNode, arg_index: int, target: Procedure, scope: Optional[Procedure],
                  program: Program) -> None:
        """`app.MapGet("/x", handler)`: the handler is registered with the call as written, with
        the receiver's declared type (`IEndpointRouteBuilder.MapGet`), and, once value origins are
        known, with the receiver's origin (`registrations.refresh_registered_via`)."""
        from frame.sil.registrations import Registration
        callee = self._get_method_name(call)
        if not callee:
            return
        vias = [callee] + (self._call_ids(callee, scope) if scope is not None else [])
        for via in vias:
            if via not in target.registered_via:
                target.registered_via.append(via)
        parts = callee.split(".")
        if not all(x.isidentifier() for x in parts):
            # `app.MapGroup("/api").MapGet(...)`: registered on what app.MapGroup returns
            parts = self._callee_path(call) or parts
        if scope is not None and len(parts) > 1 and all(x.isidentifier() for x in parts):
            program.registrations.append(Registration(
                scope=scope.name, callee_text=callee, root=parts[0], rest=tuple(parts[1:]),
                arg_index=arg_index, target=target.name))

    def _callee_path(self, call: TSNode) -> Optional[List[str]]:
        """`app.MapGroup("/api").MapGet` as ["app", "MapGroup", "MapGet"]: the names along a callee made
        of member accesses and calls (their arguments dropped), from the syntax tree; else None."""
        names: List[str] = []
        node = call.child_by_field_name("function")
        while node is not None:
            if node.type == "invocation_expression":
                node = node.child_by_field_name("function")
                continue
            parts = self._member_parts(node)
            if parts is not None:
                names.insert(0, self._strip_generics(self._get_text(parts[1])))
                node = parts[0]
                continue
            if node.type in ("identifier", "generic_name"):
                names.insert(0, self._strip_generics(self._get_text(node)))
                return names
            return None
        return None

    def _translate_lambdas(self, owner_node: TSNode, owner: Procedure, program: Program) -> None:
        owner_types = self._proc_types.get(id(owner), {})
        for lam, call in self._lambda_args(owner_node):
            delegate = self._delegate_types(lam, call, owner)
            proc = self._translate_lambda(lam, call, owner.name, owner.class_name, owner_types, program, delegate)
            if proc is not None:
                positions = [c for c in (call.child_by_field_name("arguments").children
                                         if call.child_by_field_name("arguments") is not None else ())
                             if c.type == "argument"]
                proc.registered_via = []
                saved, owner.class_name = owner.class_name, owner.class_name or self._current_class
                try:
                    self._register(call, positions.index(lam.parent) if lam.parent in positions else 0,
                                   proc, owner, program)
                finally:
                    owner.class_name = saved
                # the enclosing variables the lambda reads: attacker data they hold reaches its body
                proc.parent = owner.name
                body = lam.child_by_field_name("body") or lam
                enclosing = (set(owner_types) | {p.name for p, _ in owner.params}) - {p.name for p, _ in proc.params}
                used = {self._get_text(n) for n in self._descendants_of(body) if n.type == "identifier"}
                proc.captures = sorted(enclosing & used)
                self._translate_lambdas(lam, proc, program)
                self._translate_local_functions(lam, proc, program)

    def _delegate_types(self, lam: TSNode, call: TSNode, owner: Procedure) -> Tuple[str, ...]:
        """The parameter types the library method a lambda is passed to gives it
        (`services.AddCors(options => ...)`: CorsOptions; value-types.toml `[csharp.delegates]`)."""
        from frame.sil.value_origins import delegate_params
        args = call.child_by_field_name("arguments")
        positions = [a for a in (args.children if args is not None else ()) if a.type == "argument"]
        if lam.parent not in positions:
            return ()
        arg = positions.index(lam.parent)
        saved = owner.class_name
        owner.class_name = owner.class_name or self._current_class
        try:
            ids = self._call_ids(self._get_method_name(call) or "", owner)
        finally:
            owner.class_name = saved
        return next((t for t in (delegate_params("csharp", i, arg) for i in ids) if t), ())

    def _translate_lambda(self, lam: TSNode, call: TSNode, owner_name: str, class_name: Optional[str],
                          outer_types: Dict[str, str], program: Program,
                          delegate: Tuple[str, ...] = ()) -> Optional[Procedure]:
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
        for (pv, _), typ in zip(params, delegate):         # the types the delegate gives undeclared ones
            ptypes.setdefault(pv.name, typ)
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
        types = {**outer_types, **ptypes, **self._declared_types(lam)}
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
        self._record_member_sources(lam, proc)
        self._scopes.append((lam.start_byte, lam.end_byte, proc))
        return proc

    def _translate_lambda_expression_body(self, body: TSNode) -> None:
        """`x => Results.Redirect(x)`: the call is a statement-level call and the returned value."""
        loc = self._get_location(body)
        inner = body
        if inner.type == "await_expression":
            inner = next((c for c in inner.children if c.type not in ("await",)), inner)
        unwrapped = self._unwrap_value(inner)
        if unwrapped is not None and unwrapped.type == "conditional_expression" and self._needs_branches(unwrapped):
            tmp = f"$ret{self._ident_counter}"             # `=> all ? Redirect("/") : Redirect(q)`
            self._ident_counter += 1
            self._lower_conditional(tmp, unwrapped, loc, self._return_type)
            self._add_instr(Return(loc=loc, value=ExpVar(PVar(tmp))))
            return
        if inner.type == "invocation_expression":
            self._add_instrs(self._translate_invocation(inner))
        elif inner.type in self._CREATIONS:
            self._add_instrs(self._translate_object_creation(inner, None, loc, type_name=self._return_type))
        elif inner.type == "assignment_expression":
            self._translate_assignment(inner)          # its value is what the target now holds
            self._add_instr(Return(loc=loc, value=self._translate_expression(inner.child_by_field_name("left"))))
            return
        self._add_instr(Return(loc=loc, value=self._translate_expression(body)))

    def _translate_expression_body(self, clause: TSNode, returns: bool) -> None:
        """`=> e` of a method, accessor or constructor is `{ return e; }` (`{ e; }` when nothing is
        returned): its calls, creations and assignments run like any statement's. The clause used to
        keep only the returned value, so `=> Redirect(q)` reached no sink."""
        expr = next((c for c in clause.named_children if c.type != "comment"), None)
        if expr is None:
            return
        if returns:
            self._translate_lambda_expression_body(expr)
        else:
            self._translate_effect(expr)

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
            self._record_member_sources(gs, proc)
            self._scopes.append((gs.start_byte, gs.end_byte, proc))
            self._translate_lambdas(gs, proc, program)
        for gs in statements:
            self._translate_local_functions(gs, proc, program, top_level=True)

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
        if body is not None and body.type == "arrow_expression_clause":
            self._translate_expression_body(body, returns=False)      # `public C(string a) => _a = a;`
        elif body:
            self._translate_block(body)

        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id

        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)

        self._current_proc = None
        return proc

    def _translate_property(self, node: TSNode) -> List[Optional[Procedure]]:
        """Translate property with getter/setter (blocks or `=>` bodies; `public string P => e;` is a getter)"""
        procs = []
        name_node = node.child_by_field_name("name")
        prop_name = self._get_text(name_node) if name_node else "Property"
        saved_return, self._return_type = self._return_type, self._type_text(node.child_by_field_name("type")) or None

        value = node.child_by_field_name("value")
        if value is not None and value.type == "arrow_expression_clause":
            procs.append(self._accessor_procedure(f"{prop_name}.get", node, value, returns=True))
        for child in node.children:
            if child.type == "accessor_list":
                for accessor in child.children:
                    if accessor.type == "accessor_declaration":
                        accessor_type = None
                        for ac in accessor.children:
                            if ac.type in ("get", "set", "init"):
                                accessor_type = self._get_text(ac)
                                break

                        body = accessor.child_by_field_name("body")
                        if body and accessor_type:
                            procs.append(self._accessor_procedure(f"{prop_name}.{accessor_type}", accessor,
                                                                  body, returns=accessor_type == "get"))
        self._return_type = saved_return
        return procs

    def _accessor_procedure(self, name: str, node: TSNode, body: TSNode, returns: bool) -> Procedure:
        proc = Procedure(
            name=name,
            params=[],
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
        if body.type == "arrow_expression_clause":
            self._translate_expression_body(body, returns=returns)
        else:
            self._translate_block(body)
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)
        self._current_proc = None
        return proc

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
        elif node.type == "variable_declaration":             # a `for` initializer
            self._translate_variable_declaration(node)
        elif node.type in ("lock_statement", "checked_statement", "unsafe_statement", "labeled_statement"):
            # `lock (x) { ... }`, `checked { ... }`, `L: stmt`: the body runs (it used to be dropped)
            body = next((c for c in reversed(node.named_children)
                         if c.type == "block" or c.type.endswith("_statement")), None)
            if body is not None:
                self._translate_statement(body)
        elif node.type == "fixed_statement":                   # `fixed (char* p = q) { ... }`
            self._translate_local_declaration(node)
            body = next((c for c in reversed(node.named_children)
                         if c.type == "block" or c.type.endswith("_statement")), None)
            if body is not None:
                self._translate_statement(body)
        elif node.type == "yield_statement":
            self._translate_yield(node)
        elif node.type in ("preproc_if", "preproc_ifdef", "preproc_elif", "preproc_else"):
            self._translate_preproc(node)
        elif node.type in ("break_statement", "continue_statement"):
            self._translate_jump(node)
        elif node.type in ("local_function_statement", "empty_statement", "goto_statement",
                           "comment") or node.type.startswith("preproc_"):
            pass        # declarations and jumps (a local function's body is not run where it is declared)
        elif node.is_named:
            # a statement kind with no lowering of its own: what it holds still runs
            self._record_unlowered("statement:" + node.type)
            self._translate_expression_statement(node)

    def _tuple_variables(self, root: TSNode) -> Dict[str, Dict[str, TSNode]]:
        """Locals declared once from a written-out tuple and never written again (`var t = (a: "x",
        b: q);`), with each element by name (`a`, and `Item1`...): a read of `t.a` is that element's,
        not every element's."""
        declared: Dict[str, int] = {}
        tuples: Dict[str, Dict[str, TSNode]] = {}
        written: set = set()
        for n in [root, *self._descendants_of(root)]:
            if n.type == "variable_declarator":
                nm = n.child_by_field_name("name") or next((c for c in n.children if c.type == "identifier"), None)
                if nm is None:
                    continue
                name = self._get_text(nm)
                declared[name] = declared.get(name, 0) + 1
                value = self._unwrap_value(self._declarator_value(n))
                if value is not None and value.type == "tuple_expression":
                    fields: Dict[str, TSNode] = {}
                    elements = [c for c in value.named_children if c.type == "argument"]
                    for i, arg in enumerate(elements):
                        v = self._argument_value(arg)
                        label = arg.child_by_field_name("name")
                        if v is None:
                            continue
                        fields[f"Item{i + 1}"] = v
                        if label is not None:
                            fields[self._get_text(label)] = v
                    tuples[name] = fields
            elif n.type in ("parameter", "declaration_expression"):
                nm = n.child_by_field_name("name")
                if nm is not None:
                    declared[self._get_text(nm)] = declared.get(self._get_text(nm), 0) + 1
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                for c in [left, *self._descendants_of(left)] if left is not None else ():
                    if c.type == "identifier":
                        written.add(self._get_text(c))
            elif n.type == "argument" and any(c.type in ("out", "ref") for c in n.children):
                v = self._argument_value(n)
                if v is not None and v.type == "identifier":
                    written.add(self._get_text(v))
        return {k: v for k, v in tuples.items() if declared.get(k) == 1 and k not in written}

    def _is_iterator(self, body: TSNode) -> bool:
        """Does the body (not a lambda or local function inside it) `yield`?"""
        stack = list(body.children)
        while stack:
            n = stack.pop()
            if n.type == "yield_statement":
                return True
            if n.type in self._LAMBDA_TYPES or n.type == "local_function_statement":
                continue
            stack.extend(n.children)
        return False

    def _translate_jump(self, node: TSNode) -> None:
        """`break` goes to the end of the innermost loop or switch, `continue` to the next iteration
        of the innermost loop: an edge, after which nothing runs on this path. Both used to fall
        through, so `while (true) { ...; break; }` lost everything after the loop (the exit prune of a
        constant-true condition is infeasible) and a `break` inside an `if` ran the rest of the body."""
        proc = self._current_proc
        if proc is None or self._current_node is None:
            return
        brk = node.type == "break_statement"
        for break_to, continue_to in reversed(self._jumps):
            target = break_to if brk else continue_to
            if target is not None:
                proc.connect(self._current_node.id, target.id)
                self._current_node = None
                return

    _YIELDED = "$yielded"

    def _translate_yield(self, node: TSNode) -> None:
        """`yield return e;` runs e's calls (the path goes on) and adds e to what the iterator returns
        (`$yielded`, returned when it ends); `yield break;` ends the iterator."""
        loc = self._get_location(node)
        if any(c.type == "break" for c in node.children):
            self._add_instr(Return(loc=loc, value=ExpVar(PVar(self._YIELDED))))
            return
        value = next((c for c in node.named_children if c.type != "comment"), None)
        if value is not None and self._current_proc is not None:
            v = self._value_exp(value, loc)
            self._add_instr(Assign(loc=loc, id=PVar(self._YIELDED),
                                   exp=ExpBinOp("?:", ExpVar(PVar(self._YIELDED)), v)))
            return
        inner = self._unwrap_value(value.named_children[0] if value is not None and value.type == "await_expression"
                                   and value.named_children else value)
        if inner is not None and inner.type == "invocation_expression":
            self._add_instrs(self._translate_invocation(inner))
        elif inner is not None and inner.type in self._CREATIONS:
            self._add_instrs(self._translate_object_creation(inner, None, self._get_location(node)))
        elif inner is not None:
            self._translate_expression(inner)

    def _translate_preproc(self, node: TSNode) -> None:
        """`#if X ... #elif Y ... #else ... #endif` inside a body: which arm is compiled depends on the
        build, so each arm is a branch of its own (none taken when there is no `#else`)."""
        proc = self._current_proc
        if proc is None or self._current_node is None:
            return
        before = self._current_node
        join = proc.new_node(NodeKind.JOIN)
        proc.add_node(join)
        arm = node
        has_else = False
        while arm is not None:
            arm_node = proc.new_node(NodeKind.NORMAL)
            proc.add_node(arm_node)
            proc.connect(before.id, arm_node.id)
            self._current_node = arm_node
            alternative = None
            for i, c in enumerate(arm.children):
                if arm.field_name_for_child(i) in ("condition", "alternative"):
                    if arm.field_name_for_child(i) == "alternative":
                        alternative = c
                    continue
                if c.is_named:
                    self._translate_statement(c)
            if self._current_node is not None:
                proc.connect(self._current_node.id, join.id)
            has_else = has_else or arm.type == "preproc_else"
            arm = alternative
        if not has_else:
            proc.connect(before.id, join.id)
        self._current_node = join

    def _translate_expression_statement(self, node: TSNode) -> None:
        """Translate expression statement"""
        for child in node.children:
            if child.is_named:
                self._translate_effect(child)

    def _translate_effect(self, child: TSNode) -> None:
        """An expression evaluated for what it does (a statement, a `for` update)."""
        if child.type in ("block",) or child.type.endswith("_statement"):
            self._translate_statement(child)          # (a statement kind lowered by its children)
        elif child.type == "invocation_expression":
            instrs = self._translate_invocation(child)
            self._add_instrs(instrs)
        elif child.type in self._CREATIONS:
            self._add_instrs(self._translate_object_creation(
                child, None, self._get_location(child)))
        elif child.type == "assignment_expression":
            self._translate_assignment(child)
        elif child.type == "postfix_unary_expression" or child.type == "prefix_unary_expression":
            self._translate_update(child)
        elif child.type == "await_expression":
            self._translate_await(child)
        elif child.type == "parenthesized_expression":
            inner = self._unwrap_value(child)
            if inner is not None and inner is not child:
                self._translate_effect(inner)
        elif child.type != "comment":
            # Other expression
            self._translate_expression(child)

    def _translate_local_declaration(self, node: TSNode) -> None:
        """Translate local variable declaration"""
        for child in node.children:
            if child.type == "variable_declaration":
                self._translate_variable_declaration(child)

    def _translate_variable_declaration(self, node: TSNode) -> None:
        """`string a = x, b;`, `var (a, b) = (q, "x");`, `SqlCommand cmd = new(sql, conn);`"""
        tnode = node.child_by_field_name("type")
        declared = self._type_text(tnode) if tnode is not None else None
        if declared == "var":
            declared = None
        for decl in node.children:
            if decl.type != "variable_declarator":
                continue
            loc = self._get_location(decl)
            value_node = self._declarator_value(decl)
            pattern = next((c for c in decl.named_children
                            if c.type in ("tuple_pattern", "parenthesized_variable_designation")), None)
            if pattern is not None:                          # `var (a, b) = (q, "x")`
                self._translate_deconstruction(pattern, value_node, loc)
                continue
            name_node = decl.child_by_field_name("name") or next(
                (nc for nc in decl.children if nc.type == "identifier"), None)
            if not name_node:
                continue
            var_name = self._get_text(name_node)
            if value_node is not None:
                self._assign_value(var_name, value_node, loc, declared_type=declared)
                for field, element in self._tuple_vars.get(var_name, {}).items():
                    # `var t = (a: "x", b: q)`: t.a and t.Item1 hold "x" only
                    self._add_instr(Assign(loc=loc, id=PVar(f"{var_name}.{field}"),
                                           exp=self._translate_expression(element)))
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
        elif t == "postfix_unary_expression" and any(c.type == "!" for c in node.children):
            yield from self._source_accesses(next((c for c in node.named_children), None))
        elif t == "invocation_expression":
            parts = self._member_parts(node.child_by_field_name("function"))
            if parts is not None and self._get_text(parts[1]) in _passthrough().csharp_methods:
                yield from self._source_accesses(parts[0])

    def _member_source_spec(self, node: TSNode) -> Optional[ProcSpec]:
        """The source a property / indexer access reads (`Request.Query["a"]`, `ctx.Request.Form`,
        `uploadFile.PostedFile.FileName`), by type: the head's declared, field or inherited type
        (or a type named statically: `HttpContext.Current`), then each member's documented type
        ([csharp.returns]), until a (type, member) that is a source row. A chain is recorded on
        the procedure (`Procedure.member_sources`) so the translator reads inline uses the same way."""
        if node is None or node.type not in ("member_access_expression", "element_access_expression"):
            return None
        chain = self._get_member_chain(node)
        if not chain:
            return None
        parts = chain.split(".") + (["Item"] if node.type == "element_access_expression" and "." not in chain else [])
        spec = self._typed_member_source(parts)
        if spec is not None and self._current_proc is not None:
            self._current_proc.member_sources[chain] = spec.is_source
        return spec

    def _record_member_sources(self, node: TSNode, proc: Procedure) -> None:
        """Every property / indexer access written in `node` that reads a source, by type, on
        `proc.member_sources` (inline reads in expressions are the translator's)."""
        saved = self._current_proc
        self._current_proc = proc
        try:
            for n in self._descendants_of(node):
                if n.type in ("member_access_expression", "element_access_expression"):
                    self._member_source_spec(n)
        finally:
            self._current_proc = saved

    def _typed_member_source(self, parts: List[str]) -> Optional[ProcSpec]:
        from frame.sil.value_origins import load as _value_types
        returns = _value_types().get("csharp", ({}, {}))[0]
        declared = self._receiver_types()
        head, rest = parts[0], parts[1:]
        owner = None                                       # the qualified type the walk is at
        if head in declared:
            owner = qualify_type("csharp", declared[head], self._imports, self._local_types) or declared[head]
        elif self._program is not None and self._current_class:
            base = library_base(self._program, self._current_class, head, self._imports, self._local_types)
            owner = returns.get(f"{base}.{head}") if base else None
        if owner is None and head[:1].isupper():
            static = qualify_type("csharp", head, self._imports, self._local_types)
            if static is not None:                         # `HttpContext.Current.Request`: a type's static member
                owner = static
        for member in rest:
            if owner is None:
                return None
            for t in _dotnet().lineage(owner):
                spec = self.specs.get(f"{t}.{member}")
                if spec is not None and spec.is_taint_source():
                    return spec
            owner = returns.get(f"{owner}.{member}")
        return None

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

        target = self._path_name(left)
        loc = self._get_location(node)
        op_node = node.child_by_field_name("operator")
        op = self._get_text(op_node) if op_node is not None else "="
        inner = self._unwrap_value(right)

        if left.type in self._TUPLE_TARGETS and op == "=":
            self._translate_deconstruction(left, right, loc)       # `(a, b) = (q, "x")`
            return
        if op != "=":
            # `sql += x` is `sql = sql + x` (`??=`: `sql = sql ?? x`): the target keeps what it held
            value = self._compound_value(op, left, right, loc)
            self._store(left, value, loc)
            self._assignment_effects(left, right, loc, value)
            return
        if inner is not None and inner.type == "assignment_expression":
            # `a = b = q`: b is assigned, then a takes b's new value
            value = self._translate_expression(inner)
            self._store(left, value, loc)
            innermost = inner
            while innermost is not None and innermost.type == "assignment_expression":
                innermost = self._unwrap_value(innermost.child_by_field_name("right"))
            self._assignment_effects(left, innermost or right, loc, value)
            return
        if self._element_container(left) is not None:
            # `d["k"] = q`: the container (a variable) now holds q as well
            self._store(left, self._value_exp(right, loc), loc)
            return

        self._assign_value(target, right, loc, declared_type=self._receiver_types().get(target))
        self._assignment_effects(left, right, loc)

    _TUPLE_TARGETS = ("tuple_expression", "tuple_pattern", "parenthesized_variable_designation")

    def _assign_value(self, target: str, value: TSNode, loc: Location,
                      declared_type: Optional[str] = None) -> None:
        """Lower `target = value` for every kind of value: a call (its spec's sources and sinks), a
        creation (a target-typed `new(...)` of `declared_type`), an awaited call, an assignment written
        as the value (`x = y = q`), or any other expression (with the property sources it reads)."""
        inner = self._unwrap_value(value) or value
        if inner.type == "assignment_expression":
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=self._translate_expression(inner)))
        elif inner.type == "invocation_expression" and self._source_in(inner) is None and not self._is_nameof(inner):
            self._add_instrs(self._translate_call_assignment(target, inner, loc))
        elif inner.type in ("object_creation_expression", "implicit_object_creation_expression"):
            self._add_instrs(self._translate_object_creation(inner, target, loc, type_name=declared_type))
        elif inner.type == "await_expression" and self._source_in(inner) is None:
            self._translate_await_assignment(target, inner, loc)
        elif inner.type == "conditional_expression" and self._needs_branches(inner):
            self._lower_conditional(target, inner, loc, declared_type)
        else:
            exp = self._translate_expression(inner)
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=exp))
            self._emit_member_source(inner, target, loc)

    def _needs_branches(self, node: TSNode) -> bool:
        """A `c ? a : b` whose arm runs a call or a creation (`all ? Redirect("/") : Redirect(q)`), or
        ends the path (`ok ? q : throw new E()`): lowered as a branch, not as a value."""
        for field_name in ("consequence", "alternative"):
            arm = self._unwrap_value(node.child_by_field_name(field_name))
            if arm is None:
                continue
            if arm.type == "throw_expression":
                return True
            stack = [arm]
            while stack:
                n = stack.pop()
                if n.type in self._LAMBDA_TYPES:
                    continue
                if n.type in ("invocation_expression",) + self._CREATIONS:
                    return True
                stack.extend(n.children)
        return False

    def _lower_conditional(self, target: str, node: TSNode, loc: Location,
                           declared_type: Optional[str] = None) -> None:
        """`target = c ? a : b` as `if (c) target = a; else target = b;`: each arm's calls, sinks and
        creations run on its own branch, guarded by the condition (`Regex.IsMatch(q, p) ? q : throw ...`
        leaves only a checked q), and a `throw` arm ends its path."""
        proc = self._current_proc
        if proc is None or self._current_node is None:
            return
        cond = self._branch_condition(self._translate_expression(node.child_by_field_name("condition")))
        before = self._current_node
        join = proc.new_node(NodeKind.JOIN)
        arms = []
        for field_name in ("consequence", "alternative"):
            arm_node = proc.new_node(NodeKind.NORMAL)
            proc.add_node(arm_node)
            arms.append((arm_node, node.child_by_field_name(field_name)))
        proc.add_node(join)
        before.add_instr(Prune(loc=loc, condition=cond, is_true_branch=True))
        proc.connect(before.id, arms[0][0].id)
        before.add_instr(Prune(loc=loc, condition=cond, is_true_branch=False))
        proc.connect(before.id, arms[1][0].id)
        for arm_node, arm in arms:
            self._current_node = arm_node
            inner = self._unwrap_value(arm)
            if inner is None:
                self._add_instr(Assign(loc=loc, id=PVar(target), exp=ExpConst.null()))
            elif inner.type == "throw_expression":
                thrown = next((c for c in inner.named_children if c.type != "comment"), None)
                if thrown is not None and thrown.type in self._CREATIONS:
                    self._add_instrs(self._translate_object_creation(thrown, None, loc))
                self._add_instr(Return(loc=loc, value=None))   # the path ends (an exception is no result)
                continue
            else:
                self._assign_value(target, arm, loc, declared_type)
            if self._current_node is not None:
                proc.connect(self._current_node.id, join.id)
        self._current_node = join

    def _value_exp(self, value: TSNode, loc: Location) -> Exp:
        """The value of an expression as an operand: a call, creation, awaited call or property source
        is lowered to a temporary first (`$valN`), so its spec, sinks and sources still apply."""
        inner = self._unwrap_value(value) or value
        if inner.type in ("invocation_expression", "object_creation_expression",
                          "implicit_object_creation_expression", "await_expression") \
                or self._source_in(inner) is not None:
            tmp = f"$val{self._ident_counter}"
            self._ident_counter += 1
            self._assign_value(tmp, inner, loc)
            return ExpVar(PVar(tmp))
        return self._translate_expression(inner)

    def _compound_value(self, op: str, left: TSNode, right: TSNode, loc: Location) -> Exp:
        current = self._translate_expression(left)
        rhs = self._value_exp(right, loc)
        if op == "+=":
            return ExpStringConcat([current, rhs])          # as `+` is lowered
        if op == "??=":
            return ExpBinOp("??", current, rhs)
        return ExpBinOp(op[:-1], current, rhs)

    def _element_container(self, left: TSNode) -> Optional[str]:
        """`d` of an element target `d[k]` when d is a plain name (a local, parameter or field)."""
        if left.type != "element_access_expression":
            return None
        base = left.child_by_field_name("expression")
        return self._get_text(base) if base is not None and base.type == "identifier" else None

    def _store(self, left: TSNode, value: Exp, loc: Location) -> None:
        """Write `value` to an assignment target: a name or member path; an element of a container
        held in a variable as a weak update (`d = d ?: v`: it holds v as well as what it held); a
        deconstruction target element by element."""
        if left.type in self._TUPLE_TARGETS or left.type == "declaration_expression":
            self._bind_target(left, value, loc)
            return
        container = self._element_container(left)
        if container is not None:
            self._add_instr(Assign(loc=loc, id=PVar(container),
                                   exp=ExpBinOp("?:", ExpVar(PVar(container)), value)))
            return
        self._add_instr(Assign(loc=loc, id=PVar(self._path_name(left)), exp=value))

    def _tuple_elements(self, node: TSNode) -> List[TSNode]:
        """The elements of `(a, b)` / `var (a, b)` / `(string a, var b)` / `(q, "x")`."""
        out = []
        for c in node.named_children:
            if c.type == "comment":
                continue
            if c.type == "argument":
                c = self._argument_value(c)
            if c is not None:
                out.append(c)
        return out

    def _translate_deconstruction(self, target: TSNode, value: Optional[TSNode], loc: Location) -> None:
        """`var (a, b) = (q, "x")`, `(a, b) = (b, a)`: each target its own element when the value is a
        tuple written out with as many elements (all evaluated first, so a swap swaps); otherwise
        (`var (a, b) = Pair()`) every target holds the whole value, as an element of it. The targets
        used to be bound as one variable named by their text, or not at all."""
        targets = self._tuple_elements(target)
        value = self._unwrap_value(value) if value is not None else None
        values = self._tuple_elements(value) if value is not None and value.type == "tuple_expression" else None
        if values is not None and len(values) == len(targets):
            nested = []
            for t, v in zip(targets, values):
                if t.type in self._TUPLE_TARGETS + ("declaration_expression",) and self._is_tuple_target(t) \
                        and (self._unwrap_value(v) or v).type == "tuple_expression":
                    nested.append((t, v))                   # `(v, (a, b)) = (q, (1, 2))`: element by element
                    continue
                tmp = f"$unpack{self._ident_counter}"
                self._ident_counter += 1
                self._assign_value(tmp, v, loc)
                nested.append((t, ExpVar(PVar(tmp))))
            for t, v in nested:
                if isinstance(v, Exp):
                    self._bind_target(t, v, loc)
                else:
                    self._translate_deconstruction(self._tuple_target_of(t), v, loc)
            return
        tmp = f"$unpack{self._ident_counter}"
        self._ident_counter += 1
        if value is not None:
            self._assign_value(tmp, value, loc)
        else:
            self._add_instr(Assign(loc=loc, id=PVar(tmp), exp=ExpConst.null()))
        self._bind_target(target, ExpVar(PVar(tmp)), loc)

    def _tuple_target_of(self, node: TSNode) -> TSNode:
        """`var (a, b)` written as an element: the parenthesized designation inside it."""
        if node.type == "declaration_expression":
            nm = node.child_by_field_name("name")
            return nm if nm is not None else node
        return node

    def _is_tuple_target(self, node: TSNode) -> bool:
        return node.type in self._TUPLE_TARGETS or self._tuple_target_of(node).type in self._TUPLE_TARGETS

    def _bind_target(self, target: TSNode, value: Exp, loc: Location) -> None:
        """Write `value` to every variable a deconstruction target names."""
        t = target.type
        if t in self._TUPLE_TARGETS:
            for element in self._tuple_elements(target):
                self._bind_target(element, value, loc)
        elif t == "declaration_expression":                 # `string a` / `var (a, b)`
            nm = target.child_by_field_name("name")
            if nm is not None:
                typ = target.child_by_field_name("type")
                held = ExpConst.null() if self._type_text(typ) in self._NON_INJECTABLE_TYPES else value
                self._bind_target(nm, held, loc)
        elif t == "identifier":
            self._add_instr(Assign(loc=loc, id=PVar(self._get_text(target)), exp=value))
        elif t in ("member_access_expression", "element_access_expression"):
            self._store(target, value, loc)
        elif t not in ("discard", "comment"):
            self._record_unlowered("target:" + t)          # recorded like an unlowered expression

    def _assignment_effects(self, left: TSNode, right: TSNode, loc: Location, value: Optional[Exp] = None) -> None:
        """What writing a member does beyond holding the value: a TLS callback replaced, a protection
        switched off, a property that is a sink on its declared type. `value`: what the member now
        holds, when it is not simply `right` (a compound or chained assignment)."""
        # Assignment to a sink property (e.g. cmd.CommandText = "..."+input)
        # flows the right-hand value into a sink.
        prop = (left.child_by_field_name("name")
                if left.type == "member_access_expression" else None)
        # Overriding a TLS certificate-validation callback (= or += an always-true
        # delegate) is improper certificate validation regardless of the RHS.
        if prop and self._get_text(prop) in _dotnet().certificate_callback_members:
            self._add_instr(Call(loc=loc, ret=None,
                                 func=ExpConst.string("ServerCertificateValidationCallback"),
                                 args=[]))
        member_type = None
        if prop is not None:
            recv_node = left.child_by_field_name("expression")
            recv_chain = self._unqualified(self._get_member_chain(recv_node))
            declared = self._receiver_types()
            # `p.StartInfo.Arguments = x`: the type of a member chain (`Process.StartInfo`)
            member_type = declared.get(recv_chain) or self._member_type(recv_chain, declared)
            recv_type = member_type or recv_chain
            self._add_instrs(self._config_flag_instrs(recv_type, self._get_text(prop), right, loc))
        sink_kind_str = None
        if prop is not None:                       # a property that is a sink on its declared type
            sink_kind_str = self._typed_prop_sink(member_type or "", self._get_text(prop))
        if sink_kind_str and (value is not None or right.type not in ("invocation_expression",
                                                                       "object_creation_expression")):
            self._add_instr(TaintSink(
                loc=loc, exp=value if value is not None else self._translate_expression(right),
                kind=resolve_sink_kind(sink_kind_str),
                description=f"assignment to {self._get_text(prop)} sink", arg_index=0))

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
        kind = desc = None
        for st in self._member_settings():
            if st.kind in _SETTING_SINK_KINDS and prop in st.keys and _glob_any(st.receiver, owner, owner.split(".")[-1]) \
                    and (text == str(st.value).lower() or (st.values and text.endswith(tuple(st.values)))):
                kind = _SETTING_SINK_KINDS[st.kind]
                desc = st.description or st.kind.replace("_", " ")
                break
        if kind is None and prop in _dotnet().certificate_callback_members and self._always_true_callback(rhs):
            kind, desc = "cert_validation", "TLS certificate validation disabled"
        if kind is None:
            return []
        return [TaintSink(loc=loc, exp=ExpConst.string(text), kind=resolve_sink_kind(kind),
                          description=f"{owner}.{prop} = {text}: {desc}", arg_index=0)]

    def _member_settings(self) -> list:
        """The `[[setting]] at = "member"` entries of the C# packs this file's `using`s select
        (cookie options switched off: `new CookieOptions { Secure = false }`)."""
        packs = self.packs if self.packs is not None else default_packs()
        values = list(self._imports.names.values()) + list(self._imports.wildcards)
        return [st for p in packs.for_language("csharp")
                if not p.detect_imports or any(v == pre or v.startswith(pre + ".") for v in values
                                               for pre in p.detect_imports)
                for st in p.settings if st.at == "member"]

    def _always_true_callback(self, node: Optional[TSNode]) -> bool:
        """`(m, c, ch, e) => true`, `delegate { return true; }`, `DangerousAcceptAnyServerCertificateValidator`."""
        if node is None:
            return False
        if node.type == "member_access_expression":
            return self._get_text(node).endswith(_dotnet().accept_all_validators)
        if node.type in self._LAMBDA_TYPES:
            body = node.child_by_field_name("body") or next((c for c in node.children if c.type == "block"), None)
            if body is None:
                return False
            if body.type in ("true_literal", "boolean_literal") and self._get_text(body) == "true":
                return True
            return bool(re.fullmatch(r"\{\s*return\s+true\s*;\s*\}", self._get_text(body).strip()))
        return False

    def _typed_prop_sink(self, type_name: str, prop: str, init: Optional[TSNode] = None) -> Optional[str]:
        """A property that is a sink on this declared type (dotnet-api.toml `typed_property_sink`); one
        with `when` only if the object initializer `init` sets that property to a matching literal
        (`new ContentResult { Content = x, ContentType = "text/html" }`)."""
        t = _dotnet().typed_sink(type_name, prop)
        if t is None:
            return None
        if t.when is None:
            return t.kind
        for c in (init.children if init is not None else ()):
            if c.type == "assignment_expression":
                left, right = c.child_by_field_name("left"), c.child_by_field_name("right")
                if left is not None and right is not None and self._get_text(left) == t.when[0]:
                    return t.kind if t.when[1] in self._get_text(right).lower() else None
        return None

    # -- XML parser hardening ----------------------------------------------------
    #
    # `new XmlDocument()` / `new XmlTextReader(x)` are XXE sinks unless the parser is configured:
    # `XmlResolver = null` or `DtdProcessing = Prohibit|Ignore` makes them safe, and XmlReader.Create
    # is unsafe only with settings that parse DTDs AND resolve external resources. The flags are
    # read from the syntax tree of the procedure (assignments and object initializers).

    def _xml_member_flags(self, prop: str, rhs: Optional[TSNode]) -> set:
        text = self._get_text(rhs).strip() if rhs is not None else ""
        x = _parser_hardening().dotnet                      # parser-hardening.toml [dotnet]
        flags = set()
        if prop == x["resolver_property"]:
            flags.add("null_resolver" if text == "null" else "resolver")
        elif prop == x["dtd_property"]:
            if text.endswith(tuple(x["dtd_parse"])):
                flags.add("parse")
            elif text.endswith(tuple(x["dtd_safe"])):
                flags.add("no_dtd")
        elif prop == x["prohibit_dtd_property"]:
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
                create = next((c for c in n.children if c.type in self._CREATIONS), None)
                if create is None:
                    eq = next((c for c in n.children if c.type == "equals_value_clause"), None)
                    create = next((c for c in (eq.children if eq is not None else ())
                                   if c.type in self._CREATIONS), None)
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
        init = self._initializer_of(create)
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
        if node.type in self._CREATIONS:
            flags = self._initializer_xml_flags(node)
        else:
            flags = self._xml_flags.get(self._get_text(node), set())
        return "parse" in flags and "resolver" in flags and "null_resolver" not in flags

    def _xml_create_instrs(self, call_node: TSNode, loc: Location) -> List[Instr]:
        """`XmlReader.Create(input, settings)` with unsafe settings parses attacker XML with DTDs."""
        name = self._get_method_name(call_node)
        factory = _parser_hardening().dotnet["reader_factory"]
        if name != factory and not name.endswith("." + factory):
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
        declared = self._receiver_types()
        name = self._unqualified(name)                  # `this._http.GetStringAsync`: the field's type
        spec = self.specs.get(name) or self.specs.get(csharp_without_namespace(name, self._imports.wildcards))
        if "." not in name:
            # an unqualified call is a constructor / function the row names (`SqlCommand`), the
            # class's own method, or one it inherits (`Redirect(url)` in a Controller)
            base = self._inherited_base(name)
            inherited = self._typed_row(base, name) if base else None
            return inherited or spec
        recv, _, method = name.rpartition(".")
        head = name.split(".", 1)[0]
        if spec is not None and (not _source_or_sink(spec) or head not in declared):
            return spec                   # a type or an inherited member (`File.ReadAllText`, `Request.Query`)
        rtype = declared.get(recv) or self._member_type(recv, declared)
        if rtype:
            spec = self._typed_row(rtype, method)
            if spec and not (spec.is_taint_source() and not spec.is_taint_sink()):
                return spec               # (typed receivers add sinks / sanitizers, never new sources)
        cls = self._extension_class(method)
        if cls is not None and self.specs.get(f"{cls}.{method}") is not None:
            return self.specs.get(f"{cls}.{method}")
        return None                       # a bare method name on another receiver is not that row's

    def _member_type(self, chain: str, declared: Dict[str, str]) -> Optional[str]:
        """The type of `head.Member` where head is declared and Member comes from its library base
        (`_db.Database` of an `AppDb : DbContext` is a DatabaseFacade / an EF6 Database), from
        value-types.toml [csharp.returns]."""
        head, _, member = chain.partition(".")
        if not member or "." in member or head not in declared or self._program is None:
            return None
        base = library_base(self._program, declared[head], member, self._imports, self._local_types)
        if base is None:
            base = qualify_type("csharp", declared[head], self._imports, self._local_types)
        from frame.sil.value_origins import load as _value_types
        returns = _value_types().get("csharp", ({}, {}))[0]
        return returns.get(f"{base}.{member}") if base else None

    def _typed_row(self, type_name: str, method: str) -> Optional[ProcSpec]:
        """The row of `method` on the type or its nearest documented supertype (dotnet-api.toml)."""
        for t in _dotnet().lineage(type_name):
            spec = self.specs.get(f"{t}.{method}")
            if spec is not None:
                return spec
        return None

    def _extension_class(self, method: str) -> Optional[str]:
        """The static class declaring the extension method `method` that this file's usings bring in
        (exactly one), as C# binds it."""
        hits = {table[method] for ns, table in _dotnet().extension_methods.items()
                if method in table and ns in self._imports.wildcards}
        return next(iter(hits)) if len(hits) == 1 else None

    def _inherited_base(self, method: str) -> Optional[str]:
        """The library base class an unqualified call's method comes from (the class does not
        declare it), as its simple name."""
        cls = self._current_class or ""
        if not cls or method in self._declared_methods.get(cls, set()) or self._program is None:
            return None
        base = library_base(self._program, cls, method, self._imports, self._local_types)
        return base.rsplit(".", 1)[-1] if base else None

    # -- `out` / `ref` arguments ------------------------------------------------------
    #
    # `d.TryGetValue(k, out var v)`, `Copy(q, out var v)`, `Pick(ref v)`: the call writes the
    # variable. A method of the project returns what it leaves in its out/ref parameters (its
    # returns are `<out>(value, b...)`, `_out_returns`), so its summary carries them; at the call
    # the variable takes the call's result. A library method takes the result of its spec (a
    # numeric TryParse sanitizes), or for a method handing out an element of its receiver
    # (`out_from_receiver`: a dictionary's TryGetValue) what the receiver holds. `out _` discards.

    def _table_membership(self, call: TSNode) -> Optional[Exp]:
        """`ALLOWED.Contains(x)` on a constant table of this file (`_constant_tables`) is a membership
        test of a constant collection, `x in <literal-collection>`, which the branch guards read."""
        parts = self._member_parts(call.child_by_field_name("function"))
        args = self._get_method_args(call)
        if parts is None or len(args) != 1 or parts[0].type != "identifier" \
                or self._get_text(parts[0]) not in self._tables \
                or self._get_text(parts[1]) not in _guards().membership_methods:
            return None
        return ExpBinOp("in", self._translate_expression(args[0]),
                        ExpCall(ExpConst.string(LITERAL_COLLECTION), []))

    def _out_arguments(self, call: TSNode) -> List[TSNode]:
        """The values passed by `out` / `ref` in a call's argument list."""
        args = self._arguments_node(call)
        out = []
        for a in (args.children if args is not None else ()):
            if a.type == "argument" and any(c.type in ("out", "ref") for c in a.children):
                value = self._argument_value(a)
                if value is not None:
                    out.append(value)
        return out

    def _has_out_arguments(self, call: TSNode) -> bool:
        return bool(self._out_arguments(call))

    def _out_writes(self, call: TSNode, result: Exp, loc: Location) -> List[Instr]:
        """What a call leaves in the variables passed to it by `out` / `ref`."""
        targets = self._out_arguments(call)
        if not targets:
            return []
        parts = self._member_parts(call.child_by_field_name("function"))
        method = self._strip_generics(self._get_text(parts[1])) if parts is not None else ""
        value = result
        if parts is not None and method in _dotnet().out_from_receiver and not self._own_method_call(call):
            value = self._translate_expression(parts[0])
            spec = self._source_in(parts[0])
            if spec is not None:                         # `Request.Headers.TryGetValue("X", out var v)`
                tmp = f"$recv{self._ident_counter}"
                self._ident_counter += 1
                self._add_instr(Assign(loc=loc, id=PVar(tmp), exp=value))
                self._emit_member_source(parts[0], tmp, loc)
                value = ExpVar(PVar(tmp))
        instrs: List[Instr] = []
        for target in targets:
            typ = None
            if target.type == "declaration_expression":
                typ = self._type_text(target.child_by_field_name("type"))
                target = target.child_by_field_name("name")
            if target is None or (target.type == "identifier" and self._get_text(target) == "_"):
                continue                                 # `out _`: a discard
            if target.type == "identifier" and not typ:
                typ = self._receiver_types().get(self._get_text(target))
            held = ExpConst.null() if (typ or "") in self._NON_INJECTABLE_TYPES else value
            container = self._element_container(target)
            if container is not None:                    # `ref a[i]`: the array holds it as well
                instrs.append(Assign(loc=loc, id=PVar(container),
                                     exp=ExpBinOp("?:", ExpVar(PVar(container)), held)))
            elif target.type in ("identifier", "member_access_expression"):
                instrs.append(Assign(loc=loc, id=PVar(self._path_name(target)), exp=held))
        return instrs

    def _own_field(self, name: str) -> bool:
        """`name` is a field of the class being translated that no parameter or local hides."""
        proc = self._current_proc
        if proc is None or name not in self._class_fields_of.get(self._current_class or proc.class_name or "", {}):
            return False
        return name not in self._proc_types.get(id(proc), {}) and all(p.name != name for p, _ in proc.params)

    def _path_name(self, node: TSNode) -> str:
        """The name a target or a member path is tracked under: `this._x` (`this._x.Y`) is the field
        `_x` (`_x.Y`), the name a bare `_x` reads, unless a parameter or local hides the field. The two
        spellings used to be two variables, so `this._x = q` was not what `_x` read."""
        text = self._get_text(node)
        if text.startswith("this."):
            field = text[5:].split(".", 1)[0]
            if field.isidentifier() and self._own_field(field):
                return text[5:]
        return text

    def _out_parameters(self, node: TSNode) -> List[str]:
        params = node.child_by_field_name("parameters")
        out = []
        for p in (params.children if params is not None else ()):
            if p.type == "parameter" and any(c.type == "modifier" and self._get_text(c) in ("out", "ref")
                                             for c in p.children):
                nm = p.child_by_field_name("name")
                if nm is not None:
                    out.append(self._get_text(nm))
        return out

    def _out_returns(self, proc: Procedure, outs: List[str]) -> None:
        """A method with out / ref parameters returns them with its value (`<out>(value, b)`), on
        every return and when it falls off its end, so its summary says what they carry."""
        from dataclasses import replace
        held = [ExpVar(PVar(o)) for o in outs]
        for n in proc.nodes.values():
            n.instrs = [replace(i, value=ExpCall(ExpConst.string("<out>"), ([i.value] if i.value else []) + held))
                        if isinstance(i, Return) else i for i in n.instrs]
        if self._current_node is not None and not any(isinstance(i, Return) for i in self._current_node.instrs):
            self._current_node.add_instr(Return(loc=proc.loc, value=ExpCall(ExpConst.string("<out>"), list(held))))

    def _extension_methods(self, root: TSNode) -> Dict[str, List[Tuple[str, int]]]:
        """This file's extension methods (`static string Shell(this string s)` in a static class):
        method name -> [(class, number of parameters)]."""
        out: Dict[str, List[Tuple[str, int]]] = {}
        for n in self._descendants_of(root):
            if n.type != "method_declaration":
                continue
            plist = n.child_by_field_name("parameters")
            params = [c for c in (plist.children if plist is not None else ()) if c.type == "parameter"]
            cls = n.parent.parent if n.parent is not None else None
            name = n.child_by_field_name("name")
            if not params or name is None or cls is None or cls.type != "class_declaration" \
                    or not any(c.type == "modifier" and self._get_text(c) == "this" for c in params[0].children):
                continue
            cname = cls.child_by_field_name("name")
            if cname is not None:
                out.setdefault(self._get_text(name), []).append((self._get_text(cname), len(params)))
        return out

    def _extension_call(self, call: TSNode) -> Optional[Tuple[str, TSNode]]:
        """`q.Shell()` calling an extension method this file declares (one by that name taking the
        receiver plus the arguments; no library row and no method of the receiver's own class by
        that name): (`Ext.Shell`, the receiver), so the call is lowered as `Ext.Shell(q)`, the static
        call C# binds it to."""
        parts = self._member_parts(call.child_by_field_name("function"))
        if parts is None or not self._extensions:
            return None
        method = self._strip_generics(self._get_text(parts[1]))
        nargs = len(self._get_method_args(call))
        hits = [c for c, n in self._extensions.get(method, []) if n == nargs + 1]
        if len(hits) != 1:
            return None
        if parts[0].type == "identifier" and self._get_text(parts[0]) in self._local_types \
                and self._get_text(parts[0]) not in self._receiver_types():
            return None                                   # `Ext.Shell(q)` written as the static call it is
        if self._lookup_spec(self._get_method_name(call)) is not None:
            return None
        recv_type = self._value_type(parts[0])
        owner = (recv_type or "").split("<", 1)[0].rsplit(".", 1)[-1]
        if owner and method in self._declared_methods.get(self._local_types.get(owner, ""), set()):
            return None                                   # an instance method of the receiver's class wins
        return f"{hits[0]}.{method}", parts[0]

    def _stored_arguments(self, call: TSNode, loc: Location) -> List[Instr]:
        """`list.Add(q)`, `d.Add(k, q)`, `queue.Enqueue(q)` on a receiver of a declared collection type
        (dotnet-api.toml [stores_arguments]): the collection holds the argument as well (a weak update,
        as an element write is)."""
        parts = self._member_parts(call.child_by_field_name("function"))
        if parts is None or parts[0].type not in ("identifier", "member_access_expression"):
            return []
        recv = self._path_name(parts[0])
        typ = self._receiver_types().get(self._unqualified(recv)) or self._receiver_types().get(recv)
        positions = _dotnet().stored_arguments(typ, self._strip_generics(self._get_text(parts[1]))) if typ else ()
        args = self._get_method_args(call)
        values = [self._translate_expression(args[i]) for i in positions if i < len(args)]
        if not values or not all(x.isidentifier() for x in recv.split(".")):
            return []
        held: Exp = ExpVar(PVar(recv))
        for v in values:
            held = ExpBinOp("?:", held, v)
        return [Assign(loc=loc, id=PVar(recv), exp=held)]

    def _sink_call(self, call: TSNode) -> bool:
        """A call that is a sink by its spec, found through the receiver's type where need be
        (`_db.Database.ExecuteSqlRaw(sql)`, an extension method): written inside another call's
        argument (`return Ok(_db.Database.ExecuteSqlRaw(sql))`) it is lowered to a call of its own,
        as only this frontend can type its receiver."""
        spec = self._lookup_spec(self._get_method_name(call))
        return bool(spec and spec.is_taint_sink())

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
        args = self._arguments_node(call_node)
        stack = list(args.children) if args is not None else []
        while stack:
            n = stack.pop()
            if n.type in self._LAMBDA_TYPES:
                continue
            if n.type == "invocation_expression" and (n.start_byte, n.end_byte) not in self._hoisted \
                    and (self._sanitizer_spec(self._get_method_name(n)) or self._own_method_call(n)
                         or self._created_receiver(n) is not None or self._sink_call(n)
                         or self._has_out_arguments(n)):
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
        extension = self._extension_call(call_node)
        hoisted = self._hoist_receiver(call_node) if extension is None else None
        if hoisted is not None:
            receiver_instrs, method_name = hoisted
            instrs.extend(receiver_instrs)
        args = self._get_method_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]
        if extension is not None:                         # `q.Trim().Shell()` is `Ext.Shell(q.Trim())`
            method_name = extension[0]
            args_exp = [(self._value_exp(extension[1], loc), Typ.unknown_type())] + args_exp

        ret_id = self._new_ident(target)

        call_instr = Call(
            loc=loc,
            ret=(ret_id, Typ.unknown_type()),
            func=ExpConst.string(method_name),
            args=args_exp,
            kwarg_names=self._named_arg_names(call_node),
            type_args=self._type_args(call_node),
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

        if hoisted is None:                 # (a hoisted receiver was lowered with its own sinks)
            instrs.extend(self._receiver_chain_instrs(call_node))
        instrs.extend(self._rsa_padding_instrs(call_node, loc))
        instrs.extend(self._xml_create_instrs(call_node, loc))
        instrs.extend(self._arg_initializer_instrs(call_node, loc))
        instrs.extend(self._out_writes(call_node, ExpVar(ret_id), loc))
        instrs.extend(self._stored_arguments(call_node, loc))
        return instrs

    def _hoist_receiver(self, call_node: TSNode) -> Optional[Tuple[List[Instr], str]]:
        """`q.Trim().ToLower()`, `q?.Trim()?.ToLower()`, `new StringBuilder().Append(q).ToString()`,
        `Process.Start(psi).StandardOutput.ReadToEnd()`: a call made on another call's result. The
        translator reads a call's receiver as the name before its last dot, which `q.Trim()` is not,
        so the receiver's value was lost. The inner call is lowered first to a temporary of its own
        (`$chainN = q.Trim()`, with its own spec, sources and sinks), a member read on its result
        becomes one too, and the outer call is made on the last (`$chainN.ToLower`). Returns None
        when the receiver is a plain path (`_db.Users.Find`), whose written name the specs match."""
        parts = self._member_parts(call_node.child_by_field_name("function"))
        if parts is None:
            return None
        node, method = parts
        path: List[str] = []                 # members read between the inner call and the method
        while True:
            inner = self._member_parts(node)
            if inner is None:
                break
            node, member = inner
            path.insert(0, self._get_text(member))
        node = self._unwrap_value(node)
        if node is None:
            return None
        loc = self._get_location(node)
        if node.type == "invocation_expression":
            tmp = f"$chain{self._ident_counter}"
            self._ident_counter += 1
            instrs = self._translate_call_assignment(tmp, node, loc)
        elif node.type == "object_creation_expression" and self._created_receiver_type(node) is not None:
            tmp = f"$new{self._ident_counter}"
            self._ident_counter += 1
            instrs = self._translate_object_creation(node, tmp, loc)
        elif node.type not in self._NAME_RECEIVERS + self._LITERALS + self._CREATIONS:
            # `(a + q).Trim()`, `d["k"].Trim()`, `("x" + q)?.Trim()` as the grammar reads `"x" + q?.Trim()`
            tmp = f"$chain{self._ident_counter}"
            self._ident_counter += 1
            instrs = [Assign(loc=loc, id=PVar(tmp), exp=self._translate_expression(node))]
            spec = self._source_in(node)
            if spec is not None:
                kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
                instrs.append(TaintSource(loc=loc, var=PVar(tmp), kind=kind, description=spec.description))
        else:
            return None
        for member in path:
            nxt = f"$chain{self._ident_counter}"
            self._ident_counter += 1
            instrs.append(Assign(loc=loc, id=PVar(nxt), exp=ExpFieldAccess(ExpVar(PVar(tmp)), member)))
            tmp = nxt
        return instrs, f"{tmp}.{self._strip_generics(self._get_text(method))}"

    def _created_receiver_type(self, creation: TSNode) -> Optional[str]:
        """The type of `new T(...)` used as a receiver when no spec describes T (library types with a
        spec keep their own handling: `new Regex(p).IsMatch(s)`)."""
        type_node = creation.child_by_field_name("type")
        type_name = self._get_text(type_node) if type_node else ""
        return type_name if type_name and self.specs.get(type_name) is None else None

    def _translate_object_creation(self, node: TSNode, target: Optional[str],
                                   loc: Location, type_name: Optional[str] = None) -> List[Instr]:
        """Translate `new Type(args)` so constructor sinks fire: usage-based
        sinks (new MD5CryptoServiceProvider(), new BinaryFormatter()) via the
        emitted Call, and taint-arg sinks (new SqlCommand(q),
        new DirectorySearcher(filter)) via an explicit TaintSink.

        `type_name`: the type a target-typed `new(...)` creates (the declaration's or the target's);
        it never replaces a type written in the creation."""
        instrs = self._hoist_sanitizers(node)              # sinks and sanitizers written in its arguments
        type_node = node.child_by_field_name("type")
        if type_node is not None or node.type != "implicit_object_creation_expression":
            type_name = self._get_text(type_node) if type_node else "Object"
        args = self._get_method_args(node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]
        elements = self._collection_elements(node)          # `new List<string> { q }` holds q
        if not type_name:
            # `new(q)` whose type nothing here declares: a value built from what it is given
            if target is not None:
                ret = self._new_ident(target)
                instrs.append(Call(loc=loc, ret=(ret, Typ.unknown_type()), func=ExpConst.string("new"),
                                   args=args_exp + [(e, Typ.unknown_type()) for e in elements]))
                instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpVar(ret)))
            return instrs
        members: List[Tuple[str, Exp]] = []

        # Object initializer: new T { Prop = value, ... }. Translate the value
        # expressions so dangerous configuration values (e.g.
        # TypeNameHandling = TypeNameHandling.All) are seen by the member hook.
        init = self._initializer_of(node)
        if init:
            instrs.extend(self._initializer_members(init, type_name, "", members))

        # A parser configured not to resolve external entities is not an XXE sink.
        if type_name.split(".")[-1] in _parser_hardening().dotnet["parser_types"] and (
                self._xml_parser_hardened(target)
                or {"null_resolver", "no_dtd"} & self._initializer_xml_flags(node)):
            if target is not None:
                instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpConst.null()))
            return instrs

        # Emit a Call named after the type so the translator's usage-based sink
        # path (empty sink_args) can fire on the constructor. The overload reading a stream
        # (`new StreamReader(Request.Body)`) is not the path sink its row describes: renamed.
        over_stream = self._stream_overload(type_name, args)
        instrs.append(Call(loc=loc, ret=None,
                           func=ExpConst.string(type_name + self._STREAM_OVERLOAD_SUFFIX if over_stream
                                                else type_name), args=args_exp))
        spec = self.specs.get(type_name)
        held = [(e, Typ.unknown_type()) for e in elements]
        if target is not None and spec is None:
            # A type no spec describes (the project's own `new Job(q)`): the variable is
            # bound to the constructor call, so the project can resolve the constructor
            # and follow what it stores in the new object's fields. A collection's
            # elements follow the constructor's arguments.
            ret = self._new_ident(target)
            instrs.append(Call(loc=loc, ret=(ret, Typ.unknown_type()),
                               func=ExpConst.string(f"new {type_name}"), args=args_exp + held))
            instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpVar(ret)))
        elif target is not None:
            # the object carries what it is made from (`new StreamReader(Request.Body)` reads the
            # body, `new Uri(u)` is u; `new List<string> { q }` holds q). The arguments of a sink
            # constructor are reported where it is built (`new ProcessStartInfo("sh", q)`): the object
            # does not carry them on, or every later use of it is the same flow reported again.
            sink_built = bool(spec.is_taint_sink()) and not over_stream
            values = ([] if sink_built else [e for e, _ in args_exp]) + elements
            instrs.append(Assign(loc=loc, id=PVar(target),
                                 exp=ExpCall(ExpConst.string(f"new {type_name}"), values) if values
                                 else ExpConst.null()))
            for a in ([] if sink_built else args):        # a request property read in its arguments
                source = self._source_in(a)
                if source is not None:
                    kind = TaintKind(source.is_source) if source.is_source in [t.value for t in TaintKind] \
                        else TaintKind.USER_INPUT
                    instrs.append(TaintSource(loc=loc, var=PVar(target), kind=kind, description=source.description))
                    break
        if target is not None:
            # `new Box { Val = q }` sets b.Val (after the object is bound: binding it replaces its fields)
            for member, value in members:
                instrs.append(Assign(loc=loc, id=PVar(f"{target}.{member}"), exp=value))

        if spec and spec.is_taint_sink() and not over_stream:
            kind = resolve_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    instrs.append(TaintSink(
                        loc=loc, exp=self._translate_expression(args[arg_idx]),
                        kind=kind, description=spec.description, arg_index=arg_idx))

        # Insufficient asymmetric key size: new RSACryptoServiceProvider(1024)
        # etc. with an integer-literal key size below 2048 bits (CWE-326).
        short_type = type_name.split('.')[-1]
        if short_type in _dotnet().key_size_types and args:
            ksize = self._int_literal(args[0])
            if ksize is not None and ksize < _dotnet().key_size_minimum:
                instrs.append(Call(loc=loc, ret=None,
                                   func=ExpConst.string("__weak_key_size__"), args=[]))
        return instrs

    _STREAM_OVERLOAD_SUFFIX = "<stream>"

    def _stream_overload(self, type_name: str, args: List[TSNode]) -> bool:
        """`new StreamReader(Request.Body)`, `new StreamReader(file.OpenReadStream())`: the constructor
        overload that reads a Stream (dotnet-api.toml [stream_overloads]), told by the argument's type."""
        hit = _dotnet().stream_overloads.get(type_name.split("<", 1)[0].rsplit(".", 1)[-1])
        if hit is None or hit[0] >= len(args):
            return False
        typ = self._value_type(args[hit[0]])
        return bool(typ) and any(t in hit[1] for t in _dotnet().lineage(typ))

    def _value_type(self, node: Optional[TSNode]) -> Optional[str]:
        """The type of a value, from what the file says: a declared name, a creation, a member chain
        or a call on a typed receiver through the documented member types ([csharp.returns]; a head
        the class inherits from a library base: `Request` in a controller). None when unknown."""
        from frame.sil.value_origins import load as _value_types
        returns = _value_types().get("csharp", ({}, {}))[0]
        node = self._unwrap_value(node)
        if node is None:
            return None
        if node.type in self._CREATIONS:
            t = node.child_by_field_name("type")
            return self._type_text(t) if t is not None else None
        if node.type in ("cast_expression",):
            return self._type_text(node.child_by_field_name("type")) or None
        if node.type == "identifier":
            name = self._get_text(node)
            declared = self._receiver_types().get(name)
            if declared:
                return declared
            if self._program is not None and self._current_class:
                base = library_base(self._program, self._current_class, name, self._imports, self._local_types)
                return returns.get(f"{base}.{name}") if base else None
            return None
        if node.type in ("member_access_expression", "invocation_expression"):
            target = node.child_by_field_name("function") if node.type == "invocation_expression" else node
            parts = self._member_parts(target)
            if parts is None:
                return None
            owner = self._value_type(parts[0])
            if not owner:
                return None
            q = owner if "." in owner else qualify_type("csharp", owner.split("<", 1)[0], self._imports,
                                                       self._local_types)
            return returns.get(f"{q}.{self._strip_generics(self._get_text(parts[1]))}") if q else None
        return None

    def _initializer_members(self, init: TSNode, type_name: str, prefix: str,
                             members: List[Tuple[str, Exp]]) -> List[Instr]:
        """An object initializer `{ Prop = value, ... }` of a `type_name`: each value (a call or a
        creation in it runs first: `StartInfo = new ProcessStartInfo("/bin/sh", "-c " + q)`), the
        sinks and switched-off protections of the properties it sets, and a nested member initializer
        (`StartInfo = { Arguments = "-c " + q }`) on the member's documented type ([csharp.returns]).
        The members set go to `members` as (path, value)."""
        instrs: List[Instr] = []
        for child in init.children:
            if child.type == "object_creation_expression" and not prefix:   # `new List<T> { new T { Sql = q } }`
                instrs.extend(self._translate_object_creation(child, None, self._get_location(child)))
            if child.type != "assignment_expression":
                continue
            lhs, rhs = child.child_by_field_name("left"), child.child_by_field_name("right")
            if lhs is None or rhs is None:
                continue
            loc = self._get_location(child)
            prop = self._get_text(lhs)
            if rhs.type == "initializer_expression" and lhs.type == "identifier":
                inner_type = self._member_result_type(type_name, prop)
                if inner_type:
                    instrs.extend(self._initializer_members(rhs, inner_type, f"{prefix}{prop}.", members))
                    continue
            value = self._value_exp(rhs, loc) if lhs.type == "identifier" else self._translate_expression(rhs)
            if lhs.type == "identifier":
                members.append((f"{prefix}{prop}", value))
            kind = self._typed_prop_sink(type_name, prop, init)
            instrs.extend(self._config_flag_instrs(type_name, prop, rhs, loc))
            if kind:
                instrs.append(TaintSink(loc=loc, exp=value, kind=resolve_sink_kind(kind),
                                        description=f"{type_name.rsplit('.', 1)[-1]} initializer sets {prop}",
                                        arg_index=0))
        return instrs

    def _member_result_type(self, type_name: str, member: str) -> Optional[str]:
        """The documented type of `type_name.member` ([csharp.returns]): `Process.StartInfo` is a
        ProcessStartInfo."""
        from frame.sil.value_origins import load as _value_types
        q = qualify_type("csharp", type_name.split("<", 1)[0], self._imports, self._local_types) \
            if "." not in type_name else type_name
        return _value_types().get("csharp", ({}, {}))[0].get(f"{q}.{member}") if q else None

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
        parts = self._member_parts(call_node.child_by_field_name("function"))
        recv = parts[0] if parts is not None else None
        while recv is not None:
            if recv.type == "invocation_expression":
                loc = self._get_location(recv)
                name = self._get_method_name(recv)
                # The inner call also gets a Call of its own, so framework packs see it
                # (`conn.Query<T>(sql).ToList()`); it defines nothing.
                instrs.append(Call(loc=loc, ret=None, func=ExpConst.string(name),
                                   args=[(self._translate_expression(a), Typ.unknown_type())
                                         for a in self._get_method_args(recv)],
                                   kwarg_names=self._named_arg_names(recv),
                                   type_args=self._type_args(recv)))
                spec = self._lookup_spec(name)
                if spec and spec.is_taint_sink():
                    kind = resolve_sink_kind(spec.is_sink)
                    rargs = self._get_method_args(recv)
                    for arg_idx in spec.sink_args:
                        if arg_idx < len(rargs):
                            instrs.append(TaintSink(
                                loc=loc, exp=self._translate_expression(rargs[arg_idx]),
                                kind=kind, description=spec.description, arg_index=arg_idx))
                inner = self._member_parts(recv.child_by_field_name("function"))
                recv = inner[0] if inner is not None else None
            elif recv.type in ("member_access_expression", "conditional_access_expression"):
                inner = self._member_parts(recv)
                recv = inner[0] if inner is not None else None
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
        extension = self._extension_call(call_node)
        if extension is not None:                         # `q.Shell()` is `Ext.Shell(q)`
            method_name = extension[0]
            args_exp = [(self._translate_expression(extension[1]), Typ.unknown_type())] + args_exp
        # a call writing `out` / `ref` arguments: they take its result (`_out_writes`)
        out_ret = self._new_ident("$out") if self._has_out_arguments(call_node) else None

        call_instr = Call(
            loc=loc,
            ret=(out_ret, Typ.unknown_type()) if out_ret is not None else None,
            func=ExpConst.string(method_name),
            args=args_exp,
            kwarg_names=self._named_arg_names(call_node),
            type_args=self._type_args(call_node),
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
        if out_ret is not None:
            instrs.extend(self._out_writes(call_node, ExpVar(out_ret), loc))
        instrs.extend(self._stored_arguments(call_node, loc))
        return instrs

    def _translate_await(self, node: TSNode) -> None:
        """Translate await expression (standalone)"""
        awaited = self._unwrap_value(next((c for c in node.named_children if c.type != "comment"), None))
        if awaited is not None and awaited.type == "invocation_expression":
            self._add_instrs(self._translate_invocation(awaited))

    def _translate_await_assignment(self, target: str, node: TSNode, loc: Location) -> None:
        """Translate await expression with assignment"""
        awaited = self._unwrap_value(next((c for c in node.named_children if c.type != "comment"), None))
        if awaited is not None and awaited.type == "invocation_expression":
            self._add_instrs(self._translate_call_assignment(target, awaited, loc))
        elif awaited is not None:                       # `var r = await task;`: what the task gives
            self._assign_value(target, awaited, loc)

    def _translate_update(self, node: TSNode) -> None:
        """Translate update expression: i++ or ++i"""
        loc = self._get_location(node)
        # (tree-sitter-c-sharp names no field here: the operand is the one named child)
        operand = node.child_by_field_name("operand") or next(
            (c for c in node.named_children if c.type != "comment"), None)
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
                unwrapped = self._unwrap_value(inner)
                if unwrapped is not None and unwrapped.type == "conditional_expression" \
                        and self._needs_branches(unwrapped):
                    # `return all ? Redirect("/") : Redirect(q);`: each arm runs on its own branch
                    tmp = f"$ret{self._ident_counter}"
                    self._ident_counter += 1
                    self._lower_conditional(tmp, unwrapped, loc, self._return_type)
                    value_exp = ExpVar(PVar(tmp))
                    break
                if inner.type == "invocation_expression":
                    self._add_instrs(self._translate_invocation(inner))
                elif inner.type in self._CREATIONS:      # `return new(q);` creates the declared return type
                    self._add_instrs(self._translate_object_creation(inner, None, loc, type_name=self._return_type))
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
        condition_exp = self._branch_condition(
            self._translate_expression(condition) if condition else ExpConst.boolean(True))

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

    @staticmethod
    def _branch_condition(exp: Exp) -> Exp:
        """An `if` on a literal (`if (false)`) as a comparison: the translator folds comparisons over
        constants, never a bare literal (frontends use one as a loop placeholder), so `if (false) {...}`
        was reachable. Loop conditions keep the literal (CWE-835 reads it)."""
        if isinstance(exp, ExpConst) and isinstance(exp.value, bool):
            return ExpBinOp("==", exp, ExpConst.boolean(True))
        return exp

    def _translate_while(self, node: TSNode) -> None:
        """Translate while loop"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)
        condition = node.child_by_field_name("condition")

        before_node = self._current_node

        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)
        # the condition is evaluated on every iteration: what it does (`(line = r.ReadLine()) != null`)
        # happens at the head
        loop_head.instrs.extend(self._loop_widening(loc, condition, node.child_by_field_name("body")))
        self._current_node = loop_head
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)
        self._current_node = before_node

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
            self._jumps.append((after_node, loop_head))
            try:
                self._translate_statement(body)
            finally:
                self._jumps.pop()

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node

    def _translate_for(self, node: TSNode) -> None:
        """Translate for loop"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        # Initialize: `int i = 0, j = 1` or `i = 0, j = 1` (the field names a node per part)
        fields = [(node.field_name_for_child(i), c) for i, c in enumerate(node.children) if c.is_named]
        for field_name, init in fields:
            if field_name != "initializer":
                continue
            if init.type == "variable_declaration":
                self._translate_variable_declaration(init)
            else:
                self._translate_effect(init)

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
        loop_head.instrs.extend(self._loop_widening(
            loc, condition, node.child_by_field_name("body"), *[u for f, u in fields if f == "update"]))
        self._current_node = loop_head                  # evaluated on every iteration
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)
        self._current_node = before_node

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=True, kind=PruneKind.FOR_ENTER))
        proc.connect(loop_head.id, body_node.id)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=False, kind=PruneKind.FOR_EXIT))
        proc.connect(loop_head.id, after_node.id)

        # `continue` goes to the update, which runs before the condition is tested again
        update_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(update_node)
        self._current_node = body_node
        body = node.child_by_field_name("body")
        if body:
            self._jumps.append((after_node, update_node))
            try:
                self._translate_statement(body)
            finally:
                self._jumps.pop()
        if self._current_node:
            proc.connect(self._current_node.id, update_node.id)

        # Update (`i++, j++`: one `update` field per part). Lowered together with the initializer:
        # `i = 0` without `i++` would make the loop's exit look unreachable.
        self._current_node = update_node
        for field_name, update in fields:
            if field_name == "update":
                self._translate_effect(update)

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node

    def _loop_widening(self, loc: Location, condition: Optional[TSNode], *parts: Optional[TSNode]) -> List[Instr]:
        """At a loop's head, a variable the loop itself changes holds whatever the iterations made
        it, not the constant it had on entry: with `i = 0` before `while (i < 3) { i++; }` the exit
        must not look unreachable. (The translator re-walks a loop head when taint changes, not when
        a constant is forgotten at the join, so the exit pruned on the first visit stayed pruned and
        everything after the loop was lost.) Only variables the condition reads are widened."""
        if condition is None:
            return []
        read = {self._get_text(n) for n in [condition, *self._descendants_of(condition)] if n.type == "identifier"}
        written = set()
        for part in (condition,) + parts:
            for n in ([part, *self._descendants_of(part)] if part is not None else ()):
                target = None
                if n.type == "assignment_expression":
                    target = n.child_by_field_name("left")
                elif n.type in ("postfix_unary_expression", "prefix_unary_expression") \
                        and any(c.type in ("++", "--") for c in n.children):
                    target = next((c for c in n.named_children), None)
                if target is not None and target.type == "identifier":
                    written.add(self._get_text(target))
        return [Assign(loc=loc, id=PVar(v), exp=ExpCall(ExpConst.string("<loop>"), [ExpVar(PVar(v))]))
                for v in sorted(read & written)]

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
        element = ExpCall(ExpConst.string("GetEnumerator.Current"), [iterable_exp])
        if left is not None and self._is_tuple_target(left):
            # `foreach (var (k, v) in pairs)`: every name an element of the element
            tmp = f"$elem{self._ident_counter}"
            self._ident_counter += 1
            body_node.add_instr(Assign(loc=loc, id=PVar(tmp), exp=element))
            saved, self._current_node = self._current_node, body_node
            self._bind_target(self._tuple_target_of(left), ExpVar(PVar(tmp)), loc)
            self._current_node = saved
        else:
            body_node.add_instr(Assign(loc=loc, id=PVar(loop_var), exp=element))
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
        self._current_node = body_node
        if body:
            self._jumps.append((after_node, loop_head))
            try:
                self._translate_statement(body)
            finally:
                self._jumps.pop()

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
        self._current_node = body_node
        if body:
            self._jumps.append((after_node, loop_head))
            try:
                self._translate_statement(body)
            finally:
                self._jumps.pop()

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
        """`switch (x) { case 0: ...; case string s when ...: ...; default: ... }`: each section is a
        branch of its own (C# has no fall-through into a section with statements), entered with its
        patterns' variables bound to x; with no `default`, no section may be taken. The sections used
        to run one after another, so a later one overwrote what an earlier one assigned."""
        proc = self._current_proc
        body = node.child_by_field_name("body")
        if proc is None or body is None or self._current_node is None:
            return
        value = node.child_by_field_name("value")
        subject = self._translate_expression(value) if value is not None else ExpConst.null()
        before = self._current_node
        join = proc.new_node(NodeKind.JOIN)
        proc.add_node(join)
        has_default = False
        for section in body.children:
            if section.type != "switch_section":
                continue
            section_node = proc.new_node(NodeKind.NORMAL)
            proc.add_node(section_node)
            proc.connect(before.id, section_node.id)
            self._current_node = section_node
            loc = self._get_location(section)
            has_default = has_default or any(c.type == "default" for c in section.children) \
                or any(c.type == "default_switch_label" for c in section.named_children)
            self._jumps.append((join, None))         # `break` ends the section
            for child in section.named_children:
                if child.type in ("case_switch_label", "default_switch_label", "comment"):
                    continue
                if child.type == "when_clause":
                    cond = next((c for c in child.named_children), None)
                    if cond is not None:
                        self._translate_expression(cond)          # its own pattern bindings
                elif child.type == "block" or child.type.endswith("_statement"):
                    self._translate_statement(child)
                else:                                             # a case label's pattern
                    self._bind_pattern(child, subject, loc)
            self._jumps.pop()
            if self._current_node is not None:
                proc.connect(self._current_node.id, join.id)
        if not has_default:
            proc.connect(before.id, join.id)
        self._current_node = join

    def _translate_try(self, node: TSNode) -> None:
        """Translate try/catch/finally"""
        # The handler's control flow is not modelled below, so record that this
        # procedure's CFG understates how control can leave it.
        if self._current_proc:
            self._current_proc.has_exception_handler = True

        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)

        # A catch runs only when the body throws, so it is an alternative to the normal exit, not a
        # continuation of it: in sequence, every path ran every handler (`v = ""` in a handler
        # overwrote what the body assigned). As in Java, an exception is approximated as leaving
        # the body at its end; the paths join before the finally block.
        proc = self._current_proc
        catches = [c for c in node.children if c.type == "catch_clause"]
        if proc is not None and catches and self._current_node is not None:
            after_body = self._current_node
            join = proc.new_node(NodeKind.JOIN)
            proc.add_node(join)
            proc.connect(after_body.id, join.id)
            for clause in catches:
                handler = proc.new_node(NodeKind.NORMAL)
                proc.add_node(handler)
                proc.connect(after_body.id, handler.id)
                self._current_node = handler
                for part in clause.named_children:
                    if part.type == "catch_filter_clause":          # `when (cond)`: its own effects
                        cond = next((c for c in part.named_children), None)
                        if cond is not None:
                            self._translate_expression(cond)
                catch_body = clause.child_by_field_name("body") or next(
                    (c for c in clause.named_children if c.type == "block"), None)
                if catch_body:
                    self._translate_block(catch_body)
                if self._current_node is not None:
                    proc.connect(self._current_node.id, join.id)
            self._current_node = join
        for child in node.children:
            if child.type == "finally_clause":
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
        # (its constructor and call sinks apply like any other); `using (Open(q))` an expression
        self._translate_local_declaration(node)
        body = node.child_by_field_name("body")
        for child in node.named_children:
            if child.type not in ("variable_declaration", "comment") and (body is None or child.id != body.id):
                self._translate_effect(child)

        # Translate the body
        if body:
            self._translate_statement(body)

    def _translate_expression(self, node: TSNode) -> Exp:
        """Translate expression"""
        if node is None:
            return ExpConst.null()

        if node.type == "identifier":
            return ExpVar(PVar(self._get_text(node)))

        elif node.type == "typeof_expression":
            # `typeof(T)`: a constant naming a type (DI registrations read it, packs.apply._typeof_type)
            t = node.child_by_field_name("type") or next((c for c in node.named_children), None)
            return ExpCall(ExpConst.string("typeof"), [ExpConst.string(self._get_text(t) if t is not None else "")])

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
                    # `{q}`, `{n:D2}`, `{q,5}`: the expression (braces, alignment and format carry no data)
                    value = next((ic for ic in child.named_children
                                  if ic.type not in ("interpolation_brace", "interpolation_alignment_clause",
                                                     "interpolation_format_clause", "comment")), None)
                    if value is not None:
                        parts.append(self._translate_expression(value))
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

        elif node.type == "boolean_literal":               # `true` / `false` (break/continue are edges)
            return ExpConst.boolean(self._get_text(node).strip() == "true")

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
            return self._compare(op, left_exp, right_exp)

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
            if expr is not None and expr.type in self._THIS and name is not None \
                    and self._own_field(self._get_text(name)):
                return ExpVar(PVar(self._get_text(name)))        # `this._x` reads the field `_x`
            if expr is not None and expr.type == "identifier" and name is not None \
                    and self._get_text(name) in self._tuple_vars.get(self._get_text(expr), {}):
                return ExpVar(PVar(f"{self._get_text(expr)}.{self._get_text(name)}"))   # `t.a` of a tuple
            # Some member-access values are inherently insecure configuration
            # (e.g. TypeNameHandling.All, HashAlgorithmName.MD5, CipherMode.ECB).
            # Emit a Call named after the value so the usage-based sink path
            # (its spec has empty sink_args) fires on the mere reference.
            chain = self._get_member_chain(node)
            short = ".".join(chain.split(".")[-2:]) if "." in chain else chain
            if chain in _dotnet().dangerous_values or short in _dotnet().dangerous_values:
                self._add_instr(Call(loc=self._get_location(node), ret=None,
                                     func=ExpConst.string(short), args=[]))
            return ExpFieldAccess(self._translate_expression(expr), self._get_text(name) if name else "")

        elif node.type == "element_access_expression":
            # `a[i]`: the grammar names the brackets `subscript` (older grammars `arguments`); the
            # index used to be read from a field that does not exist, so every index was 0
            expr = node.child_by_field_name("expression")
            args = node.child_by_field_name("subscript") or node.child_by_field_name("arguments")
            idx_exp = ExpConst.integer(0)
            if args:
                for child in args.children:
                    if child.type not in ("[", "]", ",", "comment"):
                        idx_exp = self._translate_expression(child)
                        break
            return ExpIndex(self._translate_expression(expr), idx_exp)

        elif node.type == "invocation_expression":
            hoisted = self._hoisted.get((node.start_byte, node.end_byte))
            if hoisted is not None:
                return ExpVar(PVar(hoisted))
            fn = node.child_by_field_name("function")
            if self._is_nameof(node):                 # `nameof(q)` is the constant "q"
                args = self._get_method_args(node)
                return ExpConst.string(self._get_text(args[-1]).rsplit(".", 1)[-1] if args else "")
            membership = self._table_membership(node)
            if membership is not None:
                return membership
            if self._quiet == 0 and self._current_proc is not None and self._current_node is not None \
                    and self._has_out_arguments(node):
                # `if (d.TryGetValue(k, out var v))`: the call runs where the expression is evaluated,
                # and writes its out arguments
                tmp = f"$san{len(self._hoisted)}"
                self._hoisted[(node.start_byte, node.end_byte)] = tmp
                self._add_instrs(self._translate_call_assignment(tmp, node, self._get_location(node)))
                return ExpVar(PVar(tmp))
            parts = self._member_parts(fn)
            if parts is not None:
                recv, name = parts
                if (self._get_text(name) in _passthrough().csharp_methods
                        and self._source_in(recv) is not None):
                    return self._translate_expression(recv)   # Request.Query["a"].ToString() reads like Request.Query["a"]
            if parts is not None:
                recv, name = parts
                if recv.type == "invocation_expression" or recv.type in self._VALUE_RECEIVERS:
                    # `_db.Database.SqlQueryRaw(q).ToList()` in an expression: the inner call stays a call
                    # (its own spec, its own arguments); the method is called on what it returns. So is a
                    # method of any other value that is not a name (`(a + q).Trim()`, `d["k"].Trim()`; the
                    # grammar reads `"x" + q?.Trim()` as `("x" + q)?.Trim()`), whose text is no variable.
                    return ExpCall(ExpFieldAccess(self._translate_expression(recv), self._get_text(name).split("<", 1)[0]),
                                   [self._translate_expression(a) for a in self._get_method_args(node)])
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
                    if child.type not in ("(", ")", ",", "comment"):
                        args.append(self._translate_expression(child))
            # `new List<string> { q }`: the collection holds its elements (after the constructor's arguments)
            return ExpCall(ExpConst.string(f"new {type_name}"), args + self._collection_elements(node))

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

        elif node.type in self._THIS or node.type == "base":
            return ExpVar(PVar("this"))

        elif node.type == "await_expression":
            inner = next((c for c in node.named_children if c.type != "comment"), None)
            return self._translate_expression(inner) if inner is not None else ExpConst.null()

        elif node.type == "lambda_expression":
            # A function value: its body runs in a procedure of its own (`_translate_lambda`); read
            # here only for the value an expression-bodied lambda returns, without running it.
            body = node.child_by_field_name("body")
            if body is None or body.type == "block":
                return ExpConst.null()
            self._quiet += 1
            try:
                return self._translate_expression(body)
            finally:
                self._quiet -= 1

        elif node.type == "anonymous_method_expression":
            return ExpConst.null()                  # `delegate (string s) { ... }`: a function value

        elif node.type in ("predefined_type", "qualified_name", "alias_qualified_name", "generic_name"):
            # a type named as a static receiver (`string.Join`) or a generic method group: no data
            return ExpVar(PVar(self._get_text(node)))

        elif node.type == "raw_string_literal":            # `"""SELECT ..."""` (C# 11)
            content = next((c for c in node.children if c.type == "raw_string_content"), None)
            return ExpConst.string(self._get_text(content) if content is not None else "")

        elif node.type == "argument":                      # `(a: q, 1)`, `ref x`: the value passed
            return self._translate_expression(self._argument_value(node))

        elif node.type == "postfix_unary_expression":
            operand = next((c for c in node.named_children if c.type != "comment"), None)
            if any(c.type == "!" for c in node.children):  # `q!`: null-forgiving, the value itself
                return self._translate_expression(operand)
            # `i++` inside an expression: a number that changes, never a constant the path knows
            op = next((c.type for c in node.children if not c.is_named), "++")
            return ExpCall(ExpConst.string(op), [self._translate_expression(operand)])

        elif node.type == "as_expression":                 # `o as string`: o, or null
            return self._translate_expression(node.child_by_field_name("left"))

        elif node.type == "is_expression":                 # `o is string`: a type test
            right = node.child_by_field_name("right")
            return ExpBinOp("is", self._translate_expression(node.child_by_field_name("left")),
                            ExpConst.string(self._get_text(right)))

        elif node.type == "is_pattern_expression":
            return self._translate_is_pattern(node)

        elif node.type == "switch_expression":
            return self._translate_switch_expression(node)

        elif node.type == "conditional_access_expression":
            # `q?.Length`, `q?[0]`: the member / element of q (or null)
            base = self._translate_expression(node.child_by_field_name("condition"))
            binding = next((c for c in node.named_children
                            if c.type in ("member_binding_expression", "element_binding_expression")), None)
            if binding is not None and binding.type == "member_binding_expression":
                name = binding.child_by_field_name("name")
                return ExpFieldAccess(base, self._get_text(name) if name is not None else "")
            if binding is not None:
                return ExpIndex(base, ExpConst.integer(0))
            return base

        elif node.type == "implicit_object_creation_expression":
            # `new(sql, conn)` with no target type in sight (an argument): a value built from its
            # arguments and its collection elements
            return ExpCall(ExpConst.string("new"), [self._translate_expression(a) for a in self._get_method_args(node)]
                           + self._collection_elements(node))

        elif node.type in self._ARRAY_VALUES:
            # `new[] { q }`, `new string[] { q }`, `{ q }`, `[q, "x"]`: an array holding its elements
            return ExpCall(ExpConst.string("new[]"), self._array_elements(node))

        elif node.type == "anonymous_object_creation_expression":
            # `new { Name = q }`: an object made of its members' values
            return ExpCall(ExpConst.string("new <anonymous>"),
                           [self._translate_expression(v) for v in self._anonymous_member_values(node)])

        elif node.type == "tuple_expression":
            # `(q, 200)`: a value made of its elements (a deconstruction reads them one by one)
            return ExpCall(ExpConst.string("<tuple>"),
                           [self._translate_expression(a) for a in node.named_children if a.type != "comment"])

        elif node.type == "assignment_expression":
            # `x = y = q`, `while ((line = r.ReadLine()) != null)`: the assignment happens, and its value
            # is what the target now holds
            if self._quiet == 0 and self._current_proc is not None:
                self._translate_assignment(node)
            return self._translate_expression(node.child_by_field_name("left"))

        elif node.type == "declaration_expression":       # `out var x`: the variable declared
            nm = node.child_by_field_name("name")
            return ExpVar(PVar(self._get_text(nm))) if nm is not None and nm.type == "identifier" else ExpConst.null()

        elif node.type in ("default_expression", "throw_expression", "sizeof_expression", "range_expression"):
            return ExpConst.null()                  # no value (`?? throw ...`), or a number of no one's choosing

        elif node.type in ("checked_expression", "ref_expression"):
            inner = next((c for c in node.named_children if c.type != "comment"), None)
            return self._translate_expression(inner)

        elif node.type == "with_expression":
            # `r with { X = q }`: a copy of r with the members the initializer sets
            parts = [c for c in node.named_children if c.type != "comment"]
            values = [self._translate_expression(parts[0])] if parts else []
            for w in parts[1:]:
                kids = [c for c in w.named_children if c.type != "comment"]
                if kids:
                    values.append(self._translate_expression(kids[-1]))
            return ExpCall(ExpConst.string("with"), values)

        elif node.type == "query_expression":
            # `from s in list where ... select s.Trim()`: elements drawn from what it ranges over
            sources = []
            for clause in node.named_children:
                if clause.type in ("from_clause", "join_clause"):
                    name = clause.child_by_field_name("name")
                    src = next((c for c in reversed(clause.named_children)
                                if name is None or c.id != name.id), None)
                    if src is not None:
                        sources.append(self._translate_expression(src))
            return ExpCall(ExpConst.string("<query>"), sources)

        # Default: lowered as a variable named by the source text, so whatever data the node carried is
        # lost. Each such node type is recorded (`Program.unlowered_syntax`), held to an allowlist of
        # data-free node types by tests/test_lowering_coverage_csharp.py.
        self._record_unlowered(node.type)
        text = self._get_text(node)
        if text:
            return ExpVar(PVar(text))
        return ExpConst.null()

    @staticmethod
    def _compare(op: str, left: Exp, right: Exp) -> Exp:
        """`c == false` is `!c` (`c != false`, `c == true`: c; `c != true`: `!c`), so a guard
        written against a boolean literal reads like the plain test (`!Regex.IsMatch(q, p)`)."""
        if op in ("==", "!="):
            for value, other in ((right, left), (left, right)):
                if isinstance(value, ExpConst) and isinstance(value.value, bool) \
                        and not (isinstance(other, ExpConst) and isinstance(other.value, bool)):
                    return other if value.value == (op == "==") else ExpUnOp("!", other)
        return ExpBinOp(op, left, right)

    # receivers that are names (a call on one is named after it: `string.Join`, `_db.Users.Find`)
    _NAME_RECEIVERS = ("identifier", "generic_name", "predefined_type", "qualified_name", "alias_qualified_name",
                       "this", "this_expression", "base")
    _LITERALS = ("string_literal", "verbatim_string_literal", "raw_string_literal", "character_literal",
                 "integer_literal", "real_literal", "boolean_literal", "null_literal")

    # receivers that are values, never names: a call made on one is read through the value
    _VALUE_RECEIVERS = ("binary_expression", "parenthesized_expression", "element_access_expression",
                        "cast_expression", "postfix_unary_expression", "conditional_expression",
                        "as_expression", "await_expression", "switch_expression", "query_expression",
                        "interpolated_string_expression", "tuple_expression")

    # `new[] { q }`, `new string[] { q }`, `stackalloc`, a bare `{ q }` initializer, `[q, "x"]`
    _ARRAY_VALUES = ("array_creation_expression", "implicit_array_creation_expression",
                     "stackalloc_array_creation_expression", "implicit_stackalloc_expression",
                     "initializer_expression", "element_binding_expression", "collection_expression")

    def _array_elements(self, node: TSNode) -> List[Exp]:
        """The elements of an array value, nested initializers (`{ {a, b}, {c} }`) flattened."""
        out: List[Exp] = []
        for c in node.named_children:
            if c.type in ("initializer_expression", "element_binding_expression"):
                out.extend(self._array_elements(c))
            elif c.type in ("array_type", "array_rank_specifier", "comment") or c.type.endswith("_type"):
                continue
            elif c.type == "argument":
                out.append(self._translate_expression(self._argument_value(c)))
            else:
                out.append(self._translate_expression(c))
        return out

    def _initializer_of(self, creation: TSNode) -> Optional[TSNode]:
        init = creation.child_by_field_name("initializer")
        if init is None:
            init = next((c for c in creation.children if c.type == "initializer_expression"), None)
        return init

    def _collection_elements(self, creation: TSNode) -> List[Exp]:
        """The values a collection initializer adds (`new List<string> { q }`, `{ {"k", q} }`,
        `{ ["k"] = q }`); an object initializer's member assignments (`{ Name = q }`) are not elements."""
        init = self._initializer_of(creation)
        out: List[Exp] = []
        for c in (init.named_children if init is not None else ()):
            if c.type == "assignment_expression":
                left = c.child_by_field_name("left")
                if left is not None and left.type == "element_binding_expression":
                    out.append(self._translate_expression(c.child_by_field_name("right")))
            elif c.type == "initializer_expression":
                out.extend(self._array_elements(c))
            elif c.type != "comment":
                out.append(self._translate_expression(c))
        return out

    @staticmethod
    def _anonymous_member_values(node: TSNode) -> List[TSNode]:
        """`new { Name = q, x.Id }`: the member values (a name before `=` is not one)."""
        kids = node.children
        out = []
        for i, c in enumerate(kids):
            if not c.is_named or c.type == "comment":
                continue
            if i + 1 < len(kids) and kids[i + 1].type == "=":
                continue
            out.append(c)
        return out

    # -- patterns ------------------------------------------------------------------
    #
    # `o is string s`, `case Box { Val: var v }:`, `x switch { string s => s, ... }`: a pattern tests a
    # value and may declare variables holding it. C#'s definite assignment lets code read those only
    # where the match succeeded, so binding them where the test is evaluated gives every read the
    # compiler permits its value.

    def _translate_is_pattern(self, node: TSNode) -> Exp:
        loc = self._get_location(node)
        subject = self._translate_expression(node.child_by_field_name("expression"))
        pattern = node.child_by_field_name("pattern")
        held = subject
        if isinstance(subject, ExpCall) and self._pattern_declares(pattern):
            tmp = f"$is{self._ident_counter}"          # `Find(q) is string s`: the call's value, once
            self._ident_counter += 1
            self._emit(Assign(loc=loc, id=PVar(tmp), exp=subject))
            held = ExpVar(PVar(tmp))
        self._bind_pattern(pattern, held, loc)
        return self._pattern_test(pattern, subject)

    _DECLARING_PATTERNS = ("declaration_pattern", "var_pattern", "recursive_pattern")

    def _pattern_declares(self, pattern: Optional[TSNode]) -> bool:
        return pattern is not None and any(
            n.type in self._DECLARING_PATTERNS for n in [pattern, *self._descendants_of(pattern)])

    def _bind_pattern(self, pattern: Optional[TSNode], subject: Exp, loc: Location) -> None:
        """Bind the variables `pattern` declares to the value it matches (a property subpattern's to
        that member). A variable of a number or other value type cannot hold text, so it holds
        nothing a sink could care about."""
        if pattern is None:
            return
        t = pattern.type
        if t in self._DECLARING_PATTERNS:
            typ = pattern.child_by_field_name("type")
            value = ExpConst.null() if self._type_text(typ) in self._NON_INJECTABLE_TYPES else subject
            self._bind_designation(pattern.child_by_field_name("name")
                                   or pattern.child_by_field_name("designation"), value, loc)
        if t == "recursive_pattern":
            for clause in pattern.named_children:
                if clause.type == "property_pattern_clause":
                    for sub in clause.named_children:
                        kids = [c for c in sub.named_children if c.type != "comment"]
                        if len(kids) >= 2:              # `Val: var v`: v is subject.Val
                            member = subject
                            for part in self._get_text(kids[0]).split("."):
                                member = ExpFieldAccess(member, part.strip())
                            self._bind_pattern(kids[-1], member, loc)
                        elif kids:
                            self._bind_pattern(kids[0], subject, loc)
                elif clause.type == "positional_pattern_clause":
                    for sub in clause.named_children:   # `(var a, var b)`: each an element of subject
                        kids = [c for c in sub.named_children if c.type != "comment"] if sub.type == "subpattern" else [sub]
                        if kids:
                            self._bind_pattern(kids[-1], subject, loc)
        elif t in ("negated_pattern", "parenthesized_pattern", "and_pattern", "or_pattern",
                   "list_pattern", "slice_pattern", "subpattern"):
            for c in pattern.named_children:
                self._bind_pattern(c, subject, loc)

    def _bind_designation(self, designation: Optional[TSNode], value: Exp, loc: Location) -> None:
        if designation is None:
            return
        if designation.type == "identifier":
            self._emit(Assign(loc=loc, id=PVar(self._get_text(designation)), exp=value))
        elif designation.type in ("parenthesized_variable_designation", "tuple_pattern"):
            for c in designation.named_children:
                self._bind_designation(c, value, loc)

    def _pattern_test(self, pattern: Optional[TSNode], subject: Exp) -> Exp:
        """What `subject is <pattern>` tests, as a condition: constant patterns as equality (`x is null`),
        `not` / `and` / `or` as their connectives, relational patterns as comparisons; a type test
        or any other pattern is an opaque atom, which proves nothing about the value."""
        if pattern is None:
            return ExpBinOp("is", subject, ExpConst.string(""))
        t = pattern.type
        kids = [c for c in pattern.named_children if c.type != "comment"]
        if t == "constant_pattern" and kids:
            return self._compare("==", subject, self._translate_expression(kids[0]))
        if t in self._LITERALS:                                # `x is false` (the literal is the pattern)
            return self._compare("==", subject, self._translate_expression(pattern))
        if t in ("negated_pattern", "parenthesized_pattern") and kids:
            inner = self._pattern_test(kids[0], subject)
            return ExpUnOp("!", inner) if t == "negated_pattern" else inner
        if t in ("and_pattern", "or_pattern"):
            left, right = pattern.child_by_field_name("left"), pattern.child_by_field_name("right")
            if left is not None and right is not None:
                return ExpBinOp("&&" if t == "and_pattern" else "||",
                                self._pattern_test(left, subject), self._pattern_test(right, subject))
        if t == "relational_pattern" and kids:
            op = next((c.type for c in pattern.children if not c.is_named), None)
            if op in ("<", "<=", ">", ">="):
                return ExpBinOp(op, subject, self._translate_expression(kids[0]))
        return ExpBinOp("is", subject, ExpConst.string(self._get_text(pattern)))

    def _translate_switch_expression(self, node: TSNode) -> Exp:
        """`x switch { 0 => "none", string s => s, _ => q }`: any arm can be the value, so the result
        carries the taint of every arm (as `c ? a : b` does); the arms' pattern variables hold x."""
        named = [c for c in node.named_children if c.type != "comment"]
        if not named:
            return ExpConst.null()
        subject = self._translate_expression(named[0])
        values: List[Exp] = []
        for arm in named[1:]:
            if arm.type != "switch_expression_arm":
                continue
            loc = self._get_location(arm)
            parts = [c for c in arm.named_children if c.type not in ("when_clause", "comment")]
            if len(parts) < 2:
                continue
            self._bind_pattern(parts[0], subject, loc)
            when = next((c for c in arm.named_children if c.type == "when_clause"), None)
            cond = next((c for c in when.named_children), None) if when is not None else None
            if cond is not None:
                self._translate_expression(cond)        # its own pattern bindings
            if parts[-1].type != "throw_expression":
                values.append(self._translate_expression(parts[-1]))
        if not values:
            return ExpConst.null()
        result = values[-1]
        for v in reversed(values[:-1]):
            result = ExpBinOp("?:", v, result)
        return result

    # =========================================================================
    # Helpers
    # =========================================================================

    def _call_ids(self, func: str, proc: Optional[Procedure] = None) -> List[str]:
        """While translating: the ids a call written `func` in `proc` (default: the procedure being
        translated) has (the receiver's declared type, or the library base a member is inherited
        from), with the typed names they reach (`Url.IsLocalUrl` in a Controller:
        `Microsoft.AspNetCore.Mvc.IUrlHelper.IsLocalUrl`)."""
        from frame.sil.value_origins import typed_names
        proc, program = proc or self._current_proc, getattr(self, "_program", None)
        func = self._unqualified(func)
        if proc is None or program is None or "." not in func:
            return []
        head, rest = func.split(".", 1)
        cls = proc.class_name or self._current_class or ""      # set on the procedure after its body
        types = {**self._class_fields_of.get(cls, {}), **self._proc_types.get(id(proc), {})}
        found = None
        if types.get(head):
            q = qualify_type("csharp", types[head], self._imports, self._local_types)
            found = f"{q}.{rest}" if q else None
        if found is None:
            saved, proc.class_name = proc.class_name, cls
            try:
                found = _inherited_member(program, proc, func, self._imports, self._local_types)
            finally:
                proc.class_name = saved
        return [found] + typed_names(found, "csharp") if found else []

    def _local_url_exp(self, node: Optional[TSNode]):
        """For a packs' `[[same_origin_check]]` call (`Url.IsLocalUrl(x)`, parenthesised or not) on a
        plain variable, the expressions `x.startsWith("/")` and `x.startsWith("//")` that say the same."""
        while node is not None and node.type == "parenthesized_expression":
            node = next((c for c in node.children if c.type not in ("(", ")")), None)
        if node is None or node.type != "invocation_expression":
            return None
        name = self._get_method_name(node)
        packs = self.packs if self.packs is not None else default_packs()
        patterns = [g for p in packs.for_language("csharp") for c in p.same_origin_checks for g in c.call]
        ids = self._call_ids(name)
        from fnmatch import fnmatchcase
        if not patterns or not any(fnmatchcase(i, g) for i in ids for g in patterns):
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

    # A response sink whose spec names `content_type_arg`, called with a non-HTML content-type literal
    # there, is renamed so the XSS sink spec does not match it.
    _NON_HTML_RESPONSE_SUFFIX = "<non-html>"

    # C# keywords that are aliases of System types (C# spec 8.2.1 and 8.3.4): `int.Parse` is
    # `Int32.Parse`, the name the type's rows are written under.
    _PREDEFINED_TYPES = {"int": "Int32", "uint": "UInt32", "long": "Int64", "ulong": "UInt64", "short": "Int16",
                         "ushort": "UInt16", "byte": "Byte", "sbyte": "SByte", "decimal": "Decimal",
                         "double": "Double", "float": "Single", "bool": "Boolean", "char": "Char",
                         "string": "String", "object": "Object"}

    def _get_method_name(self, node: TSNode) -> str:
        func = node.child_by_field_name("function")
        if func:
            name = self._strip_generics(self._callee_text(func))
            head, dot, rest = name.partition(".")
            if dot and func.type == "member_access_expression" and head in self._PREDEFINED_TYPES:
                name = f"{self._PREDEFINED_TYPES[head]}.{rest}"
            spec = self._lookup_spec(name) if self._current_proc is not None else self.specs.get(name)
            pos = getattr(spec, "content_type_arg", None)
            if pos is not None:
                args = self._get_method_args(node)
                if len(args) > pos and args[pos].type in ("string_literal", "verbatim_string_literal") \
                        and "html" not in self._get_text(args[pos]).lower():
                    return name + self._NON_HTML_RESPONSE_SUFFIX
            return name

        # Try expression field
        expr = node.child_by_field_name("expression")
        if expr:
            return self._strip_generics(self._get_text(expr))

        return ""

    def _type_args(self, call_node: TSNode) -> Optional[List[str]]:
        """`AddScoped<IRepo, Repo>()`: the type arguments of a generic method call, as written."""
        func = call_node.child_by_field_name("function")
        name = func.child_by_field_name("name") if func is not None and func.type == "member_access_expression" else func
        if name is None or name.type != "generic_name":
            return None
        targs = next((c for c in name.children if c.type == "type_argument_list"), None)
        return [self._get_text(t) for t in targs.named_children] if targs is not None else None

    def _strip_generics(self, name: str) -> str:
        """`conn.Query<Product>` names the method `conn.Query`: type arguments do not select a spec."""
        return self._GENERIC_ARGS.sub("", name) if "<" in name else name

    def _named_arg_names(self, node: TSNode) -> Optional[List[Optional[str]]]:
        """Names of C# named arguments (`f(a: x)`), parallel to `_get_method_args`;
        None when no argument is named."""
        out: List[Optional[str]] = []
        args_node = self._arguments_node(node)
        for child in (args_node.children if args_node else []):
            if child.type in ("(", ")", ",", "argument_list", "comment"):
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

    @staticmethod
    def _arguments_node(node: TSNode) -> Optional[TSNode]:
        """The argument list of a call or creation (a target-typed `new(...)` has no field for it)."""
        args = node.child_by_field_name("arguments")
        if args is None and node.type == "implicit_object_creation_expression":
            args = next((c for c in node.children if c.type == "argument_list"), None)
        return args

    def _get_method_args(self, node: TSNode) -> List[TSNode]:
        args = []
        args_node = self._arguments_node(node)
        if args_node:
            for child in args_node.children:
                if child.type not in ("(", ")", ",", "argument_list", "comment"):
                    if child.type == "argument":
                        for ac in child.children:
                            if ac.type not in (":", "ref", "out", "in", "comment"):
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
