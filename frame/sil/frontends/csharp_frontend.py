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
from frame.sil.procedure import Procedure, Node, NodeKind, ProcSpec, Program
from frame.sil.specs.csharp_specs import CSHARP_SPECS


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
        # Treat public web-handler action parameters as request-bound taint
        # sources. This is the recall lever for pure-SL mode (regex removed):
        # it lifts IssueBlot.NET SL recall 36.8% -> 51.3% at ~81% precision.
        self.taint_action_params: bool = True

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """Translate C# source code to SIL Program."""
        self._filename = filename
        self._source = source_code
        self._source_bytes = source_code.encode("utf-8")
        self._node_counter = 0
        self._ident_counter = 0

        tree = self.parser.parse(self._source_bytes)
        program = Program(library_specs=self.specs.copy())
        program.source_files.append(filename)

        self._translate_compilation_unit(tree.root_node, program)
        return program

    def _translate_compilation_unit(self, root: TSNode, program: Program) -> None:
        """Translate C# compilation unit"""
        for child in root.children:
            if child.type == "namespace_declaration":
                self._translate_namespace(child, program)
            elif child.type == "class_declaration":
                self._translate_class(child, program)
            elif child.type == "interface_declaration":
                pass  # Skip interfaces
            elif child.type == "struct_declaration":
                self._translate_class(child, program)  # Treat struct like class
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
                if child.type == "class_declaration":
                    self._translate_class(child, program)
                elif child.type == "namespace_declaration":
                    self._translate_namespace(child, program)

        self._current_namespace = old_ns

    def _translate_file_scoped_namespace(self, node: TSNode, program: Program) -> None:
        """Translate file-scoped namespace (C# 10+)"""
        name_node = node.child_by_field_name("name")
        self._current_namespace = self._get_text(name_node) if name_node else ""

        for child in node.children:
            if child.type == "class_declaration":
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

        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "method_declaration":
                    proc = self._translate_method(child)
                    if proc:
                        proc.class_name = full_class_name
                        proc.name = f"{full_class_name}.{proc.name}"
                        program.add_procedure(proc)
                elif child.type == "constructor_declaration":
                    proc = self._translate_constructor(child)
                    if proc:
                        proc.class_name = full_class_name
                        proc.name = f"{full_class_name}..ctor"
                        program.add_procedure(proc)
                elif child.type == "property_declaration":
                    # Properties can have getters/setters
                    procs = self._translate_property(child)
                    for proc in procs:
                        if proc:
                            proc.class_name = full_class_name
                            program.add_procedure(proc)

        self._current_class = old_class

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

        # Check for static modifier
        for child in node.children:
            if child.type == "modifier" and self._get_text(child) == "static":
                proc.is_static = True

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

        # Process attributes for taint sources
        self._process_param_attributes(attributes, params, proc)

        # ASP.NET MVC/WebAPI/SignalR: a public action/handler's parameters are
        # model-bound from the HTTP request, hence attacker-controlled. This is
        # the recall lever for pure-SL mode, gated to public web-facing classes
        # and to injectable (string/object/model) param types. It is OFF by
        # default because, while the regex backstop is active, it only adds
        # false positives (each needs framework modeling: Razor output encoding,
        # redirect validators, correct path/CWE sink resolution). Enable via
        # taint_action_params=True once that modeling lands and the regex is
        # being removed.
        if self.taint_action_params:
            cls = self._current_class or ""
            is_web_handler = any(s in cls for s in
                                 ("Controller", "Hub", "WebService", "Handler", "Endpoint"))
            is_public = any(c.type == "modifier" and self._get_text(c) == "public"
                            for c in node.children)
            if is_web_handler and is_public and method_name != "Main":
                injectable = self._injectable_param_names(node)
                for param, _ in params:
                    if param.name not in injectable:
                        continue
                    self._add_instr(TaintSource(
                        loc=self._get_location(node), var=param,
                        kind=TaintKind.USER_INPUT,
                        description="ASP.NET action/handler parameter (request-bound)"))

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

    def _process_param_attributes(
        self,
        attributes: List[str],
        params: List[Tuple[PVar, Typ]],
        proc: Procedure
    ) -> None:
        """Process parameter attributes for taint sources"""
        # ASP.NET Core attributes that mark parameters as taint sources
        taint_attributes = {
            "FromQuery": TaintKind.USER_INPUT,
            "FromBody": TaintKind.USER_INPUT,
            "FromForm": TaintKind.USER_INPUT,
            "FromHeader": TaintKind.USER_INPUT,
            "FromRoute": TaintKind.USER_INPUT,
        }

        for attr in attributes:
            for pattern, kind in taint_attributes.items():
                if pattern in attr:
                    # Mark all params as tainted (simplified)
                    for param, _ in params:
                        self._add_instr(TaintSource(
                            loc=self._get_location(proc),
                            var=param,
                            kind=kind,
                            description=f"[{pattern}] attribute"
                        ))

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

                        if name_node:
                            var_name = self._get_text(name_node)
                            loc = self._get_location(decl)

                            if value_node:
                                if value_node.type == "invocation_expression":
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

    def _emit_member_source(self, value_node: TSNode, target: str, loc: Location) -> None:
        """Emit a TaintSource if value_node is a property/indexer taint source
        (e.g. Request.QueryString[...], Request.Form[...], User.Identity.Name).

        C# web sources are property/indexer accesses, not method calls, so the
        invocation path never tainted them -- this is the keystone fix that lets
        SQL/command/path/LDAP/etc. taint flows be detected at all.
        """
        if value_node is None or value_node.type not in (
            "member_access_expression", "element_access_expression"
        ):
            return
        chain = self._get_member_chain(value_node)
        if not chain:
            return
        spec = self.specs.get(chain)
        if not spec and '.' in chain:
            parts = chain.split('.')
            for i in range(1, len(parts)):
                spec = self.specs.get('.'.join(parts[i:]))
                if spec:
                    break
        if spec and spec.is_taint_source():
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

        if right.type == "invocation_expression":
            instrs = self._translate_call_assignment(target, right, loc)
            self._add_instrs(instrs)
        elif right.type == "object_creation_expression":
            self._add_instrs(self._translate_object_creation(right, target, loc))
        elif right.type == "await_expression":
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
        sink_kind_str = self._ASSIGNMENT_SINK_PROPS.get(self._get_text(prop)) if prop else None
        if sink_kind_str and right.type not in ("invocation_expression",
                                                "object_creation_expression"):
            self._add_instr(TaintSink(
                loc=loc, exp=self._translate_expression(right),
                kind=resolve_sink_kind(sink_kind_str),
                description=f"assignment to {self._get_text(prop)} sink", arg_index=0))

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

        # Check specs - try full method name first, then just the last part
        spec = self.specs.get(method_name)
        if not spec and '.' in method_name:
            # Try the last part of the method chain (e.g., ExecuteSqlCommand from context.Database.ExecuteSqlCommand)
            short_name = method_name.split('.')[-1]
            spec = self.specs.get(short_name)

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

        # Emit a Call named after the type so the translator's usage-based sink
        # path (empty sink_args) can fire on the constructor.
        instrs.append(Call(loc=loc, ret=None,
                           func=ExpConst.string(type_name), args=args_exp))
        if target is not None:
            instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpConst.null()))

        spec = self.specs.get(type_name)
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
                spec = self.specs.get(name)
                if not spec and '.' in name:
                    spec = self.specs.get(name.split('.')[-1])
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
            else:
                break
        return instrs

    def _translate_invocation(self, call_node: TSNode) -> List[Instr]:
        """Translate standalone method invocation"""
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

        # Check specs - try full method name first, then just the last part
        spec = self.specs.get(method_name)
        if not spec and '.' in method_name:
            short_name = method_name.split('.')[-1]
            spec = self.specs.get(short_name)

        if spec and spec.is_taint_sink():
            kind = resolve_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = self._translate_expression(args[arg_idx])
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description, arg_index=arg_idx))

        instrs.extend(self._receiver_chain_instrs(call_node))
        instrs.extend(self._rsa_padding_instrs(call_node, loc))
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
                if child.type == "invocation_expression":
                    self._add_instrs(self._translate_invocation(child))
                elif child.type == "object_creation_expression":
                    self._add_instrs(self._translate_object_creation(child, None, loc))
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
        # Translate the variable declaration in the using clause
        for child in node.children:
            if child.type == "variable_declaration":
                # Create a fake local_declaration_statement node to reuse translation
                for decl in child.children:
                    if decl.type == "variable_declarator":
                        name_node = None
                        value_node = None
                        for nc in decl.children:
                            if nc.type == "identifier":
                                name_node = nc
                            elif nc.type in ("invocation_expression", "object_creation_expression"):
                                value_node = nc
                        if name_node:
                            var_name = self._get_text(name_node)
                            loc = self._get_location(decl)
                            if value_node and value_node.type == "invocation_expression":
                                instrs = self._translate_call_assignment(var_name, value_node, loc)
                                self._add_instrs(instrs)
                            elif value_node:
                                exp = self._translate_expression(value_node)
                                self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=exp))

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
            op_node = node.child_by_field_name("operator")
            operand = node.child_by_field_name("operand")
            op = self._get_text(op_node) if op_node else "-"
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

        elif node.type == "conditional_expression":
            conseq = node.child_by_field_name("consequence")
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

    def _get_method_name(self, node: TSNode) -> str:
        func = node.child_by_field_name("function")
        if func:
            return self._get_text(func)

        # Try expression field
        expr = node.child_by_field_name("expression")
        if expr:
            return self._get_text(expr)

        return ""

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
