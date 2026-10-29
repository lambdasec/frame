"""
JavaScript/TypeScript to Frame SIL Frontend.

This module translates JavaScript and TypeScript source code to Frame SIL
using tree-sitter for parsing. It handles:
- Function definitions (regular, arrow, async)
- Variable declarations (var, let, const)
- Function calls (with taint source/sink detection)
- Control flow (if/else, while, for, switch)
- String operations (concatenation, template literals)
- Class methods
- Object destructuring
"""

import re
from collections import Counter
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field

try:
    import tree_sitter_javascript as tsjavascript
    from tree_sitter import Language, Parser, Node as TSNode
    TREE_SITTER_JS_AVAILABLE = True
except ImportError:
    TREE_SITTER_JS_AVAILABLE = False
    TSNode = Any

try:
    import tree_sitter_typescript as tstypescript
    TREE_SITTER_TS_AVAILABLE = True
except ImportError:
    TREE_SITTER_TS_AVAILABLE = False

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
from frame.sil.frontends._syntax import first_syntax_error_line
from frame.sil.procedure import (
    Procedure, Node, NodeKind, ProcSpec, Program, GLOBAL_OBJECTS, DB_HANDLE,
    RECEIVER_UNKNOWN, db_method_applies)
from frame.sil.metadata import (
    ClassInfo, ImportTable, annotate_program_calls, parse_annotation,
)
from frame.sil.packs import finish_program
from frame.sil.loop_exit import body_can_exit_loop
from frame.sil.specs.passthrough import load as _passthrough
from frame.sil.specs.request_objects import load as _request_objects
from frame.sil.specs.shells import is_shell
from frame.sil.specs.javascript_specs import JAVASCRIPT_SPECS


def _get_sink_kind(spec_type: str) -> SinkKind:
    """A spec's sink-kind string as a SinkKind (aliases from specs/data/kinds.toml)."""
    return resolve_sink_kind(spec_type)


class JavaScriptFrontend:
    """
    Translates JavaScript/TypeScript source code to Frame SIL.

    Usage:
        frontend = JavaScriptFrontend()
        program = frontend.translate(source_code, "example.js")

        # Now use SILTranslator to generate vulnerability checks
        from frame.sil import SILTranslator
        translator = SILTranslator(program)
        checks = translator.translate_program()
    """

    packs = None   # a frame.sil.packs.PackSet; None = the built-in packs

    def __init__(self, specs: Dict[str, ProcSpec] = None, language: str = "javascript"):
        """
        Initialize the JavaScript/TypeScript frontend.

        Args:
            specs: Library specifications (defaults to JAVASCRIPT_SPECS)
            language: "javascript" or "typescript"
        """
        self.language = language

        if language == "typescript":
            if not TREE_SITTER_TS_AVAILABLE:
                raise ImportError(
                    "tree-sitter-typescript is required for TypeScript. "
                    "Install with: pip install tree-sitter-typescript"
                )
            self.parser = Parser(Language(tstypescript.language_typescript()))
        else:
            if not TREE_SITTER_JS_AVAILABLE:
                raise ImportError(
                    "tree-sitter-javascript is required. "
                    "Install with: pip install tree-sitter-javascript"
                )
            self.parser = Parser(Language(tsjavascript.language()))

        self.specs = specs or JAVASCRIPT_SPECS

        # State during translation
        self._filename = "<unknown>"
        self._source = ""
        self._current_proc: Optional[Procedure] = None
        self._current_node: Optional[Node] = None
        self._node_counter = 0
        self._ident_counter = 0
        self._current_class: Optional[str] = None
        # Treat function parameters as untrusted input. In Node.js packages the
        # exported API is the attack surface (callers pass attacker-controlled
        # data), so this is the pure-SL recall lever for real-world JS, mirroring
        # the C# action-parameter lever.
        self.taint_function_params: bool = False

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """
        Translate JavaScript/TypeScript source code to SIL Program.

        Args:
            source_code: Source code string
            filename: Source file name for error reporting

        Returns:
            SIL Program containing all translated procedures
        """
        self._filename = filename
        self._source = source_code
        self._source_bytes = source_code.encode("utf-8")
        self._node_counter = 0
        self._ident_counter = 0

        # Parse source code
        tree = self.parser.parse(self._source_bytes)

        # File-level prototype-pollution guard signal (see _scan_proto_pollution);
        # needed up front so call-style sinks like merge(a, b) honour it too.
        self._proto_guarded = bool(self._PROTO_GUARD_RE.search(source_code))

        # Module bindings (`const cp = require('child_process')`, `import {exec}
        # from 'child_process'`): calls through them are named after the module
        # so module specs match whatever the local name is (_get_call_name).
        self._module_aliases, self._imported_names = self._module_bindings(tree.root_node)
        self._declared_names = self._file_declared_names(tree.root_node)
        self._const_tables = self._collect_const_tables(tree.root_node)
        self._ctor_fields = self._constructor_field_paths(tree.root_node) if self.taint_function_params else {}
        self._const_sets = self._collect_const_sets(tree.root_node)
        self._binding_cache = {}

        # Create program with library specs
        program = Program(library_specs=self.specs.copy(), language=self.language)
        program.source_files.append(filename)
        program.syntax_error_line = first_syntax_error_line(tree.root_node)

        self._imports = ImportTable()
        for local, module in self._module_aliases.items():
            self._imports.bind(local, module)
        for local, qualified in self._imported_names.items():
            self._imports.bind(local, qualified)
        # `const client = new OpenAI()`: a name declared once in the file and bound to an instance
        # of an imported class names what it is, so `client.chat.completions.create` has the
        # canonical id `openai.chat.completions.create` (packs match SDK clients by it)
        self._instance_names = set()
        for local, qualified in self._instance_bindings(tree.root_node).items():
            self._imports.bind(local, qualified)
            self._instance_names.add(local)
        self._imports.finish()
        program.imports = self._imports.as_dict()

        # Walk top-level definitions
        self._translate_module(tree.root_node, program)

        self._link_enclosing_procedures(program)
        annotate_program_calls(program, self._imports)

        # One-hop interprocedural taint: a request-derived value passed to a
        # same-file function taints that function's parameter (e.g. a handler
        # computes `file` from req and calls a helper verify(file) that sends it).
        self._propagate_js_interprocedural(tree.root_node, program)

        # The whole-file ReDoS and prototype-pollution passes are structural
        # heuristics, not taint-gated. On vendored third-party libraries and
        # minified/generated bundles they produce almost only false positives
        # (the code is not the application's own and is never going to be fixed
        # here), so -- like mainstream SAST tools -- we skip these heuristics on
        # such files. Taint-based detection still runs everywhere.
        if not self._is_vendored_or_minified():
            self._scan_redos(tree.root_node, program)
            self._scan_proto_pollution(tree.root_node, program)

        self._record_declarations(tree.root_node, program)
        finish_program(program, self.packs, source_code)
        self._entry_taint_into_closures(program)
        return program

    @staticmethod
    def _entry_taint_into_closures(program: Program) -> None:
        """A framework pack taints a handler's parameters (`ipcMain.handle('x', (e, tool) =>
        ...)`). A callback nested in the handler that reads such a parameter (`new Promise(
        resolve => exec('t/' + tool))`) must see it tainted too."""
        def entry_sources(proc):
            node = proc.nodes.get(proc.entry_node)
            if node is None:
                return None, []
            return node, [i for i in node.instrs
                          if isinstance(i, TaintSource) and "entry point" in (i.description or "")]

        for _ in range(4):                      # nesting depth
            changed = False
            for proc in program.procedures.values():
                parent = program.procedures.get(proc.parent) if proc.parent else None
                if parent is None or not proc.captures:
                    continue
                node, own = entry_sources(proc)
                if node is None:
                    continue
                have = {str(i.var) for i in own}
                _, inherited = entry_sources(parent)
                for src in inherited:
                    name = str(src.var)
                    if name in proc.captures and name not in have \
                            and name not in {str(p) for p, _ in proc.params}:
                        node.instrs.insert(0, TaintSource(loc=src.loc, var=src.var, kind=src.kind,
                                                          description=src.description))
                        have.add(name)
                        changed = True
            if not changed:
                break

    def _record_declarations(self, root: TSNode, program: Program) -> None:
        """Parameter types (TypeScript), the callees each function is passed to
        (`app.get('/x', handler)`), read from the tree for framework packs."""
        by_span = {p.span: p for p in program.procedures.values() if p.span}
        stack = [root]
        while stack:
            n = stack.pop()
            stack.extend(n.children)
            if n.type in self._FUNC_LIKE:
                proc = by_span.get((n.start_byte, n.end_byte))
                params = n.child_by_field_name("parameters")
                if proc is None or params is None:
                    continue
                for ch in params.children:
                    if ch.type not in ("required_parameter", "optional_parameter"):
                        continue
                    pat, ty = ch.child_by_field_name("pattern"), ch.child_by_field_name("type")
                    if pat is not None and pat.type == "identifier" and ty is not None:
                        text = self._get_text(ty).lstrip(":").strip().split("<")[0].strip()
                        if text:
                            proc.param_types[self._get_text(pat)] = text
            elif n.type in ("pair", "variable_declarator"):
                self._register_graphql_resolvers(n, by_span)
            elif n.type == "call_expression":
                callee, args = n.child_by_field_name("function"), n.child_by_field_name("arguments")
                if callee is None or args is None:
                    continue
                callee_text = self._get_text(callee)
                for arg_index, a in enumerate(args.named_children):
                    target = None
                    if a.type in self._FUNC_LIKE:
                        target = by_span.get((a.start_byte, a.end_byte))
                    elif a.type == "identifier":
                        target = program.procedures.get(self._get_text(a))
                    if target is not None and callee_text not in target.registered_via:
                        target.registered_via.append(callee_text)
                    if target is not None and (callee_text, arg_index) not in target.passed_as:
                        target.passed_as.append((callee_text, arg_index))
                    elif a.type == "object":
                        # `server.route({ handler: (request, h) => ... })`, `fastify.route({ handler() {} })`:
                        # the function is registered as `<callee>.<property>`.
                        for prop in a.named_children:
                            key = prop.child_by_field_name("key") or prop.child_by_field_name("name")
                            value = prop.child_by_field_name("value") if prop.type == "pair" else prop
                            if key is None or value is None or value.type not in self._FUNC_LIKE:
                                continue
                            fn = by_span.get((value.start_byte, value.end_byte))
                            via = f"{callee_text}.{self._get_text(key).strip(chr(39) + chr(34))}"
                            if fn is not None and via not in fn.registered_via:
                                fn.registered_via.append(via)

    _GRAPHQL_ROOTS = frozenset({"Query", "Mutation", "Subscription"})

    def _register_graphql_resolvers(self, node: TSNode, by_span) -> None:
        """Apollo / graphql-tools resolver maps: the functions in `Query: { ... }` /
        `Mutation: { ... }` and (one level deeper) in an object named `resolvers` are
        registered as "graphql.resolver" -- (parent, args, context, info) callbacks."""
        if node.type == "pair":
            key_node, value = node.child_by_field_name("key"), node.child_by_field_name("value")
        else:
            key_node, value = node.child_by_field_name("name"), node.child_by_field_name("value")
        if key_node is None or value is None or value.type != "object":
            return
        key = self._get_text(key_node).strip("'\"")

        def functions(obj):
            for member in obj.named_children:
                fn_node = member.child_by_field_name("value") if member.type == "pair" else member
                if fn_node is not None and fn_node.type in self._FUNC_LIKE:
                    fn = by_span.get((fn_node.start_byte, fn_node.end_byte))
                    if fn is not None and "graphql.resolver" not in fn.registered_via:
                        fn.registered_via.append("graphql.resolver")

        if key in self._GRAPHQL_ROOTS:
            functions(value)
        elif key.lower().endswith("resolvers"):
            for member in value.named_children:
                inner = member.child_by_field_name("value") if member.type == "pair" else None
                if inner is not None and inner.type == "object":
                    functions(inner)

    # Third-party library / generated-bundle detection: filename conventions
    # plus a content check for minification. Used to suppress the structural
    # ReDoS / prototype-pollution heuristics on non-application code.
    _VENDOR_DIR_RE = re.compile(
        r"/(?:lib|libs|vendor|vendors|plugins?|external|third[_-]?party|"
        r"bower_components|node_modules|jspm_packages|dist|build|min)/", re.I)
    _LIB_NAME_RE = re.compile(
        r"(?:^|[-_.])(?:jquery|jquery-?ui|bootstrap|angular|backbone|underscore|"
        r"lodash|moment|modernizr|d3|react|react-dom|vue|ember|knockout|prototype(?=[-_.]?\d|\.js$|\.min\b|$)|"
        r"mootools|dojo|extjs|tinymce|ckeditor|wysihtml5|select2|datatables|"
        r"highcharts|chartjs|three|ace|requirejs|handlebars|mustache|popper|slick|"
        r"swiper|flatpickr|axios|zepto|hammer|normalize|polyfill)(?:[-_.]|\d|$)",
        re.I)
    _VERSION_IN_NAME_RE = re.compile(r"[-_.]\d+\.\d+")

    def _is_vendored_or_minified(self) -> bool:
        """True for third-party libraries and minified/generated JS bundles."""
        fn = (self._filename or "").replace("\\", "/")
        low = fn.lower()
        if ".min." in low or low.endswith((".bundle.js", ".map")):
            return True
        if self._VENDOR_DIR_RE.search("/" + fn.strip("/") + "/"):
            return True
        base = fn.rsplit("/", 1)[-1]
        if self._VERSION_IN_NAME_RE.search(base) or self._LIB_NAME_RE.search(base):
            return True
        # Content minification: a very long physical line is the reliable signal.
        for line in (self._source or "").splitlines():
            if len(line) > 800:
                return True
        return False

    # Every function-like node becomes its own procedure -- including callbacks
    # and route handlers like `app.post(path, (req,res) => {...})`, which are
    # the dominant entry points in real Node.js/Express code.
    _PROTOTYPE_METHOD = re.compile(r"([A-Za-z_$][\w$]*)\.prototype\.([A-Za-z_$][\w$]*)$")
    _FUNC_NODE_TYPES = (
        "function_declaration", "function_expression", "function",
        "arrow_function", "generator_function", "generator_function_declaration",
        "method_definition",
    )

    def _translate_module(self, root: TSNode, program: Program) -> None:
        """Translate module-level definitions and every nested function.

        First the original top-level handling (named declarations, exports,
        IIFEs), then a recursive sweep that translates any remaining function
        expression -- callbacks, route handlers, object methods, promise
        chains -- as its own procedure so their bodies are analyzed.
        """
        seen_ids = set()
        for child in root.children:
            self._translate_top_level(child, program, seen_ids)
        self._collect_nested_functions(root, program, seen_ids)
        self._translate_module_scope(root, program)
        self._translate_literal_properties(root, program)

    # Top-level node types that are already procedures (or carry no behaviour).
    _MODULE_SCOPE_SKIP = frozenset({
        "function_declaration", "generator_function_declaration",
        "class_declaration", "import_statement", "comment", "empty_statement",
        "hash_bang_line", "interface_declaration", "type_alias_declaration",
        "enum_declaration", "ambient_declaration", "module", "internal_module",
    })

    def _translate_literal_properties(self, root: TSNode, program: Program) -> None:
        """Lower string-literal object properties and class fields
        (``{ password: "..." }``, ``class A { apiKey = "..." }``) so hardcoded
        credentials in config objects reach the literal scanner. Adds no
        sources or sinks, so taint results are unaffected."""
        assigns = []
        stack = [root]
        while stack:
            n = stack.pop()
            stack.extend(n.children)
            if n.type == "pair":
                key, value = n.child_by_field_name("key"), n.child_by_field_name("value")
            elif n.type == "field_definition":
                key, value = n.child_by_field_name("property"), n.child_by_field_name("value")
            else:
                continue
            if key is None or value is None or value.type != "string":
                continue
            if key.type not in ("property_identifier", "string", "private_property_identifier"):
                continue
            name = self._get_text(key).strip("'\"`")
            if name:
                assigns.append(Assign(loc=self._get_location(n), id=PVar(name),
                                      exp=self._translate_expression(value)))
        proc = literal_init_procedure("<literal-properties>",
                                      self._get_location(root), assigns)
        if proc is not None:
            program.add_procedure(proc)

    def _translate_module_scope(self, root: TSNode, program: Program) -> None:
        """Analyze module-level statements as a synthetic ``<module>`` procedure.

        Declarations and calls at file scope never ran through the analysis, so
        a script doing ``execSync('git ' + process.argv[2])`` at top level, or a
        credential literal bound to a top-level ``const``, was invisible. Function
        and class declarations are skipped (they are already their own
        procedures); function expressions nested in statements are translated
        separately by ``_collect_nested_functions``.
        """
        stmts = []
        for child in root.children:
            if child.type == "export_statement":
                # `export const x = ...` -> the declaration; `export default expr`
                # / `export { a }` carry no module-scope statement worth lowering.
                decl = child.child_by_field_name("declaration")
                if decl is not None and decl.type not in self._MODULE_SCOPE_SKIP:
                    stmts.append(decl)
            elif child.type not in self._MODULE_SCOPE_SKIP:
                stmts.append(child)
        if not stmts:
            return

        proc = Procedure(
            name="<module>",
            params=[],
            ret_type=Typ.unknown_type(),
            loc=self._get_location(root),
        )
        self._current_proc = proc
        self._node_counter = 0
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry
        for stmt in stmts:
            self._translate_statement(stmt)
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)
        self._current_proc = None
        program.add_procedure(proc)

    def _collect_nested_functions(self, node: TSNode, program: Program,
                                  seen_ids: set) -> None:
        """Recursively translate every function-like node not already handled."""
        stack = list(node.children)
        while stack:
            cur = stack.pop()
            # Guard with a body field: the bare `function` keyword is also a
            # node of type "function" but has no body, and would otherwise
            # produce an empty procedure that overwrites the real one.
            if (cur.type in self._FUNC_NODE_TYPES and cur.id not in seen_ids
                    and cur.child_by_field_name("body") is not None):
                seen_ids.add(cur.id)
                if cur.type == "method_definition":
                    proc = self._translate_method(cur)
                else:
                    name = self._infer_func_name(cur)
                    # Distinct nested functions (e.g. a route handler and a
                    # .then()/callback arrow inside it) would otherwise both be
                    # 'anonymous' and collide in the procedures dict, silently
                    # overwriting the handler that holds the sink. Disambiguate
                    # by source position (never `node.id`, a memory address that
                    # changes every run and breaks baselines and diffs).
                    if program.has_procedure(name):
                        row, col = cur.start_point
                        name = f"{name}_L{row + 1}"
                        if program.has_procedure(name):
                            name = f"{name}C{col + 1}"
                    # `C.prototype.m = function () {...}` is method m of the
                    # constructor function C, like `class C { m() {} }`.
                    proto = self._PROTOTYPE_METHOD.match(name)
                    proc = self._translate_function(cur, name=name, is_method=bool(proto))
                    if proc and proto:
                        proc.class_name = proto.group(1)
                if proc:
                    program.add_procedure(proc)
            stack.extend(cur.children)

    def _infer_func_name(self, node: TSNode) -> str:
        """Best-effort name for an anonymous function/arrow (from a containing
        declarator, assignment, or object property), else 'anonymous'."""
        name_node = node.child_by_field_name("name")
        if name_node:
            return self._get_text(name_node)
        parent = node.parent
        if parent is not None:
            if parent.type == "variable_declarator":
                nm = parent.child_by_field_name("name")
                if nm:
                    return self._get_text(nm)
            if parent.type == "pair":
                key = parent.child_by_field_name("key")
                if key:
                    return self._get_text(key)
            if parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                if left:
                    return self._get_text(left)
        return "anonymous"

    def _translate_top_level(self, node: TSNode, program: Program,
                             seen_ids: set = None) -> None:
        """Translate a top-level statement"""
        if seen_ids is None:
            seen_ids = set()
        if node.type == "function_declaration":
            seen_ids.add(node.id)
            proc = self._translate_function(node)
            if proc:
                program.add_procedure(proc)

        elif node.type == "class_declaration":
            self._translate_class(node, program, seen_ids)

        elif node.type == "lexical_declaration" or node.type == "variable_declaration":
            # const/let/var declarations - check for function expressions
            self._translate_variable_declaration(node, program, seen_ids)

        elif node.type == "export_statement":
            # Handle exports
            for child in node.children:
                self._translate_top_level(child, program, seen_ids)

        elif node.type == "expression_statement":
            # Check for IIFE or function expressions
            for child in node.children:
                if child.type == "call_expression":
                    func = child.child_by_field_name("function")
                    if func and func.type in ("arrow_function", "function"):
                        seen_ids.add(func.id)
                        proc = self._translate_function(func, name="anonymous")
                        if proc:
                            program.add_procedure(proc)

    def _translate_variable_declaration(self, node: TSNode, program: Program,
                                        seen_ids: set = None) -> None:
        """Translate variable declarations, extracting function expressions"""
        if seen_ids is None:
            seen_ids = set()
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")

                if name_node and value_node:
                    var_name = self._get_text(name_node)
                    if value_node.type in ("arrow_function", "function"):
                        seen_ids.add(value_node.id)
                        proc = self._translate_function(value_node, name=var_name)
                        if proc:
                            program.add_procedure(proc)

    def _translate_class(self, node: TSNode, program: Program,
                         seen_ids: set = None) -> None:
        """Translate class definition"""
        if seen_ids is None:
            seen_ids = set()
        name_node = node.child_by_field_name("name")
        class_name = self._get_text(name_node) if name_node else "UnknownClass"

        self._current_class = class_name

        bases: List[str] = []
        for heritage in (c for c in node.children if c.type == "class_heritage"):
            for clause in heritage.named_children:
                if clause.type in ("extends_clause", "implements_clause"):
                    bases += [self._get_text(c).split("<")[0] for c in clause.named_children
                              if c.type in ("identifier", "type_identifier", "member_expression",
                                            "nested_type_identifier", "generic_type", "call_expression")]
                elif clause.type in ("identifier", "member_expression", "call_expression"):
                    bases.append(self._get_text(clause))     # plain JS: `class A extends B`
        cfields = [self._get_text(f.child_by_field_name("property"))
                   for f in (node.child_by_field_name("body").named_children
                             if node.child_by_field_name("body") is not None else ())
                   if f.type in ("field_definition", "public_field_definition")
                   and f.child_by_field_name("property") is not None
                   or f.type == "public_field_definition" and f.child_by_field_name("name") is not None]
        program.class_info[class_name] = ClassInfo(
            name=class_name, kind="class", bases=bases, fields=cfields,
            canonical_bases=[self._imports.resolve(b) or b for b in bases],
            annotations=[parse_annotation(self._get_text(d), self._imports)
                         for d in self._leading_decorators(node)])

        # Find class body
        body_node = node.child_by_field_name("body")
        if body_node:
            for child in body_node.children:
                if child.type == "method_definition":
                    seen_ids.add(child.id)
                    proc = self._translate_method(child)
                    if proc:
                        proc.class_name = class_name
                        proc.name = f"{class_name}.{proc.name}"
                        program.add_procedure(proc)

                elif child.type == "field_definition":
                    # Check for arrow function fields
                    value = child.child_by_field_name("value")
                    if value and value.type == "arrow_function":
                        name_node = child.child_by_field_name("property")
                        if name_node:
                            seen_ids.add(value.id)
                            method_name = self._get_text(name_node)
                            proc = self._translate_function(value, name=method_name, is_method=True)
                            if proc:
                                proc.class_name = class_name
                                proc.name = f"{class_name}.{proc.name}"
                                program.add_procedure(proc)

        self._current_class = None

    def _translate_method(self, node: TSNode) -> Optional[Procedure]:
        """Translate class method definition"""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None

        method_name = self._get_text(name_node)

        # Get parameters
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = self._translate_parameters(params_node)

        # Create procedure
        proc = Procedure(
            name=method_name,
            params=params,
            ret_type=Typ.unknown_type(),
            loc=self._get_location(node),
            is_method=True,
        )

        # Check for static
        for child in node.children:
            if self._get_text(child) == "static":
                proc.is_static = True
                break

        proc.annotations = [parse_annotation(self._get_text(d), self._imports)
                            for d in self._leading_decorators(node)]
        if params_node is not None:
            for ch in params_node.children:
                if ch.type in ("required_parameter", "optional_parameter"):
                    pat = ch.child_by_field_name("pattern")
                    decs = [self._get_text(d) for d in ch.children if d.type == "decorator"]
                    if pat is not None and pat.type == "identifier" and decs:
                        proc.param_annotations[self._get_text(pat)] = [
                            parse_annotation(d, self._imports) for d in decs]

        return self._translate_function_body(node, proc)

    @staticmethod
    def _leading_decorators(node: TSNode) -> List[TSNode]:
        """Decorators applying to a class or method: its own `decorator` children,
        the decorator nodes just before it in the class body, and (for an
        exported class) those on the `export` statement."""
        found = [c for c in node.children if c.type == "decorator"]
        prev = node.prev_sibling
        while prev is not None and prev.type == "decorator":
            found.insert(0, prev)
            prev = prev.prev_sibling
        if node.parent is not None and node.parent.type == "export_statement":
            found = [c for c in node.parent.children if c.type == "decorator"] + found
        return found

    def _translate_function(
        self,
        node: TSNode,
        name: str = None,
        is_method: bool = False
    ) -> Optional[Procedure]:
        """Translate function/arrow function definition to SIL Procedure"""
        # Get function name
        if name is None:
            name_node = node.child_by_field_name("name")
            if name_node:
                name = self._get_text(name_node)
            else:
                name = "anonymous"

        # Get parameters
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = self._translate_parameters(params_node)

        # For arrow functions, parameter might be a single identifier
        if node.type == "arrow_function" and not params_node:
            param_node = node.child_by_field_name("parameter")
            if param_node:
                param_name = self._get_text(param_node)
                params = [(PVar(param_name), Typ.unknown_type())]

        # Create procedure
        proc = Procedure(
            name=name,
            params=params,
            ret_type=Typ.unknown_type(),
            loc=self._get_location(node),
            is_method=is_method,
        )

        return self._translate_function_body(node, proc)

    def _translate_function_body(self, node: TSNode, proc: Procedure) -> Procedure:
        """Translate function body to SIL"""
        self._current_proc = proc
        self._node_counter = 0

        # Create entry node
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry

        # Find and translate body
        body_node = node.child_by_field_name("body")
        proc.span = (node.start_byte, node.end_byte)
        if body_node is not None:
            own_params = {str(param) for param, _ in proc.params}
            outer = (self._enclosing_param_names(node) | self._enclosing_local_names(node)) - own_params
            proc.captures = sorted(outer & self._referenced_identifiers(body_node))

        # Treat the function's parameters as untrusted input (pure-SL recall
        # lever for real-world JS where the attack surface is exported APIs).
        if self.taint_function_params:
            own = {str(param) for param, _ in proc.params}
            for param, _ in proc.params:
                self._add_instr(TaintSource(
                    loc=proc.loc, var=param,
                    kind=TaintKind.USER_INPUT,
                    description="function parameter (untrusted input)"))
            # A method of a class whose constructor fills fields from its (untrusted)
            # parameters starts with those fields untrusted: an outside caller built the
            # object (`this.options.additional = ['"' + filename + '"']`).
            proto = self._PROTOTYPE_METHOD.match(proc.name or "")
            cls = proto.group(1) if proto else (getattr(self, "_current_class", None) if proc.is_method else None)
            for path in sorted(getattr(self, "_ctor_fields", {}).get(cls, ())):
                self._add_instr(TaintSource(
                    loc=proc.loc, var=PVar(f"this.{path}"), kind=TaintKind.USER_INPUT,
                    description="field set from a constructor parameter (untrusted input)"))

            # Closure capture: a nested function (callback, Promise executor,
            # ...) sees its enclosing functions' parameters AND locals as free
            # variables. In library mode those outer values are untrusted, so the
            # capture carries the taint -- e.g.
            #   function file(req,res){ var fp = path.join(dir, req.url);
            #     fs.exists(fp, () => fs.readFile(fp, cb)); }
            # where the readFile sink sits two callbacks deep from where `fp` is
            # a tainted local. Taint any captured outer name referenced here that
            # this function doesn't shadow with its own parameter.
            enclosing = (self._enclosing_param_names(node)
                         | self._enclosing_local_names(node)) - own
            if enclosing and body_node is not None:
                referenced = self._referenced_identifiers(body_node)
                for nm in sorted(enclosing & referenced):
                    self._add_instr(TaintSource(
                        loc=proc.loc, var=PVar(nm),
                        kind=TaintKind.USER_INPUT,
                        description="captured untrusted variable (closure)"))
        # Express-style request destructuring is a taint source regardless of
        # library mode: `({ body, params, query }: Request, res, next) => ...`.
        # `params.file` is then user-controlled just like `req.params.file`.
        for nm in self._express_request_source_names(node):
            self._add_instr(TaintSource(
                loc=proc.loc, var=PVar(nm), kind=TaintKind.USER_INPUT,
                description="destructured Express request property (user input)"))

        # Closure capture of REQUEST-DERIVED enclosing locals (precise, always on):
        # e.g. `const id = req.body.id` in a handler, then a `.then(r => db.update(
        # { _id: id }, ...))` callback whose only sink sits inside the callback.
        # Unlike library mode this taints only request-derived captures, not all
        # captured names, so it does not add the library-mode false positives.
        if body_node is not None and not self.taint_function_params:
            own = {str(param) for param, _ in proc.params}
            captured = ((self._enclosing_request_derived_locals(node)
                         & self._referenced_identifiers(body_node)) - own)
            for nm in sorted(captured):
                self._add_instr(TaintSource(
                    loc=proc.loc, var=PVar(nm), kind=TaintKind.USER_INPUT,
                    description="captured request-derived variable (closure)"))

        if body_node:
            if body_node.type == "statement_block":
                self._translate_block(body_node)
            else:
                # Arrow function with expression body: () => expr
                self._add_return_value(body_node)

        # Create exit node
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id

        # Connect last node to exit
        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)

        self._current_proc = None
        return proc

    _FUNC_LIKE = {"arrow_function", "function", "function_declaration",
                  "function_expression", "method_definition",
                  "generator_function", "generator_function_declaration"}

    @staticmethod
    def _has_unbounded_quant(body: str) -> bool:
        """True if `body` contains an unescaped unbounded quantifier (*, +, {n,})."""
        i, n = 0, len(body)
        while i < n:
            c = body[i]
            if c == '\\':
                i += 2
                continue
            if c in '*+':
                return True
            if c == '{':
                j = body.find('}', i)
                if j != -1 and ',' in body[i:j]:
                    return True
            i += 1
        return False

    _WORD_CHARS = frozenset('0123456789abcdefghijklmnopqrstuvwxyz'
                            'ABCDEFGHIJKLMNOPQRSTUVWXYZ_')
    _DIGIT_CHARS = frozenset('0123456789')
    _SPACE_CHARS = frozenset(' \t\n\r\f\v')

    @classmethod
    def _expand_class(cls, inner: str) -> frozenset:
        """Expand a char-class body (without [ ]) to its set of chars, resolving
        ranges (a-z) and the common \\d/\\w/\\s escapes."""
        chars = set()
        i = 0
        while i < len(inner):
            c = inner[i]
            if c == '\\' and i + 1 < len(inner):
                e = inner[i + 1]
                chars |= {'d': cls._DIGIT_CHARS, 'w': cls._WORD_CHARS,
                          's': cls._SPACE_CHARS}.get(e, frozenset(e))
                i += 2
                continue
            if (i + 2 < len(inner) and inner[i + 1] == '-'
                    and inner[i + 2] != ']'):
                try:
                    for o in range(ord(c), ord(inner[i + 2]) + 1):
                        chars.add(chr(o))
                except ValueError:
                    pass
                i += 3
                continue
            chars.add(c)
            i += 1
        return frozenset(chars)

    @classmethod
    def _branch_first_set(cls, branch: str):
        """First-character matcher for a regex branch, as a (negated, set) pair;
        set==None means 'matches any character' (the '.' case)."""
        branch = branch.lstrip('^')
        if not branch:
            return (False, frozenset())
        c = branch[0]
        if c == '\\' and len(branch) > 1:
            esc = branch[1]
            pos = {'d': cls._DIGIT_CHARS, 'w': cls._WORD_CHARS,
                   's': cls._SPACE_CHARS}
            if esc in pos:
                return (False, pos[esc])
            if esc == 'D':
                return (True, cls._DIGIT_CHARS)
            if esc == 'W':
                return (True, cls._WORD_CHARS)
            if esc == 'S':
                return (True, cls._SPACE_CHARS)
            return (False, frozenset(esc))
        if c == '.':
            return (False, None)
        if c == '[':
            end = branch.find(']', 2 if branch[1:2] == '^' else 1)
            inner = branch[1:end] if end != -1 else branch[1:]
            if inner.startswith('^'):
                return (True, cls._expand_class(inner[1:]))
            return (False, cls._expand_class(inner))
        if c in '(*+?':
            return (False, None)  # nested group / quantifier -- be conservative
        return (False, frozenset(c))

    @staticmethod
    def _first_sets_overlap(a, b) -> bool:
        """Whether two (negated, set) first-character matchers can match a common
        character."""
        na, sa = a
        nb, sb = b
        if sa is None or sb is None:        # '.' matches anything
            return True
        if not na and not nb:
            return bool(sa & sb)
        if na and nb:
            return True                      # two negated sets always share chars
        # one positive, one negated: positive has a char outside the negated set
        pos, neg = (sa, sb) if not na else (sb, sa)
        return bool(pos - neg)

    def _alternation_overlaps(self, body: str) -> bool:
        """True if a top-level alternation has overlapping branches (so a string
        can be matched more than one way -- the source of catastrophic
        backtracking when the group is quantified)."""
        # Split on top-level '|' (ignore '|' inside nested groups / classes).
        branches, depth, in_class, cur = [], 0, False, []
        i = 0
        while i < len(body):
            ch = body[i]
            if ch == '\\':
                cur.append(body[i:i + 2])
                i += 2
                continue
            if ch == '[':
                in_class = True
            elif ch == ']':
                in_class = False
            elif ch == '(' and not in_class:
                depth += 1
            elif ch == ')' and not in_class:
                depth -= 1
            elif ch == '|' and depth == 0 and not in_class:
                branches.append(''.join(cur))
                cur = []
                i += 1
                continue
            cur.append(ch)
            i += 1
        branches.append(''.join(cur))
        if len(branches) < 2:
            return False
        stripped = [b.lstrip('^') for b in branches]
        sets = [self._branch_first_set(b) for b in branches]
        for a in range(len(branches)):
            for b in range(a + 1, len(branches)):
                (na, sa), (nb, sb) = sets[a], sets[b]
                if sa is None or sb is None or na or nb:
                    # A '.'/negated branch is broad; fall back to set overlap.
                    if self._first_sets_overlap(sets[a], sets[b]):
                        return True
                    continue
                # Two positive branches are ambiguous under a quantifier only
                # when one can be a prefix of the other (a|ab, \d|\d\d) -- sharing
                # just a first character (~0|~1) is disambiguated by later chars.
                if sa & sb and (stripped[a].startswith(stripped[b])
                                or stripped[b].startswith(stripped[a])):
                    return True
        return False

    def redos_patterns(self, source_code: str) -> set:
        """The set of catastrophic-backtracking regex patterns this frontend
        would flag in `source_code` (literals and RegExp(...) string args).
        Exposed so callers can compare a vulnerable vs patched file at the
        regex level -- a static detector cannot observe runtime length-cap
        mitigations, so an unchanged catastrophic regex is not a false flag."""
        self._source_bytes = source_code.encode("utf-8")
        self._source = source_code
        tree = self.parser.parse(self._source_bytes)
        out = set()
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "regex":
                p = n.child_by_field_name("pattern")
                if p is not None:
                    pat = self._get_text(p)
                    if self._is_redos_pattern(pat):
                        out.add(pat)
            elif n.type in ("new_expression", "call_expression"):
                callee = (n.child_by_field_name("constructor")
                          if n.type == "new_expression"
                          else n.child_by_field_name("function"))
                if callee is not None and self._get_text(callee) in ("RegExp", "global.RegExp"):
                    an = n.child_by_field_name("arguments")
                    for child in (an.children if an is not None else []):
                        if child.type in ("string", "template_string"):
                            raw = self._get_text(child)
                            inner = raw[1:-1] if len(raw) >= 2 else raw
                            if self._is_redos_pattern(inner):
                                out.add(inner)
                            break
            stack.extend(n.children)
        return out

    def _is_redos_pattern(self, pattern: str) -> bool:
        """Heuristic detector for super-linear (ReDoS) regex patterns: a group
        that is itself quantified (*, +, {n,}) AND whose body contains an
        unbounded inner quantifier or an alternation -- the classic
        catastrophic-backtracking shape: (a+)+, (.*,)+, (\\d+)*, ([a-z]+)*,
        (a|aa)+, (?:(?:\\s*;\\s*)|x)*. Bracket-matching handles nested groups.
        A plain quantified group like (abc)+ is NOT flagged, keeping precision
        high."""
        if not pattern:
            return False
        n = len(pattern)
        i = 0
        while i < n:
            c = pattern[i]
            if c == '\\':
                i += 2
                continue
            if c == ')':
                nxt = pattern[i + 1] if i + 1 < n else ''
                # NB: use tuple membership, not `nxt in '*+'` -- an empty `nxt`
                # (a group closing at end-of-pattern) is a *substring* of any
                # string, so `'' in '*+'` is True and would treat every
                # pattern-final group like ([^;]+) as quantified (a major ReDoS
                # false-positive source).
                quantified = nxt in ('*', '+', '{')
                if quantified:
                    # Find the matching '(' by backward bracket-matching.
                    depth = 0
                    k = i
                    while k >= 0:
                        ck = pattern[k]
                        escaped = k > 0 and pattern[k - 1] == '\\'
                        if not escaped and ck == ')':
                            depth += 1
                        elif not escaped and ck == '(':
                            depth -= 1
                            if depth == 0:
                                break
                        k -= 1
                    if k >= 0:
                        body = pattern[k + 1:i]
                        for pfx in ('?:', '?=', '?!', '?<=', '?<!'):
                            if body.startswith(pfx):
                                body = body[len(pfx):]
                                break
                        # Catastrophic when the quantified group's body has an
                        # unbounded inner quantifier (nested quantifier, e.g.
                        # (\d+)*) or an overlapping alternation under the
                        # quantifier (e.g. (a|aa)+, (.|x)*, \d|\d\d). A clearly
                        # disjoint alternation like ([a-z0-9]|-)* or (~0|~1)+ is
                        # linear and is not flagged, keeping precision high.
                        if self._has_unbounded_quant(body):
                            return True
                        if '|' in body and self._alternation_overlaps(body):
                            return True
            i += 1
        return False

    def _scan_redos(self, root: TSNode, program: Program) -> None:
        """Whole-file pass: collect every catastrophic-backtracking regex
        (literal or `new RegExp("...")`/`RegExp("...")`) and emit a usage-based
        ReDoS finding for each into a synthetic procedure. Doing this at file
        scope (rather than per-expression) covers module-level regex constants,
        which are where most real-world ReDoS lives."""
        hits = []  # list of Location
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "regex":
                pat = n.child_by_field_name("pattern")
                if pat is not None and self._is_redos_pattern(self._get_text(pat)):
                    hits.append(self._get_location(n))
            elif n.type in ("new_expression", "call_expression"):
                callee = (n.child_by_field_name("constructor")
                          if n.type == "new_expression"
                          else n.child_by_field_name("function"))
                if callee is not None and self._get_text(callee) in ("RegExp", "global.RegExp"):
                    args_node = n.child_by_field_name("arguments")
                    if args_node is not None:
                        for child in args_node.children:
                            if child.type in ("string", "template_string"):
                                raw = self._get_text(child)
                                inner = raw[1:-1] if len(raw) >= 2 else raw
                                if self._is_redos_pattern(inner):
                                    hits.append(self._get_location(n))
                                break
            stack.extend(n.children)

        self._emit_findings_proc(program, "<module-redos>", "__redos__", hits)

    # A genuine guard COMPARES a key against a dangerous name or keeps a denylist
    # -- distinct from merely mentioning __proto__ (which vulnerable code does
    # too, e.g. when it sets that key or in a comment).
    _PROTO_GUARD_RE = re.compile(
        r"""(?x)
        (?:===|!==|==|!=|indexOf|includes|\bhas\b)\s*\(?\s*['"](?:__proto__|constructor|prototype)['"]
        | ['"](?:__proto__|constructor|prototype)['"]\s*(?:===|!==|==|!=)
        | \[[^\]]*['"](?:__proto__|constructor|prototype)['"][^\]]*\]
        """)

    def _scan_proto_pollution(self, root: TSNode, program: Program) -> None:
        """Whole-file pass: flag an unguarded computed-property write
        ``obj[key] = value`` whose key is attacker-influenced (a for-in/for-of
        loop variable, a path element, or -- in library mode -- any non-constant
        key). Prototype pollution (CWE-1321).

        The precision lever mirrors how these CVEs are fixed: a function that
        already checks the key against __proto__/constructor/prototype is treated
        as guarded and not flagged."""
        # Proto-awareness is a file-level signal: a patched module *checks* a key
        # against __proto__/constructor/prototype (the guard often lives in a
        # helper or a module-level denylist, not inline at the write).
        self._proto_guarded = bool(self._PROTO_GUARD_RE.search(self._source))

        hits = []
        stack = [root]
        while stack:
            n = stack.pop()
            stack.extend(n.children)
            if n.type != "assignment_expression":
                continue
            left = n.child_by_field_name("left")
            if left is None or left.type != "subscript_expression":
                continue
            index = left.child_by_field_name("index")
            if index is None or index.type in ("number", "string", "template_string"):
                continue  # constant/numeric key cannot pollute the prototype

            # Is the key attacker-influenced?
            loop_vars = self._enclosing_loop_vars(n)
            counter_vars = self._enclosing_c_for_vars(n)
            key_txt = self._get_text(index)
            params = self._enclosing_param_names(n)
            if index.type == "identifier" and key_txt in counter_vars:
                continue  # numeric C-style for-loop counter -> array index, safe
            # A key that is itself a member/subscript access (obj[item.name],
            # obj[a[i]]) is almost always benign map-building from internal data
            # (serializing form fields, indexing by a record id), not prototype
            # pollution, so it is NOT treated as suspicious on its own. Real
            # pollution flows through a loop/path/param key that could be
            # "__proto__"; attacker-controlled member keys are still caught by the
            # taint-based sinks.
            path_keys = self._enclosing_path_key_vars(n)
            key_like = (
                key_txt in loop_vars
                or key_txt in params
                or key_txt in path_keys
            )
            # `o[keys[i]]` / `o[keys[keys.length - 1]]` where `keys` came from
            # path.split('.'): the classic nested-setter shape (lodash.set, dset).
            # Only an array derived from a split/shift/pop counts; indexing by an
            # arbitrary member/subscript stays benign map-building (see above).
            if not key_like and index.type == "subscript_expression":
                base = index.child_by_field_name("object")
                if base is not None and base.type == "identifier" \
                        and self._get_text(base) in path_keys:
                    key_like = True
            if not key_like:
                continue

            # Guarded? A patched setter checks the key against __proto__/
            # constructor/prototype -- but the check often lives in a helper
            # (isValidKey) or a module-level denylist rather than inline, so a
            # reference anywhere in the file means the code is proto-aware.
            if self._proto_guarded:
                continue

            hits.append(self._get_location(n))

        self._emit_findings_proc(program, "<module-proto-pollution>",
                                 "__proto_pollution__", hits)

    def _enclosing_loop_vars(self, node: TSNode) -> set:
        """Loop variables of every for-in / for-of enclosing `node`."""
        names = set()
        cur = node.parent
        while cur is not None:
            if cur.type in ("for_in_statement", "for_of_statement"):
                left = cur.child_by_field_name("left")
                if left is not None:
                    names |= self._referenced_identifiers(left)
            cur = cur.parent
        return names

    def _enclosing_path_key_vars(self, node: TSNode) -> set:
        """Local variables in the enclosing function that hold a path/key element
        -- assigned from an index expression (keys[i], a[n-1]) or a string split
        (path.split('.')...). Such variables are the keys in nested setters like
        obj[lastKey] = value, a common prototype-pollution shape."""
        fn = self._nearest_enclosing_function(node)
        if fn is None:
            return set()
        names = set()
        stack = [fn]
        while stack:
            cur = stack.pop()
            stack.extend(cur.children)
            target = value = None
            if cur.type == "variable_declarator":
                target = cur.child_by_field_name("name")
                value = cur.child_by_field_name("value")
            elif cur.type == "assignment_expression":
                target = cur.child_by_field_name("left")
                value = cur.child_by_field_name("right")
            if target is None or value is None or target.type != "identifier":
                continue
            vtext = self._get_text(value)
            if (value.type == "subscript_expression"
                    or ".split(" in vtext or ".shift(" in vtext or ".pop(" in vtext):
                names.add(self._get_text(target))
        return names

    def _enclosing_c_for_vars(self, node: TSNode) -> set:
        """Counter variables of enclosing C-style for-loops (for(i=0;...)) -- these
        index numerically and never pollute a prototype."""
        names = set()
        cur = node.parent
        while cur is not None:
            if cur.type == "for_statement":
                init = cur.child_by_field_name("initializer")
                if init is not None:
                    names |= self._referenced_identifiers(init)
            cur = cur.parent
        return names

    def _nearest_enclosing_function(self, node: TSNode) -> Optional[TSNode]:
        cur = node.parent
        while cur is not None:
            if cur.type in self._FUNC_LIKE:
                return cur
            cur = cur.parent
        return None

    def _emit_findings_proc(self, program: Program, name: str,
                            sink_name: str, hits: list) -> None:
        """Add a synthetic procedure holding one usage-sink Call per finding."""
        if not hits:
            return
        proc = Procedure(name=name, params=[], ret_type=Typ.unknown_type(),
                         loc=hits[0], is_method=False)
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        for loc in hits:
            entry.add_instr(Call(loc=loc, ret=None,
                                 func=ExpConst.string(sink_name), args=[]))
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        proc.connect(entry.id, exit_node.id)
        program.add_procedure(proc)

    def _request_derived_names(self, func_node: TSNode) -> set:
        """Names in a function that are request-derived: destructured request
        properties plus locals initialized from a request source (small fixpoint).
        These are the values whose interprocedural flow we track."""
        names = set(self._express_request_source_names(func_node))
        body = func_node.child_by_field_name("body")
        if body is None:
            return names
        for _ in range(4):
            added = False
            stack = [body]
            while stack:
                c = stack.pop()
                if c.type == "variable_declarator":
                    nm = c.child_by_field_name("name")
                    init = c.child_by_field_name("value")
                    if (nm is not None and nm.type == "identifier" and init is not None):
                        name = self._get_text(nm)
                        if name not in names:
                            chain = self._get_member_chain(init)
                            refs = self._referenced_identifiers(init)
                            if ((chain and (chain.startswith("req.") or chain.startswith("request.")))
                                    or (refs & names)):
                                names.add(name)
                                added = True
                stack.extend(c.children)
            if not added:
                break
        return names

    def _collect_js_calls(self, node: TSNode, calls: list) -> None:
        """Collect bare-identifier calls: (callee_name, [ids-per-arg])."""
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "identifier":
                callee = self._get_text(fn)
                args = node.child_by_field_name("arguments")
                arg_ids = []
                if args is not None:
                    for a in args.children:
                        if a.type in ("(", ")", ","):
                            continue
                        arg_ids.append(self._referenced_identifiers(a))
                calls.append((callee, arg_ids))
        for ch in node.children:
            self._collect_js_calls(ch, calls)

    def _propagate_js_interprocedural(self, root: TSNode, program: Program) -> None:
        """Taint a same-file function's parameter when a caller passes it a
        request-derived value (one hop). Mirrors the Java pass; recovers e.g.
        `verify(file)` where a handler derived `file` from the request."""
        procs_by_name: Dict[str, Any] = {}
        for p in program.procedures.values():
            procs_by_name.setdefault(p.name, p)
            procs_by_name.setdefault(p.name.split(".")[-1], p)

        func_nodes = []
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type in self._FUNC_LIKE:
                func_nodes.append(n)
            stack.extend(n.children)

        to_taint: Dict[str, set] = {}
        for fn in func_nodes:
            derived = self._request_derived_names(fn)
            if not derived:
                continue
            body = fn.child_by_field_name("body")
            if body is None:
                continue
            calls: list = []
            self._collect_js_calls(body, calls)
            for callee, arg_ids in calls:
                cproc = procs_by_name.get(callee)
                if cproc is None:
                    continue
                for j, ids in enumerate(arg_ids):
                    if (ids & derived) and j < len(cproc.params):
                        to_taint.setdefault(cproc.name, set()).add(j)

        for pname, idxs in to_taint.items():
            proc = procs_by_name.get(pname)
            if proc is None or proc.entry_node is None:
                continue
            entry = proc.nodes.get(proc.entry_node)
            if entry is None:
                continue
            for j in sorted(idxs):
                if j >= len(proc.params):
                    continue
                pv = proc.params[j][0]
                entry.instrs.insert(0, TaintSource(
                    loc=proc.loc, var=pv, kind=TaintKind.USER_INPUT,
                    description="Interprocedural: request-derived argument from caller"))

    def _func_param_names(self, func_node: TSNode) -> set:
        """Identifier names of a function node's formal parameters."""
        names = set()
        params = func_node.child_by_field_name("parameters")
        if params is not None:
            for child in params.children:
                if child.type == "identifier":
                    names.add(self._get_text(child))
                elif child.type in ("required_parameter", "optional_parameter"):
                    pat = child.child_by_field_name("pattern")
                    if pat is not None:
                        names.add(self._get_text(pat))
                elif child.type == "assignment_pattern":
                    left = child.child_by_field_name("left")
                    if left is not None:
                        names.add(self._get_text(left))
        else:
            # Arrow with a single bare identifier parameter: x => ...
            for child in func_node.children:
                if child.type == "identifier":
                    names.add(self._get_text(child))
                    break
        return names

    def _enclosing_param_names(self, node: TSNode) -> set:
        """Parameter names of every function lexically enclosing `node`."""
        names = set()
        cur = node.parent
        while cur is not None:
            if cur.type in self._FUNC_LIKE:
                names |= self._func_param_names(cur)
            cur = cur.parent
        return names

    def _enclosing_local_names(self, node: TSNode) -> set:
        """Local (var/let/const) names declared in functions enclosing `node`.
        These are captured free variables in a nested function; in library mode
        an outer local often holds attacker-derived data (e.g. a filepath built
        from req.url) that flows into a sink several callbacks deep."""
        names = set()
        cur = node.parent
        while cur is not None:
            if cur.type in self._FUNC_LIKE:
                body = cur.child_by_field_name("body")
                if body is not None:
                    stack = [body]
                    while stack:
                        c = stack.pop()
                        if c.type == "variable_declarator":
                            nm = c.child_by_field_name("name")
                            if nm is not None and nm.type == "identifier":
                                names.add(self._get_text(nm))
                        stack.extend(c.children)
            cur = cur.parent
        return names

    @staticmethod
    def _link_enclosing_procedures(program: Program) -> None:
        """Set `Procedure.parent` to the innermost procedure whose source range
        contains a nested function's, so its captured variables can take the
        enclosing procedure's taint."""
        spans = [(p.span, name) for name, p in program.procedures.items() if p.span]
        for name, proc in program.procedures.items():
            if not proc.span or not proc.captures:
                continue
            best = None
            for span, other in spans:
                if other == name:
                    continue
                if span[0] <= proc.span[0] and proc.span[1] <= span[1] and span != proc.span:
                    if best is None or (span[1] - span[0]) < (best[0][1] - best[0][0]):
                        best = (span, other)
            proc.parent = best[1] if best else None

    def _enclosing_request_derived_locals(self, node: TSNode) -> set:
        """Enclosing-function locals whose initializer is request-derived.

        A local is request-derived if its initializer references `req.`/`request.`,
        a destructured request property bound in the same function, or another
        request-derived local (small fixpoint). These stay tainted when captured
        by a nested callback -- without tainting every captured name.
        """
        names: set = set()
        cur = node.parent
        while cur is not None:
            if cur.type in self._FUNC_LIKE:
                req_names = set(self._express_request_source_names(cur))
                body = cur.child_by_field_name("body")
                if body is not None:
                    for _ in range(4):  # fixpoint for chained locals
                        added = False
                        stack = [body]
                        while stack:
                            c = stack.pop()
                            if c.type == "variable_declarator":
                                nm = c.child_by_field_name("name")
                                init = c.child_by_field_name("value")
                                if (nm is not None and nm.type == "identifier"
                                        and init is not None):
                                    name = self._get_text(nm)
                                    if name not in req_names:
                                        refs = self._referenced_identifiers(init)
                                        chain = self._get_member_chain(init)
                                        if ((chain and (chain.startswith("req.")
                                                        or chain.startswith("request.")))
                                                or (refs & req_names)
                                                or ("req" in refs) or ("request" in refs)):
                                            req_names.add(name)
                                            added = True
                            stack.extend(c.children)
                        if not added:
                            break
                names |= req_names
            cur = cur.parent
        return names

    def _referenced_identifiers(self, node: TSNode) -> set:
        """All identifier names referenced in a subtree (bounded walk)."""
        refs = set()
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type in ("identifier", "shorthand_property_identifier"):
                refs.add(self._get_text(cur))
            stack.extend(cur.children)
        return refs

    def _express_request_source_names(self, node: TSNode) -> set:
        """Names bound by destructuring an Express Request handler parameter.

        Recognizes handlers like ``({ body, params, query }: Request, res, next)``
        -- returns the destructured request-property names so they can be marked
        as taint sources. Only fires when the function looks like a request
        handler (a `Request`-typed param, or a sibling `res`/`response`/`next`),
        keeping it precise.
        """
        params_node = node.child_by_field_name("parameters")
        if params_node is not None:
            param_children = list(params_node.children)
        else:
            single = node.child_by_field_name("parameter")
            param_children = [single] if single is not None else []

        destructured: List[TSNode] = []
        is_handler = False
        for ch in param_children:
            if ch.type == "identifier":
                if self._get_text(ch) in ("res", "response", "next"):
                    is_handler = True
            elif ch.type in ("required_parameter", "optional_parameter"):
                typ = ch.child_by_field_name("type")
                if typ is not None and "Request" in self._get_text(typ):
                    is_handler = True
                pat = ch.child_by_field_name("pattern")
                if pat is not None and pat.type == "object_pattern":
                    destructured.append(pat)
                elif pat is not None and pat.type == "identifier" and \
                        self._get_text(pat) in ("res", "response", "next"):
                    is_handler = True
            elif ch.type == "object_pattern":
                destructured.append(ch)

        names: set = set()
        if not is_handler:
            return names
        for pat in destructured:
            for c in pat.children:
                nm = None
                if c.type == "shorthand_property_identifier_pattern":
                    nm = self._get_text(c)
                elif c.type == "pair_pattern":
                    v = c.child_by_field_name("value")
                    if v is not None:
                        nm = self._get_text(v)
                if nm and nm in _request_objects().client_properties:     # specs/data/request-objects.toml
                    names.add(nm)
        return names

    def _translate_parameters(self, node: TSNode) -> List[Tuple[PVar, Typ]]:
        """Translate function parameters"""
        params = []
        for child in node.children:
            if child.type == "identifier":
                param_name = self._get_text(child)
                params.append((PVar(param_name), Typ.unknown_type()))

            elif child.type == "required_parameter" or child.type == "optional_parameter":
                # TypeScript parameter
                pattern = child.child_by_field_name("pattern")
                if pattern:
                    param_name = self._get_text(pattern)
                    params.append((PVar(param_name), Typ.unknown_type()))

            elif child.type == "assignment_pattern":
                # Default parameter: name = value
                left = child.child_by_field_name("left")
                if left:
                    param_name = self._get_text(left)
                    params.append((PVar(param_name), Typ.unknown_type()))

            elif child.type == "rest_pattern":
                # ...args
                for c in child.children:
                    if c.type == "identifier":
                        param_name = self._get_text(c)
                        params.append((PVar(param_name), Typ.list_of(Typ.unknown_type())))

            elif child.type == "object_pattern":
                # Destructured parameter: { a, b }
                for c in child.children:
                    if c.type == "shorthand_property_identifier_pattern":
                        param_name = self._get_text(c)
                        params.append((PVar(param_name), Typ.unknown_type()))
                    elif c.type == "pair_pattern":
                        value = c.child_by_field_name("value")
                        if value:
                            param_name = self._get_text(value)
                            params.append((PVar(param_name), Typ.unknown_type()))

        return params

    def _translate_block(self, node: TSNode) -> None:
        """Translate a block of statements"""
        for child in node.children:
            if child.type not in ("{", "}"):
                self._translate_statement(child)

    # A chat message whose role sets the model's instructions (`{ role: "system", content: x }`,
    # the OpenAI chat format): lowered as a call constructing a system message, as the Python
    # frontend does, so a pack can make its content a prompt sink.
    SYSTEM_MESSAGE_CALL = "<chat-system-message>"
    _SYSTEM_ROLES = frozenset({"system", "developer"})
    _NESTED_SCOPES = frozenset({"arrow_function", "function_expression", "function", "function_declaration",
                                "generator_function", "generator_function_declaration", "method_definition",
                                "class", "class_declaration"})

    def _system_message_instrs(self, stmt: TSNode) -> List[Instr]:
        out: List[Instr] = []
        stack = [stmt]
        while stack:
            n = stack.pop()
            if n.type in self._NESTED_SCOPES:
                continue
            if n.type == "object":
                role = content = None
                for pair in n.named_children:
                    if pair.type != "pair":
                        continue
                    k, v = pair.child_by_field_name("key"), pair.child_by_field_name("value")
                    if k is None or v is None:
                        continue
                    key = self._get_text(k).strip("\"'")
                    if key == "role":
                        role = self._get_text(v)[1:-1] if v.type == "string" else None
                    elif key == "content":
                        content = v
                if role in self._SYSTEM_ROLES and content is not None:
                    out.append(Call(loc=self._get_location(content), ret=None,
                                    func=ExpConst.string(self.SYSTEM_MESSAGE_CALL),
                                    args=[(self._translate_expression(content), Typ.unknown_type())]))
            stack.extend(reversed(n.children))
        return out

    def _translate_statement(self, node: TSNode) -> None:
        """Translate a single statement"""
        if node.type in ("expression_statement", "lexical_declaration", "variable_declaration", "return_statement"):
            self._add_instrs(self._system_message_instrs(node))
        if node.type == "expression_statement":
            self._translate_expression_statement(node)

        elif node.type == "lexical_declaration" or node.type == "variable_declaration":
            self._translate_var_declaration(node)

        elif node.type == "return_statement":
            self._translate_return(node)

        elif node.type == "if_statement":
            self._translate_if(node)

        elif node.type == "while_statement":
            self._translate_while(node)

        elif node.type == "for_statement":
            self._translate_for(node)

        elif node.type == "for_in_statement" or node.type == "for_of_statement":
            self._translate_for_in(node)

        elif node.type == "try_statement":
            self._translate_try(node)

        elif node.type == "switch_statement":
            self._translate_switch(node)

        elif node.type == "throw_statement":
            self._translate_throw(node)

    def _translate_expression_statement(self, node: TSNode) -> None:
        """Translate expression statement"""
        for child in node.children:
            child = self._unwrap_await(child)
            if child.type == "call_expression":
                instrs = self._translate_call_expr(child)
                self._add_instrs(instrs)

            elif child.type == "assignment_expression":
                self._translate_assignment(child)

            elif child.type == "update_expression":
                self._translate_update(child)

            elif child.type == "augmented_assignment_expression":
                self._translate_augmented_assignment(child)

            elif child.type == "new_expression":
                # A bare `new Function(userCode)` statement is a sink; translating
                # the expression emits the TaintSink as a side effect.
                self._translate_expression(child)

    def _translate_destructuring(self, pattern: TSNode, value_node: TSNode,
                                 loc: Location) -> None:
        """`const {id, cmd} = req.query` / `const [a, b] = f()`: each bound name
        is an Assign of its part of the value (`id = req.query.id`), with the
        value's taint. Unlowered, the bindings were never assigned and a
        destructured request field reached sinks untainted."""
        value_node = self._unwrap_await(value_node)
        src_node = None
        if value_node.type == "call_expression":
            base_name = f"$destr{self._ident_counter}"
            self._ident_counter += 1
            self._add_instrs(self._translate_call_assignment(base_name, value_node, loc))
            base: Exp = ExpVar(PVar(base_name))
        else:
            base = self._translate_expression(value_node)
            src_node = value_node
        self._bind_pattern(pattern, base, src_node, loc)

    def _bind_pattern(self, pattern: TSNode, base: Exp, src_node: Optional[TSNode],
                      loc: Location) -> None:
        t = pattern.type
        if t in ("identifier", "shorthand_property_identifier_pattern"):
            name = self._get_text(pattern)
            self._add_instr(Assign(loc=loc, id=PVar(name), exp=base))
            if src_node is not None:
                self._add_instrs(self._check_expression_for_taint_source(src_node, name, loc))
        elif t in ("assignment_pattern", "object_assignment_pattern"):
            left = pattern.child_by_field_name("left")
            if left is not None:
                self._bind_pattern(left, base, src_node, loc)
        elif t == "rest_pattern":
            for c in pattern.named_children:
                self._bind_pattern(c, base, src_node, loc)
        elif t == "object_pattern":
            for prop in pattern.named_children:
                if prop.type == "pair_pattern":
                    key = prop.child_by_field_name("key")
                    val = prop.child_by_field_name("value")
                    if key is not None and val is not None:
                        self._bind_pattern(val, ExpFieldAccess(base, self._get_text(key).strip("'\"")),
                                           src_node, loc)
                elif prop.type == "rest_pattern":
                    self._bind_pattern(prop, base, src_node, loc)
                elif prop.type in ("shorthand_property_identifier_pattern",
                                   "object_assignment_pattern"):
                    name_node = prop if prop.type != "object_assignment_pattern" \
                        else prop.child_by_field_name("left")
                    if name_node is not None:
                        self._bind_pattern(
                            prop, ExpFieldAccess(base, self._get_text(name_node)), src_node, loc)
        elif t == "array_pattern":
            for i, el in enumerate(c for c in pattern.named_children if c.type != "comment"):
                self._bind_pattern(el, ExpIndex(base, ExpConst.integer(i)), src_node, loc)

    @staticmethod
    def _unwrap_await(node: TSNode) -> TSNode:
        """`await f(x)` (or `(await f(x))`) is the call `f(x)` for lowering:
        the promise's resolved value is the call's result. Without this the
        awaited call in `const r = await db.query(q)` was an opaque Assign."""
        while node is not None and node.type in ("await_expression",
                                                 "parenthesized_expression"):
            inner = [c for c in node.named_children if c.type != "comment"]
            if len(inner) != 1:
                break
            node = inner[0]
        return node

    def _translate_var_declaration(self, node: TSNode) -> None:
        """Translate variable declaration: const/let/var x = value"""
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")

                if not name_node:
                    continue

                target_name = self._get_text(name_node)
                loc = self._get_location(child)

                if value_node and name_node.type in ("object_pattern", "array_pattern"):
                    self._translate_destructuring(name_node, value_node, loc)
                    continue

                if value_node:
                    value_node = self._unwrap_await(value_node)
                    if value_node.type == "call_expression":
                        instrs = self._translate_call_assignment(target_name, value_node, loc)
                        self._add_instrs(instrs)
                    elif value_node.type == "template_string":
                        instrs = self._translate_template_assignment(target_name, value_node, loc)
                        self._add_instrs(instrs)
                    else:
                        exp = self._translate_expression(value_node)
                        self._add_instr(Assign(loc=loc, id=PVar(target_name), exp=exp))
                        # Check if this is a property access that's a taint source
                        taint_instrs = self._check_expression_for_taint_source(value_node, target_name, loc)
                        self._add_instrs(taint_instrs)
                else:
                    # Uninitialized variable
                    self._add_instr(Assign(loc=loc, id=PVar(target_name), exp=ExpConst.null()))

    def _translate_assignment(self, node: TSNode) -> None:
        """Translate assignment expression: target = value"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        if not left or not right:
            return

        target_name = self._get_text(left)
        loc = self._get_location(node)
        right = self._unwrap_await(right)

        if right.type == "call_expression":
            instrs = self._translate_call_assignment(target_name, right, loc)
            self._add_instrs(instrs)
        elif right.type == "template_string":
            instrs = self._translate_template_assignment(target_name, right, loc)
            self._add_instrs(instrs)
        else:
            exp = self._translate_expression(right)
            self._add_instr(Assign(loc=loc, id=PVar(target_name), exp=exp))
            # Check if this expression contains a taint source
            taint_instrs = self._check_expression_for_taint_source(right, target_name, loc)
            self._add_instrs(taint_instrs)

        # Assignment to a sink property (e.g. `el.innerHTML = x`, `script.src = x`)
        # flows the right-hand value into a taint sink. We sink on the assigned
        # target, which carries the right-hand side's taint via the source check
        # above (inline sources) or assignment propagation (already-tainted
        # vars). The taint engine then reports it only when that value is
        # actually attacker-tainted; a constant right-hand side stays untainted.
        sink_spec = self._assignment_sink_spec(left)
        if sink_spec and sink_spec.is_sink in ("html", "xss") and right.type in ("object", "array") \
                and self._get_text(left).rsplit(".", 1)[-1] == "body":
            sink_spec = None            # `ctx.body = { q }` is serialised as JSON, not sent as HTML
        if sink_spec:
            self._add_instr(TaintSink(
                loc=loc,
                exp=ExpVar(PVar(target_name)),
                kind=_get_sink_kind(sink_spec.is_sink),
                description=sink_spec.description,
            ))

    def _assignment_sink_spec(self, left_node: TSNode):
        """Return the sink ProcSpec if an assignment target is a known sink
        property (e.g. ``el.innerHTML``, ``script.src``), else None.

        Matches the full member chain, its suffixes, and the bare property
        name against the taint specs (mirroring call-sink suffix matching).
        """
        if left_node is None or left_node.type != "member_expression":
            return None

        prop_node = left_node.child_by_field_name("property")
        prop_name = self._get_text(prop_node) if prop_node else ""
        chain = self._get_member_chain(left_node) or ""

        candidates = [chain]
        if "." in chain:
            parts = chain.split(".")
            candidates += [".".join(parts[i:]) for i in range(1, len(parts))]
        candidates.append(prop_name)

        for key in candidates:
            spec = self.specs.get(key)
            if (spec and spec.is_taint_sink()
                    and spec.is_sink not in self._CALL_ONLY_SINK_KINDS
                    and not spec.global_only and not spec.db_method):
                return spec
        return None

    def _arg_qualified_spec(self, func_name: str, call_node: Optional[TSNode]):
        """Specs keyed on the call's first string argument -- `crypto.createHash('md5')`,
        `createCipheriv('des...` (a prefix) -- for the weak-algorithm sinks."""
        if call_node is None:
            return None
        table = self.__dict__.get("_qualified_table")
        if table is None:
            table = {}
            for key, spec in self.specs.items():
                name, sep, rest = key.partition("('")
                if sep:
                    table.setdefault(name, []).append((rest.rstrip("')").lower(), spec))
            self._qualified_table = table
        if not table:
            return None
        args = self._get_call_args(call_node)
        if not args or args[0].type != "string":
            return None
        value = self._get_text(args[0]).strip("'\"`").lower()
        parts = func_name.split(".")
        for i in range(len(parts)):
            for prefix, spec in table.get(".".join(parts[i:]), ()):
                if value.startswith(prefix):
                    return spec
        return None

    # js-yaml: `load(text, { schema: JSON_SCHEMA })` (or the safe / core / failsafe schemas)
    # cannot construct arbitrary objects, so it is not an unsafe-deserialization sink.
    _YAML_SAFE_SCHEMA_RE = re.compile(r"\b(?:JSON_SCHEMA|CORE_SCHEMA|FAILSAFE_SCHEMA|DEFAULT_SAFE_SCHEMA|SAFE_SCHEMA)\b")

    def _safe_yaml_load(self, func_name: str, call_node: Optional[TSNode]) -> bool:
        if call_node is None or func_name.rsplit(".", 1)[-1] != "load" or "yaml" not in func_name.lower():
            return False
        args = self._get_call_args(call_node)
        return len(args) > 1 and bool(self._YAML_SAFE_SCHEMA_RE.search(self._get_text(args[1])))

    def _lookup_call_spec(self, func_name: str, call_node: Optional[TSNode] = None):
        qualified = self._arg_qualified_spec(func_name, call_node)
        if qualified is not None:
            return qualified
        spec = self._lookup_call_spec_by_name(func_name)
        if not db_method_applies(spec, func_name, self._receiver_kind(call_node)):
            return None
        return spec

    def _lookup_call_spec_by_name(self, func_name: str):
        """Spec for a call, trying suffixes of a member chain
        (`models.sequelize.query` -> `sequelize.query` -> `query`). A
        `global_only` spec matched through a suffix needs the rest of the chain
        to be the global object: `window.setTimeout` is the timer,
        `self.req.setTimeout` is a method that happens to share its name."""
        spec = self.specs.get(func_name)
        if spec or '.' not in func_name:
            return spec
        parts = func_name.split('.')
        for i in range(1, len(parts)):
            spec = self.specs.get('.'.join(parts[i:]))
            if spec:
                if spec.global_only and not self._may_be_global('.'.join(parts[:i])):
                    return None
                return spec
        return None

    def _may_be_global(self, receiver: str) -> bool:
        """Can `receiver` be the global object (or a module bound outside this
        file)? Yes for window/global/globalThis and for a bare name the file
        never declares; no for a local, parameter, function or class, for a
        member chain (`self.req`), and for a literal (`/re/`)."""
        if receiver in GLOBAL_OBJECTS:
            return True
        return receiver.isidentifier() and receiver not in getattr(self, "_declared_names", {})

    # -- what kind of value a receiver is (for db_method specs) ------------------

    # Node core modules hand out hashes, buffers, streams and handles of their
    # own -- never a database collection; nor do the in-memory collection
    # utilities, whose find / remove operate on arrays and objects.
    _NODE_CORE_MODULES = frozenset({
        "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
        "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs",
        "fs/promises", "http", "http2", "https", "inspector", "module", "net", "os",
        "path", "perf_hooks", "process", "punycode", "querystring", "readline",
        "repl", "stream", "string_decoder", "timers", "tls", "tty", "url", "util",
        "v8", "vm", "wasi", "worker_threads", "zlib"})
    _IN_MEMORY_LIBS = frozenset({"lodash", "lodash-es", "lodash/fp", "underscore", "ramda"})
    # A call of one of these methods returns a database handle (`db.collection
    # ('users')`, `mongoose.model('User', schema)`).
    _DB_HANDLE_FACTORIES = frozenset({"collection", "model"})
    # Methods that return a value of the receiver's own kind.
    _ARRAY_TO_ARRAY = frozenset({"map", "filter", "slice", "concat", "splice", "flat",
                                 "flatMap", "sort", "reverse", "fill", "copyWithin", "toSorted",
                                 "toReversed", "toSpliced", "with"})
    _STRING_TO_STRING = frozenset({"toString", "trim", "trimStart", "trimEnd", "toLowerCase",
                                   "toUpperCase", "replace", "replaceAll", "slice", "substring",
                                   "substr", "padStart", "padEnd", "repeat", "normalize",
                                   "charAt", "concat", "toLocaleLowerCase", "toLocaleUpperCase"})
    # String methods no database driver or common container shares, so the
    # result kind does not depend on knowing the receiver.
    _STRING_ONLY_METHODS = {"split": "Array", "toLowerCase": "String", "toUpperCase": "String",
                            "trim": "String", "trimStart": "String", "trimEnd": "String",
                            "padStart": "String", "padEnd": "String", "charAt": "String",
                            "toLocaleLowerCase": "String", "toLocaleUpperCase": "String"}
    _GLOBAL_CONSTRUCTOR_KINDS = {"Array": "Array", "Map": "Map", "Set": "Set", "WeakMap": "Map",
                                 "WeakSet": "Set", "RegExp": "RegExp", "String": "String",
                                 "Number": "Number", "Boolean": "Boolean", "Date": "Date",
                                 "Promise": "Promise", "Error": "Error", "URL": "URL",
                                 "URLSearchParams": "URLSearchParams", "Buffer": "Buffer"}
    _GLOBAL_FACTORIES = {"Array.from": "Array", "Array.of": "Array", "Object.keys": "Array",
                         "Object.values": "Array", "Object.entries": "Array",
                         "Object.assign": "Object", "Object.create": "Object",
                         "JSON.parse": "Object", "Buffer.from": "Buffer", "Buffer.alloc": "Buffer",
                         "Buffer.concat": "Buffer", "String": "String", "Number": "Number"}

    def _module_kind(self, module: str) -> Optional[str]:
        """Kind of the values a module hands out, if it is known not to be a
        database driver; None for anything else (a relative `./models/user`
        may well export a Mongoose model)."""
        if module in self._NODE_CORE_MODULES or module.split("/")[0] in self._NODE_CORE_MODULES:
            return f"module:{module}"
        if module in self._IN_MEMORY_LIBS or module.startswith("lodash."):
            return f"module:{module}"
        return None

    def _value_kind(self, node: Optional[TSNode], depth: int = 0) -> Optional[str]:
        """What kind of value an expression is, as far as the file shows:
        "Array", "String", "Object", "Function", a `module:` value, an
        instance (`new:X`), DB_HANDLE, or None when unknown. Follows a name to
        its lexically resolved initializer (`_resolve_binding`) and a property
        to its value in an object literal bound to a name."""
        if node is None or depth > 6:
            return None
        t = node.type
        literal = {"array": "Array", "string": "String", "template_string": "String",
                   "number": "Number", "regex": "RegExp", "true": "Boolean", "false": "Boolean",
                   "object": "Object", "arrow_function": "Function", "function": "Function",
                   "function_expression": "Function", "class": "Function"}
        if t in literal:
            return literal[t]
        if t == "parenthesized_expression" and node.named_child_count == 1:
            return self._value_kind(node.named_children[0], depth + 1)
        if t == "new_expression":
            ctor = node.child_by_field_name("constructor")
            name = self._get_text(ctor) if ctor is not None else ""
            return self._GLOBAL_CONSTRUCTOR_KINDS.get(name, f"new:{name}")
        if t == "identifier":
            name = self._get_text(node)
            module = getattr(self, "_module_aliases", {}).get(name)
            if module is not None:
                return self._module_kind(module)
            bound = self._resolve_binding(node)
            return self._value_kind(bound, depth + 1) if bound is not None else None
        if t == "member_expression":
            obj, prop = node.child_by_field_name("object"), node.child_by_field_name("property")
            if obj is None or prop is None:
                return None
            obj_kind = self._value_kind(obj, depth + 1)
            if obj_kind and obj_kind.startswith("module:"):
                return obj_kind              # `crypto.webcrypto`, `fs.promises`
            if obj.type == "identifier":
                value = self._resolve_binding(obj)
                if value is not None and value.type == "object":
                    return self._value_kind(self._object_property(value, self._get_text(prop)), depth + 1)
            return None
        if t == "call_expression":
            return self._call_result_kind(node, depth)
        return None

    def _call_result_kind(self, call: TSNode, depth: int) -> Optional[str]:
        func = call.child_by_field_name("function")
        if func is None:
            return None
        name = self._get_call_name(call)
        if name in self._GLOBAL_FACTORIES and not self._declared_names.get(name.split(".")[0]):
            return self._GLOBAL_FACTORIES[name]
        if func.type == "member_expression":
            obj, prop = func.child_by_field_name("object"), func.child_by_field_name("property")
            method = self._get_text(prop) if prop is not None else ""
            if method in self._DB_HANDLE_FACTORIES:
                return DB_HANDLE
            obj_kind = self._value_kind(obj, depth + 1)
            if obj_kind and obj_kind.startswith("module:"):
                return obj_kind              # anything a core module computes
            if obj_kind == "Array" and method in self._ARRAY_TO_ARRAY:
                return "Array"
            if obj_kind == "String":
                if method == "split" or method == "match":
                    return "Array"
                if method in self._STRING_TO_STRING:
                    return "String"
            # Methods only strings have: whatever the receiver, the result
            # kind is known (`q.split(',')` is an array).
            if method in self._STRING_ONLY_METHODS:
                return self._STRING_ONLY_METHODS[method]
            return None
        # `createHash('md5')` imported from a core module.
        module = name.split(".")[0] if "." in name else None
        if module is not None and name in getattr(self, "_imported_names", {}).values():
            return self._module_kind(module)
        return None

    def _object_property(self, obj: TSNode, key: str) -> Optional[TSNode]:
        for pair in obj.named_children:
            if pair.type == "pair":
                k = pair.child_by_field_name("key")
                if k is not None and self._get_text(k).strip("'\"") == key:
                    return pair.child_by_field_name("value")
        return None

    def _receiver_kind(self, call_node: Optional[TSNode]) -> Optional[str]:
        """Kind of the object a method call is made on (see _value_kind):
        RECEIVER_UNKNOWN when nothing is known, None for a call with no
        receiver at all. A call whose first argument is a function literal is
        also told apart: a
        database query is data, never code, so `xs.find(x => ...)` is an
        in-memory search whatever `xs` is."""
        if call_node is None:
            return None
        func = call_node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            return None
        args = self._get_call_args(call_node)
        if args and args[0].type in ("arrow_function", "function", "function_expression"):
            return "callback-search"
        return self._value_kind(func.child_by_field_name("object")) or RECEIVER_UNKNOWN

    _FUNCTION_SCOPES = frozenset({"function_declaration", "function_expression", "function",
                                  "arrow_function", "method_definition",
                                  "generator_function_declaration", "generator_function",
                                  "program"})

    def _resolve_binding(self, ident: TSNode) -> Optional[TSNode]:
        """The initializer an identifier refers to, resolved lexically: the
        nearest enclosing function scope that declares the name (a variable or
        a parameter) is its scope; the binding is known only if that scope
        declares it exactly once, as `const/let/var x = e`, and nothing in the
        scope assigns it again. Block scoping is not modelled, so two
        declarations in one function make the name unknown."""
        name = self._get_text(ident)
        scope = ident.parent
        cache = self.__dict__.setdefault("_binding_cache", {})
        while scope is not None:
            if scope.type in self._FUNCTION_SCOPES:
                key = (scope.start_byte, scope.end_byte, name)
                if key not in cache:
                    cache[key] = self._scope_binding(scope, name)
                found, value = cache[key]
                if found:
                    return value
            scope = scope.parent
        return None

    def _scope_binding(self, scope: TSNode, name: str):
        """(declared here?, initializer or None) for `name` in one scope."""
        decls, assigned = [], False
        params = scope.child_by_field_name("parameters") or scope.child_by_field_name("parameter")
        if params is not None:
            for x in [params] + self._descendants_js(params):
                if x.type == "identifier" and self._get_text(x) == name:
                    decls.append(None)
        if scope.type in ("function_declaration", "generator_function_declaration"):
            pass  # the function's own name belongs to the enclosing scope
        stack = list(scope.named_children)
        while stack:
            n = stack.pop()
            if n.type in self._FUNCTION_SCOPES:
                # A nested function: its declarations are its own, but an
                # assignment there to our variable still changes it.
                if n.type in ("function_declaration", "generator_function_declaration"):
                    fname = n.child_by_field_name("name")
                    if fname is not None and self._get_text(fname) == name:
                        decls.append(None)
                if self._assigns(n, name) and not self._declares(n, name):
                    assigned = True
                continue
            if n.type == "variable_declarator":
                nm = n.child_by_field_name("name")
                if nm is not None and nm.type == "identifier" and self._get_text(nm) == name:
                    decls.append(n.child_by_field_name("value"))
                elif nm is not None and nm.type != "identifier" and any(
                        x.type in ("identifier", "shorthand_property_identifier_pattern")
                        and self._get_text(x) == name for x in self._descendants_js(nm)):
                    decls.append(None)          # bound by destructuring
            elif n.type in ("class_declaration",):
                cname = n.child_by_field_name("name")
                if cname is not None and self._get_text(cname) == name:
                    decls.append(None)
            elif n.type in ("assignment_expression", "augmented_assignment_expression"):
                left = n.child_by_field_name("left")
                if left is not None and left.type == "identifier" and self._get_text(left) == name:
                    assigned = True
            elif n.type == "update_expression":
                arg = n.child_by_field_name("argument")
                if arg is not None and arg.type == "identifier" and self._get_text(arg) == name:
                    assigned = True
            stack.extend(n.named_children)
        if not decls:
            return False, None
        if len(decls) == 1 and decls[0] is not None and not assigned:
            return True, decls[0]
        return True, None

    def _assigns(self, root: TSNode, name: str) -> bool:
        for n in self._descendants_js(root):
            if n.type in ("assignment_expression", "augmented_assignment_expression"):
                left = n.child_by_field_name("left")
                if left is not None and left.type == "identifier" and self._get_text(left) == name:
                    return True
            elif n.type == "update_expression":
                arg = n.child_by_field_name("argument")
                if arg is not None and arg.type == "identifier" and self._get_text(arg) == name:
                    return True
        return False

    def _declares(self, fn: TSNode, name: str) -> bool:
        """Does this function scope bind `name` itself (shadowing ours)?"""
        found, _ = self._scope_binding(fn, name)
        return found

    @staticmethod
    def _descendants_js(root: TSNode) -> List[TSNode]:
        out, stack = [], list(root.named_children)
        while stack:
            n = stack.pop()
            out.append(n)
            stack.extend(n.named_children)
        return out

    _const_tables: frozenset = frozenset()

    _const_sets: frozenset = frozenset()

    def _collect_const_sets(self, root: TSNode) -> frozenset:
        """Top-level `const ALLOWED = new Set(["a", "b"])` of literals: `ALLOWED.has(x)` is a membership
        test in a constant collection, the same guard as `ALLOWED.includes(x)`."""
        sets = set()
        for stmt in root.named_children:
            if stmt.type == "export_statement" and stmt.named_children:
                stmt = stmt.named_children[-1]
            if stmt.type != "lexical_declaration" or not self._get_text(stmt).startswith("const"):
                continue
            for decl in stmt.named_children:
                name, value = decl.child_by_field_name("name"), decl.child_by_field_name("value")
                if decl.type != "variable_declarator" or name is None or value is None \
                        or name.type != "identifier" or value.type != "new_expression":
                    continue
                cons, args = value.child_by_field_name("constructor"), value.child_by_field_name("arguments")
                if cons is None or self._get_text(cons) != "Set" or args is None or not args.named_children:
                    continue
                arr = args.named_children[0]
                if arr.type == "array" and all(e.type in ("string", "number") for e in arr.named_children):
                    sets.add(self._get_text(name))
        return frozenset(sets)

    def _is_const_table_subscript(self, node: TSNode) -> bool:
        obj = node.child_by_field_name("object")
        return obj is not None and obj.type == "identifier" and self._get_text(obj) in self._const_tables

    def _collect_const_tables(self, root: TSNode) -> frozenset:
        """Top-level `const TABLE = { key: "literal", ... }` objects whose values are all literals:
        `TABLE[userKey]` yields one of the table's own constants, never the key, so looking a request
        value up in it (`FEEDS[req.query.name] || FEEDS.news`) is the allow-list idiom, not a flow."""
        tables = set()
        for stmt in root.named_children:
            if stmt.type == "export_statement" and stmt.named_children:
                stmt = stmt.named_children[-1]
            if stmt.type != "lexical_declaration" or not self._get_text(stmt).startswith("const"):
                continue
            for decl in stmt.named_children:
                name, value = decl.child_by_field_name("name"), decl.child_by_field_name("value")
                if decl.type != "variable_declarator" or name is None or value is None \
                        or name.type != "identifier" or value.type != "object" or not value.named_children:
                    continue
                if all(pair.type == "pair" and pair.child_by_field_name("value") is not None
                       and (pair.child_by_field_name("value").type in ("string", "number", "true", "false", "null")
                            or (pair.child_by_field_name("value").type == "template_string"
                                and "${" not in self._get_text(pair.child_by_field_name("value"))))
                       for pair in value.named_children):
                    tables.add(self._get_text(name))
        return frozenset(tables)

    def _file_declared_names(self, root: TSNode) -> Counter:
        """Every name the file binds -- variables (including destructuring),
        parameters, functions, classes, imports and catch parameters -- with
        the number of places that bind it."""
        names: Counter = Counter()
        binders = {"variable_declarator", "function_declaration", "class_declaration",
                   "generator_function_declaration", "import_specifier", "namespace_import",
                   "import_clause", "catch_clause"}
        stack = [root]
        while stack:
            n = stack.pop()
            t = n.type
            if t in binders or t in ("formal_parameters", "required_parameter",
                                     "optional_parameter", "arrow_function"):
                target = (n.child_by_field_name("alias") if t == "import_specifier" else None) \
                    or n.child_by_field_name("name") or n.child_by_field_name("parameter")
                pool = [target] if target is not None else []
                if t in ("formal_parameters", "import_clause", "namespace_import"):
                    pool = list(n.named_children)
                if t == "arrow_function":
                    p = n.child_by_field_name("parameter")
                    pool = [p] if p is not None else []
                for b in pool:
                    sub = [b]
                    while sub:
                        x = sub.pop()
                        if x.type in ("identifier", "shorthand_property_identifier_pattern"):
                            names[self._get_text(x)] += 1
                        elif x.type in ("object_pattern", "array_pattern", "pair_pattern",
                                        "assignment_pattern", "rest_pattern",
                                        "required_parameter", "optional_parameter"):
                            if x.type == "pair_pattern":
                                v = x.child_by_field_name("value")
                                sub.extend([v] if v is not None else [])
                            elif x.type == "assignment_pattern":
                                l = x.child_by_field_name("left")
                                sub.extend([l] if l is not None else [])
                            else:
                                sub.extend(x.named_children)
            stack.extend(n.named_children)
        return names

    def _guarded_proto_sink(self, spec) -> bool:
        """A prototype-pollution call sink in a file that already checks keys
        against __proto__/constructor/prototype is treated as guarded."""
        return spec.is_sink == "prototype_pollution" and getattr(self, "_proto_guarded", False)

    # Sinks whose vulnerability is *calling* a function (`md5(x)`,
    # `Math.random()`); assigning to a property that merely shares the name
    # (`exports.md5 = md5`) is not a call and must not match.
    _CALL_ONLY_SINK_KINDS = frozenset({"weak_hash", "weak_crypto", "insecure_random"})

    def _translate_call_assignment(
        self,
        target: str,
        call_node: TSNode,
        loc: Location
    ) -> List[Instr]:
        """Translate: target = func(args)"""
        instrs = []
        loc = self._chain_location(call_node, loc)

        func_name = self._get_call_name(call_node)
        # A call chained on a call -- `execSync(cmd).toString()`,
        # `fetch(u).then(f)` -- lowers the inner call first, into a temporary
        # that is the outer call's receiver. Named as one opaque string, the
        # inner sink was never a Call at all.
        func_node = call_node.child_by_field_name("function")
        if func_node is not None and func_node.type == "member_expression":
            obj_node = func_node.child_by_field_name("object")
            prop_node = func_node.child_by_field_name("property")
            fluent = self._fluent_call_name(call_node)
            if fluent is not None:
                # `res.status(200).send(x)`: the setter returns the same object
                instrs.extend(self._translate_call_expr(obj_node))
                func_name = fluent
            elif obj_node is not None and obj_node.type == "call_expression" and prop_node is not None:
                inner = f"$chain{self._ident_counter}"
                self._ident_counter += 1
                instrs.extend(self._translate_call_assignment(inner, obj_node, loc))
                func_name = f"{inner}.{self._get_text(prop_node)}"
        self._note_escaping_const(call_node)
        escaping = self._escaping_callee(func_node)
        if func_node is not None and func_node.type == "call_expression":
            func_name = self._hoist_callee_call(func_node, loc, instrs)
        args = self._get_call_args(call_node)
        args_exp = [(self._call_arg_exp(func_name, args, i), Typ.unknown_type()) for i in range(len(args))]
        args_exp, kwarg_names = self._with_option_kwargs(func_name, args, args_exp)

        # Create return identifier
        ret_id = self._new_ident(target)

        # Build Call instruction
        call_instr = Call(
            loc=loc,
            ret=(ret_id, Typ.unknown_type()),
            func=ExpConst.string(func_name),
            args=args_exp,
            receiver_type=self._receiver_kind(call_node),
            kwarg_names=kwarg_names,
        )
        instrs.append(call_instr)

        # Assign to target
        instrs.append(Assign(
            loc=loc,
            id=PVar(target),
            exp=ExpVar(ret_id)
        ))

        # Check if this is a taint source
        spec = self.specs.get(func_name)
        if not db_method_applies(spec, func_name, self._receiver_kind(call_node)):
            spec = None
        if spec and spec.is_taint_source():
            kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
            instrs.append(TaintSource(
                loc=loc,
                var=PVar(target),
                kind=kind,
                description=spec.description
            ))

        # `decodeURIComponent(location.hash.slice(1))`, `JSON.parse(req.body.data)`: functions that
        # only re-encode their argument return request data when the argument is request data
        # (specs/data/passthrough.toml)
        if func_name in _passthrough().javascript_calls:
            for arg in args:
                found = self._check_expression_for_taint_source(arg, target, loc)
                if found:
                    instrs.extend(found)
                    break

        # `const f = path.join(BASE, req.query.name)`: a propagator (path.join/resolve, JSON.parse,
        # url helpers...) returns request data when one of the arguments it propagates is an inline
        # request read -- not only when that argument is a variable.
        prop_spec = self._lookup_call_spec(func_name, call_node)
        if (prop_spec is not None and prop_spec.taint_propagates and not prop_spec.is_taint_sink()
                and not prop_spec.is_taint_source() and not prop_spec.is_taint_sanitizer()
                and func_name not in _passthrough().javascript_calls):
            for idx in prop_spec.taint_propagates:
                if 0 <= idx < len(args):
                    instrs.extend(self._check_expression_for_taint_source(args[idx], target, loc))

        # `f(x)(req.query.n)`: calling the value a hoisted call returned has no spec, so it returns
        # what its arguments carry -- including request data written inline in them
        if func_name.startswith("$chain") and "." not in func_name:
            for arg in args:
                parts = ([c.child_by_field_name("value") for c in arg.named_children if c.type == "pair"]
                         if arg.type == "object" else list(arg.named_children) if arg.type == "array" else [arg])
                for part in parts:
                    if part is not None:
                        instrs.extend(self._check_expression_for_taint_source(part, target, loc))

        # `req.query.p.trim()`, `req.headers.authorization.split(' ')[0]`: a method called on an
        # inline request value returns request data (a string method keeps the payload).
        if func_node is not None and func_node.type == "member_expression":
            receiver = func_node.child_by_field_name("object")
            if receiver is not None and receiver.type in ("member_expression", "new_expression") \
                    and not self._lookup_call_spec(func_name, call_node):
                instrs.extend(self._check_expression_for_taint_source(receiver, target, loc))

        # Check if this is a sink. Unlike the source check above this honours member-chain
        # suffixes (`this.db.query`, `await repo.pool.query`) and arguments that qualify the
        # spec (`createHash('md5')`), as a standalone call statement does.
        sink_spec = self._lookup_call_spec(func_name, call_node)
        if sink_spec and sink_spec.is_taint_sink() and not self._guarded_proto_sink(sink_spec):
            kind = _get_sink_kind(sink_spec.is_sink)
            for arg_idx in sink_spec.sink_args:
                if arg_idx < len(args):
                    for arg_exp in self._sink_arg_exps(func_name, args, arg_idx):
                        instrs.append(TaintSink(
                            loc=loc,
                            exp=arg_exp,
                            kind=kind,
                            description=sink_spec.description,
                            call=func_name
                        ))

        if escaping:                                      # last: after the result is defined and tainted
            instrs.append(Sanitize(loc=loc, var=PVar(target), sanitizes=[SinkKind.HTML_OUTPUT, SinkKind.XSS]))
        return instrs

    def _instance_bindings(self, root: TSNode) -> Dict[str, str]:
        """name -> the imported class it is an instance of: `const x = new C(...)` where C
        resolves through the file's imports, for names declared exactly once in the file
        (another declaration, a parameter or an assignment of the same name leaves it unbound)."""
        counts: Dict[str, int] = {}
        found: Dict[str, str] = {}
        stack = [root]
        while stack:
            n = stack.pop()
            stack.extend(n.children)
            name = None
            if n.type == "variable_declarator":
                name_node = n.child_by_field_name("name")
                name = self._get_text(name_node) if name_node is not None and name_node.type == "identifier" else None
                value = n.child_by_field_name("value")
                if name and value is not None and value.type == "new_expression":
                    ctor = value.child_by_field_name("constructor")
                    text = self._get_text(ctor) if ctor is not None else ""
                    head, _, rest = text.partition(".")
                    base = self._module_aliases.get(head) or self._imported_names.get(head)
                    if base and not base.startswith(".") and re.fullmatch(r"[\w$.]+", text):
                        found[name] = base + ("." + rest if rest else "")
            elif n.type in ("formal_parameters", "required_parameter", "optional_parameter"):
                for c in n.named_children:
                    if c.type == "identifier":
                        counts[self._get_text(c)] = counts.get(self._get_text(c), 0) + 1
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                name = self._get_text(left) if left is not None and left.type == "identifier" else None
            if name:
                counts[name] = counts.get(name, 0) + 1
        return {k: v for k, v in found.items() if counts.get(k) == 1}

    _TEMPLATE_COMPILERS = frozenset({"lodash.template", "_.template", "underscore.template", "lodash/template"})

    def _escaping_template(self, func_node: TSNode) -> bool:
        """`_.template("<b><%- x %></b>")`: a literal template whose only tags are `<%- %>`
        (lodash / underscore HTML-escape them), so what the compiled template returns is escaped
        for HTML. Not when the template has `<%= %>` (raw), `<% %>` (code that can print raw) or
        `${...}` (lodash interpolates it raw), when an options argument or `templateSettings`
        could change the delimiters, or when the template is not a literal."""
        if func_node is None or func_node.type != "call_expression":
            return False
        if self._get_call_name(func_node) not in self._TEMPLATE_COMPILERS:
            return False
        args = self._get_call_args(func_node)
        if len(args) != 1 or args[0].type not in ("string", "template_string"):
            return False
        if args[0].type == "template_string" and any(c.type == "template_substitution" for c in args[0].children):
            return False
        text = self._get_text(args[0])
        if "templateSettings" in self._source or "${" in text:
            return False
        tags = re.findall(r"<%(.?)", text)
        return bool(tags) and all(t == "-" for t in tags)

    _FUNCTION_TYPES = ("function_declaration", "function_expression", "arrow_function", "method_definition",
                       "generator_function_declaration", "program")

    def _scope_of(self, node: TSNode) -> Tuple[int, int]:
        n = node.parent
        while n is not None and n.type not in self._FUNCTION_TYPES:
            n = n.parent
        return (n.start_byte, n.end_byte) if n is not None else (0, 0)

    def _escaping_callee(self, func_node: TSNode) -> bool:
        """The callee is an escaping template: compiled right there (`_.template("<%- x %>")(d)`),
        or a `const` in the same function bound to one (`const t = _.template(...); t(d)`)."""
        if func_node is None:
            return False
        if func_node.type == "identifier":
            return (self._scope_of(func_node), self._get_text(func_node)) in getattr(self, "_escaping_consts", set())
        return self._escaping_template(func_node)

    def _note_escaping_const(self, call_node: TSNode) -> None:
        decl = call_node.parent
        stmt = decl.parent if decl is not None else None
        if (decl is not None and decl.type == "variable_declarator" and stmt is not None
                and stmt.type == "lexical_declaration" and self._get_text(stmt).startswith("const")
                and self._escaping_template(call_node)):
            name = self._get_text(decl.child_by_field_name("name"))
            self._escaping_consts = getattr(self, "_escaping_consts", set()) | {(self._scope_of(call_node), name)}

    def _hoist_callee_call(self, func_node: TSNode, loc: Location, instrs: List[Instr]) -> str:
        """`f(x)(y)` (`_.template(src)(data)`, `connect(m)(C)`): the inner call runs first and its
        result is what is called. Lowered as `$chainN = f(x)`, a real Call, so the inner call's
        specs (a sink, a source) apply; the outer call is a call of `$chainN`."""
        inner = f"$chain{self._ident_counter}"
        self._ident_counter += 1
        instrs.extend(self._translate_call_assignment(inner, func_node, loc))
        return inner

    def _translate_call_expr(self, call_node: TSNode) -> List[Instr]:
        """Translate standalone call: func(args)

        Handles chained method calls like: query(...).then(...).catch(...)
        Each call in the chain is translated separately.
        """
        instrs = []
        loc = self._chain_location(call_node, self._get_location(call_node))

        # Get the function node
        func_node = call_node.child_by_field_name("function")

        # Check if this is a chained method call (e.g., query(...).then(...))
        if func_node and func_node.type == "member_expression":
            obj_node = func_node.child_by_field_name("object")
            prop_node = func_node.child_by_field_name("property")

            # If the object is a call_expression, translate it first
            if obj_node and obj_node.type == "call_expression":
                # Recursively translate the inner call
                inner_instrs = self._translate_call_expr(obj_node)
                instrs.extend(inner_instrs)

                # Now translate this call with just the method name (or, behind
                # fluent setters, as a call on the original object)
                method_name = self._get_text(prop_node) if prop_node else ""
                func_name = self._fluent_call_name(call_node) or method_name
            else:
                # Regular method call (e.g., obj.method())
                func_name = self._get_call_name(call_node)
        elif func_node is not None and func_node.type == "call_expression":
            func_name = self._hoist_callee_call(func_node, loc, instrs)
        else:
            # Simple function call
            func_name = self._get_call_name(call_node)

        args = self._get_call_args(call_node)
        args_exp = [(self._call_arg_exp(func_name, args, i), Typ.unknown_type()) for i in range(len(args))]
        args_exp, kwarg_names = self._with_option_kwargs(func_name, args, args_exp)

        # Build Call instruction
        call_instr = Call(
            loc=loc,
            ret=None,
            func=ExpConst.string(func_name),
            args=args_exp,
            receiver_type=self._receiver_kind(call_node),
            kwarg_names=kwarg_names,
        )
        instrs.append(call_instr)

        # Check if this is a sink (with suffix matching for chained calls)
        spec = self._lookup_call_spec(func_name, call_node)

        if spec and spec.is_taint_sink() and not self._guarded_proto_sink(spec):
            kind = _get_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    for arg_exp in self._sink_arg_exps(func_name, args, arg_idx):
                        instrs.append(TaintSink(
                            loc=loc,
                            exp=arg_exp,
                            kind=kind,
                            description=spec.description,
                            arg_index=arg_idx,
                            call=func_name
                        ))

        return instrs

    @staticmethod
    def _call_argument_nodes(call_node: TSNode) -> List[TSNode]:
        arguments = call_node.child_by_field_name("arguments")
        return list(arguments.named_children) if arguments is not None else []

    def _render_data_exps(self, func_name: str, args: List[TSNode], arg_idx: int) -> Optional[List[Exp]]:
        """For `res.render("view", { a, b: x })` whose template is found and
        readable: the data values the template prints without escaping
        (`<%- a %>`, `{{{ a }}}`, `a | safe`). The rest is escaped by the engine
        and is not an XSS sink. None when this is not such a call or the
        template is unknown (every value then stays a sink)."""
        node = args[arg_idx]
        if not (arg_idx == 1 and func_name.rsplit(".", 1)[-1] == "render"
                and args[0].type == "string" and node.type == "object"):
            return None
        from frame.sil.templates import keep_render_arguments
        view = self._get_text(args[0]).strip("'\"`")
        entries: List[Tuple[Optional[str], Optional[TSNode]]] = []
        for child in node.children:
            if child.type == "pair":
                key = child.child_by_field_name("key")
                entries.append((self._get_text(key).strip("'\"`") if key is not None else None,
                                child.child_by_field_name("value")))
            elif child.type == "shorthand_property_identifier":
                entries.append((self._get_text(child), child))
            elif child.type == "spread_element":
                entries.append((None, child.named_children[0] if child.named_children else None))
        keep = keep_render_arguments(view, self._filename, [k for k, _ in entries if k is not None])
        if keep is None:
            return None
        return [self._translate_expression(v) for k, v in entries
                if v is not None and (k is None or k in keep)]

    def _call_arg_exp(self, func_name: str, args: List[TSNode], idx: int) -> Exp:
        """The expression for argument `idx` of a call; a render call's data
        object is narrowed to the values its template prints raw."""
        kept = self._render_data_exps(func_name, args, idx)
        if kept is None:
            if self._spawn_argv_is_data(func_name, args, idx):
                return ExpConst.string("")      # argv of a shell-less spawn: arguments, not a command line
            if args[idx].type in ("object", "array") and func_name.rsplit(".", 1)[-1] in ("send", "response"):
                return ExpConst.string("")      # serialised as JSON, not sent as HTML
            return self._translate_expression(args[idx])
        return ExpStringConcat(kept) if kept else ExpConst.string("")

    _SHELL_OPTION = re.compile(r"\bshell\s*:(?!\s*(?:false|0|null|undefined)\b)")

    def _spawn_argv_is_data(self, func_name: str, args: List[TSNode], idx: int) -> bool:
        """Argument `idx` is the argument vector of `spawn(program, [args])` that no shell parses:
        the program is not a shell and the options do not say `shell: true`."""
        if idx != 1 or len(args) < 2 or func_name.rsplit(".", 1)[-1] not in ("spawn", "spawnSync"):
            return False
        if args[1].type != "array" or self._is_shell_program(args[0]):
            return False
        return not (len(args) > 2 and self._SHELL_OPTION.search(self._get_text(args[2])))

    def _is_shell_program(self, node: TSNode) -> bool:
        """Is a spawn's program argument a literal naming a shell? A program that is not a literal
        stays a shell candidate (it may be `process.env.SHELL`, a variable...)."""
        if node.type == "string":
            text = self._get_text(node).strip("'\"")
            return is_shell(text)                                     # specs/data/shells.toml
        return node.type != "template_string"

    def _sink_arg_exps(self, func_name: str, args: List[TSNode], arg_idx: int) -> List[Exp]:
        """The expressions of sink argument `arg_idx`: the argument itself, or
        for a render call whose template is known, the raw-printed data values."""
        kept = self._render_data_exps(func_name, args, arg_idx)
        if kept is not None:
            return kept
        # `spawn("git", ["log", branch])`: the argument vector of a spawn without a shell is not a command
        # line. It is one only when the program is itself a shell (`spawn("sh", ["-c", cmd])`); with
        # `{ shell: true }` the framework-pack rule covers it.
        if self._spawn_argv_is_data(func_name, args, arg_idx):
            return []
        # `res.send({ q: req.query.q })` / `h.response([...])`: an object or array is
        # serialised as JSON (application/json), not sent as HTML.
        if (args[arg_idx].type in ("object", "array")
                and func_name.rsplit(".", 1)[-1] in ("send", "response")):
            return []
        return [self._translate_expression(args[arg_idx])]

    def _emit_nested_call_sink(self, call_node: TSNode, args: List[Exp]) -> None:
        """Emit a TaintSink for a call appearing inside a larger expression
        (return value, argument, concatenation) so nested sinks like
        `return eval(x)` are not lost. Standalone-statement calls go through
        _translate_call_expr instead, so this avoids double emission."""
        func_name = self._get_call_name(call_node)
        spec = self._lookup_call_spec(func_name, call_node)
        if spec and spec.is_taint_sink():
            kind = _get_sink_kind(spec.is_sink)
            loc = self._get_location(call_node)
            arg_nodes = self._call_argument_nodes(call_node)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    exps = (self._sink_arg_exps(func_name, arg_nodes, arg_idx)
                            if arg_idx < len(arg_nodes) else [args[arg_idx]])
                    for exp in exps:
                        self._add_instr(TaintSink(
                            loc=loc, exp=exp, kind=kind,
                            description=spec.description, arg_index=arg_idx,
                            call=func_name))

    def _translate_template_assignment(
        self,
        target: str,
        template_node: TSNode,
        loc: Location
    ) -> List[Instr]:
        """Translate template string assignment"""
        instrs = []
        parts = self._extract_template_parts(template_node)

        if parts:
            concat_exp = ExpStringConcat(parts)
            instrs.append(Assign(loc=loc, id=PVar(target), exp=concat_exp))
        else:
            instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpConst.string("")))

        return instrs

    def _extract_template_parts(self, node: TSNode) -> List[Exp]:
        """Extract parts from template string"""
        parts = []

        for child in node.children:
            if child.type == "string_fragment":
                text = self._get_text(child)
                parts.append(ExpConst.string(text))
            elif child.type == "template_substitution":
                # ${expr}
                for c in child.children:
                    if c.type not in ("${", "}"):
                        exp = self._translate_expression(c)
                        parts.append(exp)

        return parts

    def _translate_augmented_assignment(self, node: TSNode) -> None:
        """Translate augmented assignment: x += y"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        op_node = node.child_by_field_name("operator")

        if not left or not right:
            return

        target_name = self._get_text(left)
        loc = self._get_location(node)

        op = self._get_text(op_node) if op_node else "+="
        bin_op = op[:-1] if op.endswith("=") else "+"

        left_exp = ExpVar(PVar(target_name))
        right_exp = self._translate_expression(right)
        combined = ExpBinOp(bin_op, left_exp, right_exp)

        self._add_instr(Assign(loc=loc, id=PVar(target_name), exp=combined))

    def _translate_update(self, node: TSNode) -> None:
        """Translate update expression: x++ or ++x"""
        loc = self._get_location(node)
        arg = node.child_by_field_name("argument")
        op = node.child_by_field_name("operator")

        if not arg:
            return

        var_name = self._get_text(arg)
        op_text = self._get_text(op) if op else "++"
        bin_op = "+" if "++" in op_text else "-"

        self._add_instr(Assign(
            loc=loc,
            id=PVar(var_name),
            exp=ExpBinOp(bin_op, ExpVar(PVar(var_name)), ExpConst.integer(1))
        ))

    def _return_value_exp(self, node: TSNode, loc: Location):
        """The expression a `return` yields. A returned call (`return h.redirect(x)`,
        `return db.query(q)`) is also emitted as a call statement, so specs (sinks,
        sources, sanitizers) and framework packs apply to it as to a standalone call."""
        inner = self._unwrap_await(node)
        if inner is not None and inner.type == "call_expression":
            # the call as a statement (a Call instruction for specs, packs and canonical ids) ...
            spec = self._lookup_call_spec(self._get_call_name(inner), inner)
            if not (spec is not None and spec.taint_propagates and not spec.is_taint_sink()
                    and not spec.is_taint_source() and not spec.is_taint_sanitizer()):
                self._add_instrs(self._translate_call_expr(inner))
        # ... and the returned value as the expression, so argument -> result propagation is unchanged
        return self._translate_expression(node)

    def _add_return_value(self, body_node: TSNode) -> None:
        """`() => expr`: the expression body is the returned value."""
        loc = self._get_location(body_node)
        self._add_instr(Return(loc=loc, value=self._return_value_exp(body_node, loc)))

    def _translate_return(self, node: TSNode) -> None:
        """Translate return statement"""
        loc = self._get_location(node)
        value_exp = None

        for child in node.children:
            if child.type not in ("return", ";"):
                # Check if returning an arrow function - inline its body
                if child.type == "arrow_function" or child.type == "function":
                    # Get the arrow function's body and translate it inline
                    body_node = child.child_by_field_name("body")
                    if body_node:
                        if body_node.type == "statement_block":
                            self._translate_block(body_node)
                        else:
                            # Expression body: () => expr
                            self._add_return_value(body_node)
                    return  # Don't add another return statement
                else:
                    value_exp = self._return_value_exp(child, loc)
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

        # Translate consequence
        consequence = node.child_by_field_name("consequence")
        if consequence:
            self._current_node = true_node
            if consequence.type == "statement_block":
                self._translate_block(consequence)
            else:
                self._translate_statement(consequence)
            if self._current_node:
                proc.connect(self._current_node.id, join_node.id)

        # Translate alternative
        alternative = node.child_by_field_name("alternative")
        if alternative:
            self._current_node = false_node
            if alternative.type == "else_clause":
                for child in alternative.children:
                    if child.type not in ("else",):
                        if child.type == "statement_block":
                            self._translate_block(child)
                        else:
                            self._translate_statement(child)
            elif alternative.type == "if_statement":
                self._translate_if(alternative)
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
            if body.type == "statement_block":
                self._translate_block(body)
            else:
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
            if init.type in ("lexical_declaration", "variable_declaration"):
                self._translate_var_declaration(init)
            elif init.type == "assignment_expression":
                self._translate_assignment(init)

        # Simplified loop translation
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
            if body.type == "statement_block":
                self._translate_block(body)
            else:
                self._translate_statement(body)

        # Update
        update = node.child_by_field_name("increment")
        if update and self._current_node:
            if update.type == "update_expression":
                self._translate_update(update)
            elif update.type == "assignment_expression":
                self._translate_assignment(update)

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node

    def _translate_for_in(self, node: TSNode) -> None:
        """Translate for-in/for-of loop"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        loop_var = self._get_text(left) if left else "_iter"
        iterable_exp = self._translate_expression(right) if right else ExpConst.null()

        before_node = self._current_node

        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)

        body_node = proc.new_node(NodeKind.NORMAL)
        body_node.add_instr(Assign(
            loc=loc,
            id=PVar(loop_var),
            exp=ExpCall(ExpConst.string("next"), [iterable_exp])
        ))
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
            if body.type == "statement_block":
                self._translate_block(body)
            else:
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

        handler = node.child_by_field_name("handler")
        if handler:
            handler_body = handler.child_by_field_name("body")
            if handler_body:
                self._translate_block(handler_body)

        finalizer = node.child_by_field_name("finalizer")
        if finalizer:
            self._translate_block(finalizer)

    def _translate_switch(self, node: TSNode) -> None:
        """Translate switch statement (simplified)"""
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "switch_case" or child.type == "switch_default":
                    for stmt in child.children:
                        if stmt.type not in ("case", "default", ":", "break_statement"):
                            self._translate_statement(stmt)

    def _translate_throw(self, node: TSNode) -> None:
        """Translate throw statement"""
        loc = self._get_location(node)
        # Simplified: just mark as potential error
        for child in node.children:
            if child.type not in ("throw", ";"):
                exp = self._translate_expression(child)
                self._add_instr(Return(loc=loc, value=exp))
                break

    def _translate_expression(self, node: TSNode) -> Exp:
        """Translate expression to SIL Exp"""
        if node is None:
            return ExpConst.null()

        if node.type == "identifier":
            name = self._get_text(node)
            return ExpVar(PVar(name))

        elif node.type == "number":
            text = self._get_text(node)
            try:
                if "." in text:
                    return ExpConst.integer(int(float(text)))
                else:
                    return ExpConst.integer(int(text, 0))
            except ValueError:
                return ExpConst.integer(0)

        elif node.type == "string":
            text = self._get_string_content(node)
            return ExpConst.string(text)

        elif node.type == "template_string":
            parts = self._extract_template_parts(node)
            if parts:
                return ExpStringConcat(parts)
            return ExpConst.string("")

        elif node.type == "true":
            return ExpConst.boolean(True)

        elif node.type == "false":
            return ExpConst.boolean(False)

        elif node.type in ("null", "undefined"):
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
            arg = node.child_by_field_name("argument")
            op = self._get_text(op_node) if op_node else "-"
            arg_exp = self._translate_expression(arg)
            return ExpUnOp(op, arg_exp)

        elif node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            obj_exp = self._translate_expression(obj)
            prop_name = self._get_text(prop) if prop else ""
            return ExpFieldAccess(obj_exp, prop_name)

        elif node.type == "subscript_expression" and self._is_const_table_subscript(node):
            return ExpConst.null()

        elif node.type == "subscript_expression":
            obj = node.child_by_field_name("object")
            index = node.child_by_field_name("index")
            obj_exp = self._translate_expression(obj)
            index_exp = self._translate_expression(index)
            return ExpIndex(obj_exp, index_exp)

        elif node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func is not None and self._escaping_callee(func):
                # the compiled, escaping template's output: a temporary sanitized for HTML only
                out = f"$chain{self._ident_counter}"
                self._ident_counter += 1
                self._add_instrs(self._translate_call_assignment(out, node, self._get_location(node)))
                return ExpVar(PVar(out))
            if func is not None and func.type == "call_expression":
                hoisted: List[Instr] = []
                func_exp = ExpVar(PVar(self._hoist_callee_call(func, self._get_location(func), hoisted)))
                self._add_instrs(hoisted)
            else:
                func_exp = self._translate_expression(func)
            if (func is not None and func.type == "member_expression"
                    and self._get_text(func.child_by_field_name("property")) == "has"
                    and func.child_by_field_name("object").type == "identifier"
                    and self._get_text(func.child_by_field_name("object")) in self._const_sets):
                func_exp = ExpFieldAccess(self._translate_expression(func.child_by_field_name("object")),
                                          "includes")                # Set.has == includes on a constant set
            fluent = self._fluent_call_name(node)
            if fluent is not None:
                func_exp = ExpVar(PVar(fluent))        # `$('<li>').text(v)` -> `$.text`
            inline = self._inline_require_member(func) if func is not None else None
            if inline is not None:
                func_exp = ExpVar(PVar(inline))        # `require("m").f` -> `m.f`
            args = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ","):
                        args.append(self._translate_expression(child))
            # A call nested inside another expression (e.g. `return eval(x)`,
            # `f(exec(y))`) is still a sink -- emit its TaintSink as a side effect
            # so it is not missed just because it is not a standalone statement.
            self._emit_nested_call_sink(node, args)
            return ExpCall(func_exp, args)

        elif node.type == "regex":
            # ReDoS is detected by a dedicated whole-file pass (_scan_redos), so
            # module-level regex constants are covered too; here just yield the
            # literal as an opaque string value.
            pat_node = node.child_by_field_name("pattern")
            pattern = self._get_text(pat_node) if pat_node else ""
            return ExpConst.string(f"/{pattern}/")

        elif node.type == "parenthesized_expression":
            for child in node.children:
                if child.type not in ("(", ")"):
                    return self._translate_expression(child)

        elif node.type == "array":
            # Aggregate every element so taint in any position survives, e.g.
            # spawn('sh', ['-c', req.query.cmd]) -- not just the first element.
            elements = []
            for child in node.children:
                if child.type in ("[", "]", ",", "comment"):
                    continue
                if child.type == "spread_element":
                    elements.extend(self._translate_expression(c)
                                    for c in child.children if c.type != "...")
                else:
                    elements.append(self._translate_expression(child))
            if not elements:
                return ExpConst.null()
            return ExpStringConcat(elements) if len(elements) > 1 else elements[0]

        elif node.type == "object":
            # Aggregate the property values so taint flows through an object,
            # e.g. User.find({ $where: req.body.q }) or res.json(req.body).
            parts = []
            for child in node.children:
                if child.type == "pair":
                    val = child.child_by_field_name("value")
                    if val is not None:
                        parts.append(self._translate_expression(val))
                elif child.type in ("shorthand_property_identifier",
                                    "shorthand_property_identifier_pattern"):
                    parts.append(ExpVar(PVar(self._get_text(child))))
                elif child.type == "spread_element":
                    for c in child.children:
                        if c.type not in ("...",):
                            parts.append(self._translate_expression(c))
            if not parts:
                return ExpConst.null()
            return ExpStringConcat(parts) if len(parts) > 1 else parts[0]

        elif node.type == "ternary_expression" or node.type == "conditional_expression":
            # condition ? true : false
            # For taint tracking, we need to consider both branches
            # Simplified: prefer alternative if it looks like a taint source, otherwise consequence
            cond = node.child_by_field_name("condition")
            conseq = node.child_by_field_name("consequence")
            alt = node.child_by_field_name("alternative")

            # Check if alternative contains a taint source pattern
            alt_chain = self._get_member_chain(alt) if alt else ""
            if alt_chain and any(alt_chain.startswith(src) for src in ["req.", "request."]):
                return self._translate_expression(alt) if alt else ExpConst.null()

            # Check if consequence contains a taint source pattern
            conseq_chain = self._get_member_chain(conseq) if conseq else ""
            if conseq_chain and any(conseq_chain.startswith(src) for src in ["req.", "request."]):
                return self._translate_expression(conseq) if conseq else ExpConst.null()

            # Default: return consequence
            return self._translate_expression(conseq) if conseq else ExpConst.null()

        elif node.type == "await_expression":
            # await_expression has NO "argument" field -- the awaited expression
            # is an unnamed child after the `await` keyword. Using the (missing)
            # field dropped the inner call entirely, so every `await db.find(...)`
            # / `await fs.readFile(...)` sink was invisible. Unwrap the real child.
            inner = node.child_by_field_name("argument")
            if inner is None:
                for c in node.children:
                    if c.type != "await":
                        inner = c
                        break
            return self._translate_expression(inner) if inner is not None else ExpConst.null()

        elif node.type == "new_expression":
            cons = node.child_by_field_name("constructor")
            cons_name = self._get_text(cons) if cons else "Object"
            args = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ","):
                        args.append(self._translate_expression(child))
            # A constructor can itself be a sink (e.g. new Function(userCode) is
            # code injection). Emit the TaintSink as a side effect so it fires in
            # any context (var initializer, argument, etc.).
            qualified = cons_name
            head, dot, rest = cons_name.partition(".")
            if dot and head in self._module_aliases:
                qualified = f"{self._module_aliases[head]}.{rest}"          # new vm.Script(...)
            elif not dot and cons_name in self._imported_names:
                qualified = self._imported_names[cons_name]                 # import { Script } from 'vm'
            spec = (self.specs.get(qualified) or self.specs.get(cons_name)
                    or self.specs.get(f"new {cons_name}"))
            if spec and spec.is_taint_sink():
                kind = _get_sink_kind(spec.is_sink)
                for arg_idx in spec.sink_args:
                    if arg_idx < len(args):
                        self._add_instr(TaintSink(
                            loc=self._get_location(node), exp=args[arg_idx],
                            kind=kind, description=spec.description, arg_index=arg_idx))
            return ExpCall(ExpConst.string(f"new {cons_name}"), args)

        elif node.type in ("as_expression", "satisfies_expression",
                            "non_null_expression"):
            # TypeScript type assertions (`x as string`, `x satisfies T`, `x!`)
            # are transparent to runtime values and taint -- translate the inner
            # expression and drop the type so `req.query.id as string` stays a
            # recognized source.
            inner = node.named_child(0) if node.named_child_count else None
            return (self._translate_expression(inner) if inner is not None
                    else ExpConst.null())

        elif node.type in ("jsx_element", "jsx_self_closing_element", "jsx_fragment"):
            # JSX evaluates to a React element (opaque value for taint), but its
            # attributes may carry taint sinks (e.g. dangerouslySetInnerHTML).
            # Walk the whole subtree and emit any TaintSink instructions.
            self._scan_jsx_for_sinks(node)
            return ExpConst.null()

        # Default
        text = self._get_text(node)
        return ExpVar(PVar(text)) if text else ExpConst.null()

    def _scan_jsx_for_sinks(self, node: TSNode) -> None:
        """Recursively walk a JSX subtree and emit TaintSink instructions for
        sink-bearing attributes such as React's ``dangerouslySetInnerHTML``.

        JSX sinks are attributes nested arbitrarily deep in the element tree, so
        we walk every descendant here rather than relying on the (non-recursing)
        ``_translate_expression`` dispatch on the JSX root.
        """
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type == "jsx_attribute":
                self._emit_jsx_attribute_sink(cur)
            for child in cur.children:
                stack.append(child)

    def _emit_jsx_attribute_sink(self, attr_node: TSNode) -> None:
        """If a JSX attribute is a known taint sink, emit a TaintSink for the
        value it injects so the taint engine confirms whether that value is
        actually attacker-tainted (only then is it reported as a vulnerability).
        """
        # Attribute name is the leading property_identifier child.
        name_node = next(
            (c for c in attr_node.children if c.type == "property_identifier"),
            None,
        )
        if name_node is None:
            return

        spec = self.specs.get(self._get_text(name_node))
        if not spec or not spec.is_taint_sink():
            return

        # Attribute value lives in a JSX expression container: ={ ... }.
        # (tree-sitter-javascript names this node "jsx_expression"; some
        # grammar versions use "jsx_expression_container".)
        container = next(
            (c for c in attr_node.children
             if c.type in ("jsx_expression", "jsx_expression_container")),
            None,
        )
        if container is None:
            return

        value_node = self._extract_jsx_sink_value(container)
        if value_node is None:
            return

        self._add_instr(TaintSink(
            loc=self._get_location(attr_node),
            exp=self._translate_expression(value_node),
            kind=_get_sink_kind(spec.is_sink),
            description=spec.description,
            arg_index=0,
        ))

    def _extract_jsx_sink_value(self, container_node: TSNode) -> Optional[TSNode]:
        """Extract the taint-relevant value from a JSX expression container.

        For ``dangerouslySetInnerHTML={{ __html: EXPR }}`` returns the ``EXPR``
        node of the ``__html`` property. Falls back to the container's inner
        expression when there is no inline ``__html`` object (e.g. ``={x}``).
        """
        inner = next(
            (c for c in container_node.children if c.type not in ("{", "}")),
            None,
        )
        if inner is None:
            return None

        # Inline object literal: { __html: EXPR }
        if inner.type == "object":
            for child in inner.children:
                if child.type != "pair":
                    continue
                key_node = child.child_by_field_name("key")
                key_text = self._get_text(key_node).strip("\"'") if key_node else ""
                if key_text == "__html":
                    return child.child_by_field_name("value")
            return None

        # Otherwise the inner expression itself is the injected value.
        return inner

    # =========================================================================
    # Helpers
    # =========================================================================

    def _get_text(self, node: TSNode) -> str:
        """Get text of a node.

        tree-sitter reports byte offsets into the UTF-8-encoded source, so slice
        the byte buffer -- slicing the str directly desynchronizes on any
        multi-byte character (e.g. non-ASCII comments/strings, common in real
        npm packages) and corrupts every node extracted after it."""
        if node is None:
            return ""
        return self._source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace")

    def _get_string_content(self, node: TSNode) -> str:
        """Extract string content (without quotes)"""
        text = self._get_text(node)
        if text.startswith('"""') or text.startswith("'''"):
            return text[3:-3]
        elif text.startswith('"') or text.startswith("'") or text.startswith('`'):
            return text[1:-1]
        return text

    def _get_location(self, node: TSNode) -> Location:
        """Get source location for a node"""
        return Location(
            file=self._filename,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
            end_line=node.end_point[0] + 1,
            end_column=node.end_point[1]
        )

    def _is_library_call(self, func_name: str) -> bool:
        """Is this call named after an imported third-party package (not a relative import)?"""
        modules = {m for m in self._module_aliases.values() if not m.startswith(".")}
        modules |= {q.rsplit(".", 1)[0] for q in self._imported_names.values() if not q.startswith(".")}
        if func_name.split(".", 1)[0] in getattr(self, "_instance_names", ()):
            return True                                   # a method of an imported class's instance
        return any(func_name.startswith(m + ".") for m in modules)

    def _with_option_kwargs(self, func_name: str, args: List[TSNode], args_exp):
        """`libxmljs.parseXml(xml, { noent: true })`: an options object literal passed to a
        third-party package function also yields its simple properties as named arguments
        (`Call.kwarg_names`), so framework packs can condition on them (`when_kwarg`).
        Calls into the project's own modules are left alone (their parameters are positional)."""
        if not args or args[-1].type != "object" or not self._is_library_call(func_name):
            return args_exp, None
        names: List[Optional[str]] = [None] * len(args_exp)
        extra = []
        for prop in args[-1].named_children:
            if prop.type != "pair":
                continue
            key, value = prop.child_by_field_name("key"), prop.child_by_field_name("value")
            if key is None or value is None or key.type not in ("property_identifier", "string"):
                continue
            extra.append(((self._translate_expression(value), Typ.unknown_type()),
                          self._get_text(key).strip("'\"")))
        if not extra:
            return args_exp, None
        return list(args_exp) + [e for e, _ in extra], names + [n for _, n in extra]

    def _chain_location(self, call_node: TSNode, loc: Location) -> Location:
        """A call in a multi-line chain (`repo\n  .createQueryBuilder()\n  .where(x)`) is
        reported on the line of its method name, not on the line the chain starts."""
        func = call_node.child_by_field_name("function")
        prop = func.child_by_field_name("property") if func is not None and func.type == "member_expression" else None
        if prop is None or prop.start_point[0] == call_node.start_point[0]:
            return loc
        return Location(file=self._filename, line=prop.start_point[0] + 1, column=prop.start_point[1],
                        end_line=call_node.end_point[0] + 1, end_column=call_node.end_point[1])

    # Methods that configure the object they are called on and return it, so
    # `res.status(200).send(x)` is `res.send(x)` (Express/Fastify/Koa responses).
    _FLUENT_SETTERS = frozenset({"status", "code", "type", "contentType", "set", "header", "headers",
                                 "cookie", "clearCookie", "append", "vary", "location", "links",
                                 "attachment", "hijack", "serializer", "statusCode"})

    _JQUERY_ROOTS = frozenset({"$", "jQuery"})
    # traversal / filtering methods that return another jQuery collection
    _JQUERY_CHAIN = frozenset({"find", "children", "parent", "parents", "closest", "first", "last", "eq", "next",
                               "prev", "siblings", "filter", "not", "has", "addClass", "removeClass", "css", "show",
                               "hide", "empty", "end", "slice", "add", "contents", "nextAll", "prevAll", "wrap"})

    def _jquery_call_name(self, call_node: TSNode) -> Optional[str]:
        """`$('#x').find('li').html(v)` -> `$.html`: a method called on a jQuery collection."""
        func = call_node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            return None
        method = func.child_by_field_name("property")
        obj = func.child_by_field_name("object")
        while obj is not None and obj.type == "call_expression":
            inner = obj.child_by_field_name("function")
            if inner is None:
                return None
            if inner.type == "identifier" and self._get_text(inner) in self._JQUERY_ROOTS:
                return f"$.{self._get_text(method)}" if method is not None else None
            if inner.type != "member_expression":
                return None
            prop = inner.child_by_field_name("property")
            if prop is None or self._get_text(prop) not in self._JQUERY_CHAIN:
                return None
            obj = inner.child_by_field_name("object")
        return None

    def _sets_non_html_content_type(self, setter: str, args: List[TSNode]) -> bool:
        """`type('json')`, `contentType('text/plain')`, `set('Content-Type', 'image/png')`: a literal
        content type that is not HTML / XML."""
        value = None
        if setter in ("type", "contentType") and args:
            value = args[0]
        elif setter in ("set", "header", "append") and len(args) >= 2 \
                and args[0].type == "string" and self._get_text(args[0]).strip("'\"`").lower() == "content-type":
            value = args[1]
        if value is None or value.type != "string":
            return False
        text = self._get_text(value).strip("'\"`").lower()
        return bool(text) and "html" not in text and "xml" not in text

    def _fluent_call_name(self, call_node: TSNode) -> Optional[str]:
        """`res.status(200).type('html').send` -> `res.send`: the call's name when its
        receiver is an identifier chain followed only by fluent setter calls."""
        func = call_node.child_by_field_name("function")
        if func is None or func.type != "member_expression":
            return None
        jq = self._jquery_call_name(call_node)
        if jq is not None:
            return jq
        method = func.child_by_field_name("property")
        obj = func.child_by_field_name("object")
        if method is None or obj is None or obj.type != "call_expression":
            return None
        while obj is not None and obj.type == "call_expression":
            inner = obj.child_by_field_name("function")
            if inner is None or inner.type != "member_expression":
                return None
            prop = inner.child_by_field_name("property")
            if prop is None or self._get_text(prop) not in self._FLUENT_SETTERS:
                return None
            if self._sets_non_html_content_type(self._get_text(prop), self._get_call_args(obj)):
                return None         # `res.type('text').send(x)` is not an HTML response
            obj = inner.child_by_field_name("object")
        if obj is None or obj.type not in ("identifier", "member_expression", "this"):
            return None
        root = self._get_text(obj)
        if not all(part.isidentifier() for part in root.split(".")):
            return None
        head, dot, rest = root.partition(".")
        if dot and head in getattr(self, "_module_aliases", {}):
            root = f"{self._module_aliases[head]}.{rest}"
        return f"{root}.{self._get_text(method)}"

    def _get_call_name(self, call_node: TSNode) -> str:
        """Get full name of function being called. A call through a module
        binding is named after the module: `cp.exec` with
        `const cp = require('child_process')` is `child_process.exec`, and a
        destructured / named import `run(...)` is the function it binds."""
        func = call_node.child_by_field_name("function")
        if not func:
            return ""
        inline = self._inline_require_member(func)
        if inline is not None:
            return inline
        name = self._get_text(func)
        root, dot, rest = name.partition(".")
        if dot and root in getattr(self, "_module_aliases", {}):
            name = f"{self._module_aliases[root]}.{rest}"
        elif not dot and name in getattr(self, "_imported_names", {}):
            name = self._imported_names[name]
        if self._safe_yaml_load(name, call_node):
            return name.rsplit(".", 1)[0] + ".safeLoad"     # load(text, { schema: JSON_SCHEMA }) is safeLoad
        return name

    def _constructor_field_paths(self, root: TSNode) -> Dict[str, Set[str]]:
        """Class -> the `this.` field paths its constructor assigns from an expression that
        reads one of its parameters (nested functions excluded). A constructor is a function
        `C` with `C.prototype.m = ...` methods in the file, or an ES class's `constructor`."""
        ctors: Dict[str, TSNode] = {}
        protos: Set[str] = set()
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "function_declaration" and n.child_by_field_name("name") is not None:
                ctors.setdefault(self._get_text(n.child_by_field_name("name")), n)
            elif n.type == "assignment_expression":
                m = self._PROTOTYPE_METHOD.match(self._get_text(n.child_by_field_name("left") or n))
                if m:
                    protos.add(m.group(1))
            elif n.type in ("class_declaration", "class"):
                name, body = n.child_by_field_name("name"), n.child_by_field_name("body")
                for meth in (body.named_children if body is not None else ()):
                    if meth.type == "method_definition" and name is not None \
                            and self._get_text(meth.child_by_field_name("name")) == "constructor":
                        ctors[self._get_text(name)] = meth
                        protos.add(self._get_text(name))
            stack.extend(n.children)
        out: Dict[str, Set[str]] = {}
        for cls in protos & set(ctors):
            fn = ctors[cls]
            params = {self._get_text(p) for p in (fn.child_by_field_name("parameters") or fn).named_children
                      if p.type == "identifier"}
            body = fn.child_by_field_name("body")
            todo = list(body.named_children) if body is not None else []
            while todo:
                n = todo.pop()
                if n.type in self._FUNC_NODE_TYPES:
                    continue                         # a nested function is not the constructor's code
                if n.type == "assignment_expression":
                    left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                    text = self._get_text(left) if left is not None else ""
                    if text.startswith("this.") and right is not None \
                            and params & self._referenced_identifiers(right):
                        out.setdefault(cls, set()).add(text[len("this."):])
                todo.extend(n.named_children)
        return out

    def _inline_require_member(self, func: TSNode) -> Optional[str]:
        """`require("shell-quote").quote`: named after the module, as a call through
        `const sq = require("shell-quote")` would be (`shell-quote.quote`)."""
        if func.type != "member_expression":
            return None
        obj, prop = func.child_by_field_name("object"), func.child_by_field_name("property")
        if obj is None or prop is None or obj.type != "call_expression":
            return None
        fn, args = obj.child_by_field_name("function"), obj.child_by_field_name("arguments")
        if fn is None or self._get_text(fn) != "require" or args is None \
                or len(args.named_children) != 1 or args.named_children[0].type != "string":
            return None
        module = self._get_text(args.named_children[0])[1:-1]
        module = module[5:] if module.startswith("node:") else module
        return f"{module}.{self._get_text(prop)}" if module else None

    def _module_bindings(self, root: TSNode):
        """(alias -> module, local name -> module.function) for the file's
        top-level `require` / `import` bindings. A name bound more than once
        to different things is dropped: it cannot be resolved by name."""
        aliases: Dict[str, str] = {}
        names: Dict[str, str] = {}
        conflicts = set()

        def module_of(string_node) -> Optional[str]:
            if string_node is None or string_node.type != "string":
                return None
            text = self._get_text(string_node)[1:-1]
            return text[5:] if text.startswith("node:") else text or None

        def bind(table, local, target):
            if local in table and table[local] != target:
                conflicts.add(local)
            table[local] = target

        for stmt in root.named_children:
            decls = []
            if stmt.type in ("lexical_declaration", "variable_declaration"):
                decls = [d for d in stmt.named_children if d.type == "variable_declarator"]
            for d in decls:
                value, pattern = d.child_by_field_name("value"), d.child_by_field_name("name")
                if value is None or value.type != "call_expression" or pattern is None:
                    continue
                fn = value.child_by_field_name("function")
                args = value.child_by_field_name("arguments")
                if fn is None or self._get_text(fn) != "require" or args is None or not args.named_children:
                    continue
                module = module_of(args.named_children[0])
                if module is None:
                    continue
                if pattern.type == "identifier":
                    bind(aliases, self._get_text(pattern), module)
                elif pattern.type == "object_pattern":
                    for prop in pattern.named_children:
                        if prop.type == "shorthand_property_identifier_pattern":
                            n = self._get_text(prop)
                            bind(names, n, f"{module}.{n}")
                        elif prop.type == "pair_pattern":
                            key, val = prop.child_by_field_name("key"), prop.child_by_field_name("value")
                            if key is not None and val is not None and val.type == "identifier":
                                bind(names, self._get_text(val), f"{module}.{self._get_text(key)}")
            if stmt.type == "import_statement":
                module = module_of(stmt.child_by_field_name("source"))
                clause = next((c for c in stmt.named_children if c.type == "import_clause"), None)
                if module is None or clause is None:
                    continue
                for c in clause.named_children:
                    if c.type == "identifier":                      # import os from 'os'
                        bind(aliases, self._get_text(c), module)
                    elif c.type == "namespace_import":              # import * as fs from 'fs'
                        ident = next((x for x in c.named_children if x.type == "identifier"), None)
                        if ident is not None:
                            bind(aliases, self._get_text(ident), module)
                    elif c.type == "named_imports":                 # import {a as b} from 'm'
                        for spec in c.named_children:
                            if spec.type != "import_specifier":
                                continue
                            name_n, alias_n = spec.child_by_field_name("name"), spec.child_by_field_name("alias")
                            if name_n is not None:
                                local = self._get_text(alias_n if alias_n is not None else name_n)
                                bind(names, local, f"{module}.{self._get_text(name_n)}")
        for c in conflicts:
            aliases.pop(c, None)
            names.pop(c, None)

        # `const execAsync = util.promisify(cp.exec)` / `promisify(exec)`: the promise form is the same
        # function, so calls through it are named after the wrapped one (`child_process.exec`).
        def promisified(fn_text: str) -> bool:
            head, _, member = fn_text.rpartition(".")
            return (member == "promisify" and aliases.get(head) == "util") or \
                   (not head and names.get("promisify") == "util.promisify")
        for stmt in root.named_children:
            if stmt.type not in ("lexical_declaration", "variable_declaration"):
                continue
            for d in stmt.named_children:
                value, pattern = d.child_by_field_name("value"), d.child_by_field_name("name")
                if d.type != "variable_declarator" or value is None or pattern is None \
                        or pattern.type != "identifier" or value.type != "call_expression":
                    continue
                fn = value.child_by_field_name("function")
                args = value.child_by_field_name("arguments")
                if fn is None or args is None or len(args.named_children) != 1 or not promisified(self._get_text(fn)):
                    continue
                wrapped = self._get_text(args.named_children[0])
                head, _, member = wrapped.rpartition(".")
                target = f"{aliases[head]}.{member}" if head in aliases else (names.get(wrapped) if not head else None)
                if target:
                    names[self._get_text(pattern)] = target
        return aliases, names

    def _get_member_chain(self, node: TSNode) -> str:
        """
        Get the full member access chain as a string.
        E.g., req.body.name -> "req.body.name"
        Also handles binary expressions to extract the left-hand taint source.
        """
        if node is None:
            return ""
        if node.type == "identifier":
            return self._get_text(node)
        elif node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            obj_chain = self._get_member_chain(obj)
            prop_name = self._get_text(prop) if prop else ""
            if obj_chain:
                return f"{obj_chain}.{prop_name}"
            return prop_name
        elif node.type == "subscript_expression":
            obj = node.child_by_field_name("object")
            return self._get_member_chain(obj)
        elif node.type == "binary_expression":
            # For ?? and || operators, check the left side for taint source
            left = node.child_by_field_name("left")
            return self._get_member_chain(left)
        elif node.type == "parenthesized_expression":
            # Unwrap parentheses
            for child in node.children:
                if child.type not in ("(", ")"):
                    return self._get_member_chain(child)
            return ""
        else:
            return self._get_text(node)

    def _check_property_taint_source(
        self,
        node: TSNode,
        target: str,
        loc: Location
    ) -> List[Instr]:
        """
        Check if a property access expression is a taint source.
        Returns TaintSource instructions if the expression matches a known source pattern.

        Examples:
            req.body -> TaintSource(user)
            req.query.id -> TaintSource(user)
            req.params.userId -> TaintSource(user)
        """
        instrs = []

        if node is None:
            return instrs

        # For binary expressions, extract the left-hand side
        actual_node = node
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            if left:
                actual_node = left

        # Get the full member chain
        chain = self._get_member_chain(actual_node)
        if not chain:
            return instrs

        # Check if the full chain matches a source
        spec = self.specs.get(chain)
        if spec and spec.is_taint_source():
            kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
            instrs.append(TaintSource(
                loc=loc,
                var=PVar(target),
                kind=kind,
                description=spec.description or f"Taint from {chain}"
            ))
            return instrs

        # Check prefixes - e.g., req.body.name should match req.body
        parts = chain.split(".")
        for i in range(len(parts), 0, -1):
            prefix = ".".join(parts[:i])
            spec = self.specs.get(prefix)
            if spec and spec.is_taint_source():
                kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
                instrs.append(TaintSource(
                    loc=loc,
                    var=PVar(target),
                    kind=kind,
                    description=spec.description or f"Taint from {prefix}"
                ))
                return instrs

        # The same keys behind a qualifier: `window.location.search`, `this.route.snapshot.queryParams`
        # (only multi-segment keys, so a bare word never matches in the middle of a chain)
        for j in range(1, len(parts)):
            for i in range(len(parts), j + 1, -1):
                key = ".".join(parts[j:i])
                spec = self.specs.get(key)
                if spec and spec.is_taint_source():
                    kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
                    instrs.append(TaintSource(
                        loc=loc, var=PVar(target), kind=kind,
                        description=spec.description or f"Taint from {key}"))
                    return instrs

        return instrs

    def _check_expression_for_taint_source(
        self,
        node: TSNode,
        target: str,
        loc: Location
    ) -> List[Instr]:
        """
        Recursively check any expression for taint sources.
        Handles member_expression, binary_expression, ternary_expression, etc.

        This is more comprehensive than _check_property_taint_source as it
        handles complex expressions like:
            - req.query.q ?? ""
            - condition ? req.body.x : default
            - (req.params.id)
        """
        if node is None:
            return []

        node_type = node.type

        # Direct member expression - delegate to existing method
        if node_type == "member_expression":
            return self._check_property_taint_source(node, target, loc)

        # Binary expressions (??. ||, etc.) - check left side
        elif node_type == "binary_expression":
            left = node.child_by_field_name("left")
            if left:
                return self._check_expression_for_taint_source(left, target, loc)

        # Ternary expression - check both branches
        elif node_type == "ternary_expression":
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")

            # Check consequence first
            if consequence:
                instrs = self._check_expression_for_taint_source(consequence, target, loc)
                if instrs:
                    return instrs

            # Check alternative
            if alternative:
                instrs = self._check_expression_for_taint_source(alternative, target, loc)
                if instrs:
                    return instrs

        # Parenthesized expression - unwrap
        elif node_type == "parenthesized_expression":
            for child in node.children:
                if child.type not in ("(", ")"):
                    return self._check_expression_for_taint_source(child, target, loc)

        # TypeScript type assertions are transparent - unwrap the value
        elif node_type in ("as_expression", "satisfies_expression",
                           "non_null_expression"):
            inner = node.named_child(0) if node.named_child_count else None
            if inner is not None:
                return self._check_expression_for_taint_source(inner, target, loc)

        # Subscript expression - check the object being accessed
        elif node_type == "subscript_expression":
            obj = node.child_by_field_name("object")
            if obj:
                return self._check_expression_for_taint_source(obj, target, loc)

        # `new URLSearchParams(location.search)` / `new URL(location.href)` carry their argument
        elif node_type == "new_expression":
            cons = node.child_by_field_name("constructor")
            args_node = node.child_by_field_name("arguments")
            if cons is not None and self._get_text(cons) in ("URLSearchParams", "URL") \
                    and args_node is not None and args_node.named_children:
                return self._check_expression_for_taint_source(args_node.named_children[0], target, loc)

        # A string method on an inline request value: `req.query.p.split(',')` (in `[1]`,
        # `x || y`, ...) keeps the request data
        elif node_type == "call_expression":
            func = node.child_by_field_name("function")
            if func is not None and func.type == "member_expression":
                receiver = func.child_by_field_name("object")
                if receiver is not None and receiver.type in ("member_expression", "call_expression", "new_expression") \
                        and not self._lookup_call_spec(self._get_call_name(node), node):
                    return self._check_expression_for_taint_source(receiver, target, loc)

        return []

    def _get_call_args(self, call_node: TSNode) -> List[TSNode]:
        """Get argument nodes from call"""
        args = []
        args_node = call_node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type not in ("(", ")", ",", "comment"):
                    args.append(child)
        return args

    def _new_ident(self, prefix: str = "tmp") -> Ident:
        """Create a new unique identifier"""
        ident = Ident(prefix, self._ident_counter)
        self._ident_counter += 1
        return ident

    def _add_instr(self, instr: Instr) -> None:
        """Add instruction to current node"""
        if self._current_node:
            self._current_node.add_instr(instr)

    def _add_instrs(self, instrs: List[Instr]) -> None:
        """Add multiple instructions to current node"""
        for instr in instrs:
            self._add_instr(instr)


class TypeScriptFrontend(JavaScriptFrontend):
    """TypeScript frontend - extends JavaScript with type annotations."""

    def __init__(self, specs: Dict[str, ProcSpec] = None):
        super().__init__(specs=specs, language="typescript")
