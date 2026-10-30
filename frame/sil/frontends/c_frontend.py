"""
C/C++ to Frame SIL Frontend.

This module translates C and C++ source code to Frame SIL using tree-sitter
for parsing. It handles:
- Function definitions
- Variable declarations
- Function calls (with taint source/sink detection)
- Control flow (if/else, while, for, switch)
- Pointers and arrays
- Structs and classes (C++)
- Preprocessor directives (limited)
"""

import re
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field

try:
    import tree_sitter_c as tsc
    from tree_sitter import Language, Parser, Node as TSNode
    TREE_SITTER_C_AVAILABLE = True
except ImportError:
    TREE_SITTER_C_AVAILABLE = False
    TSNode = Any

try:
    import tree_sitter_cpp as tscpp
    TREE_SITTER_CPP_AVAILABLE = True
except ImportError:
    TREE_SITTER_CPP_AVAILABLE = False

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
from frame.sil.c_int_model import LIMITS
from frame.sil.frontends._syntax import first_syntax_error_line
from frame.sil.metadata import ClassInfo, ImportTable, annotate_program_calls
from frame.sil.packs import finish_program
from frame.sil.loop_exit import body_can_exit_loop
from frame.sil.specs.c_specs import C_SPECS, CPP_SPECS


_MACRO_EXPR_OK = re.compile(r"^[\w\s()+\-*<>/]*$")


def eval_macro_integer(text: str, known: Dict[str, int]) -> Optional[int]:
    """Value of an object-like macro body that is a constant integer expression
    (`32`, `(1 << 20)`, `BUF + 1`, `4 * KB`), else None. Only integer literals,
    already-known macros and + - * / << parentheses are understood; anything else
    (a cast, a call, `sizeof`, a string, an unknown name) is None."""
    import ast
    text = re.sub(r"/\*.*?\*/|//.*", "", text).strip()
    if not text or not _MACRO_EXPR_OK.match(text):
        return None
    text = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]+\b", r"\1", text)
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError:
        return None

    def ev(n):
        if isinstance(n, ast.Expression):
            return ev(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, int) and not isinstance(n.value, bool):
            return n.value
        if isinstance(n, ast.Name):
            return known.get(n.id)
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, (ast.USub, ast.UAdd)):
            v = ev(n.operand)
            return None if v is None else (-v if isinstance(n.op, ast.USub) else v)
        if isinstance(n, ast.BinOp):
            a, b = ev(n.left), ev(n.right)
            if a is None or b is None:
                return None
            if isinstance(n.op, ast.Add):
                return a + b
            if isinstance(n.op, ast.Sub):
                return a - b
            if isinstance(n.op, ast.Mult):
                return a * b
            if isinstance(n.op, ast.LShift) and 0 <= b < 64:
                return a << b
            if isinstance(n.op, ast.FloorDiv) and b != 0:
                return a // b
        return None

    value = ev(tree)
    return value if value is not None and abs(value) < 2 ** 62 else None


def parse_c_integer(text: str) -> Optional[int]:
    """Value of a C integer literal, or None if it is not one.

    Python's `int(text, 0)` is close but not C: it rejects the leading-zero
    octal form, so `0777` raised and silently became 0. Permission modes are
    written exactly that way, so a mode of 0777 reached the IR looking like the
    most restrictive mode possible. Integer suffixes (`10UL`, `0x1FULL`) are
    likewise not Python syntax and are stripped here.
    """
    if not text:
        return None
    body = text.strip().replace("'", "")  # C++14 digit separators
    while body and body[-1] in "uUlLzZ":
        body = body[:-1]
    if not body:
        return None

    negative = body.startswith("-")
    if negative:
        body = body[1:]

    try:
        if body[:2].lower() in ("0x", "0b", "0o"):
            value = int(body, 0)
        elif len(body) > 1 and body[0] == "0":
            value = int(body, 8)          # C octal: 0777
        else:
            value = int(body, 10)
    except ValueError:
        return None
    return -value if negative else value


class CFrontend:
    """
    Translates C source code to Frame SIL.

    Usage:
        frontend = CFrontend()
        program = frontend.translate(source_code, "example.c")

        from frame.sil import SILTranslator
        translator = SILTranslator(program)
        checks = translator.translate_program()
    """

    LANGUAGE = "c"
    packs = None   # a frame.sil.packs.PackSet; None = the built-in packs

    def __init__(self, specs: Dict[str, ProcSpec] = None):
        """
        Initialize the C frontend.

        Args:
            specs: Library specifications (defaults to C_SPECS)
        """
        if not TREE_SITTER_C_AVAILABLE:
            raise ImportError(
                "tree-sitter-c is required. "
                "Install with: pip install tree-sitter-c"
            )

        self.parser = Parser(Language(tsc.language()))
        self.specs = specs or C_SPECS

        # State during translation
        self._filename = "<unknown>"
        self._source = ""
        self._current_proc: Optional[Procedure] = None
        self._current_node: Optional[Node] = None
        self._node_counter = 0
        self._ident_counter = 0
        self._return_tmp_counter = 0
        self._int_macros: Dict[str, int] = {}

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """Translate C source code to SIL Program."""
        self._filename = filename
        self._source = source_code
        self._source_bytes = source_code.encode("utf-8")
        self._node_counter = 0
        self._ident_counter = 0
        self._return_tmp_counter = 0

        self._jump_targets: List[Tuple[str, Optional[Node], Optional[Node]]] = []
        self._lambda_names: Dict[int, str] = {}
        self._hoisted_calls: Dict[int, Exp] = {}
        self._var_types: Dict[int, Dict[str, str]] = {}      # id(Procedure) -> {variable: declared type}
        self._ref_aliases: Dict[int, Dict[str, str]] = {}    # id(Procedure) -> {C++ reference: the local it names}
        self._class_field_types: Dict[str, Dict[str, str]] = {}
        self._lambda_parent: Dict[int, Procedure] = {}

        tree = self.parser.parse(self._source_bytes)
        program = Program(library_specs=self.specs.copy(), language=self.LANGUAGE)
        self._program = program
        program.source_files.append(filename)
        program.syntax_error_line = first_syntax_error_line(tree.root_node)
        program.function_macros = self._function_macro_names(tree.root_node)
        # the standard limits (<limits.h>, <stdint.h>) under c_int_model, then the file's own
        self._int_macros = {**LIMITS, **self._integer_macros(tree.root_node)}
        program.string_macros = dict(self._string_macro_values)
        program.global_array_bounds = self._global_array_bounds(tree.root_node)

        self._translate_translation_unit(tree.root_node, program)

        includes = ImportTable()
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "preproc_include":
                path = n.child_by_field_name("path")
                if path is not None:
                    header = self._get_text(path).strip('<>"')
                    includes.wildcards.append(header)
                    program.imports[self._get_text(path)] = header
                continue
            stack.extend(n.children)
        annotate_program_calls(program, includes)
        _qualify_option_calls(program)
        if self.LANGUAGE == "cpp":
            self._qualify_member_calls(program)
            _qualify_content_type_calls(program)
        program.import_wildcards = list(includes.wildcards)
        program.language = self.LANGUAGE
        finish_program(program, self.packs, source_code)
        return program

    def _integer_macros(self, root: TSNode) -> Dict[str, int]:
        """Object-like macros that are one top-level integer constant (`#define SLOTS 32`).

        A macro stands for its value wherever it is written, so `char buf[SLOTS]` is an array of
        32 and `i <= SLOTS` compares with 32. Only a macro defined exactly once, outside every
        conditional, and never `#undef`ed counts: with several definitions (or arms of an `#if`)
        the file does not say which one applies, so the name stays unresolved."""
        defs: Dict[str, List[Optional[str]]] = {}
        undef: Set[str] = set()
        top = root.children
        stack = [(c, True) for c in top]
        while stack:
            n, at_top = stack.pop()
            if n.type == "preproc_def":
                name = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                if name is not None:
                    key = self._get_text(name)
                    text = self._get_text(value) if value is not None else ""
                    defs.setdefault(key, []).append(text if at_top else None)
            elif n.type == "preproc_call":
                directive = n.child_by_field_name("directive")
                if directive is not None and self._get_text(directive).strip() == "#undef":
                    undef.add(self._get_text(n.child_by_field_name("argument")).strip())
            elif n.type in ("preproc_function_def", "preproc_include"):
                continue
            for c in n.children:
                if c.type not in ("comment", "string_literal"):
                    stack.append((c, at_top and n.type == "translation_unit"))
        known: Dict[str, int] = {}
        for _ in range(4):                       # macros defined in terms of earlier ones
            for name, bodies in defs.items():
                if name in known or name in undef or len(bodies) != 1 or bodies[0] is None:
                    continue
                value = eval_macro_integer(bodies[0], known)
                if value is not None:
                    known[name] = value
        # `#define ALLOWED "https://api.partner.example/"`: the same rules, for one string literal.
        self._string_macro_values = {
            name: bodies[0].strip()[1:-1] for name, bodies in defs.items()
            if name not in undef and len(bodies) == 1 and bodies[0] is not None
            and re.fullmatch(r'"[^"\\]*"', bodies[0].strip())}
        return known

    def _global_array_bounds(self, root: TSNode) -> Dict[str, int]:
        """File-scope arrays whose element count is an integer literal or integer macro."""
        bounds: Dict[str, int] = {}
        for decl in root.children:
            if decl.type != "declaration":
                continue
            for d in decl.children_by_field_name("declarator"):
                arr = d.child_by_field_name("declarator") if d.type == "init_declarator" else d
                if arr is None or arr.type != "array_declarator":
                    continue
                name, size = self._extract_identifier(arr), arr.child_by_field_name("size")
                if not name or size is None:
                    continue
                bound = parse_c_integer(self._get_text(size)) if size.type == "number_literal" \
                    else eval_macro_integer(self._get_text(size), self._int_macros)
                if bound is None or bound <= 0:
                    continue
                bounds[name] = bound if bounds.get(name, bound) == bound else -1
        return bounds

    def _function_macro_names(self, root: TSNode) -> Set[str]:
        """Names of the function-like macros `#define`d in this file. A macro
        call is not a function call: `GET_ADDR(x, ...)` may assign `x` (macros
        are expanded in place), so its arguments are not by-value reads."""
        names: Set[str] = set()
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "preproc_function_def":
                name = n.child_by_field_name("name")
                if name is not None:
                    names.add(self._get_text(name))
            stack.extend(n.children)
        return names

    def _translate_translation_unit(self, root: TSNode, program: Program) -> None:
        """Translate C translation unit (file)"""
        self._translate_node_children(root, program)

    def _translate_node_children(self, node: TSNode, program: Program) -> None:
        """Recursively translate children, handling C++ namespaces and classes."""
        for child in node.children:
            if child.type == "function_definition":
                proc = self._translate_function(child)
                if proc:
                    program.add_procedure(proc)
            elif child.type == "namespace_definition":
                # C++ namespace - recurse into body to find functions
                body = child.child_by_field_name("body")
                if body:
                    self._translate_node_children(body, program)
            elif child.type == "class_specifier":
                # C++ class - recurse into body to find inline methods
                body = child.child_by_field_name("body")
                if body:
                    self._translate_node_children(body, program)
            elif child.type == "struct_specifier":
                # C/C++ struct - recurse into body to find inline methods
                body = child.child_by_field_name("body")
                if body:
                    self._translate_node_children(body, program)
            elif child.type == "declaration_list":
                # Recurse into declaration lists (namespace bodies, class bodies)
                self._translate_node_children(child, program)
            elif child.type == "declaration":
                # Global variable declaration - skip for now
                pass
            elif child.type == "preproc_include":
                # Handle includes - skip for now
                pass
            elif child.type == "preproc_define":
                # Handle defines - skip for now
                pass
            elif child.type == "preproc_ifdef" or child.type == "preproc_ifndef":
                # Recurse into ifdef/ifndef blocks
                self._translate_node_children(child, program)

    def _translate_function(self, node: TSNode) -> Optional[Procedure]:
        """Translate function definition"""
        declarator = node.child_by_field_name("declarator")
        if not declarator:
            return None

        # Get function name
        func_name = self._get_function_name(declarator)
        if not func_name:
            return None

        # Get parameters
        params = self._translate_parameters(declarator)
        param_types = dict(getattr(self, "_last_param_types", {}))

        # Get return type
        ret_type_node = node.child_by_field_name("type")
        ret_type = self._translate_type(ret_type_node) if ret_type_node else Typ.unknown_type()

        proc = Procedure(
            name=func_name,
            params=params,
            ret_type=ret_type,
            loc=self._get_location(node),
            is_method=False,
        )

        proc.param_types = param_types
        proc.scalar_types = dict(getattr(self, "_last_scalar_param_types", {}))
        proc.has_parse_errors = bool(node.has_error)
        fdecl = declarator
        while fdecl is not None and fdecl.type != "function_declarator":
            fdecl = fdecl.child_by_field_name("declarator")
        plist = fdecl.child_by_field_name("parameters") if fdecl is not None else None
        proc.has_varargs = plist is not None and any(
            c.type in ("...", "variadic_parameter") for c in plist.children)

        self._current_proc = proc
        self._node_counter = 0

        # Create entry node
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry

        # `optarg` (getopt's global) holds the text of a command-line option: attacker data
        # in any function that reads it
        if re.search(r"\boptarg\b", self._get_text(node)):
            self._add_instr(TaintSource(
                loc=self._get_location(node), var=PVar("optarg"),
                kind=TaintKind.USER_INPUT, description="getopt option argument (optarg)"))

        # Mark main parameters as taint sources
        if func_name == "main":
            for param, _ in params:
                if param.name in ("argv", "envp"):
                    self._add_instr(TaintSource(
                        loc=self._get_location(node),
                        var=param,
                        kind=TaintKind.USER_INPUT,
                        description="Command line argument"
                    ))

        # C++ member initializers (`: data_(new unsigned char[n]), size_(n)`) run before the
        # body: each is `data_ = new unsigned char[n]`.
        for init_list in (c for c in node.children if c.type == "field_initializer_list"):
            for init in (c for c in init_list.named_children if c.type == "field_initializer"):
                name = next((c for c in init.named_children if c.type == "field_identifier"), None)
                args = next((c for c in init.named_children
                             if c.type in ("argument_list", "initializer_list")), None)
                values = [a for a in args.named_children if a.type != "comment"] if args is not None else []
                if name is not None and len(values) == 1:
                    self._assign_to_identifier(self._get_text(name), values[0], "=",
                                               self._get_location(init))

        # Translate body
        body = node.child_by_field_name("body")
        if body:
            self._translate_compound_statement(body)

        # Create exit node
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id

        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)

        self._current_proc = None
        return proc

    def _get_function_name(self, declarator: TSNode) -> Optional[str]:
        """Extract function name from declarator"""
        if declarator.type == "function_declarator":
            inner = declarator.child_by_field_name("declarator")
            if inner:
                if inner.type in ("identifier", "field_identifier"):
                    return self._get_text(inner)
                elif inner.type in ("qualified_identifier", "destructor_name", "operator_name"):
                    # C++ class method: Class::method
                    return self._get_text(inner)
                elif inner.type in ("pointer_declarator", "reference_declarator"):
                    # Handle pointer return type
                    return self._get_function_name(inner)
        elif declarator.type in ("pointer_declarator", "reference_declarator"):
            inner = declarator.child_by_field_name("declarator") or (
                declarator.named_children[-1] if declarator.named_children else None)
            if inner:
                return self._get_function_name(inner)
        elif declarator.type == "identifier":
            return self._get_text(declarator)
        elif declarator.type == "qualified_identifier":
            # C++ qualified name like Class::method
            return self._get_text(declarator)
        return None

    def _translate_parameters(self, declarator: TSNode) -> List[Tuple[PVar, Typ]]:
        """Translate function parameters"""
        if declarator.type != "function_declarator":
            # Handle pointer / reference declarator around the function declarator
            if declarator.type in ("pointer_declarator", "reference_declarator"):
                inner = declarator.child_by_field_name("declarator") or (
                    declarator.named_children[-1] if declarator.named_children else None)
                if inner:
                    return self._translate_parameters(inner)
            return []
        return self._params_from_list(declarator.child_by_field_name("parameters"))

    def _params_from_list(self, params_node: Optional[TSNode]) -> List[Tuple[PVar, Typ]]:
        """The (name, type) of each parameter in a `parameter_list`; the written type
        of each is left in `self._last_param_types` (name -> `httplib::Request`)."""
        params: List[Tuple[PVar, Typ]] = []
        self._last_param_types = {}
        self._last_scalar_param_types = {}
        if not params_node:
            return params
        for child in params_node.children:
            if child.type in ("parameter_declaration", "optional_parameter_declaration",
                              "variadic_parameter_declaration"):
                param_type = Typ.unknown_type()
                param_name = None

                type_node = child.child_by_field_name("type")
                if type_node:
                    param_type = self._translate_type(type_node)

                decl_node = child.child_by_field_name("declarator")
                if decl_node:
                    param_name = self._extract_identifier(decl_node)

                if param_name:
                    params.append((PVar(param_name), param_type))
                    if type_node is not None:
                        self._last_param_types[param_name] = self._get_text(type_node)
                        if decl_node.type == "identifier":
                            self._last_scalar_param_types[param_name] = self._get_text(type_node)

        return params

    def _extract_identifier(self, node: TSNode) -> Optional[str]:
        """Extract identifier from declarator node"""
        if node.type in ("identifier", "field_identifier"):
            return self._get_text(node)
        elif node.type in ("pointer_declarator", "array_declarator", "reference_declarator",
                           "parenthesized_declarator", "init_declarator"):
            inner = node.child_by_field_name("declarator")
            if inner is None:
                named = [c for c in node.named_children if c.type != "type_qualifier"]
                inner = named[-1] if named else None
            if inner:
                return self._extract_identifier(inner)
        return None

    def _translate_type(self, node: TSNode) -> Typ:
        """Translate type specifier"""
        text = self._get_text(node)
        if "int" in text:
            return Typ.int_type()
        elif "char" in text:
            return Typ.int_type()  # char as int
        elif "float" in text or "double" in text:
            return Typ.int_type()  # simplified
        elif "void" in text:
            return Typ(kind=TypeKind.VOID)
        elif "*" in text:
            return Typ(kind=TypeKind.POINTER)
        return Typ.unknown_type()

    def _translate_compound_statement(self, node: TSNode) -> None:
        """Translate compound statement (block)"""
        for child in node.children:
            if child.type not in ("{", "}"):
                self._translate_statement(child)

    def _translate_statement(self, node: TSNode) -> None:
        """Translate a statement"""
        if node.type == "expression_statement":
            self._translate_expression_statement(node)
        elif node.type == "declaration":
            self._translate_declaration(node)
        elif node.type == "return_statement":
            self._translate_return(node)
        elif node.type == "if_statement":
            self._translate_if(node)
        elif node.type == "while_statement":
            self._translate_while(node)
        elif node.type == "for_statement":
            self._translate_for(node)
        elif node.type == "do_statement":
            self._translate_do_while(node)
        elif node.type == "switch_statement":
            self._translate_switch(node)
        elif node.type == "compound_statement":
            self._translate_compound_statement(node)
        elif node.type == "break_statement":
            self._translate_jump(is_break=True)
        elif node.type == "continue_statement":
            self._translate_jump(is_break=False)
        elif node.type in ("preproc_if", "preproc_ifdef"):
            self._translate_preproc_conditional(node)
        elif node.type == "goto_statement":
            # A goto leaves the straight-line path. The jump target is not
            # modelled, so end the path here the way a call that never returns
            # does; otherwise `if (!p) goto error;` falls through with p still
            # null and the code after it is analysed as if the guard did nothing.
            self._add_instr(Call(loc=self._get_location(node), ret=None,
                                 func=ExpConst.string("__frame_goto__"), args=[]))

    def _translate_expression_statement(self, node: TSNode) -> None:
        """Translate expression statement"""
        for child in node.children:
            if child.type == "call_expression":
                instrs = self._translate_call(child)
                self._add_instrs(instrs)
            elif child.type == "assignment_expression":
                self._translate_assignment(child)
            elif child.type == "update_expression":
                self._translate_update(child)
            elif child.type == "delete_expression":
                self._translate_delete(child)
            elif child.type != ";":
                # Other expression - translate for side effects
                exp = self._translate_expression(child)

    def _translate_delete(self, node: TSNode) -> None:
        """Translate a C++ `delete p` / `delete[] p` into a deallocator call.

        The operand's base pointer is the argument, and the routine name is the
        exact operator (`delete` vs `delete[]`) so the translator can both track
        the release for use-after-free and check it against the allocator that
        produced the pointer (a `delete[]` on a `new` object is CWE-762). Without
        this the frontend dropped `delete` entirely and every C++ deallocation was
        invisible to the heap-lifecycle analysis.
        """
        loc = self._get_location(node)
        is_array = any(c.type == "[" for c in node.children)
        # The operand is the last expression child (the pointer being deleted).
        operand = None
        for child in node.children:
            if child.type not in ("delete", "[", "]"):
                operand = child
        if operand is None:
            return
        arg_exp = self._translate_expression(operand)
        routine = "delete[]" if is_array else "delete"
        self._add_instr(Call(
            loc=loc,
            ret=None,
            func=ExpConst.string(routine),
            args=[(arg_exp, Typ.unknown_type())],
        ))

    def _record_local(self, name: Optional[str]) -> None:
        """Note `name` as a local variable declared in the current procedure.

        The IR keeps no type for most locals, but the mere fact that a name is a
        declared local (rather than a global or a struct field) is what lets the
        return-of-stack-address check tell `return &x` for a local `x` apart from
        `return &g` for a global, so the name alone is recorded.
        """
        if name and self._current_proc is not None:
            self._current_proc.locals.setdefault(name, Typ.unknown_type())

    def _translate_declaration(self, node: TSNode) -> None:
        """Translate variable declaration"""
        type_node = node.child_by_field_name("type")
        for child in node.children:
            if child.type == "init_declarator":
                decl = child.child_by_field_name("declarator")
                self._record_fixed_array_bound(decl)
                self._record_array_from_string_init(decl, child.child_by_field_name("value"))
                self._record_local(self._extract_identifier(decl))
                self._note_var_type(self._extract_identifier(decl), type_node)
                self._note_scalar_type(decl, type_node)
                if self._note_reference_alias(decl, child.child_by_field_name("value")):
                    continue
                self._translate_init_declarator(child, type_node)
            elif child.type == "function_declarator" and self._translate_vexing_constructor(child, type_node):
                continue
            elif child.type in ("identifier", "pointer_declarator", "array_declarator",
                                "reference_declarator"):
                # Declaration without initialization
                self._record_fixed_array_bound(child)
                var_name = self._extract_identifier(child)
                self._record_local(var_name)
                self._note_var_type(var_name, type_node)
                self._note_scalar_type(child, type_node)
                if var_name:
                    loc = self._get_location(child)
                    self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=ExpConst.null(),
                                           is_uninit_decl=not self._is_default_constructed(child, type_node)))

    def _record_array_from_string_init(self, declarator: Optional[TSNode],
                                       value: Optional[TSNode]) -> None:
        """A `char s[] = "..."` array has no written size but a size the
        initializer fixes: the literal's length plus the NUL terminator. Recording
        that bound lets the same stack-origin reasoning that covers `char s[N]`
        also cover the inferred form, so returning such an array is caught as a
        return of a stack address (CWE-562) and freeing it as a non-heap free.
        """
        if (declarator is None or declarator.type != "array_declarator"
                or self._current_proc is None or value is None):
            return
        if declarator.child_by_field_name("size") is not None:
            return  # an explicit size is already handled by _record_fixed_array_bound
        if value.type != "string_literal":
            return
        name = self._extract_identifier(declarator)
        if not name:
            return
        text = self._get_text(value)
        inner = text[1:-1] if len(text) >= 2 else text
        bound = len(inner) + 1
        bounds = self._current_proc.fixed_array_bounds
        if name in bounds and bounds[name] != bound:
            bounds[name] = -1
        elif bounds.get(name) != -1:
            bounds[name] = bound
            self._note_char_array(declarator, name)

    def _subscript_index(self, node: TSNode) -> Optional[TSNode]:
        """The index node of a `subscript_expression`, across both grammars.

        tree-sitter-c exposes it as an `index` field. tree-sitter-cpp wraps it
        in a `subscript_argument_list` instead, and reading the missing field
        there returned None, so a subscripted assignment in C++ produced no
        instruction at all and was invisible to every analysis downstream.
        """
        index = node.child_by_field_name("index")
        if index is not None:
            return index

        for child in node.children:
            if child.type == "subscript_argument_list":
                inner = [c for c in child.children if c.type not in ("[", "]", ",")]
                # Only a single-dimension subscript has an unambiguous index.
                return inner[0] if len(inner) == 1 else None
        return None

    _CHAR_TYPE_RE = re.compile(
        r"^(?:const\s+|volatile\s+|static\s+|register\s+)*"
        r"(?:(?:unsigned|signed)\s+)?(?:char|int8_t|uint8_t)$")

    def _note_char_array(self, declarator: TSNode, name: str) -> None:
        """Record `name` as a one-byte-element array when its declared type is a
        plain character type, so its element count is a byte capacity."""
        node = declarator.parent
        while node is not None and node.type not in ("declaration", "field_declaration"):
            node = node.parent
        if node is None:
            return
        type_node = node.child_by_field_name("type")
        if type_node is None:
            return
        # Qualifiers such as `const`/`static` are siblings of the type node.
        prefix = " ".join(self._get_text(c) for c in node.children
                          if c.type in ("type_qualifier", "storage_class_specifier"))
        if self._CHAR_TYPE_RE.match(f"{prefix} {self._get_text(type_node)}".strip()):
            self._current_proc.char_array_locals.add(name)

    def _record_fixed_array_bound(self, declarator: Optional[TSNode]) -> None:
        """Note `char buf[10]` as a bound of 10 on the current procedure.

        The IR lowers such a declaration to `buf = null` and keeps no type, so
        the element count survives nowhere else. Only a declarator whose size is
        an integer LITERAL is recorded: `char buf[N]` for a macro or a const is
        a real bound too, but resolving it means reasoning about values, and a
        wrong bound here would manufacture an out-of-bounds finding.

        A name declared twice in one procedure (an inner scope shadowing an
        outer one) is dropped entirely unless both declarations agree, because
        the IR has no scopes and cannot say which one an index refers to.
        """
        if declarator is None or declarator.type != "array_declarator" or self._current_proc is None:
            return

        name = self._extract_identifier(declarator)
        if name:
            self._current_proc.array_locals.add(name)
        size_node = declarator.child_by_field_name("size")
        if not name or size_node is None:
            return
        if size_node.type == "number_literal":
            bound = parse_c_integer(self._get_text(size_node))
        else:
            # `char buf[SLOTS]`, `char buf[BUF_MAX + 1]`: an integer macro (or arithmetic over them)
            bound = eval_macro_integer(self._get_text(size_node), self._int_macros)
        if bound is None or bound <= 0:
            return

        bounds = self._current_proc.fixed_array_bounds
        if name in bounds and bounds[name] != bound:
            # Conflicting declarations of one name: refuse to pick.
            bounds[name] = -1
        elif bounds.get(name) != -1:
            bounds[name] = bound
            self._note_char_array(declarator, name)

    def _translate_vexing_constructor(self, fdecl: TSNode, type_node: Optional[TSNode]) -> bool:
        """`std::ifstream in(path);` inside a function body is a variable initialised by a
        constructor call, but C++'s grammar also reads it as the declaration of a function `in`
        taking a `path`. When every "parameter" is a bare identifier (no parameter name), it
        is the constructor call: lower it as one."""
        if (self._current_proc is None or type_node is None
                or type_node.type not in ("type_identifier", "qualified_identifier", "template_type")):
            return False
        name_node = fdecl.child_by_field_name("declarator")
        plist = fdecl.child_by_field_name("parameters")
        if name_node is None or name_node.type != "identifier" or plist is None:
            return False
        args: List[Exp] = []
        for p in plist.children:
            if p.type in ("(", ")", ",", "comment"):
                continue
            if p.type != "parameter_declaration" or p.child_by_field_name("declarator") is not None:
                return False
            t = p.child_by_field_name("type")
            if t is None or t.type != "type_identifier" or p.named_child_count != 1:
                return False
            args.append(ExpVar(PVar(self._get_text(t))))
        var_name = self._get_text(name_node)
        loc = self._get_location(fdecl)
        self._record_local(var_name)
        self._note_var_type(var_name, type_node)
        ret_id = self._new_ident(var_name)
        self._add_instr(Call(loc=loc, ret=(ret_id, Typ.unknown_type()),
                             func=ExpConst.string(self._type_base_name(self._get_text(type_node))),
                             args=[(a, Typ.unknown_type()) for a in args]))
        self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=ExpVar(ret_id)))
        return True

    _SCALAR_TYPEDEF = re.compile(r"(?:^|::)(?:u?int\d*_t|u?intptr_t|u?intmax_t|size_t|ssize_t|ptrdiff_t|off_t|"
                                 r"time_t|pid_t|uid_t|gid_t|mode_t|socklen_t|sig_atomic_t|wchar_t|char\d*_t|"
                                 r"DWORD|BOOL|BYTE|WORD|HANDLE|LPVOID|SOCKET|qint\d+|quint\d+|qreal|uint|ulong|ushort|uchar)$")

    def _is_default_constructed(self, declarator: TSNode, type_node: Optional[TSNode]) -> bool:
        """C++ `std::ostringstream out;` / `QString s;` / `boost::asio::io_context io;` runs a
        constructor: it is not an uninitialised read waiting to happen (CWE-457 is about
        scalars and raw buffers). A pointer, reference or array of such a type, and a
        typedef that is a plain scalar (`size_t n;`), still are uninitialised."""
        if self.LANGUAGE != "cpp" or type_node is None or declarator.type != "identifier":
            return False
        if type_node.type not in ("type_identifier", "qualified_identifier", "template_type"):
            return False
        return not self._SCALAR_TYPEDEF.search(self._get_text(type_node))

    def _note_var_type(self, name: Optional[str], type_node: Optional[TSNode]) -> None:
        """Remember the declared type of a local (C++): member calls on it are then
        qualified with the type (`proc.start(...)` -> `QProcess::start`)."""
        if name and type_node is not None and self._current_proc is not None:
            text = self._get_text(type_node)
            if text and text not in ("auto", "var"):
                self._var_types.setdefault(id(self._current_proc), {})[name] = text

    def _note_reference_alias(self, declarator: Optional[TSNode], value: Optional[TSNode]) -> bool:
        """C++ `T &r = x;` with `x` a local or parameter of this function: a reference is
        another name for `x` and can never be bound to anything else, so every later use of
        `r` is lowered as `x` (reads and writes alike). Anything else (a field, an element, a
        call, a name declared twice) is left as an ordinary variable."""
        proc = self._current_proc
        if (self.LANGUAGE != "cpp" or proc is None or declarator is None or value is None
                or declarator.type != "reference_declarator" or value.type != "identifier"):
            return False
        inner = next((c for c in declarator.named_children if c.type == "identifier"), None)
        if inner is None:
            return False
        ref, target = self._get_text(inner), self._alias_of(self._get_text(value))
        aliases = self._ref_aliases.setdefault(id(proc), {})
        is_local = target in (proc.locals or {}) or target in {p.name for p, _ in proc.params}
        if ref in aliases or ref == target or not is_local:
            aliases.pop(ref, None)
            return False
        aliases[ref] = target
        return True

    def _alias_of(self, name: str) -> str:
        proc = self._current_proc
        return self._ref_aliases.get(id(proc), {}).get(name, name) if proc is not None else name

    def _note_scalar_type(self, declarator: Optional[TSNode], type_node: Optional[TSNode]) -> None:
        """`Procedure.scalar_types`: a plain variable's declared type (not a pointer or array)."""
        if declarator is None or type_node is None or declarator.type != "identifier" \
                or self._current_proc is None:
            return
        name, text = self._get_text(declarator), " ".join(self._get_text(type_node).split())
        known = self._current_proc.scalar_types
        known[name] = text if known.get(name, text) == text else ""

    def _translate_init_declarator(self, node: TSNode, type_node: Optional[TSNode] = None) -> None:
        """Translate init_declarator (var = value)"""
        declarator = node.child_by_field_name("declarator")
        value = node.child_by_field_name("value")

        if not declarator:
            return

        var_name = self._extract_identifier(declarator)
        if not var_name:
            return

        loc = self._get_location(node)

        if (value is not None and value.type == "argument_list" and type_node is not None
                and type_node.type in ("type_identifier", "qualified_identifier", "template_type")):
            # constructor-style initialisation `QFile f(path);` / `std::ifstream in(path);`:
            # a call to the type's constructor, so specs and packs can see it
            args = [a for a in value.children if a.type not in ("(", ")", ",", "comment")]
            for a in args:
                if a.type == "lambda_expression":
                    self._lower_lambda(a)
            type_text = self._type_base_name(self._get_text(type_node))
            ret_id = self._new_ident(var_name)
            self._add_instr(Call(loc=loc, ret=(ret_id, Typ.unknown_type()),
                                 func=ExpConst.string(type_text),
                                 args=[(self._translate_expression(a), Typ.unknown_type()) for a in args]))
            self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=ExpVar(ret_id)))
            return

        if value:
            if value.type == "call_expression":
                instrs = self._translate_call_assignment(var_name, value, loc)
                self._add_instrs(instrs)
            else:
                exp = self._translate_expression(value)
                self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=exp))
        else:
            self._add_instr(Assign(loc=loc, id=PVar(var_name),
                                   exp=ExpConst.null(), is_uninit_decl=True))

    def _assign_to_identifier(self, target: str, right: TSNode, op: str, loc: Location) -> None:
        """`target op right` for a plain name (a local, a global, or a member written by its
        bare name or in a constructor's initializer list)."""
        target = self._alias_of(target)
        if op != "=":
            # Compound assignment `x += e` is `x = x + e`; lowering it as
            # `x = e` dropped the old value (and made `x == e` a false fact).
            exp = ExpBinOp(op[:-1], ExpVar(PVar(target)), self._translate_expression(right))
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=exp))
        elif right.type == "call_expression":
            instrs = self._translate_call_assignment(target, right, loc)
            self._add_instrs(instrs)
        else:
            exp = self._translate_expression(right)
            if isinstance(exp, ExpCall) and not self._is_local_name(target):
                # `data_ = new T[n]` / `g_buf = (char *)malloc(n)` where `data_` is a member or a
                # global: the allocation is handed to something that outlives the function. Bind it to
                # a temporary first, as for `p = malloc(n)`, so the ownership analysis sees the hand-off.
                self._return_tmp_counter += 1
                tmp = f"$own{self._return_tmp_counter}"
                self._add_instr(Assign(loc=loc, id=PVar(tmp), exp=exp))
                exp = ExpVar(PVar(tmp))
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=exp))

    def _translate_assignment(self, node: TSNode) -> None:
        """Translate assignment expression"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        if not left or not right:
            return

        loc = self._get_location(node)

        op_node = node.child_by_field_name("operator")
        op = self._get_text(op_node) if op_node is not None else "="

        # Get target variable/field
        if left.type == "identifier":
            self._assign_to_identifier(self._get_text(left), right, op, loc)
        elif left.type == "pointer_expression":
            # *ptr = value (store)
            inner = left.child_by_field_name("argument")
            if inner:
                ptr_exp = self._translate_expression(inner)
                val_exp = self._translate_expression(right)
                self._add_instr(Store(loc=loc, addr=ptr_exp, value=val_exp, typ=Typ.unknown_type()))
        elif left.type == "subscript_expression":
            # arr[i] = value
            arr = left.child_by_field_name("argument")
            idx = self._subscript_index(left)
            if arr and idx:
                arr_exp = self._translate_expression(arr)
                idx_exp = self._translate_expression(idx)
                val_exp = self._translate_expression(right)
                # Model as store to arr + idx
                addr = ExpBinOp("+", arr_exp, idx_exp)
                self._add_instr(Store(loc=loc, addr=addr, value=val_exp, typ=Typ.unknown_type()))
        elif left.type == "field_expression":
            # struct.field = value or ptr->field = value
            obj = left.child_by_field_name("argument")
            field = left.child_by_field_name("field")
            if obj and field:
                obj_exp = self._translate_expression(obj)
                field_name = self._get_text(field)
                # Model as assignment to synthetic variable
                target = f"{self._get_text(obj)}_{field_name}"
                if right.type == "call_expression" and op == "=" and self._current_node is not None:
                    # `out->key = strdup(s)`: the call is its own Call bound to a temporary and the
                    # field receives the temporary, exactly as for `p = strdup(s)`. The ownership
                    # analysis then sees an allocation handed to a caller-visible location (an escape),
                    # not a fresh allocation owned by a local called `out_key` that is never freed.
                    self._return_tmp_counter += 1
                    tmp = f"$fld{self._return_tmp_counter}"
                    self._add_instrs(self._translate_call_assignment(tmp, right, loc))
                    val_exp = ExpVar(PVar(tmp))
                else:
                    val_exp = self._translate_expression(right)
                if self._is_arrow_access(left):
                    # `p->f = v` stores THROUGH p. The synthetic assignment below
                    # hides that, so expose the dereference of p as a marker read
                    # (a dummy temp bound to `p->f`) for the null/freed-pointer
                    # checks. The marker adds no taint and no value flow.
                    self._add_instr(Assign(
                        loc=loc, id=PVar(f"$deref_{target}"),
                        exp=ExpFieldAccess(obj_exp, field_name, True)))
                self._add_instr(Assign(loc=loc, id=PVar(target), exp=val_exp))

    @staticmethod
    def _is_arrow_access(field_node: TSNode) -> bool:
        """Is this field_expression `ptr->field` (vs `struct.field`)?"""
        return any(c.type == "->" for c in field_node.children)

    def _translate_call_assignment(
        self,
        target: str,
        call_node: TSNode,
        loc: Location
    ) -> List[Instr]:
        """Translate: target = func(args)"""
        instrs = []

        accessed = self._content_accessor_receiver(call_node)
        if accessed is not None:
            # `fmt = body["format"].s()` / `t = text.toStdString()`: the receiver's contents
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=self._translate_expression(accessed)))
            return []

        func_name = self._get_call_name(call_node)
        args = self._get_call_args(call_node)
        self._lower_lambda_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        ret_id = self._new_ident(target)
        instrs.extend(self._alias_chain_receiver(func_name, loc))
        instrs.extend(self._nested_usage_sink_calls(args, loc))

        call_instr = Call(
            loc=loc,
            ret=(ret_id, Typ.unknown_type()),
            func=ExpConst.string(func_name),
            args=args_exp
        )
        instrs.append(call_instr)
        instrs.append(Assign(loc=loc, id=PVar(target), exp=ExpVar(ret_id)))

        # Check specs
        spec = self.specs.get(func_name)
        if spec and spec.is_taint_source():
            kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
            instrs.append(TaintSource(loc=loc, var=PVar(target), kind=kind, description=spec.description))

        if spec and spec.is_taint_sink():
            kind = resolve_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = self._translate_expression(args[arg_idx])
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description,
                                            arg_index=arg_idx, call=func_name))

        return instrs

    _CHAIN_CALL = re.compile(r"^([A-Za-z_]\w*)((?:\.[A-Za-z_]\w*)+)\.[A-Za-z_]\w*$")

    def _alias_chain_receiver(self, func_name: str, loc: Location) -> List[Instr]:
        """`req.url_params.get(k)`: the translator carries a receiver's taint to the call's
        result by the receiver's name ("req.url_params"), which no assignment ever tainted.
        Alias the receiver chain to its root variable first (C++ only)."""
        if self.LANGUAGE != "cpp":
            return []
        m = self._CHAIN_CALL.match(func_name)
        if not m or m.group(1) in ("this", "std"):
            return []
        receiver = func_name.rsplit(".", 1)[0]
        return [Assign(loc=loc, id=PVar(receiver), exp=ExpVar(PVar(m.group(1))))]

    def _nested_usage_sink_calls(self, args: List[TSNode], loc: Location) -> List[Instr]:
        """Argument-less calls written as arguments whose use alone is the finding
        (`EVP_md5()`, `EVP_des_ecb()`, `TLSv1_method()` in `EVP_DigestInit_ex(ctx,
        EVP_md5(), NULL)`): lowered as arguments they have no Call instruction of
        their own, so a usage-based sink spec or pack rule never fired. Emit the
        bare call ahead of the enclosing one (it has no arguments to carry taint)."""
        out: List[Instr] = []
        for a in args:
            while a is not None and a.type == "parenthesized_expression" and a.named_child_count == 1:
                a = a.named_children[0]
            if a is None or a.type != "call_expression":
                continue
            name = self._get_call_name(a)
            if name and not self._get_call_args(a):
                out.append(Call(loc=self._get_location(a), ret=None,
                                func=ExpConst.string(name), args=[]))
        return out

    def _translate_call(self, call_node: TSNode) -> List[Instr]:
        """Translate standalone function call"""
        instrs = []
        loc = self._get_location(call_node)

        func_name = self._get_call_name(call_node)
        args = self._get_call_args(call_node)
        self._lower_lambda_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        instrs.extend(self._alias_chain_receiver(func_name, loc))
        instrs.extend(self._nested_usage_sink_calls(args, loc))
        call_instr = Call(
            loc=loc,
            ret=None,
            func=ExpConst.string(func_name),
            args=args_exp
        )
        instrs.append(call_instr)

        spec = self.specs.get(func_name)
        if spec and spec.is_taint_sink():
            kind = resolve_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = self._translate_expression(args[arg_idx])
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description,
                                            arg_index=arg_idx, call=func_name))

        return instrs

    def _preproc_arms(self, node: TSNode) -> List[List[TSNode]]:
        """The statement lists of each arm of an `#if` / `#ifdef` chain (through
        `#elif` / `#else`). A chain with no `#else` has an implicit empty arm,
        and an `#if 0` arm is dead code and contributes nothing."""
        arms: List[List[TSNode]] = []
        cur = node
        while cur is not None:
            alt = cur.child_by_field_name("alternative")
            cond = cur.child_by_field_name("condition")
            header = {c.id for c in (cur.child_by_field_name("name"), cond, alt) if c is not None}
            dead = cond is not None and cond.type == "number_literal" and self._get_text(cond).strip() == "0"
            if not dead:
                arms.append([c for c in cur.children if c.is_named and c.id not in header])
            if alt is None:
                if cur.type != "preproc_else":
                    arms.append([])
                break
            cur = alt
        return arms

    def _translate_preproc_conditional(self, node: TSNode) -> None:
        """`#if` / `#ifdef` inside a function body. Which arm is compiled is not
        known, so each arm is a branch from the current node with no guard, and
        the arms rejoin afterwards. Skipping the directive (as before) dropped
        every statement in it, e.g. both assignments of `src` in
        `#ifdef X  src = a(); #else  src = b(); #endif`."""
        proc = self._current_proc
        if proc is None or self._current_node is None:
            return
        before = self._current_node
        join = proc.new_node(NodeKind.JOIN)
        proc.add_node(join)
        for stmts in self._preproc_arms(node):
            arm = proc.new_node(NodeKind.NORMAL)
            proc.add_node(arm)
            proc.connect(before.id, arm.id)
            self._current_node = arm
            for stmt in stmts:
                self._translate_statement(stmt)
            if self._current_node:
                proc.connect(self._current_node.id, join.id)
        self._current_node = join

    def _translate_jump(self, is_break: bool) -> None:
        """`break` / `continue`: an edge to the innermost enclosing loop's exit
        (or next iteration), then a fresh unreachable node, so nothing after the
        jump falls through. Without these edges a loop exited only by `break`
        looked as if it could leave through its condition before the body ran,
        and every path fact after the loop described the wrong paths.

        A `break` inside a switch is an edge to the join after the switch (see
        _translate_switch); a `continue` inside a switch targets the enclosing loop."""
        proc = self._current_proc
        if proc is None or self._current_node is None:
            return
        target = None
        for kind, exit_node, next_node in reversed(self._jump_targets):
            if is_break:
                target = exit_node
                break
            if next_node is not None:
                target = next_node
                break
        if target is None:
            return
        proc.connect(self._current_node.id, target.id)
        unreachable = proc.new_node(NodeKind.NORMAL)
        proc.add_node(unreachable)
        self._current_node = unreachable

    def _translate_effects(self, node: TSNode) -> None:
        """Lower an expression evaluated only for its side effects (a `for`
        initializer or update), including every element of a comma list:
        `for (i = 0, j = s; ...; i++, j += step)`."""
        if node is None:
            return
        if node.type == "comma_expression":
            self._translate_effects(node.child_by_field_name("left"))
            self._translate_effects(node.child_by_field_name("right"))
        elif node.type == "assignment_expression":
            self._translate_assignment(node)
        elif node.type == "update_expression":
            self._translate_update(node)
        elif node.type in ("parenthesized_expression", "condition_clause"):
            for child in node.children:
                if child.type not in ("(", ")"):
                    self._translate_effects(child)
        else:
            self._translate_expression(node)

    def _translate_update(self, node: TSNode) -> None:
        """Translate update expression: i++ or ++i"""
        loc = self._get_location(node)
        arg = node.child_by_field_name("argument")
        if arg and arg.type == "identifier":
            var_name = self._get_text(arg)
            op = self._get_text(node.child_by_field_name("operator")) if node.child_by_field_name("operator") else "++"
            if "++" in self._get_text(node):
                self._add_instr(Assign(
                    loc=loc,
                    id=PVar(var_name),
                    exp=ExpBinOp("+", ExpVar(PVar(var_name)), ExpConst.integer(1))
                ))
            elif "--" in self._get_text(node):
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
                inner = child
                while inner.type == "parenthesized_expression" and inner.named_child_count == 1:
                    inner = inner.named_children[0]
                if inner.type == "call_expression" and not self._is_value_call(inner):
                    # `return system(cmd);` is `tmp = system(cmd); return tmp;`: the call must be a
                    # Call instruction of its own or no spec (sink, source, sanitizer) ever sees it.
                    self._return_tmp_counter += 1
                    tmp = f"$ret{self._return_tmp_counter}"
                    self._add_instrs(self._translate_call_assignment(tmp, inner, loc))
                    value_exp = ExpVar(PVar(tmp))
                else:
                    value_exp = self._translate_expression(child)
                break

        self._add_instr(Return(loc=loc, value=value_exp))

    def _is_local_name(self, name: str) -> bool:
        """Is `name` a local variable or parameter of the procedure being translated? Anything else
        assigned in a function body is a member, a global or a captured variable."""
        proc = self._current_proc
        if proc is None:
            return True
        return name in (proc.locals or {}) or name in {p.name for p, _ in proc.params}

    def _delivers_into_arguments(self, call_node: TSNode) -> bool:
        """Must this call be its own Call instruction even inside an expression? It fills one of
        its arguments with input (`read`, `recv`, `fgets`, `fread`), or the call itself is a
        finding: a usage sink (`MD5(...)`, `tmpnam(...)`) or a weak algorithm constant at its
        `algorithm_arg` (`if (!CryptCreateHash(prov, CALG_MD5, ...))`). An expression-level call
        only carries its return value, so none of those would be seen."""
        spec = self.specs.get(self._get_call_name(call_node))
        if spec is None:
            return False
        usage_sink = bool(spec.is_sink) and spec.sink_args is not None and not spec.sink_args
        return bool(getattr(spec, "taint_out_args", None)) or spec.algorithm_arg is not None or usage_sink

    def _is_value_call(self, call_node: TSNode) -> bool:
        """A call the expression translator already lowers to a value (`sizeof`-like or a
        content accessor): left alone."""
        return self._content_accessor_receiver(call_node) is not None

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
            # tree-sitter wraps the else body in an `else_clause` node, which
            # `_translate_statement` does not recognise; descending into it is what
            # keeps the else branch in the CFG at all (otherwise the whole branch,
            # and any definition it makes, is silently dropped).
            if alternative.type == "else_clause":
                for child in alternative.children:
                    if child.type != "else":
                        self._translate_statement(child)
            else:
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

        before_node = self._current_node

        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)

        # The condition is evaluated in the loop head on every iteration, so any
        # assignment inside it (`while ((e = next(f)))`) is lowered there.
        self._current_node = loop_head
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)

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
            self._jump_targets.append(("loop", after_node, loop_head))
            try:
                self._translate_statement(body)
            finally:
                self._jump_targets.pop()

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
            if init.type == "declaration":
                self._translate_declaration(init)
            elif init.type in ("assignment_expression", "comma_expression",
                               "update_expression"):
                # A bare `for(i = 0; ...)` or `for(i = 0, j = s; ...)` initializer
                # is an expression, not a statement, so `_translate_statement`
                # would silently drop it (leaving the loop variables with no
                # definition); lower each effect directly.
                self._translate_effects(init)
            else:
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
        self._current_node = loop_head   # evaluated (with any side effect) per iteration
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=True, kind=PruneKind.FOR_ENTER))
        proc.connect(loop_head.id, body_node.id)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=False, kind=PruneKind.FOR_EXIT))
        proc.connect(loop_head.id, after_node.id)

        # The update runs at the end of every iteration, including one ended by
        # `continue`, so it gets its own node and `continue` jumps there.
        update_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(update_node)

        body = node.child_by_field_name("body")
        if body:
            self._current_node = body_node
            self._jump_targets.append(("loop", after_node, update_node))
            try:
                self._translate_statement(body)
            finally:
                self._jump_targets.pop()
        else:
            self._current_node = body_node

        if self._current_node:
            proc.connect(self._current_node.id, update_node.id)
        self._current_node = update_node

        update = node.child_by_field_name("update")
        if update is not None:
            self._translate_effects(update)

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node
        # `for (p = s; *p; p++) if (!isalnum(*p)) return -1;`: when the loop finishes, every
        # character of s passed the test, so s holds only those characters.
        validated = self._validation_loop_var(node)
        if validated is not None:
            self._add_instr(Sanitize(loc=loc, var=PVar(validated[0]), sanitizes=list(SinkKind),
                                     description=f"every character passed {validated[1]}()"))

    # Character-class tests whose characters (letters, digits) are inert for every sink.
    _CHARSET_TESTS = frozenset({"isalnum", "isalpha", "isdigit", "isxdigit", "isupper", "islower"})

    def _validation_loop_var(self, node: TSNode) -> Optional[Tuple[str, str]]:
        """(s, test) for a loop that visits every character of string s and leaves the path
        (return / exit / abort / goto) at the first one failing a character-class test, with
        nothing else in its body. Pointer form `for (p = s; *p; p++)`, index form
        `for (i = 0; s[i]; i++)` / `i < strlen(s)`."""
        init, cond = node.child_by_field_name("initializer"), node.child_by_field_name("condition")
        update, body = node.child_by_field_name("update"), node.child_by_field_name("body")
        if None in (init, cond, update, body):
            return None
        strip = self._strip_parens_casts
        # the cursor and, for the pointer form, the string it starts at
        cursor, start = None, None
        if init.type == "declaration":
            d = next((c for c in init.named_children if c.type == "init_declarator"), None)
            if d is not None:
                cursor = self._extract_identifier(d.child_by_field_name("declarator"))
                start = d.child_by_field_name("value")
        elif init.type == "assignment_expression":
            cursor, start = self._get_text(init.child_by_field_name("left")), init.child_by_field_name("right")
        if not cursor or start is None:
            return None
        start = strip(start)
        step = strip(update)
        if not (step.type == "update_expression" and self._get_text(step.child_by_field_name("argument")) == cursor
                and "++" in self._get_text(step)):
            return None

        def element(e):           # the string a `*p` / `p[0]` / `s[i]` reads, else None
            e = strip(e)
            if e.type == "pointer_expression" and self._get_text(e).startswith("*") \
                    and self._get_text(e.child_by_field_name("argument")) == cursor and start.type == "identifier":
                return self._get_text(start)
            if e.type == "subscript_expression":
                base, idx = e.child_by_field_name("argument"), self._subscript_index(e)
                if base is None or idx is None:
                    return None
                if self._get_text(base) == cursor and self._get_text(idx) == "0" and start.type == "identifier":
                    return self._get_text(start)
                if self._get_text(idx) == cursor and base.type == "identifier" and self._get_text(start) == "0":
                    return self._get_text(base)
            return None

        c = strip(cond)
        if c.type == "binary_expression" and self._get_text(c.child_by_field_name("operator")) == "!=" \
                and self._get_text(c.child_by_field_name("right")) in ("'\\0'", "0"):
            target = element(c.child_by_field_name("left"))
        elif c.type == "binary_expression" and self._get_text(c.child_by_field_name("operator")) == "<" \
                and self._get_text(c.child_by_field_name("left")) == cursor and self._get_text(start) == "0":
            limit = strip(c.child_by_field_name("right"))
            fn = limit.child_by_field_name("function") if limit.type == "call_expression" else None
            args = limit.child_by_field_name("arguments") if fn is not None else None
            target = self._get_text(args.named_children[0]) if fn is not None and self._get_text(fn) == "strlen" \
                and args is not None and len(args.named_children) == 1 else None
        else:
            target = element(c)
        if not target:
            return None
        # the body: exactly `if (!test(<element>)) <leave the path>;`
        stmts = [x for x in body.named_children if x.type != "comment"] if body.type == "compound_statement" else [body]
        if len(stmts) != 1 or stmts[0].type != "if_statement" or stmts[0].child_by_field_name("alternative") is not None:
            return None
        test = strip(stmts[0].child_by_field_name("condition"))
        if test.type != "unary_expression" or self._get_text(test.child_by_field_name("operator")) != "!":
            return None
        call = strip(test.child_by_field_name("argument"))
        fn = call.child_by_field_name("function") if call.type == "call_expression" else None
        args = call.child_by_field_name("arguments") if fn is not None else None
        name = self._get_text(fn) if fn is not None else ""
        if name not in self._CHARSET_TESTS or args is None or len(args.named_children) != 1:
            return None
        arg = args.named_children[0]
        if element(arg) != target and not (strip(arg).type == "subscript_expression" and element(arg) == target):
            return None
        then = stmts[0].child_by_field_name("consequence")
        last = [x for x in then.named_children if x.type != "comment"][-1:] if then.type == "compound_statement" else [then]
        if not last or not self._leaves_path(last[0]):
            return None
        return target, name

    def _leaves_path(self, stmt: TSNode) -> bool:
        """`return ...;`, `goto x;`, or a call to exit/abort/_exit."""
        if stmt.type in ("return_statement", "goto_statement"):
            return True
        if stmt.type == "expression_statement" and stmt.named_children:
            e = stmt.named_children[0]
            fn = e.child_by_field_name("function") if e.type == "call_expression" else None
            return fn is not None and self._get_text(fn) in ("exit", "abort", "_exit", "std::exit", "std::abort")
        return False

    @staticmethod
    def _strip_parens_casts(node: TSNode) -> TSNode:
        while node is not None and node.type in ("parenthesized_expression", "cast_expression"):
            inner = node.child_by_field_name("value") if node.type == "cast_expression" else None
            if inner is None:
                named = [c for c in node.named_children if c.type != "comment"]
                inner = named[-1] if named else None
            if inner is None:
                break
            node = inner
        return node

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
            self._jump_targets.append(("loop", after_node, loop_head))
            try:
                self._translate_statement(body)
            finally:
                self._jump_targets.pop()

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        condition = node.child_by_field_name("condition")
        self._current_node = loop_head   # evaluated (with any side effect) per iteration
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=True, kind=PruneKind.LOOP_ENTER))
        proc.connect(loop_head.id, body_node.id)

        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=False, kind=PruneKind.LOOP_EXIT))
        proc.connect(loop_head.id, after_node.id)

        self._current_node = after_node

    def _translate_switch(self, node: TSNode) -> None:
        """Translate a switch: one unguarded branch per case, fall-through edges between
        neighbouring cases, `break` as an edge to the join after the switch, and an edge past
        every case when there is no `default`. Lowering the cases one after another on a
        single path (as this used to) made `default: return 2;` end the path for every
        statement after it -- the usual getopt loop lost all its assignments."""
        body = node.child_by_field_name("body")
        proc = self._current_proc
        if not body or proc is None or self._current_node is None:
            return
        before = self._current_node
        join = proc.new_node(NodeKind.JOIN)
        proc.add_node(join)
        self._jump_targets.append(("switch", join, None))
        has_default = False
        fallthrough: Optional[Node] = None
        try:
            for child in body.children:
                if child.type != "case_statement":
                    continue
                arm = proc.new_node(NodeKind.NORMAL)
                proc.add_node(arm)
                proc.connect(before.id, arm.id)
                if fallthrough is not None:
                    proc.connect(fallthrough.id, arm.id)
                self._current_node = arm
                value = child.child_by_field_name("value")
                if value is None:
                    has_default = True
                for stmt in child.children:
                    if not stmt.is_named or stmt.type == "comment" or (value is not None and stmt.id == value.id):
                        continue
                    if stmt.type == "break_statement":
                        self._translate_jump(True)
                    else:
                        self._translate_statement(stmt)
                # the arm falls through unless a `break` (a fresh unreachable node) ended it
                ended = child.named_children[-1].type in ("break_statement", "return_statement") \
                    if child.named_children else False
                fallthrough = None if ended else self._current_node
            if fallthrough is not None:
                proc.connect(fallthrough.id, join.id)
            if not has_default:
                proc.connect(before.id, join.id)
        finally:
            self._jump_targets.pop()
        self._current_node = join

    def _translate_expression(self, node: TSNode) -> Exp:
        """Translate expression"""
        if node is None:
            return ExpConst.null()

        if node.type == "identifier":
            text = self._alias_of(self._get_text(node))
            if text in self._int_macros:
                return ExpConst.integer(self._int_macros[text])     # the preprocessor's view
            return ExpVar(PVar(text))

        elif node.type == "number_literal":
            text = self._get_text(node)
            try:
                if "." in text:
                    return ExpConst.integer(int(float(text)))
                parsed = parse_c_integer(text)
                return ExpConst.integer(parsed if parsed is not None else 0)
            except ValueError:
                return ExpConst.integer(0)

        elif node.type == "string_literal":
            text = self._get_text(node)
            # Remove quotes
            if len(text) >= 2:
                text = text[1:-1]
            return ExpConst.string(text)

        elif node.type == "char_literal":
            text = self._get_text(node)
            if len(text) >= 3:
                return ExpConst.string(text[1:-1])
            return ExpConst.string(text)

        elif node.type == "true":
            return ExpConst.boolean(True)

        elif node.type == "false":
            return ExpConst.boolean(False)

        elif node.type == "null":
            return ExpConst.null()

        elif node.type == "binary_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")
            left_exp = self._translate_expression(left)
            right_exp = self._translate_expression(right)
            op = self._get_text(op_node) if op_node else "+"
            return ExpBinOp(op, left_exp, right_exp)

        elif node.type == "unary_expression":
            op_node = node.child_by_field_name("operator")
            arg = node.child_by_field_name("argument")
            op = self._get_text(op_node) if op_node else "-"
            arg_exp = self._translate_expression(arg)
            # Use ExpUnOp for dereference (*) and address-of (&)
            return ExpUnOp(op, arg_exp)

        elif node.type == "pointer_expression":
            op = node.child_by_field_name("operator")
            arg = node.child_by_field_name("argument")
            if op:
                op_str = self._get_text(op)
                if op_str in ("*", "&"):
                    return ExpUnOp(op_str, self._translate_expression(arg))
            return self._translate_expression(arg)

        elif node.type == "subscript_expression":
            arr = node.child_by_field_name("argument")
            idx = self._subscript_index(node)
            if arr is None or idx is None:
                return ExpConst.null()
            return ExpIndex(self._translate_expression(arr), self._translate_expression(idx))

        elif node.type == "field_expression":
            obj = node.child_by_field_name("argument")
            field = node.child_by_field_name("field")
            return ExpFieldAccess(self._translate_expression(obj),
                                  self._get_text(field) if field else "",
                                  self._is_arrow_access(node))

        elif node.type == "call_expression" and self._content_accessor_receiver(node) is not None:
            return self._translate_expression(self._content_accessor_receiver(node))

        elif (node.type == "call_expression" and self.LANGUAGE == "cpp"
              and self._get_call_name(node) in self._VIEW_WRAPPERS and self._get_call_args(node)):
            # asio::buffer(data, n) / std::span(buf) / std::ref(x) are views of their first argument:
            # a read "into the buffer" fills `data`
            return self._translate_expression(self._get_call_args(node)[0])

        elif (node.type == "call_expression" and self.LANGUAGE == "cpp" and self._current_node is not None
              and node.child_by_field_name("function") is not None
              and node.child_by_field_name("function").type == "field_expression"):
            # A member call written inside an expression (`QString::fromUtf8(sock->readLine())`,
            # `run(req.get_param_value("n"))`) is its own Call, so sources, sinks and pack rules
            # (matched on Call instructions) see it; the expression uses its result.
            cached = self._hoisted_calls.get(node.id)
            if cached is not None:
                return cached
            member = self._get_text(node.child_by_field_name("function").child_by_field_name("field"))
            tmp = f"{member}_result{self._ident_counter}"
            self._ident_counter += 1
            exp = ExpVar(PVar(tmp))
            self._hoisted_calls[node.id] = exp
            self._add_instrs(self._translate_call_assignment(tmp, node, self._get_location(node)))
            return exp

        elif (node.type == "call_expression" and self._current_node is not None
              and self._delivers_into_arguments(node)):
            # `if (read(fd, &n, 4) != 4)`, `while ((n = recv(s, buf, cap, 0)) > 0)`, `if (!fgets(b, n, in))`:
            # a call that fills a buffer is its own Call instruction, or the buffer it fills is never
            # tainted (an expression-level call only carries its return value).
            cached = self._hoisted_calls.get(node.id)
            if cached is not None:
                return cached
            tmp = f"{self._get_call_name(node).replace('::', '_')}_result{self._ident_counter}"
            self._ident_counter += 1
            exp = ExpVar(PVar(tmp))
            self._hoisted_calls[node.id] = exp
            self._add_instrs(self._translate_call_assignment(tmp, node, self._get_location(node)))
            return exp

        elif node.type == "call_expression":
            func_name = self._get_call_name(node)
            self._lower_lambda_args(node)
            args = [self._translate_expression(a) for a in self._get_call_args(node)]
            return ExpCall(ExpConst.string(func_name), args)

        elif node.type == "lambda_expression":
            # a lambda is its own procedure (handlers are lambdas in every C++ web framework)
            return ExpConst.string(self._lower_lambda(node))

        elif node.type == "new_expression":
            # `new T` / `new T[n]` -> a call to the allocator operator, so the
            # allocation flows through the same allocator spec as malloc. The
            # array form (a `new_declarator` child, the `[n]`) is a distinct
            # allocator whose only correct release is `delete[]`.
            is_array = any(c.type == "new_declarator" for c in node.children)
            return ExpCall(ExpConst.string("new[]" if is_array else "new"), [])

        elif node.type == "parenthesized_expression":
            for child in node.children:
                if child.type not in ("(", ")"):
                    return self._translate_expression(child)

        elif node.type == "condition_clause":
            # C++ wraps `if` / `while` / `switch` conditions in a clause (`if (x > 0)`, also
            # `if (init; cond)`); its value is the condition. Read as text it was an opaque name,
            # so no C++ branch said anything to the solver.
            value = node.child_by_field_name("value")
            if value is not None:
                return self._translate_expression(value)
            named = [c for c in node.named_children if c.type != "comment"]
            return self._translate_expression(named[-1]) if named else ExpConst.boolean(True)

        elif node.type == "conditional_expression":
            conseq = node.child_by_field_name("consequence")
            return self._translate_expression(conseq) if conseq else ExpConst.null()

        elif node.type == "cast_expression":
            value = node.child_by_field_name("value")
            return self._translate_expression(value)

        elif node.type == "sizeof_expression":
            return ExpConst.integer(0)  # Placeholder

        elif node.type == "assignment_expression":
            # An assignment nested in an expression (`while ((e = next(f)))`,
            # `if ((p = malloc(n)) == NULL)`) still WRITES its target. Lower the
            # write as an Assign in the current node, ahead of whatever consumes
            # the value, and yield the target as the expression's value -- so the
            # condition becomes a guard on `e` and the IR sees `e` change.
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            rhs = self._translate_expression(right)
            if (left is not None and left.type == "identifier"
                    and self._current_node is not None):
                name = self._get_text(left)
                op_node = node.child_by_field_name("operator")
                op = self._get_text(op_node) if op_node is not None else "="
                value = rhs if op == "=" else ExpBinOp(op[:-1], ExpVar(PVar(name)), rhs)
                self._add_instr(Assign(loc=self._get_location(node), id=PVar(name), exp=value))
                return ExpVar(PVar(name))
            return rhs

        elif node.type == "update_expression":
            # `x++` / `--x` inside an expression (`a[n++] = c`, `while (n--)`)
            # writes x. Lower the write in the current node; a postfix form
            # yields x's old value through a fresh temporary.
            arg = node.child_by_field_name("argument")
            if (arg is not None and arg.type == "identifier"
                    and self._current_node is not None):
                name = self._get_text(arg)
                text = self._get_text(node).strip()
                loc = self._get_location(node)
                bump = Assign(loc=loc, id=PVar(name), exp=ExpBinOp(
                    "+" if "++" in text else "-", ExpVar(PVar(name)), ExpConst.integer(1)))
                if text.startswith(("++", "--")):
                    self._add_instr(bump)
                    return ExpVar(PVar(name))
                old = self._new_ident(name)
                self._add_instr(Assign(loc=loc, id=old, exp=ExpVar(PVar(name))))
                self._add_instr(bump)
                return ExpVar(old)
            return self._translate_expression(arg)

        elif node.type == "comma_expression":
            # Evaluate the left operand for its effects; the value is the right.
            self._translate_expression(node.child_by_field_name("left"))
            right = node.child_by_field_name("right")
            return self._translate_expression(right)

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

    # -- typed member calls (C++) ------------------------------------------------------

    @staticmethod
    def _type_base_name(text: str) -> str:
        """`const QProcess *` -> `QProcess`; `std::unique_ptr<QProcess>` -> `QProcess`;
        `httplib::Client&` -> `httplib::Client`; other templates lose their arguments."""
        text = re.sub(r"\b(const|volatile|struct|class|typename|static|mutable|extern)\b", " ", text)
        text = text.replace("*", " ").replace("&", " ")
        m = re.search(r"(?:std::)?(?:unique_ptr|shared_ptr|weak_ptr|optional|scoped_ptr|QScopedPointer|"
                      r"QSharedPointer|QPointer)\s*<\s*([\w:]+)", text)
        if m:
            return m.group(1)
        text = re.sub(r"<.*>", "", text, flags=re.S)
        return "".join(text.split())

    _MEMBER_CALL = re.compile(r"^(?:this\.)?([A-Za-z_]\w*)\.([A-Za-z_]\w*)$")

    def _qualify_member_calls(self, program: Program) -> None:
        """`obj.method(...)` where `obj` is a local, parameter or field of a known class
        type gets the canonical id `Type::method`, as a static call `Type::method(...)`
        has. Packs then match `QProcess::start` instead of every `.start`."""
        for proc in program.procedures.values():
            types: Dict[str, str] = {}
            chain: List[Procedure] = []
            cur: Optional[Procedure] = proc
            while cur is not None and cur not in chain:       # lambdas see the enclosing function
                chain.append(cur)
                cur = self._lambda_parent.get(id(cur))
            fields = self._class_field_types.get(proc.class_name or "", {})
            for c in reversed(chain):
                types.update(self._var_types.get(id(c), {}))
                types.update(c.param_types)
            for node in proc.nodes.values():
                for instr in node.instrs:
                    if not isinstance(instr, Call) or instr.canonical:
                        continue
                    m = self._MEMBER_CALL.match(_func_str(instr))
                    if not m:
                        continue
                    declared = types.get(m.group(1)) or fields.get(m.group(1))
                    if not declared:
                        continue
                    base = self._type_base_name(declared)
                    if base and base[0].isalpha() or base.startswith("::"):
                        instr.canonical = f"{base}::{m.group(2)}"

    # -- lambdas ---------------------------------------------------------------------

    @staticmethod
    def _registration_callee(call_node: TSNode) -> str:
        """The callee a lambda argument is registered with: `svr.Get(path, [](..){..})`
        -> "svr.Get"; `CROW_ROUTE(app, "/x").methods("POST"_method)([](..){..})` ->
        "CROW_ROUTE" (the route macro at the root of the chain)."""
        node = call_node.child_by_field_name("function")
        while node is not None:
            if node.type == "call_expression":
                node = node.child_by_field_name("function")
            elif node.type == "field_expression":
                arg = node.child_by_field_name("argument")
                if arg is not None and arg.type == "call_expression":
                    node = arg
                    continue
                break
            else:
                break
        return node.text.decode("utf-8", "replace") if node is not None else ""

    def _lower_lambda_args(self, call_node: TSNode) -> None:
        """Lower each lambda written directly as an argument of this call, recording the
        callee it is registered with (`Procedure.registered_via`)."""
        via = None
        for a in self._get_call_args(call_node):
            if a.type == "lambda_expression":
                if via is None:
                    via = self._registration_callee(call_node)
                self._lower_lambda(a, via)

    def _lower_lambda(self, node: TSNode, via: Optional[str] = None) -> str:
        """Translate a lambda expression into a Procedure of its own and return its name."""
        cached = self._lambda_names.get(node.id)
        if cached is not None:
            return cached
        row, col = node.start_point
        name = f"lambda@{row + 1}_{col}"
        self._lambda_names[node.id] = name

        decl = node.child_by_field_name("declarator")
        params_node = decl.child_by_field_name("parameters") if decl is not None else None
        params = self._params_from_list(params_node)
        proc = Procedure(name=name, params=params, ret_type=Typ.unknown_type(),
                         loc=self._get_location(node), is_method=False)
        proc.param_types = dict(getattr(self, "_last_param_types", {}))
        proc.scalar_types = dict(getattr(self, "_last_scalar_param_types", {}))
        if via:
            proc.registered_via.append(via)
        proc.has_parse_errors = bool(node.has_error)

        saved = (self._current_proc, self._current_node, self._node_counter, self._jump_targets)
        if self._current_proc is not None:
            self._lambda_parent[id(proc)] = self._current_proc
        self._current_proc = proc
        self._node_counter = 0
        self._jump_targets = []
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry
        body = node.child_by_field_name("body")
        if body:
            self._translate_compound_statement(body)
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id
        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)
        self._current_proc, self._current_node, self._node_counter, self._jump_targets = saved

        program = getattr(self, "_program", None)
        if program is not None:
            program.add_procedure(proc)
        return name

    def _get_call_name(self, node: TSNode) -> str:
        func = node.child_by_field_name("function")
        if func:
            text = self._get_text(func)
            # `p->m()` and `o.m()` are the same call shape to every spec and to the
            # translator's receiver handling, which looks for a '.'
            if self.LANGUAGE == "cpp" and func.type == "field_expression" and "->" in text:
                text = text.replace("->", ".")
            if self.LANGUAGE == "cpp" and func.type == "qualified_identifier":
                # `std::memcpy` / `::free` are the C library function: the translator's name sets
                # (non-retaining calls, allocators, deallocators) are keyed on the plain name
                for prefix in ("std::", "::"):
                    if text.startswith(prefix) and text[len(prefix):] in C_SPECS:
                        return text[len(prefix):]
            return text
        return ""

    # Methods that hand back (a view of) the receiver's own contents: `cmd.c_str()`,
    # `text.toStdString()`, `buf.data()`. In an expression they are the receiver itself,
    # so taint on it reaches `system(cmd.c_str())` without a spec per container type.
    _CONTENT_ACCESSORS = frozenset({
        "c_str", "data", "str", "string", "c_string", "view", "get_str", "toStdString", "toUtf8",
        "toLatin1", "toLocal8Bit", "toAscii", "constData", "toStdWString", "utf8", "trimmed",
        "simplified", "toLower", "toUpper", "substr", "substring", "left", "right", "mid", "s",
    })

    _VIEW_WRAPPERS = frozenset({
        "asio::buffer", "boost::asio::buffer", "asio::mutable_buffer", "boost::asio::mutable_buffer",
        "boost::asio::buffer_cast", "std::span", "std::ref", "std::cref", "std::string_view",
        "boost::asio::mutable_buffers_1",
    })

    def _content_accessor_receiver(self, node: TSNode) -> Optional[TSNode]:
        """For `recv.c_str()`-style calls, the receiver node (else None)."""
        func = node.child_by_field_name("function")
        if func is None or func.type != "field_expression":
            return None
        field = func.child_by_field_name("field")
        if field is None or self._get_text(field) not in self._CONTENT_ACCESSORS:
            return None
        return func.child_by_field_name("argument")

    def _get_call_args(self, node: TSNode) -> List[TSNode]:
        args = []
        args_node = node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                # a comment between arguments is a child of the list, not an argument
                if child.type not in ("(", ")", ",", "comment"):
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


class CppFrontend(CFrontend):
    """
    Translates C++ source code to Frame SIL.

    Extends CFrontend with C++ specific features:
    - Classes and methods
    - Namespaces
    - Templates (limited)
    - STL (via specs)
    """

    LANGUAGE = "cpp"

    def __init__(self, specs: Dict[str, ProcSpec] = None):
        """
        Initialize the C++ frontend.

        Args:
            specs: Library specifications (defaults to CPP_SPECS)
        """
        if not TREE_SITTER_CPP_AVAILABLE:
            raise ImportError(
                "tree-sitter-cpp is required. "
                "Install with: pip install tree-sitter-cpp"
            )

        # Initialize with C++ parser
        from tree_sitter import Language, Parser
        import tree_sitter_cpp as tscpp

        self.parser = Parser(Language(tscpp.language()))
        self.specs = specs or CPP_SPECS

        # State during translation
        self._filename = "<unknown>"
        self._source = ""
        self._current_proc: Optional[Procedure] = None
        self._current_node: Optional[Node] = None
        self._node_counter = 0
        self._ident_counter = 0
        self._current_class: Optional[str] = None
        self._current_namespace: Optional[str] = None

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """Translate C++ source; label the program "cpp" (CFrontend says "c") so
        language-sensitive analyses can tell C's by-value arguments from C++
        references."""
        program = super().translate(source_code, filename)
        program.language = "cpp"
        return program

    def _translate_translation_unit(self, root: TSNode, program: Program) -> None:
        """Translate C++ translation unit"""
        for child in root.children:
            if child.type == "function_definition":
                proc = self._translate_function(child)
                if proc:
                    # Detect class methods defined outside class body (e.g., ClassName::MethodName)
                    if '::' in proc.name:
                        parts = proc.name.split('::')
                        if len(parts) >= 2:
                            # Last part is method name, second-to-last is class name
                            method_name = parts[-1]
                            class_name = parts[-2]
                            proc.class_name = class_name
                            proc.is_method = True
                            # Detect constructor: ClassName::ClassName
                            if method_name == class_name:
                                proc.is_constructor = True
                            # Detect destructor: ClassName::~ClassName
                            elif method_name == f'~{class_name}':
                                proc.is_constructor = False
                    program.add_procedure(proc)
            elif child.type == "class_specifier":
                self._translate_class(child, program)
            elif child.type == "struct_specifier":
                self._translate_class(child, program)
            elif child.type == "namespace_definition":
                self._translate_namespace(child, program)
            elif child.type == "preproc_ifdef" or child.type == "preproc_ifndef":
                # Recurse into preprocessor conditional blocks
                self._translate_translation_unit(child, program)
            elif child.type in ("declaration_list", "template_declaration", "linkage_specification"):
                # Recurse into declaration lists (namespace bodies), `template <...>`
                # and `extern "C" { ... }`
                self._translate_translation_unit(child, program)
            elif child.type == "declaration":
                pass  # Skip global declarations

    def _translate_class(self, node: TSNode, program: Program) -> None:
        """Translate C++ class/struct"""
        name_node = node.child_by_field_name("name")
        class_name = self._get_text(name_node) if name_node else "UnknownClass"
        bases = [self._get_text(b).split("<")[0] for c in node.children if c.type == "base_class_clause"
                 for b in c.named_children
                 if b.type in ("type_identifier", "qualified_identifier", "template_type")]
        program.class_info[class_name] = ClassInfo(
            name=class_name, kind="struct" if node.type == "struct_specifier" else "class",
            bases=bases, canonical_bases=list(bases),
            package=self._current_namespace or None)

        old_class = self._current_class
        self._current_class = class_name

        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "function_definition":
                    proc = self._translate_function(child)
                    if proc:
                        proc.class_name = class_name
                        if not proc.name.startswith(f"{class_name}::"):
                            proc.name = f"{class_name}::{proc.name}"
                        proc.is_method = True
                        program.add_procedure(proc)
                elif child.type == "template_declaration":
                    # a templated member function
                    for inner in child.children:
                        if inner.type == "function_definition":
                            proc = self._translate_function(inner)
                            if proc:
                                proc.class_name = class_name
                                if not proc.name.startswith(f"{class_name}::"):
                                    proc.name = f"{class_name}::{proc.name}"
                                proc.is_method = True
                                program.add_procedure(proc)
                elif child.type == "field_declaration":
                    # Member variable: remember its type for member-call qualification
                    ftype = child.child_by_field_name("type")
                    if ftype is not None:
                        for d in child.children_by_field_name("declarator"):
                            fname = self._extract_identifier(d)
                            if fname:
                                self._class_field_types.setdefault(class_name, {})[fname] = self._get_text(ftype)
                elif child.type == "access_specifier":
                    # public, private, protected - skip
                    pass

        self._current_class = old_class

    def _translate_namespace(self, node: TSNode, program: Program) -> None:
        """Translate namespace definition"""
        name_node = node.child_by_field_name("name")
        ns_name = self._get_text(name_node) if name_node else ""

        old_ns = self._current_namespace
        self._current_namespace = ns_name

        body = node.child_by_field_name("body")
        if body:
            self._translate_translation_unit(body, program)

        self._current_namespace = old_ns

    def _translate_function(self, node: TSNode) -> Optional[Procedure]:
        """Translate C++ function/method"""
        proc = super()._translate_function(node)

        if proc:
            # Add namespace prefix
            if self._current_namespace:
                proc.name = f"{self._current_namespace}::{proc.name}"

            # Add class prefix (for inline methods)
            if self._current_class and not proc.name.startswith(f"{self._current_class}::"):
                proc.name = f"{self._current_class}::{proc.name}"
                proc.is_method = True
                proc.class_name = self._current_class

        return proc


def _func_str(call: Call) -> str:
    return str(getattr(call.func, "value", call.func))


# -- option-dispatch APIs ---------------------------------------------------------
# `curl_easy_setopt(h, CURLOPT_URL, x)` is one function whose meaning is the constant
# in its second argument; `xmlReadMemory(..., XML_PARSE_NOENT)` is only an XXE hazard
# with certain flags. A pack rule matches calls by canonical id, so for these APIs the
# canonical id carries the constant: `curl_easy_setopt:CURLOPT_URL`,
# `curl_easy_setopt:CURLOPT_SSL_VERIFYPEER:off` (value 0/false),
# `SSL_CTX_set_verify:SSL_VERIFY_NONE`, `xmlReadMemory:XML_PARSE_NOENT|XML_PARSE_DTDLOAD`.
# Only identifier constants written at the call are read; an option held in a variable
# leaves the plain id, which no rule matches (no guess).
_OPTION_ARG = {
    "curl_easy_setopt": 1, "curl_multi_setopt": 1, "curl_share_setopt": 1,
    "SSL_CTX_set_verify": 1, "SSL_set_verify": 1,
    "xmlReadMemory": 4, "xmlReadFile": 2, "xmlReadDoc": 3, "xmlReadIO": 5,
    "xmlCtxtReadMemory": 5, "xmlCtxtReadFile": 3, "xmlCtxtReadDoc": 4, "xmlCtxtUseOptions": 1,
    "xmlCtxtSetOptions": 1,
}
_OPTION_VALUE_ARG = {"curl_easy_setopt": 2, "curl_multi_setopt": 2, "curl_share_setopt": 2}
_IDENT = re.compile(r"[A-Za-z_]\w*")
_OFF_VALUES = {"0", "0l", "0ul", "false", "null", "nullptr"}


# A response writer whose meaning depends on the content type written beside the body:
# `res.set_content(body, "text/html")` is an XSS sink, `res.set_content(json, "application/json")`
# is not. Calls named here whose type argument is an HTML literal get the suffix ":html"
# (`res.set_content:html`), which a pack's `name` rule can target.
_CONTENT_TYPE_ARG = {"set_content": 1}


def _qualify_content_type_calls(program: Program) -> None:
    for proc in program.procedures.values():
        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call):
                    continue
                name = _func_str(instr)
                idx = _CONTENT_TYPE_ARG.get(name.rsplit(".", 1)[-1])
                if idx is None or "." not in name or idx >= len(instr.args):
                    continue
                arg = instr.args[idx][0]
                if isinstance(arg, ExpConst) and "html" in str(getattr(arg, "value", "")).lower():
                    instr.func = ExpConst.string(name + ":html")
                    if instr.canonical:
                        instr.canonical += ":html"


def _qualify_option_calls(program: Program) -> None:
    for proc in program.procedures.values():
        for node in proc.nodes.values():
            for instr in node.instrs:
                if not isinstance(instr, Call) or not instr.canonical:
                    continue
                idx = _OPTION_ARG.get(instr.canonical)
                if idx is None or idx >= len(instr.args):
                    continue
                text = str(instr.args[idx][0])
                idents = [w for w in _IDENT.findall(text) if w.isupper() or "_" in w]
                if not idents:
                    continue
                canonical = f"{instr.canonical}:{'|'.join(idents)}"
                vidx = _OPTION_VALUE_ARG.get(instr.canonical)
                if vidx is not None and vidx < len(instr.args):
                    if str(instr.args[vidx][0]).strip().lower() in _OFF_VALUES:
                        canonical += ":off"
                # The call is renamed as well: a pack rule that matches registers its spec under
                # the call's plain name for later expression-nested calls, which would turn every
                # other curl_easy_setopt / xmlReadMemory in the file into a sink.
                instr.canonical = canonical
                instr.func = ExpConst.string(canonical)
