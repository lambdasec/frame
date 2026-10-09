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
from frame.sil.loop_exit import body_can_exit_loop
from frame.sil.specs.c_specs import C_SPECS, CPP_SPECS


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

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """Translate C source code to SIL Program."""
        self._filename = filename
        self._source = source_code
        self._source_bytes = source_code.encode("utf-8")
        self._node_counter = 0
        self._ident_counter = 0

        self._jump_targets: List[Tuple[str, Optional[Node], Optional[Node]]] = []

        tree = self.parser.parse(self._source_bytes)
        program = Program(library_specs=self.specs.copy(), language="c")
        program.source_files.append(filename)
        program.function_macros = self._function_macro_names(tree.root_node)

        self._translate_translation_unit(tree.root_node, program)
        return program

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

        proc.has_parse_errors = bool(node.has_error)

        self._current_proc = proc
        self._node_counter = 0

        # Create entry node
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry

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
                if inner.type == "identifier":
                    return self._get_text(inner)
                elif inner.type == "qualified_identifier":
                    # C++ class method: Class::method
                    return self._get_text(inner)
                elif inner.type == "pointer_declarator":
                    # Handle pointer return type
                    return self._get_function_name(inner)
        elif declarator.type == "pointer_declarator":
            inner = declarator.child_by_field_name("declarator")
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
        params = []

        if declarator.type != "function_declarator":
            # Handle pointer declarator
            if declarator.type == "pointer_declarator":
                inner = declarator.child_by_field_name("declarator")
                if inner:
                    return self._translate_parameters(inner)
            return params

        params_node = declarator.child_by_field_name("parameters")
        if not params_node:
            return params

        for child in params_node.children:
            if child.type == "parameter_declaration":
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

        return params

    def _extract_identifier(self, node: TSNode) -> Optional[str]:
        """Extract identifier from declarator node"""
        if node.type == "identifier":
            return self._get_text(node)
        elif node.type == "pointer_declarator":
            inner = node.child_by_field_name("declarator")
            if inner:
                return self._extract_identifier(inner)
        elif node.type == "array_declarator":
            inner = node.child_by_field_name("declarator")
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
        for child in node.children:
            if child.type == "init_declarator":
                decl = child.child_by_field_name("declarator")
                self._record_fixed_array_bound(decl)
                self._record_array_from_string_init(decl, child.child_by_field_name("value"))
                self._record_local(self._extract_identifier(decl))
                self._translate_init_declarator(child)
            elif child.type in ("identifier", "pointer_declarator", "array_declarator"):
                # Declaration without initialization
                self._record_fixed_array_bound(child)
                var_name = self._extract_identifier(child)
                self._record_local(var_name)
                if var_name:
                    loc = self._get_location(child)
                    self._add_instr(Assign(loc=loc, id=PVar(var_name),
                                           exp=ExpConst.null(), is_uninit_decl=True))

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
        if not name or size_node is None or size_node.type != "number_literal":
            return

        bound = parse_c_integer(self._get_text(size_node))
        if bound is None or bound <= 0:
            return

        bounds = self._current_proc.fixed_array_bounds
        if name in bounds and bounds[name] != bound:
            # Conflicting declarations of one name: refuse to pick.
            bounds[name] = -1
        elif bounds.get(name) != -1:
            bounds[name] = bound
            self._note_char_array(declarator, name)

    def _translate_init_declarator(self, node: TSNode) -> None:
        """Translate init_declarator (var = value)"""
        declarator = node.child_by_field_name("declarator")
        value = node.child_by_field_name("value")

        if not declarator:
            return

        var_name = self._extract_identifier(declarator)
        if not var_name:
            return

        loc = self._get_location(node)

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
            target = self._get_text(left)
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
                self._add_instr(Assign(loc=loc, id=PVar(target), exp=exp))
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
                val_exp = self._translate_expression(right)
                # Model as assignment to synthetic variable
                target = f"{self._get_text(obj)}_{field_name}"
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

        func_name = self._get_call_name(call_node)
        args = self._get_call_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        ret_id = self._new_ident(target)

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
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description))

        return instrs

    def _translate_call(self, call_node: TSNode) -> List[Instr]:
        """Translate standalone function call"""
        instrs = []
        loc = self._get_location(call_node)

        func_name = self._get_call_name(call_node)
        args = self._get_call_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

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
                    instrs.append(TaintSink(loc=loc, exp=arg_exp, kind=kind, description=spec.description, arg_index=arg_idx))

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

        Switch cases are lowered one after another on a single path (see
        _translate_switch), so a `break` that belongs to a switch stays a no-op;
        a `continue` inside a switch still targets the enclosing loop."""
        proc = self._current_proc
        if proc is None or self._current_node is None:
            return
        target = None
        for kind, exit_node, next_node in reversed(self._jump_targets):
            if is_break:
                if kind == "switch":
                    return
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
        elif node.type == "parenthesized_expression":
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
        """Translate switch statement (simplified)"""
        body = node.child_by_field_name("body")
        if body:
            self._jump_targets.append(("switch", None, None))
            try:
                for child in body.children:
                    if child.type == "case_statement":
                        for stmt in child.children:
                            if stmt.type not in ("case", "default", ":", "break_statement"):
                                self._translate_statement(stmt)
            finally:
                self._jump_targets.pop()

    def _translate_expression(self, node: TSNode) -> Exp:
        """Translate expression"""
        if node is None:
            return ExpConst.null()

        if node.type == "identifier":
            return ExpVar(PVar(self._get_text(node)))

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

        elif node.type == "call_expression":
            func_name = self._get_call_name(node)
            args = [self._translate_expression(a) for a in self._get_call_args(node)]
            return ExpCall(ExpConst.string(func_name), args)

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

    def _get_call_name(self, node: TSNode) -> str:
        func = node.child_by_field_name("function")
        if func:
            return self._get_text(func)
        return ""

    def _get_call_args(self, node: TSNode) -> List[TSNode]:
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


class CppFrontend(CFrontend):
    """
    Translates C++ source code to Frame SIL.

    Extends CFrontend with C++ specific features:
    - Classes and methods
    - Namespaces
    - Templates (limited)
    - STL (via specs)
    """

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
            elif child.type == "declaration_list":
                # Recurse into declaration lists (e.g., namespace bodies)
                self._translate_translation_unit(child, program)
            elif child.type == "declaration":
                pass  # Skip global declarations

    def _translate_class(self, node: TSNode, program: Program) -> None:
        """Translate C++ class/struct"""
        name_node = node.child_by_field_name("name")
        class_name = self._get_text(name_node) if name_node else "UnknownClass"

        old_class = self._current_class
        self._current_class = class_name

        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "function_definition":
                    proc = self._translate_function(child)
                    if proc:
                        proc.class_name = class_name
                        proc.name = f"{class_name}::{proc.name}"
                        proc.is_method = True
                        program.add_procedure(proc)
                elif child.type == "field_declaration":
                    # Member variable - skip
                    pass
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
