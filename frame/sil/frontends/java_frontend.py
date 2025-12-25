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

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """Translate Java source code to SIL Program."""
        self._filename = filename
        self._source = source_code
        self._node_counter = 0
        self._ident_counter = 0

        tree = self.parser.parse(bytes(source_code, "utf8"))
        program = Program(library_specs=self.specs.copy())
        program.source_files.append(filename)

        self._translate_compilation_unit(tree.root_node, program)
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

        self._current_class = None

    def _translate_interface(self, node: TSNode, program: Program) -> None:
        """Translate interface (skip method bodies as they're abstract)"""
        pass

    def _translate_enum(self, node: TSNode, program: Program) -> None:
        """Translate enum (similar to class)"""
        self._translate_class(node, program)

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

        # Create entry node
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry

        # Mark annotated parameters as taint sources
        self._process_param_annotations(annotations, params, proc)

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

    def _process_param_annotations(
        self,
        annotations: List[str],
        params: List[Tuple[PVar, Typ]],
        proc: Procedure
    ) -> None:
        """Process parameter annotations for taint sources"""
        # Spring annotations that mark parameters as taint sources
        taint_annotations = {
            "@RequestParam": TaintKind.USER_INPUT,
            "@PathVariable": TaintKind.USER_INPUT,
            "@RequestBody": TaintKind.USER_INPUT,
            "@RequestHeader": TaintKind.USER_INPUT,
            "@CookieValue": TaintKind.USER_INPUT,
        }

        for ann in annotations:
            for pattern, kind in taint_annotations.items():
                if pattern in ann:
                    # Mark all params as tainted (simplified)
                    for param, _ in params:
                        self._add_instr(TaintSource(
                            loc=self._get_location(proc.nodes[proc.entry_node].instrs[0] if proc.nodes[proc.entry_node].instrs else proc),
                            var=param,
                            kind=kind,
                            description=f"{pattern} annotation"
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
        elif node.type == "switch_expression":
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
                        else:
                            exp = self._translate_expression(value_node)
                            self._add_instr(Assign(loc=loc, id=PVar(var_name), exp=exp))
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
        else:
            exp = self._translate_expression(right)
            self._add_instr(Assign(loc=loc, id=PVar(target), exp=exp))

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

        # Check specs
        spec = self.specs.get(method_name)
        if spec and spec.is_taint_source():
            kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
            instrs.append(TaintSource(loc=loc, var=PVar(target), kind=kind, description=spec.description))

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

        spec = self.specs.get(method_name)
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

    def _translate_switch(self, node: TSNode) -> None:
        """Translate switch (simplified)"""
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "switch_block_statement_group":
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
            conseq = node.child_by_field_name("consequence")
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
        return self._source[node.start_byte:node.end_byte]

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
