"""
Python to Frame SIL Frontend.

This module translates Python source code to Frame SIL using tree-sitter
for parsing. It handles:
- Function definitions
- Assignments and expressions
- Function calls (with taint source/sink detection)
- Control flow (if/else, while, for)
- String operations (concatenation, f-strings)
- Class methods
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

try:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser, Node as TSNode
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    TSNode = Any  # Type hint fallback

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
from frame.sil.specs.python_specs import PYTHON_SPECS


class PythonFrontend:
    """
    Translates Python source code to Frame SIL.

    Usage:
        frontend = PythonFrontend()
        program = frontend.translate(source_code, "example.py")

        # Now use SILTranslator to generate vulnerability checks
        from frame.sil import SILTranslator
        translator = SILTranslator(program)
        checks = translator.translate_program()
    """

    def __init__(self, specs: Dict[str, ProcSpec] = None):
        """
        Initialize the Python frontend.

        Args:
            specs: Library specifications (defaults to PYTHON_SPECS)
        """
        if not TREE_SITTER_AVAILABLE:
            raise ImportError(
                "tree-sitter and tree-sitter-python are required. "
                "Install with: pip install tree-sitter tree-sitter-python"
            )

        self.parser = Parser(Language(tspython.language()))
        self.specs = specs or PYTHON_SPECS

        # State during translation
        self._filename = "<unknown>"
        self._source = ""
        self._current_proc: Optional[Procedure] = None
        self._current_node: Optional[Node] = None
        self._node_counter = 0
        self._ident_counter = 0
        self._current_class: Optional[str] = None

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        """
        Translate Python source code to SIL Program.

        Args:
            source_code: Python source code string
            filename: Source file name for error reporting

        Returns:
            SIL Program containing all translated procedures
        """
        self._filename = filename
        self._source = source_code
        self._node_counter = 0
        self._ident_counter = 0

        # Parse source code
        tree = self.parser.parse(bytes(source_code, "utf8"))

        # Create program with library specs
        program = Program(library_specs=self.specs.copy())
        program.source_files.append(filename)

        # Walk top-level definitions
        self._translate_module(tree.root_node, program)

        return program

    def _translate_module(self, root: TSNode, program: Program) -> None:
        """Translate module-level definitions"""
        for child in root.children:
            if child.type == "function_definition":
                proc = self._translate_function(child, program=program)
                if proc:
                    program.add_procedure(proc)

            elif child.type == "class_definition":
                self._translate_class(child, program)

            elif child.type == "decorated_definition":
                # Handle decorated functions/classes
                definition = None
                for c in child.children:
                    if c.type in ("function_definition", "class_definition"):
                        definition = c
                        break

                if definition:
                    if definition.type == "function_definition":
                        proc = self._translate_function(definition, program=program)
                        if proc:
                            program.add_procedure(proc)
                    elif definition.type == "class_definition":
                        self._translate_class(definition, program)

    def _translate_class(self, node: TSNode, program: Program) -> None:
        """Translate class definition"""
        name_node = node.child_by_field_name("name")
        class_name = self._get_text(name_node) if name_node else "UnknownClass"

        self._current_class = class_name

        # Find class body
        body_node = node.child_by_field_name("body")
        if body_node:
            for child in body_node.children:
                if child.type == "function_definition":
                    proc = self._translate_function(child, is_method=True, program=program)
                    if proc:
                        proc.class_name = class_name
                        proc.name = f"{class_name}.{proc.name}"
                        program.add_procedure(proc)

                elif child.type == "decorated_definition":
                    for c in child.children:
                        if c.type == "function_definition":
                            proc = self._translate_function(c, is_method=True, program=program)
                            if proc:
                                proc.class_name = class_name
                                proc.name = f"{class_name}.{proc.name}"
                                program.add_procedure(proc)
                            break

        self._current_class = None

    def _translate_function(self, node: TSNode, is_method: bool = False, program: Program = None) -> Optional[Procedure]:
        """Translate function definition to SIL Procedure"""
        # Get function name
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None
        func_name = self._get_text(name_node)

        # Get parameters
        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = self._translate_parameters(params_node)

        # Create procedure
        proc = Procedure(
            name=func_name,
            params=params,
            ret_type=Typ.unknown_type(),
            loc=self._get_location(node),
            is_method=is_method,
        )

        # Check for static method decorator
        if is_method:
            parent = node.parent
            if parent and parent.type == "decorated_definition":
                for child in parent.children:
                    if child.type == "decorator":
                        decorator_text = self._get_text(child)
                        if "@staticmethod" in decorator_text:
                            proc.is_static = True
                        if "@classmethod" in decorator_text:
                            proc.is_static = True

        self._current_proc = proc
        self._node_counter = 0

        # Create entry node
        entry = proc.new_node(NodeKind.ENTRY)
        proc.add_node(entry)
        proc.entry_node = entry.id
        self._current_node = entry

        # Translate body (pass program for nested functions)
        body_node = node.child_by_field_name("body")
        if body_node:
            self._translate_block(body_node, program=program)

        # Create exit node
        exit_node = proc.new_node(NodeKind.EXIT)
        proc.add_node(exit_node)
        proc.exit_node = exit_node.id

        # Connect last node to exit
        if self._current_node:
            proc.connect(self._current_node.id, exit_node.id)

        self._current_proc = None
        return proc

    def _translate_parameters(self, node: TSNode) -> List[Tuple[PVar, Typ]]:
        """Translate function parameters"""
        params = []
        for child in node.children:
            if child.type == "identifier":
                param_name = self._get_text(child)
                params.append((PVar(param_name), Typ.unknown_type()))

            elif child.type == "typed_parameter":
                name_node = child.child_by_field_name("name")
                if name_node:
                    param_name = self._get_text(name_node)
                    params.append((PVar(param_name), Typ.unknown_type()))

            elif child.type == "default_parameter":
                name_node = child.child_by_field_name("name")
                if name_node:
                    param_name = self._get_text(name_node)
                    params.append((PVar(param_name), Typ.unknown_type()))

            elif child.type == "typed_default_parameter":
                name_node = child.child_by_field_name("name")
                if name_node:
                    param_name = self._get_text(name_node)
                    params.append((PVar(param_name), Typ.unknown_type()))

            elif child.type == "list_splat_pattern":
                # *args
                for c in child.children:
                    if c.type == "identifier":
                        param_name = self._get_text(c)
                        params.append((PVar(param_name), Typ.list_of(Typ.unknown_type())))

            elif child.type == "dictionary_splat_pattern":
                # **kwargs
                for c in child.children:
                    if c.type == "identifier":
                        param_name = self._get_text(c)
                        params.append((PVar(param_name), Typ.dict_of(Typ.string_type(), Typ.unknown_type())))

        return params

    def _translate_block(self, node: TSNode, program: Program = None) -> None:
        """Translate a block of statements"""
        for child in node.children:
            # Handle nested function definitions
            if child.type == "function_definition":
                if program:
                    proc = self._translate_function(child)
                    if proc:
                        program.add_procedure(proc)
            elif child.type == "decorated_definition":
                # Handle decorated nested functions
                if program:
                    for c in child.children:
                        if c.type == "function_definition":
                            proc = self._translate_function(c)
                            if proc:
                                program.add_procedure(proc)
                            break
            else:
                self._translate_statement(child)

    def _translate_statement(self, node: TSNode) -> None:
        """Translate a single statement"""
        if node.type == "expression_statement":
            self._translate_expression_statement(node)

        elif node.type == "assignment":
            self._translate_assignment(node)

        elif node.type == "augmented_assignment":
            self._translate_augmented_assignment(node)

        elif node.type == "return_statement":
            self._translate_return(node)

        elif node.type == "if_statement":
            self._translate_if(node)

        elif node.type == "while_statement":
            self._translate_while(node)

        elif node.type == "for_statement":
            self._translate_for(node)

        elif node.type == "try_statement":
            self._translate_try(node)

        elif node.type == "with_statement":
            self._translate_with(node)

        elif node.type == "match_statement":
            self._translate_match(node)

        elif node.type == "pass_statement":
            pass  # No SIL needed

        elif node.type == "break_statement":
            pass  # Handled by loop structure

        elif node.type == "continue_statement":
            pass  # Handled by loop structure

    def _translate_expression_statement(self, node: TSNode) -> None:
        """Translate expression statement (usually a call or assignment)"""
        for child in node.children:
            if child.type == "call":
                instrs = self._translate_call_expr(child)
                self._add_instrs(instrs)

            elif child.type == "assignment":
                # Assignment wrapped in expression_statement
                self._translate_assignment(child)

            elif child.type == "augmented_assignment":
                # Augmented assignment wrapped in expression_statement
                self._translate_augmented_assignment(child)

            elif child.type == "string":
                # Docstring - skip
                pass

    def _translate_assignment(self, node: TSNode) -> None:
        """Translate assignment: target = value"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        if not left or not right:
            return

        loc = self._get_location(node)

        # Check for subscript assignment: target[key] = value
        # This handles patterns like session['userid'] = bar (CWE-501)
        if left.type == "subscript":
            self._translate_subscript_assignment(left, right, loc)
            return

        target_name = self._get_text(left)

        # Handle different RHS types
        if right.type == "call":
            # x = func(...)
            instrs = self._translate_call_assignment(target_name, right, loc)
            self._add_instrs(instrs)

        elif right.type == "string" or right.type == "concatenated_string":
            # x = "literal" or x = "a" "b"
            exp = self._translate_expression(right)
            self._add_instr(Assign(
                loc=loc,
                id=PVar(target_name),
                exp=exp
            ))

        elif right.type == "formatted_string" or right.type == "f_string":
            # x = f"..."
            instrs = self._translate_fstring_assignment(target_name, right, loc)
            self._add_instrs(instrs)

        elif right.type == "binary_operator":
            # x = a + b
            # First, extract all nested calls to generate Call instructions
            nested_call_instrs = self._extract_all_calls_from_node(right, loc)
            self._add_instrs(nested_call_instrs)

            exp = self._translate_expression(right)
            self._add_instr(Assign(
                loc=loc,
                id=PVar(target_name),
                exp=exp
            ))

            # Check for string concatenation taint propagation
            self._check_concat_taint(target_name, right, loc)

        else:
            # General case
            # First, extract all nested calls to generate Call instructions
            # This enables detection of usage-based sinks (like weak random) in nested expressions
            nested_call_instrs = self._extract_all_calls_from_node(right, loc)
            self._add_instrs(nested_call_instrs)

            exp = self._translate_expression(right)
            self._add_instr(Assign(
                loc=loc,
                id=PVar(target_name),
                exp=exp
            ))

    def _translate_subscript_assignment(
        self,
        subscript_node: TSNode,
        value_node: TSNode,
        loc: Location
    ) -> None:
        """
        Translate subscript assignment: target[key] = value

        Converts to synthetic __setitem__ call for taint tracking.
        This handles patterns like:
        - session['userid'] = bar  (CWE-501 Trust Boundary)
        - dict['key'] = value
        """
        # Get the target (e.g., 'session' from 'session['userid']')
        target = subscript_node.child_by_field_name("value")
        key = subscript_node.child_by_field_name("subscript")

        if not target or not key:
            return

        target_name = self._get_text(target)
        key_exp = self._translate_expression(key)
        value_exp = self._translate_expression(value_node)

        # Generate synthetic __setitem__ call: target.__setitem__(key, value)
        # This allows our spec system to detect trust boundary violations
        func_name = f"{target_name}.__setitem__"

        call_instr = Call(
            loc=loc,
            ret=None,  # __setitem__ returns None
            func=ExpConst.string(func_name),
            args=[
                (key_exp, Typ.unknown_type()),
                (value_exp, Typ.unknown_type())
            ]
        )
        self._add_instr(call_instr)

        # Also add a simple call with just the target name for broader spec matching
        # e.g., "session" spec can match session['key'] = value
        if '.' not in target_name:
            simple_call = Call(
                loc=loc,
                ret=None,
                func=ExpConst.string(target_name),
                args=[
                    (key_exp, Typ.unknown_type()),
                    (value_exp, Typ.unknown_type())
                ]
            )
            self._add_instr(simple_call)

    def _translate_call_assignment(
        self,
        target: str,
        call_node: TSNode,
        loc: Location
    ) -> List[Instr]:
        """Translate: target = func(args)"""
        instrs = []

        # Check for method chain: obj.method1().method2()
        # The "function" field will be an "attribute" whose object is a "call"
        func_node = call_node.child_by_field_name("function")
        inner_call = None

        if func_node and func_node.type == "attribute":
            # Check if the attribute's object is a call (method chain)
            obj_node = func_node.child_by_field_name("object")
            if obj_node and obj_node.type == "call":
                inner_call = obj_node

        if inner_call:
            # Method chain - expand the inner call first
            inner_instrs, inner_var = self._expand_nested_call(inner_call, loc)
            instrs.extend(inner_instrs)

            # Get the method name from the attribute
            attr_name = func_node.child_by_field_name("attribute")
            if attr_name:
                method_name = self._get_text(attr_name)
                # Create method call name like "var.method"
                func_name = f"{inner_var}.{method_name}"
            else:
                func_name = self._get_call_name(call_node)
        elif func_node and func_node.type == "call":
            # Direct function call that is another call (rare but possible)
            inner_instrs, inner_var = self._expand_nested_call(func_node, loc)
            instrs.extend(inner_instrs)
            func_name = inner_var  # The result of the call IS the function
        else:
            func_name = self._get_call_name(call_node)

        args = self._get_call_args(call_node)

        # Handle nested calls in arguments - expand them first
        args_exp = []
        for i, arg in enumerate(args):
            if arg.type == "call":
                # Nested call - expand it first
                nested_instrs, nested_var = self._expand_nested_call(arg, loc)
                instrs.extend(nested_instrs)
                args_exp.append((ExpVar(PVar(nested_var)), Typ.unknown_type()))
            else:
                args_exp.append((self._translate_expression(arg), Typ.unknown_type()))

        # Create return identifier
        ret_id = self._new_ident(target)

        # Build Call instruction
        call_instr = Call(
            loc=loc,
            ret=(ret_id, Typ.unknown_type()),
            func=ExpConst.string(func_name),
            args=args_exp
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
        if spec and spec.is_taint_source():
            kind = TaintKind(spec.is_source) if spec.is_source in [t.value for t in TaintKind] else TaintKind.USER_INPUT
            instrs.append(TaintSource(
                loc=loc,
                var=PVar(target),
                kind=kind,
                description=spec.description
            ))

        # Check if this is a sink (unusual but possible)
        if spec and spec.is_taint_sink():
            kind = SinkKind(spec.is_sink) if spec.is_sink in [s.value for s in SinkKind] else SinkKind.SQL_QUERY
            for arg_idx in spec.sink_args:
                if arg_idx < len(args_exp):
                    instrs.append(TaintSink(
                        loc=loc,
                        exp=args_exp[arg_idx][0],
                        kind=kind,
                        description=spec.description
                    ))

        return instrs

    def _expand_nested_call(self, call_node: TSNode, loc: Location) -> Tuple[List[Instr], str]:
        """Expand a nested call and return (instructions, result_var_name)"""
        # Generate a temp variable for the result
        temp_var = f"__nested_{self._ident_counter}"
        self._ident_counter += 1

        # Translate the nested call as an assignment
        nested_instrs = self._translate_call_assignment(temp_var, call_node, loc)

        return nested_instrs, temp_var

    def _extract_all_calls_from_node(self, node: TSNode, loc: Location) -> List[Instr]:
        """
        Walk a tree-sitter node and extract all call nodes as Call instructions.
        This is used to detect usage-based sinks (like weak random) in nested expressions.
        Returns list of Call instructions for all calls found.
        """
        instrs = []

        def walk(n: TSNode):
            if n is None:
                return
            if n.type == "call":
                # Generate Call instruction for this call
                func_name = self._get_call_name(n)
                args = self._get_call_args(n)
                args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

                # Create a Call instruction (result discarded for detection purposes)
                call_instr = Call(
                    loc=self._get_location(n),
                    ret=None,
                    func=ExpConst.string(func_name),
                    args=args_exp
                )
                instrs.append(call_instr)

                # Also recurse into the call's function and arguments to find nested calls
                func = n.child_by_field_name("function")
                if func:
                    walk(func)
                args_node = n.child_by_field_name("arguments")
                if args_node:
                    for child in args_node.children:
                        walk(child)
            else:
                # Recurse into children
                for child in n.children:
                    walk(child)

        walk(node)
        return instrs

    def _translate_call_expr(self, call_node: TSNode) -> List[Instr]:
        """Translate standalone call: func(args)"""
        instrs = []
        loc = self._get_location(call_node)

        func_name = self._get_call_name(call_node)
        args = self._get_call_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        # Build Call instruction (no return)
        call_instr = Call(
            loc=loc,
            ret=None,
            func=ExpConst.string(func_name),
            args=args_exp
        )
        instrs.append(call_instr)

        # Check if this is a sink
        spec = self.specs.get(func_name)
        if spec and spec.is_taint_sink():
            kind = SinkKind(spec.is_sink) if spec.is_sink in [s.value for s in SinkKind] else SinkKind.SQL_QUERY
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = self._translate_expression(args[arg_idx])
                    instrs.append(TaintSink(
                        loc=loc,
                        exp=arg_exp,
                        kind=kind,
                        description=spec.description,
                        arg_index=arg_idx
                    ))

        return instrs

    def _translate_fstring_assignment(
        self,
        target: str,
        fstring_node: TSNode,
        loc: Location
    ) -> List[Instr]:
        """Translate f-string assignment"""
        instrs = []

        # Extract parts of f-string
        parts = self._extract_fstring_parts(fstring_node)

        if parts:
            # Create string concatenation expression
            concat_exp = ExpStringConcat(parts)

            instrs.append(Assign(
                loc=loc,
                id=PVar(target),
                exp=concat_exp
            ))
        else:
            # Empty or unparseable f-string
            instrs.append(Assign(
                loc=loc,
                id=PVar(target),
                exp=ExpConst.string("")
            ))

        return instrs

    def _extract_fstring_parts(self, node: TSNode) -> List[Exp]:
        """Extract parts from f-string"""
        parts = []

        def walk(n: TSNode):
            if n.type == "string_content":
                # Literal string content between interpolations
                text = self._get_text(n)
                if text:
                    parts.append(ExpConst.string(text))

            elif n.type == "interpolation":
                # {expr} inside f-string
                for child in n.children:
                    if child.type not in ("{", "}", ":", "format_specifier"):
                        exp = self._translate_expression(child)
                        parts.append(exp)

            elif n.type in ("string_start", "string_end"):
                # Skip f-string delimiters
                pass

            elif n.type == "string" or n.type == "formatted_string" or n.type == "f_string":
                # Walk children of string node
                for child in n.children:
                    walk(child)

            else:
                # For other nodes, recurse into children
                for child in n.children:
                    walk(child)

        walk(node)
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

        # Get operator (+=, -=, *=, etc.)
        op = self._get_text(op_node) if op_node else "+="
        bin_op = op[:-1] if op.endswith("=") else "+"

        # Translate as: target = target op value
        left_exp = ExpVar(PVar(target_name))
        right_exp = self._translate_expression(right)
        combined = ExpBinOp(bin_op, left_exp, right_exp)

        self._add_instr(Assign(
            loc=loc,
            id=PVar(target_name),
            exp=combined
        ))

        # Check for string concatenation (+=)
        if bin_op == "+":
            self._check_concat_taint(target_name, right, loc)

    def _translate_return(self, node: TSNode) -> None:
        """Translate return statement"""
        loc = self._get_location(node)

        # Find return value (if any)
        value_exp = None
        value_node = None
        for child in node.children:
            if child.type not in ("return",):
                value_node = child
                break

        if value_node:
            # If the return value is a call, translate it as a call assignment
            if value_node.type == "call":
                instrs = self._translate_call_assignment("__return_val", value_node, loc)
                self._add_instrs(instrs)
                value_exp = ExpVar(PVar("__return_val"))
            else:
                # Extract nested calls from the expression first
                nested_call_instrs = self._extract_all_calls_from_node(value_node, loc)
                self._add_instrs(nested_call_instrs)
                value_exp = self._translate_expression(value_node)

        self._add_instr(Return(loc=loc, value=value_exp))

    def _translate_if(self, node: TSNode) -> None:
        """Translate if statement"""
        loc = self._get_location(node)
        proc = self._current_proc
        if not proc:
            return

        # Get condition
        condition = node.child_by_field_name("condition")
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)

        # Save current node
        before_node = self._current_node

        # Create nodes for branches
        true_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(true_node)

        false_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(false_node)

        join_node = proc.new_node(NodeKind.JOIN)
        proc.add_node(join_node)

        # Add prunes
        if before_node:
            # True branch
            before_node.add_instr(Prune(
                loc=loc,
                condition=condition_exp,
                is_true_branch=True,
                kind=PruneKind.IF_TRUE
            ))
            proc.connect(before_node.id, true_node.id)

            # False branch
            before_node.add_instr(Prune(
                loc=loc,
                condition=condition_exp,
                is_true_branch=False,
                kind=PruneKind.IF_FALSE
            ))
            proc.connect(before_node.id, false_node.id)

        # Translate true branch (consequence)
        consequence = node.child_by_field_name("consequence")
        if consequence:
            self._current_node = true_node
            self._translate_block(consequence)
            if self._current_node:
                proc.connect(self._current_node.id, join_node.id)

        # Translate false branch (alternative)
        alternative = node.child_by_field_name("alternative")
        if alternative:
            self._current_node = false_node
            # Handle elif or else
            if alternative.type == "elif_clause":
                self._translate_elif(alternative, join_node)
            elif alternative.type == "else_clause":
                self._translate_else(alternative)
                if self._current_node:
                    proc.connect(self._current_node.id, join_node.id)
        else:
            proc.connect(false_node.id, join_node.id)

        self._current_node = join_node

    def _translate_elif(self, node: TSNode, final_join: Node) -> None:
        """Translate elif clause"""
        # Treat as nested if
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        condition = node.child_by_field_name("condition")
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)

        before_node = self._current_node

        true_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(true_node)

        false_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(false_node)

        if before_node:
            before_node.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=True))
            proc.connect(before_node.id, true_node.id)

            before_node.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=False))
            proc.connect(before_node.id, false_node.id)

        # True branch
        consequence = node.child_by_field_name("consequence")
        if consequence:
            self._current_node = true_node
            self._translate_block(consequence)
            if self._current_node:
                proc.connect(self._current_node.id, final_join.id)

        # Handle next alternative
        alternative = node.child_by_field_name("alternative")
        if alternative:
            self._current_node = false_node
            if alternative.type == "elif_clause":
                self._translate_elif(alternative, final_join)
            elif alternative.type == "else_clause":
                self._translate_else(alternative)
                if self._current_node:
                    proc.connect(self._current_node.id, final_join.id)
        else:
            proc.connect(false_node.id, final_join.id)

    def _translate_else(self, node: TSNode) -> None:
        """Translate else clause"""
        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)

    def _translate_while(self, node: TSNode) -> None:
        """Translate while loop"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        condition = node.child_by_field_name("condition")
        condition_exp = self._translate_expression(condition) if condition else ExpConst.boolean(True)

        before_node = self._current_node

        # Loop head
        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)

        # Loop body
        body_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(body_node)

        # After loop
        after_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(after_node)

        # Connect before -> head
        if before_node:
            proc.connect(before_node.id, loop_head.id)

        # Head: prune for entering loop
        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=True, kind=PruneKind.LOOP_ENTER))
        proc.connect(loop_head.id, body_node.id)

        # Head: prune for exiting loop
        loop_head.add_instr(Prune(loc=loc, condition=condition_exp, is_true_branch=False, kind=PruneKind.LOOP_EXIT))
        proc.connect(loop_head.id, after_node.id)

        # Translate body
        body = node.child_by_field_name("body")
        if body:
            self._current_node = body_node
            self._translate_block(body)

        # Back edge
        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node

    def _translate_for(self, node: TSNode) -> None:
        """Translate for loop (simplify to while-like)"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        # Get loop variable
        left = node.child_by_field_name("left")
        loop_var = self._get_text(left) if left else "_iter"

        # Get iterable
        right = node.child_by_field_name("right")
        iterable_exp = self._translate_expression(right) if right else ExpConst.null()

        before_node = self._current_node

        # For simplicity, model for loop as:
        # loop_var = next(iter)  (assignment from iterable)
        # while has_next: body

        # Loop head
        loop_head = proc.new_node(NodeKind.LOOP_HEAD)
        proc.add_node(loop_head)

        # Loop body (includes assignment to loop var)
        body_node = proc.new_node(NodeKind.NORMAL)
        body_node.add_instr(Assign(
            loc=loc,
            id=PVar(loop_var),
            exp=ExpCall(ExpConst.string("next"), [iterable_exp])
        ))
        proc.add_node(body_node)

        # After loop
        after_node = proc.new_node(NodeKind.NORMAL)
        proc.add_node(after_node)

        if before_node:
            proc.connect(before_node.id, loop_head.id)

        # Loop condition (simplified)
        cond = ExpConst.boolean(True)  # Simplified: always enter
        loop_head.add_instr(Prune(loc=loc, condition=cond, is_true_branch=True, kind=PruneKind.FOR_ENTER))
        proc.connect(loop_head.id, body_node.id)

        loop_head.add_instr(Prune(loc=loc, condition=cond, is_true_branch=False, kind=PruneKind.FOR_EXIT))
        proc.connect(loop_head.id, after_node.id)

        # Translate body
        body = node.child_by_field_name("body")
        if body:
            self._current_node = body_node
            self._translate_block(body)

        if self._current_node:
            proc.connect(self._current_node.id, loop_head.id)

        self._current_node = after_node

    def _translate_try(self, node: TSNode) -> None:
        """Translate try/except/finally"""
        # Simplified: just translate the body
        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)

        # Also translate handlers (they might contain vulnerable code)
        for child in node.children:
            if child.type == "except_clause":
                body = child.child_by_field_name("body")
                if body:
                    self._translate_block(body)

            elif child.type == "finally_clause":
                body = child.child_by_field_name("body")
                if body:
                    self._translate_block(body)

    def _translate_with(self, node: TSNode) -> None:
        """Translate with statement: with expr as var: body"""
        loc = self._get_location(node)

        # Translate the context manager expression(s) in with_clause
        # Pattern: with open(file, 'rb') as fd: ...
        for child in node.children:
            if child.type == "with_clause":
                for item in child.children:
                    if item.type == "with_item":
                        # with_item can contain:
                        # 1. Direct call: with open(...): ...
                        # 2. as_pattern: with open(...) as fd: ...
                        call_node = None
                        alias_name = None

                        for subchild in item.children:
                            if subchild.type == "call":
                                call_node = subchild
                            elif subchild.type == "as_pattern":
                                # as_pattern contains: call "as" identifier
                                for as_child in subchild.children:
                                    if as_child.type == "call":
                                        call_node = as_child
                                    elif as_child.type == "as_pattern_target":
                                        for target_child in as_child.children:
                                            if target_child.type == "identifier":
                                                alias_name = self._get_text(target_child)

                        if call_node:
                            # Translate the call (e.g., open(fileName, 'wb'))
                            instrs = self._translate_call_expr(call_node)
                            self._add_instrs(instrs)

                            # If there's an alias, assign the result to it
                            if alias_name and instrs:
                                last_instr = instrs[-1]
                                if hasattr(last_instr, 'ret') and last_instr.ret:
                                    ret_var = str(last_instr.ret[0])
                                    assign = Assign(
                                        Ident(alias_name, self._next_id()),
                                        ExpVar(PVar(ret_var)),
                                        loc
                                    )
                                    self._add_instr(assign)

        # Translate the body
        body = node.child_by_field_name("body")
        if body:
            self._translate_block(body)

    def _translate_match(self, node: TSNode) -> None:
        """Translate Python 3.10+ match statement (structural pattern matching)"""
        proc = self._current_proc
        if not proc:
            return

        loc = self._get_location(node)

        # Get match subject
        subject = node.child_by_field_name("subject")
        if not subject:
            # Try to find subject in children
            for child in node.children:
                if child.type not in ("match", ":", "case_clause", "block"):
                    subject = child
                    break

        before_node = self._current_node

        # Create join node for after match
        join_node = proc.new_node(NodeKind.JOIN)
        proc.add_node(join_node)

        # Find all case clauses
        case_clauses = []
        for child in node.children:
            if child.type == "case_clause":
                case_clauses.append(child)
            elif child.type == "block":
                # Block may contain case clauses
                for block_child in child.children:
                    if block_child.type == "case_clause":
                        case_clauses.append(block_child)

        # Get subject expression for Prune conditions
        subject_exp = self._translate_expression(subject) if subject else None

        # Translate each case
        for case_node in case_clauses:
            # Create case node
            case_entry = proc.new_node(NodeKind.NORMAL)
            proc.add_node(case_entry)

            if before_node:
                proc.connect(before_node.id, case_entry.id)

            self._current_node = case_entry

            # Extract case pattern and add Prune instruction
            # This enables constant folding to eliminate unreachable cases
            pattern_exp = None
            for child in case_node.children:
                if child.type in ("case_pattern", "pattern"):
                    pattern_exp = self._extract_case_pattern(child)
                    break
                # Also check for direct string/identifier patterns
                elif child.type in ("string", "integer", "identifier"):
                    pattern_exp = self._translate_expression(child)
                    break

            # Add Prune instruction for case condition (subject == pattern)
            if subject_exp and pattern_exp:
                from ..instructions import Prune
                cond = ExpBinOp(subject_exp, "==", pattern_exp)
                prune_instr = Prune(condition=cond, is_true_branch=True, loc=loc)
                self._current_node.instrs.append(prune_instr)

            # Translate case body - look for the block/consequence
            for child in case_node.children:
                if child.type == "block":
                    self._translate_block(child)

            if self._current_node:
                proc.connect(self._current_node.id, join_node.id)

        self._current_node = join_node

    def _extract_case_pattern(self, pattern_node: TSNode) -> Optional[Exp]:
        """Extract the expression from a case pattern for Prune conditions."""
        if pattern_node is None:
            return None

        # Handle different pattern types
        # case 'A': -> string literal
        # case _: -> wildcard (return None to skip)
        for child in pattern_node.children:
            if child.type == "string":
                return self._translate_expression(child)
            elif child.type == "integer":
                return self._translate_expression(child)
            elif child.type == "identifier":
                name = self._get_text(child)
                if name == "_":
                    return None  # Wildcard pattern, matches anything
                return self._translate_expression(child)
            elif child.type in ("case_pattern", "pattern"):
                # Nested pattern
                return self._extract_case_pattern(child)
            elif child.type == "union_pattern":
                # 'C' | 'D' - for now, return first pattern
                for sub in child.children:
                    if sub.type != "|":
                        return self._translate_expression(sub)

        # Try the pattern node itself if it's a simple type
        if pattern_node.type == "string":
            return self._translate_expression(pattern_node)
        elif pattern_node.type == "integer":
            return self._translate_expression(pattern_node)

        return None

    def _translate_expression(self, node: TSNode) -> Exp:
        """Translate expression to SIL Exp"""
        if node is None:
            return ExpConst.null()

        if node.type == "identifier":
            name = self._get_text(node)
            return ExpVar(PVar(name))

        elif node.type in ("integer", "float"):
            text = self._get_text(node)
            try:
                if node.type == "integer":
                    return ExpConst.integer(int(text, 0))
                else:
                    return ExpConst.integer(int(float(text)))
            except ValueError:
                return ExpConst.integer(0)

        elif node.type == "string" or node.type == "concatenated_string":
            # Check if it's an f-string by looking for interpolation children
            has_interpolation = False
            for child in node.children:
                if child.type == "interpolation":
                    has_interpolation = True
                    break
                elif child.type == "string_start":
                    start_text = self._get_text(child)
                    if start_text.startswith('f') or start_text.startswith('F'):
                        has_interpolation = True
                        break

            if has_interpolation:
                # It's an f-string - extract parts
                parts = self._extract_fstring_parts(node)
                if parts:
                    return ExpStringConcat(parts)
                return ExpConst.string("")
            else:
                text = self._get_string_content(node)
                return ExpConst.string(text)

        elif node.type in ("true", "True"):
            return ExpConst.boolean(True)

        elif node.type in ("false", "False"):
            return ExpConst.boolean(False)

        elif node.type in ("none", "None"):
            return ExpConst.null()

        elif node.type == "binary_operator":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")

            left_exp = self._translate_expression(left)
            right_exp = self._translate_expression(right)
            op = self._get_text(op_node) if op_node else "+"

            # Check for string concatenation
            if op == "+":
                # Could be string concat - create StringConcat
                return ExpStringConcat([left_exp, right_exp])

            return ExpBinOp(op, left_exp, right_exp)

        elif node.type == "comparison_operator":
            # Handle chained comparisons
            children = [c for c in node.children if c.type != "comment"]
            if len(children) >= 3:
                left = self._translate_expression(children[0])
                op = self._get_text(children[1])
                right = self._translate_expression(children[2])
                return ExpBinOp(op, left, right)
            return ExpConst.boolean(True)

        elif node.type == "unary_operator":
            op_node = node.child_by_field_name("operator")
            operand = node.child_by_field_name("argument")
            op = self._get_text(op_node) if op_node else "-"
            operand_exp = self._translate_expression(operand)
            return ExpUnOp(op, operand_exp)

        elif node.type == "not_operator":
            operand = node.child_by_field_name("argument")
            operand_exp = self._translate_expression(operand)
            return ExpUnOp("!", operand_exp)

        elif node.type == "boolean_operator":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            op_node = node.child_by_field_name("operator")

            left_exp = self._translate_expression(left)
            right_exp = self._translate_expression(right)
            op_text = self._get_text(op_node) if op_node else "and"
            op = "&&" if op_text == "and" else "||"

            return ExpBinOp(op, left_exp, right_exp)

        elif node.type == "attribute":
            obj = node.child_by_field_name("object")
            attr = node.child_by_field_name("attribute")

            obj_exp = self._translate_expression(obj)
            attr_name = self._get_text(attr) if attr else ""

            return ExpFieldAccess(obj_exp, attr_name)

        elif node.type == "subscript":
            value = node.child_by_field_name("value")
            subscript = node.child_by_field_name("subscript")

            value_exp = self._translate_expression(value)
            subscript_exp = self._translate_expression(subscript)

            return ExpIndex(value_exp, subscript_exp)

        elif node.type == "call":
            func = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")

            func_exp = self._translate_expression(func)
            args = []
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ","):
                        args.append(self._translate_expression(child))

            return ExpCall(func_exp, args)

        elif node.type == "parenthesized_expression":
            for child in node.children:
                if child.type not in ("(", ")"):
                    return self._translate_expression(child)

        elif node.type == "list" or node.type == "tuple":
            # [a, b, c] or (a, b, c)
            elements = []
            for child in node.children:
                if child.type not in ("[", "]", "(", ")", ","):
                    elements.append(self._translate_expression(child))
            # Return first element or null (simplified)
            return elements[0] if elements else ExpConst.null()

        elif node.type == "dictionary":
            # {k: v} - simplified
            return ExpConst.null()

        elif node.type == "formatted_string" or node.type == "f_string":
            parts = self._extract_fstring_parts(node)
            if parts:
                return ExpStringConcat(parts)
            return ExpConst.string("")

        elif node.type == "conditional_expression":
            # Python ternary: value_if_true if condition else value_if_false
            # Structure: consequence "if" condition "else" alternative
            consequence = None
            condition = None
            alternative = None
            state = 0  # 0=consequence, 1=condition, 2=alternative
            for child in node.children:
                if child.type == "if":
                    state = 1
                    continue
                elif child.type == "else":
                    state = 2
                    continue
                elif state == 0:
                    consequence = self._translate_expression(child)
                elif state == 1:
                    condition = child  # Keep AST node for text extraction
                else:
                    alternative = self._translate_expression(child)

            # Try to evaluate the condition for constant folding
            cons_is_const = isinstance(consequence, ExpConst)
            alt_is_const = isinstance(alternative, ExpConst) if alternative else True

            # Check if condition can be evaluated as constant
            if condition:
                cond_text = self._get_text(condition)
                # Try simple constant evaluation
                try:
                    # Handle simple arithmetic conditions
                    import re
                    # Replace common patterns with evaluable Python
                    eval_cond = cond_text
                    # Only eval if it looks like a safe arithmetic expression
                    if re.match(r'^[\d\s\+\-\*/%<>=!()]+$', eval_cond):
                        cond_result = eval(eval_cond)
                        if cond_result is True:
                            # Condition is always TRUE - return consequence
                            return consequence if consequence else ExpConst.null()
                        elif cond_result is False:
                            # Condition is always FALSE - return alternative
                            return alternative if alternative else ExpConst.null()
                except:
                    pass

            # Fallback: if constant folding didn't work, use heuristics
            if cons_is_const and not alt_is_const:
                # Safe consequence, potentially tainted alternative - include both
                # so translator can do constant folding at runtime
                if consequence and alternative:
                    return ExpBinOp(consequence, "?:", alternative)
                return alternative
            elif not cons_is_const and alt_is_const:
                # Potentially tainted consequence, safe alternative - include both
                if consequence and alternative:
                    return ExpBinOp(consequence, "?:", alternative)
                return consequence
            elif consequence and alternative:
                # Both are variables or both are constants - include both
                return ExpBinOp(consequence, "?:", alternative)
            elif alternative:
                return alternative
            elif consequence:
                return consequence
            return ExpConst.null()

        # Default: return as identifier
        text = self._get_text(node)
        return ExpVar(PVar(text)) if text else ExpConst.null()

    def _check_concat_taint(self, target: str, value_node: TSNode, loc: Location) -> None:
        """Check if string concatenation might propagate taint"""
        # This is handled by the translator, not the frontend
        # The frontend just needs to mark the concatenation
        pass

    # =========================================================================
    # Helpers
    # =========================================================================

    def _get_text(self, node: TSNode) -> str:
        """Get text of a node"""
        if node is None:
            return ""
        return self._source[node.start_byte:node.end_byte]

    def _get_string_content(self, node: TSNode) -> str:
        """Extract string content (without quotes)"""
        text = self._get_text(node)
        # Remove quotes
        if text.startswith('"""') or text.startswith("'''"):
            return text[3:-3]
        elif text.startswith('"') or text.startswith("'"):
            return text[1:-1]
        elif text.startswith('f"') or text.startswith("f'"):
            return text[2:-1]
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

    def _get_call_name(self, call_node: TSNode) -> str:
        """Get full name of function being called"""
        func = call_node.child_by_field_name("function")
        if func:
            return self._get_text(func)
        return ""

    def _get_call_args(self, call_node: TSNode) -> List[TSNode]:
        """Get argument nodes from call"""
        args = []
        args_node = call_node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type not in ("(", ")", ",", "comment"):
                    # Skip keyword argument names
                    if child.type == "keyword_argument":
                        value = child.child_by_field_name("value")
                        if value:
                            args.append(value)
                    else:
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
