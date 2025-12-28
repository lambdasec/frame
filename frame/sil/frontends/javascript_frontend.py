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

from typing import Dict, List, Optional, Tuple, Any
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
    TaintKind, SinkKind, PruneKind
)
from frame.sil.procedure import Procedure, Node, NodeKind, ProcSpec, Program
from frame.sil.specs.javascript_specs import JAVASCRIPT_SPECS


# Mapping from spec sink type strings to SinkKind enum
# Available SinkKind values: SQL_QUERY, HTML_OUTPUT, SHELL_COMMAND, LDAP_QUERY,
# XPATH_QUERY, EVAL, TEMPLATE, NOSQL_QUERY, XML_PARSE, REGEX, ORM_QUERY,
# EXPRESSION_LANG, FILE_PATH, REDIRECT, SSRF, AUTHZ_CHECK, CORS, HEADER,
# SECRET_EXPOSURE, DEBUG_INFO, WEAK_CRYPTO, HARDCODED_SECRET, INSECURE_RANDOM,
# WEAK_HASH, CREDENTIAL, SESSION, PASSWORD_STORE, TRUST_BOUNDARY, INSECURE_COOKIE,
# DESERIALIZATION, LOG, SENSITIVE_LOG, ERROR_DISCLOSURE, XSS, COMMAND, MEMORY
SINK_TYPE_MAP = {
    # Direct matches
    "sql": SinkKind.SQL_QUERY,
    "html": SinkKind.HTML_OUTPUT,
    "xss": SinkKind.XSS,
    "command": SinkKind.COMMAND,
    "shell": SinkKind.SHELL_COMMAND,
    "ldap": SinkKind.LDAP_QUERY,
    "xpath": SinkKind.XPATH_QUERY,
    "eval": SinkKind.EVAL,
    "template": SinkKind.TEMPLATE,
    "redirect": SinkKind.REDIRECT,
    "ssrf": SinkKind.SSRF,
    "deserialize": SinkKind.DESERIALIZATION,

    # Path/filesystem
    "path": SinkKind.FILE_PATH,
    "filesystem": SinkKind.FILE_PATH,
    "file": SinkKind.FILE_PATH,

    # NoSQL
    "nosql": SinkKind.NOSQL_QUERY,

    # Crypto
    "weak_crypto": SinkKind.WEAK_CRYPTO,
    "weak_hash": SinkKind.WEAK_HASH,
    "hardcoded_secret": SinkKind.HARDCODED_SECRET,
    "hardcoded_cred": SinkKind.CREDENTIAL,
    "insecure_random": SinkKind.INSECURE_RANDOM,

    # Auth/session
    "auth": SinkKind.AUTHZ_CHECK,
    "session": SinkKind.SESSION,

    # Headers
    "header": SinkKind.HEADER,
    "header_injection": SinkKind.HEADER,

    # Logging
    "sensitive_log": SinkKind.SENSITIVE_LOG,
    "log_injection": SinkKind.LOG,

    # Misc
    "code": SinkKind.EVAL,
    "config": SinkKind.SECRET_EXPOSURE,
    "cors": SinkKind.CORS,
    "ssl": SinkKind.WEAK_CRYPTO,
    "exception": SinkKind.ERROR_DISCLOSURE,
    "info_disclosure": SinkKind.DEBUG_INFO,
    "prototype_pollution": SinkKind.EVAL,  # Closest match
    "redos": SinkKind.REGEX,
}


def _get_sink_kind(spec_type: str) -> SinkKind:
    """Convert spec sink type string to SinkKind enum"""
    if spec_type in SINK_TYPE_MAP:
        return SINK_TYPE_MAP[spec_type]
    # Try direct conversion
    try:
        return SinkKind(spec_type)
    except ValueError:
        return SinkKind.SQL_QUERY  # Default fallback


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
            self._translate_top_level(child, program)

    def _translate_top_level(self, node: TSNode, program: Program) -> None:
        """Translate a top-level statement"""
        if node.type == "function_declaration":
            proc = self._translate_function(node)
            if proc:
                program.add_procedure(proc)

        elif node.type == "class_declaration":
            self._translate_class(node, program)

        elif node.type == "lexical_declaration" or node.type == "variable_declaration":
            # const/let/var declarations - check for function expressions
            self._translate_variable_declaration(node, program)

        elif node.type == "export_statement":
            # Handle exports
            for child in node.children:
                self._translate_top_level(child, program)

        elif node.type == "expression_statement":
            # Check for IIFE or function expressions
            for child in node.children:
                if child.type == "call_expression":
                    func = child.child_by_field_name("function")
                    if func and func.type in ("arrow_function", "function"):
                        proc = self._translate_function(func, name="anonymous")
                        if proc:
                            program.add_procedure(proc)

    def _translate_variable_declaration(self, node: TSNode, program: Program) -> None:
        """Translate variable declarations, extracting function expressions"""
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")

                if name_node and value_node:
                    var_name = self._get_text(name_node)
                    if value_node.type in ("arrow_function", "function"):
                        proc = self._translate_function(value_node, name=var_name)
                        if proc:
                            program.add_procedure(proc)

    def _translate_class(self, node: TSNode, program: Program) -> None:
        """Translate class definition"""
        name_node = node.child_by_field_name("name")
        class_name = self._get_text(name_node) if name_node else "UnknownClass"

        self._current_class = class_name

        # Find class body
        body_node = node.child_by_field_name("body")
        if body_node:
            for child in body_node.children:
                if child.type == "method_definition":
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

        return self._translate_function_body(node, proc)

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
        if body_node:
            if body_node.type == "statement_block":
                self._translate_block(body_node)
            else:
                # Arrow function with expression body: () => expr
                exp = self._translate_expression(body_node)
                self._add_instr(Return(loc=self._get_location(body_node), value=exp))

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

    def _translate_statement(self, node: TSNode) -> None:
        """Translate a single statement"""
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
            if child.type == "call_expression":
                instrs = self._translate_call_expr(child)
                self._add_instrs(instrs)

            elif child.type == "assignment_expression":
                self._translate_assignment(child)

            elif child.type == "update_expression":
                self._translate_update(child)

            elif child.type == "augmented_assignment_expression":
                self._translate_augmented_assignment(child)

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

                if value_node:
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

        # Check if this is a sink
        if spec and spec.is_taint_sink():
            kind = _get_sink_kind(spec.is_sink)
            for arg_idx in spec.sink_args:
                if arg_idx < len(args):
                    arg_exp = self._translate_expression(args[arg_idx])
                    instrs.append(TaintSink(
                        loc=loc,
                        exp=arg_exp,
                        kind=kind,
                        description=spec.description
                    ))

        return instrs

    def _translate_call_expr(self, call_node: TSNode) -> List[Instr]:
        """Translate standalone call: func(args)

        Handles chained method calls like: query(...).then(...).catch(...)
        Each call in the chain is translated separately.
        """
        instrs = []
        loc = self._get_location(call_node)

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

                # Now translate this call with just the method name
                method_name = self._get_text(prop_node) if prop_node else ""
                func_name = method_name
            else:
                # Regular method call (e.g., obj.method())
                func_name = self._get_call_name(call_node)
        else:
            # Simple function call
            func_name = self._get_call_name(call_node)

        args = self._get_call_args(call_node)
        args_exp = [(self._translate_expression(a), Typ.unknown_type()) for a in args]

        # Build Call instruction
        call_instr = Call(
            loc=loc,
            ret=None,
            func=ExpConst.string(func_name),
            args=args_exp
        )
        instrs.append(call_instr)

        # Check if this is a sink (with suffix matching for chained calls)
        spec = self.specs.get(func_name)
        if not spec and '.' in func_name:
            # Try suffix matching: models.sequelize.query -> sequelize.query
            parts = func_name.split('.')
            for i in range(1, len(parts)):
                suffix = '.'.join(parts[i:])
                spec = self.specs.get(suffix)
                if spec:
                    break

        if spec and spec.is_taint_sink():
            kind = _get_sink_kind(spec.is_sink)
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
                            exp = self._translate_expression(body_node)
                            self._add_instr(Return(loc=self._get_location(body_node), value=exp))
                    return  # Don't add another return statement
                else:
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

        elif node.type == "subscript_expression":
            obj = node.child_by_field_name("object")
            index = node.child_by_field_name("index")
            obj_exp = self._translate_expression(obj)
            index_exp = self._translate_expression(index)
            return ExpIndex(obj_exp, index_exp)

        elif node.type == "call_expression":
            func = node.child_by_field_name("function")
            func_exp = self._translate_expression(func)
            args = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ","):
                        args.append(self._translate_expression(child))
            return ExpCall(func_exp, args)

        elif node.type == "parenthesized_expression":
            for child in node.children:
                if child.type not in ("(", ")"):
                    return self._translate_expression(child)

        elif node.type == "array":
            elements = []
            for child in node.children:
                if child.type not in ("[", "]", ","):
                    elements.append(self._translate_expression(child))
            return elements[0] if elements else ExpConst.null()

        elif node.type == "object":
            return ExpConst.null()

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
            arg = node.child_by_field_name("argument")
            return self._translate_expression(arg)

        elif node.type == "new_expression":
            cons = node.child_by_field_name("constructor")
            cons_name = self._get_text(cons) if cons else "Object"
            args = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ","):
                        args.append(self._translate_expression(child))
            return ExpCall(ExpConst.string(f"new {cons_name}"), args)

        # Default
        text = self._get_text(node)
        return ExpVar(PVar(text)) if text else ExpConst.null()

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

    def _get_call_name(self, call_node: TSNode) -> str:
        """Get full name of function being called"""
        func = call_node.child_by_field_name("function")
        if func:
            return self._get_text(func)
        return ""

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

        # Subscript expression - check the object being accessed
        elif node_type == "subscript_expression":
            obj = node.child_by_field_name("object")
            if obj:
                return self._check_expression_for_taint_source(obj, target, loc)

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
