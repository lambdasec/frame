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
        self._node_counter = 0
        self._ident_counter = 0

        # Parse source code
        tree = self.parser.parse(bytes(source_code, "utf8"))

        # Create program with library specs
        program = Program(library_specs=self.specs.copy())
        program.source_files.append(filename)

        # Walk top-level definitions
        self._translate_module(tree.root_node, program)

        # Whole-file ReDoS pass (covers module-level regex constants too).
        self._scan_redos(tree.root_node, program)
        # Whole-file prototype-pollution pass.
        self._scan_proto_pollution(tree.root_node, program)

        return program

    # Every function-like node becomes its own procedure -- including callbacks
    # and route handlers like `app.post(path, (req,res) => {...})`, which are
    # the dominant entry points in real Node.js/Express code.
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
                    # overwriting the handler that holds the sink. Disambiguate.
                    if program.has_procedure(name):
                        name = f"{name}_{cur.id}"
                    proc = self._translate_function(cur, name=name)
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

        # Treat the function's parameters as untrusted input (pure-SL recall
        # lever for real-world JS where the attack surface is exported APIs).
        if self.taint_function_params:
            own = {str(param) for param, _ in proc.params}
            for param, _ in proc.params:
                self._add_instr(TaintSource(
                    loc=proc.loc, var=param,
                    kind=TaintKind.USER_INPUT,
                    description="function parameter (untrusted input)"))

            # Closure capture: a nested function (callback, Promise executor,
            # ...) sees its enclosing functions' parameters as free variables.
            # When those params are untrusted, the capture carries the taint --
            # e.g. promistify(cmd){ new Promise((res, rej) => exec(cmd)) }. Taint
            # any enclosing param referenced here that this function doesn't
            # shadow with its own parameter.
            enclosing = self._enclosing_param_names(node) - own
            if enclosing and body_node is not None:
                referenced = self._referenced_identifiers(body_node)
                for nm in sorted(enclosing & referenced):
                    self._add_instr(TaintSource(
                        loc=proc.loc, var=PVar(nm),
                        kind=TaintKind.USER_INPUT,
                        description="captured untrusted variable (closure)"))
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
                quantified = nxt in '*+' or nxt == '{'
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
                        # (\d+)*) or an alternation (overlap-prone under a
                        # quantifier, e.g. (a|aa)+). A plain (abc)+ is neither.
                        if '|' in body or self._has_unbounded_quant(body):
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
            key_like = (
                index.type in ("subscript_expression", "member_expression")
                or key_txt in loop_vars
                or key_txt in params
                or key_txt in self._enclosing_path_key_vars(n)
            )
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

            elif child.type == "new_expression":
                # A bare `new Function(userCode)` statement is a sink; translating
                # the expression emits the TaintSink as a side effect.
                self._translate_expression(child)

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

        # Assignment to a sink property (e.g. `el.innerHTML = x`, `script.src = x`)
        # flows the right-hand value into a taint sink. We sink on the assigned
        # target, which carries the right-hand side's taint via the source check
        # above (inline sources) or assignment propagation (already-tainted
        # vars). The taint engine then reports it only when that value is
        # actually attacker-tainted; a constant right-hand side stays untainted.
        sink_spec = self._assignment_sink_spec(left)
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
            if spec and spec.is_taint_sink():
                return spec
        return None

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
            elements = []
            for child in node.children:
                if child.type not in ("[", "]", ","):
                    elements.append(self._translate_expression(child))
            return elements[0] if elements else ExpConst.null()

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
            # A constructor can itself be a sink (e.g. new Function(userCode) is
            # code injection). Emit the TaintSink as a side effect so it fires in
            # any context (var initializer, argument, etc.).
            spec = self.specs.get(cons_name) or self.specs.get(f"new {cons_name}")
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
