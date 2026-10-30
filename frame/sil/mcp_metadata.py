"""MCP tool metadata: what a server tells the model about its tools (names, descriptions,
parameter descriptions), read from the syntax tree of a file whose packs say how the server
library registers tools (`[[tool_registration]]`).

A client shows the user a tool's description and passes it to the model verbatim, so text there
is instructions to the model. Two properties are checked, both decided by the code, not by the
wording (Frame does not guess at whether a sentence is malicious):

* hidden characters: Unicode tag characters (U+E0000-U+E007F, which spell out ASCII the user
  never sees), bidirectional overrides and isolates, zero-width spaces and word joiners, a byte
  order mark. Text a person approves should read the same to the model; these make it not.
  Escapes count (`"\\U000e0049"`, `"\\u{E0049}"`), and tag characters are decoded in the
  finding so the hidden text can be read.
* a description computed at run time: from the environment, a file, the network, a call. The
  server can then tell the model something else than what was reviewed and approved (a "rug
  pull"). A literal, literals joined, or a module constant bound once to a literal is fixed.

Which calls register a tool, and where their name, description and handler are, is pack data
(`[[tool_registration]]` in `python/mcp-servers` and `javascript/mcp-servers`): FastMCP's
`@x.tool(...)`, `Tool(name=..., description=...)`, the TypeScript SDK's `tool`/`registerTool`,
fastmcp's `addTool`. Strings in the registration's arguments count; a handler's body does not.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Dict, Iterator, List, Optional, Tuple

HIDDEN = "hidden"
DYNAMIC = "dynamic"

_INVISIBLE = {0x200B: "zero-width space", 0x2060: "word joiner", 0x2061: "invisible function application",
              0x2062: "invisible times", 0x2063: "invisible separator", 0x2064: "invisible plus",
              0xFEFF: "zero-width no-break space"}
_BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


@dataclass
class Finding:
    kind: str           # HIDDEN or DYNAMIC
    tool: str
    line: int
    column: int
    description: str


def hidden_characters(text: str) -> Tuple[Dict[str, int], str]:
    """({kind: count}, the ASCII the tag characters spell) for the invisible characters in text."""
    counts: Dict[str, int] = {}
    spelled = []
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            counts["Unicode tag character"] = counts.get("Unicode tag character", 0) + 1
            if 0x20 <= cp - 0xE0000 < 0x7F:
                spelled.append(chr(cp - 0xE0000))
        elif cp in _BIDI:
            counts["bidirectional control"] = counts.get("bidirectional control", 0) + 1
        elif cp in _INVISIBLE:
            counts[_INVISIBLE[cp]] = counts.get(_INVISIBLE[cp], 0) + 1
    return counts, "".join(spelled)


# -- string values ---------------------------------------------------------------------------

def _text(node) -> str:
    return node.text.decode("utf-8", "replace")


def _python_string(node) -> Optional[str]:
    """The value of a Python string literal (escapes decoded); None for an f-string."""
    if node.type == "concatenated_string":
        parts = [_python_string(c) for c in node.named_children]
        return None if any(p is None for p in parts) else "".join(parts)  # type: ignore[arg-type]
    if node.type != "string" or any(c.type == "interpolation" for c in node.named_children):
        return None
    try:
        value = ast.literal_eval(_text(node))
    except (ValueError, SyntaxError):
        return None
    return value if isinstance(value, str) else None


_JS_ESCAPE = re.compile(r"\\(u\{[0-9A-Fa-f]+\}|u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}|.)", re.DOTALL)


def _js_unescape(body: str) -> str:
    def one(m):
        e = m.group(1)
        if e.startswith("u{"):
            return chr(int(e[2:-1], 16))
        if e[0] in "ux" and len(e) > 1:
            return chr(int(e[1:], 16))
        return {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(e, e)
    out = _JS_ESCAPE.sub(one, body)
    # a surrogate pair written as two \u escapes is one character
    return out.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def _js_string(node) -> Optional[str]:
    if node.type == "string":
        return _js_unescape(_text(node)[1:-1])
    if node.type == "template_string" and not any(c.type == "template_substitution" for c in node.named_children):
        return _js_unescape(_text(node)[1:-1])
    return None


def _strings(node, is_string, skip=()) -> Iterator[Tuple[object, str]]:
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in skip:
            continue
        value = is_string(n)
        if value is not None:
            yield n, value
            continue
        stack.extend(n.named_children)


# -- constant expressions ---------------------------------------------------------------------

def _module_bindings(root, assign_types: Tuple[str, ...]) -> Dict[str, List[object]]:
    """name -> the values bound to it at module level."""
    out: Dict[str, List[object]] = {}
    for stmt in root.named_children:
        nodes = [stmt] + list(stmt.named_children)
        for n in nodes:
            if n.type in assign_types:
                left = n.child_by_field_name("left") or n.child_by_field_name("name")
                right = n.child_by_field_name("right") or n.child_by_field_name("value")
                if left is not None and right is not None and left.type == "identifier":
                    out.setdefault(_text(left), []).append(right)
    return out


def _constant(node, is_string, bindings, depth: int = 0) -> bool:
    if node is None or depth > 8:
        return False
    if is_string(node) is not None:
        return True
    t = node.type
    if t in ("parenthesized_expression",):
        return all(_constant(c, is_string, bindings, depth + 1) for c in node.named_children)
    if t in ("binary_operator", "binary_expression"):
        op = node.child_by_field_name("operator")
        return op is not None and _text(op) == "+" and all(
            _constant(node.child_by_field_name(k), is_string, bindings, depth + 1) for k in ("left", "right"))
    if t == "string":                                       # a Python f-string: constant substitutions only
        return all(_constant(i.named_children[0] if i.named_children else None, is_string, bindings, depth + 1)
                   for i in node.named_children if i.type == "interpolation")
    if t == "template_string":
        return all(_constant(s.named_children[0] if s.named_children else None, is_string, bindings, depth + 1)
                   for s in node.named_children if s.type == "template_substitution")
    if t == "identifier":
        bound = bindings.get(_text(node), [])
        return len(bound) == 1 and _constant(bound[0], is_string, bindings, depth + 1)
    if t in ("integer", "float", "number", "true", "false", "none", "null"):
        return True
    return False


def _dynamic(tool: str, node, what: str) -> Finding:
    shown = _text(node).replace("\n", " ")
    shown = shown if len(shown) <= 60 else shown[:57] + "..."
    return Finding(DYNAMIC, tool, node.start_point[0] + 1, node.start_point[1],
                   f"MCP tool '{tool}' {what} is computed at run time ({shown}): the server can tell the model "
                   "something other than what was reviewed and approved")


def _hidden(tool: str, node, value: str) -> Optional[Finding]:
    counts, spelled = hidden_characters(value)
    if not counts:
        return None
    what = ", ".join(f"{n} {k}{'s' if n > 1 else ''}" for k, n in sorted(counts.items()))
    if spelled.strip():
        s = spelled.strip()
        what += f" (spelling \"{s if len(s) <= 80 else s[:77] + '...'}\")"
    return Finding(HIDDEN, tool, node.start_point[0] + 1, node.start_point[1],
                   f"Hidden characters in MCP tool '{tool}' metadata: {what}. The model reads what the user "
                   "approving the tool cannot see")


# -- Python -----------------------------------------------------------------------------------

def _decorator_form(dec, regs):
    """(registration, call node or None, callee node) when `dec` registers a tool."""
    call = dec.named_children[0] if dec.named_children else None
    target = call.child_by_field_name("function") if call is not None and call.type == "call" else call
    if target is None:
        return None
    reg = next((r for r in regs if r.decorator and any(fnmatchcase(_text(target), g) for g in r.decorator)), None)
    return (reg, call if call.type == "call" else None) if reg is not None else None


def _kwargs(args) -> Dict[str, object]:
    return {_text(k.child_by_field_name("name")): k.child_by_field_name("value")
            for k in (args.named_children if args is not None else [])
            if k.type == "keyword_argument" and k.child_by_field_name("name") is not None}


def scan_python(root, regs) -> List[Finding]:
    """`regs`: the `[[tool_registration]]` entries of the packs applied to the file."""
    bindings = _module_bindings(root, ("assignment",))
    out: List[Finding] = []
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.named_children)
        if n.type == "decorated_definition":
            fn = n.child_by_field_name("definition")
            for dec in (c for c in n.named_children if c.type == "decorator"):
                form = _decorator_form(dec, regs)
                if form is None or fn is None:
                    continue
                reg, call = form
                name_node = fn.child_by_field_name("name")
                tool = _text(name_node) if name_node is not None else "?"
                args = call.child_by_field_name("arguments") if call is not None else None
                kws = _kwargs(args)
                if kws.get(reg.name_kwarg) is not None and _python_string(kws[reg.name_kwarg]) is not None:
                    tool = _python_string(kws[reg.name_kwarg]) or tool
                for key in reg.text_kwargs:
                    if kws.get(key) is not None and not _constant(kws[key], _python_string, bindings):
                        out.append(_dynamic(tool, kws[key], key))
                regions = [args] if args is not None else []
                if reg.signature:
                    regions += [r for r in (fn.child_by_field_name("parameters"), fn.child_by_field_name("return_type"))
                                if r is not None]
                body = fn.child_by_field_name("body")
                if reg.docstring and body is not None and body.named_children \
                        and body.named_children[0].type == "expression_statement":
                    first = body.named_children[0].named_children
                    if first and first[0].type == "string":
                        regions.append(first[0])
                for region in regions:
                    for s, value in _strings(region, _python_string):
                        f = _hidden(tool, s, value)
                        if f:
                            out.append(f)
        elif n.type == "call":
            fn = n.child_by_field_name("function")
            last = _text(fn).rsplit(".", 1)[-1] if fn is not None else ""
            args = n.child_by_field_name("arguments")
            kws = _kwargs(args)
            reg = next((r for r in regs if last in r.call and any(k in kws for k in r.when_kwargs)), None)
            if reg is None:
                continue
            tool = (_python_string(kws[reg.name_kwarg]) if kws.get(reg.name_kwarg) is not None else None) or "?"
            for key in reg.text_kwargs:
                if kws.get(key) is not None and not _constant(kws[key], _python_string, bindings):
                    out.append(_dynamic(tool, kws[key], key))
            for s, value in _strings(args, _python_string):
                f = _hidden(tool, s, value)
                if f:
                    out.append(f)
    return _unique(out)


# -- JavaScript / TypeScript ------------------------------------------------------------------

_FUNCTIONS = ("arrow_function", "function_expression", "function", "function_declaration", "method_definition")


def _js_env(node) -> bool:
    return node.type == "member_expression" and _text(node).startswith("process.env")


def _js_registration(n, regs):
    """(registration, argument nodes, config fields) when call `n` registers a tool."""
    if n.type != "call_expression":
        return None
    fn = n.child_by_field_name("function")
    prop = fn.child_by_field_name("property") if fn is not None and fn.type == "member_expression" else None
    method = _text(prop) if prop is not None else ""
    args_node = n.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node is not None else []
    for reg in regs:
        if method not in reg.method or not args:
            continue
        config = None
        if reg.config_arg is not None:
            if len(args) <= reg.config_arg or args[reg.config_arg].type != "object":
                continue
            config = _object_fields(args[reg.config_arg])
        if reg.name_arg is not None and (len(args) <= reg.name_arg or _js_string(args[reg.name_arg]) is None):
            continue
        if reg.handler_arg is not None and len(args) < 2:
            continue                                       # a name and nothing to run
        return reg, args, config or {}
    return None


def _js_tool_name(reg, args, config) -> Optional[str]:
    if reg.name_arg is not None:
        return _js_string(args[reg.name_arg])
    value = config.get(reg.name_field)
    return _js_string(value) if value is not None else None


def scan_javascript(root, regs) -> List[Finding]:
    """`regs`: the `[[tool_registration]]` entries of the packs applied to the file."""
    bindings = _module_bindings(root, ("variable_declarator",))
    out: List[Finding] = []
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.named_children)
        form = _js_registration(n, regs)
        if form is None:
            continue
        reg, args, config = form
        tool = _js_tool_name(reg, args, config) or "?"
        described: List[Tuple[str, object]] = [(k, config[k]) for k in reg.text_fields if config.get(k) is not None]
        d = reg.description_arg
        if d is not None and len(args) > d + 1:            # the last argument is the handler
            second = args[d]
            if _js_string(second) is not None or second.type in ("template_string", "binary_expression") \
                    or _js_env(second) or (second.type == "identifier"
                                           and any(_js_string(b) is not None or b.type == "template_string"
                                                   for b in bindings.get(_text(second), []))):
                described.append(("description", second))
        for key, value in described:
            if not _constant(value, _js_string, bindings):
                out.append(_dynamic(tool, value, key))
        for s, value in _strings(n.child_by_field_name("arguments"), _js_string, skip=_FUNCTIONS):
            f = _hidden(tool, s, value)
            if f:
                out.append(f)
    return _unique(out)


def _object_fields(obj) -> Dict[str, object]:
    out = {}
    for pair in obj.named_children:
        if pair.type == "pair":
            key, value = pair.child_by_field_name("key"), pair.child_by_field_name("value")
            if key is not None and value is not None:
                k = _js_string(key) if key.type == "string" else _text(key)
                out[k] = value
    return out


def _unique(found: List[Finding]) -> List[Finding]:
    seen, out = set(), []
    for f in sorted(found, key=lambda f: (f.line, f.column, f.kind)):
        if (f.kind, f.line, f.column) not in seen:
            seen.add((f.kind, f.line, f.column))
            out.append(f)
    return out




# -- what each tool can do (frame inventory) ----------------------------------------------------

# sink kinds -> the capability a tool has when its handler reaches one, whatever the arguments
CAPABILITIES = {
    "shell": "shell", "command": "shell", "shell_command": "shell",
    "eval": "code execution", "code": "code execution",
    "filesystem": "files", "path": "files",
    "ssrf": "network",
    "sql": "database", "nosql": "database", "orm": "database",
    "deserialize": "deserialization", "deserialize_unsafe": "deserialization",
}


def tool_names(root, language: str, regs) -> Dict[int, str]:
    """Line of each tool handler -> the tool's name (Python: the decorated function's `def`
    line; JS: the handler function's first line)."""
    out: Dict[int, str] = {}
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.named_children)
        if language == "python" and n.type == "decorated_definition":
            fn = n.child_by_field_name("definition")
            for dec in (c for c in n.named_children if c.type == "decorator"):
                form = _decorator_form(dec, regs)
                if fn is None or form is None:
                    continue
                reg, call = form
                name = _text(fn.child_by_field_name("name"))
                kws = _kwargs(call.child_by_field_name("arguments") if call is not None else None)
                if reg.name_kwarg and kws.get(reg.name_kwarg) is not None:
                    name = _python_string(kws[reg.name_kwarg]) or name
                out[fn.start_point[0] + 1] = name
        elif language != "python":
            form = _js_registration(n, regs)
            if form is None:
                continue
            reg, args, config = form
            handler = config.get(reg.handler_field) if reg.handler_field else \
                (args[reg.handler_arg] if reg.handler_arg is not None and -len(args) <= reg.handler_arg < len(args)
                 else None)
            name = _js_tool_name(reg, args, config)
            if handler is not None and name and handler.type in _FUNCTIONS:
                out[handler.start_point[0] + 1] = name
    return out


def registrations(program) -> list:
    """The `[[tool_registration]]` entries of the packs applied to `program`."""
    return [r for p in getattr(program, "active_packs", ()) for r in getattr(p, "tool_registrations", ())]


def tool_entry_kinds(program) -> set:
    """`Procedure.entry_kinds` values that make a procedure a tool handler."""
    return {f"{p.name}:{r.entrypoint}" for p in getattr(program, "active_packs", ())
            for r in getattr(p, "tool_registrations", ()) if r.entrypoint}


def capabilities(program, proc) -> List[str]:
    """What a handler can do: the sinks it and the file's procedures it calls reach."""
    from frame.sil.instructions import Call, TaintSink
    seen, todo, found = set(), [proc], set()
    while todo:
        p = todo.pop()
        if p.name in seen:
            continue
        seen.add(p.name)
        for node in p.nodes.values():
            for instr in node.instrs:
                kind = None
                if isinstance(instr, TaintSink):
                    kind = instr.kind.value
                elif isinstance(instr, Call):
                    spec = program.spec_for_call(instr)
                    kind = getattr(spec, "is_sink", None) if spec is not None else None
                    callee = str(getattr(instr.func, "value", instr.func)).strip('"')
                    for name in (callee, callee.rsplit(".", 1)[-1]):
                        if name in program.procedures and name not in seen:
                            todo.append(program.procedures[name])
                if kind in CAPABILITIES:
                    found.add(CAPABILITIES[kind])
    return sorted(found)


__all__ = ["Finding", "HIDDEN", "DYNAMIC", "hidden_characters", "scan_python", "scan_javascript", "tool_names",
           "registrations", "tool_entry_kinds", "capabilities", "CAPABILITIES"]
