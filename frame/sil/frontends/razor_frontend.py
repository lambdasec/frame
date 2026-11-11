"""ASP.NET Razor pages (`.cshtml`, `.razor`) scanned through the C# engine.

A Razor file interleaves HTML markup with C#: code blocks `@{ ... }`, member blocks
`@functions { ... }` / `@code { ... }`, implicit expressions `@Model.Name`, explicit expressions
`@( ... )`, and directives `@model` / `@inject` / `@using`. Razor itself compiles a page into a
generated C# class with an `ExecuteAsync` method whose body is the code blocks and `Write(...)`
calls; `@expr` is HTML-encoded, `@Html.Raw(expr)` is written raw (an XSS sink the C# specs already
know). This frontend transpiles the Razor to that shape and hands it to `CSharpFrontend`, then maps
the findings' line numbers back to the `.cshtml` through a per-line map. Nothing is executed.

Control flow written in markup (`@if (...) { ... } else { ... }`, `@foreach`, `@for`, `@while`,
`@switch`, `@using (...)`, `@lock`, `do`/`try`) is C# whose blocks hold markup again: it is emitted
as the statement, so a loop variable holds the collection's elements and a guard guards the markup
inside it. Inside code (`@{ ... }` and those blocks) a statement that starts with a tag or `@`
(`<p>@Html.Raw(x)</p>`, `@Html.Raw(x)`, `@: text`) is markup: its expressions become `Write(...)`
calls where they are written (they used to be emitted as C# text, which does not parse, and were lost).

The transpile is deliberately simple and sound: it never invents a source or sink, only moves the
C# the page contains into a method/class the analysis can read. Brace and parenthesis matching skips
string and character literals but does not parse C#, so an exotic block may extract imprecisely; that
can only make the page look like different C#, never add a finding the page's own code does not
express.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from frame.sil.procedure import Program

# `@model T`, `@inject T name`, `@using X`, `@functions {`, `@code {`, `@{`
_MODEL = re.compile(r"^\s*@model\s+(?P<type>[\w.<>,\[\] ]+?)\s*$")
_INJECT = re.compile(r"^\s*@inject\s+(?P<type>[\w.<>,\[\] ]+?)\s+(?P<name>\w+)\s*$")
_USING = re.compile(r"^\s*@using\s+(?P<ns>[\w.=\s]+?)\s*$")
_OTHER_DIRECTIVE = re.compile(r"^\s*@(page|namespace|implements|inherits|attribute|layout|rendermode|typeparam|preservewhitespace|addTagHelper|removeTagHelper|tagHelperPrefix)\b")


def _balance(text: str, depth: int, open_ch: str, close_ch: str) -> int:
    for ch in text:
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
    return depth


_CONTROL = ("if", "foreach", "for", "while", "switch", "lock", "using", "do", "try")
_CONTINUATIONS = ("else", "catch", "finally")
_IDENT = re.compile(r"[A-Za-z_]\w*")


def _skip_literal(s: str, i: int, end: int) -> int:
    """Index past the string / character literal starting at s[i] (`"..."`, `@"..."`, `'c'`)."""
    if s[i] == "@" and s[i + 1:i + 2] == '"':          # verbatim: "" is a quote
        j = i + 2
        while j < end:
            if s[j] == '"':
                if s[j + 1:j + 2] == '"':
                    j += 2
                    continue
                return j + 1
            j += 1
        return end
    quote = s[i]
    j = i + 1
    while j < end and s[j] != quote and s[j] != "\n":
        j += 2 if s[j] == "\\" else 1
    return min(j + 1, end)


def _match(s: str, i: int, end: int, open_ch: str, close_ch: str) -> int:
    """Index of the bracket closing the one at s[i] (string and character literals skipped), or
    `end` when it is not closed."""
    depth = 0
    j = i
    while j < end:
        c = s[j]
        if c in "\"'" or (c == "@" and s[j + 1:j + 2] == '"'):
            j = _skip_literal(s, j, end)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return end


def _implicit_end(s: str, i: int, end: int) -> int:
    """End of an implicit expression starting at the identifier at s[i]: `Model.Name`,
    `Html.Raw(x)`, `items[0].Name`, `await Html.PartialAsync("p")`."""
    m = _IDENT.match(s, i, end)
    if m is None:
        return i
    j = m.end()
    if m.group() == "await" and j < end and s[j] == " ":
        k = j
        while k < end and s[k] == " ":
            k += 1
        if _IDENT.match(s, k, end):
            return _implicit_end(s, k, end)
    while j < end:
        if s[j] in "([":
            close = _match(s, j, end, s[j], ")" if s[j] == "(" else "]")
            if close >= end:
                return j
            j = close + 1
        elif s[j] == "." and j + 1 < end and _IDENT.match(s, j + 1, end):
            j = _IDENT.match(s, j + 1, end).end()
        else:
            break
    return j


class RazorFrontend:
    """Transpile a Razor page to C# and analyse it with CSharpFrontend."""

    PAGE_CLASS = "__FrameRazorPage"

    def translate(self, source_code: str, filename: str = "<unknown>") -> Program:
        csharp, line_map = self._to_csharp(source_code)
        from frame.sil.frontends.csharp_frontend import CSharpFrontend
        program = CSharpFrontend().translate(csharp, filename)
        self._remap_lines(program, line_map, filename)
        return program

    def _consume_block(self, lines: List[str], i: int, after: str) -> Tuple[List[Tuple[str, int]], int]:
        """A `@{` / `@functions {` block from just past its opening `{` (`after` is the rest of that
        line): its inner lines with their 1-based original line numbers, and the index past the
        block. The matching closing `}` is dropped so it does not close the synthetic method/class."""
        start = i + 1
        collected: List[Tuple[str, int]] = [(after, start)]
        depth = 1 + _balance(after, 0, "{", "}")
        i += 1
        n = len(lines)
        while i < n and depth > 0:
            depth = _balance(lines[i], depth, "{", "}")
            collected.append((lines[i], i + 1))
            i += 1
        if depth <= 0 and collected:                   # drop the delimiter `}` on the closing line
            text, ln = collected[-1]
            cut = text.rfind("}")
            if cut >= 0:
                collected[-1] = (text[:cut] + text[cut + 1:], ln)
        return collected, i

    def _to_csharp(self, source: str) -> Tuple[str, List[int]]:
        """Return (C# text, line_map) where line_map[i] is the original 1-based Razor line the
        i-th (0-based) C# line came from, or 0 for a synthetic line."""
        lines = source.splitlines()
        usings: List[Tuple[str, int]] = []
        members: List[Tuple[str, int]] = []           # @functions / @code, class-level
        model_type = "dynamic"
        injects: List[Tuple[str, str, int]] = []
        markup: List[str] = [""] * len(lines)         # the lines that are page content (not directives)

        i = 0
        n = len(lines)
        while i < n:
            ln = i + 1
            text = lines[i]
            m = _MODEL.match(text)
            if m:
                model_type = m.group("type").strip()
                i += 1
                continue
            m = _INJECT.match(text)
            if m:
                injects.append((m.group("type").strip(), m.group("name"), ln))
                i += 1
                continue
            m = _USING.match(text)
            if m:
                usings.append((m.group("ns").strip(), ln))
                i += 1
                continue
            if _OTHER_DIRECTIVE.match(text):
                i += 1
                continue
            block = re.match(r"^\s*@(functions|code)\s*\{", text)
            if block:                                  # a class-level member block
                collected, i = self._consume_block(lines, i, text[block.end():])
                members.extend(collected)
                continue
            markup[i] = text                           # the page itself: read by the scanner below
            i += 1
        body = _Transpiler("\n".join(markup)).markup()

        out: List[str] = []
        lmap: List[int] = []

        def emit(s: str, orig: int) -> None:
            out.append(s)
            lmap.append(orig)

        for ns, ln in usings:
            emit(f"using {ns};", ln)
        emit(f"namespace FrameRazor {{ public class {self.PAGE_CLASS} "
             f": global::Microsoft.AspNetCore.Mvc.Razor.RazorPage {{", 0)
        # the view intrinsics a Razor page reads, with their framework types, so the C# engine
        # resolves `Request.Query`, `Context.Request`, `Html.Raw`, `User` ... the way it does in
        # a controller (learn.microsoft.com/aspnet/core/mvc/views/razor).
        for decl in ("Microsoft.AspNetCore.Http.HttpContext Context",
                     "Microsoft.AspNetCore.Http.HttpRequest Request",
                     "Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper Html",
                     "Microsoft.AspNetCore.Mvc.IUrlHelper Url",
                     "System.Security.Claims.ClaimsPrincipal User",
                     "Microsoft.AspNetCore.Routing.RouteData RouteData"):
            emit(f"public {decl};", 0)
        emit(f"public {model_type} Model;", 0)
        for typ, name, ln in injects:
            emit(f"public {typ} {name};", ln)
        for mtext, ln in members:
            emit(mtext, ln)
        emit("public async System.Threading.Tasks.Task ExecuteAsync() {", 0)
        for btext, ln in body:
            emit(btext, ln)
        emit("}", 0)
        emit("}}", 0)
        return "\n".join(out), lmap

    def _remap_lines(self, program: Program, line_map: List[int], filename: str) -> None:
        """Map each instruction's synthetic C# line back to its Razor line. Location is frozen, so
        the line is set through object.__setattr__; only locations in this file and in range are
        touched (the shared `unknown` singleton and cross-file locs are left alone)."""
        seen = set()

        def fix(loc) -> None:
            if loc is None or id(loc) in seen:
                return
            seen.add(id(loc))
            line = getattr(loc, "line", None)
            if getattr(loc, "file", None) == filename and isinstance(line, int) and 1 <= line <= len(line_map):
                object.__setattr__(loc, "line", line_map[line - 1] or 1)
        for proc in program.procedures.values():
            for node in proc.nodes.values():
                for instr in node.instrs:
                    fix(getattr(instr, "loc", None))
                    fix(getattr(getattr(instr, "exp", None), "loc", None))


class _Transpiler:
    """The page content (markup with C# in it) as the statements of the generated method: code as
    written, control flow as its statement with markup inside it again, and `Write(expr)` for each
    expression the markup prints. Each piece keeps the 1-based line it came from."""

    def __init__(self, text: str):
        self.s = text
        self.out: List[Tuple[str, int]] = []
        self._starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]

    def line(self, i: int) -> int:
        import bisect
        return bisect.bisect_right(self._starts, i)

    def emit(self, text: str, at: int) -> None:
        """C# text that starts at index `at`, one piece per source line it spans."""
        first = self.line(at)
        for k, part in enumerate(text.split("\n")):
            if part.strip():
                self.out.append((part, first + k))

    def markup(self) -> List[Tuple[str, int]]:
        self._markup(0, len(self.s))
        lines = {ln for _, ln in self.out}
        for ln in range(1, len(self._starts) + 1):     # keep every line in the map (markup has no code)
            if ln not in lines:
                self.out.append(("", ln))
        self.out.sort(key=lambda t: t[1])
        return self.out

    def _markup(self, i: int, end: int) -> None:
        s = self.s
        while i < end:
            at = s.find("@", i, end)
            if at < 0:
                return
            i = self._transition(at, end)

    def _transition(self, at: int, end: int) -> int:
        """One `@...` construct starting at `at` (in markup): what it runs or prints; the index after it."""
        s = self.s
        nxt = s[at + 1:at + 2]
        if nxt == "@":                                 # `@@`: a literal @
            return at + 2
        if at > 0 and (s[at - 1].isalnum() or s[at - 1] in "._-"):
            return at + 1                              # `user@example.com`: text
        if nxt == "*":                                 # `@* comment *@`
            close = s.find("*@", at + 2, end)
            return end if close < 0 else close + 2
        if nxt == "{":
            close = _match(s, at + 1, end, "{", "}")
            self._code(at + 2, close)
            return min(close + 1, end)
        if nxt == "(":
            close = _match(s, at + 1, end, "(", ")")
            self.emit(f"Write({s[at + 2:close]});", at + 2)
            return min(close + 1, end)
        if nxt == ":":                                 # `@: text` (in code): the rest of the line is markup
            stop = s.find("\n", at, end)
            stop = end if stop < 0 else stop
            self._markup(at + 2, stop)
            return stop
        m = _IDENT.match(s, at + 1, end)
        if m is None:
            return at + 1
        if m.group() in _CONTROL:
            return self._control(at + 1, end)
        if m.group() == "section":                     # `@section Scripts { ...markup... }`
            brace = s.find("{", m.end(), end)
            if brace >= 0 and s[m.end():brace].strip().replace("_", "").isalnum():
                close = _match(s, brace, end, "{", "}")
                self._markup(brace + 1, close)
                return min(close + 1, end)
        stop = _implicit_end(s, at + 1, end)
        self.emit(f"Write({s[at + 1:stop]});", at + 1)
        return stop

    def _control(self, k: int, end: int) -> int:
        """`if (c) { ... } else { ... }`, `foreach (...) { ... }`, `do { ... } while (c);`: the statement,
        with its blocks read as code (holding markup)."""
        s = self.s
        while True:
            m = _IDENT.match(s, k, end)
            word = m.group() if m else ""
            j = m.end() if m else k
            while j < end and s[j].isspace():
                j += 1
            if word == "else" and _IDENT.match(s, j, end) and _IDENT.match(s, j, end).group() == "if":
                j = _IDENT.match(s, j, end).end()
                while j < end and s[j].isspace():
                    j += 1
            if j < end and s[j] == "(":                # the statement's header
                close = _match(s, j, end, "(", ")")
                j = min(close + 1, end)
                while j < end and s[j].isspace():
                    j += 1
            header = s[k:j].strip()
            if j < end and s[j] == ";":                # `while (c);` ending a do
                self.emit(header + ";", k)
                return j + 1
            if j >= end or s[j] != "{":
                self.emit(header + " { }", k)          # no block: nothing of the page inside it
                return j
            close = _match(s, j, end, "{", "}")
            self.emit(header + " {", k)
            self._code(j + 1, close)
            self.emit("}", min(close, end - 1) if end else 0)
            k = min(close + 1, end)
            n = k
            while n < end and s[n].isspace():
                n += 1
            m = _IDENT.match(s, n, end)
            nxt_word = m.group() if m else ""
            if nxt_word in _CONTINUATIONS or (word == "do" and nxt_word == "while"):
                k = n
                continue
            return k

    def _code(self, start: int, end: int) -> None:
        """C# with markup statements in it: code is emitted as written; a statement that starts with
        a tag, `@` or `@:` is markup (its expressions printed where they are)."""
        s = self.s
        i = start
        chunk = start                                  # start of the code not yet emitted
        at_stmt = True
        while i < end:
            c = s[i]
            if c.isspace():
                i += 1
                continue
            if at_stmt and (c == "@" or (c == "<" and i + 1 < end and (s[i + 1].isalpha() or s[i + 1] in "/!"))):
                if s[chunk:i].strip():
                    self.emit(s[chunk:i], chunk)
                if c == "@":
                    i = self._transition(i, end)
                else:                                  # a tag: markup to the end of its line or block
                    stop = s.find("\n", i, end)
                    stop = end if stop < 0 else stop
                    depth, k = 0, i
                    while k < stop:
                        if s[k] == "{":
                            depth += 1
                        elif s[k] == "}":
                            if depth == 0:
                                stop = k
                                break
                            depth -= 1
                        k += 1
                    self._markup(i, stop)
                    i = stop
                chunk = i
                at_stmt = True
                continue
            if c in "\"'" or (c == "@" and s[i + 1:i + 2] == '"'):
                i = _skip_literal(s, i, end)
                at_stmt = False
                continue
            if c == "/" and s[i + 1:i + 2] == "/":     # a line comment
                stop = s.find("\n", i, end)
                i = end if stop < 0 else stop
                continue
            at_stmt = c in ";{}:"
            i += 1
        if s[chunk:end].strip():
            self.emit(s[chunk:end], chunk)


__all__ = ["RazorFrontend"]
