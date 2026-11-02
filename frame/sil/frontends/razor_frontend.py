"""ASP.NET Razor pages (`.cshtml`, `.razor`) scanned through the C# engine.

A Razor file interleaves HTML markup with C#: code blocks `@{ ... }`, member blocks
`@functions { ... }` / `@code { ... }`, implicit expressions `@Model.Name`, explicit expressions
`@( ... )`, and directives `@model` / `@inject` / `@using`. Razor itself compiles a page into a
generated C# class with an `ExecuteAsync` method whose body is the code blocks and `Write(...)`
calls; `@expr` is HTML-encoded, `@Html.Raw(expr)` is written raw (an XSS sink the C# specs already
know). This frontend transpiles the Razor to that shape and hands it to `CSharpFrontend`, then maps
the findings' line numbers back to the `.cshtml` through a per-line map. Nothing is executed.

The transpile is deliberately simple and sound: it never invents a source or sink, only moves the
C# the page contains into a method/class the analysis can read. Brace matching is naive (it does
not track braces inside strings), so an exotic code block may extract imprecisely; that can only
make the page look like different C#, never add a finding the page's own code does not express.
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
# an implicit/explicit expression: @( ... ), or @Ident.chain(...) with balanced () / []
_EXPR = re.compile(r"@(\((?P<paren>)|(?P<name>[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*))")


def _balance(text: str, depth: int, open_ch: str, close_ch: str) -> int:
    for ch in text:
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
    return depth


def _match_paren(s: str, start: int) -> Optional[int]:
    """Index just past the `)` matching the `(` at `s[start]`, or None."""
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return None


def _expressions(line: str) -> List[str]:
    """The C# expressions `@...` written in a markup line (`@Model.Name`, `@(a + b)`,
    `@Html.Raw(x)`); `@@` is an escaped literal `@` and is skipped."""
    out: List[str] = []
    i = 0
    while i < len(line):
        at = line.find("@", i)
        if at < 0:
            break
        if line[at:at + 2] == "@@":
            i = at + 2
            continue
        rest = line[at + 1:]
        if rest.startswith("("):                       # @( expr )
            end = _match_paren(line, at + 1)
            if end is not None:
                out.append(line[at + 2:end - 1])
                i = end
                continue
            break
        m = re.match(r"[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*", rest)
        if not m:
            i = at + 1
            continue
        expr_end = at + 1 + m.end()
        if expr_end < len(line) and line[expr_end] == "(":  # a call: include balanced args
            end = _match_paren(line, expr_end)
            if end is not None:
                expr_end = end
        out.append(line[at + 1:expr_end])
        i = expr_end
    return out


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
        body: List[Tuple[str, int]] = []              # method-body C#, with original line

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
            code = re.search(r"@\{", text)
            if code:                                   # a method-body code block
                collected, i = self._consume_block(lines, i, text[code.end():])
                body.extend(collected)
                continue
            exprs = _expressions(text)
            if exprs:
                for e in exprs:
                    body.append((f"Write({e.strip()});", ln))
            else:
                body.append(("", ln))                  # pure markup: keep the line, no code
            i += 1

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


__all__ = ["RazorFrontend"]
