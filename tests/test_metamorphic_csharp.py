"""Metamorphic tests for C#: a vulnerability rewritten without changing its meaning is still found.

The C# frontend lowered syntax it did not know as a variable named by its source text, or dropped
it: `sql += x` was `sql = x`, `q!` and `o as string` were variables named `q!` and `o as string`,
a chained assignment bound the inner assignment's text, a deconstruction emitted nothing, an
expression-bodied member kept only its returned value, and `lock`/`checked`/labeled statements
vanished with everything inside them. Every seed flow (request data reaching a sink) is rewritten
here by each transform and the finding must survive; the same rewrite of a constant must stay
clean, and a rewrite that overwrites the request value with a constant must clean it, so recall
is never bought with noise.

A shape Frame does not handle yet is a strict xfail with the reason (KNOWN_GAPS, OUT_OF_SCOPE):
fixing it makes the test pass and CI asks for the entry to be removed.
"""

import re

import pytest

from frame.sil.frontends.csharp_frontend import CSharpFrontend
from frame.sil.scanner import FrameScanner

CS_HEAD = """using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace App {
public class AppDb : DbContext { }
public class Box {
    public string Val;
    public Box(string v) { Val = v; }
    public string Get() { return Val; }
}
[ApiController]
public class C : ControllerBase {
    private string _last;
    private readonly AppDb _db;
    private static string Ident(string s) { return s; }
    private static string Arrow(string s) => s;
    private static void Copy(string a, out string b) { b = a; }
    private static IEnumerable<string> Each(string s) { yield return s; }
    [HttpGet("x")]
    public IActionResult X([FromQuery] string q) {
{body}
        return Ok();
    }
}}
"""
CS_SINKS = {
    "CWE-78": 'Process.Start("cmd.exe", "/c ping " + {v});',
    "CWE-89": 'var cmd = new SqlCommand("SELECT * FROM t WHERE n = \'" + {v} + "\'", new SqlConnection("cs"));',
    "CWE-22": 'System.IO.File.ReadAllText("/srv/files/" + {v});',
}
# Each transform: statements that leave q's value in v.
CS_TRANSFORMS = {
    "plain": ["var v = q;"],
    "typed": ["string v = q;"],
    "declare-then-assign": ["string v;", "v = q;"],
    "chained-assignment": ["string v, w;", "v = w = q;"],
    "chained-inner": ["string v, w;", "w = v = q;"],
    "chained-in-declaration": ["string w;", "string v = w = q;"],
    "assignment-in-condition": ["string v;", "if ((v = q) != null) { }"],
    "compound": ['string v = "";', "v += q;"],
    "compound-then-constant": ['string v = "a";', "v += q;", 'v += "b";'],
    "null-coalescing-assignment": ["string v = null;", "v ??= q;"],
    "coalesce": ['var v = q ?? "x";'],
    "ternary": ['var v = q != null ? q : "x";'],
    "null-forgiving": ["var v = q!;"],
    "null-forgiving-assignment": ["string v;", "v = q!;"],
    "null-forgiving-receiver": ["var v = q!.Trim();"],
    "as-cast": ["object o = q;", "var v = o as string;"],
    "cast": ["object o = q;", "var v = (string)o;"],
    "cast-receiver": ["object o = q;", "var v = ((string)o).Trim();"],
    "parenthesized": ["var v = (q);"],
    "parenthesized-receiver": ['var v = (q + "").Trim();'],
    "interpolation": ['var v = $"{q}";'],
    "format": ['var v = string.Format("{0}", q);'],
    "concat": ['var v = string.Concat("a", q);'],
    "concat-receiver": ['var v = string.Concat(q, "x").Trim();'],
    "trim": ["var v = q.Trim();"],
    "method-chain": ["var v = q.Trim().ToLower();"],
    "method-chain-assignment": ["string v;", "v = q.Trim().ToLower();"],
    "conditional-access": ["var v = q?.Trim();"],
    "conditional-access-chain": ["var v = q?.Trim()?.ToLower();"],
    "conditional-access-in-concat": ['var v = "x" + q?.Trim();'],
    "stringbuilder-chain": ['var v = new StringBuilder().Append(q).Append("x").ToString();'],
    "stringbuilder-variable": ["var sb = new StringBuilder();", "sb.Append(q);", "var v = sb.ToString();"],
    "deconstruction": ["var (v, n) = (q, 1);"],
    "deconstruction-swap": ["var (n, v) = (1, q);"],
    "deconstruction-typed": ["(string v, int n) = (q, 1);"],
    "deconstruction-assignment": ["string v;", "int n;", "(v, n) = (q, 1);"],
    "deconstruction-nested": ["var (v, (a, b)) = (q, (1, 2));"],
    "deconstruction-of-a-call": ["var (v, n) = (Ident(q), 1);"],
    "tuple-element": ["var t = (a: q, b: 1);", "var v = t.a;"],
    "is-pattern": ["object o = q;", 'string v = "";', "if (o is string s) { v = s; }"],
    "is-pattern-and": ["object o = q;", 'string v = "";', "if (o is string s && s.Length > 0) { v = s; }"],
    "is-pattern-negated": ["object o = q;", 'string v = "";', "if (o is not string s) { return Ok(); }",
                           "v = s;"],
    "is-pattern-property": ["object o = new Box(q);", 'string v = "";', "if (o is Box { Val: var s }) { v = s; }"],
    "is-pattern-of-a-call": ['string v = "";', "if (Ident(q) is string s) { v = s; }"],
    "switch-expression": ['var v = q.Length switch { 0 => "none", _ => q };'],
    "switch-expression-pattern": ["object o = q;", 'var v = o switch { string s => s, _ => "" };'],
    "switch-case-pattern": ["object o = q;", 'string v = "";',
                            "switch (o) { case string s: v = s; break; default: break; }"],
    "switch-case-overwrite": ["string v = q;", 'switch (q.Length) { case 0: v = "x"; break; default: break; }'],
    "list-initializer": ["var l = new List<string> { q };", "var v = l[0];"],
    "implicit-array": ["var a = new[] { q };", "var v = a[0];"],
    "array-initializer": ["string[] a = { q };", "var v = a[0];"],
    "array-creation": ["var a = new string[] { q };", "var v = a[0];"],
    "element-receiver": ["var a = new[] { q };", "var v = a[0].Trim();"],
    "dictionary-initializer": ['var d = new Dictionary<string, string> { ["k"] = q };', 'var v = d["k"];'],
    "dictionary-add-initializer": ['var d = new Dictionary<string, string> { { "k", q } };', 'var v = d["k"];'],
    "indexer-write": ["var d = new Dictionary<string, string>();", 'd["k"] = q;', 'var v = d["k"];'],
    "anonymous-object": ["var o = new { Name = q };", "var v = o.Name;"],
    "object-field": ["var b = new Box(q);", "var v = b.Val;"],
    "object-getter": ["var b = new Box(q);", "var v = b.Get();"],
    "object-initializer": ['var b = new Box("") { Val = q };', "var v = b.Val;"],
    "target-typed-new": ["Box b = new(q);", "var v = b.Val;"],
    "target-typed-initializer": ['Box b = new("") { Val = q };', "var v = b.Val;"],
    "linq-query": ["var v = (from s in new[] { q } select s).First();"],
    "helper": ["var v = Ident(q);"],
    "expression-bodied-helper": ["var v = Arrow(q);"],
    "local-function": ["string Id(string s) => s;", "var v = Id(q);"],
    "local-function-block": ["string Id(string s) { return s; }", "var v = Id(q);"],
    "lambda": ["Func<string, string> f = s => s;", "var v = f(q);"],
    "foreach": ['string v = "";', "foreach (var s in new[] { q }) { v = s; }"],
    "foreach-deconstruction": ['string v = "";', 'foreach (var (k, s) in new[] { ("k", q) }) { v = s; }'],
    "for": ['string v = "";', "for (int i = 0; i < 1; i++) { v = q; }"],
    "for-two-counters": ['string v = "";', "for (int i = 0, j = 0; i < 1; i++, j++) { v = q; }"],
    "while": ['string v = "";', 'while (v == "") { v = q; }'],
    "while-counter": ['string v = "";', "int i = 0;", "while (i < 3) { i++; }", "v = q;"],
    "do-while": ['string v = "";', 'do { v = q; } while (v == "");'],
    "try-finally": ['string v = "";', "try { v = q; } finally { }"],
    "try-catch": ['string v = "";', "try { v = q; } catch (Exception) { }"],
    "try-catch-overwrite": ["string v = q;", 'try { v = q; } catch (Exception) { v = ""; }'],
    "using-block": ['string v = "";', "using (var ms = new MemoryStream()) { v = q; }"],
    "lock": ['string v = "";', "lock (this) { v = q; }"],
    "checked": ['string v = "";', "checked { v = q; }"],
    "unchecked": ['string v = "";', "unchecked { v = q; }"],
    "unsafe": ['string v = "";', "unsafe { v = q; }"],
    "labeled": ['string v = "";', "L: v = q;"],
    "preprocessor": ['string v = "";', "#if DEBUG", "v = q;", "#endif"],
    "if-else": ["string v;", 'if (q.Length > 3) { v = q; } else { v = q + "!"; }'],
    "switch-statement": ['string v = "";', "switch (q.Length) { case 0: v = q; break; default: v = q; break; }"],
    "string-join": ['var v = string.Join(",", new[] { q });'],
    "to-string": ["var v = q.ToString();"],
    "substring": ["var v = q.Substring(0);"],
    "replace": ['var v = q.Replace("a", "b");'],
    "field": ["_last = q;", "var v = _last;"],
    "this-field": ["this._last = q;", "var v = this._last;"],
}
# Sink arguments written inline (the value never passes through a variable).
CS_INLINE = {
    "null-forgiving-inline": 'Process.Start("cmd.exe", "/c ping " + q!);',
    "as-inline": 'Process.Start("cmd.exe", "/c ping " + (q as string));',
    "chain-inline": 'Process.Start("cmd.exe", "/c ping " + q.Trim().ToLower());',
    "conditional-access-inline": 'Process.Start("cmd.exe", "/c ping " + q?.Trim());',
    "switch-inline": 'Process.Start("cmd.exe", "/c ping " + (q.Length switch { 0 => "x", _ => q }));',
    "ternary-inline": 'Process.Start("cmd.exe", "/c ping " + (q.Length > 0 ? q : "x"));',
    "creation-inline": 'Process.Start(new ProcessStartInfo("cmd.exe", "/c ping " + q));',
}
# Each overwrite: statements after `var v = q;` that leave only a constant in v (the sink must
# not fire). A binding construct that did not write its target left the request value there.
CS_OVERWRITES = {
    "plain": ['v = "x";'],
    "chained": ["string w;", 'v = w = "x";'],
    "deconstruction": ["int n;", '(v, n) = ("x", 1);'],
    "deconstruction-discard": ['(v, _) = ("ls", 1);'],
    "deconstruction-other-element": ['(v, var w) = ("x", q);'],
    "switch-expression": ['v = v.Length switch { _ => "x" };'],
    "switch-every-section": ['switch (q.Length) { case 0: v = "a"; break; default: v = "b"; break; }'],
    "pattern-of-a-number": ["object o = q;", "if (o is int n) { v = n.ToString(); } else { v = \"x\"; }"],
    "nameof": ["v = nameof(q);"],
}

# (language, transform) -> why the rewrite still loses the flow
KNOWN_GAPS: dict = {}

# Shapes outside this frontend's lowering: each needs type resolution, receiver mutation or
# interprocedural facts the frontend does not have. (lines, the CWE a correct scan reports, or
# None when the shape is safe and must stay clean)
OUT_OF_SCOPE = {
    "sink-nested-in-a-call-argument": (
        ["return Ok(_db.Database.ExecuteSqlRaw(\"DELETE FROM t WHERE n = '\" + q + \"'\"));"], "CWE-89",
        "a sink call nested in another call's argument is matched only by type resolution the "
        "translator does not do for nested calls"),
    "sink-in-a-ternary-arm": (
        ["var r = q.Length > 0 ? _db.Database.ExecuteSqlRaw(\"DELETE FROM t WHERE n = '\" + q + \"'\") : 0;"],
        "CWE-89", "a call in a ternary arm is an expression, matched only by type resolution"),
    "process-start-info-member-chain": (
        ["var p = new Process();", 'p.StartInfo.FileName = "sh";', 'p.StartInfo.Arguments = "-c " + q;',
         "p.Start();"], "CWE-78", "`p.StartInfo.Arguments` needs the type of a member chain"),
    "nested-object-initializer": (
        ['var p = new Process { StartInfo = new ProcessStartInfo { FileName = "sh", Arguments = "-c " + q } };',
         "p.Start();"], "CWE-78", "a creation nested in an object initializer is not lowered as a creation"),
    "nested-member-initializer": (
        ['var p = new Process { StartInfo = { FileName = "sh", Arguments = "-c " + q } };', "p.Start();"],
        "CWE-78", "a nested member initializer (`StartInfo = { ... }`) is not lowered"),
    "out-argument": (
        ["Copy(q, out var v);", 'Process.Start("cmd.exe", "/c ping " + v);'], "CWE-78",
        "an `out`/`ref` argument is not written by the call"),
    "list-add": (
        ["var l = new List<string>();", "l.Add(q);", 'Process.Start("cmd.exe", "/c ping " + l[0]);'],
        "CWE-78", "a collection's Add does not taint the collection (no receiver-propagation spec)"),
    "iterator-helper": (
        ["var v = Each(q).First();", 'Process.Start("cmd.exe", "/c ping " + v);'], "CWE-78",
        "`yield return` is not a return: an iterator's summary returns nothing"),
    "this-field-mixed": (
        ["this._last = q;", 'Process.Start("cmd.exe", "/c ping " + _last);'], "CWE-78",
        "`this._x` and `_x` are lowered as two names"),
    "tuple-element-of-a-variable": (
        ['var t = (a: "x", b: q);', 'Process.Start("cmd.exe", "/c ping " + t.a);'], None,
        "a tuple held in a variable carries every element: its element reads are not told apart"),
    "constant-false-branch": (
        ['if (false) { Process.Start("cmd.exe", "/c ping " + q); }'], None,
        "boolean literals are not constants to the path (lowering them needs `break` edges first: "
        "`while (true) { ... break; }` would lose everything after the loop)"),
    "stream-reader-over-the-request-body": (
        ["using var r = new StreamReader(Request.Body);", "var body = r.ReadToEnd();"], None,
        "`new StreamReader(stream)` is reported as a path sink: the constructor's sink is chosen by "
        "name, not by its argument's type"),
}


def _scan(code, name="App.cs"):
    r = FrameScanner(language="csharp").scan(code, name)
    assert not r.errors, r.errors
    return {v.cwe_id for v in r.vulnerabilities}


def _cs(lines):
    return CS_HEAD.replace("{body}", "\n".join(("" if ln.startswith("#") else "        ") + ln for ln in lines))


def _gap(transform):
    reason = KNOWN_GAPS.get(("csharp", transform))
    return [pytest.mark.xfail(reason=reason, strict=True)] if reason else []


@pytest.mark.parametrize("transform,cwe", [
    pytest.param(t, c, id=f"{t}-{c}", marks=_gap(t)) for t in CS_TRANSFORMS for c in CS_SINKS])
def test_csharp_flow_survives_the_rewrite(transform, cwe):
    sink = CS_SINKS[cwe].replace("{v}", "v")
    assert cwe in _scan(_cs(CS_TRANSFORMS[transform] + [sink]))


@pytest.mark.parametrize("transform", [pytest.param(t, id=t, marks=_gap(t)) for t in CS_INLINE])
def test_csharp_inline_flow_survives_the_rewrite(transform):
    assert "CWE-78" in _scan(_cs([CS_INLINE[transform]]))


def _constant(lines):
    """The transform applied to a constant instead of the request value."""
    return [re.sub(r"\bq\b", '"localhost"', ln) for ln in lines]


@pytest.mark.parametrize("transform", list(CS_TRANSFORMS))
def test_csharp_rewrite_of_a_constant_stays_clean(transform):
    sink = CS_SINKS["CWE-78"].replace("{v}", "v")
    assert "CWE-78" not in _scan(_cs(_constant(CS_TRANSFORMS[transform]) + [sink]))


@pytest.mark.parametrize("transform", list(CS_INLINE))
def test_csharp_inline_rewrite_of_a_constant_stays_clean(transform):
    assert "CWE-78" not in _scan(_cs(_constant([CS_INLINE[transform]])))


@pytest.mark.parametrize("overwrite", list(CS_OVERWRITES))
def test_csharp_constant_written_over_the_value_cleans_it(overwrite):
    sink = CS_SINKS["CWE-78"].replace("{v}", "v")
    assert "CWE-78" not in _scan(_cs(["var v = q;"] + CS_OVERWRITES[overwrite] + [sink]))


@pytest.mark.parametrize("case", [
    pytest.param(c, id=c, marks=[pytest.mark.xfail(reason=OUT_OF_SCOPE[c][2], strict=True)])
    for c in OUT_OF_SCOPE])
def test_csharp_shapes_outside_the_frontend(case):
    lines, cwe, _ = OUT_OF_SCOPE[case]
    found = _scan(_cs(lines))
    assert (cwe in found) if cwe else not found


# -- ways of building the sink: each must be recognised whichever is used ----------------------

SQL = "var sql = \"SELECT * FROM t WHERE n = '\" + q + \"'\";"
CS_SQL_COMMANDS = {
    "new": ['var cmd = new SqlCommand(sql, new SqlConnection("cs"));', "cmd.ExecuteReader();"],
    "target-typed": ['SqlCommand cmd = new(sql, new SqlConnection("cs"));', "cmd.ExecuteReader();"],
    "target-typed-assignment": ["SqlCommand cmd;", 'cmd = new(sql, new SqlConnection("cs"));'],
    "using-declaration": ['using var cmd = new SqlCommand(sql, new SqlConnection("cs"));'],
    "initializer": ["var cmd = new SqlCommand { CommandText = sql };"],
    "target-typed-initializer": ["SqlCommand cmd = new() { CommandText = sql };"],
    "local-connection": ['var conn = new SqlConnection("cs");', "var cmd = conn.CreateCommand();",
                         "cmd.CommandText = sql;", "cmd.ExecuteReader();"],
    "parameter-connection": ["var cmd = conn.CreateCommand();", "cmd.CommandText = sql;"],
    "compound-text": ['var cmd = new SqlCommand("", new SqlConnection("cs"));', "cmd.CommandText += sql;"],
    "compound-query": ['var s2 = "SELECT * FROM t WHERE 1 = 1";', "s2 += \" AND a = '\" + q + \"'\";",
                       's2 += " ORDER BY id";', 'var cmd = new SqlCommand(s2, new SqlConnection("cs"));'],
}


def _with_connection_parameter(code):
    return code.replace("public IActionResult X([FromQuery] string q)",
                        "public IActionResult X([FromQuery] string q, [FromServices] SqlConnection conn)")


@pytest.mark.parametrize("how", list(CS_SQL_COMMANDS))
def test_csharp_command_built_any_way_is_a_sink(how):
    assert "CWE-89" in _scan(_with_connection_parameter(_cs([SQL] + CS_SQL_COMMANDS[how])))


@pytest.mark.parametrize("how", list(CS_SQL_COMMANDS))
def test_csharp_command_built_any_way_from_a_constant_is_clean(how):
    lines = ['var sql = "SELECT * FROM t";'] + [ln for ln in CS_SQL_COMMANDS[how] if "q" not in ln]
    assert "CWE-89" not in _scan(_with_connection_parameter(_cs(lines)))


def test_target_typed_process_start_info_is_a_command_sink():
    code = _cs(['ProcessStartInfo psi = new() { FileName = "sh", Arguments = "-c " + q };', "Process.Start(psi);"])
    assert "CWE-78" in _scan(code)
    assert "CWE-78" not in _scan(_cs(['ProcessStartInfo psi = new() { FileName = "sh", Arguments = "-c ls" };',
                                      "Process.Start(psi);"]))


def test_a_target_typed_creation_records_its_type():
    program = CSharpFrontend().translate(_cs(['SqlCommand cmd = new("SELECT 1", new SqlConnection("cs"));']), "App.cs")
    proc = next(p for p in program.procedures.values() if p.name.endswith("C.X"))
    assert proc.var_types.get("cmd") == "SqlCommand"
    calls = {str(i.func.value) for n in proc.nodes.values() for i in n.instrs if type(i).__name__ == "Call"}
    assert "SqlCommand" in calls                     # the constructor's usage call, as for `new SqlCommand(...)`


# -- expression-bodied members: `=> e` is `{ return e; }` ---------------------------------------

MEMBERS = """using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
namespace App {
public class C : Controller {
    [HttpGet("r")] public IActionResult R(string q) => Redirect({r});
    [HttpGet("f")] public string F(string q) => System.IO.File.ReadAllText("/srv/" + {f});
    [HttpGet("p")] public void P(string q) => Process.Start("sh", "-c " + {p});
}}
"""


def test_expression_bodied_actions_reach_their_sinks():
    found = _scan(MEMBERS.replace("{r}", "q").replace("{f}", "q").replace("{p}", "q"))
    assert {"CWE-601", "CWE-22", "CWE-78"} <= found


def test_expression_bodied_actions_with_constants_are_clean():
    found = _scan(MEMBERS.replace("{r}", '"/home"').replace("{f}", '"index.html"').replace("{p}", '"ls"'))
    assert not found & {"CWE-601", "CWE-22", "CWE-78"}


def _calls(program, suffix):
    proc = next(p for p in program.procedures.values() if p.name.endswith(suffix))
    return [i for n in proc.nodes.values() for i in n.instrs if type(i).__name__ in ("Call", "Assign", "Return")]


def test_expression_bodied_properties_accessors_and_constructors_are_lowered():
    code = ("using System.Diagnostics;\nnamespace App {\npublic class S {\n  private string _a;\n"
            "  public S(string a) => _a = a;\n"
            "  public string Out => Process.Start(\"sh\", _a).StandardOutput.ReadToEnd();\n"
            "  public string Name { get => _a.Trim(); set => _a = value; }\n}}\n")
    program = CSharpFrontend().translate(code, "S.cs")
    assert any(type(i).__name__ == "Assign" and str(i.id) == "_a" for i in _calls(program, "S..ctor"))
    assert any(type(i).__name__ == "Call" and "Process.Start" in str(i.func) for i in _calls(program, "Out.get"))
    assert any(type(i).__name__ == "Call" and "_a.Trim" in str(i.func) for i in _calls(program, "Name.get"))
    assert any(type(i).__name__ == "Assign" and str(i.id) == "_a" for i in _calls(program, "Name.set"))


# -- receivers ----------------------------------------------------------------------------------

def test_this_qualified_receivers_keep_their_types():
    code = ("using System.Diagnostics;\nusing System.Net.Http;\nusing Microsoft.AspNetCore.Mvc;\nnamespace App {\n"
            "public class C : Controller {\n  private readonly HttpClient _http = new HttpClient();\n"
            "  [HttpGet(\"r\")] public IActionResult R(string q) { return this.Redirect(q); }\n"
            "  [HttpGet(\"s\")] public object S(string q) { return this._http.GetStringAsync(q); }\n}}\n")
    found = _scan(code)
    assert {"CWE-601", "CWE-918"} <= found
    assert not _scan(code.replace("Redirect(q)", 'Redirect("/home")').replace("GetStringAsync(q)",
                                                                            'GetStringAsync("https://a.example")'))


def test_a_declared_type_seen_before_its_use():
    # `var cmd = conn.CreateCommand()` needs conn's type: a parameter or an earlier local
    program = CSharpFrontend().translate(_with_connection_parameter(_cs(
        ["var cmd = conn.CreateCommand();", 'var c2 = new SqlConnection("cs");', "var cmd2 = c2.CreateCommand();"])),
        "App.cs")
    proc = next(p for p in program.procedures.values() if p.name.endswith("C.X"))
    assert proc.var_types.get("cmd") == "SqlCommand" and proc.var_types.get("cmd2") == "SqlCommand"


def test_a_var_takes_the_type_it_creates_not_one_created_in_its_arguments():
    program = CSharpFrontend().translate(_cs(['var r = Ident(new SqlConnection("cs").ConnectionString);']), "App.cs")
    proc = next(p for p in program.procedures.values() if p.name.endswith("C.X"))
    assert proc.var_types.get("r") != "SqlConnection"


# -- minimal APIs: a handler registered on a route group made in the same expression ------------

MINIMAL = """using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapGroup("/api").MapGet("/ping", (string host) => Process.Start("ping", {arg}));
app.Run();
"""


def test_a_handler_registered_on_a_chained_route_group():
    assert "CWE-78" in _scan(MINIMAL.replace("{arg}", "host"), "Program.cs")
    assert "CWE-78" not in _scan(MINIMAL.replace("{arg}", '"localhost"'), "Program.cs")


def test_a_chained_registration_is_recorded_by_its_names():
    program = CSharpFrontend().translate(MINIMAL.replace("{arg}", "host"), "Program.cs")
    reg = next(r for r in program.registrations if r.callee_text.endswith("MapGet"))
    assert (reg.root, reg.rest) == ("app", ("MapGroup", "MapGet"))


# -- statements ---------------------------------------------------------------------------------

def test_sinks_inside_lowered_statement_kinds():
    for stmt in ("lock (this) { %s }", "checked { %s }", "unchecked { %s }", "unsafe { %s }", "L: %s",
                 "fixed (char* p = q) { %s }", "using (Ident(q)) { %s }"):
        code = _cs([stmt % 'Process.Start("cmd.exe", "/c ping " + q);'])
        assert "CWE-78" in _scan(code), stmt


def test_a_sink_in_a_preprocessor_arm_is_a_branch():
    code = _cs(["string v = q;", "#if DEBUG", 'v = "x";', "#else", "v = Ident(v);", "#endif",
                'Process.Start("cmd.exe", "/c ping " + v);'])
    assert "CWE-78" in _scan(code)
    clean = _cs(["string v = q;", "#if DEBUG", 'v = "x";', "#else", 'v = "y";', "#endif",
                 'Process.Start("cmd.exe", "/c ping " + v);'])
    assert "CWE-78" not in _scan(clean)


def test_yield_return_runs_its_calls():
    code = ("using System.Collections.Generic;\nusing System.Diagnostics;\nusing Microsoft.AspNetCore.Mvc;\n"
            "public class C : ControllerBase {\n  [HttpGet(\"x\")] public IEnumerable<object> X([FromQuery] string q) {\n"
            "    yield return Process.Start(\"cmd.exe\", \"/c ping \" + q);\n  }\n}\n")
    assert "CWE-78" in _scan(code)


# -- local functions and primary constructors ---------------------------------------------------

LOCAL_SINK = 'void Run(string s) { Process.Start("cmd.exe", "/c ping " + s); }'


def test_a_local_function_is_a_procedure_its_callers_reach():
    assert "CWE-78" in _scan(_cs([LOCAL_SINK, "Run(q);"]))
    assert "CWE-78" in _scan(_cs(['void Run(string s) => Process.Start("cmd.exe", "/c ping " + s);', "Run(q);"]))
    assert "CWE-78" not in _scan(_cs([LOCAL_SINK, 'Run("localhost");']))


def test_a_local_function_reads_the_variables_it_captures():
    assert "CWE-78" in _scan(_cs(['void Run() { Process.Start("cmd.exe", "/c ping " + q); }', "Run();"]))
    assert "CWE-78" not in _scan(_cs(['var h = "localhost";',
                                      'void Run() { Process.Start("cmd.exe", "/c ping " + h); }', "Run();"]))


TOP_LEVEL = """using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapGet("/ping", Ping);
app.Run();
static object Ping(string host) => Process.Start("ping", {arg});
"""


def test_a_top_level_local_function_registered_as_a_handler():
    assert "CWE-78" in _scan(TOP_LEVEL.replace("{arg}", "host"), "Program.cs")
    assert "CWE-78" not in _scan(TOP_LEVEL.replace("{arg}", '"localhost"'), "Program.cs")


PRIMARY_REPO = """using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
namespace App {
public class Repo(SqlConnection conn) {
    public void Find(string q) {
        var c = conn.CreateCommand();
        c.CommandText = {text};
        c.ExecuteReader();
    }
}
[ApiController]
public class C : ControllerBase {
    [HttpGet("x")]
    public IActionResult X([FromQuery] string q) { new Repo(new SqlConnection("cs")).Find(q); return Ok(); }
}}
"""


def test_primary_constructor_parameters_are_typed_members():
    assert "CWE-89" in _scan(PRIMARY_REPO.replace("{text}", "\"SELECT * FROM t WHERE n = '\" + q + \"'\""))
    assert "CWE-89" not in _scan(PRIMARY_REPO.replace("{text}", '"SELECT * FROM t"'))
    program = CSharpFrontend().translate(PRIMARY_REPO.replace("{text}", '"x"'), "App.cs")
    assert next(p for p in program.procedures.values() if p.name.endswith("Repo.Find")).var_types["conn"] == "SqlConnection"


def test_a_primary_constructor_stores_its_arguments(tmp_path):
    (tmp_path / "Runner.cs").write_text('using System.Diagnostics;\nnamespace App {\npublic class Runner(string cmd) {\n'
                                        '    public void Go() { Process.Start("sh", "-c " + cmd); }\n}}\n')
    ctrl = ("using Microsoft.AspNetCore.Mvc;\nnamespace App {\n[ApiController]\npublic class C : ControllerBase {\n"
            "    [HttpGet(\"x\")]\n    public IActionResult X([FromQuery] string q) {\n"
            "        var r = new Runner({arg});\n        r.Go();\n        return Ok();\n    }\n}}\n")
    (tmp_path / "C.cs").write_text(ctrl.replace("{arg}", "q"))
    found = {v.cwe_id for r in FrameScanner(verify=False).scan_directory(str(tmp_path), None) for v in r.vulnerabilities}
    assert "CWE-78" in found
    (tmp_path / "C.cs").write_text(ctrl.replace("{arg}", '"ls"'))
    found = {v.cwe_id for r in FrameScanner(verify=False).scan_directory(str(tmp_path), None) for v in r.vulnerabilities}
    assert "CWE-78" not in found


RAZOR_FOREACH = """@page
@{
    var q = Context.Request.Query["q"];
}
@foreach (var item in q)
{
    <p>@Html.Raw(item)</p>
}
"""


@pytest.mark.xfail(strict=True, reason="Razor control flow: `@foreach` is not transpiled as a loop over its "
                                       "collection (`@if` is), so the loop variable holds nothing")
def test_razor_loop_variable_reaches_raw_output():
    r = FrameScanner(language="razor", verify=False, llm_detect=False).scan(RAZOR_FOREACH, "Index.cshtml")
    assert "CWE-79" in {v.cwe_id for v in r.vulnerabilities}
