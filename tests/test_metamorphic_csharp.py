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
    private static void Pick(out string b) { b = "localhost"; }
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

# Shapes that need type resolution, receiver mutation, interprocedural facts or control flow the
# frontend lowers specially. name -> (lines, the CWE a correct scan reports, or None when the shape
# is safe and must stay clean). Each positive is paired with its nearest safe variant.
CS_SHAPES = {
    # a sink nested in another call's argument or in a ternary arm, known only by the receiver's type
    "sink-nested-in-a-call-argument": (
        ["return Ok(_db.Database.ExecuteSqlRaw(\"DELETE FROM t WHERE n = '\" + q + \"'\"));"], "CWE-89"),
    "sink-nested-in-a-call-argument-constant": (
        ['return Ok(_db.Database.ExecuteSqlRaw("DELETE FROM t"));'], None),
    "extension-sink-nested-in-a-call-argument": (
        ["return Ok(_db.Users.FromSqlRaw(\"SELECT * FROM u WHERE n = '\" + q + \"'\"));"], "CWE-89"),
    "extension-sink-nested-in-a-call-argument-constant": (
        ['return Ok(_db.Users.FromSqlRaw("SELECT * FROM u"));'], None),
    "sink-in-a-ternary-arm": (
        ["var r = q.Length > 0 ? _db.Database.ExecuteSqlRaw(\"DELETE FROM t WHERE n = '\" + q + \"'\") : 0;"],
        "CWE-89"),
    "sink-in-a-ternary-arm-constant": (
        ['var r = q.Length > 0 ? _db.Database.ExecuteSqlRaw("DELETE FROM t") : 0;'], None),
    "returned-ternary-of-redirects": (
        ["bool all = q.Length > 2;", 'return all ? Redirect("/") : Redirect(q);'], "CWE-601"),
    "returned-ternary-of-redirects-constant": (
        ["bool all = q.Length > 2;", 'return all ? Redirect("/") : Redirect("/home");'], None),
    "returned-ternary-content": (
        ["bool c = q.Length > 2;", 'return c ? Content(q, "text/html") : BadRequest();'], "CWE-79"),
    "returned-ternary-content-plain-text": (
        ["bool c = q.Length > 2;", 'return c ? Content(q, "text/plain") : BadRequest();'], None),
    "throw-arm-after-a-check": (
        ['var x = System.Text.RegularExpressions.Regex.IsMatch(q, "^[a-z]+$") ? q : throw new ArgumentException();',
         'Process.Start("cmd.exe", "/c ping " + x);'], None),
    "throw-arm-without-a-check": (
        ["var x = q.Length < 9 ? q : throw new ArgumentException();", 'Process.Start("cmd.exe", "/c ping " + x);'],
        "CWE-78"),
    # Process.StartInfo: a member chain's type, nested creations and nested member initializers
    "process-start-info-member-chain": (
        ["var p = new Process();", 'p.StartInfo.FileName = "sh";', 'p.StartInfo.Arguments = "-c " + q;',
         "p.Start();"], "CWE-78"),
    "process-start-info-member-chain-constant": (
        ["var p = new Process();", 'p.StartInfo.FileName = "sh";', 'p.StartInfo.Arguments = "-c ls";',
         "p.Start();"], None),
    "nested-object-initializer": (
        ['var p = new Process { StartInfo = new ProcessStartInfo { FileName = "sh", Arguments = "-c " + q } };',
         "p.Start();"], "CWE-78"),
    "nested-object-initializer-constant": (
        ['var p = new Process { StartInfo = new ProcessStartInfo { FileName = "sh", Arguments = "-c ls" } };',
         "p.Start();"], None),
    "nested-creation-in-an-initializer": (
        ['var p = new Process { StartInfo = new ProcessStartInfo("/bin/sh", "-c " + q) };', "p.Start();"], "CWE-78"),
    "nested-creation-in-an-initializer-constant": (
        ['var p = new Process { StartInfo = new ProcessStartInfo("/bin/sh", "-c ls") };', "p.Start();"], None),
    "nested-member-initializer": (
        ['var p = new Process { StartInfo = { FileName = "sh", Arguments = "-c " + q } };', "p.Start();"],
        "CWE-78"),
    "nested-member-initializer-constant": (
        ['var p = new Process { StartInfo = { FileName = "sh", Arguments = "-c ls" } };', "p.Start();"], None),
    # out / ref arguments
    "out-argument": (["Copy(q, out var v);", 'Process.Start("cmd.exe", "/c ping " + v);'], "CWE-78"),
    "out-argument-overwritten-by-the-callee": (
        ["string v = q;", "Pick(out v);", 'Process.Start("cmd.exe", "/c ping " + v);'], None),
    "out-argument-of-a-header-lookup": (
        ['Request.Headers.TryGetValue("X", out var v);', 'Process.Start("cmd.exe", "/c ping " + v);'], "CWE-78"),
    "out-argument-of-a-query-lookup-in-a-condition": (
        ['if (Request.Query.TryGetValue("x", out var v)) { Process.Start("cmd.exe", "/c ping " + v.ToString()); }'],
        "CWE-78"),
    "out-discard": (['Request.Query.TryGetValue("x", out _);', 'Process.Start("cmd.exe", "/c ping x");'], None),
    "out-argument-of-a-number-parse": (
        ["if (int.TryParse(q, out var n)) { Process.Start(\"cmd.exe\", \"/c ping \" + n); }"], None),
    "out-argument-of-a-constant-table": (
        ['var hosts = new Dictionary<string, string> { ["a"] = "a.example" };',
         'if (hosts.TryGetValue(q, out var h)) { Process.Start("cmd.exe", "/c ping " + h); }'], None),
    # a StreamReader over a stream reads it (it opens no file), and carries what it reads
    "stream-reader-over-the-request-body": (
        ["using var r = new StreamReader(Request.Body);", "var body = r.ReadToEnd();"], None),
    "stream-reader-over-the-request-body-to-a-sink": (
        ["using var r = new StreamReader(Request.Body);", "var body = r.ReadToEnd();",
         'Process.Start("cmd.exe", "/c ping " + body);'], "CWE-78"),
    "stream-reader-over-a-path": (['using var r = new StreamReader("/srv/files/" + q);'], "CWE-22"),
    # collections, iterators, fields, tuples
    "list-add": (["var l = new List<string>();", "l.Add(q);", 'Process.Start("cmd.exe", "/c ping " + l[0]);'],
                 "CWE-78"),
    "list-add-constant": (['var l = new List<string>();', 'l.Add("x");', 'Process.Start("cmd.exe", "/c ping " + l[0]);'],
                          None),
    "queue-enqueue": (["var w = new Queue<string>();", "w.Enqueue(q);",
                       'Process.Start("cmd.exe", "/c ping " + w.Dequeue());'], "CWE-78"),
    "iterator-helper": (["var v = Each(q).First();", 'Process.Start("cmd.exe", "/c ping " + v);'], "CWE-78"),
    "iterator-helper-constant": (['var v = Each("x").First();', 'Process.Start("cmd.exe", "/c ping " + v);'], None),
    "this-field-mixed": (["this._last = q;", 'Process.Start("cmd.exe", "/c ping " + _last);'], "CWE-78"),
    "this-field-mixed-constant": (['this._last = "x";', 'Process.Start("cmd.exe", "/c ping " + _last);'], None),
    "field-read-through-this": (["_last = q;", 'Process.Start("cmd.exe", "/c ping " + this._last);'], "CWE-78"),
    "tuple-element-of-a-variable": (['var t = (a: "x", b: q);', 'Process.Start("cmd.exe", "/c ping " + t.a);'],
                                    None),
    "tuple-element-of-a-variable-tainted": (
        ['var t = (a: "x", b: q);', 'Process.Start("cmd.exe", "/c ping " + t.b);'], "CWE-78"),
    "tuple-element-by-position": (['var t = ("x", q);', 'Process.Start("cmd.exe", "/c ping " + t.Item2);'],
                                  "CWE-78"),
    "tuple-element-by-position-constant": (['var t = ("x", q);', 'Process.Start("cmd.exe", "/c ping " + t.Item1);'],
                                           None),
    "tuple-as-a-whole": (['var t = (a: "x", b: q);', 'Process.Start("cmd.exe", "/c ping " + t.ToString());'],
                         "CWE-78"),
    # boolean literals are constants, `break` / `continue` are edges
    "constant-false-branch": (['if (false) { Process.Start("cmd.exe", "/c ping " + q); }'], None),
    "constant-true-branch": (['if (true) { Process.Start("cmd.exe", "/c ping " + q); }'], "CWE-78"),
    "code-after-a-loop-left-by-break": (
        ['string v = "";', "while (true) { v = q; break; }", 'Process.Start("cmd.exe", "/c ping " + v);'], "CWE-78"),
    "code-after-a-loop-left-by-break-constant": (
        ['string v = "";', 'while (true) { v = "x"; break; }', 'Process.Start("cmd.exe", "/c ping " + v);'], None),
    "break-before-a-write": (
        ['string v = q;', 'foreach (var s in new[] { "a" }) { break; v = "x"; }',
         'Process.Start("cmd.exe", "/c ping " + v);'], "CWE-78"),
    "continue-skips-the-rest-of-the-body": (
        ['string v = "";', 'for (int i = 0; i < 2; i++) { if (i == 0) { continue; } v = q; }',
         'Process.Start("cmd.exe", "/c ping " + v);'], "CWE-78"),
    "break-in-a-switch-section": (
        ['string v = q;', 'switch (q.Length) { case 0: if (q == "") { v = "a"; break; } v = "b"; break; '
         'default: v = "c"; break; }', 'Process.Start("cmd.exe", "/c ping " + v);'], None),
    "guard-compared-with-false": (
        ['if (System.Text.RegularExpressions.Regex.IsMatch(q, "^[a-z]+$") == false) { return BadRequest(); }',
         'Process.Start("cmd.exe", "/c ping " + q);'], None),
    "guard-compared-with-true": (
        ['if (System.Text.RegularExpressions.Regex.IsMatch(q, "^[a-z]+$") != true) { return BadRequest(); }',
         'Process.Start("cmd.exe", "/c ping " + q);'], None),
    "guard-pattern-false": (
        ['if (System.Text.RegularExpressions.Regex.IsMatch(q, "^[a-z]+$") is false) { return BadRequest(); }',
         'Process.Start("cmd.exe", "/c ping " + q);'], None),
    "guard-compared-with-false-the-wrong-way": (
        ['if (System.Text.RegularExpressions.Regex.IsMatch(q, "^[a-z]+$") == true) { return BadRequest(); }',
         'Process.Start("cmd.exe", "/c ping " + q);'], "CWE-78"),
    # element reads index by the subscript; a constant table's elements are its literals
    "constant-table-read-by-the-request": (
        ['var verbs = new Dictionary<string, string> { ["a"] = "ls" };', 'Process.Start("cmd.exe", "/c " + verbs[q]);'],
        None),
    "written-table-read-by-the-request": (
        ['var verbs = new Dictionary<string, string> { ["a"] = "ls" };', 'verbs["b"] = q;',
         'Process.Start("cmd.exe", "/c " + verbs["b"]);'], "CWE-78"),
    "constant-table-membership-check": (
        ['var allowed = new HashSet<string> { "a.example", "b.example" };',
         'if (!allowed.Contains(q)) { return BadRequest(); }', 'Process.Start("cmd.exe", "/c ping " + q);'], None),
    "membership-check-of-a-written-set": (
        ['var allowed = new HashSet<string> { "a.example" };', 'allowed.Add(q);',
         'if (!allowed.Contains(q)) { return BadRequest(); }', 'Process.Start("cmd.exe", "/c ping " + q);'],
        "CWE-78"),
    # string.Join / Concat / Format take any number of arguments; numbers are not text
    "string-join-of-many": (['var v = string.Join(",", "a", "b", q);', 'Process.Start("cmd.exe", "/c ping " + v);'],
                            "CWE-78"),
    "string-format-third-argument": (['var v = string.Format("{0}{1}", "a", q);',
                                      'Process.Start("cmd.exe", "/c ping " + v);'], "CWE-78"),
    "string-join-of-constants": (['var v = string.Join(",", "a", "b", "c");',
                                  'Process.Start("cmd.exe", "/c ping " + v);'], None),
    "number-parsed-into-sql": (["var id = int.Parse(q);",
                               'var cmd = new SqlCommand("SELECT * FROM t WHERE n = " + id, new SqlConnection("cs"));'],
                               None),
    "number-parsed-inline-into-sql": (
        ['var cmd = new SqlCommand("SELECT * FROM t WHERE n = " + Convert.ToInt32(q), new SqlConnection("cs"));'],
        None),
    "guid-parsed-into-sql": (
        ["var cmd = new SqlCommand(\"SELECT * FROM t WHERE n = '\" + Guid.Parse(q) + \"'\", new SqlConnection(\"cs\"));"],
        None),
    "text-into-sql": (['var cmd = new SqlCommand("SELECT * FROM t WHERE n = " + q.Trim(), new SqlConnection("cs"));'],
                      "CWE-89"),
}

# Shapes this frontend does not lower yet: name -> (lines, expected CWE or None, why it is missed).
# Each is a strict xfail, so fixing one makes CI ask for its entry to be moved to CS_SHAPES.
OUT_OF_SCOPE: dict = {}


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


@pytest.mark.parametrize("case", list(CS_SHAPES))
def test_csharp_shapes(case):
    lines, cwe = CS_SHAPES[case]
    found = _scan(_cs(lines))
    assert (cwe in found) if cwe else not found, found


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


# -- Razor control flow and markup inside code -------------------------------------------------

RAZOR_PAGES = {
    # `@foreach` is a loop over its collection: the loop variable holds its elements
    "foreach": ('@page\n@{\n    var q = Context.Request.Query["q"];\n}\n@foreach (var item in q)\n{\n'
                '    <p>@Html.Raw(item)</p>\n}\n', [(7, "CWE-79")]),
    "foreach-over-a-split": ('@{\n    var q = Request.Query["q"].ToString();\n}\n@foreach (var part in q.Split(\',\'))\n'
                             '{\n    <li>@Html.Raw(part)</li>\n}\n', [(6, "CWE-79")]),
    "foreach-encoded": ('@{\n    var q = Request.Query["q"].ToString();\n}\n@foreach (var part in q.Split(\',\'))\n'
                        '{\n    <li>@part</li>\n}\n', []),
    # `@if` guards the markup inside it, written on one line or over several, with its `else`
    "if-guard-on-one-line": ('@using System.Text.RegularExpressions\n@{ var q = Request.Query["q"].ToString(); }\n'
                             '@if (Regex.IsMatch(q, "^[a-z]+$")) { @Html.Raw(q) }\n', []),
    "if-without-a-guard-on-one-line": ('@{ var q = Request.Query["q"].ToString(); }\n'
                                       '@if (q.Length > 2) { @Html.Raw(q) }\n', [(2, "CWE-79")]),
    "if-guard-in-a-code-block": ('@using System.Text.RegularExpressions\n@{\n var q = Request.Query["q"].ToString();\n'
                                 ' if (Regex.IsMatch(q, "^[a-z]+$")) {\n  <b>@Html.Raw(q)</b>\n }\n}\n', []),
    "else-branch": ('@{ var q = Request.Query["q"].ToString(); }\n@if (q == "a") {\n <p>a</p>\n} else {\n'
                    ' <p>@Html.Raw(q)</p>\n}\n', [(5, "CWE-79")]),
    # markup written inside a code block is markup (it used to be emitted as C# text and lost)
    "markup-in-a-code-block": ('@{\n    var q = Request.Query["q"].ToString();\n    <div>@Html.Raw(q)</div>\n}\n',
                               [(3, "CWE-79")]),
    "markup-in-a-code-block-encoded": ('@{\n    var q = Request.Query["q"].ToString();\n    <div>@q</div>\n}\n', []),
    "text-line-in-a-code-block": ('@{ var q = Request.Query["q"].ToString();\n  @:Hello @Html.Raw(q)\n}\n',
                                  [(2, "CWE-79")]),
    "comment-and-email": ('@* @Html.Raw(Request.Query["q"]) *@\n<p>me@example.com</p>\n', []),
    "section": ('@section Scripts {\n<script>var x = "@Html.Raw(Request.Query["q"])";</script>\n}\n', [(2, "CWE-79")]),
    "switch-section-markup": ('@{ var n = Request.Query["q"].ToString(); }\n@switch (n.Length) {\n case 1:\n'
                              '  <p>@Html.Raw(n)</p>\n  break;\n}\n', [(4, "CWE-79")]),
    "using-block": ('@using (Html.BeginForm()) {\n  <input value="@Html.Raw(Request.Query["q"])" />\n}\n',
                    [(2, "CWE-79")]),
}


@pytest.mark.parametrize("page", list(RAZOR_PAGES))
def test_razor_control_flow_and_markup(page):
    text, expected = RAZOR_PAGES[page]
    r = FrameScanner(language="razor", verify=False, llm_detect=False).scan(text, "Index.cshtml")
    assert not r.errors, r.errors
    assert sorted((v.line, v.cwe_id) for v in r.vulnerabilities) == expected


# -- what only a whole file shows ---------------------------------------------------------------

FILE = """using System;
using System.Diagnostics;
using System.IO;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
namespace App {
public static class Ext { public static void Shell(this string s) { Process.Start("sh", "-c " + s); } }
public static class Helpers { public static void Run(string s) { Process.Start("sh", "-c " + s); } }
[ApiController]
public class C : ControllerBase {
    [HttpGet("x")]
    public IActionResult X([FromQuery] string q, [FromQuery] int id, [FromQuery] Guid g, IFormFile file) {
{body}
        return Ok();
    }
#if DEBUG
    [HttpGet("debug")]
    public IActionResult Debug([FromQuery] string q) { Process.Start("sh", "-c " + {debug}); return Ok(); }
#endif
}}
"""


def _file(body, debug='"ls"'):
    return FILE.replace("{body}", body).replace("{debug}", debug)


@pytest.mark.parametrize("body, cwe", [
    ("Helpers.Run(q);", "CWE-78"),                    # a static helper of this file
    ('Helpers.Run("ls");', None),
    ("q.Shell();", "CWE-78"),                         # an extension method of this file
    ('"ls".Shell();', None),
    ('var cmd = new SqlCommand("SELECT * FROM t WHERE n = " + id, new SqlConnection("cs"));', None),
    ("var cmd = new SqlCommand(\"SELECT * FROM t WHERE n = '\" + g + \"'\", new SqlConnection(\"cs\"));", None),
    ("var cmd = new SqlCommand(\"SELECT * FROM t WHERE n = '\" + q + \"'\", new SqlConnection(\"cs\"));", "CWE-89"),
    ("using var r = new StreamReader(file.OpenReadStream());", None),   # a stream, not a path
    # an uploaded file's contents are the client's: read through a StreamReader they still are
    ("using var r = new StreamReader(file.OpenReadStream());\nProcess.Start(\"sh\", \"-c \" + r.ReadToEnd());", "CWE-78"),
    ("using var r = new StreamReader(Request.Body);\nProcess.Start(\"sh\", \"-c \" + r.ReadLine());", "CWE-78"),
])
def test_csharp_file_shapes(body, cwe):
    found = _scan(_file(body))
    assert (cwe in found) if cwe else not found, found


def test_class_level_preprocessor_arms_declare_their_members():
    assert "CWE-78" in _scan(_file("", debug="q"))
    assert "CWE-78" not in _scan(_file(""))


def test_an_element_read_indexes_by_its_subscript():
    program = CSharpFrontend().translate(_cs(["var v = _items[q];"]).replace(
        "private string _last;", "private string _last;\n    private Dictionary<string, string> _items;"), "App.cs")
    proc = next(p for p in program.procedures.values() if p.name.endswith("C.X"))
    reads = [i.exp for n in proc.nodes.values() for i in n.instrs
             if type(i).__name__ == "Assign" and str(i.id) == "v"]
    assert reads and type(reads[0]).__name__ == "ExpIndex" and str(reads[0].index) == "q"
