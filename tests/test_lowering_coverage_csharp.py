"""No C# syntax silently loses data on its way to SIL (the class of bug behind GitHub issue #9).

The C# frontend lowers each expression node it knows; anything else falls back to a variable named
by the node's source text, so whatever data the node carried is lost without a trace (`q!`,
`o as string`, `new(sql, conn)`, a chained assignment, a switch expression and a tuple were all
lowered that way), and a statement kind it does not know is lowered only through its children.
Both are recorded (`Program.unlowered_syntax`: the node type, or `statement:<type>` /
`target:<type>`); a syntax zoo of everyday forms must reach the fallback only with node types
that carry no data. A new construct, or a refactor that breaks one, fails here instead of quietly
costing findings.
"""

from frame.sil.frontends.csharp_frontend import CSharpFrontend

# Node types that may reach the fallback: they carry no data a finding could depend on.
CS_ALLOWED = {
    "boolean_literal",      # `true` / `false` (deliberately not constants yet: see test_metamorphic_csharp)
    "comment",
}

CS_ZOO = '''
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
namespace Zoo {
public record Point(int X, int Y);
public class Box { public string Val; public Box(string v) { Val = v; } }
public class C {
    private string _f;
    private readonly List<string> _items = new();
    public string Name => _f.Trim();
    public string Other { get => _f; set => _f = value; }
    public C(string f) => _f = f;
    public void Run(string cmd) => Process.Start("sh", cmd);
    public object M(string q, object o, int n, Point p, string[] args) {
        string a, b;
        a = b = q;
        var s1 = q + "x";
        s1 += q;
        s1 ??= q;
        var s2 = q!;
        var s3 = o as string;
        var s4 = (string)o;
        var s5 = q ?? "x";
        var s6 = q != null ? q : "x";
        var s7 = q?.Trim();
        var s8 = q?.Trim()?.ToLower();
        var s9 = q.Trim().ToLower();
        var s10 = $"{q}:{n}";
        var s11 = new StringBuilder().Append(q).ToString();
        var s12 = n switch { 0 => "none", 1 => q, _ => "many" };
        var s13 = o switch { string t => t, Box { Val: var v } => v, _ => "" };
        var s14 = new[] { q, "x" };
        var s15 = new string[] { q };
        string[] s16 = { q };
        var s17 = new List<string> { q };
        var s18 = new Dictionary<string, string> { ["k"] = q, { "j", q } };
        var s19 = new { Name = q, Count = n };
        var s20 = (q, 1);
        var (d1, d2) = (q, "x");
        (a, b) = (b, a);
        (var d3, string d4) = (q, q);
        var s21 = p with { X = n };
        var s22 = from x in args where x != null select x.Trim();
        var s23 = default(string);
        var s24 = typeof(string);
        var s25 = nameof(q);
        var s26 = checked(n + 1);
        var s27 = q[1..^1];
        var s28 = args?[0];
        var s29 = q is string;
        var s30 = """raw""";
        var s31 = await System.Threading.Tasks.Task.FromResult(q);
        Box s32 = new(q);
        Box s33 = new(q) { Val = q };
        Func<string, string> f1 = x => x.Trim();
        Func<string, string> f2 = delegate (string x) { return x; };
        int i = 0;
        i++;
        --i;
        var k = i++;
        if (o is string os && os.Length > 0) { _f = os; }
        if (o is not null) { }
        if (o is > 5 and < 10) { }
        if ((a = q) != null) { }
        foreach (var (fk, fv) in s18) { }
        foreach (var item in s17) { }
        for (int x = 0, y = 0; x < n; x++, y++) { }
        while (i < n) { i++; }
        do { i--; } while (i > 0);
        switch (o) { case string cs when cs.Length > 0: break; case int ci: break; default: break; }
        try { Run(q); } catch (Exception e) when (e.Message != null) { } finally { }
        lock (this) { Run(q); }
        checked { i++; }
        unchecked { i--; }
        using (var sb = new StringBuilder()) { }
        using (Run2(q)) { }
        L: Run(q);
#if DEBUG
        Run(q);
#endif
        this._f = q;
        _items.Add(q);
        Run(q ?? throw new ArgumentNullException(nameof(q)));
        return Ok(new { q });
    }
    private IDisposable Run2(string s) => null;
    private object Ok(object o) => o;
    private IEnumerable<string> Each(string s) { yield return s; yield break; }
}}
'''


def test_csharp_zoo_lowers_every_data_carrying_node():
    program = CSharpFrontend().translate(CS_ZOO, "Zoo.cs")
    unexpected = {k: n for k, n in (program.unlowered_syntax or {}).items() if k not in CS_ALLOWED}
    assert not unexpected, f"node types lowered as their source text: {unexpected}"


def test_the_fallback_is_recorded():
    # The tripwire itself: a construct the frontend does not lower must show up.
    program = CSharpFrontend().translate("class C { void M(bool q) { var x = true; } }", "t.cs")
    assert "boolean_literal" in (program.unlowered_syntax or {})
