"""The disjunctive join keeps a branch guard alive across an inner if/else.

The main walk re-analyses a join node when taint changes there. Before, the
merged state dropped the whole path condition at every join, so the second
analysis saw a sink under `a > 5` and then `a < 3` as reachable: an infeasible
path reported as a finding. The join now keeps `shared & (rest1 | rest2)`, so
the outer `a > 5` survives and the infeasible-path filter drops it. The
feasible variant (`a > 7`) must still be reported. The taint enters in the
branch analysed SECOND, which is what forces the re-analysis.
"""

import pytest

from frame.sil.scanner import FrameScanner


def python_src(cond):
    return f"""import os
from flask import request
def f(a, b):
    q = request.args.get('q')
    if a > 5:
        if b:
            x = "safe"
        else:
            x = q
        if {cond}:
            os.system(x)
"""


def javascript_src(cond):
    return f"""const cp = require('child_process');
app.get('/x', (req, res) => {{
  const q = req.query.q; const a = Number(req.query.a); const b = req.query.b;
  let x;
  if (a > 5) {{
    if (b) {{ x = "safe"; }} else {{ x = q; }}
    if ({cond}) {{ cp.exec(x); }}
  }}
}});
"""


def java_src(cond):
    return f"""import javax.servlet.http.*;
public class T extends HttpServlet {{
  public void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {{
    String q = req.getParameter("q"); int a = Integer.parseInt(req.getParameter("a"));
    boolean b = q.isEmpty();
    String x;
    if (a > 5) {{
      if (b) {{ x = "safe"; }} else {{ x = q; }}
      if ({cond}) {{ Runtime.getRuntime().exec(x); }}
    }}
  }}
}}
"""


def csharp_src(cond):
    return f"""using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
public class T : Controller {{
  public void Run(string q, int a, bool b) {{
    string x;
    if (a > 5) {{
      if (b) {{ x = "safe"; }} else {{ x = Request.Query["q"]; }}
      if ({cond}) {{ Process.Start("sh", x); }}
    }}
  }}
}}
"""


CASES = [("python", python_src, "t.py"), ("javascript", javascript_src, "t.js"),
         ("java", java_src, "T.java"), ("csharp", csharp_src, "T.cs")]


def command_injections(lang, src, name):
    r = FrameScanner(language=lang, verify=False).scan(src, name)
    assert not r.errors, r.errors
    return [v for v in r.vulnerabilities if v.cwe_id == "CWE-78"]


@pytest.mark.parametrize("lang, make, name", CASES)
def test_sink_on_a_path_the_outer_guard_rules_out_is_dropped(lang, make, name):
    assert not command_injections(lang, make("a < 3"), name)


@pytest.mark.parametrize("lang, make, name", CASES)
def test_sink_on_a_feasible_path_is_still_reported(lang, make, name):
    assert command_injections(lang, make("a > 7"), name)


def _salt_runas_src():
    # salt modules/archive.py: the sink is reachable with runas falsy (second
    # `if` not taken). The walk used to reach it first along the impossible
    # path "runas falsy, then `if runas and ...` taken"; the feasible path
    # arrived later with identical taint and was never analysed.
    return """import os
from flask import request
def unzip(dest, runas, euid, uid):
    target = request.args.get('t')
    if runas:
        euid = 1
        if not uid:
            return 1
    if runas and euid != uid:
        os.seteuid(uid)
    for x in [1, 2]:
        if x:
            os.symlink(target, os.path.join(dest, target))
"""


def test_finding_reachable_only_on_the_later_feasible_path_is_kept():
    r = FrameScanner(language="python", verify=False).scan(_salt_runas_src(), "t.py")
    assert any(v.line == 13 for v in r.vulnerabilities), [(v.cwe_id, v.line) for v in r.vulnerabilities]


def test_walk_does_not_follow_an_edge_the_solver_rules_out(monkeypatch):
    from frame.sil.translator import SILTranslator
    taken = []
    orig = SILTranslator._edge_feasible

    def spy(self, pc, guard):
        ok = orig(self, pc, guard)
        taken.append((str(guard), ok))
        return ok
    monkeypatch.setattr(SILTranslator, "_edge_feasible", spy)
    FrameScanner(language="python", verify=False).scan(python_src("a < 3"), "t.py")
    assert ("a < 3", False) in taken, taken
