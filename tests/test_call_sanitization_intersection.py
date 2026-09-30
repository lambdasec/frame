"""
A call result is sanitized for a sink kind only if EVERY tainted input to the
call was.

The translator used to give a call's result the UNION of the sanitized kinds of
its tainted inputs, so one sanitized argument laundered the raw ones beside it:
``open(os.path.join(os.path.basename(p), q))`` with both ``p`` and ``q``
user-controlled reported nothing, although ``q`` reaches ``open`` unchecked.
These tests pin the intersection rule end to end, together with the negatives
that keep it from over-reporting: a sanitizer on the only tainted input still
clears its kind, and a sanitized input joined with a constant stays clean.
"""

from frame.sil import FrameScanner


def _cwes(src, language, filename):
    result = FrameScanner(language=language, verify=False).scan(src, filename)
    return {v.cwe_id for v in result.vulnerabilities}


# =============================================================================
# Python: CWE-22 through os.path.join (callee has a propagator spec)
# =============================================================================

_PY = '''import os
from flask import request

def handler():
    p = request.args.get("p")
    q = request.args.get("q")
    return open(%s).read()
'''


def _py(expr):
    return _cwes(_PY % expr, "python", "t.py")


def test_python_raw_join_is_reported():
    # Control: two raw inputs joined into a path.
    assert "CWE-22" in _py("os.path.join(p, q)")


def test_python_sanitized_input_does_not_launder_raw_sibling():
    # basename(p) is safe, q is not: the joined path is still attacker-controlled.
    assert "CWE-22" in _py("os.path.join(os.path.basename(p), q)")


def test_python_sanitized_input_joined_with_constant_is_clean():
    assert "CWE-22" not in _py('os.path.join(os.path.basename(p), "x")')


def test_python_sanitizer_on_only_tainted_input_clears_kind():
    assert "CWE-22" not in _py("os.path.basename(p)")


def test_python_reassigned_target_does_not_keep_its_own_stale_sanitization():
    # The call's result overwrites q; q's old (raw) value is one of its inputs,
    # so the sanitized basename(p) beside it must not launder it.
    src = '''import os
from flask import request

def handler():
    p = request.args.get("p")
    q = request.args.get("q")
    q = os.path.join(q, os.path.basename(p))
    return open(q).read()
'''
    assert "CWE-22" in _cwes(src, "python", "t.py")


# =============================================================================
# JavaScript: CWE-89 through an unresolved helper (callee has no spec)
# =============================================================================

_JS = '''const mysql = require("mysql");
app.get("/f", (req, res) => {
  const a = req.query.a;
  const b = req.query.b;
  const s = mysql.escape(a);
  const q = buildQuery(%s);
  connection.query(q);
});
'''


def _js(args):
    return _cwes(_JS % args, "javascript", "t.js")


def test_js_raw_helper_call_is_reported():
    assert "CWE-89" in _js("a, b")


def test_js_escaped_input_does_not_launder_raw_sibling():
    assert "CWE-89" in _js("s, b")


def test_js_escaped_input_with_constant_is_clean():
    assert "CWE-89" not in _js('s, "x"')


def test_js_escaped_only_input_is_clean():
    assert "CWE-89" not in _js("s")


# =============================================================================
# Java: CWE-79 through an unresolved helper (callee has no spec)
# =============================================================================

_JAVA = '''import javax.servlet.http.*;
import org.owasp.esapi.ESAPI;
public class T extends HttpServlet {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String a = request.getParameter("a");
    String b = request.getParameter("b");
    String s = ESAPI.encoder().encodeForHTML(a);
    String t = ESAPI.encoder().encodeForHTML(b);
    String out = helper(%s);
    response.getWriter().println(out);
  }
}
'''


def _java(args):
    return _cwes(_JAVA % args, "java", "T.java")


def test_java_encoded_input_does_not_launder_raw_sibling():
    assert "CWE-79" in _java("s, b")


def test_java_all_inputs_encoded_is_clean():
    assert "CWE-79" not in _java("s, t")


# =============================================================================
# C#: CWE-79 through string.Concat
# =============================================================================

_CS = '''using System.Web;
public class C : System.Web.UI.Page {
  protected void Page_Load(object sender, System.EventArgs e) {
    string a = Request.QueryString["a"];
    string b = Request.QueryString["b"];
    string s = HttpUtility.HtmlEncode(a);
    string t = HttpUtility.HtmlEncode(b);
    string o = string.Concat(%s);
    Response.Write(o);
  }
}
'''


def _cs(args):
    return _cwes(_CS % args, "csharp", "C.cs")


def test_csharp_encoded_input_does_not_launder_raw_sibling():
    assert "CWE-79" in _cs("s, b")


def test_csharp_all_inputs_encoded_is_clean():
    assert "CWE-79" not in _cs("s, t")
