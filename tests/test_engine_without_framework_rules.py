"""Framework and benchmark knowledge lives in packs and in the project, never in the engine.

- ASP.NET controllers are found by the conventions the framework documents (packs/data/csharp),
  not by a class name containing "Controller"/"Handler" in the frontend.
- A Java `Properties` value read from a classpath resource is the resource's value (as
  `Properties.load` parses it), not a guess from the key's name.
- A URL host compared against a literal list is an allowlist; a substring test is not.
"""

from frame.sil.frontends._java_properties import parse, resource
from frame.sil.scanner import FrameScanner


def _scan(language, src, name):
    return sorted((v.line, v.cwe_id) for v in FrameScanner(language=language, verify=False).scan(src, name).vulnerabilities)


ASPNET_CORE = """using Microsoft.AspNetCore.Mvc;
public class OrdersController {
  public OrdersController(string db) { System.Diagnostics.Process.Start(db); }
  public IActionResult Find(string q) { System.Diagnostics.Process.Start(q); return null; }
  [NonAction] public void Helper(string h) { System.Diagnostics.Process.Start(h); }
  private void Inner(string i) { System.Diagnostics.Process.Start(i); }
  public static void Util(string u) { System.Diagnostics.Process.Start(u); }
}
public class OrdersHandler {
  public void Find(string q) { System.Diagnostics.Process.Start(q); }
}
"""


def test_conventional_controller_actions_only():
    # the action; not the constructor, [NonAction], private or static methods, nor a class that
    # merely has "Handler" in its name
    assert _scan("csharp", ASPNET_CORE, "OrdersController.cs") == [(4, "CWE-78")]


def test_asmx_web_method_and_websocket_message():
    src = """using System.Web;
using System.Web.Services;
using Microsoft.Web.WebSockets;
public class Svc : System.Web.Services.WebService {
  [WebMethod] public string Read(string f) { return System.IO.File.ReadAllText(f); }
  public string NotExposed(string f) { return System.IO.File.ReadAllText(f); }
}
public class Ws : WebSocketHandler {
  public override void OnMessage(string m) { System.Diagnostics.Process.Start(m); }
}
"""
    assert _scan("csharp", src, "Svc.cs") == [(5, "CWE-22"), (9, "CWE-78")]


def test_properties_format():
    text = "# c\n! c\na=1\nb : two \\\n   parts\nc\\=d=e\n  f   g\nu=\\u0041\\t\n"
    assert parse(text) == {"a": "1", "b": "two parts", "c=d": "e", "f": "g", "u": "A\t"}


JAVA = """import java.security.MessageDigest;
import java.util.Properties;
public class T {
  public void h() throws Exception {
    Properties p = new Properties();
    p.load(T.class.getClassLoader().getResourceAsStream("app.properties"));
    String alg = p.getProperty("hashAlg", "SHA-256");
    MessageDigest md = MessageDigest.getInstance(alg);
  }
}
"""


def test_algorithm_from_the_projects_properties(tmp_path):
    res = tmp_path / "src" / "main" / "resources"
    res.mkdir(parents=True)
    src = tmp_path / "src" / "main" / "java" / "T.java"
    src.parent.mkdir(parents=True)
    src.write_text(JAVA)
    (tmp_path / ".git").mkdir()
    assert resource(str(src), "app.properties") is None
    assert _scan("java", JAVA, str(src)) == []                         # default SHA-256
    (res / "app.properties").write_text("hashAlg=MD5\n")
    assert resource(str(src), "app.properties") == {"hashAlg": "MD5"}
    assert [c for _, c in _scan("java", JAVA, str(src))] == ["CWE-328"]


PY = """from flask import request, redirect
import urllib.parse
def allowed():
    bar = request.args.get("u")
    url = urllib.parse.urlparse(bar)
    if url.netloc not in ["example.com"] or url.scheme != "https":
        return "no"
    return redirect(bar)
def wrong_branch():
    bar = request.args.get("u")
    url = urllib.parse.urlparse(bar)
    if url.netloc in ["example.com"]:
        return "no"
    return redirect(bar)
def substring():
    bar = request.args.get("u")
    if bar in "example.com":
        return redirect(bar)
    return ""
"""


def test_host_allowlist_by_literal_list():
    assert _scan("python", PY, "r.py") == [(14, "CWE-601"), (18, "CWE-601")]
