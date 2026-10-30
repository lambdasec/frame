"""Framework and benchmark knowledge lives in packs and in the project, never in the engine.

- ASP.NET controllers are found by the conventions the framework documents (packs/data/csharp),
  not by a class name containing "Controller"/"Handler" in the frontend.
- A Java `Properties` value read from a classpath resource is the resource's value (as
  `Properties.load` parses it), not a guess from the key's name.
- A URL host compared against a literal list is an allowlist; a substring test is not.
"""

import pytest

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


# --- JavaScript: framework conventions are pack / spec data ---------------------------------

from frame.sil.packs.loader import load_pack_file  # noqa: E402


def _js(src, name="app.js", packs=(), builtin=True):
    scanner = FrameScanner(language="javascript", verify=False, packs=[str(p) for p in packs],
                           use_builtin_packs=builtin)
    return sorted((v.line, v.cwe_id) for v in scanner.scan(src, name).vulnerabilities)


def test_fluent_response_and_content_type():
    src = """const express = require('express');
const app = express();
app.get('/a', (req, res) => { res.status(200).send(req.query.q); });
app.get('/b', (req, res) => { res.status(200).type('json').send(req.query.q); });
"""
    assert _js(src) == [(3, "CWE-79")]


def test_without_the_pack_a_chained_send_is_not_resolved(tmp_path):
    src = "app.get('/a', (req, res) => { res.status(200).send(req.query.q); });\n"
    assert _js(src) == [(1, "CWE-79")]
    assert _js(src, builtin=False) == []


def test_a_pack_declares_its_own_fluent_object(tmp_path):
    pack = tmp_path / "acme.toml"
    pack.write_text('[pack]\nname = "acme"\nlanguage = "javascript"\n\n'
                    '[[fluent]]\nroots = ["W"]\nname = "W"\nmethods = ["pick"]\n')
    sinks = tmp_path / "sinks.toml"
    sinks.write_text('[pack]\nname = "acme-sinks"\nlanguage = "javascript"\n\n'
                     '[[sink]]\nname = ["W.html"]\nkind = "html"\n')
    src = ("const express = require('express');\nconst app = express();\n"
           "app.get('/a', (req, res) => { W('#x').pick('li').html(req.query.q); });\n")
    assert _js(src, packs=[pack, sinks]) == [(3, "CWE-79")]
    assert _js(src, packs=[sinks]) == []


def test_json_bodies_and_safe_yaml_schema():
    src = """const express = require('express');
const yaml = require('js-yaml');
const app = express();
app.get('/a', (req, res) => { res.send({ q: req.query.q }); });
app.get('/b', (req, res) => { yaml.load(req.body.y, { schema: yaml.JSON_SCHEMA }); res.end(); });
app.get('/c', (req, res) => { yaml.load(req.body.y); res.end(); });
"""
    assert [c for _, c in _js(src)] == ["CWE-502"]


def test_graphql_args_are_the_second_parameter():
    src = """const { ApolloServer } = require('@apollo/server');
const { exec } = require('child_process');
const resolvers = {
  Query: {
    run(parent, args, ctx) { exec(args.cmd); },
    who(req, args) { exec(req.cmd); },
  },
};
"""
    assert _js(src) == [(5, "CWE-78")]


@pytest.mark.parametrize("body, error", [
    ('[[fluent]]\nmethods = []\n', "methods must not be empty"),
    ('[[fluent]]\nroots = ["$"]\nmethods = ["find"]\n', "roots and name go together"),
    ('[[registration]]\nkeys = ["Query"]\n', "needs registered_as"),
    ('[[entrypoint]]\nmethod = ["*"]\nparams = "all"\nparam_positions = [-1]\n', "param_positions"),
])
def test_new_pack_keys_are_validated(tmp_path, body, error):
    from frame.sil.packs.schema import PackError
    p = tmp_path / "bad.toml"
    p.write_text('[pack]\nname = "bad"\nlanguage = "javascript"\n\n' + body)
    with pytest.raises(PackError, match=error):
        load_pack_file(p)


# --- Python: handlers come from packs, not from a guess -------------------------------------

def _py(src, name="app.py"):
    return sorted((v.line, v.cwe_id) for v in FrameScanner(language="python", verify=False).scan(src, name).vulnerabilities)


def test_flask_route_arguments_and_no_guessed_handlers():
    src = """import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/run/<cmd>")
def run(cmd):
    os.system(cmd)

def helper(cmd):
    request.args.get("x")
    os.system(cmd)
"""
    # `helper` reads the request object but is no handler: its parameter is not attacker data
    assert _py(src) == [(7, "CWE-78")]


def test_django_view_and_graphene_resolver():
    django = """import os
from django.http import HttpResponse

def view(request, name):
    os.system(name)
    return HttpResponse(request.GET["q"], content_type="application/json")

def page(request):
    return HttpResponse(request.GET["q"])
"""
    assert _py(django, "views.py") == [(5, "CWE-78"), (9, "CWE-79")]
    graphene = """import os
import graphene

class Query(graphene.ObjectType):
    def resolve_file(self, info, name):
        os.system(name)
        os.system(info)
"""
    assert _py(graphene, "schema.py") == [(6, "CWE-78")]


def test_celery_delay_runs_the_task(tmp_path):
    (tmp_path / "tasks.py").write_text("import os\n\ndef convert(path):\n    os.system(path)\n")
    (tmp_path / "views.py").write_text("from flask import Flask, request\nfrom . import tasks\napp = Flask(__name__)\n\n"
                                      "@app.post('/c')\ndef c():\n    tasks.convert.delay(request.form['p'])\n    return ''\n")
    (tmp_path / "__init__.py").write_text("")
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    found = {(r.filename.rsplit("/", 1)[-1], v.cwe_id) for r in results for v in r.vulnerabilities}
    assert ("tasks.py", "CWE-78") in found


# --- Java: framework facts are pack entries -------------------------------------------------

def _java(src, name="T.java", builtin=True):
    scanner = FrameScanner(language="java", verify=False, use_builtin_packs=builtin)
    return sorted((v.line, v.cwe_id) for v in scanner.scan(src, name).vulnerabilities)


def test_mybatis_substitution_from_the_pack():
    src = """import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Param;
public interface UserMapper {
  @Select("SELECT * FROM users ORDER BY ${col}")
  java.util.List<Object> sorted(@Param("col") String column);
  @Select("SELECT * FROM users WHERE id = #{id}")
  Object byId(@Param("id") String id);
}
"""
    procs = {p.name: p for p in __import__("frame.sil.frontends.java_frontend", fromlist=["x"])
             .JavaFrontend().translate(src, "UserMapper.java").procedures.values()}
    assert "UserMapper.sorted" in procs and "UserMapper.byId" not in procs


COOKIES = """import javax.servlet.http.*;
public class C extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
    Cookie a = new Cookie("a", "1");
    a.setSecure(true);
    a.setHttpOnly(true);
    resp.addCookie(a);
    Cookie b = new Cookie("b", "1");
    b.setSecure(true);
    resp.addCookie(b);
  }
}
"""


def test_servlet_cookie_flags():
    assert _java(COOKIES, "C.java") == [(10, "CWE-1004")]
    assert _java(COOKIES, "C.java", builtin=False) == []


def test_spring_redirect_and_view_name():
    src = """import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
@Controller
public class W {
  @GetMapping("/go")
  public String go(@RequestParam String url) { return "redirect:" + url; }
  @GetMapping("/view")
  public String view(@RequestParam String name) { return "pages/" + name; }
  @GetMapping("/body")
  @ResponseBody
  public String body(@RequestParam String name) { return "pages/" + name; }
}
"""
    # redirect view; view name; not the @ResponseBody handler's body
    assert _java(src, "W.java") == [(6, "CWE-601"), (8, "CWE-1336")]
    assert _java(src, "W.java", builtin=False) == []


# --- C#: ASP.NET conventions are pack entries, .NET facts are data ---------------------------

def _cs(src, name="C.cs", builtin=True):
    scanner = FrameScanner(language="csharp", verify=False, use_builtin_packs=builtin)
    return sorted((v.line, v.cwe_id) for v in scanner.scan(src, name).vulnerabilities)


ASPNET_COOKIES = """using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
public class HomeController : Controller {
  public IActionResult A() {
    Response.Cookies.Append("a", "1", new CookieOptions { Secure = false });
    var o = new CookieOptions { HttpOnly = true, Secure = true };
    Response.Cookies.Append("b", "1", o);
    return Ok();
  }
}
"""


def test_aspnet_cookie_off_switches_come_from_the_pack():
    assert [c for _, c in _cs(ASPNET_COOKIES, "HomeController.cs")] == ["CWE-614"]
    assert _cs(ASPNET_COOKIES, "HomeController.cs", builtin=False) == []


def test_islocalurl_and_content_type():
    src = """using Microsoft.AspNetCore.Mvc;
public class GoController : Controller {
  public IActionResult Go(string url) {
    if (Url.IsLocalUrl(url)) { return Redirect(url); }
    return Redirect("/");
  }
  public IActionResult Echo(string q) { return Content(q, "application/json"); }
  public IActionResult Page(string q) { return Content(q, "text/html"); }
}
"""
    assert _cs(src, "GoController.cs") == [(8, "CWE-79")]


# --- translator: pack kinds and spec fields instead of framework lists ----------------------

def test_flask_abort_ends_the_path_through_the_pack():
    src = """import os
from flask import Flask, request, abort
app = Flask(__name__)

@app.route("/x")
def x():
    cmd = request.args.get("c")
    if cmd not in ("ls", "pwd"):
        abort(403)
    os.system(cmd)
    return ""
"""
    assert _py(src) == []


def test_cookie_sink_only_with_an_explicit_false():
    src = """from flask import Flask, make_response
app = Flask(__name__)

@app.route("/a")
def a():
    r = make_response("x")
    r.set_cookie("s", "1", secure=False)
    r.set_cookie("t", "1", secure=True)
    return r
"""
    assert _py(src) == [(7, "CWE-614")]


def test_c_header_writer_from_a_pack():
    src = """#include <stdlib.h>
#include <microhttpd.h>
void f(struct MHD_Response *r) {
    int t = rand();
    MHD_add_response_header(r, "Set-Cookie", t);
}
"""
    def scan(builtin):
        s = FrameScanner(language="c", verify=False, use_builtin_packs=builtin)
        return sorted((v.line, v.cwe_id) for v in s.scan(src, "s.c").vulnerabilities)
    assert scan(True) == [(5, "CWE-338")]      # c/libmicrohttpd says the call writes headers
    assert scan(False) == []
