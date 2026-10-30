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
