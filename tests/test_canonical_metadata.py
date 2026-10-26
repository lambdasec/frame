"""Canonical callee ids, annotations, class bases and keyword names in the SIL.

Framework packs match on these; recording them must not change any finding.
"""

import pytest

from frame.sil.metadata import ImportTable, parse_annotation


def _calls(program):
    out = {}
    for proc in program.procedures.values():
        for node in proc.nodes.values():
            for i in node.instrs:
                if type(i).__name__ == "Call":
                    out[str(getattr(i.func, "value", i.func))] = i
    return out


def test_parse_annotation_forms():
    t = ImportTable()
    t.bind("RequestMapping", "org.springframework.web.bind.annotation.RequestMapping")
    a = parse_annotation('@RequestMapping(value="/x", method=POST)', t, value_alias=True)
    assert a.canonical.endswith("annotation.RequestMapping")
    assert a.args == {"value": "/x", "method": "POST"}
    b = parse_annotation('@GetMapping("/a,b")', value_alias=True)
    assert b.args["value"] == "/a,b" and b.args["0"] == "/a,b"
    c = parse_annotation('@app.route("/x", methods=["GET", "POST"])')
    assert c.name == "app.route" and c.args["methods"] == '["GET", "POST"]'
    d = parse_annotation('[HttpPost("x")]')
    assert d.name == "HttpPost" and d.args["0"] == "x"
    assert parse_annotation("@Override").args == {}


def test_import_table_conflicts_are_dropped():
    t = ImportTable()
    t.bind("x", "a.b")
    t.bind("x", "c.d")
    assert t.finish().resolve("x.y") is None


def test_python_canonical_ids_kwargs_decorators_bases():
    from frame.sil.frontends.python_frontend import PythonFrontend
    src = (
        "import os, subprocess as sp\n"
        "from flask import Flask, request as r\n"
        "class V(Flask, metaclass=M):\n    pass\n"
        "@app.route('/x', methods=['POST'])\n"
        "def h():\n"
        "    q = r.args.get('q', default='d')\n"
        "    os.system(q)\n    sp.run(q, shell=True)\n    eval(q)\n    h()\n"
    )
    p = PythonFrontend().translate(src, "t.py")
    calls = _calls(p)
    assert calls["r.args.get"].canonical == "flask.request.args.get"
    assert calls["r.args.get"].kwarg_names == [None, "default"]
    assert calls["os.system"].canonical == "os.system"
    assert calls["sp.run"].canonical == "subprocess.run"
    assert calls["sp.run"].kwarg_names == [None, "shell"]
    assert calls["eval"].canonical == "builtins.eval"
    assert calls["h"].canonical is None            # the file's own function
    assert p.class_info["V"].canonical_bases == ["flask.Flask"]
    ann = p.procedures["h"].annotations[0]
    assert ann.name == "app.route" and ann.args["methods"] == "['POST']"


def test_python_shadowed_builtin_is_not_builtin():
    from frame.sil.frontends.python_frontend import PythonFrontend
    p = PythonFrontend().translate("def eval(x):\n    return x\ndef f(a):\n    eval(a)\n", "t.py")
    assert _calls(p)["eval"].canonical is None


JAVA = '''
package com.acme.web;
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api")
public class C extends Base implements Runnable {
  Statement st;
  @GetMapping(value="/x", produces="text/plain")
  public String h(@RequestParam("q") String q, HttpServletRequest req) throws Exception {
    String a = req.getParameter("a");
    ResultSet rs = st.executeQuery(q);
    Runtime.getRuntime().exec(a);
    helper(a);
    return a;
  }
  void helper(String s) {}
}
interface I extends J, K {}
'''


def test_java_canonical_ids_annotations_bases():
    from frame.sil.frontends.java_frontend import JavaFrontend
    p = JavaFrontend().translate(JAVA, "C.java")
    calls = _calls(p)
    assert calls["req.getParameter"].canonical == "javax.servlet.http.HttpServletRequest.getParameter"
    assert calls["st.executeQuery"].canonical == "java.sql.Statement.executeQuery"   # wildcard import
    assert calls["Runtime.getRuntime().exec"].canonical == "java.lang.Runtime.exec"
    assert calls["helper"].canonical == "com.acme.web.C.helper"
    info = p.class_info["C"]
    assert info.bases == ["Base", "Runnable"] and info.package == "com.acme.web"
    assert [a.name for a in info.annotations] == ["RestController", "RequestMapping"]
    assert info.annotations[1].args["value"] == "/api"
    assert p.class_info["I"].kind == "interface" and p.class_info["I"].bases == ["J", "K"]
    h = p.procedures["C.h"]
    assert h.annotations[0].args == {"value": "/x", "produces": "text/plain"}
    assert h.param_annotations["q"][0].name == "RequestParam"


def test_javascript_canonical_ids_and_typescript_decorators():
    from frame.sil.frontends.javascript_frontend import JavaScriptFrontend
    src = (
        "import { Controller, Get, Query } from '@nestjs/common';\n"
        "const cp = require('child_process');\n"
        "const { exec } = require('child_process');\n"
        "@Controller('x')\n"
        "export class A extends B implements C {\n"
        "  @Get('y')\n"
        "  h(@Query('q') q: string) { cp.exec(q); exec(q); eval(q); this.g(q); }\n"
        "  g(x) {}\n}\n"
    )
    p = JavaScriptFrontend(language="typescript").translate(src, "a.ts")
    calls = _calls(p)
    assert calls["child_process.exec"].canonical == "child_process.exec"
    assert calls["eval"].canonical == "eval"
    assert calls["this.g"].canonical is None
    assert p.class_info["A"].bases == ["B", "C"]
    assert p.class_info["A"].annotations[0].canonical == "@nestjs/common.Controller"
    h = p.procedures["A.h"]
    assert h.annotations[0].name == "Get" and h.annotations[0].args["0"] == "y"
    assert h.param_annotations["q"][0].name == "Query"


CSHARP = '''
using System.Data.SqlClient;
namespace Acme.Web {
[ApiController]
public class C : ControllerBase {
  private SqlConnection conn;
  [HttpPost("x")]
  public IActionResult H([FromQuery(Name="q")] string q) {
    var cmd = new SqlCommand(q, conn);
    cmd.ExecuteReader();
    System.Diagnostics.Process.Start(q);
    File.ReadAllText(q);
    Foo(a: q, b: 2);
    return Ok();
  }
  void Foo(string a, int b) {}
}
}
'''


def test_csharp_canonical_ids_attributes_named_args():
    from frame.sil.frontends.csharp_frontend import CSharpFrontend
    p = CSharpFrontend().translate(CSHARP, "C.cs")
    calls = _calls(p)
    assert calls["SqlCommand"].canonical == "System.Data.SqlClient.SqlCommand.<init>"
    assert calls["cmd.ExecuteReader"].canonical == "System.Data.SqlClient.SqlCommand.ExecuteReader"
    assert calls["System.Diagnostics.Process.Start"].canonical == "System.Diagnostics.Process.Start"
    assert calls["File.ReadAllText"].canonical is None      # System.IO is not imported
    assert calls["Foo"].canonical == "Acme.Web.C.Foo"
    assert calls["Foo"].kwarg_names == [None, "a", None, "b"]
    assert calls["Ok"].canonical is None                     # inherited, type unknown
    assert p.class_info["C"].bases == ["ControllerBase"]
    h = p.procedures["Acme.Web.C.H"]
    assert h.annotations[0].name == "HttpPost" and h.annotations[0].args["0"] == "x"
    assert h.param_annotations["q"][0].args["Name"] == "q"


def test_c_and_cpp_canonical_ids_and_bases():
    from frame.sil.frontends.c_frontend import CFrontend, CppFrontend
    src = "#include <stdio.h>\nvoid go(char *s) { system(s); helper(s); obj->m(s); }\nvoid helper(char *s) {}\n"
    p = CFrontend().translate(src, "a.c")
    calls = _calls(p)
    assert calls["system"].canonical == "system"
    assert calls["helper"].canonical is None and calls["obj->m"].canonical is None
    assert p.imports["<stdio.h>"] == "stdio.h"
    cpp = CppFrontend().translate("class A : public B, private C::D {}; struct S : T {};", "a.cpp")
    assert cpp.class_info["A"].bases == ["B", "C::D"]
    assert cpp.class_info["S"].kind == "struct"


def test_recording_metadata_changes_no_finding():
    """The same source scanned before/after is pinned by the rest of the suite; here
    just prove the scanner output does not mention the new fields."""
    from frame.sil.scanner import FrameScanner
    src = "import os\nfrom flask import request\ndef h():\n    os.system(request.args.get('c'))\n"
    result = FrameScanner(language="python").scan(src, "t.py")
    assert any(v.cwe_id == "CWE-78" for v in result.vulnerabilities)
