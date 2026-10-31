"""C# pack rules match the values a call is made on: the receiver's declared type, a member the
class inherits from a library base (`Request`, `PhysicalFile` in a `Controller`), a project class's
library base (`AppDb : DbContext`, also declared in another file), never a member's name alone."""

import pytest

from frame.sil.frontends.csharp_frontend import CSharpFrontend
from frame.sil.metadata import _wildcard_types
from frame.sil.scanner import FrameScanner


def _ids(code):
    p = CSharpFrontend().translate(code, "c.cs")
    return {i.get_full_name(): i.canonical for pr in p.procedures.values() for n in pr.nodes.values()
            for i in n.instrs if type(i).__name__ == "Call"}


def test_inherited_members_are_the_base_classes():
    ids = _ids("using Microsoft.AspNetCore.Mvc;\nnamespace N {\npublic class B : Controller { }\n"
               "public class C : B {\n  public IActionResult A(string q) { var f = Request.ReadFormAsync();\n"
               "    Helper(q); return PhysicalFile(q, \"text/plain\"); }\n  void Helper(string s) { }\n}}\n")
    assert ids["Request.ReadFormAsync"] == "Microsoft.AspNetCore.Mvc.Controller.Request.ReadFormAsync"
    assert ids["PhysicalFile"] == "Microsoft.AspNetCore.Mvc.Controller.PhysicalFile"
    assert ids["Helper"] == "N.C.Helper"                          # the class's own method


def test_a_property_is_a_declared_member():
    ids = _ids("using Microsoft.AspNetCore.Components;\npublic class S : ComponentBase {\n"
               "  [Inject] private NavigationManager Navigation { get; set; }\n"
               "  void Go(string u) { Navigation.NavigateTo(u); }\n}\n")
    assert ids["Navigation.NavigateTo"] == "Microsoft.AspNetCore.Components.NavigationManager.NavigateTo"


def test_a_static_member_chain_on_a_type():
    ids = _ids("using System.Text.Encodings.Web;\npublic class S { string E(string x) { return HtmlEncoder.Default.Encode(x); } }\n")
    assert ids["HtmlEncoder.Default.Encode"] == "System.Text.Encodings.Web.HtmlEncoder.Default.Encode"


EF = ("using System.Linq;\nusing Microsoft.AspNetCore.Mvc;\nusing Microsoft.EntityFrameworkCore;\nnamespace Shop {\n"
      "public class P { }\n{ctx}\n[ApiController]\npublic class C : ControllerBase {\n  private readonly AppDb _db;\n"
      "  public C(AppDb db) { _db = db; }\n  [HttpGet(\"x\")]\n  public IActionResult X([FromQuery] string m) {\n"
      "    return Ok(_db.Database.SqlQueryRaw<P>(\"SELECT * FROM P WHERE m = '\" + m + \"'\").ToList());\n  }\n}}\n")


@pytest.mark.parametrize("ctx, flagged", [
    ("public class AppDb : DbContext { }", True),
    ("public class AppDb { public Fake Database { get; set; } }", False),     # its own `Database`
    ("", False),                                                               # no evidence of what it is
])
def test_a_project_context_is_its_library_base(ctx, flagged):
    found = {v.cwe_id for v in FrameScanner(language="csharp", verify=False).scan(EF.replace("{ctx}", ctx), "c.cs").vulnerabilities}
    assert ("CWE-89" in found) == flagged


def test_the_base_may_be_declared_in_another_file(tmp_path):
    (tmp_path / "AppDb.cs").write_text("using Microsoft.EntityFrameworkCore;\nnamespace Shop {\n"
                                       "public class AppDb : DbContext { }\n}\n")
    (tmp_path / "C.cs").write_text(EF.replace("{ctx}", ""))
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    assert "CWE-89" in {v.cwe_id for r in results for v in r.vulnerabilities}


def test_namespace_types_are_data():
    table = _wildcard_types()
    assert "SqlConnection" in table["csharp"]["Microsoft.Data.SqlClient"] and "Connection" in table["java"]["java.sql"]
