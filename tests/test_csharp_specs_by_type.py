"""C# sources and sinks are found through the receiver's declared type and its documented supertypes,
an inherited member, an extension method the file's usings bring in, or a namespace-qualified class;
a variable's name or a bare method name finds at most a propagator or sanitizer."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.specs.dotnet_api import load

HEAD = ("using System.Data.SqlClient;\nusing Microsoft.AspNetCore.Mvc;\nusing Microsoft.EntityFrameworkCore;\n"
        "using Microsoft.Extensions.Logging;\n")


def _found(body, members="", base=" : ControllerBase"):
    code = HEAD + ("public class C%s {\n%s\n  public IActionResult A([FromQuery] string q) {\n    %s\n    return Ok();\n  }\n}\n"
                   % (base, members, body))
    return {v.cwe_id for v in FrameScanner(language="csharp", verify=False).scan(code, "C.cs").vulnerabilities}


@pytest.mark.parametrize("members, body, cwe", [
    ("  private SqlConnection _conn;", 'var cmd = new SqlCommand("SELECT * FROM t WHERE n = \'" + q + "\'", _conn);\n    cmd.ExecuteReader();', "CWE-89"),
    ("  private SqlConnection _conn;", 'var cmd = _conn.CreateCommand();\n    cmd.CommandText = "SELECT " + q;', "CWE-89"),
    ("  private DbContext _db;", '_db.Database.ExecuteSqlRaw("DELETE FROM t WHERE n = \'" + q + "\'");', "CWE-89"),
    ("  private ILogger<C> _logger;", '_logger.LogInformation("user " + q);', "CWE-117"),
    ("", 'System.IO.File.ReadAllText("/srv/" + q);', "CWE-22"),
    ("", 'Redirect(q);', "CWE-601"),
])
def test_found_through_types_inheritance_extensions_and_namespaces(members, body, cwe):
    assert cwe in _found(body, members)


@pytest.mark.parametrize("members, body, cwe", [
    ("  private Form cmd;", 'cmd.ExecuteReader("SELECT " + q);', "CWE-89"),          # a variable named cmd
    ("  private Widget logger;", 'logger.LogInformation(q);', "CWE-117"),              # a variable named logger
    ("  private Report r;", 'r.CommandText = "SELECT " + q;', "CWE-89"),               # CommandText of something else
])
def test_names_alone_make_no_sink(members, body, cwe):
    assert cwe not in _found(body, members)


def test_an_own_method_named_like_a_controller_helper_is_not_the_library_s():
    members = "  public IActionResult Redirect(string u) { return Ok(); }"
    assert "CWE-601" not in _found("Redirect(q);", members)


def test_the_type_facts_are_data():
    d = load()
    assert d.lineage("NpgsqlCommand") == ("NpgsqlCommand", "DbCommand", "IDbCommand")
    assert d.extension_methods["Microsoft.EntityFrameworkCore"]["FromSqlRaw"] == "RelationalQueryableExtensions"
    assert d.typed_sink("SqlCommand", "CommandText").kind == "sql"


# --- member-path sources by type -------------------------------------------------------------------

def _cmd(src):
    return "CWE-78" in {v.cwe_id for v in FrameScanner(language="csharp", verify=False).scan(src, "C.cs").vulnerabilities}


@pytest.mark.parametrize("cls, read, flagged", [
    (": Controller", 'Request.Query["c"]', True),                  # the controller's inherited Request
    (": Controller", 'HttpContext.Request.Query["c"]', True),
    ("", 'Request.Query["c"]', False),                              # no such member: not a request
    ("", 'new Holder().Request.Query["c"]', False),                 # a member named Request of something else
])
def test_request_reads_by_the_members_types(cls, read, flagged):
    src = ("using System.Diagnostics;\nusing Microsoft.AspNetCore.Mvc;\n"
           "public class Holder { public Bag Request { get; set; } }\n"
           f"public class C {cls} {{\n  public void A() {{ Process.Start(\"sh\", \"-c \" + {read}); }}\n}}\n")
    assert _cmd(src) == flagged


def test_a_control_declared_in_another_part_of_the_partial_class(tmp_path):
    (tmp_path / "Upload.aspx.designer.cs").write_text(
        "namespace Site {\n  public partial class Upload {\n"
        "    protected global::System.Web.UI.WebControls.FileUpload uploadFile;\n  }\n}\n")
    page = tmp_path / "Upload.aspx.cs"
    page.write_text("using System.Diagnostics;\nusing System.Web.UI;\nnamespace Site {\n"
                    "  public partial class Upload : Page {\n    protected void Go(object s, System.EventArgs e) {\n"
                    "      Process.Start(\"sh\", \"-c \" + uploadFile.PostedFile.FileName);\n    }\n  }\n}\n")
    found = {v.cwe_id for v in FrameScanner(language="csharp", verify=False).scan_file(str(page)).vulnerabilities}
    assert "CWE-78" in found
