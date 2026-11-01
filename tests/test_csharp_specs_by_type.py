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
