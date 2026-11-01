"""ASP.NET Core hosting facts by value, never by name: a lambda's parameters typed by the delegate
the library method takes (CORS policy builders), minimal API handlers registered on the
application's value or a declared IEndpointRouteBuilder, the usings a file gets from its project
(SDK implicit usings, `<Using>` items, `global using`), and the services the app registers in DI,
which handlers receive from the container instead of the request."""

import pytest

from frame.sil.dotnet_project import project_file, usings_for
from frame.sil.frontends.csharp_frontend import CSharpFrontend
import tomllib

from frame.sil.packs.schema import PackError, parse_pack
from frame.sil.scanner import FrameScanner
from frame.sil.value_origins import delegate_params, load


def _cwes(code, name="c.cs"):
    return sorted(v.cwe_id for v in FrameScanner(language="csharp", verify=False).scan(code, name).vulnerabilities)


def _dir_findings(root, target=None):
    results = FrameScanner(verify=False).scan_directory(str(target or root), None)
    return sorted((r.filename.rsplit("/", 1)[-1], v.line, v.cwe_id) for r in results for v in r.vulnerabilities)


# -- CORS: the policy builder is the parameter of the lambda AddPolicy / UseCors take ------------

CORS = """using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
public class Startup {
    public void ConfigureServices(IServiceCollection services) {
        services.AddCors(o => o.AddPolicy("p", policy => {BODY}));
    }
}
"""


@pytest.mark.parametrize("body, flagged", [
    ("policy.AllowAnyOrigin()", True),
    ("policy.WithOrigins(\"https://a.example\").AllowAnyHeader().AllowAnyOrigin()", True),   # fluent chain
    ("policy.WithOrigins(\"https://a.example\").AllowAnyHeader()", False),
])
def test_the_policy_lambda_parameter_is_a_cors_policy_builder(body, flagged):
    assert ("CWE-942" in _cwes(CORS.replace("{BODY}", body))) == flagged


def test_use_cors_and_a_constructed_builder():
    code = ("using Microsoft.AspNetCore.Builder;\nusing Microsoft.AspNetCore.Cors.Infrastructure;\n"
            "public class S {\n  public void Configure(IApplicationBuilder app) {\n"
            "    app.UseCors(b => b.AllowAnyOrigin());\n  }\n"
            "  public object P() {\n    return new CorsPolicyBuilder().AllowAnyOrigin().Build();\n  }\n}\n")
    lines = {v.line for v in FrameScanner(language="csharp", verify=False).scan(code, "c.cs").vulnerabilities
             if v.cwe_id == "CWE-942"}
    assert lines == {5, 8}


def test_a_method_of_another_type_named_allow_any_origin_is_not_cors():
    code = "public class Widget { public void AllowAnyOrigin() { } }\npublic class S { void M(Widget w) { w.AllowAnyOrigin(); } }\n"
    assert "CWE-942" not in _cwes(code)


def test_an_untyped_lambda_parameter_of_an_unknown_call_stays_unknown():
    code = "public class S { void M(Registry r) { r.Configure(policy => policy.AllowAnyOrigin()); } }\n"
    assert "CWE-942" not in _cwes(code)


def test_delegate_parameter_types_are_data():
    load()
    assert delegate_params("csharp", "Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions.AddPolicy", 1) == (
        "Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder",)
    assert delegate_params("csharp", "Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions.AddPolicy", 0) == ()


# -- minimal APIs: registered on the application's value ----------------------------------------

MIN = """using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
{DECL}
app.MapGet("/ping", (string host) => Process.Start("ping", "-c 1 " + host));
"""


@pytest.mark.parametrize("decl, flagged", [
    ("var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();", True),
    ("var app = WebApplication.Create(args);", True),
    ("var app = new Router();", False),                       # a MapGet of something else
])
def test_a_minimal_api_handler_is_registered_on_the_application(decl, flagged):
    assert ("CWE-78" in _cwes(MIN.replace("{DECL}", decl), "Program.cs")) == flagged


def test_route_groups_and_a_declared_endpoint_route_builder():
    code = ("using System.Diagnostics;\nusing Microsoft.AspNetCore.Builder;\nusing Microsoft.AspNetCore.Routing;\n"
            "public static class E {\n  public static void Map(this IEndpointRouteBuilder app) {\n"
            "    var g = app.MapGroup(\"/x\").RequireAuthorization();\n"
            "    g.MapPost(\"/run\", (string cmd) => Process.Start(\"sh\", \"-c \" + cmd));\n"
            "    app.MapGet(\"/ls\", Ls);\n  }\n"
            "  static object Ls(string dir) { return Process.Start(\"ls\", dir); }\n}\n")
    lines = {v.line for v in FrameScanner(language="csharp", verify=False).scan(code, "E.cs").vulnerabilities
             if v.cwe_id == "CWE-78"}
    assert lines == {7, 10}


# -- usings from the project ----------------------------------------------------------------------

WEB = """<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>{IMPLICIT}</ImplicitUsings>
  </PropertyGroup>
  {ITEMS}
</Project>
"""
PROGRAM = """var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapGet("/ping", (string host) => System.Diagnostics.Process.Start("ping", "-c 1 " + host));
app.Run();
"""


def _project(tmp_path, implicit="enable", items="", props=None, extra=None):
    root = tmp_path / "Api"
    root.mkdir()
    (root / "Api.csproj").write_text(WEB.replace("{IMPLICIT}", implicit).replace("{ITEMS}", items))
    (root / "Program.cs").write_text(PROGRAM)
    if props is not None:
        (tmp_path / "Directory.Build.props").write_text(props)
    for name, text in (extra or {}).items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


@pytest.mark.parametrize("implicit, flagged", [("enable", True), ("true", True), ("disable", False),
                                               ("$(UseImplicit)", False)])
def test_implicit_usings_come_from_the_project_file(tmp_path, implicit, flagged):
    root = _project(tmp_path, implicit)
    assert ("CWE-78" in _cwes(PROGRAM, str(root / "Program.cs"))) == flagged


def test_a_using_item_can_remove_an_implicit_namespace(tmp_path):
    root = _project(tmp_path, items='<ItemGroup><Using Remove="Microsoft.AspNetCore.Builder" /></ItemGroup>')
    assert "Microsoft.AspNetCore.Builder" not in usings_for(str(root / "Program.cs")).wildcards
    assert "CWE-78" not in _cwes(PROGRAM, str(root / "Program.cs"))


def test_using_items_aliases_and_conditions(tmp_path):
    root = _project(tmp_path, "disable", items=(
        '<ItemGroup><Using Include="Microsoft.AspNetCore.Builder" /><Using Include="Shop.Data.Store" Alias="Db" />'
        '<Using Include="System.Math" Static="true" /></ItemGroup>'
        '<ItemGroup Condition="\'$(Configuration)\' == \'Debug\'"><Using Include="Debug.Only" /></ItemGroup>'))
    u = usings_for(str(root / "Program.cs"))
    assert u.wildcards == ("Microsoft.AspNetCore.Builder",)
    assert u.aliases == {"Db": "Shop.Data.Store"}


def test_directory_build_props_and_the_project_file_order(tmp_path):
    props = "<Project><PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>"
    root = _project(tmp_path, "disable", props=props)        # the project file is evaluated last
    assert usings_for(str(root / "Program.cs")).wildcards == ()
    (root / "Api.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk.Web"></Project>')
    from frame.sil import dotnet_project
    dotnet_project._usings_of.cache_clear()
    assert "Microsoft.AspNetCore.Builder" in usings_for(str(root / "Program.cs")).wildcards


def test_global_using_directives_of_the_project(tmp_path):
    root = _project(tmp_path, "disable", extra={"GlobalUsings.cs": "global using Microsoft.AspNetCore.Builder;\n"
                                                                    "global using Ord = Shop.Orders;\n",
                                                "bin/Old.cs": "global using Not.Compiled;\n"})
    u = usings_for(str(root / "Program.cs"))
    assert "Microsoft.AspNetCore.Builder" in u.wildcards and "Not.Compiled" not in u.wildcards
    assert u.aliases == {"Ord": "Shop.Orders"}


def test_the_project_is_the_nearest_folder_with_one_project_file(tmp_path):
    root = _project(tmp_path)
    nested = root / "Tools"
    nested.mkdir()
    (nested / "Tools.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"></Project>')
    (nested / "T.cs").write_text("class T { }\n")
    assert project_file(str(nested / "T.cs")) == (nested / "Tools.csproj").resolve()
    (nested / "Other.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"></Project>')
    assert project_file(str(nested / "T.cs")) is None                # two projects in one folder
    assert usings_for(str(tmp_path / "missing.cs")).wildcards == ()


def test_an_unlisted_sdk_adds_no_implicit_usings(tmp_path):
    root = tmp_path / "X"
    root.mkdir()
    (root / "X.csproj").write_text('<Project Sdk="Contoso.Custom.Sdk"><PropertyGroup>'
                                   '<ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>')
    (root / "A.cs").write_text("class A { }\n")
    assert usings_for(str(root / "A.cs")).wildcards == ()


# -- dependency injection -----------------------------------------------------------------------

STORE = """using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
namespace Api {
public interface IStore { string Command(); }
public class Store : IStore { public string Command() { return "ls"; } }
public class Body { public string Command() { return "ls"; } }
public static class E {
  public static void Map(this IEndpointRouteBuilder app) {
    app.MapGet("/a", (IStore s) => Process.Start("sh", "-c " + s.Command()));
    app.MapGet("/b", (Body b) => Process.Start("sh", "-c " + b.Command()));
    app.MapGet("/c", ([FromServices] Body b) => Process.Start("sh", "-c " + b.Command()));
  }
  {REG}
}}
"""


@pytest.mark.parametrize("reg, lines", [
    ("public static void Reg(IServiceCollection services) { services.AddScoped<IStore, Store>(); }", {13}),
    ("public static void Reg(IServiceCollection services) { services.AddSingleton(typeof(IStore), typeof(Store)); }",
     {13}),
    ("public static void Reg(IServiceCollection services) { services.AddTransient<Store>(); }", {12, 13}),
    ("", {12, 13}),                                          # registered nowhere: bound from the request
])
def test_a_registered_service_is_the_containers_value(reg, lines):
    found = {v.line for v in FrameScanner(language="csharp", verify=False).scan(STORE.replace("{REG}", reg), "E.cs")
             .vulnerabilities if v.cwe_id == "CWE-78"}
    assert found == lines


def test_registrations_in_another_file_count(tmp_path):
    (tmp_path / "E.cs").write_text(STORE.replace("{REG}", ""))
    (tmp_path / "Program.cs").write_text(
        "using Api;\nusing Microsoft.AspNetCore.Builder;\nusing Microsoft.Extensions.DependencyInjection;\n"
        "var builder = WebApplication.CreateBuilder(args);\n"
        "builder.Services.AddDbContext<Ctx>().AddScoped<IStore, Store>();\nvar app = builder.Build();\napp.Map();\n")
    assert [f for f in _dir_findings(tmp_path) if f[2] == "CWE-78"] == [("E.cs", 13, "CWE-78")]


def test_a_service_type_name_alone_is_not_a_service():
    code = STORE.replace("IStore", "IOrderService").replace("{REG}", "")
    found = {v.line for v in FrameScanner(language="csharp", verify=False).scan(code, "E.cs").vulnerabilities
             if v.cwe_id == "CWE-78"}
    assert 12 in found                                       # `*Service` names nothing the app registered


def _pack(text):
    return parse_pack(tomllib.loads(text), "x.toml")


def test_service_registration_entries_load_strictly():
    head = '[pack]\nname = "x"\nlanguage = "csharp"\n'
    with pytest.raises(PackError, match="registers nothing"):
        _pack(head + '[[service_registration]]\ncall = ["A.B"]\n')
    with pytest.raises(PackError, match="position"):
        _pack(head + '[[service_registration]]\ncall = ["A.B"]\ntype_arg = -1\n')
    with pytest.raises(PackError, match="C# packs"):
        _pack('[pack]\nname = "x"\nlanguage = "python"\n[[service_registration]]\ncall = ["A"]\n'
                       'type_arg = 0\n')
    with pytest.raises(PackError, match="true or false"):
        _pack(head + '[[entrypoint]]\nmethod = ["*"]\nparams = "all"\nexclude_services = "yes"\n')
