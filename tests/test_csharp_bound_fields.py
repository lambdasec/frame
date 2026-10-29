"""Which C# fields a framework fills from the request is pack data (`aspnetcore` pack:
`fields = "annotated"` with `field_annotation`, `fields = "settable"`), not frontend code.
The frontend records every instance member, its attributes and whether outside code can assign it."""

import pytest

try:                                        # Python 3.11+
    import tomllib
except ModuleNotFoundError:                 # pragma: no cover - 3.10
    import tomli as tomllib                 # type: ignore[no-redef]

from frame.sil.frontends.csharp_frontend import CSharpFrontend
from frame.sil.packs.schema import PackError, parse_pack
from frame.sil.scanner import FrameScanner

PAGE = """using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Data.SqlClient;

public class SearchModel : PageModel
{{
{attrs}
    public string Term {{ get; set; }}
    public string Fixed {{ get; }} = "x";
    private readonly string _conn = "Server=db";

    public void OnGet()
    {{
        var cmd = new SqlCommand("SELECT * FROM t WHERE n = '" + Term + "'");
        cmd.ExecuteReader();
    }}
}}
"""


def _cwes(code):
    res = FrameScanner(language="csharp", verify=False).scan(code, "t.cs")
    return {v.cwe_id for v in res.vulnerabilities}


def _page(class_attr="", member_attr=""):
    return PAGE.format(attrs=member_attr).replace("public class", f"{class_attr}\npublic class")


@pytest.mark.parametrize("member_attr", ["    [BindProperty]", "    [BindProperty(SupportsGet = true)]",
                                         "    [FromQuery]", "    [Microsoft.AspNetCore.Mvc.BindProperty]"])
def test_a_bound_property_is_request_data(member_attr):
    assert "CWE-89" in _cwes(_page(member_attr=member_attr))


@pytest.mark.parametrize("member_attr", ["", "    [BindNever]", "    [Parameter]"])
def test_an_unbound_property_is_not(member_attr):
    assert "CWE-89" not in _cwes(_page(member_attr=member_attr))


def test_bind_properties_binds_every_public_settable_property():
    assert "CWE-89" in _cwes(_page(class_attr="[BindProperties]"))


def test_the_frontend_records_members_attributes_and_settability():
    prog = CSharpFrontend().translate(_page(member_attr="    [BindProperty]"), "t.cs")
    info = prog.class_info["SearchModel"]
    assert info.fields == ["Term", "Fixed", "_conn"]
    assert [a.name for a in info.field_annotations["Term"]] == ["BindProperty"]
    assert info.settable_fields == ["Term"]


def _entry(extra):
    return tomllib.loads('[pack]\nname = "x"\nlanguage = "csharp"\n[[entrypoint]]\nextends = ["PageModel"]\n'
                         'method = ["On*"]\n' + extra)


@pytest.mark.parametrize("extra, needle", [
    ('fields = "annotated"\n', "field_annotation"),
    ('fields = true\nfield_annotation = ["BindProperty"]\n', "field_annotation"),
    ('fields = "some"\n', "fields"),
])
def test_field_keys_are_validated(extra, needle):
    with pytest.raises(PackError, match=needle):
        parse_pack(_entry(extra), "x.toml")


def test_fields_true_still_means_every_field():
    pack = parse_pack(_entry("fields = true\n"), "x.toml")
    assert pack.entrypoints[0].fields == "all"
