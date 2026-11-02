"""Razor pages (.cshtml / .razor) scanned through the C# engine (frame/sil/frontends/razor_frontend.py).
The Razor is transpiled to the generated-page shape C# compiles it to (a RazorPage class with an
ExecuteAsync method, the view intrinsics declared with their framework types), the existing C#
specs decide the sources and sinks (Request.* a source, Html.Raw an XSS sink), and line numbers
map back to the .cshtml."""

import pytest

from frame.sil.frontends.razor_frontend import RazorFrontend
from frame.sil.scanner import EXTENSION_LANGUAGES, FrameScanner, language_for_file


def _cwes(page, name="Index.cshtml"):
    r = FrameScanner(language="razor", verify=False, llm_detect=False).scan(page, name)
    return sorted((v.line, v.cwe_id) for v in r.vulnerabilities)


def test_cshtml_and_razor_route_to_the_razor_frontend():
    assert EXTENSION_LANGUAGES[".cshtml"] == "razor" and EXTENSION_LANGUAGES[".razor"] == "razor"
    assert language_for_file("Pages/Index.cshtml") == "razor"


@pytest.mark.parametrize("page, expected", [
    # request data written raw is XSS; the line is the .cshtml line
    ('@{\n    var q = Context.Request.Query["q"];\n}\n<div>@Html.Raw(q)</div>\n', [(4, "CWE-79")]),
    ('<p>@Html.Raw(Request.Query["x"])</p>\n', [(1, "CWE-79")]),
    ('@model App.Item\n@{ var q = Request.Form["c"]; }\n<b>@Html.Raw(q)</b>\n', [(3, "CWE-79")]),
    # encoded output (@expr), and raw output of model/app data, are safe
    ('@{\n    var q = Request.Query["q"];\n}\n<div>@q</div>\n', []),
    ('@model App.Item\n<div>@Html.Raw(Model.Description)</div>\n', []),
    ('<div>@Html.Raw("<b>static</b>")</div>\n', []),
])
def test_raw_output_of_request_data(page, expected):
    assert _cwes(page) == expected


def test_a_sink_inside_a_code_block():
    page = ('@using Microsoft.EntityFrameworkCore\n'
            '@inject Microsoft.EntityFrameworkCore.DbContext Db\n'
            '@{\n'
            '    var id = Request.Query["id"];\n'
            '    Db.Database.ExecuteSqlRaw("SELECT * FROM t WHERE id = " + id);\n'
            '}\n')
    assert (5, "CWE-89") in _cwes(page)


def test_functions_block_and_directives_do_not_break_the_parse():
    page = ('@using System.Text\n'
            '@functions {\n'
            '    string Greeting() { return "hi"; }\n'
            '}\n'
            '<h1>@Greeting()</h1>\n'
            '<div>@Html.Raw(Request.Query["q"])</div>\n')
    assert (6, "CWE-79") in _cwes(page)


def test_escaped_at_is_not_an_expression():
    assert _cwes('<span>user@@example.com @Html.Raw(Request.Query["q"])</span>\n') == [(1, "CWE-79")]
