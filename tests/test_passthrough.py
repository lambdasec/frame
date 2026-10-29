"""Calls that hand back their input are data (`specs/data/passthrough.toml`), read by the JS
frontend (inline request reads inside a re-encoding call) and the C# frontend (request reads
followed by `.ToString()`, `.FirstOrDefault()`...)."""

import pytest

from frame.sil.scanner import FrameScanner
from frame.sil.specs import passthrough


def test_the_shipped_file_loads():
    p = passthrough.load()
    assert "decodeURIComponent" in p.javascript_calls
    assert "FirstOrDefault" in p.csharp_methods


@pytest.mark.parametrize("text, needle", [
    ('[javascript]\ncalls = ["a"]\n', "needs exactly"),
    ('[javascript]\ncalls = []\n[csharp]\nmethods = ["x"]\n', r"\[javascript\]"),
    ('[javascript]\ncalls = ["a"]\n[csharp]\nmethods = ["x"]\nother = 1\n', r"\[csharp\]"),
])
def test_the_loader_is_strict(tmp_path, text, needle):
    bad = tmp_path / "passthrough.toml"
    bad.write_text(text)
    with pytest.raises(ValueError, match=needle):
        passthrough.load(bad)


def _cwes(code, lang, name):
    return {v.cwe_id for v in FrameScanner(language=lang, verify=False).scan(code, name).vulnerabilities}


_JS = """const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/a', (req, res) => {
  const cmd = %s(req.query.c);
  exec(cmd);
  res.end();
});
"""


def test_js_inline_request_read_through_a_passthrough_call():
    assert "CWE-78" in _cwes(_JS % "decodeURIComponent", "javascript", "a.js")


_CS = """using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

public class Orders : Controller
{
    public void Find()
    {
        var name = Request.Query["n"].%s();
        var cmd = new SqlCommand("SELECT * FROM t WHERE n = '" + name + "'");
        cmd.ExecuteReader();
    }
}
"""


@pytest.mark.parametrize("method", ["ToString", "FirstOrDefault"])
def test_csharp_request_read_through_a_passthrough_method(method):
    assert "CWE-89" in _cwes(_CS % method, "csharp", "Orders.cs")
