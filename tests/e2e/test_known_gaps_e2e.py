"""Realistic flows Frame does not follow yet, pinned so they cannot go unnoticed.

Each test is a strict xfail: it documents what a user would expect, and the day the analysis
learns the idiom the test XPASSes and fails the run until it is moved into the regular matrix
(`projects_*.py`, with a safe twin).
"""

import pytest

from e2e_helpers import scan, write_tree

pytestmark = pytest.mark.xfail(strict=True, reason="known limitation (see CLAUDE.md)")


def test_prototype_style_constructor_methods_resolve_in_file(tmp_path):
    write_tree(tmp_path, {"app.js": '''const express = require("express");
const { execSync } = require("child_process");
const app = express();

function Exporter() {}
Exporter.prototype.run = function (name) {
  return execSync("export --name " + name).toString();
};

app.get("/e", (req, res) => {
  const e = new Exporter();
  res.send(e.run(req.query.name));
});
'''})
    assert any(f["cwe_id"] == "CWE-78" for f in scan(tmp_path).findings)
