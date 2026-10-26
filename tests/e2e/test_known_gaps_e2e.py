"""Realistic flows Frame does not follow yet, pinned so they cannot go unnoticed.

Each test is a strict xfail: it documents what a user would expect, and the day the analysis
learns the idiom the test XPASSes and fails the run until it is moved into the regular matrix.
"""

import pytest

from e2e_helpers import scan, write_tree

pytestmark = pytest.mark.xfail(strict=True, reason="known limitation (see CLAUDE.md)")


def test_user_defined_callback_parameter_is_followed(tmp_path):
    write_tree(tmp_path, {"app.js": '''const express = require("express");
const { execSync } = require("child_process");
const app = express();

function withName(req, cb) {
  cb(req.query.name);
}

app.get("/a", (req, res) => {
  withName(req, (name) => {
    execSync("echo " + name);
    res.send("ok");
  });
});
'''})
    assert any(f["cwe_id"] == "CWE-78" for f in scan(tmp_path).findings)


def test_request_object_passed_under_another_name_is_a_source(tmp_path):
    write_tree(tmp_path, {"app.py": '''import os
from flask import Flask, request

app = Flask(__name__)


def render(req):
    os.system("report --title " + req.args.get("title", ""))


@app.route("/r")
def r():
    render(request)
    return "ok"
'''})
    assert any(f["cwe_id"] == "CWE-78" for f in scan(tmp_path).findings)
