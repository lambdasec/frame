"""JavaScript rows written as one name are global functions or module values: they match a bare
call, or a method of the global object, never a method of the same name on another receiver."""

import pytest

from frame.sil.scanner import FrameScanner

APP = ("const express = require('express');\nconst app = express();\n%s\n"
       "app.get('/u', (req, res) => {\n  %s\n  res.end();\n});\n")


def _cwes(setup, body):
    code = APP % (setup, body)
    return {v.cwe_id for v in FrameScanner(language="javascript", verify=False).scan(code, "a.js").vulnerabilities}


@pytest.mark.parametrize("setup, body, cwe", [
    ("", "fetch(req.query.u);", "CWE-918"),
    ("", "window.fetch(req.query.u);", "CWE-918"),
    ("const axios = require('axios');", "axios(req.query.u);", "CWE-918"),
    ("const _ = require('lodash');", "_.merge({}, req.body);", "CWE-1321"),
    ("const cp = require('child_process');", "cp.exec('ls ' + req.query.d);", "CWE-78"),
])
def test_globals_and_module_values(setup, body, cwe):
    assert cwe in _cwes(setup, body)


@pytest.mark.parametrize("setup, body, cwe", [
    ("const cache = new Map();", "cache.fetch(req.query.u);", "CWE-918"),       # a method named fetch
    ("const api = require('./api');", "api.request(req.query.u);", "CWE-918"),
    ("", "cp.exec('ls ' + req.query.d);", "CWE-78"),                            # cp is never declared
    ("function merge(a, b) { return Object.freeze(Object.assign({}, a)); }", "merge({}, req.body);", "CWE-1321"),
])
def test_a_name_alone_is_no_sink(setup, body, cwe):
    assert cwe not in _cwes(setup, body)


# --- the prototype-pollution pass reads a module's guard from the syntax tree ---------------------

MERGE = """function merge(target, source) {
  for (const key in source) {
    %s
    target[key] = source[key];
  }
  return target;
}
module.exports = merge;
"""


@pytest.mark.parametrize("guard, flagged", [
    ("", True),
    ("if (key === '__proto__' || key === 'constructor') continue;", False),
    ("if (BLOCKED.includes(key)) continue;", False),
    ("if (!isSafe(key)) continue;", False),
    ("// a comment naming '__proto__' === key guards nothing", True),
])
def test_a_guard_is_a_comparison_in_the_code(guard, flagged):
    code = ("const BLOCKED = ['__proto__', 'constructor', 'prototype'];\n"
            "function isSafe(k) { return k !== '__proto__'; }\n") + MERGE % guard
    if "BLOCKED" not in guard and "isSafe" not in guard:
        code = MERGE % guard
    found = {v.cwe_id for v in FrameScanner(language="javascript", verify=False, library_mode=True)
             .scan(code, "lib/merge.js").vulnerabilities}
    assert ("CWE-1321" in found) == flagged
