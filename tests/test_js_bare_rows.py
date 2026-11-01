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
