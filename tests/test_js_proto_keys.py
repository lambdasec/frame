"""Prototype pollution: an Array iteration callback's index is a number and never `__proto__`, but
only when the receiver is known to be an Array (a Map's forEach hands its key in that position)."""

import pytest

from frame.sil import FrameScanner
from frame.sil.specs.javascript_types import load


def _pp(code):
    r = FrameScanner(language="javascript", verify=False, library_mode=True).scan(code, "x.js")
    return "CWE-1321" in {v.cwe_id for v in r.vulnerabilities}


@pytest.mark.parametrize("code, flagged", [
    ('var out = {};\nfunction f(src) {\n  src.split(".").forEach((p, i) => { out[i] = p; });\n}\nmodule.exports = f;\n', False),
    ('var out = {};\nfunction f(src) {\n  [1, 2].map(function (v, i) { out[i] = src; });\n}\nmodule.exports = f;\n', False),
    ('var out = {};\nfunction f(m) {\n  new Map(m).forEach((v, k) => { out[k] = v; });\n}\nmodule.exports = f;\n', True),
    ('function f(a, b) {\n  for (const k in b) { a[k] = b[k]; }\n}\nmodule.exports = f;\n', True),
])
def test_an_array_index_is_no_key(code, flagged):
    assert _pp(code) == flagged


def test_the_index_positions_are_data():
    t = load()
    assert t.array_index_params["forEach"] == 1 and t.array_index_params["reduce"] == 2
