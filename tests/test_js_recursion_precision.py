"""CWE-674 (uncontrolled recursion) in JS/TS: only a function that really calls itself."""

import pytest

from frame.sil.scanner import FrameScanner


def cwe674(src):
    return [v.line for v in FrameScanner(language="javascript", verify=False).scan(src, "t.js").vulnerabilities
            if v.cwe_id == "CWE-674"]


@pytest.mark.parametrize("src", [
    "function f(n) { return f(n - 1); }\n",
    "class A { f(n) { return this.f(n - 1); } }\n",
])
def test_real_self_recursion_is_reported(src):
    assert cwe674(src) == [1]


@pytest.mark.parametrize("src", [
    # the last link of a chain is a method of another object
    "var P = V.extend({ snap: function (x) { return this.client(x).snap(1); } });\n",
    # in an arrow function `this` is the enclosing object, not the arrow
    "class A { m() { const c = { err: (msg) => this.err(msg) }; return c; } err(m) {} }\n",
    # a wrapper delegating to a differently-qualified function of the same name
    "const lib = require('lib');\nfunction parse(s) { return lib.parse(s); }\n",
])
def test_calls_on_another_object_are_not_recursion(src):
    assert cwe674(src) == []
