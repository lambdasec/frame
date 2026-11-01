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


# --- a parameter's kind, when the file proves it ---------------------------------------------------

_IDX = "xs.forEach((v, i) => { out[i] = v; });"


@pytest.mark.parametrize("lang, code, flagged", [
    ("javascript", f"var out = {{}};\nfunction f(...xs) {{ {_IDX} }}\nmodule.exports = f;\n", False),       # rest parameter
    ("javascript", f"var out = {{}};\nfunction f(xs) {{\n  if (!Array.isArray(xs)) return;\n  {_IDX}\n}}\nmodule.exports = f;\n", False),
    ("javascript", f"var out = {{}};\nfunction f(xs) {{ if (Array.isArray(xs)) {{ {_IDX} }} }}\nmodule.exports = f;\n", False),
    ("javascript", f"var out = {{}};\nfunction f(xs) {{ if (Array.isArray(xs)) {{ return; }} {_IDX} }}\nmodule.exports = f;\n", True),
    ("javascript", f"var out = {{}};\nfunction g(xs) {{ {_IDX} }}\nfunction f(s) {{ g(s.split(\",\")); g([s]); }}\nmodule.exports = f;\n", False),
    ("javascript", f"var out = {{}};\nfunction g(xs) {{ {_IDX} }}\nfunction f(m) {{ g(m); }}\nmodule.exports = f;\n", True),         # one call passes an unknown
    ("javascript", f"var out = {{}};\nfunction g(xs) {{ {_IDX} }}\nfunction f(s) {{ g(s.split(\",\")); }}\nmodule.exports = {{ f, g }};\n", True),  # exported: callers unknown
    ("javascript", f"var out = {{}};\nfunction g(xs) {{ {_IDX} }}\nfunction f(s) {{ g(s.split(\",\")); return [g]; }}\nmodule.exports = f;\n", True),
    ("javascript", f"var out = {{}};\nfunction f(...xs) {{ xs = xs[0]; {_IDX} }}\nmodule.exports = f;\n", True),          # reassigned
    ("javascript", f"var out = {{}};\nfunction f(xs) {{ {_IDX} }}\nmodule.exports = f;\n", True),                        # unknown
    ("typescript", f"const out: any = {{}};\nexport function f(xs: string[]) {{ {_IDX} }}\n", False),
    ("typescript", "const out: any = {};\nexport function f(xs: ReadonlyArray<string>) { xs.forEach((v, i: number) => { out[i] = v; }); }\n", False),
    ("typescript", f"const out: any = {{}};\nexport function f(xs: Map<string, string>) {{ {_IDX} }}\n", True),
    ("typescript", f"const out: any = {{}};\nexport function f(xs: string[] | Map<string, string>) {{ {_IDX} }}\n", True),
])
def test_a_parameter_proved_an_array(lang, code, flagged):
    ext = "ts" if lang == "typescript" else "js"
    r = FrameScanner(language=lang, verify=False, library_mode=True).scan(code, f"x.{ext}")
    assert ("CWE-1321" in {v.cwe_id for v in r.vulnerabilities}) == flagged
