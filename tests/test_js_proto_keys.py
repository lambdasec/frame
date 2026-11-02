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


# --- kind facts over the path, through helpers (frontends/_js_kinds.py) ------------------------------

UTIL = """export const isArray = target => Array.isArray(target);
export const isMap = target => target instanceof Map;
export const isObject = t => Object.prototype.toString.call(t) === '[object Object]';
export const isType = (target, type) => {
  return { object: isObject, array: isArray, map: isMap }?.[type]?.(target) ?? false;
};
"""


@pytest.mark.parametrize("guard, flagged", [
    ("if (!isType(xs, 'array')) { throw new Error('no'); }", False),     # dispatch on a constant key, imported
    ("if (!isArray(xs)) return;", False),
    ("if (!(typeof xs === 'object' && Array.isArray(xs))) throw new Error('no');", False),
    ("if (Object.prototype.toString.call(xs) !== '[object Array]') return;", False),
    ("if (!isType(xs, 'map')) { throw new Error('no'); }", True),        # a Map: forEach hands its key
    ("if (!isType(xs, 'nothing')) { throw new Error('no'); }", False),   # no such key: always false, so it always throws
    ("if (isArray(xs)) return;", True),                                   # the opposite branch
    ("if (!isArray(other)) return;", True),                               # another variable
    ("if (!unknownCheck(xs)) return;", True),                             # a test the files do not define
    ("", True),
])
def test_type_tests_on_the_path_through_helpers(tmp_path, guard, flagged):
    (tmp_path / "util.js").write_text(UTIL)
    (tmp_path / "index.js").write_text(
        "import { isArray, isType } from './util';\nconst out = {};\n"
        f"export const merge = (xs, other) => {{\n  {guard}\n  xs.forEach((v, i) => {{ out[i] = v; }});\n}};\n")
    r = FrameScanner(language="javascript", verify=False, library_mode=True).scan_file(str(tmp_path / "index.js"))
    assert ("CWE-1321" in {v.cwe_id for v in r.vulnerabilities}) == flagged


def test_a_ternary_and_an_and_branch_carry_their_condition(tmp_path):
    for body, flagged in [("Array.isArray(xs) && xs.forEach((v, i) => { out[i] = v; });", False),
                          ("Array.isArray(xs) || xs.forEach((v, i) => { out[i] = v; });", True),
                          ("Array.isArray(xs) ? xs.forEach((v, i) => { out[i] = v; }) : null;", False)]:
        assert _pp(f"var out = {{}};\nfunction f(xs) {{ {body} }}\nmodule.exports = f;\n") == flagged, body


def test_conditions_the_model_does_not_read_prove_nothing_and_never_break_the_scan():
    """`a === b` between two variables, `typeof` against a variable: free booleans, not an error
    (a Z3 expression used as a Python truth value used to abort the file's whole scan)."""
    code = ("var out = {};\nfunction f(xs, a, b, t) {\n  if (a === b) return;\n  if (typeof xs === t) return;\n"
            "  if (xs.length !== a) throw new Error('x');\n  xs.forEach((v, i) => { out[i] = v; });\n}\nmodule.exports = f;\n")
    assert _pp(code)
