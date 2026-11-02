"""A substring-rejection guard (`if '../' in x: return`, `if "'" in x: return`) clears a value
only where the string it is built into puts that substring out of reach: no `../` under a constant
path prefix (filesystem), no `'` inside a single-quoted literal (sql, xpath). On its own it proves
nothing, so an absolute path or a value outside a quoted literal stays flagged. This is the sound
version of what OWASP's Benchmark guards assume (frame/sil/translator.py)."""

import pytest

from frame.sil.scanner import FrameScanner

HEAD = ("from flask import Flask, request\n"
        "app = Flask(__name__)\nPREFIX = '/app/data'\n\n\n@app.route('/h')\ndef h():\n    bar = request.args.get('q')\n")


def _cwes(body):
    code = HEAD + body
    return {v.cwe_id for v in FrameScanner(language="python", verify=False, llm_detect=False).scan(code, "app.py").vulnerabilities}


@pytest.mark.parametrize("body, flagged", [
    # path traversal: '../' rejected and a constant prefix -> safe; otherwise flagged
    ("    if '../' in bar:\n        return 'no'\n    open(f'{PREFIX}/{bar}', 'wb')\n", False),
    ("    if '../' in bar:\n        return 'no'\n    open(PREFIX + '/' + bar, 'wb')\n", False),
    ("    open(f'{PREFIX}/{bar}', 'wb')\n", True),                              # no guard
    ("    if '../' in bar:\n        return 'no'\n    open(bar, 'wb')\n", True),  # no prefix: absolute path escapes
    ("    if '/' in bar:\n        return 'no'\n    open(f'{PREFIX}/{bar}', 'wb')\n", True),  # wrong substring
])
def test_path_traversal_substring_guard(body, flagged):
    assert ("CWE-22" in _cwes(body)) == flagged


@pytest.mark.parametrize("body, flagged", [
    # single quote rejected and the value inside a single-quoted literal -> safe; else flagged
    ("    import lxml.etree as e\n    if \"'\" in bar:\n        return 'no'\n"
     "    e.parse('x').xpath(\"//u[@n='\" + bar + \"']\")\n", False),
    ("    import lxml.etree as e\n"
     "    e.parse('x').xpath(\"//u[@n='\" + bar + \"']\")\n", True),            # no guard
    ("    import lxml.etree as e\n    if \"'\" in bar:\n        return 'no'\n"
     "    e.parse('x').xpath('//u[@n=' + bar + ']')\n", True),                  # not inside a quote
])
def test_single_quote_substring_guard(body, flagged):
    assert ("CWE-643" in _cwes(body)) == flagged
