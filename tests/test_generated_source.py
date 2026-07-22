"""Minified and generated files are build artifacts, not source.

Analysing them costs a great deal of time (a single 277KB line of bundled
JavaScript burns minutes of CPU in the symbolic engine) and yields nothing a
security advisory would ever point at. Detection is structural, based on line
geometry, so it does not depend on a `.min.js` naming convention that generated
files may not follow.

These tests pin the conservative direction hardest: real source must never be
skipped, because a skipped file is a silent false negative.
"""

import pytest

from frame.sil import FrameScanner
from frame.sil.scanner import is_generated_source


# --- what counts as generated ------------------------------------------------

def test_minified_bundle_is_detected():
    # One enormous line: the classic bundler/minifier signature.
    assert is_generated_source("var a=1;" + "x" * 5000)


def test_single_long_line_without_newline_is_detected():
    assert is_generated_source("y" * 3000)


def test_long_line_buried_among_normal_lines_is_detected():
    src = "def ok():\n    return 1\n" + "z" * 4000 + "\nmore = 2\n"
    assert is_generated_source(src)


# --- what must NOT count (silent false negatives are the real risk) ----------

def test_ordinary_source_is_not_generated():
    src = (
        "from flask import request\n"
        "def handler(db):\n"
        "    uid = request.args.get('id')\n"
        "    db.execute('SELECT * FROM t WHERE id=' + uid)\n"
    )
    assert not is_generated_source(src)


def test_many_moderately_long_lines_are_not_generated():
    # Wide but human-written: 100 lines of 200 chars is formatting, not minification.
    assert not is_generated_source("\n".join(["x" * 200] * 100))


def test_large_file_with_normal_lines_is_not_generated():
    # Size alone must not trigger it; only line geometry.
    assert not is_generated_source("\n".join(["def f%d(): return %d" % (i, i)
                                              for i in range(5000)]))


def test_empty_and_trivial_input():
    assert not is_generated_source("")
    assert not is_generated_source(None)
    assert not is_generated_source("x")


def test_threshold_is_honoured():
    src = "a" * 500
    assert is_generated_source(src, threshold=100)
    assert not is_generated_source(src, threshold=10000)


def test_threshold_of_zero_disables_the_check():
    assert not is_generated_source("x" * 100000, threshold=0)


# --- end-to-end through the scanner -----------------------------------------

def test_scanner_skips_minified_file_and_says_so(tmp_path):
    f = tmp_path / "bundle.js"
    f.write_text("!function(){var e=require('child_process');e.exec(x)}();"
                 + "a" * 5000)
    result = FrameScanner(language="javascript", verify=False).scan_file(str(f))
    assert result.vulnerabilities == []
    assert any("generated or minified" in w for w in result.warnings)


def test_scanner_still_analyses_normal_file_of_same_language(tmp_path):
    # The guard must not suppress a real finding in ordinary source.
    f = tmp_path / "app.js"
    f.write_text(
        "const cp = require('child_process');\n"
        "function handler(req) {\n"
        "  const name = req.query.name;\n"
        "  cp.exec('ls ' + name);\n"
        "}\n"
    )
    result = FrameScanner(language="javascript", verify=False).scan_file(str(f))
    assert not any("generated or minified" in w for w in result.warnings)
