"""What a scan reports, and how the CLI finds and formats it.

The scanner reports every finding a user must fix: each distinct sink in a
function (same-CWE reports within a few lines merge as one flow), so five
injectable endpoints in one controller are five findings. The
one-label-per-file view that OWASP/Juliet-style benchmarks score is
`collapse_per_file_cwe`, applied by the scoring code -- not by the scanner.
"""

import json

from frame.cli import create_parser as frame_parser, main as frame_main
from frame.sil.cli import create_parser as sil_parser
from frame.sil.scanner import (
    FrameScanner, collapse_per_file_cwe, language_extensions, language_for_file)

TWO_ENDPOINTS = """
from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/a")
def a():
    db = sqlite3.connect("x")
    db.execute("select * from t where n='%s'" % request.args.get("n"))
    return "ok"

@app.route("/b")
def b():
    db = sqlite3.connect("x")
    db.execute("select * from t where m='%s'" % request.args.get("m"))
    return "ok"
"""

SQLI_AND_XSS = """
from flask import Flask, request, render_template_string
import sqlite3
app = Flask(__name__)

@app.route("/a")
def a():
    n = request.args.get("n")
    sqlite3.connect("x").execute("select * from t where n='%s'" % n)
    return render_template_string("<p>" + n + "</p>")
"""


def _vulns(code, name="t.py"):
    r = FrameScanner(language="python").scan(code, name)
    assert not r.errors, r.errors
    return r.vulnerabilities


# ---- dedupe granularity --------------------------------------------------------

def test_same_cwe_in_two_procedures_is_two_findings():
    vulns = [v for v in _vulns(TWO_ENDPOINTS) if v.cwe_id == "CWE-89"]
    assert sorted(v.procedure for v in vulns) == ["a", "b"]


def test_benchmark_view_collapses_to_one_per_file_cwe():
    vulns = collapse_per_file_cwe(_vulns(TWO_ENDPOINTS))
    assert [v.cwe_id for v in vulns].count("CWE-89") == 1


def test_handler_with_sqli_and_xss_reports_both():
    cwes = {v.cwe_id for v in _vulns(SQLI_AND_XSS)}
    assert {"CWE-89", "CWE-79"} <= cwes


def _finding(vtype, cwe, proc, sink, line=1):
    from frame.sil.scanner import Severity, Vulnerability
    return Vulnerability(type=vtype, severity=Severity.HIGH, location="t.py", line=line,
                         column=0, description="", procedure=proc, sink_type=sink, cwe_id=cwe)


def test_benchmark_view_drops_html_xss_beside_another_finding():
    from frame.sil.translator import VulnType
    sqli = _finding(VulnType.SQL_INJECTION, "CWE-89", "a", "sql")
    xss_here = _finding(VulnType.XSS, "CWE-79", "a", "html", line=2)
    xss_elsewhere = _finding(VulnType.XSS, "CWE-79", "b", "html", line=9)
    assert collapse_per_file_cwe([sqli, xss_here]) == [sqli]
    assert collapse_per_file_cwe([sqli, xss_elsewhere]) == [sqli, xss_elsewhere]


# ---- language detection ------------------------------------------------------

def test_module_and_header_extensions():
    assert language_for_file("a.mjs") == "javascript"
    assert language_for_file("a.cjs") == "javascript"
    assert language_for_file("a.mts") == "typescript"
    assert language_for_file("a.hh") == "cpp"
    assert language_for_file("a.hxx") == "cpp"
    assert language_for_file("a.php", default="python") == "python"


def test_h_header_is_cpp_only_when_it_uses_cpp():
    assert language_for_file("a.h", "int f(char *s);\n") == "c"
    assert language_for_file("a.h", "namespace io {\nclass File {\npublic:\n};\n}\n") == "cpp"
    assert language_for_file("a.h", "#include <string>\nstd::string name();\n") == "cpp"


def test_extensionless_script_by_shebang():
    assert language_for_file("bin/deploy", "#!/usr/bin/env python3\nimport os\n") == "python"
    assert language_for_file("bin/deploy", "#!/usr/bin/python3.11 -u\n") == "python"
    assert language_for_file("bin/serve", "#!/usr/bin/env -S node --no-warnings\n") == "javascript"
    assert language_for_file("bin/run", "#!/bin/bash\necho hi\n") is None
    assert language_for_file("README", "docs\n") is None
    # An extension still decides: a shebang never overrides it.
    assert language_for_file("tool.py", "#!/usr/bin/env node\n") == "python"


def test_directory_scan_picks_up_scripts_of_the_scanned_languages(tmp_path):
    (tmp_path / "deploy").write_text("#!/usr/bin/env python3\nimport os\n")
    (tmp_path / "serve").write_text("#!/usr/bin/env node\nconsole.log(1)\n")
    (tmp_path / "build").write_text("#!/bin/sh\nmake\n")
    (tmp_path / "LICENSE").write_text("Apache\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook").write_text("#!/usr/bin/env python3\n")
    names = lambda files: sorted(p.name for p in files)
    scanner = FrameScanner()
    walk = lambda exts: scanner._candidate_files(tmp_path, None, exts, frozenset({".git"}))
    assert names(walk(None)) == ["deploy", "serve"]
    assert names(walk(language_extensions("python"))) == ["deploy"]
    assert names(walk(language_extensions("java"))) == []
    picked = FrameScanner._selected_files(tmp_path, [tmp_path / "deploy", tmp_path / "build"], None, None)
    assert names(picked) == ["deploy"]


def test_language_extensions():
    assert ".py" in language_extensions(None) and ".java" in language_extensions(None)
    assert language_extensions("java") == [".java"]
    assert language_extensions("c") == [".c", ".h"]
    assert language_extensions("php") == [".php"]


# ---- CLI -------------------------------------------------------------------------

def _scan_opts(parser):
    import argparse
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    return {o for a in sub.choices["scan"]._actions for o in a.option_strings}


def test_both_scan_parsers_take_the_same_flags():
    # `--model` is consumed by frame/cli.py before it delegates.
    assert _scan_opts(frame_parser()) - {"--model"} == _scan_opts(sil_parser())


def test_frame_scan_accepts_every_language_and_repo_scale():
    args = frame_parser().parse_args(["scan", "src", "-l", "java", "--repo-scale"])
    assert args.language == "java" and args.repo_scale


def _mixed_tree(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "server.js").write_text("const y = 2;\n")
    (tmp_path / "web" / "lib.mjs").write_text("export const z = 3;\n")
    (tmp_path / "Main.java").write_text("class Main {}\n")
    (tmp_path / "notes.txt").write_text("not source\n")


def _scanned(tmp_path, capsys, *extra):
    rc = frame_main(["scan", str(tmp_path), "--no-verify", "-f", "json",
                     "--fail-on", "none", *extra])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    return {f["filename"].rsplit("/", 1)[-1] for f in data["files"]}


def test_directory_scan_defaults_to_every_supported_language(tmp_path, capsys):
    _mixed_tree(tmp_path)
    assert _scanned(tmp_path, capsys) == {"app.py", "server.js", "lib.mjs", "Main.java"}


def test_language_flag_limits_a_directory_scan(tmp_path, capsys):
    _mixed_tree(tmp_path)
    assert _scanned(tmp_path, capsys, "-l", "javascript") == {"server.js", "lib.mjs"}


def test_explicit_pattern_still_wins(tmp_path, capsys):
    _mixed_tree(tmp_path)
    assert _scanned(tmp_path, capsys, "-p", "**/*.py") == {"app.py"}


def test_json_shape_follows_the_target_not_the_file_count(tmp_path, capsys):
    (tmp_path / "only.py").write_text("x = 1\n")
    assert _scanned(tmp_path, capsys) == {"only.py"}     # directory: {"files": [...]}
    rc = frame_main(["scan", str(tmp_path / "only.py"), "--no-verify", "-f", "json",
                     "--fail-on", "none"])
    assert rc == 0
    assert "vulnerabilities" in json.loads(capsys.readouterr().out)   # file: one object
