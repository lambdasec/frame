"""A pack rule that names a call a source, sink or sanitizer applies even when the callee is a
project procedure Frame can see -- the same file or another project file -- not only when the
callee is an external import. A pack tagging a team's own render/query/exec/clean helper would
otherwise be silently ignored once the helper is defined in the project
(frame/sil/translator.py `_resolve_callee`, frame/sil/procedure.py `_get_spec`)."""

from frame.sil.scanner import FrameScanner

PACK = """[pack]
name = "acme"
language = "python"
description = "acme project helpers"

[[sink]]
name = "run_cmd"
kind = "shell"

[[sanitizer]]
name = "clean_sh"
kinds = ["shell"]
"""


def _project(tmp_path, files):
    (tmp_path / ".frame" / "packs").mkdir(parents=True)
    (tmp_path / ".frame" / "packs" / "acme.toml").write_text(PACK)
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    run = FrameScanner(language="python", verify=False).scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    return {f.filename.rsplit("/", 1)[-1]: sorted((v.line, v.cwe_id) for v in f.vulnerabilities) for f in run}


HANDLER = ("from flask import Flask, request\napp = Flask(__name__)\n\n"
           "@app.route('/a')\ndef a():\n    return run_cmd(request.args.get('q'))\n\n"
           "@app.route('/b')\ndef b():\n    return run_cmd(clean_sh(request.args.get('q')))\n")


def test_pack_sink_and_sanitizer_on_a_same_file_helper(tmp_path):
    defs = "def run_cmd(c):\n    return c\n\ndef clean_sh(x):\n    return x\n\n\n"
    out = _project(tmp_path, {"app.py": defs + HANDLER})
    # the sink fires once (the unsanitised call) and the same-file sanitizer clears the other
    assert [cwe for _, cwe in out["app.py"]] == ["CWE-78"]


def test_pack_sink_on_a_helper_defined_in_another_project_file(tmp_path):
    out = _project(tmp_path, {
        "helpers.py": "def run_cmd(c):\n    return c\n\ndef clean_sh(x):\n    return x\n",
        "app.py": "from helpers import run_cmd, clean_sh\n" + HANDLER})
    assert [cwe for _, cwe in out["app.py"]] == ["CWE-78"]


def test_pack_sink_on_an_external_import_still_fires(tmp_path):
    out = _project(tmp_path, {
        "app.py": "from acmelib import run_cmd, clean_sh\n" + HANDLER})
    assert [cwe for _, cwe in out["app.py"]] == ["CWE-78"]


def test_defining_the_helper_is_not_itself_a_finding(tmp_path):
    out = _project(tmp_path, {"helpers.py": "def run_cmd(c):\n    return c\n"})
    assert out.get("helpers.py", []) == []
