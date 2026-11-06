"""Proof-carrying dependency findings (Phase 5c foundation): spec extraction + test emit."""

from frame.sil.proof_deps import deps_repro_spec, python_deps_test


def _tainted_finding():
    return {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "package": "acme-xml",
        "version": "1.2.0",
        "fixed": ["1.2.1"],
        "summary": "XXE in acme_xml.parse",
        "functions": [{"id": "acme_xml/parse"}],
        "reachability": {
            "level": "tainted",
            "calls": [{"function": "acme_xml/parse", "location": "app/views.py:42",
                       "source": "", "call": "acme_xml.parse"}],
            "flows": [{"location": "app/views.py:42", "type": "xxe",
                       "evidence": "data-flow", "source": "body"}],
        },
    }


def test_spec_extracted_from_a_tainted_finding():
    spec = deps_repro_spec(_tainted_finding())
    assert spec is not None
    assert spec.advisory == "GHSA-xxxx-yyyy-zzzz"
    assert spec.package == "acme-xml" and spec.version == "1.2.0"
    assert spec.vuln_function == "acme_xml/parse"
    assert spec.call_site == "app/views.py:42"
    assert spec.source_var == "body"
    assert spec.fixed == "1.2.1"
    assert spec.module_path == "app/views.py"


def test_no_spec_unless_tainted():
    for level in ("installed", "imported", "called"):
        f = _tainted_finding()
        f["reachability"]["level"] = level
        assert deps_repro_spec(f) is None
    # a tainted finding with no flow is also not actionable
    f = _tainted_finding(); f["reachability"]["flows"] = []
    assert deps_repro_spec(f) is None


def test_emitted_test_names_the_advisory_and_spies_the_function():
    spec = deps_repro_spec(_tainted_finding())
    src = python_deps_test(spec)
    assert "GHSA-xxxx-yyyy-zzzz" in src
    assert "acme_xml/parse" in src
    assert "monkeypatch" in src and "PROOF_MARKER_7F3A" in src
    assert "def test_attacker_data_reaches_the_vulnerable_function" in src
    # the emitted test is valid Python
    compile(src, "emitted_test.py", "exec")


import json as _json
from pathlib import Path
from frame.sil.proof_deps import DepsReproSpec, run_deps_repro


def _mini_project(root: Path):
    (root / "acme_xml.py").write_text("def parse(data):\n    return 'parsed:' + str(data)\n")
    (root / "app.py").write_text(
        "import acme_xml\n\ndef handle(payload):\n    return acme_xml.parse(payload)\n")
    return DepsReproSpec(advisory="GHSA-x", package="acme-xml", version="1.0",
                         vuln_function="acme_xml/parse", call_text="acme_xml.parse",
                         call_site="app.py:4", source_var="payload")


def test_runner_confirms_a_genuine_driver(tmp_path):
    spec = _mini_project(tmp_path)
    r = run_deps_repro("from app import handle\nhandle(MARKER)", spec, str(tmp_path))
    assert r.reproduced is True
    assert r.result["marker_in_args"] and r.result["via_callsite"]


def test_runner_rejects_a_direct_call_cheat(tmp_path):
    # Calling the vulnerable function straight from the driver bypasses the project:
    # the call-site file is not on the stack, so it must NOT count.
    spec = _mini_project(tmp_path)
    r = run_deps_repro("import acme_xml\nacme_xml.parse(MARKER)", spec, str(tmp_path))
    assert r.reproduced is False


def test_runner_rejects_a_driver_without_the_marker(tmp_path):
    spec = _mini_project(tmp_path)
    r = run_deps_repro("from app import handle\nhandle('benign')", spec, str(tmp_path))
    assert r.reproduced is False


def test_runner_handles_from_import_binding(tmp_path):
    # `from acme_xml import parse` binds before the patch would normally apply;
    # the harness patches first, so it is still spied.
    (tmp_path / "acme_xml.py").write_text("def parse(d):\n    return 1\n")
    (tmp_path / "app.py").write_text(
        "from acme_xml import parse\n\ndef handle(p):\n    return parse(p)\n")
    spec = DepsReproSpec(advisory="a", package="acme-xml", version="1",
                         vuln_function="acme_xml/parse", call_text="parse",
                         call_site="app.py:4", source_var="p")
    r = run_deps_repro("from app import handle\nhandle(MARKER)", spec, str(tmp_path))
    assert r.reproduced is True


class _StubClient:
    def __init__(self, driver):
        self._driver = driver; self._n = 0; self.last_call = {}

    def chat_raw(self, messages, tools):
        self._n += 1
        if self._n == 1:
            return {"content": "", "tool_calls": [{"id": "1", "function": {
                "name": "try_driver", "arguments": _json.dumps({"driver": self._driver})}}]}
        return {"content": "done", "tool_calls": []}


def test_reproduce_loop_confirms_via_project(tmp_path):
    from frame.sil.proof_deps_reproduce import reproduce_deps_finding
    spec = _mini_project(tmp_path)
    r = reproduce_deps_finding(spec, str(tmp_path), config=None,
                               client=_StubClient("from app import handle\nhandle(MARKER)"),
                               max_steps=4)
    assert r.reproduced is True
    assert "handle(MARKER)" in r.driver


def test_reproduce_loop_rejects_a_forged_direct_call(tmp_path):
    from frame.sil.proof_deps_reproduce import reproduce_deps_finding
    spec = _mini_project(tmp_path)
    r = reproduce_deps_finding(spec, str(tmp_path), config=None,
                               client=_StubClient("import acme_xml\nacme_xml.parse(MARKER)"),
                               max_steps=3)
    assert r.reproduced is False
    assert not r.driver


def test_load_dependency_findings_from_sca_json():
    from frame.cli import _load_dependency_findings
    import json as J
    payload = J.dumps({"dependencies": {"findings": [
        {"id": "CVE-1", "package": "p", "version": "1", "reachability": {"level": "tainted"}}]}})
    out = _load_dependency_findings(payload)
    assert len(out) == 1 and out[0]["id"] == "CVE-1"
    # bare list, filtered to reachability dicts
    assert _load_dependency_findings(J.dumps([{"reachability": {}}, {"x": 1}])) == [{"reachability": {}}]


def test_exploit_deps_parses_without_a_target():
    from frame.cli import create_parser
    args = create_parser().parse_args(
        ["exploit", "--deps", "--guidance", "f.json", "--root", ".", "--out-dir", "o"])
    assert args.deps is True and args.target is None and args.root == "."


from frame.sil.proof_deps import taint_repro_spec


def test_taint_spec_from_a_code_finding():
    spec = taint_repro_spec({"type": "command_injection", "cwe_id": "CWE-78",
                             "sink_call": "os.system", "location": "app.py", "line": 3,
                             "source_var": "cmd"})
    assert spec is not None
    assert spec.vuln_function == "os.system" and spec.call_site == "app.py:3"
    assert spec.source_var == "cmd" and spec.advisory == "CWE-78"


def test_taint_spec_none_for_a_bare_textual_sink():
    # a sink with no dotted/canonical path cannot be import-resolved
    assert taint_repro_spec({"type": "sql_injection", "sink_call": "execute",
                             "location": "a.py", "line": 1}) is None
    assert taint_repro_spec({"type": "sql_injection", "sink_call": "",
                             "location": "a.py", "line": 1}) is None


def test_taint_reproduction_module_function_sink(tmp_path):
    # command injection via os.system (a module-level sink)
    (tmp_path / "app.py").write_text("import os\ndef handle(cmd):\n    os.system(cmd)\n")
    spec = taint_repro_spec({"type": "command_injection", "cwe_id": "CWE-78",
                             "sink_call": "os.system", "location": "app.py", "line": 3,
                             "source_var": "cmd"})
    r = run_deps_repro("from app import handle\nhandle(MARKER)", spec, str(tmp_path))
    assert r.reproduced is True


def test_taint_reproduction_class_method_sink(tmp_path):
    # SQLi via a class method -> exercises attribute-walk patching
    (tmp_path / "db.py").write_text("class Cursor:\n    def execute(self, q):\n        return q\n")
    (tmp_path / "app.py").write_text(
        "from db import Cursor\ndef handle(q):\n    return Cursor().execute(q)\n")
    spec = taint_repro_spec({"type": "sql_injection", "cwe_id": "CWE-89",
                             "sink_call": "db.Cursor.execute", "location": "app.py", "line": 3,
                             "source_var": "q"})
    r = run_deps_repro("from app import handle\nhandle(MARKER)", spec, str(tmp_path))
    assert r.reproduced is True


import shutil as _shutil
from frame.sil.proof_deps import run_deps_repro_js

_need_node = __import__("pytest").mark.skipif(
    _shutil.which("node") is None, reason="node not available")


def _js_project(root: Path):
    (root / "shell.js").write_text(
        "const cp = require('child_process');\n"
        "module.exports.run = function(c){ return cp.exec('ping ' + c); };\n")
    (root / "routes.js").write_text(
        "const { run } = require('./shell');\n"
        "module.exports.ping = function(host){ return run(host); };\n")
    return DepsReproSpec(advisory="CWE-78", package="", version="",
                         vuln_function="child_process.exec", call_text="cp.exec",
                         call_site="shell.js:2", source_var="c")


@_need_node
def test_js_runner_confirms_a_genuine_driver(tmp_path):
    spec = _js_project(tmp_path)
    r = run_deps_repro_js("const { ping } = require('./routes');\nping(MARKER);", spec, str(tmp_path))
    assert r.reproduced is True


@_need_node
def test_js_runner_rejects_a_direct_call_cheat(tmp_path):
    spec = _js_project(tmp_path)
    r = run_deps_repro_js("require('child_process').exec(MARKER);", spec, str(tmp_path))
    assert r.reproduced is False


@_need_node
def test_js_runner_rejects_without_the_marker(tmp_path):
    spec = _js_project(tmp_path)
    r = run_deps_repro_js("const { ping } = require('./routes');\nping('benign');", spec, str(tmp_path))
    assert r.reproduced is False


from frame.sil.proof_deps import java_repro_test


def test_java_repro_test_generation():
    spec = DepsReproSpec(advisory="CWE-78", package="", version="",
                         vuln_function="java.lang.Runtime.exec", call_text="Runtime.exec",
                         call_site="app/ShellService.java:4", source_var="host")
    t = java_repro_test(spec, "new app.Api().ping(MARKER);")
    assert t is not None
    assert 'CALLSITE = "ShellService"' in t          # call-site class for the via-project guard
    assert "mockStatic(Runtime.class)" in t
    assert "new app.Api().ping(MARKER);" in t
    assert "seen[0] && seen[1]" in t                 # marker AND via-project


def test_java_repro_test_none_for_unsupported_sink():
    spec = DepsReproSpec(advisory="x", package="", version="", vuln_function="com.acme.Foo.bar",
                         call_text="bar", call_site="a.java:1", source_var="x")
    assert java_repro_test(spec, "x") is None
