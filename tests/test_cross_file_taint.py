"""Taint across the files of a project (Python, JS/TS).

A handler in one file that passes request data to a helper in another, or calls a
helper that returns request data, is one flow. Each positive is paired with the
nearest safe shape (a constant argument, a sanitizing helper, an import that
cannot be resolved) so following imports does not turn into noise. Resolution is
deliberately narrow -- plain functions reached through a resolvable import --
and the tests pin both what resolves and what must not.
"""

import json
import subprocess
from pathlib import Path

import pytest

from frame.cli import main as frame_main
from frame.sil.project import ProjectIndex
from frame.sil.scanner import FrameScanner


def write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def findings(root: Path, cross_file: bool = True, **kw):
    """{(file name, CWE)} of a directory scan."""
    results = FrameScanner(verify=False).scan_directory(
        str(root), None, cross_file=cross_file, **kw)
    return {(Path(r.filename).name, v.cwe_id) for r in results for v in r.vulnerabilities}


FLASK = "from flask import Flask, request\n{imports}\napp = Flask(__name__)\n"

DB = """import sqlite3

def run_query(q):
    conn = sqlite3.connect("x")
    return conn.execute("SELECT * FROM u WHERE n = '%s'" % q)
"""


def views(imports: str, call: str) -> str:
    return (FLASK.format(imports=imports)
            + f'\n@app.route("/u")\ndef u():\n    return str({call})\n')


# ---- Python: what resolves -----------------------------------------------------

@pytest.mark.parametrize("imports,call", [
    ("from db import run_query", 'run_query(request.args.get("n"))'),
    ("import db", 'db.run_query(request.args.get("n"))'),
    ("import db as d", 'd.run_query(request.args.get("n"))'),
    ("from db import run_query as rq", 'rq(request.args.get("n"))'),
    ("from db import run_query", 'run_query(request.args["n"])'),
])
def test_python_import_forms_carry_taint_into_the_helper(tmp_path, imports, call):
    write(tmp_path, {"db.py": DB, "views.py": views(imports, call)})
    assert ("db.py", "CWE-89") in findings(tmp_path)


def test_python_flow_is_not_found_without_cross_file(tmp_path):
    write(tmp_path, {"db.py": DB,
                     "views.py": views("from db import run_query", 'run_query(request.args.get("n"))')})
    assert ("db.py", "CWE-89") not in findings(tmp_path, cross_file=False)


def test_python_constant_argument_is_clean(tmp_path):
    write(tmp_path, {"db.py": DB, "views.py": views("from db import run_query", 'run_query("bob")')})
    assert ("db.py", "CWE-89") not in findings(tmp_path)


def test_python_package_relative_imports(tmp_path):
    write(tmp_path, {
        "app/__init__.py": "",
        "app/db.py": DB,
        "app/views.py": views("from . import db", 'db.run_query(request.args.get("n"))'),
        "app/other.py": views("from .db import run_query", 'run_query(request.args.get("n"))'),
    })
    assert ("db.py", "CWE-89") in findings(tmp_path)


def test_python_absolute_package_import(tmp_path):
    write(tmp_path, {
        "src/app/__init__.py": "",
        "src/app/db.py": DB,
        "src/app/views.py": views("from app.db import run_query",
                                  'run_query(request.args.get("n"))'),
    })
    assert ("db.py", "CWE-89") in findings(tmp_path)


def test_python_reexport_through_package_init(tmp_path):
    write(tmp_path, {
        "app/__init__.py": "from .db import run_query\n",
        "app/db.py": DB,
        "web.py": views("from app import run_query", 'run_query(request.args.get("n"))'),
    })
    assert ("db.py", "CWE-89") in findings(tmp_path)


def test_python_flow_through_a_chain_of_three_files(tmp_path):
    write(tmp_path, {
        "db.py": DB,
        "service.py": "from db import run_query\n\ndef find(name):\n    return run_query(name)\n",
        "views.py": views("from service import find", 'find(request.args.get("n"))'),
    })
    assert ("db.py", "CWE-89") in findings(tmp_path)


def test_python_helper_used_with_tainted_and_constant_callers(tmp_path):
    write(tmp_path, {
        "db.py": DB,
        "views.py": views("from db import run_query", 'run_query(request.args.get("n"))'),
        "jobs.py": "from db import run_query\n\ndef nightly():\n    run_query('stats')\n",
    })
    assert ("db.py", "CWE-89") in findings(tmp_path)


def test_python_circular_imports_terminate(tmp_path):
    write(tmp_path, {
        "a.py": "import b\n\ndef fa(x):\n    return b.fb(x)\n",
        "b.py": "import os\nimport a\n\ndef fb(x):\n    os.system('ls ' + x)\n",
        "views.py": views("import a", 'a.fa(request.args.get("d"))'),
    })
    assert ("b.py", "CWE-78") in findings(tmp_path)


# ---- Python: what must not resolve ----------------------------------------------

def test_python_local_definition_wins_over_import(tmp_path):
    write(tmp_path, {
        "db.py": DB,
        "views.py": (FLASK.format(imports="from db import run_query")
                     + '\ndef run_query(q):\n    return q\n\n@app.route("/u")\n'
                       'def u():\n    return str(run_query(request.args.get("n")))\n'),
    })
    assert ("db.py", "CWE-89") not in findings(tmp_path)


def test_python_ambiguous_module_name_is_not_guessed(tmp_path):
    write(tmp_path, {
        "x/helpers.py": DB, "y/helpers.py": DB,
        "views.py": views("from helpers import run_query", 'run_query(request.args.get("n"))'),
    })
    assert findings(tmp_path) == set()


def test_python_unresolvable_import_is_harmless(tmp_path):
    write(tmp_path, {
        "views.py": views("from vendor_lib import run_query", 'run_query(request.args.get("n"))'),
        "other.py": "x = 1\n",
    })
    assert findings(tmp_path) == set()


def test_python_method_on_an_object_is_not_resolved(tmp_path):
    write(tmp_path, {
        "svc.py": "import os\n\nclass Svc:\n    def run(self, d):\n        os.system('ls ' + d)\n",
        "views.py": views("from svc import Svc", 'Svc().run(request.args.get("d"))'),
    })
    assert ("svc.py", "CWE-78") not in findings(tmp_path)


def test_python_a_lone_file_is_scanned_alone(tmp_path):
    write(tmp_path, {"db.py": DB,
                     "views.py": views("from db import run_query", 'run_query(request.args.get("n"))')})
    assert FrameScanner(verify=False).scan_file(str(tmp_path / "db.py")).vulnerabilities == []


# ---- Python: sanitizers and return values -----------------------------------------

def test_python_caller_sanitizes_before_the_call(tmp_path):
    write(tmp_path, {
        "run.py": "import os\n\ndef go(d):\n    os.system('ls ' + d)\n",
        "views.py": views("import shlex\nfrom run import go",
                          'go(shlex.quote(request.args.get("d")))'),
    })
    assert ("run.py", "CWE-78") not in findings(tmp_path)


def test_python_helper_returns_request_data(tmp_path):
    write(tmp_path, {
        "inputs.py": "from flask import request\n\ndef get_dir():\n    return request.args.get('d')\n",
        "views.py": ("import os\nfrom inputs import get_dir\nfrom flask import Flask\napp = Flask(__name__)\n"
                     '\n@app.route("/a")\ndef a():\n    os.system("ls " + get_dir())\n    return "ok"\n'),
    })
    assert ("views.py", "CWE-78") in findings(tmp_path)


def test_python_helper_returns_sanitized_value(tmp_path):
    write(tmp_path, {
        "inputs.py": ("import shlex\nfrom flask import request\n\n"
                      "def get_dir():\n    return shlex.quote(request.args.get('d'))\n"),
        "views.py": ("import os\nfrom inputs import get_dir\nfrom flask import Flask\napp = Flask(__name__)\n"
                     '\n@app.route("/a")\ndef a():\n    os.system("ls " + get_dir())\n    return "ok"\n'),
    })
    assert ("views.py", "CWE-78") not in findings(tmp_path)


def test_python_helper_passes_its_argument_through(tmp_path):
    write(tmp_path, {
        "util.py": "def ident(x):\n    return x\n",
        "views.py": ("import os\nfrom util import ident\nfrom flask import Flask, request\n"
                     'app = Flask(__name__)\n\n@app.route("/a")\ndef a():\n'
                     '    os.system("ls " + ident(request.args.get("d")))\n    return "ok"\n'),
    })
    assert ("views.py", "CWE-78") in findings(tmp_path)


def test_python_helper_that_drops_its_argument_is_clean(tmp_path):
    write(tmp_path, {
        "util.py": "def fixed(x):\n    return '/tmp'\n",
        "views.py": ("import os\nfrom util import fixed\nfrom flask import Flask, request\n"
                     'app = Flask(__name__)\n\n@app.route("/a")\ndef a():\n'
                     '    os.system("ls " + fixed(request.args.get("d")))\n    return "ok"\n'),
    })
    assert ("views.py", "CWE-78") not in findings(tmp_path)


def test_python_finding_location_is_the_scanned_path(tmp_path):
    write(tmp_path, {"db.py": DB,
                     "views.py": views("from db import run_query", 'run_query(request.args.get("n"))')})
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    for r in results:
        for v in r.vulnerabilities:
            assert v.location == r.filename          # not a resolved/absolute variant
    flow = next(v for r in results for v in r.vulnerabilities if v.cwe_id == "CWE-89")
    assert "views.py" in flow.source_location and flow.data_flow


# ---- JS / TS ---------------------------------------------------------------------------

STORE = """const { exec } = require('child_process');
function run(d) { exec('ls ' + d); }
module.exports = { run };
"""

EXPRESS = "const express = require('express');\nconst app = express();\n"


@pytest.mark.parametrize("name,header,call", [
    ("a.js", "const store = require('./store');", "store.run(req.query.dir)"),
    ("b.js", "const { run } = require('./store');", "run(req.query.dir)"),
    ("c.js", "const { run: go } = require('./store.js');", "go(req.query.dir)"),
])
def test_js_require_forms(tmp_path, name, header, call):
    write(tmp_path, {
        "store.js": STORE,
        name: EXPRESS + header + f"\napp.get('/a', (req, res) => {{ {call}; res.send('ok'); }});\n",
    })
    assert ("store.js", "CWE-78") in findings(tmp_path)


def test_js_constant_argument_is_clean(tmp_path):
    write(tmp_path, {
        "store.js": STORE,
        "a.js": EXPRESS + "const { run } = require('./store');\n"
                          "app.get('/a', (req, res) => { run('/tmp'); res.send('ok'); });\n",
    })
    assert ("store.js", "CWE-78") not in findings(tmp_path)


@pytest.mark.parametrize("exports", [
    "exports.run = function (d) { exec('ls ' + d); };",
    "module.exports.run = (d) => { exec('ls ' + d); };",
    "function run(d) { exec('ls ' + d); }\nmodule.exports = { run };",
    "function run(d) { exec('ls ' + d); }\nmodule.exports = { run: run };",
])
def test_js_export_forms(tmp_path, exports):
    write(tmp_path, {
        "store.js": "const { exec } = require('child_process');\n" + exports + "\n",
        "a.js": EXPRESS + "const { run } = require('./store');\n"
                          "app.get('/a', (req, res) => { run(req.query.dir); res.send('ok'); });\n",
    })
    assert ("store.js", "CWE-78") in findings(tmp_path)


def test_ts_es_modules(tmp_path):
    write(tmp_path, {
        "store.ts": ("import { exec } from 'child_process';\n"
                     "export function run(d: string) { exec('ls ' + d); }\n"),
        "a.ts": ("import express from 'express';\nimport { run } from './store';\n"
                 "const app = express();\n"
                 "app.get('/a', (req, res) => { run(req.query.dir as string); res.send('ok'); });\n"),
    })
    assert ("store.ts", "CWE-78") in findings(tmp_path)


def test_ts_namespace_import_and_index_file(tmp_path):
    write(tmp_path, {
        "lib/index.ts": ("import { exec } from 'child_process';\n"
                         "export const run = (d: string) => { exec('ls ' + d); };\n"),
        "a.ts": ("import express from 'express';\nimport * as lib from './lib';\n"
                 "const app = express();\n"
                 "app.get('/a', (req, res) => { lib.run(req.query.dir as string); res.send('ok'); });\n"),
    })
    assert ("index.ts", "CWE-78") in findings(tmp_path)


def test_js_reexport_through_a_barrel(tmp_path):
    write(tmp_path, {
        "impl.js": STORE,
        "barrel.js": "export { run } from './impl';\n",
        "a.js": EXPRESS + "const { run } = require('./barrel');\n"
                          "app.get('/a', (req, res) => { run(req.query.dir); res.send('ok'); });\n",
    })
    assert ("impl.js", "CWE-78") in findings(tmp_path)


def test_js_helper_returns_request_data(tmp_path):
    write(tmp_path, {
        "inputs.js": "function getDir(req) { return req.query.dir; }\nmodule.exports = { getDir };\n",
        "a.js": EXPRESS + "const { exec } = require('child_process');\n"
                          "const { getDir } = require('./inputs');\n"
                          "app.get('/a', (req, res) => { exec('ls ' + getDir(req)); res.send('ok'); });\n",
    })
    assert ("a.js", "CWE-78") in findings(tmp_path)


def test_js_package_import_is_not_a_project_file(tmp_path):
    write(tmp_path, {
        "a.js": EXPRESS + "const { run } = require('some-package');\n"
                          "app.get('/a', (req, res) => { run(req.query.dir); res.send('ok'); });\n",
        "b.js": "const x = 1;\n",
    })
    assert findings(tmp_path) == set()


# ---- the project index ---------------------------------------------------------------------

def _index(root: Path) -> ProjectIndex:
    from frame.sil.frontends.javascript_frontend import JavaScriptFrontend, TypeScriptFrontend
    from frame.sil.frontends.python_frontend import PythonFrontend
    fes = {"python": PythonFrontend(), "javascript": JavaScriptFrontend(),
           "typescript": TypeScriptFrontend()}
    files = [p for p in sorted(root.rglob("*")) if p.suffix in (".py", ".js", ".ts")]
    index = ProjectIndex(root, files, lambda lang: fes[lang].parser)
    for key, mod in index.modules.items():
        fe = fes["python"] if mod.family == "python" else fes["javascript"]
        index.set_procedures(key, fe.translate(mod.path.read_text(), str(mod.path)).procedures)
    return index


def test_index_closure_covers_importers_then_their_imports(tmp_path):
    write(tmp_path, {
        "leaf.py": "def f(): pass\n",
        "mid.py": "import leaf\n",
        "top.py": "import mid\n",
        "sibling.py": "import leaf\n",
        "island.py": "x = 1\n",
    })
    index = _index(tmp_path)
    closure = index.closure(["mid.py"])
    assert closure.files[0] == "mid.py"
    assert set(closure.files) == {"mid.py", "top.py", "leaf.py"}        # not sibling/island
    assert index.closure(["leaf.py"]).files[0] == "leaf.py"
    assert set(index.closure(["leaf.py"]).files) == {"leaf.py", "mid.py", "top.py", "sibling.py"}


def test_index_closure_truncates_nearest_first(tmp_path):
    write(tmp_path, {"a.py": "import b\n", "b.py": "import c\n", "c.py": "x = 1\n", "d.py": "import a\n"})
    index = _index(tmp_path)
    closure = index.closure(["b.py"], limit=2)
    assert closure.truncated and closure.files[0] == "b.py" and len(closure.files) == 2


def test_index_resolves_what_it_documents(tmp_path):
    write(tmp_path, {
        "app/__init__.py": "from .db import run_query\n",
        "app/db.py": DB,
        "app/views.py": ("import app.db\nimport app.db as m\nfrom app.db import run_query as rq\n"
                         "from . import db\nimport json\n"),
    })
    index = _index(tmp_path)
    target = ("app/db.py", "run_query")
    for name in ("app.db.run_query", "m.run_query", "rq", "db.run_query"):
        assert index.resolve_call("app/views.py", name) == target, name
    for name in ("json.dumps", "db.nothing", "run_query_typo", "app.db"):
        assert index.resolve_call("app/views.py", name) is None, name


# ---- --changed, baselines and verify -----------------------------------------------------------

def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
                   check=True, capture_output=True)


@pytest.fixture
def clean_repo(tmp_path, monkeypatch):
    write(tmp_path, {"db.py": DB,
                     "views.py": views("from db import run_query", 'run_query("bob")')})
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run_scan(capsys, *args):
    rc = frame_main(["scan", ".", "--no-verify", "-f", "json", *args])
    captured = capsys.readouterr()
    return rc, json.loads(captured.out), captured.err


def new_cwes(doc):
    return {(Path(f["filename"]).name, v["cwe_id"]) for f in doc["files"] for v in f["vulnerabilities"]}


def test_editing_only_the_caller_surfaces_a_new_finding_in_the_untouched_callee(clean_repo, capsys):
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "--write-baseline", "bl.json"])
    capsys.readouterr()
    (clean_repo / "views.py").write_text(
        views("from db import run_query", 'run_query(request.args.get("n"))'))
    rc, doc, _ = run_scan(capsys, "--changed", "--baseline", "bl.json")
    assert rc == 1
    assert new_cwes(doc) == {("db.py", "CWE-89")}
    assert doc["scope"]["cross_file"] and doc["scope"]["selected"] == 1 and doc["scope"]["files"] == 2
    finding = doc["files"][0]["vulnerabilities"][0] if doc["files"][0]["vulnerabilities"] \
        else doc["files"][1]["vulnerabilities"][0]
    assert "views.py" in finding["data_flow"][0] and finding["path"] == "db.py"


def test_the_same_edit_is_invisible_without_cross_file(clean_repo, capsys):
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "--write-baseline", "bl.json"])
    capsys.readouterr()
    (clean_repo / "views.py").write_text(
        views("from db import run_query", 'run_query(request.args.get("n"))'))
    rc, doc, _ = run_scan(capsys, "--changed", "--baseline", "bl.json", "--no-cross-file")
    assert rc == 0 and new_cwes(doc) == set()


def test_editing_the_callee_surfaces_a_finding_for_callers_that_pass_request_data(tmp_path, monkeypatch, capsys):
    safe_db = DB.replace("""execute("SELECT * FROM u WHERE n = '%s'" % q)""",
                         """execute("SELECT * FROM u WHERE n = ?", (q,))""")
    write(tmp_path, {"db.py": safe_db,
                     "views.py": views("from db import run_query", 'run_query(request.args.get("n"))')})
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    monkeypatch.chdir(tmp_path)
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "--write-baseline", "bl.json"])
    capsys.readouterr()
    (tmp_path / "db.py").write_text(DB)                      # an agent "simplifies" the query
    rc, doc, _ = run_scan(capsys, "--changed", "--baseline", "bl.json")
    assert rc == 1 and new_cwes(doc) == {("db.py", "CWE-89")}


def test_unrelated_files_are_not_pulled_into_a_narrow_scan(clean_repo, capsys):
    write(clean_repo, {"island.py": "x = 1\n", "other.py": "import island\n"})
    git(clean_repo, "add", "-A")
    git(clean_repo, "commit", "-qm", "more")
    (clean_repo / "views.py").write_text(
        views("from db import run_query", 'run_query(request.args.get("n"))') + "\n# touched\n")
    _, doc, _ = run_scan(capsys, "--changed", "--fail-on", "none")
    assert doc["scope"]["files"] == 2          # views + db, not island/other


def test_a_full_scan_over_the_limit_analyses_files_alone_with_a_warning(clean_repo, capsys):
    (clean_repo / "views.py").write_text(
        views("from db import run_query", 'run_query(request.args.get("n"))'))
    rc, doc, err = run_scan(capsys, "--cross-file-limit", "1", "--fail-on", "none")
    assert new_cwes(doc) == set()
    assert doc["scope"]["cross_file"] is False and "exceed the cross-file limit" in err


def test_a_narrow_scan_over_the_limit_is_truncated_with_a_warning(clean_repo, capsys):
    (clean_repo / "views.py").write_text(
        views("from db import run_query", 'run_query(request.args.get("n"))'))
    _, doc, err = run_scan(capsys, "--changed", "--cross-file-limit", "1", "--fail-on", "none")
    assert doc["scope"]["truncated"] and "cut at 1 files" in err


def _verify(capsys, path):
    rc = frame_main(["verify", str(path), "-f", "json"])
    doc = json.loads(capsys.readouterr().out)
    return rc, [r["status"] for r in doc["results"]]


@pytest.fixture
def flagged(clean_repo, capsys):
    (clean_repo / "views.py").write_text(
        views("from db import run_query", 'run_query(request.args.get("n"))'))
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "-f", "json", "-o", "findings.json"])
    capsys.readouterr()
    return clean_repo / "findings.json"


def test_verify_a_cross_file_finding_is_present_while_the_caller_still_passes_data(flagged, capsys):
    # Re-scanning db.py alone would call this fixed: it only exists because of views.py.
    assert _verify(capsys, flagged) == (1, ["present"])


def test_verify_fixed_when_the_caller_stops_passing_request_data(flagged, capsys):
    (flagged.parent / "views.py").write_text(views("from db import run_query", 'run_query("bob")'))
    assert _verify(capsys, flagged) == (0, ["fixed"])


def test_verify_fixed_when_the_sink_is_parameterised(flagged, capsys):
    (flagged.parent / "db.py").write_text(DB.replace(
        """execute("SELECT * FROM u WHERE n = '%s'" % q)""",
        """execute("SELECT * FROM u WHERE n = ?", (q,))"""))
    assert _verify(capsys, flagged) == (0, ["fixed"])


# ---- cli ------------------------------------------------------------------------------------------

def test_cli_text_reports_the_cross_file_scope(clean_repo, capsys):
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none"])
    assert "Cross-file analysis: 2 files" in capsys.readouterr().out
    frame_main(["scan", ".", "--no-verify", "--fail-on", "none", "--no-cross-file"])
    assert "Cross-file analysis" not in capsys.readouterr().out


# ---- depth, order independence, and the safety budget ----------------------------------------

def _chain(root: Path, depth: int, reverse_names: bool, returns: bool) -> None:
    """m0 -> m1 -> ... -> m(depth-1). `reverse_names` makes file names sort opposite to the
    call direction (the worst case for a fixpoint that visits files in name order)."""
    def name(i):
        return f"m{depth - i:04d}" if reverse_names else f"m{i:04d}"
    files = {}
    for i in range(depth):
        nxt = name(i + 1)
        if returns:
            if i == 0:
                files[name(i)] = ("import os\nfrom flask import Flask\nimport %s\napp = Flask(__name__)\n"
                                  "\n@app.route('/a')\ndef h():\n    os.system('ls ' + %s.f())\n"
                                  "    return 'ok'\n") % (nxt, nxt)
            elif i == depth - 1:
                files[name(i)] = "from flask import request\n\ndef f():\n    return request.args.get('d')\n"
            else:
                files[name(i)] = f"import {nxt}\n\ndef f():\n    return {nxt}.f()\n"
        else:
            if i == 0:
                files[name(i)] = ("from flask import Flask, request\nimport %s\napp = Flask(__name__)\n"
                                  "\n@app.route('/a')\ndef h():\n    %s.f(request.args.get('d'))\n"
                                  "    return 'ok'\n") % (nxt, nxt)
            elif i == depth - 1:
                files[name(i)] = "import os\n\ndef f(x):\n    os.system('ls ' + x)\n"
            else:
                files[name(i)] = f"import {nxt}\n\ndef f(x):\n    return {nxt}.f(x)\n"
    write(root, {f"{k}.py": v for k, v in files.items()})


@pytest.mark.parametrize("reverse_names", [False, True])
@pytest.mark.parametrize("returns", [False, True])
def test_a_long_chain_of_files_is_followed_in_either_direction(tmp_path, reverse_names, returns):
    _chain(tmp_path, 40, reverse_names, returns)
    assert any(cwe == "CWE-78" for _, cwe in findings(tmp_path))


def test_results_do_not_depend_on_the_order_files_are_reported_in(tmp_path, monkeypatch):
    write(tmp_path, {
        "db.py": DB,
        "service.py": "from db import run_query\n\ndef find(name):\n    return run_query(name)\n",
        "views.py": views("from service import find", 'find(request.args.get("n"))'),
        "inputs.py": "from flask import request\n\ndef get():\n    return request.args.get('d')\n",
        "run.py": ("import os\nfrom inputs import get\n\ndef go():\n    os.system('ls ' + get())\n"),
    })
    forward = findings(tmp_path)
    original = FrameScanner._candidate_files

    def reversed_candidates(self, *a, **kw):
        return list(reversed(original(self, *a, **kw)))

    monkeypatch.setattr(FrameScanner, "_candidate_files", reversed_candidates)
    assert findings(tmp_path) == forward and ("db.py", "CWE-89") in forward \
        and ("run.py", "CWE-78") in forward


def test_an_exhausted_budget_is_reported_not_silent(tmp_path, monkeypatch, capsys):
    from frame.sil import translator
    _chain(tmp_path, 30, True, False)
    monkeypatch.setattr(translator, "IPA_VISITS_PER_PROC", 0)
    monkeypatch.setattr(translator, "IPA_EXTRA_VISITS", 5)
    monkeypatch.chdir(tmp_path)
    rc = frame_main(["scan", ".", "--no-verify", "-f", "json", "--fail-on", "none"])
    captured = capsys.readouterr()
    assert json.loads(captured.out)["scope"]["complete"] is False
    assert "ran out of its budget" in captured.err


# ---- callable and default-exported functions --------------------------------------------------

def test_js_callable_module(tmp_path):
    write(tmp_path, {
        "run.js": ("const { exec } = require('child_process');\n"
                   "module.exports = function (d) { exec('ls ' + d); };\n"),
        "a.js": EXPRESS + "const run = require('./run');\n"
                          "app.get('/a', (req, res) => { run(req.query.dir); res.send('ok'); });\n",
    })
    assert ("run.js", "CWE-78") in findings(tmp_path)


def test_js_callable_module_with_a_constant_argument_is_clean(tmp_path):
    write(tmp_path, {
        "run.js": ("const { exec } = require('child_process');\n"
                   "module.exports = function (d) { exec('ls ' + d); };\n"),
        "a.js": EXPRESS + "const run = require('./run');\n"
                          "app.get('/a', (req, res) => { run('/tmp'); res.send('ok'); });\n",
    })
    assert ("run.js", "CWE-78") not in findings(tmp_path)


def test_ts_default_export_of_a_named_function(tmp_path):
    write(tmp_path, {
        "run.ts": ("import { exec } from 'child_process';\n"
                   "export default function run(d: string) { exec('ls ' + d); }\n"),
        "a.ts": ("import express from 'express';\nimport run from './run';\nconst app = express();\n"
                 "app.get('/a', (req, res) => { run(req.query.dir as string); res.send('ok'); });\n"),
    })
    assert ("run.ts", "CWE-78") in findings(tmp_path)


# ---- a baselined cross-file finding keeps its identity as the caller grows ---------------------

def test_cross_file_fingerprint_survives_unrelated_calls_added_above_the_flow(tmp_path):
    from frame.sil.fingerprints import assign_fingerprints

    def fingerprints():
        results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
        assign_fingerprints(results, tmp_path)
        return sorted(v.fingerprint for r in results for v in r.vulnerabilities)

    write(tmp_path, {"db.py": DB,
                     "views.py": views("from db import run_query", 'run_query(request.args.get("n"))')})
    before = fingerprints()
    assert len(before) == 1
    # Unrelated calls renumber the frontend's temporaries (`__nested_1` -> `__nested_7`).
    text = (tmp_path / "views.py").read_text().replace(
        "def u():\n", "def u():\n    x = str(len('abc'))\n    y = str(len(x))\n", 1)
    (tmp_path / "views.py").write_text(text)
    assert fingerprints() == before


# ---- classes: static calls, instances, injected and inherited receivers ---------------------------

REPO_PY = """import sqlite3

class Repo:
    def find(self, name):
        return sqlite3.connect("x").execute("SELECT * FROM u WHERE n = '%s'" % name)

    @staticmethod
    def create(name):
        return sqlite3.connect("x").execute("INSERT INTO u VALUES ('%s')" % name)

    @classmethod
    def build(cls, name):
        return sqlite3.connect("x").execute("INSERT INTO u VALUES ('%s')" % name)
"""


def handler(body: str, imports: str = "from repo import Repo") -> str:
    return (FLASK.format(imports=imports) + f'\n@app.route("/a")\ndef a():\n{body}\n    return "ok"\n')


@pytest.mark.parametrize("body", [
    '    Repo.create(request.args.get("n"))',
    '    Repo.build(request.args.get("n"))',
    '    r = Repo()\n    r.find(request.args.get("n"))',
    '    Repo().find(request.args.get("n"))',
])
def test_python_class_calls_carry_taint(tmp_path, body):
    write(tmp_path, {"repo.py": REPO_PY, "views.py": handler(body)})
    assert ("repo.py", "CWE-89") in findings(tmp_path)


@pytest.mark.parametrize("body", [
    '    Repo.create("bob")',
    '    r = Repo()\n    r.find("bob")',
])
def test_python_class_calls_with_constant_arguments_are_clean(tmp_path, body):
    write(tmp_path, {"repo.py": REPO_PY, "views.py": handler(body)})
    assert ("repo.py", "CWE-89") not in findings(tmp_path)


def test_python_instance_held_on_self(tmp_path):
    write(tmp_path, {"repo.py": REPO_PY, "views.py": (
        FLASK.format(imports="from repo import Repo")
        + "\nclass Service:\n    def __init__(self):\n        self.repo = Repo()\n\n"
          "    def lookup(self):\n        return self.repo.find(request.args.get('n'))\n")})
    assert ("repo.py", "CWE-89") in findings(tmp_path)


def test_python_annotated_parameter_gives_the_receiver_its_class(tmp_path):
    write(tmp_path, {"repo.py": REPO_PY, "views.py": (
        FLASK.format(imports="from repo import Repo")
        + "\ndef lookup(repo: Repo):\n    return repo.find(request.args.get('n'))\n")})
    assert ("repo.py", "CWE-89") in findings(tmp_path)


def test_python_method_inherited_from_a_base_class(tmp_path):
    write(tmp_path, {"repo.py": REPO_PY + "\nclass Cached(Repo):\n    pass\n",
                     "views.py": handler('    Cached().find(request.args.get("n"))',
                                         "from repo import Cached")})
    assert ("repo.py", "CWE-89") in findings(tmp_path)


def test_python_receiver_with_conflicting_classes_is_not_guessed(tmp_path):
    write(tmp_path, {
        "repo.py": REPO_PY,
        "other.py": "class Other:\n    def find(self, name):\n        return name\n",
        "views.py": handler('    r = Repo()\n    r = Other()\n    r.find(request.args.get("n"))',
                            "from repo import Repo\nfrom other import Other"),
    })
    assert ("repo.py", "CWE-89") not in findings(tmp_path)


def test_python_receiver_from_a_factory_is_not_guessed(tmp_path):
    write(tmp_path, {
        "repo.py": REPO_PY,
        "views.py": handler('    r = make_repo()\n    r.find(request.args.get("n"))',
                            "from repo import Repo\n\ndef make_repo():\n    return Repo()"),
    })
    assert ("repo.py", "CWE-89") not in findings(tmp_path)


def test_python_instance_method_called_unbound_is_not_resolved(tmp_path):
    # `Repo.find(obj, q)` passes the instance explicitly; only static/class methods are resolved
    write(tmp_path, {"repo.py": REPO_PY,
                     "views.py": handler('    Repo.find(None, request.args.get("n"))')})
    assert ("repo.py", "CWE-89") not in findings(tmp_path)


def test_python_async_static_dao_like_dvpwa(tmp_path):
    write(tmp_path, {
        "dao.py": ("class Student:\n    @staticmethod\n    async def create(conn, name):\n"
                   "        q = (\"INSERT INTO students (name) VALUES ('%(name)s')\" % {'name': name})\n"
                   "        async with conn.cursor() as cur:\n            await cur.execute(q)\n"),
        "views.py": ("from aiohttp.web import Request\nfrom dao import Student\n\n"
                     "async def students(request: Request, conn):\n"
                     "    data = await request.post()\n"
                     "    await Student.create(conn, data['name'])\n"),
    })
    assert ("dao.py", "CWE-89") in findings(tmp_path)


DAO_TS = ("import { exec } from 'child_process';\n"
          "export class Dao {\n"
          "  run(d: string) { exec('ls ' + d); }\n"
          "  static go(d: string) { exec('ls ' + d); }\n"
          "}\n")


@pytest.mark.parametrize("body", [
    "const d = new Dao(); d.run(req.query.dir as string);",
    "Dao.go(req.query.dir as string);",
])
def test_ts_class_calls_carry_taint(tmp_path, body):
    write(tmp_path, {"dao.ts": DAO_TS, "a.ts": (
        "import express from 'express';\nimport { Dao } from './dao';\nconst app = express();\n"
        "app.get('/a', (req, res) => { " + body + " res.send('ok'); });\n")})
    assert ("dao.ts", "CWE-78") in findings(tmp_path)


def test_ts_constructor_injected_dependency(tmp_path):
    write(tmp_path, {"dao.ts": DAO_TS, "svc.ts": (
        "import { Dao } from './dao';\n"
        "export class Service {\n"
        "  constructor(private readonly dao: Dao) {}\n"
        "  handle(req: any) { this.dao.run(req.query.dir); }\n"
        "}\n")})
    assert ("dao.ts", "CWE-78") in findings(tmp_path)


def test_js_constructor_function_dao_like_nodegoat(tmp_path):
    write(tmp_path, {
        "dao.js": ("const { exec } = require('child_process');\n"
                   "const Dao = function (db) {\n"
                   "  this.run = (d, cb) => { exec('ls ' + d); };\n"
                   "  this.other = (x) => { return x; };\n"
                   "};\n"
                   "module.exports.Dao = Dao;\n"),
        "handler.js": ("const Dao = require('./dao').Dao;\n"
                       "function Handler(db) {\n"
                       "  const dao = new Dao(db);\n"
                       "  this.show = (req, res) => { dao.run(req.query.dir, () => res.send('ok')); };\n"
                       "}\n"),
    })
    assert ("dao.js", "CWE-78") in findings(tmp_path)


def test_js_constructor_function_dao_with_a_constant_is_clean(tmp_path):
    write(tmp_path, {
        "dao.js": ("const { exec } = require('child_process');\n"
                   "const Dao = function (db) {\n  this.run = (d) => { exec('ls ' + d); };\n};\n"
                   "module.exports.Dao = Dao;\n"),
        "handler.js": ("const Dao = require('./dao').Dao;\n"
                       "function Handler(db) {\n  const dao = new Dao(db);\n"
                       "  this.show = (req, res) => { dao.run('/tmp'); res.send('ok'); };\n}\n"),
    })
    assert ("dao.js", "CWE-78") not in findings(tmp_path)


def test_two_constructor_functions_with_the_same_method_name_are_kept_apart(tmp_path):
    write(tmp_path, {
        "dao.js": ("const { exec } = require('child_process');\n"
                   "const Unsafe = function () { this.go = (d) => { exec('ls ' + d); }; };\n"
                   "const Safe = function () { this.go = (d) => { return d; }; };\n"
                   "module.exports = { Unsafe, Safe };\n"),
        "h.js": ("const { Safe } = require('./dao');\n"
                 "function H() {\n  const s = new Safe();\n"
                 "  this.show = (req, res) => { s.go(req.query.dir); res.send('ok'); };\n}\n"),
    })
    assert ("dao.js", "CWE-78") not in findings(tmp_path)


def test_python_field_assigned_from_annotated_constructor_parameter(tmp_path):
    write(tmp_path, {"repo.py": REPO_PY, "svc.py": (
        FLASK.format(imports="from repo import Repo")
        + "\nclass Svc:\n    def __init__(self, repo: Repo):\n        self.repo = repo\n\n"
          "    def go(self):\n        return self.repo.find(request.args.get('n'))\n")})
    assert ("repo.py", "CWE-89") in findings(tmp_path)


def test_js_constructor_function_exported_as_the_whole_module(tmp_path):
    write(tmp_path, {
        "dao.js": ("const { exec } = require('child_process');\n"
                   "function Dao() {\n  this.run = (d) => { exec('ls ' + d); };\n}\n"
                   "module.exports = Dao;\n"),
        "h.js": ("const Dao = require('./dao');\n"
                 "function H() {\n  const dao = new Dao();\n"
                 "  this.show = (req, res) => { dao.run(req.query.dir); res.send('ok'); };\n}\n"),
    })
    assert ("dao.js", "CWE-78") in findings(tmp_path)


# ---- scanning a subdirectory of a project: imports rooted above the target -------------------

def _pkg_repo(tmp_path):
    write(tmp_path, {
        "app/dao/student.py": ("import sqlite3\n\n\ndef create(name):\n"
                               "    return sqlite3.connect('x').execute(\"INSERT INTO s VALUES ('%s')\" % name)\n"),
        "app/views.py": (FLASK.format(imports="from app.dao.student import create")
                         + "\n@app.route('/a')\ndef a():\n    create(request.args.get('n'))\n    return 'ok'\n"),
        "other/unrelated.py": "import os\n\n\ndef f(x):\n    os.system('ls ' + x)\n",
    })
    return tmp_path


def _scan_sub(root, sub, **kw):
    s = FrameScanner(verify=False)
    res = s.scan_directory(str(root / sub), None, project_root=str(root), **kw)
    return s, {(Path(r.filename).relative_to(root).as_posix(), v.cwe_id)
               for r in res for v in r.vulnerabilities}


def test_subdirectory_scan_resolves_imports_rooted_above_it(tmp_path):
    root = _pkg_repo(tmp_path)
    scanner, found = _scan_sub(root, "app")
    assert ("app/dao/student.py", "CWE-89") in found
    assert scanner.last_project_scope["context_root"] == str(root.resolve())


def test_subdirectory_scan_reports_only_the_target(tmp_path):
    root = _pkg_repo(tmp_path)
    _, found = _scan_sub(root, "app")
    assert not any(f.startswith("other/") for f, _ in found)


def test_subdirectory_scan_equals_the_same_files_in_a_root_scan(tmp_path):
    root = _pkg_repo(tmp_path)
    _, sub = _scan_sub(root, "app")
    _, whole = _scan_sub(root, ".")
    assert sub == {f for f in whole if f[0].startswith("app/")}


def test_subdirectory_scan_over_the_limit_warns_and_scans_the_target_alone(tmp_path):
    root = _pkg_repo(tmp_path)
    scanner, found = _scan_sub(root, "app", cross_file_limit=2)
    assert ("app/dao/student.py", "CWE-89") not in found
    assert "imports rooted above" in scanner.last_project_scope.get("context", "")
