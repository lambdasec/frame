"""`frame query`: engine facts over a project, one query or a warm server (frame/sil/engine_query.py)."""

import io
import json
import os
from pathlib import Path

import pytest

from frame.cli import main
from frame.sil.engine_query import TOOLS, QueryIndex, serve
from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS, EXTENSION_LANGUAGES, FrameScanner

APP = '''\
import sqlite3
from flask import Flask, request, abort
from flask_login import login_required, current_user

app = Flask(__name__)


def run_query(q):
    return sqlite3.connect("db").execute(q)


@app.route("/item")
def item():
    name = request.args.get("name")
    return str(run_query("SELECT * FROM t WHERE n = '" + name + "'"))


@app.route("/admin")
def admin():
    if not current_user.is_admin:
        abort(403)
    return str(run_query("SELECT 1"))
'''


@pytest.fixture
def project(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    return tmp_path


def _bump(path: Path, text: str) -> None:
    path.write_text(text)
    st = path.stat()                     # make sure the mtime moves even on a coarse clock
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))


def test_every_answer_carries_evidence_resolution_limits_and_the_index(project):
    q = QueryIndex(str(project))
    for tool in TOOLS:
        args = {"name": "item", "line": 15, "kind": "guarded_by", "pattern": "admin"}
        a = q.query(tool, args)
        assert a["tool"] == tool and "result" in a
        assert a["evidence"] and a["resolution"] and a["limits"]
        assert a["index"]["files"] == 1 and a["index"]["build_ms"] > 0
        assert a["query_ms"] >= 0
    assert q.builds == 1                  # one build answered every tool


def test_handlers_trace_callers_and_callees(project):
    q = QueryIndex(str(project))
    names = {h["name"] for h in q.query("handlers")["result"]}
    assert {"item", "admin"} <= names
    # The flow is reported at its sink, in the helper the handler hands the data to.
    flows = q.query("trace", {"name": "run_query"})["result"]["flows"]
    assert any(f["cwe"] == "CWE-89" and f["evidence"] == "solver-verified" for f in flows)
    callers = q.query("callers", {"name": "run_query"})["result"]["callers"]
    assert {c["caller"] for c in callers} >= {"item", "admin"}
    assert all("run_query(" in c["code"] for c in callers)       # the call site's own line
    calls = q.query("callees", {"name": "item"})["result"]["calls"]
    rq = [c for c in calls if c["call"] == "run_query"]
    assert rq and rq[0]["defined_in"] and "run_query(" in rq[0]["code"]


def test_guards_and_check_are_engine_facts(project):
    q = QueryIndex(str(project))
    g = q.query("guards", {"name": "admin", "line": 22})["result"]
    assert any("admin" in x["text"] for x in g["guards_by_line"]["22"])
    assert "run_query" in g["code"]["22"]
    assert q.query("check", {"name": "admin", "line": 22, "kind": "guarded_by",
                             "pattern": "is_admin"})["result"]["verdict"] == "proved"
    refuted = q.query("check", {"name": "item", "line": 15, "kind": "guarded_by",
                                "pattern": "is_admin"})["result"]
    assert refuted["verdict"] == "refuted"


def test_missing_arguments_and_unknown_tools_are_errors_not_crashes(project):
    q = QueryIndex(str(project))
    assert "error" in q.query("nope")
    assert "error" in q.query("callers")["result"]
    assert "error" in q.query("check", {"name": "item"})["result"]
    assert "error" in q.query("handler_facts", {"name": "no_such_function"})["result"]


def test_the_index_is_warm_until_a_file_changes(project):
    q = QueryIndex(str(project))
    assert q.query("handlers")["index"]["rebuilt"] is True
    warm = q.query("handlers")
    assert warm["index"]["rebuilt"] is False and q.builds == 1
    _bump(project / "app.py", APP + '\n\n@app.route("/new")\ndef fresh():\n    return "x"\n')
    a = q.query("handlers")
    assert a["index"]["rebuilt"] is True and "fresh" in {h["name"] for h in a["result"]}
    (project / "more.py").write_text("def helper(x):\n    return run(x)\n")   # a new file
    d = project
    st = d.stat()
    os.utime(d, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
    assert q.query("handlers")["index"]["rebuilt"] is True and q.builds == 3
    assert q.query("callers", {"name": "run"})["result"]["callers"][0]["file"] == "more.py"


def test_serve_answers_one_json_line_per_request(project):
    q = QueryIndex(str(project))
    reqs = "\n".join([json.dumps({"tool": "tools"}),
                      json.dumps({"id": 7, "tool": "callers", "args": {"name": "run_query"}}),
                      "not json",
                      "",
                      json.dumps({"tool": "handlers"})]) + "\n"
    out = io.StringIO()
    assert serve(q, io.StringIO(reqs), out) == 0
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert len(lines) == 4
    assert set(lines[0]["tools"]) == set(TOOLS)
    assert lines[1]["id"] == 7 and lines[1]["result"]["callers"]
    assert "bad request" in lines[2]["error"]
    assert lines[3]["index"]["rebuilt"] is False and q.builds == 1


def test_cli_one_shot(project, capsys):
    assert main(["query", str(project), "callers", "--name", "run_query"]) == 0
    a = json.loads(capsys.readouterr().out)
    assert a["tool"] == "callers" and a["result"]["callers"]
    assert main(["query", str(project), "bogus"]) == 2
    capsys.readouterr()
    assert main(["query", str(project)]) == 2
    assert main(["query", str(project / "app.py"), "handlers"]) == 2


# -- the pruned walk lists exactly what rglob + the per-file exclusion test listed -----------

def _old_candidates(sc, d):
    exts = {e.lower() for e in EXTENSION_LANGUAGES}
    raw = sorted(p for p in d.rglob("*") if p.suffix.lower() in exts or not p.suffix)
    return [p for p in raw if p.is_file()
            and not sc._is_excluded_dir_member(p, d, DEFAULT_EXCLUDED_SCAN_DIRS)
            and (p.suffix or sc._is_script(p, None))]


def test_walk_prunes_excluded_directories_and_lists_the_same_files(tmp_path):
    files = ["a.py", "src/b.js", "node_modules/x/i.js", ".venv/lib/c.py", "venv/real.py",
             "env/venv/lib/d.py", ".claude/worktrees/w/e.py", ".claude/hooks/f.py",
             "pkg/__pycache__/g.py", "bin/tool", "README"]
    for f in files:
        p = tmp_path / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("#!/usr/bin/env python3\nprint(1)\n" if f == "bin/tool" else "x = 1\n")
    (tmp_path / "env/venv/pyvenv.cfg").write_text("home = /usr\n")   # a real virtualenv
    sc = FrameScanner()
    new = sc._candidate_files(tmp_path, None, None, DEFAULT_EXCLUDED_SCAN_DIRS)
    assert new == _old_candidates(sc, tmp_path)
    rel = {p.relative_to(tmp_path).as_posix() for p in new}
    assert rel == {"a.py", "src/b.js", "venv/real.py", ".claude/hooks/f.py", "bin/tool"}


def test_js_name_index_keeps_findings(tmp_path):
    # A function every call of which passes an Array (the kind fact `_name_uses` serves), and
    # nested callbacks reading an enclosing local (`_enclosing_local_names`'s cache).
    src = '''\
const express = require("express");
const cp = require("child_process");
const app = express();
function each(xs) { xs.forEach((x, i) => { obj[i] = x; }); }
each([1, 2]);
app.get("/run", (req, res) => {
  const cmd = req.query.cmd;
  [1].forEach(() => { [2].forEach(() => { cp.exec(cmd); }); });
  res.send("ok");
});
'''
    f = tmp_path / "app.js"
    f.write_text(src)
    res = FrameScanner().scan_file(str(f))
    assert any(v.cwe_id == "CWE-78" for v in res.vulnerabilities)
    assert not any(v.cwe_id == "CWE-1321" for v in res.vulnerabilities)
