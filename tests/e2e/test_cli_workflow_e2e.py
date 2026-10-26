"""What a developer or a CI job does with Frame, start to finish, through the real CLI process.

Exit codes, output formats, config, suppressions, mixed-language repositories, and the
git-based incremental loop (baseline -> scan only what changed -> verify the fix).
"""

import json
import subprocess
import sys

import pytest

from e2e_helpers import scan, scan_subprocess, write_tree

FLASK_SQLI = '''import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name", "")
    row = sqlite3.connect("app.db").execute("SELECT * FROM users WHERE name = '" + name + "'").fetchone()
    return str(row)
'''
CLEAN = '''def add(a, b):
    return a + b
'''


def frame(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "frame.cli", *args], capture_output=True, text=True,
                          cwd=str(cwd) if cwd else None)


# ---- exit status ------------------------------------------------------------------------

def test_exit_status_follows_the_findings_and_fail_on(tmp_path):
    write_tree(tmp_path, {"app.py": FLASK_SQLI})
    assert scan_subprocess(tmp_path).returncode == 1                       # critical finding, default --fail-on high
    assert scan_subprocess(tmp_path, "--fail-on", "none").returncode == 0
    assert scan_subprocess(tmp_path, "--fail-on", "critical").returncode == 1


def test_clean_project_exits_zero(tmp_path):
    write_tree(tmp_path, {"util.py": CLEAN})
    done = scan_subprocess(tmp_path)
    assert done.returncode == 0


def test_missing_target_exits_two(tmp_path):
    done = scan_subprocess(tmp_path / "nope")
    assert done.returncode == 2 and "not found" in done.stderr.lower()


# ---- output formats ---------------------------------------------------------------------

def test_text_output_names_file_line_and_cwe(tmp_path):
    write_tree(tmp_path, {"app.py": FLASK_SQLI})
    out = scan_subprocess(tmp_path, "--fail-on", "none").stdout
    assert "app.py" in out and "CWE-89" in out


def test_sarif_output_is_valid_and_carries_the_result(tmp_path):
    write_tree(tmp_path, {"app.py": FLASK_SQLI})
    done = scan_subprocess(tmp_path, "-f", "sarif", "--fail-on", "none")
    doc = json.loads(done.stdout)
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    assert results and results[0]["ruleId"] == "frame/sql_injection"
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "external/cwe/cwe-89" in rule["properties"]["tags"] and rule["properties"]["security-severity"] == "9.5"
    assert results[0]["properties"]["cwe"] == "CWE-89"


def test_json_has_stable_paths_fingerprints_and_scope(tmp_path):
    write_tree(tmp_path, {"app.py": FLASK_SQLI, "sub/util.py": CLEAN})
    doc = json.loads(scan_subprocess(tmp_path, "-f", "json", "--fail-on", "none").stdout)
    finding = next(v for f in doc["files"] for v in f["vulnerabilities"])
    assert finding["path"] == "app.py" and finding["cwe_id"] == "CWE-89"
    assert finding["fingerprint"] and finding["fingerprint_loose"]
    assert doc["summary"]["files_scanned"] == 2


def test_paths_do_not_depend_on_the_working_directory(tmp_path):
    write_tree(tmp_path, {"proj/app.py": FLASK_SQLI})
    (tmp_path / "proj" / ".git").mkdir()
    here = json.loads(scan_subprocess(tmp_path / "proj", "-f", "json", "--fail-on", "none", cwd=tmp_path).stdout)
    there = json.loads(scan_subprocess(tmp_path / "proj", "-f", "json", "--fail-on", "none",
                                       cwd=tmp_path / "proj").stdout)
    fp = lambda d: [v["fingerprint"] for f in d["files"] for v in f["vulnerabilities"]]  # noqa: E731
    assert fp(here) == fp(there) and fp(here)


# ---- config and suppressions ------------------------------------------------------------

def test_inline_ignore_suppresses_but_keeps_the_finding_visible(tmp_path):
    write_tree(tmp_path, {"app.py": FLASK_SQLI.replace(".fetchone()", ".fetchone()  # frame: ignore[CWE-89] reviewed")})
    got = scan(tmp_path)
    assert got.findings == []
    assert got.doc["summary"]["suppressed"] == 1
    assert got.doc["files"][0]["suppressed"][0]["cwe_id"] == "CWE-89"


def test_ignore_for_another_cwe_does_not_suppress(tmp_path):
    write_tree(tmp_path, {"app.py": FLASK_SQLI.replace(".fetchone()", ".fetchone()  # frame: ignore[CWE-79]")})
    assert [f["cwe_id"] for f in scan(tmp_path).findings] == ["CWE-89"]


def test_config_file_exclude_disable_and_fail_on(tmp_path):
    write_tree(tmp_path, {
        "app.py": FLASK_SQLI,
        "vendor/lib.py": FLASK_SQLI,
        ".frame.toml": 'exclude = ["vendor"]\nfail_on = "none"\n',
    })
    got = scan(tmp_path, fail_on="high")            # the CLI flag wins over the config's fail_on
    assert {f["path"] for f in got.findings} == {"app.py"}
    assert scan_subprocess(tmp_path).returncode == 0     # config fail_on = none


def test_config_disable_drops_a_cwe(tmp_path):
    write_tree(tmp_path, {"app.py": FLASK_SQLI, ".frame.toml": 'disable = ["CWE-89"]\n'})
    assert scan(tmp_path).findings == []


def test_malformed_config_is_an_error(tmp_path):
    write_tree(tmp_path, {"app.py": FLASK_SQLI, ".frame.toml": "disable = nonsense\n"})
    done = scan_subprocess(tmp_path)
    assert done.returncode == 2


# ---- a mixed-language repository ---------------------------------------------------------

MIXED = {
    "py/app.py": FLASK_SQLI,
    "js/server.js": '''const express = require("express");
const { exec } = require("child_process");
const app = express();
app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host);
  res.send("ok");
});
''',
    "java/Search.java": '''import java.io.IOException;
import java.sql.*;
import javax.servlet.http.*;

public class Search extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String q = req.getParameter("q");
        try {
            Connection c = DriverManager.getConnection("jdbc:h2:mem:x");
            c.createStatement().executeQuery("SELECT * FROM t WHERE n = '" + q + "'");
        } catch (SQLException e) { }
    }
}
''',
    "cs/Search.cs": '''using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class SearchController : Controller
{
    public IActionResult Find(string q)
    {
        var cmd = new SqlCommand("SELECT * FROM t WHERE n = '" + q + "'", new SqlConnection("x"));
        cmd.ExecuteReader();
        return Ok();
    }
}
''',
    "c/run.c": '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "ls %s", argv[1]);
    system(cmd);
    return 0;
}
''',
}


def test_directory_scan_analyses_every_supported_language(tmp_path):
    write_tree(tmp_path, MIXED)
    got = scan(tmp_path)
    by_file = {}
    for f in got.findings:
        by_file.setdefault(f["path"], set()).add(f["cwe_id"])
    assert "CWE-89" in by_file.get("py/app.py", set())
    assert "CWE-78" in by_file.get("js/server.js", set())
    assert "CWE-89" in by_file.get("java/Search.java", set())
    assert "CWE-89" in by_file.get("cs/Search.cs", set())
    assert "CWE-78" in by_file.get("c/run.c", set())


def test_language_flag_narrows_the_scan(tmp_path):
    write_tree(tmp_path, MIXED)
    got = scan(tmp_path, "-l", "javascript")
    assert {f["path"] for f in got.findings} == {"js/server.js"}


# ---- the incremental loop: baseline -> changed -> verify ---------------------------------

def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
                   check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    write_tree(tmp_path, {"app.py": FLASK_SQLI, "util.py": CLEAN})
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_baseline_then_changed_reports_only_what_is_new(repo):
    baseline = repo / "baseline.json"
    assert frame("scan", str(repo), "--fail-on", "none", "--write-baseline", str(baseline)).returncode == 0
    # an agent edits a file and introduces a second flaw
    (repo / "util.py").write_text(CLEAN + '''

import os
from flask import request


def run():
    os.system("ls " + request.args.get("d", ""))
''')
    done = frame("scan", str(repo), "--changed", "--baseline", str(baseline), "-f", "json")
    doc = json.loads(done.stdout)
    new = [(v["path"], v["cwe_id"]) for f in doc["files"] for v in f["vulnerabilities"]]
    assert new == [("util.py", "CWE-78")]
    assert doc["baseline"]["new"] == 1
    assert done.returncode == 1                                  # new finding at/above --fail-on


def test_known_findings_alone_do_not_fail_the_build(repo):
    baseline = repo / "baseline.json"
    frame("scan", str(repo), "--fail-on", "none", "--write-baseline", str(baseline))
    done = frame("scan", str(repo), "--baseline", str(baseline))
    assert done.returncode == 0


def test_nothing_changed_is_a_clean_scan(repo):
    done = frame("scan", str(repo), "--changed", "-f", "json")
    assert done.returncode == 0
    assert json.loads(done.stdout)["summary"]["total_vulnerabilities"] == 0


def test_verify_reports_fixed_present_and_suppressed(repo, tmp_path):
    findings = repo / "findings.json"
    findings.write_text(frame("scan", str(repo), "-f", "json", "--fail-on", "none").stdout)
    # not fixed yet
    present = frame("verify", str(findings), "-f", "json", cwd=repo)
    assert json.loads(present.stdout)["results"][0]["status"] == "present" and present.returncode == 1
    # silencing it is not fixing it
    (repo / "app.py").write_text(FLASK_SQLI.replace(".fetchone()", ".fetchone()  # frame: ignore"))
    silenced = frame("verify", str(findings), "-f", "json", cwd=repo)
    assert json.loads(silenced.stdout)["results"][0]["status"] == "suppressed" and silenced.returncode == 1
    # the real fix
    (repo / "app.py").write_text(FLASK_SQLI.replace(
        '''.execute("SELECT * FROM users WHERE name = '" + name + "'")''',
        '''.execute("SELECT * FROM users WHERE name = ?", (name,))'''))
    fixed = frame("verify", str(findings), "-f", "json", cwd=repo)
    assert json.loads(fixed.stdout)["results"][0]["status"] == "fixed" and fixed.returncode == 0


def test_helper_change_is_caught_in_the_files_that_depend_on_it(tmp_path):
    """--changed widens to the files that import the changed one: editing only the helper
    must surface the flow whose sink is in the helper and whose source is in the caller."""
    write_tree(tmp_path, {
        "views.py": ('from flask import Flask, request\nfrom helper import archive\n\napp = Flask(__name__)\n\n\n'
                     '@app.route("/a")\ndef a():\n    archive(request.args.get("n", ""))\n    return "ok"\n'),
        "helper.py": 'import subprocess\n\n\ndef archive(name):\n    subprocess.run(["tar", "cf", "o.tar", name])\n',
    })
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    assert scan(tmp_path, "--changed").findings == []
    (tmp_path / "helper.py").write_text(
        'import os\n\n\ndef archive(name):\n    os.system("tar cf o.tar " + name)\n')
    got = scan(tmp_path, "--changed")
    assert [(f["path"], f["cwe_id"]) for f in got.findings] == [("helper.py", "CWE-78")]
