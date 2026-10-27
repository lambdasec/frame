"""`frame scan` options, one behaviour per test, through the real CLI process.

Covers target selection (`--files`, `--root`, `-l`, `-p`), reporting (`--min-severity`, `--fail-on`, `-o`,
formats), analysis switches (`--no-verify`, `--timeout`, `--no-cross-file`, `--cross-file-limit`), config
(`--config`, `--no-config`, `--disable`), the baseline loop, `frame verify`, `frame packs`, and that the
module entry point `python -m frame.sil.cli scan` behaves like `frame scan`.
"""

import json
import re
import subprocess
import sys

import pytest

from e2e_helpers import write_tree

FLASK_CMD = '''import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/x")
def x():
    os.system("echo " + request.args.get("q", ""))
    return "ok"
'''
WEAK_HASH = '''import hashlib


def digest(password):
    return hashlib.md5(password.encode()).hexdigest()
'''
EXPRESS_CMD = '''const express = require("express");
const cp = require("child_process");
const app = express();

app.get("/a", (req, res) => {
  cp.exec("ls " + req.query.dir);
  res.send("ok");
});
'''
C_CMD = '''#include <stdlib.h>

int main(void)
{
    system(getenv("JOB"));
    return 0;
}
'''
PROJECT = {"app.py": FLASK_CMD, "weak.py": WEAK_HASH, "srv.js": EXPRESS_CMD, "c/job.c": C_CMD,
           "clean.py": "def add(a, b):\n    return a + b\n"}

ALL = [("app.py", "CWE-78"), ("c/job.c", "CWE-78"), ("srv.js", "CWE-78"), ("weak.py", "CWE-328")]


def frame(*args, module="frame.cli", cwd=None, timeout=180):
    return subprocess.run([sys.executable, "-m", module, *args], capture_output=True, text=True,
                          cwd=str(cwd) if cwd else None, timeout=timeout)


def run_scan(target, *flags, fail_on="none", module="frame.cli", cwd=None):
    argv = ["scan", str(target), "-f", "json", *flags]
    if "--fail-on" not in flags and fail_on:
        argv += ["--fail-on", fail_on]
    return frame(*argv, module=module, cwd=cwd)


def docs(done):
    return json.loads(done.stdout)


def found(doc):
    files = doc["files"] if "files" in doc else [doc]
    return sorted((v.get("path") or f["filename"], v["cwe_id"]) for f in files for v in f["vulnerabilities"])


@pytest.fixture
def project(tmp_path):
    return write_tree(tmp_path / "proj", PROJECT)


# ---- choosing what to scan -------------------------------------------------------------------

def test_files_scans_only_the_named_files(project):
    assert found(docs(run_scan(project, "--files", str(project / "app.py")))) == [("app.py", "CWE-78")]


def test_files_with_a_missing_path_warns_and_skips_it(project):
    done = run_scan(project, "--files", str(project / "app.py"), str(project / "nope.py"))
    assert "nope.py" in done.stderr and found(docs(done)) == [("app.py", "CWE-78")]


def test_files_with_nothing_to_scan_exits_cleanly_or_with_a_message(project):
    done = run_scan(project, "--files", str(project / "clean.py"))
    assert done.returncode == 0 and found(docs(done)) == []


def test_root_is_the_base_of_reported_paths(project):
    doc = docs(run_scan(project, "--root", str(project / "c"), "-l", "c"))
    assert found(doc) == [("job.c", "CWE-78")]


@pytest.mark.parametrize("language, expected", [
    ("python", [("app.py", "CWE-78"), ("weak.py", "CWE-328")]),
    ("javascript", [("srv.js", "CWE-78")]),
    ("c", [("c/job.c", "CWE-78")]),
])
def test_language_flag_selects_the_files_a_directory_scan_walks(project, language, expected):
    assert found(docs(run_scan(project, "-l", language))) == expected


def test_language_flag_with_no_matching_files_exits_two(project):
    done = run_scan(project, "-l", "go")
    assert done.returncode == 2 and "No files found" in done.stderr


def test_pattern_flag_selects_files_by_glob(project):
    assert found(docs(run_scan(project, "-p", "*.js"))) == [("srv.js", "CWE-78")]


def test_pattern_flag_with_a_file_name(project):
    assert found(docs(run_scan(project, "-p", "weak.py"))) == [("weak.py", "CWE-328")]


def test_no_flags_scans_every_supported_language(project):
    assert found(docs(run_scan(project))) == ALL


# ---- reporting ---------------------------------------------------------------------------------

def test_min_severity_hides_lower_findings_in_text_output(project):
    out = frame("scan", str(project), "--fail-on", "none", "--min-severity", "critical").stdout
    assert "CWE-78" in out and "CWE-328" not in out


@pytest.mark.xfail(strict=True, reason="--min-severity is applied to text output only; json and sarif ignore it")
def test_min_severity_applies_to_json_output_too(project):
    assert ("weak.py", "CWE-328") not in found(docs(run_scan(project, "--min-severity", "critical")))


@pytest.mark.xfail(strict=True, reason="--min-severity is applied to text output only; json and sarif ignore it")
def test_min_severity_applies_to_sarif_output_too(project):
    done = frame("scan", str(project), "-f", "sarif", "--fail-on", "none", "--min-severity", "critical")
    assert "frame/weak_hash" not in {r["ruleId"] for r in json.loads(done.stdout)["runs"][0]["results"]}


@pytest.mark.parametrize("fail_on, status", [
    ("critical", 0), ("high", 1), ("medium", 1), ("low", 1), ("any", 1), ("none", 0),
])
def test_fail_on_levels_against_a_high_severity_finding(tmp_path, fail_on, status):
    write_tree(tmp_path, {"weak.py": WEAK_HASH})
    assert frame("scan", str(tmp_path), "-f", "json", "--fail-on", fail_on).returncode == status


def test_fail_on_critical_still_fails_for_a_critical_finding(project):
    assert frame("scan", str(project), "-f", "json", "--fail-on", "critical").returncode == 1


def test_a_clean_tree_exits_zero_whatever_fail_on_says(tmp_path):
    write_tree(tmp_path, {"clean.py": PROJECT["clean.py"]})
    assert frame("scan", str(tmp_path), "--fail-on", "any").returncode == 0


def test_output_flag_writes_the_report_to_a_file_and_leaves_stdout_empty(project, tmp_path):
    out = tmp_path / "report.json"
    done = run_scan(project, "-o", str(out))
    assert done.stdout == "" and found(json.loads(out.read_text())) == ALL


def test_output_flag_works_for_sarif(project, tmp_path):
    out = tmp_path / "report.sarif"
    frame("scan", str(project), "-f", "sarif", "--fail-on", "none", "-o", str(out))
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_text_json_and_sarif_report_the_same_findings(project):
    as_json = docs(run_scan(project))
    fingerprints = sorted(v["fingerprint"] for f in as_json["files"] for v in f["vulnerabilities"])
    text = frame("scan", str(project), "--fail-on", "none").stdout
    sarif = json.loads(frame("scan", str(project), "-f", "sarif", "--fail-on", "none").stdout)
    sarif_ids = sorted(r["partialFingerprints"]["frame/v1"] for r in sarif["runs"][0]["results"])
    assert fingerprints == sorted(re.findall(r"ID: ([0-9a-f]{16})", text)) == sarif_ids and len(fingerprints) == 4


# ---- analysis switches -------------------------------------------------------------------------

def test_no_verify_reports_the_same_findings(project):
    assert found(docs(run_scan(project, "--no-verify"))) == ALL


def test_a_tiny_verification_timeout_still_completes_and_reports(project):
    done = run_scan(project, "--timeout", "1")
    assert done.returncode == 0 and found(docs(done)) == ALL


CROSS_FILE = {
    "app/__init__.py": "",
    "app/routes.py": '''from flask import Flask, request
from app import helpers

app = Flask(__name__)


@app.route("/x")
def x():
    return helpers.run(request.args.get("q", ""))
''',
    "app/helpers.py": '''import os


def run(cmd):
    os.system("echo " + cmd)
    return "ok"
''',
}


def test_cross_file_taint_is_followed_by_default(tmp_path):
    write_tree(tmp_path, CROSS_FILE)
    assert found(docs(run_scan(tmp_path))) == [("app/helpers.py", "CWE-78")]


def test_no_cross_file_analyses_each_file_alone(tmp_path):
    write_tree(tmp_path, CROSS_FILE)
    assert found(docs(run_scan(tmp_path, "--no-cross-file"))) == []


def test_cross_file_limit_below_the_file_count_warns_and_falls_back(tmp_path):
    write_tree(tmp_path, CROSS_FILE)
    done = run_scan(tmp_path, "--cross-file-limit", "1")
    assert "exceed the cross-file limit (1)" in done.stderr and found(docs(done)) == []


def test_cross_file_limit_is_recorded_in_the_scope(tmp_path):
    write_tree(tmp_path, CROSS_FILE)
    scope = docs(run_scan(tmp_path, "--cross-file-limit", "1"))["scope"]
    assert scope["cross_file"] is False and "limit (1)" in scope["reason"]


def test_cross_file_limit_at_the_file_count_keeps_the_analysis(tmp_path):
    write_tree(tmp_path, CROSS_FILE)
    done = run_scan(tmp_path, "--cross-file-limit", "3")
    assert "limit" not in done.stderr and found(docs(done)) == [("app/helpers.py", "CWE-78")]


# ---- config ------------------------------------------------------------------------------------

def test_config_flag_reads_a_config_outside_the_project(project, tmp_path):
    cfg = tmp_path / "ci.toml"
    cfg.write_text('disable = ["CWE-78"]\n')
    assert found(docs(run_scan(project, "--config", str(cfg), "--root", str(project)))) == [("weak.py", "CWE-328")]


def test_project_config_is_picked_up_without_a_flag(project):
    (project / ".frame.toml").write_text('disable = ["CWE-78"]\n')
    assert found(docs(run_scan(project))) == [("weak.py", "CWE-328")]


def test_no_config_ignores_the_project_config(project):
    (project / ".frame.toml").write_text('disable = ["CWE-78"]\n')
    assert found(docs(run_scan(project, "--no-config"))) == ALL


def test_config_fail_on_is_used_and_no_config_restores_the_default(project):
    (project / ".frame.toml").write_text('fail_on = "none"\n')
    assert (frame("scan", str(project), "-f", "json").returncode,
            frame("scan", str(project), "-f", "json", "--no-config").returncode) == (0, 1)


def test_disable_drops_a_cwe(project):
    assert found(docs(run_scan(project, "--disable", "CWE-78"))) == [("weak.py", "CWE-328")]


def test_disable_drops_a_finding_type_and_can_repeat(project):
    done = run_scan(project, "--disable", "weak_hash", "--disable", "CWE-78")
    assert found(docs(done)) == []


# ---- baseline, verify, packs -------------------------------------------------------------------

def test_write_baseline_then_baseline_reports_nothing_new(project, tmp_path):
    baseline = tmp_path / "baseline.json"
    run_scan(project, "--write-baseline", str(baseline))
    done = frame("scan", str(project), "-f", "json", "--baseline", str(baseline))      # default --fail-on high
    assert done.returncode == 0 and found(docs(done)) == [] and docs(done)["summary"]["baselined"] == 4


def test_write_baseline_does_not_change_the_exit_status(project, tmp_path):
    done = frame("scan", str(project), "-f", "json", "--write-baseline", str(tmp_path / "b.json"))
    assert done.returncode == 1


def test_a_new_finding_after_the_baseline_is_reported_and_fails_the_run(project, tmp_path):
    baseline = tmp_path / "baseline.json"
    run_scan(project, "--write-baseline", str(baseline))
    write_tree(project, {"extra.py": FLASK_CMD.replace("/x", "/y").replace("def x", "def y")})
    done = frame("scan", str(project), "-f", "json", "--baseline", str(baseline))
    assert done.returncode == 1 and found(docs(done)) == [("extra.py", "CWE-78")]


def test_a_fixed_finding_is_listed_under_baseline_fixed(project, tmp_path):
    baseline = tmp_path / "baseline.json"
    run_scan(project, "--write-baseline", str(baseline))
    (project / "weak.py").write_text(WEAK_HASH.replace("md5", "sha256"))
    fixed = docs(run_scan(project, "--baseline", str(baseline)))["baseline"]["fixed"]
    assert [(f["path"], f["cwe_id"]) for f in fixed] == [("weak.py", "CWE-328")]


def test_verify_id_checks_only_that_finding(project, tmp_path):
    report = tmp_path / "findings.json"
    run_scan(project, "-o", str(report))
    ids = {v["path"]: v["fingerprint"] for f in json.loads(report.read_text())["files"] for v in f["vulnerabilities"]}
    (project / "weak.py").write_text(WEAK_HASH.replace("md5", "sha256"))
    done = frame("verify", str(report), "-f", "json", "--id", ids["weak.py"])
    results = json.loads(done.stdout)["results"]
    assert done.returncode == 0 and [(r["path"], r["status"]) for r in results] == [("weak.py", "fixed")]


def test_verify_reports_a_still_present_finding_with_status_one(project, tmp_path):
    report = tmp_path / "findings.json"
    run_scan(project, "-o", str(report))
    done = frame("verify", str(report), "-f", "json")
    assert done.returncode == 1 and {r["status"] for r in json.loads(done.stdout)["results"]} == {"present"}


def test_verify_with_an_unknown_id_exits_two(project, tmp_path):
    report = tmp_path / "findings.json"
    run_scan(project, "-o", str(report))
    assert frame("verify", str(report), "--id", "deadbeefdeadbeef").returncode == 2


def test_packs_list_names_the_builtin_packs_for_a_language():
    done = frame("packs", "list", "--language", "cpp")
    assert done.returncode == 0 and "qt" in done.stdout and "boost-asio-beast" in done.stdout


def test_packs_check_accepts_a_valid_pack(tmp_path):
    pack = tmp_path / "mine.toml"
    pack.write_text('[pack]\nname = "mine"\nlanguage = "python"\ndetect = { imports = ["acme"] }\n\n'
                    '[[sink]]\ncall = "acme.run"\nargs = [0]\nkind = "command"\n')
    assert frame("packs", "check", str(pack)).returncode == 0


def test_packs_check_rejects_an_invalid_pack_and_names_the_field(tmp_path):
    pack = tmp_path / "bad.toml"
    pack.write_text('[pack]\nname = "mine"\nlanguage = "klingon"\n')
    done = frame("packs", "check", str(pack))
    assert done.returncode == 1 and "[pack].language" in done.stdout + done.stderr


# ---- python -m frame.sil.cli scan behaves like frame scan --------------------------------------

def _stable(doc):
    if isinstance(doc, dict):
        return {k: _stable(v) for k, v in doc.items() if "time" not in k}
    if isinstance(doc, list):
        return [_stable(v) for v in doc]
    return doc


@pytest.mark.parametrize("flags", [
    [],
    ["-l", "python"],
    ["-p", "*.js"],
    ["--no-verify"],
    ["--no-cross-file"],
    ["--disable", "CWE-328"],
    ["--min-severity", "critical"],
    ["--cross-file-limit", "2"],
    ["--no-default-excludes"],
    ["--no-packs"],
])
def test_module_entry_point_matches_frame_scan(project, flags):
    via_frame = run_scan(project, "--root", str(project), *flags)
    via_module = run_scan(project, "--root", str(project), *flags, module="frame.sil.cli")
    assert (via_module.returncode, _stable(docs(via_module))) == (via_frame.returncode, _stable(docs(via_frame)))


def test_module_entry_point_exit_status_matches(project):
    assert (frame("scan", str(project), "--fail-on", "critical", module="frame.sil.cli").returncode ==
            frame("scan", str(project), "--fail-on", "critical").returncode == 1)
