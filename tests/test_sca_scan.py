"""frame scan --sca: dependency findings in a source scan, and the tainted reachability level
(attacker data reaching a vulnerable function, found by the taint engine at the call site)."""

import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca.advisories import build_advisories

ROOT = Path(__file__).resolve().parents[1]
OSV = ROOT / "tests" / "fixtures" / "sca" / "osv"
RECORDS = json.loads(gzip.decompress((OSV / "records.json.gz").read_bytes()))
LODASH_TEMPLATE = "GHSA-35jh-r3h4-6jhm"            # _.template: also a built-in template-injection sink
LODASH_REDOS = "GHSA-29mw-wpgm-hmr9"               # _.toNumber / _.trim ReDoS: a sink only through --sca


@pytest.fixture
def env(tmp_path):
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    fns = tmp_path / "functions"
    fns.mkdir()
    (fns / "npm.json").write_text(json.dumps({LODASH_TEMPLATE: [{"id": "lodash.template", "source": "curated"}],
                                              LODASH_REDOS: [{"id": "lodash.toNumber", "source": "curated"}]}))
    (fns / "PyPI.json").write_text(json.dumps({"GHSA-8q59-q68h-6hv4": [{"id": "yaml.load", "source": "curated"}]}))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", functions_dir=fns)
    e = {**os.environ, "FRAME_KB_CACHE": str(tmp_path / "cache"), "FRAME_ADVISORIES_SOURCE": str(mirror)}
    subprocess.run([sys.executable, "-m", "frame.cli", "kb", "pull", "--advisories", "--all"],
                   env=e, check=True, capture_output=True, cwd=str(ROOT))
    return e


def scan(path, env, *extra):
    out = subprocess.run([sys.executable, "-m", "frame.cli", "scan", str(path), "--sca", "-f", "json",
                          "--fail-on", "none", *extra], env=env, capture_output=True, text=True, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


EXPRESS = """const express = require('express');
const _ = require('lodash');
const app = express();
app.get('/greet', (req, res) => {
  const page = _.template(req.query.tpl);
  res.send(page({}));
});
app.get('/static', (req, res) => {
  res.send(_.template('<b>hi</b>')({}));
});
app.get('/count', (req, res) => {
  res.send(String(_.toNumber(req.query.n)));
});
app.get('/one', (req, res) => {
  res.send(String(_.toNumber('1')));
});
"""


def test_attacker_data_reaching_a_vulnerable_function_is_tainted(tmp_path, env):
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"express": "4.18.2", "lodash": "4.17.20"}}))
    (proj / "server.js").write_text(EXPRESS)
    doc = scan(proj, env)
    deps = {f["id"]: f for f in doc["dependencies"]["findings"]}
    # _.template is already a template-injection sink: that finding at line 5 is the flow
    template = deps[LODASH_TEMPLATE]["reachability"]
    assert template["level"] == "tainted"
    assert [fl["location"] for fl in template["flows"]] == ["server.js:5"]      # not the constant template
    assert deps[LODASH_TEMPLATE]["evidence"] in ("data-flow", "solver-verified")
    # _.toNumber is a sink only because the ReDoS advisory names it: a vulnerable_dependency finding
    redos = deps[LODASH_REDOS]["reachability"]
    assert redos["level"] == "tainted" and [fl["location"] for fl in redos["flows"]] == ["server.js:12"]
    vulns = [v for f in doc["files"] for v in f["vulnerabilities"] if v["type"] == "vulnerable_dependency"]
    assert [v["line"] for v in vulns] == [12]                                     # not the constant at 15
    assert vulns[0]["cwe_id"] == "CWE-1395" and vulns[0]["category"] == "dependency"
    assert LODASH_REDOS in vulns[0]["description"] and "lodash@4.17.20" in vulns[0]["description"]
    assert "fixed in 4.17.21" in vulns[0]["description"]


def test_an_existing_sink_keeps_its_kind_and_still_taints_the_dependency(tmp_path, env):
    """yaml.load is already Frame's deserialization sink: the generated sink never replaces it,
    and the CWE-502 finding at the call raises the PyYAML advisory to tainted."""
    proj = tmp_path / "svc"
    proj.mkdir()
    (proj / "requirements.txt").write_text("flask==2.0.0\npyyaml==5.3\n")
    (proj / "app.py").write_text("import yaml\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
                                 "@app.route('/load', methods=['POST'])\ndef load():\n"
                                 "    return str(yaml.load(request.data))\n")
    doc = scan(proj, env)
    types = {v["type"] for f in doc["files"] for v in f["vulnerabilities"]}
    assert "vulnerable_dependency" not in types and types & {"deserialization", "unsafe_deserialization"}
    dep = [f for f in doc["dependencies"]["findings"] if f["id"] == "GHSA-8q59-q68h-6hv4"][0]
    assert dep["reachability"]["level"] == "tainted"
    assert dep["reachability"]["flows"][0]["location"] == "app.py:7"


def test_without_sca_the_scan_is_unchanged(tmp_path, env):
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    (proj / "server.js").write_text(EXPRESS)
    out = subprocess.run([sys.executable, "-m", "frame.cli", "scan", str(proj), "-f", "json", "--fail-on", "none"],
                         env=env, capture_output=True, text=True, cwd=str(ROOT))
    doc = json.loads(out.stdout)
    assert "dependencies" not in doc
    assert not [v for f in doc["files"] for v in f["vulnerabilities"] if v["type"] == "vulnerable_dependency"]


def test_sca_without_cached_advisories_warns_and_never_fetches(tmp_path):
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    (proj / "index.js").write_text("module.exports = 1;\n")
    e = {**os.environ, "FRAME_KB_CACHE": str(tmp_path / "empty"), "FRAME_ADVISORIES_SOURCE": "https://127.0.0.1:9/x"}
    doc = scan(proj, e)
    assert doc["dependencies"]["findings"] == []
    assert any("frame kb pull --advisories" in w for w in doc["dependencies"]["warnings"])


def test_sca_findings_gate_the_exit_status_and_appear_in_sarif(tmp_path, env):
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"minimist": "1.2.5"}}))
    (proj / "index.js").write_text("module.exports = 1;\n")
    run = lambda *a: subprocess.run([sys.executable, "-m", "frame.cli", "scan", str(proj), "--sca", *a],
                                    env=env, capture_output=True, text=True, cwd=str(ROOT))
    assert run("--fail-on", "none").returncode == 0
    assert run("--fail-on", "any").returncode == 1
    sarif = json.loads(run("-f", "sarif", "--fail-on", "none").stdout)
    deps = [r for r in sarif["runs"][0]["results"] if r["ruleId"].startswith("dependency/")]
    assert deps and deps[0]["properties"]["category"] == "dependency"
    assert deps[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "package.json"
