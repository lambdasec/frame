"""Code mitigation of vulnerable dependencies: a proposed patch is kept only when re-running
the whole analysis on a patched copy shows the flow (or the call) gone and nothing new. The
proposals are injected here; the verification is the real taint engine."""

import gzip
import json
from pathlib import Path

import pytest

from frame.sca.advisories import build_advisories
from frame.sca.mitigate import mitigate
from frame.sil.scanner import DEFAULT_EXCLUDED_SCAN_DIRS

ROOT = Path(__file__).resolve().parents[1]
OSV = ROOT / "tests" / "fixtures" / "sca" / "osv"
RECORDS = json.loads(gzip.decompress((OSV / "records.json.gz").read_bytes()))


@pytest.fixture(autouse=True)
def advisories(tmp_path, monkeypatch):
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(json.dumps(RECORDS))
    fns = tmp_path / "functions"
    fns.mkdir()
    (fns / "PyPI.json").write_text(json.dumps({"GHSA-8q59-q68h-6hv4": [{"id": "yaml.load", "source": "curated"}]}))
    (fns / "npm.json").write_text(json.dumps({"GHSA-29mw-wpgm-hmr9": [{"id": "lodash.toNumber", "source": "curated"}]}))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", functions_dir=fns)
    from frame.kb.store import pull
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    pull(None, source=str(mirror))


APP = ("import yaml\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
       "@app.route('/load', methods=['POST'])\ndef load():\n    return str(yaml.load(request.data))\n")


def project(tmp_path, files):
    proj = tmp_path / "proj"
    proj.mkdir()
    for rel, text in files.items():
        (proj / rel).write_text(text)
    return proj


def run(proj, patch, write=False):
    return mitigate(proj, DEFAULT_EXCLUDED_SCAN_DIRS, config=None, write=write,
                    proposer=lambda site, src: patch)


def test_replacing_the_vulnerable_call_is_verified_removed(tmp_path):
    proj = project(tmp_path, {"requirements.txt": "flask==2.0.0\npyyaml==5.3\n", "app.py": APP})
    [r] = run(proj, {"original": "yaml.load(request.data)", "replacement": "yaml.safe_load(request.data)",
                     "rationale": "safe_load builds only plain objects"}, write=True)
    assert (r.site.level, r.verdict, r.verified) == ("tainted", "removed", True)
    assert "yaml.safe_load(request.data)" in (proj / "app.py").read_text()        # written: verified


def test_a_cosmetic_patch_is_rejected_and_not_written(tmp_path):
    proj = project(tmp_path, {"requirements.txt": "flask==2.0.0\npyyaml==5.3\n", "app.py": APP})
    [r] = run(proj, {"original": "    return str(yaml.load(request.data))",
                     "replacement": "    body = request.data\n    return str(yaml.load(body))"}, write=True)
    assert r.verdict == "still-tainted" and not r.verified
    assert (proj / "app.py").read_text() == APP


def test_a_patch_that_trades_one_bug_for_another_is_rejected(tmp_path):
    proj = project(tmp_path, {"requirements.txt": "flask==2.0.0\npyyaml==5.3\n", "app.py": APP})
    [r] = run(proj, {"original": "yaml.load(request.data)", "replacement": "eval(request.data)"})
    assert r.verdict == "introduces-findings" and r.introduced


JS = ("const express = require('express');\nconst _ = require('lodash');\nconst app = express();\n"
      "app.get('/count', (req, res) => {\n  const n = req.query.n;\n  res.send(String(_.toNumber(n)));\n});\n")


def test_an_allowlist_in_front_of_the_call_is_verified_untainted(tmp_path):
    proj = project(tmp_path, {"package.json": json.dumps({"dependencies": {"express": "4.18.2", "lodash": "4.17.20"}}),
                              "server.js": JS})
    [r] = run(proj, {"original": "  const n = req.query.n;\n",
                     "replacement": "  const ALLOWED = ['1', '10', '100'];\n  const n = req.query.n;\n"
                                    "  if (!ALLOWED.includes(n)) { return res.sendStatus(400); }\n"}, write=True)
    assert (r.verdict, r.verified) == ("untainted", True)                          # the call stays, the flow is cut
    assert "ALLOWED.includes(n)" in (proj / "server.js").read_text()


def test_a_character_class_check_does_not_cut_the_flow_to_a_vulnerable_function(tmp_path):
    """Digits only still lets an attacker choose a long input (the ReDoS this advisory is
    about); only a value pinned to constants is no longer attacker data."""
    proj = project(tmp_path, {"package.json": json.dumps({"dependencies": {"express": "4.18.2", "lodash": "4.17.20"}}),
                              "server.js": JS})
    [r] = run(proj, {"original": "  const n = req.query.n;\n",
                     "replacement": "  const n = req.query.n;\n  if (!/^\\d+$/.test(n)) { return res.sendStatus(400); }\n"})
    assert r.verdict == "still-tainted"


def test_a_patch_that_does_not_apply_is_reported(tmp_path):
    proj = project(tmp_path, {"requirements.txt": "flask==2.0.0\npyyaml==5.3\n", "app.py": APP})
    [r] = run(proj, {"original": "this text is not in the file", "replacement": "x"})
    assert r.verdict == "could-not-apply" and not r.applied


def test_no_reachable_site_means_nothing_to_do(tmp_path):
    proj = project(tmp_path, {"requirements.txt": "pyyaml==5.3\n", "util.py": "import yaml\n"})
    assert run(proj, {"original": "x", "replacement": "y"}) == []
