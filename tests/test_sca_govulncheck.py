"""Go reachability from govulncheck (`frame deps --govulncheck FILE`, frame/sca/govulncheck.py).

The fixture is a real `govulncheck -json ./...` report (v1.1.4, go1.22.12) on
examples/upgrade-nuget-go/go, a gin 1.7.0 service; its `osv` and `progress` objects are left out
(their content is the advisories Frame already has). Live (FRAME_SCA_REAL=1), govulncheck runs
again and every advisory's level must be what Frame reports.
"""

import gzip
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca.govulncheck import GovulncheckError, apply, read

ROOT = Path(__file__).parent.parent
REPORT = ROOT / "tests" / "fixtures" / "sca" / "govulncheck" / "shop.json.gz"
EXAMPLE = ROOT / "examples" / "upgrade-nuget-go"


@pytest.fixture
def report(tmp_path):
    p = tmp_path / "govulncheck.json"
    p.write_bytes(gzip.decompress(REPORT.read_bytes()))
    return p


def test_each_advisory_gets_its_deepest_level(report):
    rep = read(report)
    assert rep.go_version == "go1.22.12" and rep.scanner == "govulncheck v1.1.4"
    levels = {k: v["level"] for k, v in rep.by_advisory.items()}
    assert levels["GO-2021-0052"] == "called"                  # gin's Engine.Run, called from main
    assert levels["GO-2023-1737"] == "imported" and levels["GO-2022-0493"] == "imported"
    assert sum(1 for v in levels.values() if v == "installed") == len(levels) - 3
    [call] = rep.by_advisory["GO-2021-0052"]["calls"][:1]
    assert call == {"function": "github.com/gin-gonic/gin.(*Engine).Run", "location": "main.go:8",
                    "in": "example.com/shop.main", "source": "govulncheck"}
    assert len(rep.stdlib) == 66 and sum(1 for v in rep.stdlib.values() if v == "called") == 33


def test_findings_are_matched_by_id_or_alias_and_only_for_go(report):
    findings = [{"id": "GHSA-h395-qcrw-5vmq", "aliases": ["GO-2021-0052", "CVE-2020-28483"], "ecosystem": "Go",
                 "reachability": {"level": "installed"}},
                {"id": "GO-2023-1737", "aliases": [], "ecosystem": "Go"},
                {"id": "GO-2021-0052", "aliases": [], "ecosystem": "npm"}]          # another ecosystem
    notes = apply(findings, [read(report)])
    assert findings[0]["reachability"]["level"] == "called"
    assert findings[0]["reachability"]["calls"][0]["location"] == "main.go:8"
    assert "govulncheck" in findings[0]["reachability"]["evidence"]
    assert findings[1]["reachability"]["level"] == "imported"
    assert "reachability" not in findings[2]
    assert "66 advisory(ies) in the Go standard library of go1.22.12 (33 called)" in notes[0]


@pytest.mark.parametrize("text,why", [
    ('{"config": {"scan_mode": "binary"}}\n', "binary-mode"),
    ('{"finding": {"osv": "GO-1", "trace": [{"module": "m"}]}}\n', "no govulncheck config"),
    ("not json at all", "not govulncheck -json output"),
])
def test_what_is_not_a_source_mode_report_is_refused(tmp_path, text, why):
    p = tmp_path / "r.json"
    p.write_text(text)
    with pytest.raises(GovulncheckError, match=why):
        read(p)


def _frame(cwd, env, *args):
    return subprocess.run([sys.executable, "-m", "frame.cli", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=600).stdout


def test_frame_deps_shows_govulncheck_s_reachability(tmp_path, report):
    work = tmp_path / "ex"
    shutil.copytree(EXAMPLE, work)
    env = {**os.environ, "FRAME_KB_CACHE": str(tmp_path / "kb"), "PYTHONPATH": str(ROOT)}
    env.pop("FRAME_ADVISORIES_SOURCE", None)
    _frame(work, env, "kb", "pull", "--advisories", "--source", "offline-advisories", "--ecosystems", "Go")
    out = _frame(work, env, "deps", "go", "--vulns", "--govulncheck", str(report))
    assert "github.com/gin-gonic/gin@1.7.0 (direct, called) GHSA-h395-qcrw-5vmq" in out
    assert "calls github.com/gin-gonic/gin.(*Engine).Run at main.go:8" in out
    assert "golang.org/x/sys@0.0.0-20200116001909-b77594299b42 (transitive, imported) GHSA-p782-xgp4-8hr8" in out
    data = json.loads(_frame(work, env, "deps", "go", "--vulns", "--govulncheck", str(report), "-f", "json"))
    levels = [f["reachability"]["level"] for f in data["vulnerabilities"]]
    assert levels.count("called") == 1 and levels.count("imported") == 2


@pytest.mark.skipif(os.environ.get("FRAME_SCA_REAL") != "1", reason="live: set FRAME_SCA_REAL=1 (needs go)")
def test_live_a_fresh_govulncheck_run_is_what_frame_reports(tmp_path):
    """govulncheck run now on the example: every Go finding of Frame's that it decided carries its
    level, and gin's Engine.Run advisory is still called from main.go:8."""
    if shutil.which("go") is None:
        pytest.fail("go is not installed")
    work = tmp_path / "ex"
    shutil.copytree(EXAMPLE, work)
    gobin = tmp_path / "bin"
    subprocess.run(["go", "install", "golang.org/x/vuln/cmd/govulncheck@v1.1.4"], check=True, timeout=600,
                   env={**os.environ, "GOBIN": str(gobin)})
    out = subprocess.run([str(gobin / "govulncheck"), "-json", "./..."], cwd=work / "go", capture_output=True,
                         text=True, timeout=900).stdout
    (tmp_path / "r.json").write_text(out)
    rep = read(tmp_path / "r.json")
    env = {**os.environ, "FRAME_KB_CACHE": str(tmp_path / "kb"), "PYTHONPATH": str(ROOT)}
    env.pop("FRAME_ADVISORIES_SOURCE", None)
    _frame(work, env, "kb", "pull", "--advisories", "--source", "offline-advisories", "--ecosystems", "Go")
    data = json.loads(_frame(work, env, "deps", "go", "--vulns", "--govulncheck", str(tmp_path / "r.json"),
                             "-f", "json"))
    decided = 0
    for f in data["vulnerabilities"]:
        hit = next((rep.by_advisory[i] for i in [f["id"], *f["aliases"]] if i in rep.by_advisory), None)
        if hit is not None:
            decided += 1
            assert f["reachability"]["level"] == hit["level"], f["id"]
    assert decided and rep.by_advisory["GO-2021-0052"]["level"] == "called"
