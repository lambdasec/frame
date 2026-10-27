"""VEX output: OpenVEX 0.2.0 and CycloneDX 1.6 documents validated against the official JSON
schemas (tests/fixtures/sca/schemas, from openvex/spec and CycloneDX/specification), and
statements that follow Frame's evidence: affected unless a recorded decision says otherwise,
never not_affected against a verified flow."""

import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca.vex import (VexError, build_statements, load_decisions, to_cyclonedx, to_openvex)

jsonschema = pytest.importorskip("jsonschema")
referencing = pytest.importorskip("referencing")

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "tests" / "fixtures" / "sca" / "schemas"
OSV = ROOT / "tests" / "fixtures" / "sca" / "osv"
TS = "2026-10-28T12:00:00Z"


def validate_openvex(doc):
    schema = json.loads((SCHEMAS / "openvex-0.2.0.schema.json").read_text())
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(doc)


def validate_cyclonedx(doc):
    from referencing import Registry, Resource
    resources = []
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        s = json.loads((SCHEMAS / name).read_text())
        resources += [(name, Resource.from_contents(s)), (s.get("$id", name), Resource.from_contents(s))]
    registry = Registry().with_resources(resources)
    schema = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text())
    jsonschema.Draft7Validator(schema, registry=registry, format_checker=jsonschema.FormatChecker()).validate(doc)


def finding(adv, pkg, version, level="installed", dev=False, fixed=("9.9.9",), **extra):
    reach = {"level": level, "calls": [], "flows": []}
    if level in ("called", "tainted"):
        reach["calls"] = [{"function": f"{pkg}.fn", "location": "src/app.js:7", "source": "curated"}]
    if level == "tainted":
        reach["flows"] = [{"location": "src/app.js:7", "evidence": "solver-verified", "type": "template_injection"}]
    return {"id": adv, "aliases": extra.get("aliases", ["CVE-2021-23337"]), "summary": "Command injection",
            "severity": "high", "score": 7.2, "cvss": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "ecosystem": "npm", "package": pkg, "version": version, "purl": f"pkg:npm/{pkg}@{version}",
            "path": "package-lock.json", "direct": True, "dev": dev, "fixed": list(fixed), "via": [],
            "functions": [], "category": "dependency",
            "evidence": "solver-verified" if level == "tainted" else "matched", "reachability": reach}


PLANS = [{"path": "package-lock.json", "package": "lodash", "current": "4.17.20", "target": "4.18.0",
          "action": "raise-requirement"}]


def test_documents_validate_and_follow_the_evidence():
    findings = [finding("GHSA-35jh-r3h4-6jhm", "lodash", "4.17.20", "tainted"),
                finding("GHSA-xxxx-dev", "jest-util", "1.0.0", "installed", dev=True, aliases=[])]
    stmts, warnings = build_statements(findings, PLANS)
    assert not warnings
    ovx = to_openvex(stmts, "pkg:generic/shop", timestamp=TS)
    validate_openvex(ovx)
    by = {s["vulnerability"]["name"]: s for s in ovx["statements"]}
    lodash = by["GHSA-35jh-r3h4-6jhm"]
    assert lodash["status"] == "affected" and "4.18.0" in lodash["action_statement"]
    assert lodash["vulnerability"]["aliases"] == ["CVE-2021-23337"]
    assert lodash["products"] == [{"@id": "pkg:generic/shop", "subcomponents": [{"@id": "pkg:npm/lodash@4.17.20"}]}]
    assert "tainted" in lodash["status_notes"] and "src/app.js:7" in lodash["status_notes"]
    assert by["GHSA-xxxx-dev"]["status"] == "affected"                   # dev only, but not opted in
    cdx = to_cyclonedx(stmts, "pkg:generic/shop", timestamp=TS)
    validate_cyclonedx(cdx)
    v = {x["id"]: x for x in cdx["vulnerabilities"]}
    assert v["GHSA-35jh-r3h4-6jhm"]["analysis"]["state"] == "exploitable"
    assert v["GHSA-35jh-r3h4-6jhm"]["analysis"]["response"] == ["update"]
    assert v["GHSA-35jh-r3h4-6jhm"]["ratings"][0] == {"severity": "high", "score": 7.2, "method": "CVSSv31",
                                                      "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}
    assert v["GHSA-xxxx-dev"]["analysis"]["state"] == "in_triage"
    assert {c["purl"] for c in cdx["components"]} == {"pkg:npm/lodash@4.17.20", "pkg:npm/jest-util@1.0.0"}


def test_the_schema_checks_have_teeth():
    stmts, _ = build_statements([finding("GHSA-35jh-r3h4-6jhm", "lodash", "4.17.20", "tainted")], PLANS)
    bad = to_openvex(stmts, "pkg:generic/shop", timestamp=TS)
    del bad["statements"][0]["action_statement"]                 # affected requires an action statement
    with pytest.raises(jsonschema.ValidationError):
        validate_openvex(bad)
    bad = to_cyclonedx(stmts, "pkg:generic/shop", timestamp=TS)
    bad["vulnerabilities"][0]["analysis"]["state"] = "probably_fine"
    with pytest.raises(jsonschema.ValidationError):
        validate_cyclonedx(bad)


def test_dev_not_shipped_is_opt_in_and_justified():
    stmts, _ = build_statements([finding("GHSA-xxxx-dev", "jest-util", "1.0.0", dev=True, aliases=[])],
                                dev_not_shipped=True)
    ovx = to_openvex(stmts, "pkg:generic/shop", timestamp=TS)
    validate_openvex(ovx)
    s = ovx["statements"][0]
    assert (s["status"], s["justification"]) == ("not_affected", "component_not_present")
    cdx = to_cyclonedx(stmts, "pkg:generic/shop", timestamp=TS)
    validate_cyclonedx(cdx)
    assert cdx["vulnerabilities"][0]["analysis"]["justification"] == "code_not_present"


def write_decisions(tmp_path, text):
    (tmp_path / ".frame").mkdir(exist_ok=True)
    (tmp_path / ".frame" / "vex.toml").write_text(text)


def test_a_recorded_decision_is_used_by_alias_but_never_against_a_verified_flow(tmp_path):
    write_decisions(tmp_path, '''
[[statement]]
vulnerability = "CVE-2021-23337"
status = "not_affected"
justification = "vulnerable_code_cannot_be_controlled_by_adversary"
impact_statement = "Templates come from a fixed map."
author = "appsec@example.com"

[[statement]]
vulnerability = "GHSA-gone-0000"
status = "not_affected"
justification = "vulnerable_code_not_present"
''')
    decisions = load_decisions(tmp_path)
    called, _ = build_statements([finding("GHSA-35jh-r3h4-6jhm", "lodash", "4.17.20", "called")], PLANS, decisions)
    assert called[0].status == "not_affected" and called[0].justification.startswith("vulnerable_code")
    validate_openvex(to_openvex(called, "pkg:generic/shop", timestamp=TS))
    decisions = load_decisions(tmp_path)
    tainted, warnings = build_statements([finding("GHSA-35jh-r3h4-6jhm", "lodash", "4.17.20", "tainted")],
                                         PLANS, decisions)
    assert tainted[0].status == "affected" and tainted[0].conflict
    assert any("kept as affected" in w for w in warnings)
    assert any("GHSA-gone-0000" in w and "matches no current finding" in w for w in warnings)


@pytest.mark.parametrize("text,message", [
    ('[[statement]]\nvulnerability = "X"\nstatus = "fine"\n', "status"),
    ('[[statement]]\nvulnerability = "X"\nstatus = "not_affected"\n', "justification or an impact_statement"),
    ('[[statement]]\nvulnerability = "X"\nstatus = "not_affected"\njustification = "trust_me"\n', "justification"),
    ('[[statement]]\nvulnerability = "X"\nstatus = "affected"\nnote = "x"\n', "unknown key"),
])
def test_malformed_decisions_are_errors(tmp_path, text, message):
    write_decisions(tmp_path, text)
    with pytest.raises(VexError, match=message):
        load_decisions(tmp_path)


@pytest.fixture
def advisories(tmp_path, monkeypatch):
    from frame.sca.advisories import build_advisories
    from frame.kb.store import pull
    raw = tmp_path / "osv"
    raw.mkdir()
    (raw / "all.json").write_text(gzip.decompress((OSV / "records.json.gz").read_bytes()).decode())
    fns = tmp_path / "fns"
    fns.mkdir()
    (fns / "npm.json").write_text(json.dumps({"GHSA-29mw-wpgm-hmr9": [{"id": "lodash.toNumber", "source": "curated"}]}))
    mirror = tmp_path / "mirror"
    build_advisories([raw], mirror, "r1", functions_dir=fns)
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("FRAME_ADVISORIES_SOURCE", str(mirror))
    pull(None, source=str(mirror))


def run(*args):
    return subprocess.run([sys.executable, "-m", "frame.cli", *args], capture_output=True, text=True,
                          env=dict(os.environ), cwd=str(ROOT))


def test_frame_deps_vex_cli(tmp_path, advisories):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("pyyaml==5.3\n")
    out = run("deps", str(proj), "--vex", "openvex", "--product", "pkg:pypi/acme-api@1.0")
    assert out.returncode == 0, out.stderr
    doc = json.loads(out.stdout)
    validate_openvex(doc)
    assert doc["statements"] and all(s["status"] == "affected" for s in doc["statements"])
    assert all("pyyaml to 5.4" in s["action_statement"] for s in doc["statements"])
    cdx = json.loads(run("deps", str(proj), "--vex", "cyclonedx").stdout)
    validate_cyclonedx(cdx)


def test_frame_scan_sca_vex_states_a_reached_function_exploitable(tmp_path, advisories):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"dependencies": {"express": "4.18.2", "lodash": "4.17.20"}}))
    (proj / "server.js").write_text("const express = require('express');\nconst _ = require('lodash');\n"
                                    "const app = express();\napp.get('/n', (req, res) => {\n"
                                    "  res.send(String(_.toNumber(req.query.n)));\n});\n")
    vex = tmp_path / "vex.cdx.json"
    out = run("scan", str(proj), "--sca", "--vex", "cyclonedx", "--vex-out", str(vex), "--fail-on", "none")
    assert out.returncode == 0, out.stderr
    doc = json.loads(vex.read_text())
    validate_cyclonedx(doc)
    states = {v["id"]: v["analysis"]["state"] for v in doc["vulnerabilities"]}
    assert states["GHSA-29mw-wpgm-hmr9"] == "exploitable"
    assert set(states.values()) <= {"exploitable", "in_triage"}
