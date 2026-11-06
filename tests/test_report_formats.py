"""GitLab SAST and SonarQube generic-issue report serializers."""
import json
from frame.sil.scanner import Severity, Vulnerability, ScanResult
from frame.sil.cli import format_gitlab_result, format_sonar_result
from frame.sil.translator import VulnType


def _res(sev=Severity.HIGH):
    v = Vulnerability(type=VulnType.SQL_INJECTION, severity=sev, location="app/db.py",
                      line=20, column=1, description="SQLi in q", procedure="q", cwe_id="CWE-89")
    v.path = "app/db.py"
    r = ScanResult(filename="app/db.py"); r.vulnerabilities = [v]; return r


def test_gitlab_shape_and_severity_and_cwe():
    doc = json.loads(format_gitlab_result([_res(Severity.CRITICAL)], Severity.LOW))
    assert doc["version"].startswith("15.") and doc["scan"]["type"] == "sast"
    v = doc["vulnerabilities"][0]
    assert v["category"] == "sast" and v["severity"] == "Critical"
    assert v["location"] == {"file": "app/db.py", "start_line": 20}
    cwe = v["identifiers"][0]
    assert cwe["type"] == "cwe" and cwe["value"] == "89" and "89.html" in cwe["url"]


def test_sonar_shape_and_severity_map():
    doc = json.loads(format_sonar_result([_res(Severity.HIGH)], Severity.LOW))
    i = doc["issues"][0]
    assert i["engineId"] == "frame" and i["type"] == "VULNERABILITY"
    assert i["severity"] == "CRITICAL"            # HIGH -> CRITICAL in Sonar
    assert i["primaryLocation"]["filePath"] == "app/db.py"
    assert i["primaryLocation"]["textRange"]["startLine"] == 20


def test_min_severity_filters_both():
    assert json.loads(format_gitlab_result([_res(Severity.LOW)], Severity.HIGH))["vulnerabilities"] == []
    assert json.loads(format_sonar_result([_res(Severity.LOW)], Severity.HIGH))["issues"] == []


def test_formats_in_both_parsers():
    from frame.cli import create_parser as fp
    from frame.sil.cli import create_parser as sp
    for mk in (fp, sp):
        for fmt in ("gitlab", "sonar"):
            assert mk().parse_args(["scan", "x.py", "-f", fmt]).format == fmt
