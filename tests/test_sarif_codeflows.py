"""SARIF codeFlows + relatedLocations from the taint data already on a finding."""
from frame.sil.scanner import Severity, Vulnerability, ScanResult
from frame.sil.translator import VulnType


def _result(**kw):
    v = Vulnerability(type=VulnType.SQL_INJECTION, severity=Severity.HIGH,
                      location="app/db.py", line=20, column=3, description="SQLi",
                      procedure="q", cwe_id="CWE-89", **kw)
    r = ScanResult(filename="app/db.py"); r.vulnerabilities = [v]
    return r.to_sarif()["runs"][0]["results"][0]


def test_codeflow_from_source_and_flow():
    res = _result(source_var="name", source_location="app/views.py:5",
                  data_flow=["name", "query"], sink_type="sql")
    assert "relatedLocations" in res
    rl = res["relatedLocations"][0]["physicalLocation"]
    assert rl["artifactLocation"]["uri"] == "app/views.py" and rl["region"]["startLine"] == 5
    steps = res["codeFlows"][0]["threadFlows"][0]["locations"]
    # source step, two hop steps, sink step
    assert len(steps) == 4
    assert "source: name" in steps[0]["location"]["message"]["text"]
    assert steps[-1]["location"]["message"]["text"].startswith("sink: ")


def test_flow_without_parseable_source_still_emits_codeflow():
    res = _result(source_var="", source_location="", data_flow=["a", "b"], sink_type="sql")
    assert "relatedLocations" not in res
    steps = res["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(steps) == 3            # two hops + sink


def test_no_codeflow_without_flow_or_source():
    res = _result()                   # no data_flow, no source_location
    assert "codeFlows" not in res and "relatedLocations" not in res


def test_sarif_physical_parses_file_line_col():
    r = ScanResult(filename="x.py")
    assert r._sarif_physical("a/b.py:12:4")["region"]["startLine"] == 12
    assert r._sarif_physical("a/b.py:12")["region"]["startLine"] == 12
    assert r._sarif_physical("nonsense") is None
    assert r._sarif_physical("") is None
