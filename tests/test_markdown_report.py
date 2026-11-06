"""`frame scan -f markdown`: a human report for PR comments / job summaries."""
from frame.sil.scanner import Severity, Vulnerability, ScanResult
from frame.sil.cli import format_markdown_result
from frame.sil.translator import VulnType


def _v(evidence, sev=Severity.HIGH, flow=None, proof=None):
    return Vulnerability(type=VulnType.SQL_INJECTION, severity=sev, location="app/db.py",
                         line=12, column=1, description="d", procedure="q",
                         data_flow=flow or [], evidence=evidence, cwe_id="CWE-89", proof=proof)


def _r(*vs):
    r = ScanResult(filename="app/db.py"); r.vulnerabilities = list(vs); return r


def test_empty_says_no_findings():
    md = format_markdown_result([_r()], Severity.LOW)
    assert "No findings" in md and md.startswith("## Frame security scan")


def test_headline_counts_proven_and_confirmed():
    md = format_markdown_result([_r(_v("exploit-confirmed"), _v("data-flow"), _v("solver-verified"))],
                                Severity.LOW)
    assert "3 findings" in md
    assert "2 solver-verified or higher" in md    # solver-verified + exploit-confirmed
    assert "1 exploit-confirmed" in md


def test_table_has_rows_and_flow():
    md = format_markdown_result([_r(_v("data-flow", flow=["req.name", "query"]))], Severity.LOW)
    assert "| Severity | Type | CWE | Evidence | Location | Flow |" in md
    assert "sql_injection" in md and "CWE-89" in md and "data-flow" in md
    assert "req.name -> query" in md
    assert "`app/db.py:12`" in md


def test_pipes_escaped():
    md = format_markdown_result([_r(_v("data-flow", flow=["a|b"]))], Severity.LOW)
    assert "a\\|b" in md


def test_min_severity_filters():
    md = format_markdown_result([_r(_v("data-flow", sev=Severity.LOW))], Severity.HIGH)
    assert "No findings" in md


def test_proof_test_paths_listed():
    md = format_markdown_result([_r(_v("exploit-confirmed", proof={"test_path": "proofs/t.c"}))],
                                Severity.LOW)
    assert "Reproduction tests written" in md and "proofs/t.c" in md


def test_markdown_in_format_choices_both_parsers():
    from frame.cli import create_parser as fp
    from frame.sil.cli import create_parser as sp
    for mk in (fp, sp):
        assert mk().parse_args(["scan", "x.py", "-f", "markdown"]).format == "markdown"
