"""`--fail-on-evidence`: break CI only on findings at/above an evidence tier, ANDed with --fail-on."""

import pytest
from frame.sil.scanner import Severity, Vulnerability
from frame.sil.cli import should_fail, _evidence_value, ScanResult
from frame.sil.translator import VulnType


def _vuln(evidence, severity=Severity.HIGH):
    return Vulnerability(type=VulnType.SQL_INJECTION, severity=severity, location="a.py",
                         line=1, column=1, description="d", procedure="p", evidence=evidence)


def _res(*vulns):
    r = ScanResult(filename="a.py")
    r.vulnerabilities = list(vulns)
    return r


def test_evidence_value_ordering():
    assert _evidence_value("matched") < _evidence_value("data-flow") < \
        _evidence_value("solver-verified") < _evidence_value("exploit-confirmed")
    assert _evidence_value("nonsense") == 0


def test_no_evidence_gate_is_unchanged():
    res = [_res(_vuln("data-flow"))]
    assert should_fail(res, "high") is True            # severity alone fails


def test_evidence_gate_filters_below_tier():
    res = [_res(_vuln("data-flow", Severity.HIGH))]
    # a high-severity data-flow finding, but we only fail on solver-verified+
    assert should_fail(res, "high", "solver-verified") is False


def test_evidence_gate_passes_at_tier():
    res = [_res(_vuln("solver-verified", Severity.HIGH))]
    assert should_fail(res, "high", "solver-verified") is True
    assert should_fail(res, "high", "exploit-confirmed") is False


def test_evidence_gate_anded_with_severity():
    # exploit-confirmed but only LOW severity; fail-on high -> should not fail
    res = [_res(_vuln("exploit-confirmed", Severity.LOW))]
    assert should_fail(res, "high", "data-flow") is False


def test_evidence_gate_with_any():
    res = [_res(_vuln("matched"))]
    assert should_fail(res, "any", "solver-verified") is False
    assert should_fail(res, "any", "matched") is True


def test_none_overrides_evidence():
    res = [_res(_vuln("exploit-confirmed"))]
    assert should_fail(res, "none", "matched") is False


def test_flag_parses_on_both_entrypoints():
    from frame.cli import create_parser as fp
    from frame.sil.cli import create_parser as sp
    for mk in (fp, sp):
        a = mk().parse_args(["scan", "x.py", "--fail-on-evidence", "solver-verified"])
        assert a.fail_on_evidence == "solver-verified"
