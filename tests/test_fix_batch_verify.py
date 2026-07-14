"""TDD contract for batched fix verification (Workstream B).

Today `verify_fix` re-runs detection once PER finding, which timed out on a CVE
with 13 findings. `verify_fixes` verifies all of a file's findings with a SINGLE
re-scan: apply every patch, then detect once and check which CWEs are gone.
Red now (verify_fixes does not exist), green after implementation.
"""

import frame.sil.llm_fix as fix_mod
from frame.sil.llm_client import LLMConfig


class _V:
    def __init__(self, cwe):
        self.cwe_id = cwe


def test_verify_fixes_one_rescan_for_all_findings(monkeypatch):
    calls = {"n": 0}

    def fake_detect(source, language, filename, config, client=None):
        calls["n"] += 1
        return [_V("CWE-89")]                 # 89 still present, 22 gone

    monkeypatch.setattr(fix_mod, "detect_in_file", fake_detect)
    findings = [{"cwe_id": "CWE-89", "line": 5}, {"cwe_id": "CWE-22", "line": 9}]
    res = fix_mod.verify_fixes("patched source", "python", "app.py", findings, LLMConfig())
    assert calls["n"] == 1                    # ONE re-scan covers both findings
    assert res == [False, True]               # 89 still detects -> not fixed; 22 gone -> fixed


def test_verify_fixes_detect_failure_is_none(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("scan broke")

    monkeypatch.setattr(fix_mod, "detect_in_file", boom)
    findings = [{"cwe_id": "CWE-89"}, {"cwe_id": "CWE-22"}]
    res = fix_mod.verify_fixes("src", "python", "app.py", findings, LLMConfig())
    assert res == [None, None]                # verification couldn't run -> unknown, not False


def test_verify_fixes_empty_findings(monkeypatch):
    def fake_detect(*a, **k):
        raise AssertionError("must not re-scan when there are no findings")

    monkeypatch.setattr(fix_mod, "detect_in_file", fake_detect)
    assert fix_mod.verify_fixes("src", "python", "app.py", [], LLMConfig()) == []
