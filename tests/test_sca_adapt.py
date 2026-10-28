"""Breaking-change adaptation (`frame deps --apply --verify COMMAND --adapt`): the project's own
command and Frame's re-scan decide; the model only proposes. The model and the command are
injected here; the live test uses a real model (FRAME_LLM_*) and Werkzeug 2 -> 3, which removed
werkzeug.urls.url_parse / url_quote."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from frame.sca.adapt import adapt, usage_files
from frame.sca.apply import apply_plan

APP = '''from werkzeug.urls import url_parse


def host_of(url):
    return url_parse(url).host
'''
UPGRADE = [{"ecosystem": "PyPI", "package": "werkzeug", "current": "2.2.3", "target": "3.1.9", "major": True}]


def project(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "requirements.txt").write_text("werkzeug==2.2.3\n")
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "util.py").write_text("def unrelated():\n    return 1\n")
    return tmp_path


def passes_when(text):
    """A stand-in for the project's command: passes once app.py no longer uses url_parse."""
    return lambda cmd, root: ("url_parse" not in (Path(root) / "app.py").read_text(), "ImportError: url_parse")


FIX = {"edits": [{"path": "app.py", "original": "from werkzeug.urls import url_parse",
                  "replacement": "from urllib.parse import urlsplit"},
                 {"path": "app.py", "original": "url_parse(url).host", "replacement": "urlsplit(url).hostname"}],
       "rationale": "url_parse was removed in Werkzeug 3"}


def test_only_the_code_that_imports_the_package_is_given():
    root = Path(__file__).parent / "fixtures" / "sca" / "solve" / "flask-app"
    assert usage_files(root, UPGRADE) == []


def test_an_adaptation_that_passes_is_kept(tmp_path):
    root = project(tmp_path)
    assert usage_files(root, UPGRADE) == ["app.py"]
    res = adapt(root, UPGRADE, "check", "ImportError", proposer=lambda u, o, s: FIX, run=passes_when(None))
    assert res.status == "adapted" and res.rounds == 1 and [c.path for c in res.changes] == ["app.py"]
    assert "urlsplit(url).hostname" in (root / "app.py").read_text()


def test_one_that_keeps_failing_is_restored(tmp_path):
    root = project(tmp_path)
    seen = []

    def proposer(u, output, sources):
        seen.append(output)
        return {"edits": [{"path": "app.py", "original": "def host_of", "replacement": f"def host_of{len(seen)}"}]}
    res = adapt(root, UPGRADE, "check", "first failure", proposer=proposer, rounds=3,
                run=lambda c, r: (False, f"failure after round {len(seen)}"))
    assert res.status == "failed" and res.rounds == 3 and (root / "app.py").read_text() == APP
    assert seen == ["first failure", "failure after round 1", "failure after round 2"]     # each round sees the last


def test_one_that_adds_a_finding_is_restored(tmp_path):
    root = project(tmp_path)
    bad = {"edits": [{"path": "app.py", "original": "from werkzeug.urls import url_parse",
                      "replacement": "import os\nfrom urllib.parse import urlsplit\nfrom flask import request"},
                     {"path": "app.py", "original": "    return url_parse(url).host",
                      "replacement": "    os.system('ping ' + request.args['h'])\n    return urlsplit(url).hostname"}]}
    res = adapt(root, UPGRADE, "check", "ImportError", proposer=lambda u, o, s: bad, run=passes_when(None))
    assert res.status == "introduces-findings" and res.introduced and (root / "app.py").read_text() == APP


def test_a_manifest_or_lockfile_is_never_edited(tmp_path):
    root = project(tmp_path)
    undo = {"edits": [{"path": "requirements.txt", "original": "werkzeug==2.2.3", "replacement": "werkzeug==2.2.3"},
                      {"path": "../outside.py", "original": "x", "replacement": "y"}]}
    res = adapt(root, UPGRADE, "check", "ImportError", proposer=lambda u, o, s: undo, run=passes_when(None))
    assert res.status == "failed" and (root / "requirements.txt").read_text() == "werkzeug==2.2.3\n"


def _plan():
    return [{"ecosystem": "PyPI", "package": "werkzeug", "current": "2.2.3", "target": "3.1.9",
             "action": "raise-requirement", "path": "requirements.txt", "direct": True, "dev": False,
             "fixes": ["GHSA-x"], "unfixed": [], "via": [], "major": True, "requirers": [], "known_requirements": True}]


def _check_script(tmp_path):
    """The command: passes on 2.2.3, and on 3.x only once app.py stops using url_parse."""
    script = tmp_path / "check.py"
    script.write_text("import pathlib, sys\n"
                      "old = '2.2.3' in pathlib.Path('requirements.txt').read_text()\n"
                      "sys.exit(0 if old or 'url_parse' not in pathlib.Path('app.py').read_text() else 1)\n")
    return f'"{sys.executable}" "{script}"'


def test_apply_keeps_an_adapted_upgrade_and_rolls_back_a_failed_one(tmp_path):
    root = project(tmp_path / "ok")
    out = apply_plan(_plan(), root, write=True, verify=_check_script(tmp_path),
                     adapt_fn=lambda o: adapt(root, UPGRADE, _check_script(tmp_path), o,
                                              proposer=lambda u, oo, s: FIX))
    assert out.verify == "adapted" and (root / "requirements.txt").read_text() == "werkzeug==3.1.9\n"
    root2 = project(tmp_path / "bad")
    out = apply_plan(_plan(), root2, write=True, verify=_check_script(tmp_path),
                     adapt_fn=lambda o: adapt(root2, UPGRADE, _check_script(tmp_path), o,
                                              proposer=lambda u, oo, s: {"edits": []}))
    assert out.verify == "rolled-back" and out.adaptation.status == "failed"
    assert (root2 / "requirements.txt").read_text() == "werkzeug==2.2.3\n" and (root2 / "app.py").read_text() == APP


@pytest.mark.skipif(not (os.environ.get("FRAME_SCA_REAL") == "1" and os.environ.get("FRAME_LLM_BASE_URL")),
                    reason="live: FRAME_SCA_REAL=1 and a model (FRAME_LLM_*); installs Werkzeug from PyPI")
def test_live_a_real_model_adapts_to_werkzeug_3(tmp_path):
    from frame.sil.llm_client import LLMConfig
    root = project(tmp_path)
    (root / "test_app.py").write_text("from app import host_of\n\n\ndef test_host():\n"
                                      "    assert host_of('https://example.com:8443/a') == 'example.com'\n")
    subprocess.run([sys.executable, "-m", "venv", str(root / ".venv")], check=True)
    pip = str(root / ".venv" / "bin" / "pip")
    subprocess.run([pip, "install", "-q", "pytest", "-r", str(root / "requirements.txt")], check=True)
    check = ".venv/bin/pip install -q -r requirements.txt && .venv/bin/python -m pytest -q"
    if shutil.which("bash") is None:
        pytest.skip("needs a POSIX shell")
    out = apply_plan(_plan(), root, write=True, verify=check,
                     adapt_fn=lambda o: adapt(root, UPGRADE, check, o, LLMConfig.from_env()))
    assert out.verify == "adapted", (out.verify, getattr(out.adaptation, "status", None), out.verify_output[-500:])
    assert "url_parse" not in (root / "app.py").read_text()


def test_a_rescan_that_fails_restores_the_edits(tmp_path, monkeypatch):
    """The re-scan is the safety check: if it cannot run, the edits are not kept."""
    import frame.sil.scanner as S
    root = project(tmp_path)
    real = S.FrameScanner.scan_file
    calls = {"n": 0}

    def flaky(self, path, *a, **k):
        calls["n"] += 1
        if calls["n"] > 1:                                   # the "before" scan works, the "after" one fails
            raise RuntimeError("scanner crashed")
        return real(self, path, *a, **k)
    monkeypatch.setattr(S.FrameScanner, "scan_file", flaky)
    res = adapt(root, UPGRADE, "check", "ImportError", proposer=lambda u, o, s: FIX, run=passes_when(None))
    assert res.status == "introduces-findings" and (root / "app.py").read_text() == APP
