"""A directory scan must give the LLM layer a repo root.

`detect_agentic` can trace flows across files with its read_file/grep tools, but
only when `config.repo_root` is set. When it is empty the function silently falls
back to single-file detection, so cross-file flows are lost with no error and no
warning. A directory scan knows the root, so it supplies one.

The silent-degradation failure mode is why these tests exist: nothing else would
catch it.
"""

import pathlib

import pytest

from frame.sil import FrameScanner


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("FRAME_LLM_REPO_ROOT", raising=False)
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://endpoint.invalid/v1")
    monkeypatch.setenv("FRAME_LLM_MODEL", "test-model")


def _tree(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    return tmp_path


def test_directory_scan_sets_repo_root(tmp_path):
    d = _tree(tmp_path)
    scanner = FrameScanner(language="python", verify=False, llm_detect=True)
    scanner.scan_directory(str(d), "**/*.py")
    assert scanner._llm_config.repo_root == str(d.resolve())


def test_repo_root_is_absolute(tmp_path):
    d = _tree(tmp_path)
    scanner = FrameScanner(language="python", verify=False, llm_detect=True)
    scanner.scan_directory(str(d), "**/*.py")
    assert pathlib.Path(scanner._llm_config.repo_root).is_absolute()


def test_triage_only_also_gets_a_root(tmp_path):
    d = _tree(tmp_path)
    scanner = FrameScanner(language="python", verify=False, llm_triage=True)
    scanner.scan_directory(str(d), "**/*.py")
    assert scanner._llm_config.repo_root == str(d.resolve())


def test_explicit_env_repo_root_wins(tmp_path, monkeypatch):
    d = _tree(tmp_path)
    monkeypatch.setenv("FRAME_LLM_REPO_ROOT", "/explicitly/chosen/root")
    scanner = FrameScanner(language="python", verify=False, llm_detect=True)
    scanner.scan_directory(str(d), "**/*.py")
    assert scanner._llm_config.repo_root == "/explicitly/chosen/root"


def test_preconfigured_repo_root_is_not_overwritten(tmp_path):
    from frame.sil.llm_triage import TriageConfig
    d = _tree(tmp_path)
    cfg = TriageConfig.from_env()
    cfg.repo_root = "/already/set"
    scanner = FrameScanner(language="python", verify=False, llm_detect=True,
                           llm_config=cfg)
    scanner.scan_directory(str(d), "**/*.py")
    assert scanner._llm_config.repo_root == "/already/set"


def test_no_llm_layer_creates_no_config(tmp_path):
    # The symbolic-only path must stay untouched: no config, no env reads.
    d = _tree(tmp_path)
    scanner = FrameScanner(language="python", verify=False)
    scanner.scan_directory(str(d), "**/*.py")
    assert scanner._llm_config is None


def test_scan_still_returns_results(tmp_path):
    # Wiring the root must not disturb the scan itself.
    d = _tree(tmp_path)
    scanner = FrameScanner(language="python", verify=False, llm_detect=True)
    results = scanner.scan_directory(str(d), "**/*.py")
    assert len(results) == 2
