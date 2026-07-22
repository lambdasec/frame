"""Repository-scale LLM detection (no network -- stubbed transport).

Per-file agentic detection opens one model session per candidate file. On a real
project that is unusable: a 500-file repository costs 500 sessions, each paying to
rediscover the same context, and the wall-clock makes `--ai` impractical on
anything but toy inputs. `detect_repo` runs ONE session over the whole tree and
lets the model navigate with grep/read_file instead.

Because findings now come from many files in a single session, each one has to
name its own file. That is the part most likely to go wrong, so the tests below
lean hardest on path handling: a model-supplied path is untrusted input.
"""

import json

from frame.sil.llm_triage import TriageConfig, LLMTriageClient
from frame.sil.llm_detect import (
    DETECT_REPO_SCHEMA, _repo_findings_to_vulns, _repo_inventory, detect_repo,
)


def _client(script):
    """A client whose chat_raw returns scripted assistant messages in order."""
    c = LLMTriageClient(TriageConfig(base_url="x", model="m"))
    seq = {"i": 0}

    def chat(messages, tools=None):
        msg = script[min(seq["i"], len(script) - 1)]
        seq["i"] += 1
        return msg

    c.chat_raw = chat
    return c


def _final(findings):
    return {"content": json.dumps({"reasoning": "r", "findings": findings}),
            "tool_calls": []}


def _repo(tmp_path):
    (tmp_path / "app.py").write_text("import os\nos.system(x)\n")
    (tmp_path / "util.py").write_text("y = 2\n")
    return tmp_path


# --- inventory ---------------------------------------------------------------

def test_inventory_lists_source_files(tmp_path):
    inv = _repo_inventory(str(_repo(tmp_path)), "python")
    assert "app.py" in inv and "util.py" in inv


def test_inventory_skips_dependency_and_vcs_directories(tmp_path):
    d = _repo(tmp_path)
    for junk in ("node_modules", "vendor", "__pycache__", ".git"):
        (d / junk).mkdir()
        (d / junk / "noise.py").write_text("z = 3\n")
    inv = _repo_inventory(str(d), "python")
    assert "noise.py" not in inv
    assert "app.py" in inv


def test_inventory_filters_by_language(tmp_path):
    d = _repo(tmp_path)
    (d / "readme.md").write_text("# hi\n")
    (d / "script.js").write_text("var a = 1;\n")
    inv = _repo_inventory(str(d), "python")
    assert "app.py" in inv
    assert "script.js" not in inv and "readme.md" not in inv


def test_inventory_is_bounded(tmp_path):
    for i in range(50):
        (tmp_path / f"f{i}.py").write_text("x = 1\n")
    inv = _repo_inventory(str(tmp_path), "python", limit=10)
    assert "truncated" in inv
    assert len([ln for ln in inv.splitlines() if ln.endswith(".py")]) <= 10


# --- finding paths are untrusted input ---------------------------------------

def test_path_traversal_in_model_output_is_dropped(tmp_path):
    # A model-supplied path escaping the repo is not clamped, it is discarded: it
    # means the model named something it never read.
    out = _repo_findings_to_vulns([{
        "file": "../../etc/passwd", "cwe": "CWE-22", "line": 1,
        "type": "path", "confidence": 0.9, "reasoning": "r"}], str(_repo(tmp_path)))
    assert out == []


def test_absolute_path_outside_repo_is_dropped(tmp_path):
    out = _repo_findings_to_vulns([{
        "file": "/etc/passwd", "cwe": "CWE-22", "line": 1,
        "type": "path", "confidence": 0.9, "reasoning": "r"}], str(_repo(tmp_path)))
    assert out == []


def test_nonexistent_file_is_dropped(tmp_path):
    # A finding we cannot locate is not reportable, however plausible it sounds.
    out = _repo_findings_to_vulns([{
        "file": "does_not_exist.py", "cwe": "CWE-89", "line": 1,
        "type": "sqli", "confidence": 0.9, "reasoning": "r"}], str(_repo(tmp_path)))
    assert out == []


def test_missing_or_empty_file_field_is_dropped(tmp_path):
    d = _repo(tmp_path)
    for bad in ({"file": ""}, {}):
        f = {"cwe": "CWE-89", "line": 1, "type": "sqli", "confidence": 0.9,
             "reasoning": "r", **bad}
        assert _repo_findings_to_vulns([f], str(d)) == []


def test_real_repo_relative_path_is_kept_and_resolved(tmp_path):
    d = _repo(tmp_path)
    out = _repo_findings_to_vulns([{
        "file": "app.py", "cwe": "CWE-78", "line": 2,
        "type": "command injection", "confidence": 0.9, "reasoning": "r"}], str(d))
    assert len(out) == 1
    assert out[0].cwe_id == "CWE-78"


def test_malformed_entries_do_not_raise(tmp_path):
    d = _repo(tmp_path)
    assert _repo_findings_to_vulns(["not a dict", None, 42], str(d)) == []


# --- end to end through the agent loop ---------------------------------------

def test_detect_repo_returns_findings_across_files(tmp_path):
    d = _repo(tmp_path)
    client = _client([_final([
        {"file": "app.py", "cwe": "CWE-78", "line": 2, "type": "cmdi",
         "confidence": 0.9, "reasoning": "os.system on tainted input"},
        {"file": "util.py", "cwe": "CWE-89", "line": 1, "type": "sqli",
         "confidence": 0.8, "reasoning": "r"},
    ])])
    out = detect_repo(str(d), "python", TriageConfig(base_url="x", model="m"), client)
    assert {v.cwe_id for v in out} == {"CWE-78", "CWE-89"}


def test_detect_repo_handles_clean_repo(tmp_path):
    d = _repo(tmp_path)
    client = _client([_final([])])
    assert detect_repo(str(d), "python", TriageConfig(base_url="x", model="m"), client) == []


def test_detect_repo_is_one_session_not_one_per_file(tmp_path):
    # The whole point: a repository costs one session regardless of file count.
    d = tmp_path
    for i in range(25):
        (d / f"mod{i}.py").write_text("x = 1\n")
    calls = {"n": 0}
    client = _client([_final([])])
    inner = client.chat_raw

    def counting(messages, tools=None):
        calls["n"] += 1
        return inner(messages, tools)

    client.chat_raw = counting
    detect_repo(str(d), "python", TriageConfig(base_url="x", model="m"), client)
    assert calls["n"] == 1, f"expected a single session, made {calls['n']} calls"


def test_detect_repo_on_missing_directory_is_best_effort(tmp_path):
    cfg = TriageConfig(base_url="x", model="m")
    assert detect_repo(str(tmp_path / "nope"), "python", cfg, _client([_final([])])) == []
    assert detect_repo("", "python", cfg, _client([_final([])])) == []


def test_detect_repo_with_no_source_files_makes_no_call(tmp_path):
    (tmp_path / "notes.txt").write_text("hello\n")
    calls = {"n": 0}
    client = _client([_final([])])
    inner = client.chat_raw

    def counting(messages, tools=None):
        calls["n"] += 1
        return inner(messages, tools)

    client.chat_raw = counting
    assert detect_repo(str(tmp_path), "python", TriageConfig(base_url="x", model="m"),
                       client) == []
    assert calls["n"] == 0


def test_schema_requires_a_file_field():
    # Repo-scale findings are useless without a location; the schema must enforce it.
    item = DETECT_REPO_SCHEMA["properties"]["findings"]["items"]
    assert "file" in item["properties"]
    assert "file" in item["required"]


# --- scanner integration -----------------------------------------------------

def test_repo_scale_mode_replaces_per_file_llm_pass(tmp_path, monkeypatch):
    """One repo-wide session, and the per-file LLM pass must not also fire."""
    from frame.sil import FrameScanner
    import frame.sil.scanner as scanner_mod
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("FRAME_LLM_MODEL", "m")
    for i in range(6):
        (tmp_path / f"m{i}.py").write_text("import os\nos.system(x)\n")

    calls = {"repo": 0, "per_file": 0}

    def fake_repo(root, language, config, client=None, max_steps=None):
        calls["repo"] += 1
        return []

    monkeypatch.setattr("frame.sil.llm_detect.detect_repo", fake_repo)
    sc = FrameScanner(language="python", verify=False, llm_detect=True,
                      llm_repo_scale=True)
    monkeypatch.setattr(sc, "_apply_llm_detect",
                        lambda v, *a, **k: (calls.__setitem__("per_file",
                                            calls["per_file"] + 1), v)[1])
    sc.scan_directory(str(tmp_path), "**/*.py")
    assert calls["repo"] == 1, "expected exactly one repository-wide session"
    assert calls["per_file"] == 0, "per-file LLM pass must be suppressed"


def test_repo_scale_off_by_default_keeps_per_file(tmp_path, monkeypatch):
    # Default must be unchanged, so existing benchmark numbers cannot move.
    from frame.sil import FrameScanner
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("FRAME_LLM_MODEL", "m")
    (tmp_path / "a.py").write_text("x = 1\n")
    sc = FrameScanner(language="python", verify=False, llm_detect=True)
    assert sc.llm_repo_scale is False
    calls = {"n": 0}
    monkeypatch.setattr(sc, "_apply_llm_detect",
                        lambda v, *a, **k: (calls.__setitem__("n", calls["n"] + 1), v)[1])
    sc.scan_directory(str(tmp_path), "**/*.py")
    assert calls["n"] == 1


def test_repo_scale_failure_preserves_symbolic_findings(tmp_path, monkeypatch):
    # A broken LLM tier must never discard proven symbolic findings.
    from frame.sil import FrameScanner
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("FRAME_LLM_MODEL", "m")
    (tmp_path / "a.py").write_text(
        "import os\nfrom flask import request\n"
        "def h():\n    os.system('ls ' + request.args.get('x'))\n")

    def boom(*a, **k):
        raise RuntimeError("endpoint down")

    monkeypatch.setattr("frame.sil.llm_detect.detect_repo", boom)
    sc = FrameScanner(language="python", verify=False, llm_detect=True,
                      llm_repo_scale=True)
    results = sc.scan_directory(str(tmp_path), "**/*.py")
    assert sum(len(r.vulnerabilities) for r in results) >= 1


def test_repo_scale_attaches_finding_to_named_file(tmp_path, monkeypatch):
    from frame.sil import FrameScanner
    from frame.sil.llm_detect import _repo_findings_to_vulns
    monkeypatch.setenv("FRAME_LLM_BASE_URL", "http://x/v1")
    monkeypatch.setenv("FRAME_LLM_MODEL", "m")
    (tmp_path / "a.py").write_text("x = 1\n")
    vulns = _repo_findings_to_vulns([{
        "file": "a.py", "cwe": "CWE-78", "line": 1, "type": "cmdi",
        "confidence": 0.9, "reasoning": "r"}], str(tmp_path))
    monkeypatch.setattr("frame.sil.llm_detect.detect_repo",
                        lambda *a, **k: vulns)
    sc = FrameScanner(language="python", verify=False, llm_detect=True,
                      llm_repo_scale=True)
    results = sc.scan_directory(str(tmp_path), "**/*.py")
    assert any(v.cwe_id == "CWE-78" for r in results for v in r.vulnerabilities)
