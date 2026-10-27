"""Knowledge base: build a revision, pull it (verified, per language), pin it, and have scans
load its packs without touching the network."""

import json
import shutil

import pytest

from frame.kb import KBError, build, kb_pack_dirs, pull, read_lock, write_lock
from frame.sil.scanner import FrameScanner

ACME = '''[pack]
name = "acme"
language = "python"
detect = { imports = ["acme"] }

[[sink]]
call = ["acme.run"]
kind = "command"
'''
JS = '''[pack]
name = "acmejs"
language = "javascript"
detect = { imports = ["acmejs"] }

[[sink]]
call = ["acmejs.run"]
kind = "command"
'''
APP = ("import acme\nfrom flask import Flask, request\napp = Flask(__name__)\n"
       "@app.route('/r')\ndef r():\n    acme.run(request.args.get('c'))\n    return 'ok'\n")


@pytest.fixture
def kb(tmp_path, monkeypatch):
    monkeypatch.setenv("FRAME_KB_CACHE", str(tmp_path / "cache"))
    monkeypatch.delenv("FRAME_KB", raising=False)
    src = tmp_path / "packs"
    (src / "python").mkdir(parents=True)
    (src / "javascript").mkdir(parents=True)
    (src / "python" / "acme.toml").write_text(ACME)
    (src / "javascript" / "acmejs.toml").write_text(JS)
    out = tmp_path / "mirror"
    build(src, out, "2026.10.1")
    return out


def test_build_writes_a_verified_manifest(kb):
    m = json.loads((kb / "manifest.json").read_text())
    assert m["schema"] == 1 and m["revision"] == "2026.10.1"
    assert set(m["files"]) == {"packs/python/acme.toml", "packs/javascript/acmejs.toml"}
    assert all(len(f["sha256"]) == 64 for f in m["files"].values())


def test_pull_only_the_project_languages_and_reuse_the_cache(kb):
    got = pull(["python"], source=str(kb))
    assert got.files == ["packs/python/acme.toml"] and got.fetched == 1 and got.revision == "2026.10.1"
    again = pull(["python"], source=str(kb))
    assert again.fetched == 0


def test_a_tampered_file_is_refused(kb):
    (kb / "packs" / "python" / "acme.toml").write_text(ACME + "\n# changed\n")
    with pytest.raises(KBError, match="sha256"):
        pull(["python"], source=str(kb))


def test_a_manifest_may_only_list_data_files(kb):
    m = json.loads((kb / "manifest.json").read_text())
    m["files"]["../evil.py"] = {"sha256": "0" * 64}
    (kb / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(KBError, match="may not hold"):
        pull(None, source=str(kb))


def test_a_pinned_manifest_must_not_change(kb, tmp_path):
    got = pull(None, source=str(kb))
    project = tmp_path / "proj"
    project.mkdir()
    write_lock(project, got)
    lock = read_lock(project)
    assert lock["revision"] == "2026.10.1"
    m = json.loads((kb / "manifest.json").read_text())
    m["note"] = "republished"
    (kb / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(KBError, match="pinned"):
        pull(None, source=str(kb), expect_manifest_sha256=lock["manifest_sha256"])


def test_scans_load_kb_packs_and_never_fetch(kb, tmp_path, monkeypatch):
    code_cwes = lambda: {v.cwe_id for v in FrameScanner(language="python").scan(APP, "a.py").vulnerabilities}
    assert "CWE-78" not in code_cwes()                       # nothing pulled: built-in packs only
    pull(["python"], source=str(kb))
    monkeypatch.setenv("FRAME_KB_SOURCE", str(kb))
    shutil.rmtree(kb)                                       # the scan must not need the source
    assert kb_pack_dirs() and "CWE-78" in code_cwes()
    monkeypatch.setenv("FRAME_KB", "off")
    assert "CWE-78" not in code_cwes()
