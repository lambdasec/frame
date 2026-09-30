"""`frame scan` skips agent/tool state directories by default; `--no-default-
excludes` restores the old unfiltered walk.

Companion to tests/test_scan_directory_excludes.py, which exercises
`FrameScanner.scan_directory` directly. These tests exercise the same
behavior through the CLI flag end to end.
"""

import json

from frame.sil.cli import create_parser, main


def _tree(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app2.py").write_text("y = 2\n")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "hook.py").write_text("print('hook')\n")
    return git_dir / "hook.py"


def test_flag_parses_and_defaults_to_false():
    parser = create_parser()
    args = parser.parse_args(["scan", "app.py"])
    assert args.no_default_excludes is False

    args = parser.parse_args(["scan", "app.py", "--no-default-excludes"])
    assert args.no_default_excludes is True


def test_default_scan_skips_git_directory(tmp_path, capsys):
    hook = _tree(tmp_path)

    rc = main(["scan", str(tmp_path), "--no-verify", "-f", "json", "--fail-on", "none"])
    captured = capsys.readouterr()
    assert rc == 0

    data = json.loads(captured.out)
    filenames = {f["filename"] for f in data["files"]}
    assert str(hook) not in filenames
    assert any(name.endswith("app.py") for name in filenames)
    assert any(name.endswith("app2.py") for name in filenames)


def test_no_default_excludes_flag_scans_everything(tmp_path, capsys):
    hook = _tree(tmp_path)

    rc = main([
        "scan", str(tmp_path), "--no-verify", "--no-default-excludes",
        "-f", "json", "--fail-on", "none",
    ])
    captured = capsys.readouterr()
    assert rc == 0

    data = json.loads(captured.out)
    filenames = {f["filename"] for f in data["files"]}
    assert str(hook) in filenames
