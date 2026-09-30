"""Directory scans must not descend into agent worktree copies or similar.

`FrameScanner.scan_directory` used to glob the whole tree with no exclusions
at all. On a real repository that meant scanning full copies of the project
sitting under `.claude/worktrees/<branch>/` (Claude Code agent worktrees), so
every finding showed up once per worktree in addition to the real source.
VCS internals (`.git`), agent worktree copies (`.claude/worktrees`,
`.cursor/worktrees`, `.worktrees`), IDE config, dependency directories and
virtualenvs are not project source and must be skipped by default, for every
language -- the exclusion is on the directory walk, not on any one frontend.

The exclusion is deliberately narrow where a tool's whole state directory
also holds real, user-authored code: `.claude/hooks/*.py` and skill scripts
are project source a security scanner should see, so only the `worktrees`
subdirectory under `.claude`/`.cursor` is excluded, never the bare tool
directory itself.

These tests were written RED (failing against the old, unfiltered
`scan_directory`, or against the earlier too-broad `.claude`/`.cursor`
exclusion) and are GREEN against the current default-exclude behavior.
"""

import pathlib

from frame.sil.scanner import FrameScanner, DEFAULT_EXCLUDED_SCAN_DIRS


def _scanned_filenames(results):
    return {r.filename for r in results}


def test_default_excludes_constant_has_worktrees_and_git():
    # `.git` is a plain name; `.claude/worktrees` and `.cursor/worktrees` are
    # narrowed to the worktrees subdirectory specifically (see module docstring).
    assert ".git" in DEFAULT_EXCLUDED_SCAN_DIRS
    assert (".claude", "worktrees") in DEFAULT_EXCLUDED_SCAN_DIRS
    assert (".cursor", "worktrees") in DEFAULT_EXCLUDED_SCAN_DIRS


def test_claude_worktree_copy_is_skipped(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    worktree = tmp_path / ".claude" / "worktrees" / "some-branch"
    worktree.mkdir(parents=True)
    (worktree / "app.py").write_text("x = 1\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py")

    filenames = _scanned_filenames(results)
    assert str(tmp_path / "app.py") in filenames
    assert str(worktree / "app.py") not in filenames
    assert len(results) == 1


def test_cursor_worktree_copy_is_skipped(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    worktree = tmp_path / ".cursor" / "worktrees" / "some-branch"
    worktree.mkdir(parents=True)
    (worktree / "app.py").write_text("x = 1\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py")

    filenames = _scanned_filenames(results)
    assert str(tmp_path / "app.py") in filenames
    assert str(worktree / "app.py") not in filenames
    assert len(results) == 1


def test_claude_hooks_are_real_source_and_still_scanned(tmp_path):
    # A blanket `.claude` exclusion would also hide `.claude/hooks/*.py` and
    # skill scripts, which are real, user-authored project code -- only
    # `.claude/worktrees` is excluded, never the bare `.claude` directory.
    (tmp_path / "app.py").write_text("x = 1\n")
    hooks = tmp_path / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "h.py").write_text("y = 2\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py")

    filenames = _scanned_filenames(results)
    assert str(tmp_path / "app.py") in filenames
    assert str(hooks / "h.py") in filenames
    assert len(results) == 2


def test_bare_venv_with_pyvenv_cfg_is_skipped(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    venv = tmp_path / "venv"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    lib = venv / "lib"
    lib.mkdir()
    (lib / "site.py").write_text("z = 3\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py")

    filenames = _scanned_filenames(results)
    assert str(tmp_path / "app.py") in filenames
    assert str(lib / "site.py") not in filenames
    assert len(results) == 1


def test_bare_venv_without_pyvenv_cfg_is_scanned(tmp_path):
    # A bare `venv` collides with CPython's stdlib package name and is a
    # plausible real source directory; without `pyvenv.cfg` it is not
    # actually a virtualenv, so it must not be excluded.
    (tmp_path / "app.py").write_text("x = 1\n")
    venv = tmp_path / "venv"
    venv.mkdir()
    (venv / "module.py").write_text("z = 3\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py")

    filenames = _scanned_filenames(results)
    assert str(tmp_path / "app.py") in filenames
    assert str(venv / "module.py") in filenames
    assert len(results) == 2


def test_dot_venv_is_skipped_unconditionally(tmp_path):
    # `.venv` has no naming ambiguity, so it is excluded even without
    # `pyvenv.cfg` -- unlike the bare `venv` name above.
    (tmp_path / "app.py").write_text("x = 1\n")
    dot_venv = tmp_path / ".venv"
    dot_venv.mkdir()
    (dot_venv / "module.py").write_text("z = 3\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py")

    filenames = _scanned_filenames(results)
    assert str(tmp_path / "app.py") in filenames
    assert str(dot_venv / "module.py") not in filenames
    assert len(results) == 1


def test_git_internals_are_skipped(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    git_hooks = tmp_path / ".git" / "hooks"
    git_hooks.mkdir(parents=True)
    (git_hooks / "pre-commit.py").write_text("print('hook')\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py")

    filenames = _scanned_filenames(results)
    assert str(tmp_path / "app.py") in filenames
    assert str(git_hooks / "pre-commit.py") not in filenames
    assert len(results) == 1


def test_file_outside_excluded_dir_is_still_scanned(tmp_path):
    # A directory that merely *looks* related (not one of the excluded names)
    # is ordinary project source and must not be touched.
    (tmp_path / "app.py").write_text("x = 1\n")
    src = tmp_path / "src" / "worktrees"
    src.mkdir(parents=True)
    (src / "helper.py").write_text("y = 2\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py")

    filenames = {pathlib.Path(f).name for f in _scanned_filenames(results)}
    assert "app.py" in filenames
    assert "helper.py" in filenames
    assert len(results) == 2


def test_scan_root_inside_excluded_dir_still_scans_its_files(tmp_path):
    # Matching is on path components *relative to the scan root*. If the root
    # itself sits inside a directory that would otherwise be excluded, its own
    # files are still real, explicitly requested scan targets.
    root = tmp_path / ".claude" / "worktrees" / "some-branch"
    root.mkdir(parents=True)
    (root / "app.py").write_text("x = 1\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(root), "**/*.py")

    filenames = _scanned_filenames(results)
    assert str(root / "app.py") in filenames
    assert len(results) == 1


def test_explicit_single_file_scan_is_unaffected(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    target = git_dir / "app.py"
    target.write_text("x = 1\n")

    scanner = FrameScanner(language="python", verify=False)
    result = scanner.scan_file(str(target))

    assert result.filename == str(target)
    assert not result.errors


def test_exclude_dirs_empty_list_disables_filtering(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "hook.py").write_text("print('hook')\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py", exclude_dirs=[])

    filenames = _scanned_filenames(results)
    assert str(tmp_path / "app.py") in filenames
    assert str(git_dir / "hook.py") in filenames
    assert len(results) == 2


def test_exclude_dirs_custom_set_overrides_default(tmp_path):
    # A caller-supplied exclude set replaces the default rather than adding to
    # it: `.git` is not excluded here, but the custom name `scratch` is.
    (tmp_path / "app.py").write_text("x = 1\n")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "hook.py").write_text("print('hook')\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "throwaway.py").write_text("z = 3\n")

    scanner = FrameScanner(language="python", verify=False)
    results = scanner.scan_directory(str(tmp_path), "**/*.py", exclude_dirs={"scratch"})

    filenames = _scanned_filenames(results)
    assert str(tmp_path / "app.py") in filenames
    assert str(git_dir / "hook.py") in filenames
    assert str(scratch / "throwaway.py") not in filenames
