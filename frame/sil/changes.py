"""Which files changed: the selection behind `frame scan --changed`."""

import subprocess
from pathlib import Path
from typing import List


class GitError(Exception):
    """git is unavailable, the path is not in a repository, or a ref is invalid."""


def _git(root: Path, *args: str) -> str:
    try:
        out = subprocess.run(["git", "-C", str(root), *args],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        raise GitError(f"cannot run git: {e}")
    if out.returncode != 0:
        raise GitError(out.stderr.strip() or f"git {' '.join(args)} failed")
    return out.stdout


def _has_commits(root: Path) -> bool:
    try:
        _git(root, "rev-parse", "--verify", "--quiet", "HEAD")
        return True
    except GitError:
        return False


def changed_files(root: Path, ref: str = "HEAD") -> List[Path]:
    """Files that differ between `ref` and the working tree (staged or not),
    plus untracked files git does not ignore. Deleted files are left out. In a
    repository with no commits yet, every file in the index counts as changed."""
    try:
        top = Path(_git(root, "rev-parse", "--show-toplevel").strip())
    except GitError as e:
        raise GitError(f"--changed needs a git repository ({e})")
    if ref == "HEAD" and not _has_commits(top):
        tracked = _git(top, "ls-files", "-z")
    else:
        tracked = _git(top, "diff", "--name-only", "-z", "--diff-filter=ACMRT", ref, "--")
    untracked = _git(top, "ls-files", "--others", "--exclude-standard", "-z")
    names = {n for n in (tracked + untracked).split("\0") if n}
    return sorted(p for p in (top / n for n in names) if p.is_file())
