"""Provider credentials anywhere in a repository's git history (`frame history`).

A credential deleted from the code is still in every clone's history: it is leaked until it is
rotated. This reads every line each commit added (`git log -p`, all refs by default) and reports
each distinct credential once, at the commit that first added it, with whether the current tree
still has it. The formats are `secret-formats.toml`'s (a fixed provider prefix and length; the
providers' published example values are ignored). Unlike the source scan, comments count here:
a real key in a comment is as leaked as one in a string.

The value itself is never printed or stored: a finding carries its first four characters, its
length and a SHA-256 fingerprint, enough to tell two findings apart and to find the key with the
provider, not enough to use it.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from frame.sil.secret_formats import formats

_COMMIT = re.compile(r"^commit ([0-9a-f]{40}) (\d+)$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class HistoryError(RuntimeError):
    pass


@dataclass
class Leak:
    format: str
    provider: str
    description: str
    commit: str
    date: int                      # commit time, seconds since the epoch
    path: str
    line: int
    redacted: str                  # the first four characters and the length
    fingerprint: str               # sha256 of the value
    in_head: bool = False          # the current tree still has it
    commits: int = 1               # how many commits added it

    def to_dict(self) -> dict:
        return asdict(self)


def redact(value: str) -> str:
    return f"{value[:4]}... ({len(value)} characters)"


def _matches(text: str) -> Iterator[Tuple[object, str, int]]:
    """Every provider credential in a text and where it starts (`find` stops at the first)."""
    for f in formats():
        for m in f.regex.finditer(text):
            value = m.group(0)
            if value not in f.ignore and not any(x in value for x in f.ignore):
                yield f, value, m.start()


def _added_hunks(repo: Path, rev: Optional[str]) -> Iterator[Tuple[str, int, str, int, List[str]]]:
    """(commit, time, path, first line, lines) for every run of lines a commit added, oldest
    first: a private key spans lines, so formats are searched in the run, not line by line."""
    run: List[str] = []
    start = 0
    key: Tuple[str, int, str] = ("", 0, "")
    for commit, when, path, line, text in _added_lines(repo, rev):
        if run and (key != (commit, when, path) or line != start + len(run)):
            yield key[0], key[1], key[2], start, run
            run = []
        if not run:
            key, start = (commit, when, path), line
        run.append(text)
    if run:
        yield key[0], key[1], key[2], start, run


def _added_lines(repo: Path, rev: Optional[str]) -> Iterator[Tuple[str, int, str, int, str]]:
    """(commit, time, path, line number, text) for every line a commit added, oldest first."""
    cmd = ["git", "-C", str(repo), "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-renames",
           "--reverse", "--format=commit %H %ct", *(["--all"] if rev is None else [rev])]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise HistoryError(f"git: {e}") from e
    commit, when, path, line = "", 0, None, 0
    assert proc.stdout is not None
    for raw in proc.stdout:
        text = raw.decode("utf-8", "replace").rstrip("\n")
        m = _COMMIT.match(text)
        if m:
            commit, when, path = m.group(1), int(m.group(2)), None
            continue
        if text.startswith("+++ "):
            target = text[4:]
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            continue
        h = _HUNK.match(text)
        if h:
            line = int(h.group(1))
            continue
        if path and text.startswith("+") and not text.startswith("+++"):
            yield commit, when, path, line, text[1:]
            line += 1
    proc.wait()
    if proc.returncode not in (0, None):
        err = (proc.stderr.read().decode("utf-8", "replace") if proc.stderr else "").strip()
        raise HistoryError(f"git log failed: {err[-300:]}")


def _head_has(repo: Path, value: str) -> bool:
    r = subprocess.run(["git", "-C", str(repo), "grep", "-q", "-F", "-e", value, "HEAD", "--"],
                       capture_output=True)
    return r.returncode == 0


def scan_history(repo: Path, rev: Optional[str] = None) -> List[Leak]:
    """Each distinct credential the history added, at its first commit (oldest first)."""
    repo = Path(repo)
    if subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-dir"], capture_output=True).returncode != 0:
        raise HistoryError(f"{repo}: not a git repository")
    found: Dict[str, Leak] = {}
    values: Dict[str, str] = {}
    order: Dict[str, Tuple[int, int]] = {}
    for seq, (commit, when, path, first, lines) in enumerate(_added_hunks(repo, rev)):
        text = "\n".join(lines)
        for fmt, value, at in _matches(text):
            line = first + text.count("\n", 0, at)
            fp = hashlib.sha256(value.encode()).hexdigest()
            if fp in found:
                if found[fp].commit != commit:
                    found[fp].commits += 1
                continue
            values[fp] = value
            order[fp] = (seq, line)
            found[fp] = Leak(fmt.id, fmt.provider, fmt.description, commit, when, path, line,
                             redact(value), fp)
    has_head = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "-q", "HEAD"],
                              capture_output=True).returncode == 0
    for fp, leak in found.items():
        leak.in_head = has_head and _head_has(repo, values[fp])
    return [found[fp] for fp in sorted(found, key=order.__getitem__)]   # as git added them, oldest first


def format_text(leaks: List[Leak]) -> str:
    if not leaks:
        return "No provider credentials in the history."
    lines = [f"{len(leaks)} credential(s) in the history (rotate each one: removing it from the code does not "
             "remove it from clones):"]
    for x in leaks:
        where = "still in the current tree" if x.in_head else "not in the current tree, still in the history"
        lines.append(f"  {x.provider} {x.description}: {x.redacted} added in {x.commit[:12]} {x.path}:{x.line} "
                     f"({where})")
    return "\n".join(lines)
