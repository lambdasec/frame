"""Helpers for end-to-end tests: run Frame the way a user does and read its JSON.

`scan()` calls the real `frame` CLI entry point (`frame.cli.main`) with a real
argv and parses what it prints; `scan_subprocess()` spawns `python -m frame.cli`
for the few tests that care about process-level behaviour (exit status, stderr).
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from frame.cli import main as frame_main

_MARKER = re.compile(r"frame-expect:\s*((?:CWE-\d+)(?:\s*,\s*CWE-\d+)*)")
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".cs", ".c", ".h",
                   ".cc", ".cpp", ".cxx", ".hpp"}


@dataclass
class Scan:
    exit_code: int
    doc: dict
    stderr: str = ""
    findings: List[dict] = field(default_factory=list)

    def at(self, path: str, line: int) -> Set[str]:
        return {f["cwe_id"] for f in self.findings if f.get("path") == path and f.get("line") == line}

    def cwes(self, path: Optional[str] = None) -> Set[str]:
        return {f["cwe_id"] for f in self.findings if path is None or f.get("path") == path}

    def in_file(self, path: str) -> List[dict]:
        return [f for f in self.findings if f.get("path") == path]

    @property
    def packs_applied(self) -> Set[str]:
        out: Set[str] = set()
        for f in self.doc.get("files", [self.doc]):
            out |= set(f.get("packs", []))
        return out


def _flatten(doc: dict) -> List[dict]:
    files = doc["files"] if "files" in doc else [doc]
    out = []
    for f in files:
        out.extend(f.get("vulnerabilities", []))
    return out


def scan(target: Path, *flags: str, root: Optional[Path] = None, fail_on: str = "none") -> Scan:
    """`frame scan TARGET -f json ...` through the real CLI entry point."""
    target = Path(target)
    argv = ["scan", str(target), "-f", "json", "--fail-on", fail_on]
    if root is not None:
        argv += ["--root", str(root)]
    elif target.is_dir():
        argv += ["--root", str(target)]
    argv += list(flags)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = frame_main(argv)
    text = out.getvalue()
    doc = json.loads(text) if text.strip().startswith("{") else {}
    return Scan(exit_code=code, doc=doc, stderr=err.getvalue(), findings=_flatten(doc) if doc else [])


def scan_subprocess(target: Path, *flags: str, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    """`python -m frame.cli scan TARGET ...` in a child process."""
    return subprocess.run([sys.executable, "-m", "frame.cli", "scan", str(target), *flags],
                          capture_output=True, text=True, cwd=str(cwd) if cwd else None)


def write_tree(root: Path, files: Dict[str, str]) -> Path:
    """Create `files` (relative path -> content) under root and return root."""
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


def expectations(app_dir: Path) -> Dict[Tuple[str, int], Set[str]]:
    """`frame-expect: CWE-89[, CWE-79]` markers in a fixture app: {(relative path, line): CWEs}."""
    out: Dict[Tuple[str, int], Set[str]] = {}
    for f in sorted(app_dir.rglob("*")):
        if not f.is_file() or f.suffix not in SOURCE_SUFFIXES:
            continue
        for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            m = _MARKER.search(line)
            if m:
                out[(f.relative_to(app_dir).as_posix(), n)] = {c.strip() for c in m.group(1).split(",")}
    return out
